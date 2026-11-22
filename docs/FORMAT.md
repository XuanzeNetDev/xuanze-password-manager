# 璇泽密钥库 · 文件格式规范 v2

> 版本：1 · 状态：稳定 · 最后修改：2026-11-21
>
> 本文档是格式的**规范来源**。实现（`crates/xz-core`）与文档不一致时，文档与实现
> 同时视为缺陷，须一起提交修复。任何破坏兼容性的改动都必须提升 `version` 字段。

---

## 0. 设计原则

1. **头即 AAD。** 文件头（71 字节）整个参与 AEAD 认证。改任何一个头字段，解密必然失败。
   这让「降级攻击」（把 KDF 参数改小、换算法）在密码学上不可行，不需要额外逻辑。
2. **两个独立密文段。** 索引与正文分开加密，用不同子密钥。
   索引可以在不解密正文的情况下单独读取，为将来「只给搜索结果的只读预览」留出口。
3. **固定结构，无 TLV。** v1 只有三个定长/带长度前缀的段。
   TLV 好扩展但要线性扫描，v1 用不到；真需要扩展时升 v2。
4. **参数有上限。** 文件里可声明 KDF 参数，但读取端**强制**校验边界（见 §4）。
   恶意构造一个 `memory_kib = 4 GiB` 的 vault 就能把客户端打死，必须拦住。
5. **不透露密码是否正确。** 密码错误、文件被篡改、段损坏，对外都表现为同一个错误。
   唯一的例外是 `verify_block` 的结构性缺失，那是文件格式错误，与密码无关。

---

## 1. 总体布局

全部**小端序**。偏移量从文件起始算。

```
┌───────────────────────────────────────────── 偏移 0
│  文件头（71 字节，见 §2）                    │
├───────────────────────────────────────────── 偏移 71
│  u32  index_len                             │
│  bytes index_blob   (index_len 字节)        │
│  u32  body_len                              │
│  bytes body_blob    (body_len 字节)         │
│  bytes verify_block （固定 46 字节）         │
└───────────────────────────────────────────── 文件尾
```

**注意**：`verify_block` 没有长度前缀，长度恒为 **46 字节**
（12 nonce + 18 明文 + 16 tag）。读取端必须**严格校验**这个长度——
多一字节少一字节都拒绝，否则「文件被追加数据却仍能打开」这种语义说不清。

### 密文段结构

`index_blob`、`body_blob`、`verify_block` 都是同一个形状：

```
┌──────────────┬──────────────────────────────────┐
│ nonce (12 B) │ AES-256-GCM 密文 + tag (n + 16 B) │
└──────────────┴──────────────────────────────────┘
```

`nonce` 每次加密都用 CSPRNG 重新生成，**绝不复用**。同一把密钥下 nonce 复用会
直接摧毁 GCM 的安全性，代码里没有任何就地重加密的路径可以绕过这一点。

---

## 2. 文件头（71 字节）

| 偏移 | 长度 | 字段 | 值 / 含义 |
|---:|---:|---|---|
| 0 | 8 | `magic` | `58 5A 56 4C 54 00 02 00`（即 `XZVLT\0\x02\0`） |
| 8 | 2 | `version` | 格式版本，v2 = `0x0002` |
| 10 | 1 | `kdf_algo` | `0x01` = Argon2id v0x13。**算法与版本合成一个枚举值**，不是两个字段 |
| 11 | 4 | `kdf_mem_kib` | Argon2 内存开销，单位 KiB |
| 15 | 4 | `kdf_iterations` | Argon2 迭代次数 |
| 19 | 4 | `kdf_parallelism` | Argon2 lanes |
| 23 | 32 | `kdf_salt` | 随机盐。**创建后永不改变**，除非换主密码 |
| 55 | 16 | `vault_id` | 库的稳定标识，创建时随机生成，终身不变 |
| 71 | — | （段区开始） | |

### `kdf_algo` 为什么把算法和版本合成一个值

只有一个字节的空间，里面既要表达「用哪个算法」又要表达「该算法的哪个版本」。
做法是把它当作一个**枚举**，而不是拆成两个字段：

| 值 | 含义 |
|---:|---|
| `0x01` | Argon2id v0x13（当前唯一在用的） |
| `0x02` | 留给未来的 Argon2id v0x14 或别的算法 |

读取端只认 `0x01`，遇到别的值直接报「不支持的 KDF 参数」并拒绝打开 ——
不会误用错误的派生参数。

**将来 Argon2 升版怎么办：** 新增一个枚举值（比如 `0x02`），
旧库继续用 `0x01` 读，新库写 `0x02`。**不需要改文件头长度，也不需要升 `version`。**
把算法和版本分成两个字段反而会让「`0x02` 算法 + 未知版本」这种非法组合变得可能。

### 为什么盐永不轮换

轮换盐意味着用新盐重新派生主密钥、重新加密全部数据。v1 里换主密码时确实会连盐
一起换（`Vault::change_password`），但**日常保存不碰盐**。若每次保存都换盐，
等于每次保存都要重跑 KDF 并全量重加密——与「极致性能」直接冲突，且没有安全收益：
salt 的作用是防预计算表和跨库关联，一次性足够。

### `vault_id` 的用途

应用只接受**它自己创建的那个库**。首次创建时把 `vault_id` 用 DPAPI 封存到本机
登记表；打开时先比对这个 ID，不认识就直接拒绝，连密码验证都不给。

这是「认库不认人」：从别处拷来的 `.xzvlt` 哪怕密码完全正确也打不开。目标是让
「拷走文件 → 离线慢慢爆破」这条路彻底没有收益——攻击者拿到的是一个没有意义的
文件，而不是一个可攻击的密文。

---

## 3. 密码学构造

### 3.1 密钥派生

```
master_key  = Argon2id(password, kdf_salt, m, t, p, out = 32 B)
payload_key = HKDF-SHA256(master_key, info = "xzvlt/v1/payload", len = 32)
index_key   = HKDF-SHA256(master_key, info = "xzvlt/v1/index",   len = 32)
verify_key  = HKDF-SHA256(master_key, info = "xzvlt/v1/verify",  len = 32)
```

`HKDF` 的 salt 参数为 `None`（即全零盐），因为 `master_key` 本身已经是高熵随机值，
不需要再搅一次。用途隔离靠 `info` 串完成——三个子密钥互不通用，泄露一把不会连坐。

### 3.2 加密

```
blob = nonce(12 B, CSPRNG) || AES-256-GCM(payload_key, nonce, plaintext, aad = 文件头 71 字节) 
```

- 三个段的 AAD 都是**同一份**文件头字节。
- 认证标签 16 字节，附在密文尾部（GCM 标准布局）。

### 3.3 校验块（`verify_block`）

```
verify_block = nonce(12) || AES-256-GCM(verify_key, nonce, "xzvlt/v1/verify-ok", aad = 文件头)
```

明文是固定字符串 `xzvlt/v1/verify-ok`（18 字节），所以校验块长度恒为 12 + 18 + 16 = **46 字节**。

**它不能省。** 没有它，一次错误的密码会表现为「索引 JSON 解析失败」，
用户看到的是「文件损坏」而不是「密码错误」——这在体验上是灾难。

---

## 4. KDF 参数边界

读取端**必须**拒绝超出下列范围的参数，否则就是自找 DoS：

| 字段 | 下限 | 上限 | 理由 |
|---|---:|---:|---|
| `kdf_mem_kib` | 8 192 (8 MiB) | 1 048 576 (1 GiB) | 低于 8 MiB 起不到内存硬的作用；高于 1 GiB 会让弱机直接换页 |
| `kdf_iterations` | 1 | 32 | 32 轮是安全冗余的上界，再多只是自罚 |
| `kdf_parallelism` | 1 | 16 | 超过物理核数没有收益，且放大内存 |

推荐档位（写入端使用）：

| 档位 | mem_kib | iterations | parallelism | 本机实测耗时 |
|---|---:|---:|---:|---:|
| `light` | 19 456 | 2 | 1 | ≈ 16 ms |
| `balanced` | 65 536 | 3 | 4 | ≈ 85 ms |
| `paranoid`（默认） | 262 144 | 4 | 4 | ≈ 510 ms |

实测环境：Windows / Ryzen（32 逻辑核）/ release 构建。
具体数字随机器浮动，量级是关键：**KDF 是打开 vault 唯一值得等的部分**。

---

## 5. 明文内容（加密前）

两段明文都是 UTF-8 JSON。用 JSON 而不是 MessagePack / bincode 的理由：
开源项目需要可审计、可人工比对、可写测试夹具；JSON 的解析开销在 release 下
对 1 万条条目是毫秒级（见基准），不值得为省几毫秒牺牲可读性。

### 5.1 索引段（用 `index_key` 加密）

```json
{
  "items": [
    {
      "id": "0123456789abcdef0123456789abcdef",
      "kind": 1,
      "name": "OpenAI 生产 Key",
      "lower_name": "openai 生产 key",
      "username": "team-prod",
      "lower_username": "team-prod",
      "url": "https://api.openai.com",
      "lower_url": "https://api.openai.com",
      "tags": [["api", "api"], ["prod", "prod"]],
      "updated_at": 1732000000,
      "use_count": 12,
      "last_used_at": 1732000100,
      "expires_at": 0
    }
  ]
}
```

**硬约束：索引段不含任何秘密。** 不含 `secret` 字段、不含敏感自定义字段的值。
这条有单测守着（`entry::tests::index_never_carries_secrets`）。

`lower_*` 是搜索用的小写副本。它让搜索不必每次击键都对全库做 `to_lowercase`，
代价是索引体积约 ×1.7。桌面端这个交换永远划算。

`tags` 是 `[原文, 小写]` 的二元组数组，原因同上。

`kind` 是数值：`0`=Login `1`=ApiKey `2`=Note `3`=Card `4`=Credential。
这五个值的含义一旦发布就冻结。

### 5.2 正文段（用 `payload_key` 加密）

```json
{
  "entries": [
    {
      "id": "0123456789abcdef0123456789abcdef",
      "kind": "api_key",
      "name": "OpenAI 生产 Key",
      "username": "team-prod",
      "secret": "sk-...",
      "url": "https://api.openai.com",
      "fields": [
        {"name": "org", "value": "org-123", "secret": true},
        {"name": "region", "value": "ap-east-1", "secret": false}
      ],
      "tags": ["api", "prod"],
      "notes": "轮换周期 90 天",
      "created_at": 1732000000,
      "updated_at": 1732000000,
      "expires_at": 0,
      "use_count": 12,
      "last_used_at": 1732000100
    }
  ]
}
```

`id` 是 32 位十六进制（16 字节 CSPRNG）。它是条目的稳定身份，改 id 等于换条目。

---

## 6. 打开流程（读取端）

```
1. 读文件 → 校验长度 ≥ 75（`HEADER_LEN` 71 + 4 字节 `index_len`）
2. FileHeader::parse(前 71 字节)
   ├─ magic 不符        → NotAVault
   ├─ version > 支持版本 → UnsupportedVersion
   └─ KDF 参数越界       → UnacceptableKdf
3. split_sealed 切出三段，任一段越界 → Corrupt
4. derive_master_key（慢，唯一一处）
5. check_verify_block
   ├─ 认证失败 / 明文不符 → BadPasswordOrTampered
6. decrypt index 段 → 反序列化
7. decrypt body 段  → 反序列化 → 建 HashMap + Index
8. 以正文为准重建索引（落盘索引仅供 v2 快速路径使用）
```

第 8 步的取舍：落盘的索引和正文理论上一致，但**不信任**它。
以正文为准重建，避免索引被单独篡改时搜出幽灵条目。代价是打开时多做一遍索引构建
（1 万条约 30 ms，见基准）。安全 > 这点开销。

---

## 7. 保存流程（写入端）

```
1. 组装文件头（version / kdf / salt 原样，不重新生成 salt）
2. 正文序列化 → payload_key 加密
3. 索引序列化 → index_key 加密
4. 生成 verify_block
5. 拼接完整字节
6. 写同目录临时文件 .<name>.tmp → fsync → rename 覆盖
```

第 6 步是**原子保存**。断电或崩溃时，磁盘上要么是完整旧文件、要么是完整新文件，
不会出现半截 vault。

落在文件系统上是 `std::fs::rename`，它在 Windows 上走
`MoveFileExW(MOVEFILE_REPLACE_EXISTING)`。需要厘清两点：

- 它**不是** `ReplaceFile`。没有备份副本、没有事务语义，就是一次替换。
- 目标文件正被别的进程占着（杀软扫描、同步盘、索引服务）时，它会**直接失败**
  而不是重试。这是可接受的行为：失败会返回错误，用户看到「写不进去」，
  旧文件仍然完好。反过来，如果它静默成功一半，才是灾难。

临时文件名带 16 字节随机后缀，且用 `create_new(true)` 占位 —— 后者能挡住
「攻击者预先在同目录放一个同名符号链接」这类劫持。

保存**不重跑 KDF**。这是「极致性能」的核心：主密钥已经在内存里，
保存只是序列化 + AES，1 万条约 40 ms。

---

## 8. 版本演进规则

升 `version` 的触发条件（任一）：

- 更换 KDF 算法或改变 `info` 串
- 改变 AAD 覆盖范围
- 改变段布局
- 给 `kind` 数值重新赋值
- 改变索引/正文的 JSON 结构且无法向后兼容

不升版本的改动：新增可选 JSON 字段（读取端必须 `#[serde(default)]` ignore）、
调整 KDF 推荐档位、算法内部实现优化。

读取端对 `version` 的处理：**只接受 ≤ 自身支持的最高版本**，高于则明确报错
`UnsupportedVersion`，绝不猜测解析。

---

## 9. 已知限制与后续待办

1. **索引不轮换。** 每次保存都全量重加密正文。5 万条时保存 ≈ 400 ms，
   对个人库够用，但不适合「十万条 + 高频写入」。v2 可考虑分段 + 只重写变动部分。
2. **无增量落盘。** 同上。
3. **JSON 开销。** 5 万条正文 33 MiB，其中 JSON 语法字符占比可观。
   v2 可在格式层换 binary，但需保留「可人工审阅」的导出路径。
4. **机器绑定是应用层行为，不在格式里。** `.xzvlt` 文件本身不含任何设备指纹，
   换台机器用 `format` 里的规则仍可解析。绑定发生在应用层：主密钥派生时混入
   本机 DPAPI 封存的随机串 + 机器名 + 卷序列号（见 `crates/xz-core/src/binding.rs`），
   同时应用只接受 `vault_id` 匹配本机登记表的库。
   结果是：文件格式保持可移植，但用它解密需要原机器的身份。
   未来可加硬件密钥（TPM / FIDO2）作为额外因子。
5. **`parallelism` 不加速。** 当前构建不启用 Argon2 的多线程实现
   （`argon2` crate 的并行特性依赖 rayon，会引入额外依赖树）。
   档位字段照写入，为将来留出口。

---

## 10. 测试向量

`crates/xz-core` 的单元测试即行为规范，重点覆盖：

| 测试 | 守的是什么 |
|---|---|
| `wrong_password_rejected` | 错误密码必须失败且不可区分 |
| `corrupted_file_rejected` | 翻一个 bit 必须失败 |
| `header_is_aad_so_tampering_fails` | 改头字段必须失败 |
| `nonce_is_not_reused` | 两次加密不共用 nonce |
| `subkeys_are_distinct` | 三把子密钥互不相等 |
| `index_never_carries_secrets` | 索引段不含秘密 |
| `secrets_never_searchable` | 秘密不可被搜索 |
| `remove_fixes_swapped_index` | 索引删除后 id 映射不串位 |
| `save_and_open_from_disk` | 原子保存无残留临时文件 |
| `change_password_then_old_fails` | 换密码后旧密码失效 |

`cargo test -p xz-core` 应全绿（当前 60 项）。
