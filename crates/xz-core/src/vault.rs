//! Vault：一次打开、内存常驻、原子保存。
//!
//! 生命周期：
//!
//! ```text
//!   Vault::open(bytes, password)  ── 解析头 → KDF → 校验 → 解密索引+正文 → 建索引
//!          │
//!          ├─ search()     纯内存，微秒级
//!          ├─ reveal(id)   纯内存，微秒级
//!          ├─ record_use() 纯内存，内存写回
//!          └─ save()       序列化 → 加密 → 原子写盘
//!          │
//!   lock()/drop  ── 密钥与明文全部 zeroize
//! ```
//!
//! 「极致性能」的实际含义就在这里：**KDF 只在打开时跑一次**，
//! 之后所有高频操作（搜索、复制、列表）都不产生任何密码学开销。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::codec::{self, FileHeader};
use crate::crypto::{self, KeyPurpose};
use crate::entry::{Entry, IndexItem};
use crate::error::{Error, Result};
use crate::index::Index;
use crate::kdf::{self, KdfParams};
use crate::secure::{SecretBytes, SecretString};

/// 正文容器：vault 解密后的全部条目。
#[derive(Debug, Serialize, Deserialize)]
struct Body {
    #[serde(default)]
    entries: Vec<Entry>,
}

/// 索引容器：轻量、无秘密。
#[derive(Debug, Serialize, Deserialize)]
struct IndexPayload {
    items: Vec<IndexItem>,
}

/// v3 起跟着库文件走的绑定材料。
///
/// 存在的理由：`%APPDATA%` 会被清空、DPAPI 主密钥会随重装系统换掉，
/// 而库文件本身还在。把绑定材料用硬件指纹封装后写进文件，
/// 重装系统（硬件没变）就能靠它把库打开。
pub struct Binding {
    /// 本机随机串（256 bit）。
    secret: SecretBytes,
    /// 封装绑定块用的硬件指纹。换了硬件就解不开。
    hardware_fp: Vec<u8>,
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binding")
            .field("secret", &self.secret) // SecretBytes 只打印长度
            .field("hardware_fp_len", &self.hardware_fp.len())
            .finish()
    }
}

impl Clone for Binding {
    /// 显式复制：`secret` 用 `duplicate()`，两份都会被擦除。
    fn clone(&self) -> Self {
        Self {
            secret: self.secret.duplicate(),
            hardware_fp: self.hardware_fp.clone(),
        }
    }
}

impl Binding {
    /// 按 v3 规则派生主密钥。
    ///
    /// **「这个库用哪套 pepper 规则」只有这一个地方说了算。**
    ///
    /// 之前这个知识散在三处：打开（`commands::binding_for`）、改密码后重封
    /// （`reseal_snapshot`）、改密码后换内存密钥（`change_password_bound`）。
    /// 三处里两处写对了、一处漏了，结果就是「改了个密码把库改坏」——
    /// 文件头写着 v3、主密钥却按 v2 算。收敛到这里之后，不会再各写各的。
    fn derive_key(&self, password: &str, salt: &[u8], params: KdfParams) -> Result<SecretBytes> {
        crate::binding::derive_bound_key_v3(password.as_bytes(), self.secret.as_slice(), salt, params)
    }
}

/// 打开后的 vault。
pub struct Vault {
    /// 落盘路径。`None` 表示纯内存（新建未保存）。
    path: Option<PathBuf>,
    /// KDF 参数，保存时原样写回。
    kdf: KdfParams,
    /// KDF 盐，保存时原样写回。**永不轮换**（轮换=重新加密全部数据）。
    salt: [u8; 32],
    /// 库的稳定标识，创建时随机生成，之后永不改变。
    vault_id: [u8; 16],
    /// 主密钥。drop 时擦除。
    master_key: SecretBytes,
    /// id → 完整条目。真正持有秘密的地方。
    entries: HashMap<String, Entry>,
    /// 内存索引。
    index: Index,
    /// 是否有未落盘改动。
    dirty: bool,
    /// 写回时用的格式版本。打开老库时保持原版本，不会偷偷升级。
    format_version: u16,
    /// 绑定材料（仅 v3）。写回时用它重写绑定块。
    binding: Option<Binding>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不打印任何秘密。
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("kdf", &self.kdf)
            .field("entries", &self.entries.len())
            .field("dirty", &self.dirty)
            .finish()
    }
}

impl Vault {
    /// 新建空 vault。
    pub fn create(password: &str, params: KdfParams) -> Result<Self> {
        Self::create_bound(password, params, &[])
    }

    /// 新建空 vault，并绑定到本机材料（v2 规则）。
    ///
    /// `pepper` 为空表示不绑定（只用于测试）；正式使用必须给。
    /// 新代码应该用 [`Vault::create_bound_v3`]。
    pub fn create_bound(password: &str, params: KdfParams, pepper: &[u8]) -> Result<Self> {
        let salt = kdf::random_salt();
        let master_key = if pepper.is_empty() {
            kdf::derive_master_key(password.as_bytes(), &salt, params)?
        } else {
            crate::binding::derive_bound_key(password.as_bytes(), pepper, &salt, params)?
        };
        Ok(Self {
            path: None,
            kdf: params,
            salt,
            vault_id: kdf::random_bytes::<16>(),
            master_key,
            entries: HashMap::new(),
            index: Index::new(),
            dirty: true,
            // v2 规则建的库：不带绑定块，写回时也保持 v2 布局。
            format_version: 2,
            binding: None,
        })
    }

    /// 新建空 vault，绑定规则用 v3：绑定材料跟着文件走。
    ///
    /// 和 v2 的区别只有一个：pepper 不再混机器名与卷序列号，
    /// 而 `binding_secret` 会用 `hardware_fp` 加密封进文件（见 [`Binding`]）。
    /// 于是「改计算机名 / 重装系统」不再导致数据报废，换硬件依然打不开。
    pub fn create_bound_v3(
        password: &str,
        params: KdfParams,
        binding_secret: &[u8],
        hardware_fp: Vec<u8>,
    ) -> Result<Self> {
        let salt = kdf::random_salt();
        let master_key = crate::binding::derive_bound_key_v3(
            password.as_bytes(),
            binding_secret,
            &salt,
            params,
        )?;
        Ok(Self {
            path: None,
            kdf: params,
            salt,
            vault_id: kdf::random_bytes::<16>(),
            master_key,
            entries: HashMap::new(),
            index: Index::new(),
            dirty: true,
            format_version: crate::FORMAT_VERSION,
            binding: Some(Binding {
                secret: SecretBytes::from_vec(binding_secret.to_vec()),
                hardware_fp,
            }),
        })
    }

    /// 装配 v3 的绑定材料（打开库之后调用）。
    ///
    /// 只是把「已知的 binding_secret + 当前硬件指纹」记进 `Vault`，
    /// 以便下次 `save()` 时重写绑定块。不改主密钥、不改任何条目。
    pub fn adopt_binding(&mut self, binding_secret: SecretBytes, hardware_fp: Vec<u8>) {
        self.binding = Some(Binding {
            secret: binding_secret,
            hardware_fp,
        });
    }

    /// 这个库是否带 v3 的绑定块。
    #[must_use]
    pub fn has_binding(&self) -> bool {
        self.binding.is_some()
    }

    /// 从字节打开。
    ///
    /// 这是全流程唯一跑 KDF 的地方，也是唯一的慢路径。
    pub fn open_from_bytes(bytes: &[u8], password: &str) -> Result<Self> {
        Self::open_bound(bytes, password, &[])
    }

    /// 从字节打开，并用本机材料解绑。
    ///
    /// `pepper` 必须和创建时的一致，否则校验块过不去。
    pub fn open_bound(bytes: &[u8], password: &str, pepper: &[u8]) -> Result<Self> {
        // 1) KDF（慢）
        let key = Self::derive_key_for(bytes, password, pepper)?;
        // 2) 剩下的解密/解析
        Self::open_bound_with_key(bytes, key)
    }

    /// 只跑 KDF，拿到主密钥。**这一步不碰任何 `Vault` 状态。**
    ///
    /// 拆出来是为了让调用方能把这几秒放到锁外：KDF 是全场唯一的慢路径，
    /// 持着锁跑等于把整个界面冻住。先读文件 + 算密钥，再加锁装配。
    pub fn derive_key_for(bytes: &[u8], password: &str, pepper: &[u8]) -> Result<SecretBytes> {
        let header = FileHeader::parse(bytes)?;
        if pepper.is_empty() {
            kdf::derive_master_key(password.as_bytes(), &header.salt, header.kdf)
        } else {
            crate::binding::derive_bound_key(password.as_bytes(), pepper, &header.salt, header.kdf)
        }
    }

    /// 用已经算好的主密钥完成打开。
    ///
    /// 快：只有 AES-GCM 解密和 JSON 解析，几毫秒量级。
    pub fn open_bound_with_key(bytes: &[u8], master_key: SecretBytes) -> Result<Self> {
        let header = FileHeader::parse(bytes)?;
        let header_bytes = header.to_bytes();
        let parts = codec::split_sealed(bytes)?;

        // 主密码校验（快，但不可省：它把「密码错」和「索引损坏」分开）
        codec::check_verify_block(&master_key, &header_bytes, parts.verify)?;

        // 3) 解密索引
        let idx_key = crypto::derive_subkey(&master_key, KeyPurpose::Index)?;
        let idx_plain = crypto::open(&idx_key, &header_bytes, parts.index)?;
        let idx_payload: IndexPayload = serde_json::from_slice(idx_plain.as_slice())
            .map_err(|_| Error::Corrupt("索引 JSON 解析失败"))?;

        // 4) 解密正文
        let body_key = crypto::derive_subkey(&master_key, KeyPurpose::Payload)?;
        let body_plain = crypto::open(&body_key, &header_bytes, parts.body)?;
        let body: Body = serde_json::from_slice(body_plain.as_slice())
            .map_err(|_| Error::Corrupt("正文 JSON 解析失败"))?;

        let mut entries = HashMap::with_capacity(body.entries.len());
        for e in body.entries {
            entries.insert(e.id.clone(), e);
        }

        // 5) 建索引。优先用落盘的索引（它可能被单独更新过），
        //    但以正文为准重建，避免两边不一致时搜出幽灵条目。
        let mut index = Index::with_capacity(entries.len());
        for e in entries.values() {
            index.upsert(e);
        }
        let _ = idx_payload; // 保留字段，v2 可做「索引只更新」的快速路径
        index.clear_dirty();

        Ok(Self {
            path: None,
            kdf: header.kdf,
            salt: header.salt,
            vault_id: header.vault_id,
            master_key,
            entries,
            index,
            dirty: false,
            // 记住原文件是哪个版本，写回时保持原样 —— 打开一个老库不应该
            // 偷偷把它升级成新格式。
            format_version: header.version,
            // 绑定材料由调用方解出来后 `adopt_binding()` 补上。
            binding: None,
        })
    }

    /// 从文件打开。
    pub fn open(path: impl AsRef<Path>, password: &str) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        let mut v = Self::open_from_bytes(&bytes, password)?;
        v.path = Some(path.to_path_buf());
        Ok(v)
    }

    /// 绑定落盘路径（另存为时用）。
    pub fn set_path(&mut self, path: impl Into<PathBuf>) {
        self.path = Some(path.into());
    }

    /// 取出主密钥的切片，供「本机自动解锁」封存用。
    ///
    /// 调用方只应该把它立刻交给 `CryptProtectData` 封存，
    /// 不要持有、不要打印、不要复制到别的地方。
    pub fn master_key_slice(&self) -> &[u8] {
        self.master_key.as_slice()
    }

    /// 库的稳定标识（十六进制）。应用侧靠它判断「是不是自己创建的那个库」。
    #[must_use]
    pub fn vault_id(&self) -> String {
        let mut s = String::with_capacity(32);
        for b in self.vault_id {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// 当前路径。
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// 条目总数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 是否有未保存改动。
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// 只读索引。
    #[must_use]
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// 取完整条目（含秘密）。**调用方负责不要把它长留内存。**
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.get(id)
    }

    /// 取出主秘密，包进会被擦除的容器。
    pub fn reveal_secret(&self, id: &str) -> Result<SecretString> {
        let e = self
            .entries
            .get(id)
            .ok_or_else(|| Error::EntryNotFound(id.to_owned()))?;
        Ok(crate::secure::secret_string(e.secret.clone()))
    }

    /// 新增条目。id 冲突会报错，避免静默覆盖。
    pub fn insert(&mut self, entry: Entry) -> Result<String> {
        entry.validate()?;
        if self.entries.contains_key(&entry.id) {
            return Err(Error::DuplicateEntry(entry.id.clone()));
        }
        let id = entry.id.clone();
        self.index.upsert(&entry);
        self.entries.insert(id.clone(), entry);
        self.dirty = true;
        Ok(id)
    }

    /// 更新条目。不存在则报错。
    pub fn update(&mut self, entry: Entry) -> Result<()> {
        entry.validate()?;
        if !self.entries.contains_key(&entry.id) {
            return Err(Error::EntryNotFound(entry.id.clone()));
        }
        let id = entry.id.clone();
        self.index.upsert(&entry);
        self.entries.insert(id, entry);
        self.dirty = true;
        Ok(())
    }

    /// 删除条目。
    pub fn remove(&mut self, id: &str) -> Result<()> {
        if self.entries.remove(id).is_none() {
            return Err(Error::EntryNotFound(id.to_owned()));
        }
        self.index.remove(id);
        self.dirty = true;
        Ok(())
    }

    /// 记一次使用，用于热度排序。这是「快捷复制」的燃料。
    pub fn record_use(&mut self, id: &str, now: i64) -> Result<()> {
        let e = self
            .entries
            .get_mut(id)
            .ok_or_else(|| Error::EntryNotFound(id.to_owned()))?;
        e.use_count = e.use_count.saturating_add(1);
        e.last_used_at = now;
        // 直接把借用的条目交给索引，不 clone。
        //
        // 原先写的是 `let snapshot = e.clone(); index.upsert(&snapshot)` —— 那是
        // 把整条 Entry（secret、notes、所有自定义字段）复制一遍再扔掉，而
        // IndexItem::from 只读 id/kind/name/username/url/tags/时间戳这几个字段。
        // 复制出来的副本虽然会 ZeroizeOnDrop，但内存抖动是真的，而这是
        // 「按一下复制」的热路径 —— 一条 10 KB 备注的条目每次都白拷 10 KB。
        self.index.upsert(e);
        self.dirty = true;
        Ok(())
    }

    /// 序列化 + 加密，返回待写盘的完整字节。
    ///
    /// 不落盘，方便调用方决定写哪里（Tauri 层可以走 `fs::write` 或流式）。
    pub fn seal(&mut self) -> Result<Vec<u8>> {
        // 版本决定布局：带绑定材料 → v3（头后面多一段绑定块）；
        // 不带 → 保持打开时的版本（新建的按 v2）。
        //
        // 这里有一条不能含糊的规则：**v3 的文件头必须配一段真的绑定块**。
        // 少了它，读取端会按 v3 布局去解析、把 index_len 当成 bind_len，
        // 长度对不上就整库打不开。所以宁可直接报错，也不要写出一个
        // 「标着 v3 却缺段」的文件。
        let version = if self.binding.is_some() {
            crate::FORMAT_VERSION.max(3)
        } else {
            if self.format_version >= 3 {
                return Err(Error::Invalid(
                    "这个库是 v3 格式，但内存里没有绑定材料 —— 拒绝写出会降级/损坏的文件",
                ));
            }
            self.format_version
        };
        let header = FileHeader {
            version,
            kdf: self.kdf,
            salt: self.salt,
            vault_id: self.vault_id,
        };
        let header_bytes = header.to_bytes();

        // 正文
        //
        // `entries` 和 `body_plain` 都是全库明文：前者是条目本体，后者是它的
        // JSON 序列化。两者都必须擦 —— 尤其 `body_plain`，它是这一整库密码
        // 的明文快照，留在堆上等于前面所有加密白做。
        let entries: Vec<Entry> = self.entries.values().cloned().collect();
        let body_plain = zeroize::Zeroizing::new(
            serde_json::to_vec(&Body { entries }).map_err(|_| Error::Corrupt("正文序列化失败"))?,
        );
        let body_key = crypto::derive_subkey(&self.master_key, KeyPurpose::Payload)?;
        let body_blob = crypto::seal(&body_key, &header_bytes, &body_plain)?;

        // 索引
        let items: Vec<IndexItem> = self.index.all_sorted().into_iter().cloned().collect();
        let idx_plain = zeroize::Zeroizing::new(
            serde_json::to_vec(&IndexPayload { items })
                .map_err(|_| Error::Corrupt("索引序列化失败"))?,
        );
        let idx_key = crypto::derive_subkey(&self.master_key, KeyPurpose::Index)?;
        let idx_blob = crypto::seal(&idx_key, &header_bytes, &idx_plain)?;

        // 校验块
        let verify = codec::make_verify_block(&self.master_key, &header_bytes)?;

        // 绑定块（v3）：把本机随机串用硬件指纹加密封进文件。
        //
        // 它存在的唯一目的是「重装系统之后还能把库打开」——
        // `%APPDATA%` 会被清空、DPAPI 主密钥会换掉，而文件还在。
        // 换了硬件则解不开，那正是「设备绑定」要的效果。
        let bind_blob = match &self.binding {
            Some(b) => Some(crate::binding::wrap_binding_secret(
                &b.hardware_fp,
                b.secret.as_slice(),
            )?),
            None => None,
        };

        Ok(codec::assemble(
            &header_bytes,
            bind_blob.as_deref(),
            &idx_blob,
            &body_blob,
            &verify,
        ))
    }

    /// 原子保存：先写同目录临时文件，再 rename 覆盖。
    ///
    /// 断电/崩溃时要么是旧文件、要么是新文件，不会出现半截 vault。
    pub fn save(&mut self) -> Result<()> {
        let path = self
            .path
            .clone()
            .ok_or(Error::Invalid("vault 还没有落盘路径"))?;
        let bytes = self.seal()?;
        write_atomic(&path, &bytes)?;
        self.dirty = false;
        self.index.clear_dirty();
        Ok(())
    }

    /// 另存为。
    pub fn save_as(&mut self, path: impl Into<PathBuf>) -> Result<()> {
        self.path = Some(path.into());
        self.save()
    }

    /// 换主密码并重新加密。
    ///
    /// 盐一并轮换（换密码就该换盐），然后把全部数据用新密钥重封。
    pub fn change_password(&mut self, new_password: &str, params: Option<KdfParams>) -> Result<()> {
        self.change_password_bound(new_password, params, &[])
    }

    /// 换主密码，同时用给定机器材料重新绑定。
    ///
    /// 盐会随之轮换（重跑 KDF），所以换密码之后旧密钥彻底失效。
    ///
    /// **不提供「空密码」这条路。** 早先的设计允许把主密码改成空串，
    /// 那等于把一个加密库变成「谁都能开」的普通文件，而且点一下设置里的
    /// 勾选就永久生效 —— 那不是便利，是把产品的前提抽掉。
    /// 应用层已经明确拒绝空密码，见 `commands.rs::vault_rekey`。
    pub fn change_password_bound(
        &mut self,
        new_password: &str,
        params: Option<KdfParams>,
        pepper: &[u8],
    ) -> Result<()> {
        let params = params.unwrap_or(self.kdf);
        let salt = kdf::random_salt();
        // 和 `reseal_snapshot` 一样：规则跟着库走，不跟着调用方走。
        // 两处必须一致，否则「写盘用的规则」和「内存里那把钥匙」会对不上。
        let master_key = match &self.binding {
            Some(b) => b.derive_key(new_password, &salt, params)?,
            None => {
                if pepper.is_empty() {
                    kdf::derive_master_key(new_password.as_bytes(), &salt, params)?
                } else {
                    crate::binding::derive_bound_key(new_password.as_bytes(), pepper, &salt, params)?
                }
            }
        };
        self.master_key.wipe();
        self.master_key = master_key;
        self.salt = salt;
        self.kdf = params;
        self.dirty = true;
        Ok(())
    }

    /// 校验一个密码是不是当前库的密码。
    ///
    /// 不改变任何状态。用于「导出前再确认一次是本人」「改密码前先验旧密码」。
    pub fn verify_password(&self, password: &str) -> Result<()> {
        self.verify_password_bound(password, &[])
    }

    /// 校验密码，带机器绑定的 pepper。
    ///
    /// ## 判定方式：重新派生，再和内存里的主密钥做常量时间比对
    ///
    /// 这里曾经是「用派生出的 key 生成一个校验块，再用同一把 key 校验它」——
    /// 那是**自证**：任何密码派生出的 key 都能生成并校验自己的块，
    /// 所以无论输什么都会通过。而这道门守的是「导出全库明文」「改主密码」
    /// 「开免密码模式」这三件事，它的失效等于把产品的主要闸门一起拆掉。
    ///
    /// 正确的判据只有一个：**用这个密码重新派生，看能不能得到同一把主密钥。**
    /// 派生本身是慢的（这正是它安全的原因），所以调用方应该把它放到锁外、
    /// 后台线程里做 —— 见 `kdf_material` / `matches_master_key`。
    pub fn verify_password_bound(&self, password: &str, pepper: &[u8]) -> Result<()> {
        // 规则同样跟着库走（v3 用 binding，v2 用外部 pepper）。
        // 这里也是「三处里被漏掉的第四处」—— 少了它，改密码之后
        // 库能打开，但「再输一次密码」的校验会一直报错。
        let key = match &self.binding {
            Some(b) => b.derive_key(password, &self.salt, self.kdf)?,
            None => {
                if pepper.is_empty() {
                    kdf::derive_master_key(password.as_bytes(), &self.salt, self.kdf)?
                } else {
                    crate::binding::derive_bound_key(password.as_bytes(), pepper, &self.salt, self.kdf)?
                }
            }
        };
        if !crate::secure::ct_eq(key.as_slice(), self.master_key.as_slice()) {
            return Err(Error::BadPasswordOrTampered);
        }
        Ok(())
    }

    /// 校验所需的公开材料：KDF 参数 + 盐。
    ///
    /// 这两样都在文件头里明文写着，脱离主密钥没有任何攻击价值。
    /// 单独暴露出来是为了让调用方能在**锁外**用它们重新派生 ——
    /// KDF 是全场唯一的慢路径，持锁跑会把界面冻住。
    #[must_use]
    pub fn kdf_material(&self) -> (KdfParams, [u8; 32]) {
        (self.kdf, self.salt)
    }

    /// 与内存里的主密钥做常量时间比对。
    ///
    /// 配合 `kdf_material` + `derive_key_with` 使用：
    /// 锁内取材料 → 放锁 → 后台派生 → 锁内比对（微秒级）。
    #[must_use]
    pub fn matches_master_key(&self, candidate: &SecretBytes) -> bool {
        crate::secure::ct_eq(candidate.as_slice(), self.master_key.as_slice())
    }

    /// 按给定参数与盐派生主密钥（不碰 `Vault` 状态）。
    ///
    /// `pepper` 为空表示不绑定本机。给锁外做密码校验用。
    pub fn derive_key_with(
        password: &str,
        pepper: &[u8],
        salt: &[u8],
        params: KdfParams,
    ) -> Result<SecretBytes> {
        if pepper.is_empty() {
            kdf::derive_master_key(password.as_bytes(), salt, params)
        } else {
            crate::binding::derive_bound_key(password.as_bytes(), pepper, salt, params)
        }
    }

    /// 用新密码把当前内容重新封装成完整文件字节，**不改动自身状态**。
    ///
    /// 给「改密码」用：调用方先拿到字节、安全落盘成功、再回来
    /// `change_password_bound`。顺序反过来的话，落盘失败会留下
    /// 「内存新密码、磁盘旧密码」的不一致状态。
    /// 导出全部条目 + KDF 参数 + vault_id（+ v3 绑定材料）的快照。
    ///
    /// 用途：让调用方**先放锁**再去跑重的加密流程。改密码要跑两轮 Argon2，
    /// 全程持锁会把整个应用冻住。
    #[must_use]
    pub fn export_all(&self) -> VaultSnapshot {
        VaultSnapshot {
            entries: self.entries.values().cloned().collect(),
            kdf: self.kdf,
            vault_id: self.vault_id,
            // 改密码之后仍然是同一个库，绑定材料必须跟着走 ——
            // 否则重新封装出来的文件会丢掉绑定块，v3 库被降级成 v2，
            // 然后用原来的 pepper 规则再也打不开。
            binding: self.binding.clone(),
        }
    }

    pub fn reseal_with_password(&self, new_password: &str, pepper: &[u8]) -> Result<Vec<u8>> {
        let salt = kdf::random_salt();
        let key = if pepper.is_empty() {
            kdf::derive_master_key(new_password.as_bytes(), &salt, self.kdf)?
        } else {
            crate::binding::derive_bound_key(new_password.as_bytes(), pepper, &salt, self.kdf)?
        };

        let header = FileHeader {
            version: if self.binding.is_some() {
                crate::FORMAT_VERSION.max(3)
            } else {
                self.format_version.min(crate::FORMAT_VERSION)
            },
            kdf: self.kdf,
            salt,
            vault_id: self.vault_id,
        }
        .to_bytes();

        let entries: Vec<Entry> = self.entries.values().cloned().collect();
        let body_plain = zeroize::Zeroizing::new(
            serde_json::to_vec(&Body { entries }).map_err(|_| Error::Corrupt("正文序列化失败"))?,
        );
        let body_key = crypto::derive_subkey(&key, KeyPurpose::Payload)?;
        let body_blob = crypto::seal(&body_key, &header, &body_plain)?;

        let items: Vec<IndexItem> = self.index.all_sorted().into_iter().cloned().collect();
        let idx_plain = zeroize::Zeroizing::new(
            serde_json::to_vec(&IndexPayload { items })
                .map_err(|_| Error::Corrupt("索引序列化失败"))?,
        );
        let idx_key = crypto::derive_subkey(&key, KeyPurpose::Index)?;
        let idx_blob = crypto::seal(&idx_key, &header, &idx_plain)?;

        let verify = codec::make_verify_block(&key, &header)?;
        let bind_blob = match &self.binding {
            Some(b) => Some(crate::binding::wrap_binding_secret(
                &b.hardware_fp,
                b.secret.as_slice(),
            )?),
            None => None,
        };
        Ok(codec::assemble(
            &header,
            bind_blob.as_deref(),
            &idx_blob,
            &body_blob,
            &verify,
        ))
    }

    /// 主动锁定：擦除密钥、擦除全部条目明文。之后这个 `Vault` 只剩个空壳。
    ///
    /// 关键是 `entries` 那一步：`Entry` 实现了 `Zeroize`，这里逐个显式擦，
    /// 再 `clear()`。只 `clear()` 是不够的 —— `HashMap` 丢弃元素时会 drop
    /// 每个 `Entry`，但 `Drop` 里的擦除要等元素真正被回收，
    /// 而且分配器可能把缓冲区留给下一个使用者。
    pub fn lock(&mut self) {
        self.master_key.wipe();
        for (_, mut e) in self.entries.drain() {
            e.zeroize();
        }
        self.entries.shrink_to_fit();
        self.index = Index::new();
        self.dirty = false;
    }

    /// 统计信息，给「库概览」页用。
    #[must_use]
    pub fn stats(&self, now: i64) -> VaultStats {
        VaultStats {
            total: self.entries.len(),
            expired: self.entries.values().filter(|e| e.is_expired(now)).count(),
            never_used: self.entries.values().filter(|e| e.use_count == 0).count(),
            tags: self.index.tag_counts().len(),
        }
    }
}

/// 一次解锁过程需要的全部信息，脱离 `Vault` 独立存在。
///
/// 存在的理由只有一个：**让加密/解密的慢动作能在锁外做**。
/// 调用方先 `export_all()` 拿快照，再释放互斥锁，然后慢慢跑 Argon2。
#[derive(Clone)]
pub struct VaultSnapshot {
    /// 全部条目。
    pub entries: Vec<Entry>,
    /// KDF 参数（改密码时保持不变）。
    pub kdf: KdfParams,
    /// 库标识（写回文件头用，不能变）。
    pub vault_id: [u8; 16],
    /// v3 的绑定材料。改密码之后仍然是同一个库，这块必须跟着走。
    pub binding: Option<Binding>,
}

/// 用新密码把快照重新封装成完整文件字节。
///
/// 这是 `Vault::reseal_with_password` 的自由函数版本 ——
/// 不需要持有 `Vault`，因此可以在锁外调用。
pub fn reseal_snapshot(snap: &VaultSnapshot, new_password: &str, pepper: &[u8]) -> Result<Vec<u8>> {
    let salt = kdf::random_salt();
    // pepper 规则必须和「这个库是怎么建的」一致，而不是由调用方随手给一个。
    //
    // 这里曾经只看 `pepper` 空不空，于是应用层传进来的 v2 pepper
    // （`machine::pepper()`，含机器名与卷序列号）被用在 v3 库上：
    // 文件头写成 v3、绑定块也写了，但主密钥是按 v2 规则派生的。
    // 再打开时按 v3 算 pepper —— 直接「密码错误或文件已被篡改」。
    // 表现就是「改了个密码把库改坏了」。
    let key = match &snap.binding {
        // v3：绑定材料就在快照里，外部 pepper 无关
        Some(b) => b.derive_key(new_password, &salt, snap.kdf)?,
        // v2：沿用调用方给的（含机器名与卷序列号的）pepper
        None => {
            if pepper.is_empty() {
                kdf::derive_master_key(new_password.as_bytes(), &salt, snap.kdf)?
            } else {
                crate::binding::derive_bound_key(new_password.as_bytes(), pepper, &salt, snap.kdf)?
            }
        }
    };

    let header = FileHeader {
        version: if snap.binding.is_some() {
            crate::FORMAT_VERSION.max(3)
        } else {
            2
        },
        kdf: snap.kdf,
        salt,
        vault_id: snap.vault_id,
    }
    .to_bytes();

    let entries: Vec<Entry> = snap.entries.clone();
    let body_plain = zeroize::Zeroizing::new(
        serde_json::to_vec(&Body { entries }).map_err(|_| Error::Corrupt("正文序列化失败"))?,
    );
    let body_key = crypto::derive_subkey(&key, KeyPurpose::Payload)?;
    let body_blob = crypto::seal(&body_key, &header, &body_plain)?;

    // 索引从条目现场重建，保证两边一致
    let mut index = Index::with_capacity(snap.entries.len());
    for e in &snap.entries {
        index.upsert(e);
    }
    let items: Vec<IndexItem> = index.all_sorted().into_iter().cloned().collect();
    let idx_plain = zeroize::Zeroizing::new(
        serde_json::to_vec(&IndexPayload { items })
            .map_err(|_| Error::Corrupt("索引序列化失败"))?,
    );
    let idx_key = crypto::derive_subkey(&key, KeyPurpose::Index)?;
    let idx_blob = crypto::seal(&idx_key, &header, &idx_plain)?;

    let verify = codec::make_verify_block(&key, &header)?;
    // 绑定块跟着快照走：改密码不能把 v3 库降级成 v2。
    let bind_blob = match &snap.binding {
        Some(b) => Some(crate::binding::wrap_binding_secret(
            &b.hardware_fp,
            b.secret.as_slice(),
        )?),
        None => None,
    };
    Ok(codec::assemble(
        &header,
        bind_blob.as_deref(),
        &idx_blob,
        &body_blob,
        &verify,
    ))
}

/// 概览统计。
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VaultStats {
    /// 总条目数。
    pub total: usize,
    /// 已过期数量。
    pub expired: usize,
    /// 从未使用过的数量。
    pub never_used: usize,
    /// 标签种类数。
    pub tags: usize,
}

/// 原子写文件。
///
/// 公开出来的原因：改密码要整库重写，那是全流程里最不能掉电崩坏的时刻。
/// 上层如果自己调 `std::fs::write`，就绕过了随机后缀 + create_new 占位 +
/// 落盘同步这一整套措施，一次断电能把整个库写坏 —— 而那时候旧密码已经没用了。
///
/// **边界**：这里保证的是「文件内容」层面的原子性 —— 先 `sync_all` 落盘，
/// 再 rename 替换。断电后你看到的要么是全旧、要么是全新，不会是半截。
///
/// 但不保证「目录项」层面：`sync_all` 只刷文件本身，rename 之后没有对父目录
/// 再 fsync（标准库的 `rename` 在 Windows 上用的是 `MoveFileExW`，不带
/// `MOVEFILE_WRITE_THROUGH`）。理论上断电可能让目录项还停在旧值上，极端情况下
/// 出现「两个名字都不在」。这个窗口比 Linux 小得多，因为 NTFS 的元数据日志
/// 会保证事务性，但我们不宣称绝对。
///
/// 说「要么旧要么新」是准确的，说「断电绝对不丢」就过了 —— 那句话这里不写。
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;

    // 临时文件名带 16 字节随机后缀。
    //
    // 原先用的是固定的 `.{name}.tmp`，两个问题：同机进程能预置同名
    // 符号链接/硬链接把内容导向别处；两次保存并发时会互相覆盖。
    let rand: [u8; 16] = kdf::random_bytes::<16>();
    let mut suffix = String::with_capacity(32);
    for b in rand {
        use std::fmt::Write as _;
        let _ = write!(suffix, "{b:02x}");
    }
    let base = path.file_name().and_then(|s| s.to_str()).unwrap_or("vault");
    let tmp = dir.join(format!(".{base}.{suffix}.tmp"));

    // RAII：任何提前返回（write 失败、sync 失败、panic）都会删掉临时文件。
    struct TmpGuard(PathBuf);
    impl Drop for TmpGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let guard = TmpGuard(tmp.clone());

    {
        // create_new 占住这个名字，不让别人抢先放东西
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    // Windows 上 std::fs::rename 走 MoveFileExW(MOVEFILE_REPLACE_EXISTING)：
    // 目标已存在会被替换，但**目标正被占用时会直接失败、不重试**。
    // （这里不是 ReplaceFile，别按 ReplaceFile 的事务语义去理解。）
    std::fs::rename(&tmp, path)?;
    // rename 成功后 tmp 已不存在，guard 的 remove 是幂等的空操作
    drop(guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    // 测试里 unwrap 是正常写法：出错就该 panic，不需要优雅降级。
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::entry::EntryKind;

    fn now() -> i64 {
        1_700_000_000
    }

    fn entry(id: &str, name: &str) -> Entry {
        Entry {
            id: id.into(),
            kind: EntryKind::ApiKey,
            name: name.into(),
            username: "user".into(),
            secret: "sk-very-secret".into(),
            url: "https://api.example.com".into(),
            fields: vec![],
            tags: vec!["test".into()],
            notes: String::new(),
            created_at: now(),
            updated_at: now(),
            expires_at: 0,
            use_count: 0,
            last_used_at: 0,
        }
    }

    #[test]
    fn create_insert_seal_open_roundtrip() {
        let mut v = Vault::create("hunter2", KdfParams::light()).unwrap();
        v.insert(entry("a", "OpenAI")).unwrap();
        v.insert(entry("b", "GitHub")).unwrap();
        let bytes = v.seal().unwrap();

        let v2 = Vault::open_from_bytes(&bytes, "hunter2").unwrap();
        assert_eq!(v2.len(), 2);
        assert_eq!(v2.get("a").unwrap().name, "OpenAI");
        assert_eq!(v2.get("a").unwrap().secret, "sk-very-secret");
        assert!(!v2.is_dirty());
    }

    #[test]
    fn wrong_password_rejected() {
        let mut v = Vault::create("right", KdfParams::light()).unwrap();
        v.insert(entry("a", "X")).unwrap();
        let bytes = v.seal().unwrap();
        assert!(matches!(
            Vault::open_from_bytes(&bytes, "wrong"),
            Err(Error::BadPasswordOrTampered)
        ));
    }

    #[test]
    fn corrupted_file_rejected() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "X")).unwrap();
        let mut bytes = v.seal().unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0xFF;
        assert!(Vault::open_from_bytes(&bytes, "pw").is_err());
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "X")).unwrap();
        assert!(matches!(
            v.insert(entry("a", "Y")),
            Err(Error::DuplicateEntry(_))
        ));
    }

    #[test]
    fn update_and_remove_keep_index_in_sync() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "Alpha")).unwrap();
        let mut e = v.get("a").unwrap().clone();
        e.name = "Alpha Renamed".into();
        v.update(e).unwrap();
        assert_eq!(v.index().get("a").unwrap().name, "Alpha Renamed");

        v.remove("a").unwrap();
        assert!(v.index().get("a").is_none());
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn record_use_bumps_heat() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "Alpha")).unwrap();
        v.record_use("a", 1234).unwrap();
        let idx = v.index().get("a").unwrap();
        assert_eq!(idx.use_count, 1);
        assert_eq!(idx.last_used_at, 1234);
    }

    #[test]
    fn reveal_returns_secret() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "Alpha")).unwrap();
        assert_eq!(&*v.reveal_secret("a").unwrap(), "sk-very-secret");
    }

    #[test]
    fn lock_wipes_everything() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "Alpha")).unwrap();
        v.lock();
        assert_eq!(v.len(), 0);
        assert!(v.get("a").is_none());
    }

    #[test]
    fn change_password_then_old_fails() {
        let mut v = Vault::create("old", KdfParams::light()).unwrap();
        v.insert(entry("a", "Alpha")).unwrap();
        v.change_password("new", Some(KdfParams::light())).unwrap();
        let bytes = v.seal().unwrap();

        assert!(Vault::open_from_bytes(&bytes, "old").is_err());
        let v2 = Vault::open_from_bytes(&bytes, "new").unwrap();
        assert_eq!(v2.len(), 1);
    }

    #[test]
    fn save_and_open_from_disk() {
        let dir = std::env::temp_dir().join("xzvlt-test-save");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("v.xzvlt");

        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "Alpha")).unwrap();
        v.save_as(&path).unwrap();
        assert!(!v.is_dirty());

        let v2 = Vault::open(&path, "pw").unwrap();
        assert_eq!(v2.len(), 1);

        // 无临时文件残留
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stats() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "A")).unwrap();
        let mut e = entry("b", "B");
        e.expires_at = now() - 10;
        v.insert(e).unwrap();
        let s = v.stats(now());
        assert_eq!(s.total, 2);
        assert_eq!(s.expired, 1);
        assert_eq!(s.never_used, 2);
        assert_eq!(s.tags, 1);
    }
}

#[cfg(test)]
mod binding_tests {
    // 测试里 unwrap 是正常写法：出错就该 panic，不需要优雅降级。
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// v3：绑定材料跟着文件走。
    ///
    /// 守的是「重装系统 / `%APPDATA%` 被清空之后还能把库打开」这条承诺：
    /// 硬件没变，就能从文件里的绑定块解出本机随机串；
    /// 换了硬件，就解不开。这是 v3 存在的全部理由。
    #[test]
    fn v3_binding_travels_with_the_file() {
        use crate::kdf::KdfParams;

        let secret = [3u8; crate::binding::BINDING_SECRET_LEN];
        let fp_a: Vec<u8> = b"hardware-fingerprint-A".to_vec();
        let pw = "unit-test-password";

        let mut v =
            Vault::create_bound_v3(pw, KdfParams::light(), &secret, fp_a.clone()).unwrap();
        v.insert(crate::entry::Entry {
            id: "x".into(),
            kind: crate::entry::EntryKind::Login,
            name: "测试".into(),
            username: "u".into(),
            secret: "s".into(),
            url: String::new(),
            fields: vec![],
            tags: vec![],
            notes: String::new(),
            created_at: 1,
            updated_at: 1,
            expires_at: 0,
            use_count: 0,
            last_used_at: 0,
        })
        .unwrap();
        let bytes = v.seal().unwrap();

        // 文件头是 v3，且真的带了绑定块
        let header = FileHeader::parse(&bytes).unwrap();
        assert_eq!(header.version, 3);
        let parts = codec::split_sealed(&bytes).unwrap();
        let blob = parts.bind.expect("v3 文件必须有绑定块");
        assert_eq!(blob.len(), crate::binding::BIND_BLOCK_LEN);

        // 同一台硬件：能从文件里解出绑定材料，并据此打开库
        let recovered = crate::binding::unwrap_binding_secret(&fp_a, blob).unwrap();
        assert_eq!(recovered.as_slice(), &secret);
        let key = crate::binding::derive_bound_key_v3(
            pw.as_bytes(),
            recovered.as_slice(),
            &header.salt,
            header.kdf,
        )
        .unwrap();
        let reopened = Vault::open_bound_with_key(&bytes, key).unwrap();
        assert_eq!(reopened.len(), 1);

        // 换了硬件：绑定块解不开 —— 这正是「设备绑定」要的效果
        assert!(
            crate::binding::unwrap_binding_secret(b"hardware-fingerprint-B", blob).is_err(),
            "换硬件必须解不开绑定块"
        );
    }

    /// 打开 v3 库但没补上绑定材料时，不允许写出（那会把库降级成 v2）。
    #[test]
    fn sealing_v3_without_binding_is_refused() {
        use crate::kdf::KdfParams;

        let secret = [4u8; crate::binding::BINDING_SECRET_LEN];
        let mut v = Vault::create_bound_v3(
            "pw",
            KdfParams::light(),
            &secret,
            b"fp".to_vec(),
        )
        .unwrap();
        let bytes = v.seal().unwrap();

        // 模拟「打开后忘了 adopt_binding」
        let header = FileHeader::parse(&bytes).unwrap();
        let recovered = crate::binding::unwrap_binding_secret(b"fp", codec::split_sealed(&bytes).unwrap().bind.unwrap()).unwrap();
        let k = crate::binding::derive_bound_key_v3(
            b"pw",
            recovered.as_slice(),
            &header.salt,
            header.kdf,
        )
        .unwrap();
        let mut opened = Vault::open_bound_with_key(&bytes, k).unwrap();
        // 没有 adopt_binding → seal 必须拒绝，而不是写出一个缺绑定块的 v3 文件
        assert!(opened.seal().is_err(), "缺绑定材料的 v3 库不该被写回");
        // 补上之后就能写
        opened.adopt_binding(recovered, b"fp".to_vec());
        assert!(opened.seal().is_ok());
    }

    /// 改密码之后，v3 库必须还能用**新密码**打开。
    ///
    /// 这条守的是一个真实踩过的坑：`reseal_snapshot` 只用「外部给的 pepper」
    /// 派生主密钥，而应用层那里传的是 v2 规则的 pepper
    /// （`machine::pepper()`，含机器名与卷序列号）。于是改完密码，
    /// 文件头写着 v3、带着绑定块，主密钥却是按 v2 规则算的 ——
    /// 再打开时按 v3 算 pepper，直接「密码错误或文件已被篡改」。
    #[test]
    fn v3_rekey_then_reopen_with_new_password() {
        use crate::kdf::KdfParams;

        let secret = [5u8; crate::binding::BINDING_SECRET_LEN];
        let fp: Vec<u8> = b"hardware-A".to_vec();

        let mut v = Vault::create_bound_v3("old-password", KdfParams::light(), &secret, fp.clone())
            .unwrap();
        v.insert(crate::entry::Entry {
            id: "x".into(),
            kind: crate::entry::EntryKind::Login,
            name: "测试".into(),
            username: "u".into(),
            secret: "s".into(),
            url: String::new(),
            fields: vec![],
            tags: vec![],
            notes: String::new(),
            created_at: 1,
            updated_at: 1,
            expires_at: 0,
            use_count: 0,
            last_used_at: 0,
        })
        .unwrap();
        let snap = v.export_all();

        // 模拟 commands::vault_rekey 的调用：它传的是 v2 规则的 pepper。
        let v2_pepper = crate::binding::make_pepper(&[9u8; 32], "PC-FAKE");
        let resealed = reseal_snapshot(&snap, "new-password", &v2_pepper).unwrap();

        // 用新密码 + v3 规则重开
        let header = FileHeader::parse(&resealed).unwrap();
        assert_eq!(header.version, 3);
        let parts = codec::split_sealed(&resealed).unwrap();
        let recovered = crate::binding::unwrap_binding_secret(&fp, parts.bind.unwrap()).unwrap();
        let key = crate::binding::derive_bound_key_v3(
            b"new-password",
            recovered.as_slice(),
            &header.salt,
            header.kdf,
        )
        .unwrap();
        let reopened = Vault::open_bound_with_key(&resealed, key);
        assert!(
            reopened.is_ok(),
            "改密码之后必须能用新密码打开，否则就是「改了个密码把库改坏了」"
        );
        assert_eq!(reopened.unwrap().len(), 1);
    }

    /// `change_password_bound` 之后，内存里的主密钥也要符合 v3 规则。
    #[test]
    fn v3_change_password_keeps_master_key_consistent() {
        use crate::kdf::KdfParams;

        let secret = [6u8; crate::binding::BINDING_SECRET_LEN];
        let fp: Vec<u8> = b"hardware-A".to_vec();
        let mut v =
            Vault::create_bound_v3("old", KdfParams::light(), &secret, fp.clone()).unwrap();

        // 应用层传 v2 pepper；v3 库应该忽略它，按 binding 自己算
        let v2_pepper = crate::binding::make_pepper(&[9u8; 32], "PC-FAKE");
        v.change_password_bound("new", None, &v2_pepper).unwrap();

        // 用 v3 规则独立派生一遍，和内存里的主密钥比
        let (params, salt) = v.kdf_material();
        let expected =
            crate::binding::derive_bound_key_v3(b"new", &secret, &salt, params).unwrap();
        assert!(
            v.matches_master_key(&expected),
            "改密码后内存主密钥必须按 v3 规则派生"
        );

        // 用新密码自校验也应该过
        assert!(v.verify_password_bound("new", &v2_pepper).is_ok());
    }

    /// `verify_password` 必须真的拒绝错密码。
    ///
    /// 这条守的是「导出 / 导入 / 改密码 / 开免密码模式」那几道要重输密码的门。
    /// 曾经的实现是「用派生出的 key 生成校验块，再用同一把 key 校验它」——
    /// 那是自证：任何密码都会通过，门等于没有。
    #[test]
    fn verify_password_rejects_wrong_password() {
        use crate::kdf::KdfParams;

        // 无绑定（pepper 为空）的库
        let v = Vault::create("right-password", KdfParams::light()).unwrap();
        assert!(v.verify_password("right-password").is_ok());
        assert!(
            v.verify_password("wrong-password").is_err(),
            "错密码必须被拒绝"
        );

        // 绑定本机的库
        let pepper = crate::binding::make_pepper(&[7u8; 32], "PC1-ABCD1234");
        let b = Vault::create_bound("right-password", KdfParams::light(), &pepper).unwrap();
        assert!(b.verify_password_bound("right-password", &pepper).is_ok());
        assert!(
            b.verify_password_bound("wrong-password", &pepper).is_err(),
            "绑定库也必须拒绝错密码"
        );
        // 密码对但 pepper 不对 → 也是错的（派生不出同一把钥匙）
        assert!(
            b.verify_password_bound("right-password", b"other-pepper").is_err(),
            "pepper 不匹配同样不能通过"
        );
    }

    /// pepper 不同 → 派生出的主密钥不同 → 校验块过不去。
    #[test]
    fn wrong_pepper_cannot_open() {
        use crate::kdf::KdfParams;
        let pw = "unit-test-password";
        let pepper_a = crate::binding::make_pepper(b"secret-on-this-machine", "PC1-ABCD1234");
        let pepper_b = crate::binding::make_pepper(b"secret-on-this-machine", "PC2-FFFF0000");

        let mut v = Vault::create_bound(pw, KdfParams::light(), &pepper_a).unwrap();
        let ts = 1_700_000_000i64;
        v.insert(crate::entry::Entry {
            id: "x".into(),
            kind: crate::entry::EntryKind::Login,
            name: "测试".into(),
            username: "u".into(),
            secret: "s".into(),
            url: String::new(),
            fields: vec![],
            tags: vec![],
            notes: String::new(),
            created_at: ts,
            updated_at: ts,
            expires_at: 0,
            use_count: 0,
            last_used_at: 0,
        })
        .unwrap();
        let bytes = v.seal().unwrap();

        // 同一台机器：能开
        assert!(
            Vault::open_bound(&bytes, pw, &pepper_a).is_ok(),
            "本机应该能打开"
        );
        // 换机器：密码对也打不开
        assert!(
            Vault::open_bound(&bytes, pw, &pepper_b).is_err(),
            "换了机器标识必须打不开"
        );
        // 没有 pepper：同样打不开
        assert!(
            Vault::open_bound(&bytes, pw, &[]).is_err(),
            "缺 pepper 必须打不开"
        );
    }

    /// 错的随机串也不行。
    #[test]
    fn wrong_secret_cannot_open() {
        use crate::kdf::KdfParams;
        let pw = "unit-test-password";
        let real = crate::binding::make_pepper(&[7u8; 32], "PC1-ABCD1234");
        let fake = crate::binding::make_pepper(&[9u8; 32], "PC1-ABCD1234");

        let mut v = Vault::create_bound(pw, KdfParams::light(), &real).unwrap();
        v.insert(crate::entry::Entry {
            id: "y".into(),
            kind: crate::entry::EntryKind::Login,
            name: "n".into(),
            username: String::new(),
            secret: "s".into(),
            url: String::new(),
            fields: vec![],
            tags: vec![],
            notes: String::new(),
            created_at: 1,
            updated_at: 1,
            expires_at: 0,
            use_count: 0,
            last_used_at: 0,
        })
        .unwrap();
        let bytes = v.seal().unwrap();
        assert!(Vault::open_bound(&bytes, pw, &real).is_ok());
        assert!(
            Vault::open_bound(&bytes, pw, &fake).is_err(),
            "换了随机串必须打不开"
        );
    }
}

#[cfg(test)]
mod vault_identity_tests {
    // 测试里 unwrap 是正常写法：出错就该 panic，不需要优雅降级。
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::kdf::KdfParams;

    /// 每个库的 vault_id 不同，且能从头里读回来。
    #[test]
    fn vault_id_is_stable_and_unique() {
        let mut a = Vault::create("TestPass1234", KdfParams::light()).unwrap();
        let b = Vault::create("TestPass1234", KdfParams::light()).unwrap();
        assert_ne!(a.vault_id(), b.vault_id(), "两个库的标识必须不同");

        let bytes = a.seal().unwrap();
        let reopened = Vault::open_from_bytes(&bytes, "TestPass1234").unwrap();
        assert_eq!(reopened.vault_id(), a.vault_id(), "重开后标识必须一致");
    }

    /// 头部被改（换了 vault_id）会导致 AAD 不匹配，解不开。
    ///
    /// 这是「认库」机制的密码学兜底：光比对 id 还不够，
    /// 改 id 会直接破坏认证。
    #[test]
    fn tampered_vault_id_breaks_open() {
        let mut v = Vault::create("TestPass1234", KdfParams::light()).unwrap();
        let mut bytes = v.seal().unwrap();
        // vault_id 在头部的 [55..71]
        bytes[55] ^= 0xFF;
        assert!(
            Vault::open_from_bytes(&bytes, "TestPass1234").is_err(),
            "改了库标识必须打不开"
        );
    }
}
