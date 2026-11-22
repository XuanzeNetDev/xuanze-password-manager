# 璇泽密钥库 · Xuanze Password Manager

[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/tauri-v2-24C8DB)](https://tauri.app/)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)]()
[![Tests](https://img.shields.io/badge/tests-54%20passing-brightgreen)]()

**A fast, local-first password manager and secrets vault for Windows.**
Rust core + Tauri v2 shell. Argon2id + AES-256-GCM. No cloud, no account,
no telemetry — everything stays on your machine and is bound to it.

Stores API keys, access tokens, database credentials, SSH keys, and website
passwords in one encrypted file.

> 极致性能的本地密钥 / 凭据管理器。Rust 核心 + Tauri v2 桌面壳，Windows 优先。
>
> **存的是 API 密钥、访问令牌、数据库口令、SSH 私钥，以及顺手一起管的网站密码。**

---

## 界面

下面这些图都是从真实软件里截的，不是画的原型图。

### 锁屏

打开软件第一眼看到的就是这个。一个输入框，输密码，进库。

中间那行小字平时是空的，有情况才冒出来——比如「密码不对」，
或者你出门忘了锁，「闲置超时，已自动锁定」也会写在这儿。
底下那句是提醒：密码不上传，忘了就真找不回来了，我们也没有后门帮你重置。

背景那片青色和紫色的光斑会慢慢漂，不快，就是让静止的画面别那么死。

![锁屏](docs/screenshots/08-lock.png)

### 主界面

左边一列是专辑，右边是表格。所有条目摊开在一张表里，名称、类型、账号、
密钥、网址、专辑，横向一排，眼睛从上往下扫一遍就够了。

这里跟多数密码管理器不一样的地方：它们通常给你「列表 → 点进详情 → 编辑」三步。
我们直接省掉后两步——数据本来就是表格形状的，摊开看最快。
想改哪一格，点那一格就改。

左边专辑是从标签自动长出来的。你给条目打上 `prod`，`prod` 就出现在左边，
不用提前建目录，也不用纠结它该放哪个文件夹。

![主界面](docs/screenshots/02-main.png)

### 查看密钥

密码平时是 `••••••`。点眼睛，那一格当场变成明文。

注意只有这一格变了，别的行一动没动。有些软件点「显示」会整个列表重排一遍，
眼睛会跟着跳一下，很难受。

![显示密钥](docs/screenshots/03-reveal.png)

### 按专辑筛选

点左边的 `prod`，右边就只剩打了 prod 标签的 4 条。

上边那条横线写着「prod　4 条」，告诉你现在在哪、还剩多少。
再点「全部」就回来了。

![专辑筛选](docs/screenshots/04-album.png)

### 搜索

输了「Key」，出来两条：Docker Registry 和阿里云 AccessKey。

搜索不看大小写，也不要求你连着打。输 `ol` 就能找到 `OpenAI`，
因为 `O` 和 `L` 在名字里按顺序出现。名称、账号、网址、标签、备注，全都查。

这儿的想法很简单：你记得的往往不是全名，是「那个带 openai 的」，
所以宁可多搜出来几条，也别让你一个字一个字打全。

![搜索结果](docs/screenshots/07-search.png)

### 新建条目

名称、类型、账号、密钥、网址、专辑，一行行填下来。

类型选一下——登录、密钥、凭据、笔记、银行卡，不同东西存的地方不一样。

专辑那栏可以直接新建，输完按回车就有。下面还能加自定义字段，
放什么都行，比如「二步验证方式」「bucket 名」「服务器端口」。
标成敏感的字段会跟密钥一样加密。

![新建条目](docs/screenshots/09-new-entry.png)

### 设置

就四项，没别的：主题、主密码、退出登录、关于。

改主密码要输原密码，改完之后旧密码立刻失效，整个库用新密码重新封一遍。
界面里那句「数据用新密码重新封装」不是客套话，是真的全量重加密。

![设置](docs/screenshots/05-settings.png)

### 浅色主题

深色是纯黑，浅色是纯白，两边都不透背景。

为什么不透？因为这是看数据的地方。底下要是流光溢彩，读起来会累。
光斑只留在左边专辑栏和锁屏，那边不需要盯字。

![浅色主题](docs/screenshots/06-light.png)

### 第一次用

第一次打开没库，就让你设个密码。

只输一次不够，要输两遍，两遍一样才放行。密码至少 8 位。

![注册](docs/screenshots/01-register.png)

---
## 为什么做这个

日常要记的东西早就不是「网站密码」了：

- 十几个云厂商的 AccessKey / SecretKey
- 一堆服务的 API token（OpenAI、GitHub、Stripe、各种 SaaS）
- 数据库连接串、SSH 私钥、证书私钥
- 还有那些「三个月用一次、用的时候想不起来」的旧账号

浏览器自带的密码管理器管不了这些；笔记软件存密钥又等于明文。所以就有了这个库。

**核心取舍：一切围绕「便捷」和「快」。** 打开要快、搜到要快、复制要快、锁上要快。

---

## 特点

| | |
|---|---|
| **快** | 1 万条条目，搜索 < 1 ms，取密钥 44 ns，打开 56 ms（含 64 MiB Argon2） |
| **小** | Tauri 壳，安装包 MB 级，不是 Electron 的 100 MB |
| **安全默认** | Argon2id + AES-256-GCM + HKDF 子密钥隔离，密钥材料全量 zeroize |
| **格式公开** | 完整二进制格式规范（[docs/FORMAT.md](docs/FORMAT.md)），可自行实现读取器 |
| **本地** | 不联网、不注册、不上传。vault 就是一个文件，扔 U 盘就能带走 |

---

## 快捷操作

| 操作 | 说明 |
|---|---|
| `Ctrl+K` | 聚焦搜索框 |
| `Ctrl+N` | 新建条目 |
| `Enter` | 复制选中条目的密钥 |
| `↑` `↓` | 在列表里上下移动选中 |
| `Ctrl+Shift+1…9` | 直接复制热度榜第 N 条的密钥 |
| `Ctrl+L` | 立即锁库（擦除内存中的密钥与明文） |
| `Esc` | 关闭弹窗 |

输入框内不触发以上快捷键。

另外两项自动行为：闲置超时自动锁库；复制的密钥在剪贴板里停留固定时长后自动清除。

---

## 项目结构

```
.
├── crates/
│   ├── xz-core/      核心库：格式、加密、KDF、索引、搜索、内存擦除
│   ├── xzc/          命令行工具：不装 GUI 也能用
│   └── xz-bench/     性能基准
├── src-tauri/        桌面壳（Tauri v2 命令层 + 自动锁定 + 剪贴板）
├── src/              前端界面（原生 TS，无框架）
└── docs/
    ├── FORMAT.md       二进制格式规范（规范来源）
    ├── PERFORMANCE.md  性能报告与优化过程（含被回退的尝试）
    └── screenshots/    界面截图
```

## 构建

```bash
# 只跑核心库测试（不需要 Tauri 环境）
cargo test -p xz-core

# 性能基准
cargo run --release -p xz-bench

# 命令行
cargo run --release -p xzc -- --help

# 桌面应用（需要 WebView2 与 Tauri CLI）
cargo tauri dev
cargo tauri build
```

## 命令行速览

```bash
xzc init   my.xzvlt --password -
xzc add    my.xzvlt --password - --name "OpenAI 生产 Key" --kind api-key \
                          --secret sk-xxxx --tag api --tag prod
xzc find   my.xzvlt --password - openai
xzc show   my.xzvlt --password - <id> --reveal
xzc export my.xzvlt --password - --out backup.csv
```

`--password -` 表示从环境变量 `XZ_PASSWORD` 读取，避免密码进 shell 历史。

---

## 安全模型（说清楚边界）

**防的：**

- 磁盘上被拷走 → 没有主密码打不开（Argon2id 64 MiB + AES-256-GCM）
- 文件被篡改 → 头参与 AAD，任一位改动都会认证失败
- 密码泄漏到日志 → 所有密钥材料走 `SecretBytes`，`Debug` 只打印长度
- 内存残留 → `zeroize`，锁库时主动擦除

**不防的：**

- 主密码本身被录屏 / 键盘记录
- 已提权的本地恶意软件读进程内存
- 用户把导出的 CSV 明文留在桌面

这类工具的上限就在这，写进 README 比藏在文档里诚实。

---

## 状态

v0.1 —— 格式与核心库已稳定（50 项单测全绿）；CLI 端到端验证通过；
桌面壳可运行、可建库、可存条目，界面三栏布局与三语切换均已可用。

开发过程中实测发现并已修复的三个界面问题，记在这里免得别人再踩：

1. **WebView2 在高 DPI 下把窗口尺寸当成物理视口**，150% 缩放时页面只填满窗口的 2/3。
   修法见 `src-tauri/src/lib.rs` 的 `setup`。
2. **模态框底部的保存按钮会被顶出可视区**，因为 `.modal` 自己滚又限高。
   改成头/脚固定、只有主体滚（`src/style.css`）。
3. **新建库后没有立即落盘**，用户关窗口就丢数据。现在建库成功立刻弹保存对话框。

## 构建注意

`cargo build` 直接编会在二进制里留下 dev URL（`tauri-build` 只要看到 `tauri.conf.json`
有 `devUrl` 就设 `cfg(dev)`，与构建 profile 无关）。正式构建请走 Tauri CLI 并覆盖配置：

```bash
cargo tauri build --config '{"build":{"frontendDist":"../dist","devUrl":null}}'
```

## 许可

**PolyForm Noncommercial 1.0.0**。见 [LICENSE](LICENSE)。

简单说：源代码开放，你可以自由查看、修改、自己使用，用于个人学习、研究、
非营利组织都没问题；**但不得用于商业用途**，也不能把修改后的版本当商业产品
分发或销售。

为什么要开源：密码管理器的安全性不该建立在「相信作者」之上。算法、密钥派生、
文件格式全部可查、可审、可复现——这样安全性才是能被验证的，而不是被宣称的。
