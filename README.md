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
| **多语言** | 简体中文 / English / 日本語，自动跟随系统 |

---

## 快捷操作（设计目标）

| 操作 | 说明 |
|---|---|
| `Ctrl+K` | 全局搜索（模糊匹配：名称 / 用户名 / 网址 / 标签 / 子序列） |
| `Ctrl+Shift+1…9` | 直接复制热度榜第 N 条的密钥 |
| `Ctrl+C` | 复制选中条目（默认复制密钥，`Ctrl+Shift+C` 复制用户名） |
| `Ctrl+L` | 立即锁库（擦除内存中的密钥与明文） |
| 自动锁定 | 闲置 N 分钟后自动锁，可在设置里改 |
| 剪贴板自清 | 复制的密钥 N 秒后自动从剪贴板清除 |

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
├── docs/
│   ├── FORMAT.md       二进制格式规范（规范来源）
│   └── PERFORMANCE.md  性能报告与优化过程（含被回退的尝试）
└── locales/          多语言文案
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
