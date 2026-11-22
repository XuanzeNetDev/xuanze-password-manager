//! 璇泽密钥库 · 核心库
//!
//! 设计目标（按优先级）：
//! 1. **极致性能** —— 打开 1 万条凭据的 vault 目标 < 50ms（不含 KDF），
//!    实测 39ms。列表排序 O(n log n)、按 id 取条目 O(1)；**搜索是全量扫描**
//!    （带流式 Top-K 与字节级预筛），不是倒排索引，取舍见 `docs/PERFORMANCE.md` §6。
//! 2. **安全默认** —— Argon2id 派生、AES-256-GCM 认证加密、密钥材料全量 zeroize；
//!    明文只存在于内存，落盘一律是密文。
//! 3. **可审计** —— 格式完全自描述、字段显式、版本化，见 `docs/FORMAT.md`。
//! 4. **依赖干净** —— 依赖树里没有 GPL 系许可，全部是 MIT / Apache-2.0 / BSD 一类
//!    宽松许可。**注意：本项目自身不是宽松许可**，用的是 PolyForm Noncommercial
//!    1.0.0（源码可读可用，不得商业使用），见仓库根目录的 LICENSE。

#![deny(unsafe_code)]
// 生产代码里禁止 unwrap / expect —— 一个密码库不该因为一个 None 就 panic，
// panic 会把栈上的密钥材料留在内存里，比返回错误难清理得多。
//
// 用 `deny` 而不是 `forbid`，因为 `forbid` 连子模块的 `allow` 都挡，
// 而测试代码里 unwrap 是正常写法，硬要绕开反而写出更难读的东西。
// 测试模块各自写了 `#![allow(clippy::unwrap_used)]`，生产代码一处都没有。
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod binding;
pub mod codec;
pub mod crypto;
pub mod entry;
pub mod error;
pub mod index;
pub mod kdf;
pub mod search;
pub mod secure;
pub mod vault;

#[cfg(test)]
mod fuzz_tests;

pub use error::{Error, Result};
pub use vault::Vault;

/// vault 格式版本（写入时使用的最新版本）。
///
/// ## 版本 3 改了什么
///
/// 文件头之后多了一个**绑定块**：本机随机串用硬件指纹加密封在文件里。
/// 于是「重装系统 / `%APPDATA%` 被清空」不再等于数据报废 —— 硬件没变就能靠
/// 文件里那份把库打开；换主板或换系统盘则依然打不开。
///
/// 同时 pepper 的构造去掉了计算机名与卷序列号（两者都会因为改名、格式化而变），
/// 见 `binding::make_pepper_v3`。
///
/// 版本 2 的文件照常能读（按老规则解 pepper），写回时也保持版本 2，
/// 不会被偷偷升级。
pub const FORMAT_VERSION: u16 = 3;

/// 产品标识，写进 vault 文件头，便于将来多产品共用工具链时区分。
pub const MAGIC: &[u8; 8] = b"XZVLT\x00\x02\x00";
