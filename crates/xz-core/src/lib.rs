//! 璇泽密钥库 · 核心库
//!
//! 设计目标（按优先级）：
//! 1. **极致性能** —— 打开 1 万条凭据的 vault 目标 < 50ms（不含 KDF），
//!    列表查询走内存索引，O(1) 到 O(log n)，不做全量反序列化。
//! 2. **安全默认** —— Argon2id 派生、AES-256-GCM 认证加密、密钥材料全量 zeroize、
//!    vault 文件内所有明文字段一律不出内存。
//! 3. **可审计** —— 格式完全自描述、字段显式、版本化，见 `docs/FORMAT.md`。
//! 4. **开源友好** —— 无 GPL 依赖，全部 permissive 许可。

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
pub const FORMAT_VERSION: u16 = 2;

/// 产品标识，写进 vault 文件头，便于将来多产品共用工具链时区分。
pub const MAGIC: &[u8; 8] = b"XZVLT\x00\x02\x00";
