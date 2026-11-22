//! KDF：主密码 → 主密钥。
//!
//! 选型：**Argon2id**（RFC 9106 推荐），内存硬 + 时间硬，抗 GPU/ASIC。
//!
//! 参数与性能的取舍写在 `docs/FORMAT.md#kdf` 里。核心结论：
//! Argon2id 是打开 vault 时**唯一**的慢路径，其它一切必须快到无感。
//! 因此我们把它单独隔离在这一层，UI 层可以放到后台线程做进度条，
//! 并且允许用户按自己的机器性能调档（牺牲安全换手感，显式选择）。

use crate::error::{Error, Result};
use crate::secure::SecretBytes;
use serde::{Deserialize, Serialize};

/// Argon2 参数档位。
///
/// 数字是「内存 KiB / 迭代次数 / 并行度」。默认 [`KdfParams::paranoid`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, zeroize::Zeroize)]
pub struct KdfParams {
    /// 内存开销，单位 KiB。RFC 9106 第二推荐值 64 MiB。
    pub memory_kib: u32,
    /// 迭代次数。
    pub iterations: u32,
    /// 并行度（lanes）。不启用 `parallel-kdf` feature 时仅影响 KDF 结构，不加速。
    pub parallelism: u32,
}

impl Default for KdfParams {
    /// 与产品默认一致：`paranoid`（256 MiB × 4 轮）。
    ///
    /// 这里曾经返回 `balanced`，而命令层的 `kdf_from(None)` 返回 `paranoid` ——
    /// 两个「默认」不一样。目前没有代码依赖 `Default`，所以行为看不出来，
    /// 但只要有谁给某个字段加上 `#[serde(default)]` 就会悄悄降一档。
    /// 宁可只有一种默认。
    fn default() -> Self {
        Self::paranoid()
    }
}

impl KdfParams {
    /// 最高档：1 GiB，3 次，4 lanes。约 2 秒。
    ///
    /// 内存是抗爆破成本的主体（GPU 上要同时持有 1 GiB），轮数只是
    /// 在内存成本上再乘一个系数。1 GiB × 16 轮实测 7.3 秒，而
    /// 1 GiB × 3 轮约 2 秒 —— 安全边际掉得很少，体验差好几倍。
    /// 参数本身也不该超过 RFC 9106 推荐配置的合理倍数。
    #[must_use]
    pub const fn maximum() -> Self {
        Self {
            memory_kib: 1_048_576,
            iterations: 3,
            parallelism: 4,
        }
    }

    /// 移动端 / 老机器可用：19 MiB，2 次。仍高于 OWASP 最低线。
    #[must_use]
    pub const fn light() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }
    }

    /// 64 MiB，3 次，4 lanes。OWASP 2024 推荐配置。
    #[must_use]
    pub const fn balanced() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 4,
        }
    }

    /// 高安全档：256 MiB，4 次。打开会明显变慢，适合低频高价值 vault。
    #[must_use]
    pub const fn paranoid() -> Self {
        Self {
            memory_kib: 262_144,
            iterations: 4,
            parallelism: 4,
        }
    }
    /// 合理性检查：防止恶意 vault 文件塞一个 4 GiB / 9999 轮的参数把我们打死。
    pub fn validate(&self) -> Result<()> {
        const MIN_MEM: u32 = 8 * 1024; // 8 MiB
        const MAX_MEM: u32 = 1024 * 1024; // 1 GiB
        const MIN_ITER: u32 = 1;
        const MAX_ITER: u32 = 32;
        const MAX_LANES: u32 = 16;

        if self.memory_kib < MIN_MEM {
            return Err(Error::UnacceptableKdf {
                reason: "内存开销低于 8 MiB，安全性不足",
            });
        }
        if self.memory_kib > MAX_MEM {
            return Err(Error::UnacceptableKdf {
                reason: "内存开销超过 1 GiB，拒绝打开（可能是恶意参数）",
            });
        }
        if self.iterations < MIN_ITER || self.iterations > MAX_ITER {
            return Err(Error::UnacceptableKdf {
                reason: "迭代次数超出 1..=32",
            });
        }
        if self.parallelism == 0 || self.parallelism > MAX_LANES {
            return Err(Error::UnacceptableKdf {
                reason: "并行度超出 1..=16",
            });
        }
        Ok(())
    }
}

/// 主密钥长度（AES-256 需要 32 字节）。
pub const MASTER_KEY_LEN: usize = 32;

/// 由主密码和盐派生 32 字节主密钥。
///
/// # 错误
/// 参数不合法或 Argon2 内部失败时返回错误。**不会**把密码写进错误信息。
pub fn derive_master_key(password: &[u8], salt: &[u8], params: KdfParams) -> Result<SecretBytes> {
    use argon2::{Algorithm, Argon2, Params, Version};

    params.validate()?;

    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(MASTER_KEY_LEN),
    )
    .map_err(|_| Error::UnacceptableKdf {
        reason: "Argon2 参数组合非法",
    })?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);

    let mut out = SecretBytes::zeroed(MASTER_KEY_LEN);

    argon
        .hash_password_into(password, salt, out.as_mut_slice())
        .map_err(|_| Error::UnacceptableKdf {
            reason: "Argon2 派生失败",
        })?;

    Ok(out)
}

/// 生成 32 字节随机盐。
#[must_use]
pub fn random_salt() -> [u8; 32] {
    let mut buf = [0u8; 32];
    // getrandom 在 Windows 上走 BCryptGenRandom，失败概率极低；真失败就 abort，
    // 因为用可预测的盐比崩溃更糟。
    if getrandom::getrandom(&mut buf).is_err() {
        std::process::abort();
    }
    buf
}

/// 生成 `N` 字节随机数（nonce、id 等）。
#[must_use]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    if getrandom::getrandom(&mut buf).is_err() {
        std::process::abort();
    }
    buf
}

#[cfg(test)]
mod tests {
    // 测试里 unwrap 是正常写法：出错就该 panic，不需要优雅降级。
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let salt = [7u8; 32];
        let a = derive_master_key(b"correct horse", &salt, KdfParams::light()).unwrap();
        let b = derive_master_key(b"correct horse", &salt, KdfParams::light()).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
        assert_eq!(a.len(), MASTER_KEY_LEN);
    }

    #[test]
    fn different_password_different_key() {
        let salt = [7u8; 32];
        let a = derive_master_key(b"one", &salt, KdfParams::light()).unwrap();
        let b = derive_master_key(b"two", &salt, KdfParams::light()).unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn rejects_absurd_params() {
        let bad = KdfParams {
            memory_kib: 4 * 1024 * 1024,
            iterations: 3,
            parallelism: 4,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn salt_is_random() {
        let a = random_salt();
        let b = random_salt();
        assert_ne!(a, b);
    }
}
