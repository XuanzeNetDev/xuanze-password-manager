//! 认证加密：AES-256-GCM。
//!
//! 密钥分级（全部由主密钥经 HKDF-SHA256 单向派生，互不通用）：
//!
//! ```text
//! master_key (32B, Argon2id 派生)
//!    ├─ HKDF(info="xzvlt/v1/payload")  → payload_key  加密条目体
//!    ├─ HKDF(info="xzvlt/v1/index")    → index_key    加密索引（名称等可搜索字段）
//!    └─ HKDF(info="xzvlt/v1/verify")   → verify_key   仅用于校验主密码是否正确
//! ```
//!
//! 为什么分开：索引要常驻内存、要频繁解密来做搜索；条目体可以懒加载。
//! 万一某key泄漏，不会连带另一部分。

use crate::error::{Error, Result};
use crate::secure::SecretBytes;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// AES-GCM 的 nonce 长度（96 bit，GCM 推荐值）。
pub const NONCE_LEN: usize = 12;
/// AES-GCM 认证标签长度。
pub const TAG_LEN: usize = 16;
/// 密钥长度。
pub const KEY_LEN: usize = 32;

/// 派生用途标签。改这些字符串等于改格式，`FORMAT_VERSION` 必须跟着升。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// 条目正文。
    Payload,
    /// 索引（条目名称、标签等需要搜索的字段）。
    Index,
    /// 主密码校验块。
    Verify,
}

impl KeyPurpose {
    #[must_use]
    const fn info(self) -> &'static [u8] {
        match self {
            KeyPurpose::Payload => b"xzvlt/v1/payload",
            KeyPurpose::Index => b"xzvlt/v1/index",
            KeyPurpose::Verify => b"xzvlt/v1/verify",
        }
    }
}

/// 从主密钥派生一把用途专用的子密钥。
pub fn derive_subkey(master: &SecretBytes, purpose: KeyPurpose) -> Result<SecretBytes> {
    if master.len() != KEY_LEN {
        return Err(Error::Corrupt("主密钥长度不是 32 字节"));
    }
    let hk = Hkdf::<Sha256>::new(None, master.as_slice());
    let mut out = SecretBytes::zeroed(KEY_LEN);
    hk.expand(purpose.info(), out.as_mut_slice())
        .map_err(|_| Error::Corrupt("HKDF 派生失败"))?;
    Ok(out)
}

/// 用给定密钥加密，返回 `nonce || ciphertext || tag`。
///
/// `aad` 是附加认证数据（不加密但参与完整性校验）。格式里我们把文件头
/// 当 AAD 用，这样**改任何一个头字段都会导致解密失败**，杜绝降级攻击。
pub fn seal(key: &SecretBytes, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes = crate::kdf::random_bytes::<NONCE_LEN>();

    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| Error::Corrupt("AES 密钥长度非法"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Corrupt("加密失败"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解密 `nonce || ciphertext || tag`。
///
/// # 错误
/// 密钥错、AAD 被改、密文被改、截断，全部归一到 [`Error::BadPasswordOrTampered`]，
/// 不给攻击者任何区分信号。
pub fn open(key: &SecretBytes, aad: &[u8], blob: &[u8]) -> Result<SecretBytes> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Corrupt("密文长度不足"));
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);

    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| Error::Corrupt("AES 密钥长度非法"))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let pt = cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| Error::BadPasswordOrTampered)?;

    Ok(SecretBytes::from_vec(pt))
}

#[cfg(test)]
mod tests {
    // 测试里 unwrap 是正常写法：出错就该 panic，不需要优雅降级。
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn master() -> SecretBytes {
        SecretBytes::from_vec(vec![9u8; KEY_LEN])
    }

    #[test]
    fn roundtrip() {
        let mk = master();
        let key = derive_subkey(&mk, KeyPurpose::Payload).unwrap();
        let blob = seal(&key, b"header", b"hello vault").unwrap();
        assert!(blob.len() > b"hello vault".len());
        let pt = open(&key, b"header", &blob).unwrap();
        assert_eq!(pt.as_slice(), b"hello vault");
    }

    #[test]
    fn subkeys_are_distinct() {
        let mk = master();
        let p = derive_subkey(&mk, KeyPurpose::Payload).unwrap();
        let i = derive_subkey(&mk, KeyPurpose::Index).unwrap();
        assert_ne!(p.as_slice(), i.as_slice());
    }

    #[test]
    fn aad_mismatch_fails() {
        let mk = master();
        let key = derive_subkey(&mk, KeyPurpose::Payload).unwrap();
        let blob = seal(&key, b"header-a", b"x").unwrap();
        assert!(matches!(
            open(&key, b"header-b", &blob),
            Err(Error::BadPasswordOrTampered)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mk = master();
        let key = derive_subkey(&mk, KeyPurpose::Payload).unwrap();
        let mut blob = seal(&key, b"h", b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(
            open(&key, b"h", &blob),
            Err(Error::BadPasswordOrTampered)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let a = derive_subkey(&master(), KeyPurpose::Payload).unwrap();
        let b = derive_subkey(&SecretBytes::from_vec(vec![1u8; 32]), KeyPurpose::Payload).unwrap();
        let blob = seal(&a, b"", b"x").unwrap();
        assert!(open(&b, b"", &blob).is_err());
    }

    #[test]
    fn nonce_is_not_reused() {
        let key = derive_subkey(&master(), KeyPurpose::Payload).unwrap();
        let a = seal(&key, b"", b"same").unwrap();
        let b = seal(&key, b"", b"same").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }
}
