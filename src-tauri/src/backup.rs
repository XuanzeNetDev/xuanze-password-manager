//! 加密备份容器（`.xzbak`）。
//!
//! 导出的内容仍然是一份 xlsx（能被 Excel 打开、能被人读），但**落盘时**
//! 外面包了一层我们自己的加密：Argon2id 派生 + AES-256-GCM。
//! 磁盘上从头到尾不出现明文表格。
//!
//! ## 为什么不直接用 Excel 自带的密码保护
//!
//! OOXML 那套（ECMA-376）早就被 hashcat 一类工具穿透得很彻底，
//! 几小时到几天的事。而这里要保护的是「全部账号密码」——
//! 不能拿一个已知能被跑穿的锁去锁它。
//!
//! ## 文件布局
//!
//! ```text
//! "XZBK" (4) | version (2) | mem_kib (4) | iterations (4) | parallelism (4)
//!            | salt (32) | nonce (12) | ciphertext + tag (16)
//! ```
//!
//! 前 50 字节是头部，整个头部作为 AAD —— 改任何一个参数（比如把内存
//! 开销调小做降级攻击）都会让解密失败。

use xz_core::kdf::{self, KdfParams};
use xz_core::secure::SecretBytes;

/// 容器魔数。
const MAGIC: &[u8; 4] = b"XZBK";
/// 容器版本。
const VERSION: u16 = 1;
/// 头部长度：magic + version + 三个 KDF 参数 + salt。
const HEADER_LEN: usize = 4 + 2 + 4 + 4 + 4 + 32;
/// 盐长度。
const SALT_LEN: usize = 32;
/// 最短合法文件：头部 + nonce + tag。
const MIN_LEN: usize = HEADER_LEN + 12 + 16;

/// 备份用的 KDF 档位。
///
/// 用 `balanced`（64 MiB × 3）而不是默认的 `paranoid`：
/// 备份是低频动作，但每次都要等人；64 MiB 的爆破成本和 256 MiB 是同一
/// 数量级，而等待时间从 0.5 秒降到 0.1 秒左右。
fn backup_params() -> KdfParams {
    KdfParams::balanced()
}

fn build_header(params: KdfParams, salt: &[u8; SALT_LEN]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(MAGIC);
    h[4..6].copy_from_slice(&VERSION.to_le_bytes());
    h[6..10].copy_from_slice(&params.memory_kib.to_le_bytes());
    h[10..14].copy_from_slice(&params.iterations.to_le_bytes());
    h[14..18].copy_from_slice(&params.parallelism.to_le_bytes());
    h[18..50].copy_from_slice(salt);
    h
}

/// 这段字节看起来是不是一个加密备份。
#[must_use]
pub fn looks_like_backup(blob: &[u8]) -> bool {
    blob.len() >= 4 && &blob[..4] == MAGIC
}

/// 把明文字节（xlsx）封装成加密备份。
///
/// # 错误
/// 密码为空、或加密失败时返回错误。密码为空是不允许的 ——
/// 那等于把「备份是密文」这个唯一的好处扔掉。
pub fn seal(plain: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if password.is_empty() {
        return Err("备份密码不能为空".to_owned());
    }
    let params = backup_params();
    let salt = kdf::random_salt();
    let header = build_header(params, &salt);

    let key = kdf::derive_master_key(password.as_bytes(), &salt, params)
        .map_err(|e| format!("派生备份密钥失败：{e}"))?;
    let blob = xz_core::crypto::seal(&key, &header, plain)
        .map_err(|e| format!("加密备份失败：{e}"))?;

    let mut out = Vec::with_capacity(HEADER_LEN + blob.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&blob);
    Ok(out)
}

/// 解开加密备份，返回里面的 xlsx 字节。
///
/// # 错误
/// 不是本格式、密码错、文件被改过时返回错误。三者对外都是同一句话 ——
/// 不给攻击者区分信号。
pub fn open(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if !looks_like_backup(blob) {
        return Err("这不是璇泽密钥库的加密备份文件".to_owned());
    }
    if blob.len() < MIN_LEN {
        return Err("备份文件不完整".to_owned());
    }
    let version = u16::from_le_bytes([blob[4], blob[5]]);
    if version > VERSION {
        return Err(format!(
            "备份格式版本 {version} 高于当前支持的 {VERSION}，请升级软件"
        ));
    }
    let params = KdfParams {
        memory_kib: u32::from_le_bytes([blob[6], blob[7], blob[8], blob[9]]),
        iterations: u32::from_le_bytes([blob[10], blob[11], blob[12], blob[13]]),
        parallelism: u32::from_le_bytes([blob[14], blob[15], blob[16], blob[17]]),
    };
    // 参数边界必须校验：一个声明 4 GiB 内存备份文件能把客户端打死。
    // 这里返回的错误文案刻意和「密码错」不同 —— 那是文件本身有问题，
    // 与用户输什么密码无关。
    if let Err(e) = params.validate() {
        return Err(format!("备份文件的加密参数不合法：{e}"));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&blob[18..50]);
    let header = &blob[..HEADER_LEN];

    let key = kdf::derive_master_key(password.as_bytes(), &salt, params)
        .map_err(|e| format!("派生备份密钥失败：{e}"))?;
    let plain: SecretBytes = xz_core::crypto::open(&key, header, &blob[HEADER_LEN..])
        .map_err(|_| "备份密码不对，或者文件已经损坏".to_owned())?;
    Ok(plain.as_slice().to_vec())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    #[test]
    fn roundtrip() {
        let data = b"whatever bytes, pretending to be an xlsx";
        let blob = super::seal(data, "backup-password").unwrap();
        assert!(super::looks_like_backup(&blob));
        assert_eq!(super::open(&blob, "backup-password").unwrap(), data);
    }

    #[test]
    fn wrong_password_rejected() {
        let blob = super::seal(b"x", "right").unwrap();
        assert!(super::open(&blob, "wrong").is_err());
    }

    #[test]
    fn empty_password_rejected() {
        assert!(super::seal(b"x", "").is_err());
    }

    #[test]
    fn tampered_header_rejected() {
        let mut blob = super::seal(b"payload", "pw").unwrap();
        // 改一个 KDF 参数（头部参与 AAD，必须失败）
        blob[6] ^= 0xFF;
        assert!(super::open(&blob, "pw").is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut blob = super::seal(b"payload", "pw").unwrap();
        let n = blob.len();
        blob[n - 1] ^= 0xFF;
        assert!(super::open(&blob, "pw").is_err());
    }

    #[test]
    fn not_a_backup() {
        assert!(!super::looks_like_backup(b"PK\x03\x04"));
        assert!(super::open(b"PK\x03\x04xxx", "pw").is_err());
    }
}
