//! 文件格式编解码。
//!
//! 二进制布局（全部小端），完整说明见 `docs/FORMAT.md`：
//!
//! ```text
//! offset  size  field
//! 0       8     magic            "XZVLT\0\x02\0"
//! 8       2     version          u16 = 2
//! 10      1     kdf_algo         u8  = 1 (Argon2id v0x13)
//! 11      4     kdf_mem_kib      u32
//! 15      4     kdf_iterations   u32
//! 19      4     kdf_parallelism  u32
//! 23      32    kdf_salt
//! 55      16    vault_id         库标识，创建后终身不变
//! 71      4     index_len        u32
//! 75      n     index_blob       nonce || AES-GCM(index_json)
//! 75+n    4     body_len         u32
//! 79+n    m     body_blob        nonce || AES-GCM(body_json)
//! 79+n+m  46    verify_block     nonce || AES-GCM(const)
//! ```
//!
//! 头 71 字节作为整个文件的 AAD，改一个 bit 就解不开。

use crate::crypto::{self, KeyPurpose};
use crate::error::{Error, Result};
use crate::kdf::{KdfParams, MASTER_KEY_LEN};
use crate::{FORMAT_VERSION, MAGIC};

/// 固定头长度（到 index_len 之前）。
pub const HEADER_LEN: usize = 71;
/// KDF 算法编号：Argon2id v0x13。
const KDF_ARGON2ID: u8 = 1;
/// 校验块明文内容。固定值，用来确认主密码正确。
const VERIFY_PLAINTEXT: &[u8] = b"xzvlt/v1/verify-ok";

/// 校验块的固定长度：nonce + 明文 + tag。
///
/// 明文的字面量是 `xzvlt/v1/verify-ok`（18 字节），所以整块恒为
/// 12 + 18 + 16 = 46 字节。
///
/// 这里的 `v1` 是**用途标签的命名空间**，不是格式版本号 —— 格式版本看头里的
/// `version` 字段（当前 2）。两者各自独立演进，见 `crypto.rs` 的 `KeyPurpose`。
pub const VERIFY_BLOCK_LEN: usize = crypto::NONCE_LEN + VERIFY_PLAINTEXT.len() + crypto::TAG_LEN;

/// 解析出来的文件头。
#[derive(Debug, Clone)]
pub struct FileHeader {
    /// 格式版本。
    pub version: u16,
    /// KDF 参数。
    pub kdf: KdfParams,
    /// KDF 盐。
    pub salt: [u8; 32],
    /// 库的稳定标识（创建时随机生成，终身不变）。
    ///
    /// 作用是「认库不认人」：应用只接受自己创建的那个库，
    /// 陌生文件哪怕密码正确也拒绝 —— 见 `machine` 侧的登记表。
    pub vault_id: [u8; 16],
}

impl FileHeader {
    /// 序列化固定头（前 55 字节）。
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..8].copy_from_slice(MAGIC);
        buf[8..10].copy_from_slice(&self.version.to_le_bytes());
        buf[10] = KDF_ARGON2ID;
        buf[11..15].copy_from_slice(&self.kdf.memory_kib.to_le_bytes());
        buf[15..19].copy_from_slice(&self.kdf.iterations.to_le_bytes());
        buf[19..23].copy_from_slice(&self.kdf.parallelism.to_le_bytes());
        buf[23..55].copy_from_slice(&self.salt);
        buf[55..71].copy_from_slice(&self.vault_id);
        buf
    }

    /// 从字节解析固定头。只读前 55 字节，不要求后面还有数据。
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::NotAVault);
        }
        if &bytes[0..8] != MAGIC {
            return Err(Error::NotAVault);
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version > FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: version,
                supported: FORMAT_VERSION,
            });
        }
        if bytes[10] != KDF_ARGON2ID {
            return Err(Error::Corrupt("未知 KDF 算法编号"));
        }
        let memory_kib = u32::from_le_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]);
        let iterations = u32::from_le_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]);
        let parallelism = u32::from_le_bytes([bytes[19], bytes[20], bytes[21], bytes[22]]);
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes[23..55]);
        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&bytes[55..71]);

        let kdf = KdfParams {
            memory_kib,
            iterations,
            parallelism,
        };
        kdf.validate()?;

        Ok(Self {
            version,
            kdf,
            salt,
            vault_id,
        })
    }
}

/// 从文件全量字节里切出的各段密文。
///
/// 分离出来是因为 Tauri 层可以「只读头」判断是否本产品文件，
/// 不必把整个文件读进内存。
pub struct SealedParts<'a> {
    /// 绑定块（仅 v3 及以后有）。
    ///
    /// 里面是「本机随机串」的密文，用硬件指纹派生的密钥封装。
    /// 它让库文件自己带着一份绑定材料的副本 —— 重装系统、`%APPDATA%` 被清空时
    /// 靠它把库救回来，而不需要一份明文 Excel。
    pub bind: Option<&'a [u8]>,
    /// 索引密文。
    pub index: &'a [u8],
    /// 正文密文。
    pub body: &'a [u8],
    /// 校验块。
    pub verify: &'a [u8],
}

/// 切分文件。
///
/// 布局随 `version` 变化：
///
/// ```text
/// v2: 头 | u32 index_len | index | u32 body_len | body | verify(46)
/// v3: 头 | u32 bind_len  | bind  | u32 index_len | index | u32 body_len | body | verify(46)
/// ```
pub fn split_sealed(bytes: &[u8]) -> Result<SealedParts<'_>> {
    let header = FileHeader::parse(bytes)?;
    if bytes.len() < HEADER_LEN + 4 {
        return Err(Error::Corrupt("文件长度不足"));
    }
    let mut off = HEADER_LEN;

    let read_len = |off: &mut usize| -> Result<usize> {
        if *off + 4 > bytes.len() {
            return Err(Error::Corrupt("段长度字段被截断"));
        }
        let n = u32::from_le_bytes([
            bytes[*off],
            bytes[*off + 1],
            bytes[*off + 2],
            bytes[*off + 3],
        ]) as usize;
        *off += 4;
        Ok(n)
    };

    let slice_of = |off: &mut usize, n: usize, what: &'static str| -> Result<&[u8]> {
        if *off + n > bytes.len() {
            return Err(Error::Corrupt(what));
        }
        let s = &bytes[*off..*off + n];
        *off += n;
        Ok(s)
    };

    // v3 起多一个绑定块
    let bind = if header.version >= 3 {
        let n = read_len(&mut off)?;
        // 绑定块固定是「nonce + 32 字节明文 + tag」，别的一律拒绝：
        // 长度不吻合的文件不可能是我们写出来的。
        if n != crate::binding::BIND_BLOCK_LEN {
            return Err(Error::Corrupt("绑定块长度非法"));
        }
        Some(slice_of(&mut off, n, "绑定块越界")?)
    } else {
        None
    };

    let index_len = read_len(&mut off)?;
    let index = slice_of(&mut off, index_len, "索引段越界")?;

    let body_len = read_len(&mut off)?;
    let body = slice_of(&mut off, body_len, "正文段越界")?;

    // 校验块长度是恒定的：nonce(12) + 明文(18) + tag(16) = 46。
    // 之前只查 `>= 28`，等于「靠后面的 GCM 兜底」——格式层不该把
    // 判断权交给密码学，而且尾部多出的字节会被当成密文的一部分，
    // 产生「文件被追加了数据却仍然能打开」这种说不清的语义。
    let verify = &bytes[off..];
    if verify.len() != VERIFY_BLOCK_LEN {
        return Err(Error::Corrupt("校验块长度非法"));
    }

    Ok(SealedParts {
        bind,
        index,
        body,
        verify,
    })
}

/// 把各段密文组装成完整文件字节。
///
/// `bind` 只在 `version >= 3` 时写入；v2 传 `None`。
#[must_use]
pub fn assemble(
    header: &[u8; HEADER_LEN],
    bind: Option<&[u8]>,
    index: &[u8],
    body: &[u8],
    verify: &[u8],
) -> Vec<u8> {
    let bind_len = bind.map_or(0, |b| b.len() + 4);
    let total = HEADER_LEN + bind_len + 4 + index.len() + 4 + body.len() + verify.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(header);
    if let Some(b) = bind {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    out.extend_from_slice(&(index.len() as u32).to_le_bytes());
    out.extend_from_slice(index);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(verify);
    out
}

/// 生成校验块。
pub fn make_verify_block(
    master_key: &crate::secure::SecretBytes,
    header: &[u8; HEADER_LEN],
) -> Result<Vec<u8>> {
    let vk = crypto::derive_subkey(master_key, KeyPurpose::Verify)?;
    crypto::seal(&vk, header, VERIFY_PLAINTEXT)
}

/// 校验块是否与主密码匹配。
///
/// 这是打开 vault 时**唯一**需要完整 KDF 的地方，也是判断「密码对不对」的关口。
pub fn check_verify_block(
    master_key: &crate::secure::SecretBytes,
    header: &[u8; HEADER_LEN],
    block: &[u8],
) -> Result<()> {
    let vk = crypto::derive_subkey(master_key, KeyPurpose::Verify)?;
    let pt = crypto::open(&vk, header, block)?;
    if !crate::secure::ct_eq(pt.as_slice(), VERIFY_PLAINTEXT) {
        return Err(Error::BadPasswordOrTampered);
    }
    Ok(())
}

/// 主密钥长度常量转导出，方便上层使用。
pub const fn master_key_len() -> usize {
    MASTER_KEY_LEN
}

#[cfg(test)]
mod tests {
    // 测试里 unwrap 是正常写法：出错就该 panic，不需要优雅降级。
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn hdr() -> FileHeader {
        FileHeader {
            version: FORMAT_VERSION,
            kdf: KdfParams::light(),
            salt: [3u8; 32],
            vault_id: [5u8; 16],
        }
    }

    #[test]
    fn header_roundtrip() {
        let h = hdr();
        let bytes = h.to_bytes();
        let back = FileHeader::parse(&bytes).unwrap();
        assert_eq!(back.version, FORMAT_VERSION);
        assert_eq!(back.kdf, h.kdf);
        assert_eq!(back.salt, h.salt);
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut bytes = hdr().to_bytes();
        bytes[0] = b'Y';
        assert!(matches!(FileHeader::parse(&bytes), Err(Error::NotAVault)));
    }

    #[test]
    fn rejects_future_version() {
        let mut bytes = hdr().to_bytes();
        bytes[8..10].copy_from_slice(&99u16.to_le_bytes());
        assert!(matches!(
            FileHeader::parse(&bytes),
            Err(Error::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn assemble_split_roundtrip() {
        // v2 布局：没有绑定块
        let mut h = hdr();
        h.version = 2;
        let h = h.to_bytes();
        let verify = vec![7u8; VERIFY_BLOCK_LEN];
        let file = assemble(&h, None, b"indexxxx", b"bodyyyyy", &verify);
        let parts = split_sealed(&file).unwrap();
        assert!(parts.bind.is_none());
        assert_eq!(parts.index, b"indexxxx");
        assert_eq!(parts.body, b"bodyyyyy");
    }

    #[test]
    fn assemble_split_roundtrip_v3_with_bind_block() {
        // v3 布局：头后面多一个绑定块
        let h = hdr().to_bytes();
        let verify = vec![7u8; VERIFY_BLOCK_LEN];
        let bind = vec![9u8; crate::binding::BIND_BLOCK_LEN];
        let file = assemble(&h, Some(&bind), b"indexxxx", b"bodyyyyy", &verify);
        let parts = split_sealed(&file).unwrap();
        assert_eq!(parts.bind, Some(&bind[..]));
        assert_eq!(parts.index, b"indexxxx");
        assert_eq!(parts.body, b"bodyyyyy");
    }

    /// v3 文件里绑定块长度不对时必须拒绝，不能糊过去。
    #[test]
    fn v3_rejects_wrong_bind_block_length() {
        let h = hdr().to_bytes();
        let verify = vec![7u8; VERIFY_BLOCK_LEN];
        let bind = vec![9u8; 10]; // 不是 BIND_BLOCK_LEN
        let file = assemble(&h, Some(&bind), b"index", b"body", &verify);
        assert!(split_sealed(&file).is_err());
    }

    #[test]
    fn truncated_is_rejected() {
        let mut h = hdr();
        h.version = 2;
        let h = h.to_bytes();
        let verify = vec![7u8; VERIFY_BLOCK_LEN];
        let file = assemble(&h, None, b"index", b"body", &verify);
        assert!(split_sealed(&file[..HEADER_LEN + 2]).is_err());
    }

    #[test]
    fn verify_block_matches_only_correct_key() {
        let h = hdr().to_bytes();
        let mk = crate::secure::SecretBytes::from_vec(vec![5u8; 32]);
        let block = make_verify_block(&mk, &h).unwrap();
        assert!(check_verify_block(&mk, &h, &block).is_ok());

        let wrong = crate::secure::SecretBytes::from_vec(vec![6u8; 32]);
        assert!(check_verify_block(&wrong, &h, &block).is_err());
    }

    #[test]
    fn header_is_aad_so_tampering_fails() {
        let h = hdr().to_bytes();
        let mk = crate::secure::SecretBytes::from_vec(vec![5u8; 32]);
        let block = make_verify_block(&mk, &h).unwrap();

        let mut tampered = h;
        tampered[11] ^= 0xFF; // 改 KDF 内存参数
        assert!(check_verify_block(&mk, &tampered, &block).is_err());
    }
}
