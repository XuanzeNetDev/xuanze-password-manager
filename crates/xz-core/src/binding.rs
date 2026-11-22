//! 机器绑定：让 vault 文件只在创建它的这台**硬件**上能解开。
//!
//! 思路是给 Argon2id 再加一段**用户密码之外的密钥材料**（下称 pepper）。
//!
//! ## 两代规则
//!
//! **v2（老库，只读兼容）：**
//!
//! ```text
//! pepper = "xzvlt-bind-v1\0" || 32 字节随机串 || 0x00 || 机器名 + "-" + 卷序列号
//! ```
//!
//! **v3（当前）：**
//!
//! ```text
//! pepper = "xzvlt-bind-v2\0" || 32 字节随机串
//! ```
//!
//! v3 去掉了机器名和卷序列号，因为那两个值都会变 —— 计算机名右键就能改，
//! 卷序列号格式化就重新生成。把它们编进密钥派生，等于「改个名字 / 重装系统
//! 就打不开」，而设备绑定想表达的是「换一台**硬件**就打不开」。
//!
//! ## 那 32 字节存哪
//!
//! 两份，任一可解：
//!
//! 1. `%APPDATA%\cn.xuanze.vault\machine.bind`，DPAPI 封存（日常快路径）
//! 2. **库文件里的绑定块**，用硬件指纹（SMBIOS UUID）加密（重装系统后靠它）
//!
//! 第二份是 v3 的关键：它跟着文件走，`%APPDATA%` 被清空也不影响。
//! 换硬件则两份都失效 —— 那正是想要的效果。
//!
//! 这是**主动提高倒库门槛**的做法，不是绝对安全 —— 能同时读走内存和
//! 硬件标识的攻击者仍然可以解密正在使用中的数据。它的目标是把
//! 「拷走文件 → 慢慢爆破密码」这条路堵死。
//!
//! 核心库不碰系统 API（`deny(unsafe_code)`），DPAPI 与 SMBIOS 的读取在宿主层，
//! 这里只负责把材料拼成 pepper、以及封装/解封绑定块。

use crate::crypto::{open as crypto_open, seal as crypto_seal, KEY_LEN};
use crate::error::{Error, Result};
use crate::kdf::{self, KdfParams};
use crate::secure::SecretBytes;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// v2 格式的 pepper 前导标记，防止和别的用途的密钥材料混淆。
const PEPPER_TAG: &[u8] = b"xzvlt-bind-v1\x00";

/// v3 格式的 pepper 前导标记。
///
/// 内容变了（不再拼机器名与卷序列号），所以换一个标记：
/// 两个版本各有自己的命名空间，不会因为前缀相同产生歧义。
const PEPPER_TAG_V3: &[u8] = b"xzvlt-bind-v2\x00";

/// 「本机随机串」的长度。256 bit，这是绑定材料里唯一真正的熵来源。
pub const BINDING_SECRET_LEN: usize = 32;

/// 绑定块的固定长度：nonce + 明文 + tag。
pub const BIND_BLOCK_LEN: usize = crate::crypto::NONCE_LEN + BINDING_SECRET_LEN + crate::crypto::TAG_LEN;

/// 绑定块的 AAD。
///
/// 用它把「封装格式」钉住：同一个密钥拿去封别的东西、或者换个用途复用
/// 这段密文，都会认证失败。
///
/// **注意这里是常量，没有掺 `vault_id`。** 掺进去能让「拿 A 库的绑定块
/// 塞进 B 库」这种操作连解都解不开，属于防御深度。没做的原因是：
/// 改 AAD 会让所有既有的 v3 库读不出来，而它挡的那种攻击本来也走不通 ——
/// 换过来的绑定块里是另一把 secret，pepper 对不上，主密钥照样派生不出来。
/// 收益是零，代价是破坏兼容，不划算。
const BIND_AAD: &[u8] = b"xzvlt/bind-block/v1";

/// 把「本机随机串」和「本机标识」拼成喂给 Argon2 的额外材料。
///
/// `secret` 由宿主用 DPAPI 解出来；`identity` 是机器名+卷序列号。
#[must_use]
pub fn make_pepper(secret: &[u8], identity: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(PEPPER_TAG.len() + secret.len() + 1 + identity.len());
    out.extend_from_slice(PEPPER_TAG);
    out.extend_from_slice(secret);
    // 分隔符，避免 secret 和 identity 拼接时产生歧义
    out.push(0);
    out.extend_from_slice(identity.as_bytes());
    out
}

/// 派生主密钥：密码和 pepper 一起进 Argon2。
///
/// 两者的顺序固定为 `password || pepper`，改动会让已有 vault 打不开。
pub fn derive_bound_key(
    password: &[u8],
    pepper: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretBytes> {
    if pepper.is_empty() {
        return Err(Error::Corrupt("缺少机器绑定材料"));
    }
    let mut combined = Vec::with_capacity(password.len() + pepper.len());
    combined.extend_from_slice(password);
    combined.extend_from_slice(pepper);
    let key = kdf::derive_master_key(&combined, salt, params);
    // combined 里含密码。用手写 `for b in .. { *b = 0 }` 是不可靠的：
    // LLVM 的 dead-store elimination 有权把「写完立刻丢」的存储整段删掉，
    // 而我们 release 档开的正是最激进的 lto=fat + cgu=1。
    // zeroize 用 volatile 写 + compiler fence，编译器删不掉。
    combined.zeroize();
    key
}

// ───────────────────── v3：绑定材料跟着文件走 ─────────────────────

/// v3 的 pepper：只由「本机随机串」构成，不混机器名与卷序列号。
///
/// ## 为什么把机器名和卷序列号拿掉
///
/// 那两个值都会变，而且变得很随意：
///
/// - 计算机名：右键「此电脑」→ 属性 → 就能改
/// - C 盘卷序列号：格式化就重新生成
///
/// 把它们编进密钥派生，语义就变成了「改个名字 / 重装系统 = 数据永久报废」。
/// 而「设备绑定」想表达的其实是「换一台**硬件**就打不开」，不是「改个标签就打不开」。
///
/// 换机器/换主板依然打不开，靠的是别的机制：`binding_secret` 要么封在
/// 本机 DPAPI 里，要么用**硬件指纹**加密封在库文件内（见 [`wrap_binding_secret`]）。
/// 硬件指纹取自 SMBIOS UUID 这类重装系统不会变、换主板才会变的东西。
#[must_use]
pub fn make_pepper_v3(binding_secret: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PEPPER_TAG_V3.len() + binding_secret.len());
    out.extend_from_slice(PEPPER_TAG_V3);
    out.extend_from_slice(binding_secret);
    out
}

/// 从硬件指纹派生「绑定块封装密钥」。
///
/// 硬件指纹本身不是秘密，所以这里不指望它保密 —— 它的作用是让
/// **别的机器解不开这个块**。要冒充，攻击者得先知道目标机器的 SMBIOS UUID。
fn bind_wrap_key(hardware_fp: &[u8]) -> Result<SecretBytes> {
    if hardware_fp.is_empty() {
        return Err(Error::Corrupt("缺少硬件指纹"));
    }
    let hk = Hkdf::<Sha256>::new(None, hardware_fp);
    let mut out = SecretBytes::zeroed(KEY_LEN);
    hk.expand(b"xzvlt/bind-wrap/v1", out.as_mut_slice())
        .map_err(|_| Error::Corrupt("HKDF 派生失败"))?;
    Ok(out)
}

/// 把 `binding_secret` 封进绑定块，写进库文件。
///
/// 这是「重装系统还能打开」的关键：库文件自己带着一份绑定材料的副本，
/// 而这份副本只有**同一台硬件**能解开。`%APPDATA%` 被清空、DPAPI 主密钥
/// 换掉，都不影响它。
///
/// # 错误
/// 硬件指纹为空、或加密失败时返回错误。
pub fn wrap_binding_secret(hardware_fp: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    if secret.len() != BINDING_SECRET_LEN {
        return Err(Error::Corrupt("绑定材料长度不是 32 字节"));
    }
    let key = bind_wrap_key(hardware_fp)?;
    crypto_seal(&key, BIND_AAD, secret)
}

/// 解开库文件里的绑定块。换了硬件会失败。
pub fn unwrap_binding_secret(hardware_fp: &[u8], blob: &[u8]) -> Result<SecretBytes> {
    let key = bind_wrap_key(hardware_fp)?;
    crypto_open(&key, BIND_AAD, blob)
}

/// 由绑定材料派生主密钥（v3 规则）。
pub fn derive_bound_key_v3(
    password: &[u8],
    binding_secret: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretBytes> {
    let pepper = make_pepper_v3(binding_secret);
    let mut combined = Vec::with_capacity(password.len() + pepper.len());
    combined.extend_from_slice(password);
    combined.extend_from_slice(&pepper);
    let key = kdf::derive_master_key(&combined, salt, params);
    combined.zeroize();
    key
}
