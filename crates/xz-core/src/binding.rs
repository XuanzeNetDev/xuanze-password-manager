//! 机器绑定：让 vault 文件只在创建它的这台机器、这个 Windows 账号上能解开。
//!
//! 思路是给 Argon2id 再加一段**用户密码之外的密钥材料**（下称 pepper）：
//!
//! ```text
//! master_key = Argon2id(password || pepper, salt, 最大档参数)
//! ```
//!
//! pepper 由两段拼成：
//! 1. **本机随机串** —— 由宿主（Tauri 层）用 Windows DPAPI 封存，
//!    只有当前 Windows 账号能解开。拷走 vault 文件、甚至拷走保管文件，
//!    到别的机器/账号都解不出来。
//! 2. **本机标识** —— 机器名 + 系统卷序列号，换个硬盘或换台机器就不一样。
//!
//! 效果：即使有人把 `.xzvlt` 文件和软件一起搬走，没有这台机器的 DPAPI
//! 身份也派生不出正确的 master_key。
//!
//! 这是**主动提高倒库门槛**的做法，不是绝对安全 —— 能同时读走内存和
//! DPAPI 身份的攻击者仍然可以解密正在使用中的数据。它的目标是把
//! 「拷走文件 → 慢慢爆破密码」这条路彻底堵死。
//!
//! 核心库不碰系统 API（`deny(unsafe_code)`），DPAPI 的调用在宿主层，
//! 这里只负责把材料拼成 pepper 并按固定规则派生。

use crate::error::{Error, Result};
use crate::kdf::{self, KdfParams};
use crate::secure::SecretBytes;
use zeroize::Zeroize;

/// pepper 的前导标记，防止和别的用途的密钥材料混淆。
const PEPPER_TAG: &[u8] = b"xzvlt-bind-v1\x00";

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
