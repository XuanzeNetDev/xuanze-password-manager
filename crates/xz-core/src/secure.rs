//! 内存安全工具：可擦除缓冲区。
//!
//! 原则：**任何持有主密码、派生密钥、条目明文的缓冲区，都必须是 [`SecretBytes`]。**
//! 普通 `Vec<u8>` 被 drop 后内存里还留着明文，这是密码管理器最典型的翻车点。

use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// 一块会被安全擦除的字节缓冲。
///
/// - `Drop` 时 `zeroize`（编译器栅栏，不会被优化掉）
/// - 不实现 `Debug` / `Display` / `Clone` 之外的任何泄漏路径
/// - `Debug` 只打印长度
#[derive(Default)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// 空缓冲。
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// 从 `Vec` 接管所有权。
    #[must_use]
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self(v)
    }

    /// 预分配容量。
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self(Vec::with_capacity(cap))
    }

    /// 分配 `len` 个零字节。
    #[must_use]
    pub fn zeroed(len: usize) -> Self {
        Self(vec![0u8; len])
    }

    /// 确保长度正好是 `len`，多退少补（补的部分是 0）。
    ///
    /// 缩容时先把要丢弃的尾部擦掉 —— `Vec::resize` 只是改 `len`，
    /// 那段内存在分配器或取证工具眼里仍然可读。
    pub fn resize(&mut self, len: usize) {
        if len < self.0.len() {
            self.0[len..].zeroize();
        }
        self.0.resize(len, 0);
    }

    /// 只读视图。
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// 可写视图。
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// 长度。
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 立即擦除并清空。
    pub fn wipe(&mut self) {
        self.0.zeroize();
        self.0.clear();
    }

    /// 复制一份。两份都会在 drop 时被擦除。
    ///
    /// 为什么需要它：绑定材料要在「快照」和「Vault」之间各留一份
    /// （改密码时快照会被搬到锁外去跑 KDF），而 `SecretBytes` 故意
    /// 不实现 `Clone` —— 克隆秘密这件事必须是显式的，不能顺手 `clone()`。
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }

    /// 交给需要 `Vec<u8>` 的第三方 API 使用。
    ///
    /// 返回 `Zeroizing`，调用方**不需要也不能**手动擦除 —— 出了这个门
    /// 也还是会被擦的类型。早先这里返回裸 `Vec<u8>`，等于把秘密从安全
    /// 容器里偷渡出去，调用方一个 `drop` 就留下明文。
    #[must_use]
    pub fn into_inner(mut self) -> Zeroizing<Vec<u8>> {
        let v = std::mem::take(&mut self.0);
        self.wipe();
        Zeroizing::new(v)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 绝不打印内容，只给长度。
        f.debug_struct("SecretBytes")
            .field("len", &self.0.len())
            .finish()
    }
}

/// 把字符串塞进可擦除容器。用于主密码 / API key 等文本形式的秘密。
pub type SecretString = Zeroizing<String>;

/// 构造一个会被擦除的字符串。
#[must_use]
pub fn secret_string(s: impl Into<String>) -> SecretString {
    Zeroizing::new(s.into())
}

/// 常量时间比较，防时序侧信道。
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    // 测试里 unwrap 是正常写法：出错就该 panic，不需要优雅降级。
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn debug_never_leaks_content() {
        let s = SecretBytes::from_vec(b"super-secret-token".to_vec());
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("super"));
        assert!(rendered.contains("len"));
    }

    #[test]
    fn wipe_clears() {
        let mut s = SecretBytes::from_vec(vec![1, 2, 3]);
        s.wipe();
        assert!(s.is_empty());
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
