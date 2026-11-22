//! 统一错误类型。核心库不依赖任何 UI 框架，错误只描述事实。

use std::fmt;

/// 核心库结果别名。
pub type Result<T> = std::result::Result<T, Error>;

/// 核心库错误。
///
/// 刻意不携带任何密钥、明文片段或解密中间态，保证错误可以安全地打到日志里。
#[derive(Debug)]
pub enum Error {
    /// 文件头魔数不对，或者根本不是本产品的文件。
    NotAVault,
    /// 格式版本高于本实现能理解的版本。
    UnsupportedVersion { found: u16, supported: u16 },
    /// 文件被截断或结构损坏。
    Corrupt(&'static str),
    /// 主密码错误，或文件被篡改（GCM 认证失败，两者不可区分，这是故意的）。
    BadPasswordOrTampered,
    /// 条目 id 重复（导入时常见）。
    DuplicateEntry(String),
    /// 找不到条目。
    EntryNotFound(String),
    /// 字段校验失败，例如必填项为空、名称超长。
    Invalid(&'static str),
    /// IO 错误。
    Io(std::io::Error),
    /// KDF 参数超出本实现允许的安全/性能边界。
    UnacceptableKdf { reason: &'static str },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAVault => f.write_str("不是璇泽密钥库文件（魔数不匹配）"),
            Error::UnsupportedVersion { found, supported } => {
                write!(f, "格式版本 {found} 高于当前支持的 {supported}，请升级软件")
            }
            Error::Corrupt(what) => write!(f, "vault 结构损坏：{what}"),
            Error::BadPasswordOrTampered => f.write_str("主密码错误或文件已被篡改"),
            Error::DuplicateEntry(id) => write!(f, "条目 id 重复：{id}"),
            Error::EntryNotFound(id) => write!(f, "条目不存在：{id}"),
            Error::Invalid(what) => write!(f, "字段不合法：{what}"),
            Error::Io(e) => write!(f, "IO 错误：{e}"),
            Error::UnacceptableKdf { reason } => write!(f, "KDF 参数不可接受：{reason}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
