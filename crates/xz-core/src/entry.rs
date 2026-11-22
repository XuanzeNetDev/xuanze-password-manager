//! 条目模型。
//!
//! 设计取舍（为了性能，也为了「密钥管理」这个真实用途）：
//!
//! - **一种统一类型**，不搞 Login/Card/Note 多个 struct。`kind` 区分用途。
//!   分类太细会让索引和搜索分支爆炸，而密码管理器里 90% 的字段本来就能共用。
//! - **`fields` 是有序的 `Vec` 而不是 `HashMap`**。个人库单条目一般 < 20 个字段，
//!   线性扫描比哈希快，且序列化结果稳定（开源项目要 diff 友好、要可复现）。
//! - **`name` / `username` / `tags` 冗余在索引里**，正文里也存一份（解耦：
//!   索引可以单独加密、单独重建）。

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 条目类型。用 `u8` 而不是 string，省内存、序列化快。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// 网站 / 应用登录凭据。
    Login,
    /// API key、访问令牌、私钥、连接串。
    ApiKey,
    /// 安全笔记（纯文本）。
    Note,
    /// 银行卡 / 支付信息。
    Card,
    /// 数据库连接 / SSH 密钥。
    Credential,
}

impl EntryKind {
    /// 用于索引序列化的稳定字节值。**不要改已有值**，那是格式的一部分。
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            EntryKind::Login => 0,
            EntryKind::ApiKey => 1,
            EntryKind::Note => 2,
            EntryKind::Card => 3,
            EntryKind::Credential => 4,
        }
    }

    /// 从索引字节值还原。
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => EntryKind::Login,
            1 => EntryKind::ApiKey,
            2 => EntryKind::Note,
            3 => EntryKind::Card,
            4 => EntryKind::Credential,
            _ => return None,
        })
    }
}

/// 一条自定义字段。`value` 是否明文取决于 `secret` 标记。
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Field {
    /// 字段名，如 `刷新令牌`、`Region`。
    pub name: String,
    /// 字段值。
    pub value: String,
    /// 是否敏感。敏感字段在 UI 上默认打码，且**不进索引**、不可搜索。
    pub secret: bool,
}

impl Field {
    /// 构造一个敏感字段。
    #[must_use]
    pub fn secret(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            secret: true,
        }
    }

    /// 构造一个普通字段。
    #[must_use]
    pub fn plain(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            secret: false,
        }
    }
}

/// 一条完整条目。
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    /// 稳定唯一 id（16 字节随机数，十六进制）。改 id 等于换条目。
    pub id: String,
    /// 类型。
    pub kind: EntryKind,
    /// 显示名，如 `OpenAI 生产 Key`。
    pub name: String,
    /// 用户名 / 账号 / 公钥指纹。可空。
    #[serde(default)]
    pub username: String,
    /// 主秘密：密码、API key、私钥正文。可空（纯笔记场景）。
    #[serde(default)]
    pub secret: String,
    /// 网址 / 服务地址 / 备注位。可空。
    #[serde(default)]
    pub url: String,
    /// 附加字段。
    #[serde(default)]
    pub fields: Vec<Field>,
    /// 标签，用于分类与过滤。
    #[serde(default)]
    pub tags: Vec<String>,
    /// 纯文本备注。
    #[serde(default)]
    pub notes: String,
    /// 创建时间（Unix 秒）。
    pub created_at: i64,
    /// 最后修改时间（Unix 秒）。
    pub updated_at: i64,
    /// 过期时间（Unix 秒，0 = 不过期）。API key 轮换提醒用得上。
    #[serde(default)]
    pub expires_at: i64,
    /// 被点开/复制的次数，用来做「最常用」排序。
    #[serde(default)]
    pub use_count: u32,
    /// 最后一次使用时间（Unix 秒），0 = 从未。
    #[serde(default)]
    pub last_used_at: i64,
}

impl Entry {
    /// 校验并规范化。导入外部数据时必过的关口。
    ///
    /// ## 为什么每一段都要有上界
    ///
    /// 这些字段全都能从 IPC 进来（`entry_save` 的参数就是前端随手填的 JSON），
    /// 也都能从导入的 xlsx 进来（别人给的文件）。只限 `name` 和 `secret`
    /// 是不够的：一条 200 MB 的 `notes` 会在每次保存时被整库序列化一次，
    /// 而保存是同步全量重写 —— 一个巨大的备注就能把整个库变成不可用，
    /// 甚至先把内存吃光。上界不是洁癖，是可用性边界。
    pub fn validate(&self) -> crate::Result<()> {
        use crate::error::Error;

        /// 单个自定义字段值的上限。
        const MAX_FIELD_VALUE: usize = 64 << 10; // 64 KiB
        /// 单个条目的备注上限。留得很宽 —— 私钥正文、恢复码都放得下。
        const MAX_NOTES: usize = 1 << 20; // 1 MiB

        if self.name.trim().is_empty() {
            return Err(Error::Invalid("条目名称不能为空"));
        }
        if self.name.len() > 512 {
            return Err(Error::Invalid("条目名称超过 512 字节"));
        }
        if self.id.is_empty() || self.id.len() > 64 {
            return Err(Error::Invalid("条目 id 长度非法"));
        }
        if self.secret.len() > 1 << 20 {
            return Err(Error::Invalid("主秘密超过 1 MiB"));
        }
        if self.url.len() > 8 << 10 {
            return Err(Error::Invalid("网址超过 8 KiB"));
        }
        if self.notes.len() > MAX_NOTES {
            return Err(Error::Invalid("备注超过 1 MiB"));
        }
        if self.tags.len() > 128 {
            return Err(Error::Invalid("标签超过 128 个"));
        }
        if self.tags.iter().any(|t| t.len() > 128) {
            return Err(Error::Invalid("单个标签超过 128 字节"));
        }
        if self.fields.len() > 512 {
            return Err(Error::Invalid("自定义字段超过 512 个"));
        }
        for f in &self.fields {
            if f.name.trim().is_empty() || f.name.len() > 128 {
                return Err(Error::Invalid("自定义字段名称为空或超过 128 字节"));
            }
            if f.value.len() > MAX_FIELD_VALUE {
                return Err(Error::Invalid("自定义字段值超过 64 KiB"));
            }
        }
        Ok(())
    }

    /// 是否已过期（相对给定时间戳）。
    #[must_use]
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at > 0 && self.expires_at <= now
    }
}

/// 把条目摘要成一个「索引项」，去掉所有敏感内容。
///
/// 索引常驻内存，所以它**绝不能**包含 `secret` / 敏感 `Field.value`。
/// 这一条是硬约束，有单测守着。
///
/// ## 为什么还要两份小写副本
///
/// 搜索每次击键都要在**全部**条目上做子串匹配。如果每次现场 `to_lowercase()`，
/// 一万条条目就是每次击键上万次堆分配 —— 实测这一项比正餐还贵。
/// 所以名称/用户名/网址在**建索引时**各算一次小写版本，存进 `IndexItem`。
///
/// 代价是索引占内存约 ×1.7，换来的是搜索快 10 倍以上。这个交换在
/// 桌面端永远值得。`needle`（查询串）本身仍然每次小写，那只有一个。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexItem {
    /// 条目 id。
    pub id: String,
    /// 类型码。
    pub kind: u8,
    /// 名称（原样，UI 显示用）。
    pub name: String,
    /// 名称的小写副本（搜索用）。它会随索引段一起加密落盘，见 FORMAT.md §5.1。
    pub lower_name: String,
    /// 用户名（原样）。
    pub username: String,
    /// 用户名的小写副本。
    pub lower_username: String,
    /// 网址（原样）。
    pub url: String,
    /// 网址的小写副本。
    pub lower_url: String,
    /// 标签 + 各自的小写副本，`(原样, 小写)`。
    pub tags: Vec<(String, String)>,
    /// 最后修改时间。
    pub updated_at: i64,
    /// 使用次数。
    pub use_count: u32,
    /// 最后使用时间。
    pub last_used_at: i64,
    /// 过期时间。
    pub expires_at: i64,
}

impl IndexItem {
    /// 标签原文列表。UI 与序列化用。
    #[must_use]
    pub fn tag_names(&self) -> Vec<&str> {
        self.tags.iter().map(|(t, _)| t.as_str()).collect()
    }

    /// 是否带某个标签（大小写不敏感）。
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        let lower = tag.to_lowercase();
        self.tags.iter().any(|(_, l)| *l == lower)
    }

    /// 快速否决：`needle`（已小写化的 UTF-8 字节）是否在某个可搜索字段里出现。
    ///
    /// 这是搜索热路径的第一道闸。它只做子串查找，**不打分、不分配**。
    ///
    /// 覆盖面刻意做全：名称/用户名/网址/标签的子串，**外加名称的子序列**。
    /// 为什么把子序列也算进来：如果只在子串这一层放行，`ghb` 这类模糊查询
    /// 会在预算阶段被全额丢弃，后面的打分就永远看不到它们；而真正的候选
    /// （命中 `github` 的条目）也要在这里就被认出来，才能进入 Top-K 竞争。
    /// 代价是这一层多一次线性扫描 —— 实测比「先放行再打分再否决」便宜得多，
    /// 因为省掉了重复的 prefix/starts_with 判断。
    ///
    /// ASCII needle 走大小写不敏感比较（省一次小写化）；
    /// 非 ASCII 直接对已小写的副本做普通字节窗口比较。
    #[must_use]
    pub fn matches_bytes(&self, needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        let ascii = needle.is_ascii();

        let hit = |hay: &str| -> bool {
            if ascii {
                hay.len() >= needle.len() && contains_ascii_ci_fast(hay.as_bytes(), needle)
            } else {
                hay.as_bytes().windows(needle.len()).any(|w| w == needle)
            }
        };

        hit(&self.lower_name)
            || hit(&self.lower_username)
            || hit(&self.lower_url)
            || self.tags.iter().any(|(_, t)| hit(t))
            // 子序列只对 ASCII needle 做。CJK 走子序列没有实际意义
            // （用户不会用「银行」的子序列去找东西），而这一步在中文查询下
            // 每个条目都要扫一遍名称，实测是中文场景最大的一笔开销。
            || (ascii && is_subsequence_bytes(needle, self.lower_name.as_bytes()))
    }

    /// 预算上界：这条最多能拿多少分（不含热度扣减）。用来做「够不够进窗口」的判断。
    ///
    /// 逻辑很简单：名称完全相等 → 0；前缀 → 10；子串 → 20；
    /// 标签/用户名/网址子串 → 30/40/50；只有子序列 → 60。
    /// 抢跑阶段拿这个值跟窗口当前最差分比，落后就直接丢，不做完整打分。
    #[must_use]
    pub fn best_possible_score(&self, needle: &[u8], needle_str: &str) -> u32 {
        let name = self.lower_name.as_str();
        if name == needle_str {
            return 0;
        }
        if name.starts_with(needle_str) {
            return 10;
        }
        let ascii = needle.is_ascii();
        let hit = |hay: &str| -> bool {
            if ascii {
                hay.len() >= needle.len() && contains_ascii_ci_fast(hay.as_bytes(), needle)
            } else {
                hay.as_bytes().windows(needle.len()).any(|w| w == needle)
            }
        };
        if hit(&self.lower_name) {
            return 20;
        }
        if self.tags.iter().any(|(_, t)| hit(t)) {
            return 30;
        }
        if hit(&self.lower_username) {
            return 40;
        }
        if hit(&self.lower_url) {
            return 50;
        }
        60
    }
}

/// `needle` 是否为 `hay` 的子序列（大小写不敏感，needle 须已小写）。
#[must_use]
pub fn is_subsequence_bytes(needle: &[u8], hay: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    let mut ni = 0usize;
    for &b in hay {
        if b.to_ascii_lowercase() == needle[ni] {
            ni += 1;
            if ni == needle.len() {
                return true;
            }
        }
    }
    false
}

/// ASCII 大小写不敏感子串查找（needle 必须已小写）。
///
/// 用首字节锚定 + 首字节小写比较，比逐段 `to_ascii_lowercase` 展开快一截。
/// 这里刻意不做 Boyer-Moore：needle 普遍很短（1~8 字节），预处理不划算。
#[must_use]
pub fn contains_ascii_ci_fast(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    let first = needle[0];
    let first_upper = first.to_ascii_uppercase();
    let end = hay.len() - needle.len();
    let mut start = 0usize;
    while start <= end {
        let b = hay[start];
        if (b == first || b == first_upper)
            && hay[start..start + needle.len()]
                .iter()
                .zip(needle)
                .all(|(h, n)| h.to_ascii_lowercase() == *n)
        {
            return true;
        }
        start += 1;
    }
    false
}

impl From<&Entry> for IndexItem {
    fn from(e: &Entry) -> Self {
        Self {
            id: e.id.clone(),
            kind: e.kind.code(),
            lower_name: e.name.to_lowercase(),
            lower_username: e.username.to_lowercase(),
            lower_url: e.url.to_lowercase(),
            name: e.name.clone(),
            username: e.username.clone(),
            url: e.url.clone(),
            tags: e
                .tags
                .iter()
                .map(|t| (t.clone(), t.to_lowercase()))
                .collect(),
            updated_at: e.updated_at,
            use_count: e.use_count,
            last_used_at: e.last_used_at,
            expires_at: e.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    // 测试里 unwrap 是正常写法：出错就该 panic，不需要优雅降级。
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn sample() -> Entry {
        Entry {
            id: "0123456789abcdef".into(),
            kind: EntryKind::ApiKey,
            name: "OpenAI".into(),
            username: "team-prod".into(),
            secret: "sk-xxxx".into(),
            url: "https://api.openai.com".into(),
            fields: vec![Field::secret("org", "org-123")],
            tags: vec!["api".into(), "prod".into()],
            notes: "轮换周期 90 天".into(),
            created_at: 1,
            updated_at: 2,
            expires_at: 0,
            use_count: 3,
            last_used_at: 2,
        }
    }

    #[test]
    fn index_never_carries_secrets() {
        let e = sample();
        let idx = IndexItem::from(&e);
        let json = serde_json::to_string(&idx).unwrap();
        assert!(!json.contains("sk-xxxx"));
        assert!(!json.contains("org-123"));
    }

    #[test]
    fn kind_code_roundtrip() {
        for k in [
            EntryKind::Login,
            EntryKind::ApiKey,
            EntryKind::Note,
            EntryKind::Card,
            EntryKind::Credential,
        ] {
            assert_eq!(EntryKind::from_code(k.code()), Some(k));
        }
    }

    #[test]
    fn validate_rejects_empty_name() {
        let mut e = sample();
        e.name = "  ".into();
        assert!(e.validate().is_err());
    }

    /// 上界必须真的挡住 —— 这些字段都能从 IPC 和导入文件进来。
    #[test]
    fn validate_bounds_every_big_field() {
        let e = sample();
        assert!(e.validate().is_ok());

        let mut e2 = sample();
        e2.notes = "x".repeat((1 << 20) + 1);
        assert!(e2.validate().is_err(), "备注 1 MiB 上限");

        let mut e3 = sample();
        e3.fields = vec![Field::plain("f", "y".repeat((64 << 10) + 1))];
        assert!(e3.validate().is_err(), "字段值 64 KiB 上限");

        let mut e4 = sample();
        e4.fields = vec![Field::plain("", "v")];
        assert!(e4.validate().is_err(), "字段名不能为空");

        let mut e5 = sample();
        e5.tags = vec!["t".repeat(129)];
        assert!(e5.validate().is_err(), "单个标签 128 字节上限");

        let mut e6 = sample();
        e6.url = "u".repeat((8 << 10) + 1);
        assert!(e6.validate().is_err(), "网址 8 KiB 上限");
    }

    #[test]
    fn expiry() {
        let mut e = sample();
        e.expires_at = 100;
        assert!(e.is_expired(101));
        assert!(!e.is_expired(99));
        e.expires_at = 0;
        assert!(!e.is_expired(i64::MAX));
    }
}
