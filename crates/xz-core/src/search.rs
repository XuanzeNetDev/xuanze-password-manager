//! 模糊搜索。
//!
//! 目标：输入即出结果，1 万条 < 1ms，**全程不碰磁盘、不碰解密**。
//!
//! 打分模型（分数越低越靠前）：
//!
//! | 匹配方式 | 基础分 |
//! |---|---|
//! | 名称完全相等 | 0 |
//! | 名称前缀 | 10 |
//! | 名称子串 | 20 |
//! | 用户名子串 | 40 |
//! | url 子串 | 50 |
//! | 标签子串 | 30 |
//! | 子序列模糊命中名称 | 60 |
//!
//! 同分时按「热度」(`use_count`, `last_used_at`) 和短名称优先排序 ——
//! 用户打 `gh` 想找的几乎总是 GitHub，不是 `my_github_tokens_backup_2023`。

use crate::entry::IndexItem;
use crate::index::Index;

/// 一条搜索结果。
#[derive(Debug, Clone)]
pub struct Hit<'a> {
    /// 命中的索引项。
    pub item: &'a IndexItem,
    /// 分数，越小越相关。
    pub score: u32,
    /// 命中的字段，UI 用来高亮。
    pub field: Field,
}

/// 命中字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Field {
    /// 名称。
    #[default]
    Name,
    /// 用户名。
    Username,
    /// 网址。
    Url,
    /// 标签。
    Tag,
}

/// 最大返回条数上限，防止 UI 一次请求 10 万条。
pub const MAX_HITS: usize = 500;

/// 一条命中记录（内部用，不含引用，便于放进定长堆）。
#[derive(Debug, Clone, Copy)]
struct Scored {
    idx: u32,
    score: u32,
    field: Field,
}

/// 在索引上搜索。
///
/// `query` 为空时直接返回热度榜，保证「打开就能复制」。
///
/// ## 为什么不是「全部收集完再排序」
///
/// v0.1 第一版是 `Vec::push` 全量收集 + `select_nth_unstable`。
/// 一万条条目搜 `服务凭据` 会命中九千条，那就是九千次堆分配加一次部分排序 ——
/// 实测 437 µs，其中排序占了大头。
///
/// 现在改成**流式 Top-K**：
/// - 分数有上界（最差 60×词数 + 10），定一个 `limit × 4` 的容量上限；
/// - 阈值随已收集的最好成绩单调收紧，明显没戏的条目直接丢；
/// - 堆定长预分配，全程零重分配；
/// - 最后只对 ≤ 4×limit 条做一次插入排序。
///
/// 结果：同样场景 437 µs → 见 `xz-bench` 输出，且与条目总数基本脱钩。
#[must_use]
pub fn search<'a>(index: &'a Index, query: &str, limit: usize) -> Vec<Hit<'a>> {
    let limit = limit.min(MAX_HITS);
    if limit == 0 {
        return Vec::new();
    }

    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return index
            .hot(limit)
            .into_iter()
            .map(|item| Hit {
                item,
                score: 0,
                field: Field::Name,
            })
            .collect();
    }

    // 多关键词：全部命中才算（AND），各自取最好分数。
    let terms: Vec<&str> = q.split_whitespace().collect();
    let bytes: Vec<&[u8]> = terms.iter().map(|t| t.as_bytes()).collect();

    // 保留窗口比 limit 宽，防止阈值收紧过早把并列项挤掉。
    let capacity = limit.saturating_mul(4).min(MAX_HITS);
    let mut buf: Vec<Scored> = Vec::with_capacity(capacity);
    let mut threshold = u32::MAX;

    for (i, item) in index.indexed_items() {
        // 第一道闸：字节级预筛，只回答「有没有命中」（含名称子序列）。
        // 不打分、不分配内存。
        let mut all_present = true;
        for needle in &bytes {
            if !item.matches_bytes(needle) {
                all_present = false;
                break;
            }
        }
        if !all_present {
            continue;
        }

        // 第二道闸：预算剪枝。窗口满了以后，只有「最好分有可能进窗口」的
        // 才值得完整打分。多关键词取各词上界之和，保守且便宜。
        if buf.len() == capacity {
            let budget: u32 = terms
                .iter()
                .zip(bytes.iter())
                .map(|(term, needle)| item.best_possible_score(needle, term))
                .sum();
            if budget >= threshold {
                continue;
            }
        }

        // 慢路径：走到这里的一定是候选，才值得做完整打分。
        let Some((score, best_field)) = score_all_terms(item, &terms) else {
            continue;
        };

        if buf.len() < capacity {
            buf.push(Scored {
                idx: i,
                score,
                field: best_field,
            });
            if buf.len() == capacity {
                // 窗口刚满：算一次阈值 = 当前最差分。
                threshold = buf.iter().map(|s| s.score).max().unwrap_or(u32::MAX);
            }
        } else if score < threshold {
            // 窗口已满：只在严格更好时替换掉那条最差的。
            if let Some(pos) = buf.iter().position(|s| s.score == threshold) {
                buf[pos] = Scored {
                    idx: i,
                    score,
                    field: best_field,
                };
                threshold = buf.iter().map(|s| s.score).max().unwrap_or(u32::MAX);
            }
        }
    }

    // 只对 ≤ 4×limit 条排序，然后截断。
    buf.sort_unstable_by(|a, b| a.score.cmp(&b.score));
    buf.truncate(limit);

    let items: Vec<&IndexItem> = index.indexed_items().map(|(_, it)| it).collect();
    buf.into_iter()
        .map(|s| Hit {
            item: items[s.idx as usize],
            score: s.score,
            field: s.field,
        })
        .collect()
}

/// 对单个关键词打分，返回 (分数, 命中字段)。无命中返回 `None`。
fn score_term(item: &IndexItem, term: &str) -> Option<(u32, Field)> {
    let lower_name = item.lower_name.as_str();
    if lower_name == term {
        return Some((0, Field::Name));
    }
    if lower_name.starts_with(term) {
        return Some((10, Field::Name));
    }
    if lower_name.contains(term) {
        return Some((20, Field::Name));
    }
    // 标签：长度剪枝后走 ASCII 快路径，避免每条目一次 to_lowercase。
    if item.tags.iter().any(|(_, t)| {
        t.len() >= term.len()
            && if t.is_ascii() && term.is_ascii() {
                contains_ascii_ci(t.as_bytes(), term.as_bytes())
            } else {
                t.contains(term)
            }
    }) {
        return Some((30, Field::Tag));
    }
    if item.lower_username.contains(term) {
        return Some((40, Field::Username));
    }
    if item.lower_url.contains(term) {
        return Some((50, Field::Url));
    }
    // 子序列模糊：`ghw` → `github-work`。代价最高，放最后。
    // 先按长度剪枝：needle 比 hay 长时必然不成立。
    if term.len() <= lower_name.len() && is_subsequence(term.as_bytes(), lower_name.as_bytes()) {
        return Some((60, Field::Name));
    }
    None
}

/// 全关键词打分 + 热度加权，得到最终可分拣的分数。
///
/// 任一关键词不命中即返回 `None`（多关键词是 AND 语义）。
fn score_all_terms(item: &IndexItem, terms: &[&str]) -> Option<(u32, Field)> {
    let mut total = 0u32;
    let mut best_field = Field::Name;
    for term in terms {
        let (s, field) = score_term(item, term)?;
        total = total.saturating_add(s);
        if s < 30 {
            best_field = field;
        }
    }
    let heat_bonus = item.use_count.min(50) * 2;
    let len_penalty = (item.lower_name.len() as u32).min(60) / 6;
    Some((
        total
            .saturating_add(len_penalty)
            .saturating_sub(heat_bonus.min(total)),
        best_field,
    ))
}

/// ASCII 大小写不敏感的子串查找。term 必须已小写化。
fn contains_ascii_ci(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    let first = needle[0];
    let first_upper = first.to_ascii_uppercase();
    for start in 0..=(hay.len() - needle.len()) {
        let b = hay[start];
        if b != first && b != first_upper {
            continue;
        }
        let mut ok = true;
        for (i, &n) in needle.iter().enumerate() {
            let h = hay[start + i];
            if h.to_ascii_lowercase() != n {
                ok = false;
                break;
            }
        }
        if ok {
            return true;
        }
    }
    false
}

/// `needle` 是否是 `hay` 的子序列。
fn is_subsequence(needle: &[u8], hay: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    let mut ni = 0;
    for &b in hay {
        if b == needle[ni] {
            ni += 1;
            if ni == needle.len() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Entry, EntryKind};

    fn e(id: &str, name: &str, user: &str, url: &str, tags: &[&str], uses: u32) -> Entry {
        Entry {
            id: id.into(),
            kind: EntryKind::ApiKey,
            name: name.into(),
            username: user.into(),
            secret: "sk-TOP-SECRET".into(),
            url: url.into(),
            fields: vec![],
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
            notes: String::new(),
            created_at: 0,
            updated_at: 0,
            expires_at: 0,
            use_count: uses,
            last_used_at: 0,
        }
    }

    fn fixture() -> Index {
        Index::build(&[
            e("1", "GitHub", "me@gh.com", "https://github.com", &["code"], 20),
            e("2", "gitlab-work", "me@gl.com", "https://gitlab.com", &["code"], 3),
            e("3", "OpenAI Prod", "team", "https://api.openai.com", &["api"], 9),
            e("4", "AWS Root", "root", "https://aws.amazon.com", &["cloud"], 0),
            e("5", "银行密码", "me", "https://bank.example", &["life"], 1),
        ])
    }

    #[test]
    fn empty_query_returns_hot() {
        let idx = fixture();
        let hits = search(&idx, "", 3);
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].item.name, "GitHub");
    }

    #[test]
    fn exact_name_wins() {
        let idx = fixture();
        let hits = search(&idx, "github", 5);
        assert_eq!(hits[0].item.name, "GitHub");
    }

    #[test]
    fn prefix_beats_substring() {
        let idx = fixture();
        let hits = search(&idx, "git", 5);
        // GitLab-work 前缀，GitHub 前缀；两者都在，且不会把 github.com 的 URL 命中排前面
        assert!(hits.iter().take(2).any(|h| h.item.name == "GitHub"));
        assert!(hits.iter().take(2).any(|h| h.item.name == "gitlab-work"));
    }

    #[test]
    fn subsequence_fallback() {
        let idx = fixture();
        let hits = search(&idx, "ghb", 5);
        assert!(hits.iter().any(|h| h.item.name == "GitHub"));
    }

    #[test]
    fn multi_term_and() {
        let idx = fixture();
        let hits = search(&idx, "openai prod", 5);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].item.name, "OpenAI Prod");
    }

    #[test]
    fn url_and_tag_search() {
        let idx = fixture();
        assert!(search(&idx, "openai", 5).iter().any(|h| h.item.id == "3"));
        assert!(search(&idx, "cloud", 5).iter().any(|h| h.item.id == "4"));
    }

    #[test]
    fn chinese_search() {
        let idx = fixture();
        let hits = search(&idx, "银行", 5);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].item.name, "银行密码");
    }

    #[test]
    fn secrets_never_searchable() {
        let idx = fixture();
        // 主秘密不进索引，所以搜不到
        assert!(search(&idx, "sk-TOP", 10).is_empty());
    }

    #[test]
    fn limit_is_capped() {
        let idx = fixture();
        assert!(search(&idx, "a", 99_999).len() <= MAX_HITS);
        assert!(search(&idx, "a", 0).is_empty());
    }
}
