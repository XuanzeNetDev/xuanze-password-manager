//! 内存索引。
//!
//! 性能关键点：
//!
//! 1. **常驻内存的只有 [`IndexItem`]**，不含任何秘密。解密一次，之后所有
//!    列表、搜索、排序都在内存里跑，不再碰磁盘、不再碰 AES。
//! 2. **名称小写化一次缓存**，搜索时不做重复 `to_lowercase`。
//! 3. **按使用频率维护热度表**，`hot()` 是 O(k)，k = 请求条数。
//! 4. 支持增量更新（`upsert` / `remove`），改一条不用重建整个索引。

use std::collections::HashMap;

use crate::entry::{Entry, IndexItem};

/// 一条索引项的运行时包装。
///
/// 小写副本已经存进 [`IndexItem`] 本身，这里只保留 id → 下标映射，
/// 不再做二次缓存（v0.1 的实现曾经在这里再存一份小写串，纯属重复）。
#[derive(Debug, Clone)]
struct Cached {
    item: IndexItem,
}

impl Cached {
    fn new(item: IndexItem) -> Self {
        Self { item }
    }
}

/// 内存索引。
#[derive(Debug, Default)]
pub struct Index {
    items: Vec<Cached>,
    /// id → 在 `items` 中的下标。删除用 `swap_remove` 维护。
    by_id: HashMap<String, usize>,
    dirty: bool,
}

impl Index {
    /// 空索引。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 从条目列表一次性重建（打开 vault 时用）。
    #[must_use]
    pub fn build(entries: &[Entry]) -> Self {
        let mut idx = Self::with_capacity(entries.len());
        for e in entries {
            idx.insert_item(IndexItem::from(e));
        }
        idx.dirty = false;
        idx
    }

    /// 预分配。
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            items: Vec::with_capacity(n),
            by_id: HashMap::with_capacity(n),
            dirty: false,
        }
    }

    /// 条目数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// 自上次 `clear_dirty` 以来是否有改动。
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// 清除脏标记（保存成功后调用）。
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    fn insert_item(&mut self, item: IndexItem) {
        let cached = Cached::new(item);
        let id = cached.item.id.clone();
        if let Some(&pos) = self.by_id.get(&id) {
            self.items[pos] = cached;
        } else {
            self.by_id.insert(id, self.items.len());
            self.items.push(cached);
        }
        self.dirty = true;
    }

    /// 插入或更新一条（用完整条目，自动去掉秘密）。
    pub fn upsert(&mut self, entry: &Entry) {
        self.insert_item(IndexItem::from(entry));
    }

    /// 删除一条。返回是否真的删掉了。
    pub fn remove(&mut self, id: &str) -> bool {
        let Some(pos) = self.by_id.remove(id) else {
            return false;
        };
        self.items.swap_remove(pos);
        // swap_remove 把最后一个元素挪到了 pos，修正它在 map 里的下标。
        if let Some(moved) = self.items.get(pos) {
            self.by_id.insert(moved.item.id.clone(), pos);
        }
        self.dirty = true;
        true
    }

    /// 按 id 取索引项。
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&IndexItem> {
        self.by_id.get(id).map(|&p| &self.items[p].item)
    }

    /// 全部索引项，按名称排序。冷路径，UI 首次渲染用。
    #[must_use]
    pub fn all_sorted(&self) -> Vec<&IndexItem> {
        let mut v: Vec<&IndexItem> = self.items.iter().map(|c| &c.item).collect();
        v.sort_unstable_by_key(|a| a.name.to_lowercase());
        v
    }

    /// 热度榜：按 `use_count` 降序、`last_used_at` 降序，取前 `k` 条。
    ///
    /// 这是「快捷复制」的核心：用户按 Ctrl+Shift+1..9 就是取这里的前 9 条。
    #[must_use]
    pub fn hot(&self, k: usize) -> Vec<&IndexItem> {
        let mut v: Vec<&IndexItem> = self.items.iter().map(|c| &c.item).collect();
        // 部分排序比全排快；k 一般 ≤ 20，n 可能上万。
        if k < v.len() {
            v.select_nth_unstable_by(k - 1, |a, b| {
                b.use_count
                    .cmp(&a.use_count)
                    .then(b.last_used_at.cmp(&a.last_used_at))
            });
            v.truncate(k);
        }
        v.sort_unstable_by(|a, b| {
            b.use_count
                .cmp(&a.use_count)
                .then(b.last_used_at.cmp(&a.last_used_at))
        });
        v
    }

    /// 过期条目。
    #[must_use]
    pub fn expired(&self, now: i64) -> Vec<&IndexItem> {
        self.items
            .iter()
            .map(|c| &c.item)
            .filter(|i| i.expires_at > 0 && i.expires_at <= now)
            .collect()
    }

    /// 所有标签及其条目数，按数量降序。
    #[must_use]
    pub fn tag_counts(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for c in &self.items {
            for (t, _) in &c.item.tags {
                *counts.entry(t.as_str()).or_insert(0) += 1;
            }
        }
        let mut v: Vec<(String, usize)> =
            counts.into_iter().map(|(k, n)| (k.to_owned(), n)).collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    /// 内部用：给搜索模块访问索引项及其下标。
    pub(crate) fn indexed_items(&self) -> impl Iterator<Item = (u32, &IndexItem)> {
        self.items
            .iter()
            .enumerate()
            .map(|(i, c)| (i as u32, &c.item))
    }
}

#[cfg(test)]
mod tests {
    // 测试里 unwrap 是正常写法：出错就该 panic，不需要优雅降级。
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::entry::EntryKind;

    fn e(id: &str, name: &str, uses: u32) -> Entry {
        Entry {
            id: id.into(),
            kind: EntryKind::Login,
            name: name.into(),
            username: format!("{id}@example.com"),
            secret: "s".into(),
            url: "https://example.com".into(),
            fields: vec![],
            tags: vec!["t".into()],
            notes: String::new(),
            created_at: 0,
            updated_at: 0,
            expires_at: 0,
            use_count: uses,
            last_used_at: 0,
        }
    }

    #[test]
    fn build_and_lookup() {
        let idx = Index::build(&[e("a", "Alpha", 0), e("b", "Beta", 0)]);
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.get("a").unwrap().name, "Alpha");
        assert!(idx.get("zzz").is_none());
    }

    #[test]
    fn upsert_updates_in_place() {
        let mut idx = Index::build(&[e("a", "Alpha", 0)]);
        idx.upsert(&e("a", "Alpha2", 5));
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.get("a").unwrap().name, "Alpha2");
    }

    #[test]
    fn remove_fixes_swapped_index() {
        let mut idx = Index::build(&[e("a", "A", 0), e("b", "B", 0), e("c", "C", 0)]);
        assert!(idx.remove("a"));
        assert_eq!(idx.len(), 2);
        // c 被 swap 到 a 的位置，必须仍能查到
        assert_eq!(idx.get("c").unwrap().name, "C");
        assert_eq!(idx.get("b").unwrap().name, "B");
        assert!(!idx.remove("a"));
    }

    #[test]
    fn hot_returns_most_used() {
        let mut entries = Vec::new();
        for i in 0..100 {
            entries.push(e(&format!("id{i}"), &format!("n{i}"), i as u32));
        }
        let idx = Index::build(&entries);
        let hot = idx.hot(5);
        assert_eq!(hot.len(), 5);
        assert_eq!(hot[0].use_count, 99);
        assert_eq!(hot[4].use_count, 95);
    }

    #[test]
    fn hot_on_small_index() {
        let idx = Index::build(&[e("a", "A", 1)]);
        assert_eq!(idx.hot(10).len(), 1);
        let empty = Index::new();
        assert!(empty.hot(10).is_empty());
    }

    #[test]
    fn dirty_tracking() {
        let mut idx = Index::build(&[e("a", "A", 0)]);
        assert!(!idx.is_dirty());
        idx.upsert(&e("b", "B", 0));
        assert!(idx.is_dirty());
        idx.clear_dirty();
        assert!(!idx.is_dirty());
    }
}
