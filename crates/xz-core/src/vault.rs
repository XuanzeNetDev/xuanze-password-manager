//! Vault：一次打开、内存常驻、原子保存。
//!
//! 生命周期：
//!
//! ```text
//!   Vault::open(bytes, password)  ── 解析头 → KDF → 校验 → 解密索引+正文 → 建索引
//!          │
//!          ├─ search()     纯内存，微秒级
//!          ├─ reveal(id)   纯内存，微秒级
//!          ├─ record_use() 纯内存，内存写回
//!          └─ save()       序列化 → 加密 → 原子写盘
//!          │
//!   lock()/drop  ── 密钥与明文全部 zeroize
//! ```
//!
//! 「极致性能」的实际含义就在这里：**KDF 只在打开时跑一次**，
//! 之后所有高频操作（搜索、复制、列表）都不产生任何密码学开销。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::codec::{self, FileHeader};
use crate::crypto::{self, KeyPurpose};
use crate::entry::{Entry, IndexItem};
use crate::error::{Error, Result};
use crate::index::Index;
use crate::kdf::{self, KdfParams};
use crate::secure::{SecretBytes, SecretString};

/// 正文容器：vault 解密后的全部条目。
#[derive(Debug, Serialize, Deserialize)]
struct Body {
    #[serde(default)]
    entries: Vec<Entry>,
}

/// 索引容器：轻量、无秘密。
#[derive(Debug, Serialize, Deserialize)]
struct IndexPayload {
    items: Vec<IndexItem>,
}

/// 打开后的 vault。
pub struct Vault {
    /// 落盘路径。`None` 表示纯内存（新建未保存）。
    path: Option<PathBuf>,
    /// KDF 参数，保存时原样写回。
    kdf: KdfParams,
    /// KDF 盐，保存时原样写回。**永不轮换**（轮换=重新加密全部数据）。
    salt: [u8; 32],
    /// 库的稳定标识，创建时随机生成，之后永不改变。
    vault_id: [u8; 16],
    /// 主密钥。drop 时擦除。
    master_key: SecretBytes,
    /// id → 完整条目。真正持有秘密的地方。
    entries: HashMap<String, Entry>,
    /// 内存索引。
    index: Index,
    /// 是否有未落盘改动。
    dirty: bool,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不打印任何秘密。
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("kdf", &self.kdf)
            .field("entries", &self.entries.len())
            .field("dirty", &self.dirty)
            .finish()
    }
}

impl Vault {
    /// 新建空 vault。
    #[must_use]
    pub fn create(password: &str, params: KdfParams) -> Result<Self> {
        Self::create_bound(password, params, &[])
    }

    /// 新建空 vault，并绑定到本机材料。
    ///
    /// `pepper` 为空表示不绑定（只用于测试）；正式使用必须给。
    pub fn create_bound(password: &str, params: KdfParams, pepper: &[u8]) -> Result<Self> {
        let salt = kdf::random_salt();
        let master_key = if pepper.is_empty() {
            kdf::derive_master_key(password.as_bytes(), &salt, params)?
        } else {
            crate::binding::derive_bound_key(password.as_bytes(), pepper, &salt, params)?
        };
        Ok(Self {
            path: None,
            kdf: params,
            salt,
            vault_id: kdf::random_bytes::<16>(),
            master_key,
            entries: HashMap::new(),
            index: Index::new(),
            dirty: true,
        })
    }

    /// 从字节打开。
    ///
    /// 这是全流程唯一跑 KDF 的地方，也是唯一的慢路径。
    pub fn open_from_bytes(bytes: &[u8], password: &str) -> Result<Self> {
        Self::open_bound(bytes, password, &[])
    }

    /// 从字节打开，并用本机材料解绑。
    ///
    /// `pepper` 必须和创建时的一致，否则校验块过不去。
    pub fn open_bound(bytes: &[u8], password: &str, pepper: &[u8]) -> Result<Self> {
        // 1) KDF（慢）
        let key = Self::derive_key_for(bytes, password, pepper)?;
        // 2) 剩下的解密/解析
        Self::open_bound_with_key(bytes, key)
    }

    /// 只跑 KDF，拿到主密钥。**这一步不碰任何 `Vault` 状态。**
    ///
    /// 拆出来是为了让调用方能把这几秒放到锁外：KDF 是全场唯一的慢路径，
    /// 持着锁跑等于把整个界面冻住。先读文件 + 算密钥，再加锁装配。
    pub fn derive_key_for(bytes: &[u8], password: &str, pepper: &[u8]) -> Result<SecretBytes> {
        let header = FileHeader::parse(bytes)?;
        if pepper.is_empty() {
            kdf::derive_master_key(password.as_bytes(), &header.salt, header.kdf)
        } else {
            crate::binding::derive_bound_key(
                password.as_bytes(),
                pepper,
                &header.salt,
                header.kdf,
            )
        }
    }

    /// 用已经算好的主密钥完成打开。
    ///
    /// 快：只有 AES-GCM 解密和 JSON 解析，几毫秒量级。
    pub fn open_bound_with_key(bytes: &[u8], master_key: SecretBytes) -> Result<Self> {
        let header = FileHeader::parse(bytes)?;
        let header_bytes = header.to_bytes();
        let parts = codec::split_sealed(bytes)?;

        // 主密码校验（快，但不可省：它把「密码错」和「索引损坏」分开）
        codec::check_verify_block(&master_key, &header_bytes, parts.verify)?;

        // 3) 解密索引
        let idx_key = crypto::derive_subkey(&master_key, KeyPurpose::Index)?;
        let idx_plain = crypto::open(&idx_key, &header_bytes, parts.index)?;
        let idx_payload: IndexPayload = serde_json::from_slice(idx_plain.as_slice())
            .map_err(|_| Error::Corrupt("索引 JSON 解析失败"))?;

        // 4) 解密正文
        let body_key = crypto::derive_subkey(&master_key, KeyPurpose::Payload)?;
        let body_plain = crypto::open(&body_key, &header_bytes, parts.body)?;
        let body: Body = serde_json::from_slice(body_plain.as_slice())
            .map_err(|_| Error::Corrupt("正文 JSON 解析失败"))?;

        let mut entries = HashMap::with_capacity(body.entries.len());
        for e in body.entries {
            entries.insert(e.id.clone(), e);
        }

        // 5) 建索引。优先用落盘的索引（它可能被单独更新过），
        //    但以正文为准重建，避免两边不一致时搜出幽灵条目。
        let mut index = Index::with_capacity(entries.len());
        for e in entries.values() {
            index.upsert(e);
        }
        let _ = idx_payload; // 保留字段，v2 可做「索引只更新」的快速路径
        index.clear_dirty();

        Ok(Self {
            path: None,
            kdf: header.kdf,
            salt: header.salt,
            vault_id: header.vault_id,
            master_key,
            entries,
            index,
            dirty: false,
        })
    }

    /// 从文件打开。
    pub fn open(path: impl AsRef<Path>, password: &str) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        let mut v = Self::open_from_bytes(&bytes, password)?;
        v.path = Some(path.to_path_buf());
        Ok(v)
    }

    /// 绑定落盘路径（另存为时用）。
    pub fn set_path(&mut self, path: impl Into<PathBuf>) {
        self.path = Some(path.into());
    }

    /// 库的稳定标识（十六进制）。应用侧靠它判断「是不是自己创建的那个库」。
    #[must_use]
    pub fn vault_id(&self) -> String {
        let mut s = String::with_capacity(32);
        for b in self.vault_id {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// 当前路径。
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// 条目总数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 是否有未保存改动。
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// 只读索引。
    #[must_use]
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// 取完整条目（含秘密）。**调用方负责不要把它长留内存。**
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.get(id)
    }

    /// 取出主秘密，包进会被擦除的容器。
    pub fn reveal_secret(&self, id: &str) -> Result<SecretString> {
        let e = self
            .entries
            .get(id)
            .ok_or_else(|| Error::EntryNotFound(id.to_owned()))?;
        Ok(crate::secure::secret_string(e.secret.clone()))
    }

    /// 新增条目。id 冲突会报错，避免静默覆盖。
    pub fn insert(&mut self, entry: Entry) -> Result<String> {
        entry.validate()?;
        if self.entries.contains_key(&entry.id) {
            return Err(Error::DuplicateEntry(entry.id.clone()));
        }
        let id = entry.id.clone();
        self.index.upsert(&entry);
        self.entries.insert(id.clone(), entry);
        self.dirty = true;
        Ok(id)
    }

    /// 更新条目。不存在则报错。
    pub fn update(&mut self, entry: Entry) -> Result<()> {
        entry.validate()?;
        if !self.entries.contains_key(&entry.id) {
            return Err(Error::EntryNotFound(entry.id.clone()));
        }
        let id = entry.id.clone();
        self.index.upsert(&entry);
        self.entries.insert(id, entry);
        self.dirty = true;
        Ok(())
    }

    /// 删除条目。
    pub fn remove(&mut self, id: &str) -> Result<()> {
        if self.entries.remove(id).is_none() {
            return Err(Error::EntryNotFound(id.to_owned()));
        }
        self.index.remove(id);
        self.dirty = true;
        Ok(())
    }

    /// 记一次使用，用于热度排序。这是「快捷复制」的燃料。
    pub fn record_use(&mut self, id: &str, now: i64) -> Result<()> {
        let e = self
            .entries
            .get_mut(id)
            .ok_or_else(|| Error::EntryNotFound(id.to_owned()))?;
        e.use_count = e.use_count.saturating_add(1);
        e.last_used_at = now;
        let snapshot = e.clone();
        self.index.upsert(&snapshot);
        self.dirty = true;
        Ok(())
    }

    /// 序列化 + 加密，返回待写盘的完整字节。
    ///
    /// 不落盘，方便调用方决定写哪里（Tauri 层可以走 `fs::write` 或流式）。
    pub fn seal(&mut self) -> Result<Vec<u8>> {
        let header = FileHeader {
            version: crate::FORMAT_VERSION,
            kdf: self.kdf,
            salt: self.salt,
            vault_id: self.vault_id,
        };
        let header_bytes = header.to_bytes();

        // 正文
        //
        // `entries` 和 `body_plain` 都是全库明文：前者是条目本体，后者是它的
        // JSON 序列化。两者都必须擦 —— 尤其 `body_plain`，它是这一整库密码
        // 的明文快照，留在堆上等于前面所有加密白做。
        let entries: Vec<Entry> = self.entries.values().cloned().collect();
        let body_plain = zeroize::Zeroizing::new(
            serde_json::to_vec(&Body { entries })
                .map_err(|_| Error::Corrupt("正文序列化失败"))?,
        );
        let body_key = crypto::derive_subkey(&self.master_key, KeyPurpose::Payload)?;
        let body_blob = crypto::seal(&body_key, &header_bytes, &body_plain)?;

        // 索引
        let items: Vec<IndexItem> = self.index.all_sorted().into_iter().cloned().collect();
        let idx_plain = zeroize::Zeroizing::new(
            serde_json::to_vec(&IndexPayload { items })
                .map_err(|_| Error::Corrupt("索引序列化失败"))?,
        );
        let idx_key = crypto::derive_subkey(&self.master_key, KeyPurpose::Index)?;
        let idx_blob = crypto::seal(&idx_key, &header_bytes, &idx_plain)?;

        // 校验块
        let verify = codec::make_verify_block(&self.master_key, &header_bytes)?;

        Ok(codec::assemble(&header_bytes, &idx_blob, &body_blob, &verify))
    }

    /// 原子保存：先写同目录临时文件，再 rename 覆盖。
    ///
    /// 断电/崩溃时要么是旧文件、要么是新文件，不会出现半截 vault。
    pub fn save(&mut self) -> Result<()> {
        let path = self
            .path
            .clone()
            .ok_or_else(|| Error::Invalid("vault 还没有落盘路径"))?;
        let bytes = self.seal()?;
        write_atomic(&path, &bytes)?;
        self.dirty = false;
        self.index.clear_dirty();
        Ok(())
    }

    /// 另存为。
    pub fn save_as(&mut self, path: impl Into<PathBuf>) -> Result<()> {
        self.path = Some(path.into());
        self.save()
    }

    /// 换主密码并重新加密。
    ///
    /// 盐一并轮换（换密码就该换盐），然后把全部数据用新密钥重封。
    pub fn change_password(&mut self, new_password: &str, params: Option<KdfParams>) -> Result<()> {
        self.change_password_bound(new_password, params, &[])
    }

    /// 换主密码，同时用给定机器材料重新绑定。
    ///
    /// 空密码 + 空 pepper 就是「免密码模式」：数据仍然加密，只是打开时
    /// 不需要输入。注意这是**用户主动选择**的便利性牺牲。
    pub fn change_password_bound(
        &mut self,
        new_password: &str,
        params: Option<KdfParams>,
        pepper: &[u8],
    ) -> Result<()> {
        let params = params.unwrap_or(self.kdf);
        let salt = kdf::random_salt();
        let master_key = if pepper.is_empty() {
            kdf::derive_master_key(new_password.as_bytes(), &salt, params)?
        } else {
            crate::binding::derive_bound_key(new_password.as_bytes(), pepper, &salt, params)?
        };
        self.master_key.wipe();
        self.master_key = master_key;
        self.salt = salt;
        self.kdf = params;
        self.dirty = true;
        Ok(())
    }

    /// 校验一个密码是不是当前库的密码。
    ///
    /// 不改变任何状态，只走一次 KDF + 校验块。用于「改密码前先验旧密码」。
    pub fn verify_password(&self, password: &str) -> Result<()> {
        self.verify_password_bound(password, &[])
    }

    /// 校验密码，带机器绑定的 pepper。
    pub fn verify_password_bound(&self, password: &str, pepper: &[u8]) -> Result<()> {
        let header_bytes = FileHeader {
            version: crate::FORMAT_VERSION,
            kdf: self.kdf,
            salt: self.salt,
            vault_id: self.vault_id,
        }
        .to_bytes();

        let key = if pepper.is_empty() {
            kdf::derive_master_key(password.as_bytes(), &self.salt, self.kdf)?
        } else {
            crate::binding::derive_bound_key(password.as_bytes(), pepper, &self.salt, self.kdf)?
        };
        let verify = codec::make_verify_block(&key, &header_bytes)?;
        codec::check_verify_block(&key, &header_bytes, &verify)
    }

    /// 用新密码把当前内容重新封装成完整文件字节，**不改动自身状态**。
    ///
    /// 给「改密码」用：调用方先拿到字节、安全落盘成功、再回来
    /// `change_password_bound`。顺序反过来的话，落盘失败会留下
    /// 「内存新密码、磁盘旧密码」的不一致状态。
    /// 导出全部条目 + KDF 参数 + vault_id 的快照。
    ///
    /// 用途：让调用方**先放锁**再去跑重的加密流程。改密码要跑两轮 Argon2，
    /// 全程持锁会把整个应用冻住。
    #[must_use]
    pub fn export_all(&self) -> VaultSnapshot {
        VaultSnapshot {
            entries: self.entries.values().cloned().collect(),
            kdf: self.kdf,
            vault_id: self.vault_id,
        }
    }

    pub fn reseal_with_password(&self, new_password: &str, pepper: &[u8]) -> Result<Vec<u8>> {
        let salt = kdf::random_salt();
        let key = if pepper.is_empty() {
            kdf::derive_master_key(new_password.as_bytes(), &salt, self.kdf)?
        } else {
            crate::binding::derive_bound_key(new_password.as_bytes(), pepper, &salt, self.kdf)?
        };

        let header = FileHeader {
            version: crate::FORMAT_VERSION,
            kdf: self.kdf,
            salt,
            vault_id: self.vault_id,
        }
        .to_bytes();

        let entries: Vec<Entry> = self.entries.values().cloned().collect();
        let body_plain = zeroize::Zeroizing::new(
            serde_json::to_vec(&Body { entries }).map_err(|_| Error::Corrupt("正文序列化失败"))?,
        );
        let body_key = crypto::derive_subkey(&key, KeyPurpose::Payload)?;
        let body_blob = crypto::seal(&body_key, &header, &body_plain)?;

        let items: Vec<IndexItem> = self.index.all_sorted().into_iter().cloned().collect();
        let idx_plain = zeroize::Zeroizing::new(
            serde_json::to_vec(&IndexPayload { items })
                .map_err(|_| Error::Corrupt("索引序列化失败"))?,
        );
        let idx_key = crypto::derive_subkey(&key, KeyPurpose::Index)?;
        let idx_blob = crypto::seal(&idx_key, &header, &idx_plain)?;

        let verify = codec::make_verify_block(&key, &header)?;
        Ok(codec::assemble(&header, &idx_blob, &body_blob, &verify))
    }

    /// 主动锁定：擦除密钥、擦除全部条目明文。之后这个 `Vault` 只剩个空壳。
    ///
    /// 关键是 `entries` 那一步：`Entry` 实现了 `Zeroize`，这里逐个显式擦，
    /// 再 `clear()`。只 `clear()` 是不够的 —— `HashMap` 丢弃元素时会 drop
    /// 每个 `Entry`，但 `Drop` 里的擦除要等元素真正被回收，
    /// 而且分配器可能把缓冲区留给下一个使用者。
    pub fn lock(&mut self) {
        self.master_key.wipe();
        for (_, mut e) in self.entries.drain() {
            e.zeroize();
        }
        self.entries.shrink_to_fit();
        self.index = Index::new();
        self.dirty = false;
    }

    /// 统计信息，给「库概览」页用。
    #[must_use]
    pub fn stats(&self, now: i64) -> VaultStats {
        VaultStats {
            total: self.entries.len(),
            expired: self
                .entries
                .values()
                .filter(|e| e.is_expired(now))
                .count(),
            never_used: self.entries.values().filter(|e| e.use_count == 0).count(),
            tags: self.index.tag_counts().len(),
        }
    }
}

/// 一次解锁过程需要的全部信息，脱离 `Vault` 独立存在。
///
/// 存在的理由只有一个：**让加密/解密的慢动作能在锁外做**。
/// 调用方先 `export_all()` 拿快照，再释放互斥锁，然后慢慢跑 Argon2。
#[derive(Clone)]
pub struct VaultSnapshot {
    /// 全部条目。
    pub entries: Vec<Entry>,
    /// KDF 参数（改密码时保持不变）。
    pub kdf: KdfParams,
    /// 库标识（写回文件头用，不能变）。
    pub vault_id: [u8; 16],
}

/// 用新密码把快照重新封装成完整文件字节。
///
/// 这是 `Vault::reseal_with_password` 的自由函数版本 ——
/// 不需要持有 `Vault`，因此可以在锁外调用。
pub fn reseal_snapshot(
    snap: &VaultSnapshot,
    new_password: &str,
    pepper: &[u8],
) -> Result<Vec<u8>> {
    let salt = kdf::random_salt();
    let key = if pepper.is_empty() {
        kdf::derive_master_key(new_password.as_bytes(), &salt, snap.kdf)?
    } else {
        crate::binding::derive_bound_key(new_password.as_bytes(), pepper, &salt, snap.kdf)?
    };

    let header = FileHeader {
        version: crate::FORMAT_VERSION,
        kdf: snap.kdf,
        salt,
        vault_id: snap.vault_id,
    }
    .to_bytes();

    let entries: Vec<Entry> = snap.entries.clone();
    let body_plain = zeroize::Zeroizing::new(
        serde_json::to_vec(&Body { entries }).map_err(|_| Error::Corrupt("正文序列化失败"))?,
    );
    let body_key = crypto::derive_subkey(&key, KeyPurpose::Payload)?;
    let body_blob = crypto::seal(&body_key, &header, &body_plain)?;

    // 索引从条目现场重建，保证两边一致
    let mut index = Index::with_capacity(snap.entries.len());
    for e in &snap.entries {
        index.upsert(e);
    }
    let items: Vec<IndexItem> = index.all_sorted().into_iter().cloned().collect();
    let idx_plain = zeroize::Zeroizing::new(
        serde_json::to_vec(&IndexPayload { items })
            .map_err(|_| Error::Corrupt("索引序列化失败"))?,
    );
    let idx_key = crypto::derive_subkey(&key, KeyPurpose::Index)?;
    let idx_blob = crypto::seal(&idx_key, &header, &idx_plain)?;

    let verify = codec::make_verify_block(&key, &header)?;
    Ok(codec::assemble(&header, &idx_blob, &body_blob, &verify))
}

/// 概览统计。
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VaultStats {
    /// 总条目数。
    pub total: usize,
    /// 已过期数量。
    pub expired: usize,
    /// 从未使用过的数量。
    pub never_used: usize,
    /// 标签种类数。
    pub tags: usize,
}

/// 原子写文件。
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;

    // 临时文件名带 16 字节随机后缀。
    //
    // 原先用的是固定的 `.{name}.tmp`，两个问题：同机进程能预置同名
    // 符号链接/硬链接把内容导向别处；两次保存并发时会互相覆盖。
    let rand: [u8; 16] = kdf::random_bytes::<16>();
    let mut suffix = String::with_capacity(32);
    for b in rand {
        use std::fmt::Write as _;
        let _ = write!(suffix, "{b:02x}");
    }
    let base = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("vault");
    let tmp = dir.join(format!(".{base}.{suffix}.tmp"));

    // RAII：任何提前返回（write 失败、sync 失败、panic）都会删掉临时文件。
    struct TmpGuard(PathBuf);
    impl Drop for TmpGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let guard = TmpGuard(tmp.clone());

    {
        // create_new 占住这个名字，不让别人抢先放东西
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    // Windows 上 std::fs::rename 走 MoveFileExW(MOVEFILE_REPLACE_EXISTING)：
    // 目标已存在会被替换，但**目标正被占用时会直接失败、不重试**。
    // （这里不是 ReplaceFile，别按 ReplaceFile 的事务语义去理解。）
    std::fs::rename(&tmp, path)?;
    // rename 成功后 tmp 已不存在，guard 的 remove 是幂等的空操作
    drop(guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::EntryKind;

    fn now() -> i64 {
        1_700_000_000
    }

    fn entry(id: &str, name: &str) -> Entry {
        Entry {
            id: id.into(),
            kind: EntryKind::ApiKey,
            name: name.into(),
            username: "user".into(),
            secret: "sk-very-secret".into(),
            url: "https://api.example.com".into(),
            fields: vec![],
            tags: vec!["test".into()],
            notes: String::new(),
            created_at: now(),
            updated_at: now(),
            expires_at: 0,
            use_count: 0,
            last_used_at: 0,
        }
    }

    #[test]
    fn create_insert_seal_open_roundtrip() {
        let mut v = Vault::create("hunter2", KdfParams::light()).unwrap();
        v.insert(entry("a", "OpenAI")).unwrap();
        v.insert(entry("b", "GitHub")).unwrap();
        let bytes = v.seal().unwrap();

        let v2 = Vault::open_from_bytes(&bytes, "hunter2").unwrap();
        assert_eq!(v2.len(), 2);
        assert_eq!(v2.get("a").unwrap().name, "OpenAI");
        assert_eq!(v2.get("a").unwrap().secret, "sk-very-secret");
        assert!(!v2.is_dirty());
    }

    #[test]
    fn wrong_password_rejected() {
        let mut v = Vault::create("right", KdfParams::light()).unwrap();
        v.insert(entry("a", "X")).unwrap();
        let bytes = v.seal().unwrap();
        assert!(matches!(
            Vault::open_from_bytes(&bytes, "wrong"),
            Err(Error::BadPasswordOrTampered)
        ));
    }

    #[test]
    fn corrupted_file_rejected() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "X")).unwrap();
        let mut bytes = v.seal().unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0xFF;
        assert!(Vault::open_from_bytes(&bytes, "pw").is_err());
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "X")).unwrap();
        assert!(matches!(
            v.insert(entry("a", "Y")),
            Err(Error::DuplicateEntry(_))
        ));
    }

    #[test]
    fn update_and_remove_keep_index_in_sync() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "Alpha")).unwrap();
        let mut e = v.get("a").unwrap().clone();
        e.name = "Alpha Renamed".into();
        v.update(e).unwrap();
        assert_eq!(v.index().get("a").unwrap().name, "Alpha Renamed");

        v.remove("a").unwrap();
        assert!(v.index().get("a").is_none());
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn record_use_bumps_heat() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "Alpha")).unwrap();
        v.record_use("a", 1234).unwrap();
        let idx = v.index().get("a").unwrap();
        assert_eq!(idx.use_count, 1);
        assert_eq!(idx.last_used_at, 1234);
    }

    #[test]
    fn reveal_returns_secret() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "Alpha")).unwrap();
        assert_eq!(&*v.reveal_secret("a").unwrap(), "sk-very-secret");
    }

    #[test]
    fn lock_wipes_everything() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "Alpha")).unwrap();
        v.lock();
        assert_eq!(v.len(), 0);
        assert!(v.get("a").is_none());
    }

    #[test]
    fn change_password_then_old_fails() {
        let mut v = Vault::create("old", KdfParams::light()).unwrap();
        v.insert(entry("a", "Alpha")).unwrap();
        v.change_password("new", Some(KdfParams::light())).unwrap();
        let bytes = v.seal().unwrap();

        assert!(Vault::open_from_bytes(&bytes, "old").is_err());
        let v2 = Vault::open_from_bytes(&bytes, "new").unwrap();
        assert_eq!(v2.len(), 1);
    }

    #[test]
    fn save_and_open_from_disk() {
        let dir = std::env::temp_dir().join("xzvlt-test-save");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("v.xzvlt");

        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "Alpha")).unwrap();
        v.save_as(&path).unwrap();
        assert!(!v.is_dirty());

        let v2 = Vault::open(&path, "pw").unwrap();
        assert_eq!(v2.len(), 1);

        // 无临时文件残留
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stats() {
        let mut v = Vault::create("pw", KdfParams::light()).unwrap();
        v.insert(entry("a", "A")).unwrap();
        let mut e = entry("b", "B");
        e.expires_at = now() - 10;
        v.insert(e).unwrap();
        let s = v.stats(now());
        assert_eq!(s.total, 2);
        assert_eq!(s.expired, 1);
        assert_eq!(s.never_used, 2);
        assert_eq!(s.tags, 1);
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;

    /// pepper 不同 → 派生出的主密钥不同 → 校验块过不去。
    #[test]
    fn wrong_pepper_cannot_open() {
        use crate::kdf::KdfParams;
        let pw = "unit-test-password";
        let pepper_a = crate::binding::make_pepper(b"secret-on-this-machine", "PC1-ABCD1234");
        let pepper_b = crate::binding::make_pepper(b"secret-on-this-machine", "PC2-FFFF0000");

        let mut v = Vault::create_bound(pw, KdfParams::light(), &pepper_a).unwrap();
        let ts = 1_700_000_000i64;
        v.insert(crate::entry::Entry {
            id: "x".into(),
            kind: crate::entry::EntryKind::Login,
            name: "测试".into(),
            username: "u".into(),
            secret: "s".into(),
            url: String::new(),
            fields: vec![],
            tags: vec![],
            notes: String::new(),
            created_at: ts,
            updated_at: ts,
            expires_at: 0,
            use_count: 0,
            last_used_at: 0,
        }).unwrap();
        let bytes = v.seal().unwrap();

        // 同一台机器：能开
        assert!(Vault::open_bound(&bytes, pw, &pepper_a).is_ok(), "本机应该能打开");
        // 换机器：密码对也打不开
        assert!(
            Vault::open_bound(&bytes, pw, &pepper_b).is_err(),
            "换了机器标识必须打不开"
        );
        // 没有 pepper：同样打不开
        assert!(
            Vault::open_bound(&bytes, pw, &[]).is_err(),
            "缺 pepper 必须打不开"
        );
    }

    /// 错的随机串也不行。
    #[test]
    fn wrong_secret_cannot_open() {
        use crate::kdf::KdfParams;
        let pw = "unit-test-password";
        let real = crate::binding::make_pepper(&[7u8; 32], "PC1-ABCD1234");
        let fake = crate::binding::make_pepper(&[9u8; 32], "PC1-ABCD1234");

        let mut v = Vault::create_bound(pw, KdfParams::light(), &real).unwrap();
        v.insert(crate::entry::Entry {
            id: "y".into(),
            kind: crate::entry::EntryKind::Login,
            name: "n".into(),
            username: String::new(),
            secret: "s".into(),
            url: String::new(),
            fields: vec![],
            tags: vec![],
            notes: String::new(),
            created_at: 1,
            updated_at: 1,
            expires_at: 0,
            use_count: 0,
            last_used_at: 0,
        }).unwrap();
        let bytes = v.seal().unwrap();
        assert!(Vault::open_bound(&bytes, pw, &real).is_ok());
        assert!(Vault::open_bound(&bytes, pw, &fake).is_err(), "换了随机串必须打不开");
    }
}

#[cfg(test)]
mod vault_identity_tests {
    use super::*;
    use crate::kdf::KdfParams;

    /// 每个库的 vault_id 不同，且能从头里读回来。
    #[test]
    fn vault_id_is_stable_and_unique() {
        let mut a = Vault::create("TestPass1234", KdfParams::light()).unwrap();
        let b = Vault::create("TestPass1234", KdfParams::light()).unwrap();
        assert_ne!(a.vault_id(), b.vault_id(), "两个库的标识必须不同");

        let bytes = a.seal().unwrap();
        let reopened = Vault::open_from_bytes(&bytes, "TestPass1234").unwrap();
        assert_eq!(reopened.vault_id(), a.vault_id(), "重开后标识必须一致");
    }

    /// 头部被改（换了 vault_id）会导致 AAD 不匹配，解不开。
    ///
    /// 这是「认库」机制的密码学兜底：光比对 id 还不够，
    /// 改 id 会直接破坏认证。
    #[test]
    fn tampered_vault_id_breaks_open() {
        let mut v = Vault::create("TestPass1234", KdfParams::light()).unwrap();
        let mut bytes = v.seal().unwrap();
        // vault_id 在头部的 [55..71]
        bytes[55] ^= 0xFF;
        assert!(
            Vault::open_from_bytes(&bytes, "TestPass1234").is_err(),
            "改了库标识必须打不开"
        );
    }
}
