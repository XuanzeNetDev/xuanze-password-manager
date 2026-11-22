//! Tauri 命令层。
//!
//! 约定：
//! - 参数与返回值全部是 JSON 可序列化的扁平结构，前端零解析负担。
//! - **秘密只在 `entry_reveal` / `copy_*` 里出现**，且不常驻前端状态。
//! - 任何命令都会刷新 `last_activity`（除了状态查询，那不该算「在用」）。
//! - 错误统一转成字符串给前端直接显示，不暴露内部结构。

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::State;
use xz_core::entry::{Entry, EntryKind, Field};
use xz_core::kdf::KdfParams;
use xz_core::search;

use crate::clipboard;
use crate::AppState;

/// 剪贴板里的秘密存活时长。
///
/// 敏感内容（密码、密钥、私钥）短一些：目标用户是「复制完立刻去粘贴」，
/// 15 秒足够走完这个动作，多留一刻就多一分被别的程序读到的机会。
const SECRET_TTL: Duration = Duration::from_secs(15);

/// 非敏感内容的存活时长。
///
/// 账号、网址这类东西粘完可能还要再粘一两次，留得久一些更像正常剪贴板。
const PLAIN_TTL: Duration = Duration::from_secs(60);

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// 库状态快照，给前端渲染用。**不含任何秘密。**
#[derive(Debug, Serialize)]
pub struct VaultStatus {
    /// 是否已解锁。
    unlocked: bool,
    /// 当前 vault 文件路径。
    path: Option<String>,
    /// 是否有未保存改动。
    dirty: bool,
    /// 条目数。
    count: usize,
    /// 距离自动锁定还有多少秒。
    seconds_until_lock: Option<u64>,
}

/// 列表项（无秘密）。
#[derive(Debug, Serialize)]
pub struct ItemView {
    id: String,
    kind: u8,
    name: String,
    username: String,
    url: String,
    tags: Vec<String>,
    use_count: u32,
    last_used_at: i64,
    expires_at: i64,
    /// 是否已过期（相对当前时间）。
    expired: bool,
}

impl From<&xz_core::entry::IndexItem> for ItemView {
    fn from(i: &xz_core::entry::IndexItem) -> Self {
        let now = now_ts();
        Self {
            id: i.id.clone(),
            kind: i.kind,
            name: i.name.clone(),
            username: i.username.clone(),
            url: i.url.clone(),
            tags: i.tag_names().into_iter().map(str::to_owned).collect(),
            use_count: i.use_count,
            last_used_at: i.last_used_at,
            expires_at: i.expires_at,
            expired: i.expires_at > 0 && i.expires_at <= now,
        }
    }
}

/// 搜索结果项。
#[derive(Debug, Serialize)]
pub struct HitView {
    #[serde(flatten)]
    item: ItemView,
    /// 相关度分，越小越靠前。
    score: u32,
    /// 命中字段：name / username / url / tag。
    field: String,
}

/// 条目详情。**不含秘密**（秘密只能单独取）。
#[derive(Debug, Serialize)]
pub struct EntryView {
    id: String,
    kind: String,
    name: String,
    username: String,
    url: String,
    notes: String,
    tags: Vec<String>,
    fields: Vec<FieldView>,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
    use_count: u32,
    last_used_at: i64,
    /// 秘密的长度，用于 UI 显示占位圆点，不泄漏内容。
    secret_len: usize,
}

/// 自定义字段。敏感字段的 `value` 为空，需要单独取。
#[derive(Debug, Serialize)]
pub struct FieldView {
    name: String,
    /// 非敏感字段直接给值；敏感字段给空串。
    value: String,
    secret: bool,
}

/// 前端提交的条目（新增/修改）。
#[derive(Debug, Deserialize)]
pub struct EntryInput {
    /// 为空表示新增。
    #[serde(default)]
    id: String,
    kind: String,
    name: String,
    #[serde(default)]
    username: String,
    /// 空串且 `id` 非空时表示「保持原秘密不变」。
    #[serde(default)]
    secret: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    fields: Vec<FieldInput>,
    #[serde(default)]
    expires_at: i64,
}

/// 前端提交的自定义字段。
#[derive(Debug, Deserialize)]
pub struct FieldInput {
    name: String,
    value: String,
    secret: bool,
}

fn kind_from(s: &str) -> EntryKind {
    match s {
        "login" => EntryKind::Login,
        "note" => EntryKind::Note,
        "card" => EntryKind::Card,
        "credential" => EntryKind::Credential,
        _ => EntryKind::ApiKey,
    }
}

fn kind_to(k: EntryKind) -> &'static str {
    match k {
        EntryKind::Login => "login",
        EntryKind::ApiKey => "api_key",
        EntryKind::Note => "note",
        EntryKind::Card => "card",
        EntryKind::Credential => "credential",
    }
}

fn new_id() -> String {
    let b: [u8; 16] = xz_core::kdf::random_bytes::<16>();
    let mut s = String::with_capacity(32);
    for byte in b {
        use std::fmt::Write as _;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

fn kdf_from(level: Option<&str>) -> KdfParams {
    match level {
        Some("light") => KdfParams::light(),
        Some("paranoid") => KdfParams::paranoid(),
        Some("balanced") => KdfParams::balanced(),
        // 默认最高档：宁可开库慢一两秒，也不留一个好爆破的库
        _ => KdfParams::maximum(),
    }
}

// ───────────────────────────── 库操作 ─────────────────────────────

/// 前端首帧绘制完成，可以把窗口显示出来了。
///
/// 窗口在配置里是 `visible: false` —— 这样启动时用户什么都看不到，
/// 而不是先看到 WebView2 的白底、再看到我们的界面。
/// 前端在 `boot()` 末尾（第一屏已经渲染进 DOM 之后）调这个命令，
/// Rust 侧才 `show()`，第一眼就是成品。
///
/// 参考 Tauri 官方建议（tao#1142）：隐藏创建 + NavigationCompleted 后显示。
#[tauri::command]
pub fn ui_ready(window: tauri::Window) -> Result<(), String> {
    window.show().map_err(|e| e.to_string())?;
    // 显示后再置前，避免只显示不聚焦
    let _ = window.set_focus();
    Ok(())
}

/// 查询当前状态。
#[tauri::command]
pub fn vault_status(state: State<'_, AppState>) -> Result<VaultStatus, String> {
    let mut guard = state.session.lock().map_err(err)?;
    match guard.un() {
        Some(u) => Ok(VaultStatus {
            unlocked: true,
            path: u.vault.path().map(|p| p.display().to_string()),
            dirty: u.vault.is_dirty(),
            count: u.vault.len(),
            seconds_until_lock: guard.seconds_until_lock(),
        }),
        None => Ok(VaultStatus {
            unlocked: false,
            path: None,
            dirty: false,
            count: 0,
            seconds_until_lock: None,
        }),
    }
}

/// 新建库（内存中，需再调 `vault_save` 落盘）。
#[tauri::command]
pub async fn vault_create(
    state: State<'_, AppState>,
    password: String,
    level: Option<String>,
) -> Result<(), String> {
    // 为什么是 async：
    //
    // Tauri 的**同步**命令在主线程（UI 那个线程）上执行。建库要跑
    // Argon2id 1 GiB × 3 轮，约 1.5 秒 —— 这段时间整个窗口不处理任何
    // 消息，Windows 判定程序无响应，直接弹「关闭程序」。
    // 所以这里必须 async + spawn_blocking，把重活挪到线程池。
    let params = kdf_from(level.as_deref());

    let vault = tauri::async_runtime::spawn_blocking(move || -> Result<_, String> {
        let pepper = crate::machine::pepper()?;
        let mut vault =
            xz_core::vault::Vault::create_bound(&password, params, &pepper).map_err(err)?;
        // 登记：这个库从此归本机所有，别的 .xzvlt 进不来
        crate::machine::register_vault(&vault.vault_id())?;
        vault.set_path(std::path::PathBuf::new());
        Ok(vault)
    })
    .await
    .map_err(|e| format!("建库任务失败：{e}"))??;

    // 加锁只在装配这几十微秒内发生，不跨 await
    let mut guard = state.session.lock().map_err(err)?;
    guard.adopt(vault);
    Ok(())
}

/// 打开库。
#[tauri::command]
pub async fn vault_open(
    state: State<'_, AppState>,
    path: String,
    password: String,
) -> Result<(), String> {
    let path = PathBuf::from(path);

    let bytes = std::fs::read(&path).map_err(|e| format!("读不了文件：{e}"))?;

    // 先认库，再验密码。
    //
    // 只读文件头拿 `vault_id`，这一步不做任何解密，几微秒。
    // 不认识的库直接拒绝 —— 密码对不对都不重要：这个软件只服务
    // 它自己建的那个库。从别处拷来的文件在这里就死了，
    // 连给攻击者「试密码」的机会都不给。
    let header = xz_core::codec::FileHeader::parse(&bytes).map_err(err)?;
    let id = {
        let mut s = String::with_capacity(32);
        for b in header.vault_id {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    };
    if !crate::machine::is_known_vault(&id) {
        return Err("这不是本机创建的密钥库".to_owned());
    }

    // 快路径：有有效票据就跳过 Argon2。
    //
    // 票据里是 DPAPI 封存的主密钥，绑定当前 Windows 账户 ——
    // 身份已经验证过，再算一遍 KDF 只是让用户盯着转圈。
    // 票据缺失/过期/换机器时自动退回下面的完整 KDF。
    if let Some(raw) = crate::machine::load_ticket(&id) {
        if raw.len() == 32 {
            let mut key = xz_core::secure::SecretBytes::zeroed(32);
            key.as_mut_slice().copy_from_slice(&raw);
            // 拿票据里的密钥试一次校验块：密码改过就自然失效，退回完整流程
            if let Ok(()) = xz_core::codec::check_verify_block(
                &key,
                &header.to_bytes(),
                xz_core::codec::split_sealed(&bytes).map_err(err)?.verify,
            ) {
                let mut guard = state.session.lock().map_err(err)?;
                return guard.install(&path, &bytes, key).map_err(err);
            }
        }
    }

    // 慢路径：走完整 KDF（票据没有 / 已过期 / 换过密码）
    //
    // 这一段是秒级的，必须丢到阻塞线程池。`async fn` 本身不够 ——
    // 里面照样同步跑，就等于还是占着主线程。
    let bytes_for_kdf = bytes.clone();
    let id_for_ticket = id.clone();
    let key = tauri::async_runtime::spawn_blocking(move || -> Result<_, String> {
        let pepper = crate::machine::pepper()?;
        let key = xz_core::vault::Vault::derive_key_for(&bytes_for_kdf, &password, &pepper)
            .map_err(err)?;
        // 验过了就发一张新票据，下次进来就是秒开
        let _ = crate::machine::save_ticket(&id_for_ticket, key.as_slice());
        Ok(key)
    })
    .await
    .map_err(|e| format!("解锁任务失败：{e}"))??;

    let mut guard = state.session.lock().map_err(err)?;
    guard.install(&path, &bytes, key).map_err(err)
}

/// 关闭库：先保存（如果脏），再锁定。
#[tauri::command]
pub fn vault_close(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.session.lock().map_err(err)?;
    if let Some(u) = guard.un() {
        if u.vault.is_dirty() && u.vault.path().is_some() {
            u.vault.save().map_err(err)?;
        }
    }
    guard.lock();
    Ok(())
}

/// 仅锁定，不保存（用于「立即锁库」快捷键）。
#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.session.lock().map_err(err)?;
    guard.lock();
    clipboard::purge_if_ours();
    Ok(())
}

/// 默认库文件路径。
///
/// 「一个应用一个库」——用户不需要知道库存在哪，也不该被问到。
/// 放在系统的应用数据目录下，文件名固定，随用户配置一起被备份/漫游。
#[tauri::command]
pub fn default_vault_path(app: tauri::AppHandle) -> Result<String, String> {
    use tauri::Manager as _;
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("拿不到应用数据目录：{e}"))?;
    std::fs::create_dir_all(&dir).map_err(err)?;
    Ok(dir.join("vault.xzvlt").display().to_string())
}

/// 换密码并落盘。
///
/// `new_password` 允许为空 —— 空密码就是「免密码模式」：
/// 数据仍然加密（盐会轮换），只是打开时不再需要输入，便利优先。
#[tauri::command]
pub async fn vault_rekey(
    state: State<'_, AppState>,
    old_password: String,
    new_password: String,
    path: String,
) -> Result<(), String> {
    // 不允许把主密码改成空串。
    //
    // 早先「免密码模式」是直接把库改成空密码，那等于把一个加密库
    // 变成「谁都能开」的文件 —— 点一下设置里的勾选就永久生效，
    // 没有二次确认、不校验原密码。「便利」不能这样换。
    // 真要免密，正确做法是保留主密码，只把「解锁」换成 DPAPI 托管。
    if new_password.is_empty() {
        return Err("密码不能为空".to_owned());
    }
    if new_password.len() < 8 {
        return Err("密码至少 8 位".to_owned());
    }

    // 用块作用域把「持锁 + 验旧密码 + 取快照」圈起来。
    // 编译器只看得到 `drop(guard)`，看不到作用域结束同样会释放 ——
    // 而 `MutexGuard` 跨 await 会让整个 future 不再是 Send。
    let snapshot = {
        let mut guard = state.session.lock().map_err(err)?;
        let u = guard.un().ok_or("尚未解锁")?;
        u.last_activity = std::time::Instant::now();

        // 先校验旧密码：防止有人趁会话还开着悄悄换掉密码
        u.vault
            .verify_password(&old_password)
            .map_err(|_| "原密码不对".to_owned())?;

        // 拿一份明文快照，离开作用域立刻放锁。
        // 改密码要跑两轮 Argon2，全程持锁会把界面冻住。
        u.vault.export_all()
    };

    let new_pw = new_password.clone();
    let sealed = tauri::async_runtime::spawn_blocking(move || -> Result<Vec<u8>, String> {
        let pepper = crate::machine::pepper()?;
        xz_core::vault::reseal_snapshot(&snapshot, &new_pw, &pepper).map_err(err)
    })
    .await
    .map_err(|e| format!("改密码任务失败：{e}"))??;

    // 先落盘成功，再换内存里的密钥 —— 顺序反过来的话，落盘失败会留下
    // 「内存是新密码、磁盘是旧密码」的状态，用户以为改成了，其实没有。
    std::fs::write(&path, &sealed).map_err(|e| format!("写不进去：{e}"))?;

    {
        let mut guard = state.session.lock().map_err(err)?;
        let u = guard.un().ok_or("尚未解锁")?;
        let pepper = crate::machine::pepper()?;
        u.vault
            .change_password_bound(&new_password, None, &pepper)
            .map_err(err)?;
        u.vault.set_path(PathBuf::from(path));
    }

    // 密码变了，旧票据必须作废。只清不发 —— 票据里存的是主密钥，
    // 旧密钥在这里已经不成立，发一张空的只会让人误读成「刚发了新票据」。
    crate::machine::clear_ticket();
    Ok(())
}

/// 保存到路径（首次保存或另存为）。
#[tauri::command]
pub fn vault_save(state: State<'_, AppState>, path: Option<String>) -> Result<(), String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();
    if let Some(p) = path {
        u.vault.save_as(PathBuf::from(p)).map_err(err)
    } else {
        u.vault.save().map_err(err)
    }
}

/// 概览统计。
#[tauri::command]
pub fn vault_stats(state: State<'_, AppState>) -> Result<xz_core::vault::VaultStats, String> {
    let mut guard = state.session.lock().map_err(err)?;
    guard.stats(now_ts()).ok_or_else(|| "尚未解锁".to_owned())
}

// ───────────────────────────── 查询 ─────────────────────────────

/// 热度榜（快捷复制用）。
#[tauri::command]
pub fn list_hot(state: State<'_, AppState>, limit: usize) -> Result<Vec<ItemView>, String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();
    Ok(u.vault
        .index()
        .hot(limit)
        .into_iter()
        .map(ItemView::from)
        .collect())
}

/// 全部条目（按名称排序）。
#[tauri::command]
pub fn list_all(state: State<'_, AppState>) -> Result<Vec<ItemView>, String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();
    Ok(u.vault
        .index()
        .all_sorted()
        .into_iter()
        .map(ItemView::from)
        .collect())
}

/// 模糊搜索。
#[tauri::command]
pub fn search_entries(
    state: State<'_, AppState>,
    query: String,
    limit: Option<usize>,
) -> Result<Vec<HitView>, String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();
    let limit = limit.unwrap_or(50);
    Ok(search::search(u.vault.index(), &query, limit)
        .into_iter()
        .map(|h| HitView {
            item: ItemView::from(h.item),
            score: h.score,
            field: match h.field {
                search::Field::Name => "name",
                search::Field::Username => "username",
                search::Field::Url => "url",
                search::Field::Tag => "tag",
            }
            .to_owned(),
        })
        .collect())
}

/// 标签列表与计数。
#[tauri::command]
pub fn list_tags(state: State<'_, AppState>) -> Result<Vec<(String, usize)>, String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    Ok(u.vault.index().tag_counts())
}

/// 条目详情（不含秘密）。
#[tauri::command]
pub fn entry_get(state: State<'_, AppState>, id: String) -> Result<EntryView, String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();
    let e = u
        .vault
        .get(&id)
        .ok_or_else(|| format!("条目不存在：{id}"))?;
    Ok(EntryView {
        id: e.id.clone(),
        kind: kind_to(e.kind).to_owned(),
        name: e.name.clone(),
        username: e.username.clone(),
        url: e.url.clone(),
        notes: e.notes.clone(),
        tags: e.tags.clone(),
        fields: e
            .fields
            .iter()
            .map(|f| FieldView {
                name: f.name.clone(),
                value: if f.secret {
                    String::new()
                } else {
                    f.value.clone()
                },
                secret: f.secret,
            })
            .collect(),
        created_at: e.created_at,
        updated_at: e.updated_at,
        expires_at: e.expires_at,
        use_count: e.use_count,
        last_used_at: e.last_used_at,
        secret_len: e.secret.chars().count(),
    })
}

/// 取出秘密字段。`field_index` 为 `None` 时取主秘密。
#[tauri::command]
pub fn entry_reveal(
    state: State<'_, AppState>,
    id: String,
    field_index: Option<usize>,
) -> Result<String, String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();
    let e = u
        .vault
        .get(&id)
        .ok_or_else(|| format!("条目不存在：{id}"))?;
    match field_index {
        None => Ok(e.secret.clone()),
        Some(i) => e
            .fields
            .get(i)
            .map(|f| f.value.clone())
            .ok_or_else(|| format!("字段不存在：{i}")),
    }
}

// ───────────────────────────── 写入 ─────────────────────────────

/// 新增或修改条目。
#[tauri::command]
pub fn entry_save(state: State<'_, AppState>, input: EntryInput) -> Result<String, String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();
    let ts = now_ts();

    let is_new = input.id.trim().is_empty();
    let id = if is_new { new_id() } else { input.id.clone() };

    // 已有条目：保留秘密、创建时间、使用统计。
    // 前端传空 secret 表示「不改秘密」——这条规则让「只改名字」不需要回传密钥。
    let (secret, created_at, use_count, last_used_at) = if is_new {
        (input.secret, ts, 0, 0)
    } else {
        match u.vault.get(&id) {
            Some(old) => {
                let secret = if input.secret.is_empty() {
                    old.secret.clone()
                } else {
                    input.secret.clone()
                };
                (secret, old.created_at, old.use_count, old.last_used_at)
            }
            None => (input.secret, ts, 0, 0),
        }
    };

    let entry = Entry {
        id: id.clone(),
        kind: kind_from(&input.kind),
        name: input.name,
        username: input.username,
        secret,
        url: input.url,
        fields: input
            .fields
            .into_iter()
            .map(|f| Field {
                name: f.name,
                value: f.value,
                secret: f.secret,
            })
            .collect(),
        tags: input.tags,
        notes: input.notes,
        created_at,
        updated_at: ts,
        expires_at: input.expires_at,
        use_count,
        last_used_at,
    };

    if is_new {
        u.vault.insert(entry).map_err(err)?;
    } else {
        u.vault.update(entry).map_err(err)?;
    }
    Ok(id)
}

/// 删除条目。
#[tauri::command]
pub fn entry_delete(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();
    u.vault.remove(&id).map_err(err)
}

/// 记一次使用（热度统计）。
#[tauri::command]
pub fn entry_record_use(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();
    u.vault.record_use(&id, now_ts()).map_err(err)
}

// ───────────────────────────── 剪贴板 ─────────────────────────────

/// 复制任意文本到剪贴板。`sensitive` 为真时安排定时清除。
#[tauri::command]
pub fn copy_to_clipboard(
    state: State<'_, AppState>,
    text: String,
    sensitive: bool,
) -> Result<(), String> {
    // 锁定态不允许写剪贴板。
    //
    // 这条命令接受任意调用方给的文本，不加限制的话它就是一个
    // 「任意写剪贴板」的通道：本机任何能 invoke 的进程都能塞内容进来，
    // 而且 sensitive=false 时不会登记指纹，vault_lock 也清不掉它。
    let mut guard = state.session.lock().map_err(err)?;
    guard.un().ok_or("尚未解锁")?;

    // 敏感内容用短 TTL，非敏感用长 TTL。两者都会登记指纹，
    // 锁库时一律清掉 —— 区别只在「你不锁的情况下它能在剪贴板待多久」。
    let ttl = if sensitive { SECRET_TTL } else { PLAIN_TTL };
    clipboard::copy_with_ttl(&text, ttl)
}

/// 复制热度榜第 N 条的密钥。`index` 从 0 开始。
///
/// 这是「Ctrl+Shift+1..9 直接复制」的后端。前端只传序号，不传 id，
/// 保证了这个快捷路径永远取当前的热度榜，不会因为界面没刷新而复制错条目。
#[tauri::command]
pub fn copy_secret_by_heat(state: State<'_, AppState>, index: usize) -> Result<String, String> {
    let (id, name, secret) = {
        let mut guard = state.session.lock().map_err(err)?;
        let u = guard.un().ok_or("尚未解锁")?;
        u.last_activity = std::time::Instant::now();
        let hot = u.vault.index().hot(index + 1);
        let item = hot.get(index).ok_or("热度榜没有这一条")?;
        let id = item.id.clone();
        let name = item.name.clone();
        let secret = u.vault.reveal_secret(&id).map_err(err)?.to_string();
        (id, name, secret)
    };

    clipboard::copy_with_ttl(&secret, SECRET_TTL)?;

    // 记一次使用，热榜随之更新。
    if let Ok(mut guard) = state.session.lock() {
        if let Some(u) = guard.un() {
            let _ = u.vault.record_use(&id, now_ts());
        }
    }
    Ok(name)
}

// ───────────────────────────── 生命周期 ─────────────────────────────

/// 前端任何交互都调一次，用于刷新自动锁定计时。
#[tauri::command]
pub fn touch_activity(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.session.lock().map_err(err)?;
    guard.touch();
    Ok(())
}

/// 检查自动锁定。前端定时轮询（比如每 5 秒一次）。
/// 返回 `true` 表示刚刚被锁定，前端应切回锁屏。
#[tauri::command]
pub fn autolock_check(state: State<'_, AppState>) -> Result<bool, String> {
    let mut guard = state.session.lock().map_err(err)?;
    let locked = guard.check_autolock();
    if locked {
        clipboard::purge_if_ours();
    }
    Ok(locked)
}

/// 导出 CSV（明文！）。前端必须先弹确认框。
#[tauri::command]
pub fn export_csv(state: State<'_, AppState>, path: String) -> Result<usize, String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();

    let mut out = String::from("name,kind,username,secret,url,tags,notes\n");
    let mut count = 0usize;
    for item in u.vault.index().all_sorted() {
        if let Some(e) = u.vault.get(&item.id) {
            out.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                csv_escape(&e.name),
                kind_to(e.kind),
                csv_escape(&e.username),
                csv_escape(&e.secret),
                csv_escape(&e.url),
                csv_escape(&e.tags.join("|")),
                csv_escape(&e.notes),
            ));
            count += 1;
        }
    }
    std::fs::write(&path, out).map_err(err)?;
    Ok(count)
}

/// 导出 Excel（.xlsx，明文）。
///
/// 为什么不用 CSV：Excel 打开 CSV 会把 `=` 开头的密码当公式、
/// 长数字串会变成科学计数法、中文还要手动选编码。xlsx 没有这些坑。
#[tauri::command]
pub fn export_xlsx(state: State<'_, AppState>, path: String) -> Result<usize, String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();

    let headers = [
        "名称",
        "类型",
        "账号",
        "密码 / 密钥",
        "网址",
        "专辑",
        "备注",
    ];
    let mut rows: Vec<Vec<String>> = Vec::new();
    for item in u.vault.index().all_sorted() {
        if let Some(e) = u.vault.get(&item.id) {
            rows.push(vec![
                e.name.clone(),
                kind_to(e.kind).to_owned(),
                e.username.clone(),
                e.secret.clone(),
                e.url.clone(),
                e.tags.join("、"),
                e.notes.clone(),
            ]);
        }
    }
    let n = rows.len();
    write_xlsx(&path, &headers, &rows)?;
    Ok(n)
}

/// 导出一张单表 xlsx。
///
/// 手写最小 OOXML：一个 zip 里放几份 XML。不引第三方 xlsx 库 ——
/// 我们只需要「一行一条、全部转成内联文本」，几百行代码就够，
/// 换来的是更小的安装包和更少的信任面。
fn write_xlsx(path: &str, headers: &[&str], rows: &[Vec<String>]) -> Result<(), String> {
    use std::io::Write;

    let esc = |s: &str| -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .chars()
            .filter(|c| *c >= ' ' || *c == '\t' || *c == '\n')
            .collect()
    };

    // 行号从 1 开始；所有单元格用内联字符串（t="inlineStr"），
    // 这样 "00123" 和 "=SUM(A1)" 都原样保留，不会被 Excel 解释。
    let mut sheet = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>"#,
    );

    let mut push_row = |idx: usize, cells: &[String]| {
        sheet.push_str(&format!(r#"<row r="{idx}">"#));
        for (ci, v) in cells.iter().enumerate() {
            let col = col_name(ci);
            sheet.push_str(&format!(
                r#"<c r="{col}{idx}" t="inlineStr"><is><t xml:space="preserve">{}</t></is></c>"#,
                esc(v)
            ));
        }
        sheet.push_str("</row>");
    };

    let head: Vec<String> = headers.iter().map(|h| (*h).to_owned()).collect();
    push_row(1, &head);
    for (i, r) in rows.iter().enumerate() {
        push_row(i + 2, r);
    }
    sheet.push_str("</sheetData></worksheet>");

    let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#;

    let rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#;

    let workbook = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="密钥库" sheetId="1" r:id="rId1"/></sheets></workbook>"#;

    let wb_rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#;

    let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut put = |name: &str, data: &str| -> Result<(), String> {
        zip.start_file(name, opts).map_err(|e| e.to_string())?;
        zip.write_all(data.as_bytes()).map_err(|e| e.to_string())
    };
    put("[Content_Types].xml", content_types)?;
    put("_rels/.rels", rels)?;
    put("xl/workbook.xml", workbook)?;
    put("xl/_rels/workbook.xml.rels", wb_rels)?;
    put("xl/worksheets/sheet1.xml", &sheet)?;
    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}

/// 列序号 → Excel 列名（0 → A，26 → AA）。
fn col_name(mut i: usize) -> String {
    let mut s = String::new();
    loop {
        s.insert(0, (b'A' + (i % 26) as u8) as char);
        if i < 26 {
            break;
        }
        i = i / 26 - 1;
    }
    s
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

#[cfg(test)]
mod xlsx_tests {
    #[test]
    fn col_names() {
        assert_eq!(super::col_name(0), "A");
        assert_eq!(super::col_name(25), "Z");
        assert_eq!(super::col_name(26), "AA");
        assert_eq!(super::col_name(27), "AB");
        assert_eq!(super::col_name(51), "AZ");
        assert_eq!(super::col_name(52), "BA");
    }

    #[test]
    fn writes_valid_zip() {
        let p = std::env::temp_dir().join("xz-xlsx-test.xlsx");
        let rows = vec![
            vec!["名称".to_string(), "=SUM(A1)".to_string()],
            vec!["00123".to_string(), "含<标签>&符号".to_string()],
        ];
        super::write_xlsx(p.to_str().unwrap(), &["A", "B"], &rows).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        assert!(bytes.len() > 200, "文件太小: {}", bytes.len());
        // zip 魔数 PK\x03\x04
        assert_eq!(&bytes[0..2], b"PK");
        let _ = std::fs::remove_file(&p);
    }
}
