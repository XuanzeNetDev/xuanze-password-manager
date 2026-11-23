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
use tauri_plugin_dialog::DialogExt;
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

/// 前端传上来的类型字符串 → `EntryKind`。
fn kind_from(s: &str) -> EntryKind {
    match s {
        "login" => EntryKind::Login,
        "note" => EntryKind::Note,
        "card" => EntryKind::Card,
        "credential" => EntryKind::Credential,
        _ => EntryKind::ApiKey,
    }
}

/// `EntryKind` → 前端用的类型字符串。
fn kind_to(k: EntryKind) -> &'static str {
    match k {
        EntryKind::Login => "login",
        EntryKind::ApiKey => "api_key",
        EntryKind::Note => "note",
        EntryKind::Card => "card",
        EntryKind::Credential => "credential",
    }
}

/// 解析一个提交上来的自定义字段的最终值。
///
/// 规则：**敏感字段值留空 = 保持原值**。理由见 `entry_save` 里的说明 ——
/// 前端本来就拿不到敏感字段的值，空串不是「用户清空了」，而是「用户没碰」。
fn resolve_field_value(name: &str, value: String, secret: bool, old: &[Field]) -> String {
    if secret && value.is_empty() {
        old.iter()
            .find(|x| x.name == name)
            .map(|x| x.value.clone())
            .unwrap_or_default()
    } else {
        value
    }
}

fn new_id() -> String {
    let b: [u8; 16] = xz_core::kdf::random_bytes::<16>();
    hex16(&b)
}

/// 16 字节 → 32 个 hex 字符。`vault_id` 与条目 id 都用这个形态。
fn hex16(b: &[u8; 16]) -> String {
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
        Some("balanced") => KdfParams::balanced(),
        Some("maximum") => KdfParams::maximum(),
        // 默认 paranoid（256 MiB × 4 轮）。
        //
        // 这里以前是 maximum（1 GiB），而前端建库时显式传 "paranoid" ——
        // 两个「默认」不一样，文档里又各写各的，三处对不上。
        // 现在统一：不指定就用 paranoid，想更强就显式传 "maximum"。
        _ => KdfParams::paranoid(),
    }
}

/// 判定「操作者是本人」。
///
/// 免密码模式已开启时，本机封存的主密钥在启动阶段已经解开过一次，
/// 会话处于解锁态就等同于本人已验证 —— 那个模式省的就是这一步。
/// 因此在它开启期间，导出备份、导入、改主密码、关闭该模式都不再追问密码。
///
/// 其余情况走完整的主密码重新派生校验。**开启**免密码模式本身仍然要求密码：
/// 那是进入这个状态的入口，此时本机还没有可用的封存材料。
async fn ensure_authorized(
    state: &State<'_, AppState>,
    password: &str,
    wrong_msg: &str,
) -> Result<(), String> {
    if crate::machine::auto_unlock_enabled() {
        let guard = state.session.lock().map_err(err)?;
        if guard.is_unlocked() {
            return Ok(());
        }
        return Err("尚未解锁".to_owned());
    }
    confirm_master_password(state, password, wrong_msg).await
}

/// 重新校验主密码：锁外跑 KDF，锁内做一次常量时间比对。
///
/// ## 为什么单独抽出来
///
/// 「导出明文」「导入」「改主密码」「开关免密码模式」这四件事都必须确认
/// 操作者是知道主密码的本人 —— 这是本产品最主要的几道闸门。
/// 判定方式只有一种是对的：**用这个密码重新派生，看能不能得到同一把主密钥**
/// （见 `Vault::verify_password_bound`，那里记着为什么不能用「校验块自证」）。
///
/// 重新派生意味着要跑一次完整 Argon2id（paranoid 档约 1 秒）。
/// 这一步必须在锁外、在线程池里做，否则整个窗口会冻住变成「未响应」。
async fn confirm_master_password(
    state: &State<'_, AppState>,
    password: &str,
    wrong_msg: &str,
) -> Result<(), String> {
    if password.is_empty() {
        return Err("请输入主密码".to_owned());
    }

    // 1) 锁内取出全部派生材料（KDF 参数 + 盐 + v3 绑定串副本），立刻放锁。
    //    这些都在文件头或绑定块里，脱离主密钥没有攻击价值。
    let (params, salt, binding) = {
        let mut guard = state.session.lock().map_err(err)?;
        let u = guard.un().ok_or("尚未解锁")?;
        u.last_activity = std::time::Instant::now();
        let (p, s) = u.vault.kdf_material();
        (p, s, u.vault.binding_secret_copy())
    };

    // 2) 锁外派生。这是全场唯一的慢路径。
    //
    //    规则必须跟库走：v3 库用绑定串，v2 老库才去碰 machine.bind。
    //    这里曾经一律调 `machine::pepper()`，于是 v3 库按 v2 规则派生，
    //    再拿去和按 v3 规则算出来的主密钥比对 —— 输对密码也报「密码不对」。
    let pw = password.to_owned();
    let candidate = tauri::async_runtime::spawn_blocking(move || -> Result<_, String> {
        let pepper = if binding.is_some() {
            Vec::new()
        } else {
            crate::machine::pepper()?
        };
        xz_core::vault::Vault::derive_key_with(
            &pw,
            &pepper,
            binding.as_ref().map(|b| b.as_slice()),
            &salt,
            params,
        )
        .map_err(err)
    })
    .await
    .map_err(|e| format!("校验任务失败：{e}"))??;

    // 3) 锁内比对（微秒级）。候选密钥由 `SecretBytes` 持有，出作用域即擦除。
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    if !u.vault.matches_master_key(&candidate) {
        return Err(wrong_msg.to_owned());
    }
    u.last_activity = std::time::Instant::now();
    Ok(())
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
///
/// 绑定规则选 v3（如果读得到硬件指纹）：绑定材料跟着文件走，
/// 见 `xz_core::vault::Binding` 与 `machine::hardware_fingerprint`。
/// 读不到硬件指纹的机器退回 v2 规则（绑机器名 + 卷序列号）。
#[tauri::command]
pub async fn vault_create(
    state: State<'_, AppState>,
    password: String,
    level: Option<String>,
) -> Result<CreateResult, String> {
    // 为什么是 async：
    //
    // Tauri 的**同步**命令在主线程（UI 那个线程）上执行。建库要跑
    // Argon2id 1 GiB × 3 轮，约 1.5 秒 —— 这段时间整个窗口不处理任何
    // 消息，Windows 判定程序无响应，直接弹「关闭程序」。
    // 所以这里必须 async + spawn_blocking，把重活挪到线程池。
    let params = kdf_from(level.as_deref());

    let (vault, hardware_bound) =
        tauri::async_runtime::spawn_blocking(move || -> Result<_, String> {
            let (vault, bound) = match crate::machine::hardware_fingerprint() {
                Some(fp) => {
                    // v3：本机随机串封进文件，重装系统也能开
                    let binding_secret: [u8; xz_core::binding::BINDING_SECRET_LEN] =
                        xz_core::kdf::random_bytes();
                    let v = xz_core::vault::Vault::create_bound_v3(
                        &password,
                        params,
                        &binding_secret,
                        fp,
                    )
                    .map_err(err)?;
                    (v, true)
                }
                None => {
                    // 读不到硬件指纹：退回 v2 规则（绑机器名 + 卷序列号）。
                    //
                    // 这条路是脆的：改个计算机名、重装一次系统就打不开。
                    // 但它只在极老的机器和部分虚拟机上会走到，所以不能因为
                    // 读不到指纹就不让人建库。**但必须告诉用户** ——
                    // 静默降级等于把「重装即失联」这个后果瞒着人家。
                    let pepper = crate::machine::pepper()?;
                    let v = xz_core::vault::Vault::create_bound(&password, params, &pepper)
                        .map_err(err)?;
                    (v, false)
                }
            };
            // 登记：这个库从此归本机所有，别的 .xzvlt 进不来
            crate::machine::register_vault(&vault.vault_id())?;
            Ok((vault, bound))
        })
        .await
        .map_err(|e| format!("建库任务失败：{e}"))??;

    // 加锁只在装配这几十微秒内发生，不跨 await
    let mut guard = state.session.lock().map_err(err)?;
    guard.adopt(vault);
    Ok(CreateResult { hardware_bound })
}

/// 建库结果。
#[derive(Debug, serde::Serialize)]
pub struct CreateResult {
    /// 是否用上了 v3 绑定（读得到主板 SMBIOS UUID）。
    ///
    /// `false` 意味着退回了 v2 规则：那种库**改计算机名或重装系统就打不开**。
    /// 前端必须把这件事明确告诉用户，不能当没事发生。
    hardware_bound: bool,
}

/// 打开库。
///
/// **不接受路径参数。** 这里以前是 `vault_open(path, password)`，路径由前端
/// 用 `localStorage` 记住再传回来 —— 等于把「读哪个文件」的决定权交给了
/// 一个可被清空、可被改写的存储。现在路径由后端自己算（固定默认位置），
/// 前端连选择的机会都没有：本产品就是一个应用一个库。
#[tauri::command]
pub async fn vault_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    let path = PathBuf::from(default_path_of(&app)?);

    // 先看大小再读。正常库最大也就几十 MB；一个被替换成巨型文件的默认路径
    // 会让 `fs::read` 直接把内存打爆 —— 而这里只是打开库的第一步。
    {
        let meta = std::fs::metadata(&path).map_err(|e| format!("读不了文件：{e}"))?;
        if meta.len() > MAX_VAULT_BYTES {
            return Err(format!(
                "库文件异常大（{} MiB），拒绝读取",
                meta.len() >> 20
            ));
        }
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("读不了文件：{e}"))?;

    // 先认库，再验密码。
    //
    // 只读文件头拿 `vault_id`，这一步不做任何解密，几微秒。
    // 不认识的库直接拒绝 —— 密码对不对都不重要：这个软件只服务
    // 它自己建的那个库。从别处拷来的文件在这里就死了，
    // 连给攻击者「试密码」的机会都不给。
    let header = xz_core::codec::FileHeader::parse(&bytes).map_err(err)?;
    let id = hex16(&header.vault_id);
    if !crate::machine::is_known_vault(&id) {
        return Err("这不是本机创建的密钥库".to_owned());
    }

    // 快路径：免密码模式已开启 → 直接用本机封存的主密钥。
    //
    // 「免密码」不是把主密码改成空，而是把主密钥用 DPAPI 封存到本机。
    // 文件本身仍然用完整主密码 + 机器绑定加密，拷到别处一样打不开；
    // 只有这台机器、这个 Windows 账户能解开这份封存。
    if crate::machine::auto_unlock_enabled() {
        if let Some(key) = crate::machine::load_auto_unlock(&id) {
            if key.len() == 32
                && xz_core::codec::check_verify_block(
                    &key,
                    &header.to_bytes(),
                    xz_core::codec::split_sealed(&bytes).map_err(err)?.verify,
                )
                .is_ok()
            {
                // 绑定材料必须一起解出来。v3 库少了它，这个会话一旦保存就会报
                // 「v3 格式但缺绑定材料」—— 用户改完条目存不进去，而且提示
                // 会指向一个他看不懂的内部错误。
                let material = v3_binding_material(&bytes, &header)?;
                let mut guard = state.session.lock().map_err(err)?;
                guard.install(&path, &bytes, key).map_err(err)?;
                if let Some((secret, fp)) = material {
                    if let Some(u) = guard.un() {
                        u.vault.adopt_binding(secret, fp);
                    }
                }
                return Ok(());
            }
        }
    }

    // 慢路径：走完整 KDF
    //
    // 这一段是秒级的，必须丢到阻塞线程池。`async fn` 本身不够 ——
    // 里面照样同步跑，就等于还是占着主线程。
    //
    // pepper 按文件版本选规则：
    //   v2（老库）：机器名 + 卷序列号 + DPAPI 封存的随机串
    //   v3（新库）：只有随机串，从文件里的绑定块用硬件指纹解出来
    let info = binding_for(&bytes, &header)?;
    let pepper = info.pepper;
    let binding = info.material;

    let bytes_for_kdf = bytes.clone();
    let pepper_for_kdf = pepper.clone();
    let key = tauri::async_runtime::spawn_blocking(move || -> Result<_, String> {
        xz_core::vault::Vault::derive_key_for(&bytes_for_kdf, &password, &pepper_for_kdf)
            .map_err(err)
    })
    .await
    .map_err(|e| format!("解锁任务失败：{e}"))??;

    let mut guard = state.session.lock().map_err(err)?;
    guard.install(&path, &bytes, key).map_err(err)?;
    // v3 库：把绑定材料记进 Vault，否则下次保存会写不出绑定块
    if let Some((secret, fp)) = binding {
        if let Some(u) = guard.un() {
            u.vault.adopt_binding(secret, fp);
        }
    }
    Ok(())
}

/// `binding_for` 的结果。
struct BindingInfo {
    /// 喂给 KDF 的 pepper。
    pepper: Vec<u8>,
    /// v3 才有：本机随机串 + 硬件指纹。要交给 `Vault::adopt_binding` 记住，
    /// 否则下次保存写不出绑定块。
    material: Option<(xz_core::secure::SecretBytes, Vec<u8>)>,
}

/// v3 库：从文件里的绑定块解出本机随机串。v2 库返回 `None`。
///
/// 单独抽出来是因为有两条路径要用它：正常开库（`binding_for`）
/// 和免密码模式的快路径。快路径以前漏了这一步，打开是能打开，
/// 但那个会话保存时会失败。
fn v3_binding_material(
    bytes: &[u8],
    header: &xz_core::codec::FileHeader,
) -> Result<Option<(xz_core::secure::SecretBytes, Vec<u8>)>, String> {
    if header.version < 3 {
        return Ok(None);
    }
    let fp = crate::machine::hardware_fingerprint().ok_or(
        "这台机器读不到硬件标识（SMBIOS），无法解开发它的密钥库。\n\n\
         这个库是在一台能读到硬件标识的机器上创建的，请在原机器上打开。",
    )?;
    let parts = xz_core::codec::split_sealed(bytes).map_err(err)?;
    let blob = parts.bind.ok_or("库文件缺少绑定块，文件可能损坏")?;
    let secret = xz_core::binding::unwrap_binding_secret(&fp, blob).map_err(|_| {
        "这个库绑定的不是当前设备（换过主板或系统盘？），无法打开。\n\n\
         库文件本身没有问题 —— 是「设备绑定」在起作用。"
            .to_owned()
    })?;
    Ok(Some((secret, fp)))
}

/// 按文件版本算出 pepper，并顺带带回 v3 的绑定材料。
///
/// v3 这条路径是「重装系统还能打开」的全部实现：绑定块在文件里，
/// 用当前机器的硬件指纹解。换了硬件就解不开 —— 那就是设备绑定。
fn binding_for(bytes: &[u8], header: &xz_core::codec::FileHeader) -> Result<BindingInfo, String> {
    if header.version < 3 {
        // 老库：沿用 v2 规则。machine::pepper() 内部会去读 machine.bind。
        return Ok(BindingInfo {
            pepper: crate::machine::pepper()?,
            material: None,
        });
    }
    let material = v3_binding_material(bytes, header)?
        .ok_or("这个库标记为 v3 格式，但没有绑定块")?;
    let pepper = xz_core::binding::make_pepper_v3(material.0.as_slice());
    Ok(BindingInfo {
        pepper,
        material: Some(material),
    })
}

/// 查询免密码模式是否已开启。
#[tauri::command]
pub fn auto_unlock_status() -> bool {
    crate::machine::auto_unlock_enabled()
}

/// 开启免密码模式。必须给主密码 —— 要验证是本人。
#[tauri::command]
pub async fn enable_auto_unlock(
    state: State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    confirm_master_password(&state, &password, "主密码不对").await?;

    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();
    let id = u.vault.vault_id();
    let key = u.vault.master_key_slice();
    crate::machine::enable_auto_unlock(&id, key)
}

/// 关闭免密码模式。同样要主密码 —— 不能因为库开着就谁都能关掉别人的保护。
#[tauri::command]
pub async fn disable_auto_unlock(
    state: State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    // 关闭发生在免密码模式已开启的状态下，此时不需要再问密码。
    ensure_authorized(&state, &password, "主密码不对").await?;
    crate::machine::disable_auto_unlock();
    Ok(())
}

/// 仅锁定，不保存（用于「立即锁库」快捷键）。
#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.session.lock().map_err(err)?;
    let result = guard.lock();
    clipboard::purge_if_ours();
    result
}

/// 默认库文件路径。
///
/// 「一个应用一个库」——用户不需要知道库存在哪，也不该被问到。
/// 放在系统的应用数据目录下，文件名固定，随用户配置一起被备份/漫游。
#[tauri::command]
pub fn default_vault_path(app: tauri::AppHandle) -> Result<String, String> {
    default_path_of(&app)
}

fn default_path_of(app: &tauri::AppHandle) -> Result<String, String> {
    use tauri::Manager as _;
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("拿不到应用数据目录：{e}"))?;
    std::fs::create_dir_all(&dir).map_err(err)?;
    Ok(dir.join("vault.xzvlt").display().to_string())
}

/// 本机是否已经有库。
///
/// 这个判断**必须问后端**。前端以前靠 `localStorage["xz.lastVault"]` 判断
/// 「是不是第一次使用」，那条记录只要清一次 WebView 数据就没了，于是
/// 老用户会被带进注册页，在默认路径上建一个新库、覆盖掉原来那个 ——
/// 加密数据就这么没了，而且没有任何提示。
///
/// 现在的判据是三个客观事实：本机登记表里有没有库、默认路径上有没有文件。
#[derive(Debug, Serialize)]
pub struct VaultPresence {
    /// 登记表里有没有记录（= 这台机器建过库）。
    known: bool,
    /// 默认路径上现在有没有库文件。
    file_exists: bool,
    /// 默认路径本身。
    path: String,
}

#[tauri::command]
pub fn vault_exists(app: tauri::AppHandle) -> Result<VaultPresence, String> {
    let path = default_path_of(&app)?;
    Ok(VaultPresence {
        known: crate::machine::has_registered_vault(),
        file_exists: std::path::Path::new(&path).is_file(),
        path,
    })
}

/// 换密码并落盘。
///
/// `new_password` 不能为空，也不能短于 8 位 —— 下面第一件事就是挡这两种。
/// 早先允许空密码（所谓「免密码模式」），那是把一个加密库变成普通文件，
/// 而且一次勾选就永久生效，没有二次确认。已经去掉。
///
/// **不接受路径参数**：写回的位置由后端决定（固定默认位置）。
/// 让 IPC 决定「往哪写」就等于给解锁状态开一条任意写盘的通道。
#[tauri::command]
pub async fn vault_rekey(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    old_password: String,
    new_password: String,
) -> Result<(), String> {
    let path = default_path_of(&app)?;
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
    // 先校验旧密码：防止有人趁会话还开着悄悄换掉密码。
    // 这一步要重跑 KDF，所以走锁外的那条路。
    // 免密码模式下不再追问旧密码；其余情况仍要验证。
    ensure_authorized(&state, &old_password, "原密码不对").await?;

    let snapshot = {
        let mut guard = state.session.lock().map_err(err)?;
        let u = guard.un().ok_or("尚未解锁")?;
        u.last_activity = std::time::Instant::now();

        // 拿一份明文快照，离开作用域立刻放锁。
        // 改密码要跑两轮 Argon2，全程持锁会把界面冻住。
        u.vault.export_all()
    };

    let new_pw = new_password.clone();
    // v3 库的绑定材料在快照里，不需要去碰 machine.bind ——
    // 那一步在「%APPDATA% 被清过」的机器上会失败，而那种机器上
    // 改密码本来是完全可行的。
    let needs_v2_pepper = snapshot.binding.is_none();
    let sealed = tauri::async_runtime::spawn_blocking(move || -> Result<Vec<u8>, String> {
        let pepper = if needs_v2_pepper {
            crate::machine::pepper()?
        } else {
            Vec::new()
        };
        xz_core::vault::reseal_snapshot(&snapshot, &new_pw, &pepper).map_err(err)
    })
    .await
    .map_err(|e| format!("改密码任务失败：{e}"))??;

    // 先落盘成功，再换内存里的密钥 —— 顺序反过来的话，落盘失败会留下
    // 「内存是新密码、磁盘是旧密码」的状态，用户以为改成了，其实没有。
    //
    // 必须走 write_atomic 而不是 std::fs::write：改密码是唯一一次全量重加密，
    // 此刻旧密码已经作废（下面的 change_password_bound 会换掉内存密钥），
    // 写出一个半截文件就等于整库丢失。原子写保证要么是旧库、要么是新库。
    xz_core::vault::write_atomic(std::path::Path::new(&path), &sealed)
        .map_err(|e| format!("写不进去：{e}"))?;

    {
        let mut guard = state.session.lock().map_err(err)?;
        let u = guard.un().ok_or("尚未解锁")?;
        // 同上：v3 库不需要 machine.bind
        let pepper = if u.vault.has_binding() {
            Vec::new()
        } else {
            crate::machine::pepper()?
        };
        u.vault
            .change_password_bound(&new_password, None, &pepper)
            .map_err(err)?;
        u.vault.set_path(PathBuf::from(&path));
    }

    // 密码变了，之前封存的主密钥必须作废。
    //
    // 免密码模式存的是「旧密码派生出来的那把钥匙」。改完密码它就对不上了，
    // 留着只会让人下次启动时莫名其妙地退回要密码 —— 而且那个状态看起来
    // 像「免密码坏了」。直接删掉，用户重新开启一次即可。
    crate::machine::disable_auto_unlock();
    Ok(())
}

/// 保存到默认位置。
///
/// **不接受路径参数。** 以前是 `vault_save(path: Option<String>)`，
/// 前端可以把任意路径传进来 —— 在库解锁的状态下，那等于给同机任何进程
/// 一个「用加密内容覆盖任意文件」的写盘通道（内容虽然是密文，覆盖本身
/// 就能毁掉用户的文件）。现在路径只由后端决定，前端只表达「保存」这个意图。
///
/// 另外加了一道**覆盖保护**：目标位置已经躺着另一个库（或别的文件）时，
/// 拒绝写入。见函数内的注释 —— 这条守的是「静默毁数据」。
#[tauri::command]
pub fn vault_save(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let path = default_path_of(&app)?;
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();

    // 覆盖保护。
    //
    // 前端一旦误判成「本机第一次使用」，就会建一个空库再调这里保存 ——
    // 那会把用户原来的库直接覆盖掉，全程没有提示，也没法撤销。
    // 判据现在改成问后端了，但后端自己必须有最后一道路障：
    //
    // - 文件不存在 → 正常（新建库）
    // - 文件存在且是**当前这个库** → 正常（日常保存）
    // - 文件存在但是别的库、或者根本不是库 → 拒绝
    if let Ok(existing) = std::fs::read(&path) {
        if !may_overwrite(&existing, &u.vault.vault_id()) {
            return Err(
                "这个位置已经有一个密钥库（或别的文件），为避免覆盖它，保存被拒绝。\n\
                 如果那是你原有的库，请直接打开它；如果要从备份恢复，\
                 请先建新库再走「导入」。"
                    .to_owned(),
            );
        }
    }

    u.vault.save_as(PathBuf::from(path)).map_err(err)
}

/// 目标位置上的内容能不能被当前这个库覆盖。
///
/// 只有一种情况可以：那正是当前这个库（`vault_id` 相同，就是日常保存）。
/// 其余一律拒绝 —— 包括「文件存在但不是 vault」，那种情况下覆盖等于
/// 替用户删掉一个我们看不懂的文件。
fn may_overwrite(existing: &[u8], current_vault_id: &str) -> bool {
    xz_core::codec::FileHeader::parse(existing)
        .map(|h| hex16(&h.vault_id) == current_vault_id)
        .unwrap_or(false)
}

// ───────────────────────────── 查询 ─────────────────────────────

/// 热度榜。
///
/// 两拨用户：前端的「常用」专辑要一次拿一批（最多几百条），
/// 快捷键 Ctrl+Shift+1..9 只要前 9 条。
///
/// `limit` 从 IPC 直接进来，先夹到合理区间再去索引里用：
/// `hot(0)` 曾经会 `k - 1` 下溢导致 panic，而本库 panic = abort =
/// 整个进程消失 —— 一条 `invoke('list_hot',{limit:0})` 就够。
/// 这里兜一道，`Index::hot` 自己也兜了一道，两处都不省。
///
/// 上界取 1000：既够「常用」专辑用，又不会让人传个 `usize::MAX`
/// 逼着索引做一次全排序。
#[tauri::command]
pub fn list_hot(state: State<'_, AppState>, limit: usize) -> Result<Vec<ItemView>, String> {
    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();
    let limit = limit.clamp(1, 1000);
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
        Some(i) => {
            let f = e.fields.get(i).ok_or_else(|| format!("字段不存在：{i}"))?;
            // 非敏感字段在 entry_get 里本来就明文返回，不必走 reveal。
            // 在这里挡住，「reveal 只取敏感内容」这个契约就是代码保证的，
            // 不靠调用方自觉 —— 否则将来若把 entry_get 改成一律返回空串，
            // 这里就成了后门。
            if !f.secret {
                return Err("这个字段不是敏感字段，不需要单独显示".to_owned());
            }
            Ok(f.value.clone())
        }
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
    let (secret, created_at, use_count, last_used_at, old_fields) = if is_new {
        (input.secret, ts, 0, 0, Vec::new())
    } else {
        match u.vault.get(&id) {
            Some(old) => {
                let secret = if input.secret.is_empty() {
                    old.secret.clone()
                } else {
                    input.secret.clone()
                };
                (
                    secret,
                    old.created_at,
                    old.use_count,
                    old.last_used_at,
                    old.fields.clone(),
                )
            }
            None => (input.secret, ts, 0, 0, Vec::new()),
        }
    };

    // 自定义字段：敏感字段留空 = 保持原值。
    //
    // 为什么需要这条：`entry_get` 刻意不把敏感字段的**值**发给前端（只给
    // `secret: true`），所以编辑界面里那一格天生是空的。如果这里把空串
    // 当成新值写回去，「打开编辑器 → 什么都不改 → 点保存」就会把这些字段
    // 的值擦掉 —— 一次静默的数据丢失，而且看起来什么都没发生。
    // 主 secret 早就用「空串不改」这条规则避开了同一个坑，自定义字段
    // 之前漏了。
    let fields: Vec<Field> = input
        .fields
        .into_iter()
        .map(|f| Field {
            value: resolve_field_value(&f.name, f.value, f.secret, &old_fields),
            name: f.name,
            secret: f.secret,
        })
        .collect();

    let entry = Entry {
        id: id.clone(),
        kind: kind_from(&input.kind),
        name: input.name,
        username: input.username,
        secret,
        url: input.url,
        fields,
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
    // `index + 1` 在这里也会因为 `index == usize::MAX` 而溢出。
    // 热键只有 1..9，多夹一层不花钱。
    if index >= 9 {
        return Err("热度榜没有这一条".to_owned());
    }
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

/// 当前自动锁定的闲置分钟数。
#[tauri::command]
pub fn autolock_minutes() -> u32 {
    crate::machine::autolock_minutes()
}

/// 设置自动锁定的闲置分钟数（1..=120），立即生效并持久化。
///
/// 返回值是**实际生效**的值（会被夹到合法区间），前端应据此刷新显示 ——
/// 不要假设传什么就存什么。
#[tauri::command]
pub fn set_autolock(state: State<'_, AppState>, minutes: u32) -> Result<u32, String> {
    // 先确认解锁，再落盘。
    //
    // 这条命令对同机任何进程可达，而锁着的时候把锁定时间拉长，等于替
    // 下一个人关掉一把锁。顺序也要对：先校验再写文件，不要让「被拒绝的
    // 请求」留下副作用。
    let mut guard = state.session.lock().map_err(err)?;
    if !guard.is_unlocked() {
        return Err("尚未解锁".to_owned());
    }
    let applied = crate::machine::set_autolock_minutes(minutes)?;
    guard.set_auto_lock(applied);
    Ok(applied)
}

/// 前端任何交互都调一次，用于刷新自动锁定计时。
#[tauri::command]
pub fn touch_activity(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.session.lock().map_err(err)?;
    guard.touch();
    Ok(())
}

/// 检查自动锁定。前端定时轮询（比如每 5 秒一次）。
#[tauri::command]
pub fn autolock_check(state: State<'_, AppState>) -> Result<AutolockResult, String> {
    let mut guard = state.session.lock().map_err(err)?;
    let (locked, save_error) = guard.check_autolock();
    if locked {
        clipboard::purge_if_ours();
    }
    Ok(AutolockResult { locked, save_error })
}

/// 自动锁定的结果。
#[derive(Debug, Serialize)]
pub struct AutolockResult {
    /// 刚刚是否锁定了（前端应切回锁屏）。
    locked: bool,
    /// 锁定前落盘失败的原因。有值时前端必须让用户看见 ——
    /// 否则「改完就自动锁了」会静默丢掉那批改动。
    save_error: Option<String>,
}

// ───────────────────────────── 备份 / 导出 ─────────────────────────────

/// 导出加密备份（`.xzbak`）。
///
/// 里面是一份完整的 xlsx（能被 Excel 打开），但**外面包了一层我们自己的
/// 强加密**：Argon2id 64 MiB × 3 + AES-256-GCM。磁盘上不会出现明文表格。
///
/// 两个密码：
/// - `password`（主密码）：证明操作者是本人。这一步要重跑 KDF，走锁外。
/// - `backup_password`（备份密码）：加密这个文件。留空等于没加密，直接拒绝。
///
/// **不接受路径参数。** 落盘位置由本函数自己弹系统对话框取得，与
/// `vault_save` 同一口径。理由也相同：库解锁期间任何能构造 IPC 请求的本地
/// 进程都能调用本命令，路径若由前端给，那就是一条往任意位置写文件的通道。
///
/// 返回 `None` 表示用户在对话框里取消了，调用方不必当失败处理。
#[tauri::command]
pub async fn export_backup(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    password: String,
    backup_password: String,
) -> Result<Option<usize>, String> {
    if backup_password.is_empty() {
        return Err("备份密码不能为空 —— 它就是这个文件的锁".to_owned());
    }
    // 先确认是本人（免密码模式下已解锁即视为通过）
    ensure_authorized(&state, &password, "主密码不对").await?;

    // 锁内取快照，拿到就放锁 —— 序列化 + 加密要几十毫秒，不该卡住会话。
    let (sheets, total) = {
        let mut guard = state.session.lock().map_err(err)?;
        let u = guard.un().ok_or("尚未解锁")?;
        u.last_activity = std::time::Instant::now();

        let mut all: Vec<xz_core::entry::Entry> = Vec::new();
        for item in u.vault.index().all_sorted() {
            if let Some(e) = u.vault.get(&item.id) {
                all.push(e.clone());
            }
        }
        let total = all.len();

        // 「全部」表
        let mut sheets = vec![crate::export::Sheet {
            name: "全部".to_owned(),
            headers: crate::export::HEADERS.to_vec(),
            rows: all.iter().map(crate::export::entry_to_row).collect(),
        }];

        // 每个专辑一张表
        let mut tags: Vec<String> = Vec::new();
        for e in &all {
            for t in &e.tags {
                if !tags.iter().any(|x| x == t) {
                    tags.push(t.clone());
                }
            }
        }
        tags.sort();
        for tag in tags {
            let rows: Vec<Vec<String>> = all
                .iter()
                .filter(|e| e.tags.iter().any(|t| t == &tag))
                .map(crate::export::entry_to_row)
                .collect();
            if !rows.is_empty() {
                sheets.push(crate::export::Sheet {
                    name: tag,
                    headers: crate::export::HEADERS.to_vec(),
                    rows,
                });
            }
        }
        (sheets, total)
    };

    // 落盘位置由后端弹系统对话框取得，前端不参与 —— 与 `vault_save` 同一口径。
    //
    // 这道关的意义：库解锁期间，任何能构造 IPC 请求的本地进程都能调用本命令。
    // 如果路径由前端给，那就是一条「往任意路径写文件」的通道；路径从对话框
    // 出来，写到哪里就完全取决于坐在机器前的那个人点了什么。
    //
    // `blocking_*` 不能在主线程调（会死锁），所以整个调用移进阻塞线程池。
    let picked = {
        let app = app.clone();
        let suggested = format!("璇泽密钥库-{}.xzbak", crate::export::fmt_ts(now_ts()));
        // 日期部分就够，时间带进去文件名太长
        let suggested = suggested
            .replace(' ', "-")
            .replace(':', "")
            .split('.')
            .next()
            .unwrap_or("璇泽密钥库.xzbak")
            .to_owned();
        tauri::async_runtime::spawn_blocking(move || {
            app.dialog()
                .file()
                .set_title("导出加密备份")
                .set_file_name(&suggested)
                .add_filter("璇泽密钥库备份", &["xzbak"])
                .blocking_save_file()
        })
        .await
        .map_err(|e| format!("打开保存对话框失败：{e}"))?
    };
    // 用户取消：不写文件，也不算失败
    let Some(fp) = picked else { return Ok(None) };
    let path_buf = fp
        .into_path()
        .map_err(|e| format!("这个位置不能用：{e}"))?;

    // 生成 xlsx 字节 → 整体加密 → 落盘，全程在阻塞线程池。
    tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        let xlsx = crate::export::write_xlsx_bytes(&sheets)?;
        let sealed = crate::backup::seal(&xlsx, &backup_password)?;
        // 写临时文件再改名：失败时不会在用户选的位置留下半截文件。
        let tmp = path_buf.with_extension("xzbak.tmp");
        std::fs::write(&tmp, &sealed).map_err(|e| format!("写不进去：{e}"))?;
        std::fs::rename(&tmp, &path_buf).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("写不进去：{e}")
        })
    })
    .await
    .map_err(|e| format!("导出任务失败：{e}"))??;

    Ok(Some(total))
}

/// 从备份文件（`.xzbak`）或普通 xlsx 导入。
///
/// 两种都能吃：
/// - `.xzbak`：先用备份密码解开，拿到 xlsx 字节再解析
/// - `.xlsx`：直接解析（接受别人给的手工表格、老备份）
///
/// 需要主密码 —— 导入会改动库内容。
///
/// **不接受路径参数**，选文件由本函数弹系统对话框。返回 `None` 表示用户取消。
///
/// 这条路径的定位是**灾备恢复**，所以自定义字段、创建/过期时间、
/// 使用次数都要一起还原，否则「恢复」是假的。
///
/// 去重规则：**名称 + 账号都相同**视为同一条，跳过不导入。
#[tauri::command]
pub async fn import_backup(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    password: String,
    backup_password: Option<String>,
) -> Result<Option<ImportSummary>, String> {
    if password.is_empty() {
        return Err("请输入主密码".to_owned());
    }

    // 选文件：同样由后端弹对话框。
    let picked = {
        let app = app.clone();
        tauri::async_runtime::spawn_blocking(move || {
            app.dialog()
                .file()
                .set_title("选择要导入的文件")
                .add_filter("璇泽备份或 Excel", &["xzbak", "xlsx"])
                .blocking_pick_file()
        })
        .await
        .map_err(|e| format!("打开文件对话框失败：{e}"))?
    };
    let Some(fp) = picked else { return Ok(None) };
    let path_buf = fp
        .into_path()
        .map_err(|e| format!("这个位置读不了：{e}"))?;

    // 读文件 + 解密（如果是备份）+ 解析，全放锁外。
    let backup_pw = backup_password.unwrap_or_default();
    let sheets = tauri::async_runtime::spawn_blocking(move || -> Result<_, String> {
        let raw = std::fs::read(&path_buf).map_err(|e| format!("打不开文件：{e}"))?;
        if crate::backup::looks_like_backup(&raw) {
            if backup_pw.is_empty() {
                return Err("这是加密备份文件，需要输入备份密码".to_owned());
            }
            let xlsx = crate::backup::open(&raw, &backup_pw)?;
            crate::export::read_xlsx_bytes(&xlsx)
        } else {
            crate::export::read_xlsx_bytes(&raw)
        }
    })
    .await
    .map_err(|e| format!("读取任务失败：{e}"))??;

    // 与导出一致：免密码模式下已解锁即视为通过
    ensure_authorized(&state, &password, "主密码不对").await?;

    let mut guard = state.session.lock().map_err(err)?;
    let u = guard.un().ok_or("尚未解锁")?;
    u.last_activity = std::time::Instant::now();

    let now = now_ts();
    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut errors: Vec<String> = Vec::new();

    // 已存在的 (名称, 账号) 组合，用于去重
    let mut existing: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    for item in u.vault.index().all_sorted() {
        if let Some(e) = u.vault.get(&item.id) {
            existing.insert((e.name.clone(), e.username.clone()));
        }
    }

    'sheets: for sheet in &sheets {
        // 表内解析不出条目的行（名称为空）
        skipped += sheet.skipped;
        for row in &sheet.rows {
            // 上限只为挡住畸形/恶意文件一次性把内存吃光，正常库远不到这个量级
            if imported + skipped > MAX_IMPORT_ROWS {
                errors.push(format!("文件超过 {MAX_IMPORT_ROWS} 行，后面的没有导入"));
                break 'sheets;
            }

            let p = &row.entry;
            if existing.contains(&(p.name.clone(), p.username.clone())) {
                skipped += 1;
                continue;
            }

            // 恢复成条目：自定义字段、创建/过期时间、使用次数都在这里还回去。
            // 以前这里写死了 `fields: Vec::new()` 和 `created_at: now`，
            // 「导出即灾备」就是一句空话 —— 恢复出来的是一条残记录。
            let entry = p.clone().into_entry(new_id(), now);
            match u.vault.insert(entry) {
                Ok(_) => {
                    existing.insert((p.name.clone(), p.username.clone()));
                    imported += 1;
                }
                Err(e) => {
                    // 静默跳过是最坏的处理：用户以为恢复了，其实少了一条。
                    // 前几条原因带回去，前端能说清楚「为什么少了」。
                    if errors.len() < 10 {
                        errors.push(format!(
                            "{}/第 {} 行「{}」：{e}",
                            sheet.name, row.row_number, p.name
                        ));
                    }
                    skipped += 1;
                }
            }
        }
    }

    if imported > 0 {
        u.vault.save().map_err(|e| format!("导入后保存失败：{e}"))?;
    }

    Ok(Some(ImportSummary {
        imported,
        skipped,
        errors,
    }))
}

/// 单次导入的行数上限。只为挡住畸形/恶意文件，正常备份连零头都用不到。
const MAX_IMPORT_ROWS: usize = 200_000;

/// 库文件大小上限。
///
/// 5 万条 ≈ 40 MiB，真实个人库很少超过这个量级的一半。设上限是为了让
/// 「默认路径上的文件被换成一个几十 GB 的东西」不至于在打开时把内存吃光。
const MAX_VAULT_BYTES: u64 = 1 << 30;

/// 导入结果，给前端提示用。
#[derive(serde::Serialize)]
pub struct ImportSummary {
    /// 成功导入的条数。
    pub imported: usize,
    /// 跳过的条数（重复、空行、或无法解析）。
    pub skipped: usize,
    /// 失败原因（最多 10 条）。导入是恢复路径，少一条都得说清为什么。
    pub errors: Vec<String>,
}


#[cfg(test)]
mod tests {
    // 测试里 unwrap 是正常写法：出错就该 panic，不需要优雅降级。
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    /// 覆盖保护：只有「同一个库」才允许写回原位置。
    ///
    /// 这条守的是「静默毁数据」—— 前端一旦误判成新用户，就会建空库再保存，
    /// 把用户原来的库覆盖掉。后端必须自己挡住。
    #[test]
    fn only_the_same_vault_may_be_overwritten() {
        use xz_core::kdf::KdfParams;

        let mut a =
            xz_core::vault::Vault::create_bound("pw-a", KdfParams::light(), b"pepper").unwrap();
        let b = xz_core::vault::Vault::create_bound("pw-b", KdfParams::light(), b"pepper").unwrap();
        let bytes_a = a.seal().unwrap();

        // 同一个库 → 允许（日常保存）
        assert!(super::may_overwrite(&bytes_a, &a.vault_id()));
        // 另一个库 → 拒绝
        assert!(!super::may_overwrite(&bytes_a, &b.vault_id()));
        // 不是 vault 的文件 → 拒绝（不替用户删掉看不懂的文件）
        assert!(!super::may_overwrite(b"not a vault at all", &a.vault_id()));
        // 空文件 → 拒绝
        assert!(!super::may_overwrite(&[], &a.vault_id()));
    }

    /// 敏感自定义字段留空 = 保持原值。
    ///
    /// 没有这条，「打开编辑器 → 什么都不改 → 保存」会把这些字段的值擦掉：
    /// 前端从 `entry_get` 拿到的是空值（后端刻意不发敏感值），原样交回去
    /// 就等于用空串覆盖。
    #[test]
    fn blank_secret_field_keeps_old_value() {
        use xz_core::entry::Field;

        let old = vec![
            Field::secret("刷新令牌", "rt-abc"),
            Field::plain("Region", "cn-north-1"),
        ];

        // 敏感字段留空 → 保持原值
        assert_eq!(
            super::resolve_field_value("刷新令牌", String::new(), true, &old),
            "rt-abc"
        );
        // 敏感字段给了新值 → 用新值
        assert_eq!(
            super::resolve_field_value("刷新令牌", "rt-new".into(), true, &old),
            "rt-new"
        );
        // 非敏感字段留空 → 就是清空（用户看得见那一格，清空是他的明确意思）
        assert_eq!(
            super::resolve_field_value("Region", String::new(), false, &old),
            ""
        );
        // 新字段（老库里没有同名）→ 留空就是空
        assert_eq!(
            super::resolve_field_value("新字段", String::new(), true, &old),
            ""
        );
    }
}
