//! 机器绑定的宿主侧：DPAPI 封存本机随机串，产出喂给核心库的 pepper。
//!
//! 核心库自己不做系统调用（`deny(unsafe_code)`），所以 DPAPI 在这里。

use std::path::PathBuf;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;

/// 取 `FOLDERID_RoamingAppData` 的真实路径。
///
/// 不能用 `%APPDATA%` 环境变量：它是可被改写的。让 `APPDATA` 指向攻击者
/// 可控目录，再放一份攻击者自己 DPAPI 封存的 `machine.bind`，就能让任何
/// 拷来的 vault 在这台机器上被解开（或反过来让真库打不开）。
fn roaming_appdata() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_RoamingAppData, SHGetKnownFolderPath, KF_FLAG_DEFAULT,
    };

    let mut ptr: *mut u16 = std::ptr::null_mut();
    // SAFETY: 传入已知的 FOLDERID 常量；成功时 ptr 由系统分配，
    // 立刻转成 PathBuf 后 CoTaskMemFree 释放。
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_RoamingAppData,
            KF_FLAG_DEFAULT as u32,
            std::ptr::null_mut(),
            &mut ptr,
        )
    };
    if hr < 0 || ptr.is_null() {
        return None;
    }
    // SAFETY: hr >= 0 时 ptr 是以 NUL 结尾的有效宽字符串
    let s = unsafe {
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        let p = PathBuf::from(std::ffi::OsString::from_wide(slice));
        CoTaskMemFree(ptr as *mut core::ffi::c_void);
        p
    };
    Some(s)
}

/// 绑定材料存放目录与 vault 同父级，但文件名不同。
fn binding_path() -> Option<PathBuf> {
    let base = roaming_appdata()?;
    Some(base.join("cn.wordpeak.xuanze.vault").join("machine.bind"))
}

/// 库登记表：本机自己创建过的库的 ID。
fn registry_path() -> Option<PathBuf> {
    let base = roaming_appdata()?;
    Some(base.join("cn.wordpeak.xuanze.vault").join("registry"))
}

/// 解锁票据：把主密钥用 DPAPI 封存，下次进入直接取用，跳过 Argon2。
///
/// 这是「软件内重新进入」和「从磁盘开陌生库」的区别：
/// 后者必须老实跑 KDF（那是抗爆破的门槛），前者身份已经验证过了，
/// 再算一遍 KDF 只是让用户白白盯着转圈。
///
/// 安全性由 DPAPI 保证：票据绑定当前 Windows 账户，
/// 拷到别的账户/机器解不开；换机器也就等于没有票据，退回完整 KDF。
fn ticket_path() -> Option<PathBuf> {
    let base = roaming_appdata()?;
    Some(base.join("cn.wordpeak.xuanze.vault").join("unlock.ticket"))
}


/// 票据有效期。到期后必须重新输密码走完整 KDF。
const TICKET_TTL_SECS: u64 = 12 * 3600;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 保存解锁票据。
pub fn save_ticket(vault_id: &str, key: &[u8]) -> Result<(), String> {
    let Some(path) = ticket_path() else {
        return Err("拿不到应用数据目录".to_owned());
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("建不了目录：{e}"))?;
    }
    let payload = format!(
        "{vault_id}\n{}\n{}",
        now_secs() + TICKET_TTL_SECS,
        to_hex(key)
    );
    let sealed = dpapi_protect(payload.as_bytes())?;
    std::fs::write(&path, sealed).map_err(|e| format!("写不了票据：{e}"))?;
    Ok(())
}

/// 取出可用的解锁票据。没有、过期、或库不匹配都返回 `None`。
pub fn load_ticket(vault_id: &str) -> Option<Vec<u8>> {
    let path = ticket_path()?;
    let sealed = std::fs::read(path).ok()?;
    let plain = dpapi_unprotect(&sealed).ok()?;
    let text = String::from_utf8(plain).ok()?;

    let mut lines = text.lines();
    let tid = lines.next()?;
    let exp: u64 = lines.next()?.parse().ok()?;
    let hex = lines.next()?;

    // 库必须对得上，过期就作废
    if tid != vault_id || now_secs() >= exp {
        return None;
    }
    from_hex(hex)
}

/// 删除票据（锁定/退出时调用）。
pub fn clear_ticket() {
    if let Some(path) = ticket_path() {
        let _ = std::fs::remove_file(path);
    }
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write as _;
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// 登记一个新库。
///
/// 建库时调用，把它的 `vault_id` 记下来。之后打开时只认这个表里的 ID ——
/// 从别处拷来的 `.xzvlt`，哪怕密码完全正确，也不给开。
pub fn register_vault(vault_id: &str) -> Result<(), String> {
    let mut ids = known_vaults();
    if !ids.iter().any(|x| x == vault_id) {
        ids.push(vault_id.to_owned());
    }
    write_registry(&ids)
}

/// 这个库是不是本机创建的。
pub fn is_known_vault(vault_id: &str) -> bool {
    known_vaults().iter().any(|x| x == vault_id)
}

/// 读登记表。读不到就当空表（首次使用）。
///
/// 内容用 DPAPI 封存：手工往文件里塞一个 ID 是无效的，
/// 得先能解开当前用户的 DPAPI。
fn known_vaults() -> Vec<String> {
    let Some(path) = registry_path() else {
        return Vec::new();
    };
    let Ok(sealed) = std::fs::read(&path) else {
        return Vec::new();
    };
    let Ok(plain) = dpapi_unprotect(&sealed) else {
        return Vec::new();
    };
    String::from_utf8(plain)
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn write_registry(ids: &[String]) -> Result<(), String> {
    let Some(path) = registry_path() else {
        return Err("拿不到应用数据目录".to_owned());
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("建不了目录：{e}"))?;
    }
    let text = ids.join("\n");
    let sealed = dpapi_protect(text.as_bytes())?;
    std::fs::write(&path, sealed).map_err(|e| format!("写不了登记表：{e}"))?;
    Ok(())
}

/// 本机标识：机器名 + 系统卷序列号。
fn machine_identity() -> String {
    let mut s = std::env::var("COMPUTERNAME").unwrap_or_default();
    if let Some(serial) = volume_serial() {
        s.push('-');
        s.push_str(&serial);
    }
    if s.is_empty() {
        s.push_str("fallback-host");
    }
    s
}

/// 系统卷序列号。
fn volume_serial() -> Option<String> {
    use std::os::windows::ffi::OsStrExt;

    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
    let root: Vec<u16> = std::ffi::OsStr::new(&format!("{drive}\\"))
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut serial: u32 = 0;
    // SAFETY: root 是以 NUL 结尾的宽字符串，其余出参允许为空指针。
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return None;
    }
    Some(format!("{serial:08X}"))
}

/// 取（必要时创建）本机随机串。
///
/// 存在 `%APPDATA%\cn.wordpeak.xuanze.vault\machine.bind`，
/// 用 DPAPI 以当前用户身份加密。拷到别的机器/账号解不开。
fn local_secret() -> Result<Vec<u8>, String> {
    let path = binding_path().ok_or("拿不到应用数据目录")?;
    if path.is_file() {
        let sealed = std::fs::read(&path).map_err(|e| format!("读不了绑定材料：{e}"))?;
        return dpapi_unprotect(&sealed);
    }

    // 第一次：生成 32 字节随机串并封存
    // 复用核心库的随机源（BCryptGenRandom，失败就 abort）
    let secret: [u8; 32] = xz_core::kdf::random_bytes::<32>();
    let sealed = dpapi_protect(&secret)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("建不了目录：{e}"))?;
    }
    std::fs::write(&path, &sealed).map_err(|e| format!("写不了绑定材料：{e}"))?;
    restrict_acl(&path);
    Ok(secret.to_vec())
}

/// 产出喂给 `Vault` 的 pepper。
///
/// 每次开库都要重新取（DPAPI 解密本身很便宜）。
pub fn pepper() -> Result<Vec<u8>, String> {
    let secret = local_secret()?;
    Ok(xz_core::binding::make_pepper(&secret, &machine_identity()))
}

/// 尽力把文件权限收紧到只有当前用户可读。
fn restrict_acl(path: &std::path::Path) {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "*S-1-1-0".to_owned());
    // 失败也不影响加密强度，只是少一层文件系统保护
    let _ = std::process::Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{user}:F"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// DPAPI 加密（当前用户）。
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: BLOB 指向本栈帧的有效内存；成功时 output 由系统分配，
    // 立刻拷出后 LocalFree 释放。
    let ok = unsafe {
        CryptProtectData(
            &mut input,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err("DPAPI 加密失败".to_owned());
    }
    // SAFETY: ok != 0 时 output 指向系统分配的有效缓冲区
    let bytes = unsafe {
        let v = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as *mut core::ffi::c_void);
        v
    };
    Ok(bytes)
}

/// DPAPI 解密（当前用户）。换机器或换账号会失败。
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Err("绑定材料为空".to_owned());
    }
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: 同上
    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err("绑定材料解不开：不是这台机器或这个账号".to_owned());
    }
    // SAFETY: ok != 0 时 output 有效
    let bytes = unsafe {
        let v = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as *mut core::ffi::c_void);
        v
    };
    Ok(bytes)
}
