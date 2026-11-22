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
    Some(base.join("cn.xuanze.vault").join("machine.bind"))
}

/// 库登记表：本机自己创建过的库的 ID。
fn registry_path() -> Option<PathBuf> {
    let base = roaming_appdata()?;
    Some(base.join("cn.xuanze.vault").join("registry"))
}

/// 免密码模式的开关文件。存在即表示已开启。
fn auto_unlock_path() -> Option<PathBuf> {
    let base = roaming_appdata()?;
    Some(base.join("cn.xuanze.vault").join("auto_unlock"))
}

/// 免密码模式是否已开启。
#[must_use]
pub fn auto_unlock_enabled() -> bool {
    auto_unlock_path().is_some_and(|p| p.is_file())
}

/// 开启免密码模式：把主密钥用 DPAPI 封存到本机。
///
/// 和「把主密码改成空」有本质区别：
///
/// - 库文件本身没变，仍然用**完整主密码** + 机器绑定加密
/// - 封存的主密钥只有当前 Windows 账户能解开（DPAPI 用户级）
/// - 拷到别的机器或别的账户，这层就没了，退回必须输主密码
///
/// 所以：文件离开这台机器，保护一点没少；只是在本机上少了一道每次询问。
pub fn enable_auto_unlock(vault_id: &str, key: &[u8]) -> Result<(), String> {
    let Some(path) = auto_unlock_path() else {
        return Err("拿不到应用数据目录".to_owned());
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("建不了目录：{e}"))?;
    }
    // 格式：vault_id 换行 主密钥十六进制
    let payload = [vault_id, "\n", &to_hex(key)].concat();
    let sealed = dpapi_protect(payload.as_bytes())?;
    std::fs::write(&path, sealed).map_err(|e| format!("写不了免密码标记：{e}"))?;
    restrict_acl(&path);
    Ok(())
}

/// 关闭免密码模式：删掉封存的主密钥。
pub fn disable_auto_unlock() {
    if let Some(path) = auto_unlock_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// 取出封存的主密钥。未开启、库不匹配、或解不开都返回 `None`。
pub fn load_auto_unlock(vault_id: &str) -> Option<Vec<u8>> {
    let path = auto_unlock_path()?;
    let sealed = std::fs::read(path).ok()?;
    let plain = dpapi_unprotect(&sealed).ok()?;
    let text = String::from_utf8(plain).ok()?;

    let mut lines = text.lines();
    let tid = lines.next()?;
    let hex = lines.next()?;
    if tid != vault_id {
        return None;
    }
    from_hex(hex)
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

/// 本机是否已经建过库（登记表非空）。
///
/// 用来区分「第一次使用」和「绑定材料丢了」——这两种情况都表现为
/// `machine.bind` 不存在，但处理方式完全相反。
fn has_registered_vault() -> bool {
    !known_vaults().is_empty()
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
///
/// 两个成分都走 Win32 API 读取，不读环境变量。
///
/// 为什么：`COMPUTERNAME` 和 `SystemDrive` 都是用户态可改的环境变量，
/// 任何进程都能在启动时把它们改掉再拉起见程序，得到的 pepper 就变了。
/// 而本文件上面 `roaming_appdata()` 已经明确写过「不能用 `%APPDATA%`，
/// 因为它可被改写」—— 同样的理由对这两个变量一样成立，标准得一致。
fn machine_identity() -> String {
    let mut s = computer_name().unwrap_or_default();
    if let Some(serial) = volume_serial() {
        s.push('-');
        s.push_str(&serial);
    }
    if s.is_empty() {
        s.push_str("fallback-host");
    }
    s
}

/// 机器名，走 `GetComputerNameExW`。
///
/// 走 API 而不是环境变量的原因见 `machine_identity` 的注释。
fn computer_name() -> Option<String> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsHostname, GetComputerNameExW,
    };

    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: buf 有 256 个 u16 的容量，len 是其真实长度按引用传入，
    // API 只在这段可写区间内填充并以 NUL 结尾。
    let ok = unsafe { GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), &mut len) };
    if ok == 0 || len == 0 {
        return None;
    }
    Some(
        std::ffi::OsString::from_wide(&buf[..len as usize])
            .to_string_lossy()
            .into_owned(),
    )
}

/// 系统卷序列号。
fn volume_serial() -> Option<String> {
    use std::os::windows::ffi::OsStrExt;

    // 系统盘固定取 C:，不读 `SystemDrive` —— 理由同 `machine_identity`。
    // Windows 装在别的盘的机器极少，而且那种情况下这一项退化为空，
    // 由机器名单独承担区分度，不影响正确性。
    let root: Vec<u16> = std::ffi::OsStr::new("C:\\")
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
/// 存在 `%APPDATA%\cn.xuanze.vault\machine.bind`，
/// 用 DPAPI 以当前用户身份加密。拷到别的机器/账号解不开。
fn local_secret() -> Result<Vec<u8>, String> {
    let path = binding_path().ok_or("拿不到应用数据目录")?;
    if path.is_file() {
        let sealed = std::fs::read(&path).map_err(|e| format!("读不了绑定材料：{e}"))?;
        return dpapi_unprotect(&sealed);
    }

    // 文件不在，但登记表里已经有库 —— 说明原来的绑定材料丢了，
    // 不是「第一次使用」。
    //
    // 这时候生成一个新的随机串只会骗人：算出来的主密钥必然不对，
    // 用户会看到「密码错误」，然后一遍遍重试一个其实正确的密码。
    // 必须直接说清楚发生了什么。
    if has_registered_vault() {
        return Err(
            "本机的绑定材料（machine.bind）不见了，无法打开已有的库。\n\n\
             可能的原因为：清理了 %APPDATA%、重装系统、或换过硬件。\n\
             绑定材料是解密库的必要条件，丢失后无法重建 —— 这是本产品\
             「数据只能在本机使用」这一设计的直接后果。"
                .to_owned(),
        );
    }

    // 第一次使用：生成 32 字节随机串并封存。
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
///
/// 用当前进程的实际令牌取 SID，不读 `USERNAME` 环境变量 ——
/// 那个变量任何进程都能在拉起子进程前改掉，改完这里就会给
/// 「攻击者指定的那个用户名」授权，等于把保护反着用。
///
/// 失败也不影响加密强度，只是少一层文件系统保护。
fn restrict_acl(path: &std::path::Path) {
    let Some(sid) = current_user_sid() else {
        return;
    };
    let _ = std::process::Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        // SID 形如 S-1-5-21-...，只含数字与连字符，不含空格和引号，
        // 不会有命令行解析问题。
        .arg(format!("{sid}:F"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// 取当前进程所属用户的 SID 字符串。
fn current_user_sid() -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: 全程只用本函数持有的句柄；每个 Open 都有对应的 Close，
    // 缓冲区通过两段式调用（先问长度、再分配）保证足够大。
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }

        let mut len: u32 = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        if len == 0 {
            CloseHandle(token);
            return None;
        }

        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
        CloseHandle(token);
        if ok == 0 {
            return None;
        }

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut raw: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(token_user.User.Sid, &mut raw) == 0 {
            return None;
        }

        let mut n = 0usize;
        while *raw.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(raw, n));
        // LocalFree 用进程堆的通用释放函数
        windows_sys::Win32::Foundation::LocalFree(raw.cast());
        Some(s)
    }
}

/// DPAPI 加密（当前用户）。
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    let input = CRYPT_INTEGER_BLOB {
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
            &input,
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
    let input = CRYPT_INTEGER_BLOB {
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
            &input,
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
