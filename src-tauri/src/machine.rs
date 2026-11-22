//! 机器绑定的宿主侧：读硬件身份、管 DPAPI 封存的材料、产出 pepper 的来源。
//!
//! 核心库自己不做系统调用（`deny(unsafe_code)`），所以这些都在这儿。
//!
//! 这个模块管三样东西：
//!
//! - **硬件指纹**（[`hardware_fingerprint`]）：SMBIOS UUID，重装不变、换板才变
//! - **机器身份**（[`machine_identity`]）：机器名 + 卷序列号，**只给 v2 老库用**
//! - **免密码模式**（`enable_auto_unlock`）：DPAPI 封存主密钥，与绑定无关

use std::path::PathBuf;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;
use zeroize::{Zeroize, Zeroizing};
use xz_core::secure::SecretBytes;

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

/// 自动锁定分钟数的存放文件。纯文本，不是秘密。
fn autolock_path() -> Option<PathBuf> {
    let base = roaming_appdata()?;
    Some(base.join("cn.xuanze.vault").join("autolock"))
}

/// 自动锁定的闲置分钟数。默认 5 分钟。
///
/// 为什么不放前端的 `localStorage`：清一次 WebView 数据就回到默认值，
/// 而用户以为自己设的是 30 分钟 —— 这种「设置其实没生效」的不一致，
/// 在安全选项上尤其不能有。
#[must_use]
pub fn autolock_minutes() -> u32 {
    /// 默认值。也是文件缺失/读不懂时的兜底。
    const DEFAULT: u32 = 5;
    let Some(path) = autolock_path() else {
        return DEFAULT;
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return DEFAULT;
    };
    text.trim()
        .parse::<u32>()
        .map(|v| v.clamp(1, MAX_AUTOLOCK_MINUTES))
        .unwrap_or(DEFAULT)
}

/// 自动锁定分钟数的上界。再长就接近「实际上不锁」了。
pub const MAX_AUTOLOCK_MINUTES: u32 = 120;

/// 写入自动锁定分钟数。
pub fn set_autolock_minutes(minutes: u32) -> Result<u32, String> {
    let minutes = minutes.clamp(1, MAX_AUTOLOCK_MINUTES);
    let Some(path) = autolock_path() else {
        return Err("拿不到应用数据目录".to_owned());
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("建不了目录：{e}"))?;
    }
    std::fs::write(&path, minutes.to_string()).map_err(|e| format!("写不了设置：{e}"))?;
    Ok(minutes)
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
    //
    // 这条 payload 里握着**主密钥本身**（以 hex 形式）。它是整个产品里
    // 最不能留在堆上的字符串 —— 早先这里是一个裸 `String`，封存完就
    // 交给分配器，那段内存里还躺着能解开全库的钥匙。
    // 现在从拼接到 drop 全程 `Zeroizing`。
    let payload = Zeroizing::new(format!("{vault_id}\n{}", to_hex(key).as_str()));
    let sealed = Zeroizing::new(dpapi_protect(payload.as_bytes())?);
    std::fs::write(&path, sealed.as_slice()).map_err(|e| format!("写不了免密码标记：{e}"))?;
    tighten(&path);
    Ok(())
}

/// 关闭免密码模式：删掉封存的主密钥。
pub fn disable_auto_unlock() {
    if let Some(path) = auto_unlock_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// 取出封存的主密钥。未开启、库不匹配、或解不开都返回 `None`。
///
/// 返回 `SecretBytes` 而不是裸 `Vec<u8>`：调用方拿到后会立刻用掉，
/// 但「调用方自己记得擦」这件事早就证明靠不住 —— 早先这里返回裸 Vec，
/// 上层拷进 `SecretBytes` 之后，原来那一份仍然带着 32 字节主密钥躺在堆上。
pub fn load_auto_unlock(vault_id: &str) -> Option<SecretBytes> {
    let path = auto_unlock_path()?;
    let sealed = std::fs::read(path).ok()?;
    let plain = dpapi_unprotect(&sealed).ok()?;
    let text = Zeroizing::new(String::from_utf8(plain.to_vec()).ok()?);

    let mut lines = text.lines();
    let tid = lines.next()?;
    let hex = lines.next()?;
    if tid != vault_id {
        return None;
    }
    from_hex(hex).map(SecretBytes::from_vec)
}

/// 32 字节 → 64 个 hex 字符。返回 `Zeroizing`：它承载的是主密钥。
fn to_hex(b: &[u8]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(b.len() * 2));
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
///
/// 前端也靠它判断「该显示注册页还是登录页」：`localStorage` 里那条
/// 「上次用的路径」清一次 WebView 数据就没了，拿它当判据会让老用户
/// 走进注册流程、在默认路径上盖掉原来那个库。判据必须问后端。
pub fn has_registered_vault() -> bool {
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
    String::from_utf8(plain.to_vec())
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
/// **只用于 v2 格式的老库**（那些库的 pepper 里混了这两个值）。
/// 新库（v3）改用 [`hardware_fingerprint`]，因为这里两个值都会随便变：
/// 计算机名右键就能改，卷序列号格式化就重新生成。
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

/// 主板 UUID（SMBIOS Type 1 的 UUID 字段）。
///
/// 这是「这台设备」最稳的标识：
///
/// - 重装系统 → 不变
/// - 格式化硬盘 → 不变
/// - 改计算机名 → 不变
/// - **换主板 → 变**
///
/// 正好是「设备绑定」想表达的语义。
///
/// 返回 `None` 表示读不到（很老的机器、部分虚拟机、SMBIOS 里没填）。
/// 调用方必须给兜底路径 —— 不能因为读不到就不让用。
fn smbios_uuid() -> Option<[u8; 16]> {
    use windows_sys::Win32::System::SystemInformation::GetSystemFirmwareTable;

    // 'RSMB' 的多字符常量值：MSVC 把第一个字符放在最高位，
    // 所以 'R'<<24 | 'S'<<16 | 'M'<<8 | 'B' = 0x52534D42。
    // （写成 0x42534D52 是按小端读出来的反序值，Windows 不认。）
    const RSMB: u32 = 0x5253_4D42;

    // SAFETY: 两段式调用 —— 先问长度、再按长度分配缓冲，缓冲由本函数持有。
    let size = unsafe { GetSystemFirmwareTable(RSMB, 0, std::ptr::null_mut(), 0) };
    if size < 8 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: buf 至少 size 字节，函数只在这段可写区间内填充。
    let got = unsafe { GetSystemFirmwareTable(RSMB, 0, buf.as_mut_ptr().cast(), size) };
    if got == 0 || got as usize > buf.len() {
        return None;
    }
    let data = &buf[..got as usize];

    // RawSMBIOSData：4 字节版本信息，然后 u32 Length，然后是结构表本身。
    let table_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let table = data.get(8..8usize.checked_add(table_len)?)?;

    // 逐个结构扫，找 Type 1（System Information）。
    let mut off = 0usize;
    while off + 4 <= table.len() {
        let stype = table[off];
        let slen = table[off + 1] as usize;
        if slen < 4 || off + slen > table.len() {
            break;
        }
        // Type 1 的 UUID 在结构内偏移 0x08，长 16 字节；整个结构至少 0x19 字节。
        if stype == 1 && slen >= 0x19 {
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&table[off + 8..off + 24]);
            // 全 0 / 全 FF 是「厂商没填」，不能当设备标识用 ——
            // 那会让一大批机器共用同一个指纹。
            if uuid.iter().all(|&b| b == 0) || uuid.iter().all(|&b| b == 0xFF) {
                return None;
            }
            return Some(uuid);
        }
        // 跳到下一个结构：结构头 + 格式化区，以双 NUL 结束（有的固件只补一个）。
        let mut next = off + slen;
        while next + 1 < table.len() {
            if table[next] == 0 && table[next + 1] == 0 {
                next += 2;
                break;
            }
            next += 1;
        }
        if next <= off {
            break;
        }
        off = next;
    }
    None
}

/// 当前设备的硬件指纹。读不到时返回 `None`。
///
/// 只收「换硬件才会变」的标识。前端拿到 `None` 就该退回 v2 的绑定规则
/// （那条路会绑定机器名和卷序列号，虽然脆，但总比没有强）。
#[must_use]
pub fn hardware_fingerprint() -> Option<Vec<u8>> {
    let uuid = smbios_uuid()?;
    let mut out = Vec::with_capacity(16 + 12);
    out.extend_from_slice(b"xzvlt-hw-v1\x00");
    out.extend_from_slice(&uuid);
    Some(out)
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
fn local_secret() -> Result<Zeroizing<Vec<u8>>, String> {
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
    let mut secret: [u8; 32] = xz_core::kdf::random_bytes::<32>();
    let sealed = Zeroizing::new(dpapi_protect(&secret)?);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("建不了目录：{e}"))?;
    }
    std::fs::write(&path, sealed.as_slice()).map_err(|e| format!("写不了绑定材料：{e}"))?;
    tighten(&path);
    // 栈上这一份也要擦：它没有 Drop，离开作用域只是「不再引用」。
    let out = Zeroizing::new(secret.to_vec());
    secret.zeroize();
    Ok(out)
}

/// 产出喂给 `Vault` 的 pepper。
///
/// 每次开库都要重新取（DPAPI 解密本身很便宜）。
pub fn pepper() -> Result<Vec<u8>, String> {
    let secret = local_secret()?;
    Ok(xz_core::binding::make_pepper(secret.as_slice(), &machine_identity()))
}

/// 尽力把文件权限收紧到只有当前用户可读。
///
/// 用当前进程的实际令牌取 SID，不读 `USERNAME` 环境变量 ——
/// 那个变量任何进程都能在拉起子进程前改掉，改完这里就会给
/// 「攻击者指定的那个用户名」授权，等于把保护反着用。
///
/// 失败不影响加密强度，只是少一层文件系统保护。但**不能静默**：
/// 如果这一步失败了，`auto_unlock` 那种「本机任何程序都能读」的性质
/// 可能扩散到别的账户。返回布尔值，调用方在 debug 构建下记一笔。
fn restrict_acl(path: &std::path::Path) -> bool {
    let Some(sid) = current_user_sid() else {
        return false;
    };
    std::process::Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        // SID 形如 S-1-5-21-...，只含数字与连字符，不含空格和引号，
        // 不会有命令行解析问题。
        .arg(format!("{sid}:F"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// 收紧权限并处理失败：debug 下留痕，release 下不打扰用户。
fn tighten(path: &std::path::Path) {
    if !restrict_acl(path) {
        #[cfg(debug_assertions)]
        eprintln!("[machine] 收紧文件权限失败：{}", path.display());
    }
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
///
/// 解出来的**是明文**（机器串 / 主密钥 hex / 登记表），所以返回
/// `Zeroizing` 而不是 `Vec<u8>`：出了这个函数也不许留残影。
fn dpapi_unprotect(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
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
        let v = Zeroizing::new(
            std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec(),
        );
        LocalFree(output.pbData as *mut core::ffi::c_void);
        v
    };
    Ok(bytes)
}
