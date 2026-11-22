//! 剪贴板：写入 + 定时清除。
//!
//! 这里直接调 Win32，不用第三方 crate，理由：
//! - 少一个依赖，开源项目的依赖树越短越好
//! - 需要精确控制「只清自己写进去的那份」——如果用通用 clipboard crate，
//!   清空逻辑没法判断当前剪贴板是不是已经被用户换了内容
//!
//! 清除策略：写入后记一个序号 + 到期时间，后台线程到点检查：
//! 如果剪贴板里的内容**还是我们写的那份**（序号/内容比对），就清空；
//! 已经被用户覆盖的就不动，避免踩掉用户刚复制的东西。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 当前待清除内容的指纹。0 表示没有待清除项。
static PENDING_FP: AtomicU64 = AtomicU64::new(0);
/// 待清除内容被写入时的时间。
static PENDING_AT: Mutex<Option<Instant>> = Mutex::new(None);
/// 后台清理线程是否已启动。
static STARTED: AtomicU64 = AtomicU64::new(0);

/// 内容指纹（简易 FNV-1a，只用于「是不是同一份」的判断，不需要抗碰撞）。
fn fingerprint(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h.max(1)
}

/// 把文本写进剪贴板，并在 `ttl` 后自动清除。
///
/// # 错误
/// Win32 剪贴板被别的进程占用时会返回错误，调用方应提示用户重试。
pub fn copy_with_ttl(text: &str, ttl: Duration) -> Result<(), String> {
    write_clipboard(text)?;

    PENDING_FP.store(fingerprint(text), Ordering::SeqCst);
    if let Ok(mut guard) = PENDING_AT.lock() {
        *guard = Some(Instant::now() + ttl);
    }

    ensure_cleaner();
    Ok(())
}

/// 写入剪贴板（不安排清除）。用于非敏感内容，如用户名。
pub fn copy_plain(text: &str) -> Result<(), String> {
    write_clipboard(text)
}

/// 立即尝试清除（如果剪贴板还是我们写的内容）。
pub fn purge_if_ours() {
    let expected = PENDING_FP.swap(0, Ordering::SeqCst);
    if expected == 0 {
        return;
    }
    // 读回来比对：只有内容没被用户换掉时才清。
    if let Ok(current) = read_clipboard() {
        if fingerprint(&current) == expected {
            let _ = write_clipboard("");
        }
    }
}

fn ensure_cleaner() {
    if STARTED.swap(1, Ordering::SeqCst) != 0 {
        return;
    }
    std::thread::spawn(|| loop {
        std::thread::sleep(Duration::from_millis(500));
        let due = PENDING_AT
            .lock()
            .ok()
            .and_then(|g| *g)
            .is_some_and(|at| Instant::now() >= at);
        if due {
            purge_if_ours();
            if let Ok(mut g) = PENDING_AT.lock() {
                *g = None;
            }
        }
    });
}

#[cfg(windows)]
mod win {
    use std::ptr;

    use windows_sys::Win32::Foundation::HGLOBAL;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

    /// 打开剪贴板并执行操作。
    fn with_clipboard<T>(f: impl FnOnce() -> Option<T>) -> Result<T, String> {
        // SAFETY: 成对调用 Open/Close，所有指针都在作用域内使用完毕。
        unsafe {
            // 剪贴板可能被别的进程短暂占用，重试几次。
            let mut opened = false;
            for _ in 0..10 {
                if OpenClipboard(ptr::null_mut()) != 0 {
                    opened = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            if !opened {
                return Err("剪贴板被其他程序占用".to_owned());
            }
            let result = f().ok_or_else(|| "剪贴板操作失败".to_owned());
            CloseClipboard();
            result
        }
    }

    pub fn write(text: &str) -> Result<(), String> {
        // 转成 UTF-16 并补 NUL 结尾。
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let byte_len = wide.len() * std::mem::size_of::<u16>();

        with_clipboard(|| {
            // SAFETY: 全局内存分配后立刻加锁写入，写满 byte_len 字节再解锁。
            unsafe {
                if EmptyClipboard() == 0 {
                    return None;
                }
                let h: HGLOBAL = GlobalAlloc(GMEM_MOVEABLE, byte_len);
                if h.is_null() {
                    return None;
                }
                let dst = GlobalLock(h) as *mut u16;
                if dst.is_null() {
                    return None;
                }
                ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
                GlobalUnlock(h);
                if SetClipboardData(CF_UNICODETEXT as u32, h).is_null() {
                    return None;
                }
                Some(())
            }
        })
    }

    pub fn read() -> Result<String, String> {
        with_clipboard(|| {
            // SAFETY: GetClipboardData 返回句柄，在其有效期（剪贴板打开期间）内读取。
            unsafe {
                let h = GetClipboardData(CF_UNICODETEXT as u32);
                if h.is_null() {
                    return Some(String::new());
                }
                let p = GlobalLock(h) as *const u16;
                if p.is_null() {
                    return Some(String::new());
                }
                let mut len = 0usize;
                while *p.add(len) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(p, len);
                let s = String::from_utf16_lossy(slice);
                GlobalUnlock(h);
                Some(s)
            }
        })
    }
}

#[cfg(windows)]
fn write_clipboard(text: &str) -> Result<(), String> {
    win::write(text)
}

#[cfg(windows)]
fn read_clipboard() -> Result<String, String> {
    win::read()
}

#[cfg(not(windows))]
fn write_clipboard(_text: &str) -> Result<(), String> {
    Err("当前平台不支持剪贴板".to_owned())
}

#[cfg(not(windows))]
fn read_clipboard() -> Result<String, String> {
    Err("当前平台不支持剪贴板".to_owned())
}
