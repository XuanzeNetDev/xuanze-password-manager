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
//!
//! 两个容易做错的地方，都在下面注释里写清楚了：
//! 1. 读回来的内容**不一定**以 NUL 结尾（别的进程可以往剪贴板放任意字节），
//!    所以扫描必须有上界，否则是越界读。
//! 2. 「清除」可能因为剪贴板被占用而失败。失败不能当作「已清除」，
//!    否则那份密码会一直躺在剪贴板里，直到用户自己复制别的东西。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 当前待清除内容的指纹。0 表示没有待清除项。
static PENDING_FP: AtomicU64 = AtomicU64::new(0);
/// 待清除内容被写入时的时间。
static PENDING_AT: Mutex<Option<Instant>> = Mutex::new(None);
/// 每写入一次自增，用来识别「我正在处理的是不是最新那次写入」。
static GENERATION: AtomicU64 = AtomicU64::new(0);
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
    GENERATION.fetch_add(1, Ordering::SeqCst);
    if let Ok(mut guard) = PENDING_AT.lock() {
        *guard = Some(Instant::now() + ttl);
    }

    ensure_cleaner();
    Ok(())
}


/// 立即尝试清除（如果剪贴板还是我们写的内容）。
///
/// 返回 `true` 表示「已经处理完，不用再试」；`false` 表示这次没清掉
/// （剪贴板被别的程序占着），调用方应当稍后重试 —— 别把失败当成成功。
pub fn purge_if_ours() -> bool {
    let expected = PENDING_FP.load(Ordering::SeqCst);
    if expected == 0 {
        return true;
    }

    // 读不回来（剪贴板被占用）：**保留指纹**，下次再试。
    // 早先这里是 `swap(0)` 先清掉指纹再读，读失败就等于永久放弃了这次清除，
    // 那份密码会一直躺在剪贴板里。
    let Ok(current) = read_clipboard() else {
        return false;
    };

    // 内容已经被用户换了 → 不是我们的东西了，放手（并且可以取消计划）。
    if fingerprint(&current) != expected {
        PENDING_FP.store(0, Ordering::SeqCst);
        return true;
    }

    if write_clipboard("").is_err() {
        return false; // 写不进去，保留指纹下次重试
    }
    PENDING_FP.store(0, Ordering::SeqCst);
    true
}

fn ensure_cleaner() {
    if STARTED.swap(1, Ordering::SeqCst) != 0 {
        return;
    }
    std::thread::spawn(|| loop {
        std::thread::sleep(Duration::from_millis(500));

        // 先把「到期」这个判断和代际号一起取出来。
        //
        // 竞态：清理线程判定到期的同一刻，主线程可能刚写入了新的敏感内容。
        // 若不校验代际号，紧接着的 purge 会把**刚写进去的那份**清掉 ——
        // 表现是「复制了，粘贴出来是空的」。所以只处理「我还看着的那一代」。
        let (due, gen) = {
            let Ok(guard) = PENDING_AT.lock() else {
                continue;
            };
            (
                guard.is_some_and(|at| Instant::now() >= at),
                GENERATION.load(Ordering::SeqCst),
            )
        };
        if !due {
            continue;
        }

        // 仍然是同一代 → 没人插队，可以清
        if GENERATION.load(Ordering::SeqCst) == gen && purge_if_ours() {
            if let Ok(mut g) = PENDING_AT.lock() {
                // 再确认一次代际，避免把新一代的到期时间抹掉
                if GENERATION.load(Ordering::SeqCst) == gen {
                    *g = None;
                }
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
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
    };
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
                    // 加锁失败就得自己释放：SetClipboardData 还没拿到这个句柄。
                    // 用 LocalFree 而不是 GlobalFree：32/64 位 Windows 上
                    // 全局堆和本地堆是同一个堆，两者等价（windows-sys 0.59
                    // 也没导出 GlobalFree）。
                    LocalFree(h);
                    return None;
                }
                ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
                GlobalUnlock(h);
                if SetClipboardData(CF_UNICODETEXT as u32, h).is_null() {
                    // 失败时所有权没有转移给系统，同样要自己释放。
                    LocalFree(h);
                    return None;
                }
                Some(())
            }
        })
    }

    pub fn read() -> Result<String, String> {
        with_clipboard(|| {
            // SAFETY: GetClipboardData 返回句柄，在其有效期（剪贴板打开期间）内读取。
            // 扫描长度用 GlobalSize 上界：剪贴板里的数据是**别的进程**放进去的，
            // 格式上要求 NUL 结尾，但没人强制它照做 —— 无界扫描就是越界读。
            unsafe {
                let h = GetClipboardData(CF_UNICODETEXT as u32);
                if h.is_null() {
                    return Some(String::new());
                }
                let p = GlobalLock(h) as *const u16;
                if p.is_null() {
                    return Some(String::new());
                }
                let bytes = GlobalSize(h);
                let cap = bytes / std::mem::size_of::<u16>();
                if cap == 0 {
                    GlobalUnlock(h);
                    return Some(String::new());
                }
                let mut len = 0usize;
                while len < cap && *p.add(len) != 0 {
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
