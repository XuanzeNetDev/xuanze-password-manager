//! 桌面二进制入口。
//!
//! 全部逻辑在 `lib.rs`，这里只负责「启动并在出错时给个能看见的提示」。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(e) = xuanze_vault_lib::run() {
        // 生产构建下没有控制台，用系统弹窗兜底。
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            let wide: Vec<u16> = OsStr::new(&e)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            // SAFETY: 宽字符串以 NUL 结尾，MessageBoxW 只读不持有。
            unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
                    std::ptr::null_mut(),
                    wide.as_ptr(),
                    std::ptr::null(),
                    0x0000_0010, // MB_ICONERROR
                );
            }
        }
        #[cfg(not(windows))]
        eprintln!("{e}");
        std::process::exit(1);
    }
}
