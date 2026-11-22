//! 库入口。
//!
//! Windows 上二进制是主入口（`main.rs`），这里把同一套代码暴露成库，
//! 便于将来加集成测试、以及给移动端复用（Tauri v2 的移动端要求有 lib 入口）。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod clipboard;
pub mod commands;
pub mod export;
pub mod machine;
pub mod session;

use std::sync::Mutex;

use session::Session;

/// 应用全局状态。只有一个可变入口 [`Session`]，其余全是配置。
pub struct AppState {
    /// 当前会话（未解锁时为 `Locked`）。
    pub session: Mutex<Session>,
}

/// 启动应用。桌面 `main.rs` 与移动端入口都调它。
///
/// # 错误
/// Tauri 初始化失败或事件循环异常退出时返回错误字符串。
pub fn run() -> Result<(), String> {
    tauri::Builder::default()
        // 导出要用系统「另存为」对话框选位置。没有这个插件就只能在代码里
        // 猜一个路径写下去 —— 用户既不知道文件在哪，也没法取消。
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            session: Mutex::new(Session::locked()),
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::vault_create,
            commands::vault_open,
            commands::vault_lock,
            commands::auto_unlock_status,
            commands::enable_auto_unlock,
            commands::disable_auto_unlock,
            commands::vault_save,
            commands::vault_rekey,
            commands::default_vault_path,
            commands::list_hot,
            commands::list_all,
            commands::search_entries,
            commands::entry_get,
            commands::entry_reveal,
            commands::entry_save,
            commands::entry_delete,
            commands::entry_record_use,
            commands::copy_to_clipboard,
            commands::copy_secret_by_heat,
            commands::touch_activity,
            commands::autolock_check,
            commands::ui_ready,
            commands::export_xlsx,
            commands::import_xlsx,
        ])
        .setup(|_app| {
            use tauri::Manager as _;

            #[cfg(debug_assertions)]
            if let Some(window) = _app.get_webview_window("main") {
                window.open_devtools();
            }

            // 发布版关掉一切能让用户打开控制台的口子。
            //
            // 为什么这件事对密码管理器特别重要：这台界面里最敏感的东西
            // 就是解密后的明文。控制台一开，`await invoke('list_all')` 就能
            // 把整个库打印出来 —— 那之前所有的加密、绑定、擦除都白做了。
            //
            // 三层一起上：
            //   1. Cargo.toml 的 tauri features 不含 `devtools` —— 编译期就没有这个能力
            //   2. tauri.conf.json 的窗口 `devtools: false` —— 运行时不注册
            //   3. 下面这段 —— 把 WebView2 自带的快捷键和右键菜单也堵掉
            //
            // 第 3 层是必须的：WebView2 自己认 F12 / Ctrl+Shift+I，
            // 那是浏览器内核的行为，不受 Tauri 的 devtools 开关管。
            #[cfg(not(debug_assertions))]
            if let Some(window) = _app.get_webview_window("main") {
                let _ = window.eval(
                    r#"
                    (() => {
                      // 拦开发工具快捷键：F12、Ctrl+Shift+I/J/C、Ctrl+U（看源码）
                      addEventListener('keydown', (e) => {
                        const k = e.key.toLowerCase();
                        if (e.key === 'F12') { e.preventDefault(); return false; }
                        if (e.ctrlKey && e.shiftKey && ['i','j','c'].includes(k)) {
                          e.preventDefault(); return false;
                        }
                        if (e.ctrlKey && k === 'u') { e.preventDefault(); return false; }
                      }, true);

                      // 关掉右键菜单 —— 里面的「检查」是另一条入口
                      addEventListener('contextmenu', (e) => {
                        e.preventDefault(); return false;
                      }, true);
                    })();
                    "#,
                );
            }

            // 关键：Windows 上的 WebView2 在高 DPI（本机 150%）下，
            // Tauri 给的 `width/height` 会被当成**物理**像素塞给 WebView，
            // 于是页面按 CSS 像素排版后发现视口只有 787×507，只填满窗口的 2/3，
            // 剩下 1/3 露出桌面。
            //
            // 修法：把窗口尺寸按 `scale_factor` 放大到「逻辑尺寸 × 缩放」的物理尺寸，
            // 让 WebView 的物理视口恰好等于 1180×760 CSS px 的物理等价物。
            // 用 PhysicalSize 而不是 LogicalSize —— 后者会被 Tauri 再乘一次缩放，等于没改。
            #[cfg(desktop)]
            if let Some(window) = _app.get_webview_window("main") {
                if let Ok(scale) = window.scale_factor() {
                    if scale > 1.0 {
                        let _ = window.set_size(tauri::PhysicalSize::new(
                            (1180.0 * scale).round() as u32,
                            (760.0 * scale).round() as u32,
                        ));
                        let _ = window.center();
                    }
                }
            }
            Ok(())
        })
        // 关窗口时把改动落盘。
        //
        // 没有这段的话，用户改完条目直接点 × 关闭，那些改动随进程一起消失 ——
        // 而界面上没有任何提示说「还没保存」。早先有一个 vault_close 命令，
        // 但从来没人调用它，等于这个兜底一直是空的。
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                use tauri::Manager as _;
                let state = window.state::<AppState>();
                if let Ok(mut guard) = state.session.lock() {
                    let _ = guard.lock();
                }
                clipboard::purge_if_ours();
            }
        })
        .run(tauri::generate_context!())
        .map_err(|e| format!("Tauri 启动失败：{e}"))
}
