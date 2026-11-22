//! 库入口。
//!
//! Windows 上二进制是主入口（`main.rs`），这里把同一套代码暴露成库，
//! 便于将来加集成测试、以及给移动端复用（Tauri v2 的移动端要求有 lib 入口）。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod machine;
pub mod clipboard;
pub mod commands;
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
        .manage(AppState {
            session: Mutex::new(Session::locked()),
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::vault_create,
            commands::vault_open,
            commands::vault_close,
            commands::vault_lock,
            commands::vault_save,
            commands::vault_rekey,
            commands::default_vault_path,
            commands::vault_stats,
            commands::list_hot,
            commands::list_all,
            commands::search_entries,
            commands::list_tags,
            commands::entry_get,
            commands::entry_reveal,
            commands::entry_save,
            commands::entry_delete,
            commands::entry_record_use,
            commands::copy_to_clipboard,
            commands::copy_secret_by_heat,
            commands::touch_activity,
            commands::autolock_check,
            commands::export_csv,
            commands::export_xlsx,
            commands::ui_ready,
        ])
        .setup(|_app| {
            use tauri::Manager as _;

            #[cfg(debug_assertions)]
            if let Some(window) = _app.get_webview_window("main") {
                window.open_devtools();
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
        .run(tauri::generate_context!())
        .map_err(|e| format!("Tauri 启动失败：{e}"))
}