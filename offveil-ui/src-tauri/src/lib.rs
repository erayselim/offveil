mod autoconnect;
mod autostart;
mod core_ipc;
mod service;

use core_ipc::{DiagnosticsBundle, Status, TestReport};
use service::BootstrapInfo;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tauri::{
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    webview::PageLoadEvent,
    AppHandle, Emitter, Manager, PhysicalPosition, RunEvent, Theme, WindowEvent,
};

/// True while we are intentionally quitting (stop core service first).
pub(crate) static QUITTING: AtomicBool = AtomicBool::new(false);
/// Cancel a pending click-outside hide (tray click races with blur).
static BLUR_HIDE: AtomicBool = AtomicBool::new(false);
/// Blur-to-tray only after the window has been focused once (avoids hiding on launch).
static EVER_FOCUSED: AtomicBool = AtomicBool::new(false);
/// Started with --tray / --minimized; do not auto-show after first paint.
static START_HIDDEN: AtomicBool = AtomicBool::new(false);
/// WebView has finished its first document load (safe to uncloak).
static WEBVIEW_READY: AtomicBool = AtomicBool::new(false);
/// Cancels an in-flight show/hide fade when the other starts.
static MAIN_GEN: AtomicU64 = AtomicU64::new(0);
/// True while the hide fade is running (window still visible).
static DISMISSING: AtomicBool = AtomicBool::new(false);
/// Native tray menu labels: false = Turkish, true = English.
static TRAY_LOCALE_EN: AtomicBool = AtomicBool::new(false);

const TRAY_ID: &str = "main";
const REVEAL_MS: u64 = 160;

/// Embedded tray PNGs (compile-time). 32×32 keeps the binary small.
const ICON_DEFAULT: &[u8] = include_bytes!("../icons/32x32.png");
const ICON_LIGHT: &[u8] = include_bytes!("../icons/tray-light.png");
const ICON_DARK: &[u8] = include_bytes!("../icons/tray-dark.png");

/// Fully transparent native fill so CSS `clip-path` can anti-alias the corners.
/// `SetWindowRgn` is a 1-bit mask and looks pixelated; do not bring it back.
const WINDOW_BG_CLEAR: tauri::window::Color = tauri::window::Color(0, 0, 0, 0);

async fn run_blocking<T, F>(f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("task join: {e}"))?
}

#[tauri::command]
async fn probe_bootstrap() -> BootstrapInfo {
    tauri::async_runtime::spawn_blocking(service::probe)
        .await
        .unwrap_or_else(|_| BootstrapInfo {
            state: service::BootstrapState::NeedsInstall,
            message: "Durum alınamadı".into(),
            core_path: None,
            service_installed: false,
            pipe_ok: false,
        })
}

#[tauri::command]
async fn ensure_service() -> Result<BootstrapInfo, String> {
    run_blocking(service::ensure_service).await
}

#[tauri::command]
async fn get_status() -> Result<Status, String> {
    run_blocking(|| {
        // Do not pre-ping (was doubling latency / freezes). status itself fails fast if down.
        match core_ipc::status() {
            Ok(s) => Ok(s),
            Err(e)
                if e.contains("pipe not found")
                    || e.contains("pipe open")
                    || e.contains("pipe unavailable") =>
            {
                Err(format!("not_connected: Core servisine bağlanılamadı ({e})"))
            }
            Err(e) => Err(e),
        }
    })
    .await
}

#[tauri::command]
async fn set_protection(enabled: bool) -> Result<Status, String> {
    run_blocking(move || {
        if enabled {
            service::start_installed()?;
            core_ipc::start()
        } else if !core_ipc::is_reachable() {
            Ok(core_ipc::Status::stopped())
        } else {
            core_ipc::stop()
        }
    })
    .await
}

#[tauri::command]
async fn restart_protection() -> Result<Status, String> {
    run_blocking(|| {
        service::start_installed()?;
        core_ipc::restart()
    })
    .await
}

#[tauri::command]
async fn revert_network() -> Result<Status, String> {
    run_blocking(|| {
        if core_ipc::is_reachable() {
            match core_ipc::repair() {
                Ok(s) => return Ok(s),
                Err(e) if core_ipc::is_unknown_method(&e) => {
                    // Stale offveil-core (pre-repair). Tear it down so the
                    // next start can load the current binary.
                    let _ = core_ipc::stop();
                    let _ = core_ipc::shutdown();
                    std::thread::sleep(Duration::from_millis(600));
                }
                Err(e) => return Err(e),
            }
        }
        match service::start_installed() {
            Ok(()) => {}
            Err(e) if service::is_needs_install(&e) => {
                service::ensure_service()?;
            }
            Err(e) => return Err(e),
        }
        match core_ipc::repair() {
            Ok(s) => Ok(s),
            Err(e) if core_ipc::is_unknown_method(&e) => {
                // Still an old image — stop is the best live cleanup we have.
                match core_ipc::stop() {
                    Ok(s) => Ok(s),
                    Err(stop_err) if stop_err.contains("not_running") => {
                        Ok(core_ipc::Status::stopped())
                    }
                    Err(stop_err) => Err(stop_err),
                }
            }
            Err(e) => Err(e),
        }
    })
    .await
}

#[tauri::command]
async fn run_connection_test() -> Result<TestReport, String> {
    run_blocking(|| {
        if !core_ipc::is_reachable() {
            return Err("not_connected: Core servisine bağlanılamadı".into());
        }
        core_ipc::test_connection(None)
    })
    .await
}

#[tauri::command]
async fn export_diagnostics() -> Result<DiagnosticsBundle, String> {
    run_blocking(|| {
        if !core_ipc::is_reachable() {
            return Err("not_connected: Core servisine bağlanılamadı".into());
        }
        core_ipc::diagnostics()
    })
    .await
}

#[tauri::command]
fn open_diag_folder(path: String) -> Result<(), String> {
    let p = std::path::PathBuf::from(&path);
    let target = if p.is_file() {
        p.parent()
            .map(|x| x.to_path_buf())
            .ok_or_else(|| "geçersiz yol".to_string())?
    } else {
        p
    };
    let canon = target
        .canonicalize()
        .map_err(|e| format!("yol açılamadı: {e}"))?;
    let mut root = std::path::PathBuf::from(
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()),
    );
    root.push("offveil");
    let root_canon = root.canonicalize().unwrap_or(root);
    if !canon.starts_with(&root_canon) {
        return Err("yalnızca ProgramData\\offveil altı açılır".into());
    }
    std::process::Command::new("explorer")
        .arg(&canon)
        .spawn()
        .map_err(|e| format!("explorer: {e}"))?;
    Ok(())
}

#[tauri::command]
async fn core_path() -> Option<String> {
    tauri::async_runtime::spawn_blocking(|| {
        service::resolve_core_path().map(|p| p.display().to_string())
    })
    .await
    .ok()
    .flatten()
}

#[tauri::command]
fn prepare_update() -> Result<(), String> {
    if core_ipc::is_reachable() {
        let _ = core_ipc::stop();
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Ok(())
}

fn wants_tray_start() -> bool {
    std::env::args().any(|a| a == "--tray" || a == "--minimized")
}

fn cancel_blur_hide() {
    BLUR_HIDE.store(false, Ordering::SeqCst);
}

/// Win32 popup menus (tray) stay light unless the process opts into dark mode.
fn set_win32_popup_mode(dark: bool) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

        // uxtheme!SetPreferredAppMode: Default=0 AllowDark=1 ForceDark=2 ForceLight=3
        let mode: i32 = if dark { 2 } else { 3 };
        unsafe {
            let uxtheme = LoadLibraryA(b"uxtheme.dll\0".as_ptr());
            if uxtheme.is_null() {
                return;
            }
            if let Some(set_mode) = GetProcAddress(uxtheme, 135usize as *const u8) {
                let set_mode: unsafe extern "system" fn(i32) -> i32 = std::mem::transmute(set_mode);
                let _ = set_mode(mode);
            }
            if let Some(flush) = GetProcAddress(uxtheme, 136usize as *const u8) {
                let flush: unsafe extern "system" fn() = std::mem::transmute(flush);
                flush();
            }
            if let Some(refresh) = GetProcAddress(uxtheme, 104usize as *const u8) {
                let refresh: unsafe extern "system" fn() = std::mem::transmute(refresh);
                refresh();
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = dark;
    }
}

fn set_dwm_cloaked(win: &tauri::WebviewWindow, cloaked: bool) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_CLOAK};
        if let Ok(hwnd) = win.hwnd() {
            let value: i32 = i32::from(cloaked);
            unsafe {
                let _ = DwmSetWindowAttribute(
                    hwnd.0,
                    DWMWA_CLOAK as u32,
                    (&value as *const i32).cast(),
                    std::mem::size_of::<i32>() as u32,
                );
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (win, cloaked);
    }
}

fn apply_native_chrome(win: &tauri::WebviewWindow) {
    // Do not call set_decorations() here: Tauri toggles the Win32 frame
    // asynchronously and flashes native chrome if the window is visible.
    let _ = win.set_shadow(false);
    let _ = win.set_skip_taskbar(true);
    let dark = win.theme().map(|t| t == Theme::Dark).unwrap_or(true);
    let _ = win.set_background_color(Some(WINDOW_BG_CLEAR));
    #[cfg(windows)]
    {
        use windows_sys::Win32::Graphics::Dwm::{
            DwmSetWindowAttribute, DWMNCRP_DISABLED, DWMSBT_NONE, DWMWA_BORDER_COLOR,
            DWMWA_CAPTION_COLOR, DWMWA_NCRENDERING_POLICY, DWMWA_SYSTEMBACKDROP_TYPE,
            DWMWA_TRANSITIONS_FORCEDISABLED, DWMWA_USE_IMMERSIVE_DARK_MODE,
            DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_DONOTROUND,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GetWindowLongPtrW, SetWindowLongPtrW, SetWindowPos, GWL_EXSTYLE, GWL_STYLE,
            SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, WS_BORDER,
            WS_CAPTION, WS_DLGFRAME, WS_EX_CLIENTEDGE, WS_EX_DLGMODALFRAME, WS_EX_STATICEDGE,
            WS_EX_TOOLWINDOW, WS_EX_WINDOWEDGE, WS_MAXIMIZEBOX, WS_MINIMIZEBOX, WS_POPUP,
            WS_SYSMENU, WS_THICKFRAME,
        };
        const DWMWA_COLOR_NONE: u32 = 0xFFFFFFFE;
        if let Ok(hwnd) = win.hwnd() {
            let handle = hwnd.0;
            let color = DWMWA_COLOR_NONE;
            let corner = DWMWCP_DONOTROUND;
            let immersive_dark: i32 = i32::from(dark);
            let no_transition: i32 = 1;
            let backdrop = DWMSBT_NONE;
            let no_nc = DWMNCRP_DISABLED;
            unsafe {
                let style = GetWindowLongPtrW(handle, GWL_STYLE);
                let _ = SetWindowLongPtrW(
                    handle,
                    GWL_STYLE,
                    (style
                        & !(WS_CAPTION as isize
                            | WS_BORDER as isize
                            | WS_THICKFRAME as isize
                            | WS_DLGFRAME as isize
                            | WS_SYSMENU as isize
                            | WS_MINIMIZEBOX as isize
                            | WS_MAXIMIZEBOX as isize))
                        | WS_POPUP as isize,
                );
                // Keep WS_EX_NOREDIRECTIONBITMAP — WebView2 needs it for
                // per-pixel transparency so CSS-rounded corners can show through.
                let ex = GetWindowLongPtrW(handle, GWL_EXSTYLE);
                let _ = SetWindowLongPtrW(
                    handle,
                    GWL_EXSTYLE,
                    (ex & !(WS_EX_CLIENTEDGE as isize
                        | WS_EX_WINDOWEDGE as isize
                        | WS_EX_DLGMODALFRAME as isize
                        | WS_EX_STATICEDGE as isize))
                        | WS_EX_TOOLWINDOW as isize,
                );
                let _ = DwmSetWindowAttribute(
                    handle,
                    DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
                    (&immersive_dark as *const i32).cast(),
                    std::mem::size_of::<i32>() as u32,
                );
                let _ = DwmSetWindowAttribute(
                    handle,
                    DWMWA_TRANSITIONS_FORCEDISABLED as u32,
                    (&no_transition as *const i32).cast(),
                    std::mem::size_of::<i32>() as u32,
                );
                let _ = DwmSetWindowAttribute(
                    handle,
                    DWMWA_BORDER_COLOR as u32,
                    (&color as *const u32).cast(),
                    std::mem::size_of::<u32>() as u32,
                );
                let _ = DwmSetWindowAttribute(
                    handle,
                    DWMWA_CAPTION_COLOR as u32,
                    (&color as *const u32).cast(),
                    std::mem::size_of::<u32>() as u32,
                );
                let _ = DwmSetWindowAttribute(
                    handle,
                    DWMWA_SYSTEMBACKDROP_TYPE as u32,
                    (&backdrop as *const i32).cast(),
                    std::mem::size_of::<i32>() as u32,
                );
                let _ = DwmSetWindowAttribute(
                    handle,
                    DWMWA_WINDOW_CORNER_PREFERENCE as u32,
                    (&corner as *const i32).cast(),
                    std::mem::size_of::<i32>() as u32,
                );
                let _ = DwmSetWindowAttribute(
                    handle,
                    DWMWA_NCRENDERING_POLICY as u32,
                    (&no_nc as *const i32).cast(),
                    std::mem::size_of::<i32>() as u32,
                );
                let _ = SetWindowPos(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
                );
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = dark;
    }
}

fn window_ready(_label: &str) -> bool {
    WEBVIEW_READY.load(Ordering::SeqCst)
}

fn bump_gen() -> u64 {
    MAIN_GEN.fetch_add(1, Ordering::SeqCst) + 1
}

fn current_gen() -> u64 {
    MAIN_GEN.load(Ordering::SeqCst)
}

/// Freeze #root opacity without a transition (safe to call while cloaked/hidden).
fn page_set_hidden_now(win: &tauri::WebviewWindow, hidden: bool) {
    let js = if hidden {
        "document.documentElement.classList.add('window-no-anim','window-hidden')"
    } else {
        "document.documentElement.classList.remove('window-no-anim','window-hidden')"
    };
    let _ = win.eval(js);
}

/// CSS-fade the opaque #root. Does not use SetLayeredWindowAttributes, so
/// per-pixel corner transparency stays intact.
fn page_fade(win: &tauri::WebviewWindow, hide: bool) {
    let js = if hide {
        "document.documentElement.classList.remove('window-no-anim');\
         document.documentElement.classList.add('window-hidden')"
    } else {
        "document.documentElement.classList.remove('window-no-anim');\
         requestAnimationFrame(function(){\
           requestAnimationFrame(function(){\
             document.documentElement.classList.remove('window-hidden')\
           })\
         })"
    };
    let _ = win.eval(js);
}

fn finish_reveal(win: &tauri::WebviewWindow) {
    page_set_hidden_now(win, true);
    apply_native_chrome(win);
    set_dwm_cloaked(win, false);
    page_fade(win, false);
}

fn reveal_webview(win: &tauri::WebviewWindow) {
    let _ = win.app_handle().emit("window-revealing", ());
    DISMISSING.store(false, Ordering::SeqCst);
    let _ = bump_gen();
    set_dwm_cloaked(win, true);
    apply_native_chrome(win);
    page_set_hidden_now(win, true);
    let _ = win.set_skip_taskbar(true);
    let _ = win.show();
    let _ = win.unminimize();
    // show() can drop DWM cloak / restore a caption; hide that before uncloak.
    set_dwm_cloaked(win, true);
    apply_native_chrome(win);
    let _ = win.set_focus();
    if window_ready(win.label()) {
        finish_reveal(win);
    }
}

fn dismiss_webview(window: &tauri::WebviewWindow) {
    let _ = window.app_handle().emit("window-dismissing", ());
    apply_native_chrome(window);
    if QUITTING.load(Ordering::SeqCst) {
        DISMISSING.store(false, Ordering::SeqCst);
        page_set_hidden_now(window, true);
        set_dwm_cloaked(window, true);
        let _ = window.hide();
        let _ = window.set_skip_taskbar(true);
        return;
    }
    DISMISSING.store(true, Ordering::SeqCst);
    let gen = bump_gen();
    page_fade(window, true);
    let window = window.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(REVEAL_MS));
        if current_gen() != gen || QUITTING.load(Ordering::SeqCst) {
            return;
        }
        page_set_hidden_now(&window, true);
        set_dwm_cloaked(&window, true);
        let _ = window.hide();
        apply_native_chrome(&window);
        let _ = window.set_skip_taskbar(true);
        DISMISSING.store(false, Ordering::SeqCst);
    });
}

fn hide_window_to_tray(window: &tauri::Window) {
    if let Some(win) = window.app_handle().get_webview_window(window.label()) {
        dismiss_webview(&win);
        return;
    }
    let _ = window.hide();
    let _ = window.set_skip_taskbar(true);
}

fn position_over_tray(win: &tauri::WebviewWindow) {
    let monitor = win
        .current_monitor()
        .ok()
        .flatten()
        .or_else(|| win.primary_monitor().ok().flatten());
    let Some(monitor) = monitor else {
        return;
    };
    let scale = monitor.scale_factor();
    let work = monitor.work_area();
    let outer = win.outer_size().unwrap_or_else(|_| {
        tauri::PhysicalSize::new((420.0 * scale) as u32, (520.0 * scale) as u32)
    });
    let margin = (12.0 * scale).round() as i32;
    let x = work.position.x + work.size.width as i32 - outer.width as i32 - margin;
    let y = work.position.y + work.size.height as i32 - outer.height as i32 - margin;
    let _ = win.set_position(PhysicalPosition::new(
        x.max(work.position.x),
        y.max(work.position.y),
    ));
}

fn show_main(app: &AppHandle) {
    cancel_blur_hide();
    if let Some(win) = app.get_webview_window("main") {
        position_over_tray(&win);
        reveal_webview(&win);
    }
}

fn toggle_main(app: &AppHandle) {
    cancel_blur_hide();
    if let Some(win) = app.get_webview_window("main") {
        let visible = win.is_visible().unwrap_or(false);
        if visible && !DISMISSING.load(Ordering::SeqCst) {
            dismiss_webview(&win);
        } else {
            show_main(app);
        }
    }
}

fn tray_labels(english: bool) -> (&'static str, &'static str) {
    if english {
        ("Show", "Quit")
    } else {
        ("Göster", "Çıkış")
    }
}

fn build_tray_menu(app: &AppHandle, english: bool) -> tauri::Result<Menu<tauri::Wry>> {
    let (show, quit) = tray_labels(english);
    let show_i = MenuItem::with_id(app, "tray-show", show, true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit_i = MenuItem::with_id(app, "tray-quit", quit, true, None::<&str>)?;
    Menu::with_items(app, &[&show_i, &sep, &quit_i])
}

fn apply_tray_locale(app: &AppHandle, english: bool) {
    TRAY_LOCALE_EN.store(english, Ordering::SeqCst);
    let Ok(menu) = build_tray_menu(app, english) else {
        return;
    };
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_menu(Some(menu));
    }
}

fn schedule_blur_hide(app: AppHandle) {
    BLUR_HIDE.store(true, Ordering::SeqCst);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(180));
        if !BLUR_HIDE.swap(false, Ordering::SeqCst) {
            return;
        }
        if QUITTING.load(Ordering::SeqCst) {
            return;
        }
        if let Some(win) = app.get_webview_window("main") {
            if !win.is_focused().unwrap_or(false) {
                dismiss_webview(&win);
            }
        }
    });
}

#[tauri::command]
fn hide_to_tray(app: AppHandle) {
    cancel_blur_hide();
    if let Some(win) = app.get_webview_window("main") {
        dismiss_webview(&win);
    }
}

#[tauri::command]
fn set_native_theme(app: AppHandle, dark: bool) {
    set_win32_popup_mode(dark);
    app.set_theme(Some(if dark { Theme::Dark } else { Theme::Light }));
    if let Some(win) = app.get_webview_window("main") {
        apply_native_chrome(&win);
    }
}

#[tauri::command]
fn set_tray_locale(app: AppHandle, locale: String) {
    let english = locale.eq_ignore_ascii_case("en");
    if TRAY_LOCALE_EN.load(Ordering::SeqCst) == english {
        return;
    }
    apply_tray_locale(&app, english);
}

/// Change the system tray icon. `"default"` | `"light"` | `"dark"`.
#[tauri::command]
fn set_app_icon(app: AppHandle, variant: String) -> Result<(), String> {
    let icon_bytes: &[u8] = match variant.as_str() {
        "light" => ICON_LIGHT,
        "dark" => ICON_DARK,
        _ => ICON_DEFAULT,
    };
    let image =
        Image::from_bytes(icon_bytes).map_err(|e| format!("Failed to decode icon image: {e}"))?;
    let tray = app
        .tray_by_id(TRAY_ID)
        .ok_or_else(|| "Tray icon not found".to_string())?;
    tray.set_icon(Some(image))
        .map_err(|e| format!("Failed to set tray icon: {e}"))?;
    Ok(())
}

#[tauri::command]
fn tray_quit(app: AppHandle) {
    quit_with_core(&app);
}

#[tauri::command]
fn autostart_is_enabled(app: AppHandle) -> bool {
    autostart::pref_enabled(&app)
}

#[tauri::command]
fn autostart_set(app: AppHandle, enabled: bool) -> Result<bool, String> {
    autostart::set_enabled(&app, enabled)
}

#[tauri::command]
fn autoconnect_is_enabled(app: AppHandle) -> bool {
    autoconnect::pref_enabled(&app)
}

#[tauri::command]
fn autoconnect_set(app: AppHandle, enabled: bool) -> Result<bool, String> {
    autoconnect::set_enabled(&app, enabled)
}

/// Stop offveil-core (protection + Windows service), then exit the UI.
fn quit_with_core(app: &AppHandle) {
    if QUITTING.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    std::thread::spawn(move || {
        if core_ipc::is_reachable() {
            let _ = core_ipc::shutdown();
            // Brief wait for SCM to release the pipe / process.
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        app.exit(0);
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    set_win32_popup_mode(true);
    let start_hidden = wants_tray_start();
    START_HIDDEN.store(start_hidden, Ordering::SeqCst);

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            probe_bootstrap,
            ensure_service,
            get_status,
            set_protection,
            restart_protection,
            revert_network,
            run_connection_test,
            export_diagnostics,
            open_diag_folder,
            prepare_update,
            core_path,
            hide_to_tray,
            set_native_theme,
            set_tray_locale,
            set_app_icon,
            tray_quit,
            autostart_is_enabled,
            autostart_set,
            autoconnect_is_enabled,
            autoconnect_set
        ])
        .setup(move |app| {
            let english = TRAY_LOCALE_EN.load(Ordering::SeqCst);
            let menu = build_tray_menu(app.handle(), english)?;
            let mut tray = TrayIconBuilder::with_id(TRAY_ID)
                .tooltip("offveil")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "tray-show" => show_main(app),
                    "tray-quit" => quit_with_core(app),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        toggle_main(tray.app_handle());
                    }
                });

            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }

            let _ = tray.build(app)?;

            autostart::sync_on_launch(app.handle());
            autoconnect::spawn(app.handle());

            if let Some(win) = app.get_webview_window("main") {
                set_dwm_cloaked(&win, true);
                apply_native_chrome(&win);
                let _ = win.set_skip_taskbar(true);
                if start_hidden {
                    dismiss_webview(&win);
                } else {
                    position_over_tray(&win);
                }
            }
            app.set_theme(Some(Theme::Dark));
            Ok(())
        })
        .on_page_load(|webview, payload| {
            if payload.event() != PageLoadEvent::Finished {
                return;
            }
            let label = webview.label().to_string();
            if label != "main" {
                return;
            }
            WEBVIEW_READY.store(true, Ordering::SeqCst);
            let app = webview.app_handle();
            if let Some(win) = app.get_webview_window(&label) {
                apply_native_chrome(&win);
                if win.is_visible().unwrap_or(false) {
                    finish_reveal(&win);
                } else if label == "main" && !START_HIDDEN.load(Ordering::SeqCst) {
                    show_main(app);
                }
            }
        })
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                hide_window_to_tray(window);
            }
            WindowEvent::Focused(false) => {
                if let Some(win) = window.app_handle().get_webview_window(window.label()) {
                    apply_native_chrome(&win);
                }
                if EVER_FOCUSED.load(Ordering::SeqCst) && !QUITTING.load(Ordering::SeqCst) {
                    schedule_blur_hide(window.app_handle().clone());
                }
            }
            WindowEvent::Focused(true) => {
                EVER_FOCUSED.store(true, Ordering::SeqCst);
                cancel_blur_hide();
            }
            WindowEvent::Resized(_) => {
                if !QUITTING.load(Ordering::SeqCst) && window.is_minimized().unwrap_or(false) {
                    let _ = window.unminimize();
                    hide_window_to_tray(window);
                }
            }
            _ => {}
        })
        .build(tauri::generate_context!())
        .expect("error while building offveil UI")
        .run(|_app, event| {
            if let RunEvent::ExitRequested { api, code, .. } = event {
                // Tray hide must not quit; only explicit quit (code Some) exits.
                if code.is_none() {
                    api.prevent_exit();
                }
            }
        });
}
