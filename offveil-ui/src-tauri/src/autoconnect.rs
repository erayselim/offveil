//! Auto-connect: start protection when the UI process launches (default on).
//!
//! The core service is demand-start. After a reboot it is stopped, so we
//! StartService (no UAC — AU is granted start in the NSIS hook) then IPC `start`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tauri::{AppHandle, Manager};

use crate::core_ipc;
use crate::service::{self, BootstrapState};
use crate::QUITTING;

static CONNECTING: AtomicBool = AtomicBool::new(false);

fn disabled_marker(app: &AppHandle) -> PathBuf {
    let dir = app.path().app_config_dir().unwrap_or_else(|_| {
        PathBuf::from(std::env::var("APPDATA").unwrap_or_default()).join("com.offveil.app")
    });
    dir.join("autoconnect-disabled")
}

pub fn pref_enabled(app: &AppHandle) -> bool {
    !disabled_marker(app).is_file()
}

fn write_pref(app: &AppHandle, enabled: bool) -> Result<(), String> {
    let path = disabled_marker(app);
    if enabled {
        if path.is_file() {
            std::fs::remove_file(&path).map_err(|e| format!("autoconnect pref: {e}"))?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("autoconnect pref: {e}"))?;
    }
    std::fs::write(&path, b"1").map_err(|e| format!("autoconnect pref: {e}"))
}

pub fn set_enabled(app: &AppHandle, enabled: bool) -> Result<bool, String> {
    write_pref(app, enabled)?;
    if enabled {
        spawn(app);
    }
    Ok(enabled)
}

/// Best-effort: bring the service up and turn protection on. Never prompts UAC.
pub fn spawn(app: &AppHandle) {
    if !pref_enabled(app) {
        return;
    }
    // ACCESS_DENIED / missing SCM DACL cannot recover without UAC — don't retry.
    if matches!(service::probe().state, BootstrapState::NeedsInstall) {
        return;
    }
    if CONNECTING.swap(true, Ordering::SeqCst) {
        return;
    }
    thread::spawn(|| {
        let _ok = try_connect_loop();
        CONNECTING.store(false, Ordering::SeqCst);
    });
}

fn is_permanent_err(err: &str) -> bool {
    err.contains(service::NEEDS_INSTALL) || err.contains("OpenService: 5")
}

fn try_connect_loop() -> bool {
    for attempt in 0..16 {
        if QUITTING.load(Ordering::SeqCst) {
            return false;
        }
        if marker_from_env().is_file() {
            return false;
        }
        match try_connect_once() {
            Ok(()) => return true,
            Err(e) if is_permanent_err(&e) => {
                eprintln!("offveil autoconnect: skipped ({e})");
                return false;
            }
            Err(e) => {
                eprintln!("offveil autoconnect ({attempt}): {e}");
                thread::sleep(Duration::from_millis(if attempt < 4 { 400 } else { 1500 }));
            }
        }
    }
    false
}

fn marker_from_env() -> PathBuf {
    PathBuf::from(std::env::var("APPDATA").unwrap_or_default())
        .join("com.offveil.app")
        .join("autoconnect-disabled")
}

fn try_connect_once() -> Result<(), String> {
    if QUITTING.load(Ordering::SeqCst) {
        return Err("quitting".into());
    }
    if let Ok(s) = core_ipc::status() {
        if s.protection {
            return Ok(());
        }
    }
    service::start_installed()?;
    if let Ok(s) = core_ipc::status() {
        if s.protection {
            return Ok(());
        }
    }
    match core_ipc::start() {
        Ok(s) if s.protection || s.state == "starting" || s.state == "active" => Ok(()),
        Ok(_) => Err("start returned without protection".into()),
        Err(e) if e.contains("already_running") => Ok(()),
        Err(e) => Err(e),
    }
}
