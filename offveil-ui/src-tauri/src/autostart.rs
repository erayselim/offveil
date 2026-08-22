//! User-login autostart for the tray UI.
//!
//! `tauri-plugin-autostart` (auto-launch 0.5) writes an unquoted path, so a
//! per-machine install under `C:\Program Files\offveil\` never actually starts.
//! We write HKCU Run ourselves with a quoted command, re-enable Task Manager's
//! StartupApproved flag, and repair the key on every launch (default: on).

use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

const VALUE_NAME: &str = "offveil";
const LEGACY_VALUE_NAMES: &[&str] = &["offveil-ui"];
const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APPROVED_SUBKEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
const TRAY_ARG: &str = "--tray";
/// 02 + 8 zero bytes = enabled in Task Manager / Settings > Startup apps.
const STARTUP_APPROVED_ENABLED: [u8; 12] = [
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn disabled_marker(app: &AppHandle) -> PathBuf {
    let dir = app.path().app_config_dir().unwrap_or_else(|_| {
        PathBuf::from(std::env::var("APPDATA").unwrap_or_default()).join("com.offveil.app")
    });
    dir.join("autostart-disabled")
}

pub fn pref_enabled(app: &AppHandle) -> bool {
    !disabled_marker(app).is_file()
}

fn write_pref(app: &AppHandle, enabled: bool) -> Result<(), String> {
    let path = disabled_marker(app);
    if enabled {
        if path.is_file() {
            std::fs::remove_file(&path).map_err(|e| format!("autostart pref: {e}"))?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("autostart pref: {e}"))?;
    }
    std::fs::write(&path, b"1").map_err(|e| format!("autostart pref: {e}"))
}

fn exe_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    Ok(strip_verbatim(exe))
}

fn strip_verbatim(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    for prefix in [r"\\?\", r"//?/"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return PathBuf::from(rest);
        }
    }
    path
}

fn is_cargo_debug_exe(path: &Path) -> bool {
    let mut saw_target = false;
    for c in path.components() {
        let s = c.as_os_str();
        if s == "target" {
            saw_target = true;
        } else if saw_target && s == "debug" {
            return true;
        }
    }
    false
}

fn run_command() -> Result<String, String> {
    let exe = exe_path()?;
    let path = exe.to_string_lossy().replace('"', "");
    Ok(format!("\"{path}\" {TRAY_ARG}"))
}

/// On installed builds, make the registry match the user preference (default on).
pub fn sync_on_launch(app: &AppHandle) {
    let want = pref_enabled(app);
    if let Ok(exe) = exe_path() {
        if is_cargo_debug_exe(&exe) {
            return;
        }
    }
    if let Err(e) = apply_registry(want) {
        eprintln!("offveil autostart sync: {e}");
    }
}

pub fn set_enabled(app: &AppHandle, enabled: bool) -> Result<bool, String> {
    apply_registry(enabled)?;
    write_pref(app, enabled)?;
    Ok(enabled)
}

fn apply_registry(enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        if enabled {
            let cmd = run_command()?;
            win::set_sz(RUN_SUBKEY, VALUE_NAME, &cmd)?;
            win::set_bin(APPROVED_SUBKEY, VALUE_NAME, &STARTUP_APPROVED_ENABLED)?;
        } else {
            win::delete_value(RUN_SUBKEY, VALUE_NAME);
            win::delete_value(APPROVED_SUBKEY, VALUE_NAME);
        }
        for name in LEGACY_VALUE_NAMES {
            win::delete_value(RUN_SUBKEY, name);
            win::delete_value(APPROVED_SUBKEY, name);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Ok(())
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegSetValueExW, HKEY_CURRENT_USER,
        KEY_SET_VALUE, REG_BINARY, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn open_write(subkey: &str) -> Result<windows_sys::Win32::System::Registry::HKEY, String> {
        let sub = wide(subkey);
        let mut hkey = std::ptr::null_mut();
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                sub.as_ptr(),
                0,
                std::ptr::null_mut(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut hkey,
                std::ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("RegCreateKeyExW {subkey}: {status}"));
        }
        Ok(hkey)
    }

    pub fn set_sz(subkey: &str, name: &str, value: &str) -> Result<(), String> {
        let hkey = open_write(subkey)?;
        let wname = wide(name);
        let wval = wide(value);
        let status = unsafe {
            RegSetValueExW(
                hkey,
                wname.as_ptr(),
                0,
                REG_SZ,
                wval.as_ptr().cast(),
                (wval.len() * 2) as u32,
            )
        };
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        if status != ERROR_SUCCESS {
            return Err(format!("RegSetValueExW {name}: {status}"));
        }
        Ok(())
    }

    pub fn set_bin(subkey: &str, name: &str, value: &[u8]) -> Result<(), String> {
        let hkey = open_write(subkey)?;
        let wname = wide(name);
        let status = unsafe {
            RegSetValueExW(
                hkey,
                wname.as_ptr(),
                0,
                REG_BINARY,
                value.as_ptr(),
                value.len() as u32,
            )
        };
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        if status != ERROR_SUCCESS {
            return Err(format!("RegSetValueExW bin {name}: {status}"));
        }
        Ok(())
    }

    pub fn delete_value(subkey: &str, name: &str) {
        let Ok(hkey) = open_write(subkey) else {
            return;
        };
        let wname = wide(name);
        unsafe {
            let _ = RegDeleteValueW(hkey, wname.as_ptr());
            let _ = RegCloseKey(hkey);
        }
    }
}
