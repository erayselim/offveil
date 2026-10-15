//! Tray appearance is independent of the application's own light/dark theme.

use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{image::Image, AppHandle};

const GREEN: &[u8] = include_bytes!("../icons/32x32.png");
const WHITE: &[u8] = include_bytes!("../icons/tray-light.png");
const BLACK: &[u8] = include_bytes!("../icons/tray-dark.png");

static FOLLOW_SYSTEM: AtomicBool = AtomicBool::new(true);

pub fn image() -> tauri::Result<Image<'static>> {
    let bytes = if !FOLLOW_SYSTEM.load(Ordering::SeqCst) {
        GREEN
    } else if system_is_dark() {
        WHITE
    } else {
        BLACK
    };
    Image::from_bytes(bytes)
}

pub fn is_template() -> bool {
    cfg!(target_os = "macos") && FOLLOW_SYSTEM.load(Ordering::SeqCst)
}

pub fn refresh(app: &AppHandle) -> Result<(), String> {
    let image = image().map_err(|e| format!("Failed to decode tray icon: {e}"))?;
    let tray = app
        .tray_by_id(super::TRAY_ID)
        .ok_or_else(|| "Tray icon not found".to_string())?;
    tray.set_icon_with_as_template(Some(image), is_template())
        .map_err(|e| format!("Failed to set tray icon: {e}"))
}

pub fn set_preference(app: &AppHandle, variant: &str) -> Result<(), String> {
    // Old monochrome selections also migrate to System.
    FOLLOW_SYSTEM.store(variant != "default", Ordering::SeqCst);
    refresh(app)
}

#[cfg(not(windows))]
fn system_is_dark() -> bool {
    // On macOS AppKit uses the alpha mask of this black template, and chooses
    // its actual color for the menu bar background, including wallpaper tint.
    false
}

#[cfg(windows)]
fn system_is_dark() -> bool {
    windows_theme::is_dark()
}

pub fn watch_system_theme(_app: &AppHandle) {
    #[cfg(windows)]
    windows_theme::watch(_app.clone());
}

#[cfg(windows)]
mod windows_theme {
    use std::ptr;
    use tauri::AppHandle;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_SUCCESS, WAIT_OBJECT_0},
        System::{
            Registry::{
                RegCloseKey, RegGetValueW, RegNotifyChangeKeyValue, RegOpenKeyExW,
                HKEY_CURRENT_USER, KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
                RRF_RT_REG_DWORD,
            },
            Threading::{CreateEventW, WaitForSingleObject, INFINITE},
        },
    };

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    pub fn is_dark() -> bool {
        let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        let name = wide("SystemUsesLightTheme");
        let mut light: u32 = 0;
        let mut size = std::mem::size_of_val(&light) as u32;
        // Read the taskbar/system setting, not AppsUseLightTheme: Windows lets
        // users configure these separately, and offveil can override its own UI.
        let result = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_DWORD,
                ptr::null_mut(),
                (&mut light as *mut u32).cast(),
                &mut size,
            )
        };
        result != ERROR_SUCCESS || light == 0
    }

    pub fn watch(app: AppHandle) {
        std::thread::spawn(move || unsafe {
            let path = wide(r"Software\Microsoft\Windows\CurrentVersion\Themes");
            let mut key = ptr::null_mut();
            if RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_NOTIFY, &mut key)
                != ERROR_SUCCESS
            {
                return;
            }
            let event = CreateEventW(ptr::null(), 0, 0, ptr::null());
            if event.is_null() {
                RegCloseKey(key);
                return;
            }
            loop {
                // Arm before reading, so a change between reading and waiting
                // is retained by the event. This also handles a new Personalize key.
                if RegNotifyChangeKeyValue(
                    key,
                    1,
                    REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME,
                    event,
                    1,
                ) != ERROR_SUCCESS
                {
                    break;
                }
                let handle = app.clone();
                if app
                    .run_on_main_thread(move || {
                        // Read the latest preference on the UI thread: an already
                        // queued theme change must never overwrite a Green choice.
                        if super::FOLLOW_SYSTEM.load(std::sync::atomic::Ordering::SeqCst) {
                            if let Err(error) = super::refresh(&handle) {
                                crate::diagnostics::record_error("tray", &error);
                            }
                        }
                    })
                    .is_err()
                {
                    break;
                }
                if WaitForSingleObject(event, INFINITE) != WAIT_OBJECT_0 {
                    break;
                }
            }
            CloseHandle(event);
            RegCloseKey(key);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monochrome_icons_are_transparent_masks() {
        for bytes in [BLACK, WHITE] {
            let image = Image::from_bytes(bytes).unwrap();
            assert_eq!((image.width(), image.height()), (32, 32));
            let pixels: Vec<_> = image.rgba().chunks_exact(4).collect();
            assert!(
                pixels.iter().any(|p| p[3] == 0),
                "background must be transparent"
            );
            assert!(
                pixels.iter().any(|p| p[3] == 255),
                "logo must remain visible"
            );
        }
    }
}
