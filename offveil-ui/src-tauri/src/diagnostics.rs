//! Support export works even before installation or when engine IPC is stuck.
use crate::core_ipc::DiagnosticsBundle;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;

static EXPORTED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

struct DialogGuard;
struct TemporaryBundle(PathBuf);
impl Drop for TemporaryBundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
impl Drop for DialogGuard {
    fn drop(&mut self) {
        crate::NATIVE_DIALOG_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

pub fn record_error(operation: &str, error: &str) {
    if let Ok(mut last) = LAST_ERROR.lock() {
        *last = Some(format!("{operation}: {error}"));
    }
}

pub fn is_exported(path: &Path) -> bool {
    EXPORTED
        .get()
        .is_some_and(|paths| paths.lock().is_ok_and(|paths| paths.contains(path)))
}

pub fn export(app: tauri::AppHandle) -> Result<Option<DiagnosticsBundle>, String> {
    crate::NATIVE_DIALOG_ACTIVE.store(true, std::sync::atomic::Ordering::SeqCst);
    crate::cancel_blur_hide();
    let _guard = DialogGuard;
    let mut dialog = app
        .dialog()
        .file()
        .add_filter("Support ZIP", &["zip"])
        .set_file_name("offveil-support.zip");
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    if let Ok(downloads) = app.path().download_dir() {
        dialog = dialog.set_directory(downloads);
    }
    let Some(destination) = dialog.blocking_save_file() else {
        return Ok(None);
    };
    let path = destination.into_path().map_err(|e| e.to_string())?;
    // Collect inside app storage. The UI process that owns the native save
    // panel performs the final write to the user-selected destination.
    let cache = app.path().app_cache_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&cache).map_err(|e| e.to_string())?;
    let temporary = TemporaryBundle(cache.join(format!("support-{}.zip", uuid::Uuid::new_v4())));
    let core = crate::service::resolve_core_path()
        .ok_or("Destek dosyası için paket içindeki core bulunamadı")?;
    let mut command = std::process::Command::new(core);
    command.arg("support").arg("--output").arg(&temporary.0);
    if let Some(error) = LAST_ERROR.lock().ok().and_then(|last| last.clone()) {
        command.arg("--ui-error").arg(error);
    }
    let output = crate::command::run(&mut command, Duration::from_secs(20))?;
    if !output.status.success() {
        return Err(format!(
            "Destek dosyası kaydedilemedi: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut bundle: DiagnosticsBundle = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Destek dosyası yanıtı okunamadı: {e}"))?;
    let collected = temporary
        .0
        .canonicalize()
        .map_err(|e| format!("Destek dosyası oluşturulmadı: {e}"))?;
    if Path::new(&bundle.path).canonicalize().ok().as_ref() != Some(&collected)
        || std::fs::metadata(&collected)
            .map_err(|e| e.to_string())?
            .len()
            < 100
    {
        return Err("Destek dosyası doğrulanamadı".into());
    }
    std::fs::copy(&collected, &path).map_err(|e| format!("Seçilen konuma kaydedilemedi: {e}"))?;
    let canonical = path.canonicalize().map_err(|e| e.to_string())?;
    bundle.path = canonical.to_string_lossy().into_owned();
    EXPORTED
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .map_err(|e| e.to_string())?
        .insert(canonical);
    Ok(Some(bundle))
}
