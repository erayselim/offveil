//! Windows Service bootstrap.
//!
//! After NSIS (or a one-time elevated `setup`), `offveil-core` is a demand-start
//! service. The UI is `asInvoker`. Authenticated Users may `StartService`
//! (SDDL from the installer / `setup`) so toggle, restart, and login
//! auto-connect never prompt UAC.
//!
//! Elevated `offveil-core setup` is only for a missing SCM entry or a DACL
//! that rejects start (broken / pre-grant install).

use std::env;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::core_ipc;

const SERVICE_NAME: &str = "offveil-core";
const PIPE_WAIT: Duration = Duration::from_secs(20);
const SETUP_PIPE_WAIT: Duration = Duration::from_secs(30);

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const ERROR_CANCELLED: u32 = 1223;

/// Prefix the UI uses to drop into the one-time admin setup screen.
pub const NEEDS_INSTALL: &str = "needs_install:";

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapState {
    Ready,
    NeedsInstall,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BootstrapInfo {
    pub state: BootstrapState,
    pub message: String,
    pub core_path: Option<String>,
    pub service_installed: bool,
    pub pipe_ok: bool,
}

pub fn resolve_core_path() -> Option<PathBuf> {
    if let Ok(p) = env::var("OFFVEIL_CORE_PATH") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("offveil-core.exe"));
            candidates.push(dir.join("offveil-core").join("offveil-core.exe"));
            if let Some(repo) = dir
                .ancestors()
                .find(|p| p.join("offveil-core").join("offveil-core.exe").is_file())
            {
                candidates.push(repo.join("offveil-core").join("offveil-core.exe"));
            }
            if let Some(repo) = dir.ancestors().nth(4) {
                candidates.push(repo.join("offveil-core").join("offveil-core.exe"));
            }
        }
    }

    if let Ok(cwd) = env::current_dir() {
        candidates.push(cwd.join("offveil-core.exe"));
        candidates.push(cwd.join("offveil-core").join("offveil-core.exe"));
        candidates.push(cwd.join("..").join("offveil-core").join("offveil-core.exe"));
        candidates.push(
            cwd.join("..")
                .join("..")
                .join("offveil-core")
                .join("offveil-core.exe"),
        );
    }

    if let Ok(pf) = env::var("ProgramFiles") {
        candidates.push(PathBuf::from(pf).join("offveil").join("offveil-core.exe"));
    }

    candidates.into_iter().find(|c| c.is_file())
}

#[cfg(windows)]
pub fn service_installed() -> bool {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
    };

    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return false;
        }
        let name: Vec<u16> = SERVICE_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let svc = OpenServiceW(scm, name.as_ptr(), SERVICE_QUERY_STATUS);
        let ok = !svc.is_null();
        if !svc.is_null() {
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
        ok
    }
}

#[cfg(not(windows))]
pub fn service_installed() -> bool {
    false
}

/// True if this (filtered) token may `StartService`. False on a default SCM
/// DACL from `offveil-core install` without `setup` / NSIS `sdset`.
#[cfg(windows)]
fn service_start_granted() -> bool {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SERVICE_START,
    };

    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return false;
        }
        let name: Vec<u16> = SERVICE_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let svc = OpenServiceW(scm, name.as_ptr(), SERVICE_START);
        let ok = !svc.is_null();
        if !svc.is_null() {
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
        ok
    }
}

#[cfg(not(windows))]
fn service_start_granted() -> bool {
    false
}

pub fn is_needs_install(err: &str) -> bool {
    err.starts_with(NEEDS_INSTALL)
}

fn elevation_required(code: u32) -> bool {
    code == ERROR_ACCESS_DENIED || code == ERROR_SERVICE_DOES_NOT_EXIST
}

fn wait_for_pipe(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if core_ipc::is_reachable() {
            return true;
        }
        thread::sleep(Duration::from_millis(250));
    }
    false
}

/// Start the already-installed demand-start service without UAC.
/// Requires the SDDL grant (Authenticated Users → SERVICE_START).
pub fn start_installed() -> Result<(), String> {
    if core_ipc::is_reachable() {
        return Ok(());
    }
    if !service_installed() {
        return Err(format!("{NEEDS_INSTALL} offveil-core servisi kurulu değil"));
    }
    start_scm()?;
    if wait_for_pipe(PIPE_WAIT) {
        return Ok(());
    }
    Err("servis başladı ama IPC hazır olmadı".into())
}

#[cfg(windows)]
fn start_scm() -> Result<(), String> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, StartServiceW, SC_MANAGER_CONNECT,
        SERVICE_QUERY_STATUS, SERVICE_START,
    };

    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(format!("OpenSCManager: {}", GetLastError()));
        }
        let name: Vec<u16> = SERVICE_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let svc = OpenServiceW(scm, name.as_ptr(), SERVICE_START | SERVICE_QUERY_STATUS);
        if svc.is_null() {
            let err = GetLastError();
            CloseServiceHandle(scm);
            return Err(scm_start_err("OpenService", err));
        }
        let ok = StartServiceW(svc, 0, std::ptr::null());
        let err = if ok == 0 { GetLastError() } else { 0 };
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if ok == 0 && err != ERROR_SERVICE_ALREADY_RUNNING {
            return Err(scm_start_err("StartService", err));
        }
        Ok(())
    }
}

fn scm_start_err(op: &str, err: u32) -> String {
    if elevation_required(err) {
        format!("{NEEDS_INSTALL} {op}: {err}")
    } else {
        format!("{op}: {err}")
    }
}

#[cfg(not(windows))]
fn start_scm() -> Result<(), String> {
    Err("Windows dışı platformda servis yok".into())
}

pub fn probe() -> BootstrapInfo {
    // Fast path first — must return in <<1s when core is down.
    let pipe_ok = core_ipc::is_reachable();
    let installed = service_installed();
    let core_path = resolve_core_path().map(|p| p.display().to_string());

    if pipe_ok {
        return BootstrapInfo {
            state: BootstrapState::Ready,
            message: "Servis hazır".into(),
            core_path,
            service_installed: installed,
            pipe_ok: true,
        };
    }

    if installed && service_start_granted() {
        // Demand-start: registered but stopped is the normal post-reboot state.
        // The UI stays on the main switch; StartService has no UAC.
        return BootstrapInfo {
            state: BootstrapState::Ready,
            message: "Servis kurulu".into(),
            core_path,
            service_installed: true,
            pipe_ok: false,
        };
    }

    BootstrapInfo {
        state: BootstrapState::NeedsInstall,
        message: "İlk kurulum: offveil core servisi kurulacak (tek UAC)".into(),
        core_path,
        service_installed: installed,
        pipe_ok: false,
    }
}

/// Make the core reachable. `StartService` first; elevate `setup` only if the
/// service is missing or its DACL rejects start.
pub fn ensure_service() -> Result<BootstrapInfo, String> {
    if core_ipc::is_reachable() {
        return Ok(probe());
    }

    match start_installed() {
        Ok(()) => return Ok(probe()),
        Err(e) if is_needs_install(&e) => { /* repair / first install */ }
        Err(e) => return Err(e),
    }

    let core = resolve_core_path().ok_or_else(|| {
        "offveil-core.exe bulunamadı. OFFVEIL_CORE_PATH ayarlayın veya core'u UI yanına koyun."
            .to_string()
    })?;

    elevate_setup(&core)?;

    if wait_for_pipe(SETUP_PIPE_WAIT) {
        return Ok(BootstrapInfo {
            state: BootstrapState::Ready,
            message: "Servis kuruldu ve çalışıyor".into(),
            core_path: Some(core.display().to_string()),
            service_installed: true,
            pipe_ok: true,
        });
    }

    Err("Servis kuruldu ama IPC hazır olmadı (zaman aşımı). Core loglarına bakın.".into())
}

fn elevate_setup(core: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::mem::size_of;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{
            CloseHandle, GetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        use windows_sys::Win32::UI::Shell::{
            ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

        let file: Vec<u16> = core
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let params: Vec<u16> = "setup".encode_utf16().chain(std::iter::once(0)).collect();
        let verb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();

        let mut info = unsafe { std::mem::zeroed::<SHELLEXECUTEINFOW>() };
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_HIDE as i32;

        let ok = unsafe { ShellExecuteExW(&mut info) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_CANCELLED {
                return Err(
                    "Kurulum iptal edildi veya başarısız (UAC reddedilmiş olabilir)".into(),
                );
            }
            return Err(format!("elevate: ShellExecuteEx {err}"));
        }
        if info.hProcess.is_null() {
            return Err("elevate: süreç henüz oluşmadı".into());
        }

        let wait = unsafe { WaitForSingleObject(info.hProcess, 90_000) };
        let mut exit: u32 = 1;
        let got = unsafe { GetExitCodeProcess(info.hProcess, &mut exit) };
        unsafe { CloseHandle(info.hProcess) };

        if wait == WAIT_TIMEOUT {
            return Err("Servis kurulumu zaman aşımına uğradı".into());
        }
        if wait != WAIT_OBJECT_0 || got == 0 {
            return Err("Kurulum iptal edildi veya başarısız (UAC reddedilmiş olabilir)".into());
        }
        if exit != 0 {
            return Err(format!("offveil-core setup çıkış kodu {exit}"));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = core;
        Err("Windows dışı platformda servis kurulumu yok".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_denied_and_missing_need_elevation() {
        assert!(elevation_required(ERROR_ACCESS_DENIED));
        assert!(elevation_required(ERROR_SERVICE_DOES_NOT_EXIST));
        assert!(!elevation_required(ERROR_SERVICE_ALREADY_RUNNING));
        assert!(!elevation_required(1053));
    }

    #[test]
    fn needs_install_prefix() {
        assert!(is_needs_install(&format!("{NEEDS_INSTALL} OpenService: 5")));
        assert!(!is_needs_install("StartService: 1053"));
        assert!(!is_needs_install("servis başladı ama IPC hazır olmadı"));
    }
}
