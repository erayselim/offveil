//! Bounded subprocess execution without pipes that can fill while waiting.
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

struct Capture {
    path: PathBuf,
    file: File,
}
impl Capture {
    fn new() -> Result<Self, String> {
        let path =
            std::env::temp_dir().join(format!("offveil-command-{}.log", uuid::Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|e| e.to_string())?;
        Ok(Self { path, file })
    }
    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        // Retain the tail when an external tool prints excessive diagnostics.
        let len = self.file.metadata().map_err(|e| e.to_string())?.len();
        self.file
            .seek(SeekFrom::Start(len.saturating_sub(256 * 1024)))
            .map_err(|e| e.to_string())?;
        let mut result = Vec::new();
        self.file
            .by_ref()
            .take(256 * 1024)
            .read_to_end(&mut result)
            .map_err(|e| e.to_string())?;
        Ok(result)
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn run(command: &mut Command, timeout: Duration) -> Result<Output, String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut stdout = Capture::new()?;
    let mut stderr = Capture::new()?;
    command.stdin(std::process::Stdio::null());
    command.stdout(stdout.file.try_clone().map_err(|e| e.to_string())?);
    command.stderr(stderr.file.try_clone().map_err(|e| e.to_string())?);
    let mut child = command.spawn().map_err(|e| format!("command start: {e}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(Output {
                status,
                stdout: stdout.bytes()?,
                stderr: stderr.bytes()?,
            });
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "command timed out after {}s: {}",
                timeout.as_secs(),
                String::from_utf8_lossy(&stderr.bytes()?)
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_output() {
        match std::env::var("OFFVEIL_COMMAND_CHILD_MODE").as_deref() {
            Ok("large") => {
                print!("{}", "o".repeat(1024 * 1024));
                eprint!("{}", "e".repeat(1024 * 1024));
            }
            Ok("hang") => std::thread::sleep(Duration::from_secs(10)),
            _ => {}
        }
    }
    fn child(mode: &str) -> Command {
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.args(["--exact", "command::tests::child_output", "--nocapture"])
            .env("OFFVEIL_COMMAND_CHILD_MODE", mode);
        c
    }
    #[test]
    fn large_stdout_and_stderr_do_not_deadlock() {
        let output = run(&mut child("large"), Duration::from_secs(5)).unwrap();
        assert!(output.status.success());
        assert!(!output.stdout.is_empty() && output.stdout.len() <= 256 * 1024);
        assert!(!output.stderr.is_empty() && output.stderr.len() <= 256 * 1024);
    }
    #[test]
    fn stuck_process_is_bounded() {
        let started = Instant::now();
        assert!(run(&mut child("hang"), Duration::from_millis(80))
            .unwrap_err()
            .contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
