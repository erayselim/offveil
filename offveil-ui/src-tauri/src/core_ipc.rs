//! Named-pipe JSON-RPC client → offveil-core (`\\.\pipe\offveil-core`).
//! Kontrat: docs/contracts.md §2.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::thread;
use std::time::{Duration, Instant};

pub const PIPE_PATH: &str = r"\\.\pipe\offveil-core";

const ERROR_PIPE_BUSY: i32 = 231;
const ERROR_FILE_NOT_FOUND: i32 = 2;

#[derive(Debug, Serialize)]
struct Request {
    id: String,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct Response {
    #[allow(dead_code)]
    id: String,
    ok: bool,
    result: Option<Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub state: String,
    pub protection: bool,
    pub summary: String,
    #[serde(default)]
    pub outbound_hint: Option<String>,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub targets: Vec<TargetStatus>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub health: Option<String>,
    #[serde(default)]
    pub tunnel: Option<Value>,
}

impl Status {
    /// Local snapshot when the demand-start service is not running (protection off).
    pub fn stopped() -> Self {
        Self {
            state: "stopped".into(),
            protection: false,
            summary: String::new(),
            outbound_hint: None,
            since: None,
            targets: Vec::new(),
            last_error: None,
            health: None,
            tunnel: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetStatus {
    pub id: String,
    pub label: String,
    pub outcome: String,
    #[serde(default)]
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PingResult {
    pub version: String,
    pub contracts_version: i32,
    pub service: String,
}

#[derive(Clone, Copy)]
pub struct CallOpts {
    /// Overall wall-clock budget for connect+RPC.
    pub timeout: Duration,
    /// Retry only while pipe is busy (server exists but no free instance).
    pub busy_retries: u32,
}

impl Default for CallOpts {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),
            busy_retries: 40,
        }
    }
}

pub fn call(method: &str, params: Option<Value>) -> Result<Value, String> {
    call_with(method, params, CallOpts::default())
}

pub fn call_with(method: &str, params: Option<Value>, opts: CallOpts) -> Result<Value, String> {
    let req = Request {
        id: uuid::Uuid::new_v4().to_string(),
        method: method.to_string(),
        params,
    };
    let body = serde_json::to_vec(&req).map_err(|e| e.to_string())?;

    let deadline = Instant::now() + opts.timeout;
    let mut busy_left = opts.busy_retries;
    let mut last_err = String::from("pipe unavailable");

    loop {
        if Instant::now() >= deadline {
            return Err(last_err);
        }
        match try_once(&body) {
            Ok(v) => return Ok(v),
            Err(e) => {
                let busy = e == "pipe busy";
                last_err = e;
                if busy && busy_left > 0 {
                    busy_left -= 1;
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
                // NotFound / access / other → fail immediately (no 25s spin).
                return Err(last_err);
            }
        }
    }
}

fn try_once(body: &[u8]) -> Result<Value, String> {
    let file = open_pipe()?;
    let mut writer = file.try_clone().map_err(|e| format!("pipe clone: {e}"))?;
    writer
        .write_all(body)
        .map_err(|e| format!("pipe write: {e}"))?;
    writer
        .write_all(b"\n")
        .map_err(|e| format!("pipe write nl: {e}"))?;
    writer.flush().map_err(|e| format!("pipe flush: {e}"))?;

    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("pipe read: {e}"))?;
    if line.is_empty() {
        return Err("empty response".into());
    }

    let resp: Response = serde_json::from_str(line.trim()).map_err(|e| format!("json: {e}"))?;
    if !resp.ok {
        let err = resp.error.unwrap_or(RpcError {
            code: "internal".into(),
            message: "unknown error".into(),
        });
        return Err(format!("{}: {}", err.code, err.message));
    }
    Ok(resp.result.unwrap_or(Value::Null))
}

fn open_pipe() -> Result<std::fs::File, String> {
    #[cfg(windows)]
    {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(PIPE_PATH)
            .map_err(|e| match e.raw_os_error() {
                Some(ERROR_PIPE_BUSY) => "pipe busy".into(),
                Some(ERROR_FILE_NOT_FOUND) => "pipe not found".into(),
                _ => format!("pipe open: {e}"),
            })
    }
    #[cfg(not(windows))]
    {
        let _ = OpenOptions::new();
        Err("named pipe IPC is Windows-only".into())
    }
}

/// Single quick probe - must not block the UI for seconds when core is down.
pub fn is_reachable() -> bool {
    call_with(
        "ping",
        None,
        CallOpts {
            timeout: Duration::from_millis(400),
            busy_retries: 4,
        },
    )
    .is_ok()
}

/// Kept for diagnostics / future health checks.
#[allow(dead_code)]
pub fn ping() -> Result<PingResult, String> {
    let v = call_with(
        "ping",
        None,
        CallOpts {
            timeout: Duration::from_secs(2),
            busy_retries: 20,
        },
    )?;
    serde_json::from_value(v).map_err(|e| e.to_string())
}

pub fn status() -> Result<Status, String> {
    let v = call("status", None)?;
    serde_json::from_value(v).map_err(|e| e.to_string())
}

pub fn start() -> Result<Status, String> {
    let params = serde_json::json!({ "mode": "auto" });
    // Engine start can take several seconds (probe + sidecars).
    let v = call_with(
        "start",
        Some(params),
        CallOpts {
            timeout: Duration::from_secs(30),
            busy_retries: 20,
        },
    )?;
    serde_json::from_value(v).map_err(|e| e.to_string())
}

pub fn stop() -> Result<Status, String> {
    let v = call_with(
        "stop",
        None,
        CallOpts {
            timeout: Duration::from_secs(15),
            busy_retries: 20,
        },
    )?;
    serde_json::from_value(v).map_err(|e| e.to_string())
}

/// Stop (if needed) then start - UI “Yenile”.
pub fn restart() -> Result<Status, String> {
    let v = call_with(
        "restart",
        None,
        CallOpts {
            timeout: Duration::from_secs(45),
            busy_retries: 20,
        },
    )?;
    serde_json::from_value(v).map_err(|e| e.to_string())
}

/// Stop protection, restore leftover DNS/NRPT/adapter, flush cache.
pub fn repair() -> Result<Status, String> {
    repair_once()
}

fn repair_once() -> Result<Status, String> {
    let v = call_with(
        "repair",
        None,
        CallOpts {
            timeout: Duration::from_secs(25),
            busy_retries: 20,
        },
    )?;
    let status = v
        .get("status")
        .cloned()
        .ok_or_else(|| "repair: missing status".to_string())?;
    serde_json::from_value(status).map_err(|e| e.to_string())
}

pub fn is_unknown_method(err: &str) -> bool {
    let low = err.to_ascii_lowercase();
    low.contains("unknown method") || (low.contains("bad_request") && low.contains("repair"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestReport {
    pub asn: String,
    #[serde(default)]
    pub isp_hint: Option<String>,
    #[serde(default)]
    pub results: Vec<TestResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub target: String,
    pub class: String,
    pub path: String,
    pub ok: bool,
}

/// IPC `test` - UI “Bağlantı testi” (contracts.md §4.3).
pub fn test_connection(targets: Option<Vec<String>>) -> Result<TestReport, String> {
    let params = match targets {
        Some(t) if !t.is_empty() => Some(serde_json::json!({ "targets": t })),
        _ => Some(serde_json::json!({})),
    };
    let v = call_with(
        "test",
        params,
        CallOpts {
            timeout: Duration::from_secs(20),
            busy_retries: 20,
        },
    )?;
    serde_json::from_value(v).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsBundle {
    pub path: String,
    pub created_at: String,
    pub sha256: String,
    pub version: String,
    #[serde(default)]
    pub note: Option<String>,
}

/// Stop protection if needed, then ask the Windows service to exit (UI quit).
pub fn shutdown() -> Result<(), String> {
    let _ = call_with(
        "shutdown",
        None,
        CallOpts {
            timeout: Duration::from_secs(20),
            busy_retries: 5,
        },
    );
    // Pipe may close before a full JSON response - treat unreachable as success.
    Ok(())
}

/// IPC `diagnostics` - PII-safe zip under ProgramData/offveil/diagnostics.
pub fn diagnostics() -> Result<DiagnosticsBundle, String> {
    let v = call_with(
        "diagnostics",
        None,
        CallOpts {
            timeout: Duration::from_secs(15),
            busy_retries: 20,
        },
    )?;
    serde_json::from_value(v).map_err(|e| e.to_string())
}
