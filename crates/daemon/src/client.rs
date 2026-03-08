//! Daemon client for IPC communication.

use std::path::Path;
use std::time::Duration;

use parry_core::{Config, ScanError, ScanResult};
use tracing::{debug, info, trace, warn};

use crate::protocol::{self, ScanRequest, ScanResponse, ScanType};
use crate::transport::Stream;

/// Timeout for ping/liveness checks (must be fast).
const PING_TIMEOUT: Duration = Duration::from_millis(50);

/// Timeout for scan requests (model loading on first call can take tens of seconds).
const SCAN_TIMEOUT: Duration = Duration::from_secs(120);

/// Run a full scan (with ML) via the daemon.
///
/// # Errors
///
/// Returns `ScanError::DaemonIo` if the daemon is unreachable.
pub fn scan_full(text: &str, config: &Config) -> Result<ScanResult, ScanError> {
    debug!(text_len = text.len(), "attempting full scan via daemon");
    let req = ScanRequest {
        scan_type: ScanType::Full,
        threshold: config.threshold,
        text: text.to_string(),
    };
    send_request(&req, config.runtime_dir.as_deref())
}

/// Check if a daemon is running by sending a ping.
#[must_use]
pub fn is_daemon_running(runtime_dir: Option<&Path>) -> bool {
    trace!("checking if daemon is running");
    let Ok(mut stream) = Stream::connect(PING_TIMEOUT, runtime_dir) else {
        trace!("daemon not running (connection failed)");
        return false;
    };

    let req = ScanRequest {
        scan_type: ScanType::Ping,
        threshold: 0.0,
        text: String::new(),
    };

    if protocol::write_request(&mut stream, &req).is_err() {
        trace!("daemon not running (write failed)");
        return false;
    }

    let running = matches!(protocol::read_response(&mut stream), Ok(ScanResponse::Pong));
    trace!(running, "daemon running check complete");
    running
}

/// Spawn the daemon as a detached background process.
///
/// # Errors
///
/// Returns `ScanError::DaemonStart` if the executable path cannot be resolved
/// or the process fails to spawn.
pub fn spawn_daemon(config: &Config) -> Result<(), ScanError> {
    let exe = std::env::current_exe()
        .map_err(|e| ScanError::DaemonStart(format!("failed to resolve executable: {e}")))?;

    let mut cmd = std::process::Command::new(&exe);

    cmd.arg("--threshold").arg(config.threshold.to_string());

    cmd.arg("--scan-mode").arg(config.scan_mode.as_str());

    if let Some(ref token) = config.hf_token {
        let token_file = crate::transport::parry_dir(config.runtime_dir.as_deref())
            .map_err(|e| ScanError::DaemonStart(format!("failed to resolve parry dir: {e}")))?
            .join(".hf-token");
        std::fs::write(&token_file, token)
            .map_err(|e| ScanError::DaemonStart(format!("failed to write token file: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&token_file, perms).map_err(|e| {
                ScanError::DaemonStart(format!("failed to set token file permissions: {e}"))
            })?;
        }
        cmd.arg("--hf-token-path").arg(&token_file);
    }

    // NOTE: runtime_dir is not passed to the child process. It's test-only —
    // production always uses None (hardcoded in main.rs). No CLI flag needed:
    // an attacker who can inject --runtime-dir already has code execution.
    cmd.arg("serve");

    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    cmd.spawn()
        .map_err(|e| ScanError::DaemonStart(format!("failed to spawn daemon: {e}")))?;
    Ok(())
}

/// Ensure the daemon is running. Spawns it if needed and waits for readiness.
///
/// # Errors
///
/// Returns `ScanError::DaemonStart` if the daemon fails to start within the timeout.
pub fn ensure_running(config: &Config) -> Result<(), ScanError> {
    let rd = config.runtime_dir.as_deref();
    if is_daemon_running(rd) {
        return Ok(());
    }
    crate::transport::cleanup_stale_state(rd);
    info!("daemon not running, starting...");
    spawn_daemon(config)?;

    if wait_for_ready(rd) {
        info!("daemon ready");
        return Ok(());
    }

    warn!("daemon did not come up after first spawn, retrying...");
    crate::transport::cleanup_stale_state(rd);
    spawn_daemon(config)?;

    if wait_for_ready(rd) {
        info!("daemon ready after retry");
        return Ok(());
    }

    Err(ScanError::DaemonStart(
        "timed out waiting for daemon after retry".into(),
    ))
}

const BACKOFF_MS: [u64; 6] = [100, 200, 500, 1000, 2000, 3000];

fn wait_for_ready(runtime_dir: Option<&Path>) -> bool {
    for delay_ms in BACKOFF_MS {
        std::thread::sleep(Duration::from_millis(delay_ms));
        // Bail early if socket doesn't exist — daemon clearly not spawning
        if !crate::transport::socket_exists(runtime_dir) {
            trace!("socket file missing, daemon not starting");
            return false;
        }
        if is_daemon_running(runtime_dir) {
            return true;
        }
    }
    false
}

fn send_request(req: &ScanRequest, runtime_dir: Option<&Path>) -> Result<ScanResult, ScanError> {
    let mut stream = Stream::connect(SCAN_TIMEOUT, runtime_dir)?;
    protocol::write_request(&mut stream, req)?;
    let resp = protocol::read_response(&mut stream)?;
    match resp {
        ScanResponse::Error => Err(ScanError::DaemonScanFailed),
        resp => Ok(response_to_scan_result(resp)),
    }
}

fn response_to_scan_result(resp: ScanResponse) -> ScanResult {
    match resp {
        ScanResponse::Clean | ScanResponse::Pong => ScanResult::Clean,
        ScanResponse::Injection => ScanResult::Injection,
        ScanResponse::Secret => ScanResult::Secret,
        ScanResponse::Error => unreachable!("Error handled before conversion"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_clean_maps_to_clean() {
        assert!(response_to_scan_result(ScanResponse::Clean).is_clean());
    }

    #[test]
    fn response_pong_maps_to_clean() {
        assert!(response_to_scan_result(ScanResponse::Pong).is_clean());
    }

    #[test]
    fn response_injection_maps_to_injection() {
        assert!(response_to_scan_result(ScanResponse::Injection).is_injection());
    }

    #[test]
    fn response_secret_maps_to_secret() {
        assert!(matches!(
            response_to_scan_result(ScanResponse::Secret),
            ScanResult::Secret
        ));
    }

    #[test]
    fn is_daemon_running_returns_false_without_daemon() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_daemon_running(Some(dir.path())));
    }

    #[test]
    #[cfg(unix)]
    fn token_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();

        let config = Config {
            hf_token: Some("test-token".to_string()),
            runtime_dir: Some(dir.path().to_path_buf()),
            ..Config::default()
        };

        // spawn_daemon will fail (no parry binary) but should still create the token file
        let _ = spawn_daemon(&config);

        let token_path = dir.path().join(".hf-token");
        if token_path.exists() {
            let perms = std::fs::metadata(&token_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600, "token file should be 0600");
        }
    }
}
