//! Daemon client for IPC communication.

use std::path::Path;
use std::time::Duration;

use parry_guard_core::{Config, ScanError, ScanResult};
use tracing::{debug, info, trace, warn};

use crate::protocol::{self, ScanRequest, ScanResponse, ScanType};
use crate::transport::Stream;

/// Timeout for ping/liveness checks (must be fast).
const PING_TIMEOUT: Duration = Duration::from_millis(50);

/// Timeout for scan requests (model loading on first call can take tens of seconds).
const SCAN_TIMEOUT: Duration = Duration::from_mins(2);

/// Run a full scan (with ML) via the daemon.
///
/// # Errors
///
/// Returns `ScanError::DaemonIo` if the daemon is unreachable.
pub fn scan_full(text: &str, config: &Config) -> Result<ScanResult, ScanError> {
    scan_full_with_threshold(text, config, config.threshold)
}

/// Run a full scan with a custom ML threshold.
///
/// # Errors
///
/// Returns `ScanError::DaemonIo` if the daemon is unreachable.
pub fn scan_full_with_threshold(
    text: &str,
    config: &Config,
    threshold: f32,
) -> Result<ScanResult, ScanError> {
    debug!(
        text_len = text.len(),
        threshold, "attempting full scan via daemon"
    );
    let req = ScanRequest {
        scan_type: ScanType::Full,
        threshold,
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
        write_private(&token_file, token)
            .map_err(|e| ScanError::DaemonStart(format!("failed to write token file: {e}")))?;
        cmd.arg("--hf-token-path").arg(&token_file);
    }

    // runtime_dir is not passed to the child. It's test-only; production always
    // uses None (hardcoded in main.rs). No CLI flag needed: an attacker who can
    // inject --runtime-dir already has code execution.
    cmd.arg("serve");

    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    cmd.spawn()
        .map_err(|e| ScanError::DaemonStart(format!("failed to spawn daemon: {e}")))?;
    Ok(())
}

/// Write `contents` to a file that is owner-only before any byte lands in it.
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    // mode() only applies on create; tighten a pre-existing file too
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(contents.as_bytes())
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
        // no socket file means the daemon isn't starting, so bail early
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
    response_to_scan_result(protocol::read_response(&mut stream)?)
}

const fn response_to_scan_result(resp: ScanResponse) -> Result<ScanResult, ScanError> {
    match resp {
        ScanResponse::Clean | ScanResponse::Pong => Ok(ScanResult::Clean),
        ScanResponse::Injection => Ok(ScanResult::Injection),
        ScanResponse::Secret => Ok(ScanResult::Secret),
        ScanResponse::Error => Err(ScanError::DaemonScanFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_clean_maps_to_clean() {
        assert!(response_to_scan_result(ScanResponse::Clean)
            .unwrap()
            .is_clean());
    }

    #[test]
    fn response_pong_maps_to_clean() {
        assert!(response_to_scan_result(ScanResponse::Pong)
            .unwrap()
            .is_clean());
    }

    #[test]
    fn response_injection_maps_to_injection() {
        assert!(response_to_scan_result(ScanResponse::Injection)
            .unwrap()
            .is_injection());
    }

    #[test]
    fn response_secret_maps_to_secret() {
        assert!(matches!(
            response_to_scan_result(ScanResponse::Secret),
            Ok(ScanResult::Secret)
        ));
    }

    #[test]
    fn response_error_maps_to_scan_failed() {
        assert!(matches!(
            response_to_scan_result(ScanResponse::Error),
            Err(ScanError::DaemonScanFailed)
        ));
    }

    /// Answers a single ping, then exits so tests can join it.
    fn pong_daemon(runtime_dir: &Path) -> std::thread::JoinHandle<()> {
        use futures_util::{SinkExt, StreamExt};
        use interprocess::local_socket::traits::tokio::Listener as _;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let listener = rt
            .block_on(async { crate::transport::bind_async(Some(runtime_dir)) })
            .unwrap();
        std::thread::spawn(move || {
            rt.block_on(async move {
                let stream = listener.accept().await.unwrap();
                let mut framed = tokio_util::codec::Framed::new(stream, protocol::DaemonCodec);
                framed.next().await.unwrap().unwrap();
                framed.send(ScanResponse::Pong).await.unwrap();
            });
        })
    }

    fn config_in(dir: &Path) -> Config {
        Config {
            runtime_dir: Some(dir.to_path_buf()),
            ..Config::default()
        }
    }

    #[test]
    fn is_daemon_running_detects_live_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = pong_daemon(dir.path());
        assert!(is_daemon_running(Some(dir.path())));
        daemon.join().unwrap();
    }

    #[test]
    fn wait_for_ready_sees_live_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = pong_daemon(dir.path());
        assert!(wait_for_ready(Some(dir.path())));
        daemon.join().unwrap();
    }

    #[test]
    fn wait_for_ready_bails_without_socket() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!wait_for_ready(Some(dir.path())));
    }

    #[test]
    fn ensure_running_reuses_live_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = pong_daemon(dir.path());
        ensure_running(&config_in(dir.path())).unwrap();
        daemon.join().unwrap();
    }

    #[test]
    fn ensure_running_fails_when_daemon_never_comes_up() {
        let dir = tempfile::tempdir().unwrap();
        // current_exe is the test binary, which exits without binding a socket
        let result = ensure_running(&config_in(dir.path()));
        assert!(matches!(result, Err(ScanError::DaemonStart(_))));
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

        // spawns the test binary, which rejects the daemon args and exits
        spawn_daemon(&config).unwrap();

        let token_path = dir.path().join(".hf-token");
        assert_eq!(std::fs::read_to_string(&token_path).unwrap(), "test-token");
        let perms = std::fs::metadata(&token_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600, "token file should be 0600");
    }

    #[test]
    fn write_private_tightens_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".hf-token");
        std::fs::write(&path, "old-token-longer").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_private(&path, "new").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
