//! Async daemon server.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use interprocess::local_socket::traits::tokio::Listener as _;
use tokio::time::Instant;
use tokio_util::codec::Framed;
use tracing::{debug, info, instrument, warn};

use parry_guard_core::{Config, ScanResult};
use parry_guard_ml::MlScanner;

const MAX_ML_RETRIES: u8 = 3;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const ML_LOAD_TIMEOUT: Duration = Duration::from_mins(2);

enum MlState {
    NotLoaded,
    Loaded(MlScanner),
    Failed(u8),
}

impl MlState {
    /// Return the scanner, loading it first unless it already failed `MAX_ML_RETRIES` times.
    fn get_or_load(&mut self, load: impl FnOnce() -> Option<MlScanner>) -> Option<&mut MlScanner> {
        let attempt = match *self {
            Self::NotLoaded => Some(0),
            Self::Failed(n) if n < MAX_ML_RETRIES => Some(n),
            Self::Loaded(_) | Self::Failed(_) => None,
        };
        if let Some(attempt) = attempt {
            info!(
                attempt = attempt + 1,
                max = MAX_ML_RETRIES,
                "loading ML model"
            );
            *self = load().map_or_else(
                || {
                    warn!(
                        attempt = attempt + 1,
                        max = MAX_ML_RETRIES,
                        "ML model failed to load, scans will fail-close"
                    );
                    Self::Failed(attempt + 1)
                },
                |scanner| {
                    info!(ml = "loaded", "ML model ready");
                    Self::Loaded(scanner)
                },
            );
        }
        match self {
            Self::Loaded(scanner) => Some(scanner),
            Self::NotLoaded | Self::Failed(_) => None,
        }
    }
}

use crate::protocol::{DaemonCodec, ScanRequest, ScanResponse, ScanType};
use crate::scan_cache::{self, ScanCache};
use crate::transport;

pub struct DaemonConfig {
    pub idle_timeout: Duration,
}

/// RAII cleanup for PID file and socket.
struct CleanupGuard {
    pid_path: PathBuf,
    runtime_dir: Option<PathBuf>,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        // a replacement daemon may have rebound the socket and rewritten the PID file
        let owns_state = std::fs::read_to_string(&self.pid_path)
            .is_ok_and(|pid| pid.trim() == std::process::id().to_string());
        if !owns_state {
            return;
        }
        let _ = std::fs::remove_file(&self.pid_path);
        transport::cleanup_stale_state(self.runtime_dir.as_deref());
    }
}

/// Run the daemon server. ML model loads lazily on first scan request.
///
/// # Errors
///
/// Returns an error if another daemon is running or the socket cannot be bound.
#[instrument(skip(config, daemon_config), fields(idle_timeout = ?daemon_config.idle_timeout))]
pub async fn run(config: &Config, daemon_config: &DaemonConfig) -> eyre::Result<()> {
    let rd = config.runtime_dir.as_deref();
    // a plain connect, not a ping: a daemon busy loading the model accepts
    // connections but can't answer a ping in time, and must not lose its socket
    if transport::Stream::connect(Duration::from_millis(50), rd).is_ok() {
        warn!("another daemon is already listening");
        return Err(eyre::eyre!("another daemon is already running"));
    }

    // stale socket: nobody answered the ping
    transport::cleanup_stale_state(rd);
    let listener = transport::bind_async(rd)?;

    let pid_path = transport::pid_file_path(rd)?;
    // PID file is informational; socket bind is the real mutual exclusion
    std::fs::write(&pid_path, std::process::id().to_string())?;

    let _cleanup = CleanupGuard {
        pid_path: pid_path.clone(),
        runtime_dir: rd.map(std::path::Path::to_path_buf),
    };

    // ML loads lazily on first scan so pings work immediately
    let mut ml_state = MlState::NotLoaded;
    let cache = ScanCache::open(rd).map(Arc::new);

    let model_fingerprint = config.resolve_models().map_or([0u8; 32], |models| {
        let repos: Vec<String> = models.into_iter().map(|m| m.repo).collect();
        scan_cache::model_fingerprint(&repos)
    });

    let cache_status = if cache.is_some() { "loaded" } else { "off" };
    info!(
        pid = std::process::id(),
        cache = cache_status,
        "daemon started, ML loads on first scan"
    );

    let prune_handle = cache.as_ref().map(|c| {
        let c = Arc::clone(c);
        tokio::spawn(async move { scan_cache::prune_task(&c).await })
    });

    let idle_timeout = daemon_config.idle_timeout;
    let mut deadline = Instant::now() + idle_timeout;

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(stream) => {
                        debug!("accepted connection");
                        handle_connection(stream, &mut ml_state, config, cache.as_deref(), &model_fingerprint).await;
                        deadline = Instant::now() + idle_timeout;
                    }
                    Err(e) => {
                        warn!(%e, "accept error");
                    }
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                info!("idle timeout, shutting down");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received SIGINT, shutting down");
                break;
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM, shutting down");
                break;
            }
        }
    }

    if let Some(handle) = prune_handle {
        handle.abort();
    }
    drop(listener);
    Ok(())
}

/// On timeout the background thread keeps running. `MlState::Failed`
/// stops concurrent loads from piling up.
fn load_ml_scanner(config: &Config) -> Option<MlScanner> {
    let config = config.clone();
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| MlScanner::load(&config)));
        let _ = tx.send(result);
    });

    match rx.recv_timeout(ML_LOAD_TIMEOUT) {
        Ok(Ok(Ok(scanner))) => Some(scanner),
        Ok(Ok(Err(e))) => {
            warn!(%e, "ML scanner failed to load");
            None
        }
        Ok(Err(_)) => {
            warn!("ML scanner panicked during load");
            None
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            warn!(
                "ML scanner load timed out after {}s",
                ML_LOAD_TIMEOUT.as_secs()
            );
            None
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            warn!("ML scanner load thread terminated unexpectedly");
            None
        }
    }
}

async fn handle_connection(
    stream: interprocess::local_socket::tokio::Stream,
    ml_state: &mut MlState,
    config: &Config,
    cache: Option<&ScanCache>,
    model_fingerprint: &[u8; 32],
) {
    let mut framed = Framed::new(stream, DaemonCodec);

    let req = match tokio::time::timeout(IO_TIMEOUT, framed.next()).await {
        Ok(Some(Ok(req))) => req,
        Ok(Some(Err(e))) => {
            warn!(%e, "client read error");
            return;
        }
        Ok(None) | Err(_) => {
            debug!("client disconnected or read timed out");
            return;
        }
    };

    let resp = match req.scan_type {
        ScanType::Ping => ScanResponse::Pong,
        ScanType::Full => {
            let scanner = ml_state.get_or_load(|| load_ml_scanner(config));
            handle_request(&req, scanner, cache, model_fingerprint)
        }
    };
    match tokio::time::timeout(IO_TIMEOUT, framed.send(resp)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!(%e, "response send failed"),
        Err(_) => warn!("response send timed out"),
    }
}

fn handle_request(
    req: &ScanRequest,
    ml_scanner: Option<&mut MlScanner>,
    cache: Option<&ScanCache>,
    model_fingerprint: &[u8; 32],
) -> ScanResponse {
    debug!(
        text_len = req.text.len(),
        threshold = req.threshold,
        "handling full scan request"
    );
    if let Some(c) = cache {
        let hash =
            scan_cache::hash_content_with_threshold(&req.text, req.threshold, model_fingerprint);

        if let Some(cached) = c.get(&hash) {
            debug!(?cached, "cache hit");
            return scan_result_to_response(cached);
        }

        let result = run_full_scan(&req.text, req.threshold, ml_scanner);
        // don't cache errors: the model may load after a restart
        if let Some(cacheable) = response_to_result(result) {
            c.put(&hash, cacheable);
        }
        result
    } else {
        run_full_scan(&req.text, req.threshold, ml_scanner)
    }
}

fn run_full_scan(text: &str, threshold: f32, ml_scanner: Option<&mut MlScanner>) -> ScanResponse {
    let fast = parry_guard_core::scan_text_fast(text);
    if !fast.is_clean() {
        debug!(?fast, "fast scan detected issue");
        return scan_result_to_response(fast);
    }

    let Some(scanner) = ml_scanner else {
        debug!("ML model failed to load, scan cannot proceed (fail-closed)");
        return ScanResponse::Error;
    };

    let stripped = parry_guard_core::unicode::strip_invisible(text);
    match scanner.scan_chunked(&stripped, threshold) {
        Ok(false) => {
            debug!("ML scan clean");
            ScanResponse::Clean
        }
        Ok(true) => {
            debug!("ML scan detected injection");
            ScanResponse::Injection
        }
        Err(e) => {
            warn!(%e, "ML scan error, treating as injection (fail-closed)");
            ScanResponse::Injection
        }
    }
}

const fn response_to_result(resp: ScanResponse) -> Option<ScanResult> {
    match resp {
        ScanResponse::Injection => Some(ScanResult::Injection),
        ScanResponse::Secret => Some(ScanResult::Secret),
        ScanResponse::Clean | ScanResponse::Pong => Some(ScanResult::Clean),
        ScanResponse::Error => None,
    }
}

const fn scan_result_to_response(result: ScanResult) -> ScanResponse {
    match result {
        ScanResult::Injection => ScanResponse::Injection,
        ScanResult::Secret => ScanResponse::Secret,
        ScanResult::Clean => ScanResponse::Clean,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn guard_with_state(dir: &Path, pid: u32) -> (CleanupGuard, PathBuf, PathBuf) {
        let pid_path = transport::pid_file_path(Some(dir)).unwrap();
        let sock = dir.join("parry-guard.sock");
        std::fs::write(&pid_path, pid.to_string()).unwrap();
        std::fs::write(&sock, "").unwrap();
        let guard = CleanupGuard {
            pid_path: pid_path.clone(),
            runtime_dir: Some(dir.to_path_buf()),
        };
        (guard, pid_path, sock)
    }

    #[test]
    fn ml_load_gives_up_after_max_retries() {
        // a subscriber makes the log fields evaluate, so they're covered
        let subscriber = tracing_subscriber::fmt().with_test_writer().finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let mut state = MlState::NotLoaded;
        let mut loads = 0;
        for _ in 0..MAX_ML_RETRIES + 2 {
            let scanner = state.get_or_load(|| {
                loads += 1;
                None
            });
            assert!(scanner.is_none());
        }
        assert_eq!(loads, MAX_ML_RETRIES);
        assert!(matches!(state, MlState::Failed(MAX_ML_RETRIES)));
    }

    #[test]
    fn cleanup_guard_removes_own_state() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, pid_path, sock) = guard_with_state(dir.path(), std::process::id());
        drop(guard);
        assert!(!pid_path.exists());
        assert!(!sock.exists());
    }

    #[test]
    fn cleanup_guard_keeps_state_of_replacement_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let other_daemon = std::os::unix::process::parent_id();
        let (guard, pid_path, sock) = guard_with_state(dir.path(), other_daemon);
        drop(guard);
        assert!(
            pid_path.exists(),
            "must not delete another daemon's PID file"
        );
        assert!(sock.exists(), "must not delete another daemon's socket");
    }

    #[test]
    fn run_refuses_to_replace_busy_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // listens but never accepts, like a daemon stuck loading the model
            let _busy = transport::bind_async(Some(dir.path())).unwrap();
            let config = Config {
                runtime_dir: Some(dir.path().to_path_buf()),
                ..Config::default()
            };
            let daemon_config = DaemonConfig {
                idle_timeout: Duration::from_secs(1),
            };
            let result = run(&config, &daemon_config).await;
            assert!(result.is_err(), "must not take over a live socket");
            assert!(transport::socket_exists(Some(dir.path())));
        });
    }
}
