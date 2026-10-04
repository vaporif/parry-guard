//! Daemon server.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
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

/// `S` is the scanner; tests use a stand-in so no model is needed.
enum MlState<S = MlScanner> {
    NotLoaded,
    /// A load thread is running. Requests wait on its result instead of starting another.
    Loading {
        result: Receiver<Option<S>>,
        attempt: u8,
        timeouts: u8,
    },
    Loaded(S),
    Failed(u8),
}

impl<S> MlState<S> {
    /// Return the scanner, starting a load unless one is running or `MAX_ML_RETRIES` failed.
    ///
    /// A load still running after `timeout` keeps going. Later requests wait on it
    /// again, `MAX_ML_RETRIES` times at most, then only check whether it has finished.
    fn get_or_load(
        &mut self,
        start_load: impl FnOnce() -> Receiver<Option<S>>,
        timeout: Duration,
    ) -> Option<&mut S> {
        let attempt = match *self {
            Self::NotLoaded => Some(0),
            Self::Failed(n) if n < MAX_ML_RETRIES => Some(n),
            Self::Loading { .. } | Self::Loaded(_) | Self::Failed(_) => None,
        };
        if let Some(attempt) = attempt {
            info!(
                attempt = attempt + 1,
                max = MAX_ML_RETRIES,
                "loading ML model"
            );
            *self = Self::Loading {
                result: start_load(),
                attempt,
                timeouts: 0,
            };
        }
        if let Self::Loading {
            result,
            attempt,
            timeouts,
        } = self
        {
            let received = if *timeouts < MAX_ML_RETRIES {
                result.recv_timeout(timeout)
            } else {
                result.try_recv().map_err(|e| match e {
                    TryRecvError::Empty => RecvTimeoutError::Timeout,
                    TryRecvError::Disconnected => RecvTimeoutError::Disconnected,
                })
            };
            match received {
                Ok(Some(scanner)) => {
                    info!(ml = "loaded", "ML model ready");
                    *self = Self::Loaded(scanner);
                }
                Ok(None) | Err(RecvTimeoutError::Disconnected) => {
                    warn!(
                        attempt = *attempt + 1,
                        max = MAX_ML_RETRIES,
                        "ML model failed to load, scans will fail-close"
                    );
                    *self = Self::Failed(*attempt + 1);
                }
                Err(RecvTimeoutError::Timeout) => {
                    *timeouts = timeouts.saturating_add(1);
                    warn!(
                        waited_secs = timeout.as_secs(),
                        "ML model still loading, scans will fail-close until it is ready"
                    );
                }
            }
        }
        match self {
            Self::Loaded(scanner) => Some(scanner),
            Self::NotLoaded | Self::Loading { .. } | Self::Failed(_) => None,
        }
    }
}

use crate::protocol::{DaemonCodec, ScanRequest, ScanResponse, ScanType};
use crate::scan_cache::{self, ScanCache};
use crate::transport;

pub struct DaemonConfig {
    pub idle_timeout: Duration,
}

/// Removes PID file and socket on drop.
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

/// # Errors
/// Fails if another daemon is running or the socket can't be bound.
#[instrument(skip(config, daemon_config), fields(idle_timeout = ?daemon_config.idle_timeout))]
pub async fn run(config: &Config, daemon_config: &DaemonConfig) -> eyre::Result<()> {
    let rd = config.runtime_dir.as_deref();
    // a plain connect, not a ping: a daemon busy loading the model accepts
    // connections but can't answer a ping in time, and must not lose its socket
    if transport::Stream::connect(Duration::from_millis(50), rd).is_ok() {
        warn!("another daemon is already listening");
        return Err(eyre::eyre!("another daemon is already running"));
    }

    transport::cleanup_stale_state(rd);
    let listener = transport::bind_async(rd)?;

    let pid_path = transport::pid_file_path(rd)?;
    // PID file is informational; the socket bind enforces mutual exclusion
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

/// Load the scanner on a thread of its own and hand back the result channel.
/// The thread outlives any wait on it, so a slow load can still finish.
fn spawn_ml_load(config: &Config) -> Receiver<Option<MlScanner>> {
    let config = config.clone();
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| MlScanner::load(&config)));
        let scanner = match result {
            Ok(Ok(scanner)) => Some(scanner),
            Ok(Err(e)) => {
                warn!(%e, "ML scanner failed to load");
                None
            }
            Err(_) => {
                warn!("ML scanner panicked during load");
                None
            }
        };
        let _ = tx.send(scanner);
    });

    rx
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
            let scanner = ml_state.get_or_load(|| spawn_ml_load(config), ML_LOAD_TIMEOUT);
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

    const SHORT_WAIT: Duration = Duration::from_millis(10);

    fn finished_load(scanner: Option<u8>) -> Receiver<Option<u8>> {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(scanner).unwrap();
        rx
    }

    #[test]
    fn ml_load_gives_up_after_max_retries() {
        // a subscriber makes the log fields evaluate, so they're covered
        let subscriber = tracing_subscriber::fmt().with_test_writer().finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let mut state = MlState::<u8>::NotLoaded;
        let mut loads = 0;
        for _ in 0..MAX_ML_RETRIES + 2 {
            let scanner = state.get_or_load(
                || {
                    loads += 1;
                    finished_load(None)
                },
                SHORT_WAIT,
            );
            assert!(scanner.is_none());
        }
        assert_eq!(loads, MAX_ML_RETRIES);
        assert!(matches!(state, MlState::Failed(MAX_ML_RETRIES)));
    }

    /// Hands out one pending load and counts how many loads were started.
    struct FakeLoader {
        pending: Option<Receiver<Option<u8>>>,
        starts: usize,
    }

    impl FakeLoader {
        fn pending() -> (std::sync::mpsc::Sender<Option<u8>>, Self) {
            let (tx, rx) = std::sync::mpsc::channel();
            let loader = Self {
                pending: Some(rx),
                starts: 0,
            };
            (tx, loader)
        }

        fn start(&mut self) -> Receiver<Option<u8>> {
            self.starts += 1;
            self.pending.take().unwrap_or_else(|| finished_load(None))
        }
    }

    #[test]
    fn slow_load_is_awaited_not_restarted() {
        let (tx, mut loader) = FakeLoader::pending();
        let mut state = MlState::<u8>::NotLoaded;
        for _ in 0..2 {
            let scanner = state.get_or_load(|| loader.start(), SHORT_WAIT);
            assert_eq!(scanner, None, "the load has not finished yet");
        }
        assert_eq!(
            loader.starts, 1,
            "a timed-out load must not start another thread"
        );

        tx.send(Some(7)).unwrap();
        let scanner = state.get_or_load(|| loader.start(), SHORT_WAIT);
        assert_eq!(scanner.copied(), Some(7), "a late success still installs");
        assert_eq!(loader.starts, 1);
    }

    #[test]
    fn hung_load_stops_blocking_after_max_waits() {
        let (tx, mut loader) = FakeLoader::pending();
        let mut state = MlState::<u8>::Loading {
            result: loader.pending.take().unwrap(),
            attempt: 0,
            timeouts: MAX_ML_RETRIES,
        };
        // past the wait budget only a non-blocking check runs, so this returns at once
        let scanner = state.get_or_load(|| loader.start(), Duration::from_hours(1));
        assert_eq!(scanner, None);

        tx.send(Some(7)).unwrap();
        let scanner = state.get_or_load(|| loader.start(), Duration::from_hours(1));
        assert_eq!(scanner.copied(), Some(7));
        assert_eq!(loader.starts, 0, "the running load is reused");
    }

    #[test]
    fn failed_load_after_wait_allows_retry() {
        let (tx, mut loader) = FakeLoader::pending();
        let mut state = MlState::<u8>::NotLoaded;
        assert_eq!(state.get_or_load(|| loader.start(), SHORT_WAIT), None);

        tx.send(None).unwrap();
        assert_eq!(state.get_or_load(|| loader.start(), SHORT_WAIT), None);
        assert!(matches!(state, MlState::Failed(1)));
        assert_eq!(loader.starts, 1);

        let scanner = state.get_or_load(|| finished_load(Some(3)), SHORT_WAIT);
        assert_eq!(scanner.copied(), Some(3));
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
