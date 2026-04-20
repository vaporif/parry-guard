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
        let _ = std::fs::remove_file(&self.pid_path);
        crate::transport::cleanup_stale_state(self.runtime_dir.as_deref());
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
    if crate::client::is_daemon_running(rd) {
        warn!("another daemon is already running");
        return Err(eyre::eyre!("another daemon is already running"));
    }

    // stale socket -nobody responded to ping
    crate::transport::cleanup_stale_state(rd);
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

/// On timeout the background thread is left running — `MlState::Failed`
/// prevents piling up concurrent loads.
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
            let should_load = match ml_state {
                MlState::NotLoaded => Some(0),
                MlState::Failed(n) if *n < MAX_ML_RETRIES => Some(*n),
                _ => None,
            };
            if let Some(attempt) = should_load {
                info!(
                    attempt = attempt + 1,
                    max = MAX_ML_RETRIES,
                    "loading ML model"
                );
                *ml_state = load_ml_scanner(config).map_or_else(
                    || {
                        warn!(
                            attempt = attempt + 1,
                            max = MAX_ML_RETRIES,
                            "ML model failed to load, scans will fail-close"
                        );
                        MlState::Failed(attempt + 1)
                    },
                    |scanner| {
                        info!(ml = "loaded", "ML model ready");
                        MlState::Loaded(scanner)
                    },
                );
            }
            let scanner = match ml_state {
                MlState::Loaded(ref mut s) => Some(s),
                _ => None,
            };
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
        // don't cache errors -model may load on next restart
        if result != ScanResponse::Error {
            c.put(&hash, response_to_result(result));
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

fn response_to_result(resp: ScanResponse) -> ScanResult {
    match resp {
        ScanResponse::Injection => ScanResult::Injection,
        ScanResponse::Secret => ScanResult::Secret,
        ScanResponse::Clean | ScanResponse::Pong => ScanResult::Clean,
        ScanResponse::Error => unreachable!("Error responses must not be cached"),
    }
}

const fn scan_result_to_response(result: ScanResult) -> ScanResponse {
    match result {
        ScanResult::Injection => ScanResponse::Injection,
        ScanResult::Secret => ScanResponse::Secret,
        ScanResult::Clean => ScanResponse::Clean,
    }
}
