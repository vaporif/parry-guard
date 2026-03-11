//! Async daemon server.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use interprocess::local_socket::traits::tokio::Listener as _;
use tokio::time::Instant;
use tokio_util::codec::Framed;
use tracing::{debug, info, instrument, warn};

use parry_core::{Config, ScanResult};
use parry_ml::MlScanner;

enum MlState {
    NotLoaded,
    Loaded(MlScanner),
    Failed,
}

use crate::protocol::{DaemonCodec, ScanRequest, ScanResponse, ScanType};
use crate::scan_cache::{self, ScanCache};
use crate::transport;

pub struct DaemonConfig {
    pub idle_timeout: Duration,
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

    // Socket exists but nobody responded to ping — stale, clean up
    crate::transport::cleanup_stale_state(rd);
    let listener = transport::bind_async(rd)?;

    let pid_path = transport::pid_file_path(rd)?;
    std::fs::write(&pid_path, std::process::id().to_string())?;

    // ML model loads lazily on first scan request so Pings work immediately
    let mut ml_state = MlState::NotLoaded;
    let cache = ScanCache::open(rd).map(Arc::new);

    let cache_status = if cache.is_some() { "loaded" } else { "off" };
    info!(
        pid = std::process::id(),
        cache = cache_status,
        "daemon started, ML loads on first scan"
    );

    if let Some(ref c) = cache {
        let c = Arc::clone(c);
        tokio::spawn(async move { scan_cache::prune_task(&c).await });
    }

    let idle_timeout = daemon_config.idle_timeout;
    let mut deadline = Instant::now() + idle_timeout;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(stream) => {
                        debug!("accepted connection");
                        handle_connection(stream, &mut ml_state, config, cache.as_deref()).await;
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
        }
    }

    drop(listener);
    let _ = std::fs::remove_file(&pid_path);
    crate::transport::cleanup_stale_state(rd);

    Ok(())
}

fn load_ml_scanner(config: &Config) -> Option<MlScanner> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| MlScanner::load(config))) {
        Ok(Ok(scanner)) => Some(scanner),
        Ok(Err(e)) => {
            warn!(%e, "ML scanner failed to load");
            None
        }
        Err(_) => {
            warn!("ML scanner panicked during load");
            None
        }
    }
}

async fn handle_connection(
    stream: interprocess::local_socket::tokio::Stream,
    ml_state: &mut MlState,
    config: &Config,
    cache: Option<&ScanCache>,
) {
    let mut framed = Framed::new(stream, DaemonCodec);

    let Some(Ok(req)) = framed.next().await else {
        return;
    };

    let resp = if req.scan_type == ScanType::Ping {
        ScanResponse::Pong
    } else {
        if matches!(ml_state, MlState::NotLoaded) {
            info!("loading ML model");
            *ml_state = load_ml_scanner(config).map_or_else(
                || {
                    warn!(
                        ml = "unavailable",
                        "ML model failed to load, scans will fail-close"
                    );
                    MlState::Failed
                },
                |scanner| {
                    info!(ml = "loaded", "ML model ready");
                    MlState::Loaded(scanner)
                },
            );
        }
        let scanner = if let MlState::Loaded(ref mut s) = ml_state {
            Some(s)
        } else {
            None
        };
        handle_request(&req, scanner, cache)
    };
    let _ = framed.send(resp).await;
}

fn handle_request(
    req: &ScanRequest,
    ml_scanner: Option<&mut MlScanner>,
    cache: Option<&ScanCache>,
) -> ScanResponse {
    debug!(text_len = req.text.len(), threshold = req.threshold, "handling full scan request");
    if let Some(c) = cache {
        let hash = scan_cache::hash_content_with_threshold(&req.text, req.threshold);

        if let Some(cached) = c.get(&hash) {
            debug!(?cached, "cache hit");
            return scan_result_to_response(cached);
        }

        let result = run_full_scan(&req.text, req.threshold, ml_scanner);
        // Don't cache errors — model may load on next daemon restart
        if result != ScanResponse::Error {
            c.put(&hash, response_to_result(result));
        }
        result
    } else {
        run_full_scan(&req.text, req.threshold, ml_scanner)
    }
}

fn run_full_scan(text: &str, threshold: f32, ml_scanner: Option<&mut MlScanner>) -> ScanResponse {
    let fast = parry_core::scan_text_fast(text);
    if !fast.is_clean() {
        debug!(?fast, "fast scan detected issue");
        return scan_result_to_response(fast);
    }

    let Some(scanner) = ml_scanner else {
        debug!("ML model failed to load, scan cannot proceed (fail-closed)");
        return ScanResponse::Error;
    };

    let stripped = parry_core::unicode::strip_invisible(text);
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
