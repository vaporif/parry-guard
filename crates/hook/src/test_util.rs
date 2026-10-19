//! Shared test utilities for tests that manipulate cwd.

use std::path::{Path, PathBuf};
use std::sync::MutexGuard;

/// Single mutex shared across all test modules that touch cwd.
static CWD_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII guard that serializes cwd access and restores it on drop.
pub(crate) struct CwdGuard<'a> {
    prev_cwd: PathBuf,
    _lock: MutexGuard<'a, ()>,
}

impl CwdGuard<'_> {
    pub(crate) fn new(dir: &Path) -> Self {
        let lock = CWD_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        Self {
            prev_cwd,
            _lock: lock,
        }
    }
}

impl Drop for CwdGuard<'_> {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.prev_cwd);
    }
}

pub(crate) fn test_config_with_dir(dir: &Path) -> parry_guard_core::Config {
    parry_guard_core::Config {
        runtime_dir: Some(dir.to_path_buf()),
        ..parry_guard_core::Config::default()
    }
}

pub(crate) fn test_db(dir: &Path) -> parry_guard_core::repo_db::RepoDb {
    parry_guard_core::repo_db::RepoDb::open(Some(dir)).unwrap()
}

/// Text containing this marker is reported as injection by [`fake_daemon`].
pub(crate) const FAKE_ML_INJECTION: &str = "FAKE_ML_INJECTION_MARKER";

/// Model-free daemon on `runtime_dir`: `Injection` iff text contains [`FAKE_ML_INJECTION`].
pub(crate) fn fake_daemon(runtime_dir: &Path) {
    use futures_util::{SinkExt, StreamExt};
    use interprocess::local_socket::traits::tokio::Listener as _;
    use parry_guard_daemon::protocol::{DaemonCodec, ScanResponse, ScanType};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    let listener = rt
        .block_on(async { parry_guard_daemon::transport::bind_async(Some(runtime_dir)) })
        .unwrap();
    std::thread::spawn(move || {
        rt.block_on(async move {
            while let Ok(stream) = listener.accept().await {
                tokio::spawn(async move {
                    let mut framed = tokio_util::codec::Framed::new(stream, DaemonCodec);
                    while let Some(Ok(req)) = framed.next().await {
                        let resp = match req.scan_type {
                            ScanType::Ping => ScanResponse::Pong,
                            ScanType::Full if req.text.contains(FAKE_ML_INJECTION) => {
                                ScanResponse::Injection
                            }
                            ScanType::Full => ScanResponse::Clean,
                        };
                        if framed.send(resp).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    });
}
