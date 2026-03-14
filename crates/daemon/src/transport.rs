//! IPC transport layer for daemon communication.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use interprocess::local_socket::{prelude::*, GenericFilePath, ListenerOptions};

/// Returns the parry runtime directory.
/// If `runtime_dir` is `Some`, returns it directly. Otherwise returns `~/.parry-guard/`.
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined (when `runtime_dir` is `None`).
pub fn parry_dir(runtime_dir: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(dir) = runtime_dir {
        return Ok(dir.to_path_buf());
    }

    home_dir()
        .map(|h| h.join(".parry-guard"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "cannot determine home directory"))
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
}

fn socket_path(runtime_dir: Option<&Path>) -> io::Result<PathBuf> {
    Ok(parry_dir(runtime_dir)?.join("parry-guard.sock"))
}

/// Check if the daemon socket file exists on disk.
#[must_use]
pub fn socket_exists(runtime_dir: Option<&Path>) -> bool {
    socket_path(runtime_dir).is_ok_and(|p| p.exists())
}

fn socket_name(
    runtime_dir: Option<&Path>,
) -> io::Result<interprocess::local_socket::Name<'static>> {
    // Always use filesystem path for reliable cleanup across all platforms.
    // Namespaced sockets (Linux abstract, Windows named pipes) can leave stale
    // references that are difficult to clean up, causing "Address already in use".
    socket_path(runtime_dir)?
        .to_fs_name::<GenericFilePath>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// # Errors
///
/// Returns an error if the parry runtime directory cannot be determined.
pub fn pid_file_path(runtime_dir: Option<&Path>) -> io::Result<PathBuf> {
    Ok(parry_dir(runtime_dir)?.join("daemon.pid"))
}

// ─── Stale state cleanup ─────────────────────────────────────────────────────

/// Check if a process with the given PID is alive.
#[cfg(unix)]
fn is_process_alive(pid: u32) -> bool {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    if pid == 0 {
        return false;
    }
    // SAFETY: kill with signal 0 checks process existence without sending a signal.
    unsafe { kill(pid, 0) == 0 }
}

#[cfg(not(unix))]
fn is_process_alive(_pid: u32) -> bool {
    // Cannot verify on non-Unix; assume alive to avoid accidental cleanup.
    true
}

/// Remove stale daemon state (PID file and socket) if the recorded process is no longer alive.
pub fn cleanup_stale_state(runtime_dir: Option<&Path>) {
    let Ok(pid_path) = pid_file_path(runtime_dir) else {
        return;
    };

    // If PID file exists, check if that process is alive
    if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
        match pid_str.trim().parse::<u32>() {
            Ok(pid) if is_process_alive(pid) => return,
            Ok(pid) => {
                tracing::info!(pid, "removing stale daemon state (process not alive)");
            }
            Err(_) => {
                tracing::info!("removing corrupt daemon PID file");
            }
        }
        let _ = std::fs::remove_file(&pid_path);
    }

    // Clean up orphaned socket even if PID file was missing
    if let Ok(sock) = socket_path(runtime_dir) {
        if sock.exists() {
            tracing::info!("removing stale socket");
            let _ = std::fs::remove_file(&sock);
        }
    }
}

// ─── Async listener (for daemon server) ──────────────────────────────────────

/// Create an async tokio listener for the daemon.
///
/// # Errors
///
/// Returns an error if the socket cannot be created.
pub fn bind_async(
    runtime_dir: Option<&Path>,
) -> io::Result<interprocess::local_socket::tokio::Listener> {
    let dir = parry_dir(runtime_dir)?;
    std::fs::create_dir_all(&dir)?;

    // Remove stale socket file before binding
    let sock_path = socket_path(runtime_dir)?;
    if sock_path.exists() {
        let _ = std::fs::remove_file(&sock_path);
    }

    let name = socket_name(runtime_dir)?;
    ListenerOptions::new().name(name).create_tokio()
}

// ─── Sync stream (for daemon client) ────────────────────────────────────────

pub struct Stream {
    inner: interprocess::local_socket::Stream,
}

impl Stream {
    /// Connect to the daemon with a timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established.
    pub fn connect(timeout: Duration, runtime_dir: Option<&Path>) -> io::Result<Self> {
        let name = socket_name(runtime_dir)?;
        let inner = interprocess::local_socket::Stream::connect(name)?;
        let _ = inner.set_recv_timeout(Some(timeout));
        let _ = inner.set_send_timeout(Some(timeout));
        Ok(Self { inner })
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parry_dir_uses_runtime_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = parry_dir(Some(dir.path())).unwrap();
        assert_eq!(result, dir.path().to_path_buf());
    }

    #[test]
    fn connect_fails_without_listener() {
        let dir = tempfile::tempdir().unwrap();
        let result = Stream::connect(Duration::from_millis(50), Some(dir.path()));
        assert!(result.is_err());
    }
}
