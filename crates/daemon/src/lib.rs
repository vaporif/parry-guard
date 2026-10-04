//! Daemon that keeps the ML model loaded and serves scans over IPC.

pub mod client;
pub mod protocol;
pub mod scan_cache;
pub mod server;
pub mod transport;

pub use client::{
    ensure_running, is_daemon_running, scan_full, scan_full_with_threshold, spawn_daemon,
};
pub use protocol::{ScanRequest, ScanResponse, ScanType};
pub use server::{run, DaemonConfig};
