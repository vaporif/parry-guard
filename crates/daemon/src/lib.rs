//! Async daemon for persistent ML model loading.
//!
//! The daemon keeps the ML model loaded in memory and serves scan requests
//! via IPC, avoiding repeated model loading overhead.

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
