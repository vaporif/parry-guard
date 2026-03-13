//! Centralized repo state database at `~/.parry/parry.redb`.

use std::path::Path;

use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use tracing::{debug, warn};

const REPO_STATE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("repo_state");
const GUARD_CACHE_TABLE: TableDefinition<&str, u64> = TableDefinition::new("guard_cache");
const AUDIT_CACHE_TABLE: TableDefinition<&str, u64> = TableDefinition::new("audit_cache");

const DB_FILE: &str = "parry.redb";

/// Per-repo scanning state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RepoState {
    Unknown = 0,
    Monitored = 1,
    Ignored = 2,
}

impl RepoState {
    const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Monitored,
            2 => Self::Ignored,
            _ => Self::Unknown,
        }
    }

    /// Display name for CLI output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Monitored => "monitored",
            Self::Ignored => "ignored",
        }
    }
}

/// Encoded repo state value: `[state_byte][remote_url_bytes]`.
fn encode_state(state: RepoState, remote: Option<&str>) -> Vec<u8> {
    let mut buf = vec![state as u8];
    if let Some(url) = remote {
        buf.extend_from_slice(url.as_bytes());
    }
    buf
}

/// Decode repo state value.
fn decode_state(bytes: &[u8]) -> (RepoState, Option<String>) {
    if bytes.is_empty() {
        return (RepoState::Unknown, None);
    }
    let state = RepoState::from_u8(bytes[0]);
    let remote = if bytes.len() > 1 {
        String::from_utf8(bytes[1..].to_vec()).ok()
    } else {
        None
    };
    (state, remote)
}

/// Centralized repository state database.
pub struct RepoDb {
    db: redb::Database,
}

/// Entry returned by `list_repos`.
pub struct RepoEntry {
    pub path: String,
    pub state: RepoState,
    pub remote: Option<String>,
}

/// Errors from `RepoDb` operations.
#[derive(Debug, thiserror::Error)]
pub enum RepoDbError {
    #[error("cannot determine home directory")]
    NoHomeDir,
    #[error("io error: {0}")]
    Io(String),
    #[error("database error: {0}")]
    Db(String),
}

impl RepoDb {
    /// Open (or create) the centralized database.
    ///
    /// Uses `runtime_dir` if provided, otherwise `~/.parry/`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or created.
    pub fn open(runtime_dir: Option<&Path>) -> Result<Self, RepoDbError> {
        let dir = if let Some(d) = runtime_dir {
            d.to_path_buf()
        } else {
            dirs::home_dir()
                .ok_or(RepoDbError::NoHomeDir)?
                .join(".parry")
        };
        std::fs::create_dir_all(&dir).map_err(|e| RepoDbError::Io(e.to_string()))?;
        let path = dir.join(DB_FILE);
        match redb::Database::create(&path) {
            Ok(db) => Ok(Self { db }),
            Err(redb::DatabaseError::UpgradeRequired(_)) => {
                warn!("repo db version mismatch, recreating");
                let _ = std::fs::remove_file(&path);
                redb::Database::create(&path)
                    .map(|db| Self { db })
                    .map_err(|e| RepoDbError::Db(e.to_string()))
            }
            Err(e) => Err(RepoDbError::Db(e.to_string())),
        }
    }

    /// Get the state and remote URL for a repo path.
    #[must_use]
    pub fn get_repo_state(&self, repo_path: &str) -> (RepoState, Option<String>) {
        let Ok(txn) = self.db.begin_read() else {
            return (RepoState::Unknown, None);
        };
        let Ok(table) = txn.open_table(REPO_STATE_TABLE) else {
            return (RepoState::Unknown, None);
        };
        table
            .get(repo_path)
            .ok()
            .flatten()
            .map_or((RepoState::Unknown, None), |v| decode_state(v.value()))
    }

    /// Set the state and optional remote URL for a repo path.
    pub fn set_repo_state(&self, repo_path: &str, state: RepoState, remote: Option<&str>) {
        let Ok(txn) = self.db.begin_write() else {
            return;
        };
        if let Ok(mut table) = txn.open_table(REPO_STATE_TABLE) {
            let encoded = encode_state(state, remote);
            let _ = table.insert(repo_path, encoded.as_slice());
        }
        let _ = txn.commit();
    }

    /// List all known repos and their states.
    #[must_use]
    pub fn list_repos(&self) -> Vec<RepoEntry> {
        let Ok(txn) = self.db.begin_read() else {
            return Vec::new();
        };
        let Ok(table) = txn.open_table(REPO_STATE_TABLE) else {
            return Vec::new();
        };
        let mut entries = Vec::new();
        if let Ok(iter) = table.iter() {
            for item in iter {
                let Ok(item) = item else { continue };
                let path = item.0.value().to_string();
                let (state, remote) = decode_state(item.1.value());
                entries.push(RepoEntry {
                    path,
                    state,
                    remote,
                });
            }
        }
        entries
    }

    /// Reset a repo to unknown state and clear its guard/audit caches.
    pub fn reset_repo(&self, repo_path: &str) {
        let Ok(txn) = self.db.begin_write() else {
            return;
        };
        if let Ok(mut table) = txn.open_table(REPO_STATE_TABLE) {
            let _ = table.remove(repo_path);
        }
        if let Ok(mut table) = txn.open_table(GUARD_CACHE_TABLE) {
            let prefix = format!("{repo_path}\0");
            let keys_to_remove: Vec<String> = table
                .iter()
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|item| {
                    let key = item.0.value().to_string();
                    key.starts_with(&prefix).then_some(key)
                })
                .collect();
            for key in &keys_to_remove {
                let _ = table.remove(key.as_str());
            }
        }
        if let Ok(mut table) = txn.open_table(AUDIT_CACHE_TABLE) {
            let _ = table.remove(repo_path);
        }
        let _ = txn.commit();
    }

    /// Build the composite guard cache key: `repo_path\0file_path`.
    fn guard_key(repo_path: &str, file_path: &str) -> String {
        format!("{repo_path}\0{file_path}")
    }

    /// Check if a CLAUDE.md file is cached with the given content hash.
    #[must_use]
    pub fn is_guard_cached(&self, repo_path: &str, file_path: &str, hash: u64) -> bool {
        let key = Self::guard_key(repo_path, file_path);
        let Ok(txn) = self.db.begin_read() else {
            return false;
        };
        let Ok(table) = txn.open_table(GUARD_CACHE_TABLE) else {
            return false;
        };
        table
            .get(key.as_str())
            .ok()
            .flatten()
            .is_some_and(|v| v.value() == hash)
    }

    /// Mark a CLAUDE.md file as clean with the given content hash.
    pub fn mark_guard_clean(&self, repo_path: &str, file_path: &str, hash: u64) {
        let key = Self::guard_key(repo_path, file_path);
        let Ok(txn) = self.db.begin_write() else {
            return;
        };
        if let Ok(mut table) = txn.open_table(GUARD_CACHE_TABLE) {
            let _ = table.insert(key.as_str(), hash);
        }
        let _ = txn.commit();
    }

    /// Check if a project audit is cached with the given state hash.
    #[must_use]
    pub fn is_audit_cached(&self, repo_path: &str, hash: u64) -> bool {
        let Ok(txn) = self.db.begin_read() else {
            return false;
        };
        let Ok(table) = txn.open_table(AUDIT_CACHE_TABLE) else {
            return false;
        };
        table
            .get(repo_path)
            .ok()
            .flatten()
            .is_some_and(|v| v.value() == hash)
    }

    /// Mark a project audit as clean with the given state hash.
    pub fn mark_audit_clean(&self, repo_path: &str, hash: u64) {
        let Ok(txn) = self.db.begin_write() else {
            return;
        };
        if let Ok(mut table) = txn.open_table(AUDIT_CACHE_TABLE) {
            let _ = table.insert(repo_path, hash);
        }
        let _ = txn.commit();
    }

    /// Remove obsolete per-project `.parry-guard.redb` if it exists.
    pub fn cleanup_old_db(repo_path: &Path) {
        let old_path = repo_path.join(".parry-guard.redb");
        if !old_path.exists() {
            return;
        }

        if let Err(e) = std::fs::remove_file(&old_path) {
            warn!(path = %old_path.display(), %e, "failed to delete old guard db");
        } else {
            debug!(path = %old_path.display(), "deleted obsolete per-project guard db");
        }
    }
}

/// Canonicalize a repo path. If `path` is None, uses CWD.
/// Returns None if canonicalization fails.
#[must_use]
pub fn canonicalize_repo_path(path: Option<&Path>) -> Option<String> {
    let target = if let Some(p) = path {
        p.to_path_buf()
    } else {
        std::env::current_dir().ok()?
    };
    std::fs::canonicalize(target)
        .ok()
        .and_then(|p| p.to_str().map(String::from))
}

/// Best-effort git remote URL for display purposes.
#[must_use]
pub fn git_remote_url(path: &Path) -> Option<String> {
    std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(path)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_state_no_remote() {
        let encoded = encode_state(RepoState::Monitored, None);
        let (state, remote) = decode_state(&encoded);
        assert_eq!(state, RepoState::Monitored);
        assert!(remote.is_none());
    }

    #[test]
    fn roundtrip_state_with_remote() {
        let encoded = encode_state(RepoState::Ignored, Some("github.com/user/repo"));
        let (state, remote) = decode_state(&encoded);
        assert_eq!(state, RepoState::Ignored);
        assert_eq!(remote.as_deref(), Some("github.com/user/repo"));
    }

    #[test]
    fn unknown_from_empty() {
        let (state, remote) = decode_state(&[]);
        assert_eq!(state, RepoState::Unknown);
        assert!(remote.is_none());
    }

    #[test]
    fn unknown_from_invalid_byte() {
        let (state, _) = decode_state(&[255]);
        assert_eq!(state, RepoState::Unknown);
    }

    #[test]
    fn state_display_names() {
        assert_eq!(RepoState::Unknown.as_str(), "unknown");
        assert_eq!(RepoState::Monitored.as_str(), "monitored");
        assert_eq!(RepoState::Ignored.as_str(), "ignored");
    }

    #[test]
    fn open_and_get_unknown_repo() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        let (state, _) = db.get_repo_state("/some/path");
        assert_eq!(state, RepoState::Unknown);
    }

    #[test]
    fn set_and_get_repo_state() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        db.set_repo_state(
            "/my/repo",
            RepoState::Monitored,
            Some("github.com/user/repo"),
        );
        let (state, remote) = db.get_repo_state("/my/repo");
        assert_eq!(state, RepoState::Monitored);
        assert_eq!(remote.as_deref(), Some("github.com/user/repo"));
    }

    #[test]
    fn list_repos_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        let repos = db.list_repos();
        assert!(repos.is_empty());
    }

    #[test]
    fn list_repos_returns_all() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        db.set_repo_state("/a", RepoState::Monitored, None);
        db.set_repo_state("/b", RepoState::Ignored, Some("origin"));
        let repos = db.list_repos();
        assert_eq!(repos.len(), 2);
    }

    #[test]
    fn reset_repo_clears_state() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        db.set_repo_state("/my/repo", RepoState::Ignored, None);
        db.reset_repo("/my/repo");
        let (state, _) = db.get_repo_state("/my/repo");
        assert_eq!(state, RepoState::Unknown);
    }

    #[test]
    fn guard_cache_miss_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        assert!(!db.is_guard_cached("/repo", "/repo/CLAUDE.md", 12345));
    }

    #[test]
    fn guard_cache_hit() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        db.mark_guard_clean("/repo", "/repo/CLAUDE.md", 12345);
        assert!(db.is_guard_cached("/repo", "/repo/CLAUDE.md", 12345));
    }

    #[test]
    fn guard_cache_different_hash_is_miss() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        db.mark_guard_clean("/repo", "/repo/CLAUDE.md", 12345);
        assert!(!db.is_guard_cached("/repo", "/repo/CLAUDE.md", 99999));
    }

    #[test]
    fn audit_cache_miss_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        assert!(!db.is_audit_cached("/repo", 12345));
    }

    #[test]
    fn audit_cache_hit() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        db.mark_audit_clean("/repo", 12345);
        assert!(db.is_audit_cached("/repo", 12345));
    }

    #[test]
    fn reset_clears_guard_and_audit_caches() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        db.mark_guard_clean("/repo", "/repo/CLAUDE.md", 111);
        db.mark_guard_clean("/repo", "/repo/.claude/CLAUDE.md", 222);
        db.mark_audit_clean("/repo", 333);
        db.set_repo_state("/repo", RepoState::Monitored, None);

        db.reset_repo("/repo");

        assert!(!db.is_guard_cached("/repo", "/repo/CLAUDE.md", 111));
        assert!(!db.is_guard_cached("/repo", "/repo/.claude/CLAUDE.md", 222));
        assert!(!db.is_audit_cached("/repo", 333));
        let (state, _) = db.get_repo_state("/repo");
        assert_eq!(state, RepoState::Unknown);
    }

    #[test]
    fn canonicalize_repo_path_resolves_existing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = canonicalize_repo_path(Some(dir.path()));
        assert!(result.is_some());
    }

    #[test]
    fn canonicalize_repo_path_none_uses_cwd() {
        let result = canonicalize_repo_path(None);
        assert!(result.is_some());
    }

    #[test]
    fn ignore_then_status_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        db.set_repo_state("/my/repo", RepoState::Ignored, Some("github.com/user/repo"));
        let (state, remote) = db.get_repo_state("/my/repo");
        assert_eq!(state, RepoState::Ignored);
        assert_eq!(remote.as_deref(), Some("github.com/user/repo"));
    }

    #[test]
    fn monitor_then_list_repos() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        db.set_repo_state("/a", RepoState::Monitored, None);
        db.set_repo_state("/b", RepoState::Ignored, Some("origin"));
        let repos = db.list_repos();
        assert_eq!(repos.len(), 2);
        assert!(repos
            .iter()
            .any(|r| r.path == "/a" && r.state == RepoState::Monitored));
        assert!(repos
            .iter()
            .any(|r| r.path == "/b" && r.state == RepoState::Ignored));
    }

    #[test]
    fn reset_then_verify_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let db = RepoDb::open(Some(dir.path())).unwrap();
        db.set_repo_state("/my/repo", RepoState::Ignored, None);
        db.reset_repo("/my/repo");
        let (state, _) = db.get_repo_state("/my/repo");
        assert_eq!(state, RepoState::Unknown);
        let repos = db.list_repos();
        assert!(repos.is_empty(), "reset should remove from list");
    }

    #[test]
    fn cleanup_old_db_deletes_file() {
        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join(".parry-guard.redb");
        std::fs::write(&old_path, b"dummy").unwrap();
        assert!(old_path.exists());

        RepoDb::cleanup_old_db(dir.path());

        assert!(!old_path.exists());
    }

    #[test]
    fn cleanup_old_db_noop_if_missing() {
        let dir = tempfile::tempdir().unwrap();
        RepoDb::cleanup_old_db(dir.path());
    }
}
