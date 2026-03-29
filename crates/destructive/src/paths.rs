//! Protected path definitions and CWD exclusion logic.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

/// WSL drive letter pattern: /mnt/[a-z]/
static WSL_DRIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/mnt/[a-z]/").expect("valid regex"));

// === macOS protected paths ===

const MACOS_SYSTEM: &[&str] = &[
    "/System/",
    "/Library/",
    "/usr/local/",
    "/etc/",
    "/var/",
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/Applications/",
];

const MACOS_USER: &[&str] = &[
    "~/Library/",
    "~/Desktop/",
    "~/Documents/",
    "~/Downloads/",
    "~/.Trash/",
];

// === Linux protected paths ===

const LINUX_SYSTEM: &[&str] = &[
    "/etc/", "/var/", "/usr/", "/bin/", "/sbin/", "/opt/", "/boot/", "/lib/", "/lib64/", "/srv/",
];

const LINUX_USER: &[&str] = &[
    "~/Desktop/",
    "~/Documents/",
    "~/Downloads/",
    "~/.local/share/",
    "~/.local/bin/",
];

// === WSL Windows protected paths ===

const WSL_SYSTEM_SUFFIXES: &[&str] = &[
    "Windows/",
    "Program Files/",
    "Program Files (x86)/",
    "ProgramData/",
];

const WSL_USER_SUFFIXES: &[&str] = &["AppData/", "Desktop/", "Documents/", "Downloads/"];

// === Cross-platform protected paths ===

const CROSS_PLATFORM_CONFIG: &[&str] = &["~/.config/", "~/.local/"];

const CROSS_PLATFORM_TOOLCHAINS: &[&str] = &[
    "~/.cargo/",
    "~/.rustup/",
    "~/.npm/",
    "~/.bun/",
    "~/go/",
    "~/.pyenv/",
    "~/.conda/",
    "~/.virtualenvs/",
];

const NIX_SYSTEM: &[&str] = &["/nix/"];
const NIX_USER: &[&str] = &["~/.nix-profile/", "~/.nix-defexpr/"];

/// Expand `~` prefix to actual home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}/{rest}", home.display());
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home.display().to_string();
        }
    }
    path.to_string()
}

/// Resolve a potentially relative path against CWD using lexical normalization.
/// Does NOT follow symlinks -avoids macOS `/private` prefix issues.
fn resolve_path(path: &str, cwd: &str) -> PathBuf {
    let expanded = expand_tilde(path);
    let p = Path::new(&expanded);

    if p.is_absolute() {
        lexical_normalize(p)
    } else {
        let joined = Path::new(cwd).join(p);
        lexical_normalize(&joined)
    }
}

/// Lexical normalization: resolve `.` and `..` without touching the filesystem.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                if !components.is_empty() {
                    components.pop();
                }
            }
            std::path::Component::CurDir => {}
            other => components.push(other),
        }
    }
    components.iter().collect()
}

/// Ensure path string ends with `/` for prefix matching.
fn ensure_trailing_slash(s: &str) -> String {
    if s.ends_with('/') {
        s.to_string()
    } else {
        format!("{s}/")
    }
}

/// Check if a path is under CWD (CWD itself or any subdirectory).
fn is_under_cwd(resolved: &Path, cwd: &Path) -> bool {
    resolved.starts_with(cwd)
}

/// Check if a resolved path matches any protected prefix (including user-configured extras).
fn matches_protected_prefix(resolved_str: &str) -> Option<String> {
    let resolved_with_slash = ensure_trailing_slash(resolved_str);

    let config = &crate::commands::CONFIG;
    for extra in &config.extra_paths {
        let expanded = expand_tilde(extra);
        if resolved_with_slash.starts_with(&expanded)
            && !config.removed_paths.iter().any(|r| r == extra)
        {
            return Some(extra.clone());
        }
    }

    for &prefix in MACOS_SYSTEM.iter().chain(LINUX_SYSTEM).chain(NIX_SYSTEM) {
        if !prefix.starts_with('~') && resolved_with_slash.starts_with(prefix) {
            return Some(prefix.to_string());
        }
    }

    // home-relative (need tilde expansion)
    let home_prefixes = MACOS_USER
        .iter()
        .chain(LINUX_USER)
        .chain(CROSS_PLATFORM_CONFIG)
        .chain(CROSS_PLATFORM_TOOLCHAINS)
        .chain(NIX_USER);

    for &prefix in home_prefixes {
        let expanded = expand_tilde(prefix);
        if resolved_with_slash.starts_with(&expanded) {
            return Some(prefix.to_string());
        }
    }

    // WSL
    if WSL_DRIVE.is_match(resolved_str) {
        let after_drive = &resolved_str[7..];

        for &suffix in WSL_SYSTEM_SUFFIXES {
            if after_drive.starts_with(suffix) {
                return Some(suffix.to_string());
            }
        }

        // /mnt/c/Users/*/...
        if let Some(after_users) = after_drive.strip_prefix("Users/") {
            if let Some(slash_pos) = after_users.find('/') {
                let after_username = &after_users[slash_pos + 1..];
                for &suffix in WSL_USER_SUFFIXES {
                    if after_username.starts_with(suffix) {
                        return Some(suffix.to_string());
                    }
                }
            }
        }

        // drive root itself
        if after_drive.is_empty() || after_drive == "/" {
            return Some("WSL drive root".to_string());
        }
    }

    None
}

/// Check if a file path targets a protected location.
///
/// Returns `Some(reason)` if the path is protected and not under CWD.
/// CWD and its subdirectories are excluded from protection.
#[must_use]
pub fn check_protected(path: &str, cwd: &str) -> Option<String> {
    let resolved = resolve_path(path, cwd);
    let cwd_path = lexical_normalize(Path::new(cwd));

    if is_under_cwd(&resolved, &cwd_path) {
        return None;
    }

    let resolved_str = resolved.to_string_lossy();

    if let Some(prefix) = matches_protected_prefix(&resolved_str) {
        return Some(format!(
            "targets protected path '{prefix}' (resolved: {resolved_str})"
        ));
    }

    None
}

/// Check if a path resolves to CWD itself (not a subdirectory).
#[must_use]
pub fn is_cwd_itself(path: &str, cwd: &str) -> bool {
    let resolved = resolve_path(path, cwd);
    let cwd_path = lexical_normalize(Path::new(cwd));
    resolved == cwd_path
}

/// Check if a path resolves to somewhere outside CWD.
#[must_use]
pub fn is_outside_cwd(path: &str, cwd: &str) -> bool {
    let resolved = resolve_path(path, cwd);
    let cwd_path = lexical_normalize(Path::new(cwd));
    !is_under_cwd(&resolved, &cwd_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expansion() {
        let expanded = expand_tilde("~/Documents/file.txt");
        assert!(!expanded.starts_with('~'), "tilde should be expanded");
        assert!(expanded.ends_with("Documents/file.txt"));
    }

    #[test]
    fn tilde_only() {
        let expanded = expand_tilde("~");
        assert!(!expanded.starts_with('~'));
    }

    #[test]
    fn no_tilde() {
        assert_eq!(expand_tilde("/etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn resolve_relative_path() {
        let cwd = std::env::temp_dir();
        let cwd_str = cwd.to_str().unwrap();
        let resolved = resolve_path("subdir/file.txt", cwd_str);
        assert!(resolved.starts_with(&cwd));
    }

    #[test]
    fn resolve_absolute_path() {
        let resolved = resolve_path("/etc/passwd", "/tmp");
        assert!(resolved.to_string_lossy().contains("etc"));
    }

    #[test]
    fn resolve_parent_traversal() {
        let resolved = resolve_path("../../etc/passwd", "/home/user/project");
        let s = resolved.to_string_lossy();
        assert!(
            s.contains("etc/passwd"),
            "should resolve to /etc/passwd: {s}"
        );
    }

    #[test]
    fn cwd_subdir_not_protected() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        assert!(check_protected("./src/main.rs", cwd).is_none());
    }

    #[test]
    fn etc_is_protected() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let result = check_protected("/etc/passwd", cwd);
        assert!(result.is_some(), "/etc/passwd should be protected");
    }

    #[test]
    fn system_root_protected() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        assert!(check_protected("/usr/bin/something", cwd).is_some());
    }

    #[test]
    fn home_config_protected() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let result = check_protected("~/.config/some-app/config.toml", cwd);
        assert!(result.is_some(), "~/.config should be protected");
    }

    #[test]
    fn nix_store_protected() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        assert!(check_protected("/nix/store/something", cwd).is_some());
    }

    #[test]
    fn outside_cwd_detection() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        assert!(is_outside_cwd("/tmp/other", cwd));
        assert!(!is_outside_cwd("./subdir", cwd));
    }

    #[test]
    fn cwd_itself_not_outside() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        assert!(!is_outside_cwd(".", cwd));
    }

    #[test]
    fn cwd_itself_detected() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        assert!(is_cwd_itself(".", cwd));
        assert!(is_cwd_itself("./", cwd));
        assert!(!is_cwd_itself("./subdir", cwd));
    }

    #[test]
    fn lexical_normalize_resolves_dotdot() {
        let p = Path::new("/home/user/project/../../etc/passwd");
        let normalized = lexical_normalize(p);
        assert_eq!(normalized, PathBuf::from("/home/etc/passwd"));
    }
}
