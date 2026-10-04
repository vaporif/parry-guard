//! Protected path definitions and CWD exclusion logic.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::commands::{CompiledDestructive, CONFIG};

#[expect(clippy::expect_used, reason = "literal pattern, exercised by tests")]
static WSL_DRIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/mnt/[a-z]/").expect("valid regex"));

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

const WSL_SYSTEM_SUFFIXES: &[&str] = &[
    "Windows/",
    "Program Files/",
    "Program Files (x86)/",
    "ProgramData/",
];

const WSL_USER_SUFFIXES: &[&str] = &["AppData/", "Desktop/", "Documents/", "Downloads/"];

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

/// Lexical only: following symlinks would add macOS `/private` prefixes.
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

/// Resolves `.` and `..` without touching the filesystem.
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
            other @ (std::path::Component::Prefix(_)
            | std::path::Component::RootDir
            | std::path::Component::Normal(_)) => components.push(other),
        }
    }
    components.iter().collect()
}

fn ensure_trailing_slash(s: &str) -> String {
    if s.ends_with('/') {
        s.to_string()
    } else {
        format!("{s}/")
    }
}

fn is_under_cwd(resolved: &Path, cwd: &Path) -> bool {
    resolved.starts_with(cwd)
}

/// Check if a resolved path matches any protected prefix, honoring user config overrides.
fn matches_protected_prefix(resolved_str: &str, config: &CompiledDestructive) -> Option<String> {
    let resolved_with_slash = ensure_trailing_slash(resolved_str);

    let builtin = MACOS_SYSTEM
        .iter()
        .chain(LINUX_SYSTEM)
        .chain(NIX_SYSTEM)
        .chain(MACOS_USER)
        .chain(LINUX_USER)
        .chain(CROSS_PLATFORM_CONFIG)
        .chain(CROSS_PLATFORM_TOOLCHAINS)
        .chain(NIX_USER)
        .copied();

    config
        .extra_paths
        .iter()
        .map(String::as_str)
        .chain(builtin)
        .filter(|prefix| !config.is_removed_path(prefix))
        .find(|prefix| resolved_with_slash.starts_with(&expand_tilde(prefix)))
        .map(str::to_string)
        .or_else(|| matches_wsl_prefix(&resolved_with_slash))
}

fn matches_wsl_prefix(resolved_with_slash: &str) -> Option<String> {
    let after_drive = resolved_with_slash.get(WSL_DRIVE.find(resolved_with_slash)?.end()..)?;
    if after_drive.is_empty() {
        return Some("WSL drive root".to_string());
    }

    let after_username = after_drive
        .strip_prefix("Users/")
        .and_then(|users| users.split_once('/'))
        .map_or("", |(_, rest)| rest);

    WSL_SYSTEM_SUFFIXES
        .iter()
        .find(|suffix| after_drive.starts_with(**suffix))
        .or_else(|| {
            WSL_USER_SUFFIXES
                .iter()
                .find(|suffix| after_username.starts_with(**suffix))
        })
        .map(|suffix| (*suffix).to_string())
}

/// Reason if `path` is protected; CWD and its subdirectories are exempt.
#[must_use]
pub(crate) fn check_protected(path: &str, cwd: &str) -> Option<String> {
    let resolved = resolve_path(path, cwd);
    let cwd_path = lexical_normalize(Path::new(cwd));

    if is_under_cwd(&resolved, &cwd_path) {
        return None;
    }

    let resolved_str = resolved.to_string_lossy();

    if let Some(prefix) = matches_protected_prefix(&resolved_str, &CONFIG) {
        return Some(format!(
            "targets protected path '{prefix}' (resolved: {resolved_str})"
        ));
    }

    None
}

/// True only for CWD itself, not its subdirectories.
#[must_use]
pub(crate) fn is_cwd_itself(path: &str, cwd: &str) -> bool {
    let resolved = resolve_path(path, cwd);
    let cwd_path = lexical_normalize(Path::new(cwd));
    resolved == cwd_path
}

#[must_use]
pub(crate) fn is_outside_cwd(path: &str, cwd: &str) -> bool {
    let resolved = resolve_path(path, cwd);
    let cwd_path = lexical_normalize(Path::new(cwd));
    !is_under_cwd(&resolved, &cwd_path)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::commands::{DestructiveConfig, ListOverrides};

    fn config_with_paths(add: &[&str], remove: &[&str]) -> CompiledDestructive {
        let to_vec = |items: &[&str]| items.iter().map(ToString::to_string).collect();
        CompiledDestructive::from_config(DestructiveConfig {
            destructive_paths: ListOverrides {
                add: to_vec(add),
                remove: to_vec(remove),
            },
            destructive_commands: ListOverrides::default(),
        })
    }

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

    #[rstest]
    #[case::tmp("/tmp/scratch")]
    #[case::home_project("~/projects/app")]
    #[case::wsl_users_dir("/mnt/c/Users/bob")]
    #[case::wsl_other_dir("/mnt/c/code/app")]
    fn unprotected_paths_pass(#[case] path: &str) {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        assert_eq!(check_protected(path, cwd), None);
    }

    #[rstest]
    #[case::wsl_drive_root("/mnt/c", "WSL drive root")]
    #[case::wsl_drive_root_slash("/mnt/c/", "WSL drive root")]
    #[case::wsl_windows_dir("/mnt/c/Windows", "Windows/")]
    #[case::wsl_windows_file("/mnt/c/Windows/System32/x.dll", "Windows/")]
    #[case::wsl_user_desktop("/mnt/c/Users/bob/Desktop", "Desktop/")]
    #[case::wsl_user_appdata("/mnt/d/Users/bob/AppData/Roaming/x", "AppData/")]
    #[case::etc("/etc/hosts", "/etc/")]
    #[case::etc_dir_itself("/etc", "/etc/")]
    fn protected_reason_names_prefix(#[case] path: &str, #[case] prefix: &str) {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let reason = check_protected(path, cwd).unwrap();
        assert!(reason.contains(&format!("'{prefix}'")), "{reason}");
    }

    #[test]
    fn extra_path_protected() {
        let config = config_with_paths(&["/data/shared/"], &[]);
        assert_eq!(
            matches_protected_prefix("/data/shared/db", &config),
            Some("/data/shared/".into())
        );
        assert_eq!(matches_protected_prefix("/data/other", &config), None);
    }

    #[test]
    fn removed_path_overrides_extra_path() {
        let config = config_with_paths(&["/data/shared/"], &["/data/shared/"]);
        assert_eq!(matches_protected_prefix("/data/shared/db", &config), None);
    }

    #[test]
    fn removed_path_overrides_builtin_prefix() {
        let config = config_with_paths(&[], &["/nix/"]);
        assert_eq!(matches_protected_prefix("/nix/store/x", &config), None);
        assert_eq!(
            matches_protected_prefix("/etc/hosts", &config),
            Some("/etc/".into())
        );
    }

    #[test]
    fn removed_home_prefix_overrides_builtin() {
        let config = config_with_paths(&[], &["~/.cargo/"]);
        let cargo = expand_tilde("~/.cargo/bin/rg");
        assert_eq!(matches_protected_prefix(&cargo, &config), None);
        let default = config_with_paths(&[], &[]);
        assert_eq!(
            matches_protected_prefix(&cargo, &default),
            Some("~/.cargo/".into())
        );
    }
}
