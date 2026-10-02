//! Configuration for destructive operation overrides.
//!
//! Loads from `~/.config/parry/patterns.toml` (same file as exfil patterns).

use std::sync::LazyLock;

use serde::Deserialize;
use tracing::warn;

/// User-configurable overrides for destructive detection.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
pub struct DestructiveConfig {
    #[serde(default)]
    pub destructive_paths: ListOverrides,
    #[serde(default)]
    pub destructive_commands: ListOverrides,
}

/// Add/remove overrides for a list.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
pub struct ListOverrides {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

impl DestructiveConfig {
    /// Load configuration from the default path.
    #[must_use]
    pub fn load() -> Self {
        Self::load_from_path(Self::default_path())
    }

    fn default_path() -> Option<std::path::PathBuf> {
        dirs::config_dir().map(|p| p.join("parry-guard").join("patterns.toml"))
    }

    fn load_from_path(path: Option<std::path::PathBuf>) -> Self {
        let Some(path) = path else {
            return Self::default();
        };
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => toml::from_str(&content).unwrap_or_else(|e| {
                warn!(path = %path.display(), %e, "failed to parse destructive config");
                Self::default()
            }),
            Err(e) => {
                warn!(path = %path.display(), %e, "failed to read destructive config");
                Self::default()
            }
        }
    }
}

/// Runtime-compiled destructive detection config with user overrides applied.
pub struct CompiledDestructive {
    /// Additional protected paths from user config.
    pub extra_paths: Vec<String>,
    /// Protected paths removed by user config.
    pub removed_paths: Vec<String>,
    /// Additional commands to flag as destructive.
    pub extra_commands: Vec<String>,
    /// Commands removed from destructive detection.
    pub removed_commands: Vec<String>,
}

impl CompiledDestructive {
    /// Load from default config path.
    #[must_use]
    pub fn load() -> Self {
        Self::from_config(DestructiveConfig::load())
    }

    /// Create from explicit config (useful for testing).
    #[must_use]
    pub fn from_config(config: DestructiveConfig) -> Self {
        Self {
            extra_paths: config.destructive_paths.add,
            removed_paths: config.destructive_paths.remove,
            extra_commands: config.destructive_commands.add,
            removed_commands: config.destructive_commands.remove,
        }
    }

    /// Check if a command has been removed from detection by user config.
    #[must_use]
    pub fn is_removed_command(&self, cmd: &str) -> bool {
        self.removed_commands.iter().any(|r| r == cmd)
    }

    /// Check if a command was added to destructive detection by user config.
    #[must_use]
    pub fn is_extra_command(&self, cmd: &str) -> bool {
        self.extra_commands.iter().any(|c| c == cmd)
    }

    /// Check if a protected path prefix has been removed by user config.
    #[must_use]
    pub fn is_removed_path(&self, path: &str) -> bool {
        self.removed_paths.iter().any(|r| r == path)
    }
}

/// Global compiled config (loaded once).
pub static CONFIG: LazyLock<CompiledDestructive> = LazyLock::new(CompiledDestructive::load);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_empty_overrides() {
        let compiled = CompiledDestructive::from_config(DestructiveConfig::default());
        assert_eq!(compiled.extra_paths, Vec::<String>::new());
        assert_eq!(compiled.removed_paths, Vec::<String>::new());
        assert_eq!(compiled.extra_commands, Vec::<String>::new());
        assert_eq!(compiled.removed_commands, Vec::<String>::new());
    }

    #[test]
    fn config_add_remove() {
        let config = DestructiveConfig {
            destructive_paths: ListOverrides {
                add: vec!["/my/protected".into()],
                remove: vec!["~/.cargo/".into()],
            },
            destructive_commands: ListOverrides {
                add: vec!["custom-destroy".into()],
                remove: vec!["kill".into()],
            },
        };
        let compiled = CompiledDestructive::from_config(config);
        assert_eq!(compiled.extra_paths, vec!["/my/protected"]);
        assert_eq!(compiled.removed_paths, vec!["~/.cargo/"]);
        assert!(compiled.is_removed_command("kill"));
        assert!(!compiled.is_removed_command("rm"));
        assert!(compiled.is_extra_command("custom-destroy"));
        assert!(!compiled.is_extra_command("kill"));
        assert!(compiled.is_removed_path("~/.cargo/"));
        assert!(!compiled.is_removed_path("/my/protected"));
    }

    #[test]
    fn default_path_points_at_patterns_toml() {
        let path = DestructiveConfig::default_path().unwrap();
        assert!(path.ends_with("parry-guard/patterns.toml"), "{path:?}");
    }

    #[test]
    fn load_from_path_parses_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("patterns.toml");
        std::fs::write(
            &path,
            "[destructive_paths]\nadd = [\"/srv/data/\"]\n\n[destructive_commands]\nremove = [\"kill\"]\n",
        )
        .unwrap();

        let config = DestructiveConfig::load_from_path(Some(path));

        assert_eq!(config.destructive_paths.add, vec!["/srv/data/"]);
        assert_eq!(config.destructive_commands.remove, vec!["kill"]);
    }

    #[test]
    fn load_from_path_falls_back_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let invalid = dir.path().join("invalid.toml");
        std::fs::write(&invalid, "not = [valid").unwrap();

        for path in [None, Some(dir.path().join("missing.toml")), Some(invalid)] {
            assert_eq!(
                DestructiveConfig::load_from_path(path),
                DestructiveConfig::default()
            );
        }
    }
}
