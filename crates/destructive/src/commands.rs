//! Configuration for destructive operation overrides.
//!
//! Loads from `~/.config/parry/patterns.toml` (same file as exfil patterns).

use std::sync::LazyLock;

use serde::Deserialize;
use tracing::warn;

/// User-configurable overrides for destructive detection.
#[derive(Debug, Default, Deserialize)]
pub struct DestructiveConfig {
    #[serde(default)]
    pub destructive_paths: ListOverrides,
    #[serde(default)]
    pub destructive_commands: ListOverrides,
}

/// Add/remove overrides for a list.
#[derive(Debug, Default, Deserialize)]
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
        dirs::home_dir().map(|p| p.join(".config").join("parry").join("patterns.toml"))
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
        let config = DestructiveConfig::load();
        Self::from_config(&config)
    }

    /// Create from explicit config (useful for testing).
    #[must_use]
    pub fn from_config(config: &DestructiveConfig) -> Self {
        Self {
            extra_paths: config.destructive_paths.add.clone(),
            removed_paths: config.destructive_paths.remove.clone(),
            extra_commands: config.destructive_commands.add.clone(),
            removed_commands: config.destructive_commands.remove.clone(),
        }
    }

    /// Check if a command has been removed from detection by user config.
    #[must_use]
    pub fn is_removed_command(&self, cmd: &str) -> bool {
        self.removed_commands.iter().any(|r| r == cmd)
    }
}

/// Global compiled config (loaded once).
pub static CONFIG: LazyLock<CompiledDestructive> = LazyLock::new(CompiledDestructive::load);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_empty_overrides() {
        let config = DestructiveConfig::default();
        let compiled = CompiledDestructive::from_config(&config);
        assert!(compiled.extra_paths.is_empty());
        assert!(compiled.removed_paths.is_empty());
        assert!(compiled.extra_commands.is_empty());
        assert!(compiled.removed_commands.is_empty());
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
        let compiled = CompiledDestructive::from_config(&config);
        assert_eq!(compiled.extra_paths, vec!["/my/protected"]);
        assert_eq!(compiled.removed_paths, vec!["~/.cargo/"]);
        assert!(compiled.is_removed_command("kill"));
        assert!(!compiled.is_removed_command("rm"));
    }
}
