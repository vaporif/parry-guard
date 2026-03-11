//! Runtime configuration for parry scanning.

use std::path::PathBuf;

use serde::Deserialize;

const DEFAULT_MODEL: &str = "ProtectAI/deberta-v3-small-prompt-injection-v2";
const FULL_MODELS: &[&str] = &[DEFAULT_MODEL, "meta-llama/Llama-Prompt-Guard-2-86M"];

/// Scan mode controlling which ML models are used.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ScanMode {
    /// Single model (default `DeBERTa` v3).
    #[default]
    Fast,
    /// Two-model ensemble (`DeBERTa` + Llama Prompt Guard).
    Full,
    /// User-defined model list from `~/.config/parry/models.toml`.
    Custom,
}

impl ScanMode {
    /// String representation for CLI argument forwarding.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Full => "full",
            Self::Custom => "custom",
        }
    }
}

/// A single model definition for ML scanning.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelDef {
    /// `HuggingFace` repo ID (e.g. `"ProtectAI/deberta-v3-small-prompt-injection-v2"`).
    pub repo: String,
    /// Optional per-model threshold; falls back to global `Config::threshold`.
    pub threshold: Option<f32>,
}

/// TOML configuration for custom models (`~/.config/parry/models.toml`).
#[derive(Debug, Deserialize)]
struct ModelsConfig {
    models: Vec<ModelDef>,
}

/// Default ML threshold for CLAUDE.md scanning (higher to reduce false positives).
const DEFAULT_CLAUDE_MD_THRESHOLD: f32 = 0.9;

/// Runtime configuration for parry scanning.
#[derive(Debug, Clone)]
pub struct Config {
    pub hf_token: Option<String>,
    pub threshold: f32,
    /// ML threshold for CLAUDE.md scanning (default 0.9).
    ///
    /// Higher than `threshold` because CLAUDE.md files are instructions
    /// by design and `DeBERTa` scores them higher than normal text.
    pub claude_md_threshold: f32,
    pub ignore_paths: Vec<String>,
    pub scan_mode: ScanMode,
    /// Explicit runtime directory for daemon IPC, caches, and taint files.
    /// `None` means use default paths (`~/.parry/` for daemon, cwd for hook files).
    /// Set in tests to avoid process-global env var mutation.
    pub runtime_dir: Option<PathBuf>,
}

impl Config {
    /// Check if the given path should be ignored (prefix match against `ignore_paths`).
    #[must_use]
    pub fn is_ignored(&self, path: &str) -> bool {
        self.ignore_paths
            .iter()
            .any(|ignored| path.starts_with(ignored))
    }

    /// Resolve the list of models to load based on `scan_mode`.
    ///
    /// # Errors
    ///
    /// Returns an error if `Custom` mode config is missing or has no models.
    pub fn resolve_models(&self) -> crate::Result<Vec<ModelDef>> {
        match self.scan_mode {
            ScanMode::Fast => Ok(vec![ModelDef {
                repo: DEFAULT_MODEL.to_string(),
                threshold: None,
            }]),
            ScanMode::Full => Ok(FULL_MODELS
                .iter()
                .map(|repo| ModelDef {
                    repo: repo.to_string(),
                    threshold: None,
                })
                .collect()),
            ScanMode::Custom => load_custom_models(),
        }
    }
}

fn custom_models_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|p| p.join(".config").join("parry").join("models.toml"))
}

fn load_custom_models() -> crate::Result<Vec<ModelDef>> {
    let path = custom_models_path()
        .ok_or_else(|| eyre::eyre!("cannot resolve config directory for models.toml"))?;

    let content = std::fs::read_to_string(&path)
        .map_err(|e| eyre::eyre!("failed to read {}: {e}", path.display()))?;

    let config: ModelsConfig = toml::from_str(&content)
        .map_err(|e| eyre::eyre!("failed to parse {}: {e}", path.display()))?;

    if config.models.is_empty() {
        return Err(eyre::eyre!(
            "models.toml must contain at least one [[models]] entry"
        ));
    }

    Ok(config.models)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hf_token: None,
            threshold: 0.7,
            claude_md_threshold: DEFAULT_CLAUDE_MD_THRESHOLD,
            ignore_paths: Vec::new(),
            scan_mode: ScanMode::default(),
            runtime_dir: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scan_mode_is_fast() {
        let config = Config::default();
        assert_eq!(config.scan_mode, ScanMode::Fast);
    }

    #[test]
    fn resolve_models_fast() {
        let config = Config::default();
        let models = config.resolve_models().unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].repo, DEFAULT_MODEL);
        assert!(models[0].threshold.is_none());
    }

    #[test]
    fn resolve_models_full() {
        let config = Config {
            scan_mode: ScanMode::Full,
            ..Config::default()
        };
        let models = config.resolve_models().unwrap();
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].repo, DEFAULT_MODEL);
        assert_eq!(models[1].repo, "meta-llama/Llama-Prompt-Guard-2-86M");
    }

    #[test]
    fn resolve_models_custom_missing() {
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HOME", dir.path()) };
        let config = Config {
            scan_mode: ScanMode::Custom,
            ..Config::default()
        };
        let result = config.resolve_models();
        unsafe { std::env::remove_var("HOME") };
        assert!(result.is_err());
    }

    #[test]
    fn default_claude_md_threshold() {
        let config = Config::default();
        assert!(
            config.claude_md_threshold > config.threshold,
            "CLAUDE.md threshold ({}) should be higher than default threshold ({})",
            config.claude_md_threshold,
            config.threshold,
        );
        assert!(
            (config.claude_md_threshold - 0.9).abs() < f32::EPSILON,
            "default CLAUDE.md threshold should be 0.9"
        );
    }

    #[test]
    fn is_ignored_prefix_match() {
        let config = Config {
            ignore_paths: vec!["/home/user/safe".to_string()],
            ..Config::default()
        };
        assert!(config.is_ignored("/home/user/safe/project"));
        assert!(!config.is_ignored("/home/user/other"));
    }
}
