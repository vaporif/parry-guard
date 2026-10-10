//! Runtime scan configuration.

use std::path::PathBuf;

use secrecy::SecretString;
use serde::Deserialize;

const DEFAULT_MODEL: &str = "ProtectAI/deberta-v3-small-prompt-injection-v2";
#[cfg(feature = "candle")]
const FULL_MODELS: &[&str] = &[DEFAULT_MODEL, "meta-llama/Llama-Prompt-Guard-2-86M"];

/// Which ML models to run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ScanMode {
    /// Single model (default `DeBERTa` v3).
    #[default]
    Fast,
    /// Two-model ensemble (`DeBERTa` + Llama Prompt Guard).
    Full,
    /// User-defined model list from `<config dir>/parry-guard/models.toml`.
    Custom,
}

impl ScanMode {
    /// Form used when forwarding as a CLI argument.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Full => "full",
            Self::Custom => "custom",
        }
    }
}

/// One ML model to load.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelDef {
    /// `HuggingFace` repo ID.
    pub repo: String,
    /// Overrides `Config::threshold` for this model.
    pub threshold: Option<f32>,
}

/// Contents of `<config dir>/parry-guard/models.toml`.
#[derive(Debug, Deserialize)]
struct ModelsConfig {
    models: Vec<ModelDef>,
}

const DEFAULT_CLAUDE_MD_THRESHOLD: f32 = 0.9;

// SecretString's Debug keeps `hf_token` out of tracing spans
#[derive(Clone, Debug)]
pub struct Config {
    pub hf_token: Option<SecretString>,
    /// Shell command printing the token; run lazily when `hf_token` is unset.
    pub hf_token_command: Option<String>,
    pub threshold: f32,
    /// Higher than `threshold`: CLAUDE.md is instructions by design, so `DeBERTa` scores it high.
    pub claude_md_threshold: f32,
    pub scan_mode: ScanMode,
    /// Dir for daemon IPC, caches, and taint files; `None` uses defaults.
    /// Tests set it to avoid mutating process-global env vars.
    pub runtime_dir: Option<PathBuf>,
}

impl Config {
    /// The token from `hf_token`, else from running `hf_token_command`.
    ///
    /// # Errors
    /// Fails if `hf_token_command` fails.
    pub fn resolve_hf_token(&self) -> crate::Result<Option<SecretString>> {
        if let Some(ref token) = self.hf_token {
            return Ok(Some(token.clone()));
        }
        self.hf_token_command
            .as_deref()
            .map(crate::hf_token::run_token_command)
            .transpose()
    }

    /// Models to load for `scan_mode`.
    ///
    /// # Errors
    /// Fails if the `Custom` config is missing or has no models.
    pub fn resolve_models(&self) -> crate::Result<Vec<ModelDef>> {
        self.resolve_models_in(dirs::config_dir().as_deref())
    }

    fn resolve_models_in(
        &self,
        config_dir: Option<&std::path::Path>,
    ) -> crate::Result<Vec<ModelDef>> {
        match self.scan_mode {
            ScanMode::Fast => Ok(vec![ModelDef {
                repo: DEFAULT_MODEL.to_string(),
                threshold: None,
            }]),
            ScanMode::Full => {
                #[cfg(not(feature = "candle"))]
                return Err(eyre::eyre!(
                    "scan-mode 'full' requires the candle backend (Llama Prompt Guard 2 has no ONNX export). \
                     Build with --features candle or use --scan-mode fast"
                ));

                #[cfg(feature = "candle")]
                Ok(FULL_MODELS
                    .iter()
                    .map(|repo| ModelDef {
                        repo: repo.to_string(),
                        threshold: None,
                    })
                    .collect())
            }
            ScanMode::Custom => load_custom_models(config_dir),
        }
    }
}

fn load_custom_models(config_dir: Option<&std::path::Path>) -> crate::Result<Vec<ModelDef>> {
    let path = config_dir
        .map(|p| p.join("parry-guard").join("models.toml"))
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
            hf_token_command: None,
            threshold: 0.7,
            claude_md_threshold: DEFAULT_CLAUDE_MD_THRESHOLD,
            scan_mode: ScanMode::default(),
            runtime_dir: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn scan_mode_as_str() {
        assert_eq!(ScanMode::Fast.as_str(), "fast");
        assert_eq!(ScanMode::Full.as_str(), "full");
        assert_eq!(ScanMode::Custom.as_str(), "custom");
    }

    #[test]
    fn resolve_models_custom_reads_models_toml() {
        let config_dir = tempfile::tempdir().unwrap();
        let dir = config_dir.path().join("parry-guard");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("models.toml"),
            indoc::indoc! {r#"
                [[models]]
                repo = "org/model"
                threshold = 0.5
            "#},
        )
        .unwrap();

        let config = Config {
            scan_mode: ScanMode::Custom,
            ..Config::default()
        };
        let models = config.resolve_models_in(Some(config_dir.path())).unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].repo, "org/model");
        assert_eq!(
            models[0].threshold.map(f32::to_bits),
            Some(0.5f32.to_bits())
        );
    }

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
    #[cfg(feature = "candle")]
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
    #[cfg(not(feature = "candle"))]
    fn resolve_models_full_errors_without_candle() {
        let config = Config {
            scan_mode: ScanMode::Full,
            ..Config::default()
        };
        let err = config.resolve_models().unwrap_err();
        assert!(
            err.to_string().contains("requires the candle backend"),
            "{err}"
        );
    }

    #[test]
    fn resolve_models_custom_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            scan_mode: ScanMode::Custom,
            ..Config::default()
        };
        let err = config.resolve_models_in(Some(dir.path())).unwrap_err();
        assert!(err.to_string().contains("failed to read"), "{err}");
        let err = config.resolve_models_in(None).unwrap_err();
        assert!(
            err.to_string().contains("cannot resolve config directory"),
            "{err}"
        );
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
        assert_eq!(
            config.claude_md_threshold.to_bits(),
            0.9f32.to_bits(),
            "default CLAUDE.md threshold should be 0.9"
        );
    }

    #[test]
    fn debug_redacts_hf_token() {
        let config = Config {
            hf_token: Some("hf_secret123".into()),
            ..Config::default()
        };
        let dbg = format!("{config:?}");
        assert!(!dbg.contains("hf_secret123"), "{dbg}");
        assert!(dbg.contains("REDACTED"), "{dbg}");
    }

    #[test]
    #[cfg(unix)]
    fn resolve_hf_token_prefers_direct_value() {
        let config = Config {
            hf_token: Some("direct".into()),
            hf_token_command: Some("exit 1".into()),
            ..Config::default()
        };
        let token = config.resolve_hf_token().unwrap().unwrap();
        assert_eq!(token.expose_secret(), "direct", "direct value should win");
    }

    #[test]
    #[cfg(unix)]
    fn resolve_hf_token_runs_command() {
        let config = Config {
            hf_token_command: Some("echo from-cmd".into()),
            ..Config::default()
        };
        let token = config.resolve_hf_token().unwrap().unwrap();
        assert_eq!(token.expose_secret(), "from-cmd", "command output expected");
    }

    #[test]
    #[cfg(unix)]
    fn resolve_hf_token_propagates_command_failure() {
        let config = Config {
            hf_token_command: Some("exit 1".into()),
            ..Config::default()
        };
        let _ = config.resolve_hf_token().unwrap_err();
    }

    #[test]
    fn resolve_hf_token_none_when_unset() {
        assert!(
            Config::default().resolve_hf_token().unwrap().is_none(),
            "no token configured"
        );
    }
}
