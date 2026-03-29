use clap::{Parser, Subcommand};
use parry_guard_core::config::ScanMode;
use std::path::PathBuf;

fn threshold_in_range(s: &str) -> Result<f32, String> {
    let val: f32 = s.parse().map_err(|e| format!("{e}"))?;
    if (0.0..=1.0).contains(&val) {
        Ok(val)
    } else {
        Err(format!("threshold must be between 0.0 and 1.0, got {val}"))
    }
}

fn parse_scan_mode(s: &str) -> Result<ScanMode, String> {
    match s.to_ascii_lowercase().as_str() {
        "fast" => Ok(ScanMode::Fast),
        "full" => Ok(ScanMode::Full),
        "custom" => Ok(ScanMode::Custom),
        other => Err(format!(
            "invalid scan mode '{other}', expected: fast, full, custom"
        )),
    }
}

#[derive(Parser)]
#[command(name = "parry-guard", about = "Prompt injection scanner", version)]
pub struct Cli {
    /// `HuggingFace` token (direct value)
    #[arg(long, env = "HF_TOKEN")]
    pub hf_token: Option<String>,

    /// Path to `HuggingFace` token file
    #[arg(long, env = "HF_TOKEN_PATH")]
    pub hf_token_path: Option<PathBuf>,

    /// ML detection threshold (0.0-1.0)
    #[arg(long, env = "PARRY_THRESHOLD", default_value = "0.7",
          value_parser = threshold_in_range)]
    pub threshold: f32,

    /// ML threshold for CLAUDE.md scanning (0.0-1.0, default 0.9)
    #[arg(long, env = "PARRY_CLAUDE_MD_THRESHOLD", default_value = "0.9",
          value_parser = threshold_in_range)]
    pub claude_md_threshold: f32,

    /// ML scan mode: fast (1 model), full (2-model ensemble), custom (models.toml)
    #[arg(long, env = "PARRY_SCAN_MODE", default_value = "fast",
          value_parser = parse_scan_mode)]
    pub scan_mode: ScanMode,

    /// Ask before monitoring new projects (default: auto-monitor)
    #[arg(long, env = "PARRY_ASK_ON_NEW_PROJECT")]
    pub ask_on_new_project: bool,

    /// Parent directories to ignore - all repos under these paths are skipped (comma-separated)
    #[arg(long, env = "PARRY_IGNORE_DIRS", value_delimiter = ',')]
    pub ignore_dirs: Vec<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    /// Resolve the HF token from `--hf-token`, `--hf-token-path`, or default paths.
    #[must_use]
    pub fn resolve_hf_token(&self) -> Option<String> {
        // 1. Direct token value (--hf-token or HF_TOKEN env)
        if let Some(ref token) = self.hf_token {
            let trimmed = token.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        // 2. Token file (--hf-token-path or HF_TOKEN_PATH env)
        if let Some(ref path) = self.hf_token_path {
            if let Some(token) = read_token_file(path) {
                return Some(token);
            }
        }

        // 3. Default file path
        read_token_file("/run/secrets/hf-token-scan-injection".as_ref())
    }
}

fn read_token_file(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[derive(Subcommand)]
pub enum Command {
    /// Claude Code hook mode (JSON stdin -> JSON stdout)
    Hook,
    /// Run as a daemon with the ML model loaded in memory
    Serve {
        /// Idle timeout in seconds before the daemon shuts down
        #[arg(long, default_value = "1800", env = "PARRY_IDLE_TIMEOUT")]
        idle_timeout: u64,
    },
    /// Scan only files changed since a git ref (commit, branch, tag)
    Diff {
        /// Git ref to compare against (e.g., main, HEAD~5, abc123)
        #[arg(name = "REF")]
        git_ref: String,
        /// Only scan specific file extensions (comma-separated, e.g., "md,txt,py")
        #[arg(long, short = 'e')]
        extensions: Option<String>,
        /// Run full ML scan (slow). Default is fast scan only (patterns + unicode + secrets)
        #[arg(long)]
        full: bool,
    },
    /// Set repo to ignored (no scanning)
    Ignore {
        /// Repo path (defaults to CWD)
        path: Option<std::path::PathBuf>,
    },
    /// Set repo to monitored (scan silently, alert on findings)
    Monitor {
        /// Repo path (defaults to CWD)
        path: Option<std::path::PathBuf>,
    },
    /// Reset repo to unknown (clear state + caches)
    Reset {
        /// Repo path (defaults to CWD)
        path: Option<std::path::PathBuf>,
    },
    /// Show current repo state
    Status {
        /// Repo path (defaults to CWD)
        path: Option<std::path::PathBuf>,
    },
    /// List all known repos and their states
    Repos,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scan_mode_valid() {
        assert_eq!(parse_scan_mode("fast").unwrap(), ScanMode::Fast);
        assert_eq!(parse_scan_mode("full").unwrap(), ScanMode::Full);
        assert_eq!(parse_scan_mode("custom").unwrap(), ScanMode::Custom);
        assert_eq!(parse_scan_mode("FAST").unwrap(), ScanMode::Fast);
        assert_eq!(parse_scan_mode("Full").unwrap(), ScanMode::Full);
    }

    #[test]
    fn parse_scan_mode_invalid() {
        assert!(parse_scan_mode("turbo").is_err());
        assert!(parse_scan_mode("").is_err());
    }

    #[test]
    fn ask_on_new_project_defaults_to_false() {
        let cli = Cli::try_parse_from(["parry-guard"]).unwrap();
        assert!(!cli.ask_on_new_project);
    }

    #[test]
    fn ask_on_new_project_flag() {
        let cli = Cli::try_parse_from(["parry-guard", "--ask-on-new-project"]).unwrap();
        assert!(cli.ask_on_new_project);
    }

    #[test]
    fn ignore_dirs_empty_by_default() {
        let cli = Cli::try_parse_from(["parry-guard"]).unwrap();
        assert!(cli.ignore_dirs.is_empty());
    }

    #[test]
    fn ignore_dirs_comma_separated() {
        let cli = Cli::try_parse_from(["parry-guard", "--ignore-dirs", "/a,/b,/c"]).unwrap();
        assert_eq!(cli.ignore_dirs, vec!["/a", "/b", "/c"]);
    }
}
