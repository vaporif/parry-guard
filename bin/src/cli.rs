use clap::{Parser, Subcommand};
use parry_guard_core::config::ScanMode;
use parry_guard_core::{ExposeSecret, SecretString};
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
pub(crate) struct Cli {
    /// `HuggingFace` token (direct value)
    #[arg(long, env = "HF_TOKEN")]
    pub hf_token: Option<String>,

    /// Shell command that prints the `HuggingFace` token (e.g. `pass show hf/token`).
    /// Run by the daemon when it loads models; the token is never written to disk.
    #[arg(long, env = "HF_TOKEN_COMMAND")]
    pub hf_token_command: Option<String>,

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

    /// Parent directories to ignore; all repos under these paths are skipped (comma-separated)
    #[arg(long, env = "PARRY_IGNORE_DIRS", value_delimiter = ',')]
    pub ignore_dirs: Vec<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    /// Resolve the HF token source: `--hf-token`, then `--hf-token-command`,
    /// then `--hf-token-path`, then the default path. The command isn't run here.
    #[must_use]
    pub(crate) fn resolve_hf_token(&self) -> HfTokenSource {
        if let Some(token) = non_blank(self.hf_token.as_deref()) {
            return HfTokenSource::Token(token.into());
        }
        if let Some(command) = non_blank(self.hf_token_command.as_deref()) {
            return HfTokenSource::Command(command);
        }
        self.read_token_files()
            .map_or(HfTokenSource::None, HfTokenSource::Token)
    }

    fn read_token_files(&self) -> Option<SecretString> {
        if let Some(ref path) = self.hf_token_path {
            if let Some(token) = read_token_file(path) {
                return Some(token);
            }
        }

        read_token_file("/run/secrets/hf-token-scan-injection".as_ref())
    }
}

#[derive(Debug)]
pub(crate) enum HfTokenSource {
    Token(SecretString),
    Command(String),
    None,
}

fn non_blank(s: Option<&str>) -> Option<String> {
    s.map(str::trim).filter(|s| !s.is_empty()).map(String::from)
}

fn read_token_file(path: &std::path::Path) -> Option<SecretString> {
    let raw = SecretString::from(std::fs::read_to_string(path).ok()?);
    let token = raw.expose_secret().trim();
    (!token.is_empty()).then(|| token.into())
}

#[derive(Subcommand)]
pub(crate) enum Command {
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
    #[command(flatten)]
    Repo(RepoCommand),
}

/// Per-repo state management subcommands.
#[derive(Subcommand)]
pub(crate) enum RepoCommand {
    /// Set repo to ignored (no scanning)
    Ignore {
        /// Repo path (defaults to CWD)
        path: Option<PathBuf>,
    },
    /// Set repo to monitored (scan silently, alert on findings)
    Monitor {
        /// Repo path (defaults to CWD)
        path: Option<PathBuf>,
    },
    /// Reset repo to unknown (clear state + caches)
    Reset {
        /// Repo path (defaults to CWD)
        path: Option<PathBuf>,
    },
    /// Show current repo state
    Status {
        /// Repo path (defaults to CWD)
        path: Option<PathBuf>,
    },
    /// List all known repos and their states
    Repos,
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

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
        parse_scan_mode("turbo").unwrap_err();
        parse_scan_mode("").unwrap_err();
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
        assert_eq!(cli.ignore_dirs, Vec::<String>::new());
    }

    #[test]
    fn ignore_dirs_comma_separated() {
        let cli = Cli::try_parse_from(["parry-guard", "--ignore-dirs", "/a,/b,/c"]).unwrap();
        assert_eq!(cli.ignore_dirs, vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn threshold_accepts_bounds() {
        assert!((threshold_in_range("0.0").unwrap() - 0.0).abs() < f32::EPSILON);
        assert!((threshold_in_range("0.42").unwrap() - 0.42).abs() < f32::EPSILON);
        assert!((threshold_in_range("1.0").unwrap() - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn threshold_rejects_out_of_range() {
        threshold_in_range("-0.1").unwrap_err();
        threshold_in_range("1.01").unwrap_err();
        threshold_in_range("abc").unwrap_err();
    }

    fn describe(source: HfTokenSource) -> String {
        match source {
            HfTokenSource::Token(t) => format!("token:{}", t.expose_secret()),
            HfTokenSource::Command(c) => format!("command:{c}"),
            HfTokenSource::None => "none".into(),
        }
    }

    #[rstest]
    #[case::direct_trimmed(Some("  tok123\n"), None, None, "token:tok123")]
    #[case::direct_wins_over_file(Some("direct"), None, Some("from-file"), "token:direct")]
    #[case::blank_direct_falls_back_to_file(
        Some("   "),
        None,
        Some("  from-file\n"),
        "token:from-file"
    )]
    #[case::direct_wins_over_command(Some("direct"), Some("pass show hf"), None, "token:direct")]
    #[case::command_wins_over_file(
        None,
        Some(" pass show hf \n"),
        Some("from-file"),
        "command:pass show hf"
    )]
    #[case::blank_command_falls_back_to_file(
        None,
        Some("  "),
        Some("from-file"),
        "token:from-file"
    )]
    fn resolve_hf_token_precedence(
        #[case] token: Option<&str>,
        #[case] command: Option<&str>,
        #[case] file: Option<&str>,
        #[case] expected: &str,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut cli = Cli::try_parse_from(["parry-guard"]).unwrap();
        cli.hf_token = token.map(String::from);
        cli.hf_token_command = command.map(String::from);
        cli.hf_token_path = file.map(|contents| {
            let path = dir.path().join("token");
            std::fs::write(&path, contents).unwrap();
            path
        });
        assert_eq!(describe(cli.resolve_hf_token()), expected);
    }

    #[test]
    fn hf_token_command_not_run_during_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let mut cli = Cli::try_parse_from(["parry-guard"]).unwrap();
        cli.hf_token = None;
        cli.hf_token_command = Some(format!("touch {}", marker.display()));
        let _ = cli.resolve_hf_token();
        assert!(
            !marker.exists(),
            "command must not run during CLI resolution"
        );
    }

    #[test]
    fn read_token_file_cases() {
        let dir = tempfile::tempdir().unwrap();
        let tok = dir.path().join("tok");
        std::fs::write(&tok, " abc \n").unwrap();
        let token = read_token_file(&tok).unwrap();
        assert_eq!(token.expose_secret(), "abc", "token should be trimmed");

        let blank = dir.path().join("blank");
        std::fs::write(&blank, " \n").unwrap();
        assert!(read_token_file(&blank).is_none(), "blank file is no token");

        assert!(
            read_token_file(&dir.path().join("missing")).is_none(),
            "missing file is no token"
        );
    }
}
