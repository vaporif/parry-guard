//! Pattern matching for sensitive paths and exfil domains.
//!
//! Supports configuration overrides via `~/.config/parry/patterns.toml`.

use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use tracing::{trace, warn};

/// How a pattern should be matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// Match as a path segment (between `/` or at boundaries).
    /// Example: `".env"` matches `/home/user/.env` but not `.environment`.
    #[default]
    PathSegment,
    /// Match as a filename suffix (extension check).
    /// Example: `"_rsa"` matches `id_rsa` but not `rsa_util`.
    Suffix,
    /// Match anywhere as substring (use sparingly - high false positive risk).
    Substring,
}

/// A pattern for detecting sensitive content.
#[derive(Debug, Clone)]
pub struct Pattern {
    pub value: String,
    pub kind: MatchKind,
    lower: String,
}

impl Pattern {
    pub fn new(value: impl Into<String>, kind: MatchKind) -> Self {
        let value = value.into();
        let lower = value.to_lowercase();
        Self { value, kind, lower }
    }

    pub fn path_segment(value: impl Into<String>) -> Self {
        Self::new(value, MatchKind::PathSegment)
    }

    pub fn suffix(value: impl Into<String>) -> Self {
        Self::new(value, MatchKind::Suffix)
    }

    pub fn substring(value: impl Into<String>) -> Self {
        Self::new(value, MatchKind::Substring)
    }

    /// Check if this pattern matches the given text.
    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        let lower = text.to_lowercase();
        match self.kind {
            MatchKind::PathSegment => self.matches_path_segment(&lower),
            MatchKind::Suffix => lower.ends_with(&self.lower),
            MatchKind::Substring => lower.contains(&self.lower),
        }
    }

    fn matches_path_segment(&self, text: &str) -> bool {
        for segment in text.split(['/', '\\']) {
            if segment == self.lower {
                return true;
            }
            if self.lower.ends_with('/') && segment == self.lower.trim_end_matches('/') {
                return true;
            }
        }
        if text.ends_with(&self.lower) {
            let prefix_len = text.len() - self.lower.len();
            if prefix_len == 0 {
                return true;
            }
            let prev_char = text.chars().nth(prefix_len - 1);
            if prev_char == Some('/') || prev_char == Some('\\') {
                return true;
            }
        }
        self.matches_in_quoted_string(text)
    }

    /// Check if pattern appears at a word boundary (for code like `open('.env')`).
    fn matches_in_quoted_string(&self, text: &str) -> bool {
        let boundary_chars = |c: char| -> bool {
            c.is_whitespace()
                || matches!(
                    c,
                    '\'' | '"'
                        | '`'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | ','
                        | ';'
                        | '='
                        | '@'
                        | '/'
                        | '\\'
                )
        };

        let mut pos = 0;
        while let Some(idx) = text[pos..].find(&self.lower) {
            let abs_idx = pos + idx;
            let pattern_end = abs_idx + self.lower.len();

            let at_start = abs_idx == 0
                || text[..abs_idx]
                    .chars()
                    .next_back()
                    .is_some_and(boundary_chars);
            let at_end = pattern_end >= text.len()
                || text[pattern_end..]
                    .chars()
                    .next()
                    .is_some_and(boundary_chars);

            if at_start && at_end {
                return true;
            }

            pos = abs_idx + 1;
        }

        false
    }
}

/// Configuration for pattern overrides.
#[derive(Debug, Default, Deserialize)]
pub struct PatternConfig {
    #[serde(default)]
    pub sensitive_paths: PatternOverrides,
    #[serde(default)]
    pub exfil_domains: ListOverrides,
}

#[derive(Debug, Default, Deserialize)]
pub struct PatternOverrides {
    #[serde(default)]
    pub add: Vec<PatternEntry>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PatternEntry {
    pub pattern: String,
    #[serde(default)]
    pub kind: MatchKind,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListOverrides {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

impl PatternConfig {
    /// Load configuration from the default path.
    #[must_use]
    pub fn load() -> Self {
        Self::load_from_path(Self::default_path())
    }

    fn default_path() -> Option<std::path::PathBuf> {
        dirs::home_dir().map(|p| p.join(".config").join("parry-guard").join("patterns.toml"))
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
                warn!(path = %path.display(), %e, "failed to parse pattern config");
                Self::default()
            }),
            Err(e) => {
                warn!(path = %path.display(), %e, "failed to read pattern config");
                Self::default()
            }
        }
    }
}

/// Built-in sensitive path patterns.
static DEFAULT_SENSITIVE_PATHS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        // Environment files (path segment match)
        Pattern::path_segment(".env"),
        Pattern::path_segment(".envrc"),
        // Shell config
        Pattern::path_segment(".bashrc"),
        Pattern::path_segment(".zshrc"),
        Pattern::path_segment(".profile"),
        Pattern::path_segment(".bash_profile"),
        Pattern::path_segment(".bash_history"),
        Pattern::path_segment(".zsh_history"),
        // SSH directory and keys
        Pattern::path_segment(".ssh"),
        Pattern::suffix("/id_rsa"),
        Pattern::suffix("/id_ed25519"),
        Pattern::suffix("/id_dsa"),
        Pattern::suffix("/id_ecdsa"),
        Pattern::path_segment("known_hosts"),
        Pattern::path_segment("authorized_keys"),
        // Cloud credentials
        Pattern::path_segment(".aws"),
        Pattern::path_segment(".azure"),
        Pattern::path_segment(".config/gcloud"),
        Pattern::path_segment(".kube"),
        Pattern::path_segment(".docker"),
        // GPG
        Pattern::path_segment(".gnupg"),
        Pattern::path_segment(".pgp"),
        // Package managers
        Pattern::path_segment(".npmrc"),
        Pattern::path_segment(".yarnrc"),
        Pattern::path_segment(".pypirc"),
        Pattern::path_segment(".gem"),
        Pattern::path_segment(".cargo/credentials"),
        Pattern::path_segment(".cargo/credentials.toml"),
        Pattern::path_segment(".nuget"),
        // Git credentials
        Pattern::path_segment(".git-credentials"),
        Pattern::path_segment(".gitconfig"),
        Pattern::path_segment(".netrc"),
        Pattern::path_segment(".curlrc"),
        Pattern::path_segment(".wgetrc"),
        // System files (use substring - these are explicit absolute paths)
        Pattern::substring("/etc/passwd"),
        Pattern::substring("/etc/shadow"),
        Pattern::substring("/etc/sudoers"),
        Pattern::substring("/etc/hosts"),
        // Database configs with credentials
        Pattern::path_segment(".pgpass"),
        Pattern::path_segment(".my.cnf"),
        Pattern::path_segment(".mongoshrc.js"),
        // CI/CD secrets
        Pattern::path_segment(".travis.yml"),
        Pattern::path_segment(".circleci"),
        Pattern::substring(".github/secrets"),
        // macOS keychain
        Pattern::path_segment("keychain"),
        Pattern::path_segment(".keychain"),
    ]
});

/// Built-in exfil domains.
static DEFAULT_EXFIL_DOMAINS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        // Request catchers (commonly used for exfil)
        "webhook.site",
        "requestbin.com",
        "requestcatcher.com",
        "hookbin.com",
        "beeceptor.com",
        "mockbin.org",
        "postb.in",
        "ptsv2.com",
        "putsreq.com",
        // Tunneling services
        "ngrok.io",
        "ngrok-free.app",
        "ngrok.app",
        "localtunnel.me",
        "serveo.net",
        "localhost.run",
        "tunnelto.dev",
        "loca.lt",
        "telebit.cloud",
        // Security testing tools
        "burpcollaborator.net",
        "oastify.com",
        "interact.sh",
        "canarytokens.com",
        "dnslog.cn",
        "ceye.io",
        // Pastebin services
        "pastebin.com",
        "paste.ee",
        "hastebin.com",
        "dpaste.org",
        "ghostbin.com",
        "rentry.co",
        // Pipelines/automation
        "pipedream.com",
        "pipedream.net",
        "zapier.com",
        "ifttt.com",
        // File sharing
        "transfer.sh",
        "file.io",
        "0x0.st",
        "temp.sh",
        "termbin.com",
    ]
});

/// Compiled patterns with user overrides applied.
pub struct CompiledPatterns {
    pub sensitive_paths: Vec<Pattern>,
    pub exfil_domains: Vec<String>,
    exfil_regex: Regex,
}

impl CompiledPatterns {
    /// Load patterns with configuration overrides.
    #[must_use]
    pub fn load() -> Self {
        let config = PatternConfig::load();
        Self::from_config(&config)
    }

    /// Create from explicit config (useful for testing).
    #[must_use]
    pub fn from_config(config: &PatternConfig) -> Self {
        let mut sensitive_paths: Vec<Pattern> = DEFAULT_SENSITIVE_PATHS
            .iter()
            .filter(|p| !config.sensitive_paths.remove.contains(&p.value))
            .cloned()
            .collect();
        sensitive_paths.extend(
            config
                .sensitive_paths
                .add
                .iter()
                .map(|e| Pattern::new(e.pattern.clone(), e.kind)),
        );

        let remove_set: std::collections::HashSet<&str> = config
            .exfil_domains
            .remove
            .iter()
            .map(String::as_str)
            .collect();
        let mut exfil_domains: Vec<String> = DEFAULT_EXFIL_DOMAINS
            .iter()
            .filter(|d| !remove_set.contains(*d))
            .copied()
            .map(String::from)
            .collect();
        for domain in &config.exfil_domains.add {
            if !exfil_domains.contains(domain) {
                exfil_domains.push(domain.clone());
            }
        }

        let exfil_regex = Self::build_domain_regex(&exfil_domains);

        Self {
            sensitive_paths,
            exfil_domains,
            exfil_regex,
        }
    }

    #[allow(clippy::trivial_regex)]
    fn build_domain_regex(domains: &[String]) -> Regex {
        if domains.is_empty() {
            return Regex::new(r"^$").expect("valid regex");
        }
        let escaped: Vec<String> = domains.iter().map(|d| regex::escape(d)).collect();
        let pattern = format!(r"(?i)(^|[./])({})($|[:/])", escaped.join("|"));
        Regex::new(&pattern).expect("valid regex")
    }

    /// Check if text contains a sensitive path.
    #[must_use]
    pub fn has_sensitive_path(&self, text: &str) -> bool {
        self.sensitive_paths.iter().any(|p| p.matches(text))
    }

    /// Check if text contains an exfil domain.
    #[must_use]
    pub fn has_exfil_domain(&self, text: &str) -> bool {
        self.exfil_regex.is_match(text)
    }
}

/// Global compiled patterns (loaded once).
pub static PATTERNS: LazyLock<CompiledPatterns> = LazyLock::new(CompiledPatterns::load);

/// Check if text contains a sensitive path (convenience function).
pub fn has_sensitive_path(text: &str) -> bool {
    let matched = PATTERNS.has_sensitive_path(text);
    if matched {
        trace!("sensitive path matched");
    }
    matched
}

/// Check if text contains an exfil domain (convenience function).
pub fn has_exfil_domain(text: &str) -> bool {
    let matched = PATTERNS.has_exfil_domain(text);
    if matched {
        trace!("exfil domain matched");
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Pattern matching tests ===

    #[test]
    fn path_segment_matches_exact() {
        let p = Pattern::path_segment(".env");
        assert!(p.matches("/home/user/.env"));
        assert!(p.matches(".env"));
        assert!(p.matches("/project/.env"));
    }

    #[test]
    fn path_segment_rejects_substring() {
        let p = Pattern::path_segment(".env");
        assert!(!p.matches(".environment"));
        assert!(!p.matches("/path/.env.local")); // Different segment
        assert!(!p.matches("myenv"));
    }

    #[test]
    fn suffix_matches_end() {
        let p = Pattern::suffix("/id_rsa");
        assert!(p.matches("/home/user/.ssh/id_rsa"));
        assert!(p.matches("~/.ssh/id_rsa"));
    }

    #[test]
    fn suffix_rejects_non_suffix() {
        let p = Pattern::suffix("/id_rsa");
        assert!(!p.matches("id_rsa_backup"));
        assert!(!p.matches("grid_rsax"));
    }

    #[test]
    fn substring_matches_anywhere() {
        let p = Pattern::substring("secret");
        assert!(p.matches("my_secret_key"));
        assert!(p.matches("/path/secrets/file"));
        assert!(p.matches("SECRET")); // case insensitive
    }

    // === Sensitive path tests ===

    #[test]
    fn detects_env_file() {
        assert!(has_sensitive_path("/home/user/project/.env"));
        assert!(has_sensitive_path(".env"));
    }

    #[test]
    fn rejects_env_substring() {
        assert!(!has_sensitive_path(".environment"));
        assert!(!has_sensitive_path("environment.txt"));
    }

    #[test]
    fn detects_ssh_keys() {
        assert!(has_sensitive_path("~/.ssh/id_rsa"));
        assert!(has_sensitive_path("/home/user/.ssh/id_ed25519"));
    }

    #[test]
    fn rejects_similar_names() {
        assert!(!has_sensitive_path("grid_rsax.log"));
        assert!(!has_sensitive_path("id_rsa_util.py"));
    }

    #[test]
    fn detects_cloud_creds() {
        assert!(has_sensitive_path("~/.aws/credentials"));
        assert!(has_sensitive_path("~/.kube/config"));
        assert!(has_sensitive_path("~/.docker/config.json"));
    }

    // === Exfil domain tests ===

    #[test]
    fn detects_exfil_domains() {
        assert!(has_exfil_domain("https://webhook.site/abc123"));
        assert!(has_exfil_domain("http://abc.ngrok.io/path"));
        assert!(has_exfil_domain("https://x.burpcollaborator.net"));
    }

    #[test]
    fn rejects_partial_domain_match() {
        // Should not match if domain is substring of larger domain
        assert!(!has_exfil_domain("https://notwebhook.site.com/"));
        assert!(!has_exfil_domain("https://mypastebin.com/"));
    }

    #[test]
    fn domain_match_is_case_insensitive() {
        assert!(has_exfil_domain("https://WEBHOOK.SITE/test"));
        assert!(has_exfil_domain("https://Ngrok.IO/path"));
    }

    // === Config override tests ===

    #[test]
    fn config_add_pattern() {
        let config = PatternConfig {
            sensitive_paths: PatternOverrides {
                add: vec![PatternEntry {
                    pattern: ".custom-secret".into(),
                    kind: MatchKind::PathSegment,
                }],
                remove: vec![],
            },
            exfil_domains: ListOverrides::default(),
        };
        let patterns = CompiledPatterns::from_config(&config);
        assert!(patterns.has_sensitive_path("/path/.custom-secret"));
    }

    #[test]
    fn config_remove_pattern() {
        let config = PatternConfig {
            sensitive_paths: PatternOverrides {
                add: vec![],
                remove: vec![".env".into()],
            },
            exfil_domains: ListOverrides::default(),
        };
        let patterns = CompiledPatterns::from_config(&config);
        assert!(!patterns.has_sensitive_path("/path/.env"));
    }

    #[test]
    fn config_add_domain() {
        let config = PatternConfig {
            sensitive_paths: PatternOverrides::default(),
            exfil_domains: ListOverrides {
                add: vec!["evil-custom.com".into()],
                remove: vec![],
            },
        };
        let patterns = CompiledPatterns::from_config(&config);
        assert!(patterns.has_exfil_domain("https://evil-custom.com/"));
    }

    #[test]
    fn config_remove_domain() {
        let config = PatternConfig {
            sensitive_paths: PatternOverrides::default(),
            exfil_domains: ListOverrides {
                add: vec![],
                remove: vec!["pastebin.com".into()],
            },
        };
        let patterns = CompiledPatterns::from_config(&config);
        assert!(!patterns.has_exfil_domain("https://pastebin.com/abc"));
    }
}
