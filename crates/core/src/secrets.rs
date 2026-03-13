//! Secret pattern detection with configurable overrides.
//!
//! Supports configuration via `~/.config/parry/patterns.toml` under `[secrets]`.

use regex::RegexSet;
use serde::Deserialize;
use std::sync::LazyLock;
use tracing::{trace, warn};

/// Built-in secret patterns.
static DEFAULT_SECRET_PATTERNS: &[&str] = &[
    // AWS Access Key ID
    r"AKIA[0-9A-Z]{16}",
    // AWS Secret Access Key (40 chars, base64-ish)
    r#"(?i)aws.{0,20}secret.{0,20}['"][A-Za-z0-9/+=]{40}['"]"#,
    // GitHub Personal Access Token (classic)
    r"gh[ps]_[A-Za-z0-9_]{36,}",
    // GitHub Fine-grained PAT
    r"github_pat_[A-Za-z0-9_]{82,}",
    // GitLab Personal Access Token
    r"glpat-[A-Za-z0-9\-_]{20,}",
    // Slack tokens
    r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    // OpenAI project key
    r"sk-proj-[A-Za-z0-9\-_]{40,}",
    // Anthropic API key
    r"sk-ant-[A-Za-z0-9\-_]{20,}",
    // Stripe secret/publishable key
    r"[rs]k_(test|live)_[A-Za-z0-9]{24,}",
    // Google API key
    r"AIza[0-9A-Za-z\-_]{35}",
    // Google OAuth client secret
    r"GOCSPX-[A-Za-z0-9_-]{28}",
    // Firebase
    r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    // JWT token
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
    // Private key header
    r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    // npm token
    r"npm_[A-Za-z0-9]{36}",
    // PyPI token
    r"pypi-[A-Za-z0-9]{16,}",
    // SendGrid API key
    r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    // Twilio API key
    r"SK[a-f0-9]{32}",
    // Discord bot token
    r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}",
    // Heroku API key
    r"[hH]eroku.{0,20}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    // Datadog API key
    r#"(?i)datadog.{0,20}['"][a-f0-9]{32}['"]"#,
    // Datadog APP key
    r#"(?i)datadog.{0,20}['"][a-f0-9]{40}['"]"#,
    // Netlify access token
    r#"(?i)netlify.{0,20}['"][A-Za-z0-9_-]{40,}['"]"#,
    // Vercel token
    r#"(?i)vercel.{0,20}['"][A-Za-z0-9]{24}['"]"#,
    // Supabase key (anon/service)
    r"sbp_[a-f0-9]{40}",
    // Supabase JWT-style key
    r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    // Azure Storage Account Key (88 chars base64)
    r#"(?i)azure.{0,20}(account|storage).{0,20}key.{0,20}['"][A-Za-z0-9+/]{86}==['"]"#,
    // Azure Client Secret
    r#"(?i)azure.{0,20}(client|app).{0,20}secret.{0,20}['"][A-Za-z0-9~._-]{34}['"]"#,
    // MongoDB connection string with password
    r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+",
    // PostgreSQL connection string with password
    r"postgres(ql)?://[^:]+:[^@]+@[^/]+",
    // MySQL connection string with password
    r"mysql://[^:]+:[^@]+@[^/]+",
    // Redis connection string with password
    r"redis://:[^@]+@[^/]+",
    // Mailgun API key
    r"key-[a-f0-9]{32}",
    // Mailchimp API key
    r"[a-f0-9]{32}-us[0-9]{1,2}",
    // DigitalOcean token
    r"dop_v1_[a-f0-9]{64}",
    // DigitalOcean OAuth
    r"doo_v1_[a-f0-9]{64}",
    // Linear API key
    r"lin_api_[A-Za-z0-9]{40}",
    // Doppler token
    r"dp\.pt\.[A-Za-z0-9]{40,}",
    // Planetscale password
    r"pscale_pw_[A-Za-z0-9_-]{40,}",
    // Grafana API key
    r"eyJrIjoi[A-Za-z0-9_-]{50,}",
    // HashiCorp Vault token
    r"hvs\.[A-Za-z0-9_-]{24,}",
    // Pulumi access token
    r"pul-[a-f0-9]{40}",
];

/// Configuration for secret pattern overrides.
#[derive(Debug, Default, Deserialize)]
pub struct SecretConfig {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Full patterns config (only secrets section used here).
#[derive(Debug, Default, Deserialize)]
struct PatternConfig {
    #[serde(default)]
    secrets: SecretConfig,
}

impl PatternConfig {
    fn load() -> Self {
        let Some(path) = dirs::config_dir().map(|p| p.join("parry-guard").join("patterns.toml"))
        else {
            return Self::default();
        };
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => toml::from_str(&content).unwrap_or_else(|e| {
                warn!(path = %path.display(), %e, "failed to parse secret patterns config");
                Self::default()
            }),
            Err(e) => {
                warn!(path = %path.display(), %e, "failed to read secret patterns config");
                Self::default()
            }
        }
    }
}

/// Compiled secret patterns with user overrides applied.
pub struct CompiledSecrets {
    patterns: RegexSet,
}

impl CompiledSecrets {
    /// Load patterns with configuration overrides.
    #[must_use]
    pub fn load() -> Self {
        let config = PatternConfig::load();
        Self::from_config(&config.secrets)
    }

    /// Create from an explicit config.
    ///
    /// # Panics
    ///
    /// Panics if hardcoded default regex patterns are invalid.
    #[must_use]
    pub fn from_config(config: &SecretConfig) -> Self {
        let remove_set: std::collections::HashSet<&str> =
            config.remove.iter().map(String::as_str).collect();

        let mut patterns: Vec<&str> = DEFAULT_SECRET_PATTERNS
            .iter()
            .filter(|p| !remove_set.contains(*p))
            .copied()
            .collect();

        let add_refs: Vec<&str> = config.add.iter().map(String::as_str).collect();
        patterns.extend(add_refs);

        let regex_set = RegexSet::new(&patterns).unwrap_or_else(|e| {
            warn!(%e, "failed to compile secret patterns, using defaults");
            RegexSet::new(DEFAULT_SECRET_PATTERNS).expect("valid regex")
        });

        Self {
            patterns: regex_set,
        }
    }

    /// Check if text contains a secret pattern.
    #[must_use]
    pub fn has_secret(&self, text: &str) -> bool {
        self.patterns.is_match(text)
    }
}

/// Global compiled patterns (loaded once).
static SECRETS: LazyLock<CompiledSecrets> = LazyLock::new(CompiledSecrets::load);

/// Check if text contains a secret pattern (convenience function).
pub fn has_secret(text: &str) -> bool {
    let matched = SECRETS.has_secret(text);
    if matched {
        trace!("secret pattern matched");
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_key() {
        assert!(has_secret("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn detects_github_pat() {
        assert!(has_secret(&format!("ghp_{}", "a".repeat(36))));
        assert!(has_secret(&format!("ghs_{}", "b".repeat(36))));
        assert!(has_secret(&format!("github_pat_{}", "c".repeat(82))));
    }

    #[test]
    fn detects_gitlab_pat() {
        assert!(has_secret(&format!("glpat-{}", "x".repeat(20))));
    }

    #[test]
    fn detects_slack_token() {
        assert!(has_secret("xoxb-1234567890-abcdef"));
    }

    #[test]
    fn detects_openai_key() {
        assert!(has_secret(&format!("sk-proj-{}", "a".repeat(40))));
    }

    #[test]
    fn detects_anthropic_key() {
        assert!(has_secret(&format!("sk-ant-{}", "a".repeat(20))));
    }

    #[test]
    fn detects_stripe_key() {
        assert!(has_secret(&format!("sk_live_{}", "a".repeat(24))));
        assert!(has_secret(&format!("rk_test_{}", "b".repeat(24))));
    }

    #[test]
    fn detects_google_api_key() {
        assert!(has_secret(&format!("AIza{}", "a".repeat(35))));
    }

    #[test]
    fn detects_jwt() {
        assert!(has_secret(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
        ));
    }

    #[test]
    fn detects_private_key() {
        assert!(has_secret("-----BEGIN PRIVATE KEY-----"));
        assert!(has_secret("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(has_secret("-----BEGIN EC PRIVATE KEY-----"));
        assert!(has_secret("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn detects_npm_token() {
        assert!(has_secret(&format!("npm_{}", "a".repeat(36))));
    }

    #[test]
    fn detects_pypi_token() {
        assert!(has_secret(&format!("pypi-{}", "a".repeat(16))));
    }

    #[test]
    fn detects_sendgrid_key() {
        let key = format!("SG.{}.{}", "a".repeat(22), "b".repeat(43));
        assert!(has_secret(&key));
    }

    #[test]
    fn detects_twilio_key() {
        assert!(has_secret(&format!("SK{}", "a".repeat(32))));
    }

    #[test]
    fn detects_discord_bot_token() {
        let token = format!("M{}.{}.{}", "a".repeat(23), "b".repeat(6), "c".repeat(27));
        assert!(has_secret(&token));
    }

    #[test]
    fn clean_text_passes() {
        assert!(!has_secret("Normal markdown content"));
        assert!(!has_secret("sk-not-long-enough"));
        assert!(!has_secret("The API key format is documented here"));
        assert!(!has_secret("ghp_tooshort"));
        assert!(!has_secret("Just a regular sentence with no secrets."));
    }

    #[test]
    fn detects_heroku_api_key() {
        assert!(has_secret(
            "heroku_api_key=12345678-1234-1234-1234-123456789abc"
        ));
    }

    #[test]
    fn detects_mongodb_uri() {
        assert!(has_secret("mongodb://user:password@host:27017/database"));
        assert!(has_secret(
            "mongodb+srv://user:password@cluster.mongodb.net/db"
        ));
    }

    #[test]
    fn detects_postgres_uri() {
        assert!(has_secret("postgres://user:password@host:5432/database"));
        assert!(has_secret("postgresql://admin:secret@db.example.com/prod"));
    }

    #[test]
    fn detects_mysql_uri() {
        assert!(has_secret("mysql://root:password@localhost:3306/mydb"));
    }

    #[test]
    fn detects_redis_uri() {
        assert!(has_secret("redis://:secretpassword@redis.example.com:6379"));
    }

    #[test]
    fn detects_digitalocean_token() {
        assert!(has_secret(&format!("dop_v1_{}", "a".repeat(64))));
        assert!(has_secret(&format!("doo_v1_{}", "b".repeat(64))));
    }

    #[test]
    fn detects_linear_api_key() {
        assert!(has_secret(&format!("lin_api_{}", "a".repeat(40))));
    }

    #[test]
    fn detects_mailgun_key() {
        assert!(has_secret(&format!("key-{}", "a".repeat(32))));
    }

    #[test]
    fn detects_mailchimp_key() {
        assert!(has_secret(&format!("{}-us12", "a".repeat(32))));
    }

    #[test]
    fn detects_doppler_token() {
        assert!(has_secret(&format!("dp.pt.{}", "a".repeat(40))));
    }

    #[test]
    fn detects_planetscale_password() {
        assert!(has_secret(&format!("pscale_pw_{}", "a".repeat(40))));
    }

    #[test]
    fn detects_vault_token() {
        assert!(has_secret(&format!("hvs.{}", "a".repeat(24))));
    }

    #[test]
    fn detects_pulumi_token() {
        assert!(has_secret(&format!("pul-{}", "a".repeat(40))));
    }

    #[test]
    fn detects_supabase_key() {
        assert!(has_secret(&format!("sbp_{}", "a".repeat(40))));
    }

    #[test]
    fn detects_google_oauth_secret() {
        assert!(has_secret(&format!("GOCSPX-{}", "a".repeat(28))));
    }

    // Config override tests

    #[test]
    fn config_add_pattern() {
        let config = SecretConfig {
            add: vec![r"CUSTOM_SECRET_[A-Z]{10}".into()],
            remove: vec![],
        };
        let secrets = CompiledSecrets::from_config(&config);
        assert!(secrets.has_secret("CUSTOM_SECRET_ABCDEFGHIJ"));
    }

    #[test]
    fn config_remove_pattern() {
        let config = SecretConfig {
            add: vec![],
            remove: vec![r"AKIA[0-9A-Z]{16}".into()],
        };
        let secrets = CompiledSecrets::from_config(&config);
        assert!(!secrets.has_secret("AKIAIOSFODNN7EXAMPLE"));
    }
}
