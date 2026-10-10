//! `HuggingFace` model download/caching.

use std::cell::OnceCell;
use std::path::PathBuf;

use eyre::WrapErr;
use hf_hub::api::sync::{ApiBuilder, ApiRepo};
use hf_hub::Cache;
use parry_guard_core::config::Config;
use parry_guard_core::{ExposeSecret, Result, SecretString};
use tracing::{debug, warn};

/// The configured token, resolved on first download and at most once per model load.
///
/// A failing token command isn't fatal: downloads go ahead without it (hf-hub may
/// still use its own `$HF_HOME/token`), and a gated model that then fails to
/// download reports the command's error.
pub struct LazyToken<'a> {
    config: &'a Config,
    resolved: OnceCell<std::result::Result<Option<SecretString>, String>>,
}

impl<'a> LazyToken<'a> {
    #[must_use]
    pub const fn new(config: &'a Config) -> Self {
        Self {
            config,
            resolved: OnceCell::new(),
        }
    }

    fn get(&self) -> std::result::Result<Option<&SecretString>, &str> {
        self.resolved
            .get_or_init(|| {
                self.config.resolve_hf_token().map_err(|e| {
                    warn!(%e, "token command failed, downloading without it");
                    e.to_string()
                })
            })
            .as_ref()
            .map(Option::as_ref)
            .map_err(String::as_str)
    }
}

/// Files of one `HuggingFace` repo.
pub struct ModelFiles<'a> {
    repo: String,
    cache: Cache,
    endpoint: Option<String>,
    token: &'a LazyToken<'a>,
}

impl<'a> ModelFiles<'a> {
    /// Honors `HF_HOME` and `HF_ENDPOINT`. The token is sent to that endpoint.
    #[must_use]
    pub fn from_env(repo: &str, token: &'a LazyToken<'a>) -> Self {
        Self::new(
            repo,
            Cache::from_env(),
            normalize_endpoint(std::env::var("HF_ENDPOINT").ok()),
            token,
        )
    }

    fn new(repo: &str, cache: Cache, endpoint: Option<String>, token: &'a LazyToken<'a>) -> Self {
        Self {
            repo: repo.to_string(),
            cache,
            endpoint,
            token,
        }
    }

    /// Local path of `filename`, downloading it if needed.
    /// Only a download resolves the token, so a cached model never runs the token command.
    ///
    /// # Errors
    /// Fails if the file isn't cached and can't be downloaded.
    pub fn get(&self, filename: &str) -> Result<PathBuf> {
        if let Some(path) = self.cache.model(self.repo.clone()).get(filename) {
            debug!(repo = %self.repo, filename, "cache hit");
            return Ok(path);
        }
        let token = self.token.get();
        let api = self.api(token.ok().flatten())?;
        api.download(filename).map_err(|e| {
            if let Err(token_err) = token {
                eyre::eyre!("{e} ({token_err})")
            } else {
                eyre::eyre!("{e}")
            }
        })
    }

    fn api(&self, token: Option<&SecretString>) -> Result<ApiRepo> {
        let mut builder = ApiBuilder::from_cache(self.cache.clone());
        if let Some(ref endpoint) = self.endpoint {
            builder = builder.with_endpoint(endpoint.clone());
        }
        if let Some(token) = token {
            debug!("using HuggingFace token from config");
            // hf-hub only takes a plain String
            builder = builder.with_token(Some(token.expose_secret().to_string()));
        } else {
            debug!("no HuggingFace token configured");
        }
        let api = builder
            .build()
            .wrap_err("failed to build HuggingFace API client")?;
        debug!(repo = %self.repo, "HuggingFace repo handle created");
        Ok(api.model(self.repo.clone()))
    }
}

/// Blank means unset and a trailing `/` is dropped, as in `huggingface_hub`;
/// hf-hub would otherwise build relative or `//` URLs.
fn normalize_endpoint(endpoint: Option<String>) -> Option<String> {
    endpoint
        .map(|e| e.trim().trim_end_matches('/').to_string())
        .filter(|e| !e.is_empty())
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::Path;

    use parry_guard_core::config::HfToken;

    use super::*;

    const REPO: &str = "org/model";
    // nothing listens on the discard port, so downloads fail fast offline
    const UNREACHABLE: &str = "http://127.0.0.1:9";

    fn command_config(command: String) -> Config {
        Config {
            hf_token: Some(HfToken::Command(command)),
            ..Config::default()
        }
    }

    #[expect(clippy::unwrap_used, reason = "test helper")]
    fn cache_file(cache_dir: &Path, filename: &str) {
        let repo_dir = cache_dir.join("models--org--model");
        std::fs::create_dir_all(repo_dir.join("refs")).unwrap();
        std::fs::write(repo_dir.join("refs/main"), "abc123").unwrap();
        let snapshot = repo_dir.join("snapshots/abc123");
        std::fs::create_dir_all(&snapshot).unwrap();
        std::fs::write(snapshot.join(filename), "{}").unwrap();
    }

    #[test]
    fn cached_file_skips_token_command() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        cache_file(dir.path(), "tokenizer.json");
        let config = command_config(format!("touch '{}'; echo tok", marker.display()));
        let token = LazyToken::new(&config);
        let files = ModelFiles::new(REPO, Cache::new(dir.path().into()), None, &token);

        let path = files.get("tokenizer.json").unwrap();

        assert!(path.ends_with("tokenizer.json"), "got {}", path.display());
        assert!(!marker.exists(), "token command ran for a cached file");
    }

    #[test]
    fn failed_token_command_still_attempts_download() {
        let dir = tempfile::tempdir().unwrap();
        let config = command_config("echo 'vault locked' >&2; exit 1".into());
        let token = LazyToken::new(&config);
        let files = ModelFiles::new(
            REPO,
            Cache::new(dir.path().into()),
            Some(UNREACHABLE.into()),
            &token,
        );

        let err = files.get("tokenizer.json").unwrap_err().to_string();

        assert!(
            err.contains("vault locked"),
            "error should explain the token failure: {err}"
        );
        assert!(
            !err.starts_with("hf-token-command"),
            "token failure should not abort before the download: {err}"
        );
    }

    #[test]
    fn token_command_runs_once_per_load() {
        let dir = tempfile::tempdir().unwrap();
        let counter = dir.path().join("count");
        let config = command_config(format!("echo x >> '{}'; echo tok", counter.display()));
        let token = LazyToken::new(&config);
        let cache = Cache::new(dir.path().join("hub"));
        let first = ModelFiles::new(REPO, cache.clone(), Some(UNREACHABLE.into()), &token);
        let second = ModelFiles::new("org/other", cache, Some(UNREACHABLE.into()), &token);

        let _ = first.get("tokenizer.json").unwrap_err();
        let _ = first.get("config.json").unwrap_err();
        let _ = second.get("tokenizer.json").unwrap_err();

        let runs = std::fs::read_to_string(&counter).unwrap().lines().count();
        assert_eq!(runs, 1, "token command should run once per load");
    }

    #[rstest::rstest]
    #[case::unset(None, None)]
    #[case::empty(Some(""), None)]
    #[case::blank(Some("  "), None)]
    #[case::trailing_slash(Some("https://mirror.example/"), Some("https://mirror.example"))]
    #[case::plain(Some("https://mirror.example"), Some("https://mirror.example"))]
    fn endpoint_is_normalized(#[case] raw: Option<&str>, #[case] expected: Option<&str>) {
        assert_eq!(
            normalize_endpoint(raw.map(String::from)).as_deref(),
            expected
        );
    }

    /// Accepts one HTTP request, answers 404, and returns the request head.
    #[expect(clippy::unwrap_used, reason = "test helper")]
    fn capture_one_request() -> (String, std::thread::JoinHandle<String>) {
        use std::io::{BufRead, BufReader, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            while reader.read_line(&mut head).unwrap() > 2 && !head.ends_with("\r\n\r\n") {}
            let mut stream = stream;
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            head
        });
        (endpoint, handle)
    }

    #[test]
    fn token_reaches_download_request() {
        let dir = tempfile::tempdir().unwrap();
        let config = command_config("echo tok123".into());
        let token = LazyToken::new(&config);
        let (endpoint, server) = capture_one_request();
        let files = ModelFiles::new(REPO, Cache::new(dir.path().into()), Some(endpoint), &token);

        let _ = files.get("tokenizer.json").unwrap_err();

        let head = server.join().unwrap().to_ascii_lowercase();
        assert!(
            head.contains("authorization: bearer tok123"),
            "token missing from request: {head}"
        );
    }
}
