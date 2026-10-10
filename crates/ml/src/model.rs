//! `HuggingFace` model download/caching.

use std::cell::OnceCell;
use std::path::PathBuf;

use eyre::WrapErr;
use hf_hub::{HFClient, HFClientSync, HFError, HFRepositorySync, RepoTypeModel};
use parry_guard_core::config::Config;
use parry_guard_core::{ExposeSecret, Result, SecretString};
use tracing::{debug, warn};

/// Used when `HF_ENDPOINT` is unset or blank; hf-hub would otherwise reread the raw variable.
const DEFAULT_ENDPOINT: &str = "https://huggingface.co";

/// Hub access for one model load: clients are built once, the token at most once.
///
/// A failing token command isn't fatal: downloads go ahead without it (hf-hub may
/// still use `HF_TOKEN` or its own `$HF_HOME/token`), and a gated model that then
/// fails to download reports the command's error.
pub struct Hub<'a> {
    config: &'a Config,
    cache_dir: PathBuf,
    endpoint: String,
    token: OnceCell<std::result::Result<Option<SecretString>, String>>,
    // building a client loads TLS roots and spawns a runtime thread, so reuse them
    offline: OnceCell<HFClientSync>,
    online: OnceCell<HFClientSync>,
}

impl<'a> Hub<'a> {
    /// Honors `HF_HUB_CACHE`, `HF_HOME` and `HF_ENDPOINT`. The token is sent to that endpoint.
    #[must_use]
    pub fn from_env(config: &'a Config) -> Self {
        Self::new(
            config,
            hf_hub::resolve_cache_dir(),
            normalize_endpoint(std::env::var("HF_ENDPOINT").ok()),
        )
    }

    fn new(config: &'a Config, cache_dir: PathBuf, endpoint: Option<String>) -> Self {
        Self {
            config,
            cache_dir,
            endpoint: endpoint.unwrap_or_else(|| DEFAULT_ENDPOINT.to_string()),
            token: OnceCell::new(),
            offline: OnceCell::new(),
            online: OnceCell::new(),
        }
    }

    #[must_use]
    pub fn repo(&self, repo: &str) -> ModelFiles<'_> {
        ModelFiles {
            hub: self,
            repo: repo.to_string(),
        }
    }

    fn token(&self) -> std::result::Result<Option<&SecretString>, &str> {
        self.token
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

    fn offline_client(&self) -> Result<&HFClientSync> {
        get_or_build(&self.offline, || self.build_client(None))
    }

    fn online_client(&self) -> Result<&HFClientSync> {
        get_or_build(&self.online, || {
            self.build_client(self.token().ok().flatten())
        })
    }

    fn build_client(&self, token: Option<&SecretString>) -> Result<HFClientSync> {
        let mut builder = HFClient::builder()
            .cache_dir(&self.cache_dir)
            .endpoint(&self.endpoint);
        if let Some(token) = token {
            debug!("using HuggingFace token from config");
            // hf-hub only takes a plain String
            builder = builder.token(token.expose_secret());
        } else {
            debug!("no HuggingFace token configured");
        }
        builder
            .build_sync()
            .wrap_err("failed to build HuggingFace API client")
    }
}

fn get_or_build<T>(cell: &OnceCell<T>, build: impl FnOnce() -> Result<T>) -> Result<&T> {
    if let Some(value) = cell.get() {
        return Ok(value);
    }
    let value = build()?;
    Ok(cell.get_or_init(|| value))
}

/// Files of one `HuggingFace` repo.
pub struct ModelFiles<'a> {
    hub: &'a Hub<'a>,
    repo: String,
}

impl ModelFiles<'_> {
    /// Local path of `filename`, downloading it if needed.
    /// Only a download resolves the token, so a cached model never runs the token command.
    ///
    /// # Errors
    /// Fails if the file isn't cached and can't be downloaded.
    pub fn get(&self, filename: &str) -> Result<PathBuf> {
        let cached = self
            .handle(self.hub.offline_client()?)
            .download_file()
            .filename(filename)
            .local_files_only(true)
            .send();
        match cached {
            Ok(path) => {
                debug!(repo = %self.repo, filename, "cache hit");
                return Ok(path);
            }
            Err(HFError::LocalEntryNotFound { .. }) => {}
            Err(e) => debug!(repo = %self.repo, filename, %e, "cache lookup failed"),
        }
        self.handle(self.hub.online_client()?)
            .download_file()
            .filename(filename)
            .send()
            .map_err(|e| {
                if let Err(token_err) = self.hub.token() {
                    eyre::eyre!("{e} ({token_err})")
                } else {
                    eyre::eyre!("{e}")
                }
            })
    }

    fn handle(&self, client: &HFClientSync) -> HFRepositorySync<RepoTypeModel> {
        let (owner, name) = hf_hub::split_id(&self.repo);
        client.model(owner, name)
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
        let hub = Hub::new(&config, dir.path().into(), None);
        let files = hub.repo(REPO);

        let path = files.get("tokenizer.json").unwrap();

        assert!(path.ends_with("tokenizer.json"), "got {}", path.display());
        assert!(!marker.exists(), "token command ran for a cached file");
    }

    #[test]
    fn failed_token_command_still_attempts_download() {
        let dir = tempfile::tempdir().unwrap();
        let config = command_config("echo 'vault locked' >&2; exit 1".into());
        let hub = Hub::new(&config, dir.path().into(), Some(UNREACHABLE.into()));
        let files = hub.repo(REPO);

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
        let hub = Hub::new(&config, dir.path().join("hub"), Some(UNREACHABLE.into()));
        let first = hub.repo(REPO);
        let second = hub.repo("org/other");

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
            // Stops at the blank line ending the head ("\r\n", 2 bytes) or at EOF.
            while reader.read_line(&mut head).unwrap() > 2 {}
            let mut stream = stream;
            let response = [
                "HTTP/1.1 404 Not Found",
                "Content-Length: 0",
                "Connection: close",
                "",
                "",
            ]
            .join("\r\n");
            stream.write_all(response.as_bytes()).unwrap();
            head
        });
        (endpoint, handle)
    }

    #[test]
    fn token_reaches_download_request() {
        let dir = tempfile::tempdir().unwrap();
        let config = command_config("echo tok123".into());
        let (endpoint, server) = capture_one_request();
        let hub = Hub::new(&config, dir.path().into(), Some(endpoint));
        let files = hub.repo(REPO);

        let _ = files.get("tokenizer.json").unwrap_err();

        let head = server.join().unwrap().to_ascii_lowercase();
        assert!(
            head.contains("authorization: bearer tok123"),
            "token missing from request: {head}"
        );
    }
}
