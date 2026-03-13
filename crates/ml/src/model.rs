//! `HuggingFace` model download/caching.

use eyre::WrapErr;
use parry_guard_core::config::Config;
use parry_guard_core::Result;
use tracing::debug;

/// Get a `HuggingFace` Hub repo handle for an arbitrary model repo.
///
/// # Errors
///
/// Returns an error if the `HuggingFace` API client cannot be built.
pub fn hf_repo_for(config: &Config, repo: &str) -> Result<hf_hub::api::sync::ApiRepo> {
    use hf_hub::api::sync::ApiBuilder;

    let mut builder = ApiBuilder::new();
    if let Some(ref token) = config.hf_token {
        debug!("using HuggingFace token from config");
        builder = builder.with_token(Some(token.clone()));
    } else {
        debug!("no HuggingFace token configured");
    }
    let api = builder
        .build()
        .wrap_err("failed to build HuggingFace API client")?;

    debug!(repo, "HuggingFace repo handle created");
    Ok(api.model(repo.to_string()))
}
