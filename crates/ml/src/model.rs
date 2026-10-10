//! `HuggingFace` model download/caching.

use eyre::WrapErr;
use parry_guard_core::{ExposeSecret, Result, SecretString};
use tracing::debug;

/// # Errors
/// Fails if the `HuggingFace` API client can't be built.
pub fn hf_repo_for(token: Option<&SecretString>, repo: &str) -> Result<hf_hub::api::sync::ApiRepo> {
    use hf_hub::api::sync::ApiBuilder;

    let mut builder = ApiBuilder::new();
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

    debug!(repo, "HuggingFace repo handle created");
    Ok(api.model(repo.to_string()))
}
