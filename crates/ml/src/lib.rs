//! ML-based injection detection using `DeBERTa` v3.

// Ensure at least one ML backend is enabled
#[cfg(not(any(feature = "onnx", feature = "onnx-fetch", feature = "candle")))]
compile_error!(
    "At least one ML backend must be enabled: 'onnx', 'onnx-fetch' (default), or 'candle'"
);

pub mod backend;
pub mod chunker;
pub mod model;

#[cfg(feature = "candle")]
pub mod candle;
#[cfg(any(feature = "onnx", feature = "onnx-fetch"))]
pub mod onnx;

use backend::MlBackend;
use parry_guard_core::config::Config;
use parry_guard_core::Result;
use tokenizers::Tokenizer;
use tracing::{debug, info, instrument};

/// Concrete backend type selected at compile time.
#[cfg(feature = "candle")]
type Backend = candle::CandleBackend;
#[cfg(all(any(feature = "onnx", feature = "onnx-fetch"), not(feature = "candle")))]
type Backend = onnx::OnnxBackend;

/// ML scanner parameterized by backend.
pub type MlScanner = Scanner<Backend>;

struct ModelInstance<B: MlBackend> {
    backend: B,
    tokenizer: Tokenizer,
    /// Per-model threshold override. `None` means use the request threshold.
    threshold: Option<f32>,
    repo: String,
}

pub struct Scanner<B: MlBackend> {
    instances: Vec<ModelInstance<B>>,
}

impl MlScanner {
    /// Load the ML scanner with the compile-time selected backend.
    ///
    /// # Errors
    ///
    /// Returns an error if any model cannot be downloaded or loaded.
    #[instrument(skip(config))]
    pub fn load(config: &Config) -> Result<Self> {
        let model_defs = config.resolve_models()?;
        debug!(count = model_defs.len(), "loading ML scanner");

        let mut instances = Vec::with_capacity(model_defs.len());
        for def in &model_defs {
            let repo = model::hf_repo_for(config, &def.repo)?;

            let tokenizer_path = repo
                .get("tokenizer.json")
                .map_err(|e| eyre::eyre!("tokenizer download failed for {}: {e}", def.repo))?;
            let tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(|e| eyre::eyre!(e))?;
            debug!(model = %def.repo, "tokenizer loaded");

            let backend = load_backend(&repo)?;
            let threshold = def.threshold;
            info!(model = %def.repo, ?threshold, "ML backend initialized");

            instances.push(ModelInstance {
                backend,
                tokenizer,
                threshold,
                repo: def.repo.clone(),
            });
        }

        Ok(Self { instances })
    }
}

impl<B: MlBackend> Scanner<B> {
    fn score_with(instance: &mut ModelInstance<B>, text: &str) -> Result<f32> {
        let encoding = instance
            .tokenizer
            .encode(text, true)
            .map_err(|e| eyre::eyre!(e))?;

        let score = instance
            .backend
            .score(encoding.get_ids(), encoding.get_attention_mask())?;
        debug!(score, model = %instance.repo, text_len = text.len(), "chunk scored");
        Ok(score)
    }

    /// Scan text using chunked strategy. Returns true if injection detected.
    /// Uses OR ensemble: any model detecting injection returns true.
    /// Per-model threshold overrides `request_threshold` when set.
    ///
    /// # Errors
    ///
    /// Returns an error if scoring any chunk fails.
    #[instrument(skip(self, text), fields(text_len = text.len(), models = self.instances.len()))]
    pub fn scan_chunked(&mut self, text: &str, request_threshold: f32) -> Result<bool> {
        for instance in &mut self.instances {
            let threshold = instance.threshold.unwrap_or(request_threshold);
            for chunk in chunker::chunks(text) {
                let score = Self::score_with(instance, chunk)?;
                if score >= threshold {
                    debug!(score, threshold, model = %instance.repo, "injection detected in chunk");
                    return Ok(true);
                }
            }

            if let Some(head_tail) = chunker::head_tail(text) {
                let score = Self::score_with(instance, &head_tail)?;
                if score >= threshold {
                    debug!(score, threshold, model = %instance.repo, "injection detected in head+tail");
                    return Ok(true);
                }
            }
        }

        debug!("ML scan clean (all models)");
        Ok(false)
    }
}

#[cfg(feature = "candle")]
fn load_backend(repo: &hf_hub::api::sync::ApiRepo) -> Result<Backend> {
    let safetensors_path = repo
        .get("model.safetensors")
        .map_err(|e| eyre::eyre!("safetensors download failed: {e}"))?;
    let config_path = repo
        .get("config.json")
        .map_err(|e| eyre::eyre!("config download failed: {e}"))?;
    candle::CandleBackend::load(
        &safetensors_path.to_string_lossy(),
        &config_path.to_string_lossy(),
    )
}

#[cfg(all(any(feature = "onnx", feature = "onnx-fetch"), not(feature = "candle")))]
fn load_backend(repo: &hf_hub::api::sync::ApiRepo) -> Result<Backend> {
    let model_path = repo
        .get("onnx/model.onnx")
        .map_err(|e| eyre::eyre!("model download failed: {e}"))?;
    onnx::OnnxBackend::load(&model_path.to_string_lossy())
}

#[cfg(any(feature = "onnx", feature = "onnx-fetch", feature = "candle", test))]
pub(crate) fn softmax_injection_prob(logits: &[f32]) -> f32 {
    if logits.len() < 2 {
        return 0.0;
    }
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|&l| (l - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    // 1 - P(safe) handles both 2-class and 3+ class models where label 0 is "safe"
    1.0 - exps[0] / sum
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBackend {
        score: f32,
    }

    impl MlBackend for MockBackend {
        fn score(&mut self, _input_ids: &[u32], _attention_mask: &[u32]) -> Result<f32> {
            Ok(self.score)
        }
    }

    fn mock_instance(score: f32, threshold: Option<f32>, repo: &str) -> ModelInstance<MockBackend> {
        let tokenizer = Tokenizer::from_bytes(
            br###"{
            "version": "1.0",
            "model": {
                "type": "WordPiece",
                "unk_token": "[UNK]",
                "continuing_subword_prefix": "##",
                "max_input_chars_per_word": 100,
                "vocab": {"[UNK]": 0}
            }
        }"###,
        )
        .expect("minimal tokenizer");
        ModelInstance {
            backend: MockBackend { score },
            tokenizer,
            threshold,
            repo: repo.to_string(),
        }
    }

    #[test]
    fn ensemble_or_both_clean() {
        let mut scanner = Scanner {
            instances: vec![
                mock_instance(0.1, None, "model-a"),
                mock_instance(0.2, None, "model-b"),
            ],
        };
        assert!(!scanner.scan_chunked("hello", 0.5).unwrap());
    }

    #[test]
    fn ensemble_or_first_detects() {
        let mut scanner = Scanner {
            instances: vec![
                mock_instance(0.9, None, "model-a"),
                mock_instance(0.1, None, "model-b"),
            ],
        };
        assert!(scanner.scan_chunked("hello", 0.5).unwrap());
    }

    #[test]
    fn ensemble_or_second_detects() {
        let mut scanner = Scanner {
            instances: vec![
                mock_instance(0.1, None, "model-a"),
                mock_instance(0.9, None, "model-b"),
            ],
        };
        assert!(scanner.scan_chunked("hello", 0.5).unwrap());
    }

    #[test]
    fn ensemble_per_model_threshold() {
        // Per-model threshold overrides request threshold
        let mut scanner = Scanner {
            instances: vec![mock_instance(0.6, Some(0.5), "model-a")],
        };
        assert!(scanner.scan_chunked("hello", 0.9).unwrap());

        let mut scanner = Scanner {
            instances: vec![mock_instance(0.6, Some(0.7), "model-b")],
        };
        assert!(!scanner.scan_chunked("hello", 0.3).unwrap());
    }

    #[test]
    fn request_threshold_used_when_no_per_model() {
        let mut scanner = Scanner {
            instances: vec![mock_instance(0.6, None, "model-a")],
        };
        assert!(scanner.scan_chunked("hello", 0.5).unwrap());
        assert!(!scanner.scan_chunked("hello", 0.7).unwrap());
    }

    #[test]
    fn ensemble_single_model() {
        let mut scanner = Scanner {
            instances: vec![mock_instance(0.1, None, "only-model")],
        };
        assert!(!scanner.scan_chunked("hello", 0.5).unwrap());
    }

    #[test]
    fn softmax_basic() {
        let logits = [2.0, 1.0];
        let prob = softmax_injection_prob(&logits);
        assert!(prob > 0.0 && prob < 1.0);
        assert!(prob < 0.5);
    }

    #[test]
    fn softmax_injection_dominant() {
        let logits = [0.0, 5.0];
        let prob = softmax_injection_prob(&logits);
        assert!(prob > 0.9);
    }

    #[test]
    fn softmax_three_class() {
        let logits = [0.0, 5.0, 3.0];
        let prob = softmax_injection_prob(&logits);
        assert!(prob > 0.9);

        let logits = [5.0, 0.0, 0.0];
        let prob = softmax_injection_prob(&logits);
        assert!(prob < 0.1);
    }

    #[test]
    fn softmax_two_class_equivalence() {
        // For 2-class, 1 - exps[0]/sum == exps[1]/sum
        let logits = [1.5, 3.2];
        let prob = softmax_injection_prob(&logits);
        let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let exps: Vec<f32> = logits.iter().map(|&l| (l - max).exp()).collect();
        let sum: f32 = exps.iter().sum();
        let old_way = exps[1] / sum;
        assert!((prob - old_way).abs() < 1e-6);
    }
}
