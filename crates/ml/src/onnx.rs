//! ONNX Runtime ML backend.

use ort::session::Session;
use ort::value::Tensor;
use parry_guard_core::Result;

pub struct OnnxBackend {
    session: Session,
}

impl OnnxBackend {
    /// # Errors
    ///
    /// Returns an error if the ONNX session cannot be loaded.
    pub fn load(model_path: &str) -> Result<Self> {
        let builder = Session::builder()?;

        #[cfg(feature = "onnx-coreml")]
        let builder = builder.with_execution_providers([
            ort::execution_providers::CoreMLExecutionProvider::default().build(),
        ])?;

        let session = builder.commit_from_file(model_path)?;
        Ok(Self { session })
    }
}

impl super::backend::MlBackend for OnnxBackend {
    fn score(&mut self, input_ids: &[u32], attention_mask: &[u32]) -> Result<f32> {
        let ids: Vec<i64> = input_ids.iter().map(|&id| i64::from(id)).collect();
        let mask: Vec<i64> = attention_mask.iter().map(|&m| i64::from(m)).collect();
        let len = i64::try_from(ids.len())?;
        let shape = vec![1i64, len];
        let input_ids_tensor = Tensor::from_array((shape.clone(), ids))?;
        let attention_mask_tensor = Tensor::from_array((shape, mask))?;

        let outputs = self
            .session
            .run(ort::inputs![input_ids_tensor, attention_mask_tensor])?;

        let logits_view = outputs[0].try_extract_array::<f32>()?;
        let logits = logits_view
            .as_slice()
            .ok_or_else(|| eyre::eyre!("non-contiguous logits tensor"))?;

        Ok(super::softmax_injection_prob(logits))
    }
}
