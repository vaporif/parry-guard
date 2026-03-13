//! Candle ML backend

use candle_core::{Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::debertav2::{
    Config as DebertaV2Config, DebertaV2SeqClassificationModel, DTYPE,
};

use std::collections::HashMap;

use parry_guard_core::Result;

pub struct CandleBackend {
    model: DebertaV2SeqClassificationModel,
    device: Device,
}

impl CandleBackend {
    /// # Errors
    ///
    /// Returns an error if the safetensors model or config cannot be loaded.
    ///
    /// # Safety
    ///
    /// Uses memory-mapped safetensors via `VarBuilder::from_mmaped_safetensors`.
    pub fn load(safetensors_path: &str, config_path: &str) -> Result<Self> {
        let device = Device::Cpu;

        let config_str = std::fs::read_to_string(config_path)?;
        let config: DebertaV2Config = serde_json::from_str(&config_str)?;

        let vb =
            unsafe { VarBuilder::from_mmaped_safetensors(&[safetensors_path], DTYPE, &device)? };
        let vb = vb.set_prefix("deberta");

        let id2label = config
            .id2label
            .clone()
            .or_else(|| Some(HashMap::from([(0, "SAFE".into()), (1, "INJECTION".into())])));
        let model = DebertaV2SeqClassificationModel::load(vb, &config, id2label)?;

        Ok(Self { model, device })
    }
}

impl super::backend::MlBackend for CandleBackend {
    fn score(&mut self, input_ids: &[u32], attention_mask: &[u32]) -> Result<f32> {
        let input_ids_t = Tensor::new(input_ids, &self.device)?.unsqueeze(0)?;
        let attention_mask_t = Tensor::new(attention_mask, &self.device)?.unsqueeze(0)?;
        let token_type_ids = input_ids_t.zeros_like()?;

        let logits =
            self.model
                .forward(&input_ids_t, Some(token_type_ids), Some(attention_mask_t))?;

        let logits_vec: Vec<f32> = logits.squeeze(0)?.to_vec1()?;
        Ok(super::softmax_injection_prob(&logits_vec))
    }
}
