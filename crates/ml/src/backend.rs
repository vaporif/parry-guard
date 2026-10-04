//! ML backend trait.

use parry_guard_core::Result;

pub trait MlBackend: Send {
    /// Injection probability for the token IDs.
    ///
    /// # Errors
    /// Fails if inference fails.
    fn score(&mut self, input_ids: &[u32], attention_mask: &[u32]) -> Result<f32>;
}
