//! ML backend trait.

use parry_guard_core::Result;

pub trait MlBackend: Send {
    /// Score the given token IDs for injection probability.
    ///
    /// # Errors
    ///
    /// Returns an error if inference fails.
    fn score(&mut self, input_ids: &[u32], attention_mask: &[u32]) -> Result<f32>;
}
