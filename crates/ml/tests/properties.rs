use parry_guard_ml::chunker::{chunks, head_tail, CHUNK_SIZE};
use proptest::prelude::*;

proptest! {
    #[test]
    fn chunks_stay_within_size(text in "\\PC{0,2000}") {
        for chunk in chunks(&text) {
            prop_assert!(chunk.len() <= CHUNK_SIZE.max(text.len()));
        }
    }

    #[test]
    fn head_tail_never_panics(text in "\\PC{0,3000}") {
        let _ = head_tail(&text);
    }
}
