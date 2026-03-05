//! Text chunking strategy for ML scanning.

pub const CHUNK_SIZE: usize = 256;
pub const CHUNK_OVERLAP: usize = 25;
const HEAD_TAIL_THRESHOLD: usize = 1024;
const HEAD_TAIL_SIZE: usize = 512;

/// Yields overlapping chunks of text for ML scanning.
/// For short text (<= `CHUNK_SIZE`), yields a single chunk.
/// For long text, yields sliding windows + a head+tail chunk.
#[must_use]
pub fn chunks(text: &str) -> Vec<&str> {
    if text.len() <= CHUNK_SIZE {
        return vec![text];
    }

    let step = CHUNK_SIZE - CHUNK_OVERLAP;
    let mut result = Vec::new();

    let mut start = 0;
    while start < text.len() {
        let end = text.floor_char_boundary((start + CHUNK_SIZE).min(text.len()));
        let chunk = &text[start..end];
        if !chunk.trim().is_empty() {
            result.push(chunk);
        }
        start = text.floor_char_boundary(start + step);
    }

    result
}

/// Returns the head and tail concatenated (space-separated) for texts longer than 1024 chars.
/// Returns `None` when input is shorter than `HEAD_TAIL_THRESHOLD`.
/// Catches injection appended at the very end.
#[must_use]
pub fn head_tail(text: &str) -> Option<String> {
    if text.len() <= HEAD_TAIL_THRESHOLD {
        return None;
    }
    let head_end = text.floor_char_boundary(HEAD_TAIL_SIZE.min(text.len()));
    let head = &text[..head_end];
    let tail_start = text.floor_char_boundary(text.len().saturating_sub(HEAD_TAIL_SIZE));
    let tail = &text[tail_start..];
    Some(format!("{head} {tail}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_text_single_chunk() {
        let text = "short";
        let c = chunks(text);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0], "short");
    }

    #[test]
    fn long_text_multiple_chunks() {
        let text = "a".repeat(600);
        let c = chunks(&text);
        assert!(c.len() > 1);
        // Each chunk should be <= CHUNK_SIZE
        for chunk in &c {
            assert!(chunk.len() <= CHUNK_SIZE);
        }
    }

    #[test]
    fn chunks_overlap() {
        let text = "a".repeat(300);
        let c = chunks(&text);
        assert_eq!(c.len(), 2);
        // First chunk: 0..256, second chunk: 231..300
        assert_eq!(c[0].len(), CHUNK_SIZE);
    }

    #[test]
    fn head_tail_none_for_short() {
        assert!(head_tail("short text").is_none());
        assert!(head_tail(&"a".repeat(1024)).is_none());
    }

    #[test]
    fn head_tail_some_for_long() {
        let text = "a".repeat(2000);
        let combined = head_tail(&text).unwrap();
        // head(512) + " " + tail(512) = 1025
        assert_eq!(combined.len(), 1025);
    }

    #[test]
    fn chunks_multibyte_at_boundary() {
        // 'ñ' is 2 bytes; place it so a chunk boundary falls inside it
        let text = "a".repeat(255) + "ñ" + &"b".repeat(100);
        let c = chunks(&text);
        for chunk in &c {
            // Every chunk must be valid UTF-8 (implicit via &str, but
            // floor_char_boundary is what prevents the panic)
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn chunks_emoji_at_boundary() {
        // '🔥' is 4 bytes
        let text = "a".repeat(254) + "🔥" + &"b".repeat(100);
        let c = chunks(&text);
        for chunk in &c {
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn head_tail_with_multibyte() {
        // Place multi-byte chars around the 512-byte head/tail cut points
        let text = "a".repeat(511) + "ñ" + &"b".repeat(1000) + "🔥" + &"c".repeat(100);
        let combined = head_tail(&text).unwrap();
        assert!(!combined.is_empty());
    }
}
