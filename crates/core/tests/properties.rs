use parry_guard_core::decode::{decode_variants, normalize};
use parry_guard_core::secrets::has_secret;
use parry_guard_core::substring::has_security_substring;
use parry_guard_core::unicode::{
    has_homoglyphs, has_invisible_unicode, normalize_homoglyphs, strip_invisible,
};
use parry_guard_core::{scan_injection_only, scan_text_fast};
use proptest::prelude::*;

proptest! {
    #[test]
    fn decode_variants_is_bounded(text in any::<String>()) {
        let variants = decode_variants(&text);
        prop_assert!(!variants.is_empty());
        prop_assert!(variants.len() <= 8);
    }

    #[test]
    fn decode_variants_has_no_duplicates(text in any::<String>()) {
        let variants = decode_variants(&text);
        let unique: std::collections::HashSet<_> = variants.iter().collect();
        prop_assert_eq!(unique.len(), variants.len());
    }

    #[test]
    fn normalize_collapses_whitespace(text in any::<String>()) {
        let out = normalize(&text);
        let mut prev_ws = false;
        for c in out.chars() {
            prop_assert!(!(c.is_whitespace() && prev_ws), "consecutive whitespace in {out:?}");
            prop_assert!(!c.is_whitespace() || c == ' ', "non-space whitespace in {out:?}");
            prev_ws = c.is_whitespace();
        }
    }

    #[test]
    fn strip_invisible_leaves_nothing_to_flag(text in any::<String>()) {
        let stripped = strip_invisible(&text);
        prop_assert!(!has_invisible_unicode(&stripped));
        prop_assert_eq!(strip_invisible(&stripped), stripped);
    }

    #[test]
    fn normalize_homoglyphs_leaves_nothing_to_flag(text in any::<String>()) {
        prop_assert!(!has_homoglyphs(&normalize_homoglyphs(&text)));
    }

    #[test]
    fn scanners_never_panic(text in any::<String>()) {
        let _ = scan_text_fast(&text);
        let _ = scan_injection_only(&text);
        let _ = has_secret(&text);
        let _ = has_security_substring(&text);
    }
}
