//! Fuzz targets. `cargo test` runs them briefly with random inputs;
//! `cargo bolero test -p parry-guard-core --test fuzz <name>` runs them under libFuzzer.

use parry_guard_core::decode::decode_variants;
use parry_guard_core::shell::unquote;
use parry_guard_core::{scan_injection_only, scan_text_fast};

#[test]
fn scan_text() {
    bolero::check!().with_type::<String>().for_each(|text| {
        let _ = scan_text_fast(text);
        let _ = scan_injection_only(text);
    });
}

#[test]
fn decode() {
    bolero::check!().with_type::<String>().for_each(|text| {
        let _ = decode_variants(text);
    });
}

#[test]
fn shell_unquote() {
    bolero::check!().with_type::<String>().for_each(|text| {
        let _ = unquote(text);
    });
}
