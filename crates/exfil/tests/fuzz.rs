//! Fuzz targets. `cargo test` runs them briefly with random inputs;
//! `cargo bolero test -p parry-guard-exfil --test fuzz <name>` runs them under libFuzzer.

use parry_guard_exfil::detect_exfiltration;

#[test]
fn exfiltration() {
    bolero::check!().with_type::<String>().for_each(|command| {
        let _ = detect_exfiltration(command);
    });
}
