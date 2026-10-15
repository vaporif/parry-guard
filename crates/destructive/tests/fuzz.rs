//! Fuzz targets. `cargo test` runs them briefly with random inputs;
//! `cargo bolero test -p parry-guard-destructive --test fuzz <name>` runs them under libFuzzer.

use parry_guard_destructive::{detect_destructive, is_protected_path};

#[test]
fn destructive() {
    bolero::check!()
        .with_type::<(String, String)>()
        .for_each(|(command, cwd)| {
            let _ = detect_destructive(command, cwd);
        });
}

#[test]
fn protected_path() {
    bolero::check!()
        .with_type::<(String, String)>()
        .for_each(|(path, cwd)| {
            let _ = is_protected_path(path, cwd);
        });
}
