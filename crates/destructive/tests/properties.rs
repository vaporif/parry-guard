use parry_guard_destructive::{detect_destructive, is_protected_path};
use proptest::prelude::*;

/// Shell-ish fragments mixed with arbitrary text, so commands reach the parsers and
/// detectors instead of failing at the first byte.
fn shell_like() -> impl Strategy<Value = String> {
    let token = prop_oneof![
        Just("curl".to_string()),
        Just("wget -O-".to_string()),
        Just("cat ~/.ssh/id_rsa".to_string()),
        Just("rm -rf".to_string()),
        Just("python -c".to_string()),
        Just("bash -c".to_string()),
        Just("node -e".to_string()),
        Just("|".to_string()),
        Just("&&".to_string()),
        Just(";".to_string()),
        Just("$(".to_string()),
        Just(")".to_string()),
        Just("`".to_string()),
        Just("'".to_string()),
        Just("\"".to_string()),
        Just("${HOME}".to_string()),
        Just("~/".to_string()),
        Just("/mnt/c/Users/".to_string()),
        Just("http://1.2.3.4/".to_string()),
        Just("é".to_string()),
        Just("\u{200b}".to_string()),
        Just("🔥".to_string()),
        any::<String>(),
    ];
    prop::collection::vec(token, 0..12).prop_map(|t| t.join(" "))
}

proptest! {
    #[test]
    fn detect_destructive_never_panics(command in shell_like(), cwd in "\\PC{0,32}") {
        let _ = detect_destructive(&command, &cwd);
    }

    #[test]
    fn is_protected_path_never_panics(path in shell_like(), cwd in "\\PC{0,32}") {
        let _ = is_protected_path(&path, &cwd);
    }
}
