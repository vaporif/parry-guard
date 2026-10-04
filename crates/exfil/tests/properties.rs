use parry_guard_exfil::detect_exfiltration;
use parry_guard_exfil::patterns::{MatchKind, Pattern};
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

fn match_kind() -> impl Strategy<Value = MatchKind> {
    prop_oneof![
        Just(MatchKind::PathSegment),
        Just(MatchKind::Suffix),
        Just(MatchKind::Substring),
    ]
}

proptest! {
    #[test]
    fn detect_exfiltration_never_panics(command in shell_like()) {
        let _ = detect_exfiltration(&command);
    }

    #[test]
    fn pattern_matches_never_panics(
        value in "\\PC{0,8}",
        kind in match_kind(),
        before in "\\PC{0,16}",
        after in "\\PC{0,16}",
    ) {
        // embed the pattern so the matcher's scanning loops actually run
        let text = format!("{before}{value}{after}");
        let _ = Pattern::new(value, kind).matches(&text);
    }

    #[test]
    fn quoted_path_segment_is_always_found(
        value in "[a-zéñ🔥.]{1,8}",
        before in "\\PC{0,16}",
        after in "\\PC{0,16}",
    ) {
        // an earlier unbounded occurrence must not stop the scan before the quoted one
        let text = format!("{before}{value}{after} '{value}'");
        prop_assert!(Pattern::path_segment(value).matches(&text), "{text:?}");
    }
}
