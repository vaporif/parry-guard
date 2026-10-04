//! R exfil detector.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub(crate) struct RDetector;

impl LangExfilDetector for RDetector {
    fn language(&self) -> Language {
        tree_sitter_r::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        r#"
        (identifier) @fn
        (#match? @fn "(GET|POST|httr|curl|download\\.file|url|RCurl)")
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string) @string
        "
    }
}
