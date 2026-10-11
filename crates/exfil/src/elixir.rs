//! Elixir exfil detector.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub(crate) struct ElixirDetector;

impl LangExfilDetector for ElixirDetector {
    fn language(&self) -> Language {
        tree_sitter_elixir::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        r#"
        (identifier) @fn
        (#match? @fn "^(get|post|put|delete|request|get!|post!)$")
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string) @string
        "
    }
}
