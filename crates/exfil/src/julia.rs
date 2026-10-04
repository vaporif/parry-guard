//! Julia-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub(crate) struct JuliaDetector;

impl LangExfilDetector for JuliaDetector {
    fn language(&self) -> Language {
        tree_sitter_julia::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        r#"
        (call_expression
          (field_expression) @fn
          (#match? @fn "(HTTP|Downloads)\\.(request|get|post|put|download)")
        ) @call

        (call_expression
          (identifier) @fn
          (#match? @fn "^(download|request)$")
        ) @call
        "#
    }

    fn file_source_query(&self) -> &'static str {
        r#"
        (call_expression
          (identifier) @fn
          (#match? @fn "^(read|open|readlines|readchomp|readline)$")
        ) @call
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string_literal) @string
        "
    }
}
