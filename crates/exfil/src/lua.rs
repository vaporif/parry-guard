//! Lua-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub(crate) struct LuaDetector;

impl LangExfilDetector for LuaDetector {
    fn language(&self) -> Language {
        tree_sitter_lua::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        r#"
        (function_call
          name: [
            (dot_index_expression) @fn
            (identifier) @fn
          ]
          (#match? @fn "(http|socket|request|connect)")
        ) @call
        "#
    }

    fn file_source_query(&self) -> &'static str {
        r#"
        (function_call
          name: [
            (dot_index_expression) @fn
            (method_index_expression) @fn
          ]
          (#match? @fn "(open|read|lines)")
        ) @call
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string) @string
        "
    }
}
