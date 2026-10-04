//! Ruby exfil detector.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub(crate) struct RubyDetector;

impl LangExfilDetector for RubyDetector {
    fn language(&self) -> Language {
        tree_sitter_ruby::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        r#"
        (call
          method: (identifier) @method
          (#match? @method "^(get|post|put|delete|patch|new|open)$")
        ) @call

        (call
          receiver: (scope_resolution) @receiver
          method: (identifier) @method
          (#match? @method "^(get|post|put|delete|new|start)$")
        ) @call
        "#
    }

    fn file_source_query(&self) -> &'static str {
        r#"
        (call
          receiver: (constant) @receiver
          method: (identifier) @method
          arguments: (argument_list
            (string) @path)
          (#match? @receiver "^(File|IO)$")
          (#match? @method "^(read|read!|open|readlines)$")
        ) @call
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string) @string
        "
    }
}
