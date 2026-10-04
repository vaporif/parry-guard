//! Nix exfil detector.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub(crate) struct NixDetector;

impl LangExfilDetector for NixDetector {
    fn language(&self) -> Language {
        tree_sitter_nix::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        r#"
        (identifier) @fn
        (#match? @fn "(fetchurl|fetchTarball|fetchFromGitHub|fetchgit|fetchzip|curl|wget)")
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        // Nix file paths are bare `./path` expressions, not strings
        r"
        (string_expression) @string
        (indented_string_expression) @string
        (path_expression) @string
        "
    }
}
