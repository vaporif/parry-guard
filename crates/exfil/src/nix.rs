//! Nix-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub struct NixDetector;

impl LangExfilDetector for NixDetector {
    fn language(&self) -> Language {
        tree_sitter_nix::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        // Match network operations:
        // - builtins.fetchurl
        // - builtins.fetchTarball
        // - fetchFromGitHub
        // - pkgs.fetchurl
        r#"
        (identifier) @fn
        (#match? @fn "(fetchurl|fetchTarball|fetchFromGitHub|fetchgit|fetchzip|curl|wget)")
        "#
    }

    fn file_source_query(&self) -> &'static str {
        // Match file reading operations:
        // - builtins.readFile
        // - builtins.readDir
        // - import
        r#"
        (identifier) @fn
        (#match? @fn "(readFile|readDir|pathExists|import)")
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        // Include path expressions since Nix uses ./path syntax for file paths
        r"
        (string_expression) @string
        (indented_string_expression) @string
        (path_expression) @string
        "
    }
}
