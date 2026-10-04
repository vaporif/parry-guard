//! Perl exfil detector.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub(crate) struct PerlDetector;

impl LangExfilDetector for PerlDetector {
    fn language(&self) -> Language {
        tree_sitter_perl::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        r#"
        (identifier) @fn
        (#match? @fn "(get|post|request|socket|connect|LWP|HTTP|IO::Socket)")
        "#
    }

    fn file_source_query(&self) -> &'static str {
        r#"
        (identifier) @fn
        (#match? @fn "(open|read|slurp)")
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string_single_quoted) @string
        (string_double_quoted) @string
        (string_q_quoted) @string
        (string_qq_quoted) @string
        "
    }
}
