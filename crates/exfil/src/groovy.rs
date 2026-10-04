//! Groovy exfil detector.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub(crate) struct GroovyDetector;

impl LangExfilDetector for GroovyDetector {
    fn language(&self) -> Language {
        tree_sitter_groovy::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        r#"
        (identifier) @fn
        (#match? @fn "(openConnection|getText|execute|post|get|URL|HttpURLConnection|Socket)")
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string_literal) @string
        "
    }
}
