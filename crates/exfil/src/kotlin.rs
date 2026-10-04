//! Kotlin-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub(crate) struct KotlinDetector;

impl LangExfilDetector for KotlinDetector {
    fn language(&self) -> Language {
        tree_sitter_kotlin_ng::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        r#"
        (identifier) @fn
        (#match? @fn "(readText|openConnection|execute|post|get|request|URL|HttpURLConnection|Socket|OkHttpClient)")
        "#
    }

    fn file_source_query(&self) -> &'static str {
        r#"
        (identifier) @fn
        (#match? @fn "(readText|readLines|readBytes|bufferedReader|reader|File|FileReader|FileInputStream|BufferedReader)")
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string_literal) @string
        (multiline_string_literal) @string
        "
    }
}
