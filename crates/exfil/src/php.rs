//! PHP-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub struct PhpDetector;

impl LangExfilDetector for PhpDetector {
    fn language(&self) -> Language {
        tree_sitter_php::LANGUAGE_PHP.into()
    }

    fn network_sink_query(&self) -> &'static str {
        // Match network operations:
        // - curl_exec(...)
        // - file_get_contents('http...')
        // - fopen('http...')
        // - fsockopen(...)
        r#"
        (function_call_expression
          function: (name) @fn
          (#match? @fn "^(curl_exec|curl_init|file_get_contents|fopen|fsockopen|stream_socket_client)$")
        ) @call
        "#
    }

    fn file_source_query(&self) -> &'static str {
        // Match file reading operations:
        // - file_get_contents(path)
        // - fopen(path, 'r')
        // - file(path)
        // - readfile(path)
        r#"
        (function_call_expression
          function: (name) @fn
          arguments: (arguments
            (argument
              (string) @path))
          (#match? @fn "^(file_get_contents|fopen|file|readfile|fread|fgets)$")
        ) @call
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string) @string
        (encapsed_string) @string
        "
    }
}
