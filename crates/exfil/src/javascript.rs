//! JavaScript/Node.js-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub(crate) struct JavaScriptDetector;

impl LangExfilDetector for JavaScriptDetector {
    fn language(&self) -> Language {
        tree_sitter_javascript::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        // Match network operations:
        // - fetch(url, ...)
        // - http.request(...)
        // - https.request(...)
        // - axios.get/post(...)
        // - net.connect(...)
        r#"
        (call_expression
          function: (identifier) @fn
          (#match? @fn "^(fetch)$")
        ) @call

        (call_expression
          function: (member_expression
            object: (identifier) @obj
            property: (property_identifier) @method)
          (#match? @obj "^(http|https|axios|net)$")
          (#match? @method "^(request|get|post|put|delete|patch|connect)$")
        ) @call
        "#
    }

    fn file_source_query(&self) -> &'static str {
        // Match file reading operations:
        // - fs.readFileSync(path)
        // - fs.readFile(path, ...)
        // - require('fs').readFileSync(path)
        // - Deno.readTextFileSync(path)
        // - Bun.file(path)
        r#"
        (call_expression
          function: (member_expression
            object: (identifier) @obj
            property: (property_identifier) @method)
          arguments: (arguments
            (string) @path)
          (#match? @obj "^(fs|Deno|Bun)$")
          (#match? @method "^(readFileSync|readFile|readTextFileSync|readTextFile|file)$")
        ) @call

        (call_expression
          function: (member_expression
            object: (call_expression
              function: (identifier) @req
              (#match? @req "^(require)$"))
            property: (property_identifier) @method
            (#match? @method "^(readFileSync|readFile)$"))
        ) @call
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string) @string
        (template_string) @string
        "
    }
}
