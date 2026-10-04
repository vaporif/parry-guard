//! Python exfil detector.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub(crate) struct PythonDetector;

impl LangExfilDetector for PythonDetector {
    fn language(&self) -> Language {
        tree_sitter_python::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        r#"
        (call
          function: [
            ;; urllib.request.urlopen or urllib.urlopen
            (attribute
              object: (attribute) @obj
              attribute: (identifier) @method)
            (attribute
              object: (identifier) @obj
              attribute: (identifier) @method)
          ]
          (#match? @method "^(urlopen|get|post|put|delete|patch|request|connect|create_connection)$")
        ) @call

        (call
          function: (identifier) @fn
          (#match? @fn "^(urlopen)$")
        ) @call
        "#
    }

    fn file_source_query(&self) -> &'static str {
        r#"
        (call
          function: (identifier) @fn
          arguments: (argument_list
            (string) @path)
          (#match? @fn "^(open)$")
        ) @call

        (call
          function: (attribute
            object: (call
              function: (identifier) @fn
              (#match? @fn "^(open)$"))
            attribute: (identifier) @method
            (#match? @method "^(read|readlines|readline)$"))
        ) @call
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string) @string
        "
    }
}
