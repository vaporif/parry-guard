//! PowerShell-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub struct PowerShellDetector;

impl LangExfilDetector for PowerShellDetector {
    fn language(&self) -> Language {
        tree_sitter_powershell::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        // Match network operations:
        // - Invoke-WebRequest
        // - Invoke-RestMethod
        // - New-Object Net.WebClient
        // - System.Net.WebClient
        // - [Net.WebClient]::new()
        r#"
        (command
          command_name: (_) @cmd
          (#match? @cmd "(?i)(invoke-webrequest|invoke-restmethod|wget|curl|iwr|irm)")
        ) @call

        (command
          command_name: (_) @cmd
          command_elements: (_) @args
          (#match? @cmd "(?i)new-object")
          (#match? @args "(?i)(net\\.webclient|net\\.sockets)")
        ) @call
        "#
    }

    fn file_source_query(&self) -> &'static str {
        // Match file reading operations:
        // - Get-Content
        // - [IO.File]::ReadAllText
        // - type (alias for Get-Content)
        r#"
        (command
          command_name: (_) @cmd
          (#match? @cmd "(?i)(get-content|gc|type|cat)")
        ) @call
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string_literal) @string
        (expandable_string_literal) @string
        "
    }
}
