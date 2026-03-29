//! Interpreter and shell inline code detection.
//!
//! Detects exfiltration in `python -c "..."`, `node -e "..."`, `bash -c "..."`, etc.
//! Uses AST-based detection for supported languages, keyword matching as fallback.

use tree_sitter::Node;

use crate::consts::{CODE_NETWORK_INDICATORS, INLINE_CODE_FLAGS};
use crate::lang::detect_exfil_in_code;
use crate::patterns;
use crate::util::{contains_ip_url, has_sensitive_path, node_text};

use crate::elixir::ElixirDetector;
use crate::groovy::GroovyDetector;
use crate::javascript::JavaScriptDetector;
use crate::julia::JuliaDetector;
use crate::kotlin::KotlinDetector;
use crate::lua::LuaDetector;
use crate::nix::NixDetector;
use crate::perl::PerlDetector;
use crate::php::PhpDetector;
use crate::powershell::PowerShellDetector;
use crate::python::PythonDetector;
use crate::r::RDetector;
use crate::ruby::RubyDetector;
use crate::scala::ScalaDetector;

pub fn check_interpreter_inline_code(node: Node, source: &[u8], cmd_name: &str) -> Option<String> {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    let mut i = 0;
    while i < children.len() {
        let child = children[i];
        let text = node_text(child, source);

        if INLINE_CODE_FLAGS.contains(&text) {
            // Next sibling is the code string
            if let Some(&code_node) = children.get(i + 1) {
                let code_str = extract_string_content(code_node, source);

                // Try AST-based detection first for supported languages
                if let Some(reason) = try_ast_detection(&code_str, cmd_name) {
                    return Some(reason);
                }

                // Fall back to keyword matching
                if let Some(reason) = check_code_string_for_exfil(&code_str, cmd_name) {
                    return Some(reason);
                }
            }
        }
        i += 1;
    }
    None
}

/// Try AST-based detection for supported languages.
fn try_ast_detection(code: &str, cmd_name: &str) -> Option<String> {
    let base = cmd_name
        .rsplit('/')
        .next()
        .unwrap_or(cmd_name)
        .to_lowercase();

    match base.as_str() {
        // Python
        "python" | "python2" | "python3" | "pypy" | "pypy3" => {
            detect_exfil_in_code(code, &PythonDetector, cmd_name)
        }
        // JavaScript/TypeScript
        "node" | "nodejs" | "deno" | "bun" => {
            detect_exfil_in_code(code, &JavaScriptDetector, cmd_name)
        }
        // Ruby
        "ruby" | "jruby" => detect_exfil_in_code(code, &RubyDetector, cmd_name),
        // PHP
        "php" | "php-cgi" => detect_exfil_in_code(code, &PhpDetector, cmd_name),
        // Perl
        "perl" => detect_exfil_in_code(code, &PerlDetector, cmd_name),
        // Lua
        "lua" => detect_exfil_in_code(code, &LuaDetector, cmd_name),
        // PowerShell
        "pwsh" | "powershell" => detect_exfil_in_code(code, &PowerShellDetector, cmd_name),
        // R
        "r" | "rscript" => detect_exfil_in_code(code, &RDetector, cmd_name),
        // Elixir
        "elixir" => detect_exfil_in_code(code, &ElixirDetector, cmd_name),
        // Julia
        "julia" => detect_exfil_in_code(code, &JuliaDetector, cmd_name),
        // JVM scripting
        "groovy" => detect_exfil_in_code(code, &GroovyDetector, cmd_name),
        "scala" => detect_exfil_in_code(code, &ScalaDetector, cmd_name),
        "kotlin" | "kotlinc" => detect_exfil_in_code(code, &KotlinDetector, cmd_name),
        // Nix
        "nix" | "nix-shell" | "nix-build" | "nix-instantiate" => {
            detect_exfil_in_code(code, &NixDetector, cmd_name)
        }
        // No AST support: jshell, tclsh, wish, osascript, awk, sed - fall through to keyword matching
        _ => None,
    }
}

fn extract_string_content(node: Node, source: &[u8]) -> String {
    match node.kind() {
        "string" | "\"" => {
            // tree-sitter string node: try to get string_content child
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "string_content" {
                    return node_text(child, source).to_string();
                }
            }
            // Fallback: strip surrounding quotes
            let text = node_text(node, source);
            text.trim_matches('"').to_string()
        }
        "raw_string" => {
            let text = node_text(node, source);
            text.trim_matches('\'').to_string()
        }
        _ => node_text(node, source).to_string(),
    }
}

fn check_code_string_for_exfil(code: &str, cmd_name: &str) -> Option<String> {
    let lower = code.to_lowercase();

    let has_network = CODE_NETWORK_INDICATORS
        .iter()
        .any(|ind| lower.contains(ind));
    let has_sensitive = has_sensitive_path(code);

    if has_network && has_sensitive {
        return Some(format!(
            "Interpreter '{cmd_name}' inline code with network access and sensitive file"
        ));
    }

    if patterns::has_exfil_domain(code) {
        return Some(format!(
            "Interpreter '{cmd_name}' inline code targeting exfil domain"
        ));
    }

    if contains_ip_url(&lower) {
        return Some(format!(
            "Interpreter '{cmd_name}' inline code targeting IP address"
        ));
    }

    None
}

/// For shell interpreters (bash -c, sh -c, etc.), re-parse the inner string
/// through the full detection pipeline rather than keyword matching.
pub fn check_shell_inline_code(node: Node, source: &[u8], cmd_name: &str) -> Option<String> {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    let mut i = 0;
    while i < children.len() {
        let child = children[i];
        let text = node_text(child, source);

        if text == "-c" {
            if let Some(&code_node) = children.get(i + 1) {
                let raw = node_text(code_node, source);
                let code_str = crate::util::strip_quotes(raw);
                if let Some(inner_reason) = crate::detect_exfiltration(code_str) {
                    return Some(format!(
                        "Shell '{cmd_name} -c' wrapping exfil: {inner_reason}"
                    ));
                }
            }
        }
        i += 1;
    }
    None
}
