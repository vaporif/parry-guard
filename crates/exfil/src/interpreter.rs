//! Inline code checks (`python -c`, `node -e`, `bash -c`): AST first, keywords as fallback.

use tree_sitter::Node;

use crate::consts::{CODE_NETWORK_INDICATORS, INLINE_CODE_FLAGS};
use crate::lang::detect_exfil_in_code;
use crate::patterns;
use crate::util::{contains_ip_url, has_sensitive_path, node_text, strip_quotes};

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

pub(crate) fn check_interpreter_inline_code(
    node: Node,
    source: &[u8],
    cmd_name: &str,
) -> Option<String> {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    let mut i = 0;
    while let Some(&child) = children.get(i) {
        let text = node_text(child, source);

        if INLINE_CODE_FLAGS.contains(&text) {
            if let Some(&code_node) = children.get(i + 1) {
                let code_str = extract_string_content(code_node, source);

                if let Some(reason) = try_ast_detection(&code_str, cmd_name) {
                    return Some(reason);
                }

                if let Some(reason) = check_code_string_for_exfil(&code_str, cmd_name) {
                    return Some(reason);
                }
            }
        }
        i += 1;
    }
    None
}

fn try_ast_detection(code: &str, cmd_name: &str) -> Option<String> {
    let base = cmd_name
        .rsplit('/')
        .next()
        .unwrap_or(cmd_name)
        .to_lowercase();

    match base.as_str() {
        "python" | "python2" | "python3" | "pypy" | "pypy3" => {
            detect_exfil_in_code(code, &PythonDetector, cmd_name)
        }
        "node" | "nodejs" | "deno" | "bun" => {
            detect_exfil_in_code(code, &JavaScriptDetector, cmd_name)
        }
        "ruby" | "jruby" => detect_exfil_in_code(code, &RubyDetector, cmd_name),
        "php" | "php-cgi" => detect_exfil_in_code(code, &PhpDetector, cmd_name),
        "perl" => detect_exfil_in_code(code, &PerlDetector, cmd_name),
        "lua" => detect_exfil_in_code(code, &LuaDetector, cmd_name),
        "pwsh" | "powershell" => detect_exfil_in_code(code, &PowerShellDetector, cmd_name),
        "r" | "rscript" => detect_exfil_in_code(code, &RDetector, cmd_name),
        "elixir" => detect_exfil_in_code(code, &ElixirDetector, cmd_name),
        "julia" => detect_exfil_in_code(code, &JuliaDetector, cmd_name),
        "groovy" => detect_exfil_in_code(code, &GroovyDetector, cmd_name),
        "scala" => detect_exfil_in_code(code, &ScalaDetector, cmd_name),
        "kotlin" | "kotlinc" => detect_exfil_in_code(code, &KotlinDetector, cmd_name),
        "nix" | "nix-shell" | "nix-build" | "nix-instantiate" => {
            detect_exfil_in_code(code, &NixDetector, cmd_name)
        }
        _ => None,
    }
}

fn extract_string_content(node: Node, source: &[u8]) -> String {
    let text = node_text(node, source);
    match node.kind() {
        // not the first `string_content` child: expansions split the content
        "string" | "raw_string" => strip_quotes(text).to_owned(),
        _ => text.to_owned(),
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

/// `sh -c` and friends: run the inner code through the full bash pipeline.
pub(crate) fn check_shell_inline_code(node: Node, source: &[u8], cmd_name: &str) -> Option<String> {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    let mut i = 0;
    while let Some(&child) = children.get(i) {
        let text = node_text(child, source);

        if text == "-c" {
            if let Some(&code_node) = children.get(i + 1) {
                let raw = node_text(code_node, source);
                let code_str = strip_quotes(raw);
                if let Ok(Some(inner_reason)) = crate::detect_exfiltration(code_str) {
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
