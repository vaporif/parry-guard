//! Shared AST helpers.

use tree_sitter::Node;

use crate::consts::{INTERPRETERS, NETWORK_SINKS, SENSITIVE_SOURCES, SHELL_INTERPRETERS};

pub(crate) fn node_text<'a>(node: Node, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}

pub(crate) fn basename(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((_, name)) => name,
        None => path,
    }
}

pub(crate) fn get_command_name<'a>(node: Node, source: &'a [u8]) -> Option<&'a str> {
    if node.kind() != "command" {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "command_name" {
            let text = node_text(child, source);
            return Some(basename(text));
        }
    }
    None
}

pub(crate) fn is_network_sink(name: &str) -> bool {
    NETWORK_SINKS.contains(&name)
}

pub(crate) fn is_sensitive_source_cmd(name: &str) -> bool {
    SENSITIVE_SOURCES.contains(&name)
}

pub(crate) fn is_interpreter(name: &str) -> bool {
    INTERPRETERS.contains(&name)
}

pub(crate) fn is_shell_interpreter(name: &str) -> bool {
    SHELL_INTERPRETERS.contains(&name)
}

pub(crate) fn has_sensitive_path(text: &str) -> bool {
    crate::patterns::has_sensitive_path(text)
}

/// Like `has_sensitive_path` but expands `$HOME`, `${HOME}`, and `~` first.
pub(crate) fn has_sensitive_path_expanded(text: &str) -> bool {
    let expanded = expand_shell_vars(text);
    expanded != text && has_sensitive_path(&expanded)
}

fn expand_shell_vars(text: &str) -> String {
    const DUMMY_HOME: &str = "/home/user";

    let mut s = text.to_string();
    s = s.replace("${HOME}", DUMMY_HOME);
    s = s.replace("$HOME", DUMMY_HOME);

    if let Some(rest) = s
        .strip_prefix('~')
        .filter(|r| r.is_empty() || r.starts_with('/'))
    {
        s = format!("{DUMMY_HOME}{rest}");
    }

    s
}

pub(crate) fn contains_ip_url(text: &str) -> bool {
    for prefix in &["http://", "https://"] {
        let mut search = text;
        while let Some((_, after)) = search.split_once(prefix) {
            let authority = after.split('/').next().unwrap_or(after);
            let host = authority.split(':').next().unwrap_or(authority);
            if host
                .parse::<std::net::Ipv4Addr>()
                .is_ok_and(|ip| !is_private_ipv4(ip))
            {
                return true;
            }
            search = after;
        }
    }
    false
}

#[must_use]
pub(crate) fn strip_quotes(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| {
            s.strip_prefix('\'')
                .and_then(|inner| inner.strip_suffix('\''))
        })
        .unwrap_or(s)
}

pub(crate) const fn is_private_ipv4(ip: std::net::Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_private() || ip.is_link_local()
}

pub(crate) const fn is_private_ipv6(ip: std::net::Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::home_var("$HOME/x", "/home/user/x")]
    #[case::home_braced("${HOME}/x", "/home/user/x")]
    #[case::tilde("~", "/home/user")]
    #[case::tilde_slash("~/x", "/home/user/x")]
    #[case::tilde_user("~bob/x", "~bob/x")]
    #[case::mid_tilde("a~/x", "a~/x")]
    fn expands_home(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(expand_shell_vars(input), expected);
    }

    #[rstest]
    #[case::expanded_sensitive("$HOME/.ssh", true)]
    #[case::unexpanded_sensitive(".env", false)]
    #[case::expanded_benign("~/notes", false)]
    fn sensitive_only_after_expansion(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(has_sensitive_path_expanded(input), expected);
    }
}
