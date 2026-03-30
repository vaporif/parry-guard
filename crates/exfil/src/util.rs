//! Shared utility functions for AST-based exfil detection.

use tree_sitter::Node;

use crate::consts::{INTERPRETERS, NETWORK_SINKS, SENSITIVE_SOURCES, SHELL_INTERPRETERS};

pub fn node_text<'a>(node: Node, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}

pub fn basename(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((_, name)) => name,
        None => path,
    }
}

pub fn get_command_name<'a>(node: Node, source: &'a [u8]) -> Option<&'a str> {
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

pub fn is_network_sink(name: &str) -> bool {
    NETWORK_SINKS.contains(&name)
}

pub fn is_sensitive_source_cmd(name: &str) -> bool {
    SENSITIVE_SOURCES.contains(&name)
}

pub fn is_interpreter(name: &str) -> bool {
    INTERPRETERS.contains(&name)
}

pub fn is_shell_interpreter(name: &str) -> bool {
    SHELL_INTERPRETERS.contains(&name)
}

pub fn has_sensitive_path(text: &str) -> bool {
    crate::patterns::has_sensitive_path(text)
}

/// Like `has_sensitive_path` but expands `$HOME`, `${HOME}`, and `~` first.
pub fn has_sensitive_path_expanded(text: &str) -> bool {
    let expanded = expand_shell_vars(text);
    expanded != text && has_sensitive_path(&expanded)
}

fn expand_shell_vars(text: &str) -> String {
    const DUMMY_HOME: &str = "/home/user";

    let mut s = text.to_string();
    s = s.replace("${HOME}", DUMMY_HOME);
    s = s.replace("$HOME", DUMMY_HOME);

    if s == "~" || s.starts_with("~/") {
        s = format!("{DUMMY_HOME}{}", &s[1..]);
    }

    s
}

pub fn contains_ip_url(text: &str) -> bool {
    for prefix in &["http://", "https://"] {
        let mut search = text;
        while let Some(idx) = search.find(prefix) {
            let after = &search[idx + prefix.len()..];
            let authority = after.split('/').next().unwrap_or(after);
            let host = authority.split(':').next().unwrap_or(authority);
            if host
                .parse::<std::net::Ipv4Addr>()
                .is_ok_and(|ip| !is_private_ipv4(ip))
            {
                return true;
            }
            search = &search[idx + prefix.len()..];
        }
    }
    false
}

#[must_use]
pub fn strip_quotes(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| {
            s.strip_prefix('\'')
                .and_then(|inner| inner.strip_suffix('\''))
        })
        .unwrap_or(s)
}

/// Returns true if the IPv4 address is private/loopback (RFC 1918 + loopback).
pub const fn is_private_ipv4(ip: std::net::Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_private() || ip.is_link_local()
}

/// Returns true if the IPv6 address is loopback or link-local.
pub const fn is_private_ipv6(ip: std::net::Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unicast_link_local()
}
