//! Language-specific exfiltration detection using tree-sitter queries.
//!
//! This module provides AST-based analysis of inline code from interpreters,
//! detecting when code contains both network operations and sensitive file access.

use tracing::{debug, trace};
use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator};

use crate::patterns;
use crate::util::{contains_ip_url, has_sensitive_path};

/// Trait for language-specific exfiltration detection.
pub trait LangExfilDetector: Send + Sync {
    /// Returns the tree-sitter language for this detector.
    fn language(&self) -> Language;

    /// Returns the tree-sitter query pattern for network sink calls.
    /// Query should capture the call/expression as @call.
    fn network_sink_query(&self) -> &'static str;

    /// Returns the tree-sitter query pattern for file source calls.
    /// Query should capture the call/expression as @call.
    fn file_source_query(&self) -> &'static str;

    /// Returns the tree-sitter query pattern for string literals.
    /// Query should capture the string as @string.
    fn string_literal_query(&self) -> &'static str;
}

/// Result of analyzing code for exfiltration patterns.
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct AnalysisResult {
    has_network_sink: bool,
    has_file_source: bool,
    has_exfil_domain: bool,
    has_ip_url: bool,
}

/// Analyze inline code for exfiltration using the given language detector.
/// The `interpreter` parameter is used in error messages to show the actual command.
pub fn detect_exfil_in_code<L: LangExfilDetector>(
    code: &str,
    detector: &L,
    interpreter: &str,
) -> Option<String> {
    trace!(
        interpreter,
        code_len = code.len(),
        "analyzing code for exfil"
    );
    let mut parser = Parser::new();
    parser.set_language(&detector.language()).ok()?;

    let tree = parser.parse(code, None)?;
    if tree.root_node().has_error() {
        trace!("parse error, falling back to keyword matching");
        // Fall back to keyword matching if parse fails
        return None;
    }

    let source = code.as_bytes();
    let mut result = AnalysisResult::default();

    // Check for network sinks
    if let Ok(query) = Query::new(&detector.language(), detector.network_sink_query()) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);
        if matches.next().is_some() {
            result.has_network_sink = true;
        }
    }

    // Check for file sources
    if let Ok(query) = Query::new(&detector.language(), detector.file_source_query()) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);
        while let Some(m) = matches.next() {
            // Check if any captured node contains a sensitive path
            for capture in m.captures {
                let text = capture.node.utf8_text(source).unwrap_or("");
                if has_sensitive_path(text) {
                    result.has_file_source = true;
                    break;
                }
            }
            if result.has_file_source {
                break;
            }
        }
    }

    // Check string literals for exfil domains and IPs
    if let Ok(query) = Query::new(&detector.language(), detector.string_literal_query()) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);
        while let Some(m) = matches.next() {
            for capture in m.captures {
                let text = capture.node.utf8_text(source).unwrap_or("");
                let lower = text.to_lowercase();

                // Check for exfil domains using proper domain regex
                if patterns::has_exfil_domain(text) {
                    result.has_exfil_domain = true;
                }

                // Check for IP URLs
                if contains_ip_url(&lower) {
                    result.has_ip_url = true;
                }

                // Also check if this string is a sensitive path (for file sources)
                if has_sensitive_path(text) {
                    result.has_file_source = true;
                }
            }
        }
    }

    // Detection logic: network + sensitive file, or exfil domain, or IP URL
    if result.has_network_sink && result.has_file_source {
        debug!(interpreter, "detected network + sensitive file exfil");
        return Some(format!(
            "Interpreter '{interpreter}' inline code with network access and sensitive file"
        ));
    }

    if result.has_exfil_domain {
        debug!(interpreter, "detected exfil domain");
        return Some(format!(
            "Interpreter '{interpreter}' inline code targeting exfil domain"
        ));
    }

    if result.has_ip_url {
        debug!(interpreter, "detected IP URL");
        return Some(format!(
            "Interpreter '{interpreter}' inline code targeting IP address"
        ));
    }

    trace!(interpreter, "no exfil detected");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_ip_url() {
        assert!(contains_ip_url("http://1.2.3.4/path"));
        assert!(
            !contains_ip_url("https://192.168.1.1:8080/api"),
            "private IP should not be flagged"
        );
        assert!(!contains_ip_url("http://example.com"));
        assert!(!contains_ip_url("http://localhost"));
        assert!(
            !contains_ip_url("http://10.0.0.1/api"),
            "10.x should not be flagged"
        );
        assert!(
            !contains_ip_url("http://127.0.0.1:3000"),
            "loopback should not be flagged"
        );
    }
}
