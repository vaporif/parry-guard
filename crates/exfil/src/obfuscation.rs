//! String-level obfuscation checks for bash commands.

use crate::consts::{
    CLIPBOARD_TOOLS, CLOUD_UPLOAD_COMMANDS, DNS_EXFIL_TOOLS, NETWORK_SINKS, SENSITIVE_SOURCES,
};
use crate::patterns;
use crate::{BASH_SUBSTRING_REGEX, OD_REGEX, XXD_REGEX};

/// Catches obfuscation that hides commands from the AST checks.
pub(crate) fn check_obfuscation_patterns(command: &str) -> Option<String> {
    let lower = command.to_lowercase();

    if lower.contains("base64")
        && (lower.contains("-d") || lower.contains("--decode"))
        && has_suspicious_context(command, &lower)
    {
        return Some("Command obfuscation via base64 decoding with suspicious context".into());
    }

    if command.contains("$'\\x") || command.contains("$\"\\x") {
        if let Some(decoded) = try_decode_hex_escapes(command) {
            if is_suspicious_decoded(&decoded) {
                return Some(
                    "Command obfuscation via hex escapes (decodes to suspicious content)".into(),
                );
            }
        }
    }

    if command.contains("$'\\") && command.chars().any(|c| c.is_ascii_digit()) {
        if let Some(decoded) = try_decode_octal_escapes(command) {
            if is_suspicious_decoded(&decoded) {
                return Some(
                    "Command obfuscation via octal escapes (decodes to suspicious content)".into(),
                );
            }
        }
    }

    if lower.contains("printf") && lower.contains("$(") && has_suspicious_context(command, &lower) {
        return Some("Potential command obfuscation via printf".into());
    }

    if ((XXD_REGEX.is_match(&lower) && lower.contains("-r"))
        || (OD_REGEX.is_match(&lower) && lower.contains("-c")))
        && has_suspicious_context(command, &lower)
    {
        return Some("Command obfuscation via binary decoding".into());
    }

    if (lower.contains("| rev") || lower.contains("|rev"))
        && has_suspicious_context(command, &lower)
    {
        return Some("Potential command obfuscation via string reversal".into());
    }

    if lower.contains("eval")
        && (command.contains('$') || command.contains('`'))
        && has_suspicious_context(command, &lower)
    {
        return Some("Potential command obfuscation via eval".into());
    }

    if lower.contains("/dev/tcp/") || lower.contains("/dev/udp/") {
        return Some("Network access via bash /dev/tcp or /dev/udp pseudo-device".into());
    }

    // DNS tunneling tools have no legitimate dev use, so no context needed
    for segment in lower.split('|') {
        let first_word = segment.split_whitespace().next().unwrap_or("");
        if let Some(tool) = DNS_EXFIL_TOOLS.iter().find(|&&t| first_word == t) {
            return Some(format!("DNS tunneling tool '{tool}' detected"));
        }
    }

    // ROT13: tr 'A-Za-z' 'N-ZA-Mn-za-m'
    if lower.contains("| tr ")
        && (lower.contains("a-za-z") || lower.contains("a-mn-z"))
        && has_suspicious_context(command, &lower)
    {
        return Some("Potential ROT13 obfuscation via tr".into());
    }

    if lower.contains("ifs=") && has_suspicious_context(command, &lower) {
        return Some("IFS manipulation detected with suspicious context".into());
    }

    if command.contains("${")
        && command.contains(':')
        && has_suspicious_context(command, &lower)
        && BASH_SUBSTRING_REGEX.is_match(command)
    {
        return Some("Bash substring extraction with suspicious context".into());
    }

    for upload_cmd in CLOUD_UPLOAD_COMMANDS {
        if lower.contains(upload_cmd) && has_sensitive_context_in_command(command, &lower) {
            return Some(format!(
                "Cloud storage upload '{upload_cmd}' with sensitive data"
            ));
        }
    }

    for clip_tool in CLIPBOARD_TOOLS {
        if command.contains(clip_tool) && has_sensitive_context_in_command(command, &lower) {
            return Some(format!(
                "Clipboard tool '{clip_tool}' with sensitive data (potential exfil staging)"
            ));
        }
    }

    None
}

fn has_sensitive_context_in_command(command: &str, lower: &str) -> bool {
    if patterns::has_sensitive_path(command) {
        return true;
    }

    SENSITIVE_SOURCES.iter().any(|src| lower.contains(src))
}

fn has_suspicious_context(command: &str, lower: &str) -> bool {
    if patterns::has_sensitive_path(command) {
        return true;
    }

    if lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("curl")
        || lower.contains("wget")
        || lower.contains("nc ")
        || lower.contains("netcat")
        || lower.contains("socat")
        || lower.contains("/dev/tcp/")
        || lower.contains("/dev/udp/")
    {
        return true;
    }

    patterns::has_exfil_domain(command)
}

/// Decodes `\xHH` escapes; `None` if nothing was decoded.
fn try_decode_hex_escapes(text: &str) -> Option<String> {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'x') {
            chars.next();
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            }
        } else {
            result.push(c);
        }
    }

    if result.len() < text.len() {
        Some(result)
    } else {
        None
    }
}

/// Decodes `\NNN` octal escapes; `None` if nothing was decoded.
fn try_decode_octal_escapes(text: &str) -> Option<String> {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek().is_some_and(char::is_ascii_digit) {
            // peek, so the first non-digit after a short escape isn't swallowed
            let mut octal = String::with_capacity(3);
            while octal.len() < 3 {
                match chars.next_if(char::is_ascii_digit) {
                    Some(d) => octal.push(d),
                    None => break,
                }
            }
            if let Ok(byte) = u8::from_str_radix(&octal, 8) {
                result.push(byte as char);
            }
        } else {
            result.push(c);
        }
    }

    if result.len() < text.len() {
        Some(result)
    } else {
        None
    }
}

fn is_suspicious_decoded(decoded: &str) -> bool {
    let lower = decoded.to_lowercase();

    NETWORK_SINKS.iter().any(|sink| lower.contains(sink))
        || lower.contains("bash")
        || lower.contains("/bin/sh")
        || lower.contains("eval")
        || lower.contains("exec")
        || lower.contains("/dev/tcp")
        || lower.contains("/dev/udp")
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::escapes(r"$'\x63\x75\x72\x6c'", Some("$'curl'"))]
    #[case::x_without_backslash("box12", None)]
    #[case::plain("plain", None)]
    fn hex_escapes(#[case] input: &str, #[case] expected: Option<&str>) {
        assert_eq!(try_decode_hex_escapes(input).as_deref(), expected);
    }

    #[rstest]
    #[case::escapes(r"$'\143\165\162\154'", Some("$'curl'"))]
    #[case::digit_without_backslash("a1", None)]
    #[case::plain("abc", None)]
    #[case::short_escape_keeps_next_char(r"\61x", Some("1x"))]
    #[case::space_then_word(r"\143url\40http", Some("curl http"))]
    fn octal_escapes(#[case] input: &str, #[case] expected: Option<&str>) {
        assert_eq!(try_decode_octal_escapes(input).as_deref(), expected);
    }

    #[rstest]
    #[case::sink("curl", true)]
    #[case::bash("bash", true)]
    #[case::bin_sh("/bin/sh", true)]
    #[case::eval("eval", true)]
    #[case::exec("exec", true)]
    #[case::dev_tcp("/dev/tcp", true)]
    #[case::dev_udp("/dev/udp", true)]
    #[case::benign("ls -la", false)]
    fn suspicious_decoded(#[case] decoded: &str, #[case] expected: bool) {
        assert_eq!(is_suspicious_decoded(decoded), expected);
    }
}
