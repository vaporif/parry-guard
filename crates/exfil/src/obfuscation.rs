//! Obfuscation pattern detection for bash commands.
//!
//! Detects base64, hex/octal escapes, printf construction, eval, DNS tunneling,
//! ROT13, IFS manipulation, parameter expansion, cloud uploads, and clipboard staging.

use crate::consts::{
    CLIPBOARD_TOOLS, CLOUD_UPLOAD_COMMANDS, DNS_EXFIL_TOOLS, NETWORK_SINKS, SENSITIVE_SOURCES,
};
use crate::patterns;
use crate::{BASH_SUBSTRING_REGEX, OD_REGEX, XXD_REGEX};

/// Check for command obfuscation patterns that might bypass AST-based detection.
pub fn check_obfuscation_patterns(command: &str) -> Option<String> {
    let lower = command.to_lowercase();

    // 1. Base64 decoding patterns: $(echo xxx | base64 -d), $(base64 -d <<< xxx)
    if lower.contains("base64")
        && (lower.contains("-d") || lower.contains("--decode"))
        && has_suspicious_context(command, &lower)
    {
        return Some("Command obfuscation via base64 decoding with suspicious context".into());
    }

    // 2. Hex escape sequences: $'\x63\x75\x72\x6c' (spells "curl")
    if command.contains("$'\\x") || command.contains("$\"\\x") {
        if let Some(decoded) = try_decode_hex_escapes(command) {
            if is_suspicious_decoded(&decoded) {
                return Some(
                    "Command obfuscation via hex escapes (decodes to suspicious content)".into(),
                );
            }
        }
    }

    // 3. Octal escape sequences: $'\143\165\162\154' (spells "curl")
    if command.contains("$'\\") && command.chars().any(|c| c.is_ascii_digit()) {
        if let Some(decoded) = try_decode_octal_escapes(command) {
            if is_suspicious_decoded(&decoded) {
                return Some(
                    "Command obfuscation via octal escapes (decodes to suspicious content)".into(),
                );
            }
        }
    }

    // 4. Printf-based command construction with suspicious patterns
    if lower.contains("printf") && lower.contains("$(") && has_suspicious_context(command, &lower) {
        return Some("Potential command obfuscation via printf".into());
    }

    // 5. xxd/od decoding (binary to text)
    if ((XXD_REGEX.is_match(&lower) && lower.contains("-r"))
        || (OD_REGEX.is_match(&lower) && lower.contains("-c")))
        && has_suspicious_context(command, &lower)
    {
        return Some("Command obfuscation via binary decoding".into());
    }

    // 6. rev (reverse string) obfuscation
    if (lower.contains("| rev") || lower.contains("|rev"))
        && has_suspicious_context(command, &lower)
    {
        return Some("Potential command obfuscation via string reversal".into());
    }

    // 7. eval with variable expansion
    if lower.contains("eval")
        && (command.contains('$') || command.contains('`'))
        && has_suspicious_context(command, &lower)
    {
        return Some("Potential command obfuscation via eval".into());
    }

    // 8. Bash /dev/tcp and /dev/udp pseudo-devices for raw network access
    if lower.contains("/dev/tcp/") || lower.contains("/dev/udp/") {
        return Some("Network access via bash /dev/tcp or /dev/udp pseudo-device".into());
    }

    // 9. DNS exfiltration tools are inherently suspicious (no legitimate dev use)
    for segment in lower.split('|') {
        let first_word = segment.split_whitespace().next().unwrap_or("");
        if let Some(tool) = DNS_EXFIL_TOOLS.iter().find(|&&t| first_word == t) {
            return Some(format!("DNS tunneling tool '{tool}' detected"));
        }
    }

    // 10. tr-based ROT13 obfuscation: echo xxx | tr 'A-Za-z' 'N-ZA-Mn-za-m'
    if lower.contains("| tr ")
        && (lower.contains("a-za-z") || lower.contains("a-mn-z"))
        && has_suspicious_context(command, &lower)
    {
        return Some("Potential ROT13 obfuscation via tr".into());
    }

    // 11. IFS manipulation for command splitting
    if lower.contains("ifs=") && has_suspicious_context(command, &lower) {
        return Some("IFS manipulation detected with suspicious context".into());
    }

    // 12. Bash substring/parameter expansion obfuscation: ${var:0:1}
    if command.contains("${")
        && command.contains(':')
        && has_suspicious_context(command, &lower)
        && BASH_SUBSTRING_REGEX.is_match(command)
    {
        return Some("Bash substring extraction with suspicious context".into());
    }

    // 13. Cloud storage uploads with sensitive data
    for upload_cmd in CLOUD_UPLOAD_COMMANDS {
        if lower.contains(upload_cmd) && has_sensitive_context_in_command(command, &lower) {
            return Some(format!(
                "Cloud storage upload '{upload_cmd}' with sensitive data"
            ));
        }
    }

    // 14. Clipboard exfiltration
    for clip_tool in CLIPBOARD_TOOLS {
        if command.contains(clip_tool) && has_sensitive_context_in_command(command, &lower) {
            return Some(format!(
                "Clipboard tool '{clip_tool}' with sensitive data (potential exfil staging)"
            ));
        }
    }

    None
}

/// Check if command contains sensitive data being piped or used.
fn has_sensitive_context_in_command(command: &str, lower: &str) -> bool {
    if patterns::has_sensitive_path(command) {
        return true;
    }

    SENSITIVE_SOURCES.iter().any(|src| lower.contains(src))
}

/// Check if command has suspicious context (sensitive files or network indicators).
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

/// Try to decode hex escape sequences like $'\x63\x75\x72\x6c'.
fn try_decode_hex_escapes(text: &str) -> Option<String> {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'x') {
            chars.next(); // consume 'x'
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

/// Try to decode octal escape sequences like $'\143\165\162\154'.
fn try_decode_octal_escapes(text: &str) -> Option<String> {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek().is_some_and(char::is_ascii_digit) {
            let octal: String = chars
                .by_ref()
                .take_while(char::is_ascii_digit)
                .take(3)
                .collect();
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

/// Check if decoded content contains suspicious commands.
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
