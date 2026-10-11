//! Shell text helpers shared by the bash checks: quote removal, what `echo` and
//! `printf` print, and whether a pipeline stage runs a script read from stdin.

use std::iter::Peekable;
use std::str::Chars;

/// Shells that run a script read from stdin.
pub const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "oksh", "pdksh", "ash", "fish", "csh", "tcsh",
    "yash", "rc", "es",
];

/// Commands that run another command: (`wrapper`, `options_taking_a_value`, `operands_before_command`).
pub const COMMAND_WRAPPERS: &[(&str, &[&str], usize)] = &[
    ("builtin", &[], 0),
    ("command", &[], 0),
    ("exec", &["-a"], 0),
    ("env", &["-u", "--unset", "-C", "--chdir"], 0),
    ("nice", &["-n", "--adjustment"], 0),
    ("nohup", &[], 0),
    ("time", &[], 0),
    ("timeout", &["-s", "--signal", "-k", "--kill-after"], 1),
    (
        "stdbuf",
        &["-i", "-o", "-e", "--input", "--output", "--error"],
        0,
    ),
    ("setsid", &[], 0),
    (
        "ionice",
        &[
            "-c",
            "--class",
            "-n",
            "--classdata",
            "-p",
            "--pid",
            "-P",
            "--pgid",
            "-u",
            "--uid",
        ],
        0,
    ),
    (
        "xargs",
        &[
            "-a",
            "--arg-file",
            "-d",
            "--delimiter",
            "-E",
            "-I",
            "-L",
            "--max-lines",
            "-n",
            "--max-args",
            "-P",
            "--max-procs",
            "-s",
            "--max-chars",
        ],
        0,
    ),
];

/// Approximate bash quote removal so `".."/` and `\/` match the paths bash would use.
#[must_use]
pub fn unquote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' => {}
            '\\' => out.extend(chars.next()),
            _ => out.push(c),
        }
    }
    out
}

/// Backslash escapes (`\xHH`, `\NNN`, `\n`, `\t`) decoded up to `end`, which is
/// consumed: the closing quote of `$'...'`, or `None` for the whole text.
pub fn decode_escapes(chars: &mut Peekable<Chars>, end: Option<char>) -> String {
    let mut out = String::new();
    while let Some(c) = chars.next() {
        match c {
            c if Some(c) == end => break,
            '\\' => match chars.next() {
                Some('x') => {
                    let hex: String = std::iter::from_fn(|| chars.next_if(char::is_ascii_hexdigit))
                        .take(2)
                        .collect();
                    out.extend(u8::from_str_radix(&hex, 16).ok().map(char::from));
                }
                Some(d @ '0'..='7') => {
                    let mut octal = String::from(d);
                    octal.extend(
                        std::iter::from_fn(|| chars.next_if(|c| ('0'..='7').contains(c))).take(2),
                    );
                    out.extend(u8::from_str_radix(&octal, 8).ok().map(char::from));
                }
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => {}
            },
            _ => out.push(c),
        }
    }
    out
}

fn decode_all(text: &str) -> String {
    decode_escapes(&mut text.chars().peekable(), None)
}

/// `echo` and `printf -b` write octal as `\0NNN`.
fn decode_echo_escapes(text: &str) -> String {
    decode_all(&text.replace("\\0", "\\"))
}

/// A quoted word's contents with escapes left for decoding; bare words get
/// bash quote removal.
fn strip_outer_quotes(word: &str) -> String {
    ['\'', '"']
        .iter()
        .find_map(|&q| word.strip_prefix(q).and_then(|w| w.strip_suffix(q)))
        .map_or_else(|| unquote(word), str::to_owned)
}

/// What `echo` or `printf` prints given its raw argument words, escapes decoded.
/// `None` for any other command, or `printf -v`, which prints nothing.
#[must_use]
pub fn printed_output(printer: &str, args: &[&str]) -> Option<String> {
    match printer {
        "echo" => Some(echo_output(args)),
        "printf" => printf_output(args),
        _ => None,
    }
}

/// Only leading words made of echo's own options (`-n`, `-e`, `-E`) are dropped.
fn echo_output(args: &[&str]) -> String {
    let words: Vec<String> = args
        .iter()
        .skip_while(|arg| {
            unquote(arg)
                .strip_prefix('-')
                .is_some_and(|opts| !opts.is_empty() && opts.chars().all(|c| "neE".contains(c)))
        })
        .map(|arg| strip_outer_quotes(arg))
        .collect();
    decode_echo_escapes(&words.join(" "))
}

/// The format is applied to the arguments, and reused until they run out.
fn printf_output(args: &[&str]) -> Option<String> {
    let mut args = args.iter().map(|arg| strip_outer_quotes(arg)).peekable();
    args.next_if(|arg| arg == "--");
    let format = args.next()?;
    if format == "-v" {
        return None;
    }
    let format = decode_all(&format);
    let mut out = String::new();
    loop {
        let consumed = apply_format(&format, &mut args, &mut out);
        if consumed == 0 || args.peek().is_none() {
            return Some(out);
        }
    }
}

/// One pass of `format`; returns how many arguments it consumed.
fn apply_format(format: &str, args: &mut impl Iterator<Item = String>, out: &mut String) -> usize {
    let mut consumed = 0;
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        // flags, width and precision don't change which text is printed
        while chars.next_if(|c| "-+ #0123456789.".contains(*c)).is_some() {}
        match chars.next() {
            Some('%') => out.push('%'),
            Some(conversion) => {
                consumed += 1;
                let arg = args.next().unwrap_or_default();
                if conversion == 'b' {
                    out.push_str(&decode_echo_escapes(&arg));
                } else {
                    out.push_str(&arg);
                }
            }
            None => out.push('%'),
        }
    }
    consumed
}

/// The shell a pipeline stage runs with stdin as its script, given the stage's
/// raw words (name first). Wrappers such as `env` or `nice` are looked through;
/// `-c` or a script operand without `-s` means stdin isn't the script.
#[must_use]
pub fn stdin_shell(words: &[&str]) -> Option<String> {
    let mut words: Vec<String> = words.iter().map(|word| unquote(word)).collect();
    loop {
        let name = words.first()?.rsplit('/').next()?.to_owned();
        if SHELLS.contains(&name.as_str()) {
            return reads_script_from_stdin(words.get(1..)?).then_some(name);
        }
        let rest = skip_wrapper(&name, words.get(1..)?)?;
        words = words.split_off(words.len() - rest);
    }
}

/// How many words are left once `wrapper`'s own options and operands are skipped;
/// `None` if `wrapper` isn't one, or doesn't run a command from its arguments.
fn skip_wrapper(wrapper: &str, args: &[String]) -> Option<usize> {
    if wrapper == "xargs" {
        return None;
    }
    let &(_, value_options, operands) = COMMAND_WRAPPERS
        .iter()
        .find(|(name, ..)| *name == wrapper)?;
    let mut args = args.iter().peekable();
    let mut operands_left = operands;
    while let Some(&arg) = args.peek() {
        if arg.as_str() == "--" {
            args.next();
            break;
        }
        if arg.starts_with('-') {
            if wrapper == "env" && matches!(arg.as_str(), "-S" | "--split-string") {
                return None;
            }
            args.next();
            if value_options.contains(&arg.as_str()) {
                args.next();
            }
        } else if operands_left > 0 {
            operands_left -= 1;
            args.next();
        } else if wrapper == "env" && arg.contains('=') {
            args.next();
        } else {
            break;
        }
    }
    Some(args.len())
}

fn reads_script_from_stdin(args: &[String]) -> bool {
    let mut stdin_flag = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--" {
            return stdin_flag || args.next().is_none();
        }
        let Some(flags) = arg.strip_prefix(['-', '+']).filter(|f| !f.is_empty()) else {
            // a script file operand, unless -s keeps stdin as the script
            return stdin_flag;
        };
        if flags.starts_with('-') {
            continue;
        }
        if flags.contains('c') {
            return false;
        }
        stdin_flag |= flags.contains('s');
        if flags.ends_with('o') || flags.ends_with('O') {
            args.next();
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::echo_plain(&["hello", "world"], "hello world")]
    #[case::echo_options(&["-n", "-e", "a"], "a")]
    #[case::echo_flags_after_words(&["git", "push", "--force"], "git push --force")]
    #[case::echo_quoted_option(&["'-n'", "x"], "x")]
    #[case::echo_not_an_option(&["-x", "y"], "-x y")]
    #[case::echo_octal(&[r"'\0162m'"], "rm")]
    fn echo(#[case] args: &[&str], #[case] expected: &str) {
        assert_eq!(printed_output("echo", args).as_deref(), Some(expected));
    }

    #[rstest]
    #[case::plain(&[r"'rm -rf /etc\n'"], "rm -rf /etc\n")]
    #[case::substituted(&["'%s -rf /etc'", "rm"], "rm -rf /etc")]
    #[case::reused_format(&[r"'%s\n'", "a", "b"], "a\nb\n")]
    #[case::missing_arg(&["'%s-%s'", "a"], "a-")]
    #[case::percent(&["'100%%'"], "100%")]
    #[case::width(&["'%-5s|'", "a"], "a|")]
    #[case::b_decodes(&["%b", r"'\x72m'"], "rm")]
    #[case::s_keeps_escapes(&["%s", r"'\x72m'"], r"\x72m")]
    #[case::double_dash(&["--", "x"], "x")]
    fn printf(#[case] args: &[&str], #[case] expected: &str) {
        assert_eq!(printed_output("printf", args).as_deref(), Some(expected));
    }

    #[test]
    fn printf_v_prints_nothing() {
        assert_eq!(printed_output("printf", &["-v", "x", "rm"]), None);
    }

    #[test]
    fn other_command_prints_nothing_known() {
        assert_eq!(printed_output("cat", &["x"]), None);
    }

    #[rstest]
    #[case::bare(&["sh"], Some("sh"))]
    #[case::path(&["/bin/bash"], Some("bash"))]
    #[case::stdin_flag(&["bash", "-s", "arg"], Some("bash"))]
    #[case::options(&["bash", "-e", "-o", "pipefail"], Some("bash"))]
    #[case::long_option(&["bash", "--norc"], Some("bash"))]
    #[case::env(&["env", "FOO=1", "sh"], Some("sh"))]
    #[case::nested(&["nice", "-n", "5", "exec", "bash"], Some("bash"))]
    #[case::timeout(&["timeout", "5", "sh"], Some("sh"))]
    #[case::c_flag(&["bash", "-c", "cat"], None)]
    #[case::combined_c(&["bash", "-lc", "cat"], None)]
    #[case::script_file(&["bash", "x.sh"], None)]
    #[case::not_a_shell(&["grep", "x"], None)]
    #[case::xargs(&["xargs", "sh"], None)]
    #[case::env_split_string(&["env", "-S", "sh -c cat"], None)]
    fn stdin_shells(#[case] words: &[&str], #[case] expected: Option<&str>) {
        assert_eq!(stdin_shell(words).as_deref(), expected);
    }
}
