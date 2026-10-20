//! Shell text helpers shared by the bash checks: quote removal, what `echo` and
//! `printf` print, and whether a pipeline stage runs a script read from stdin.

use std::borrow::Cow;
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
            '\\' => out.extend(decode_escape(chars)),
            _ => out.push(c),
        }
    }
    out
}

/// The character one backslash escape stands for, read after the backslash.
fn decode_escape(chars: &mut Peekable<Chars>) -> Option<char> {
    match chars.next()? {
        'x' => {
            let hex: String = std::iter::from_fn(|| chars.next_if(char::is_ascii_hexdigit))
                .take(2)
                .collect();
            u8::from_str_radix(&hex, 16).ok().map(char::from)
        }
        d @ '0'..='7' => {
            let mut octal = String::from(d);
            octal.extend(std::iter::from_fn(|| chars.next_if(|c| ('0'..='7').contains(c))).take(2));
            u8::from_str_radix(&octal, 8).ok().map(char::from)
        }
        'n' => Some('\n'),
        't' => Some('\t'),
        other => Some(other),
    }
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
    let mut out = String::new();
    loop {
        let consumed = apply_format(&format, &mut args, &mut out);
        if consumed == 0 || args.peek().is_none() {
            return Some(out);
        }
    }
}

/// One pass of `format`; returns how many arguments it consumed. Escapes are
/// decoded as they're printed, so one that decodes to `%` is a literal `%`.
fn apply_format(format: &str, args: &mut impl Iterator<Item = String>, out: &mut String) -> usize {
    let mut consumed = 0;
    let mut next_arg = || {
        consumed += 1;
        args.next().unwrap_or_default()
    };
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '%' => {}
            '\\' => {
                out.extend(decode_escape(&mut chars));
                continue;
            }
            _ => {
                out.push(c);
                continue;
            }
        }
        while chars.next_if(|c| "-+ #0".contains(*c)).is_some() {}
        // width only pads, but `*` takes it from an argument
        if chars.next_if_eq(&'*').is_some() {
            next_arg();
        }
        while chars.next_if(char::is_ascii_digit).is_some() {}
        let precision = chars.next_if_eq(&'.').map(|_| {
            if chars.next_if_eq(&'*').is_some() {
                next_arg().parse().unwrap_or(0)
            } else {
                std::iter::from_fn(|| chars.next_if(char::is_ascii_digit))
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0)
            }
        });
        let text = match chars.next() {
            Some('%') | None => "%".to_owned(),
            Some('b') => decode_echo_escapes(&next_arg()),
            Some('c') => next_arg().chars().take(1).collect(),
            Some(_) => next_arg(),
        };
        match precision {
            Some(n) => out.extend(text.chars().take(n)),
            None => out.push_str(&text),
        }
    }
    consumed
}

/// The shell a pipeline stage runs with stdin as its script, given its raw words.
///
/// Wrappers such as `env` or `nice` are looked through; `-c` or a script operand
/// without `-s` means stdin isn't the script.
#[must_use]
pub fn stdin_shell(words: &[&str]) -> Option<String> {
    let mut words: Vec<String> = words.iter().map(|word| unquote(word)).collect();
    loop {
        let name = words.first()?.rsplit('/').next()?.to_owned();
        if SHELLS.contains(&name.as_str()) {
            return reads_script_from_stdin(words.get(1..)?).then_some(name);
        }
        words = unwrap_command(&name, words.get(1..)?)?;
    }
}

/// The command `wrapper` runs, once its own options and operands are skipped;
/// `None` if `wrapper` isn't one, or doesn't run a command from its arguments.
fn unwrap_command(wrapper: &str, args: &[String]) -> Option<Vec<String>> {
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
            args.next();
            if wrapper == "env" && matches!(arg.as_str(), "-S" | "--split-string") {
                // the value is split into words ahead of the rest
                let mut words: Vec<String> =
                    args.next()?.split_whitespace().map(str::to_owned).collect();
                words.extend(args.cloned());
                return Some(words);
            }
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
    Some(args.cloned().collect())
}

/// Long shell options that take the next word as their value.
const SHELL_VALUE_OPTIONS: &[&str] = &["--rcfile", "--init-file"];

fn reads_script_from_stdin(args: &[String]) -> bool {
    let mut stdin_flag = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        // a lone `-` ends the options like `--`
        if arg == "--" || arg == "-" {
            return stdin_flag || args.next().is_none();
        }
        let Some(flags) = arg.strip_prefix(['-', '+']).filter(|f| !f.is_empty()) else {
            // a script file operand, unless -s keeps stdin as the script
            return stdin_flag;
        };
        if flags.starts_with('-') {
            if SHELL_VALUE_OPTIONS.contains(&arg.as_str()) {
                args.next();
            }
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

/// What a decoding filter writes for `input`: `base64 -d` and `xxd -r -p`, which
/// hide a script from the stage that prints it. `None` for any other command.
#[must_use]
pub fn filter_output(words: &[&str], input: &str) -> Option<String> {
    let words: Vec<String> = words.iter().map(|word| unquote(word)).collect();
    let (name, args) = words.split_first()?;
    let has = |flag: &str| args.iter().any(|arg| arg == flag);
    let encoding = match name.rsplit('/').next()? {
        "base64" if has("-d") || has("--decode") || has("-D") => &data_encoding::BASE64,
        "xxd" if has("-r") && (has("-p") || has("-ps")) => &data_encoding::HEXLOWER_PERMISSIVE,
        _ => return None,
    };
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let decoded = encoding
        .decode(cleaned.as_bytes())
        .or_else(|_| data_encoding::BASE64_NOPAD.decode(cleaned.as_bytes()))
        .ok()?;
    String::from_utf8(decoded).ok()
}

/// A script a pipeline feeds a shell: printed by `printer`, maybe passed through
/// decoding filters, then read from stdin by `shell`.
pub struct PipedScript {
    pub printer: String,
    pub shell: String,
    pub script: String,
}

/// Scripts a pipeline feeds into a shell, given each stage's raw words (name first).
#[must_use]
pub fn piped_scripts(stages: &[Vec<&str>]) -> Vec<PipedScript> {
    let mut scripts = Vec::new();
    for (i, printer) in stages.iter().enumerate() {
        let Some((name, args)) = printer.split_first() else {
            continue;
        };
        let name = unquote(name);
        let Some(mut script) = printed_output(&name, args) else {
            continue;
        };
        for stage in stages.iter().skip(i + 1) {
            if let Some(shell) = stdin_shell(stage) {
                scripts.push(PipedScript {
                    printer: name,
                    shell,
                    script,
                });
                break;
            }
            match filter_output(stage, &script) {
                Some(decoded) => script = decoded,
                None => break,
            }
        }
    }
    scripts
}

/// Most lines a script is split into before it's checked as one unparsable blob.
const MAX_SCRIPT_LINES: usize = 256;

/// The commands a shell runs from `script`; `None` if it's too long to split.
///
/// `parses` says whether text is complete, valid shell. A shell reads a line at a
/// time and runs each command once it's complete. Text that never completes is
/// kept as the last entry: the parser can reject what a shell runs (`x%`), and
/// zsh carries on past a syntax error, so checking it must fail closed.
pub fn complete_commands(script: &str, mut parses: impl FnMut(&str) -> bool) -> Option<Vec<&str>> {
    if script.lines().count() > MAX_SCRIPT_LINES {
        return None;
    }
    let mut commands = Vec::new();
    let mut start = 0;
    for (end, _) in script.match_indices('\n') {
        let chunk = script.get(start..end)?;
        if !chunk.trim().is_empty() && parses(chunk) {
            commands.push(chunk);
            start = end;
        }
    }
    let rest = script.get(start..)?;
    if !rest.trim().is_empty() {
        commands.push(rest);
    }
    Some(commands)
}

/// `command` made safe to hand to tree-sitter-bash, with byte offsets unchanged.
///
/// The bash scanner passes the codepoint after `{`, a digit or `.` to `isdigit`,
/// which glibc implements as an unchecked table lookup: past U+00FF it reads out
/// of bounds and can segfault. Such codepoints become `_` (one per UTF-8 byte),
/// which tree-sitter treats as the same kind of word character.
#[must_use]
pub fn tree_sitter_safe(command: &str) -> Cow<'_, str> {
    let mut out = Cow::Borrowed(command);
    let mut prev = None;
    for (i, c) in command.char_indices() {
        let after_digit_context =
            prev.is_some_and(|p: char| p == '{' || p == '.' || p.is_ascii_digit());
        if after_digit_context && u32::from(c) > 0xFF {
            let len = c.len_utf8();
            out.to_mut().replace_range(i..i + len, &"_".repeat(len));
        }
        prev = Some(c);
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
    #[case::echo_tab(&[r"'a\tb'"], "a\tb")]
    #[case::echo_unknown_escape_keeps_char(&[r"'\q'"], "q")]
    fn echo(#[case] args: &[&str], #[case] expected: &str) {
        assert_eq!(printed_output("echo", args).as_deref(), Some(expected));
    }

    #[rstest]
    #[case::plain(&[r"'rm -rf /etc\n'"], "rm -rf /etc\n")]
    #[case::substituted(&["'%s -rf /etc'", "rm"], "rm -rf /etc")]
    #[case::reused_format(&["'%s,'", "a", "b"], "a,b,")]
    #[case::missing_arg(&["'%s-%s'", "a"], "a-")]
    #[case::percent(&["'100%%'"], "100%")]
    #[case::width(&["'%-5s|'", "a"], "a|")]
    #[case::b_decodes(&["%b", r"'\x72m'"], "rm")]
    #[case::s_keeps_escapes(&["%s", r"'\x72m'"], r"\x72m")]
    #[case::double_dash(&["--", "x"], "x")]
    #[case::escaped_percent_is_literal(&[r"'\x25s'", "rm"], "%s")]
    #[case::escaped_percent_before_separator(&[r"'x\045;rm'"], "x%;rm")]
    fn printf(#[case] args: &[&str], #[case] expected: &str) {
        assert_eq!(printed_output("printf", args).as_deref(), Some(expected));
    }

    #[rstest]
    #[case::precision(&["'%.1s%.1s'", "rX", "mX"], "rm")]
    #[case::star_precision(&["'%.*s'", "1", "rX"], "r")]
    #[case::star_width(&["'%*s'", "5", "rm"], "rm")]
    #[case::char(&["'%c%c'", "rx", "mx"], "rm")]
    fn printf_conversions(#[case] args: &[&str], #[case] expected: &str) {
        assert_eq!(printed_output("printf", args).as_deref(), Some(expected));
    }

    #[rstest]
    #[case::base64(&["base64", "-d"], "cm0gLXJm", Some("rm -rf"))]
    #[case::base64_long(&["base64", "--decode"], "cm0gLXJm\n", Some("rm -rf"))]
    #[case::xxd(&["xxd", "-r", "-p"], "726d", Some("rm"))]
    #[case::encode_only(&["base64"], "rm", None)]
    #[case::not_a_filter(&["cat"], "rm", None)]
    #[case::base64_unpadded(&["base64", "-d"], "cm0", Some("rm"))]
    #[case::invalid_input(&["base64", "-d"], "!!!", None)]
    fn filters(#[case] words: &[&str], #[case] input: &str, #[case] expected: Option<&str>) {
        assert_eq!(filter_output(words, input).as_deref(), expected);
    }

    fn parses(text: &str) -> bool {
        // stand-in for a parser: balanced if/fi, and no lone `(`
        text.matches("if").count() == text.matches("fi").count() && !text.contains('(')
    }

    const COMPOUND: &str = indoc::indoc! {"
        if x
        then y
        fi"};
    const NEVER_COMPLETES: &str = indoc::indoc! {"
        a
        (
        b"};
    const NEVER_COMPLETES_TAIL: &str = indoc::indoc! {"

        (
        b"};
    const BLANK_LINES: &str = indoc::indoc! {"


        a"};
    const TRAILING_NEWLINE: &str = indoc::indoc! {"
        a
        b
    "};

    #[rstest]
    #[case::lines("a\nb", &["a", "\nb"])]
    #[case::compound(COMPOUND, &[COMPOUND])]
    #[case::never_completes(NEVER_COMPLETES, &["a", NEVER_COMPLETES_TAIL])]
    #[case::blank_lines(BLANK_LINES, &[BLANK_LINES])]
    #[case::trailing_newline(TRAILING_NEWLINE, &["a", "\nb"])]
    fn complete_commands_split(#[case] script: &str, #[case] expected: &[&str]) {
        assert_eq!(complete_commands(script, parses).as_deref(), Some(expected));
    }

    #[test]
    fn complete_commands_gives_up_on_long_scripts() {
        let script = "a\n".repeat(MAX_SCRIPT_LINES + 1);
        assert_eq!(complete_commands(&script, parses), None);
    }

    #[rstest]
    #[case::ascii("echo {1..3}", "echo {1..3}")]
    #[case::latin1_kept("{é", "{é")]
    #[case::after_brace("{\u{10FFFF}}", "{____}")]
    #[case::after_digit("{1€", "{1___")]
    #[case::after_dot("{1..€", "{1..___")]
    #[case::elsewhere_kept("echo €{", "echo €{")]
    fn tree_sitter_safe_replaces(#[case] input: &str, #[case] expected: &str) {
        let safe = tree_sitter_safe(input);
        assert_eq!(safe, expected);
        assert_eq!(safe.len(), input.len());
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
    #[case::env_split_string_c(&["env", "-S", "sh -c cat"], None)]
    #[case::env_split_string(&["env", "-S", "sh -e"], Some("sh"))]
    #[case::lone_dash(&["bash", "-"], Some("bash"))]
    #[case::rcfile(&["bash", "--rcfile", "/dev/null"], Some("bash"))]
    #[case::wrapper_double_dash(&["env", "--", "sh"], Some("sh"))]
    #[case::wrapper_flag_without_value(&["env", "-i", "bash"], Some("bash"))]
    fn stdin_shells(#[case] words: &[&str], #[case] expected: Option<&str>) {
        assert_eq!(stdin_shell(words).as_deref(), expected);
    }
}
