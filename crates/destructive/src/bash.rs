use std::path::Path;

use tree_sitter::Node;

use crate::commands::CONFIG;
use crate::consts;
use crate::paths;

pub(crate) fn check_node(node: Node, source: &[u8], cwd: &str) -> Option<String> {
    match node.kind() {
        "command" => check_command(node, source, cwd),
        "pipeline" => check_pipeline(node, source, cwd),
        _ => check_children(node, source, cwd),
    }
}

fn check_children(node: Node, source: &[u8], cwd: &str) -> Option<String> {
    let mut cursor = node.walk();
    let reason = node
        .children(&mut cursor)
        .find_map(|child| check_node(child, source, cwd));
    reason
}

/// `xargs` turns what the previous stage prints into arguments, so when that
/// output is known (`echo`, `printf`, `find`) it is checked as part of the command.
fn check_pipeline(node: Node, source: &[u8], cwd: &str) -> Option<String> {
    let mut cursor = node.walk();
    let stages: Vec<Node> = node.named_children(&mut cursor).collect();
    let reason = stages.iter().zip(stages.iter().skip(1)).find_map(|(&upstream, &stage)| {
        if !matches!(get_command_name(stage, source), Some(CommandName::Static(name)) if name == "xargs")
        {
            return None;
        }
        // TODO: output of any other stage (`cat list | xargs rm`) is unknown, so it's allowed.
        let input = stage_output(upstream, source, cwd)?;
        check_wrapper("xargs", stage, source, cwd, &input)
    });
    reason.or_else(|| check_children(node, source, cwd))
}

/// Words a pipeline stage prints, when they can be known without running it.
fn stage_output(node: Node, source: &[u8], cwd: &str) -> Option<Vec<String>> {
    let Some(CommandName::Static(name)) = get_command_name(node, source) else {
        return None;
    };
    let args = arguments(node, source);
    match name.as_str() {
        "echo" => Some(
            args.iter()
                .filter(|arg| !arg.starts_with('-'))
                .map(|arg| unquote(arg))
                .collect(),
        ),
        // keep `\n` as a separator instead of letting unquote turn it into `n`
        "printf" => Some(
            args.iter()
                .flat_map(|arg| {
                    arg.trim_matches(['"', '\''])
                        .replace("\\n", " ")
                        .split_whitespace()
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .collect(),
        ),
        "find" => Some(find_targets(&parse_find(node, source), cwd)),
        _ => None,
    }
}

/// What a `find` command searches and what it does with each match.
struct FindCommand<'a> {
    roots: Vec<String>,
    /// `(action, command words)` for `-exec`, `-execdir`, `-ok` and `-okdir`.
    actions: Vec<(&'a str, Vec<&'a str>)>,
    deletes: bool,
    /// A test such as `-name` limits the matches, so a root isn't wiped wholesale.
    narrowed: bool,
}

fn parse_find<'a>(node: Node, source: &'a [u8]) -> FindCommand<'a> {
    let args = arguments(node, source);
    let mut rest = args
        .iter()
        .copied()
        .skip_while(|arg| matches!(*arg, "-H" | "-L" | "-P"))
        .peekable();
    let mut roots = Vec::new();
    while let Some(root) = rest.next_if(|arg| !arg.starts_with(['-', '(', '!'])) {
        roots.push(unquote(root));
    }
    if roots.is_empty() {
        roots.push(".".to_owned());
    }

    let mut find = FindCommand {
        roots,
        actions: Vec::new(),
        deletes: false,
        narrowed: false,
    };
    let mut has_or = false;
    while let Some(arg) = rest.next() {
        if arg == "-delete" {
            find.deletes = true;
        } else if consts::FIND_EXEC_ACTIONS.contains(&arg) {
            let mut command = Vec::new();
            let terminated = rest.by_ref().any(|word| {
                let end = matches!(unquote(word).as_str(), ";" | "+");
                if !end {
                    command.push(word);
                }
                end
            });
            // find refuses to run an unterminated action
            if terminated {
                find.actions.push((arg, command));
            }
        } else if consts::FIND_OR.contains(&arg) {
            has_or = true;
        } else if arg.starts_with('-') && !consts::FIND_NON_TESTS.contains(&arg) {
            find.narrowed = true;
        }
    }
    find.narrowed &= !has_or;
    find
}

/// Paths a `find` action may touch. A narrowed search drops the project root,
/// so `find . -name '*.o' -delete` stays allowed while `find . -delete` doesn't.
fn find_targets(find: &FindCommand, cwd: &str) -> Vec<String> {
    find.roots
        .iter()
        .filter(|root| !(find.narrowed && paths::is_cwd_itself(root, cwd)))
        .cloned()
        .collect()
}

fn check_find(node: Node, source: &[u8], cwd: &str) -> Option<String> {
    let find = parse_find(node, source);
    let targets = find_targets(&find, cwd);
    if find.deletes {
        if let Some(reason) = check_rm_paths("find -delete", &targets, cwd) {
            return Some(reason);
        }
    }
    find.actions.iter().find_map(|(action, words)| {
        let command = words
            .iter()
            .map(|word| {
                if unquote(word) == "{}" {
                    targets.join(" ")
                } else {
                    (*word).to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        crate::detect_destructive(&command, cwd)
            .map(|reason| format!("'find {action}' runs: {reason}"))
    })
}

/// Always walks nested children so a harmless outer command cannot hide `$(rm -rf /)`.
fn check_command(node: Node, source: &[u8], cwd: &str) -> Option<String> {
    let reason = match get_command_name(node, source)? {
        CommandName::Static(cmd_name) => check_named_command(&cmd_name, node, source, cwd),
        CommandName::Dynamic(text) => check_dynamic_command(text, node, source, cwd),
    };
    reason.or_else(|| check_children(node, source, cwd))
}

/// A name only known at runtime could be `rm`, so its arguments get the `rm` path checks.
fn check_dynamic_command(name: &str, node: Node, source: &[u8], cwd: &str) -> Option<String> {
    check_rm(name, node, source, cwd)
        .map(|reason| format!("{reason} (command name resolved at runtime)"))
}

/// Check what a wrapper such as `env` or `xargs` runs: skip the wrapper's own
/// options, then parse the rest of the line as a command of its own.
///
/// `input` holds words piped into `xargs`, which it appends to the command.
fn check_wrapper(
    cmd_name: &str,
    node: Node,
    source: &[u8],
    cwd: &str,
    input: &[String],
) -> Option<String> {
    let &(_, value_options, operands) = consts::COMMAND_WRAPPERS
        .iter()
        .find(|(name, ..)| *name == cmd_name)?;

    let mut cursor = node.walk();
    let mut args = node
        .children_by_field_name("argument", &mut cursor)
        .peekable();
    let mut operands_left = operands;
    let mut split_string = None;
    while let Some(&arg) = args.peek() {
        let text = node_text(arg, source);
        if cmd_name == "command" && matches!(text, "-v" | "-V") {
            // lookup only, nothing runs
            return None;
        }
        if text == "--" {
            args.next();
            break;
        }
        if cmd_name == "env" && matches!(text, "-S" | "--split-string") {
            args.next();
            split_string = args.next().map(|value| unquote(node_text(value, source)));
            break;
        }
        if text.starts_with('-') {
            args.next();
            if value_options.contains(&text) {
                args.next();
            }
        } else if operands_left > 0 {
            operands_left -= 1;
            args.next();
        } else {
            break;
        }
    }

    let rest: Vec<Node> = args.collect();
    let mut inner = split_string.unwrap_or_default();
    if let (Some(first), Some(last)) = (rest.first(), rest.last()) {
        let tail = source
            .get(first.start_byte()..last.end_byte())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())?;
        inner.push(' ');
        inner.push_str(tail);
    }
    if inner.trim().is_empty() {
        return None;
    }
    if cmd_name == "xargs" {
        // a here-string feeds xargs the arguments it appends to the command
        let mut cursor = node.walk();
        for redirect in node.children(&mut cursor) {
            if redirect.kind() == "herestring_redirect" {
                let words = node_text(redirect, source).trim_start_matches("<<<");
                inner.push(' ');
                inner.push_str(&unquote(words.trim()));
            }
        }
        for word in input {
            inner.push(' ');
            inner.push_str(word);
        }
    }

    crate::detect_destructive(&inner, cwd).map(|reason| format!("'{cmd_name}' runs: {reason}"))
}

fn check_named_command(cmd_name: &str, node: Node, source: &[u8], cwd: &str) -> Option<String> {
    if CONFIG.is_removed_command(cmd_name) {
        return None;
    }

    if CONFIG.is_extra_command(cmd_name) {
        return Some(format!(
            "'{cmd_name}' matched user-configured destructive command"
        ));
    }

    // Checked first since it wraps other commands.
    if consts::PRIV_ESC.contains(&cmd_name) {
        return Some(format!(
            "Privilege escalation via '{cmd_name}' - all elevated commands require confirmation"
        ));
    }

    if let Some(reason) = check_wrapper(cmd_name, node, source, cwd, &[]) {
        return Some(reason);
    }

    if consts::UNCONDITIONAL_DESTRUCTIVE.contains(&cmd_name) {
        return Some(format!(
            "'{cmd_name}' is a destructive filesystem operation"
        ));
    }

    if consts::DISK_COMMANDS.contains(&cmd_name) {
        return Some(format!("'{cmd_name}' modifies disk/mount state"));
    }

    if let Some(reason) = check_process_service(cmd_name, node, source) {
        return Some(reason);
    }

    if cmd_name == "find" {
        return check_find(node, source, cwd);
    }

    if matches!(cmd_name, "rm" | "rmdir" | "unlink") {
        return check_rm(cmd_name, node, source, cwd);
    }

    if matches!(cmd_name, "mv" | "cp") {
        if let Some(reason) = check_taint_file_in_args(cmd_name, node, source) {
            return Some(reason);
        }
    }

    if matches!(cmd_name, "chmod" | "chown" | "chgrp") {
        return check_permissions(cmd_name, node, source, cwd);
    }

    if let Some(reason) = check_package_manager(cmd_name, node, source) {
        return Some(reason);
    }

    if cmd_name == "git" {
        return check_git(node, source);
    }

    if let Some(reason) = check_database(cmd_name, node, source) {
        return Some(reason);
    }

    if let Some(reason) = check_container(cmd_name, node, source) {
        return Some(reason);
    }

    if let Some(reason) = check_sysadmin(cmd_name, node, source) {
        return Some(reason);
    }

    if let Some(reason) = check_nix(cmd_name, node, source) {
        return Some(reason);
    }

    if cmd_name == "docker" {
        return check_docker(node, source);
    }

    if matches!(cmd_name, "eval" | "source" | ".") {
        return check_eval(cmd_name, node, source, cwd);
    }

    None
}

enum CommandName<'a> {
    /// Known after quote removal: `"rm"`, `\rm` and `r''m` are all `rm`.
    Static(String),
    /// Only known at runtime: `$(echo rm)`, `$X`, `${X:-rm}`.
    Dynamic(&'a str),
}

fn get_command_name<'a>(node: Node, source: &'a [u8]) -> Option<CommandName<'a>> {
    let name = node.child_by_field_name("name")?;
    let text = node_text(name, source);
    if has_expansion(name) {
        return Some(CommandName::Dynamic(text));
    }
    let unquoted = unquote(text);
    // /usr/bin/rm -> rm
    let base = unquoted.rsplit('/').next().unwrap_or_default();
    Some(CommandName::Static(base.to_owned()))
}

fn has_expansion(node: Node) -> bool {
    if matches!(
        node.kind(),
        "command_substitution" | "simple_expansion" | "expansion"
    ) {
        return true;
    }
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).any(has_expansion);
    found
}

/// Approximate bash quote removal so `".."/` and `\/` match the paths bash would use.
fn unquote(s: &str) -> String {
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

fn arguments<'a>(node: Node, source: &'a [u8]) -> Vec<&'a str> {
    let mut cursor = node.walk();
    let args = node
        .children_by_field_name("argument", &mut cursor)
        .map(|arg| node_text(arg, source))
        .collect();
    args
}

fn node_text<'a>(node: Node, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}

fn get_args<'a>(node: Node, source: &'a [u8]) -> Vec<&'a str> {
    let mut args = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if matches!(
            child.kind(),
            "word" | "string" | "raw_string" | "concatenation"
        ) {
            args.push(node_text(child, source));
        }
    }
    args
}

/// Also matches combined short flags (`-rf` has `-r` and `-f`).
fn has_flag(args: &[&str], flag: &str) -> bool {
    let flag_char =
        flag.strip_prefix('-')
            .and_then(|s| if s.len() == 1 { s.chars().next() } else { None });

    for arg in args {
        if *arg == flag {
            return true;
        }
        // Length cap avoids single-dash long opts like `-forward`.
        if let Some(fc) = flag_char {
            if let Some(rest) = arg.strip_prefix('-') {
                let len = rest.len();
                if !rest.starts_with('-')
                    && (2..=4).contains(&len)
                    && rest.chars().all(|c| c.is_ascii_alphabetic())
                    && rest.contains(fc)
                {
                    return true;
                }
            }
        }
    }
    false
}

fn get_path_args<'a>(args: &[&'a str]) -> Vec<&'a str> {
    args.iter()
        .filter(|a| !a.starts_with('-'))
        .copied()
        .collect()
}

/// Positional arguments after the tool's global options, so `git -C dir push`
/// starts with `push`. `--opt=value` is a single flag word and needs no skipping.
fn subcommand_args<'a>(cmd_name: &str, args: &[&'a str]) -> Vec<&'a str> {
    let value_options = consts::GLOBAL_VALUE_OPTIONS
        .iter()
        .find(|(name, _)| *name == cmd_name)
        .map_or(&[][..], |&(_, options)| options);
    let mut start = 0;
    while let Some(arg) = args.get(start).filter(|arg| arg.starts_with('-')) {
        start += if value_options.contains(arg) { 2 } else { 1 };
    }
    get_path_args(args.get(start..).unwrap_or_default())
}

fn check_eval(cmd_name: &str, node: Node, source: &[u8], cwd: &str) -> Option<String> {
    let mut has_variable = false;
    let mut words = Vec::new();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "string" | "raw_string" => {
                let inner = node_text(child, source);
                let inner = inner
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .or_else(|| inner.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                    .unwrap_or(inner);
                if let Some(reason) = crate::detect_destructive(inner, cwd) {
                    return Some(format!(
                        "'{cmd_name}' wrapping destructive command: {reason}"
                    ));
                }
            }
            "simple_expansion" | "expansion" | "concatenation" => {
                has_variable = true;
            }
            "word" => {
                words.push(node_text(child, source));
            }
            _ => {}
        }
    }

    if has_variable {
        return Some(format!(
            "'{cmd_name}' with variable expansion - cannot verify safety"
        ));
    }

    if !words.is_empty() {
        let joined = words.join(" ");
        if let Some(reason) = crate::detect_destructive(&joined, cwd) {
            return Some(format!(
                "'{cmd_name}' wrapping destructive command: {reason}"
            ));
        }
    }

    None
}

const TAINT_FILE: &str = ".parry-tainted";

fn is_taint_file(path: &str) -> bool {
    let clean = unquote(path);
    Path::new(&clean).file_name().and_then(|f| f.to_str()) == Some(TAINT_FILE)
}

fn taint_file_reason(cmd_name: &str) -> String {
    format!("'{cmd_name}' targets parry-guard safety file '{TAINT_FILE}'")
}

fn check_taint_file_in_args(cmd_name: &str, node: Node, source: &[u8]) -> Option<String> {
    let args = get_args(node, source);
    let path_args = get_path_args(&args);
    if path_args.iter().any(|p| is_taint_file(p)) {
        return Some(taint_file_reason(cmd_name));
    }
    None
}

fn check_rm(cmd_name: &str, node: Node, source: &[u8], cwd: &str) -> Option<String> {
    let args = get_args(node, source);
    check_rm_paths(cmd_name, &get_path_args(&args), cwd)
}

fn check_rm_paths<S: AsRef<str>>(cmd_name: &str, paths: &[S], cwd: &str) -> Option<String> {
    for path in paths.iter().map(AsRef::as_ref) {
        if is_taint_file(path) {
            return Some(taint_file_reason(cmd_name));
        }

        let clean = unquote(path);

        // `rm -rf .` would wipe the whole project.
        if paths::is_cwd_itself(&clean, cwd) {
            return Some(format!("'{cmd_name}' targets project directory itself"));
        }

        if paths::is_outside_cwd(&clean, cwd) {
            return Some(format!(
                "'{cmd_name}' targets '{clean}' outside project directory"
            ));
        }
    }

    None
}

fn check_permissions(cmd_name: &str, node: Node, source: &[u8], cwd: &str) -> Option<String> {
    let args = get_args(node, source);
    let path_args = get_path_args(&args);

    for path in &path_args {
        if let Some(reason) = paths::check_protected(&unquote(path), cwd) {
            return Some(format!("'{cmd_name}' on protected path: {reason}"));
        }
    }

    None
}

fn check_process_service(cmd_name: &str, node: Node, source: &[u8]) -> Option<String> {
    if consts::PROCESS_KILL.contains(&cmd_name) {
        return Some(format!("'{cmd_name}' terminates processes"));
    }

    let args = get_args(node, source);
    let path_args = get_path_args(&args);
    let first_arg = path_args.first().copied().unwrap_or("");

    if cmd_name == "systemctl" && consts::SYSTEMCTL_DESTRUCTIVE.contains(&first_arg) {
        return Some(format!("'systemctl {first_arg}' modifies system services"));
    }

    if cmd_name == "launchctl" && consts::LAUNCHCTL_DESTRUCTIVE.contains(&first_arg) {
        return Some(format!("'launchctl {first_arg}' modifies system services"));
    }

    let service_action = path_args.get(1).copied().unwrap_or("");
    if cmd_name == "service" && consts::SERVICE_DESTRUCTIVE.contains(&service_action) {
        return Some(format!(
            "'service {first_arg} {service_action}' modifies system services"
        ));
    }

    None
}

fn check_package_manager(cmd_name: &str, node: Node, source: &[u8]) -> Option<String> {
    let args = get_args(node, source);
    let path_args = get_path_args(&args);
    let first_arg = path_args.first().copied().unwrap_or("");

    for &(pm, destructive_subcmds) in consts::PKG_MANAGER_DESTRUCTIVE {
        if cmd_name == pm && destructive_subcmds.contains(&first_arg) {
            return Some(format!("'{cmd_name} {first_arg}' removes packages"));
        }
    }

    if cmd_name == "npm"
        && consts::NPM_GLOBAL_UNINSTALL.contains(&first_arg)
        && has_flag(&args, "-g")
    {
        return Some(format!("'npm {first_arg} -g' removes global packages"));
    }

    None
}

fn check_git(node: Node, source: &[u8]) -> Option<String> {
    let args = get_args(node, source);
    let path_args = subcommand_args("git", &args);
    let subcmd = path_args.first().copied().unwrap_or("");

    if consts::GIT_HISTORY_REWRITE.contains(&subcmd) {
        return Some(format!("'git {subcmd}' rewrites repository history"));
    }

    match subcmd {
        "push" => check_git_push(&args, &path_args),
        "remote" => check_git_remote(&path_args),
        "reset" => {
            if has_flag(&args, "--hard") {
                Some("'git reset --hard' discards uncommitted changes".into())
            } else {
                None
            }
        }
        "clean" => {
            if has_flag(&args, "-f") {
                Some("'git clean -f' permanently removes untracked files".into())
            } else {
                None
            }
        }
        "branch" => {
            if has_flag(&args, "-D") {
                Some("'git branch -D' force-deletes a branch".into())
            } else {
                None
            }
        }
        "checkout" => {
            if path_args.contains(&".") {
                Some("'git checkout .' discards all unstaged changes".into())
            } else {
                None
            }
        }
        "restore" => {
            // Only the wildcard form, not specific files.
            if path_args.len() == 2 && path_args.get(1).copied() == Some(".") {
                Some("'git restore .' discards all unstaged changes".into())
            } else {
                None
            }
        }
        "rebase" => Some("'git rebase' rewrites commit history".into()),
        "stash" => {
            let second = path_args.get(1).copied().unwrap_or("");
            if second == "drop" || second == "clear" {
                Some(format!(
                    "'git stash {second}' permanently removes stashed changes"
                ))
            } else {
                None
            }
        }
        "tag" => {
            if has_flag(&args, "-d") || has_flag(&args, "--delete") {
                Some("'git tag -d' deletes tags".into())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn check_git_push(args: &[&str], path_args: &[&str]) -> Option<String> {
    let has_force = has_flag(args, "--force") || has_flag(args, "-f");
    let has_force_with_lease = args.iter().any(|a| a.starts_with("--force-with-lease"));

    if has_force && !has_force_with_lease {
        return Some("'git push --force' overwrites remote history".into());
    }

    if has_flag(args, "--delete") {
        return Some("'git push --delete' deletes remote branch".into());
    }

    // `:branch` deletes remotely; only `push` is skipped since the remote may be omitted.
    for arg in path_args.iter().skip(1) {
        if arg.starts_with(':') {
            return Some(format!("'git push {arg}' deletes remote branch"));
        }
    }

    for arg in path_args.iter().skip(1) {
        if looks_like_remote_url(arg) {
            return Some(format!(
                "'git push' to URL '{arg}' may exfiltrate repository"
            ));
        }
    }

    None
}

fn check_git_remote(path_args: &[&str]) -> Option<String> {
    let sub = path_args.get(1).copied().unwrap_or("");
    if sub == "add" || sub == "set-url" {
        let url = path_args.get(3).copied().unwrap_or("");
        if !url.is_empty() {
            return Some(format!(
                "'git remote {sub}' with URL '{url}' - verify remote is trusted"
            ));
        }
    }
    None
}

fn looks_like_remote_url(s: &str) -> bool {
    s.contains("://") || (s.contains('@') && (s.contains(':') || s.contains('/')))
}

fn check_database(cmd_name: &str, node: Node, source: &[u8]) -> Option<String> {
    let args = get_args(node, source);

    if consts::DB_CLI_COMMANDS.contains(&cmd_name) {
        return check_sql_client(cmd_name, &args);
    }
    if consts::MONGO_CLI_COMMANDS.contains(&cmd_name) {
        return check_mongo(cmd_name, &args);
    }
    if cmd_name == "mongorestore" {
        return check_mongorestore(&args);
    }
    if cmd_name == consts::REDIS_CLI {
        return check_redis(&args);
    }

    let path_args = subcommand_args(cmd_name, &args);
    let first_arg = path_args.first().copied().unwrap_or("");

    if cmd_name == "ldb" && consts::LDB_DESTRUCTIVE.contains(&first_arg) {
        return Some(format!("'ldb {first_arg}' destroys database"));
    }
    if cmd_name == "rabbitmqctl" && consts::RABBITMQ_DESTRUCTIVE.contains(&first_arg) {
        return Some(format!("'rabbitmqctl {first_arg}' destroys queue data"));
    }
    if cmd_name == "celery" && consts::CELERY_DESTRUCTIVE.contains(&first_arg) {
        return Some(format!("'celery {first_arg}' purges task queue"));
    }
    if cmd_name == "etcdctl" {
        return check_etcdctl(first_arg, &args);
    }
    if (cmd_name == "kafka-topics" || cmd_name == "kafka-topics.sh") && has_flag(&args, "--delete")
    {
        return Some("'kafka-topics --delete' deletes Kafka topics".into());
    }

    None
}

fn check_sql_client(cmd_name: &str, args: &[&str]) -> Option<String> {
    let joined = args.join(" ").to_lowercase();
    for pattern in consts::DB_DESTRUCTIVE_SQL {
        if joined.contains(pattern) {
            return Some(format!(
                "'{cmd_name}' executing destructive SQL: '{pattern}'"
            ));
        }
    }
    if joined.contains("alter table") && joined.contains("drop") {
        return Some(format!(
            "'{cmd_name}' executing destructive SQL: 'ALTER TABLE ... DROP'"
        ));
    }
    if joined.contains("delete from") && !joined.contains(" where ") && !joined.ends_with(" where")
    {
        return Some(format!(
            "'{cmd_name}' executing 'DELETE FROM' without WHERE clause"
        ));
    }
    None
}

fn check_mongo(cmd_name: &str, args: &[&str]) -> Option<String> {
    let joined = args.join(" ").to_lowercase();
    for pattern in consts::MONGO_DESTRUCTIVE {
        if joined.contains(pattern) {
            return Some(format!(
                "'{cmd_name}' executing destructive MongoDB operation: '{pattern}'"
            ));
        }
    }
    None
}

fn check_mongorestore(args: &[&str]) -> Option<String> {
    for flag in consts::MONGORESTORE_DESTRUCTIVE {
        if has_flag(args, flag) {
            return Some(format!(
                "'mongorestore {flag}' drops existing data before restore"
            ));
        }
    }
    None
}

fn check_redis(args: &[&str]) -> Option<String> {
    let joined = args.join(" ").to_lowercase();
    for pattern in consts::REDIS_DESTRUCTIVE {
        if joined.contains(pattern) {
            return Some(format!(
                "'redis-cli' executing destructive operation: '{pattern}'"
            ));
        }
    }
    None
}

fn check_etcdctl(first_arg: &str, args: &[&str]) -> Option<String> {
    if first_arg == "del" && has_flag(args, "--prefix") {
        return Some("'etcdctl del --prefix' bulk-deletes keys".into());
    }
    if first_arg == "defrag" {
        return Some("'etcdctl defrag' compacts and defragments storage".into());
    }
    None
}

fn check_container(cmd_name: &str, node: Node, source: &[u8]) -> Option<String> {
    let args = get_args(node, source);
    let path_args = subcommand_args(cmd_name, &args);
    let first_arg = path_args.first().copied().unwrap_or("");

    for &(cmd, destructive_subcmds) in consts::CONTAINER_DESTRUCTIVE {
        if cmd_name == cmd && destructive_subcmds.contains(&first_arg) {
            return Some(format!(
                "'{cmd_name} {first_arg}' is a destructive operation"
            ));
        }
    }

    None
}

fn check_docker(node: Node, source: &[u8]) -> Option<String> {
    let args = get_args(node, source);
    let path_args = subcommand_args("docker", &args);
    let first_arg = path_args.first().copied().unwrap_or("");

    match first_arg {
        "system" => {
            let second = path_args.get(1).copied().unwrap_or("");
            if second == "prune" {
                return Some("'docker system prune' removes unused data".into());
            }
        }
        "volume" => {
            let second = path_args.get(1).copied().unwrap_or("");
            if second == "rm" || second == "prune" {
                return Some("'docker volume rm/prune' removes volumes".into());
            }
        }
        "rmi" if has_flag(&args, "-f") => {
            return Some("'docker rmi -f' force-removes images".into());
        }
        _ => {}
    }

    None
}

fn check_sysadmin(cmd_name: &str, node: Node, source: &[u8]) -> Option<String> {
    let args = get_args(node, source);

    if cmd_name == "crontab" && has_flag(&args, "-r") {
        return Some("'crontab -r' removes all scheduled jobs".into());
    }

    if consts::FIREWALL_COMMANDS.contains(&cmd_name) {
        for flag in consts::FIREWALL_FLUSH_FLAGS {
            if has_flag(&args, flag) {
                return Some(format!("'{cmd_name} {flag}' flushes firewall rules"));
            }
        }
    }

    if cmd_name == "nft" {
        let path_args = get_path_args(&args);
        let first_arg = path_args.first().copied().unwrap_or("");
        if consts::NFT_FLUSH.contains(&first_arg) {
            return Some("'nft flush' clears firewall ruleset".into());
        }
    }

    None
}

fn check_nix(cmd_name: &str, node: Node, source: &[u8]) -> Option<String> {
    if consts::NIX_UNCONDITIONAL.contains(&cmd_name) {
        return Some(format!("'{cmd_name}' removes Nix store entries"));
    }

    let args = get_args(node, source);
    let path_args = get_path_args(&args);

    for &(cmd, destructive_subcmds) in consts::NIX_DESTRUCTIVE {
        if cmd_name == cmd {
            // Joined for multi-word subcommands like `store gc`.
            let subcmd_str = path_args.join(" ");
            for subcmd in destructive_subcmds {
                if subcmd_str.starts_with(subcmd) {
                    return Some(format!(
                        "'{cmd_name} {subcmd}' is a destructive Nix operation"
                    ));
                }
            }
            for subcmd in destructive_subcmds {
                if args.contains(subcmd) {
                    return Some(format!(
                        "'{cmd_name} {subcmd}' is a destructive Nix operation"
                    ));
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_flag_exact() {
        assert!(has_flag(&["-r", "-f"], "-r"));
        assert!(has_flag(&["-r", "-f"], "-f"));
        assert!(!has_flag(&["-r"], "-f"));
    }

    #[test]
    fn has_flag_combined() {
        assert!(has_flag(&["-rf"], "-r"));
        assert!(has_flag(&["-rf"], "-f"));
        assert!(!has_flag(&["-rf"], "-x"));
    }

    #[test]
    fn has_flag_long() {
        assert!(has_flag(&["--force"], "--force"));
        assert!(!has_flag(&["--force"], "--hard"));
    }

    #[test]
    fn has_flag_combined_does_not_match_long() {
        assert!(!has_flag(&["-rf"], "--recursive"));
    }

    #[test]
    fn has_flag_rejects_single_dash_long_option() {
        assert!(!has_flag(&["-forward"], "-f"));
        assert!(!has_flag(&["-format"], "-f"));
    }

    #[test]
    fn has_flag_rejects_non_alpha_combined() {
        assert!(!has_flag(&["-f=value"], "-f"));
    }

    #[test]
    fn path_args_filters_flags() {
        let args = vec!["-r", "-f", "target/", "--force"];
        let paths = get_path_args(&args);
        assert_eq!(paths, vec!["target/"]);
    }
}
