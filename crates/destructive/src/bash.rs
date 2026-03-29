//! AST-based bash command analysis for destructive operations.

use tree_sitter::Node;

use crate::commands::CONFIG;
use crate::consts;
use crate::paths;

/// Walk a tree-sitter AST node looking for destructive operations.
pub fn check_node(node: Node, source: &[u8], cwd: &str) -> Option<String> {
    match node.kind() {
        "command" => check_command(node, source, cwd),
        "function_definition" => check_function_body(node, source, cwd),
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(reason) = check_node(child, source, cwd) {
                    return Some(reason);
                }
            }
            None
        }
    }
}

fn check_command(node: Node, source: &[u8], cwd: &str) -> Option<String> {
    let cmd_name = get_command_name(node, source)?;

    // user allowlisted this command
    if CONFIG.is_removed_command(cmd_name) {
        return None;
    }

    // user-configured extra destructive commands
    if CONFIG.extra_commands.iter().any(|c| c == cmd_name) {
        return Some(format!(
            "'{cmd_name}' matched user-configured destructive command"
        ));
    }

    // privilege escalation - always first since it wraps other commands
    if consts::PRIV_ESC.contains(&cmd_name) {
        return Some(format!(
            "Privilege escalation via '{cmd_name}' - all elevated commands require confirmation"
        ));
    }

    // unconditional filesystem destruction (shred, wipefs, etc.)
    if consts::UNCONDITIONAL_DESTRUCTIVE.contains(&cmd_name) {
        return Some(format!(
            "'{cmd_name}' is a destructive filesystem operation"
        ));
    }

    // disk / mount
    if consts::DISK_COMMANDS.contains(&cmd_name) {
        return Some(format!("'{cmd_name}' modifies disk/mount state"));
    }

    // process / service management
    if let Some(reason) = check_process_service(cmd_name, node, source) {
        return Some(reason);
    }

    // rm / rmdir - needs path analysis
    if cmd_name == "rm" || cmd_name == "rmdir" {
        return check_rm(cmd_name, node, source, cwd);
    }

    // permissions on protected paths
    if matches!(cmd_name, "chmod" | "chown" | "chgrp") {
        return check_permissions(cmd_name, node, source, cwd);
    }

    // package managers
    if let Some(reason) = check_package_manager(cmd_name, node, source) {
        return Some(reason);
    }

    // git destructive ops
    if cmd_name == "git" {
        return check_git(node, source);
    }

    // database / storage
    if let Some(reason) = check_database(cmd_name, node, source) {
        return Some(reason);
    }

    // container / orchestration
    if let Some(reason) = check_container(cmd_name, node, source) {
        return Some(reason);
    }

    // system admin
    if let Some(reason) = check_sysadmin(cmd_name, node, source) {
        return Some(reason);
    }

    // nix
    if let Some(reason) = check_nix(cmd_name, node, source) {
        return Some(reason);
    }

    // docker (needs subcommand inspection)
    if cmd_name == "docker" {
        return check_docker(node, source);
    }

    // nested structures (command substitutions, etc.)
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "command" {
            if let Some(reason) = check_node(child, source, cwd) {
                return Some(reason);
            }
        }
    }

    None
}

fn get_command_name<'a>(node: Node, source: &'a [u8]) -> Option<&'a str> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "command_name" {
            let text = node_text(child, source);
            // /usr/bin/rm -> rm
            return Some(text.rsplit('/').next().unwrap_or(text));
        }
    }
    None
}

fn node_text<'a>(node: Node, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}

/// Collect all arguments (non-command-name children that are words/strings).
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

/// Check if any of the given flags appear in the args list.
/// Handles combined flags like `-rf` matching both `-r` and `-f`.
fn has_flag(args: &[&str], flag: &str) -> bool {
    let flag_char =
        flag.strip_prefix('-')
            .and_then(|s| if s.len() == 1 { s.chars().next() } else { None });

    for arg in args {
        // exact match (-r, --force, etc.)
        if *arg == flag {
            return true;
        }
        // combined short flags: -rf means both -r and -f
        // cap at 4 chars to avoid matching single-dash long opts like -forward
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

/// Extract non-flag arguments (paths, subcommands, etc.)
fn get_path_args<'a>(args: &[&'a str]) -> Vec<&'a str> {
    args.iter()
        .filter(|a| !a.starts_with('-'))
        .copied()
        .collect()
}

fn check_function_body(node: Node, source: &[u8], cwd: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "compound_statement" {
            return check_node(child, source, cwd);
        }
    }
    None
}

// --- category checks ---

fn check_rm(cmd_name: &str, node: Node, source: &[u8], cwd: &str) -> Option<String> {
    let args = get_args(node, source);
    let path_args = get_path_args(&args);

    for path in &path_args {
        // strip quotes around paths
        let clean = path.trim_matches(|c| c == '\'' || c == '"');

        // rm -rf . / rm -rf ./ - nuking the project dir
        if paths::is_cwd_itself(clean, cwd) {
            return Some(format!("'{cmd_name}' targets project directory itself"));
        }

        if paths::is_outside_cwd(clean, cwd) {
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
        let clean = path.trim_matches(|c| c == '\'' || c == '"');
        if let Some(reason) = paths::check_protected(clean, cwd) {
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

    if cmd_name == "service" && consts::SERVICE_DESTRUCTIVE.contains(&first_arg) {
        return Some(format!("'service {first_arg}' modifies system services"));
    }

    None
}

fn check_package_manager(cmd_name: &str, node: Node, source: &[u8]) -> Option<String> {
    let args = get_args(node, source);
    let path_args = get_path_args(&args);
    let first_arg = path_args.first().copied().unwrap_or("");

    // standard package managers
    for &(pm, destructive_subcmds) in consts::PKG_MANAGER_DESTRUCTIVE {
        if cmd_name == pm && destructive_subcmds.contains(&first_arg) {
            return Some(format!("'{cmd_name} {first_arg}' removes packages"));
        }
    }

    // npm: only flag with -g
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
    let path_args = get_path_args(&args);
    let subcmd = path_args.first().copied().unwrap_or("");

    // history rewriting
    if consts::GIT_HISTORY_REWRITE.contains(&subcmd) {
        return Some(format!("'git {subcmd}' rewrites repository history"));
    }

    match subcmd {
        "push" => check_git_push(&args, &path_args),
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
            // git checkout . or git checkout -- .
            if args.contains(&".") {
                Some("'git checkout .' discards all unstaged changes".into())
            } else {
                None
            }
        }
        "restore" => {
            // only the wildcard form, not specific files
            let mut rest = path_args.iter().skip(1);
            if rest.clone().count() == 1 && rest.next().copied() == Some(".") {
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
    // git push --force / -f (but NOT --force-with-lease)
    let has_force = has_flag(args, "--force") || has_flag(args, "-f");
    let has_force_with_lease = args.iter().any(|a| a.starts_with("--force-with-lease"));

    if has_force && !has_force_with_lease {
        return Some("'git push --force' overwrites remote history".into());
    }

    // git push origin --delete branch
    if has_flag(args, "--delete") {
        return Some("'git push --delete' deletes remote branch".into());
    }

    // git push origin :branch (colon-prefix deletes remote branch)
    // skip "push" itself - remote name may be omitted
    for arg in path_args.iter().skip(1) {
        if arg.starts_with(':') {
            return Some(format!("'git push {arg}' deletes remote branch"));
        }
    }

    None
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

    let path_args = get_path_args(&args);
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
    let path_args = get_path_args(&args);
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
    let path_args = get_path_args(&args);
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

    // crontab -r
    if cmd_name == "crontab" && has_flag(&args, "-r") {
        return Some("'crontab -r' removes all scheduled jobs".into());
    }

    // iptables -F / ip6tables -F
    if consts::FIREWALL_COMMANDS.contains(&cmd_name) {
        for flag in consts::FIREWALL_FLUSH_FLAGS {
            if has_flag(&args, flag) {
                return Some(format!("'{cmd_name} {flag}' flushes firewall rules"));
            }
        }
    }

    // nft flush ruleset
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
    // always destructive
    if consts::NIX_UNCONDITIONAL.contains(&cmd_name) {
        return Some(format!("'{cmd_name}' removes Nix store entries"));
    }

    let args = get_args(node, source);
    let path_args = get_path_args(&args);

    // destructive only with certain subcommands
    for &(cmd, destructive_subcmds) in consts::NIX_DESTRUCTIVE {
        if cmd_name == cmd {
            // join args for multi-word subcommands like "store gc"
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
        // -forward should NOT match -f (it's not a combined short flag)
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
