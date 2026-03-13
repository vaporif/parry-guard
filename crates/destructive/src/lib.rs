//! AST-based destructive operation detection.
//!
//! Detects potentially destructive system operations in bash commands
//! and checks file paths against protected system locations.

use std::sync::Mutex;

use tracing::{debug, instrument, trace};
use tree_sitter::Parser;

mod bash;
pub mod commands;
mod consts;
mod paths;

/// Mutex to serialize tree-sitter parser creation (C runtime is not thread-safe during init).
static PARSER_LOCK: Mutex<()> = Mutex::new(());

/// Parse a bash command into a tree-sitter AST.
///
/// Returns `Err` if the parser mutex is poisoned (fail-closed).
/// Returns `Ok(None)` if parsing fails or the AST contains errors (fail-open for unparsable input).
fn parse_bash(command: &str) -> Result<Option<tree_sitter::Tree>, String> {
    let tree = {
        let _guard = PARSER_LOCK.lock().map_err(|e| {
            tracing::warn!("tree-sitter parser mutex poisoned: {e}");
            "destructive operation detection unavailable (parser mutex poisoned)".to_string()
        })?;
        let mut parser = Parser::new();
        if parser
            .set_language(&tree_sitter_bash::LANGUAGE.into())
            .is_err()
        {
            return Ok(None);
        }
        match parser.parse(command, None) {
            Some(t) => t,
            None => return Ok(None),
        }
    };
    if tree.root_node().has_error() {
        Ok(None)
    } else {
        Ok(Some(tree))
    }
}

/// Check if a Bash command contains destructive operations.
///
/// Returns a human-readable reason on match. `cwd` is resolved by the caller
/// (from `HookInput.cwd` or `std::env::current_dir()`).
#[must_use]
#[instrument(skip(command), fields(command_len = command.len()))]
pub fn detect_destructive(command: &str, cwd: &str) -> Option<String> {
    let tree = match parse_bash(command) {
        Ok(Some(tree)) => tree,
        Ok(None) => return None,
        Err(reason) => return Some(reason),
    };
    let result = bash::check_node(tree.root_node(), command.as_bytes(), cwd);
    if let Some(ref reason) = result {
        debug!(%reason, "destructive operation detected");
    } else {
        trace!("no destructive operation detected");
    }
    result
}

/// Check if a file path targets a protected location.
///
/// CWD and subdirectories are excluded. `cwd` is resolved by the caller.
#[must_use]
pub fn is_protected_path(path: &str, cwd: &str) -> Option<String> {
    paths::check_protected(path, cwd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cwd() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    // === Category 1: Filesystem Destruction ===

    #[test]
    fn rm_outside_cwd_blocked() {
        let dir = make_cwd();
        let cwd = dir.path().to_str().unwrap();
        assert!(detect_destructive("rm /tmp/important", cwd).is_some());
    }

    #[test]
    fn rm_rf_root_blocked() {
        let dir = make_cwd();
        let cwd = dir.path().to_str().unwrap();
        let result = detect_destructive("rm -rf /", cwd);
        assert!(result.is_some(), "rm -rf / should be blocked");
    }

    #[test]
    fn rm_rf_target_within_cwd_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        // Create a target dir inside cwd
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let target_str = target.to_str().unwrap();
        assert!(
            detect_destructive(&format!("rm -rf {target_str}"), cwd).is_none(),
            "rm -rf within CWD should pass"
        );
    }

    #[test]
    fn rm_rf_relative_target_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        std::fs::create_dir(dir.path().join("target")).unwrap();
        assert!(
            detect_destructive("rm -rf ./target", cwd).is_none(),
            "rm -rf ./target within CWD should pass"
        );
    }

    #[test]
    fn rm_rf_node_modules_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        std::fs::create_dir(dir.path().join("node_modules")).unwrap();
        assert!(
            detect_destructive("rm -rf node_modules", cwd).is_none(),
            "rm -rf node_modules within CWD should pass"
        );
    }

    #[test]
    fn rm_rf_dot_blocked() {
        let dir = make_cwd();
        let cwd = dir.path().to_str().unwrap();
        let result = detect_destructive("rm -rf .", cwd);
        assert!(result.is_some(), "rm -rf . should be blocked");
    }

    #[test]
    fn rm_rf_dot_slash_blocked() {
        let dir = make_cwd();
        let cwd = dir.path().to_str().unwrap();
        let result = detect_destructive("rm -rf ./", cwd);
        assert!(result.is_some(), "rm -rf ./ should be blocked");
    }

    #[test]
    fn rmdir_outside_cwd_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("rmdir /tmp/somedir", cwd).is_some());
    }

    #[test]
    fn shred_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("shred /dev/sda", cwd).is_some());
    }

    #[test]
    fn mkfs_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("mkfs -t ext4 /dev/sda1", cwd).is_some());
    }

    #[test]
    fn dd_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("dd if=/dev/zero of=/dev/sda", cwd).is_some());
    }

    #[test]
    fn truncate_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("truncate -s 0 /var/log/syslog", cwd).is_some());
    }

    // === Category 2: Process / Service ===

    #[test]
    fn kill_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("kill -9 1234", cwd).is_some());
    }

    #[test]
    fn killall_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("killall nginx", cwd).is_some());
    }

    #[test]
    fn systemctl_stop_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("systemctl stop nginx", cwd).is_some());
    }

    #[test]
    fn systemctl_start_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("systemctl start nginx", cwd).is_none());
    }

    #[test]
    fn launchctl_unload_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("launchctl unload com.example.service", cwd).is_some());
    }

    // === Category 3: Permissions on protected paths ===

    #[test]
    fn chmod_protected_path_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("chmod 777 /etc/passwd", cwd).is_some());
    }

    #[test]
    fn chmod_within_cwd_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        std::fs::write(d.path().join("script.sh"), "").unwrap();
        assert!(
            detect_destructive("chmod +x ./script.sh", cwd).is_none(),
            "chmod within CWD should pass"
        );
    }

    // === Category 4: Package Managers ===

    #[test]
    fn brew_uninstall_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("brew uninstall node", cwd).is_some());
    }

    #[test]
    fn apt_remove_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("apt remove nginx", cwd).is_some());
    }

    #[test]
    fn pip_uninstall_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("pip uninstall requests", cwd).is_some());
    }

    #[test]
    fn cargo_uninstall_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("cargo uninstall ripgrep", cwd).is_some());
    }

    #[test]
    fn npm_uninstall_global_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("npm uninstall -g typescript", cwd).is_some());
    }

    #[test]
    fn npm_uninstall_global_long_flag_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("npm uninstall --global typescript", cwd).is_some());
    }

    #[test]
    fn npm_uninstall_local_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(
            detect_destructive("npm uninstall lodash", cwd).is_none(),
            "npm uninstall without -g should pass"
        );
    }

    #[test]
    fn cargo_build_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("cargo build --release", cwd).is_none());
    }

    #[test]
    fn npm_install_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("npm install", cwd).is_none());
    }

    // === Category 5: Git Destructive ===

    #[test]
    fn git_push_force_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git push --force", cwd).is_some());
    }

    #[test]
    fn git_push_f_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git push -f", cwd).is_some());
    }

    #[test]
    fn git_push_force_with_lease_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(
            detect_destructive("git push --force-with-lease", cwd).is_none(),
            "git push --force-with-lease should pass"
        );
    }

    #[test]
    fn git_push_force_overrides_force_with_lease() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(
            detect_destructive("git push --force --force-with-lease", cwd).is_some(),
            "--force overrides --force-with-lease in git"
        );
        assert!(
            detect_destructive("git push --force-with-lease --force", cwd).is_some(),
            "--force overrides --force-with-lease regardless of order"
        );
    }

    #[test]
    fn git_push_normal_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(
            detect_destructive("git push origin main", cwd).is_none(),
            "normal git push should pass"
        );
    }

    #[test]
    fn git_push_delete_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git push origin --delete feature", cwd).is_some());
    }

    #[test]
    fn git_push_colon_delete_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git push origin :feature-branch", cwd).is_some());
    }

    #[test]
    fn git_reset_hard_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git reset --hard", cwd).is_some());
    }

    #[test]
    fn git_reset_soft_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(
            detect_destructive("git reset --soft HEAD~1", cwd).is_none(),
            "git reset --soft should pass"
        );
    }

    #[test]
    fn git_clean_f_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git clean -fd", cwd).is_some());
    }

    #[test]
    fn git_branch_d_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git branch -D feature", cwd).is_some());
    }

    #[test]
    fn git_checkout_dot_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git checkout -- .", cwd).is_some());
        assert!(detect_destructive("git checkout .", cwd).is_some());
    }

    #[test]
    fn git_restore_dot_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git restore .", cwd).is_some());
    }

    #[test]
    fn git_restore_specific_file_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(
            detect_destructive("git restore src/main.rs", cwd).is_none(),
            "git restore specific file should pass"
        );
    }

    #[test]
    fn git_rebase_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git rebase main", cwd).is_some());
    }

    #[test]
    fn git_stash_drop_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git stash drop", cwd).is_some());
    }

    #[test]
    fn git_stash_clear_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git stash clear", cwd).is_some());
    }

    #[test]
    fn git_tag_delete_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git tag -d v1.0", cwd).is_some());
    }

    #[test]
    fn git_filter_branch_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git filter-branch --force", cwd).is_some());
    }

    #[test]
    fn git_stash_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(
            detect_destructive("git stash", cwd).is_none(),
            "git stash should pass"
        );
    }

    #[test]
    fn git_status_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("git status", cwd).is_none());
    }

    // === Category 6: Database / Storage ===

    #[test]
    fn psql_drop_table_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive(r#"psql -c "DROP TABLE users""#, cwd).is_some());
    }

    #[test]
    fn mysql_truncate_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive(r#"mysql -e "TRUNCATE TABLE logs""#, cwd).is_some());
    }

    #[test]
    fn psql_select_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(
            detect_destructive(r#"psql -c "SELECT * FROM users""#, cwd).is_none(),
            "psql SELECT should pass"
        );
    }

    #[test]
    fn redis_flushall_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("redis-cli FLUSHALL", cwd).is_some());
    }

    #[test]
    fn kafka_topics_delete_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("kafka-topics --delete --topic test", cwd).is_some());
    }

    // === Category 7: Disk / Mount ===

    #[test]
    fn fdisk_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("fdisk /dev/sda", cwd).is_some());
    }

    #[test]
    fn diskutil_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("diskutil eraseDisk JHFS+ Untitled /dev/disk2", cwd).is_some());
    }

    // === Category 8: Container / Orchestration ===

    #[test]
    fn kubectl_delete_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("kubectl delete pod my-pod", cwd).is_some());
    }

    #[test]
    fn terraform_destroy_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("terraform destroy", cwd).is_some());
    }

    #[test]
    fn helm_uninstall_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("helm uninstall my-release", cwd).is_some());
    }

    #[test]
    fn docker_system_prune_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("docker system prune -a", cwd).is_some());
    }

    #[test]
    fn docker_volume_rm_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("docker volume rm my-vol", cwd).is_some());
    }

    #[test]
    fn docker_build_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(
            detect_destructive("docker build -t myapp .", cwd).is_none(),
            "docker build should pass"
        );
    }

    // === Category 9: System Admin ===

    #[test]
    fn crontab_r_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("crontab -r", cwd).is_some());
    }

    #[test]
    fn crontab_l_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(
            detect_destructive("crontab -l", cwd).is_none(),
            "crontab -l should pass"
        );
    }

    #[test]
    fn iptables_flush_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("iptables -F", cwd).is_some());
    }

    #[test]
    fn nft_flush_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("nft flush ruleset", cwd).is_some());
    }

    // === Category 10: Nix ===

    #[test]
    fn nix_collect_garbage_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("nix-collect-garbage", cwd).is_some());
    }

    #[test]
    fn nix_store_gc_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("nix store gc", cwd).is_some());
    }

    #[test]
    fn nix_profile_remove_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("nix profile remove something", cwd).is_some());
    }

    #[test]
    fn nixos_rebuild_switch_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("nixos-rebuild switch", cwd).is_some());
    }

    #[test]
    fn nix_build_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(
            detect_destructive("nix build .#default", cwd).is_none(),
            "nix build should pass"
        );
    }

    #[test]
    fn nix_develop_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(
            detect_destructive("nix develop", cwd).is_none(),
            "nix develop should pass"
        );
    }

    // === Category 11: Privilege Escalation ===

    #[test]
    fn sudo_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("sudo anything", cwd).is_some());
    }

    #[test]
    fn doas_blocked() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("doas rm /tmp/file", cwd).is_some());
    }

    // === False positive tests ===

    #[test]
    fn echo_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("echo hello world", cwd).is_none());
    }

    #[test]
    fn ls_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("ls -la", cwd).is_none());
    }

    #[test]
    fn cat_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("cat README.md", cwd).is_none());
    }

    #[test]
    fn curl_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("curl https://example.com", cwd).is_none());
    }

    #[test]
    fn grep_allowed() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("grep -r pattern .", cwd).is_none());
    }

    #[test]
    fn empty_command() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(detect_destructive("", cwd).is_none());
    }

    // === Protected path tests ===

    #[test]
    fn protected_path_etc() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(is_protected_path("/etc/hosts", cwd).is_some());
    }

    #[test]
    fn protected_path_cwd_subdir() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(is_protected_path("./src/main.rs", cwd).is_none());
    }

    #[test]
    fn protected_path_home_config() {
        let d = make_cwd();
        let cwd = d.path().to_str().unwrap();
        assert!(is_protected_path("~/.config/app/config.toml", cwd).is_some());
    }
}
