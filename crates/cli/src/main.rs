//! Parry CLI - prompt injection scanner.

mod cli;

use clap::Parser;
use parry_guard_core::Config;
use std::io::Read;
use std::process::ExitCode;
use std::time::Duration;
use tracing::{debug, info, trace, warn};
use tracing_subscriber::{fmt, EnvFilter};

fn init_tracing() {
    let filter = EnvFilter::try_from_env("PARRY_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));

    let log_file = std::env::var("PARRY_LOG_FILE")
        .ok()
        .map(std::path::PathBuf::from)
        .map_or_else(
            || {
                parry_guard_daemon::transport::parry_dir(None).and_then(|dir| {
                    std::fs::create_dir_all(&dir)?;
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(dir.join("parry-guard.log"))
                })
            },
            |path| {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
            },
        );

    match log_file {
        Ok(file) => {
            fmt()
                .with_env_filter(filter)
                .with_writer(std::sync::Mutex::new(file))
                .with_ansi(false)
                .init();
        }
        Err(_) => {
            fmt().with_env_filter(filter).init();
        }
    }
}

fn main() -> ExitCode {
    init_tracing();
    // Fail-closed: any panic exits with failure
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::exit(1);
    }));

    let cli = cli::Cli::parse();

    if cli.claude_md_threshold < cli.threshold {
        warn!(
            claude_md_threshold = cli.claude_md_threshold,
            threshold = cli.threshold,
            "claude-md-threshold is lower than threshold — CLAUDE.md scanning will be more sensitive than normal content"
        );
    }

    let hf_token = cli.resolve_hf_token();
    let deprecated_ignore_paths = cli.ignore_path;

    let config = Config {
        hf_token,
        threshold: cli.threshold,
        claude_md_threshold: cli.claude_md_threshold,
        scan_mode: cli.scan_mode,
        runtime_dir: None,
    };

    match cli.command {
        Some(cli::Command::Serve { idle_timeout }) => run_serve(&config, idle_timeout),
        Some(cli::Command::Diff {
            git_ref,
            extensions,
            full,
        }) => run_diff(&config, &git_ref, extensions.as_deref(), full),
        Some(
            cmd @ (cli::Command::Ignore { .. }
            | cli::Command::Monitor { .. }
            | cli::Command::Reset { .. }
            | cli::Command::Status { .. }
            | cli::Command::Repos),
        ) => run_repo_command(cmd, config.runtime_dir.as_deref()),
        Some(cli::Command::Hook) | None => run_hook(&config, &deprecated_ignore_paths),
    }
}

fn run_hook(config: &Config, deprecated_ignore_paths: &[String]) -> ExitCode {
    use parry_guard_core::repo_db::{self, RepoDb, RepoState};

    debug!("starting hook mode");
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        warn!("failed to read stdin (fail-closed)");
        return ExitCode::FAILURE;
    }

    let input = input.trim();
    if input.is_empty() {
        debug!("empty hook input, skipping");
        return ExitCode::SUCCESS;
    }

    let hook_input: parry_guard_hook::HookInput = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(e) => {
            warn!(%e, "invalid hook JSON (fail-closed)");
            return ExitCode::FAILURE;
        }
    };

    let repo_path = hook_input
        .cwd
        .as_ref()
        .and_then(|cwd| repo_db::canonicalize_repo_path(Some(std::path::Path::new(cwd))));
    let db = RepoDb::open(config.runtime_dir.as_deref()).ok();

    // Migrate old --ignore-path values to central db (deprecation period)
    if !deprecated_ignore_paths.is_empty() {
        if let Some(ref db) = db {
            for path in deprecated_ignore_paths {
                let canonical = repo_db::canonicalize_repo_path(Some(std::path::Path::new(path)));
                let key = canonical.as_deref().unwrap_or(path);
                let (state, _) = db.get_repo_state(key);
                if state == RepoState::Unknown {
                    let _ = db.set_repo_state(key, RepoState::Ignored, None);
                }
            }
            warn!("--ignore-path is deprecated, use 'parry ignore <path>' instead");
        }
    }

    // Remove obsolete per-project .parry-guard.redb if it exists
    if let Some(ref rp) = repo_path {
        RepoDb::cleanup_old_db(std::path::Path::new(rp.as_str()));
    }

    let repo_state = db
        .as_ref()
        .zip(repo_path.as_deref())
        .map_or(RepoState::Unknown, |(db, rp)| db.get_repo_state(rp).0);

    // Dispatch by event type
    match hook_input.hook_event_name.as_deref() {
        Some("UserPromptSubmit") => {
            debug!("detected UserPromptSubmit hook");
            let code = run_audit(
                &hook_input,
                config,
                repo_state,
                db.as_ref(),
                repo_path.as_deref(),
            );
            if code != ExitCode::SUCCESS {
                return code;
            }
        }
        Some("PostToolUse") => {
            let tool = hook_input.tool_name.as_deref().unwrap_or("unknown");
            debug!(tool, "detected PostToolUse hook");
            if let Some(output) =
                parry_guard_hook::post_tool_use::process(&hook_input, config, repo_state)
            {
                info!(tool, "threat detected in tool output");
                match serde_json::to_string(&output) {
                    Ok(json) => println!("{json}"),
                    Err(e) => warn!(%e, "failed to serialize hook output"),
                }
            }
        }
        _ => {
            let tool = hook_input.tool_name.as_deref().unwrap_or("unknown");
            debug!(tool, "detected PreToolUse hook");
            if let Some(output) = parry_guard_hook::pre_tool_use::process(
                &hook_input,
                config,
                repo_state,
                db.as_ref(),
                repo_path.as_deref(),
            ) {
                if output.is_deny() {
                    info!(tool, "tool denied by PreToolUse");
                    eprintln!("{}", output.reason());
                    return ExitCode::from(2);
                }
                info!(tool, "tool requires approval (PreToolUse)");
                match serde_json::to_string(&output) {
                    Ok(json) => println!("{json}"),
                    Err(e) => warn!(%e, "failed to serialize PreToolUse output"),
                }
            }
        }
    }

    ExitCode::SUCCESS
}

fn run_audit(
    hook_input: &parry_guard_hook::HookInput,
    config: &Config,
    repo_state: parry_guard_core::repo_db::RepoState,
    db: Option<&parry_guard_core::repo_db::RepoDb>,
    repo_path: Option<&str>,
) -> ExitCode {
    use parry_guard_core::repo_db::RepoState;

    if repo_state == RepoState::Ignored {
        debug!("repo ignored, skipping audit");
        return ExitCode::SUCCESS;
    }

    let dir = hook_input
        .cwd
        .as_ref()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_dir().ok());

    let Some(dir) = dir else {
        warn!("no cwd available for audit");
        return ExitCode::SUCCESS;
    };

    let warnings = match parry_guard_hook::project_audit::scan(&dir, config, db, repo_path) {
        Ok(w) => w,
        Err(e) => {
            warn!(%e, "audit ML scan failed (fail-closed)");
            let message = format!(
                "parry: project audit failed — ML scanner unavailable. \
                 Run `parry serve` and retry. Error: {e}"
            );
            let output = parry_guard_hook::HookOutput::user_prompt_warning(&message);
            if let Ok(json) = serde_json::to_string(&output) {
                println!("{json}");
            }
            return ExitCode::FAILURE;
        }
    };

    let is_first_run = repo_state == RepoState::Unknown;

    if is_first_run {
        if let (Some(db), Some(rp)) = (db, repo_path) {
            let remote = parry_guard_core::repo_db::git_remote_url(&dir);
            let _ = db.set_repo_state(rp, RepoState::Monitored, remote.as_deref());
        }
    }

    if warnings.is_empty() {
        if is_first_run {
            let rp_display = repo_path.unwrap_or("this repo");
            let cmd = command_name();
            let message = format!(
                "Parry: first scan of {rp_display} — no issues found. Now monitoring. \
                 Run '{cmd} ignore' to stop scanning, or '{cmd} monitor' to keep scanning."
            );
            let output = parry_guard_hook::HookOutput::user_prompt_warning(&message);
            if let Ok(json) = serde_json::to_string(&output) {
                println!("{json}");
            }
        }
        debug!("audit clean");
        return ExitCode::SUCCESS;
    }

    let mut message = parry_guard_hook::project_audit::format_warnings(&warnings);
    if is_first_run {
        let rp_display = repo_path.unwrap_or("this repo");
        let cmd = command_name();
        message.push_str(&format!(
            "\nParry: first scan of {rp_display}. Now monitoring. \
             Run '{cmd} ignore' to stop scanning, or '{cmd} reset' to re-scan."
        ));
    }
    info!(count = warnings.len(), "audit warnings");
    let output = parry_guard_hook::HookOutput::user_prompt_warning(&message);
    match serde_json::to_string(&output) {
        Ok(json) => println!("{json}"),
        Err(e) => warn!(%e, "failed to serialize audit output"),
    }

    ExitCode::SUCCESS
}

/// Detect the command prefix based on how the binary was installed.
/// Returns e.g. `"uvx parry-guard"`, `"rvx parry-guard"`, or `"parry-guard"`.
fn command_name() -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok());
    let path_str = exe.as_deref().and_then(|p| p.to_str()).unwrap_or("");

    if path_str.contains("/.cache/uv/") || path_str.contains("/.local/share/uv/") {
        "uvx parry-guard".to_string()
    } else if path_str.contains("/.cache/rvx/") || path_str.contains("/.local/share/rvx/") {
        "rvx parry-guard".to_string()
    } else {
        "parry-guard".to_string()
    }
}

fn resolve_repo_path(path: Option<&std::path::Path>) -> Result<String, ExitCode> {
    parry_guard_core::repo_db::canonicalize_repo_path(path).ok_or_else(|| {
        eprintln!("error: cannot resolve path");
        ExitCode::FAILURE
    })
}

fn run_repo_command(subcommand: cli::Command, runtime_dir: Option<&std::path::Path>) -> ExitCode {
    use parry_guard_core::repo_db::{self, RepoDb, RepoState};

    let db = match RepoDb::open(runtime_dir) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("error: cannot open repo database: {e}");
            return ExitCode::FAILURE;
        }
    };

    match subcommand {
        cli::Command::Ignore { path } => {
            let Ok(canonical) = resolve_repo_path(path.as_deref()) else {
                return ExitCode::FAILURE;
            };
            let remote = repo_db::git_remote_url(std::path::Path::new(&canonical));
            if let Err(e) = db.set_repo_state(&canonical, RepoState::Ignored, remote.as_deref()) {
                eprintln!("error: failed to set repo state: {e}");
                return ExitCode::FAILURE;
            }
            println!("Set {canonical} to ignored");
            ExitCode::SUCCESS
        }
        cli::Command::Monitor { path } => {
            let Ok(canonical) = resolve_repo_path(path.as_deref()) else {
                return ExitCode::FAILURE;
            };
            let remote = repo_db::git_remote_url(std::path::Path::new(&canonical));
            if let Err(e) = db.set_repo_state(&canonical, RepoState::Monitored, remote.as_deref()) {
                eprintln!("error: failed to set repo state: {e}");
                return ExitCode::FAILURE;
            }
            println!("Set {canonical} to monitored");
            ExitCode::SUCCESS
        }
        cli::Command::Reset { path } => {
            let Ok(canonical) = resolve_repo_path(path.as_deref()) else {
                return ExitCode::FAILURE;
            };
            db.reset_repo(&canonical);
            println!("Reset {canonical} to unknown (caches cleared)");
            ExitCode::SUCCESS
        }
        cli::Command::Status { path } => {
            let Ok(canonical) = resolve_repo_path(path.as_deref()) else {
                return ExitCode::FAILURE;
            };
            let (state, remote) = db.get_repo_state(&canonical);
            println!("Path:    {canonical}");
            println!("State:   {}", state.as_str());
            if let Some(url) = remote {
                println!("Remote:  {url}");
            }
            ExitCode::SUCCESS
        }
        cli::Command::Repos => {
            let repos = db.list_repos();
            if repos.is_empty() {
                println!("No known repos.");
            } else {
                for entry in &repos {
                    let remote = entry
                        .remote
                        .as_deref()
                        .map_or(String::new(), |r| format!("  ({r})"));
                    println!("{:<40} {:<12}{remote}", entry.path, entry.state.as_str(),);
                }
            }
            ExitCode::SUCCESS
        }
        _ => unreachable!(),
    }
}

fn run_diff(config: &Config, git_ref: &str, extensions: Option<&str>, full: bool) -> ExitCode {
    debug!(git_ref, full, "starting diff mode");

    let output = match std::process::Command::new("git")
        .args(["diff", "--name-only", git_ref])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            warn!(%e, "failed to run git diff");
            return ExitCode::FAILURE;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(%stderr, "git diff failed");
        return ExitCode::FAILURE;
    }

    let files: Vec<&str> = std::str::from_utf8(&output.stdout)
        .unwrap_or("")
        .lines()
        .filter(|s| !s.is_empty())
        .collect();

    if files.is_empty() {
        info!("no changed files");
        println!("No changed files since {git_ref}");
        return ExitCode::SUCCESS;
    }

    let ext_filter: Option<Vec<&str>> = extensions.map(|e| e.split(',').map(str::trim).collect());
    let mut detected: Vec<(&str, parry_guard_core::ScanResult)> = Vec::new();
    let mut scanned = 0;

    for file in &files {
        if let Some(ref exts) = ext_filter {
            let file_ext = std::path::Path::new(file)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if !exts.iter().any(|e| e.eq_ignore_ascii_case(file_ext)) {
                trace!(file, "skipping due to extension filter");
                continue;
            }
        }

        let content = match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(e) => {
                debug!(file, %e, "skipping file (deleted or unreadable)");
                continue;
            }
        };

        scanned += 1;
        debug!(file, "scanning");
        let result = if full {
            match parry_guard_hook::scan_text(&content, config) {
                Ok(r) => r,
                Err(e) => {
                    warn!(%e, "scan failed");
                    return ExitCode::FAILURE;
                }
            }
        } else {
            parry_guard_core::scan_text_fast(&content)
        };

        if !result.is_clean() {
            info!(file, ?result, "threat detected");
            detected.push((file, result));
        }
    }

    println!("Scanned {scanned} file(s) changed since {git_ref}");

    if detected.is_empty() {
        println!("No threats detected.");
        ExitCode::SUCCESS
    } else {
        println!("\nThreats detected in {} file(s):", detected.len());
        for (file, result) in &detected {
            println!("  {file}: {result:?}");
        }
        ExitCode::FAILURE
    }
}

fn run_serve(config: &Config, idle_timeout: u64) -> ExitCode {
    if let Err(e) = fork::daemon(false, false) {
        warn!(%e, "daemonization failed");
        return ExitCode::FAILURE;
    }

    info!(idle_timeout, "starting daemon server");
    let daemon_config = parry_guard_daemon::DaemonConfig {
        idle_timeout: Duration::from_secs(idle_timeout),
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            warn!(%e, "failed to build tokio runtime");
            return ExitCode::FAILURE;
        }
    };

    match rt.block_on(parry_guard_daemon::run(config, &daemon_config)) {
        Ok(()) => {
            info!("daemon shutdown cleanly");
            ExitCode::SUCCESS
        }
        Err(e) => {
            warn!(%e, "daemon error");
            ExitCode::FAILURE
        }
    }
}
