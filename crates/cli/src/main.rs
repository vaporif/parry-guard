//! Parry CLI - prompt injection scanner.

mod cli;

use clap::Parser;
use parry_core::Config;
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
                parry_daemon::transport::parry_dir().and_then(|dir| {
                    std::fs::create_dir_all(&dir)?;
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(dir.join("parry.log"))
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

    let config = Config {
        hf_token: cli.resolve_hf_token(),
        threshold: cli.threshold,
        ignore_paths: cli.ignore_path,
        scan_mode: cli.scan_mode,
    };

    match cli.command {
        Some(cli::Command::Serve { idle_timeout }) => run_serve(&config, idle_timeout),
        Some(cli::Command::Diff {
            git_ref,
            extensions,
            full,
        }) => run_diff(&config, &git_ref, extensions.as_deref(), full),
        Some(cli::Command::Hook) | None => run_hook(&config),
    }
}

fn run_hook(config: &Config) -> ExitCode {
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

    let hook_input: parry_hook::HookInput = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(e) => {
            warn!(%e, "invalid hook JSON (fail-closed)");
            return ExitCode::FAILURE;
        }
    };

    // Dispatch by event type
    match hook_input.hook_event_name.as_deref() {
        Some("UserPromptSubmit") => {
            debug!("detected UserPromptSubmit hook");
            let code = run_audit(&hook_input, config);
            if code != ExitCode::SUCCESS {
                return code;
            }
        }
        Some("PostToolUse") => {
            let tool = hook_input.tool_name.as_deref().unwrap_or("unknown");
            debug!(tool, "detected PostToolUse hook");
            if let Some(output) = parry_hook::post_tool_use::process(&hook_input, config) {
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
            if let Some(output) = parry_hook::pre_tool_use::process(&hook_input, config) {
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

fn run_audit(hook_input: &parry_hook::HookInput, config: &Config) -> ExitCode {
    let dir = hook_input
        .cwd
        .as_ref()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_dir().ok());

    let Some(dir) = dir else {
        warn!("no cwd available for audit");
        return ExitCode::SUCCESS;
    };

    let result = match parry_hook::project_audit::scan(&dir, config) {
        Ok(r) => r,
        Err(e) => {
            warn!(%e, "audit ML scan failed (fail-closed)");
            eprintln!("parry: project audit failed — ML scanner unavailable: {e}");
            return ExitCode::FAILURE;
        }
    };

    if result.manifest.is_empty() && result.warnings.is_empty() {
        debug!("audit clean (cached)");
        return ExitCode::SUCCESS;
    }

    let message = parry_hook::project_audit::format_output(&result);
    info!(
        warnings = result.warnings.len(),
        manifest_entries = result.manifest.len(),
        "audit complete"
    );
    let output = parry_hook::HookOutput::user_prompt_warning(&message);
    match serde_json::to_string(&output) {
        Ok(json) => println!("{json}"),
        Err(e) => warn!(%e, "failed to serialize audit output"),
    }

    ExitCode::SUCCESS
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
    let mut detected: Vec<(&str, parry_core::ScanResult)> = Vec::new();
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
            match parry_hook::scan_text(&content, config) {
                Ok(r) => r,
                Err(e) => {
                    warn!(%e, "scan failed");
                    return ExitCode::FAILURE;
                }
            }
        } else {
            parry_core::scan_text_fast(&content)
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
    let daemon_config = parry_daemon::DaemonConfig {
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

    match rt.block_on(parry_daemon::run(config, &daemon_config)) {
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
