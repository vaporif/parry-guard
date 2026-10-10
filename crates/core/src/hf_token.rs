//! Fetches the `HuggingFace` token from a user-provided command (keychain, secret manager).

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretSlice, SecretString};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const STDERR_TAIL_CHARS: usize = 200;

type PipeOutput = std::io::Result<SecretSlice<u8>>;

/// Runs `command` through the platform shell and returns its trimmed stdout.
///
/// Anything the command leaves running in its process group is killed once the
/// shell exits (unix only; processes that call `setsid` escape).
///
/// # Errors
/// Fails if the command can't be spawned, exits non-zero, times out, or prints nothing.
pub fn run_token_command(command: &str) -> crate::Result<SecretString> {
    run_with_timeout(command, COMMAND_TIMEOUT)
}

fn run_with_timeout(command: &str, timeout: Duration) -> crate::Result<SecretString> {
    let deadline = Instant::now() + timeout;
    let mut child = shell(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| eyre::eyre!("failed to spawn hf-token-command: {e}"))?;

    // read on threads so a chatty command can't block on a full pipe
    let stdout = read_in_background(child.stdout.take());
    let stderr = read_in_background(child.stderr.take());

    #[cfg(unix)]
    let exited = wait_until(&child, deadline);
    #[cfg(windows)]
    let exited = wait_until(&mut child, deadline);
    // also closes pipes held by background children, so the reads below finish
    let status = kill_tree(&mut child);
    if !exited? {
        return Err(timed_out(timeout));
    }
    let status = status.map_err(|e| eyre::eyre!("failed to wait for hf-token-command: {e}"))?;

    let stdout = match stdout.recv_timeout(remaining(deadline)) {
        Ok(output) => {
            output.map_err(|e| eyre::eyre!("failed to read hf-token-command output: {e}"))?
        }
        Err(RecvTimeoutError::Timeout) => return Err(timed_out(timeout)),
        Err(RecvTimeoutError::Disconnected) => {
            return Err(eyre::eyre!("hf-token-command reader panicked"));
        }
    };
    let stdout = std::str::from_utf8(stdout.expose_secret())
        .map_err(|e| eyre::eyre!("hf-token-command output isn't UTF-8: {e}"))?;

    if !status.success() {
        let detail = stderr
            .recv_timeout(remaining(deadline))
            .ok()
            .and_then(Result::ok)
            .and_then(|err| last_line(&String::from_utf8_lossy(err.expose_secret())))
            // a traced or echoing command could repeat the token on stderr
            .filter(|line| !repeats_stdout(line, stdout))
            .map(|line| format!(": {line}"))
            .unwrap_or_default();
        return Err(eyre::eyre!("hf-token-command failed ({status}){detail}"));
    }

    let token = stdout.trim();
    if token.is_empty() {
        return Err(eyre::eyre!("hf-token-command printed an empty token"));
    }
    Ok(SecretString::from(token))
}

fn read_in_background(pipe: Option<impl Read + Send + 'static>) -> Receiver<PipeOutput> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Some(mut pipe) = pipe else {
            let _ = tx.send(Err(std::io::Error::other("pipe not captured")));
            return;
        };
        let mut buf = Vec::new();
        let read = pipe.read_to_end(&mut buf);
        let secret = SecretSlice::from(buf);
        let _ = tx.send(read.map(|_| secret));
    });
    rx
}

/// Whether the shell exited before `deadline`. Doesn't reap it on unix: while the
/// shell is a zombie its process group id can't be reused, so `kill_tree` is safe.
#[cfg(unix)]
fn wait_until(child: &Child, deadline: Instant) -> crate::Result<bool> {
    use rustix::process::{waitid, Pid, WaitId, WaitIdOptions};

    let pid = Pid::from_child(child);
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    poll_until(deadline, || {
        waitid(WaitId::Pid(pid), options)
            .map(|status| status.is_some())
            .map_err(|e| eyre::eyre!("failed to wait for hf-token-command: {e}"))
    })
}

#[cfg(windows)]
fn wait_until(child: &mut Child, deadline: Instant) -> crate::Result<bool> {
    poll_until(deadline, || {
        child
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|e| eyre::eyre!("failed to wait for hf-token-command: {e}"))
    })
}

fn poll_until(
    deadline: Instant,
    mut done: impl FnMut() -> crate::Result<bool>,
) -> crate::Result<bool> {
    loop {
        if done()? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn timed_out(timeout: Duration) -> eyre::Report {
    eyre::eyre!("hf-token-command timed out after {timeout:?}")
}

/// Last non-blank line of `text`, minus control characters (no terminal escapes in logs),
/// capped so a noisy command can't flood the log.
fn last_line(text: &str) -> Option<String> {
    text.split(['\n', '\r'])
        .map(|line| line.chars().filter(|c| !c.is_control()).collect::<String>())
        .rfind(|line| !line.trim().is_empty())
        .map(|line| line.trim().chars().take(STDERR_TAIL_CHARS).collect())
}

fn repeats_stdout(line: &str, stdout: &str) -> bool {
    stdout
        .lines()
        .map(str::trim)
        .any(|out| !out.is_empty() && line.contains(out))
}

#[cfg(unix)]
fn shell(command: &str) -> Command {
    use std::os::unix::process::CommandExt;

    let mut cmd = Command::new("sh");
    // own process group, so a timeout can kill everything the command spawned
    cmd.arg("-c").arg(command).process_group(0);
    cmd
}

#[cfg(windows)]
fn shell(command: &str) -> Command {
    use std::os::windows::process::CommandExt;

    let mut cmd = Command::new("cmd");
    // cmd.exe doesn't parse MSVC-style escaping; /S strips exactly the outer quotes
    cmd.args(["/S", "/C"]).raw_arg(format!("\"{command}\""));
    cmd
}

/// Kills the command and everything left in its process group, then reaps the shell.
#[cfg(unix)]
fn kill_tree(child: &mut Child) -> std::io::Result<std::process::ExitStatus> {
    use rustix::process::{kill_process_group, Pid, Signal};

    let _ = kill_process_group(Pid::from_child(child), Signal::KILL);
    child.wait()
}

#[cfg(windows)]
fn kill_tree(child: &mut Child) -> std::io::Result<std::process::ExitStatus> {
    let _ = child.kill();
    child.wait()
}

#[cfg(all(test, unix))]
mod tests {
    use rstest::rstest;

    use super::*;

    #[test]
    fn returns_trimmed_stdout() {
        let token = run_token_command("printf '  hf_abc\\n'").unwrap();
        assert_eq!(token.expose_secret(), "hf_abc", "token should be trimmed");
    }

    #[rstest]
    #[case::nonzero_exit("echo hf_secret; exit 3", "failed")]
    #[case::empty_output("printf '  \\n'", "empty")]
    fn command_errors(#[case] command: &str, #[case] expected: &str) {
        let err = run_token_command(command).unwrap_err().to_string();
        assert!(err.contains(expected), "got: {err}");
        assert!(!err.contains("hf_secret"), "output leaked: {err}");
    }

    #[test]
    fn hung_command_times_out() {
        let start = Instant::now();
        let err = run_with_timeout("sleep 5", Duration::from_millis(100)).unwrap_err();
        assert!(err.to_string().contains("timed out"), "got: {err}");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "should not wait for the command to finish"
        );
    }

    #[test]
    fn background_child_holding_stdout_is_killed() {
        let start = Instant::now();
        let token = run_with_timeout("(sleep 5) & echo tok", Duration::from_secs(10)).unwrap();
        assert_eq!(token.expose_secret(), "tok", "output before exit is kept");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "should not wait for the background child"
        );
    }

    #[test]
    fn timeout_kills_grandchildren() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let command = format!("sleep 30 & echo $! > '{}'; wait", pid_file.display());

        let _ = run_with_timeout(&command, Duration::from_millis(300)).unwrap_err();

        assert_dies(&pid_file);
    }

    #[rstest]
    #[case::success("echo tok")]
    #[case::failure("exit 1")]
    fn exit_kills_stragglers(#[case] tail: &str) {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let command = format!(
            "sleep 30 >/dev/null 2>&1 & echo $! > '{}'; {tail}",
            pid_file.display()
        );

        let _ = run_with_timeout(&command, Duration::from_secs(10));

        assert_dies(&pid_file);
    }

    #[test]
    fn failure_with_straggler_holding_stderr_reports_quickly() {
        let start = Instant::now();
        let err = run_with_timeout(
            "echo 'auth failed' >&2; sleep 8 >/dev/null & exit 1",
            Duration::from_secs(10),
        )
        .unwrap_err();
        assert!(err.to_string().contains("auth failed"), "got: {err}");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "should not wait for the straggler"
        );
    }

    #[expect(clippy::unwrap_used, reason = "test helper")]
    fn assert_dies(pid_file: &std::path::Path) {
        let pid = std::fs::read_to_string(pid_file).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && process_alive(pid.trim()) {
            std::thread::sleep(POLL_INTERVAL);
        }
        assert!(!process_alive(pid.trim()), "straggler {pid} survived");
    }

    #[expect(clippy::unwrap_used, reason = "test helper")]
    fn process_alive(pid: &str) -> bool {
        Command::new("kill")
            .args(["-0", pid])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    }

    #[test]
    fn failure_reports_stderr_tail() {
        let err =
            run_token_command("echo hf_secret; echo noise >&2; echo 'item not found' >&2; exit 44")
                .unwrap_err()
                .to_string();
        assert!(err.contains("item not found"), "got: {err}");
        assert!(!err.contains("noise"), "only the last line: {err}");
        assert!(!err.contains("hf_secret"), "stdout leaked: {err}");
    }

    #[rstest]
    #[case::control_chars(r"printf 'x\033[2Jy\n' >&2", "x[2Jy")]
    #[case::invalid_utf8(r"printf 'denied \377\n' >&2", "denied \u{fffd}")]
    #[case::carriage_return(r"printf 'progress 10%%\rError: x\n' >&2", "Error: x")]
    fn stderr_tail_is_sanitized(#[case] stderr: &str, #[case] expected: &str) {
        let err = run_token_command(&format!("{stderr}; exit 1"))
            .unwrap_err()
            .to_string();
        assert!(err.ends_with(expected), "got: {err:?}");
        assert!(!err.contains("progress"), "only the last segment: {err:?}");
    }

    #[test]
    fn stderr_tail_never_repeats_stdout() {
        let err = run_token_command("echo hf_secret; echo '+ echo hf_secret' >&2; exit 1")
            .unwrap_err()
            .to_string();
        assert!(
            !err.contains("hf_secret"),
            "stdout leaked via stderr: {err}"
        );
    }

    #[test]
    fn large_output_does_not_deadlock() {
        // 1 MiB exceeds the pipe buffer
        let token = run_token_command("head -c 1048576 /dev/zero | tr '\\0' a").unwrap();
        assert_eq!(
            token.expose_secret().len(),
            1_048_576,
            "full output should be read"
        );
    }
}
