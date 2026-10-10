//! Fetches the `HuggingFace` token from a user-provided command (keychain, secret manager).

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Runs `command` through the platform shell and returns its trimmed stdout.
///
/// # Errors
/// Fails if the command can't be spawned, exits non-zero, times out, or prints nothing.
pub fn run_token_command(command: &str) -> crate::Result<SecretString> {
    run_with_timeout(command, COMMAND_TIMEOUT)
}

fn run_with_timeout(command: &str, timeout: Duration) -> crate::Result<SecretString> {
    let mut child = shell(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| eyre::eyre!("failed to spawn hf-token-command: {e}"))?;

    // read on a thread so a chatty command can't block on a full pipe
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| eyre::eyre!("hf-token-command stdout not captured"))?;
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let read = stdout.read_to_string(&mut buf);
        let secret = SecretString::from(buf);
        read.map(|_| secret)
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| eyre::eyre!("failed to wait for hf-token-command: {e}"))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(eyre::eyre!(
                "hf-token-command timed out after {}s",
                timeout.as_secs()
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    };

    if !status.success() {
        return Err(eyre::eyre!("hf-token-command failed: {status}"));
    }

    let output = reader
        .join()
        .map_err(|_panic| eyre::eyre!("hf-token-command reader panicked"))?
        .map_err(|e| eyre::eyre!("failed to read hf-token-command output: {e}"))?;
    let token = output.expose_secret().trim();
    if token.is_empty() {
        return Err(eyre::eyre!("hf-token-command printed an empty token"));
    }
    Ok(SecretString::from(token))
}

#[cfg(unix)]
fn shell(command: &str) -> Command {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);
    cmd
}

#[cfg(windows)]
fn shell(command: &str) -> Command {
    let mut cmd = Command::new("cmd");
    cmd.arg("/C").arg(command);
    cmd
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn returns_trimmed_stdout() {
        let token = run_token_command("printf '  hf_abc\\n'").unwrap();
        assert_eq!(token.expose_secret(), "hf_abc", "token should be trimmed");
    }

    #[test]
    fn nonzero_exit_is_error() {
        let err = run_token_command("echo hf_abc; exit 3").unwrap_err();
        assert!(err.to_string().contains("failed"), "got: {err}");
    }

    #[test]
    fn empty_output_is_error() {
        let err = run_token_command("printf '  \\n'").unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn error_does_not_leak_output() {
        let err = run_token_command("echo hf_secret; exit 1").unwrap_err();
        assert!(!err.to_string().contains("hf_secret"), "got: {err}");
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
