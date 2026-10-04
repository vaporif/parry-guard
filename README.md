# <img src=".github/parry.svg" height="64" alt="Parry Guard"> Parry-guard

[![ci](https://github.com/vaporif/parry-guard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vaporif/parry-guard/actions/workflows/ci.yml)
[![audit](https://github.com/vaporif/parry-guard/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/vaporif/parry-guard/actions/workflows/audit.yml)
[![codecov](https://codecov.io/gh/vaporif/parry-guard/branch/main/graph/badge.svg)](https://codecov.io/gh/vaporif/parry-guard)
[![Mentioned in Awesome Claude Code](https://awesome.re/mentioned-badge-flat.svg)](https://github.com/hesreallyhim/awesome-claude-code)

A prompt injection scanner for AI coding tool hooks. It catches injection attacks, leaked secrets, and data exfiltration in tool inputs and outputs. It's built for Claude Code, and also works with Codex or any tool that runs command hooks with the same JSON input and output.

> Early development: expect bugs and false positives. Tested on Linux and macOS.

## Prerequisites

The ML models are gated on HuggingFace. Before installing:

1. Create an account at [huggingface.co](https://huggingface.co).
2. Accept the [DeBERTa v3 license](https://huggingface.co/ProtectAI/deberta-v3-small-prompt-injection-v2). All modes need it.
3. For `full` mode, also accept the [Llama Prompt Guard 2 license](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M). Meta has to approve it.
4. Create an access token at [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens).

## Usage

### Claude Code

Add to `~/.claude/settings.json`:

With [uvx](https://docs.astral.sh/uv/):

```json
{
  "hooks": {
    "PreToolUse": [{ "command": "uvx parry-guard hook", "timeout": 1000 }],
    "PostToolUse": [{ "command": "uvx parry-guard hook", "timeout": 5000 }],
    "UserPromptSubmit": [{ "command": "uvx parry-guard hook", "timeout": 2000 }]
  }
}
```

With [rvx](https://github.com/vaporif/rvx):

```json
{
  "hooks": {
    "PreToolUse": [{ "command": "rvx parry-guard hook", "timeout": 1000 }],
    "PostToolUse": [{ "command": "rvx parry-guard hook", "timeout": 5000 }],
    "UserPromptSubmit": [{ "command": "rvx parry-guard hook", "timeout": 2000 }]
  }
}
```

With `parry-guard` on your PATH (from [Nix](#nix-home-manager), `cargo install`, or a [release binary](https://github.com/vaporif/parry-guard/releases)):

```json
{
  "hooks": {
    "PreToolUse": [{ "command": "parry-guard hook", "timeout": 1000 }],
    "PostToolUse": [{ "command": "parry-guard hook", "timeout": 5000 }],
    "UserPromptSubmit": [{ "command": "parry-guard hook", "timeout": 2000 }]
  }
}
```

### Codex

Add to `~/.codex/config.toml`:

```toml
[[hooks.PreToolUse]]
matcher = "Bash|Read|Write|Edit|Glob|Grep|WebFetch|WebSearch|apply_patch|mcp__.*"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "parry-guard hook"
timeout = 1

[[hooks.PostToolUse]]
matcher = "Bash|Read|WebFetch|Edit|apply_patch|mcp__.*"

[[hooks.PostToolUse.hooks]]
type = "command"
command = "parry-guard hook"
timeout = 5

[[hooks.UserPromptSubmit]]
matcher = ""

[[hooks.UserPromptSubmit.hooks]]
type = "command"
command = "parry-guard hook"
timeout = 2
```

### Other hook runners

`parry-guard hook` reads one JSON payload from stdin and writes a JSON decision to stdout. Any tool with command hooks can use it, as long as it sends Claude/Codex-style fields (`hook_event_name`, `tool_name`, `tool_input`, `tool_response`, `prompt`) and respects block/deny responses.

Claude Code can ask you to confirm a `PreToolUse` call. Codex can't yet, so for Codex payloads parry-guard turns an "ask" into a block: it exits with a blocking code and prints the reason to stderr.

<details>
<summary>Other installation methods</summary>

From source:

```bash
# Default: ONNX backend, statically linked, 5-6x faster than Candle
cargo install --path bin

# Candle backend: pure Rust, no native deps, portable
cargo install --path bin --no-default-features --features candle
```

### Nix (home-manager)

```nix
# flake.nix
{
  inputs.parry.url = "github:vaporif/parry-guard";

  outputs = { parry, ... }: {
    # pass parry to your home-manager config via extraSpecialArgs, overlays, etc.
  };
}
```

```nix
# home-manager module
{ inputs, pkgs, config, ... }: {
  imports = [ inputs.parry.homeManagerModules.default ];

  programs.parry-guard = {
    enable = true;
    package = inputs.parry.packages.${pkgs.system}.default;  # onnx (default)
    # package = inputs.parry.packages.${pkgs.system}.candle;  # candle (pure Rust, portable, ~5-6x slower)
    hfTokenFile = config.sops.secrets.hf-token.path;
    ignoreDirs = [ "/home/user/repos/trusted" ];
    # askOnNewProject = true;  # ask before monitoring new projects (default: monitor right away)
    # claudeMdThreshold = 0.9;  # ML threshold for CLAUDE.md scanning (default 0.9)

    # scanMode = "full";  # fast (default) | full | custom

    # Custom models (auto-sets scanMode to "custom")
    # models = [
    #   { repo = "ProtectAI/deberta-v3-small-prompt-injection-v2"; }
    #   { repo = "meta-llama/Llama-Prompt-Guard-2-86M"; threshold = 0.5; }
    # ];
  };
}
```

</details>

## Setup

### HuggingFace token

Set your token one of these ways (first match wins):
```bash
export HF_TOKEN="hf_..."                          # direct value
export HF_TOKEN_PATH="/path/to/token"              # file path
# or place token at /run/secrets/hf-token-scan-injection
```

The daemon starts on the first scan, downloads the model on the first run, and stops after 30 idle minutes. Without Nix, set the env vars in your shell profile or pass flags (see [Config](#config)).

### Project scanning

By default, every new project is scanned from its first session, with no prompt. To skip a repo, run `parry-guard ignore <path>`.

To be asked first instead, set `PARRY_ASK_ON_NEW_PROJECT=true` (`askOnNewProject = true` in Nix). [docs/opt-in-flow.md](docs/opt-in-flow.md) shows the full flow.

| Command | Effect |
|---------|-------------|
| `parry-guard monitor [path]` | Turn scanning on for a repo |
| `parry-guard ignore [path]` | Turn scanning off for a repo |
| `parry-guard reset [path]` | Clear state and caches, back to unknown |
| `parry-guard status [path]` | Show current repo state and findings |
| `parry-guard repos` | List all known repos and their states |

`path` defaults to the current directory.

### What each hook does

`PreToolUse` runs 7 checks in order and stops at the first hit:

1. Skip ignored or unknown repos
2. Enforce taint
3. Scan CLAUDE.md
4. Block exfiltration
5. Catch destructive operations
6. Block sensitive paths
7. Scan input content for injection (Write, Edit, Bash, MCP tools)

`PostToolUse` scans tool output for injection and secrets. A hit taints the project.

`UserPromptSubmit` audits your `.claude/` directory for dangerous permissions, injected commands, and hook scripts.

### Daemon and cache

Hook calls start the daemon if it isn't running. You can also run it yourself with `parry-guard serve --idle-timeout 1800`.

Scan results are cached in `~/.parry-guard/scan-cache.redb` for 30 days. A cache hit takes about 8ms, versus 70ms+ for inference. All projects share the cache, and it's pruned hourly.

## Detection layers

The scanner fails closed: if it can't tell whether something is safe, it treats it as unsafe.

1. Unicode: invisible characters (PUA, unassigned codepoints), homoglyphs, RTL overrides.
2. Substring: Aho-Corasick matching for known injection phrases.
3. Secrets: 40+ regex patterns for credentials (AWS, GitHub/GitLab, cloud providers, database URIs, private keys, and more).
4. ML classification: a DeBERTa v3 model. Text is split into 256-char chunks with 25 chars of overlap, and long texts are scanned head and tail. Default threshold is 0.7.
5. Bash exfiltration: tree-sitter AST analysis for network sinks, command substitution, obfuscation (base64, hex, ROT13), DNS tunneling, cloud storage, 60+ sensitive paths, and 40+ exfil domains.
6. Script exfiltration: the same source-to-sink analysis for script files in 16 languages.

<details>
<summary>Scan modes</summary>

| Mode | Models | Latency per chunk | Backend |
|------|--------|-------------------|---------|
| `fast` (default) | DeBERTa v3 | ~50-70ms | any |
| `full` | DeBERTa v3 + Llama Prompt Guard 2 | ~1.5s | candle only |
| `custom` | User-defined (`parry-guard/models.toml` in your config dir) | varies | any |

Use `fast` for interactive work. Use `full` for high security or batch scans (`parry-guard diff --full`). DeBERTa v3 is good at common injection patterns; Llama Prompt Guard 2 is better at subtle ones like role-play jailbreaks and indirect injection. `full` flags text if either model does, so it misses less, but each chunk takes about 20x longer.

`full` mode needs the `candle` backend, since Llama Prompt Guard 2 has no ONNX export. Build with `--features candle --no-default-features`.

</details>

## Config

<details>
<summary>Global flags</summary>

| Flag | Env | Default | Effect |
|------|-----|---------|-------------|
| `--threshold` | `PARRY_THRESHOLD` | 0.7 | ML detection threshold (0.0-1.0) |
| `--claude-md-threshold` | `PARRY_CLAUDE_MD_THRESHOLD` | 0.9 | ML threshold for CLAUDE.md scanning (0.0-1.0) |
| `--scan-mode` | `PARRY_SCAN_MODE` | fast | ML scan mode: `fast`, `full`, `custom` |
| `--hf-token` | `HF_TOKEN` | | HuggingFace token (direct value) |
| `--hf-token-path` | `HF_TOKEN_PATH` | `/run/secrets/hf-token-scan-injection` | HuggingFace token file |
| `--ask-on-new-project` | `PARRY_ASK_ON_NEW_PROJECT` | false | Ask before monitoring new projects instead of monitoring them right away |
| `--ignore-dirs` | `PARRY_IGNORE_DIRS` | | Comma-separated parent directories. Every repo under them is skipped. |

</details>

<details>
<summary>Subcommand flags</summary>

| Flag | Env | Default | Effect |
|------|-----|---------|-------------|
| `serve --idle-timeout` | `PARRY_IDLE_TIMEOUT` | 1800 | Daemon idle timeout in seconds |
| `diff --full` | | false | Add the ML scan (default is fast scan only) |
| `diff -e, --extensions` | | | Filter by file extension (comma-separated) |

</details>

<details>
<summary>Environment-only variables</summary>

| Env | Default | Effect |
|-----|---------|-------------|
| `PARRY_LOG` | warn | Tracing filter (`trace`, `debug`, `info`, `warn`, `error`) |
| `PARRY_LOG_FILE` | `~/.parry-guard/parry-guard.log` | Override log file path |

</details>

Custom patterns go in `parry-guard/patterns.toml` under your config dir: `~/.config` on Linux, `~/Library/Application Support` on macOS. You can add or remove sensitive paths, exfil domains, and secret patterns.
Custom models go in `parry-guard/models.toml` in the same dir and are used with `--scan-mode custom`. See `examples/models.toml`.

<details>
<summary><h2>ML backends</h2></summary>

You need exactly one backend; the build fails without one. Nix uses ONNX on x86_64-linux, aarch64-linux, and aarch64-darwin. On other platforms, use the `candle` package.

| Feature | |
|---------|------------|
| `onnx-fetch` | ONNX, statically linked. Downloads ORT at build time. Default. |
| `candle` | Pure Rust ML. Portable, no native deps. About 5-6x slower. |
| `onnx` | ONNX, you provide `ORT_DYLIB_PATH`. |
| `onnx-coreml` | ONNX with CoreML on Apple Silicon. Experimental. |

</details>

<details>
<summary><h2>Performance</h2></summary>

Apple Silicon, release build, `fast` mode (DeBERTa v3 only). To reproduce, run `just bench-candle` or `just bench-onnx` with `HF_TOKEN` set.

| Scenario | ONNX (default) | Candle |
|---|---|---|
| Short text (1 chunk) | ~10ms | ~61ms |
| Medium text (2 chunks) | ~32ms | ~160ms |
| Long text (6 chunks) | ~136ms | ~683ms |
| Cold start (daemon + model load) | ~580ms | ~1s |
| Fast scan short-circuit | ~7ms | ~7ms |
| Cached result | ~8ms | ~8ms |

</details>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Credits

- ML model: [ProtectAI/deberta-v3-small-prompt-injection-v2](https://huggingface.co/ProtectAI/deberta-v3-small-prompt-injection-v2), also used by [LLM Guard](https://github.com/protectai/llm-guard)
- Exfil patterns: inspired by [GuardDog](https://github.com/DataDog/guarddog), Datadog's malicious package scanner
- Full scan mode optionally uses [Llama Prompt Guard 2 86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) by Meta, licensed under the [Llama 4 Community License](https://github.com/meta-llama/llama-models/blob/main/models/llama4/LICENSE). Built with Llama.

## License

MIT

Llama Prompt Guard 2 (used in `full` mode) has its own license, the Llama 4 Community License. See [LICENSE-LLAMA](LICENSE-LLAMA).
