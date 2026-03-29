# Parry-guard
[![ci](https://github.com/vaporif/parry/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vaporif/parry/actions/workflows/ci.yml)
[![Mentioned in Awesome Claude Code](https://awesome.re/mentioned-badge-flat.svg)](https://github.com/hesreallyhim/awesome-claude-code)

Prompt injection scanner for Claude Code hooks. Catches injection attacks, leaked secrets, and data exfiltration in tool inputs and outputs.

> **Early development** - bugs and false positives happen. Tested on Linux and macOS.

## Prerequisites

The ML models are gated on HuggingFace. Before installing:

1. Create an account at [huggingface.co](https://huggingface.co)
2. Accept the [DeBERTa v3 license](https://huggingface.co/ProtectAI/deberta-v3-small-prompt-injection-v2) (required for all modes)
3. For `full` mode: also accept the [Llama Prompt Guard 2 license](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) (Meta approval required)
4. Create an access token at [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)

## Usage

Add to `~/.claude/settings.json`:

**With [uvx](https://docs.astral.sh/uv/):**

```json
{
  "hooks": {
    "PreToolUse": [{ "command": "uvx parry-guard hook", "timeout": 1000 }],
    "PostToolUse": [{ "command": "uvx parry-guard hook", "timeout": 5000 }],
    "UserPromptSubmit": [{ "command": "uvx parry-guard hook", "timeout": 2000 }]
  }
}
```

**With [rvx](https://github.com/vaporif/rvx):**

```json
{
  "hooks": {
    "PreToolUse": [{ "command": "rvx parry-guard hook", "timeout": 1000 }],
    "PostToolUse": [{ "command": "rvx parry-guard hook", "timeout": 5000 }],
    "UserPromptSubmit": [{ "command": "rvx parry-guard hook", "timeout": 2000 }]
  }
}
```

**With parry-guard on PATH** (via [Nix](#nix-home-manager), cargo install, or [release binary](https://github.com/vaporif/parry/releases)):

```json
{
  "hooks": {
    "PreToolUse": [{ "command": "parry-guard hook", "timeout": 1000 }],
    "PostToolUse": [{ "command": "parry-guard hook", "timeout": 5000 }],
    "UserPromptSubmit": [{ "command": "parry-guard hook", "timeout": 2000 }]
  }
}
```

<details>
<summary>Other installation methods</summary>

**From source:**

```bash
# Default (ONNX backend - statically linked, 5-6x faster than Candle)
cargo install --path crates/cli

# Candle backend (pure Rust, no native deps, portable)
cargo install --path crates/cli --no-default-features --features candle
```

### Nix (home-manager)

```nix
# flake.nix
{
  inputs.parry.url = "github:vaporif/parry";

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
    # askOnNewProject = true;  # Ask before monitoring new projects (default: auto-monitor)
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

### 1. Configure HuggingFace token

One of (first match wins):
```bash
export HF_TOKEN="hf_..."                          # direct value
export HF_TOKEN_PATH="/path/to/token"              # file path
# or place token at /run/secrets/hf-token-scan-injection
```

The daemon starts itself on the first scan, downloads the model on the first run, and shuts down after 30 minutes of inactivity.

> **Note (non-Nix users):** The Nix home-manager module wraps the binary with all config baked in via env vars. Without Nix, set env vars in your shell profile (e.g. `HF_TOKEN`, `PARRY_IGNORE_DIRS`, `PARRY_SCAN_MODE`) — the hook command inherits them. You can also pass flags directly: `parry-guard --hf-token-path ~/.hf-token --ignore-dirs /home/user/trusted hook`. See [Config](#config) for all options.

### Project scanning

By default, parry auto-monitors every new project - scanning is active from the first session with no prompt. To opt out of a specific repo, run `parry-guard ignore <path>`.

To get ask-first behavior, set `PARRY_ASK_ON_NEW_PROJECT=true` (or `askOnNewProject = true` in Nix). See [docs/opt-in-flow.md](docs/opt-in-flow.md) for the full flow.

| Command | What it does |
|---------|-------------|
| `parry-guard monitor [path]` | Turn on scanning for a repo |
| `parry-guard ignore [path]` | Turn off scanning for a repo |
| `parry-guard reset [path]` | Clear state and caches, back to unknown |
| `parry-guard status [path]` | Show current repo state and findings |
| `parry-guard repos` | List all known repos and their states |

All commands default to the current directory if `path` is omitted.

### What each hook does

**PreToolUse** runs 7 checks in order, stopping at the first match: ignored/unknown repo skip, taint enforcement, CLAUDE.md scanning, exfil blocking, destructive operation detection, sensitive path blocking, and input content injection scanning (Write/Edit/Bash/MCP tools).

**PostToolUse** scans tool output for injection and secrets. If it finds something, it auto-taints the project.

**UserPromptSubmit** audits your `.claude/` directory for dangerous permissions, injected commands, and hook scripts.

### Daemon and cache

You can run the daemon standalone with `parry-guard serve --idle-timeout 1800`. Hook calls start it automatically if it isn't running.

Scan results are cached in `~/.parry-guard/scan-cache.redb` with a 30-day TTL. Cache hits take about 8ms vs 70ms+ for inference. The cache is shared across projects and pruned hourly.

## Detection layers

The scanner is fail-closed: if it can't tell whether something is safe, it treats it as unsafe.

1. **Unicode** invisible characters (PUA, unassigned codepoints), homoglyphs, RTL overrides
2. **Substring** Aho-Corasick matching for known injection phrases
3. **Secrets** 40+ regex patterns for credentials (AWS, GitHub/GitLab, cloud providers, database URIs, private keys, etc.)
4. **ML classification** DeBERTa v3 transformer with text chunking (256 chars, 25 overlap) and a head+tail strategy for long texts. Threshold defaults to 0.7.
5. **Bash exfiltration** tree-sitter AST analysis for data exfil: network sinks, command substitution, obfuscation (base64, hex, ROT13), DNS tunneling, cloud storage, 60+ sensitive paths, 40+ exfil domains
6. **Script exfiltration** same source-to-sink analysis for script files across 16 languages

### Scan modes

| Mode | Models | Latency per chunk | Backend |
|------|--------|-------------------|---------|
| `fast` (default) | DeBERTa v3 | ~50-70ms | any |
| `full` | DeBERTa v3 + Llama Prompt Guard 2 | ~1.5s | candle only |
| `custom` | User-defined (`~/.config/parry-guard/models.toml`) | varies | any |

Use `fast` for interactive work and `full` for high security or batch scanning (`parry-guard diff --full`). The two models have different blind spots — DeBERTa v3 is good at common injection patterns, while Llama Prompt Guard 2 is better at subtle stuff like role-play jailbreaks and indirect injections. Running both as an OR ensemble means fewer missed attacks, but at roughly 20x higher latency per chunk.

> **Note:** `full` mode needs the `candle` backend because Llama Prompt Guard 2 doesn't have an ONNX export. Build with `--features candle --no-default-features`.

## Config

### Global flags

| Flag | Env | Default | What it does |
|------|-----|---------|-------------|
| `--threshold` | `PARRY_THRESHOLD` | 0.7 | ML detection threshold (0.0-1.0) |
| `--claude-md-threshold` | `PARRY_CLAUDE_MD_THRESHOLD` | 0.9 | ML threshold for CLAUDE.md scanning (0.0-1.0) |
| `--scan-mode` | `PARRY_SCAN_MODE` | fast | ML scan mode: `fast`, `full`, `custom` |
| `--hf-token` | `HF_TOKEN` | | HuggingFace token (direct value) |
| `--hf-token-path` | `HF_TOKEN_PATH` | `/run/secrets/hf-token-scan-injection` | HuggingFace token file |
| `--ask-on-new-project` | `PARRY_ASK_ON_NEW_PROJECT` | false | Ask before monitoring new projects (default: auto-monitor) |
| `--ignore-dirs` | `PARRY_IGNORE_DIRS` | | Parent directories to ignore, comma-separated. All repos under these paths get skipped. |

### Subcommand flags

| Flag | Env | Default | What it does |
|------|-----|---------|-------------|
| `serve --idle-timeout` | `PARRY_IDLE_TIMEOUT` | 1800 | Daemon idle timeout in seconds |
| `diff --full` | | false | Use ML scan instead of fast-only |
| `diff -e, --extensions` | | | Filter by file extension (comma-separated) |

### Env-only

| Env | Default | What it does |
|-----|---------|-------------|
| `PARRY_LOG` | warn | Tracing filter (`trace`, `debug`, `info`, `warn`, `error`) |
| `PARRY_LOG_FILE` | `~/.parry-guard/parry-guard.log` | Override log file path |

Custom patterns: `~/.config/parry-guard/patterns.toml` (add/remove sensitive paths, exfil domains, secret patterns).
Custom models: `~/.config/parry-guard/models.toml` (used with `--scan-mode custom`, see `examples/models.toml`).

## ML backends

One backend is always required (enforced at compile time). Nix defaults to ONNX on x86_64-linux, aarch64-linux, and aarch64-darwin. Use the `candle` package on other platforms.

| Feature | What it is |
|---------|------------|
| `onnx-fetch` | ONNX, statically linked (downloads ORT at build time). Default. |
| `candle` | Pure Rust ML. Portable, no native deps. About 5-6x slower. |
| `onnx` | ONNX, you provide `ORT_DYLIB_PATH`. |
| `onnx-coreml` | (experimental) ONNX with CoreML on Apple Silicon. |

```bash
# Build with Candle instead of ONNX
cargo build --no-default-features --features candle
```

## Performance

Apple Silicon, release build, `fast` mode (DeBERTa v3 only). Candle is about 5-6x slower than ONNX. Run `just bench-candle` / `just bench-onnx` to reproduce (requires `HF_TOKEN`).

| Scenario | ONNX (default) | Candle |
|---|---|---|
| Short text (1 chunk) | ~10ms | ~61ms |
| Medium text (2 chunks) | ~32ms | ~160ms |
| Long text (6 chunks) | ~136ms | ~683ms |
| Cold start (daemon + model load) | ~580ms | ~1s |
| Fast scan short-circuit | ~7ms | ~7ms |
| Cached result | ~8ms | ~8ms |

> Llama Prompt Guard 2 doesn't have an ONNX export, so `full` mode needs the `candle` backend.


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, commands, and contribution guidelines.

## Credits

- ML model: [ProtectAI/deberta-v3-small-prompt-injection-v2](https://huggingface.co/ProtectAI/deberta-v3-small-prompt-injection-v2), also used by [LLM Guard](https://github.com/protectai/llm-guard)
- Exfil patterns: inspired by [GuardDog](https://github.com/DataDog/guarddog) (Datadog's malicious package scanner)
- Full scan mode optionally uses [Llama Prompt Guard 2 86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) by Meta, licensed under the [Llama 4 Community License](https://github.com/meta-llama/llama-models/blob/main/models/llama4/LICENSE). Built with Llama.

## License

MIT

Llama Prompt Guard 2 (used in `full` scan mode) is licensed separately under the Llama 4 Community License. See [LICENSE-LLAMA](LICENSE-LLAMA).
