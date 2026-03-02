# Parry
[![Check](https://github.com/vaporif/parry/actions/workflows/check.yml/badge.svg)](https://github.com/vaporif/parry/actions/workflows/check.yml)
[![Mentioned in Awesome Claude Code](https://awesome.re/mentioned-badge-flat.svg)](https://github.com/hesreallyhim/awesome-claude-code)

Prompt injection scanner for Claude Code hooks. Scans tool inputs and outputs for injection attacks, secrets, and data exfiltration attempts.

> **Early development** — this tool is under active development and may have bugs. Only tested on macOS.

## Prerequisites

The ML models are gated on HuggingFace. Before installing:

1. Create an account at [huggingface.co](https://huggingface.co)
2. Accept the [DeBERTa v3 license](https://huggingface.co/ProtectAI/deberta-v3-small-prompt-injection-v2) (required for all modes)
3. For `full` mode: also accept the [Llama Prompt Guard 2 license](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) (Meta approval required)
4. Create an access token at [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)

## Install

### cargo-binstall

```bash
cargo binstall parry-ai
```

### From source

```bash
# Default (Candle backend - pure Rust, no native deps)
cargo install --path crates/cli

# ONNX backend (faster inference, needs native libs)
cargo install --path crates/cli --no-default-features --features onnx-fetch
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

  programs.parry = {
    enable = true;
    package = inputs.parry.packages.${pkgs.system}.default;  # candle (default)
    # package = inputs.parry.packages.${pkgs.system}.onnx;  # onnx backend (5-7x faster, see Performance)
    hfTokenFile = config.sops.secrets.hf-token.path;
    ignorePaths = [ "/home/user/repos/parry" ];

    # scanMode = "full";  # fast (default) | full | custom

    # Custom models (auto-sets scanMode to "custom")
    # models = [
    #   { repo = "ProtectAI/deberta-v3-small-prompt-injection-v2"; }
    #   { repo = "meta-llama/Llama-Prompt-Guard-2-86M"; threshold = 0.5; }
    # ];
  };
}
```

You still need to configure the Claude Code hook separately (see below).

## Setup

### 1. Configure HuggingFace token

One of (first match wins):
```bash
export HF_TOKEN="hf_..."                          # direct value
export HF_TOKEN_PATH="/path/to/token"              # file path
# or place token at /run/secrets/hf-token-scan-injection
```

### 2. Add Claude Code hook

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{ "command": "parry hook", "timeout": 1000 }],
    "PostToolUse": [{ "command": "parry hook", "timeout": 5000 }],
    "UserPromptSubmit": [{ "command": "parry hook", "timeout": 2000 }]
  }
}
```

The daemon auto-starts on first scan, downloads the model on first run, and idles out after 30 minutes.

> **Note (non-Nix users):** The Nix home-manager module wraps the binary with all config baked in via env vars. Without Nix, set env vars in your shell profile (e.g. `HF_TOKEN`, `PARRY_IGNORE_PATHS`, `PARRY_SCAN_MODE`) — the hook command inherits them. Alternatively, pass flags directly in the hook command: `parry --hf-token-path ~/.hf-token --ignore-path /home/user/safe hook`. See [Config](#config) for all options.

### What each hook does

- **PreToolUse**: 5-layer security — taint enforcement, CLAUDE.md scanning, exfil blocking, sensitive path blocking, input content injection scanning (Write/Edit/Bash/MCP tools)
- **PostToolUse**: Scans tool output for injection/secrets, auto-taints project on detection
- **UserPromptSubmit**: Audits `.claude/` directory for dangerous permissions, injected commands, hook scripts

### Daemon Mode

Keep ML model loaded in memory for faster scans:

```bash
parry serve --idle-timeout 1800  # exits after 30min idle
```

Hook calls auto-start the daemon if not running (exponential backoff).

## Detection Layers

### 1. Unicode

Flags invisible characters that can hide malicious instructions:
- Private Use Area (U+E000–U+F8FF)
- Unassigned codepoints
- 3+ format characters (single BOM allowed)

### 2. Substring

Aho-Corasick matching for known patterns:

```
ignore all previous instructions
you are now
disregard above
<system>
override safety
reveal your system prompt
reverse shell
code injection
...
```

### 3. Secrets

40+ regex patterns for credentials:
- AWS keys (`AKIA...`, secret access keys)
- GitHub/GitLab tokens (`ghp_`, `glpat-`)
- Cloud providers (GCP, Azure, DigitalOcean, Heroku)
- AI services (OpenAI, Anthropic)
- Database URIs (MongoDB, PostgreSQL, MySQL, Redis)
- CI/CD (Doppler, Pulumi, HashiCorp Vault)
- Private keys (`-----BEGIN ... PRIVATE KEY-----`)

### 4. ML Classification

DeBERTa v3 transformer for semantic detection. Supports multi-model ensemble via `--scan-mode`:

| Mode | Models | Latency per chunk | Description |
|------|--------|-------------------|-------------|
| `fast` (default) | DeBERTa v3 | ~50-70ms | Single model, good baseline coverage |
| `full` | DeBERTa v3 + Llama Prompt Guard 2 | ~1.5s | OR ensemble — catches more attacks, higher latency |
| `custom` | User-defined (`~/.config/parry/models.toml`) | varies | See `examples/models.toml` |

**When to use `full` mode:** The two models are trained on different datasets and catch different attack patterns. DeBERTa v3 excels at common injection phrases and structural patterns. Llama Prompt Guard 2 is better at subtle, context-dependent attacks (e.g. role-play jailbreaks, indirect prompt injections). Running both as an OR ensemble reduces the chance of an attack slipping through either model's blind spots — at the cost of ~20x higher latency per chunk. Use `fast` for interactive workflows where latency matters; use `full` for high-security environments or when scanning untrusted content in batch (e.g. `parry diff --full`).

- Chunks long text (256 chars, 25 overlap)
- Head+tail strategy for texts >1024 chars
- Configurable threshold (default 0.7, per-model override in custom mode)

### 5. Bash Exfiltration

Tree-sitter AST analysis detects data exfiltration patterns: piping sensitive data to network sinks (`curl`, `nc`, `wget`), command substitution, file arguments (`curl -d @.env`), inline interpreter code, obfuscation (base64, hex escapes, ROT13, IFS manipulation), DNS tunneling, `/dev/tcp` pseudo-devices, cloud storage exfil (`aws s3`, `gsutil`, `rclone`), and clipboard staging.

**Sensitive paths** (60+): `.env`, `.ssh/`, `.aws/`, `.kube/config`, `.docker/config.json`, `.git-credentials`, `.bash_history`, etc.

**Exfil domains** (40+): `webhook.site`, `ngrok.io`, `pastebin.com`, `transfer.sh`, `interact.sh`, etc.

### 6. Script Exfiltration

Same source→sink analysis for script files read via `Read` tool. Supports 16 languages: Shell, Python, JavaScript, TypeScript, Ruby, PHP, Perl, PowerShell, Lua, R, Elixir, Julia, Groovy, Scala, Kotlin, Nix.

## Architecture

```
crates/
├── cli/       # Entry point
├── core/      # Unicode, substring, secrets, config (no ML)
├── ml/        # Multi-model ML scanning (DeBERTa, Llama, custom)
├── exfil/     # Tree-sitter AST analysis
├── hook/      # Claude Code integration
└── daemon/    # Persistent ML server
```

Fail-closed: panics exit 1, ML errors → suspicious, bad input → failure.

## Config

### Global flags

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--threshold` | `PARRY_THRESHOLD` | 0.7 | ML detection threshold (0.0–1.0) |
| `--scan-mode` | `PARRY_SCAN_MODE` | fast | ML scan mode: `fast`, `full`, `custom` |
| `--hf-token` | `HF_TOKEN` | — | HuggingFace token (direct value) |
| `--hf-token-path` | `HF_TOKEN_PATH` | `/run/secrets/hf-token-scan-injection` | HuggingFace token file |
| `--ignore-path` | `PARRY_IGNORE_PATHS` | — | Paths to skip scanning (comma-separated / repeatable) |

### Subcommand flags

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `serve --idle-timeout` | `PARRY_IDLE_TIMEOUT` | 1800 | Daemon idle timeout in seconds |
| `diff --full` | — | false | Use ML scan instead of fast-only |
| `diff -e, --extensions` | — | — | Filter by file extension (comma-separated) |

### Env-only

| Env | Default | Description |
|-----|---------|-------------|
| `PARRY_LOG` | warn | Tracing filter (`trace`, `debug`, `info`, `warn`, `error`) |
| `PARRY_LOG_FILE` | `~/.parry/parry.log` | Override log file path |

Custom patterns: `~/.config/parry/patterns.toml` (add/remove sensitive paths, exfil domains, secret patterns).
Custom models: `~/.config/parry/models.toml` (used with `--scan-mode custom`, see `examples/models.toml`).

## ML Backends

One backend is always required (enforced at compile time). Nix builds candle by default.

| Feature | Description |
|---------|-------------|
| `candle` | Pure Rust ML. Portable. Default. |
| `onnx-fetch` | ONNX with auto-download. Works pretty much everywhere. |
| `onnx` | ONNX, you provide `ORT_DYLIB_PATH`. |
| `onnx-coreml` | (experimental) ONNX with CoreML on Apple Silicon. |

```bash
# Build with ONNX instead of candle
cargo build --no-default-features --features onnx-fetch
```

## Performance

Benchmarked on Apple Silicon (M-series, release build, CPU inference). The daemon keeps models loaded in memory and caches scan results.

### Backend comparison

ONNX is **5-7x faster** than Candle for ML inference. Benchmarks use [criterion](https://github.com/bheisler/criterion.rs) — run `just bench-candle` / `just bench-onnx` to reproduce (requires `HF_TOKEN`). HTML reports in `target/criterion/`.

| Text | Candle | ONNX | Speedup |
|---|---|---|---|
| Short (147 chars, 1 chunk) | ~61ms | ~10ms | **6.3x** |
| Medium (460 chars, 2 chunks) | ~160ms | ~32ms | **5.0x** |
| Long (1288 chars, 6 chunks) | ~683ms | ~136ms | **5.0x** |
| Model load | ~1s | ~580ms | **1.8x** |

> Measured with `fast` mode (DeBERTa v3 only). Llama Prompt Guard 2 does not ship an ONNX export, so `full` mode currently uses Candle for PG2 regardless of backend choice.

### Daemon latency

| Scenario | `fast` mode (DeBERTa only) | `full` mode (DeBERTa + Llama PG2) |
|---|---|---|
| Cold start (daemon spawn + model load) | ~370ms | ~2.3s |
| Warm scan, short text (~120 chars) | ~70ms | ~1.6s |
| Warm scan, medium text (~280 chars, 2 chunks) | ~130ms | ~3.1s |
| Fast-scan short-circuit (regex/substring match) | ~7ms | ~7ms |
| Cached result (repeated text) | ~8ms | ~8ms |

### Per-model inference per chunk

| Model | Candle | ONNX |
|---|---|---|
| DeBERTa v3 | ~60ms | ~10ms |
| Llama Prompt Guard 2 | ~1,500ms | N/A (no ONNX export) |


## Development

```bash
nix develop              # enter dev shell with all tools (rust, just, taplo, typos, actionlint)

just check               # run all checks (clippy, test, fmt, lint, typos, audit)
just build               # build workspace (candle)
just build-onnx          # build workspace (onnx-fetch)
just test                # run tests
just test-e2e            # run ML e2e tests (requires HF_TOKEN, see below)
just bench-candle        # benchmark ML inference, candle backend (requires HF_TOKEN)
just bench-onnx          # benchmark ML inference, ONNX backend (requires HF_TOKEN)
just clippy              # lint
just fmt                 # format all (rust + toml)
just setup-hooks         # configure git hooks
```

### ML end-to-end tests

The ML e2e tests are `#[ignore]`d by default since they require a HuggingFace token and model downloads. To run them:

```bash
HF_TOKEN=hf_... just test-e2e
```

This tests both `fast` (DeBERTa only) and `full` (DeBERTa + Llama PG2) modes with semantic injection prompts and clean text. First run downloads models (~100MB each).

## Credits

- **ML model**: [ProtectAI/deberta-v3-small-prompt-injection-v2](https://huggingface.co/ProtectAI/deberta-v3-small-prompt-injection-v2)
  - Same model used by [LLM Guard](https://github.com/protectai/llm-guard)
- **Exfil patterns**: Inspired by [GuardDog](https://github.com/DataDog/guarddog) (Datadog's malicious package scanner)
- **Full scan mode** optionally uses [Llama Prompt Guard 2 86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) by Meta, licensed under the [Llama 4 Community License](https://github.com/meta-llama/llama-models/blob/main/models/llama4/LICENSE). Built with Llama.

## License

MIT

Llama Prompt Guard 2 (used in `full` scan mode) is licensed separately under the Llama 4 Community License. See [LICENSE-LLAMA](LICENSE-LLAMA).
