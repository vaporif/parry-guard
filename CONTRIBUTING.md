# Contributing to Parry

Thanks for contributing to Parry.

> **Note:** Parry is in alpha. False positives are expected — if you encounter one, please open an issue so we can improve detection.

## How to Contribute

### Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- Parry version, Claude Code version and OS

### Suggesting Features

Open an issue describing the use case. Discussion before implementation saves time.

### Submitting Pull Requests

1. Create an issue first for non-trivial changes
2. Branch from `main`
3. Write tests for your changes
4. Run `just fmt` to auto-format before committing
5. Run `just check` (runs clippy, tests, formatting, lints, typos)
6. Submit a PR to `main` — use the PR template checklist

For minor fixes (typos, small bug fixes), a PR without an issue is fine.

## Development Setup

This project uses a [Nix](https://nixos.org/) dev shell that provides all required tools. If you have Nix installed with flakes enabled:

```bash
nix develop
```

This gives you: Rust stable toolchain (cargo, clippy, rustfmt, rust-analyzer), just, taplo, typos, actionlint, and cargo-nextest.

**Without Nix**, install these manually:

- [Rust](https://rustup.rs/) (stable)
- [just](https://github.com/casey/just) — command runner
- [taplo](https://taplo.tamasfe.dev/) — TOML formatter/linter
- [typos](https://github.com/crate-ci/typos) — spell checker
- [actionlint](https://github.com/rhysd/actionlint) — GitHub Actions linter
- [cargo-nextest](https://nexte.st/) — test runner

### Commands

```bash
just check               # run all checks (clippy, test, fmt, lint, typos, audit)
just build               # build workspace (candle)
just build-onnx          # build workspace (onnx-fetch)
just test                # run tests
just e2e                 # run ML e2e tests (requires HF_TOKEN, see below)
just bench-candle        # benchmark ML inference, candle backend (requires HF_TOKEN)
just bench-onnx          # benchmark ML inference, ONNX backend (requires HF_TOKEN)
just clippy              # lint
just fmt                 # format all (rust + toml)
just setup-hooks         # configure git hooks
```

### ML end-to-end tests

The ML e2e tests are `#[ignore]`d by default since they require a HuggingFace token and model downloads. To run them:

```bash
HF_TOKEN=hf_... just e2e
```

This tests both `fast` (DeBERTa only) and `full` (DeBERTa + Llama PG2) modes with semantic injection prompts and clean text. First run downloads models (~100MB each).

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
