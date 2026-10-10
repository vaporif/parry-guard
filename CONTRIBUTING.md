# Contributing to Parry

Thanks for helping out.

Parry is in alpha, so false positives are expected. If you hit one, please open an issue so we can improve detection.

## Bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- Parry version, Claude Code version, and OS

## Feature ideas

Open an issue that describes the use case. Talking it through before writing code saves time.

## Pull requests

1. Open an issue first for anything non-trivial. Small fixes (typos, small bugs) can go straight to a PR.
2. Branch from `main`.
3. Write tests for your change.
4. Run `just fmt` before committing.
5. Run `just c` and `just t`. Together they cover checks, clippy, formatting, lints, typos, ast-grep rules, and tests.
6. Open the PR against `main` and fill in the template checklist.

## Dev setup

The [Nix](https://nixos.org/) dev shell has every tool you need. With Nix and flakes enabled:

```bash
nix develop
```

It gives you the stable Rust toolchain (cargo, clippy, rustfmt, rust-analyzer), just, taplo, typos, actionlint, ast-grep, and cargo-nextest.

Without Nix, install these yourself:

- [Rust](https://rustup.rs/) (stable)
- [just](https://github.com/casey/just): command runner
- [taplo](https://taplo.tamasfe.dev/): TOML formatter and linter
- [typos](https://github.com/crate-ci/typos): spell checker
- [actionlint](https://github.com/rhysd/actionlint): GitHub Actions linter
- [ast-grep](https://ast-grep.github.io/): structural lint rules in `rules/`
- [cargo-nextest](https://nexte.st/): test runner

### Commands

```bash
just check / just c      # cargo check, clippy, fmt, taplo, typos, nix fmt, actionlint, ast-grep
just build               # build workspace (onnx-fetch, the default)
just build-onnx          # build workspace (onnx-fetch)
just test / just t       # run tests
just e2e                 # run ML e2e tests, candle backend (requires HF_TOKEN, see below)
just bench-candle        # benchmark ML inference, candle backend (requires HF_TOKEN)
just bench-onnx          # benchmark ML inference, ONNX backend (requires HF_TOKEN)
just clippy              # lint
just lint-ast            # run ast-grep rules
just mutants             # mutation testing, all mutants (slow)
just mutants-diff        # mutation testing on changes vs main
just fmt                 # format all (rust + toml)
just setup-hooks         # install git hooks (lefthook)
```

### ast-grep rules

The rules in `rules/` catch things clippy doesn't:

- `no-comment-above-test`: no comments right above a test. The test name should say what it checks; put extra context inside the body.
- `no-stdout-in-libs`: no `print!`, `println!`, `eprint!`, `eprintln!`, or `dbg!` in library crates. Stdout carries the hook JSON. Use `tracing`.
- `no-process-exit-in-libs`: no `process::exit` in library crates. Return an error so the caller can fail closed.
- `no-dash-in-comments`: no em or en dashes in comments.
- `no-thread-sleep-in-tests`: no `thread::sleep` in tests. Fixed sleeps are flaky; poll with a deadline in a helper, or use `#[tokio::test(start_paused = true)]` with `tokio::time`.
- `no-env-mutation`: no `set_var`/`remove_var`. Tests run on parallel threads, so env mutation races. Pass the value in as a parameter.
- `no-multiline-escaped-string`: no string literals with several `\n` escapes. Use `indoc!` with a raw string, or `writeln!`.

### ML end-to-end tests

The ML e2e tests are `#[ignore]`d by default because they need a HuggingFace token and download models. To run them:

```bash
HF_TOKEN=hf_... just e2e
```

They run injection prompts and clean text through `fast` (DeBERTa only) and `full` (DeBERTa + Llama PG2) modes. `full` needs candle (Llama PG2 has no ONNX export), so `just e2e` defaults to candle; `just e2e onnx-fetch` runs `fast` only. The `full` run gets its token through `HF_TOKEN_COMMAND`, so the gated Llama download also checks that path. The first run downloads the models, about 100MB each.

The CLI e2e tests in `bin/tests/cli_e2e.rs` that use a monitored repo skip themselves when `NIX_BUILD_TOP` is set, which `nix develop` does. Run them with `env -u NIX_BUILD_TOP cargo nextest run -p parry-guard --test cli_e2e`.

## License

Your contributions are licensed under the same license as the project.
