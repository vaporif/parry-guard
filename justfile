# List available recipes
default:
    @just --list

# Run checks (compile, clippy, fmt, lints)
check: cargo-check clippy check-fmt lint

alias c := check

# Type-check workspace
cargo-check:
    cargo check --workspace

# Lint all
lint: lint-toml check-typos check-nix-fmt lint-actions lint-ast

# Format all
fmt: fmt-rust fmt-toml fmt-nix

# Build workspace
build:
    cargo build --workspace

# Build with ONNX auto-download backend
build-onnx:
    cargo build --workspace --no-default-features --features onnx-fetch

# Run clippy
clippy:
    cargo clippy --workspace -- -D warnings

# Run tests
test:
    cargo nextest run --workspace

alias t := test

# Generate coverage (lcov)
coverage:
    cargo llvm-cov nextest --workspace --lcov --output-path lcov.info

# Generate coverage (html)
coverage-html:
    cargo llvm-cov nextest --workspace --html

# Check Rust formatting
check-fmt:
    cargo fmt --all -- --check

# Format Rust code
fmt-rust:
    cargo fmt --all

# Lint TOML files
lint-toml:
    taplo check

# Format TOML files
fmt-toml:
    taplo fmt

# Check Nix formatting
check-nix-fmt:
    alejandra --check flake.nix nix/

# Format Nix files
fmt-nix:
    alejandra flake.nix nix/

# Check for typos
check-typos:
    typos

# Lint GitHub Actions
lint-actions:
    actionlint

# Run ast-grep rules (rules/)
lint-ast:
    ast-grep scan

# Run mutation testing on the whole workspace
mutants:
    cargo mutants

# Run mutation testing on lines changed vs main
mutants-diff:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo mutants --in-diff <(git diff main...)

# Run ML e2e tests (requires HF_TOKEN); `full` mode only runs with candle
e2e feature="candle":
    cargo nextest run -p parry-guard-daemon --no-default-features --features {{feature}} --test e2e --run-ignored all --success-output immediate

# Benchmark ML inference with candle backend (requires HF_TOKEN)
bench-candle:
    cargo bench -p parry-guard-ml --bench inference --no-default-features --features candle

# Benchmark ML inference with ONNX backend (requires HF_TOKEN)
bench-onnx:
    cargo bench -p parry-guard-ml --bench inference --no-default-features --features onnx-fetch

# Run scan on stdin
scan:
    cargo run -- scan

# Start daemon
serve:
    cargo run -- serve

# Bump last version number (0.1.0-alpha.8 → 0.1.0-alpha.9)
bump:
    #!/usr/bin/env bash
    set -euo pipefail
    current=$(grep -m1 '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/')
    prefix="${current%.*}"
    last="${current##*.}"
    new="${prefix}.$((last + 1))"
    sed "s/^version = \".*\"/version = \"${new}\"/" Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml
    sed "s/\(parry-[a-z]* = { path = \"[^\"]*\", version = \)\"[^\"]*\"/\1\"${new}\"/" Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml
    echo "Bumped ${current} → ${new}"

# Install git hooks
setup-hooks:
    lefthook install
