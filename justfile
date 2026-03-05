# List available recipes
default:
    @just --list

# Run all checks
check: clippy test check-fmt lint-toml check-typos lint-actions check-nix-fmt

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

# Run ML e2e tests (requires HF_TOKEN)
e2e:
    cargo nextest run -p parry-daemon --test e2e --run-ignored all --success-output immediate

# Benchmark ML inference with candle backend (requires HF_TOKEN)
bench-candle:
    cargo bench -p parry-ml --bench inference

# Benchmark ML inference with ONNX backend (requires HF_TOKEN)
bench-onnx:
    cargo bench -p parry-ml --bench inference --no-default-features --features onnx-fetch

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

# Set up git hooks
setup-hooks:
    git config core.hooksPath .githooks
