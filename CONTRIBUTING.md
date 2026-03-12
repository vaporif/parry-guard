# Contributing to Parry

Thanks for your interest in contributing to Parry! This guide will help you get started.

> **Note:** Parry is in alpha. False positives are expected — if you encounter one, please open an issue so we can improve detection.

## How to Contribute

### Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- Parry version, Claude Code version and OS

### Suggesting Features

Open an issue describing the use case and why it would be valuable. Discussion before implementation saves everyone's time.

### Submitting Pull Requests

1. Create an issue first for non-trivial changes
2. Branch from `main`
3. Write tests for your changes
4. Run `just check` (runs clippy, tests, formatting, lints, typos)
5. Run `just fmt` to auto-format before committing
6. Submit a PR to `main` — use the PR template checklist

For minor fixes (typos, small bug fixes), a PR without an issue is fine.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
