# Contributing to OpenSwap

Thank you for your interest in contributing to **OpenSwap**!

We are building functioning, minimal-viable binaries and libraries for the trustless, peer-to-peer [Maxwell-Belcher Atomic Swap protocol](https://github.com/citadel-foss/OpenSwap-Protocol-Specification) on Bitcoin. This is **experimental security-critical software** — every change can affect atomicity, privacy (Tor), sybil resistance (fidelity bonds), or real BTC. Because of this, we maintain **very high standards** for code quality, testing, and human understanding.

We welcome contributions from everyone, but we expect contributors to understand the critical nature of this codebase.
To understand the codebase, please refer to the [Deep Wiki](https://deepwiki.com/citadel-foss/openswap).

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to abide by it.

## Table of Contents
- [Contributing to OpenSwap](#contributing-to-openswap)
  - [Code of Conduct](#code-of-conduct)
  - [Table of Contents](#table-of-contents)
  - [How Can I Contribute?](#how-can-i-contribute)
    - [Reporting Bugs](#reporting-bugs)
    - [Suggesting Features or Protocol Changes](#suggesting-features-or-protocol-changes)
    - [Code \& Documentation Contributions](#code--documentation-contributions)
  - [Development Setup](#development-setup)
    - [Prerequisites](#prerequisites)
    - [Recommended: One-Click Docker Stack](#recommended-one-click-docker-stack)
    - [Native Setup](#native-setup)
    - [Git Hooks (Strongly Recommended)](#git-hooks-strongly-recommended)
  - [Coding Standards](#coding-standards)
  - [Testing](#testing)
  - [Pull Requests](#pull-requests)
  - [AI-Generated Contributions Policy (No AI Slop)](#ai-generated-contributions-policy-no-ai-slop)
  - [Security Policy](#security-policy)
  - [Community \& Getting Help](#community--getting-help)

## How Can I Contribute?

### Reporting Bugs
- Search existing issues first.
- Use the [Bug Report issue template](.github/ISSUE_TEMPLATE/bug_report.md) (auto-loaded on GitHub when creating a new issue).
- Include steps to reproduce, regtest logs, environment (Docker vs native), and expected vs actual behavior.

### Suggesting Features or Protocol Changes
- Use the [Feature Request issue template](.github/ISSUE_TEMPLATE/feature_request.md) or open a [discussion](https://github.com/citadel-foss/openswap/discussions).
- For protocol-level ideas, please reference the [OpenSwap protocol specification](https://github.com/citadel-foss/OpenSwap-Protocol-Specification) where possible.

### Code & Documentation Contributions
See the Pull Request section below.

## Development Setup

### Prerequisites
- Rust (see [`rust-toolchain.toml`](rust-toolchain.toml))
- [Bitcoin Core](./docs/bitcoind.md) on the custom signet or regtest (fully synced), or an Electrum server
- [Tor with the correct configuration](./docs/tor.md)
- `build-essential`, `automake`, `libtool`, `protobuf-compiler` (on Ubuntu/Debian)

### Recommended: One-Click Docker Stack
```bash
git clone https://github.com/citadel-foss/openswap.git
cd openswap
./docker-setup configure
./docker-setup start
```
See [`docs/docker.md`](docs/docker.md) for full details.

### Native Setup
```bash
git clone https://github.com/citadel-foss/openswap.git
cd openswap
cargo build --release
# Install binaries (optional)
sudo install ./target/release/{taker,makerd,maker-cli} /usr/local/bin/
```

Bitcoin Core must be configured with `txindex=1` and ZMQ enabled:
```conf
txindex=1
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28332
```
See [`docs/bitcoind.md`](docs/bitcoind.md) for the full setup guide.

### Git Hooks (Strongly Recommended)
```bash
ln -s ../../git_hooks/pre-commit .git/hooks/pre-commit
```
This auto-runs formatting and basic checks on commit (see [`git_hooks/pre-commit`](git_hooks/pre-commit)).

Full documentation is in the [`docs/`](docs/) folder:
- [`docs/bitcoind.md`](docs/bitcoind.md)
- [`docs/tor.md`](docs/tor.md)
- [`docs/makerd.md`](docs/makerd.md)
- [`docs/taker.md`](docs/taker.md)
- [`docs/maker-cli.md`](docs/maker-cli.md)
- [`docs/taproot.md`](docs/taproot.md)

## Coding Standards

- Always run `cargo +nightly fmt --all`
- Always run `cargo +stable clippy --all-features --lib --bins --tests -- -D warnings`
- Always run `cargo +stable clippy --examples -- -D warnings`
- Always run `RUSTDOCFLAGS="-D warnings" cargo +nightly doc --all-features --document-private-items --no-deps`
- Write idiomatic, well-commented Rust
- Prefer explicit error handling and clear variable names
- Update relevant files in `docs/` when you change behavior
-  **Dual-protocol rule:** When modifying protocol logic, ensure changes are applied to **both** Legacy ([`legacy_messages.rs`](src/protocol/legacy_messages.rs), [`contract.rs`](src/protocol/contract.rs), [`legacy_handlers.rs`](src/maker/legacy_handlers.rs)) and Taproot-Musig2 ([`taproot_messages.rs`](src/protocol/taproot_messages.rs), [`contract2.rs`](src/protocol/contract2.rs), [`taproot_handlers.rs`](src/maker/taproot_handlers.rs)) versions unless the change is explicitly version-specific.

## Testing

All PRs **must** pass:
```bash
# Basic tests
cargo test

# Full integration tests (required for most changes)
# needs nostr-rs-relay on PATH (cargo install nostr-rs-relay)
cargo test --features integration-test -- --nocapture
```

We also strongly recommend manually testing affected flows on **regtest** (e.g. standard_swap, multi-hop, failure cases).

## Pull Requests

1. Fork the repo and create a feature branch
2. Make your changes
3. Ensure tests and lints pass
4. Fill out the **[Pull Request Template](.github/pull_request_template.md)** completely (it will be auto-loaded)
5. Use [conventional commit style](https://www.conventionalcommits.org) for the PR title (e.g. `feat(makerd): add X`, `fix: Y`, `docs: Z`)

Especially important:
- Clearly describe affected components (makerd / taker / maker-cli / core protocol / watch_tower)
- Fill out the **Security & Privacy** checklist

## AI-Generated Contributions Policy (No AI Slop)

**Contributions cannot be AI slop.**

We do **not** accept pull requests that consist primarily of low-effort, blindly generated output from large language models (ChatGPT, Claude, Grok, Cursor, etc.).

This project involves complex cryptography, Bitcoin consensus rules, Tor anonymity, state machines, and high-stakes financial logic. AI slop introduces subtle bugs, security regressions, and wastes maintainer time.

**Allowed:**
- Using AI as an assistant (refactoring ideas, explaining concepts, generating boilerplate you then review and improve)

**Not allowed:**
- Submitting large chunks of code you did not fully understand, test, or manually review
- Generic AI-generated explanations or hallucinated patterns
- Bulk changes with minimal human oversight

Every merged contribution must be something the author can **explain and defend** in review. If a PR appears to be mostly AI slop, it will be closed without detailed review.

We strongly prefer thoughtful, human-driven contributions — even if fewer in number.

## Security Policy

Security is the top priority.

- **Never** report security issues in public issues or PRs.
- Report privately via the [GitHub Security Advisory](https://github.com/citadel-foss/openswap/security/advisories/new) feature. Alternatively, reach core maintainers directly via a private message in the [Matrix server](https://matrix.to/#/#citadel-foss:matrix.org).
- We follow responsible disclosure.

Any change touching protocol logic, cryptography, or fund handling **must** preserve trustlessness and atomic guarantees.

## Community & Getting Help

- **Matrix**: [Citadel Matrix](https://matrix.to/#/#citadel-foss:matrix.org) (fastest for questions)
- [GitHub Issues](https://github.com/citadel-foss/openswap/issues) & [Discussions](https://github.com/citadel-foss/openswap/discussions)
- Look for [`good first issue`](https://github.com/citadel-foss/openswap/labels/good%20first%20issue) or [`help wanted`](https://github.com/citadel-foss/openswap/labels/help%20wanted) labels

---

**Thank you** for helping make OpenSwap more robust, private, and secure! 🧡

Happy swapping.
