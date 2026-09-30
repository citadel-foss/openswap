<div align="center">

# OpenSwap
Functioning, minimal-viable binaries and libraries to perform a trustless, p2p [Maxwell-Belcher Coinswap Protocol](https://gist.github.com/chris-belcher/9144bd57a91c194e332fb5ca371d0964).

[![MIT or Apache-2.0 Licensed](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/citadel-foss/openswap/blob/master/LICENSE)
[![Build Status](https://github.com/citadel-foss/openswap/actions/workflows/build.yaml/badge.svg)](https://github.com/citadel-foss/openswap/actions/workflows/build.yaml)
[![Lint Status](https://github.com/citadel-foss/openswap/actions/workflows/lint.yaml/badge.svg)](https://github.com/citadel-foss/openswap/actions/workflows/lint.yaml)
[![Test Status](https://github.com/citadel-foss/openswap/actions/workflows/test.yaml/badge.svg)](https://github.com/citadel-foss/openswap/actions/workflows/test.yaml)
[![Coverage](https://codecov.io/github/citadel-foss/openswap/coverage.svg?branch=master)](https://codecov.io/github/citadel-foss/openswap?branch=master)
[![Rustc Version 1.88.0+](https://img.shields.io/badge/rustc-1.88.0%2B-lightgrey.svg)](https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/)

[![Latest Release](https://img.shields.io/github/v/release/citadel-foss/openswap?label=latest%20release&color=orange)](https://github.com/citadel-foss/openswap/releases/latest)
[![Website](https://img.shields.io/badge/website-openswap.live-blue)](https://openswap.live/)

</div>

## Notice
The project is in active beta with experimental Mainnet use.

# About

OpenSwap is a trustless, self-custodial [atomic swap](https://bitcoinops.org/en/topics/coinswap/) protocol built on Bitcoin. Unlike existing solutions that rely on centralized servers as [single points of failure](https://en.wikipedia.org/wiki/Single_point_of_failure), OpenSwap's marketplace is seeded in the Bitcoin blockchain itself — no central host required, anyone with a Bitcoin node can participate. 

For a quicker dive into the idea, see the [**Website**](https://openswap.live/).

**Sybil resistance** is achieved through [Fidelity Bonds](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/fidelity-bonds.md): time-locked UTXOs that make Sybil attacks economically costly while simultaneously bootstrapping the marketplace on-chain.

**Two roles:**

- **`Makers`** are swap service providers. They earn swap fees for supplying liquidity, compete on fee rates in an open market, and signal reliability through larger fidelity bonds. Unlike Lightning nodes, maker servers need no active management — they run in *install-fund-forget* mode on any consumer hardware (Umbrel, Start9, Mynode, etc.), though liquidity must remain in the node's hot wallet to serve swap requests.

- **`Takers`** are clients initiating swaps. They pay all the fees (swap + mining), require no fidelity bond, and select makers based on bond validity, available liquidity, fee rates, and past swap history.

**Multi-hop routing** mirrors Lightning: swaps are routed through multiple makers, and no single maker sees the full route. The taker relays all messages between makers over Tor, keeping each maker's view partial. Protocol complexity lives entirely on the taker side, keeping maker servers lightweight. Users can choose to do either the legacy P2WSH, or more modern Taproot+Musig2 based atomic swap contracts.

The project extends Chris Belcher's [teleport-transactions](https://github.com/bitcoin-teleport/teleport-transactions) proof-of-concept into a production-grade implementation with full protocol handling, functional testing, sybil resistance, CLI tools, and a GUI app. The same protocol can be extended for cross-chain swaps.

For protocol-level details, see the [OpenSwap Protocol Specifications](https://github.com/citadel-foss/OpenSwap-Protocol-Specification).

For an in-depth exploration of the repository, it's recommended to use [Deep Wiki](https://deepwiki.com/citadel-foss/openswap).

# Executables

## CLI Apps
This crate compiles into the following CLI binaries. Useful for integration testing, and dev environments.

**[makerd](./docs/makerd.md)**: A maker server daemon. Requires Bitcoin Core or an Electrum server, and Tor. Runs a maker daemon to handle swap requests.

**[maker-cli](./docs/maker-cli.md)**: CLI controller for the `makerd`. Manage server, access wallet, view swap statistics, and more. [Demo](./docs/maker-cli.md)

**[taker](./docs/taker.md)**: A command-line OpenSwap client app to perform swaps, discover market, etc. [Demo](./docs/taker.md)

## Portal (GUI OpenSwap Manager)
[Portal](https://github.com/citadel-foss/portal) is a full-featured OpenSwap app, built directly on this crate's Rust APIs ([taker api](https://github.com/citadel-foss/openswap/blob/master/src/taker/api.rs), [maker api](https://github.com/citadel-foss/openswap/blob/master/src/maker/api.rs)). It is a full wallet (receive, send, coin control, history) with swaps built in.

- **Two roles:** pick **Wallet** to swap your coins (the taker), or **Router** to provide liquidity and earn swap fees (the maker).
- **Desktop or server:** run it as a desktop app, or host it yourself as a server and reach it from a browser.
- **Nothing else to install:** it bundles its own Tor and defaults to a public Electrum server. You can point it at your own Bitcoin Core node instead.
- **Same data as the CLI:** its wallet data works with the OpenSwap CLI apps too.

Download a precompiled build from the [releases page](https://github.com/citadel-foss/portal/releases) if one exists for your system, or build it from source. The [demo doc](./docs/demo.md) walks through setup and a first swap.

For swapping between on-chain BTC and the Lightning Network — including routed swaps that need no Lightning node of your own — see [lightning swaps](./docs/lightning.md).

For how wallet keys and passphrases are protected — at-rest encryption, in-memory key sealing, and the exact threat model — see [wallet security](./docs/wallet-security.md).

# Development

## Testing

Extensive functional testing simulates various protocol edge cases:

```console
# needs nostr-rs-relay on PATH (cargo install nostr-rs-relay)
cargo test --features=integration-test -- --nocapture
```

The [Test Framework](./tests/integration/test_framework/mod.rs) spawns toy marketplaces in Bitcoin regtest to test swap scenarios. Each test in [tests/integration](./tests/integration/) covers different edge cases. Start with [standard_swap](./tests/integration/standard_swap.rs) to understand programmatic simulation.

## Contributing

- Browse [issues](https://github.com/citadel-foss/openswap/issues), especially [`good first issue`](https://github.com/citadel-foss/openswap/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)
- Review [open PRs](https://github.com/citadel-foss/openswap/pulls)
- Search for `TODO`s in the codebase
- Read the [docs](./docs)
- Read the [Contributing Guide](./CONTRIBUTING.md) — including the AI contributions policy

### Git Hooks

The repo contains pre-commit githooks to do auto-linting before commits. Set up the pre-commit hook by running:

```bash
ln -s ../../git_hooks/pre-commit .git/hooks/pre-commit
```

## Security

We take the security of the protocol and its implementation seriously. If you discover a vulnerability, please report it responsibly.

**Please do not open public GitHub issues for security vulnerabilities.**

To report a security issue, email **security@citadelfoss.xyz** with a description of the vulnerability, steps to reproduce, and its potential impact. We will acknowledge your report and work with you on disclosure and remediation.

## Community

Dev community: [Matrix](https://matrix.to/#/#citadel-foss:matrix.org)

Dev discussions predominantly happen via FOSS best practices, and by using Github as the major community forum.

The Issues, PRs and Discussions are where all the hard lifting is happening.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
