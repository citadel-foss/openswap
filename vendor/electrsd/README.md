[![MIT license](https://img.shields.io/github/license/RCasatta/electrsd)](https://github.com/RCasatta/electrsd/blob/master/LICENSE)
[![Crates](https://img.shields.io/crates/v/electrsd.svg)](https://crates.io/crates/electrsd)

# Electrsd

Utility to run a regtest [electrs](https://github.com/romanz/electrs/) process connected to a given [bitcoind](https://github.com/RCasatta/bitcoind) instance,
useful in integration testing environment.

```rust
let bitcoind = bitcoind::BitcoinD::new("/usr/local/bin/bitcoind").unwrap();
let electrsd = electrsd::ElectrsD::new("/usr/local/bin/electrs", bitcoind).unwrap();
let header = electrsd.client.block_headers_subscribe().unwrap();
assert_eq!(header.height, 0);
```

## Automatic binaries download

In your project Cargo.toml, activate the following features

```yml
electrsd = { version= "0.23", features = ["bitcoind_23_1", "electrs_0_9_1"] }
```

Then use it:

```rust
let bitcoind_exe = bitcoind::downloaded_exe_path().expect("bitcoind version feature must be enabled");
let bitcoind = bitcoind::BitcoinD::new(bitcoind_exe).unwrap();
let electrs_exe = electrsd::downloaded_exe_path().expect("electrs version feature must be enabled");
let electrsd = electrsd::ElectrsD::new(electrs_exe, bitcoind).unwrap();
```

When the `ELECTRSD_DOWNLOAD_ENDPOINT`/`BITCOIND_DOWNLOAD_ENDPOINT` environment variables are set,
`electrsd`/`bitcoind` will try to download the binaries from the given endpoints.

When you don't use the auto-download feature you have the following options:

- have `electrs` executable in the `PATH`
- provide the `electrs` executable via the `ELECTRS_EXEC` env var

```rust
if let Ok(exe_path) = electrsd::exe_path() {
  let electrsd = electrsd::electrsD::new(exe_path).unwrap();
}
```

Startup options could be configured via the `Conf` struct using `electrsD::with_conf` or `electrsD::from_downloaded_with_conf`.

## Nix

For determinisim, in nix you cannot hit the internet within the `build.rs`. Moreover, some downstream crates cannot remove the auto-download feature from their dev-deps. In this case you can set the `ELECTRSD_SKIP_DOWNLOAD` env var and provide the electrs executable in the `PATH` (or skip the test execution).

## Issues with traditional approach

I used integration testing based on external bash script launching needed external processes, there are many issues with this approach like:

* External script may interfere with local development environment https://github.com/rust-bitcoin/rust-bitcoincore-rpc/blob/200fc8247c1896709a673b82a89ca0da5e7aa2ce/integration_test/run.sh#L9
* Use of a single huge test to test everything https://github.com/rust-bitcoin/rust-bitcoincore-rpc/blob/200fc8247c1896709a673b82a89ca0da5e7aa2ce/integration_test/src/main.rs#L122-L203
* If test are separated, a failing test may fail to leave a clean situation, causing other test to fail (because of the initial situation, not a real failure)
* bash script are hard, especially support different OS and versions

## Features

  * electrsd use a temporary directory as db dir
  * A free port is asked to the OS (a very low probability race condition is still possible)
  * The process is killed when the struct goes out of scope no matter how the test finishes
  * Automatically download `electrs` executable with enabled features. Since there are no official binaries, they are built using the [manual workflow](.github/workflows/build_electrs.yml) under this project. Supported version are:
    * [electrs 0.9.11](https://github.com/romanz/electrs/releases/tag/v0.9.11) (feature=electrs_0_9_11)
    * [electrs 0.9.1](https://github.com/romanz/electrs/releases/tag/v0.9.1) (feature=electrs_0_9_1)
    * [electrs 0.8.10](https://github.com/romanz/electrs/releases/tag/v0.8.10) (feature=electrs_0_8_10)
    * [electrs esplora](https://github.com/Blockstream/electrs/tree/a33e97e1a1fc63fa9c20a116bb92579bbf43b254) (feature=esplora_a33e97e1)

Thanks to these features every `#[test]` could easily run isolated with its own environment

## Deprecations

- Starting from version `0.26` the env var `ELECTRS_EXE` is deprecated in favor of `ELECTRS_EXEC`.


## Used by

  * [bdk](https://github.com/bitcoindevkit/bdk)
  * [BEWallet](https://github.com/LeoComandini/BEWallet)
  * [gdk rust](https://github.com/Blockstream/gdk/blob/master/subprojects/gdk_rust/)
  * [lwk](https://github.com/Blockstream/lwk)
