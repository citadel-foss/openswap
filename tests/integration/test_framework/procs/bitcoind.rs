//! Fetching and starting the regtest bitcoind, plus mining and payment helpers.

use std::{
    env,
    fs::{create_dir_all, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
};

use flate2::read::GzDecoder;
use tar::Archive;

use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};

const BITCOIN_VERSION: &str = "28.1";

fn download_bitcoind_tarball(download_url: &str, retries: usize) -> Vec<u8> {
    for attempt in 1..=retries {
        let response = minreq::get(download_url).send();
        match response {
            Ok(res) if res.status_code == 200 => {
                return res.as_bytes().to_vec();
            }
            Ok(res) if res.status_code == 503 => {
                // If the response is 503, log and prepare for retry
                eprintln!(
                    "Attempt {}: URL {} returned status code 503 (Service Unavailable)",
                    attempt + 1,
                    download_url
                );
            }
            Ok(res) => {
                // For other status codes, log and stop retrying
                panic!(
                    "URL {} returned unexpected status code {}. Aborting.",
                    download_url, res.status_code
                );
            }
            Err(err) => {
                eprintln!("Attempt {attempt}: Failed to fetch URL {download_url}: {err:?}");
            }
        }

        if attempt < retries {
            let delay = 1u64 << (attempt - 1);
            eprintln!("Retrying in {delay} seconds (exponential backoff)...");
            std::thread::sleep(std::time::Duration::from_secs(delay));
        }
    }
    // If all retries fail, panic with an error message
    panic!(
        "Cannot reach URL {} after {} attempts",
        download_url, retries
    );
}

fn read_tarball_from_file(path: &str) -> Vec<u8> {
    let file = File::open(path).unwrap_or_else(|_| {
        panic!(
            "Cannot find {:?} specified with env var BITCOIND_TARBALL_FILE",
            path
        )
    });
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();
    buffer
}

fn unpack_tarball(tarball_bytes: &[u8], destination: &Path) {
    let decoder = GzDecoder::new(tarball_bytes);
    let mut archive = Archive::new(decoder);
    for mut entry in archive.entries().unwrap().flatten() {
        if let Ok(file) = entry.path() {
            if file.ends_with("bitcoind") {
                entry.unpack_in(destination).unwrap();
            }
        }
    }
}

fn get_bitcoind_filename(os: &str, arch: &str) -> String {
    match (os, arch) {
        ("macos", "aarch64") => format!("bitcoin-{BITCOIN_VERSION}-arm64-apple-darwin.tar.gz"),
        ("macos", "x86_64") => format!("bitcoin-{BITCOIN_VERSION}-x86_64-apple-darwin.tar.gz"),
        ("linux", "x86_64") => format!("bitcoin-{BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz"),
        ("linux", "aarch64") => format!("bitcoin-{BITCOIN_VERSION}-aarch64-linux-gnu.tar.gz"),
        _ => format!("bitcoin-{BITCOIN_VERSION}-x86_64-apple-darwin-unsigned.zip"),
    }
}

/// Initiate the bitcoind backend. Fallible so the caller can retry on a fresh
/// ZMQ port: a released free-port pick can be sniped before bitcoind binds it.
pub(crate) fn init_bitcoind(
    datadir: &std::path::Path,
    zmq_addr: String,
) -> Result<BitcoinD, bitcoind::anyhow::Error> {
    let mut conf = bitcoind::Conf::default();
    conf.args.push("-txindex=1"); //txindex is must, or else wallet sync won't work.
                                  // Bitcoin Core 28 changed `getblockchaininfo`'s `warnings` field to an array of strings;
                                  // electrs 0.9.11 (used in the electrum-only test) still expects a string and falls over.
                                  // The deprecation flag restores the legacy single-string format.
    conf.args.push("-deprecatedrpc=warnings");
    let raw_tx = format!("-zmqpubrawtx={}", zmq_addr);
    conf.args.push(&raw_tx);
    let block_hash = format!("-zmqpubrawblock={}", zmq_addr);
    conf.args.push(&block_hash);
    // P2P always enabled — needed so electrs can attach via `--daemon-p2p-addr` in
    // electrum-only tests; harmless for tests that don't use electrs.
    conf.p2p = bitcoind::P2P::Yes;
    conf.staticdir = Some(datadir.join(".bitcoin"));
    log::info!(
        "🔗 bitcoind datadir: {:?}",
        conf.staticdir.as_ref().unwrap()
    );
    log::info!("🔧 bitcoind configuration: {:?}", conf.args);

    let os = env::consts::OS;
    let arch = env::consts::ARCH;
    let current_dir: PathBuf = std::env::current_dir().expect("failed to read current dir");
    let bitcoin_bin_dir = current_dir.join("bin");
    let download_filename = get_bitcoind_filename(os, arch);
    let bitcoin_exe_home = bitcoin_bin_dir
        .join(format!("bitcoin-{BITCOIN_VERSION}"))
        .join("bin");

    if !bitcoin_exe_home.exists() {
        let tarball_bytes = match env::var("BITCOIND_TARBALL_FILE") {
            Ok(path) => read_tarball_from_file(&path),
            Err(_) => {
                let download_endpoint = env::var("BITCOIND_DOWNLOAD_ENDPOINT")
                    .unwrap_or_else(|_| "http://170.75.166.88/bitcoin-binaries".to_owned());
                let url = format!("{download_endpoint}/{download_filename}");
                download_bitcoind_tarball(&url, 5)
            }
        };

        if let Some(parent) = bitcoin_exe_home.parent() {
            create_dir_all(parent).unwrap();
        }

        unpack_tarball(&tarball_bytes, &bitcoin_bin_dir);

        if os == "macos" {
            let bitcoind_binary = bitcoin_exe_home.join("bitcoind");
            std::process::Command::new("codesign")
                .arg("--sign")
                .arg("-")
                .arg(&bitcoind_binary)
                .output()
                .expect("Failed to sign bitcoind binary");
        }
    }

    env::set_var("BITCOIND_EXE", bitcoin_exe_home.join("bitcoind"));

    let exe_path = bitcoind::exe_path().unwrap();

    log::info!("📁 Executable path: {exe_path:?}");

    let bitcoind = BitcoinD::with_conf(exe_path, &conf)?;

    // Generate initial 101 blocks
    generate_blocks(&bitcoind, 101);
    log::info!("🚀 bitcoind initiated!!");

    Ok(bitcoind)
}

/// Generate Blocks in regtest node.
///
/// Panics if the chain never grows by `n`, so a node that cannot mine fails here
/// instead of surfacing later as an unrelated timeout.
pub(crate) fn generate_blocks(bitcoind: &BitcoinD, n: u64) {
    let before = bitcoind.client.get_block_count();
    let Err(e) = try_generate_blocks(bitcoind, n) else {
        return;
    };
    // An RPC error is not proof the blocks are missing: jsonrpc stops waiting after
    // a 15 s read timeout (resending once first) while a loaded node keeps mining,
    // and every such error prints as "Couldn't connect to host". Judge by height.
    let Ok(before) = before else {
        panic!("failed to generate {} blocks: {}", n, e);
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while std::time::Instant::now() < deadline {
        if bitcoind
            .client
            .get_block_count()
            .is_ok_and(|height| height >= before + n)
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    panic!("failed to generate {} blocks: {}", n, e);
}

/// [`generate_blocks`] that returns the RPC error instead of panicking, for
/// callers that must survive the node going away.
pub(in crate::test_framework) fn try_generate_blocks(
    bitcoind: &BitcoinD,
    n: u64,
) -> Result<(), bitcoind::bitcoincore_rpc::Error> {
    let mining_address = bitcoind
        .client
        .get_new_address(None, None)?
        .require_network(bitcoind::bitcoincore_rpc::bitcoin::Network::Regtest)
        .unwrap();
    bitcoind.client.generate_to_address(n, &mining_address)?;
    Ok(())
}

/// Send coins to a bitcoin address.
#[allow(dead_code)]
pub(crate) fn send_to_address(
    bitcoind: &BitcoinD,
    addrs: &bitcoin::Address,
    amount: bitcoin::Amount,
) -> bitcoin::Txid {
    bitcoind
        .client
        .send_to_address(addrs, amount, None, None, None, None, None, None)
        .unwrap()
}
