//! Fetching and starting the regtest bitcoind, plus mining and payment helpers.

use std::{
    env,
    fs::{self, create_dir_all, File},
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
                    "Attempt {}/{}: URL {} returned status code 503 (Service Unavailable)",
                    attempt, retries, download_url
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
                eprintln!(
                    "Attempt {attempt}/{retries}: Failed to fetch URL {download_url}: {err:?}"
                );
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
    let mut unpacked = false;
    for entry in archive
        .entries()
        .unwrap_or_else(|e| panic!("cannot read bitcoind tarball: {:?}", e))
    {
        let mut entry =
            entry.unwrap_or_else(|e| panic!("cannot read bitcoind tarball entry: {:?}", e));
        if let Ok(file) = entry.path() {
            if file.ends_with("bitcoind") {
                // `false` means the entry's path escapes `destination` and was skipped.
                unpacked |= entry
                    .unpack_in(destination)
                    .unwrap_or_else(|e| panic!("cannot unpack bitcoind from tarball: {:?}", e));
            }
        }
    }
    assert!(unpacked, "bitcoind tarball has no bitcoind binary");
    // tar stops reading at its end-of-archive marker, so drain the rest: only at EOF
    // does GzDecoder check the CRC32/size trailer that catches a corrupted payload.
    std::io::copy(&mut archive.into_inner(), &mut std::io::sink())
        .unwrap_or_else(|e| panic!("bitcoind tarball failed its gzip integrity check: {:?}", e));
}

/// Release tarball for this platform, or `None` when there is no gzipped
/// tarball to download for it.
fn get_bitcoind_filename(os: &str, arch: &str) -> Option<String> {
    match (os, arch) {
        ("macos", "aarch64") => Some(format!(
            "bitcoin-{BITCOIN_VERSION}-arm64-apple-darwin.tar.gz"
        )),
        ("macos", "x86_64") => Some(format!(
            "bitcoin-{BITCOIN_VERSION}-x86_64-apple-darwin.tar.gz"
        )),
        ("linux", "x86_64") => Some(format!("bitcoin-{BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz")),
        ("linux", "aarch64") => Some(format!(
            "bitcoin-{BITCOIN_VERSION}-aarch64-linux-gnu.tar.gz"
        )),
        _ => None,
    }
}

/// Install bitcoind into `bin/bitcoin-<V>`, unless another process got there first.
///
/// nextest runs each test in its own process, so several can find the install
/// missing at once. They take turns on a lock file, and the installer unpacks
/// into its own staging dir and renames the finished tree into place, so no
/// process ever sees an install from this function half-written.
fn install_bitcoind(bitcoin_bin_dir: &Path, os: &str, arch: &str) {
    create_dir_all(bitcoin_bin_dir).unwrap();
    let lock_path = bitcoin_bin_dir.join(".bitcoind-install.lock");
    let lock_file = File::create(&lock_path)
        .unwrap_or_else(|e| panic!("cannot create {}: {e}", lock_path.display()));
    // Held until `lock_file` drops at the end of this function.
    lock_file
        .lock()
        .unwrap_or_else(|e| panic!("cannot lock {}: {e}", lock_path.display()));

    let bitcoin_home = bitcoin_bin_dir.join(format!("bitcoin-{BITCOIN_VERSION}"));
    if bitcoin_home.join("bin").join("bitcoind").exists() {
        return; // Installed by another process while this one waited.
    }

    let tarball_bytes = match env::var("BITCOIND_TARBALL_FILE") {
        Ok(path) => read_tarball_from_file(&path),
        Err(_) => {
            let download_filename = get_bitcoind_filename(os, arch).unwrap_or_else(|| {
                panic!(
                    "no bitcoind {} tarball to download for {}/{}; \
                     set BITCOIND_TARBALL_FILE to a bitcoin-{} .tar.gz for it",
                    BITCOIN_VERSION, os, arch, BITCOIN_VERSION
                )
            });
            let download_endpoint = env::var("BITCOIND_DOWNLOAD_ENDPOINT")
                .unwrap_or_else(|_| "http://170.75.166.88/bitcoin-binaries".to_owned());
            let url = format!("{download_endpoint}/{download_filename}");
            download_bitcoind_tarball(&url, 5)
        }
    };

    // Inside `bin/`, so the rename below stays on one filesystem.
    // Holding the lock means no other install is running, so every staging dir here
    // was left by an install that crashed or panicked; clear them all.
    for entry in fs::read_dir(bitcoin_bin_dir).unwrap() {
        let path = entry.unwrap().path();
        let stale = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(".bitcoind-staging-"));
        if stale {
            let _ = fs::remove_dir_all(&path);
        }
    }
    let staging = bitcoin_bin_dir.join(format!(".bitcoind-staging-{}", std::process::id()));
    create_dir_all(&staging).unwrap();
    unpack_tarball(&tarball_bytes, &staging);

    let staged_home = staging.join(format!("bitcoin-{BITCOIN_VERSION}"));
    let staged_binary = staged_home.join("bin").join("bitcoind");
    assert!(
        staged_binary.exists(),
        "bitcoind tarball has no bitcoin-{}/bin/bitcoind",
        BITCOIN_VERSION
    );

    if os == "macos" {
        std::process::Command::new("codesign")
            .arg("--sign")
            .arg("-")
            .arg(&staged_binary)
            .output()
            .expect("Failed to sign bitcoind binary");
    }

    // A crashed install from before this lock can leave `bitcoin-<V>` without
    // its binary, and the rename needs the target gone.
    if bitcoin_home.exists() {
        fs::remove_dir_all(&bitcoin_home).unwrap();
    }
    fs::rename(&staged_home, &bitcoin_home).unwrap_or_else(|e| {
        panic!(
            "cannot move {} to {}: {e}",
            staged_home.display(),
            bitcoin_home.display()
        )
    });
    fs::remove_dir_all(&staging).unwrap();
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
    log::info!("bitcoind datadir: {:?}", conf.staticdir.as_ref().unwrap());
    log::info!("bitcoind configuration: {:?}", conf.args);

    let os = env::consts::OS;
    let arch = env::consts::ARCH;
    let current_dir: PathBuf = std::env::current_dir().expect("failed to read current dir");
    let bitcoin_bin_dir = current_dir.join("bin");
    let bitcoin_exe_home = bitcoin_bin_dir
        .join(format!("bitcoin-{BITCOIN_VERSION}"))
        .join("bin");

    // Unlocked fast path: the binary only ever appears complete, by rename.
    if !bitcoin_exe_home.join("bitcoind").exists() {
        install_bitcoind(&bitcoin_bin_dir, os, arch);
    }

    env::set_var("BITCOIND_EXE", bitcoin_exe_home.join("bitcoind"));

    let exe_path = bitcoind::exe_path().unwrap();

    log::info!("Executable path: {exe_path:?}");

    let bitcoind = BitcoinD::with_conf(exe_path, &conf)?;

    // Generate initial 101 blocks
    generate_blocks(&bitcoind, 101);
    log::info!("bitcoind initiated!!");

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

/// Waits for a bitcoind that was sent `stop` to exit, so its datadir can be
/// deleted without the shutdown writing it back. Bitcoin Core deletes
/// `<datadir>/regtest/bitcoind.pid` as one of its last shutdown steps.
pub(crate) fn wait_for_bitcoind_exit(datadir: &Path, timeout: std::time::Duration) {
    let pid_file = datadir.join("regtest").join("bitcoind.pid");
    let start = std::time::Instant::now();
    while pid_file.exists() {
        if start.elapsed() > timeout {
            log::warn!("bitcoind still running {:?} after stop", timeout);
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    log::info!("bitcoind exited {:?} after stop", start.elapsed());
}
