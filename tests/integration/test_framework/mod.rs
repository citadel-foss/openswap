//! A Framework to write functional tests for the OpenSwap Protocol.
//!
//! This framework uses [bitcoind] to automatically spawn regtest node in the background.
//!
//! Spawns one Taker and multiple Makers, with/without special behavior, connect them to bitcoind regtest node,
//! and initializes the database.
//!
//! The tests' data are stored in the `tests/temp-files` directory, which is auto-removed after each successful test.
//! Do not invoke [TestFramework::stop] function at the end of the test, to persist this data for debugging.
//!
//! The test data also includes the backend bitcoind data-directory, which is useful for observing the blockchain states after a swap.

use bip39::rand;
use bitcoin::Amount;
use std::{
    env,
    fs::{self, create_dir_all, File},
    io::{BufReader, Read},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use flate2::read::GzDecoder;
use tar::Archive;

use bitcoind::{
    bitcoincore_rpc::{Auth, RpcApi},
    BitcoinD,
};

use electrsd::ElectrsD;
use log::info;
use openswap::{
    maker::{MakerBehavior, MakerServer, MakerServerConfig},
    protocol::common_messages::{ProtocolVersion, OPENSWAP_PORT},
    taker::{Taker, TakerBehavior, TakerInitConfig},
    utill::{check_tor_status, get_ephemeral_address, setup_logger},
    wallet::{
        verify_deniability, AddressType, AnyBlockchain, BackendConfig, Blockchain, CoreRPC,
        CoreRpcConfig, Electrum, ElectrumConfig,
    },
};

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

/// Initiate the bitcoind backend.
pub(crate) fn init_bitcoind(datadir: &std::path::Path, zmq_addr: String) -> BitcoinD {
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

    let bitcoind = BitcoinD::with_conf(exe_path, &conf).unwrap();

    // Generate initial 101 blocks
    generate_blocks(&bitcoind, 101);
    log::info!("🚀 bitcoind initiated!!");

    bitcoind
}

/// Spawn an electrs process attached to `bitcoind`. The bitcoind instance must
/// have been started with P2P enabled (see [`init_bitcoind`] which now does so).
///
/// The returned [`ElectrsD`] owns the electrs child process and kills it on drop.
#[allow(dead_code)]
pub(crate) fn init_electrsd(bitcoind: &BitcoinD, datadir: &std::path::Path) -> ElectrsD {
    let exe = electrsd::exe_path().expect(
        "no electrs binary available: set ELECTRS_EXEC or enable the electrs_0_9_11 feature",
    );
    let mut conf = electrsd::Conf::default();
    let electrs_dir = datadir.join("electrs");
    std::fs::create_dir_all(&electrs_dir).ok();
    conf.staticdir = Some(electrs_dir);
    // Surface electrs stderr only when explicitly requested via env var, to keep test output clean.
    conf.view_stderr = std::env::var("ELECTRS_LOG").is_ok();
    let electrsd = ElectrsD::with_conf(exe, bitcoind, &conf).expect("failed to spawn electrs");
    log::info!("🔌 electrs spawned at {}", electrsd.electrum_url);
    electrsd
}

/// Generate Blocks in regtest node.
pub(crate) fn generate_blocks(bitcoind: &BitcoinD, n: u64) {
    let mining_address = match bitcoind.client.get_new_address(None, None) {
        Ok(addr) => addr
            .require_network(bitcoind::bitcoincore_rpc::bitcoin::Network::Regtest)
            .unwrap(),
        Err(_) => return,
    };
    let _ = bitcoind.client.generate_to_address(n, &mining_address);
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

/// Wait for all makers to complete setup, with a timeout.
///
/// Panics if any maker's `is_setup_complete` flag doesn't become true within `timeout_secs`.
#[allow(dead_code)]
pub fn wait_for_makers_setup(makers: &[Arc<MakerServer>], timeout_secs: u64) {
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    for (i, maker) in makers.iter().enumerate() {
        while !maker.is_setup_complete.load(Relaxed) {
            if start.elapsed() > timeout {
                panic!(
                    "Maker {} did not complete setup within {} seconds",
                    i, timeout_secs
                );
            }
            log::info!("Waiting for maker {} setup completion", i);
            thread::sleep(Duration::from_secs(5));
        }
    }
}

/// Fund taker and verify balance
#[allow(dead_code)]
pub fn fund_taker(
    taker: &Taker,
    bitcoind: &bitcoind::BitcoinD,
    utxo_count: u32,
    utxo_value: Amount,
    address_type: AddressType,
) -> Amount {
    log::info!("💰 Funding Taker...");

    let mut wallet = taker.get_wallet().write().unwrap();
    let prev_balances = wallet.get_balances().unwrap();

    // Fund with UTXOs
    for _ in 0..utxo_count {
        let addr = wallet.get_next_external_address(address_type).unwrap();
        send_to_address(bitcoind, &addr, utxo_value);
    }
    drop(wallet);

    generate_blocks(bitcoind, 1);

    // Poll sync until the wallet observes the expected balance. With a Bitcoin Core backend
    // the first iteration succeeds immediately; with an Electrum backend the indexer needs a
    // moment to pick up the new block.
    let expected_regular = prev_balances.regular + utxo_value * utxo_count.into();
    let balances = wait_for_balance(taker.get_wallet(), expected_regular, 30);
    assert_eq!(balances.regular, expected_regular);

    info!(
        "Taker funded successfully. Regular: {}, Spendable: {}",
        balances.regular, balances.spendable
    );

    balances.spendable
}

/// Poll a wallet, calling `sync_and_save`, until its `regular` balance reaches `expected_regular`
/// or `timeout_secs` elapses. Returns the last observed balances either way.
fn wait_for_balance(
    wallet: &std::sync::Arc<std::sync::RwLock<openswap::wallet::Wallet>>,
    expected_regular: Amount,
    timeout_secs: u64,
) -> openswap::wallet::Balances {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut last;
    loop {
        {
            let mut w = wallet.write().unwrap();
            w.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
            last = w.get_balances().unwrap();
        }
        if last.regular >= expected_regular || Instant::now() >= deadline {
            return last;
        }
        thread::sleep(Duration::from_millis(500));
    }
}

/// Fund makers and verify their balances
#[allow(dead_code)]
pub fn fund_makers(
    makers: &[Arc<MakerServer>],
    bitcoind: &bitcoind::BitcoinD,
    utxo_count: u32,
    utxo_value: Amount,
    address_type: AddressType,
) -> Vec<Amount> {
    log::info!("💰 Funding Makers...");

    let mut spendable_balances = Vec::new();

    for maker in makers {
        let prev_regular = maker.wallet.read().unwrap().get_balances().unwrap().regular;

        // Send funds with the wallet locked just long enough to derive each address.
        for _ in 0..utxo_count {
            let mut wallet = maker.wallet.write().unwrap();
            let addr = wallet.get_next_external_address(address_type).unwrap();
            drop(wallet);
            send_to_address(bitcoind, &addr, utxo_value);
        }

        generate_blocks(bitcoind, 1);
        // Wait for the funding delta on top of whatever the wallet already
        // held, not an absolute target.
        let expected_regular = prev_regular + utxo_value * utxo_count.into();
        let balances = wait_for_balance(&maker.wallet, expected_regular, 30);

        assert!(
            balances.regular >= expected_regular,
            "Maker regular balance {} should be >= expected {}",
            balances.regular,
            expected_regular
        );

        info!(
            "Maker funded successfully. Regular: {}, Fidelity: {}",
            balances.regular, balances.fidelity
        );

        spendable_balances.push(balances.spendable);
    }

    spendable_balances
}

/// Verify maker pre-swap balances
#[allow(dead_code)]
pub fn verify_maker_pre_swap_balances(makers: &[Arc<MakerServer>]) -> Vec<Amount> {
    let mut maker_spendable_balance = Vec::new();

    info!("Testing maker balance verification");

    for (i, maker) in makers.iter().enumerate() {
        let wallet = maker.wallet.read().unwrap();
        let balances = wallet.get_balances().unwrap();

        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i,
            balances.regular,
            balances.swap,
            balances.contract,
            balances.fidelity,
            balances.spendable
        );

        // Regular balance after fidelity bond creation
        let regular = balances.regular.to_sat();
        assert!(
            regular == 14999514,
            "Maker regular balance check after fidelity bond creation: {}",
            regular
        );

        assert_eq!(balances.swap, Amount::ZERO);
        assert_eq!(balances.contract, Amount::ZERO);

        assert_eq!(
            balances.fidelity,
            Amount::from_btc(0.05).unwrap(),
            "Fidelity bond should be exactly 0.05 BTC"
        );

        assert!(
            balances.spendable > Amount::ZERO,
            "Maker {} should have spendable balance",
            i
        );

        maker_spendable_balance.push(balances.spendable);
    }

    maker_spendable_balance
}

/// Test-only marker selecting which backend a [`TestFramework::init`] run uses.
/// `init::<BitcoindBackend>` / `init::<ElectrumBackend>` pick the backend config;
/// the resulting `Taker`/`MakerServer` are non-generic and resolve the backend
/// at runtime.
pub trait TestBackend {
    fn make_backend_config(
        rpc_config: &CoreRpcConfig,
        zmq_addr: &str,
        ensure_electrum_url: &mut dyn FnMut() -> String,
    ) -> BackendConfig;

    /// Block cadence for the background miner: blocks per tick and tick interval.
    /// Protocol steps take far longer over Tor than clearnet, so a backend can
    /// slow the miner to keep block-denominated timelocks ahead of wall-clock delays.
    fn block_cadence() -> (u64, Duration) {
        (BLOCKS_PER_TICK, BLOCK_TICK_INTERVAL)
    }
}

/// Marker selecting the Bitcoin Core backend in tests.
pub struct BitcoindBackend;
/// Marker selecting the Electrum backend in tests.
pub struct ElectrumBackend;
/// Marker selecting the Electrum backend reached over a Tor SOCKS5 proxy.
///
/// Publishes the local `electrsd` as an ephemeral onion service so the client
/// has something a proxy can actually route to — Tor cannot reach a loopback
/// address. Requires a bootstrapped `tor`; see `electrum_tor.rs` for the gating.
pub struct TorElectrumBackend;

/// Tor control port used by the Tor integration tests.
pub const TOR_CONTROL_PORT: u16 = 9051;
/// Tor SOCKS port used by the Tor integration tests.
pub const TOR_SOCKS_PORT: u16 = 9050;

/// Control-port password for the Tor tests, from `OPENSWAP_TOR_PASSWORD`
/// (empty when unset, which matches a cookie-less `HashedControlPassword ""`).
pub fn tor_password() -> String {
    std::env::var("OPENSWAP_TOR_PASSWORD").unwrap_or_default()
}

/// True when the Tor integration tests should run.
///
/// `OPENSWAP_TOR_IT=1` means "I require Tor", so a missing daemon **panics**
/// rather than skipping. CI gates on these tests, and a silent skip would look
/// exactly like a pass. Without the variable set they skip, for local runs.
pub fn tor_it_enabled() -> bool {
    if std::env::var("OPENSWAP_TOR_IT").as_deref() != Ok("1") {
        log::warn!("skipping Tor integration test: OPENSWAP_TOR_IT=1 not set");
        return false;
    }
    if let Err(e) = check_tor_status(TOR_CONTROL_PORT, &tor_password()) {
        panic!(
            "OPENSWAP_TOR_IT=1 but tor control port {} is unreachable: {:?}",
            TOR_CONTROL_PORT, e
        );
    }
    true
}

impl TestBackend for BitcoindBackend {
    fn make_backend_config(
        rpc_config: &CoreRpcConfig,
        zmq_addr: &str,
        _ensure_electrum_url: &mut dyn FnMut() -> String,
    ) -> BackendConfig {
        BackendConfig::CoreRpc(CoreRpcConfig {
            zmq_addr: zmq_addr.to_string(),
            ..rpc_config.clone()
        })
    }
}

impl TestBackend for ElectrumBackend {
    fn make_backend_config(
        _rpc_config: &CoreRpcConfig,
        _zmq_addr: &str,
        ensure_electrum_url: &mut dyn FnMut() -> String,
    ) -> BackendConfig {
        BackendConfig::Electrum(ElectrumConfig {
            url: ensure_electrum_url(),
            ..Default::default()
        })
    }
}

impl TestBackend for TorElectrumBackend {
    /// ~0.67 blocks/s instead of ~1.67: the 150-block refund locktime base must
    /// outlast Tor-paced setup plus recovery, which the default cadence does not allow.
    fn block_cadence() -> (u64, Duration) {
        (2, BLOCK_TICK_INTERVAL)
    }

    fn make_backend_config(
        _rpc_config: &CoreRpcConfig,
        _zmq_addr: &str,
        ensure_electrum_url: &mut dyn FnMut() -> String,
    ) -> BackendConfig {
        // `ensure_electrum_url` yields "host:port" for the local electrsd; we only
        // need its port, since the onion service maps to 127.0.0.1.
        let local = ensure_electrum_url();
        let local_port: u16 = local
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or_else(|| panic!("could not parse electrum port from {}", local));

        // `Flags=Detach` means the service outlives this process. Acceptable: the
        // CI job's tor is ephemeral and drops it on restart.
        let onion = get_ephemeral_address(
            TOR_CONTROL_PORT,
            local_port,
            &tor_password(),
            "NEW:ED25519-V3",
            None,
        )
        .expect("ADD_ONION failed; call tor_it_enabled() before using this backend");

        // The helper fixes the onion-side port to OPENSWAP_PORT and maps it to
        // electrsd's real local port.
        let url = format!("tcp://{onion}:{OPENSWAP_PORT}");
        log::info!("Tor electrum backend: {url} via socks 127.0.0.1:{TOR_SOCKS_PORT}");

        // `timeout` and `poll_interval_secs` are left at their derived proxied
        // defaults so the test exercises the cadence production actually ships.
        let cfg = ElectrumConfig {
            url,
            socks5: Some(format!("127.0.0.1:{TOR_SOCKS_PORT}")),
            ..Default::default()
        };
        warm_up_onion(&cfg);
        BackendConfig::Electrum(cfg)
    }
}

/// Connect once before handing the config out, retrying until it works.
///
/// A fresh onion service is not reachable until its descriptor reaches the HSDir
/// ring and the client fetches it, which takes tens of seconds and is where
/// nearly all Tor flakiness lives. Tor caches the descriptor after the first
/// success, so paying for it once here makes every participant's connect fast.
fn warm_up_onion(cfg: &ElectrumConfig) {
    const ATTEMPTS: u32 = 12;
    const GAP: std::time::Duration = std::time::Duration::from_secs(10);

    for attempt in 1..=ATTEMPTS {
        match Electrum::new(cfg) {
            Ok(probe) => match probe.get_block_count() {
                Ok(tip) => {
                    log::info!("onion reachable on attempt {attempt} (tip {tip})");
                    return;
                }
                Err(e) => log::warn!("onion connected but no tip on attempt {attempt}: {e:?}"),
            },
            Err(e) => log::warn!("onion not reachable yet on attempt {attempt}: {e:?}"),
        }
        std::thread::sleep(GAP);
    }
    panic!(
        "onion service never became reachable after {} attempts",
        ATTEMPTS
    );
}

/// Wait until electrs has indexed up to bitcoind's tip.
///
/// electrs syncs asynchronously, so a wallet sync right after mining can read
/// a stale tip and cache UTXOs with outdated confirmation counts — which then
/// differs from a wallet synced after electrs caught up, failing equality
/// assertions. `trigger()` (SIGUSR1) nudges electrs to sync on each poll.
#[allow(dead_code)]
pub fn wait_for_electrs_tip(bitcoind: &BitcoinD, electrsd: &ElectrsD, cfg: &ElectrumConfig) {
    let expected = bitcoind.client.get_block_count().unwrap();
    let probe = Electrum::new(cfg).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let _ = electrsd.trigger();
        if probe
            .get_block_count()
            .map(|tip| tip >= expected)
            .unwrap_or(false)
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "electrs did not reach tip {} within 60s",
            expected
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Blocks mined per tick by the background block-generation thread.
const BLOCKS_PER_TICK: u64 = 5;
/// Interval between block-generation ticks. Together with [`BLOCKS_PER_TICK`]
/// this yields ~1.67 blocks/s, slow enough that block-denominated timelocks
/// outlast the wall-clock recovery delays exercised by the abort tests.
const BLOCK_TICK_INTERVAL: Duration = Duration::from_secs(3);

/// How long abort tests must sleep for makers to detect a drop and for the
/// outer-hop timelock (225 blocks) to mature, at backend `B`'s block cadence.
pub(crate) fn timelock_recovery_wait<B: TestBackend>() -> Duration {
    let (per_tick, tick) = B::block_cadence();
    // 10s idle timeout + 225 blocks + scheduling margin.
    Duration::from_secs(175) + tick * (225u64.div_ceil(per_tick)) as u32
}

/// The Test Framework.
///
/// Handles initializing, operating and cleaning up of all backend processes. Bitcoind, Taker and Makers.
#[allow(dead_code)]
pub struct TestFramework {
    pub(super) bitcoind: BitcoinD,
    /// Present only when the backend in [`TestFramework::init`] asks for an Electrum URL.
    /// Kept alive here so the electrs child process lives for the duration of the test.
    /// Behind a `Mutex` so teardown can drop it before bitcoind, from `&self`.
    pub(super) electrsd: Mutex<Option<ElectrsD>>,
    pub(super) temp_dir: PathBuf,
    pub(super) nostr_relay_url: String,
    /// Kept so [`TestFramework::taker_init_config`] can rebuild the same backend
    /// config the takers were started with.
    zmq_addr: String,
    /// Kept for the same reason as `zmq_addr`: a taker rebuilt by
    /// [`TestFramework::taker_init_config`] must screen as the original did.
    check_blocklist: bool,
    shutdown: AtomicBool,
    block_gen_paused: AtomicBool,
    nostr_relay: Mutex<Option<Child>>,
}

impl TestFramework {
    /// Assert that a log message exists in the debug.log file
    pub fn assert_log(&self, expected_message: &str, log_path: &str) {
        match std::fs::read_to_string(log_path) {
            Ok(log_contents) => {
                assert!(
                    log_contents.contains(expected_message),
                    "Expected log message '{}' not found in log file: {}",
                    expected_message,
                    log_path
                );
                log::info!("✅ Found expected log message: '{expected_message}'");
            }
            Err(e) => {
                panic!("Could not read log file at {}: {}", log_path, e);
            }
        }
    }

    /// Initialize test framework over backend `B`. Complete segregation over the 2 backends.
    ///
    /// This creates Taker and MakerServer instances that support
    /// both Legacy (ECDSA) and Taproot (MuSig2) protocols using message types.
    ///
    /// Mines [`BLOCKS_PER_TICK`] blocks every [`BLOCK_TICK_INTERVAL`] so
    /// timelocks can mature during a test.
    #[allow(clippy::type_complexity)]
    pub fn init<B: TestBackend>(
        makers_config_map: Vec<(u16, Option<u16>)>,
        taker_behavior: Vec<TakerBehavior>,
        maker_behaviors: Vec<MakerBehavior>,
    ) -> (Arc<Self>, Vec<Taker>, Vec<Arc<MakerServer>>, JoinHandle<()>) {
        Self::init_with_blocklist_setting::<B>(
            makers_config_map,
            taker_behavior,
            maker_behaviors,
            false,
        )
    }

    /// Initialize the test framework with runtime blocklist screening enabled.
    #[allow(clippy::type_complexity)]
    pub fn init_with_blocklist<B: TestBackend>(
        makers_config_map: Vec<(u16, Option<u16>)>,
        taker_behavior: Vec<TakerBehavior>,
        maker_behaviors: Vec<MakerBehavior>,
    ) -> (Arc<Self>, Vec<Taker>, Vec<Arc<MakerServer>>, JoinHandle<()>) {
        Self::init_with_blocklist_setting::<B>(
            makers_config_map,
            taker_behavior,
            maker_behaviors,
            true,
        )
    }

    #[allow(clippy::type_complexity)]
    fn init_with_blocklist_setting<B: TestBackend>(
        makers_config_map: Vec<(u16, Option<u16>)>,
        taker_behavior: Vec<TakerBehavior>,
        maker_behaviors: Vec<MakerBehavior>,
        check_blocklist: bool,
    ) -> (Arc<Self>, Vec<Taker>, Vec<Arc<MakerServer>>, JoinHandle<()>) {
        // Setup directory — use a unique suffix so tests can run in parallel
        let unique_id = format!("openswap-{}", rand::random::<u64>());
        let temp_dir = env::temp_dir().join(unique_id);
        // Remove if previously existing
        if temp_dir.exists() {
            fs::remove_dir_all::<PathBuf>(temp_dir.clone()).unwrap();
        }
        setup_logger(log::LevelFilter::Debug, Some(temp_dir.clone()));
        log::info!("📁 temporary directory : {}", temp_dir.display());
        let zmq_addr = format!("tcp://127.0.0.1:{}", 28332 + rand::random::<u16>() % 1000);
        let bitcoind = init_bitcoind(&temp_dir, zmq_addr.clone());
        let rpc_config = CoreRpcConfig {
            url: bitcoind.rpc_url().split_at(7).1.to_string(),
            auth: Auth::CookieFile(bitcoind.params.cookie_file.clone()),
            ..Default::default()
        };
        let nostr_port = 8000 + rand::random::<u16>() % 1000;
        let nostr_relay_url = format!("ws://127.0.0.1:{nostr_port}");
        let nostr_relay = spawn_nostr_relay(&temp_dir, nostr_port);
        wait_for_relay_healthy(nostr_port);
        let mut electrsd: Option<ElectrsD> = None;
        let (takers, makers) = {
            let mut electrum_url: Option<String> = None;
            let mut ensure_electrum_url = || -> String {
                if let Some(url) = electrum_url.as_ref() {
                    return url.clone();
                }
                let e = init_electrsd(&bitcoind, &temp_dir);
                // Give electrs a moment to index the 101 blocks bitcoind has already mined.
                thread::sleep(Duration::from_secs(2));
                let _ = e.trigger();
                thread::sleep(Duration::from_secs(1));
                let url = format!("tcp://{}", e.electrum_url);
                electrsd = Some(e);
                electrum_url = Some(url.clone());
                url
            };
            let takers: Vec<Taker> = taker_behavior
                .into_iter()
                .enumerate()
                .map(|(i, behavior)| {
                    let taker_id = format!("taker{}", i + 1);
                    let backend =
                        B::make_backend_config(&rpc_config, &zmq_addr, &mut ensure_electrum_url);
                    let mut config = TakerInitConfig::default()
                        .with_data_dir(temp_dir.join(&taker_id))
                        .with_backend(backend)
                        .with_nostr_relays(vec![nostr_relay_url.clone()]);
                    config.wallet_name = taker_id;
                    // Wallet files are always encrypted; tests use a fixed
                    // passphrase (PBKDF2 rounds are 1 under `integration-test`).
                    config.password = Some("integration-test".to_string());
                    config.check_blocklist = Some(check_blocklist);
                    let mut taker = Taker::init(config).unwrap();
                    taker.behavior = behavior;
                    taker
                })
                .collect();

            let mut base_rpc_port = 4500 + (rand::random::<u16>() % 5000);
            let base_maker_port = 10000 + rand::random::<u16>() % 40000;

            // Create the MakerServers with message handling
            let makers: Vec<Arc<MakerServer>> = makers_config_map
                .into_iter()
                .enumerate()
                .map(|(i, _)| {
                    base_rpc_port += 1;
                    let network_port = base_maker_port + i as u16;
                    let maker_id = format!("maker{network_port}");
                    thread::sleep(Duration::from_secs(5)); // Avoid resource unavailable error
                    let backend =
                        B::make_backend_config(&rpc_config, &zmq_addr, &mut ensure_electrum_url);
                    let config = MakerServerConfig {
                        data_dir: temp_dir.join(network_port.to_string()),
                        wallet_name: maker_id,
                        network_port,
                        rpc_port: base_rpc_port,
                        base_fee: 500,
                        amount_relative_fee_pct: 0.0025,
                        time_relative_fee_pct: 0.0001,
                        min_swap_amount: 10_000,
                        required_confirms: 1,
                        check_blocklist,
                        supported_protocols: vec![
                            ProtocolVersion::Legacy,
                            ProtocolVersion::Taproot,
                        ],
                        fidelity_amount: 5_000_000, // 0.05 BTC
                        fidelity_timelock: 950,     // ~950 blocks for test
                        network: bitcoin::Network::Regtest,
                        nostr_relays: vec![nostr_relay_url.clone()],
                        // Wallet files are always encrypted; tests use a fixed
                        // passphrase (PBKDF2 rounds are 1 under `integration-test`).
                        password: Some("integration-test".to_string()),
                        ..MakerServerConfig::default()
                    }
                    .with_backend(backend);

                    let mut server = MakerServer::init(config).unwrap();
                    server.behavior = maker_behaviors.get(i).copied().unwrap_or_default();
                    Arc::new(server)
                })
                .collect();

            (takers, makers)
        };

        let framework = Arc::new(Self {
            bitcoind,
            electrsd: Mutex::new(electrsd),
            temp_dir: temp_dir.clone(),
            nostr_relay_url: nostr_relay_url.clone(),
            zmq_addr,
            check_blocklist,
            shutdown: AtomicBool::new(false),
            block_gen_paused: AtomicBool::new(false),
            nostr_relay: Mutex::new(Some(nostr_relay)),
        });
        let (blocks_per_tick, block_tick_interval) = B::block_cadence();
        log::info!(
            "⛏️ Spawning block generation thread ({blocks_per_tick} blocks / {block_tick_interval:?})"
        );
        let tf_weak = Arc::downgrade(&framework);
        let generate_blocks_handle = thread::spawn(move || loop {
            thread::sleep(block_tick_interval);

            let Some(tf) = tf_weak.upgrade() else {
                log::info!("🔚 Test framework dropped, ending block generation thread");
                return;
            };

            if tf.shutdown.load(Relaxed) {
                log::info!("🔚 Ending block generation thread");
                return;
            }
            if !tf.block_gen_paused.load(Relaxed) {
                generate_blocks(&tf.bitcoind, blocks_per_tick);
                if let Some(elec) = tf.electrsd.lock().unwrap().as_ref() {
                    let _ = elec.trigger();
                }
            }
        });
        log::info!("✅ Test Framework initialization complete");
        (framework, takers, makers, generate_blocks_handle)
    }

    /// Rebuild taker `i`'s init config, so a test can drop the taker and re-init
    /// it against the same wallet and data dir the way a restarted daemon would.
    /// Must stay in step with the taker setup inside [`TestFramework::init`],
    /// or the re-init opens a different wallet and proves nothing.
    #[allow(dead_code)]
    pub fn taker_init_config<B: TestBackend>(&self, i: usize) -> TakerInitConfig {
        let taker_id = format!("taker{}", i + 1);
        let rpc_config = CoreRpcConfig {
            url: self.bitcoind.rpc_url().split_at(7).1.to_string(),
            auth: Auth::CookieFile(self.bitcoind.params.cookie_file.clone()),
            ..Default::default()
        };
        let mut ensure_electrum_url = || -> String {
            format!(
                "tcp://{}",
                self.electrsd
                    .lock()
                    .unwrap()
                    .as_ref()
                    .expect("Electrum backend needs a framework started with init_electrum")
                    .electrum_url
            )
        };
        let backend = B::make_backend_config(&rpc_config, &self.zmq_addr, &mut ensure_electrum_url);
        let mut config = TakerInitConfig::default()
            .with_data_dir(self.temp_dir.join(&taker_id))
            .with_backend(backend)
            .with_nostr_relays(vec![self.nostr_relay_url.clone()]);
        config.wallet_name = taker_id;
        // Must match the passphrase set in `TestFramework::init`, or the
        // re-init cannot decrypt the wallet.
        config.password = Some("integration-test".to_string());
        config.check_blocklist = Some(self.check_blocklist);
        config
    }

    /// Wait for electrs (if this framework runs one) to reach bitcoind's tip.
    /// No-op on the Core backend.
    #[allow(dead_code)]
    pub fn wait_for_electrs_tip(&self) {
        if let Some(electrsd) = self.electrsd.lock().unwrap().as_ref() {
            let cfg = ElectrumConfig {
                url: format!("tcp://{}", electrsd.electrum_url),
                ..Default::default()
            };
            wait_for_electrs_tip(&self.bitcoind, electrsd, &cfg);
        }
    }

    /// Pause or resume the periodic mining loop, e.g. to hold a mempool tx
    /// unconfirmed while a test asserts on that state.
    pub fn set_block_gen_paused(&self, paused: bool) {
        self.block_gen_paused.store(paused, Relaxed);
    }

    /// Terminate the per-test nostr relay child process, if still running.
    pub(crate) fn kill_relay(&self) {
        if let Some(mut child) = self.nostr_relay.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Stop bitcoind, nostr relay, and clean up all test data.
    pub fn stop(&self) {
        log::info!("🛑 Stopping Test Framework");
        self.shutdown.store(true, Relaxed);
        self.kill_relay();
        // electrs's datadir sits inside `temp_dir` and it polls bitcoind, so it
        // has to go first or teardown races a live child against a dead node.
        drop(self.electrsd.lock().unwrap().take());
        // Tolerate an already-stopped node: a test may restart bitcoind
        // mid-run (e.g. to reset the mempool) and stop the framework's
        // original node itself.
        let _ = self.bitcoind.client.stop();
        std::thread::sleep(std::time::Duration::from_secs(3));
        if self.temp_dir.exists() {
            let _ = fs::remove_dir_all(&self.temp_dir);
        }
    }
}

impl Drop for TestFramework {
    fn drop(&mut self) {
        self.shutdown.store(true, Relaxed);
        self.kill_relay();
        // Field order drops bitcoind first; take electrs down ahead of it.
        drop(self.electrsd.lock().unwrap().take());
        let _ = self.bitcoind.client.stop();
        std::thread::sleep(std::time::Duration::from_secs(3));
        if self.temp_dir.exists() {
            let _ = fs::remove_dir_all(&self.temp_dir);
        }
    }
}

/// Poll a log file until `expected` appears; panics after `timeout`.
#[allow(dead_code)]
pub(crate) fn wait_for_log(log_path: &str, expected: &str, timeout: Duration) {
    let start = Instant::now();
    loop {
        if let Ok(contents) = fs::read_to_string(log_path) {
            if contents.contains(expected) {
                log::info!("✅ Found expected log message: '{expected}'");
                return;
            }
        }
        assert!(
            start.elapsed() <= timeout,
            "Timed out waiting for log message '{}' in {}",
            expected,
            log_path
        );
        thread::sleep(Duration::from_secs(2));
    }
}

/// Like [`wait_for_log`], but only matches content appended after this call.
/// Use when the needle can already sit in the file from an earlier phase
/// (fidelity-setup sightings look identical to swap-funding sightings).
#[allow(dead_code)]
pub(crate) fn wait_for_new_log(log_path: &str, expected: &str, timeout: Duration) {
    let start = Instant::now();
    let offset = fs::metadata(log_path).map(|m| m.len()).unwrap_or(0);
    loop {
        if let Ok(contents) = fs::read_to_string(log_path) {
            if contents
                .get(offset as usize..)
                .is_some_and(|new| new.contains(expected))
            {
                log::info!("✅ Found expected log message: '{expected}'");
                return;
            }
        }
        assert!(
            start.elapsed() <= timeout,
            "Timed out waiting for log message '{}' in {}",
            expected,
            log_path
        );
        thread::sleep(Duration::from_secs(2));
    }
}

/// Handle returned by [`spawn_tracker_logger`] to stop the background thread.
pub struct TrackerLoggerHandle {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl TrackerLoggerHandle {
    /// Signal the background logger to stop and wait for it to finish.
    #[allow(dead_code)]
    pub fn stop(mut self) {
        self.shutdown.store(true, Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for TrackerLoggerHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Spawn a background thread that periodically reads the swap tracker CBOR file
/// from `data_dir` and logs its contents at INFO level.
///
/// Usage in a test:
/// ```ignore
/// let logger = spawn_tracker_logger(temp_dir.join("taker1"), Duration::from_secs(5));
/// // ... run test ...
/// logger.stop();
/// ```
#[allow(dead_code)]
pub fn spawn_tracker_logger(data_dir: PathBuf, interval: Duration) -> TrackerLoggerHandle {
    use openswap::taker::swap_tracker::SwapTracker;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    let handle = thread::spawn(move || {
        while !shutdown_clone.load(Relaxed) {
            thread::sleep(interval);
            if shutdown_clone.load(Relaxed) {
                break;
            }
            match SwapTracker::load_or_create(&data_dir) {
                Ok(tracker) => tracker.log_state(),
                Err(e) => log::warn!("[TrackerLogger] Failed to load tracker: {:?}", e),
            }
        }
    });

    TrackerLoggerHandle {
        shutdown,
        handle: Some(handle),
    }
}

/// Spawns a dedicated `nostr-rs-relay` process for a single test.
///
/// Each test gets its own relay on its own random port with an in-memory
/// database, so concurrently running tests never share nostr state. The relay
/// binary is located via the `OPENSWAP_TEST_NOSTR_RELAY_BIN` env var, falling
/// back to `nostr-rs-relay` on `PATH`.
fn spawn_nostr_relay(temp_dir: &Path, port: u16) -> Child {
    let data_dir = temp_dir.join("nostr-relay");
    std::fs::create_dir_all(&data_dir).unwrap();

    // Minimal per-test relay config: bind the random port and use an in-memory
    // SQLite DB so nothing persists across or leaks between tests.
    let config_path = data_dir.join("config.toml");
    let config = format!(
        "[network]\naddress = \"127.0.0.1\"\nport = {port}\n\n[database]\ndata_directory = \"{data_dir}\"\nin_memory = true\nmin_conn = 4\nmax_conn = 8\n\n[diagnostics]\ntracing = false\n",
        data_dir = data_dir.display()
    );
    std::fs::write(&config_path, config).unwrap();

    let bin =
        env::var("OPENSWAP_TEST_NOSTR_RELAY_BIN").unwrap_or_else(|_| "nostr-rs-relay".to_string());

    Command::new(&bin)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "failed to spawn nostr relay binary '{}': {}. Install it with `cargo install nostr-rs-relay` or set OPENSWAP_TEST_NOSTR_RELAY_BIN.",
                bin, e
            )
        })
}

fn wait_for_relay_healthy(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    let timeout = Duration::from_secs(10);
    let start = Instant::now();

    while start.elapsed() < timeout {
        if TcpStream::connect(&addr).is_ok() {
            log::info!("Nostr relay is alive on port {port}");
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    log::warn!("Nostr relay did not become healthy on port {port} within 10s");
}

/// Verifies that a swap report file contains the expected number of deniability proofs,
/// and that each proof passes on-chain verification.
pub fn assert_report_has_deniability_proofs(
    report_path: &std::path::Path,
    label: &str,
    bitcoind: &BitcoinD,
    expected_count: usize,
) {
    let content = fs::read_to_string(report_path)
        .unwrap_or_else(|e| panic!("Failed to read {} report: {}", label, e));
    let json: serde_json::Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {} report: {}", label, e));
    let proofs = json
        .get("deniability_proofs")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("{} report is missing deniability_proofs", label));
    assert_eq!(
        proofs.len(),
        expected_count,
        "{} report should contain {} deniability proof(s) at {}",
        label,
        expected_count,
        report_path.display()
    );
    let rpc_config = CoreRpcConfig {
        url: bitcoind.rpc_url().split_at(7).1.to_string(),
        auth: Auth::CookieFile(bitcoind.params.cookie_file.clone()),
        ..Default::default()
    };
    let blockchain = AnyBlockchain::CoreRPC(
        CoreRPC::new(&rpc_config).expect("failed to connect blockchain backend for verification"),
    );
    for (i, proof_value) in proofs.iter().enumerate() {
        let swap_id = proof_value
            .get("swap_id")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{} proof {} is missing swap_id", label, i));
        let verified = verify_deniability(report_path, &blockchain, swap_id)
            .unwrap_or_else(|e| panic!("{} proof {} verification error: {}", label, i, e));
        assert!(
            verified,
            "{} proof {} failed on-chain verification",
            label, i
        );
        info!("{} proof {} verified ok (swap_id={})", label, i, swap_id);
    }
    info!(
        "{} all {} deniability proof(s) verified: {}",
        label,
        proofs.len(),
        report_path.display()
    );
}

/// Initializes a [`TestFramework`] given a [`CoreRpcConfig`].
impl From<&TestFramework> for CoreRpcConfig {
    fn from(value: &TestFramework) -> Self {
        let url = value.bitcoind.rpc_url().split_at(7).1.to_string();
        let auth = Auth::CookieFile(value.bitcoind.params.cookie_file.clone());
        Self {
            url,
            auth,
            ..Default::default()
        }
    }
}
