//! The [`TestFramework`] fixture: setup, background mining and teardown.

use bip39::rand;
use std::{
    env, fs,
    path::PathBuf,
    process::Child,
    sync::{
        atomic::{
            AtomicBool,
            Ordering::{Relaxed, SeqCst},
        },
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use bitcoind::{
    bitcoincore_rpc::{Auth, RpcApi},
    BitcoinD,
};

use electrsd::ElectrsD;
use openswap::{
    maker::{MakerBehavior, MakerServer, MakerServerConfig},
    protocol::common_messages::ProtocolVersion,
    taker::{Taker, TakerBehavior, TakerInitConfig},
    wallet::{CoreRpcConfig, ElectrumConfig},
};

use super::{
    backend::TestBackend,
    logs::setup_test_logger,
    ports::{free_ports, reserve_listeners},
    procs::{
        bitcoind::{init_bitcoind, try_generate_blocks},
        electrs::{init_electrsd, wait_for_electrs_tip},
        nostr::{spawn_nostr_relay, wait_for_relay_healthy},
    },
};

/// The Test Framework.
///
/// Handles initializing, operating and cleaning up of all backend processes. Bitcoind, Taker and Makers.
#[allow(dead_code)]
pub struct TestFramework {
    pub(crate) bitcoind: BitcoinD,
    /// Present only when the backend in [`TestFramework::init`] asks for an Electrum URL.
    /// Kept alive here so the electrs child process lives for the duration of the test.
    /// Behind a `Mutex` so teardown can drop it before bitcoind, from `&self`.
    pub(crate) electrsd: Mutex<Option<ElectrsD>>,
    pub(crate) temp_dir: PathBuf,
    pub(crate) nostr_relay_url: String,
    /// Kept so [`TestFramework::taker_init_config`] can rebuild the same backend
    /// config the takers were started with.
    zmq_addr: String,
    /// Kept for the same reason as `zmq_addr`: a taker rebuilt by
    /// [`TestFramework::taker_init_config`] must screen as the original did.
    check_blocklist: bool,
    shutdown: AtomicBool,
    /// Set by the first teardown, so `stop()` followed by `Drop` tears down once.
    torn_down: AtomicBool,
    block_gen_paused: AtomicBool,
    nostr_relay: Mutex<Option<Child>>,
}

/// Per-maker offer override for [`TestFramework::init`].
/// `None` keeps the shared default, so existing tests stay homogeneous.
#[derive(Clone, Copy, Debug)]
pub struct MakerFeeOverride {
    pub base_fee: u64,
    pub amount_relative_fee_pct: f64,
}

impl Default for MakerFeeOverride {
    fn default() -> Self {
        Self {
            base_fee: 500,
            amount_relative_fee_pct: 0.0025,
        }
    }
}

impl TestFramework {
    /// Path to the taker's debug.log inside this framework's temp dir.
    pub fn taker_log_path(&self) -> String {
        format!("{}/taker/debug.log", self.temp_dir.display())
    }

    /// Assert that a log message exists in the debug.log file
    #[track_caller]
    pub fn assert_log(&self, expected_message: &str, log_path: &str) {
        match std::fs::read_to_string(log_path) {
            Ok(log_contents) => {
                assert!(
                    log_contents.contains(expected_message),
                    "Expected log message '{}' not found in log file: {}",
                    expected_message,
                    log_path
                );
                log::info!("Found expected log message: '{expected_message}'");
            }
            Err(e) => {
                panic!("Could not read log file at {}: {}", log_path, e);
            }
        }
    }

    /// Initialize test framework over backend `B`. `B` builds the wallet backend
    /// config of every taker and maker (and so decides whether electrs is spawned),
    /// and sets the background miner's cadence.
    ///
    /// This creates Taker and MakerServer instances that support
    /// both Legacy (ECDSA) and Taproot (MuSig2) protocols using message types.
    /// `fee_overrides` holds one slot per maker (`None` keeps the shared fee
    /// schedule), `check_blocklist` turns on runtime blocklist screening for every
    /// taker and maker, and `maker_lightning[i]` goes to maker `i`.
    ///
    /// Mines [`BLOCKS_PER_TICK`](super::timing::BLOCKS_PER_TICK) blocks every [`BLOCK_TICK_INTERVAL`](super::timing::BLOCK_TICK_INTERVAL) so
    /// timelocks can mature during a test.
    #[allow(clippy::type_complexity)]
    pub fn init<B: TestBackend>(
        maker_count: usize,
        fee_overrides: Vec<Option<MakerFeeOverride>>,
        taker_behavior: Vec<TakerBehavior>,
        maker_behaviors: Vec<MakerBehavior>,
        check_blocklist: bool,
        #[cfg(feature = "lightning")] maker_lightning: Vec<
            std::sync::Arc<dyn openswap::lightning::LightningBackend>,
        >,
    ) -> (Arc<Self>, Vec<Taker>, Vec<Arc<MakerServer>>, JoinHandle<()>) {
        assert_eq!(
            fee_overrides.len(),
            maker_count,
            "one fee override slot per maker"
        );
        // Setup directory — use a unique suffix so tests can run in parallel
        let unique_id = format!("openswap-{}", rand::random::<u64>());
        let temp_dir = env::temp_dir().join(unique_id);
        // Remove if previously existing
        if temp_dir.exists() {
            fs::remove_dir_all::<PathBuf>(temp_dir.clone()).unwrap();
        }
        setup_test_logger(&temp_dir);
        log::info!("temporary directory : {}", temp_dir.display());
        // Names the test in its own log, so a kept data dir can be traced back.
        log::info!("test: {}", thread::current().name().unwrap_or("<unnamed>"));
        let (bitcoind, zmq_addr) = (0..3)
            .find_map(|_| {
                let zmq_addr = format!("tcp://127.0.0.1:{}", free_ports(1)[0]);
                init_bitcoind(&temp_dir, zmq_addr.clone())
                    .ok()
                    .map(|b| (b, zmq_addr))
            })
            .expect("bitcoind failed to start on three fresh ZMQ ports");
        let rpc_config = CoreRpcConfig {
            url: bitcoind.rpc_url().split_at(7).1.to_string(),
            auth: Auth::CookieFile(bitcoind.params.cookie_file.clone()),
            ..Default::default()
        };
        let (nostr_port, nostr_relay) = (0..3)
            .find_map(|_| {
                let port = free_ports(1)[0];
                let mut relay = spawn_nostr_relay(&temp_dir, port);
                if wait_for_relay_healthy(port, &mut relay) {
                    Some((port, relay))
                } else {
                    let _ = relay.kill().and_then(|_| relay.wait());
                    None
                }
            })
            .expect("nostr relay failed to start on three fresh ports");
        // Until the framework below owns the relay, a panic while building the
        // takers, makers or electrs would drop a bare `Child`, which leaves the
        // process running; the guard kills it on that path instead.
        let mut nostr_relay = RelayGuard(Some(nostr_relay));
        let nostr_relay_url = format!("ws://127.0.0.1:{nostr_port}");
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

            // Reserved sockets, one block per role, held until each maker
            // takes its pair at server start. Network ports must ascend with
            // the maker index: the taker sorts makers by address, so port
            // order decides route order and the golden balances.
            let mut network_listeners = reserve_listeners(maker_count).into_iter();
            let mut rpc_listeners = reserve_listeners(maker_count).into_iter();

            // Create the MakerServers with message handling
            let makers: Vec<Arc<MakerServer>> = (0..maker_count)
                .map(|i| {
                    let network_listener = network_listeners.next().expect("one port per maker");
                    let rpc_listener = rpc_listeners.next().expect("one port per maker");
                    let network_port = network_listener.local_addr().unwrap().port();
                    let maker_id = format!("maker{network_port}");
                    thread::sleep(Duration::from_secs(5)); // Avoid resource unavailable error
                    let backend =
                        B::make_backend_config(&rpc_config, &zmq_addr, &mut ensure_electrum_url);
                    let fee = fee_overrides.get(i).copied().flatten();
                    let config = MakerServerConfig {
                        data_dir: temp_dir.join(network_port.to_string()),
                        name: maker_id.clone(),
                        wallet_name: maker_id,
                        network_port,
                        rpc_port: rpc_listener.local_addr().unwrap().port(),
                        base_fee: fee.map_or(500, |f| f.base_fee),
                        amount_relative_fee_pct: fee.map_or(0.0025, |f| f.amount_relative_fee_pct),
                        time_relative_fee_pct: 0.0001,
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
                    *server.reserved_network_listener.lock().unwrap() = Some(network_listener);
                    *server.reserved_rpc_listener.lock().unwrap() = Some(rpc_listener);
                    #[cfg(feature = "lightning")]
                    if let Some(backend) = maker_lightning.get(i).cloned() {
                        server.set_lightning_backend(backend);
                    }
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
            torn_down: AtomicBool::new(false),
            block_gen_paused: AtomicBool::new(false),
            nostr_relay: Mutex::new(nostr_relay.0.take()),
        });
        let (blocks_per_tick, block_tick_interval) = B::block_cadence();
        log::info!(
            "Spawning block generation thread ({blocks_per_tick} blocks / {block_tick_interval:?})"
        );
        let tf_weak = Arc::downgrade(&framework);
        let generate_blocks_handle = thread::spawn(move || loop {
            thread::sleep(block_tick_interval);

            let Some(tf) = tf_weak.upgrade() else {
                log::info!("Test framework dropped, ending block generation thread");
                return;
            };

            if tf.shutdown.load(Relaxed) {
                log::info!("Ending block generation thread");
                return;
            }
            if !tf.block_gen_paused.load(Relaxed) {
                // Never panic here: teardown stops bitcoind while this thread
                // may be mid-call, and some tests restart the node themselves.
                if let Err(e) = try_generate_blocks(&tf.bitcoind, blocks_per_tick) {
                    if !tf.shutdown.load(Relaxed) {
                        log::warn!("Background block generation failed: {e}");
                    }
                }
                if let Some(elec) = tf.electrsd.lock().unwrap().as_ref() {
                    let _ = elec.trigger();
                }
            }
        });
        log::info!("Test Framework initialization complete");
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
                    .expect(
                        "Electrum backend needs electrsd, which init spawns \
                         only for an Electrum backend with at least one taker or maker, and \
                         which is gone after teardown or once a test takes it",
                    )
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
    ///
    /// Calling it is optional: `Drop` runs the same teardown, and whichever
    /// comes first does the work, so the teardown runs once either way.
    pub fn stop(&self) {
        self.teardown();
    }

    /// The teardown shared by [`TestFramework::stop`] and `Drop`. Only the
    /// first call does anything; later calls return immediately.
    fn teardown(&self) {
        if self.torn_down.swap(true, SeqCst) {
            return;
        }
        log::info!("Stopping Test Framework");
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
        self.remove_temp_dir();
    }

    /// Deletes the temp dir, unless the test is failing: then its logs,
    /// wallets and trackers stay behind for inspection (CI uploads them).
    fn remove_temp_dir(&self) {
        if thread::panicking() {
            log::warn!(
                "Keeping {} for inspection: the test failed",
                self.temp_dir.display()
            );
        } else if self.temp_dir.exists() {
            let _ = fs::remove_dir_all(&self.temp_dir);
        }
    }

    /// Drops the takers, stops the framework, then joins the block generator.
    /// Joining before stopping would hang the miner thread.
    #[allow(dead_code)]
    pub fn finish(&self, takers: Vec<Taker>, block_generation_handle: JoinHandle<()>) {
        drop(takers);
        self.stop();
        block_generation_handle.join().unwrap();
    }
}

/// Owns the nostr relay during `init`, killing it if `init` unwinds before the
/// framework takes it over.
struct RelayGuard(Option<Child>);

impl Drop for RelayGuard {
    fn drop(&mut self) {
        if let Some(mut relay) = self.0.take() {
            let _ = relay.kill().and_then(|_| relay.wait());
        }
    }
}

impl Drop for TestFramework {
    fn drop(&mut self) {
        // Field order drops bitcoind first; teardown takes electrs down ahead of it.
        self.teardown();
        // Takers and makers dropped after stop() still flush their wallets and
        // offerbooks into temp_dir, recreating it; sweep whatever they wrote.
        // A failing test's dir stays, as `teardown` already announced.
        if !thread::panicking() && self.temp_dir.exists() {
            let _ = fs::remove_dir_all(&self.temp_dir);
        }
    }
}

/// Builds a [`CoreRpcConfig`] for a [`TestFramework`]'s bitcoind: its RPC URL
/// and cookie auth, with every other field left at its default.
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
