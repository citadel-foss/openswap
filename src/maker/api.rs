//! Maker API for both Legacy (ECDSA) and Taproot (MuSig2) protocols.

use std::{
    collections::HashMap,
    convert::TryFrom,
    io::Write,
    net::TcpStream,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use bitcoin::{bip32::ChainCode, Amount, Network, OutPoint, PublicKey, Transaction};

use crate::{
    lock_debug,
    maker::nostr::NOSTR_RELAYS,
    protocol::common_messages::{FidelityProof, ProtocolVersion, SwapDetails},
    taker::api::REFUND_LOCKTIME_STEP,
    utill::{get_maker_dir, parse_field, parse_toml, MIN_FEE_RATE, MIN_RELAY_FEE_RATE},
    wallet::{
        swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
        AddressType, AnyBlockchain, BackendConfig, Blockchain, CoreRpcConfig, FidelityError,
        Wallet, WalletError, MAX_FIDELITY_TIMELOCK, MIN_FIDELITY_TIMELOCK,
    },
    watch_tower::service::WatchService,
};

#[cfg(feature = "integration-test")]
pub use super::handlers::MakerBehavior;

use super::{
    error::MakerError,
    handlers::{
        past_refund_deadline, ConnectionState, Maker as MakerTrait, MakerConfig, SwapPhase,
        MAX_CONCURRENT_SWAPS,
    },
    rpc::server::MakerRpc,
    swap_tracker::MakerSwapTracker,
};

/// Minimum swap amount in satoshis.
pub const MIN_SWAP_AMOUNT: u64 = 10_000;

/// Swap state tracked per swap_id (persisted across connections).
#[derive(Debug, Clone)]
struct SwapState {
    /// Swap amount.
    swap_amount: Amount,
    /// [maximum forwarding transaction count, maximum inputs per forwarding transaction].
    tx_count: [u32; 2],
    /// Timelock value (Legacy: relative CSV, Taproot: absolute CLTV height).
    timelock: u32,
    /// Protocol version for this swap.
    protocol: ProtocolVersion,
    /// Current phase of the swap.
    phase: SwapPhase,
    /// Incoming swapcoins (we receive).
    incoming_swapcoins: Vec<IncomingSwapCoin>,
    /// Outgoing swapcoins (we send).
    outgoing_swapcoins: Vec<OutgoingSwapCoin>,
    /// Pending funding transactions (for Legacy protocol).
    /// Stored until signature exchange completes, then broadcast.
    pending_funding_txes: Vec<Transaction>,
    /// Whether the funding transaction was actually broadcast to the network.
    funding_broadcast: bool,
    /// Contract fee rate for multi-hop swap creation.
    contract_feerate: f64,
    /// Maker service fee calculated from the accepted offer, excluding mining reimbursement.
    service_fee_sats: u64,
    /// Reserved UTXOs for this swap (prevents concurrent double-spending).
    reserve_utxo: Vec<OutPoint>,
    /// Last activity timestamp.
    last_activity: Instant,
    /// Time when this swap was accepted by the maker.
    swap_start_time: Instant,
    /// How many blocks the funds stay locked, fixed when the swap is accepted.
    /// Persisted so a fee recomputed on a later message comes out the same.
    refund_locktime_offset: u16,
    /// Height our incoming funding confirmed at. A Legacy refund deadline is counted
    /// from it, and it cannot be derived later once the swap has moved on.
    /// `None` until that confirmation is observed.
    funding_confirmation_height: Option<u32>,
}

impl Default for SwapState {
    fn default() -> Self {
        SwapState {
            swap_amount: Amount::ZERO,
            tx_count: [0, 0],
            timelock: 0,
            protocol: ProtocolVersion::Legacy,
            phase: SwapPhase::AwaitingHello,
            incoming_swapcoins: Vec::new(),
            outgoing_swapcoins: Vec::new(),
            pending_funding_txes: Vec::new(),
            funding_broadcast: false,
            contract_feerate: 0.0,
            service_fee_sats: 0,
            reserve_utxo: Vec::new(),
            last_activity: Instant::now(),
            swap_start_time: Instant::now(),
            refund_locktime_offset: 0,
            funding_confirmation_height: None,
        }
    }
}

/// Maker Server configuration.
#[derive(Debug, Clone)]
pub struct MakerServerConfig {
    /// Data directory for the Maker.
    pub data_dir: PathBuf,
    /// Network port for incoming connections.
    pub network_port: u16,
    /// RPC port for maker-cli commands.
    pub rpc_port: u16,
    /// Base fee in satoshis per swap.
    pub base_fee: u64,
    /// Amount-relative fee percentage.
    pub amount_relative_fee_pct: f64,
    /// Time-relative fee percentage.
    pub time_relative_fee_pct: f64,
    /// Minimum swap amount in satoshis.
    pub min_swap_amount: u64,
    /// Required confirmations for funding transactions.
    pub required_confirms: u32,
    /// Supported protocol versions.
    pub supported_protocols: Vec<ProtocolVersion>,
    /// Fidelity bond amount in satoshis.
    pub fidelity_amount: u64,
    /// Fidelity bond timelock in blocks.
    pub fidelity_timelock: u32,
    /// Fee rate in sats/vB for the fidelity bond transaction.
    /// Defaults to `MIN_FEE_RATE`; may go lower, but never below
    /// `MIN_RELAY_FEE_RATE`.
    pub fidelity_feerate: f64,
    /// Bitcoin network.
    pub network: Network,
    /// Selected blockchain backend (Bitcoin Core or Electrum) and its settings.
    pub backend: BackendConfig,
    /// On-disk wallet name; Same as Bitcoin Core watch-only wallet name.
    pub wallet_name: String,
    /// Control port for Tor interface.
    pub control_port: u16,
    /// Socks port for Tor proxy.
    pub socks_port: u16,
    /// Authentication password for Tor interface.
    pub tor_auth_password: String,
    /// Wallet password (optional).
    pub password: Option<String>,
    /// Nostr relay URLs for fidelity bond broadcasting.
    pub nostr_relays: Vec<String>,
}

impl Default for MakerServerConfig {
    fn default() -> Self {
        MakerServerConfig {
            data_dir: PathBuf::from("./data"),
            network_port: 6102,
            rpc_port: 6103,
            base_fee: 500,
            amount_relative_fee_pct: 0.0025,
            time_relative_fee_pct: 0.0001,
            min_swap_amount: 10_000,
            required_confirms: 1,
            supported_protocols: vec![ProtocolVersion::Legacy, ProtocolVersion::Taproot],
            fidelity_amount: 10_000,   // 0.0001 BTC
            fidelity_timelock: 15_000, // ~6 months (MAX_FIDELITY_TIMELOCK)
            fidelity_feerate: MIN_FEE_RATE,
            network: Network::Regtest,
            backend: BackendConfig::CoreRpc(CoreRpcConfig::default()),
            // "maker" predates this branch; changing it would strand an upgrading
            // operator's wallet and fidelity bond.
            wallet_name: "maker".to_string(),
            control_port: 9051,
            socks_port: 9050,
            tor_auth_password: String::new(),
            password: None,
            nostr_relays: NOSTR_RELAYS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl MakerServerConfig {
    /// Load configuration from a TOML file at the given path.
    ///
    /// If `config_path` is `None`, defaults to `~/.openswap/maker/config.toml`.
    /// If the file doesn't exist or is empty, a default config file is created.
    /// Fields missing from the file fall back to defaults.
    pub fn new(config_path: Option<&Path>) -> Result<Self, WalletError> {
        let default_config_path = get_maker_dir()?.join("config.toml");
        let config_path = config_path.unwrap_or(&default_config_path);
        let default_config = Self::default();

        if !config_path.exists() || std::fs::metadata(config_path)?.len() == 0 {
            log::warn!(
                "Maker config file not found, creating default at: {}",
                config_path.display()
            );
            default_config.write_to_file(config_path)?;
        }

        let config_map = parse_toml(config_path)?;
        log::info!("Loaded config file from: {}", config_path.display());

        let fidelity_timelock = parse_field(
            config_map.get("fidelity_timelock"),
            default_config.fidelity_timelock,
        );
        if !(MIN_FIDELITY_TIMELOCK..=MAX_FIDELITY_TIMELOCK).contains(&fidelity_timelock) {
            log::warn!(
                "Invalid fidelity_timelock: {} blocks. Accepted range is [{}-{}] blocks.",
                fidelity_timelock,
                MIN_FIDELITY_TIMELOCK,
                MAX_FIDELITY_TIMELOCK
            );
            return Err(WalletError::Fidelity(FidelityError::InvalidBondLocktime));
        }

        let min_swap_amount = parse_field(
            config_map.get("min_swap_amount"),
            default_config.min_swap_amount,
        );
        if min_swap_amount < MIN_SWAP_AMOUNT {
            log::error!(
                "Configured min_swap_amount {} is below protocol minimum {} sats",
                min_swap_amount,
                MIN_SWAP_AMOUNT
            );
            return Err(WalletError::InsufficientFund {
                available: min_swap_amount,
                required: MIN_SWAP_AMOUNT,
            });
        }

        let fidelity_feerate = parse_field(
            config_map.get("fidelity_feerate"),
            default_config.fidelity_feerate,
        );
        // The default is MIN_FEE_RATE, but an operator may go lower on
        // purpose; the only hard floor is the relay minimum. Non-finite
        // values (TOML allows `nan`/`inf`) bypass a `<` comparison, so they
        // must be filtered out explicitly.
        let fidelity_feerate = if fidelity_feerate.is_finite()
            && fidelity_feerate >= MIN_RELAY_FEE_RATE
        {
            fidelity_feerate
        } else {
            log::warn!(
                "Invalid fidelity_feerate {}; must be finite and at least {} sats/vB; using the relay minimum",
                fidelity_feerate,
                MIN_RELAY_FEE_RATE
            );
            MIN_RELAY_FEE_RATE
        };

        Ok(MakerServerConfig {
            network_port: parse_field(config_map.get("network_port"), default_config.network_port),
            rpc_port: parse_field(config_map.get("rpc_port"), default_config.rpc_port),
            base_fee: parse_field(config_map.get("base_fee"), default_config.base_fee),
            amount_relative_fee_pct: parse_field(
                config_map.get("amount_relative_fee_pct"),
                default_config.amount_relative_fee_pct,
            ),
            time_relative_fee_pct: parse_field(
                config_map.get("time_relative_fee_pct"),
                default_config.time_relative_fee_pct,
            ),
            min_swap_amount,
            required_confirms: parse_field(
                config_map.get("required_confirms"),
                default_config.required_confirms,
            ),
            fidelity_amount: parse_field(
                config_map.get("fidelity_amount"),
                default_config.fidelity_amount,
            ),
            fidelity_timelock,
            fidelity_feerate,
            control_port: parse_field(config_map.get("control_port"), default_config.control_port),
            socks_port: parse_field(config_map.get("socks_port"), default_config.socks_port),
            tor_auth_password: parse_field(
                config_map.get("tor_auth_password"),
                default_config.tor_auth_password,
            ),
            // Runtime fields — not read from config file
            data_dir: default_config.data_dir,
            network: default_config.network,
            backend: default_config.backend,
            wallet_name: default_config.wallet_name,
            password: default_config.password,
            supported_protocols: default_config.supported_protocols,
            nostr_relays: default_config.nostr_relays,
        })
    }

    /// Set the blockchain backend (Bitcoin Core or Electrum).
    /// Mirrors `TakerInitConfig::with_backend`.
    pub fn with_backend(mut self, backend: BackendConfig) -> Self {
        self.backend = backend;
        self
    }

    /// Write the current configuration to a TOML file.
    pub fn write_to_file(&self, path: &Path) -> std::io::Result<()> {
        let toml_data = format!(
            "\
# Maker Configuration File

# Network port for client connections
network_port = {}
# RPC port for maker-cli operations
rpc_port = {}
# Socks port for Tor proxy
socks_port = {}
# Control port for Tor interface
control_port = {}
# Authentication password for Tor interface
tor_auth_password = {}
# Minimum amount in satoshis that can be swapped
min_swap_amount = {}
# Fidelity Bond amount in satoshis
fidelity_amount = {}
# Fidelity Bond timelock in blocks (must be between {} and {})
fidelity_timelock = {}
# Fee rate in sats/vB for the fidelity bond transaction (must be at least {})
fidelity_feerate = {}
# A fixed base fee charged by the Maker for providing its services (in satoshis)
base_fee = {}
# A percentage fee based on the swap amount
amount_relative_fee_pct = {}
# A percentage fee based on the swap duration
time_relative_fee_pct = {}
# Required confirmations for funding transactions
required_confirms = {}
",
            self.network_port,
            self.rpc_port,
            self.socks_port,
            self.control_port,
            self.tor_auth_password,
            self.min_swap_amount,
            self.fidelity_amount,
            MIN_FIDELITY_TIMELOCK,
            MAX_FIDELITY_TIMELOCK,
            self.fidelity_timelock,
            MIN_RELAY_FEE_RATE,
            self.fidelity_feerate,
            self.base_fee,
            self.amount_relative_fee_pct,
            self.time_relative_fee_pct,
            self.required_confirms,
        );

        std::fs::create_dir_all(path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "config path has no parent directory",
            )
        })?)?;
        let mut file = std::fs::File::create(path)?;
        file.write_all(toml_data.as_bytes())?;
        file.flush()?;
        Ok(())
    }
}

/// Thread pool for managing background threads.
///
/// A connection thread is tracked with a *weak* handle on its socket. Weak so the
/// pool cannot keep a finished connection's socket open, which would leave the
/// peer waiting for an end that never comes.
pub struct ThreadPool {
    threads: Mutex<Vec<PooledThread>>,
    port: u16,
}

/// A pooled thread, plus the socket it serves when it is a connection handler.
type PooledThread = (JoinHandle<()>, Option<Weak<TcpStream>>);

impl ThreadPool {
    /// Create a new thread pool.
    pub fn new(port: u16) -> Self {
        Self {
            threads: Mutex::new(Vec::new()),
            port,
        }
    }

    /// Add a thread to the pool.
    pub fn add_thread(&self, handle: JoinHandle<()>) -> Result<(), MakerError> {
        self.push(handle, None)
    }

    /// Add a connection thread, so shutdown can close the socket it reads from.
    pub fn add_connection(
        &self,
        handle: JoinHandle<()>,
        stream: &Arc<TcpStream>,
    ) -> Result<(), MakerError> {
        self.push(handle, Some(Arc::downgrade(stream)))
    }

    fn push(
        &self,
        handle: JoinHandle<()>,
        stream: Option<Weak<TcpStream>>,
    ) -> Result<(), MakerError> {
        let finished = {
            let mut threads = lock_debug!(self.threads.lock())
                .map_err(|_| MakerError::General("thread pool lock poisoned"))?;
            let (finished, mut running): (Vec<_>, Vec<_>) = std::mem::take(&mut *threads)
                .into_iter()
                .partition(|(handle, _)| handle.is_finished());
            running.push((handle, stream));
            *threads = running;
            finished
        };
        for (handle, _) in finished {
            self.join_thread(handle);
        }
        Ok(())
    }

    /// Join all threads in the pool.
    pub fn join_all_threads(&self) -> Result<(), MakerError> {
        loop {
            let mut threads = {
                let mut owned = lock_debug!(self.threads.lock())
                    .map_err(|_| MakerError::General("Failed to lock threads"))?;
                std::mem::take(&mut *owned)
            };
            if threads.is_empty() {
                log::info!(
                    "shutdown_join_complete pid={} component=maker_pool:{}",
                    std::process::id(),
                    self.port
                );
                return Ok(());
            }

            // Closing every socket first lets connection reads exit before joins begin.
            for (_, stream) in &threads {
                if let Some(stream) = stream.as_ref().and_then(Weak::upgrade) {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
            }

            while let Some((thread, _)) = threads.pop() {
                self.join_thread(thread);
            }
        }
    }

    /// Records a lifecycle pair so a missing completion identifies the stuck handle.
    fn join_thread(&self, handle: JoinHandle<()>) {
        let component = format!("maker_pool:{}", self.port);
        let thread = handle.thread().clone();
        crate::utill::log_shutdown_join_start(&component, &thread);
        let outcome = if handle.join().is_ok() { "ok" } else { "panic" };
        crate::utill::log_shutdown_join_done(&component, &thread, outcome);
    }
}

/// Latches the server stop request while allowing its backend abort arm to reset
/// after every owned thread has joined.
pub struct ShutdownSignal {
    requested: AtomicBool,
    backend: Arc<AtomicBool>,
}

impl ShutdownSignal {
    /// Keeps construction private so both flags always start in the same state.
    fn new() -> Self {
        Self {
            requested: AtomicBool::new(false),
            backend: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Reads the terminal latch, which backend rearming never clears.
    pub fn load(&self, ordering: Ordering) -> bool {
        self.requested.load(ordering)
    }

    /// Changes both flags so every stop source cancels active backend retries.
    pub fn store(&self, value: bool, ordering: Ordering) {
        self.requested.store(value, ordering);
        self.backend.store(value, ordering);
    }

    /// Shares backend cancellation without exposing the terminal server latch.
    fn backend_flag(&self) -> Arc<AtomicBool> {
        self.backend.clone()
    }

    /// Rearms wallet access only after all server-owned backend users have joined.
    pub(crate) fn reset_backend(&self) {
        self.backend.store(false, Ordering::Relaxed);
    }
}

impl std::ops::Deref for ShutdownSignal {
    type Target = AtomicBool;

    /// Lets observation-only APIs use the latch without seeing backend rearming.
    fn deref(&self) -> &Self::Target {
        &self.requested
    }
}

/// Maker server implementing the swap protocols and their background services.
pub struct MakerServer {
    /// Configuration.
    pub config: MakerServerConfig,
    /// Wallet.
    pub wallet: Arc<RwLock<Wallet>>,
    /// Shutdown flag.
    pub shutdown: ShutdownSignal,
    /// Is setup complete flag.
    pub is_setup_complete: AtomicBool,
    /// Highest fidelity proof.
    pub highest_fidelity_proof: RwLock<Option<FidelityProof>>,
    /// Ongoing swap states by swap_id.
    ongoing_swaps: Mutex<HashMap<String, SwapState>>,
    /// Watch service for contract monitoring.
    pub watch_service: WatchService,
    /// Thread pool for background threads.
    pub thread_pool: Arc<ThreadPool>,
    /// Data directory.
    pub data_dir: PathBuf,
    /// Persistent swap tracker for recovery progress.
    pub swap_tracker: Mutex<MakerSwapTracker>,
    /// Nostr relay URLs for fidelity bond broadcasting.
    pub nostr_relays: Vec<String>,
    /// Test-only behavior override.
    #[cfg(feature = "integration-test")]
    pub behavior: MakerBehavior,
}

/// Idle swap data returned by [`MakerServer::drain_idle_swaps`].
pub struct IdleSwapData {
    /// Unique swap identifier.
    pub swap_id: String,
    /// Protocol version used for this swap.
    pub protocol: crate::protocol::common_messages::ProtocolVersion,
    /// Swap amount in satoshis.
    pub swap_amount_sat: u64,
    /// Incoming swapcoins (maker receives).
    pub incoming_swapcoins: Vec<IncomingSwapCoin>,
    /// Outgoing swapcoins (maker sends).
    pub outgoing_swapcoins: Vec<OutgoingSwapCoin>,
    /// Whether the funding transaction was actually broadcast.
    pub funding_broadcast: bool,
}

impl MakerServer {
    /// Initialize a maker server. The backend (Bitcoin Core or Electrum) is
    /// resolved from `config` via [`MakerServerConfig::backend`].
    pub fn init(mut config: MakerServerConfig) -> Result<Self, MakerError> {
        std::fs::create_dir_all(&config.data_dir).map_err(MakerError::IO)?;
        // For the Core backend, bind the node-side wallet name to the on-disk
        // wallet name (no-op for Electrum, which has no server-side wallet).
        let wallet_name = config.wallet_name.clone();
        if let BackendConfig::CoreRpc(cfg) = &mut config.backend {
            cfg.wallet_name = wallet_name.clone();
        }
        let wallet_path = config.data_dir.join("wallets").join(&wallet_name);
        let shutdown = ShutdownSignal::new();
        let backend_shutdown = shutdown.backend_flag();
        let blockchain =
            AnyBlockchain::from_config_with_shutdown(&config.backend, backend_shutdown.clone())
                .map_err(MakerError::Wallet)?;
        // Misconfiguration (no txindex, dead ZMQ) must fail here, not mid-swap.
        if let AnyBlockchain::CoreRPC(core) = &blockchain {
            core.check_node_requirements().map_err(MakerError::Wallet)?;
        }
        // Take the passphrase out of the config: the wallet keeps the derived
        // key material, so the cleartext passphrase must not linger in the
        // long-lived server config.
        let mut wallet = Wallet::load_or_init(&wallet_path, blockchain, config.password.take())?;
        let data_dir = config.data_dir.clone();
        log::info!("Sync at:----MakerServer init----");
        wallet.sync_and_save(&shutdown)?;
        let wallet_network = wallet.store.network;
        if config.network != wallet_network {
            log::info!(
                "Maker config network ({:?}) differs from wallet network ({:?}); using wallet network",
                config.network,
                wallet_network
            );
            config.network = wallet_network;
        }

        // Initialize watch service. A failure here aborts init instead of
        // entering recovery-only: that mode polls the same backend that
        // just failed to build, so there is nothing to degrade to.
        let watch_service = crate::watch_tower::service::start_maker_watch_service(
            &config.backend,
            backend_shutdown,
        )
        .map_err(MakerError::Watcher)?;

        // The watcher starts empty, so re-arm every contract still live in the
        // wallet. Without this a restart leaves them undefended. A failed
        // rescan retries inside the watcher, so an Err here means the watcher
        // is gone and the server will start in recovery-only mode.
        let mut watches = wallet.incoming_contract_outpoints();
        watches.extend(wallet.outgoing_contract_outpoints());
        if let Err(e) = watch_service.rebuild_watches(watches) {
            log::error!("could not initialize watches on startup: {e}; recovery-only mode");
        }

        let swap_tracker = MakerSwapTracker::load_or_create(&data_dir)?;
        let incomplete = swap_tracker.incomplete_swaps();
        if !incomplete.is_empty() {
            log::info!(
                "[{}] Loaded {} incomplete swap records from previous run",
                config.network_port,
                incomplete.len()
            );
            swap_tracker.log_state();
        }

        let nostr_relays = config.nostr_relays.clone();
        Ok(MakerServer {
            config: config.clone(),
            wallet: Arc::new(RwLock::new(wallet)),
            shutdown,
            is_setup_complete: AtomicBool::new(false),
            highest_fidelity_proof: RwLock::new(None),
            ongoing_swaps: Mutex::new(HashMap::new()),
            watch_service,
            thread_pool: Arc::new(ThreadPool::new(config.network_port)),
            data_dir,
            swap_tracker: Mutex::new(swap_tracker),
            nostr_relays,
            #[cfg(feature = "integration-test")]
            behavior: MakerBehavior::default(),
        })
    }

    /// Check if shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Sleeps in short slices so long-lived Maker jobs observe shutdown promptly.
    pub(crate) fn wait_for_shutdown(&self, duration: Duration) -> bool {
        let mut remaining = duration;
        while !remaining.is_zero() {
            if self.is_shutdown() {
                return false;
            }
            let slice = remaining.min(Duration::from_secs(1));
            thread::sleep(slice);
            remaining -= slice;
        }
        !self.is_shutdown()
    }

    /// Waits for live but unconfirmed fidelity bonds to confirm and records
    /// their confirmation height. No-op if no such bond exists.
    ///
    /// A bond is registered with `conf_height: None` as soon as it is
    /// broadcast, so a maker that shut down while waiting for confirmation
    /// restarts with a pending bond in the wallet. Such a bond fails
    /// valuation (`calculate_bond_value` needs the confirmation height) and
    /// would be silently discarded by `get_highest_fidelity_index`, making
    /// the maker create a second bond and doubly lock funds. Finalizing it
    /// here prevents that.
    fn finalize_pending_fidelity_bonds(&self) -> Result<(), MakerError> {
        // Snapshot the pending bonds once: an unrecoverable bond stays
        // pending in the wallet, so re-finding inside the loop would spin
        // on it forever.
        let pending: Vec<(u32, bitcoin::Txid)> = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .store
            .fidelity_bond
            .iter()
            .filter(|b| !b.is_spent && b.conf_height.is_none())
            .map(|b| (b.bond_index, b.outpoint.txid))
            .collect();

        for (index, txid) in pending {
            log::info!(
                "[{}] Found unconfirmed fidelity bond {}, waiting for confirmation instead of creating a new one",
                self.config.network_port,
                txid
            );

            // An evicted bond tx would never confirm; rebroadcast the stored
            // raw transaction before waiting. Returns the original txid
            // unchanged if the broadcast is still live.
            let txid = match lock_debug!(self.wallet.read())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?
                .ensure_fidelity_bond_broadcast(index)
            {
                Ok(txid) => txid,
                // The bond was evicted and there is no stored transaction to
                // rebroadcast: it can never confirm. Losing the bond must not
                // take the maker down — log it and start up anyway.
                Err(WalletError::Fidelity(FidelityError::BondTransactionMissing { .. })) => {
                    log::error!(
                        "[{}] Pending fidelity bond {} was evicted and has no stored transaction; \
                         it is unrecoverable. Skipping it and continuing startup.",
                        self.config.network_port,
                        txid
                    );
                    continue;
                }
                Err(e) => return Err(MakerError::Wallet(e)),
            };

            // Wait on a fresh backend connection so the wallet lock is not
            // held for the duration of the wait.
            let chain = lock_debug!(self.wallet.read())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?
                .blockchain
                .new_connection()
                .map_err(MakerError::Wallet)?;
            let conf_height = match crate::wallet::wait_for_tx_confirmation(
                &chain,
                &[txid],
                1,
                crate::utill::TX_BROADCAST_TIMEOUT,
                Some(&self.shutdown),
                None,
            ) {
                Ok(height) => height,
                // The bond tx may never confirm (e.g. evicted again at a low
                // feerate). Losing it must not take the maker down: log it,
                // skip it, and let the next restart retry.
                Err(WalletError::TxConfirmationTimeout(msg)) => {
                    log::error!(
                        "[{}] Pending fidelity bond {} did not confirm ({}); \
                         skipping it and continuing startup.",
                        self.config.network_port,
                        txid,
                        msg
                    );
                    continue;
                }
                Err(e) => return Err(MakerError::Wallet(e)),
            };

            lock_debug!(self.wallet.write())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?
                .update_fidelity_bond_conf_details(index, conf_height)
                .map_err(MakerError::Wallet)?;

            log::info!(
                "[{}] Pending fidelity bond {} confirmed at height {}",
                self.config.network_port,
                txid,
                conf_height
            );
        }

        Ok(())
    }

    /// Setup fidelity bond for this maker.
    pub fn setup_fidelity_bond(&self, maker_address: &str) -> Result<FidelityProof, MakerError> {
        use bitcoin::absolute::LockTime;

        // Adopt any bond that was broadcast but not yet confirmed (e.g. the
        // maker shut down while waiting for confirmation) before deciding
        // whether a new bond is needed.
        self.finalize_pending_fidelity_bonds()?;

        let highest_index = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .get_highest_fidelity_index()
            .map_err(MakerError::Wallet)?;

        let mut proof = lock_debug!(self.highest_fidelity_proof.write())
            .map_err(|_| MakerError::General("Failed to lock fidelity proof"))?;

        if let Some(i) = highest_index {
            // Existing fidelity bond found
            let wallet_read = lock_debug!(self.wallet.read())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;
            let bond = wallet_read
                .store
                .fidelity_bond
                .get(i as usize)
                .ok_or(MakerError::General("fidelity bond index stale"))?
                .clone();
            let (current_height, tip_time) = wallet_read.chain_tip().map_err(MakerError::Wallet)?;
            let bond_value = wallet_read
                .calculate_bond_value(&bond, current_height, tip_time)
                .map_err(MakerError::Wallet)?
                .to_sat();
            drop(wallet_read);

            let highest_proof = lock_debug!(self.wallet.read())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?
                .generate_fidelity_proof(i, maker_address)
                .map_err(MakerError::Wallet)?;

            log::info!(
                "Highest bond at outpoint {} | index {} | Amount {:?} sats | Remaining Timelock: {:?} Blocks | Bond Value: {:?} sats",
                highest_proof.bond.outpoint,
                i,
                bond.amount.to_sat(),
                bond.lock_time
                    .to_consensus_u32()
                    .saturating_sub(current_height as u32),
                bond_value
            );

            *proof = Some(highest_proof);
        } else {
            // Need to create new fidelity bond
            log::info!("No active Fidelity Bonds found. Creating one.");

            let amount = Amount::from_sat(self.config.fidelity_amount);
            log::info!("Fidelity value chosen = {:?} sats", amount.to_sat());

            let current_height = lock_debug!(self.wallet.read())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?
                .blockchain
                .get_block_count()
                .map_err(MakerError::Wallet)?;
            let current_height = u32::try_from(current_height)
                .map_err(|_| MakerError::General("backend tip does not fit u32"))?;

            // Set locktime for test (950 blocks) or production
            #[cfg(feature = "integration-test")]
            let locktime = {
                use super::handlers::MakerBehavior;
                let offset = if self.behavior == MakerBehavior::InvalidFidelityTimelock {
                    log::warn!("Test behavior: using invalid (too short) fidelity timelock");
                    10
                } else {
                    950
                };
                let height = current_height
                    .checked_add(offset)
                    .ok_or(MakerError::General("fidelity locktime height overflows"))?;
                LockTime::from_height(height).map_err(WalletError::Locktime)?
            };
            #[cfg(not(feature = "integration-test"))]
            let locktime = {
                let height = self
                    .config
                    .fidelity_timelock
                    .checked_add(current_height)
                    .ok_or(MakerError::General("fidelity locktime height overflows"))?;
                LockTime::from_height(height).map_err(WalletError::Locktime)?
            };

            log::info!(
                "Fidelity timelock {:?} blocks",
                locktime.to_consensus_u32() - current_height
            );

            // Wait for funds and create fidelity bond
            let sleep_increment = 10;
            let mut sleep_multiplier = 0;

            while !self.shutdown.load(Ordering::Relaxed) {
                sleep_multiplier += 1;

                log::info!("Sync at:----setup_fidelity_bond----");
                lock_debug!(self.wallet.write())
                    .map_err(|_| MakerError::General("Failed to lock wallet"))?
                    .sync_and_save(&self.shutdown)
                    .map_err(MakerError::Wallet)?;

                let fidelity_result = lock_debug!(self.wallet.write())
                    .map_err(|_| MakerError::General("Failed to lock wallet"))?
                    .create_fidelity(
                        amount,
                        locktime,
                        Some(maker_address),
                        self.config.fidelity_feerate,
                        AddressType::P2TR,
                    );

                match fidelity_result {
                    Err(e) => {
                        if let WalletError::InsufficientFund {
                            available,
                            required,
                        } = e
                        {
                            log::warn!("Insufficient funds to create fidelity bond.");
                            let needed = required - available;
                            let addr = lock_debug!(self.wallet.write())
                                .map_err(|_| MakerError::General("Failed to lock wallet"))?
                                .get_next_external_address(AddressType::P2TR)
                                .map_err(MakerError::Wallet)?;

                            log::info!(
                                "Send at least {:.8} BTC to {:?}",
                                Amount::from_sat(needed).to_btc(),
                                addr
                            );

                            let total_sleep = sleep_increment * sleep_multiplier.min(60);
                            log::info!("Next sync in {total_sleep:?} secs");
                            if !self.wait_for_shutdown(Duration::from_secs(total_sleep)) {
                                return Err(MakerError::General("Shutdown requested"));
                            }
                        } else {
                            log::error!(
                                "[{}] Fidelity Bond Creation failed: {:?}",
                                self.config.network_port,
                                e
                            );
                            return Err(MakerError::Wallet(e));
                        }
                    }
                    Ok((index, txid)) => {
                        // Wait for confirmation without holding the write lock.
                        log::info!(
                            "[{}] Fidelity bond broadcast, waiting for confirmation: {}",
                            self.config.network_port,
                            txid
                        );
                        let conf_height = lock_debug!(self.wallet.read())
                            .map_err(|_| MakerError::General("Failed to lock wallet"))?
                            .wait_for_tx_confirmation(&[txid], 1, Some(&self.shutdown), None)
                            .map_err(MakerError::Wallet)?;

                        // Re-acquire write lock briefly to finalize
                        lock_debug!(self.wallet.write())
                            .map_err(|_| MakerError::General("Failed to lock wallet"))?
                            .update_fidelity_bond_conf_details(index, conf_height)
                            .map_err(MakerError::Wallet)?;

                        log::info!(
                            "[{}] Successfully created fidelity bond",
                            self.config.network_port
                        );
                        let highest_proof = lock_debug!(self.wallet.read())
                            .map_err(|_| MakerError::General("Failed to lock wallet"))?
                            .generate_fidelity_proof(index, maker_address)
                            .map_err(MakerError::Wallet)?;

                        *proof = Some(highest_proof);

                        log::info!("Sync at end:----setup_fidelity_bond----");
                        lock_debug!(self.wallet.write())
                            .map_err(|_| MakerError::General("Failed to lock wallet"))?
                            .sync_and_save(&self.shutdown)
                            .map_err(MakerError::Wallet)?;
                        break;
                    }
                }
            }
        }

        proof
            .clone()
            .ok_or(MakerError::General("No fidelity proof after setup"))
    }

    /// Check if maker has enough liquidity for swaps.
    pub fn check_swap_liquidity(&self) -> Result<(), MakerError> {
        let sleep_increment = 10u64;
        let mut sleep_duration = 0u64;

        let addr = lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .get_next_external_address(AddressType::P2TR)
            .map_err(MakerError::Wallet)?;

        while !self.shutdown.load(Ordering::Relaxed) {
            log::info!("Sync at:----check_swap_liquidity----");
            lock_debug!(self.wallet.write())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?
                .sync_and_save(&self.shutdown)
                .map_err(MakerError::Wallet)?;

            let offer_max_size = lock_debug!(self.wallet.read())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?
                .store
                .offer_maxsize;

            let min_required = self.config.min_swap_amount;

            if offer_max_size < min_required {
                log::warn!(
                    "Low Swap Liquidity | Min: {min_required} sats | Available: {offer_max_size} sats. Add funds to {addr:?}"
                );

                sleep_duration = (sleep_duration + sleep_increment).min(600);
                log::info!("Next sync in {sleep_duration:?} secs");
                if !self.wait_for_shutdown(Duration::from_secs(sleep_duration)) {
                    break;
                }
            } else {
                log::info!(
                    "Swap Liquidity: {offer_max_size} sats | Min: {min_required} sats | Listening for requests."
                );
                break;
            }
        }

        Ok(())
    }

    /// Atomically release stale unfunded reservations and drain swaps requiring recovery.
    /// Returns swap data only for entries with on-chain recovery material.
    pub fn drain_idle_swaps(&self, timeout: Duration) -> Result<Vec<IdleSwapData>, MakerError> {
        // Read before the lock: a chain round trip while holding `ongoing_swaps`
        // would stall every handler. A failure here must not kill the recovery
        // thread, so this cycle falls back to the idle timeout alone.
        let current_height = match self.get_current_height() {
            Ok(height) => Some(height),
            Err(e) => {
                log::warn!(
                    "[{}] Could not read height for refund deadlines: {:?}",
                    self.config.network_port,
                    e
                );
                None
            }
        };

        let mut swaps =
            lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
        let mut idle = Vec::new();

        // An accepted swap with no funding material only reserves liquidity;
        // there is nothing on-chain to recover, so it is dropped without recovery.
        let released_ids: Vec<String> = swaps
            .iter()
            .filter(|(_, state)| {
                state.phase == SwapPhase::AwaitingContractData
                    && state.incoming_swapcoins.is_empty()
                    && state.outgoing_swapcoins.is_empty()
                    && state.pending_funding_txes.is_empty()
                    && !state.funding_broadcast
                    && state.last_activity.elapsed() > timeout
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in released_ids {
            swaps.remove(&id);
            log::info!(
                "[{}] Released idle unfunded reservation for swap {}",
                self.config.network_port,
                id
            );
        }

        // Carries why each swap was drained: an operator reading "dropped connection"
        // for a taker that never dropped would go looking for the wrong fault.
        let stale_ids: Vec<(String, bool)> = swaps
            .iter()
            .filter_map(|(id, state)| {
                if state.outgoing_swapcoins.is_empty() {
                    return None;
                }
                let past_deadline = current_height.is_some_and(|height| {
                    past_refund_deadline(
                        state.protocol,
                        state.timelock,
                        state.funding_confirmation_height,
                        height,
                    )
                });
                (past_deadline || state.last_activity.elapsed() > timeout)
                    .then(|| (id.clone(), past_deadline))
            })
            .collect();

        for (id, past_deadline) in stale_ids {
            if past_deadline {
                log::warn!(
                    "[{}] Swap {} reached its refund deadline; recovering now",
                    self.config.network_port,
                    id
                );
            }
            if let Some(state) = swaps.remove(&id) {
                idle.push(IdleSwapData {
                    swap_id: id,
                    protocol: state.protocol,
                    swap_amount_sat: state.swap_amount.to_sat(),
                    incoming_swapcoins: state.incoming_swapcoins,
                    outgoing_swapcoins: state.outgoing_swapcoins,
                    funding_broadcast: state.funding_broadcast,
                });
            }
        }

        Ok(idle)
    }

    /// Remove a completed swap's entry from `ongoing_swaps`.
    pub fn remove_swap_state(&self, swap_id: &str) -> Result<(), MakerError> {
        let mut swaps =
            lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
        swaps.remove(swap_id);
        Ok(())
    }

    /// Check if any swaps are currently in progress.
    pub fn has_ongoing_swaps(&self) -> Result<bool, MakerError> {
        Ok(!lock_debug!(self.ongoing_swaps.lock())
            .map_err(|_| MakerError::MutexPossion)?
            .is_empty())
    }

    /// Whether this maker has an unfinished outgoing swapcoin for `swap_id`.
    #[cfg(feature = "integration-test")]
    pub fn has_unfinished_outgoing_swapcoin(&self, swap_id: &str) -> Result<bool, MakerError> {
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        let (_, outgoing) = wallet.find_unfinished_swapcoins();
        Ok(outgoing
            .iter()
            .any(|coin| coin.swap_id.as_deref() == Some(swap_id)))
    }

    /// Verify the deniability proof for a specific swap.
    pub fn verify_deniability(&self, swap_id: &str) -> Result<bool, std::io::Error> {
        lock_debug!(self.wallet.read())
            .map_err(|e| std::io::Error::other(format!("wallet lock poisoned: {e}")))?
            .verify_deniability(swap_id)
    }
}

impl MakerTrait for MakerServer {
    fn network_port(&self) -> u16 {
        self.config.network_port
    }

    fn get_tweakable_keypair(
        &self,
    ) -> Result<(bitcoin::secp256k1::SecretKey, PublicKey, ChainCode), MakerError> {
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        wallet.get_tweakable_keypair().map_err(MakerError::Wallet)
    }

    fn get_fidelity_proof(&self) -> Result<FidelityProof, MakerError> {
        let proof = lock_debug!(self.highest_fidelity_proof.read())
            .map_err(|_| MakerError::General("Failed to lock fidelity proof"))?;
        proof
            .clone()
            .ok_or(MakerError::General("No fidelity proof available"))
    }

    fn get_config(&self) -> MakerConfig {
        MakerConfig {
            base_fee: self.config.base_fee,
            amount_relative_fee_pct: self.config.amount_relative_fee_pct,
            time_relative_fee_pct: self.config.time_relative_fee_pct,
            min_swap_amount: self.config.min_swap_amount,
            max_swap_amount: lock_debug!(self.wallet.read())
                .map(|w| w.store.offer_maxsize)
                .unwrap_or(u64::MAX),
            required_confirms: self.config.required_confirms,
            supported_protocols: self.config.supported_protocols.clone(),
        }
    }

    fn validate_swap_parameters(&self, details: &SwapDetails) -> Result<u16, MakerError> {
        use super::handlers::{offset_meets_reaction_time, MIN_CONTRACT_REACTION_TIME};

        let config = self.get_config();

        if details.max_tx_count() == 0 {
            return Err(MakerError::General("Transaction count must be non-zero"));
        }
        if details.max_utxos_per_tx() == 0 {
            return Err(MakerError::General(
                "UTXO count per transaction must be non-zero",
            ));
        }

        // Check amount is within bounds
        let amount_sat = details.amount.to_sat();
        if amount_sat < config.min_swap_amount {
            return Err(MakerError::General("Swap amount below minimum"));
        }
        if amount_sat > config.max_swap_amount {
            return Err(MakerError::General("Swap amount above maximum"));
        }

        // Check protocol is supported
        if !self
            .config
            .supported_protocols
            .contains(&details.protocol_version)
        {
            return Err(MakerError::General("Protocol version not supported"));
        }

        // Check maker has enough liquidity to fund the outgoing swap
        if let Ok(wallet) = lock_debug!(self.wallet.read()) {
            if let Ok(balances) = wallet.get_balances() {
                let swap_liquidity = balances.regular + balances.swap;
                if swap_liquidity < details.amount {
                    return Err(MakerError::General(
                        "Not enough liquidity for this swap amount",
                    ));
                }
            }
        }

        // Check timelock bounds and work out how long the funds stay locked.
        let locked_blocks = if details.protocol_version == ProtocolVersion::Legacy {
            if details.timelock < MIN_CONTRACT_REACTION_TIME as u32 {
                log::warn!(
                    "Legacy timelock {} is below minimum reaction time {}",
                    details.timelock,
                    MIN_CONTRACT_REACTION_TIME
                );
                return Err(MakerError::General(
                    "Legacy timelock is below minimum reaction time",
                ));
            }
            details.timelock
        } else {
            let current_height = self.get_current_height()?;
            if details.timelock.saturating_add(REFUND_LOCKTIME_STEP as u32)
                < current_height.saturating_add(MIN_CONTRACT_REACTION_TIME as u32)
            {
                log::error!(
                    "Taproot timelock {} leaves less than {} blocks of reaction time at height {}",
                    details.timelock,
                    MIN_CONTRACT_REACTION_TIME,
                    current_height
                );
                return Err(MakerError::General(
                    "Taproot timelock leaves too little contract reaction time",
                ));
            }
            if !offset_meets_reaction_time(details.refund_locktime_offset) {
                log::error!(
                    "Taproot refund locktime offset {} is below minimum reaction time {}",
                    details.refund_locktime_offset,
                    MIN_CONTRACT_REACTION_TIME
                );
                return Err(MakerError::General(
                    "Taproot refund locktime offset is below minimum reaction time",
                ));
            }
            // Price off the offset, not `timelock - current_height`: our own tip moves
            // while we negotiate, which would price the same swap differently each run.
            // The offset is not bound to the real lock duration; assess the CSV transition later.
            details.refund_locktime_offset as u32
        };

        if locked_blocks == 0 || locked_blocks > u16::MAX as u32 {
            return Err(MakerError::General("Swap timelock out of range"));
        }

        Ok(locked_blocks as u16)
    }

    fn calculate_swap_fee(&self, amount: Amount, timelock: u32) -> Amount {
        let total_fee = self.config.base_fee as f64
            + (amount.to_sat() as f64 * self.config.amount_relative_fee_pct) / 100.00
            + (amount.to_sat() as f64 * timelock as f64 * self.config.time_relative_fee_pct)
                / 100.00;
        Amount::from_sat(total_fee.ceil() as u64)
    }

    fn network(&self) -> Network {
        self.config.network
    }

    fn is_watchtower_alive(&self) -> bool {
        self.watch_service.is_alive()
    }

    fn create_funding_transaction(
        &self,
        amount: Amount,
        address: bitcoin::Address,
        excluded_outpoints: Option<Vec<OutPoint>>,
        max_inputs_per_tx: usize,
    ) -> Result<(Transaction, u32), MakerError> {
        let mut wallet = lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;

        let result = wallet
            .create_funding_txes(
                amount,
                &[address],
                crate::utill::MIN_FEE_RATE,
                None,
                excluded_outpoints,
                Some(max_inputs_per_tx),
            )
            .map_err(MakerError::Wallet)?;

        // Return the first (and only) funding tx and its output position
        let tx = result
            .funding_txes
            .into_iter()
            .next()
            .ok_or(MakerError::General("No funding tx created"))?;
        let output_position = result
            .payment_output_positions
            .first()
            .copied()
            .unwrap_or(0);

        Ok((tx, output_position))
    }

    fn get_current_height(&self) -> Result<u32, MakerError> {
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        wallet
            .blockchain
            .get_block_count()
            .map(|h| h as u32)
            .map_err(MakerError::Wallet)
    }

    /// Waits on a fresh backend connection so no wallet lock is held for the
    /// wait's duration; the shared wait bounds arrival and confirmation.
    fn wait_for_tx_on_chain(
        &self,
        txid: &bitcoin::Txid,
        required_confirms: u32,
    ) -> Result<(), MakerError> {
        let required_confirms = required_confirms.max(crate::utill::MIN_REQUIRED_CONFIRM);

        log::info!(
            "[{}] Waiting for {} confirmation(s) on tx {}",
            self.config.network_port,
            required_confirms,
            txid
        );
        let chain = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .blockchain
            .new_connection()
            .map_err(MakerError::Wallet)?;
        crate::wallet::wait_for_tx_confirmation(
            &chain,
            &[*txid],
            required_confirms,
            crate::utill::TX_BROADCAST_TIMEOUT,
            Some(&self.shutdown),
            None,
        )
        .map_err(MakerError::Wallet)?;
        Ok(())
    }

    fn broadcast_transaction(&self, tx: &Transaction) -> Result<bitcoin::Txid, MakerError> {
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;

        wallet.send_tx(tx).map_err(MakerError::Wallet)
    }

    fn is_transaction_known(&self, txid: &bitcoin::Txid) -> bool {
        lock_debug!(self.wallet.read())
            .map(|wallet| wallet.blockchain.get_raw_transaction(txid, None).is_ok())
            .unwrap_or(false)
    }

    fn save_incoming_swapcoin(
        &self,
        swapcoin: &crate::wallet::swapcoin::IncomingSwapCoin,
    ) -> Result<(), MakerError> {
        let mut wallet = lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        wallet.add_incoming_swapcoin(swapcoin);
        wallet.save_to_disk().map_err(MakerError::Wallet)
    }

    fn save_outgoing_swapcoin(
        &self,
        swapcoin: &crate::wallet::swapcoin::OutgoingSwapCoin,
    ) -> Result<(), MakerError> {
        let mut wallet = lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        wallet.add_outgoing_swapcoin(swapcoin);
        wallet.save_to_disk().map_err(MakerError::Wallet)
    }

    fn register_watch_outpoint(
        &self,
        outpoint: OutPoint,
        script_pubkey: bitcoin::ScriptBuf,
    ) -> Result<(), MakerError> {
        self.watch_service
            .register_watch_request(outpoint, script_pubkey)
            .map_err(|e| {
                log::error!("watch registration for {outpoint} failed (watcher gone): {e}");
                MakerError::General("watchtower registration failed, aborting swap")
            })
    }

    fn unwatch_outpoint(&self, outpoint: OutPoint, script_pubkey: bitcoin::ScriptBuf) {
        if let Err(e) = self.watch_service.unwatch(outpoint, script_pubkey) {
            log::error!("unwatch for {outpoint} failed (watcher gone): {e}");
        }
    }

    fn sync_and_save_wallet(&self) -> Result<(), MakerError> {
        lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .sync_and_save(&self.shutdown)
            .map_err(MakerError::Wallet)
    }

    fn sweep_incoming_swapcoins(&self) -> Result<(), MakerError> {
        log::info!(
            "[{}] Sweeping coins after successful swap",
            self.config.network_port
        );

        // Sweep all completed incoming swapcoins. The sweep takes the lock itself and
        // drops it across its waits, so a stuck tx cannot wedge the wallet.
        let chain = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .blockchain
            .new_connection()
            .map_err(MakerError::Wallet)?;
        let sweep_outcome =
            Wallet::sweep_incoming_swapcoins(&self.wallet, &chain, MIN_FEE_RATE, &self.shutdown)
                .map_err(MakerError::Wallet)?;

        if !sweep_outcome.is_empty() {
            log::info!(
                "[{}] Successfully swept {} incoming swap coins",
                self.config.network_port,
                sweep_outcome.resolved.len(),
            );
        }

        // Sync and save wallet state
        log::info!(
            "[{}] Sync at:----sweep_incoming_swapcoins----",
            self.config.network_port
        );
        lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .sync_and_save(&self.shutdown)
            .map_err(MakerError::Wallet)?;

        Ok(())
    }

    fn store_connection_state(
        &self,
        swap_id: &str,
        state: &ConnectionState,
        admission: bool,
    ) -> Result<(), MakerError> {
        // Fetch the balance before taking the swaps lock: reading the wallet
        // under it would stall every handler thread behind a mid-sync writer.
        let swap_liquidity = if admission {
            let balances = lock_debug!(self.wallet.read())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?
                .get_balances()
                .map_err(MakerError::Wallet)?;
            Some(balances.regular + balances.swap)
        } else {
            None
        };

        let mut swaps = lock_debug!(self.ongoing_swaps.lock())?;
        let is_new = !swaps.contains_key(swap_id);
        if let Some(swap_liquidity) = swap_liquidity.filter(|_| is_new) {
            let active_swaps = swaps
                .values()
                .filter(|state| state.phase != SwapPhase::Completed)
                .count();
            if active_swaps >= MAX_CONCURRENT_SWAPS {
                log::warn!(
                    "[{}] Rejecting swap {}: {} active swaps at the {} cap",
                    self.config.network_port,
                    swap_id,
                    active_swaps,
                    MAX_CONCURRENT_SWAPS
                );
                return Err(MakerError::TooManySwaps);
            }

            let reserved_liquidity = swaps
                .values()
                .filter(|state| state.phase != SwapPhase::Completed)
                .fold(Amount::ZERO, |total, state| total + state.swap_amount);
            let required_liquidity = reserved_liquidity + state.swap_amount;

            if swap_liquidity < required_liquidity {
                log::warn!(
                    "[{}] Rejecting swap {}: available liquidity {}, active reservations {}, requested {}",
                    self.config.network_port,
                    swap_id,
                    swap_liquidity,
                    reserved_liquidity,
                    state.swap_amount,
                );
                return Err(MakerError::InsufficientLiquidity {
                    available: swap_liquidity,
                    reserved: reserved_liquidity,
                    requested: state.swap_amount,
                });
            }
        }

        // A resent SwapDetails for a live swap is a reconnect after a dropped
        // connection: identical parameters just refresh the idle timer, while
        // different ones must never overwrite the stored swap.
        if admission && !is_new {
            let swap_state = swaps
                .get_mut(swap_id)
                .expect("entry exists under this lock when !is_new");
            if swap_state.swap_amount != state.swap_amount
                || swap_state.tx_count != state.tx_count
                || swap_state.timelock != state.timelock
                || swap_state.protocol != state.protocol
                || swap_state.refund_locktime_offset != state.refund_locktime_offset
            {
                log::warn!(
                    "[{}] Rejecting duplicate SwapDetails for {}: parameters differ from stored swap",
                    self.config.network_port,
                    swap_id,
                );
                return Err(MakerError::SwapParamMismatch);
            }
            swap_state.last_activity = Instant::now();
            return Ok(());
        }

        let swap_state = swaps.entry(swap_id.to_string()).or_default();
        #[cfg(debug_assertions)]
        if swap_state.phase != state.phase
            || swap_state.funding_broadcast != state.funding_broadcast
            || swap_state.incoming_swapcoins.len() != state.incoming_swapcoins.len()
            || swap_state.outgoing_swapcoins.len() != state.outgoing_swapcoins.len()
            || swap_state.reserve_utxo.len() != state.reserve_utxo.len()
        {
            log::debug!(
                "[SWAP_STATE] Source: maker::api::store_connection_state | Role: Maker | SwapID: {} | Phase: {:?} | FundingBroadcast: {} | Incoming: {} | Outgoing: {} | ReservedUtxos: {}",
                swap_id,
                state.phase,
                state.funding_broadcast,
                state.incoming_swapcoins.len(),
                state.outgoing_swapcoins.len(),
                state.reserve_utxo.len()
            );
        }
        swap_state.swap_amount = state.swap_amount;
        swap_state.tx_count = state.tx_count;
        swap_state.timelock = state.timelock;
        swap_state.protocol = state.protocol;
        swap_state.phase = state.phase;
        swap_state.incoming_swapcoins = state.incoming_swapcoins.clone();
        swap_state.outgoing_swapcoins = state.outgoing_swapcoins.clone();
        swap_state.pending_funding_txes = state.pending_funding_txes.clone();
        swap_state.funding_broadcast = state.funding_broadcast;
        swap_state.contract_feerate = state.contract_feerate;
        swap_state.service_fee_sats = state.service_fee_sats;
        swap_state.reserve_utxo = state.reserve_utxo.clone();
        swap_state.last_activity = Instant::now();
        swap_state.swap_start_time = state.swap_start_time;
        swap_state.refund_locktime_offset = state.refund_locktime_offset;
        log::debug!(
            "[{}] Stored connection state for {}: amount={}, timelock={}, protocol={:?}, outgoing_count={}",
            self.config.network_port,
            swap_id,
            state.swap_amount,
            state.timelock,
            state.protocol,
            state.outgoing_swapcoins.len()
        );

        Ok(())
    }

    fn get_connection_state(&self, swap_id: &str) -> Result<Option<ConnectionState>, MakerError> {
        let swaps = lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
        Ok(swaps.get(swap_id).map(|s| {
            let mut state = ConnectionState::new(s.protocol);
            state.swap_id = Some(swap_id.to_string());
            state.swap_amount = s.swap_amount;
            state.tx_count = s.tx_count;
            state.timelock = s.timelock;
            state.phase = s.phase;
            state.incoming_swapcoins = s.incoming_swapcoins.clone();
            state.outgoing_swapcoins = s.outgoing_swapcoins.clone();
            state.pending_funding_txes = s.pending_funding_txes.clone();
            state.funding_broadcast = s.funding_broadcast;
            state.contract_feerate = s.contract_feerate;
            state.service_fee_sats = s.service_fee_sats;
            state.reserve_utxo = s.reserve_utxo.clone();
            state.swap_start_time = s.swap_start_time;
            state.refund_locktime_offset = s.refund_locktime_offset;
            state.last_activity = s.last_activity;
            state
        }))
    }

    fn remove_connection_state(&self, swap_id: &str) -> Result<(), MakerError> {
        self.remove_swap_state(swap_id)
    }

    fn swap_past_refund_deadline(&self, swap_id: &str) -> Result<bool, MakerError> {
        let current_height = self.get_current_height()?;
        let swaps = lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
        Ok(swaps.get(swap_id).is_some_and(|state| {
            past_refund_deadline(
                state.protocol,
                state.timelock,
                state.funding_confirmation_height,
                current_height,
            )
        }))
    }

    fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    fn wallet_name(&self) -> &str {
        &self.config.wallet_name
    }

    fn collect_excluded_utxos(&self, current_swap_id: &str) -> Result<Vec<OutPoint>, MakerError> {
        let swaps = lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
        Ok(swaps
            .iter()
            .filter(|(id, _)| id.as_str() != current_swap_id)
            .flat_map(|(_, state)| state.reserve_utxo.clone())
            .collect())
    }

    fn verify_and_sign_sender_contract_txs(
        &self,
        txs_info: &[crate::protocol::legacy_messages::ContractTxInfoForSender],
        hashvalue: &crate::protocol::Hash160,
        locktime: u16,
    ) -> Result<Vec<bitcoin::ecdsa::Signature>, MakerError> {
        log::info!(
            "[{}] Verifying and signing {} sender contract txs",
            self.config.network_port,
            txs_info.len()
        );

        // Full verification: multisig format, pubkeys, structure, P2WSH output
        let (tweakable_privkey, tweakable_pubkey, _) = self.get_tweakable_keypair()?;
        super::legacy_verification::verify_req_contract_sigs_for_sender(
            txs_info,
            &tweakable_pubkey,
            hashvalue,
            locktime,
            self.config.network_port,
        )?;

        let bindings = txs_info
            .iter()
            .map(|txinfo| {
                (
                    txinfo.senders_contract_tx.input[0].previous_output,
                    txinfo.senders_contract_tx.output[0].script_pubkey.clone(),
                )
            })
            .collect::<Vec<_>>();
        lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .cache_prevout_to_contract(&bindings)?;

        let mut sigs = Vec::new();
        for txinfo in txs_info {
            // Derive multisig privkey using the nonce
            let multisig_privkey = tweakable_privkey
                .add_tweak(&txinfo.multisig_nonce.into())
                .map_err(|_| MakerError::General("Failed to derive multisig privkey"))?;

            // Sign the contract transaction
            let sig = crate::protocol::contract::sign_contract_tx(
                &txinfo.senders_contract_tx,
                &txinfo.multisig_redeemscript,
                txinfo.funding_input_value,
                &multisig_privkey,
            )
            .map_err(|e| {
                log::error!("Failed to sign contract tx: {:?}", e);
                MakerError::General("Failed to sign contract transaction")
            })?;

            log::debug!("[{}] Signed sender contract tx", self.config.network_port);
            sigs.push(sig);
        }

        log::info!(
            "[{}] Generated {} signatures for sender contracts",
            self.config.network_port,
            sigs.len()
        );
        Ok(sigs)
    }

    fn verify_proof_of_funding(
        &self,
        message: &crate::protocol::legacy_messages::ProofOfFunding,
    ) -> Result<crate::protocol::Hash160, MakerError> {
        use super::handlers::MIN_CONTRACT_REACTION_TIME;
        use crate::{
            protocol::contract::{
                check_hashlock_has_pubkey, check_multisig_has_pubkey,
                check_reedemscript_is_multisig, read_contract_locktime,
                read_hashvalue_from_contract,
            },
            utill::{redeemscript_to_scriptpubkey, MIN_REQUIRED_CONFIRM},
        };
        use bitcoin::{hashes::Hash, OutPoint};
        use std::collections::HashSet;

        log::info!(
            "[{}] Verifying proof of funding for swap {}",
            self.config.network_port,
            message.id
        );

        if message.confirmed_funding_txes.is_empty() {
            return Err(MakerError::General("No funding txs provided by Taker"));
        }

        let min_reaction_time = MIN_CONTRACT_REACTION_TIME;
        let mut hashvalue: Option<crate::protocol::Hash160> = None;
        // Each proof can be valid on its own, but repeating one outpoint makes the
        // maker count the same incoming value twice and fund excess outgoing value.
        let mut seen_outpoints = HashSet::with_capacity(message.confirmed_funding_txes.len());
        let mut funding_confirmed_at: Option<u32> = None;

        for funding_info in &message.confirmed_funding_txes {
            // Check that the new locktime is sufficiently short enough
            let locktime = read_contract_locktime(&funding_info.contract_redeemscript)?;
            // Use saturating_sub to avoid overflow
            let locktime_diff = locktime.saturating_sub(message.refund_locktime);
            if locktime_diff < min_reaction_time {
                return Err(MakerError::General(
                    "Next hop locktime too close to current hop locktime",
                ));
            }

            // Find the funding output index
            let multisig_spk = redeemscript_to_scriptpubkey(&funding_info.multisig_redeemscript)?;
            let funding_output_index = funding_info
                .funding_tx
                .output
                .iter()
                .position(|o| o.script_pubkey == multisig_spk)
                .ok_or(MakerError::General("Funding output not found"))?
                as u32;

            let funding_txid = funding_info.funding_tx.compute_txid();
            let funding_outpoint = OutPoint {
                txid: funding_txid,
                vout: funding_output_index,
            };
            if !seen_outpoints.insert(funding_outpoint) {
                return Err(MakerError::General("Duplicate funding outpoint"));
            }

            // Check the funding_tx is confirmed to required depth
            // Same source as the taproot path: the operator's config, not a hardcoded 1.
            self.wait_for_tx_on_chain(
                &funding_txid,
                self.config.required_confirms.max(MIN_REQUIRED_CONFIRM),
            )?;

            let wallet_read = lock_debug!(self.wallet.read())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;

            // A confirmed txid says nothing about its outputs. Without this the taker
            // can prove funding with an outpoint it has already spent, and the maker
            // funds the next hop against value it can never claim. Mempool spends
            // count: a spend we can already see will confirm before our next hop.
            if wallet_read
                .blockchain
                .get_tx_out(&funding_txid, funding_output_index, None)
                .map_err(MakerError::Wallet)?
                .is_none()
            {
                return Err(MakerError::General("Funding output already spent"));
            }

            // Earliest confirmation binds: that contract's refund window opens first.
            if let Some(height) = wallet_read
                .blockchain
                .tx_block_height(&funding_txid)
                .map_err(MakerError::Wallet)?
            {
                let height = height as u32;
                funding_confirmed_at = Some(match funding_confirmed_at {
                    Some(earliest) => earliest.min(height),
                    None => height,
                });
            }

            check_reedemscript_is_multisig(&funding_info.multisig_redeemscript)?;

            let (_, tweakable_pubkey, _) = wallet_read.get_tweakable_keypair()?;

            check_multisig_has_pubkey(
                &funding_info.multisig_redeemscript,
                &tweakable_pubkey,
                &funding_info.multisig_nonce,
            )?;

            check_hashlock_has_pubkey(
                &funding_info.contract_redeemscript,
                &tweakable_pubkey,
                &funding_info.hashlock_nonce,
            )?;

            // Check that the provided contract matches the scriptpubkey from the cache
            let contract_spk = redeemscript_to_scriptpubkey(&funding_info.contract_redeemscript)?;

            wallet_read.ensure_prevout_matches_cached_contract(&funding_outpoint, &contract_spk)?;

            // Extract and verify hashvalue
            let this_hashvalue = read_hashvalue_from_contract(&funding_info.contract_redeemscript)?;
            if let Some(ref prev_hashvalue) = hashvalue {
                if *prev_hashvalue != this_hashvalue {
                    return Err(MakerError::General("Hash values in contracts do not match"));
                }
            } else {
                hashvalue = Some(this_hashvalue);
            }
        }

        // Legacy's refund deadline is counted from this height and nothing later can
        // recover it, so record it while the proof is still in hand.
        if let Some(height) = funding_confirmed_at {
            if let Some(state) = lock_debug!(self.ongoing_swaps.lock())
                .map_err(|_| MakerError::MutexPossion)?
                .get_mut(&message.id)
            {
                state.funding_confirmation_height = Some(height);
            }
        }

        let hashvalue = hashvalue.ok_or(MakerError::General("No hashvalue found in contracts"))?;
        log::info!(
            "[{}] Proof of funding verified successfully, hashvalue={:?}",
            self.config.network_port,
            hashvalue.to_byte_array()
        );
        Ok(hashvalue)
    }

    fn initialize_openswap(
        &self,
        send_amount: Amount,
        next_multisig_pubkeys: &[PublicKey],
        next_hashlock_pubkeys: &[PublicKey],
        hashvalue: crate::protocol::Hash160,
        locktime: u16,
        contract_feerate: f64,
        excluded_outpoints: Option<Vec<OutPoint>>,
        max_inputs_per_tx: usize,
    ) -> Result<(Vec<Transaction>, Vec<OutgoingSwapCoin>, Amount), MakerError> {
        log::info!(
            "[{}] Initializing openswap: amount={} sats, {} pubkeys",
            self.config.network_port,
            send_amount.to_sat(),
            next_multisig_pubkeys.len()
        );

        let mut wallet = lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;

        let (openswap_addresses, my_multisig_privkeys): (Vec<_>, Vec<_>) = next_multisig_pubkeys
            .iter()
            .map(|other_key| wallet.create_and_import_swap_address(other_key))
            .collect::<Result<Vec<_>, _>>()
            .map_err(MakerError::Wallet)?
            .into_iter()
            .unzip();

        let create_funding_txes_result = wallet
            .create_funding_txes(
                send_amount,
                &openswap_addresses,
                contract_feerate,
                None,
                excluded_outpoints,
                Some(max_inputs_per_tx),
            )
            .map_err(MakerError::Wallet)?;

        let mut outgoing_swapcoins = Vec::new();
        for (
            (((my_funding_tx, &utxo_index), &my_multisig_privkey), &other_multisig_pubkey),
            hashlock_pubkey,
        ) in create_funding_txes_result
            .funding_txes
            .iter()
            .zip(create_funding_txes_result.payment_output_positions.iter())
            .zip(my_multisig_privkeys.iter())
            .zip(next_multisig_pubkeys.iter())
            .zip(next_hashlock_pubkeys.iter())
        {
            let (timelock_pubkey, timelock_privkey) = crate::utill::generate_keypair();
            let contract_redeemscript = crate::protocol::contract::create_contract_redeemscript(
                hashlock_pubkey,
                &timelock_pubkey,
                &hashvalue,
                &locktime,
            );
            let funding_amount = my_funding_tx.output[utxo_index as usize].value;
            let my_senders_contract_tx = crate::protocol::contract::create_senders_contract_tx(
                bitcoin::OutPoint {
                    txid: my_funding_tx.compute_txid(),
                    vout: utxo_index,
                },
                funding_amount,
                &contract_redeemscript,
            )?;

            outgoing_swapcoins.push(OutgoingSwapCoin::new_legacy(
                my_multisig_privkey,
                other_multisig_pubkey,
                my_senders_contract_tx,
                contract_redeemscript,
                timelock_privkey,
                funding_amount,
            ));
        }

        let mining_fees = Amount::from_sat(create_funding_txes_result.total_miner_fee);

        log::info!(
            "[{}] Created {} funding txs and {} outgoing swapcoins, mining_fees={}",
            self.config.network_port,
            create_funding_txes_result.funding_txes.len(),
            outgoing_swapcoins.len(),
            mining_fees
        );

        Ok((
            create_funding_txes_result.funding_txes,
            outgoing_swapcoins,
            mining_fees,
        ))
    }

    fn find_outgoing_swapcoin(
        &self,
        multisig_redeemscript: &bitcoin::ScriptBuf,
    ) -> Option<OutgoingSwapCoin> {
        // Check the ongoing swap states for outgoing swapcoins
        if let Ok(swaps) = lock_debug!(self.ongoing_swaps.lock()) {
            for state in swaps.values() {
                for outgoing in &state.outgoing_swapcoins {
                    if outgoing.protocol == crate::protocol::ProtocolVersion::Legacy {
                        if let (Some(my_pubkey), Some(other_pubkey)) =
                            (&outgoing.my_pubkey, &outgoing.other_pubkey)
                        {
                            let computed_script =
                                crate::protocol::contract::create_multisig_redeemscript(
                                    my_pubkey,
                                    other_pubkey,
                                );
                            if &computed_script == multisig_redeemscript {
                                log::debug!(
                                    "[{}] Found outgoing swapcoin in ongoing swap state",
                                    self.config.network_port
                                );
                                return Some(outgoing.clone());
                            }
                        }
                    }
                }
            }
        }

        // Check outgoing swapcoins in wallet
        if let Ok(wallet) = lock_debug!(self.wallet.read()) {
            if let Some(swapcoin) = wallet.find_outgoing_swapcoin_by_multisig(multisig_redeemscript)
            {
                log::debug!(
                    "[{}] Found outgoing swapcoin in wallet store",
                    self.config.network_port
                );
                return Some(swapcoin.clone());
            }
        }

        log::debug!(
            "[{}] No outgoing swapcoin found for multisig script",
            self.config.network_port
        );
        None
    }

    #[cfg(feature = "integration-test")]
    fn behavior(&self) -> MakerBehavior {
        self.behavior
    }
}

impl MakerRpc for MakerServer {
    fn wallet(&self) -> &RwLock<Wallet> {
        &self.wallet
    }

    fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    fn config(&self) -> &MakerServerConfig {
        &self.config
    }

    fn shutdown(&self) -> &ShutdownSignal {
        &self.shutdown
    }

    #[cfg(not(feature = "integration-test"))]
    fn get_tor_hostname(&self) -> Result<String, crate::utill::TorError> {
        let tor_key_bytes = lock_debug!(self.wallet.read())
            .map_err(|_| crate::utill::TorError::General("wallet lock poisoned".into()))?
            .derive_tor_key();

        crate::utill::get_tor_hostname(
            &self.data_dir,
            self.config.control_port,
            self.config.network_port,
            &self.config.tor_auth_password,
            tor_key_bytes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{MakerServerConfig, ShutdownSignal, ThreadPool};
    use crate::utill::MIN_RELAY_FEE_RATE;
    use std::{
        sync::{atomic::Ordering, mpsc, Arc, TryLockError},
        thread,
        time::{Duration, Instant},
    };

    /// Non-finite or below-minimum fidelity feerates clamp to the relay
    /// minimum; a valid value is kept. A plain `<` comparison would let
    /// `nan` through into the bond fee math.
    #[test]
    fn maker_config_clamps_invalid_fidelity_feerate() {
        // The accepted timelock range depends on the integration-test
        // feature, so write one that is valid for this build instead of
        // inheriting the 15,000-block default (invalid under the feature).
        let timelock = if cfg!(feature = "integration-test") {
            950
        } else {
            15_000
        };
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let resolve = |feerate: &str| {
            let path = dir.path().join("config.toml");
            std::fs::write(
                &path,
                format!("fidelity_timelock = {timelock}\nfidelity_feerate = {feerate}\n"),
            )
            .unwrap();
            MakerServerConfig::new(Some(&path))
                .unwrap()
                .fidelity_feerate
        };

        assert_eq!(resolve("nan"), MIN_RELAY_FEE_RATE);
        assert_eq!(resolve("inf"), MIN_RELAY_FEE_RATE);
        assert_eq!(resolve("0.5"), MIN_RELAY_FEE_RATE);
        assert_eq!(resolve("3.0"), 3.0);
    }

    /// Keeps wallet inspection usable without clearing the terminal server latch.
    #[test]
    fn shutdown_signal_latches_request_and_rearms_backend_after_joins() {
        let signal = ShutdownSignal::new();
        let backend = signal.backend_flag();

        signal.store(true, Ordering::Relaxed);
        assert!(signal.load(Ordering::Relaxed));
        assert!(backend.load(Ordering::Relaxed));

        signal.reset_backend();
        assert!(signal.load(Ordering::Relaxed));
        assert!(!backend.load(Ordering::Relaxed));
    }

    /// Proves a joined parent can register a child without deadlocking the pool.
    #[test]
    fn shutdown_join_releases_pool_lock_and_drains_late_child() {
        let pool = Arc::new(ThreadPool::new(0));
        let (parent_started_tx, parent_started_rx) = mpsc::channel();
        let (release_parent_tx, release_parent_rx) = mpsc::channel();
        let (child_done_tx, child_done_rx) = mpsc::channel();
        let parent_pool = Arc::clone(&pool);
        let parent = thread::Builder::new()
            .name("pool-parent".into())
            .spawn(move || {
                parent_started_tx.send(()).unwrap();
                release_parent_rx.recv().unwrap();
                let child = thread::Builder::new()
                    .name("pool-child".into())
                    .spawn(move || child_done_tx.send(()).unwrap())
                    .unwrap();
                parent_pool.add_thread(child).unwrap();
            })
            .unwrap();
        pool.add_thread(parent).unwrap();
        parent_started_rx.recv().unwrap();

        let join_pool = Arc::clone(&pool);
        let (join_started_tx, join_started_rx) = mpsc::channel();
        let (joined_tx, joined_rx) = mpsc::channel();
        let joiner = thread::Builder::new()
            .name("pool-joiner".into())
            .spawn(move || {
                join_started_tx.send(()).unwrap();
                let result = join_pool.join_all_threads();
                joined_tx.send(result).unwrap();
            })
            .unwrap();
        join_started_rx.recv().unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match pool.threads.try_lock() {
                Ok(threads) if threads.is_empty() => break,
                Ok(_) | Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Poisoned(_)) => panic!("thread pool lock poisoned"),
            }
            assert!(Instant::now() < deadline, "join held the thread pool lock");
            thread::yield_now();
        }

        release_parent_tx.send(()).unwrap();
        child_done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        joined_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        joiner.join().unwrap();
    }
}
