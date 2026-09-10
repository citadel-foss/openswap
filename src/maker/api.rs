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

use bitcoin::{bip32::ChainCode, Amount, Network, OutPoint, PublicKey, Transaction, Txid};

use crate::{
    lock_debug,
    maker::nostr::NOSTR_RELAYS,
    protocol::common_messages::{FidelityProof, ProtocolVersion, SwapDetails},
    taker::api::REFUND_LOCKTIME_STEP,
    utill::{
        funding_fee_policy_sats, get_maker_dir, parse_field, parse_toml, sweep_fee_policy_sats,
        MAX_TX_COUNT, MIN_RELAY_FEE_RATE,
    },
    wallet::{
        funding::{net_policy_fees, SplitPlan},
        swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
        AddressType, AnyBlockchain, BackendConfig, Blockchain, CoreRpcConfig, FidelityError,
        Wallet, WalletError, MAX_FIDELITY_TIMELOCK, MIN_FIDELITY_TIMELOCK,
    },
    watch_tower::service::WatchService,
};

use crate::utill::TX_CONFIRMATION_TIMEOUT;

#[cfg(feature = "integration-test")]
use std::env;

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

/// Hard lifetime of a swap that has shown no on-chain evidence, counted from
/// admission. The honest road to first evidence is the taker confirming its own
/// funding (bounded taker-side by `TX_CONFIRMATION_TIMEOUT`) plus one bounded
/// maker-funding wait per preceding hop; past this age the swap is dead even if
/// keepalives keep refreshing its idle timer. Test builds use the same bound —
/// a shorter one kills honest swaps whose taker waits out slow confirmations.
const UNFUNDED_SWAP_LIFETIME: Duration = Duration::from_secs(2 * TX_CONFIRMATION_TIMEOUT.as_secs());

/// The terms fixed by the taker's `SwapDetails` at negotiation, including the
/// fee rate. Compared as one value on reconnect so no field can silently
/// change between connections — a hand-written field list dropped the feerate.
#[derive(Debug, Clone, Copy, PartialEq)]
struct NegotiatedTerms {
    swap_amount: Amount,
    tx_count: u32,
    incoming_count: u32,
    max_input_budget: u32,
    timelock: u32,
    protocol: ProtocolVersion,
    /// Locked duration declared at negotiation; kept so a fee recomputed on a
    /// later message comes out the same.
    refund_locktime_offset: u16,
    /// The wire feerate as an f64; the u64-to-f64 conversion is exact for
    /// every valid rate, so a plain `==` detects a changed rate.
    swap_feerate: f64,
}

impl From<&ConnectionState> for NegotiatedTerms {
    fn from(state: &ConnectionState) -> Self {
        Self {
            swap_amount: state.swap_amount,
            tx_count: state.tx_count,
            incoming_count: state.incoming_count,
            max_input_budget: state.max_input_budget,
            timelock: state.timelock,
            protocol: state.protocol,
            refund_locktime_offset: state.refund_locktime_offset,
            swap_feerate: state.swap_feerate,
        }
    }
}

/// Swap state tracked per swap_id (persisted across connections).
#[derive(Debug, Clone)]
struct SwapState {
    /// The negotiated terms, stored as one value so a replayed SwapDetails is
    /// checked against the whole agreement.
    negotiated: NegotiatedTerms,
    /// Current phase of the swap.
    phase: SwapPhase,
    /// Incoming swapcoins (we receive).
    incoming_swapcoins: Vec<IncomingSwapCoin>,
    /// Outgoing swapcoins (we send).
    outgoing_swapcoins: Vec<OutgoingSwapCoin>,
    /// Incoming contract txids claimed at contract-data admission, before the
    /// swapcoins exist. This is what makes a concurrent duplicate fail at
    /// claim time instead of after both swaps funded the next hop.
    claimed_incoming_txids: Vec<Txid>,
    /// Pending funding transactions (for Legacy protocol).
    /// Stored until signature exchange completes, then broadcast.
    pending_funding_txes: Vec<Transaction>,
    /// Funding txids broadcast so far, one per tx as the batch progresses. A
    /// partial batch must not read as never broadcast, or recovery discards
    /// recovery material for transactions already on-chain.
    funding_broadcast_txids: Vec<Txid>,
    /// Maker service fee calculated from the accepted offer, excluding mining reimbursement.
    service_fee_sats: u64,
    /// The funding plan frozen at admission, netted of policy fees. Executed
    /// as-is; a maker never re-plans a live swap. Its inputs sit in the
    /// wallet's swap-keyed reservation map, the single owner of reservations.
    funding_plan: Vec<SplitPlan>,
    /// Last activity timestamp.
    last_activity: Instant,
    /// Time when this swap was accepted by the maker.
    swap_start_time: Instant,
    /// Height our incoming funding confirmed at. A Legacy refund deadline is counted
    /// from it, and it cannot be derived later once the swap has moved on.
    /// `None` until that confirmation is observed.
    funding_confirmation_height: Option<u32>,
}

impl Default for SwapState {
    fn default() -> Self {
        SwapState {
            negotiated: NegotiatedTerms {
                swap_amount: Amount::ZERO,
                tx_count: 0,
                incoming_count: 0,
                max_input_budget: 0,
                timelock: 0,
                protocol: ProtocolVersion::Legacy,
                refund_locktime_offset: 0,
                swap_feerate: 0.0,
            },
            phase: SwapPhase::AwaitingHello,
            incoming_swapcoins: Vec::new(),
            outgoing_swapcoins: Vec::new(),
            claimed_incoming_txids: Vec::new(),
            pending_funding_txes: Vec::new(),
            funding_broadcast_txids: Vec::new(),
            service_fee_sats: 0,
            funding_plan: Vec::new(),
            last_activity: Instant::now(),
            swap_start_time: Instant::now(),
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
    /// Defaults to `MIN_RELAY_FEE_RATE`, which is also the floor — lower
    /// rates stop relaying.
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
            fidelity_feerate: MIN_RELAY_FEE_RATE,
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
        // Non-finite values (TOML allows `nan`/`inf`) bypass a `<` comparison,
        // so they must be filtered out explicitly; rates below the relay floor
        // would not propagate.
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
    /// Funding txids broadcast so far; carried into the tracker record.
    pub funding_broadcast_txids: Vec<Txid>,
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
        // Activity refreshes the idle timer, but the admission lifetime is a hard
        // bound: keepalives cannot pin a reservation forever.
        #[cfg(feature = "integration-test")]
        let lifetime = env::var("OPENSWAP_UNFUNDED_SWAP_LIFETIME_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(UNFUNDED_SWAP_LIFETIME);
        #[cfg(not(feature = "integration-test"))]
        let lifetime = UNFUNDED_SWAP_LIFETIME;
        let released_ids: Vec<(String, bool)> = swaps
            .iter()
            .filter_map(|(id, state)| {
                let unfunded = state.phase == SwapPhase::AwaitingContractData
                    && state.incoming_swapcoins.is_empty()
                    && state.outgoing_swapcoins.is_empty()
                    && state.pending_funding_txes.is_empty()
                    && state.funding_broadcast_txids.is_empty();
                if !unfunded {
                    return None;
                }
                let expired = state.swap_start_time.elapsed() > lifetime;
                (expired || state.last_activity.elapsed() > timeout).then(|| (id.clone(), expired))
            })
            .collect();

        let mut drained_ids = Vec::new();
        for (id, expired) in released_ids {
            swaps.remove(&id);
            if expired {
                log::warn!(
                    "[{}] Released unfunded swap {} past its admission lifetime",
                    self.config.network_port,
                    id
                );
            } else {
                log::info!(
                    "[{}] Released idle unfunded reservation for swap {}",
                    self.config.network_port,
                    id
                );
            }
            drained_ids.push(id);
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
                        state.negotiated.protocol,
                        state.negotiated.timelock,
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
                drained_ids.push(id.clone());
                idle.push(IdleSwapData {
                    swap_id: id,
                    protocol: state.negotiated.protocol,
                    swap_amount_sat: state.negotiated.swap_amount.to_sat(),
                    incoming_swapcoins: state.incoming_swapcoins,
                    outgoing_swapcoins: state.outgoing_swapcoins,
                    funding_broadcast_txids: state.funding_broadcast_txids,
                });
            }
        }

        drop(swaps);
        // Every drained swap has ended, so its reservation ends with it.
        // Recovery spends contract outputs, never these inputs.
        if !drained_ids.is_empty() {
            let mut wallet = lock_debug!(self.wallet.write())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;
            for id in &drained_ids {
                wallet.release_swap_locks(id, None);
            }
        }

        Ok(idle)
    }

    /// Remove a completed swap's entry from `ongoing_swaps`.
    pub fn remove_swap_state(&self, swap_id: &str) -> Result<(), MakerError> {
        lock_debug!(self.ongoing_swaps.lock())
            .map_err(|_| MakerError::MutexPossion)?
            .remove(swap_id);
        // The swap is over; any reservation it still holds ends with it.
        let mut wallet = lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        wallet.release_swap_locks(swap_id, None);
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

    /// Plan this hop's forwarding at admission, on the forwardable amount:
    /// the declared amount minus the service fee and the sweep price of every
    /// incoming contract. Failures map to a liquidity rejection so the taker
    /// hears a refusal, not a dropped connection.
    fn plan_admission(&self, state: &ConnectionState) -> Result<Vec<SplitPlan>, MakerError> {
        let sweep_fee = sweep_fee_policy_sats(state.protocol, state.swap_feerate)
            .and_then(|per_contract| per_contract.checked_mul(state.incoming_count as u64))
            .ok_or(MakerError::General("Sweep fee arithmetic overflow"))?;
        let forwardable = state
            .swap_amount
            .to_sat()
            .checked_sub(state.service_fee_sats)
            .and_then(|rest| rest.checked_sub(sweep_fee))
            .ok_or(MakerError::General("Swap fees exceed the declared amount"))?;
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        let mut plan = wallet
            .plan_funding(
                Amount::from_sat(forwardable),
                state.tx_count,
                state.swap_feerate,
                state.max_input_budget,
                Some(state.service_fee_sats),
                None,
                None,
            )
            .map_err(|e| {
                log::warn!(
                    "[{}] Rejecting swap at admission: cannot fund {} sats forwardable: {:?}",
                    self.config.network_port,
                    forwardable,
                    e
                );
                match e {
                    WalletError::InsufficientFund {
                        available,
                        required,
                    } => MakerError::InsufficientLiquidity {
                        available: Amount::from_sat(available),
                        reserved: Amount::ZERO,
                        requested: Amount::from_sat(required),
                    },
                    _ => MakerError::InsufficientLiquidity {
                        available: Amount::ZERO,
                        reserved: Amount::ZERO,
                        requested: state.swap_amount,
                    },
                }
            })?;
        // Forwarding nets the taker-reimbursed fee out of each split; a split
        // the netting pushes below the floor is a refusal, not a smaller swap.
        net_policy_fees(&mut plan, state.max_input_budget, state.swap_feerate).map_err(|e| {
            log::warn!(
                "[{}] Rejecting swap at admission: policy netting failed: {:?}",
                self.config.network_port,
                e
            );
            MakerError::InsufficientLiquidity {
                available: Amount::ZERO,
                reserved: Amount::ZERO,
                requested: state.swap_amount,
            }
        })?;
        Ok(plan)
    }

    /// The funding plan frozen at admission. `amount` must equal the plan's
    /// pre-netting total: the frozen values plus each split's policy fee,
    /// derived from the plan shape at the negotiated rate. A missing or
    /// mismatched plan is a protocol error — the maker never re-plans.
    fn frozen_funding_plan(
        &self,
        swap_id: &str,
        amount: Amount,
    ) -> Result<Vec<SplitPlan>, MakerError> {
        let swaps = lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
        let state = swaps
            .get(swap_id)
            .filter(|state| !state.funding_plan.is_empty())
            .ok_or(MakerError::General("No frozen funding plan for this swap"))?;
        let mut gross = 0u64;
        for split in &state.funding_plan {
            let policy_fee = funding_fee_policy_sats(
                split.utxos.len(),
                state.negotiated.max_input_budget,
                state.negotiated.swap_feerate,
            )
            .ok_or(MakerError::General("Funding fee arithmetic overflow"))?;
            gross = gross
                .checked_add(policy_fee)
                .and_then(|total| total.checked_add(split.value.to_sat()))
                .ok_or(MakerError::General("Funding plan total overflow"))?;
        }
        if gross != amount.to_sat() {
            return Err(MakerError::General(
                "Requested amount does not match the frozen funding plan",
            ));
        }
        Ok(state.funding_plan.clone())
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

        // Zero knobs are meaningless: no splits to build, no inputs to price.
        if details.tx_count == 0 {
            return Err(MakerError::General("Transaction count must be non-zero"));
        }
        if details.max_input_budget == 0 {
            return Err(MakerError::General("Input budget must be non-zero"));
        }
        // These counts drive peer-controlled allocation and keygen downstream.
        if details.tx_count > MAX_TX_COUNT {
            return Err(MakerError::General(
                "Transaction count above the protocol maximum",
            ));
        }
        if details.max_input_budget > MAX_TX_COUNT {
            return Err(MakerError::General(
                "Input budget above the protocol maximum",
            ));
        }
        // The declared incoming count is exact and drives the sweep-fee math.
        if details.incoming_count == 0 || details.incoming_count > MAX_TX_COUNT {
            return Err(MakerError::General(
                "Incoming count outside the protocol bounds",
            ));
        }
        // Below the relay floor none of the swap's transactions propagate.
        if details.feerate < MIN_RELAY_FEE_RATE as u64 {
            return Err(MakerError::General("Swap feerate below the relay floor"));
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

    fn create_funding_transactions(
        &self,
        swap_id: &str,
        amount: Amount,
        addresses: &[bitcoin::Address],
        feerate: f64,
    ) -> Result<(Vec<Transaction>, Vec<u32>), MakerError> {
        let plan = self.frozen_funding_plan(swap_id, amount)?;

        // Malice hooks: tamper with the frozen plan's values after
        // verification, so the taker's exact checks are what catch it.
        #[cfg(feature = "integration-test")]
        let plan = match self.behavior() {
            MakerBehavior::FeeSkimming => {
                let mut skimmed = plan;
                skimmed[0].value = Amount::from_sat(skimmed[0].value.to_sat() - 1);
                skimmed
            }
            MakerBehavior::UnderfundTaprootContract => {
                // Keep the reported shape; fund only 10_000 sats in total.
                let mut underfunded = plan;
                let per_split = Amount::from_sat(10_000 / underfunded.len() as u64);
                for split in &mut underfunded {
                    split.value = per_split;
                }
                underfunded
            }
            _ => plan,
        };

        // Malice hook: build every split at the relay floor while the taker
        // reimburses the negotiated rate; its real-fee check must catch the
        // shortfall.
        #[cfg(feature = "integration-test")]
        let feerate = if self.behavior() == MakerBehavior::UnderpayFundingFee {
            MIN_RELAY_FEE_RATE
        } else {
            feerate
        };

        let mut funding_txes = Vec::with_capacity(plan.len());
        let mut payment_output_positions = Vec::with_capacity(plan.len());
        // One wallet lock per split, not per batch: holding it across one
        // RPC-and-sign per split stalls every other connection. A failure
        // here is before any broadcast, so the reservation is released whole.
        for (split, address) in plan.iter().zip(addresses.iter()) {
            let executed = {
                let mut wallet = lock_debug!(self.wallet.write())
                    .map_err(|_| MakerError::General("Failed to lock wallet"))?;
                wallet.execute_funding_plan(
                    std::slice::from_ref(split),
                    std::slice::from_ref(address),
                    feerate,
                )
            };
            match executed {
                Ok(result) => {
                    funding_txes.extend(result.funding_txes);
                    payment_output_positions.extend(result.payment_output_positions);
                }
                Err(e) => {
                    if let Ok(mut wallet) = lock_debug!(self.wallet.write()) {
                        wallet.release_swap_locks(swap_id, None);
                    }
                    return Err(MakerError::Wallet(e));
                }
            }
        }

        Ok((funding_txes, payment_output_positions))
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
        swap_id: &str,
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
        // The wait can outlast the idle-drain timeout, so the per-poll hook
        // refreshes this swap's stored activity: a live handler never drains.
        let keep_alive = || {
            if let Ok(mut swaps) = lock_debug!(self.ongoing_swaps.lock()) {
                if let Some(state) = swaps.get_mut(swap_id) {
                    state.last_activity = Instant::now();
                }
            }
            false
        };
        crate::wallet::wait_for_tx_confirmation(
            &chain,
            &[*txid],
            required_confirms,
            crate::utill::TX_BROADCAST_TIMEOUT,
            Some(&self.shutdown),
            Some(&keep_alive),
        )
        .map_err(MakerError::Wallet)?;
        Ok(())
    }

    fn broadcast_transaction(&self, tx: &Transaction) -> Result<bitcoin::Txid, MakerError> {
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;

        wallet.send_tx(tx).map_err(MakerError::Wallet)
    }

    fn is_transaction_known(&self, txid: &Txid) -> Result<bool, MakerError> {
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        // A failed query must surface as an error, never as "not known".
        Ok(!wallet
            .blockchain
            .is_tx_unknown(txid)
            .map_err(MakerError::Wallet)?)
    }

    fn record_funding_broadcast(&self, swap_id: &str, txid: &Txid) -> Result<(), MakerError> {
        let mut swaps =
            lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
        let state = swaps
            .get_mut(swap_id)
            .ok_or(MakerError::General("No stored state for this swap"))?;
        // Reconnects re-run the broadcast loop; one entry per txid, not per send.
        if !state.funding_broadcast_txids.contains(txid) {
            state.funding_broadcast_txids.push(*txid);
        }
        // Each proved send is activity: a long batch must not read as idle.
        state.last_activity = Instant::now();
        // Broadcast accepted is a proved outcome, so this tx's reserved inputs
        // are released. Legacy keeps its funding txs in `pending_funding_txes`
        // until the batch is sent; Taproot's contract tx is the funding tx.
        let funding_tx = match state.negotiated.protocol {
            ProtocolVersion::Legacy => state
                .pending_funding_txes
                .iter()
                .find(|tx| tx.compute_txid() == *txid),
            ProtocolVersion::Taproot => state
                .outgoing_swapcoins
                .iter()
                .map(|sc| &sc.contract_tx)
                .find(|tx| tx.compute_txid() == *txid),
        };
        let spent_inputs: Vec<OutPoint> = funding_tx
            .map(|tx| tx.input.iter().map(|i| i.previous_output).collect())
            .unwrap_or_default();
        drop(swaps);
        if !spent_inputs.is_empty() {
            let mut wallet = lock_debug!(self.wallet.write())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;
            wallet.release_swap_locks(swap_id, Some(&spent_inputs));
        }
        Ok(())
    }

    fn contract_output_unspent(&self, outpoint: &OutPoint) -> Result<bool, MakerError> {
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        Ok(wallet
            .blockchain
            .get_tx_out(&outpoint.txid, outpoint.vout, None)
            .map_err(MakerError::Wallet)?
            .is_some())
    }

    fn contract_txid_seen(&self, txid: &Txid, except_swap_id: &str) -> Result<bool, MakerError> {
        let swaps = lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
        let live_hit = swaps.iter().any(|(id, state)| {
            id.as_str() != except_swap_id
                && (state.claimed_incoming_txids.contains(txid)
                    || state
                        .incoming_swapcoins
                        .iter()
                        .any(|sc| sc.contract_tx.compute_txid() == *txid)
                    || state
                        .outgoing_swapcoins
                        .iter()
                        .any(|sc| sc.contract_tx.compute_txid() == *txid))
        });
        drop(swaps);
        if live_hit {
            return Ok(true);
        }
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        // A reconnecting taker replays this swap's own persisted contracts;
        // only another swap's swapcoin makes the txid a replay.
        let txid_string = txid.to_string();
        if let Some(swapcoin) = wallet.find_incoming_swapcoin(&txid_string) {
            return Ok(swapcoin.swap_id.as_deref() != Some(except_swap_id));
        }
        if wallet
            .outgoing_keys_for_swap(except_swap_id)
            .contains(&txid_string)
        {
            return Ok(false);
        }
        Ok(wallet
            .outgoing_contract_outpoints()
            .into_iter()
            .any(|(outpoint, _)| outpoint.txid == *txid))
    }

    fn claim_incoming_contract_txids(
        &self,
        swap_id: &str,
        txids: &[Txid],
    ) -> Result<(), MakerError> {
        let mut swaps =
            lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
        let claimed_elsewhere = swaps.iter().any(|(id, state)| {
            id.as_str() != swap_id
                && (state
                    .claimed_incoming_txids
                    .iter()
                    .any(|claimed| txids.contains(claimed))
                    || state
                        .incoming_swapcoins
                        .iter()
                        .any(|sc| txids.contains(&sc.contract_tx.compute_txid()))
                    || state
                        .outgoing_swapcoins
                        .iter()
                        .any(|sc| txids.contains(&sc.contract_tx.compute_txid())))
        });
        if claimed_elsewhere {
            return Err(MakerError::General("Contract txid already in use"));
        }
        let state = swaps
            .get_mut(swap_id)
            .ok_or(MakerError::General("No stored state for this swap"))?;
        state.claimed_incoming_txids = txids.to_vec();
        state.last_activity = Instant::now();
        Ok(())
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
        let sweep_outcome = Wallet::sweep_incoming_swapcoins(&self.wallet, &chain, &self.shutdown)
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
        // Plan before taking the swaps lock for the write: the pool snapshot,
        // the planner's sort and the policy netting are the expensive part, and
        // the wallet read lock is shared. Cheap rejections come first: a fresh
        // swap id costs the sender nothing, so the cap is enforced before any
        // planning runs.
        let planned = if admission {
            let known = lock_debug!(self.ongoing_swaps.lock())?.contains_key(swap_id);
            if known {
                None
            } else {
                // After a restart `ongoing_swaps` is empty, so a replayed
                // SwapDetails for a swap still open on disk would re-admit and
                // double-fund it. The open swap is recovered, never re-admitted.
                let tracked_open = lock_debug!(self.swap_tracker.lock())?
                    .incomplete_swaps()
                    .iter()
                    .any(|record| record.swap_id == swap_id);
                let (unfinished_incoming, unfinished_outgoing) = lock_debug!(self.wallet.read())
                    .map_err(|_| MakerError::General("Failed to lock wallet"))?
                    .find_unfinished_swapcoins();
                let persisted_open = unfinished_incoming
                    .iter()
                    .any(|sc| sc.swap_id.as_deref() == Some(swap_id))
                    || unfinished_outgoing
                        .iter()
                        .any(|sc| sc.swap_id.as_deref() == Some(swap_id));
                if tracked_open || persisted_open {
                    log::warn!(
                        "[{}] Rejecting SwapDetails for {}: swap id belongs to an unfinished swap on disk",
                        self.config.network_port,
                        swap_id,
                    );
                    return Err(MakerError::General("Swap id belongs to an unfinished swap"));
                }
                let active_swaps = lock_debug!(self.ongoing_swaps.lock())?
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
                Some(self.plan_admission(state)?)
            }
        } else {
            None
        };

        let mut swaps = lock_debug!(self.ongoing_swaps.lock())?;

        // A resent SwapDetails for a live swap is a reconnect after a dropped
        // connection: identical parameters just refresh the idle timer, while
        // different ones must never overwrite the stored swap.
        if admission && swaps.contains_key(swap_id) {
            let swap_state = swaps
                .get_mut(swap_id)
                .expect("entry exists under this lock");
            if swap_state.negotiated != NegotiatedTerms::from(state) {
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

        if let Some(plan) = &planned {
            let inputs: Vec<OutPoint> = plan
                .iter()
                .flat_map(|split| split.utxos.iter().copied())
                .collect();
            // Planning ran outside this lock, so a concurrent admission may
            // have claimed an input since. Reserve only a conflict-free plan.
            let mut wallet = lock_debug!(self.wallet.write())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;
            if inputs.iter().any(|input| wallet.is_swap_reserved(input)) {
                log::warn!(
                    "[{}] Rejecting swap {}: a concurrent admission claimed a planned input",
                    self.config.network_port,
                    swap_id,
                );
                return Err(MakerError::InsufficientLiquidity {
                    available: Amount::ZERO,
                    reserved: Amount::ZERO,
                    requested: state.swap_amount,
                });
            }
            wallet.reserve_swap_locks(swap_id, &inputs);
        }

        let swap_state = swaps.entry(swap_id.to_string()).or_default();
        #[cfg(debug_assertions)]
        if swap_state.phase != state.phase
            || swap_state.funding_broadcast_txids.len() != state.funding_broadcast_txids.len()
            || swap_state.incoming_swapcoins.len() != state.incoming_swapcoins.len()
            || swap_state.outgoing_swapcoins.len() != state.outgoing_swapcoins.len()
            || swap_state.funding_plan.len() != state.funding_plan.len()
        {
            log::debug!(
                "[SWAP_STATE] Source: maker::api::store_connection_state | Role: Maker | SwapID: {} | Phase: {:?} | FundingBroadcastTxids: {} | Incoming: {} | Outgoing: {} | FundingSplits: {}",
                swap_id,
                state.phase,
                state.funding_broadcast_txids.len(),
                state.incoming_swapcoins.len(),
                state.outgoing_swapcoins.len(),
                state.funding_plan.len()
            );
        }
        swap_state.negotiated = NegotiatedTerms::from(state);
        swap_state.phase = state.phase;
        swap_state.incoming_swapcoins = state.incoming_swapcoins.clone();
        swap_state.outgoing_swapcoins = state.outgoing_swapcoins.clone();
        swap_state.pending_funding_txes = state.pending_funding_txes.clone();
        swap_state.funding_broadcast_txids = state.funding_broadcast_txids.clone();
        swap_state.service_fee_sats = state.service_fee_sats;
        // The plan frozen at admission wins over the handler's empty one;
        // later stores carry the same plan back.
        if let Some(plan) = planned {
            swap_state.funding_plan = plan;
        } else {
            swap_state.funding_plan = state.funding_plan.clone();
        }
        swap_state.last_activity = Instant::now();
        swap_state.swap_start_time = state.swap_start_time;
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
            let mut state = ConnectionState::new(s.negotiated.protocol);
            state.swap_id = Some(swap_id.to_string());
            state.swap_amount = s.negotiated.swap_amount;
            state.tx_count = s.negotiated.tx_count;
            state.incoming_count = s.negotiated.incoming_count;
            state.max_input_budget = s.negotiated.max_input_budget;
            state.timelock = s.negotiated.timelock;
            state.phase = s.phase;
            state.incoming_swapcoins = s.incoming_swapcoins.clone();
            state.outgoing_swapcoins = s.outgoing_swapcoins.clone();
            state.pending_funding_txes = s.pending_funding_txes.clone();
            state.funding_broadcast_txids = s.funding_broadcast_txids.clone();
            state.swap_feerate = s.negotiated.swap_feerate;
            state.service_fee_sats = s.service_fee_sats;
            state.funding_plan = s.funding_plan.clone();
            state.swap_start_time = s.swap_start_time;
            state.refund_locktime_offset = s.negotiated.refund_locktime_offset;
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
                state.negotiated.protocol,
                state.negotiated.timelock,
                state.funding_confirmation_height,
                current_height,
            )
        }))
    }

    fn claimed_funding_unseen(&self, swap_id: &str) -> Result<bool, MakerError> {
        let claimed: Vec<Txid> = {
            let swaps =
                lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
            let Some(state) = swaps.get(swap_id) else {
                return Ok(false);
            };
            // Evidence is the taker's money moving, not our own artifacts.
            // Taproot's claimed txs carry the funding on-chain; a legacy
            // receiver contract is maker-built and never broadcast, so the
            // taker's funding tx behind it is the only live evidence there.
            let legacy = state.negotiated.protocol == ProtocolVersion::Legacy;
            state
                .claimed_incoming_txids
                .iter()
                .copied()
                .filter(|_| !legacy)
                .chain(state.incoming_swapcoins.iter().filter_map(|sc| {
                    if legacy {
                        sc.contract_tx.input.first().map(|i| i.previous_output.txid)
                    } else {
                        Some(sc.contract_tx.compute_txid())
                    }
                }))
                .collect()
        };
        // No funding named yet: the unfunded lifetime, not this check, bounds
        // the keepalive refresh.
        if claimed.is_empty() {
            return Ok(false);
        }
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        // Mempool counts: a broadcast-but-unconfirmed funding is live evidence.
        for txid in &claimed {
            if !wallet
                .blockchain
                .is_tx_unknown(txid)
                .map_err(MakerError::Wallet)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    fn wallet_name(&self) -> &str {
        &self.config.wallet_name
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
                &message.id,
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

    fn initialize_swap(
        &self,
        swap_id: &str,
        send_amount: Amount,
        next_multisig_pubkeys: &[PublicKey],
        next_hashlock_pubkeys: &[PublicKey],
        hashvalue: crate::protocol::Hash160,
        locktime: u16,
        contract_feerate: f64,
    ) -> Result<(Vec<Transaction>, Vec<OutgoingSwapCoin>, Amount), MakerError> {
        log::info!(
            "[{}] Initializing openswap: amount={} sats, {} pubkeys",
            self.config.network_port,
            send_amount.to_sat(),
            next_multisig_pubkeys.len()
        );

        let plan = self.frozen_funding_plan(swap_id, send_amount)?;
        // The taker derived its key bundles from the shape reported in the
        // Ack: one bundle per frozen split, no more and no fewer.
        if next_multisig_pubkeys.len() != plan.len() {
            return Err(MakerError::General(
                "Next-hop key count does not match the frozen funding plan",
            ));
        }

        // Malice hook: forward one sat less than the frozen plan promised, so
        // the taker's exact-amount check is what catches the skim.
        #[cfg(feature = "integration-test")]
        let plan = if self.behavior() == MakerBehavior::FeeSkimming {
            let mut skimmed = plan;
            skimmed[0].value = Amount::from_sat(skimmed[0].value.to_sat() - 1);
            skimmed
        } else {
            plan
        };

        let (openswap_addresses, my_multisig_privkeys): (Vec<_>, Vec<_>) = {
            let mut wallet = lock_debug!(self.wallet.write())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;
            next_multisig_pubkeys
                .iter()
                .map(|other_key| wallet.create_and_import_swap_address(other_key))
                .collect::<Result<Vec<_>, _>>()
                .map_err(MakerError::Wallet)?
                .into_iter()
                .unzip()
        };

        // Same malice hook as `create_funding_transactions`: splits built at
        // the relay floor against a negotiated-rate reimbursement.
        #[cfg(feature = "integration-test")]
        let contract_feerate = if self.behavior() == MakerBehavior::UnderpayFundingFee {
            MIN_RELAY_FEE_RATE
        } else {
            contract_feerate
        };

        let mut funding_txes = Vec::with_capacity(plan.len());
        let mut payment_output_positions = Vec::with_capacity(plan.len());
        let mut total_miner_fee = 0u64;
        // One wallet lock per split, not per batch: holding it across one
        // RPC-and-sign per split stalls every other connection. A failure
        // here is before any broadcast, so the reservation is released whole.
        for (split, address) in plan.iter().zip(openswap_addresses.iter()) {
            let executed = {
                let mut wallet = lock_debug!(self.wallet.write())
                    .map_err(|_| MakerError::General("Failed to lock wallet"))?;
                wallet.execute_funding_plan(
                    std::slice::from_ref(split),
                    std::slice::from_ref(address),
                    contract_feerate,
                )
            };
            match executed {
                Ok(result) => {
                    total_miner_fee += result.total_miner_fee;
                    funding_txes.extend(result.funding_txes);
                    payment_output_positions.extend(result.payment_output_positions);
                }
                Err(e) => {
                    if let Ok(mut wallet) = lock_debug!(self.wallet.write()) {
                        wallet.release_swap_locks(swap_id, None);
                    }
                    return Err(MakerError::Wallet(e));
                }
            }
        }

        let mut outgoing_swapcoins = Vec::new();
        for (
            (((my_funding_tx, &utxo_index), &my_multisig_privkey), &other_multisig_pubkey),
            hashlock_pubkey,
        ) in funding_txes
            .iter()
            .zip(payment_output_positions.iter())
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
                contract_feerate,
            )?;

            outgoing_swapcoins.push(OutgoingSwapCoin::new_legacy(
                my_multisig_privkey,
                other_multisig_pubkey,
                my_senders_contract_tx,
                contract_redeemscript,
                timelock_privkey,
                funding_amount,
                contract_feerate as u64,
            ));
        }

        let mining_fees = Amount::from_sat(total_miner_fee);

        log::info!(
            "[{}] Created {} funding txs and {} outgoing swapcoins, mining_fees={}",
            self.config.network_port,
            funding_txes.len(),
            outgoing_swapcoins.len(),
            mining_fees
        );

        Ok((funding_txes, outgoing_swapcoins, mining_fees))
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
