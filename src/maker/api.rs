//! Maker API for both Legacy (ECDSA) and Taproot (MuSig2) protocols.

#[cfg(feature = "integration-test")]
use std::net::TcpListener;
use std::{
    collections::{HashMap, HashSet},
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
    blocklist::AddressBlocklist,
    lock_debug,
    maker::nostr::NOSTR_RELAYS,
    protocol::common_messages::{
        check_fee_pcts, check_maker_name, FidelityProof, MakerToTakerMessage, PrivateKeyHandover,
        ProtocolVersion, SwapDetails, MAX_MAKER_NAME_LEN,
    },
    taker::api::{REFUND_LOCKTIME_BASE, REFUND_LOCKTIME_STEP},
    utill::{
        fee_at_rate_sats, funding_fee_policy_sats, get_maker_dir, parse_field, parse_toml,
        sweep_fee_policy_sats, MAX_TX_COUNT, MIN_RELAY_FEE_RATE,
    },
    wallet::{
        funding::{fit_declared_shape, net_policy_fees, SplitPlan},
        min_contract_value_sats,
        swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
        AddressType, AnyBlockchain, BackendConfig, Blockchain, CoreRpcConfig, FeePriority,
        FidelityError, RecoveryOutcome, Wallet, WalletError, MAX_FIDELITY_TIMELOCK,
        MIN_FIDELITY_BOND_AMOUNT_SATS, MIN_FIDELITY_TIMELOCK,
    },
    watch_tower::service::WatchService,
};

#[cfg(feature = "integration-test")]
pub use super::handlers::MakerBehavior;

use super::{
    error::MakerError,
    handlers::{
        past_refund_deadline, ConnectionState, Maker as MakerTrait, MakerConfig, SwapPhase,
        MAX_CONCURRENT_SWAPS, MIN_CONTRACT_REACTION_TIME,
    },
    rpc::server::MakerRpc,
    swap_tracker::{now_secs, MakerRecoveryPhase, MakerSwapPhase, MakerSwapTracker},
};

/// How often a pending fidelity bond is checked for confirmation.
const BOND_POLL_INTERVAL: Duration = Duration::from_secs(10);

// Covers all production response timeouts and finalization retry delays.
const COMPLETED_HANDOVER_TTL: Duration = Duration::from_secs(65 * 60);

/// Plan `old` again from free coins, as the same number of splits forwarding
/// the same total. The taker priced the next hop from `old`'s input counts,
/// so each new split is netted at its old count and spends at least that.
fn replan_funding(
    wallet: &Wallet,
    terms: &NegotiatedTerms,
    service_fee: u64,
    old: &[SplitPlan],
    gross: Amount,
) -> Result<Vec<SplitPlan>, MakerError> {
    let out_of_coins = || MakerError::InsufficientLiquidity {
        available: wallet.plannable_balance(),
        required: gross,
    };
    let fresh = wallet
        .plan_funding(
            gross,
            old.len() as u32,
            terms.swap_feerate,
            terms.max_input_budget,
            Some(service_fee),
            None,
            None,
            terms.protocol,
        )
        .map_err(|e| match e {
            WalletError::InsufficientFund { .. } => out_of_coins(),
            other => MakerError::Wallet(other),
        })?;
    let declared: Vec<usize> = old.iter().map(|split| split.utxos.len()).collect();
    fit_declared_shape(
        fresh,
        &declared,
        wallet.plannable_pools(),
        terms.max_input_budget,
        terms.swap_feerate,
        service_fee,
        terms.protocol,
    )
    .map_err(|e| {
        // The taker only sees the liquidity refusal; keep the cause for the operator.
        log::warn!("Re-plan could not fit the declared funding shape: {e:?}");
        out_of_coins()
    })
}

/// What a hop must keep after its own fee: the incoming sweeps plus one
/// single-input outgoing contract. No swap of this shape passes with less.
fn swap_cost_floor(
    protocol: ProtocolVersion,
    feerate: f64,
    incoming_count: u32,
    max_input_budget: u32,
) -> Option<u64> {
    sweep_fee_policy_sats(protocol, feerate)?
        .checked_mul(incoming_count as u64)?
        .checked_add(min_contract_value_sats(protocol, feerate)?)?
        .checked_add(funding_fee_policy_sats(1, max_input_budget, feerate)?)
}

/// The advertised minimum rounds up to a multiple of this, so takers see a
/// round number that still passes.
const MIN_SWAP_STEP_SATS: u64 = 500;

/// Smallest swap every supported protocol accepts: one coin in, one coin out,
/// at the relay floor and a one-maker lock, rounded up to `MIN_SWAP_STEP_SATS`.
fn min_swap_amount(config: &MakerServerConfig) -> u64 {
    let rel = (config.amount_relative_fee_pct
        + f64::from(REFUND_LOCKTIME_BASE) * config.time_relative_fee_pct)
        / 100.0;
    config
        .supported_protocols
        .iter()
        .filter_map(|p| swap_cost_floor(*p, MIN_RELAY_FEE_RATE, 1, 1))
        .max()
        // The closed form is exact only while the fee grows with the amount
        // but stays under it; outside that no minimum can be priced.
        .filter(|_| (0.0..1.0).contains(&rel))
        .map(|cost| {
            // Solves `amount - fee(amount) >= cost` for `amount`.
            let exact = (config.base_fee.saturating_add(cost) as f64 / (1.0 - rel)).ceil() as u64;
            exact
                .div_ceil(MIN_SWAP_STEP_SATS)
                .saturating_mul(MIN_SWAP_STEP_SATS)
        })
        .unwrap_or(u64::MAX)
}

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
    /// The funding plan frozen at admission, netted of policy fees. Its input
    /// counts are what the taker was charged for; its coins are only a choice.
    funding_plan: Vec<SplitPlan>,
    /// The plan whose coins funding claimed: the frozen one, or its re-plan when
    /// another swap took a coin. Every later pass reuses exactly this claim.
    claimed_plan: Vec<SplitPlan>,
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
            claimed_plan: Vec::new(),
            last_activity: Instant::now(),
            swap_start_time: Instant::now(),
            funding_confirmation_height: None,
        }
    }
}

#[derive(Clone)]
struct CompletedHandover {
    protocol: ProtocolVersion,
    request: PrivateKeyHandover,
    response: MakerToTakerMessage,
    completed_at: Instant,
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
    /// Required confirmations for funding transactions. At least 1: `init` rejects 0.
    pub required_confirms: u32,
    /// Whether funding inputs should be checked against the address blocklist.
    pub check_blocklist: bool,
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
    /// Public name sent to takers in the offer.
    pub name: String,
    /// LDK Server gRPC address (`host:port`, no scheme) for the Lightning
    /// backend. Lightning swaps are offered only when this is set (and the
    /// binary is built with the `lightning` feature).
    pub ldk_server_url: Option<String>,
    /// Path to the LDK Server API key file (raw bytes, hex-encoded on load).
    pub ldk_api_key_path: Option<String>,
    /// Path to the LDK Server TLS certificate.
    pub ldk_tls_cert_path: Option<String>,
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
            required_confirms: 1,
            check_blocklist: false,
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
            name: "default-maker".to_string(),
            ldk_server_url: None,
            ldk_api_key_path: None,
            ldk_tls_cert_path: None,
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

        let fidelity_amount = parse_field(
            config_map.get("fidelity_amount"),
            default_config.fidelity_amount,
        );
        // A bond under this floor funds and confirms fine, but every taker's
        // discovery drops the announcement, leaving the maker unreachable with
        // its coins locked. Refuse at startup rather than fail silently.
        if fidelity_amount < MIN_FIDELITY_BOND_AMOUNT_SATS {
            log::warn!(
                "Invalid fidelity_amount: {} sats. Minimum accepted is {} sats.",
                fidelity_amount,
                MIN_FIDELITY_BOND_AMOUNT_SATS
            );
            return Err(WalletError::Fidelity(FidelityError::BondAmountTooLow {
                configured: fidelity_amount,
                minimum: MIN_FIDELITY_BOND_AMOUNT_SATS,
            }));
        }

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

        let name = parse_field(config_map.get("name"), default_config.name);
        check_maker_name(&name).map_err(WalletError::General)?;

        let amount_relative_fee_pct = parse_field(
            config_map.get("amount_relative_fee_pct"),
            default_config.amount_relative_fee_pct,
        );
        let time_relative_fee_pct = parse_field(
            config_map.get("time_relative_fee_pct"),
            default_config.time_relative_fee_pct,
        );
        check_fee_pcts(amount_relative_fee_pct, time_relative_fee_pct)
            .map_err(WalletError::General)?;

        Ok(MakerServerConfig {
            network_port: parse_field(config_map.get("network_port"), default_config.network_port),
            rpc_port: parse_field(config_map.get("rpc_port"), default_config.rpc_port),
            base_fee: parse_field(config_map.get("base_fee"), default_config.base_fee),
            amount_relative_fee_pct,
            time_relative_fee_pct,
            required_confirms: parse_field(
                config_map.get("required_confirms"),
                default_config.required_confirms,
            ),
            check_blocklist: parse_field(
                config_map.get("check_blocklist"),
                default_config.check_blocklist,
            ),
            fidelity_amount,
            fidelity_timelock,
            fidelity_feerate,
            control_port: parse_field(config_map.get("control_port"), default_config.control_port),
            socks_port: parse_field(config_map.get("socks_port"), default_config.socks_port),
            tor_auth_password: parse_field(
                config_map.get("tor_auth_password"),
                default_config.tor_auth_password,
            ),
            name,
            ldk_server_url: config_map.get("ldk_server_url").cloned(),
            ldk_api_key_path: config_map.get("ldk_api_key_path").cloned(),
            ldk_tls_cert_path: config_map.get("ldk_tls_cert_path").cloned(),
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
# Fidelity Bond amount in satoshis (must be at least {})
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
# Check funding inputs against the address blocklist
check_blocklist = {}
# Public name shown to takers (required, at most {} characters, no control characters)
name = \"{}\"
",
            self.network_port,
            self.rpc_port,
            self.socks_port,
            self.control_port,
            self.tor_auth_password,
            MIN_FIDELITY_BOND_AMOUNT_SATS,
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
            self.check_blocklist,
            MAX_MAKER_NAME_LEN,
            self.name,
        );

        // Optional Lightning backend keys: only present when configured, so
        // the round-trip rewrite makerd performs on startup preserves them.
        let mut toml_data = toml_data;
        if let Some(url) = &self.ldk_server_url {
            toml_data.push_str(&format!(
                "# LDK Server gRPC address (host:port, no scheme) for Lightning swaps\nldk_server_url = {url}\n"
            ));
        }
        if let Some(path) = &self.ldk_api_key_path {
            toml_data.push_str(&format!(
                "# Path to the LDK Server API key file\nldk_api_key_path = {path}\n"
            ));
        }
        if let Some(path) = &self.ldk_tls_cert_path {
            toml_data.push_str(&format!(
                "# Path to the LDK Server TLS certificate\nldk_tls_cert_path = {path}\n"
            ));
        }

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
    pub(crate) fn new() -> Self {
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
    /// Serializes funding claims, so two passes for one swap cannot both claim.
    funding_claims: Mutex<()>,
    /// Recently completed handovers, retained for exact retry replay.
    completed_handovers: Mutex<HashMap<String, CompletedHandover>>,
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
    /// Lightning backend, present when configured. All Lightning swap
    /// handling is disabled when this is `None`.
    #[cfg(feature = "lightning")]
    pub lightning: Option<std::sync::Arc<dyn crate::lightning::LightningBackend>>,
    /// Router distributing Lightning node events to per-swap mailboxes.
    #[cfg(feature = "lightning")]
    pub ln_router: Option<std::sync::Arc<super::lightning_handlers::LnEventRouter>>,
    /// Last computed Lightning offer and when it was computed. Deriving one
    /// costs a gRPC round-trip, and `get_config` runs on every coinswap
    /// message, so the result is cached for [`LN_OFFER_TTL`].
    #[cfg(feature = "lightning")]
    ln_offer_cache: Mutex<
        Option<(
            Instant,
            Option<crate::protocol::lightning_messages::LightningOffer>,
        )>,
    >,
    /// Active Lightning swaps by swap_id (hex payment hash).
    #[cfg(feature = "lightning")]
    pub ln_swaps: Mutex<HashMap<String, super::lightning_handlers::LnMakerSwap>>,
    /// Test-only behavior override.
    #[cfg(feature = "integration-test")]
    pub behavior: MakerBehavior,
    /// Reserved by the framework at allocation; taken at server start so no
    /// parallel test can snipe the port in between.
    #[cfg(feature = "integration-test")]
    pub reserved_network_listener: Mutex<Option<TcpListener>>,
    /// Same handoff for the RPC port.
    #[cfg(feature = "integration-test")]
    pub reserved_rpc_listener: Mutex<Option<TcpListener>>,
}

/// How long a derived Lightning offer is served before it is recomputed.
#[cfg(feature = "lightning")]
const LN_OFFER_TTL: Duration = Duration::from_secs(15);

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
        // Configs built in code skip `MakerServerConfig::new`, so check here too.
        check_fee_pcts(config.amount_relative_fee_pct, config.time_relative_fee_pct)
            .map_err(|e| MakerError::Wallet(WalletError::General(e)))?;
        // A 0-conf peer can replace its funding after we fund the next hop.
        // Nothing downstream defends against that, so refuse the config.
        if config.required_confirms == 0 {
            return Err(MakerError::General("required_confirms must be at least 1"));
        }
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
        // Validate the blocklist on startup when screening is enabled.
        if config.check_blocklist {
            AddressBlocklist::load(&data_dir, config.network)?;
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
        let mut watches = wallet.incoming_contract_outpoints(None);
        watches.extend(wallet.outgoing_contract_outpoints(None));

        // Lightning swaps that were in flight when this maker last stopped.
        // Their HTLCs are re-watched alongside the coinswap contracts, and
        // the restored states let the watchdog finish or refund them.
        #[cfg(feature = "lightning")]
        let restored_ln_swaps: HashMap<String, super::lightning_handlers::LnMakerSwap> = {
            let restored: HashMap<_, _> = wallet
                .store
                .ln_maker_swaps
                .clone()
                .into_iter()
                .map(|(swap_id, record)| {
                    (
                        swap_id,
                        super::lightning_handlers::LnMakerSwap::from_record(record),
                    )
                })
                .collect();
            for swap in restored.values() {
                if let (Some((outpoint, _)), Ok(spk)) = (swap.funding, swap.htlc.script_pubkey()) {
                    watches.push((outpoint, spk));
                }
            }
            if !restored.is_empty() {
                log::info!(
                    "[{}] Restored {} in-flight Lightning swap(s) from the wallet",
                    config.network_port,
                    restored.len()
                );
            }
            restored
        };
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

        #[cfg(feature = "lightning")]
        let lightning = Self::init_lightning_backend(&config);
        #[cfg(feature = "lightning")]
        let ln_router = lightning
            .as_ref()
            .map(|ln| super::lightning_handlers::LnEventRouter::new(std::sync::Arc::clone(ln)));
        #[cfg(feature = "lightning")]
        match &ln_router {
            // Re-open a mailbox per restored swap, or their settlement events
            // would be dropped as belonging to an unknown payment.
            Some(router) => {
                for swap in restored_ln_swaps.values() {
                    router.subscribe(swap.payment_hash);
                }
            }
            None if !restored_ln_swaps.is_empty() => log::error!(
                "{} Lightning swap(s) are in flight but no Lightning backend is configured; \
                 their HTLCs cannot be resolved until one is",
                restored_ln_swaps.len()
            ),
            None => {}
        }

        Ok(MakerServer {
            config: config.clone(),
            wallet: Arc::new(RwLock::new(wallet)),
            shutdown,
            is_setup_complete: AtomicBool::new(false),
            highest_fidelity_proof: RwLock::new(None),
            ongoing_swaps: Mutex::new(HashMap::new()),
            funding_claims: Mutex::new(()),
            watch_service,
            completed_handovers: Mutex::new(HashMap::new()),
            thread_pool: Arc::new(ThreadPool::new(config.network_port)),
            data_dir,
            swap_tracker: Mutex::new(swap_tracker),
            nostr_relays,
            #[cfg(feature = "lightning")]
            lightning,
            #[cfg(feature = "lightning")]
            ln_router,
            #[cfg(feature = "lightning")]
            ln_offer_cache: Mutex::new(None),
            #[cfg(feature = "lightning")]
            ln_swaps: Mutex::new(restored_ln_swaps),
            #[cfg(feature = "integration-test")]
            behavior: MakerBehavior::default(),
            #[cfg(feature = "integration-test")]
            reserved_network_listener: Mutex::new(None),
            #[cfg(feature = "integration-test")]
            reserved_rpc_listener: Mutex::new(None),
        })
    }

    pub(super) fn replay_completed_handover(
        &self,
        protocol: ProtocolVersion,
        request: &PrivateKeyHandover,
    ) -> Result<Option<MakerToTakerMessage>, MakerError> {
        let mut completed = lock_debug!(self.completed_handovers.lock())?;
        completed.retain(|_, handover| handover.completed_at.elapsed() < COMPLETED_HANDOVER_TTL);
        Ok(completed
            .get(&request.id)
            .filter(|handover| handover.protocol == protocol && handover.request == *request)
            .map(|handover| handover.response.clone()))
    }

    pub(super) fn cache_completed_handover(
        &self,
        protocol: ProtocolVersion,
        request: PrivateKeyHandover,
        response: &MakerToTakerMessage,
    ) -> Result<(), MakerError> {
        let mut completed = lock_debug!(self.completed_handovers.lock())?;
        completed.retain(|_, handover| handover.completed_at.elapsed() < COMPLETED_HANDOVER_TTL);
        completed.insert(
            request.id.clone(),
            CompletedHandover {
                protocol,
                request,
                response: response.clone(),
                completed_at: Instant::now(),
            },
        );
        Ok(())
    }

    /// Builds the Lightning backend from config, if configured. Shared with
    /// the taker so a fix to one reaches both.
    #[cfg(feature = "lightning")]
    fn init_lightning_backend(
        config: &MakerServerConfig,
    ) -> Option<std::sync::Arc<dyn crate::lightning::LightningBackend>> {
        crate::lightning::backend_from_settings(
            config.ldk_server_url.as_ref(),
            config.ldk_api_key_path.as_ref(),
            config.ldk_tls_cert_path.as_ref(),
            config.network,
        )
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

    /// A backend connection of its own for a bond wait, built from config so
    /// no connect or poll holds the wallet guard. A failed connect is retried
    /// like a failed poll.
    fn bond_chain(&self) -> Result<AnyBlockchain, MakerError> {
        loop {
            match AnyBlockchain::from_config_with_shutdown(
                &self.config.backend,
                self.shutdown.backend_flag(),
            ) {
                Ok(chain) => return Ok(chain),
                Err(e) => log::warn!(
                    "[{}] Could not connect to the backend for the bond wait: {:?}",
                    self.config.network_port,
                    e
                ),
            }
            if !self.wait_for_shutdown(BOND_POLL_INTERVAL) {
                return Err(MakerError::General("Shutdown requested"));
            }
        }
    }

    /// Checks once on `chain` whether the bond at `index` confirmed,
    /// rebroadcasting it if the backend has lost it. A backend error reads as "not yet".
    fn check_bond_confirmation(
        &self,
        index: u32,
        chain: &AnyBlockchain,
    ) -> Result<Option<u32>, MakerError> {
        let bond = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .store
            .fidelity_bond
            .get(index as usize)
            .cloned();
        let checked = bond
            .ok_or(WalletError::Fidelity(FidelityError::BondDoesNotExist))
            .and_then(|bond| bond.ensure_broadcast(chain))
            .and_then(|txid| chain.tx_block_height(&txid))
            .and_then(|height| {
                height
                    .map(|h| {
                        u32::try_from(h).map_err(|_| {
                            WalletError::General(format!("Bond height {h} is out of range"))
                        })
                    })
                    .transpose()
            });
        match checked {
            // A broken bond record never heals; anything else is the backend.
            Err(e @ WalletError::Fidelity(_)) => Err(MakerError::Wallet(e)),
            Err(e) => {
                log::warn!(
                    "[{}] Could not check fidelity bond {}: {:?}",
                    self.config.network_port,
                    index,
                    e
                );
                Ok(None)
            }
            Ok(height) => Ok(height),
        }
    }

    /// Waits for the bond at `index` to confirm, with no deadline, and returns its height.
    fn wait_for_bond_confirmation(&self, index: u32) -> Result<u32, MakerError> {
        let chain = self.bond_chain()?;
        loop {
            if let Some(height) = self.check_bond_confirmation(index, &chain)? {
                return Ok(height);
            }
            log::info!(
                "[{}] Fidelity bond {} not confirmed yet, checking again in {}s",
                self.config.network_port,
                index,
                BOND_POLL_INTERVAL.as_secs()
            );
            if !self.wait_for_shutdown(BOND_POLL_INTERVAL) {
                return Err(MakerError::General("Shutdown requested"));
            }
        }
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
    /// here prevents that. Pending bonds are checked together, and once any
    /// bond is live the rest get one check each; the renewal loop checks again.
    fn finalize_pending_fidelity_bonds(&self, mut live_bond: bool) -> Result<(), MakerError> {
        // Snapshot the pending bonds once: an unrecoverable bond stays
        // pending in the wallet, so re-finding inside the loop would spin
        // on it forever.
        let mut pending: Vec<(u32, bitcoin::Txid)> = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .store
            .fidelity_bond
            .iter()
            .filter(|b| !b.is_spent && b.conf_height.is_none())
            .map(|b| (b.bond_index, b.outpoint.txid))
            .collect();
        if !live_bond {
            for (_, txid) in &pending {
                log::info!(
                    "[{}] Found unconfirmed fidelity bond {}, waiting for confirmation instead of creating a new one",
                    self.config.network_port,
                    txid
                );
            }
        }

        if pending.is_empty() {
            return Ok(());
        }
        let chain = self.bond_chain()?;
        while !pending.is_empty() {
            let mut unconfirmed = Vec::new();
            for (index, txid) in pending {
                match self.check_bond_confirmation(index, &chain) {
                    Ok(Some(conf_height)) => {
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
                        live_bond = true;
                    }
                    Ok(None) => unconfirmed.push((index, txid)),
                    // The bond was evicted and there is no stored transaction to
                    // rebroadcast: it can never confirm. Losing the bond must not
                    // take the maker down — log it and start up anyway.
                    Err(MakerError::Wallet(WalletError::Fidelity(
                        FidelityError::BondTransactionMissing { .. },
                    ))) => {
                        log::error!(
                            "[{}] Pending fidelity bond {} was evicted and has no stored transaction; \
                             it is unrecoverable. Skipping it and continuing startup.",
                            self.config.network_port,
                            txid
                        );
                    }
                    Err(e) => return Err(e),
                }
            }
            pending = unconfirmed;
            if live_bond {
                for (_, txid) in &pending {
                    log::info!(
                        "[{}] Fidelity bond {} still unconfirmed; advertising the live bond meanwhile",
                        self.config.network_port,
                        txid
                    );
                }
                break;
            }
            if !pending.is_empty() && !self.wait_for_shutdown(BOND_POLL_INTERVAL) {
                return Err(MakerError::General("Shutdown requested"));
            }
        }
        Ok(())
    }

    /// Setup fidelity bond for this maker.
    pub fn setup_fidelity_bond(&self, maker_address: &str) -> Result<FidelityProof, MakerError> {
        use bitcoin::absolute::LockTime;

        // Adopt any bond that was broadcast but not yet confirmed (e.g. the
        // maker shut down while waiting for confirmation) before deciding
        // whether a new bond is needed.
        let live_bond = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .has_live_fidelity_bond()
            .map_err(MakerError::Wallet)?;
        // A just-redeemed bond must not stay advertised while a new one confirms.
        if !live_bond {
            *lock_debug!(self.highest_fidelity_proof.write())
                .map_err(|_| MakerError::General("Failed to lock fidelity proof"))? = None;
        }
        self.finalize_pending_fidelity_bonds(live_bond)?;

        let highest_index = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .get_highest_fidelity_index()
            .map_err(MakerError::Wallet)?;

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

            *lock_debug!(self.highest_fidelity_proof.write())
                .map_err(|_| MakerError::General("Failed to lock fidelity proof"))? =
                Some(highest_proof);
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
            const SYNC_INTERVAL: Duration = Duration::from_secs(10);
            // One address for the whole wait, so each retry doesn't burn a new one.
            let addr = lock_debug!(self.wallet.write())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?
                .get_next_external_address(AddressType::P2TR)
                .map_err(MakerError::Wallet)?;

            while !self.shutdown.load(Ordering::Relaxed) {
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
                            // Bond change must also fund the first swap and stay at our minimum
                            // swap size, or the liquidity check right after keeps us off the market.
                            let (op_return_len, swap_feerate) = {
                                let wallet = lock_debug!(self.wallet.read())
                                    .map_err(|_| MakerError::General("Failed to lock wallet"))?;
                                let op_return = wallet
                                    .encode_fidelity_op_return(maker_address, locktime)
                                    .map_err(MakerError::Wallet)?;
                                let rate = match wallet
                                    .blockchain
                                    .estimate_feerate(FeePriority::Urgent)
                                {
                                    Ok(rate) if rate.is_finite() => rate.max(MIN_RELAY_FEE_RATE),
                                    other => {
                                        log::error!("Fee estimation for urgent priority failed, using the relay floor: {other:?}");
                                        MIN_RELAY_FEE_RATE
                                    }
                                };
                                (op_return.len() as u64, rate)
                            };
                            // Coin selection priced only the bond output and coins we hold. The tx
                            // also carries the OP_RETURN, P2TR change and the deposit as a P2TR input.
                            let unpriced_vsize = ((11 + op_return_len + 43) * 4 + 230).div_ceil(4);
                            let needed =
                                fee_at_rate_sats(unpriced_vsize, self.config.fidelity_feerate)
                                    .zip(funding_fee_policy_sats(1, 1, swap_feerate))
                                    .and_then(|(bond_fee, swap_fee)| {
                                        (required - available)
                                            .checked_add(bond_fee)?
                                            .checked_add(swap_fee)?
                                            .checked_add(min_swap_amount(&self.config))
                                    })
                                    .ok_or(MakerError::General(
                                        "Fee settings cannot price the fidelity funding amount",
                                    ))?;
                            log::info!(
                                "Send at least {:.8} BTC to {:?} (fidelity bond + fees + minimum swap liquidity) to be visible in the market",
                                Amount::from_sat(needed).to_btc(),
                                addr
                            );

                            log::info!("Next sync in {} secs", SYNC_INTERVAL.as_secs());
                            if !self.wait_for_shutdown(SYNC_INTERVAL) {
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
                        log::info!(
                            "[{}] Fidelity bond broadcast, waiting for confirmation: {}",
                            self.config.network_port,
                            txid
                        );
                        let conf_height = self.wait_for_bond_confirmation(index)?;

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

                        // Locked only to write: held across the bond wait it blocks every reader.
                        *lock_debug!(self.highest_fidelity_proof.write())
                            .map_err(|_| MakerError::General("Failed to lock fidelity proof"))? =
                            Some(highest_proof);

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

        lock_debug!(self.highest_fidelity_proof.read())
            .map_err(|_| MakerError::General("Failed to lock fidelity proof"))?
            .clone()
            .ok_or(MakerError::General("No fidelity proof after setup"))
    }

    /// Check if maker has enough liquidity for swaps.
    pub fn check_swap_liquidity(&self) -> Result<(), MakerError> {
        const SYNC_INTERVAL: Duration = Duration::from_secs(10);

        let addr = lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .get_next_external_address(AddressType::P2TR)
            .map_err(MakerError::Wallet)?;

        // Fee settings no amount can pay would otherwise wait here forever.
        let min_required = min_swap_amount(&self.config);
        if min_required == u64::MAX {
            return Err(MakerError::General(
                "Fee settings cannot price a minimum swap amount",
            ));
        }

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

            if offer_max_size < min_required {
                log::warn!(
                    "Low Swap Liquidity | Min: {min_required} sats | Available: {offer_max_size} sats. Add funds to {addr:?}"
                );

                log::info!("Next sync in {} secs", SYNC_INTERVAL.as_secs());
                if !self.wait_for_shutdown(SYNC_INTERVAL) {
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

        // An unfunded swap holds no coins and nothing on-chain, so once idle it
        // is dropped without recovery.
        let unfunded_ids: Vec<String> = swaps
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
                (state.last_activity.elapsed() > timeout).then(|| id.clone())
            })
            .collect();
        for id in &unfunded_ids {
            swaps.remove(id);
            log::info!(
                "[{}] Released idle unfunded swap {}",
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
        // A swap can claim its coins just before its state stops reading as
        // unfunded; never leave that claim behind with the dropped entry.
        {
            let mut wallet = lock_debug!(self.wallet.write())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;
            let mut freed = false;
            for id in &unfunded_ids {
                freed |= wallet.release_swap_locks(id, None);
            }
            if freed {
                wallet.save_to_disk().map_err(MakerError::Wallet)?;
            }
        }

        Ok(idle)
    }

    /// After a restart nothing in memory owns a reservation. Keep one only while
    /// a tracker record, saved swapcoins or a Lightning swap still points at it.
    pub(crate) fn release_orphan_reservations(&self) -> Result<(), MakerError> {
        let tracked: HashSet<String> = lock_debug!(self.swap_tracker.lock())
            .map_err(|_| MakerError::MutexPossion)?
            .incomplete_swaps()
            .into_iter()
            .map(|record| record.swap_id.clone())
            .collect();
        let mut wallet = lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        let (incoming, outgoing) = wallet.find_unfinished_swapcoins();
        let owned: HashSet<String> = incoming
            .iter()
            .filter_map(|sc| sc.swap_id.clone())
            .chain(outgoing.iter().filter_map(|sc| sc.swap_id.clone()))
            .chain(wallet.store.ln_maker_swaps.keys().cloned())
            .chain(tracked)
            .collect();
        let orphans: Vec<String> = wallet
            .store
            .swap_locks
            .keys()
            .filter(|id| !owned.contains(*id))
            .cloned()
            .collect();
        for id in &orphans {
            log::info!(
                "[{}] Releasing reservation of swap {}: nothing left owns it",
                self.config.network_port,
                id
            );
            wallet.release_swap_locks(id, None);
        }
        if !orphans.is_empty() {
            wallet.save_to_disk().map_err(MakerError::Wallet)?;
        }
        Ok(())
    }

    /// Remove a completed swap's entry from `ongoing_swaps`.
    pub fn remove_swap_state(&self, swap_id: &str) -> Result<(), MakerError> {
        lock_debug!(self.ongoing_swaps.lock())
            .map_err(|_| MakerError::MutexPossion)?
            .remove(swap_id);
        // The swap is over; any reservation it still holds ends with it.
        let mut wallet = lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        if wallet.release_swap_locks(swap_id, None) {
            wallet.save_to_disk().map_err(MakerError::Wallet)?;
        }
        Ok(())
    }

    /// Check if any swaps are currently in progress.
    pub fn has_ongoing_swaps(&self) -> Result<bool, MakerError> {
        Ok(!lock_debug!(self.ongoing_swaps.lock())
            .map_err(|_| MakerError::MutexPossion)?
            .is_empty())
    }

    /// Outpoints this maker still holds reserved for in-flight swaps.
    #[cfg(feature = "integration-test")]
    pub fn reserved_inputs(&self) -> Result<usize, MakerError> {
        Ok(lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .reserved_inputs())
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

    /// The signed outgoing contract txs of `swap_id`, so a test can publish
    /// one after the maker withheld it.
    #[cfg(feature = "integration-test")]
    pub fn outgoing_contract_txs(&self, swap_id: &str) -> Result<Vec<Transaction>, MakerError> {
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        let (_, outgoing) = wallet.find_unfinished_swapcoins();
        Ok(outgoing
            .into_iter()
            .filter(|coin| coin.swap_id.as_deref() == Some(swap_id))
            .map(|coin| coin.contract_tx)
            .collect())
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
        let min_kept = swap_cost_floor(
            state.protocol,
            state.swap_feerate,
            state.incoming_count,
            state.max_input_budget,
        )
        .ok_or(MakerError::General("Swap floor cannot be priced"))?;
        // `min_kept` already covers the sweeps, so the subtraction cannot underflow.
        let forwardable = state
            .swap_amount
            .to_sat()
            .checked_sub(state.service_fee_sats)
            .filter(|kept| *kept >= min_kept)
            .ok_or(MakerError::General(
                "Swap amount below the minimum for its shape",
            ))?
            - sweep_fee;
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        let shortfall = || MakerError::InsufficientLiquidity {
            available: wallet.plannable_balance(),
            required: Amount::from_sat(forwardable),
        };
        // Netting can push a split under the floor where fewer, larger splits
        // would pass, so retry one split fewer, re-planning from scratch.
        let mut max_splits = state.tx_count;
        loop {
            let mut plan = wallet
                .plan_funding(
                    Amount::from_sat(forwardable),
                    max_splits,
                    state.swap_feerate,
                    state.max_input_budget,
                    Some(state.service_fee_sats),
                    None,
                    None,
                    state.protocol,
                )
                .map_err(|e| {
                    log::warn!(
                        "[{}] Rejecting swap at admission: cannot fund {} sats forwardable: {:?}",
                        self.config.network_port,
                        forwardable,
                        e
                    );
                    match e {
                        WalletError::InsufficientFund { .. } => shortfall(),
                        other => MakerError::Wallet(other),
                    }
                })?;
            // Forwarding nets the taker-reimbursed fee out of each split; one
            // split the netting still pushes below the floor is a refusal.
            let priced: Vec<usize> = plan.iter().map(|split| split.utxos.len()).collect();
            match net_policy_fees(
                &mut plan,
                &priced,
                state.max_input_budget,
                state.swap_feerate,
                state.protocol,
            ) {
                Ok(()) => return Ok(plan),
                Err(_) if plan.len() > 1 => max_splits = plan.len() as u32 - 1,
                Err(e) => {
                    log::warn!(
                        "[{}] Rejecting swap at admission: policy netting failed: {:?}",
                        self.config.network_port,
                        e
                    );
                    return Err(shortfall());
                }
            }
        }
    }

    /// The funding plan frozen at admission. `amount` must equal the plan's
    /// pre-netting total: the frozen values plus each split's policy fee,
    /// derived from the plan shape at the negotiated rate. A missing or
    /// mismatched plan is a protocol error.
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

    /// Claim the plan's coins, then build and sign one funding tx per split; a
    /// rebuild reuses the plan it claimed before. `gross` is the plan's
    /// pre-netting total. A build failure releases the whole reservation.
    fn execute_frozen_plan(
        &self,
        swap_id: &str,
        plan: &[SplitPlan],
        gross: Amount,
        addresses: &[bitcoin::Address],
        feerate: f64,
    ) -> Result<(Vec<Transaction>, Vec<u32>, u64), MakerError> {
        // Malice hook: build every split at the relay floor while the taker
        // reimburses the negotiated rate; its real-fee check must catch the
        // shortfall.
        #[cfg(feature = "integration-test")]
        let feerate = if self.behavior() == MakerBehavior::UnderpayFundingFee {
            MIN_RELAY_FEE_RATE
        } else {
            feerate
        };

        // Once a swap has claimed coins, every later pass reuses exactly that
        // claim: some of its funding may be out, or a concurrent pass may be
        // building from it. The lock makes the check and the claim one step.
        let _claiming =
            lock_debug!(self.funding_claims.lock()).map_err(|_| MakerError::MutexPossion)?;
        let (claimed, terms, service_fee) = {
            let swaps =
                lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
            let state = swaps
                .get(swap_id)
                .ok_or(MakerError::General("No stored state for this swap"))?;
            (
                (!state.claimed_plan.is_empty()).then(|| state.claimed_plan.clone()),
                state.negotiated,
                state.service_fee_sats,
            )
        };
        let fresh = claimed.is_none();

        // Coins are claimed only now, once the previous party's funding has
        // confirmed: an admission alone costs the taker nothing.
        let plan = {
            let mut wallet = lock_debug!(self.wallet.write())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;
            let inputs = |plan: &[SplitPlan]| -> Vec<OutPoint> {
                plan.iter()
                    .flat_map(|split| split.utxos.iter().copied())
                    .collect()
            };
            #[cfg(feature = "integration-test")]
            let stand_in = (self.behavior() == MakerBehavior::ForceReplan)
                .then(|| format!("{swap_id}-stand-in"));
            #[cfg(feature = "integration-test")]
            if let Some(key) = &stand_in {
                wallet.reserve_swap_locks(key, &inputs(plan));
            }
            let selected = if let Some(claimed) = claimed {
                let held = wallet.store.swap_locks.get(swap_id).is_some_and(|locks| {
                    inputs(&claimed)
                        .iter()
                        .all(|input| locks.outpoints.contains(input))
                });
                if held {
                    Ok(claimed)
                } else {
                    Err(MakerError::General(
                        "Funding was already built; refusing to fund from other coins",
                    ))
                }
            } else if wallet.claim_swap_inputs(swap_id, &inputs(plan)) {
                Ok(plan.to_vec())
            } else {
                replan_funding(&wallet, &terms, service_fee, plan, gross).and_then(|replanned| {
                    if !wallet.claim_swap_inputs(swap_id, &inputs(&replanned)) {
                        return Err(MakerError::General(
                            "Re-planned funding inputs are not free",
                        ));
                    }
                    log::info!(
                        "[{}] Re-planned funding for swap {}: a planned coin went to another swap",
                        self.config.network_port,
                        swap_id
                    );
                    Ok(replanned)
                })
            };
            // Released before any error returns, or the stand-in leaks its coins.
            #[cfg(feature = "integration-test")]
            if let Some(key) = &stand_in {
                wallet.release_swap_locks(key, None);
            }
            let plan = selected?;
            if fresh {
                if let Err(e) = wallet.save_to_disk() {
                    wallet.release_swap_locks(swap_id, None);
                    return Err(MakerError::Wallet(e));
                }
            }
            plan
        };
        if fresh {
            let mut swaps =
                lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
            if let Some(state) = swaps.get_mut(swap_id) {
                state.claimed_plan = plan.clone();
            } else {
                drop(swaps);
                // The idle drain dropped the swap while we claimed, so nothing
                // would ever release this claim.
                let mut wallet = lock_debug!(self.wallet.write())
                    .map_err(|_| MakerError::General("Failed to lock wallet"))?;
                wallet.release_swap_locks(swap_id, None);
                wallet.save_to_disk().map_err(MakerError::Wallet)?;
                return Err(MakerError::General(
                    "Swap plan expired; the taker must send new SwapDetails",
                ));
            }
        }
        drop(_claiming);
        #[cfg(feature = "integration-test")]
        if self.behavior() == MakerBehavior::AbandonFundingClaim {
            log::warn!(
                "[{}] Test behavior: abandoning the funding claim",
                self.config.network_port
            );
            return Err(MakerError::General("Test: abandoning the funding claim"));
        }

        let mut funding_txes = Vec::with_capacity(plan.len());
        let mut payment_output_positions = Vec::with_capacity(plan.len());
        let mut total_miner_fee = 0u64;
        // One wallet lock per split, not per batch: holding it across one
        // RPC-and-sign per split stalls every other connection.
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
                    total_miner_fee += result.total_miner_fee;
                    funding_txes.extend(result.funding_txes);
                    payment_output_positions.extend(result.payment_output_positions);
                }
                Err(e) => {
                    if let Ok(mut wallet) = lock_debug!(self.wallet.write()) {
                        // Persist it: `swap_locks` is restored from disk, so an
                        // unsaved release comes back as a stale reservation.
                        if wallet.release_swap_locks(swap_id, None) {
                            let _ = wallet.save_to_disk();
                        }
                    }
                    // The claim is gone, so the next pass must claim afresh.
                    if let Some(state) = lock_debug!(self.ongoing_swaps.lock())
                        .map_err(|_| MakerError::MutexPossion)?
                        .get_mut(swap_id)
                    {
                        state.claimed_plan.clear();
                    }
                    return Err(MakerError::Wallet(e));
                }
            }
        }
        Ok((funding_txes, payment_output_positions, total_miner_fee))
    }
    /// Injects a Lightning backend (tests only): lets integration tests run
    /// the full swap stack against a mock Lightning node.
    #[cfg(all(feature = "integration-test", feature = "lightning"))]
    pub fn set_lightning_backend(
        &mut self,
        backend: std::sync::Arc<dyn crate::lightning::LightningBackend>,
    ) {
        let router = super::lightning_handlers::LnEventRouter::new(std::sync::Arc::clone(&backend));
        // Mirror init: swaps restored before the backend existed still need
        // their mailboxes, or their settlement events would be dropped.
        if let Ok(swaps) = self.ln_swaps.lock() {
            for swap in swaps.values() {
                router.subscribe(swap.payment_hash);
            }
        }
        self.ln_router = Some(router);
        self.lightning = Some(backend);
    }

    /// Lightning swap terms for the offer, derived from the coinswap fee
    /// schedule and the node's live liquidity. `None` when no backend is
    /// configured (or the build has no lightning support), which keeps the
    /// field out of the offer entirely.
    #[cfg(not(feature = "lightning"))]
    fn lightning_offer(&self) -> Option<crate::protocol::lightning_messages::LightningOffer> {
        None
    }

    /// See the non-lightning variant.
    #[cfg(feature = "lightning")]
    fn lightning_offer(&self) -> Option<crate::protocol::lightning_messages::LightningOffer> {
        // Serve a recent answer if we have one: `get_config` is on the path
        // of every coinswap message, and recomputing means a gRPC call to
        // the sidecar each time. Capacity that goes stale within the window
        // only costs a later rejection, never safety — the funding and
        // payment steps fail closed on their own.
        if let Ok(cache) = lock_debug!(self.ln_offer_cache.lock()) {
            if let Some((computed_at, offer)) = cache.as_ref() {
                if computed_at.elapsed() < LN_OFFER_TTL {
                    return *offer;
                }
            }
        }
        let offer = self.compute_lightning_offer();
        if let Ok(mut cache) = lock_debug!(self.ln_offer_cache.lock()) {
            *cache = Some((Instant::now(), offer));
        }
        offer
    }

    /// Derives the Lightning offer from live node and wallet state.
    #[cfg(feature = "lightning")]
    fn compute_lightning_offer(
        &self,
    ) -> Option<crate::protocol::lightning_messages::LightningOffer> {
        let ln = self.lightning.as_ref()?;
        // Each direction draws on a different resource, so they are sized
        // separately from live channel state rather than from one balance.
        let channels = match ln.list_channels() {
            Ok(channels) => channels,
            Err(e) => {
                log::warn!("lightning channels unavailable, omitting LN offer: {e:?}");
                return None;
            }
        };
        // A wallet we cannot read means no on-chain capacity we can promise,
        // which disables swap-outs rather than advertising an unbounded one.
        let wallet_max = lock_debug!(self.wallet.read())
            .map(|w| w.store.offer_maxsize)
            .unwrap_or(0);
        let capacity = super::lightning_handlers::directional_limits(
            &channels,
            wallet_max,
            min_swap_amount(&self.config),
        );
        if !capacity.swap_in && !capacity.swap_out {
            return None;
        }
        Some(crate::protocol::lightning_messages::LightningOffer {
            swap_in: capacity.swap_in,
            swap_out: capacity.swap_out,
            base_fee: self.config.base_fee,
            amount_relative_fee_pct: self.config.amount_relative_fee_pct,
            min_size: min_swap_amount(&self.config),
            max_swap_in: capacity.max_swap_in,
            max_swap_out: capacity.max_swap_out,
        })
    }
}

/// True when a swap other than `except_swap_id` already holds one of `txids`,
/// whether it claimed them up front or carries them on a live swapcoin.
fn live_swap_holds(
    swaps: &HashMap<String, SwapState>,
    except_swap_id: &str,
    txids: &[Txid],
) -> bool {
    swaps.iter().any(|(id, state)| {
        id.as_str() != except_swap_id
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
    })
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
            min_swap_amount: min_swap_amount(&self.config),
            max_swap_amount: lock_debug!(self.wallet.read())
                .map(|w| w.store.offer_maxsize)
                .unwrap_or(u64::MAX),
            required_confirms: self.config.required_confirms,
            supported_protocols: self.config.supported_protocols.clone(),
            name: self.config.name.clone(),
        }
    }

    fn lightning_offer(&self) -> Option<crate::protocol::lightning_messages::LightningOffer> {
        MakerServer::lightning_offer(self)
    }

    fn validate_swap_parameters(&self, details: &SwapDetails) -> Result<u16, MakerError> {
        use super::handlers::offset_meets_reaction_time;

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
        // Every incoming contract must be worth recovering at the swap feerate.
        let contract_floor =
            min_contract_value_sats(details.protocol_version, details.feerate as f64)
                .ok_or(MakerError::General("Contract floor cannot be priced"))?;
        if amount_sat < contract_floor.saturating_mul(details.incoming_count as u64) {
            return Err(MakerError::General(
                "Swap amount below the incoming contract floor",
            ));
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

        let (funding_txes, payment_output_positions, _) =
            self.execute_frozen_plan(swap_id, &plan, amount, addresses, feerate)?;
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
    fn wait_for_txs_on_chain(
        &self,
        swap_id: &str,
        txids: &[bitcoin::Txid],
        required_confirms: u32,
    ) -> Result<(), MakerError> {
        log::info!(
            "[{}] Waiting for {} confirmation(s) on tx batch of {}",
            self.config.network_port,
            required_confirms,
            txids.len()
        );
        let chain = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .blockchain
            .new_connection()
            .map_err(MakerError::Wallet)?;
        // The wait can outlast the idle-drain timeout, so the per-poll hook
        // refreshes this swap's stored activity: a live handler never drains.
        // If the swap is gone anyway, the wait stops.
        let keep_alive = || {
            if let Ok(mut swaps) = lock_debug!(self.ongoing_swaps.lock()) {
                if let Some(state) = swaps.get_mut(swap_id) {
                    state.last_activity = Instant::now();
                    return false;
                }
            }
            true
        };
        crate::wallet::wait_for_tx_confirmation(
            &chain,
            txids,
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

    fn screen_funding_tx(&self, tx: &Transaction) -> Result<(), MakerError> {
        if !self.config.check_blocklist {
            return Ok(());
        }

        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        crate::blocklist::screen_funding_tx(&self.data_dir, self.config.network, &wallet, tx)
            .map_err(MakerError::Blocklist)
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
            if wallet.release_swap_locks(swap_id, Some(&spent_inputs)) {
                wallet.save_to_disk().map_err(MakerError::Wallet)?;
            }
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
        let live_hit = live_swap_holds(&swaps, except_swap_id, &[*txid]);
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
            .outgoing_contract_outpoints(None)
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
        let claimed_elsewhere = live_swap_holds(&swaps, swap_id, txids);
        if claimed_elsewhere {
            return Err(MakerError::General("Contract txid already in use"));
        }
        let state = swaps
            .get_mut(swap_id)
            .ok_or(MakerError::General("No stored state for this swap"))?;
        // A retry re-sends the same contracts. A different list would drop the
        // first claim while its handler still holds those contracts, freeing
        // them for another swap to claim.
        if !state.claimed_incoming_txids.is_empty() && state.claimed_incoming_txids != txids {
            return Err(MakerError::General("Contract txids differ from the claim"));
        }
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

    fn get_raw_transaction(&self, txid: &bitcoin::Txid) -> Result<Transaction, MakerError> {
        let chain = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .blockchain
            .new_connection()
            .map_err(MakerError::Wallet)?;
        let transaction = chain
            .get_raw_transaction(txid, None)
            .map_err(MakerError::Wallet)?;
        if transaction.compute_txid() != *txid {
            return Err(MakerError::General(
                "backend returned an unexpected transaction",
            ));
        }
        Ok(transaction)
    }

    fn sweep_incoming_swapcoins(
        &self,
        incoming_swapcoins: &[IncomingSwapCoin],
    ) -> Result<RecoveryOutcome, MakerError> {
        #[cfg(feature = "integration-test")]
        if self.behavior() == MakerBehavior::FailSweep {
            return Err(MakerError::General("Test: sweep failed"));
        }
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
        let contract_txids = incoming_swapcoins
            .iter()
            .map(|swapcoin| swapcoin.contract_tx.compute_txid())
            .collect();
        let sweep_outcome = Wallet::sweep_incoming_swapcoins(
            &self.wallet,
            &chain,
            &self.shutdown,
            Some(&contract_txids),
        )
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

        Ok(sweep_outcome)
    }

    fn finalize_successful_swap(
        &self,
        swap_id: &str,
        expected_outgoing: usize,
    ) -> Result<(), MakerError> {
        let outgoing_keys = {
            let wallet = lock_debug!(self.wallet.read())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;
            let outgoing_keys = wallet.outgoing_keys_for_swap(swap_id);
            if outgoing_keys.len() != expected_outgoing {
                return Err(MakerError::General(
                    "persisted outgoing swapcoin count does not match completed swap",
                ));
            }
            outgoing_keys
        };

        {
            let mut wallet = lock_debug!(self.wallet.write())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;
            for key in &outgoing_keys {
                wallet.remove_outgoing_swapcoin(key);
            }
            wallet.release_swap_locks(swap_id, None);
            wallet.save_to_disk().map_err(MakerError::Wallet)?;
        }

        {
            let mut tracker =
                lock_debug!(self.swap_tracker.lock()).map_err(|_| MakerError::MutexPossion)?;
            if let Some(record) = tracker.get_record_mut(swap_id) {
                record.phase = MakerSwapPhase::Completed;
                record.recovery.phase = MakerRecoveryPhase::CleanedUp;
                record.updated_at = now_secs();
                let completed = record.clone();
                tracker.save_record(&completed)?;
            }
        }

        log::info!(
            "[{}] Finalized successful swap {} and removed {} outgoing swapcoin(s)",
            self.config.network_port,
            swap_id,
            outgoing_keys.len()
        );
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
            let mismatched = swap_state.negotiated != NegotiatedTerms::from(state);
            if !mismatched {
                swap_state.last_activity = Instant::now();
            }
            drop(swaps);
            if mismatched {
                log::warn!(
                    "[{}] Rejecting duplicate SwapDetails for {}: parameters differ from stored swap",
                    self.config.network_port,
                    swap_id,
                );
                return Err(MakerError::SwapParamMismatch);
            }
            return Ok(());
        }
        // Planning was skipped for a live swap that a drain has since removed.
        // Nothing is funded yet, so refusing beats storing this handler's empty plan.
        if admission && planned.is_none() {
            return Err(MakerError::General(
                "Swap expired while admitting; resend SwapDetails",
            ));
        }

        // The cap read before planning is only a cheap early reject: planning
        // runs unlocked, so racing admissions with distinct ids can all clear
        // it. Only a re-check under the guard that inserts actually binds.
        if planned.is_some()
            && swaps
                .values()
                .filter(|state| state.phase != SwapPhase::Completed)
                .count()
                >= MAX_CONCURRENT_SWAPS
        {
            drop(swaps);
            log::warn!(
                "[{}] Rejecting swap {}: the {} cap filled while we planned",
                self.config.network_port,
                swap_id,
                MAX_CONCURRENT_SWAPS,
            );
            return Err(MakerError::TooManySwaps);
        }

        // Only the admission a connection holds may write: a store for a drained
        // swap, or from an older admission of a reused id, would revive a stale
        // plan. A completed swap is removed before settling and may be put back.
        let stale = match swaps.get(swap_id) {
            Some(stored) => stored.swap_start_time != state.swap_start_time,
            None => state.phase != SwapPhase::Completed,
        };
        if !admission && stale {
            log::warn!(
                "[{}] Rejecting late message for swap {}: its plan expired",
                self.config.network_port,
                swap_id
            );
            return Err(MakerError::General(
                "Swap plan expired; the taker must send new SwapDetails",
            ));
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
        drop(swaps);

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

    fn touch_connection_state(&self, swap_id: &str) -> Result<(), MakerError> {
        let mut swaps =
            lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
        if let Some(state) = swaps.get_mut(swap_id) {
            state.last_activity = Instant::now();
        }
        Ok(())
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
        // No funding named yet: a later hop waits on upstream funding it cannot
        // see, so its keepalive still counts.
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

    fn incoming_contract_breached(&self, swap_id: &str) -> Result<Option<Txid>, MakerError> {
        use crate::watch_tower::{watcher::WatcherEvent, watcher_error::WatcherError};

        let funding_outpoints: Vec<OutPoint> = {
            let swaps =
                lock_debug!(self.ongoing_swaps.lock()).map_err(|_| MakerError::MutexPossion)?;
            let Some(state) = swaps.get(swap_id) else {
                return Ok(None);
            };
            if state.negotiated.protocol != ProtocolVersion::Legacy {
                return Ok(None);
            }
            state
                .incoming_swapcoins
                .iter()
                .filter_map(super::legacy_handlers::funding_watch)
                .map(|(outpoint, _)| outpoint)
                .collect()
        };

        for funding_outpoint in funding_outpoints {
            let spender = match self.watch_service.watch_request(funding_outpoint) {
                // A watched outpoint with no recorded spend replies `spending_tx: None`.
                Ok(WatcherEvent::UtxoSpent { spending_tx, .. }) => {
                    spending_tx.map(|tx| tx.compute_txid())
                }
                // `NoOutpoint` means the watch armed at ProofOfFunding is gone; the
                // service already turns a watcher `Error` reply into `Err`.
                other => {
                    return Err(MakerError::Watcher(WatcherError::General(format!(
                        "breach query for funding {funding_outpoint} of swap {swap_id} failed: {other:?}"
                    ))));
                }
            };
            // Before the handover only the previous hop's pre-signed contract can
            // spend the 2-of-2, so any spend ends the swap.
            if let Some(spender) = spender {
                log::warn!(
                    "[{}] Incoming funding {} of swap {} spent by {}: incoming contract broadcast",
                    self.config.network_port,
                    funding_outpoint,
                    swap_id,
                    spender
                );
                return Ok(Some(spender));
            }
        }
        Ok(None)
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
            utill::redeemscript_to_scriptpubkey,
        };
        use bitcoin::{hashes::Hash, OutPoint};

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

        // Validate the cheap shape of every proof before waiting: a bad locktime
        // must cost the peer a rejection, not the whole confirmation window.
        let mut funding_txids = Vec::with_capacity(message.confirmed_funding_txes.len());
        for funding_info in &message.confirmed_funding_txes {
            let locktime = read_contract_locktime(&funding_info.contract_redeemscript)?;
            if locktime.saturating_sub(message.refund_locktime) < min_reaction_time {
                return Err(MakerError::General(
                    "Next hop locktime too close to current hop locktime",
                ));
            }
            let multisig_spk = redeemscript_to_scriptpubkey(&funding_info.multisig_redeemscript)?;
            let funding_output_index = funding_info
                .funding_tx
                .output
                .iter()
                .position(|o| o.script_pubkey == multisig_spk)
                .ok_or(MakerError::General("Funding output not found"))?
                as u32;
            let funding_txid = funding_info.funding_tx.compute_txid();
            // Each proof can be valid on its own, but repeating one outpoint makes
            // the maker count the same incoming value twice and fund excess outgoing.
            if !seen_outpoints.insert(OutPoint {
                txid: funding_txid,
                vout: funding_output_index,
            }) {
                return Err(MakerError::General("Duplicate funding outpoint"));
            }
            funding_txids.push(funding_txid);
        }

        // Check the funding txs are confirmed to required depth, one wait for the
        // whole batch. Same confirm source as the taproot path: the operator's
        // config, not a hardcoded 1.
        self.wait_for_txs_on_chain(&message.id, &funding_txids, self.config.required_confirms)?;

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

        let (funding_txes, payment_output_positions, total_miner_fee) = self.execute_frozen_plan(
            swap_id,
            &plan,
            send_amount,
            &openswap_addresses,
            contract_feerate,
        )?;

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

            let mut outgoing_swapcoin = OutgoingSwapCoin::new_legacy(
                my_multisig_privkey,
                other_multisig_pubkey,
                my_senders_contract_tx,
                contract_redeemscript,
                timelock_privkey,
                funding_amount,
                contract_feerate as u64,
            );
            outgoing_swapcoin.funding_tx = Some(my_funding_tx.clone());
            outgoing_swapcoins.push(outgoing_swapcoin);
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

    #[cfg(feature = "lightning")]
    fn lightning(&self) -> Option<std::sync::Arc<dyn crate::lightning::LightningBackend>> {
        self.lightning.clone()
    }

    #[cfg(feature = "lightning")]
    fn ln_router(&self) -> Option<std::sync::Arc<super::lightning_handlers::LnEventRouter>> {
        self.ln_router.clone()
    }

    #[cfg(feature = "lightning")]
    fn store_ln_swap(
        &self,
        swap_id: &str,
        swap: super::lightning_handlers::LnMakerSwap,
    ) -> Result<(), MakerError> {
        // Persist before the in-memory insert, and before the caller commits
        // anything of value. Every store precedes an irreversible step —
        // paying an invoice, funding an HTLC — so a crash in between must
        // still leave a record that can reach the money.
        {
            let mut wallet = lock_debug!(self.wallet.write())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;
            wallet
                .store
                .ln_maker_swaps
                .insert(swap_id.to_string(), swap.to_record());
            wallet.save_to_disk().map_err(MakerError::Wallet)?;
        }
        lock_debug!(self.ln_swaps.lock())
            .map_err(|_| MakerError::MutexPossion)?
            .insert(swap_id.to_string(), swap);
        Ok(())
    }

    #[cfg(feature = "lightning")]
    fn get_ln_swap(
        &self,
        swap_id: &str,
    ) -> Result<Option<super::lightning_handlers::LnMakerSwap>, MakerError> {
        Ok(lock_debug!(self.ln_swaps.lock())
            .map_err(|_| MakerError::MutexPossion)?
            .get(swap_id)
            .cloned())
    }

    #[cfg(feature = "lightning")]
    fn remove_ln_swap(&self, swap_id: &str) -> Result<(), MakerError> {
        lock_debug!(self.ln_swaps.lock())
            .map_err(|_| MakerError::MutexPossion)?
            .remove(swap_id);
        // Dropped from disk only after the swap is resolved; an interrupted
        // removal just leaves a record the next startup re-resolves. Any
        // inputs this swap reserved for its funding are freed here too, on
        // every resolution path.
        let mut wallet = lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        let removed = wallet.store.ln_maker_swaps.remove(swap_id).is_some();
        let released = wallet.release_swap_locks(swap_id, None);
        if removed || released {
            wallet.save_to_disk().map_err(MakerError::Wallet)?;
        }
        Ok(())
    }

    #[cfg(feature = "lightning")]
    fn is_tx_confirmed(&self, txid: &bitcoin::Txid) -> Result<bool, MakerError> {
        use crate::wallet::Blockchain;
        // `tx_block_height` already distinguishes "not in a block" from a
        // query failure, across both backends. Matching on an error string
        // would not: Core reports an unknown transaction as -5 while
        // Electrum reports it as a message under -32603.
        let height = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .blockchain
            .tx_block_height(txid)
            .map_err(MakerError::Wallet)?;
        Ok(height.is_some())
    }

    #[cfg(feature = "lightning")]
    fn is_htlc_spend_confirmed(
        &self,
        outpoint: &bitcoin::OutPoint,
        script: &bitcoin::ScriptBuf,
    ) -> Result<bool, MakerError> {
        use crate::wallet::Blockchain;
        lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .blockchain
            .is_confirmed_spend(outpoint, script)
            .map_err(MakerError::Wallet)
    }

    #[cfg(feature = "lightning")]
    fn htlc_unspent_and_age(
        &self,
        outpoint: &bitcoin::OutPoint,
    ) -> Result<(bool, u32), MakerError> {
        use crate::wallet::Blockchain;
        let wallet = lock_debug!(self.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        // Mempool included: a spend that is only in the mempool still means
        // the taker is taking this output back.
        let unspent = wallet
            .blockchain
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))
            .map_err(MakerError::Wallet)?
            .is_some();
        let tip = wallet
            .blockchain
            .get_block_count()
            .map_err(MakerError::Wallet)?;
        let confirmed_at = wallet
            .blockchain
            .tx_block_height(&outpoint.txid)
            .map_err(MakerError::Wallet)?;
        // An unconfirmed funding has aged zero blocks; the confirmation wait
        // is what decides whether that is acceptable.
        let age = confirmed_at
            .map(|height| tip.saturating_sub(height) as u32)
            .unwrap_or(0);
        Ok((unspent, age))
    }

    #[cfg(feature = "lightning")]
    fn wait_for_htlc_confirmation(
        &self,
        txid: &bitcoin::Txid,
        required_confirms: u32,
    ) -> Result<(), MakerError> {
        // Its own connection, so the wait does not pin the wallet lock.
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

    #[cfg(feature = "lightning")]
    fn fund_htlc(
        &self,
        swap_id: &str,
        amount: Amount,
        address: bitcoin::Address,
    ) -> Result<(Transaction, u32), MakerError> {
        let mut wallet = lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        let htlc_spk = address.script_pubkey();
        // The swap-out hold-window check promises the funding confirms
        // inside a fixed budget, so price it to actually do that. The relay
        // floor cannot keep that promise on a busy chain, and a funding that
        // confirms late moves the CSV refund past the Lightning deadline.
        let feerate = {
            use crate::wallet::Blockchain;
            match wallet.blockchain.estimate_feerate(FeePriority::High) {
                Ok(rate) if rate.is_finite() => rate.max(MIN_RELAY_FEE_RATE),
                other => {
                    log::warn!(
                        "lightning: no feerate estimate for high priority \
                         ({other:?}); funding at the relay floor"
                    );
                    MIN_RELAY_FEE_RATE
                }
            }
        };
        // One split, one destination, no taker-reimbursed input budget.
        let plan = wallet
            .plan_funding(
                amount,
                1,
                feerate,
                u32::MAX,
                None,
                None,
                None,
                // A Lightning HTLC is a script-path P2WSH contract, so it is
                // priced like the Legacy protocol's, not Taproot's.
                ProtocolVersion::Legacy,
            )
            .map_err(MakerError::Wallet)?;
        // Claim the selected inputs under this swap before executing, so a
        // concurrent coinswap admission plans around them instead of
        // selecting the same coins.
        let selected: Vec<_> = plan
            .iter()
            .flat_map(|split| split.utxos.iter().copied())
            .collect();
        wallet.reserve_swap_locks(swap_id, &selected);
        let result = wallet.execute_funding_plan(&plan, &[address], feerate);
        let result = match result {
            Ok(result) => result,
            Err(e) => {
                // Nothing was broadcast, so hand the coins back rather than
                // leaving them reserved for a swap that never funded.
                if wallet.release_swap_locks(swap_id, None) {
                    let _ = wallet.save_to_disk();
                }
                return Err(MakerError::Wallet(e));
            }
        };
        let tx = result
            .funding_txes
            .into_iter()
            .next()
            .ok_or(MakerError::General("No funding tx created"))?;
        // Locate the HTLC by its script rather than by position: a
        // positional fallback could point at the change output, which the
        // HTLC's keys cannot spend, and the swap would be unrefundable.
        let vout = tx
            .output
            .iter()
            .position(|output| output.script_pubkey == htlc_spk)
            .ok_or(MakerError::General("funding tx has no HTLC output"))? as u32;
        Ok((tx, vout))
    }

    #[cfg(feature = "lightning")]
    fn ln_swap_count(&self) -> usize {
        lock_debug!(self.ln_swaps.lock())
            .map(|swaps| swaps.len())
            .unwrap_or(0)
    }

    #[cfg(feature = "lightning")]
    fn get_receive_address(&self) -> Result<bitcoin::Address, MakerError> {
        let mut wallet = lock_debug!(self.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        wallet
            .get_next_external_address(crate::wallet::AddressType::P2WPKH)
            .map_err(MakerError::Wallet)
    }

    #[cfg(feature = "lightning")]
    fn shutdown_requested(&self) -> bool {
        self.is_shutdown()
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

    #[cfg(feature = "integration-test")]
    fn take_reserved_rpc_listener(&self) -> Option<TcpListener> {
        self.reserved_rpc_listener.lock().unwrap().take()
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
    use super::{
        min_swap_amount, swap_cost_floor, MakerError, MakerServer, MakerServerConfig,
        ShutdownSignal, ThreadPool, MIN_SWAP_STEP_SATS, REFUND_LOCKTIME_BASE,
    };
    use crate::{
        protocol::{contract::calculate_swap_fee, ProtocolVersion},
        utill::MIN_RELAY_FEE_RATE,
        wallet::{FidelityError, WalletError, MIN_FIDELITY_BOND_AMOUNT_SATS},
    };
    use std::{
        sync::{atomic::Ordering, mpsc, Arc, TryLockError},
        thread,
        time::{Duration, Instant},
    };

    /// Non-finite or below-minimum fidelity feerates clamp to the relay
    /// minimum; a valid value is kept. A plain `<` comparison would let
    /// `nan` through into the bond fee math. A name or fee percentage takers
    /// would refuse stops startup.
    /// A bond below the shared discovery floor must stop startup, not fund a
    /// bond no taker can find. The floor itself is exactly accepted.
    #[test]
    fn maker_config_rejects_fidelity_amount_below_the_discovery_floor() {
        let timelock = if cfg!(feature = "integration-test") {
            950
        } else {
            15_000
        };
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let resolve = |amount: u64| {
            std::fs::write(
                &path,
                format!("fidelity_timelock = {timelock}\nfidelity_amount = {amount}\n"),
            )
            .unwrap();
            MakerServerConfig::new(Some(&path))
        };

        // The value that silently stranded makers before this check.
        let err = resolve(1_000).unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Fidelity(FidelityError::BondAmountTooLow {
                    configured: 1_000,
                    minimum: MIN_FIDELITY_BOND_AMOUNT_SATS,
                })
            ),
            "{:?}",
            err
        );

        // Just under the floor is still refused; the floor itself is kept.
        assert!(resolve(MIN_FIDELITY_BOND_AMOUNT_SATS - 1).is_err());
        assert_eq!(
            resolve(MIN_FIDELITY_BOND_AMOUNT_SATS)
                .unwrap()
                .fidelity_amount,
            MIN_FIDELITY_BOND_AMOUNT_SATS
        );
        assert_eq!(
            resolve(MIN_FIDELITY_BOND_AMOUNT_SATS * 50)
                .unwrap()
                .fidelity_amount,
            MIN_FIDELITY_BOND_AMOUNT_SATS * 50
        );
    }

    #[test]
    fn maker_config_checks_file_values() {
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

        let path = dir.path().join("config.toml");
        for (name, accepted) in [
            ("é".repeat(32), true),
            ("x".repeat(33), false),
            (String::new(), false),
        ] {
            std::fs::write(
                &path,
                format!("fidelity_timelock = {timelock}\nname = \"{name}\"\n"),
            )
            .unwrap();
            assert_eq!(MakerServerConfig::new(Some(&path)).is_ok(), accepted);
        }

        // Fee percentages follow the rule takers apply to offers.
        for field in ["amount_relative_fee_pct", "time_relative_fee_pct"] {
            for (pct, accepted) in [
                ("0.0", true),
                ("99.9", true),
                ("-0.01", false),
                ("100.0", false),
                ("nan", false),
                ("inf", false),
            ] {
                std::fs::write(
                    &path,
                    format!("fidelity_timelock = {timelock}\n{field} = {pct}\n"),
                )
                .unwrap();
                assert_eq!(
                    MakerServerConfig::new(Some(&path)).is_ok(),
                    accepted,
                    "{field} = {pct}"
                );
            }
        }
        // A negative component is refused even when the sum stays positive.
        std::fs::write(
            &path,
            format!(
                "fidelity_timelock = {timelock}\n\
                 amount_relative_fee_pct = 1.0\n\
                 time_relative_fee_pct = -0.01\n"
            ),
        )
        .unwrap();
        assert!(MakerServerConfig::new(Some(&path)).is_err());
    }

    /// A config built in code never goes through `MakerServerConfig::new`,
    /// so `init` must refuse a bad fee percentage before touching the backend.
    #[test]
    fn maker_init_refuses_bad_fee_pcts() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        for (amount_pct, time_pct) in [(1.0, -0.01), (-1.0, 0.0), (f64::NAN, 0.0), (0.0, 100.0)] {
            let config = MakerServerConfig {
                data_dir: dir.path().join("maker"),
                amount_relative_fee_pct: amount_pct,
                time_relative_fee_pct: time_pct,
                ..Default::default()
            };
            assert!(
                matches!(
                    MakerServer::init(config),
                    Err(MakerError::Wallet(WalletError::General(_)))
                ),
                "{}, {}",
                amount_pct,
                time_pct
            );
        }
        assert!(!dir.path().join("maker").exists());
    }

    #[test]
    fn advertised_min_swap_is_the_smallest_passing_round_amount() {
        assert_eq!(min_swap_amount(&MakerServerConfig::default()), 1_500);
        // Legacy costs more than taproot, so it sets the advertised minimum.
        let cost = swap_cost_floor(ProtocolVersion::Legacy, MIN_RELAY_FEE_RATE, 1, 1).unwrap();
        for (base_fee, amount_pct, time_pct) in [
            (500, 0.0025, 0.0001),
            (0, 0.0, 0.0),
            (900, 1.5, 0.01),
            (500, 0.0025, 0.3),
        ] {
            let config = MakerServerConfig {
                base_fee,
                amount_relative_fee_pct: amount_pct,
                time_relative_fee_pct: time_pct,
                ..Default::default()
            };
            let kept = |amount| {
                amount
                    - calculate_swap_fee(
                        amount,
                        REFUND_LOCKTIME_BASE,
                        base_fee,
                        amount_pct,
                        time_pct,
                    )
            };
            let min = min_swap_amount(&config);
            assert_eq!(min % MIN_SWAP_STEP_SATS, 0);
            assert!(kept(min) >= cost, "{:?}", config);
            assert!(kept(min - MIN_SWAP_STEP_SATS) < cost, "{:?}", config);
        }
        // Fees the formula cannot price leave no minimum; startup refuses these.
        for amount_pct in [f64::NAN, 100.0, -1000.0] {
            let config = MakerServerConfig {
                amount_relative_fee_pct: amount_pct,
                ..Default::default()
            };
            assert_eq!(min_swap_amount(&config), u64::MAX);
        }
    }

    /// A 0-conf maker would fund the next hop on replaceable funding. The
    /// config is refused before init touches disk or the backend.
    #[test]
    fn init_rejects_zero_required_confirms() {
        let config = MakerServerConfig {
            required_confirms: 0,
            ..Default::default()
        };
        assert!(matches!(
            MakerServer::init(config),
            Err(MakerError::General("required_confirms must be at least 1"))
        ));
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

#[cfg(test)]
mod lightning_config_tests {
    use super::MakerServerConfig;
    use std::io::Write as _;

    /// The Lightning settings must survive a load, and must survive the
    /// rewrite `makerd` performs on every start. A field missing from
    /// `write_to_file` would be silently dropped on the next launch, leaving
    /// a configured maker with Lightning disabled and no error.
    #[test]
    fn lightning_settings_round_trip_through_the_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let timelock = if cfg!(feature = "integration-test") {
            950
        } else {
            15_000
        };
        let mut file = std::fs::File::create(&path).unwrap();
        write!(
            file,
            "fidelity_timelock = {timelock}\n\
             ldk_server_url = 127.0.0.1:3536\n\
             ldk_api_key_path = /tmp/ldk/api_key\n\
             ldk_tls_cert_path = /tmp/ldk/tls.crt\n"
        )
        .unwrap();
        drop(file);

        let loaded = MakerServerConfig::new(Some(&path)).unwrap();
        assert_eq!(loaded.ldk_server_url.as_deref(), Some("127.0.0.1:3536"));
        assert_eq!(loaded.ldk_api_key_path.as_deref(), Some("/tmp/ldk/api_key"));
        assert_eq!(
            loaded.ldk_tls_cert_path.as_deref(),
            Some("/tmp/ldk/tls.crt")
        );

        // Rewrite and reload: this is what a restart does.
        let rewritten = dir.path().join("rewritten.toml");
        loaded.write_to_file(&rewritten).unwrap();
        let reloaded = MakerServerConfig::new(Some(&rewritten)).unwrap();
        assert_eq!(reloaded.ldk_server_url, loaded.ldk_server_url);
        assert_eq!(reloaded.ldk_api_key_path, loaded.ldk_api_key_path);
        assert_eq!(reloaded.ldk_tls_cert_path, loaded.ldk_tls_cert_path);
    }

    /// A config without the Lightning keys leaves them unset rather than
    /// inventing defaults that would point at a nonexistent sidecar.
    #[test]
    fn lightning_settings_absent_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let timelock = if cfg!(feature = "integration-test") {
            950
        } else {
            15_000
        };
        std::fs::write(&path, format!("fidelity_timelock = {timelock}\n")).unwrap();
        let loaded = MakerServerConfig::new(Some(&path)).unwrap();
        assert!(loaded.ldk_server_url.is_none());
        assert!(loaded.ldk_api_key_path.is_none());
        assert!(loaded.ldk_tls_cert_path.is_none());
    }
}
