//! Taker API for both Legacy (ECDSA) and Taproot (MuSig2) protocols.

use std::{
    collections::HashSet,
    convert::TryFrom,
    net::TcpStream,
    path::PathBuf,
    sync::{atomic::AtomicBool, mpsc, Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard},
    thread,
    time::{Duration, Instant},
};

pub(crate) use super::swap_tracker::SwapPhase;
use super::swap_tracker::{
    now_secs, ContractOutcome, ContractResolution, ExchangeProgress, FinalizationProgress,
    LegacyExchangeProgress, MakerProgress, RecoveryState, SerializableSecretKey, SwapRecord,
    SwapTracker, TaprootExchangeProgress,
};

use bitcoin::{
    hashes::{hash160::Hash as Hash160, Hash},
    hex::DisplayHex,
    secp256k1::{
        rand::{rngs::OsRng, RngCore},
        SecretKey,
    },
    Amount, OutPoint, PublicKey,
};
use bitcoind::bitcoincore_rpc::json::ListUnspentResultEntry;

use crate::{
    lock_debug,
    maker::nostr::NOSTR_RELAYS,
    protocol::{
        common_messages::{
            GetOffer, MakerToTakerMessage, Offer, PrivateKeyHandover, ProtocolVersion, SwapDetails,
            SwapPrivkey, TakerHello, TakerToMakerMessage,
        },
        contract::calculate_pubkey_from_nonce,
    },
    utill::{
        estimate_maker_reimbursable_fee_for_input_counts_sats, generate_maker_keys, get_taker_dir,
        read_message, send_message,
    },
    wallet::{
        swapcoin::{IncomingSwapCoin, OutgoingSwapCoin, WatchOnlySwapCoin},
        AnyBlockchain, BackendConfig, Blockchain, CoreRpcConfig,
        MakerFeeInfo as ReportMakerFeeInfo, RecoveryOutcome, SwapStatus, TakerReport, Wallet,
    },
    watch_tower::{
        registry_storage::FileRegistry,
        service::WatchService,
        watcher::{Role, Watcher},
    },
};

use super::{
    background_services::{BreachDetector, RecoveryLoop},
    config::TakerConfig,
    error::TakerError,
    offers::{
        MakerAddress, MakerOfferCandidate, MakerProtocol, OfferAndAddress, OfferBook,
        OfferBookHandle, OfferSyncClient, OfferSyncHandle, OfferSyncService,
    },
    payment::{hop_net_sats, HopFeeTerms, PaymentQuote},
};

#[cfg(not(feature = "integration-test"))]
use crate::utill::check_tor_status;
#[cfg(not(feature = "integration-test"))]
use crate::utill::socks5_connect;

/// Connection type for the taker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Direct TCP connection.
    Clearnet,
    /// Connection through Tor SOCKS proxy.
    Tor,
}

/// Timeout for connecting to makers.
pub const CONNECT_TIMEOUT_SECS: u64 = 30;

/// How long the taker waits for a maker's response. A maker can take minutes
/// to answer contract data — it waits for our contracts to confirm first, and
/// that wait is block-bound, not message-bound.
#[cfg(not(feature = "integration-test"))]
const MAKER_RESPONSE_TIMEOUT_SECS: u64 = 1800;
#[cfg(feature = "integration-test")]
const MAKER_RESPONSE_TIMEOUT_SECS: u64 = 60;

/// How long the taker waits for a maker's funding to show on-chain before
/// declaring the swap failed. A live maker broadcasts right after processing;
/// if nothing appears, the maker is gone and waiting longer helps no one.
#[cfg(not(feature = "integration-test"))]
pub(crate) const MAKER_FUNDING_TIMEOUT: Duration = Duration::from_secs(900);
#[cfg(feature = "integration-test")]
pub(crate) const MAKER_FUNDING_TIMEOUT: Duration = Duration::from_secs(120);

/// Gap between route keepalive pings. Must stay comfortably below the maker's
/// idle timeout, or a maker reads a live swap as dropped and starts recovery.
#[cfg(feature = "integration-test")]
pub(crate) const ROUTE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(not(feature = "integration-test"))]
pub(crate) const ROUTE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// Base refund locktime (in blocks) for the innermost hop.
///
/// In integration tests the idle-connection timeout fires after ~200 blocks
/// (60 s at 10 blocks / 3 s).  The base must exceed that so makers have time
/// to detect the drop and sweep via hashlock before the outer timelocks expire.
#[cfg(not(feature = "integration-test"))]
pub(crate) const REFUND_LOCKTIME_BASE: u16 = 20;
#[cfg(feature = "integration-test")]
pub(crate) const REFUND_LOCKTIME_BASE: u16 = 150;

/// Locktime increment per hop in the swap route.
#[cfg(not(feature = "integration-test"))]
pub(crate) const REFUND_LOCKTIME_STEP: u16 = 20;
#[cfg(feature = "integration-test")]
pub(crate) const REFUND_LOCKTIME_STEP: u16 = 75;

/// Headroom over the swap amount that the wallet must also cover, for the
/// taker's own funding-transaction mining fees.
pub(super) const FUNDING_FEE_BUFFER: Amount = Amount::from_sat(10_000);

/// Maximum number of finalization retry attempts before triggering recovery.
#[cfg(not(feature = "integration-test"))]
const MAX_FINALIZE_RETRIES: u32 = 3;
#[cfg(feature = "integration-test")]
const MAX_FINALIZE_RETRIES: u32 = 2;

/// Delay between finalization retry attempts.
#[cfg(not(feature = "integration-test"))]
const FINALIZE_RETRY_DELAY: Duration = Duration::from_secs(15);
#[cfg(feature = "integration-test")]
const FINALIZE_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Maximum number of blocks between consecutive hop confirmations.
/// If a maker's funding confirms more than this many blocks after the previous
/// hop, the relative timelock staggering may be compromised (legacy CSV only).
/// In integration tests, blocks are mined in rapid batches so the gap is larger;
/// over Tor a single hop step takes ~90s, which is ~60 blocks at the slow cadence.
#[cfg(not(feature = "integration-test"))]
pub(crate) const CONFIRMATION_HEIGHT_TOLERANCE: u32 = 6;
#[cfg(feature = "integration-test")]
pub(crate) const CONFIRMATION_HEIGHT_TOLERANCE: u32 = 150;

/// Taker configuration.
#[derive(Debug, Clone)]
pub struct TakerInitConfig {
    /// Data directory path.
    pub data_dir: Option<PathBuf>,
    /// Selected blockchain backend (Bitcoin Core or Electrum) and its settings.
    pub backend: BackendConfig,
    /// On-disk wallet name; drives the wallet path and, for the Core backend, the
    /// node-side wallet name.
    pub wallet_name: String,
    /// Tor control port (optional).
    pub control_port: Option<u16>,
    /// Tor authentication password (optional).
    pub tor_auth_password: Option<String>,
    /// SOCKS port for Tor.
    pub socks_port: u16,
    /// Wallet password (optional).
    pub password: Option<String>,
    /// Connection type (Tor or Clearnet).
    pub connection_type: ConnectionType,
    /// Nostr relay URLs for maker discovery.
    pub nostr_relays: Vec<String>,
}

impl Default for TakerInitConfig {
    fn default() -> Self {
        TakerInitConfig {
            data_dir: None,
            backend: BackendConfig::CoreRpc(CoreRpcConfig::default()),
            wallet_name: "taker-wallet".to_string(),
            control_port: None,
            tor_auth_password: None,
            socks_port: 9050,
            password: None,
            connection_type: ConnectionType::Tor,
            nostr_relays: NOSTR_RELAYS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl TakerInitConfig {
    /// Set the data directory.
    pub fn with_data_dir(mut self, path: PathBuf) -> Self {
        self.data_dir = Some(path);
        self
    }

    /// Set the blockchain backend (Bitcoin Core or Electrum).
    pub fn with_backend(mut self, backend: BackendConfig) -> Self {
        self.backend = backend;
        self
    }

    /// Set the Nostr relay URLs.
    pub fn with_nostr_relays(mut self, relays: Vec<String>) -> Self {
        self.nostr_relays = relays;
        self
    }
}

/// Swap parameters.
#[derive(Debug, Clone, Default)]
pub struct SwapParams {
    /// Protocol version to use for this swap.
    pub protocol: ProtocolVersion,
    /// Total amount to swap.
    pub send_amount: Amount,
    /// Number of makers (hops) to use.
    pub maker_count: usize,
    /// [maximum forwarding transaction count, maximum inputs per forwarding transaction].
    pub tx_count: [u32; 2],
    /// Required confirmations for funding transactions.
    pub required_confirms: u32,
    /// User-selected UTXOs (optional).
    pub manually_selected_outpoints: Option<Vec<OutPoint>>,
    /// Manually specified maker addresses (optional). When set, these makers
    /// are used instead of auto-discovery from the offerbook.
    pub preferred_makers: Option<Vec<String>>,
    /// (optional) PaySwap: settle the final incoming swapcoin to this
    /// third-party address. When set, `send_amount` is the exact amount the
    /// receiver gets; the gross route amount is solved during `prepare_swap`.
    pub payment_address: Option<bitcoin::Address<bitcoin::address::NetworkUnchecked>>,
}

impl SwapParams {
    /// Create new swap parameters.
    pub fn new(protocol: ProtocolVersion, send_amount: Amount, maker_count: usize) -> Self {
        SwapParams {
            protocol,
            send_amount,
            maker_count,
            tx_count: [3, 3],
            required_confirms: 1,
            manually_selected_outpoints: None,
            preferred_makers: None,
            payment_address: None,
        }
    }

    /// Set the number of funding transactions per hop.
    pub fn with_tx_count(mut self, tx_count: [u32; 2]) -> Self {
        self.tx_count = tx_count;
        self
    }

    pub(crate) fn max_tx_count(&self) -> u32 {
        self.tx_count[0]
    }

    pub(crate) fn max_utxos_per_tx(&self) -> u32 {
        self.tx_count[1]
    }

    /// Set the required confirmations.
    pub fn with_required_confirms(mut self, confirms: u32) -> Self {
        self.required_confirms = confirms;
        self
    }

    /// Set manual UTXO selection.
    pub fn with_utxos(mut self, outpoints: Vec<OutPoint>) -> Self {
        self.manually_selected_outpoints = Some(outpoints);
        self
    }

    /// Set preferred maker addresses (e.g. `"host:port"` strings).
    /// When set, these makers are used directly instead of auto-discovery.
    pub fn with_preferred_makers(mut self, makers: Vec<String>) -> Self {
        self.preferred_makers = Some(makers);
        self
    }

    /// Set the payment address: settle the swap to a third-party receiver's address.
    pub fn with_payment_address(
        mut self,
        address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
    ) -> Self {
        self.payment_address = Some(address);
        self
    }
}

/// Per-maker fee breakdown returned in SwapSummary.
#[derive(Debug, Clone)]
pub struct MakerFeeInfo {
    /// Maker's network address.
    pub address: String,
    /// Protocol version negotiated with this maker.
    pub protocol: ProtocolVersion,
    /// Base fee in satoshis.
    pub base_fee: u64,
    /// Percentage fee relative to swap amount.
    pub amount_relative_fee_pct: f64,
    /// Percentage fee for time-locked funds.
    pub time_relative_fee_pct: f64,
    /// Locktime (blocks) for this hop.
    pub locktime: u16,
    /// Estimated fee for this hop in satoshis.
    pub estimated_fee_sats: u64,
}

/// Summary returned after the prepare phase, before the user commits funds.
#[derive(Debug, Clone)]
pub struct SwapSummary {
    /// Unique swap ID (use this to call `start_swap`).
    pub swap_id: String,
    /// Protocol version.
    pub protocol: ProtocolVersion,
    /// Amount the taker is sending.
    pub send_amount: Amount,
    /// Per-maker fee breakdown (one entry per hop, in route order).
    pub makers: Vec<MakerFeeInfo>,
    /// Total estimated fees across all hops.
    pub total_estimated_fee: Amount,
    /// Estimated amount the taker will receive after all fees.
    pub estimated_receive_amount: Amount,
    /// PaySwap cost breakdown; present only when a payment-address was set.
    pub payment: Option<PaymentQuote>,
}

/// State for an ongoing swap.
#[derive(Debug, Clone, Default)]
pub(crate) struct OngoingSwapState {
    /// Unique swap ID.
    pub(crate) id: String,
    /// The hash preimage for this swap.
    pub(crate) preimage: [u8; 32],
    /// Swap parameters.
    pub(crate) params: SwapParams,
    /// Selected makers for this swap.
    pub(crate) makers: Vec<MakerConnection>,
    /// Outgoing swapcoins (our side of the swap).
    pub(crate) outgoing_swapcoins: Vec<OutgoingSwapCoin>,
    /// Incoming swapcoins (receiving side of the swap).
    pub(crate) incoming_swapcoins: Vec<IncomingSwapCoin>,
    /// Watch-only swapcoins for intermediate hops (between makers).
    pub(crate) watchonly_swapcoins: Vec<WatchOnlySwapCoin>,
    /// Multisig nonces for each outgoing swapcoin (Legacy only, used in ProofOfFunding).
    /// Empty for Taproot swaps.
    pub(crate) multisig_nonces: Vec<SecretKey>,
    /// Hashlock nonces for each outgoing swapcoin (used in ProofOfFunding).
    pub(crate) hashlock_nonces: Vec<SecretKey>,
    /// Spare maker addresses available to substitute if a selected maker rejects during negotiation.
    pub(crate) spare_makers: Vec<MakerAddress>,
    /// Current phase of the swap lifecycle.
    pub(crate) phase: SwapPhase,
    /// Reference block height captured during negotiation for consistent Taproot CLTV timelocks.
    /// Taproot uses absolute heights, so all timelock calculations must use the same base height.
    pub(crate) reference_height: Option<u32>,
    /// PaySwap state; `None` for regular swaps. When set, `params.send_amount`
    /// holds the solved gross route amount.
    pub(crate) payment: Option<PaymentQuote>,
}

/// Connection state for a maker in the swap route.
#[derive(Debug, Clone)]
pub(crate) struct MakerConnection {
    /// Maker's network address.
    pub(crate) address: MakerAddress,
    /// Protocol version negotiated with this maker.
    pub(crate) protocol: ProtocolVersion,
    /// Tweakable point for this swap.
    pub(crate) tweakable_point: Option<PublicKey>,
    /// Maker's offer (fee schedule), if known from offerbook discovery.
    pub(crate) offer: Option<Offer>,
    /// The timelock value sent to this maker in `SwapDetails`.
    /// For Legacy this is a relative CSV offset; for Taproot an absolute CLTV height.
    pub(crate) negotiated_timelock: u32,
    /// Protocol-specific exchange progress milestones.
    pub(crate) exchange: ExchangeProgress,
    /// Shared finalization milestones (preimage, privkey exchange).
    pub(crate) finalization: FinalizationProgress,
}

impl MakerConnection {
    /// Get mutable reference to Legacy exchange progress.
    pub(crate) fn legacy_exchange_mut(
        &mut self,
    ) -> Result<&mut LegacyExchangeProgress, TakerError> {
        match &mut self.exchange {
            ExchangeProgress::Legacy(ref mut l) => Ok(l),
            _ => Err(TakerError::General(
                "Expected Legacy exchange progress".to_string(),
            )),
        }
    }

    /// Get mutable reference to Taproot exchange progress.
    pub(crate) fn taproot_exchange_mut(
        &mut self,
    ) -> Result<&mut TaprootExchangeProgress, TakerError> {
        match &mut self.exchange {
            ExchangeProgress::Taproot(ref mut t) => Ok(t),
            _ => Err(TakerError::General(
                "Expected Taproot exchange progress".to_string(),
            )),
        }
    }
}

impl Taker {
    /// Compute the ceiling-priced output for one maker from the amount it actually received.
    ///
    /// Returns `None` if any maker along the route (up to and including `maker_idx`)
    /// has no stored offer.
    ///
    /// Fee formula: `total_fee = base_fee + (amount * amt_pct)/100 + (amount * locktime * time_pct)/100`
    /// TODO: Use fee estimation here
    pub(crate) fn expected_amount_for_hop(
        &self,
        maker_idx: usize,
        incoming_amount: Amount,
    ) -> Option<Amount> {
        let swap = self.swap_state().ok()?;
        let maker_count = swap.makers.len();
        let maker = &swap.makers[maker_idx];
        let offer = maker.offer.as_ref()?;
        let locktime = match maker.protocol {
            ProtocolVersion::Legacy => maker.negotiated_timelock,
            ProtocolVersion::Taproot => {
                (REFUND_LOCKTIME_BASE + REFUND_LOCKTIME_STEP * (maker_count - maker_idx - 1) as u16)
                    as u32
            }
        };
        let ceiling_fee = estimate_maker_reimbursable_fee_for_input_counts_sats(
            maker.protocol,
            std::iter::repeat_n(
                swap.params.max_utxos_per_tx() as usize,
                swap.params.max_tx_count() as usize,
            ),
        );
        Some(Amount::from_sat(hop_net_sats(
            &HopFeeTerms::from_offer(offer, locktime),
            ceiling_fee,
            incoming_amount.to_sat(),
        )))
    }
}

/// Taker client.
pub struct Taker {
    /// Configuration.
    pub(crate) config: TakerInitConfig,
    /// Wallet for managing funds.
    pub(crate) wallet: Arc<RwLock<Wallet>>,
    /// Stops the role and every backend connection it owns.
    shutdown: Arc<AtomicBool>,
    /// Offer book for managing maker offers.
    pub(crate) offerbook: OfferBookHandle,
    /// Watch service for transaction monitoring.
    pub(crate) watch_service: WatchService,
    /// Handle for offer sync background service.
    offer_sync_handle: OfferSyncHandle,
    /// Ongoing swap state (`None` when no swap is active).
    pub(crate) ongoing_swap: Option<OngoingSwapState>,
    /// Persistent swap tracker for crash-resilient recovery.
    pub(crate) swap_tracker: Arc<Mutex<SwapTracker>>,
    /// Background recovery loop (active when incomplete swap recovery is in progress).
    recovery_loop: Option<RecoveryLoop>,
    /// Breach detector for legacy swaps (monitors funding outpoints for adversarial contract broadcasts).
    pub(crate) breach_detector: Option<BreachDetector>,
    /// Test behavior.
    #[cfg(feature = "integration-test")]
    pub behavior: TakerBehavior,
}

impl Drop for Taker {
    fn drop(&mut self) {
        log::info!("Shutting down taker.");
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // Flush any pending swap state before shutdown
        if let Some(swap) = &self.ongoing_swap {
            if let Ok(record) = self.persist_build_record(swap) {
                // Drop can't propagate; a poisoned tracker must not abort the
                // process while we're already unwinding.
                let mut tracker =
                    lock_debug!(self.swap_tracker.lock()).unwrap_or_else(|e| e.into_inner());
                if let Err(e) = tracker.save_record(&record) {
                    log::error!("Failed to flush swap tracker on shutdown: {:?}", e);
                }
            }
        }
        // Shut down background recovery loop (if running)
        if let Some(recovery) = self.recovery_loop.take() {
            log::info!("Shutting down recovery loop");
            drop(recovery);
        }
        // Shut down breach detector (if running)
        if let Some(detector) = self.breach_detector.take() {
            log::info!("Shutting down breach detector");
            detector.stop();
        }
        log::info!("Shutting down offer sync background job");
        self.offer_sync_handle.shutdown();
        log::info!("Shutting down watch service background job");
        self.watch_service.shutdown();
        log::info!(
            "shutdown_phase_start pid={} component=taker phase=state_save",
            std::process::id()
        );
        let mut save_ok = true;
        if let Err(e) = self.offerbook.persist() {
            log::error!("Failed to persist offerbook: {:?}", e);
            save_ok = false;
        }
        if let Ok(wallet) = lock_debug!(self.wallet.write()) {
            if let Err(e) = wallet.save_to_disk() {
                log::error!("Failed to save wallet: {:?}", e);
                save_ok = false;
            }
        } else {
            log::error!("Failed to lock wallet while saving shutdown state");
            save_ok = false;
        }
        log::info!(
            "shutdown_phase_done pid={} component=taker phase=state_save outcome={}",
            std::process::id(),
            if save_ok { "ok" } else { "error" }
        );
    }
}

impl Role for Taker {
    const RUN_DISCOVERY: bool = true;
}

impl Taker {
    /// Acquire a read lock on the wallet.
    pub(crate) fn read_wallet(&self) -> Result<RwLockReadGuard<'_, Wallet>, TakerError> {
        lock_debug!(self.wallet.read())
            .map_err(|_| TakerError::General("Failed to lock wallet".to_string()))
    }

    /// Acquire a write lock on the wallet.
    pub(crate) fn write_wallet(&self) -> Result<RwLockWriteGuard<'_, Wallet>, TakerError> {
        lock_debug!(self.wallet.write())
            .map_err(|_| TakerError::General("Failed to lock wallet".to_string()))
    }

    /// Get a shared reference to the ongoing swap state.
    pub(crate) fn swap_state(&self) -> Result<&OngoingSwapState, TakerError> {
        self.ongoing_swap
            .as_ref()
            .ok_or_else(|| TakerError::General("No active swap".to_string()))
    }

    /// Get a mutable reference to the ongoing swap state.
    pub(crate) fn swap_state_mut(&mut self) -> Result<&mut OngoingSwapState, TakerError> {
        self.ongoing_swap
            .as_mut()
            .ok_or_else(|| TakerError::General("No active swap".to_string()))
    }

    /// Initialize a new taker. The backend is resolved from `config` via [`TakerInitConfig::backend`].
    pub fn init(mut config: TakerInitConfig) -> Result<Self, TakerError> {
        // Init the Wallet
        let wallet_name = config.wallet_name.clone();

        // For the Core backend, bind the node-side wallet name to the on-disk
        // wallet name (no-op for Electrum, which has no server-side wallet).
        let mut backend = config.backend.clone();
        if let BackendConfig::CoreRpc(cfg) = &mut backend {
            cfg.wallet_name = wallet_name.clone();
        }
        let data_dir = config
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(get_taker_dir)?;
        std::fs::create_dir_all(&data_dir)?;
        let wallet_path = data_dir.join("wallets").join(&wallet_name);
        let shutdown = Arc::new(AtomicBool::new(false));
        let blockchain = AnyBlockchain::from_config_with_shutdown(&backend, shutdown.clone())?;
        // Misconfiguration (no txindex, dead ZMQ) must fail here, not mid-swap.
        if let AnyBlockchain::CoreRPC(core) = &blockchain {
            core.check_node_requirements()?;
        }
        // Take the passphrase out of the config: the wallet keeps the derived
        // key material, so the cleartext passphrase must not linger in the
        // long-lived server config.
        let wallet = Wallet::load_or_init(&wallet_path, blockchain, config.password.take())?;

        // Init Watch Service
        let (watch_service, registry, initial_sync_complete) =
            Self::init_watch_service(&config, &backend, shutdown.clone())?;

        // The watcher starts empty, so re-arm every contract still live in the
        // wallet. Without this a restart leaves them undefended.
        let mut watches = wallet.incoming_contract_outpoints();
        watches.extend(wallet.outgoing_contract_outpoints());
        watches.extend(wallet.watchonly_contract_outpoints());
        if let Err(e) = watch_service.rebuild_watches(watches) {
            log::error!("could not rebuild watches on startup: {e}; recovery remains active");
        }

        Self::init_taker_config(&config, &data_dir)?;

        // Init OfferBook Sync
        let offerbook = OfferBookHandle::load_or_create(&data_dir)?;
        let offer_sync_handle = Self::init_offer_sync(
            &offerbook,
            registry,
            config.socks_port,
            Arc::new(AnyBlockchain::from_config_with_shutdown(
                &backend,
                shutdown.clone(),
            )?),
            initial_sync_complete,
            shutdown.clone(),
        )?;
        let swap_tracker = Arc::new(Mutex::new(SwapTracker::load_or_create(&data_dir)?));
        lock_debug!(swap_tracker.lock())
            .map_err(|_| TakerError::General("swap tracker lock poisoned".into()))?
            .cleanup_incomplete();

        let mut taker = Taker {
            config,
            wallet: Arc::new(RwLock::new(wallet)),
            shutdown,
            offerbook,
            watch_service,
            offer_sync_handle,
            ongoing_swap: None,
            swap_tracker,
            recovery_loop: None,
            breach_detector: None,
            #[cfg(feature = "integration-test")]
            behavior: TakerBehavior::Normal,
        };

        taker.init_recover_wallet();
        Ok(taker)
    }

    /// Called on startup to recover funds from incomplete swaps.
    ///
    /// Sweeps incoming swapcoins (hashlock path), recovers timelocked outgoing
    /// swapcoins, and spawns a background RecoveryLoop for any remaining
    /// unresolved contracts.
    fn init_recover_wallet(&mut self) {
        log::info!("Checking wallet for unresolved swap contracts...");

        // One connection serves both startup recovery passes; the sweep and
        // timelock recovery each take the lock themselves and drop it across
        // their waits, so a stuck counterparty tx cannot wedge taker startup.
        let chain = match self.read_wallet() {
            Ok(w) => match w.blockchain.new_connection() {
                Ok(chain) => Some(chain),
                Err(e) => {
                    log::warn!("Startup recovery: no backend connection: {:?}", e);
                    None
                }
            },
            Err(e) => {
                log::warn!("Startup recovery: failed to lock wallet: {:?}", e);
                None
            }
        };

        if let Some(chain) = &chain {
            match Wallet::sweep_incoming_swapcoins(
                &self.wallet,
                chain,
                2.0,
                &crate::utill::NO_SHUTDOWN,
            ) {
                Ok(ref swept) if !swept.is_empty() => {
                    log::info!(
                        "Startup recovery: swept {} incoming swapcoins",
                        swept.resolved.len()
                    );
                }
                Ok(_) => {}
                Err(e) => log::warn!("Startup incoming sweep failed: {:?}", e),
            }

            // Wallet-driven recovery: recover timelocked. Also takes the lock itself.
            match Wallet::recover_timelocked_swapcoins(
                &self.wallet,
                chain,
                2.0,
                &crate::utill::NO_SHUTDOWN,
            ) {
                Ok(ref recovered) if !recovered.is_empty() => {
                    log::info!(
                        "Startup recovery: recovered {} timelocked outgoing swapcoins",
                        recovered.len()
                    );
                }
                Ok(_) => {}
                Err(e) => log::warn!("Startup timelock recovery failed: {:?}", e),
            }
        }

        let has_remaining = match self.write_wallet() {
            Ok(wallet) => {
                !wallet.outgoing_contract_outpoints().is_empty()
                    || !wallet.incoming_contract_outpoints().is_empty()
            }
            Err(e) => {
                log::warn!("Startup recovery: failed to lock wallet: {:?}", e);
                false
            }
        };

        if has_remaining {
            let data_dir = match self
                .config
                .data_dir
                .clone()
                .map(Ok)
                .unwrap_or_else(get_taker_dir)
            {
                Ok(dir) => dir,
                Err(e) => {
                    log::warn!("Startup recovery: {e}; skipping recovery loop");
                    return;
                }
            };
            match RecoveryLoop::start(self.wallet.clone(), self.swap_tracker.clone(), data_dir) {
                Ok(rl) => self.recovery_loop = Some(rl),
                // Without the loop, remaining contracts are never swept.
                Err(e) => log::error!("Failed to spawn recovery loop: {e}"),
            }
        }
    }

    /// Initialize the watch service and spawn the watcher thread.
    /// Returns the watch service, a clone of the registry, and the initial-sync-complete flag.
    fn init_watch_service(
        config: &TakerInitConfig,
        backend: &BackendConfig,
        shutdown: Arc<AtomicBool>,
    ) -> Result<(WatchService, FileRegistry, Arc<AtomicBool>), TakerError> {
        let blockchain =
            AnyBlockchain::from_config_with_shutdown(&backend.for_watcher(), shutdown.clone())?;

        let registry = FileRegistry::new();
        let registry_clone = registry.clone();

        let (tx_requests, rx_requests) = mpsc::channel();

        let initial_sync_complete = Arc::new(AtomicBool::new(false));
        let initial_sync_clone = initial_sync_complete.clone();

        let nostr_relays = config.nostr_relays.clone();
        let mut watcher = Watcher::<Taker>::new(
            blockchain,
            registry,
            rx_requests,
            nostr_relays,
            Some((
                config.socks_port,
                config.tor_auth_password.clone().unwrap_or_default(),
            )),
            shutdown.clone(),
        );
        let watch_service = WatchService::spawn(tx_requests, shutdown, move || {
            watcher.run(initial_sync_clone)
        })
        .map_err(|e| TakerError::General(format!("failed to spawn watcher thread: {e}")))?;

        Ok((watch_service, registry_clone, initial_sync_complete))
    }

    /// Load/merge taker config and check Tor status.
    fn init_taker_config(
        config: &TakerInitConfig,
        data_dir: &std::path::Path,
    ) -> Result<(), TakerError> {
        let mut taker_config = TakerConfig::new(Some(&data_dir.join("config.toml")))?;

        if let Some(control_port) = config.control_port {
            taker_config.control_port = control_port;
        }

        if let Some(ref tor_auth_password) = config.tor_auth_password {
            taker_config.tor_auth_password = tor_auth_password.clone();
        }

        #[cfg(not(feature = "integration-test"))]
        if config.connection_type == ConnectionType::Tor {
            check_tor_status(
                taker_config.control_port,
                taker_config.tor_auth_password.as_str(),
            )?;
        }

        taker_config.write_to_file(&data_dir.join("config.toml"))?;
        Ok(())
    }

    /// Start the background offer sync service.
    fn init_offer_sync(
        offerbook: &OfferBookHandle,
        registry: FileRegistry,
        socks_port: u16,
        chain: Arc<AnyBlockchain>,
        initial_sync_complete: Arc<AtomicBool>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<OfferSyncHandle, TakerError> {
        OfferSyncService::new(
            offerbook.clone(),
            registry,
            socks_port,
            chain,
            initial_sync_complete,
            shutdown,
        )
        .start()
    }

    /// Get reference to the wallet.
    pub fn get_wallet(&self) -> &Arc<RwLock<Wallet>> {
        &self.wallet
    }

    /// The config this taker was built from, so a caller can rebuild an
    /// identical one after a shutdown.
    pub fn config(&self) -> &TakerInitConfig {
        &self.config
    }

    /// Log the current swap tracker state at INFO level.
    pub fn log_tracker_state(&self) {
        // Info-only path; a poisoned tracker should not kill the caller.
        let Ok(tracker) = lock_debug!(self.swap_tracker.lock()) else {
            log::error!("swap tracker lock poisoned; skipping tracker state log");
            return;
        };
        tracker.log_state();
    }

    /// Check whether the background recovery loop has completed.
    /// Returns `true` if no recovery is needed or if all contracts are resolved.
    pub fn is_recovery_complete(&self) -> bool {
        match &self.recovery_loop {
            Some(loop_) => loop_.is_complete(),
            None => true,
        }
    }

    /// Block until every unresolved swap contract has been recovered.
    ///
    /// Returns whether recovery finished. `false` means contracts are still
    /// unresolved with nothing retrying them, or that completion could not be
    /// confirmed.
    ///
    /// A refund is unspendable until its timelock matures, so this can block for
    /// as long as that takes — up to ~1.5 days on mainnet for Legacy. Interrupting
    /// is safe: each step is persisted as it happens and a re-run resumes.
    pub fn wait_for_recovery(&mut self) -> bool {
        if let Some(recovery) = self.recovery_loop.take() {
            return recovery.join();
        }

        match self.read_wallet() {
            Ok(wallet) => {
                wallet.get_outgoing_swapcoins_count() + wallet.get_incoming_swapcoins_count() == 0
            }
            Err(e) => {
                log::error!("Could not read wallet to check recovery progress: {:?}", e);
                false
            }
        }
    }

    /// Prepare a openswap: discover makers, negotiate, and return a summary.
    ///
    /// No funds are committed. The caller reviews the summary and then calls
    /// `start_swap` with the returned `swap_id` to execute.
    pub fn prepare_swap(&mut self, params: SwapParams) -> Result<SwapSummary, TakerError> {
        log::info!(
            "Preparing openswap: amount={}, makers={}, protocol={:?}",
            params.send_amount,
            params.maker_count,
            params.protocol
        );

        let available = self.read_wallet()?.get_balances()?.spendable;
        let required = params.send_amount + FUNDING_FEE_BUFFER;
        if available < required {
            return Err(TakerError::General(format!(
                "Insufficient balance: available={}, required={}",
                available, required
            )));
        }

        if let Some(preferred_makers) = &params.preferred_makers {
            let mut seen = HashSet::new();
            for maker in preferred_makers {
                if !seen.insert(maker.trim()) {
                    return Err(TakerError::General(format!(
                        "Duplicate maker in route: {}",
                        maker
                    )));
                }
            }
        }

        // PaySwap: reject an invalid receiver before any swap state exists.
        let payment_address = self.payment_validate_params(&params)?;

        let mut preimage = [0u8; 32];
        OsRng.fill_bytes(&mut preimage);

        let swap_id = Hash160::hash(&preimage)[0..8].to_lower_hex_string();
        log::info!("Preparing openswap with id: {}", swap_id);

        let maker_count = params.maker_count;
        let should_sync_offerbook = params.preferred_makers.is_none();

        self.ongoing_swap = Some(OngoingSwapState {
            id: swap_id.clone(),
            preimage,
            params,
            makers: Vec::new(),
            outgoing_swapcoins: Vec::new(),
            incoming_swapcoins: Vec::new(),
            watchonly_swapcoins: Vec::new(),
            multisig_nonces: Vec::new(),
            hashlock_nonces: Vec::new(),
            spare_makers: Vec::new(),
            phase: SwapPhase::MakersDiscovered,
            reference_height: None,
            payment: None,
        });

        // Only auto-discovery needs a fresh offerbook. Preferred makers are
        // selected directly and queried individually before their offers are
        // relied upon, so waiting for a full sync would not affect the route.
        if should_sync_offerbook {
            self.sync_offerbook_and_wait()?;
        }
        self.discover_makers()?;
        self.persist_swap(SwapPhase::MakersDiscovered)?;

        // PaySwap: solve the gross route amount before any amount is quoted.
        if let Some(address) = payment_address {
            self.payment_prepare_route(address)?;
        }

        #[cfg(feature = "integration-test")]
        if self.behavior == TakerBehavior::AlterPaymentQuoteBeforeNegotiation
            && self.swap_state()?.payment.is_some()
        {
            let quoted_offer = self
                .swap_state_mut()?
                .makers
                .first_mut()
                .and_then(|maker| maker.offer.as_mut())
                .ok_or_else(|| {
                    TakerError::General(
                        "Test: payment route has no quoted maker offer to alter".to_string(),
                    )
                })?;
            quoted_offer.base_fee = quoted_offer.base_fee.saturating_add(1);
        }

        #[cfg(feature = "integration-test")]
        if self.behavior == TakerBehavior::CloseEarly {
            log::warn!("Test behavior: closing early after maker selection");
            return Err(TakerError::General(
                "Test: Closing early after maker selection".to_string(),
            ));
        }

        self.negotiate_swap_details()?;
        self.persist_swap(SwapPhase::Negotiated)?;

        // Build the summary from negotiated state. Re-read the amount: a
        // payment route solve rewrites it to the gross.
        let swap = self.swap_state()?;
        let send_amount = swap.params.send_amount;
        let protocol = swap.params.protocol;
        let mut maker_fees = Vec::with_capacity(maker_count);
        let mut amount_sats = send_amount.to_sat() as f64;

        for (i, mc) in swap.makers.iter().enumerate() {
            let locktime =
                REFUND_LOCKTIME_BASE + REFUND_LOCKTIME_STEP * (maker_count - i - 1) as u16;

            let (base_fee, amt_pct, time_pct) = match &mc.offer {
                Some(offer) => (
                    offer.base_fee,
                    offer.amount_relative_fee_pct,
                    offer.time_relative_fee_pct,
                ),
                None => (0, 0.0, 0.0),
            };

            let fee = base_fee as f64
                + (amount_sats * amt_pct) / 100.0
                + (amount_sats * locktime as f64 * time_pct) / 100.0;
            let fee_sats = fee.ceil() as u64;

            maker_fees.push(MakerFeeInfo {
                address: mc.address.to_string(),
                protocol: mc.protocol,
                base_fee,
                amount_relative_fee_pct: amt_pct,
                time_relative_fee_pct: time_pct,
                locktime,
                estimated_fee_sats: fee_sats,
            });

            amount_sats = (amount_sats - fee).max(0.0);
        }

        let total_fee_sats: u64 = maker_fees.iter().map(|m| m.estimated_fee_sats).sum();
        let estimated_receive = send_amount
            .checked_sub(Amount::from_sat(total_fee_sats))
            .unwrap_or(Amount::ZERO);

        let summary = SwapSummary {
            swap_id,
            protocol,
            send_amount,
            makers: maker_fees,
            total_estimated_fee: Amount::from_sat(total_fee_sats),
            estimated_receive_amount: estimated_receive,
            payment: swap.payment.clone(),
        };

        log::info!(
            "Swap prepared: id={}, estimated_fee={}, estimated_receive={}",
            summary.swap_id,
            summary.total_estimated_fee,
            summary.estimated_receive_amount
        );

        Ok(summary)
    }

    /// Execute a prepared openswap. Call after reviewing the `SwapSummary`
    /// from `prepare_swap`.
    ///
    /// Commits funds on-chain: creates funding transactions, exchanges
    /// contracts with makers, finalizes, and sweeps.
    pub fn start_swap(&mut self, swap_id: &str) -> Result<TakerReport, TakerError> {
        let swap_start_time = Instant::now();

        // Verify the swap_id matches the prepared swap.
        let current_id = self.swap_state()?.id.clone();
        if current_id != swap_id {
            return Err(TakerError::General(format!(
                "No prepared swap with id '{}' (current: '{}')",
                swap_id, current_id
            )));
        }
        #[cfg(feature = "integration-test")]
        if self.behavior == TakerBehavior::StopWatcherBeforeSwap {
            self.watch_service.stop_watcher_for_test();
        }
        if !self.watch_service.is_alive() {
            return Err(TakerError::General("watchtower is down".into()));
        }

        let initial_utxos = self.read_wallet()?.list_all_utxo();

        log::info!("Starting openswap execution for id: {}", swap_id);

        // Taproot has no breach case: its contract output cannot be spent
        // mid-swap — key-path needs both keys, the hashlock needs the
        // taker's preimage, timelocks are immature — so no detector starts.
        if self.swap_state()?.params.protocol == ProtocolVersion::Legacy {
            let backend = self.read_wallet()?.blockchain.new_connection()?;
            self.breach_detector = Some(super::background_services::BreachDetector::start(
                self.watch_service.clone(),
                backend,
            )?);
        }

        self.funding_initialize()?;

        // SP3: Persist after funding initialization (outgoing txids created).
        self.persist_swap(SwapPhase::FundingCreated)?;

        // Protocol-specific execution with phase-aware recovery triggers.
        let protocol = self.swap_state()?.params.protocol;

        match protocol {
            ProtocolVersion::Legacy => {
                let mut exchange_result = self.exchange_legacy();

                // Pre-funding spare substitution: if exchange failed before any
                // funding was broadcast (phase < FundsBroadcast), try substituting
                // the first maker with a spare and retrying from scratch.
                while let Err(ref _e) = exchange_result {
                    let phase = self
                        .swap_state()
                        .map(|s| s.phase)
                        .unwrap_or(SwapPhase::MakersDiscovered);
                    // Payment routes cannot substitute makers (see
                    // negotiate_swap_details); aborting pre-funding is safe.
                    let payment_swap = self
                        .swap_state()
                        .map(|s| s.payment.is_some())
                        .unwrap_or(false);
                    if phase < SwapPhase::FundsBroadcast && !payment_swap {
                        if let Some(spare) = {
                            let swap = self.swap_state_mut()?;
                            swap.spare_makers.pop()
                        } {
                            log::warn!(
                                "Pre-funding exchange failure, substituting maker 0 with spare"
                            );
                            if let Err(sub_err) = self.substitute_and_negotiate_spare(0, spare) {
                                log::error!("Failed to negotiate with spare: {:?}", sub_err);
                                break;
                            }
                            if let Err(fund_err) = self.funding_reinitialize() {
                                log::error!("Failed to reinitialize funding: {:?}", fund_err);
                                break;
                            }
                            self.persist_swap(SwapPhase::FundingCreated)?;
                            exchange_result = self.exchange_legacy();
                            continue;
                        }
                    }
                    break;
                }

                match exchange_result {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("Legacy contract exchange failed: {:?}", e);
                        self.emit_failure_report(&initial_utxos, swap_start_time, &e);
                        let phase = self
                            .swap_state()
                            .map(|s| s.phase)
                            .unwrap_or(SwapPhase::MakersDiscovered);
                        if phase >= SwapPhase::FundsBroadcast {
                            log::warn!("Funding txs were broadcast, triggering recovery");
                            self.persist_failure(phase, &e);
                            if let Err(re) = self.recover_active_swap() {
                                log::error!("Recovery failed: {:?}", re);
                            }
                        } else {
                            log::info!("No funds on-chain — safe to abort");
                            let _ = lock_debug!(self.swap_tracker.lock())
                                .map_err(|_| {
                                    TakerError::General("swap tracker lock poisoned".into())
                                })?
                                .remove_record(
                                    &self.swap_state().map(|s| s.id.clone()).unwrap_or_default(),
                                );
                            self.ongoing_swap = None;
                        }
                        return Err(e);
                    }
                }
            }
            ProtocolVersion::Taproot => match self.exchange_taproot() {
                Ok(()) => {}
                Err(e) => {
                    log::error!("Taproot exchange failed: {:?}", e);
                    self.emit_failure_report(&initial_utxos, swap_start_time, &e);
                    let phase = self
                        .swap_state()
                        .map(|s| s.phase)
                        .unwrap_or(SwapPhase::MakersDiscovered);
                    if phase >= SwapPhase::FundsBroadcast {
                        log::warn!("Funds were broadcast, triggering recovery");
                        self.persist_failure(phase, &e);
                        if let Err(re) = self.recover_active_swap() {
                            log::error!("Recovery failed: {:?}", re);
                        }
                    } else {
                        log::info!("No funds on-chain — safe to abort");
                        let _ = lock_debug!(self.swap_tracker.lock())
                            .map_err(|_| TakerError::General("swap tracker lock poisoned".into()))?
                            .remove_record(
                                &self.swap_state().map(|s| s.id.clone()).unwrap_or_default(),
                            );
                        self.ongoing_swap = None;
                    }
                    return Err(e);
                }
            },
        }

        #[cfg(feature = "integration-test")]
        if self.behavior == TakerBehavior::BroadcastContractAfterFullSetup {
            log::warn!("Test behavior: broadcasting contract txs after full setup, then closing");
            // Broadcast outgoing contract transactions to trigger recovery paths
            let wallet = self.read_wallet()?;
            for outgoing in &self.swap_state()?.outgoing_swapcoins {
                let _ = wallet.send_tx(&outgoing.contract_tx);
            }
            drop(wallet);
            let phase = self
                .swap_state()
                .map(|s| s.phase)
                .unwrap_or(SwapPhase::FundsBroadcast);
            let err = TakerError::General("Test: broadcast contract after full setup".to_string());
            self.persist_failure(phase, &err);
            return Err(err);
        }

        #[cfg(feature = "integration-test")]
        if self.behavior == TakerBehavior::DropAfterFundsBroadcast {
            log::warn!("Test behavior: dropping after contract exchange");
            let phase = self
                .swap_state()
                .map(|s| s.phase)
                .unwrap_or(SwapPhase::FundsBroadcast);
            let err = TakerError::General("Test: dropped after contract exchange".to_string());
            self.persist_failure(phase, &err);
            if let Err(re) = self.recover_active_swap() {
                log::error!("Recovery failed: {:?}", re);
            }
            return Err(err);
        }

        // Die with the contracts accepted but nothing settled and no recovery
        // run — the window where incoming coins would exist only in memory.
        #[cfg(feature = "integration-test")]
        if self.behavior == TakerBehavior::CrashAfterContractExchange {
            log::warn!("Test behavior: crashing after contract exchange");
            let err = TakerError::General("Test: crashed after contract exchange".to_string());
            self.persist_failure(SwapPhase::ContractsExchanged, &err);
            return Err(err);
        }

        // SP7: Finalization starts.
        self.persist_swap(SwapPhase::Finalizing)?;

        // Crash with every contract funded and persisted but nothing settled, so
        // no counterparty has been handed a key either.
        #[cfg(feature = "integration-test")]
        if self.behavior == TakerBehavior::CrashBeforeRecovery {
            log::warn!("Test behavior: crashing before finalization");
            let err = TakerError::General("Test: crashed before finalization".to_string());
            self.persist_failure(SwapPhase::Finalizing, &err);
            return Err(err);
        }

        match self.finalize_with_retry() {
            Ok(()) => {}
            Err(e) => {
                log::error!("Finalization failed after retries: {:?}", e);
                self.emit_failure_report(&initial_utxos, swap_start_time, &e);
                self.persist_failure(SwapPhase::Finalizing, &e);
                if let Err(re) = self.recover_active_swap() {
                    log::error!("Recovery failed: {:?}", re);
                }
                return Err(e);
            }
        }

        // Finalization succeeded — disarm and stop the breach detector.
        if let Some(detector) = self.breach_detector.take() {
            detector.disarm(&self.watch_service);
            detector.stop();
        }

        // Success path: sweep + report (shared by both protocols)
        let swap_id_owned = swap_id.to_string();
        let expected_incoming_swapcoins = self.swap_state()?.incoming_swapcoins.len();
        // Hoist connection creation so the read guard drops before sweep
        // takes the write lock on the same wallet.
        let chain = self.read_wallet()?.blockchain.new_connection()?;
        let swept = Wallet::sweep_incoming_swapcoins(
            &self.wallet,
            &chain,
            2.0,
            &crate::utill::NO_SHUTDOWN,
        )?;
        log::info!("Swept {} incoming swapcoins", swept.resolved.len());
        self.write_wallet()?
            .sync_and_save(&crate::utill::NO_SHUTDOWN)?;
        if expected_incoming_swapcoins == 0 || swept.resolved.len() < expected_incoming_swapcoins {
            let err = TakerError::General(format!(
                "Swap finalization swept {}/{} incoming swapcoins",
                swept.resolved.len(),
                expected_incoming_swapcoins
            ));
            self.emit_failure_report(&initial_utxos, swap_start_time, &err);
            self.persist_failure(SwapPhase::Finalizing, &err);
            if let Err(re) = self.recover_active_swap() {
                log::error!("Recovery failed: {:?}", re);
            }
            return Err(err);
        }

        self.populate_success_outcomes(&swap_id_owned, &swept)?;

        {
            let swap_id_for_cleanup = self.swap_state()?.id.clone();
            let mut wallet = self.write_wallet()?;
            let outgoing_keys = wallet.outgoing_keys_for_swap(&swap_id_for_cleanup);
            for key in &outgoing_keys {
                wallet.remove_outgoing_swapcoin(key);
            }
            wallet.remove_watchonly_swapcoins(&swap_id_for_cleanup);
            wallet.save_to_disk()?;
        }

        self.persist_swap(SwapPhase::Completed)?;

        // Generate, save, and return the SwapReport
        let report = self.generate_swap_report(
            &initial_utxos,
            swap_start_time,
            SwapStatus::Success,
            None,
            Some(&swept),
        )?;

        log::info!("OpenSwap completed successfully: {:?}", report);
        Ok(report)
    }

    /// Discover and select makers for the swap.
    ///
    /// If `preferred_makers` is set in swap params, those addresses are used
    /// directly (no offerbook lookup). Otherwise, makers are auto-selected
    /// from the offerbook.
    fn discover_makers(&mut self) -> Result<(), TakerError> {
        let swap = self.swap_state()?;
        let maker_count = swap.params.maker_count;
        let send_amount = swap.params.send_amount;
        let protocol = swap.params.protocol;
        let preferred = swap.params.preferred_makers.clone();

        log::info!("Discovering makers for {} hops...", maker_count);

        // If preferred makers are specified, use them directly.
        let (selected_makers, spares) = if let Some(addrs) = preferred {
            let parsed: Vec<MakerAddress> = addrs
                .iter()
                .filter_map(|s| match MakerAddress::try_from(s.clone()) {
                    Ok(addr) => Some(addr),
                    Err(e) => {
                        log::warn!("Invalid maker address '{}': {:?}", s, e);
                        None
                    }
                })
                .collect();

            if parsed.len() < maker_count {
                return Err(TakerError::General(format!(
                    "Not enough valid preferred makers. Required: {}, Parsed: {}",
                    maker_count,
                    parsed.len()
                )));
            }

            let mut addrs = parsed;
            let spare_addrs = addrs.split_off(maker_count);
            let makers: Vec<MakerConnection> = addrs
                .into_iter()
                .map(|address| {
                    let exchange = match protocol {
                        ProtocolVersion::Legacy => {
                            ExchangeProgress::Legacy(LegacyExchangeProgress::default())
                        }
                        ProtocolVersion::Taproot => {
                            ExchangeProgress::Taproot(TaprootExchangeProgress::default())
                        }
                    };
                    MakerConnection {
                        address,
                        protocol,
                        tweakable_point: None,
                        offer: None,
                        negotiated_timelock: 0,
                        exchange,
                        finalization: FinalizationProgress::default(),
                    }
                })
                .collect();
            (makers, spare_addrs)
        } else {
            // Auto-select from offerbook.
            let maker_protocol = match protocol {
                ProtocolVersion::Legacy => MakerProtocol::Legacy,
                ProtocolVersion::Taproot => MakerProtocol::Taproot,
            };

            let available_makers = self.offerbook.active_makers(&maker_protocol)?;

            if available_makers.is_empty() {
                return Err(TakerError::NotEnoughMakersInOfferBook);
            }

            let suitable_makers: Vec<OfferAndAddress> = available_makers
                .into_iter()
                .filter(|maker| {
                    let min_ok = send_amount.to_sat() >= maker.offer.min_size;
                    let max_ok = send_amount.to_sat() <= maker.offer.max_size;
                    min_ok && max_ok
                })
                .collect();

            if suitable_makers.len() < maker_count {
                log::error!(
                    "Not enough suitable makers. Required: {}, Available: {}",
                    maker_count,
                    suitable_makers.len()
                );
                return Err(TakerError::NotEnoughMakersInOfferBook);
            }

            let spare_count = suitable_makers.len().saturating_sub(maker_count).min(2);
            let total_select = maker_count + spare_count;

            let mut selected: Vec<OfferAndAddress> =
                suitable_makers.into_iter().take(total_select).collect();

            let spare_oas = selected.split_off(maker_count);
            let spare_addrs: Vec<MakerAddress> =
                spare_oas.into_iter().map(|oa| oa.address).collect();
            let makers: Vec<MakerConnection> = selected
                .into_iter()
                .map(|oa| {
                    let exchange = match protocol {
                        ProtocolVersion::Legacy => {
                            ExchangeProgress::Legacy(LegacyExchangeProgress::default())
                        }
                        ProtocolVersion::Taproot => {
                            ExchangeProgress::Taproot(TaprootExchangeProgress::default())
                        }
                    };
                    MakerConnection {
                        address: oa.address,
                        protocol,
                        tweakable_point: None,
                        offer: Some(oa.offer),
                        negotiated_timelock: 0,
                        exchange,
                        finalization: FinalizationProgress::default(),
                    }
                })
                .collect();
            (makers, spare_addrs)
        };

        log::info!(
            "Selected {} makers (+ {} spares): {}",
            selected_makers.len(),
            spares.len(),
            selected_makers
                .iter()
                .enumerate()
                .map(|(i, m)| format!("#{} {}", i + 1, m.address))
                .collect::<Vec<_>>()
                .join(", ")
        );

        let swap = self.swap_state_mut()?;
        swap.makers = selected_makers;
        swap.spare_makers = spares;
        #[cfg(debug_assertions)]
        log::debug!(
            "[SWAP_ROUTE] Source: taker::api::discover_makers | SwapID: {} | Protocol: {:?} | SelectedMakers: {} | SpareMakers: {} | Amount: {}",
            swap.id,
            swap.params.protocol,
            swap.makers.len(),
            swap.spare_makers.len(),
            swap.params.send_amount.to_sat()
        );
        Ok(())
    }

    /// Negotiate swap details with each maker, substituting spare makers on failure.
    fn negotiate_swap_details(&mut self) -> Result<(), TakerError> {
        log::info!("Negotiating swap details with makers...");

        let swap = self.swap_state()?;
        let maker_count = swap.params.maker_count;
        let swap_id = swap.id.clone();
        let send_amount = swap.params.send_amount;
        let tx_count = swap.params.tx_count;
        let protocol = swap.params.protocol;

        // Get reference height once for consistent absolute timelocks (Taproot).
        // Store it in swap state so funding_create_taproot uses the same height.
        let reference_height =
            {
                let wallet = self.read_wallet()?;
                wallet.blockchain.get_block_count().map_err(|e| {
                    TakerError::General(format!("Failed to get block count: {:?}", e))
                })? as u32
            };
        self.swap_state_mut()?.reference_height = Some(reference_height);

        let mut i = 0;
        while i < maker_count {
            let result = self.negotiate_with_maker(
                i,
                &swap_id,
                send_amount,
                tx_count,
                maker_count,
                reference_height,
            );

            match result {
                Ok(()) => {
                    i += 1;
                }
                Err(e) => {
                    log::warn!("Maker {} failed during negotiation: {:?}", i, e);

                    // Payment routes are priced against the exact makers they
                    // were solved for; substitution would invalidate the gross.
                    // Nothing is funded yet, so failing is safe.
                    if self.swap_state()?.payment.is_some() {
                        return Err(TakerError::General(format!(
                            "Maker {} failed during payment swap negotiation: {:?}",
                            i, e
                        )));
                    }
                    let spare = self.swap_state_mut()?.spare_makers.pop();
                    if let Some(spare_addr) = spare {
                        log::info!("Substituting maker {} with spare at {}", i, spare_addr);
                        let exchange = match protocol {
                            ProtocolVersion::Legacy => {
                                ExchangeProgress::Legacy(LegacyExchangeProgress::default())
                            }
                            ProtocolVersion::Taproot => {
                                ExchangeProgress::Taproot(TaprootExchangeProgress::default())
                            }
                        };
                        let replacement = MakerConnection {
                            address: spare_addr,
                            protocol,
                            tweakable_point: None,
                            offer: None,
                            negotiated_timelock: 0,
                            exchange,
                            finalization: FinalizationProgress::default(),
                        };
                        self.swap_state_mut()?.makers[i] = replacement;
                        // Don't increment i — retry with the replacement
                    } else {
                        return Err(TakerError::General(format!(
                            "Maker {} failed and no spare makers available: {:?}",
                            i, e
                        )));
                    }
                }
            }
        }

        #[cfg(debug_assertions)]
        log::debug!(
            "[SWAP_ROUTE] Source: taker::api::negotiate_swap_details | SwapID: {} | NegotiatedMakers: {} | Protocol: {:?} | ReferenceHeight: {} | TxUtxoCount: {:?}",
            swap_id,
            maker_count,
            protocol,
            reference_height,
            tx_count
        );
        Ok(())
    }

    /// Negotiate swap details with a single maker at the given route index.
    fn negotiate_with_maker(
        &mut self,
        maker_idx: usize,
        swap_id: &str,
        send_amount: Amount,
        tx_count: [u32; 2],
        maker_count: usize,
        reference_height: u32,
    ) -> Result<(), TakerError> {
        let maker_address = self.swap_state()?.makers[maker_idx].address.to_string();
        log::info!("Connecting to maker {} at {}", maker_idx, maker_address);

        let mut stream = self.net_connect(&maker_address)?;

        let negotiated_protocol = self.net_handshake(&mut stream)?;
        log::info!("Handshake complete, protocol: {:?}", negotiated_protocol);

        // Fetch the maker's offer before proposing swap details.
        // This gives us the fee schedule for amount verification later.
        send_message(&mut stream, &TakerToMakerMessage::GetOffer(GetOffer))?;
        let offer_bytes = read_message(&mut stream)?;
        let offer_msg: MakerToTakerMessage = serde_cbor::from_slice(&offer_bytes)?;
        match offer_msg {
            MakerToTakerMessage::Offer(offer) => {
                log::info!(
                    "Received offer from maker {}: base_fee={}, amt_pct={}, time_pct={}",
                    maker_idx,
                    offer.base_fee,
                    offer.amount_relative_fee_pct,
                    offer.time_relative_fee_pct
                );
                Self::validate_offer(&offer, maker_idx, send_amount)?;
                // A repricing since the payment quote would silently move the
                // receiver's amount; abort while nothing is funded. Bitwise
                // float comparison is intentional: any change is a repricing.
                if let (Some(quoted), true) = (
                    self.swap_state()?.makers[maker_idx].offer.as_ref(),
                    self.swap_state()?.payment.is_some(),
                ) {
                    if quoted.base_fee != offer.base_fee
                        || quoted.amount_relative_fee_pct.to_bits()
                            != offer.amount_relative_fee_pct.to_bits()
                        || quoted.time_relative_fee_pct.to_bits()
                            != offer.time_relative_fee_pct.to_bits()
                    {
                        return Err(TakerError::General(format!(
                            "Maker {} repriced its offer between the payment quote and negotiation",
                            maker_idx
                        )));
                    }
                }
                self.swap_state_mut()?.makers[maker_idx].offer = Some(*offer);
            }
            other => {
                return Err(TakerError::General(format!(
                    "Expected Offer from maker {}, got {:?}",
                    maker_idx, other
                )));
            }
        }

        let refund_locktime_offset =
            REFUND_LOCKTIME_BASE + REFUND_LOCKTIME_STEP * (maker_count - maker_idx - 1) as u16;

        // Legacy: send relative offset (CSV). Taproot: send absolute height (CLTV).
        let timelock = if negotiated_protocol == ProtocolVersion::Taproot {
            reference_height + refund_locktime_offset as u32
        } else {
            refund_locktime_offset as u32
        };

        let swap_details = SwapDetails {
            id: swap_id.to_string(),
            protocol_version: negotiated_protocol,
            amount: send_amount,
            tx_count,
            timelock,
            refund_locktime_offset,
        };

        #[cfg(feature = "integration-test")]
        let mut swap_details = swap_details;
        #[cfg(feature = "integration-test")]
        if let TakerBehavior::ForgeBounds(amount) = self.behavior {
            swap_details.amount = amount;
        }

        send_message(
            &mut stream,
            &TakerToMakerMessage::SwapDetails(swap_details.clone()),
        )?;

        let msg_bytes = read_message(&mut stream)?;
        let msg: MakerToTakerMessage = serde_cbor::from_slice(&msg_bytes)?;

        match msg {
            MakerToTakerMessage::AckSwapDetails(ack) => {
                if let Some(tweakable_point) = ack.tweakable_point {
                    let swap = self.swap_state_mut()?;
                    swap.makers[maker_idx].tweakable_point = Some(tweakable_point);
                    swap.makers[maker_idx].protocol = negotiated_protocol;
                    swap.makers[maker_idx].negotiated_timelock = timelock;
                    log::info!("Maker {} accepted swap with tweakable point", maker_idx);

                    #[cfg(feature = "integration-test")]
                    if self.behavior == TakerBehavior::ResendMutatedDetails {
                        let identical = self.resend_swap_details(&maker_address, &swap_details)?;
                        if !matches!(identical, MakerToTakerMessage::AckSwapDetails(ref ack) if ack.tweakable_point.is_some())
                        {
                            return Err(TakerError::General(
                                "Maker rejected identical resent SwapDetails".to_string(),
                            ));
                        }
                        swap_details.amount += Amount::from_sat(1);
                        return Err(TakerError::General(
                            match self.resend_swap_details(&maker_address, &swap_details) {
                                Ok(MakerToTakerMessage::AckSwapDetails(ack)) => {
                                    if ack.tweakable_point.is_none() {
                                        "Maker rejected mutated resent SwapDetails".to_string()
                                    } else {
                                        "Maker accepted mutated resent SwapDetails".to_string()
                                    }
                                }
                                Ok(other) => format!(
                                    "Maker rejected mutated resent SwapDetails: {:?}",
                                    other
                                ),
                                Err(e) => {
                                    format!("Maker rejected mutated resent SwapDetails: {:?}", e)
                                }
                            },
                        ));
                    }

                    #[cfg(feature = "integration-test")]
                    if self.behavior == TakerBehavior::CloseAtAckResponse {
                        log::warn!(
                            "Test behavior: closing after receiving AckSwapDetails from maker {}",
                            maker_idx
                        );
                        return Err(TakerError::General(
                            "Test: closing at ack response".to_string(),
                        ));
                    }

                    Ok(())
                } else {
                    Err(TakerError::General(format!(
                        "Maker {} rejected swap",
                        maker_idx
                    )))
                }
            }
            _ => Err(TakerError::General(format!(
                "Unexpected message from maker {}: expected AckSwapDetails",
                maker_idx
            ))),
        }
    }

    #[cfg(feature = "integration-test")]
    fn resend_swap_details(
        &self,
        maker_address: &str,
        details: &SwapDetails,
    ) -> Result<MakerToTakerMessage, TakerError> {
        let mut stream = self.net_connect(maker_address)?;
        self.net_handshake(&mut stream)?;
        send_message(&mut stream, &TakerToMakerMessage::GetOffer(GetOffer))?;
        read_message(&mut stream)?;
        send_message(
            &mut stream,
            &TakerToMakerMessage::SwapDetails(details.clone()),
        )?;
        Ok(serde_cbor::from_slice(&read_message(&mut stream)?)?)
    }

    /// Validate a maker's offer for fee sanity and size limits.
    pub(super) fn validate_offer(
        offer: &Offer,
        maker_idx: usize,
        send_amount: Amount,
    ) -> Result<(), TakerError> {
        // Fee percentage sanity: must be finite and non-negative, and < 100%
        if offer.amount_relative_fee_pct.is_nan()
            || offer.amount_relative_fee_pct.is_infinite()
            || offer.amount_relative_fee_pct < 0.0
            || offer.amount_relative_fee_pct >= 100.0
        {
            return Err(TakerError::General(format!(
                "Maker {} offer has invalid amount_relative_fee_pct: {}",
                maker_idx, offer.amount_relative_fee_pct
            )));
        }
        if offer.time_relative_fee_pct.is_nan()
            || offer.time_relative_fee_pct.is_infinite()
            || offer.time_relative_fee_pct < 0.0
            || offer.time_relative_fee_pct >= 100.0
        {
            return Err(TakerError::General(format!(
                "Maker {} offer has invalid time_relative_fee_pct: {}",
                maker_idx, offer.time_relative_fee_pct
            )));
        }

        // Base fee must not exceed the send amount (that would consume everything)
        if offer.base_fee > send_amount.to_sat() {
            return Err(TakerError::General(format!(
                "Maker {} offer base_fee ({} sats) exceeds send amount ({} sats)",
                maker_idx,
                offer.base_fee,
                send_amount.to_sat()
            )));
        }

        // Size limits must be consistent
        if offer.min_size > offer.max_size {
            return Err(TakerError::General(format!(
                "Maker {} offer has min_size ({}) > max_size ({})",
                maker_idx, offer.min_size, offer.max_size
            )));
        }

        // Send amount must fall within the maker's accepted range
        let send_sats = send_amount.to_sat();
        if send_sats < offer.min_size {
            return Err(TakerError::General(format!(
                "Send amount ({} sats) is below maker {} min_size ({} sats)",
                send_sats, maker_idx, offer.min_size
            )));
        }
        if send_sats > offer.max_size {
            return Err(TakerError::General(format!(
                "Send amount ({} sats) exceeds maker {} max_size ({} sats)",
                send_sats, maker_idx, offer.max_size
            )));
        }

        Ok(())
    }

    /// Substitute a maker at the given route index with a spare, then negotiate with it.
    ///
    /// This is used during exchange when a maker fails mid-protocol. The spare address
    /// is placed at `target_idx`, and the standard negotiation handshake (offer, swap
    /// details, ack) is performed to populate its `tweakable_point` and `offer`.
    pub(crate) fn substitute_and_negotiate_spare(
        &mut self,
        target_idx: usize,
        spare_addr: MakerAddress,
    ) -> Result<(), TakerError> {
        log::info!(
            "Substituting maker {} with spare at {}",
            target_idx,
            spare_addr
        );

        let protocol = self.swap_state()?.params.protocol;
        let exchange = match protocol {
            ProtocolVersion::Legacy => ExchangeProgress::Legacy(LegacyExchangeProgress::default()),
            ProtocolVersion::Taproot => {
                ExchangeProgress::Taproot(TaprootExchangeProgress::default())
            }
        };
        let replacement = MakerConnection {
            address: spare_addr,
            protocol,
            tweakable_point: None,
            offer: None,
            negotiated_timelock: 0,
            exchange,
            finalization: FinalizationProgress::default(),
        };
        self.swap_state_mut()?.makers[target_idx] = replacement;

        // Negotiate with the spare maker.
        let swap_id = self.swap_state()?.id.clone();
        let send_amount = self.swap_state()?.params.send_amount;
        let tx_count = self.swap_state()?.params.tx_count;
        let maker_count = self.swap_state()?.params.maker_count;
        let reference_height =
            {
                let wallet = self.read_wallet()?;
                wallet.blockchain.get_block_count().map_err(|e| {
                    TakerError::General(format!("Failed to get block count: {:?}", e))
                })? as u32
            };
        self.swap_state_mut()?.reference_height = Some(reference_height);
        self.negotiate_with_maker(
            target_idx,
            &swap_id,
            send_amount,
            tx_count,
            maker_count,
            reference_height,
        )?;
        #[cfg(debug_assertions)]
        log::debug!(
            "[SWAP_ROUTE] Source: taker::api::substitute_and_negotiate_spare | SwapID: {} | Action: substitute_maker | MakerIndex: {} | Address: {} | ReferenceHeight: {}",
            swap_id,
            target_idx,
            self.swap_state()?.makers[target_idx].address,
            reference_height
        );
        Ok(())
    }

    /// Re-initialize funding after substituting the first maker.
    ///
    /// Clears old outgoing swapcoins from the wallet and swap state, then creates
    /// new funding transactions using the new first maker's tweakable point.
    pub(crate) fn funding_reinitialize(&mut self) -> Result<(), TakerError> {
        log::info!("Re-initializing funding after maker substitution");

        // Remove old outgoing swapcoins from wallet.
        let swap_id = self.swap_state()?.id.clone();
        {
            let mut wallet = self.write_wallet()?;
            let old_keys = wallet.outgoing_keys_for_swap(&swap_id);
            #[cfg(debug_assertions)]
            log::debug!(
                "[FUNDING_STATE] Source: taker::api::funding_reinitialize | SwapID: {} | Action: reset_after_substitution | OutgoingSwapcoinsRemoved: {}",
                swap_id,
                old_keys.len()
            );
            for key in &old_keys {
                wallet.remove_outgoing_swapcoin(key);
            }
            wallet.save_to_disk()?;
        }

        // Clear outgoing swapcoins from swap state.
        self.swap_state_mut()?.outgoing_swapcoins.clear();

        // Re-create funding with the new first maker.
        self.funding_initialize()
    }

    /// Initialize swap funding by creating outgoing swapcoins.
    fn funding_initialize(&mut self) -> Result<(), TakerError> {
        log::info!("Initializing swap funding...");

        let swap = self.swap_state()?;

        let first_maker = swap
            .makers
            .first()
            .ok_or_else(|| TakerError::General("No makers in swap route".to_string()))?;

        let tweakable_point = first_maker.tweakable_point.ok_or_else(|| {
            TakerError::General("First maker missing tweakable point".to_string())
        })?;

        let protocol = first_maker.protocol;

        let maker_count = swap.params.maker_count;
        let refund_locktime_offset =
            REFUND_LOCKTIME_BASE + REFUND_LOCKTIME_STEP * maker_count as u16;

        let hashvalue = Hash160::hash(&swap.preimage);
        let preimage = swap.preimage;
        let send_amount = swap.params.send_amount;
        let swap_id = swap.id.clone();
        let swap_tx_count = swap.params.max_tx_count() as usize;
        let manually_selected_outpoints = swap.params.manually_selected_outpoints.clone();
        let reference_height = swap.reference_height;

        let (multisig_pubkeys, multisig_nonces, hashlock_pubkeys, hashlock_nonces) =
            generate_maker_keys(
                &tweakable_point,
                if protocol == ProtocolVersion::Legacy {
                    swap.params.max_tx_count()
                } else {
                    1
                },
            )?;

        // For Taproot, generate hashlock nonces for ALL hops (one per maker)
        // and derive the tweaked hashlock pubkey for the first hop.
        let (taproot_hashlock_nonces, taproot_hashlock_pubkey) =
            if protocol == ProtocolVersion::Taproot {
                let nonces: Vec<SecretKey> = (0..maker_count)
                    .map(|_| SecretKey::new(&mut OsRng))
                    .collect();
                let pubkey = calculate_pubkey_from_nonce(&tweakable_point, &nonces[0])?;
                (Some(nonces), Some(pubkey))
            } else {
                (None, None)
            };

        {
            let swap = self.swap_state_mut()?;
            // Multisig nonces are only used by Legacy for ProofOfFunding recovery.
            // Taproot uses a single aggregated key, so these are not needed.
            if protocol == ProtocolVersion::Legacy {
                swap.multisig_nonces = multisig_nonces;
            }
            if let Some(ref nonces) = taproot_hashlock_nonces {
                swap.hashlock_nonces = nonces.clone();
            } else {
                swap.hashlock_nonces = hashlock_nonces;
            }
        }

        let mut wallet = self.write_wallet()?;

        let network = wallet.store.network;

        let swapcoins = match protocol {
            ProtocolVersion::Legacy => Self::funding_create_legacy(
                &mut wallet,
                &multisig_pubkeys,
                &hashlock_pubkeys,
                hashvalue,
                refund_locktime_offset,
                send_amount,
                &swap_id,
                network,
                manually_selected_outpoints,
            )?,
            ProtocolVersion::Taproot => {
                let hashlock_pubkey = taproot_hashlock_pubkey
                    .ok_or_else(|| TakerError::General("taproot hashlock pubkey not set".into()))?;
                Self::funding_create_taproot(
                    &mut wallet,
                    &vec![tweakable_point; swap_tx_count],
                    &vec![hashlock_pubkey; swap_tx_count],
                    preimage,
                    refund_locktime_offset,
                    send_amount,
                    &swap_id,
                    network,
                    manually_selected_outpoints,
                    reference_height,
                )?
            }
        };

        for swapcoin in &swapcoins {
            wallet.add_outgoing_swapcoin(swapcoin);
        }

        wallet.save_to_disk()?;
        drop(wallet);

        let swap = self.swap_state_mut()?;
        let num_swapcoins = swapcoins.len();
        swap.outgoing_swapcoins = swapcoins;

        #[cfg(debug_assertions)]
        log::debug!(
            "[FUNDING_STATE] Source: taker::api::funding_initialize | SwapID: {} | Protocol: {:?} | OutgoingSwapcoins: {} | SendAmount: {} | ManualUtxos: {}",
            swap.id,
            protocol,
            num_swapcoins,
            send_amount.to_sat(),
            swap.params
                .manually_selected_outpoints
                .as_ref()
                .map(Vec::len)
                .unwrap_or_default()
        );
        log::info!("Created {} outgoing swapcoins for funding", num_swapcoins);
        Ok(())
    }

    /// Perform handshake with a maker and verify protocol support.
    pub(crate) fn net_handshake(
        &self,
        stream: &mut TcpStream,
    ) -> Result<ProtocolVersion, TakerError> {
        // Send TakerHello
        send_message(stream, &TakerToMakerMessage::TakerHello(TakerHello))?;

        let msg_bytes = read_message(stream)?;
        let msg: MakerToTakerMessage = serde_cbor::from_slice(&msg_bytes)?;

        match msg {
            MakerToTakerMessage::MakerHello(maker_hello) => {
                let desired = self.swap_state()?.params.protocol;
                if maker_hello.supported_protocols.contains(&desired) {
                    Ok(desired)
                } else {
                    Err(TakerError::General(format!(
                        "Maker does not support {:?}. Supported: {:?}",
                        desired, maker_hello.supported_protocols
                    )))
                }
            }
            _ => Err(TakerError::General(
                "Expected MakerHello response".to_string(),
            )),
        }
    }

    /// Connect to a maker using either direct connection or Tor proxy.
    pub(crate) fn net_connect(&self, address: &str) -> Result<TcpStream, TakerError> {
        log::debug!("Connecting to maker at {}", address);
        let timeout = Duration::from_secs(CONNECT_TIMEOUT_SECS);

        #[cfg(feature = "integration-test")]
        let socket = TcpStream::connect(address)
            .map_err(|e| TakerError::General(format!("Failed to connect to {}: {}", address, e)))?;

        #[cfg(not(feature = "integration-test"))]
        let socket = match self.config.connection_type {
            ConnectionType::Clearnet => TcpStream::connect(address).map_err(|e| {
                TakerError::General(format!("Failed to connect to {}: {}", address, e))
            })?,
            ConnectionType::Tor => {
                use crate::protocol::common_messages::OPENSWAP_PORT;

                socks5_connect(
                    self.config.socks_port,
                    address,
                    OPENSWAP_PORT,
                    None,
                    timeout,
                )
                .map_err(|e| {
                    TakerError::General(format!("Failed to connect to {} via Tor: {}", address, e))
                })?
            }
        };

        // Reads can block for minutes: a maker answers contract data only after
        // our contracts confirm, and that wait is block-bound, not message-bound.
        socket
            .set_read_timeout(Some(Duration::from_secs(MAKER_RESPONSE_TIMEOUT_SECS)))
            .and_then(|_| socket.set_write_timeout(Some(timeout)))
            .map_err(|e| TakerError::General(format!("Failed to set socket timeout: {}", e)))?;

        Ok(socket)
    }

    /// Connect to every maker in the route and start the heartbeat that keeps
    /// their idle timers warm while we negotiate each hop. Connection failures
    /// are logged and skipped — the protocol's own reads report a dead maker.
    pub(crate) fn start_route_heartbeat(
        &self,
        swap_id: &str,
    ) -> Option<super::background_services::RouteHeartbeat> {
        let addresses: Vec<String> = self
            .swap_state()
            .ok()?
            .makers
            .iter()
            .map(|maker| maker.address.to_string())
            .collect();
        let mut streams = Vec::with_capacity(addresses.len());
        for address in addresses {
            match self.net_connect(&address) {
                Ok(mut stream) => {
                    if let Err(e) = self.net_handshake(&mut stream) {
                        log::warn!("route heartbeat: handshake with {address} failed: {e:?}");
                        continue;
                    }
                    streams.push(stream);
                }
                Err(e) => log::warn!("route heartbeat: connect to {address} failed: {e:?}"),
            }
        }
        match super::background_services::RouteHeartbeat::start(swap_id, streams) {
            Ok(heartbeat) => Some(heartbeat),
            Err(e) => {
                log::warn!("route heartbeat failed to start: {e:?}");
                None
            }
        }
    }

    /// Finalize the swap by exchanging private keys with all makers.
    fn finalize_swap(&mut self) -> Result<(), TakerError> {
        log::info!("Finalizing swap...");

        self.finalize_exchange_privkeys()?;

        self.persist_swap(SwapPhase::PrivkeysForwarded)?;

        self.persist_incoming_swapcoins()?;

        log::info!("Swap finalized successfully");
        Ok(())
    }

    /// Attempt finalization with retries between attempts.
    fn finalize_with_retry(&mut self) -> Result<(), TakerError> {
        // The loop runs at least once, so falling through means the last
        // attempt failed and `last_error` is set.
        let mut last_error = None;
        for attempt in 1..=MAX_FINALIZE_RETRIES {
            match self.finalize_swap() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    log::warn!(
                        "Finalization attempt {}/{} failed: {:?}",
                        attempt,
                        MAX_FINALIZE_RETRIES,
                        e
                    );

                    if self
                        .breach_detector
                        .as_ref()
                        .is_some_and(|d| d.requires_abort())
                    {
                        log::error!(
                            "Contract broadcast detected during finalization — aborting retries"
                        );
                        return Err(TakerError::General(
                            "Contract broadcast detected during finalization".to_string(),
                        ));
                    }

                    if attempt < MAX_FINALIZE_RETRIES {
                        log::info!("Retrying in {:?}...", FINALIZE_RETRY_DELAY);
                        thread::sleep(FINALIZE_RETRY_DELAY);
                    }
                    last_error = Some(e);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            TakerError::General("finalization failed with no recorded error".into())
        }))
    }

    /// Exchange private keys with all makers in forward order.
    /// Each maker receives the privkey for their incoming contract and
    /// responds with their outgoing privkey.
    fn finalize_exchange_privkeys(&mut self) -> Result<(), TakerError> {
        let swap = self.swap_state()?;
        let num_makers = swap.makers.len();
        let protocol = swap.params.protocol;
        let swap_id = swap.id.clone();

        // Start with the taker's own outgoing privkeys (for Maker[0]'s incoming)
        let mut current_privkeys: Vec<SecretKey> = swap
            .outgoing_swapcoins
            .iter()
            .filter_map(|sc| sc.my_privkey)
            .collect();
        if current_privkeys.is_empty() {
            return Err(TakerError::General("No outgoing privkey".to_string()));
        }

        for i in 0..num_makers {
            let maker_address = self.swap_state()?.makers[i].address.to_string();
            let mut stream = self.net_connect(&maker_address)?;

            self.net_handshake(&mut stream)?;

            log::info!("Sending privkey to maker {} and awaiting response", i);

            let msg = Self::msg_build_handover(protocol, swap_id.clone(), &current_privkeys);
            send_message(&mut stream, &msg)?;

            let msg_bytes = read_message(&mut stream)?;
            let msg: MakerToTakerMessage = serde_cbor::from_slice(&msg_bytes)?;

            let received_privkeys: Vec<SecretKey> = match msg {
                MakerToTakerMessage::LegacyPrivateKeyHandover(handover)
                | MakerToTakerMessage::TaprootPrivateKeyHandover(handover) => {
                    log::info!("Received private key from maker {}", i);
                    if handover.privkeys.is_empty() {
                        return Err(TakerError::General(format!(
                            "Empty privkey response from maker {}",
                            i
                        )));
                    }
                    handover.privkeys.iter().map(|p| p.key).collect()
                }
                _ => {
                    return Err(TakerError::General(format!(
                        "Unexpected response from maker {}: expected PrivateKeyHandover",
                        i
                    )));
                }
            };

            self.swap_state_mut()?.makers[i]
                .finalization
                .privkey_received = true;
            self.swap_state_mut()?.makers[i]
                .finalization
                .privkey_forwarded = true;
            #[cfg(debug_assertions)]
            log::debug!(
                "[FINALIZATION] SwapID: {} | MakerIndex: {} | MakersTotal: {} | PrivkeyReceived: true | PrivkeyForwarded: true",
                swap_id,
                i,
                num_makers
            );

            // For the last maker: validate and set their privkey on taker's incoming swapcoins.
            // Derive the public key from the received private key and verify it matches
            // the expected other_pubkey on the incoming swapcoins, preventing a malicious
            // maker from sending a garbage key that would make funds unspendable.
            if i == num_makers - 1 {
                let secp = bitcoin::secp256k1::Secp256k1::new();
                let incoming = &mut self.swap_state_mut()?.incoming_swapcoins;
                for (incoming, received_privkey) in
                    incoming.iter_mut().zip(received_privkeys.iter())
                {
                    let derived_pubkey = PublicKey {
                        compressed: true,
                        inner: bitcoin::secp256k1::PublicKey::from_secret_key(
                            &secp,
                            received_privkey,
                        ),
                    };
                    if let Some(expected_pubkey) = incoming.other_pubkey {
                        if derived_pubkey != expected_pubkey {
                            return Err(TakerError::General(format!(
                                "Last maker {} sent incorrect private key: derived pubkey {} \
                                 does not match expected {}",
                                i, derived_pubkey, expected_pubkey
                            )));
                        }
                    }
                    incoming.set_other_privkey(*received_privkey);
                }
                log::info!(
                    "Validated and set taker's incoming swapcoin other_privkeys from last maker ({})",
                    i
                );
            }

            current_privkeys = received_privkeys;
        }

        Ok(())
    }

    /// Persist incoming swapcoins, keyed by contract txid so repeats overwrite.
    /// Called when contracts are accepted — a crash before finalization must not
    /// lose what the taker is owed — and again after the privkey handover.
    pub(crate) fn persist_incoming_swapcoins(&mut self) -> Result<(), TakerError> {
        let incoming = self.swap_state()?.incoming_swapcoins.clone();
        let mut wallet = self.write_wallet()?;
        for swapcoin in &incoming {
            wallet.add_incoming_swapcoin(swapcoin);
        }

        wallet.save_to_disk()?;
        #[cfg(debug_assertions)]
        log::debug!(
            "[WALLET_STATE] Action: persist_incoming | Added: {} | IncomingStored: {}",
            incoming.len(),
            wallet.get_incoming_swapcoins_count()
        );
        Ok(())
    }

    /// Create a protocol-appropriate private key handover message.
    fn msg_build_handover(
        protocol: ProtocolVersion,
        swap_id: String,
        privkeys: &[SecretKey],
    ) -> TakerToMakerMessage {
        let handover = PrivateKeyHandover {
            id: swap_id,
            privkeys: privkeys
                .iter()
                .map(|key| SwapPrivkey {
                    identifier: bitcoin::ScriptBuf::new(),
                    key: *key,
                })
                .collect(),
        };
        match protocol {
            ProtocolVersion::Legacy => TakerToMakerMessage::LegacyPrivateKeyHandover(handover),
            ProtocolVersion::Taproot => TakerToMakerMessage::TaprootPrivateKeyHandover(handover),
        }
    }

    /// Build a `SwapRecord` from the current `OngoingSwapState`.
    fn persist_build_record(&self, swap: &OngoingSwapState) -> Result<SwapRecord, TakerError> {
        let now = now_secs();
        Ok(SwapRecord {
            swap_id: swap.id.clone(),
            preimage: swap.preimage,
            protocol: swap.params.protocol,
            send_amount_sat: swap.params.send_amount.to_sat(),
            maker_count: swap.params.maker_count,
            phase: swap.phase,
            failed_at_phase: None,
            failure_reason: None,
            makers: swap
                .makers
                .iter()
                .map(|m| MakerProgress {
                    address: m.address.to_string(),
                    negotiated: m.tweakable_point.is_some(),
                    exchange: m.exchange.clone(),
                    finalization: m.finalization.clone(),
                })
                .collect(),
            outgoing_contract_txids: swap
                .outgoing_swapcoins
                .iter()
                .map(|sc| sc.contract_tx.compute_txid())
                .collect(),
            incoming_contract_txids: swap
                .incoming_swapcoins
                .iter()
                .map(|sc| sc.contract_tx.compute_txid())
                .collect(),
            watchonly_contract_txids: swap
                .watchonly_swapcoins
                .iter()
                .map(|sc| sc.contract_tx.compute_txid())
                .collect(),
            recovery: RecoveryState::default(),
            multisig_nonces: swap
                .multisig_nonces
                .iter()
                .map(|k| SerializableSecretKey::from(*k))
                .collect(),
            hashlock_nonces: swap
                .hashlock_nonces
                .iter()
                .map(|k| SerializableSecretKey::from(*k))
                .collect(),
            payment_address: swap.payment.as_ref().map(|p| p.address.to_string()),
            payment_amount_sat: swap.payment.as_ref().map(|p| p.amount.to_sat()),
            created_at: now,
            updated_at: now,
        })
    }

    /// Flush the current swap state to the tracker on disk.
    ///
    /// Sets the swap phase and rebuilds the full record from `OngoingSwapState`
    /// so that maker progress, txids, and nonces stay up-to-date. Preserves
    /// `created_at` and `recovery` from any existing record.
    pub(crate) fn persist_swap(&mut self, phase: SwapPhase) -> Result<(), TakerError> {
        let swap = self.swap_state_mut()?;
        swap.phase = phase;

        // Snapshot preserved fields from any existing record.
        let swap_id = self.swap_state()?.id.clone();
        let tracker_guard = lock_debug!(self.swap_tracker.lock())
            .map_err(|_| TakerError::General("swap tracker lock poisoned".into()))?;
        let existing = tracker_guard.get_record(&swap_id);
        let created_at = existing.map(|r| r.created_at);
        let recovery = existing.map(|r| r.recovery.clone());
        let failed_at = existing.and_then(|r| r.failed_at_phase);
        let failure_reason = existing.and_then(|r| r.failure_reason.clone());
        drop(tracker_guard);

        // Build full record from current live state.
        let swap_ref = self.swap_state()?;
        let mut record = self.persist_build_record(swap_ref)?;

        // Restore preserved fields so we don't lose recovery progress or timestamps.
        if let Some(ts) = created_at {
            record.created_at = ts;
        }
        if let Some(rec) = recovery {
            record.recovery = rec;
        }
        if let Some(fat) = failed_at {
            record.failed_at_phase = Some(fat);
        }
        if let Some(reason) = failure_reason {
            record.failure_reason = Some(reason);
        }

        lock_debug!(self.swap_tracker.lock())
            .map_err(|_| TakerError::General("swap tracker lock poisoned".into()))?
            .save_record(&record)
    }

    /// Flush the current swap state to disk without changing the phase.
    pub(crate) fn persist_progress(&mut self) -> Result<(), TakerError> {
        let phase = self.swap_state()?.phase;
        self.persist_swap(phase)
    }

    /// Persist a swap failure (SP-ERR) with the phase at which failure occurred.
    fn persist_failure(&mut self, failed_at: SwapPhase, error: &TakerError) {
        if let Ok(swap) = self.swap_state() {
            let swap_id = swap.id.clone();
            if let Ok(mut record) = self.persist_build_record(swap) {
                record.phase = SwapPhase::Failed;
                record.failed_at_phase = Some(failed_at);
                record.failure_reason = Some(format!("{:?}", error));
                record.updated_at = now_secs();
                // The failure was already reported to the caller; a poisoned
                // tracker here is no reason to panic.
                let Ok(mut tracker) = lock_debug!(self.swap_tracker.lock()) else {
                    log::error!("swap tracker lock poisoned; skipping failure persist");
                    return;
                };
                // Preserve existing recovery state if resuming
                if let Some(existing) = tracker.get_record(&swap_id) {
                    record.recovery = existing.recovery.clone();
                    record.created_at = existing.created_at;
                }
                if let Err(e) = tracker.save_record(&record) {
                    log::error!("Failed to persist swap failure: {:?}", e);
                }
            }
        }
    }

    /// Generate a detailed swap report for audit trail (matches master's `generate_swap_report`).
    ///
    /// Computes UTXO diffs, per-maker fee breakdown, contract txids, and funding txids.
    /// Prints the report to console and saves it beside the active wallet file.
    /// `swept` carries the settlement outcome, and is `None` on failure paths
    /// where no sweep ran.
    fn generate_swap_report(
        &self,
        initial_utxos: &[ListUnspentResultEntry],
        start_time: Instant,
        status: SwapStatus,
        error_message: Option<String>,
        swept: Option<&RecoveryOutcome>,
    ) -> Result<TakerReport, TakerError> {
        let swap = self.swap_state()?;
        let swap_duration = start_time.elapsed();

        let wallet = self.read_wallet()?;

        // UTXO tracking: compute consumed inputs and new outputs
        let all_regular_utxo = wallet.list_descriptor_utxo_spend_info();

        let initial_outpoints: HashSet<OutPoint> = initial_utxos
            .iter()
            .map(|utxo| OutPoint {
                txid: utxo.txid,
                vout: utxo.vout,
            })
            .collect();

        let current_outpoints: HashSet<OutPoint> = all_regular_utxo
            .iter()
            .map(|(utxo, _)| OutPoint {
                txid: utxo.txid,
                vout: utxo.vout,
            })
            .collect();

        // Input UTXOs consumed by the swap (present initially, absent now)
        let input_utxos: Vec<u64> = initial_utxos
            .iter()
            .filter(|utxo| {
                !current_outpoints.contains(&OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                })
            })
            .map(|utxo| utxo.amount.to_sat())
            .collect();

        // New regular UTXOs created (present now, absent initially)
        let output_regular_utxos: Vec<&(ListUnspentResultEntry, _)> = all_regular_utxo
            .iter()
            .filter(|(utxo, _)| {
                !initial_outpoints.contains(&OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                })
            })
            .collect();

        let output_change_amounts: Vec<u64> = output_regular_utxos
            .iter()
            .map(|(utxo, _)| utxo.amount.to_sat())
            .collect();

        let network = wallet.store.network;
        let wallet_file_name = wallet.get_name().to_string();

        let output_swap_utxos: Vec<(u64, String)> = wallet
            .list_swept_incoming_swap_utxos()
            .iter()
            .map(|(utxo, _)| {
                let address = utxo
                    .address
                    .as_ref()
                    .and_then(|addr| addr.clone().require_network(network).ok())
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                (utxo.amount.to_sat(), address)
            })
            .collect();

        let output_swap_amounts: Vec<u64> = output_swap_utxos
            .iter()
            .map(|(amount, _)| *amount)
            .collect();

        let output_change_utxos: Vec<(u64, String)> = output_regular_utxos
            .iter()
            .map(|(utxo, _)| {
                let address = utxo
                    .address
                    .as_ref()
                    .and_then(|addr| addr.clone().require_network(network).ok())
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                (utxo.amount.to_sat(), address)
            })
            .collect();

        let output_utxos = [output_change_amounts.clone(), output_swap_amounts.clone()].concat();
        let total_input_amount: u64 = input_utxos.iter().sum();
        let total_output_amount: u64 = output_utxos.iter().sum();
        let total_output_swap_amount: u64 = output_swap_amounts.iter().sum();

        // Maker addresses
        let maker_count = swap.params.maker_count;
        let maker_addresses: Vec<String> = swap
            .makers
            .iter()
            .take(maker_count)
            .map(|m| m.address.to_string())
            .collect();

        // Funding txids from outgoing swapcoins
        let funding_txids: Vec<Vec<String>> = if !swap.outgoing_swapcoins.is_empty() {
            vec![swap
                .outgoing_swapcoins
                .iter()
                .filter_map(|sc| {
                    sc.funding_tx
                        .as_ref()
                        .map(|tx| tx.compute_txid().to_string())
                })
                .collect()]
        } else {
            vec![]
        };

        // Per-maker fee breakdown (same algorithm as master)
        let mut maker_fee_info = Vec::new();
        let mut temp_target_amount = swap.params.send_amount.to_sat();
        let completed_hops = swap.makers.len().min(maker_count);

        log::info!(
            "Calculating fees for {} makers, maker count: {}",
            swap.makers.len(),
            maker_count,
        );

        let total_maker_fees: u64 = (0..completed_hops)
            .map(|maker_index| {
                let maker_refund_locktime = REFUND_LOCKTIME_BASE
                    + REFUND_LOCKTIME_STEP * (maker_count - maker_index - 1) as u16;

                let (base_fee, amount_rel_fee, time_rel_fee) = if let Some(offer) =
                    swap.makers[maker_index].offer.as_ref()
                {
                    let bf = offer.base_fee;
                    let arf = ((offer.amount_relative_fee_pct * temp_target_amount as f64) / 100.0)
                        .ceil() as u64;
                    let trf = ((offer.time_relative_fee_pct
                        * maker_refund_locktime as f64
                        * temp_target_amount as f64)
                        / 100.0)
                        .ceil() as u64;
                    (bf, arf, trf)
                } else {
                    (0, 0, 0)
                };

                let total_maker_fee = base_fee + amount_rel_fee + time_rel_fee;

                maker_fee_info.push(ReportMakerFeeInfo {
                    maker_index,
                    maker_address: swap.makers[maker_index].address.to_string(),
                    base_fee: base_fee as f64,
                    amount_relative_fee: amount_rel_fee as f64,
                    time_relative_fee: time_rel_fee as f64,
                    total_fee: total_maker_fee as f64,
                });

                temp_target_amount = temp_target_amount.saturating_sub(total_maker_fee);
                total_maker_fee
            })
            .sum();

        // A PaySwap settlement pays an external receiver, so it does not appear
        // among this wallet's outputs. Account for the confirmed receiver output
        // before deriving fees; otherwise the payment principal is mislabeled as
        // mining/maker fees in the report.
        let payment = swap.payment.as_ref().map(|p| {
            let resolved = swept
                .map(|outcome| outcome.resolved.as_slice())
                .unwrap_or(&[]);
            // Pair each of this swap's incoming coins with the spend that
            // settled it, dropping any the sweep did not resolve.
            let settled = swap.incoming_swapcoins.iter().filter_map(|swapcoin| {
                let contract_txid = swapcoin.contract_tx.compute_txid();
                resolved
                    .iter()
                    .find(|(resolved_txid, _)| *resolved_txid == contract_txid)
                    .map(|(_, spending_txid)| (swapcoin, spending_txid))
            });

            let (settlement_txids, delivered_amount) = settled.fold(
                (Vec::new(), 0u64),
                |(mut txids, delivered), (swapcoin, spending_txid)| {
                    txids.push(spending_txid.to_string());
                    let paid = swapcoin
                        .payment_target
                        .as_ref()
                        .map_or(0, |target| target.amount.to_sat());
                    (txids, delivered + paid)
                },
            );

            // `sweep_incoming_swapcoins` adds an entry to `resolved` only after
            // the settlement transaction has reached one confirmation.
            let all_settlements_confirmed = !swap.incoming_swapcoins.is_empty()
                && settlement_txids.len() == swap.incoming_swapcoins.len();
            crate::wallet::PaymentResult {
                receiver_address: p.address.to_string(),
                requested_amount: p.amount.to_sat(),
                delivered_amount,
                settlement_txids,
                confirmed: all_settlements_confirmed && delivered_amount == p.amount.to_sat(),
            }
        });

        let delivered_payment = payment.as_ref().map_or(0, |p| p.delivered_amount);
        let accounted_output_amount = total_output_amount.saturating_add(delivered_payment);
        let total_fee = total_input_amount.saturating_sub(accounted_output_amount);
        let mining_fee = total_fee.saturating_sub(total_maker_fees);
        let fee_denominator = payment
            .as_ref()
            .map_or(swap.params.send_amount.to_sat(), |p| p.requested_amount);
        let fee_percentage = if fee_denominator == 0 {
            0.0
        } else {
            (total_fee as f64 / fee_denominator as f64) * 100.0
        };

        // Contract txids
        let outgoing_contract_txid = if !swap.outgoing_swapcoins.is_empty() {
            Some(
                swap.outgoing_swapcoins
                    .iter()
                    .map(|sc| sc.contract_tx.compute_txid().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        } else {
            None
        };

        let incoming_contract_txid = if !swap.incoming_swapcoins.is_empty() {
            Some(
                swap.incoming_swapcoins
                    .iter()
                    .map(|sc| sc.contract_tx.compute_txid().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        } else {
            None
        };

        let swap_end_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let report = TakerReport {
            status: status.clone(),
            swap_id: swap.id.clone(),
            swap_duration_seconds: swap_duration.as_secs_f64(),
            outgoing_amount: swap.params.send_amount.to_sat(),
            incoming_amount: total_output_swap_amount,
            fee_paid: total_fee,
            makers_count: maker_count,
            maker_addresses,
            funding_txids,
            total_maker_fees,
            mining_fee,
            fee_percentage,
            maker_fee_info,
            input_utxos,
            output_change_amounts,
            output_swap_amounts,
            output_change_utxos,
            output_swap_utxos,
            network: network.to_string(),
            error_message,
            incoming_contract_txid,
            outgoing_contract_txid,
            end_timestamp: swap_end_ts,
            start_timestamp: swap_end_ts.saturating_sub(swap_duration.as_secs()),
            deniability_proof: None,
            payment,
        }
        .with_proof(
            swap.incoming_swapcoins.last(),
            swap.outgoing_swapcoins.last(),
        );

        report.print();
        let data_dir = self
            .config
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(get_taker_dir)?;
        if let Err(e) = report.save_for_wallet(&data_dir, Some(&wallet_file_name)) {
            log::warn!("Failed to save taker swap report: {:?}", e);
        }

        Ok(report)
    }

    /// Emit a failure report for the current swap (best-effort, does not propagate errors).
    fn emit_failure_report(
        &self,
        initial_utxos: &[ListUnspentResultEntry],
        start_time: Instant,
        error: &TakerError,
    ) {
        if let Err(e) = self.generate_swap_report(
            initial_utxos,
            start_time,
            SwapStatus::Failed,
            Some(format!("{:?}", error)),
            None,
        ) {
            log::warn!("Failed to generate failure report: {:?}", e);
        }
    }

    /// Recover from a failed swap by persisting swapcoins to wallet and
    /// spawning a background `RecoveryLoop` for sweep/timelock recovery.
    ///
    /// All recovery attempts, per-contract outcome tracking, phase transitions,
    /// and wallet cleanup are handled by the `RecoveryLoop`.
    pub fn recover_active_swap(&mut self) -> Result<(), TakerError> {
        // A crashed process never reaches its recovery. Gate here rather than at
        // each failure site, so every path into recovery is covered.
        #[cfg(feature = "integration-test")]
        if self.behavior == TakerBehavior::CrashBeforeRecovery {
            log::warn!("Test behavior: crashing instead of recovering");
            return Ok(());
        }

        log::warn!("Starting swap recovery...");

        let swap_id = if let Some(ref swap) = self.ongoing_swap {
            let id = swap.id.clone();
            let mut wallet = self.write_wallet()?;
            for outgoing in &swap.outgoing_swapcoins {
                wallet.add_outgoing_swapcoin(outgoing);
            }
            for incoming in &swap.incoming_swapcoins {
                wallet.add_incoming_swapcoin(incoming);
            }
            wallet.save_to_disk()?;
            id
        } else {
            // Cross-session recovery: get swap_id from persisted swapcoins
            let wallet = self.read_wallet()?;
            let (incoming, outgoing) = wallet.find_unfinished_swapcoins();
            drop(wallet);
            outgoing
                .first()
                .and_then(|sc| sc.swap_id.clone())
                .or_else(|| incoming.first().and_then(|sc| sc.swap_id.clone()))
                .ok_or_else(|| {
                    TakerError::General("No persisted swapcoins found for recovery".to_string())
                })?
        };

        lock_debug!(self.swap_tracker.lock())
            .map_err(|_| TakerError::General("swap tracker lock poisoned".into()))?
            .update_and_save(&swap_id, |record| {
                record.phase = SwapPhase::Failed;
            })?;

        #[cfg(debug_assertions)]
        log::debug!(
            "[SWAP_STATE] Source: taker::api::recover_active_swap | SwapID: {} | Action: clear_active_for_recovery",
            swap_id
        );
        self.ongoing_swap = None;

        log::info!("Spawning recovery loop for swap {}", swap_id);
        let data_dir = self
            .config
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(get_taker_dir)?;
        self.recovery_loop = Some(RecoveryLoop::start(
            self.wallet.clone(),
            self.swap_tracker.clone(),
            data_dir,
        )?);

        Ok(())
    }

    /// Populate per-contract outcomes for a successful swap.
    ///
    /// On success, all contracts resolve cooperatively:
    /// - Incoming: `KeyPath` (swept via key-path using maker's privkey)
    /// - Outgoing: `KeyPath` (maker claimed via key-path using our privkey)
    /// - Watchonly: `KeyPath` (makers exchanged privkeys and spent cooperatively)
    fn populate_success_outcomes(
        &mut self,
        swap_id: &str,
        swept: &RecoveryOutcome,
    ) -> Result<(), TakerError> {
        let mut incoming_outcomes = Vec::new();
        let mut outgoing_outcomes = Vec::new();
        let mut watchonly_outcomes = Vec::new();

        // Incoming contracts were swept cooperatively (key-path spend)
        for (contract_txid, spending_txid) in &swept.resolved {
            incoming_outcomes.push(ContractOutcome {
                contract_txid: *contract_txid,
                resolution: ContractResolution::KeyPath,
                spending_txid: Some(*spending_txid),
            });
        }

        // Outgoing + watchonly contracts resolved via key-path
        if let Ok(swap) = self.swap_state() {
            for sc in &swap.outgoing_swapcoins {
                outgoing_outcomes.push(ContractOutcome {
                    contract_txid: sc.contract_tx.compute_txid(),
                    resolution: ContractResolution::KeyPath,
                    spending_txid: None, // Maker's spending tx not tracked by us
                });
            }
            for sc in &swap.watchonly_swapcoins {
                watchonly_outcomes.push(ContractOutcome {
                    contract_txid: sc.contract_tx.compute_txid(),
                    resolution: ContractResolution::KeyPath,
                    spending_txid: None,
                });
            }
        }

        lock_debug!(self.swap_tracker.lock())
            .map_err(|_| TakerError::General("swap tracker lock poisoned".into()))?
            .update_and_save(swap_id, |r| {
                r.recovery.incoming = incoming_outcomes;
                r.recovery.outgoing = outgoing_outcomes;
                r.recovery.watchonly = watchonly_outcomes;
            })?;

        Ok(())
    }

    /// Verify the deniability proof for a specific swap.
    pub fn verify_deniability(&self, swap_id: &str) -> Result<bool, std::io::Error> {
        lock_debug!(self.wallet.read())
            .map_err(|e| std::io::Error::other(format!("wallet lock poisoned: {e}")))?
            .verify_deniability(swap_id)
    }

    // ── CLI helper methods ──────────────────────────────────────────────

    /// Returns the current offerbook snapshot.
    pub fn fetch_offers(&self) -> Result<OfferBook, TakerError> {
        self.offerbook.snapshot()
    }

    /// Triggers a manual offerbook sync and blocks until it completes.
    pub fn sync_offerbook_and_wait(&self) -> Result<(), TakerError> {
        self.offer_sync_handle.sync_and_wait()
    }

    /// Returns a clone-able client for triggering offer sync operations from
    /// other threads (e.g. background workers) without requiring access to the
    /// `Taker` itself. Useful for callers that want to run a manual sync off
    /// the main thread while leaving the `Taker` free for concurrent reads.
    pub fn offer_sync_client(&self) -> OfferSyncClient {
        self.offer_sync_handle.client()
    }

    /// Fetches the offer from a single maker, verifies its fidelity proof, and
    /// stores the result in the offerbook. Adds the maker to the offerbook if
    /// it is not already present. Blocks until the poll completes and returns
    /// the maker's final state.
    pub fn poll_maker(&self, address: String) -> Result<MakerOfferCandidate, TakerError> {
        let parsed = MakerAddress::try_from(address)
            .map_err(|e| TakerError::General(format!("Invalid maker address: {e}")))?;
        self.offer_sync_handle.poll_maker(parsed)
    }

    /// Removes a maker from the offerbook by address. Returns `true` if an
    /// entry was removed, `false` if no matching address was found.
    pub fn remove_maker(&self, address: String) -> Result<bool, TakerError> {
        let parsed = MakerAddress::try_from(address)
            .map_err(|e| TakerError::General(format!("Invalid maker address: {e}")))?;
        self.offerbook.remove(&parsed)
    }

    /// Restore a wallet from a backup file (static — no taker instance needed).
    /// A `None` wallet name restores under the backup's original filename.
    pub fn restore_wallet(
        data_dir: Option<PathBuf>,
        wallet_file_name: Option<String>,
        backend: BackendConfig,
        backup_file: &String,
    ) -> Result<(), TakerError> {
        let backup_file_path = PathBuf::from(backup_file);

        let wallets_dir = data_dir
            .map(Ok)
            .unwrap_or_else(get_taker_dir)
            .map_err(|e| TakerError::General(format!("wallet restore failed: {e}")))?
            .join("wallets");
        // A nameless path resolves to the backup's filename inside `Wallet::restore`.
        let restored_wallet_path = match wallet_file_name {
            Some(name) => wallets_dir.join(name),
            None => wallets_dir,
        };

        Wallet::restore_interactive(&backup_file_path, &backend, &restored_wallet_path)?;
        Ok(())
    }
}

/// Taker behavior for testing.
#[cfg(feature = "integration-test")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TakerBehavior {
    /// Normal behavior.
    #[default]
    Normal,
    /// Stop the watcher immediately before the taker's funding gate.
    StopWatcherBeforeSwap,
    /// Stop the watcher after Legacy breach sentinels are armed.
    StopWatcherAfterSentinels,
    /// Replace the validated amount before sending SwapDetails.
    ForgeBounds(Amount),
    /// Re-send identical then mutated SwapDetails after admission.
    ResendMutatedDetails,
    /// Close connection early (after maker selection).
    CloseEarly,
    /// Drop after funds/contracts are broadcast but before finalization.
    /// Simulates a taker crash after funds are on-chain.
    DropAfterFundsBroadcast,
    /// Broadcast contract transactions after full setup, then close (malice scenario).
    BroadcastContractAfterFullSetup,
    /// Close connection after receiving AckSwapDetails (taproot taker abort).
    CloseAtAckResponse,
    /// Close connection when sending sender's contract data (taproot taker abort).
    CloseAtSendersContract,
    /// Send a Taproot contract amount that does not match the transaction output.
    InvalidTaprootContractAmount,
    /// Repeat the same incoming funding outpoint in the maker request.
    DuplicateFundingOutpoint,
    /// Append one more funding entry than negotiated (maker count guard).
    ExtraFundingTxEntry,
    /// Repeat the priciest funding entry in place of the cheapest, keeping the
    /// count but pushing the declared sum over the swap amount (maker sum guard).
    OverstatedFundingAmount,
    /// Close connection when receiving maker's contract data response (taproot taker abort).
    CloseAtSendersContractFromMaker,
    /// Skip the Legacy sender-signature request, broadcast real funding, and
    /// send ProofOfFunding directly (maker_rejects_proof_of_funding_with_missing_contract_cache).
    SkipSenderContractSigs,
    /// Spend the funding output through the contract path, then still name that
    /// outpoint in ProofOfFunding (maker_rejects_spent_funding_outpoint).
    ReplaySpentFundingOutpoint,
    /// Same replay, but only wait until the spend is visible in the mempool, so
    /// the maker must reject it without a confirmation to go on
    /// (maker_rejects_spent_funding_outpoint).
    ReplaySpentFundingOutpointMempool,
    /// Keep the route alive with keepalives but never finish the swap, so only the
    /// maker's refund deadline can end it (maker_recovers_swap_past_refund_deadline).
    StallAfterProofOfFunding,
    /// Die just before finalization, with every contract funded and persisted but
    /// no key handed over and no recovery run. Leaves every party's contract
    /// unclaimed so only a restart can settle them (restart_rebuilds_watches).
    CrashBeforeRecovery,
    /// Die right after the contract exchange, before finalization and with no
    /// recovery run — the window where incoming coins would otherwise exist only
    /// in memory (crash_after_contract_exchange).
    CrashAfterContractExchange,
    /// Alter the cached PaySwap quote before negotiation so the freshly fetched
    /// maker offer exercises the repricing guard.
    AlterPaymentQuoteBeforeNegotiation,
}
