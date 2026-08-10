//! Message handlers for the Maker.

use std::{sync::Arc, time::Instant};

use bitcoin::{bip32::ChainCode, Amount, PublicKey, Transaction};

use super::error::MakerError;
use crate::{
    protocol::{
        common_messages::{
            AckSwapDetails, FidelityProof, GetOffer, MakerHello, MakerToTakerMessage, Offer,
            ProtocolVersion, SwapDetails, TakerHello, TakerToMakerMessage,
        },
        legacy_messages::LegacyTakerMessage,
        taproot_messages::TaprootTakerMessage,
    },
    taker::api::REFUND_LOCKTIME_STEP,
    wallet::swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
};

/// Test-only behavior overrides for the maker.
#[cfg(feature = "integration-test")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MakerBehavior {
    /// Normal operation (no test override).
    #[default]
    Normal,
    /// Stop the watchtower before the maker starts its network services.
    StopWatcherOnStartup,
    /// Receive contract sigs and save swapcoins, but skip funding broadcast
    /// and close the connection. Simulates last-maker misbehavior.
    SkipFundingBroadcast,
    /// Close connection when receiving ReqContractSigsForSender (abort2 scenarios).
    CloseAtReqContractSigsForSender,
    /// Close connection when receiving ProofOfFunding (abort2 scenario).
    CloseAtProofOfFunding,
    /// Close connection when receiving RespContractSigsForRecvrAndSender (abort3 scenario).
    CloseAtContractSigsForRecvrAndSender,
    /// Close connection when receiving ReqContractSigsForRecvr (abort3 scenario).
    CloseAtContractSigsForRecvr,
    /// Close connection when receiving PrivateKeyHandover / hash preimage (abort3 scenario).
    CloseAtHashPreimage,
    /// Broadcast contract transactions after setup, then close (malice scenario).
    BroadcastContractAfterSetup,
    /// Close connection after sending AckSwapDetails (taproot maker abort).
    CloseAfterAckResponse,
    /// Close connection at private key handover phase (taproot maker abort).
    CloseAtPrivateKeyHandover,
    /// Close connection at contract sigs exchange (taproot recovery test).
    CloseAtContractSigsExchange,
    /// Sweep the incoming swapcoins, then close before handing the private key
    /// over. The sweep puts the preimage on chain, which is what the other side
    /// needs to recover.
    CloseAfterSweep,
    /// Never run the idle recovery, the way a crashed process would. Leaves the
    /// contracts unclaimed so only a restart can settle them
    /// (restart_rebuilds_watches).
    CrashBeforeRecovery,
    /// Use an invalid fidelity bond timelock (fidelity timelock violation test).
    InvalidFidelityTimelock,
    /// Point a Legacy sender contract at a funding output that is not the advertised multisig.
    MalformedLegacyFundingOutput,
    /// Underfund the Taproot contract while claiming the expected amount.
    UnderfundTaprootContract,
    /// Deduct one extra satoshi beyond the advertised fee.
    FeeSkimming,
    /// Build one more outgoing Taproot contract than requested (over-split test).
    OverSplitTaprootContract,
    /// Build one fewer outgoing Taproot contract than requested (under-split test).
    UnderSplitTaprootContract,
    /// Advertise `max_tx_splits: None` to emulate a pre-feature maker (downgrade test).
    AdvertiseNoSplitSupport,
}

/// Minimum time required to react to contract broadcasts (in blocks).
pub const MIN_CONTRACT_REACTION_TIME: u16 = 10;

/// Each admitted swap pins a connection thread and liquidity until it settles
/// or times out. Past this cap, reject new SwapDetails instead of stacking
/// unfunded admissions.
pub(crate) const MAX_CONCURRENT_SWAPS: usize = 30;

/// The taker's declared offset is also its claimed reaction window. Too small a
/// value means neither side can act on the contract.
pub(crate) fn offset_meets_reaction_time(refund_locktime_offset: u16) -> bool {
    refund_locktime_offset >= MIN_CONTRACT_REACTION_TIME
}

/// Upper bound, not equality: each hop's incoming is reduced by the earlier hops'
/// fees. Funding above the negotiated amount books capital the taker never
/// reserved, so only that direction is rejected.
pub(crate) fn incoming_within_swap_amount(total_incoming: Amount, swap_amount: Amount) -> bool {
    total_incoming <= swap_amount
}

/// We can only sweep our incoming contract until `timelock + REFUND_LOCKTIME_STEP`.
/// Past that the sender reclaims it, so a swap this close to the edge has to be
/// recovered now instead of kept alive by keepalives.
pub(crate) fn past_refund_deadline(
    protocol: ProtocolVersion,
    timelock: u32,
    funding_confirmation_height: Option<u32>,
    current_height: u32,
) -> bool {
    let incoming_deadline = match protocol {
        // Taproot's timelock is already an absolute height.
        ProtocolVersion::Taproot => timelock,
        // Legacy counts CSV blocks from its funding confirmation. With no height
        // recorded the deadline does not exist yet, so nothing can be past it.
        ProtocolVersion::Legacy => match funding_confirmation_height {
            Some(height) => height.saturating_add(timelock),
            None => return false,
        },
    };

    incoming_deadline.saturating_add(REFUND_LOCKTIME_STEP as u32)
        < current_height.saturating_add(MIN_CONTRACT_REACTION_TIME as u32)
}

/// Connection state for protocol handling.
#[derive(Debug, Clone)]
pub struct ConnectionState {
    /// Protocol version being used for this connection.
    pub protocol: ProtocolVersion,
    /// Current phase of the swap.
    pub phase: SwapPhase,
    /// Unique swap identifier.
    pub swap_id: Option<String>,
    /// Swap amount.
    pub swap_amount: Amount,
    /// Number of contract transactions agreed at negotiation.
    pub tx_count: u32,
    /// Timelock value (Legacy: relative CSV, Taproot: absolute CLTV height).
    pub timelock: u32,
    /// Relative locktime offset for deterministic fee calculation.
    pub refund_locktime_offset: u16,
    /// Number of outgoing contracts to build for this hop (Taproot per-hop splitting).
    ///
    /// `None` means the taker did not request a specific outgoing count, so the maker
    /// mirrors its incoming contract count (legacy behavior). Carried from
    /// [`SwapDetails::outgoing_tx_count`] so `process_taproot_contract` can decouple its
    /// outgoing count from the incoming one.
    pub outgoing_tx_count: Option<u32>,
    /// Incoming swap coins (we receive).
    pub incoming_swapcoins: Vec<IncomingSwapCoin>,
    /// Outgoing swap coins (we send).
    pub outgoing_swapcoins: Vec<OutgoingSwapCoin>,
    /// Pending funding transactions (not yet broadcast).
    pub pending_funding_txes: Vec<Transaction>,
    /// Contract fee rate for multi-hop swap creation.
    pub contract_feerate: f64,
    /// Maker service fee calculated from the accepted offer, excluding mining reimbursement.
    pub service_fee_sats: u64,
    /// Whether the funding transaction was actually broadcast to the network.
    pub funding_broadcast: bool,
    /// Reserved UTXOs for this swap (prevents concurrent double-spending).
    pub reserve_utxo: Vec<bitcoin::OutPoint>,
    /// Last activity timestamp.
    pub last_activity: Instant,
    /// Swap start time for duration tracking in reports.
    pub swap_start_time: Instant,
}

/// Phases of a swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapPhase {
    /// Initial state, awaiting hello.
    AwaitingHello,
    /// Hello received, awaiting offer request.
    AwaitingOfferRequest,
    /// Offer sent, awaiting swap details.
    AwaitingSwapDetails,
    /// Swap details received, awaiting contract data.
    AwaitingContractData,
    /// Contract data received (ECDSA: awaiting signatures, Taproot: awaiting preimage).
    AwaitingSignaturesOrPreimage,
    /// Signatures/preimage received, awaiting private key handover.
    AwaitingPrivateKeyHandover,
    /// Swap completed.
    Completed,
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState {
            protocol: ProtocolVersion::Legacy,
            phase: SwapPhase::AwaitingHello,
            swap_id: None,
            swap_amount: Amount::ZERO,
            tx_count: 0,
            timelock: 0,
            refund_locktime_offset: 0,
            outgoing_tx_count: None,
            incoming_swapcoins: Vec::new(),
            outgoing_swapcoins: Vec::new(),
            pending_funding_txes: Vec::new(),
            contract_feerate: 0.0,
            service_fee_sats: 0,
            funding_broadcast: false,
            reserve_utxo: Vec::new(),
            last_activity: Instant::now(),
            swap_start_time: Instant::now(),
        }
    }
}

impl ConnectionState {
    /// Create a new connection state for a specific protocol version.
    pub fn new(protocol: ProtocolVersion) -> Self {
        ConnectionState {
            protocol,
            ..Default::default()
        }
    }

    /// Update the last activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if the swap has timed out.
    pub fn is_timed_out(&self, timeout_secs: u64) -> bool {
        self.last_activity.elapsed().as_secs() > timeout_secs
    }

    /// Enforce that the current phase matches one of the expected phases.
    pub fn expect_phase(&self, expected: &[SwapPhase]) -> Result<(), MakerError> {
        if expected.contains(&self.phase) {
            Ok(())
        } else {
            Err(MakerError::General(
                format!(
                    "Unexpected message in phase {:?} (expected one of {:?})",
                    self.phase, expected
                )
                .leak(),
            ))
        }
    }

    /// Verify that the incoming message's swap_id matches the state's swap_id.
    /// If the state has no swap_id yet (initial setup), this is a no-op.
    pub fn check_swap_id(&self, msg_swap_id: &str) -> Result<(), MakerError> {
        if let Some(ref expected) = self.swap_id {
            if expected != msg_swap_id {
                return Err(MakerError::General(
                    format!(
                        "Swap ID mismatch: state has '{}' but message has '{}'",
                        expected, msg_swap_id
                    )
                    .leak(),
                ));
            }
        }
        Ok(())
    }
}

/// Trait for maker operations.
pub trait Maker: Send + Sync {
    /// Get the network port for logging.
    fn network_port(&self) -> u16;

    /// Get the Bitcoin network.
    fn network(&self) -> bitcoin::Network;

    /// Whether the watchtower can still protect newly committed funds.
    fn is_watchtower_alive(&self) -> bool;

    /// Get the tweakable keypair for swap address derivation.
    fn get_tweakable_keypair(
        &self,
    ) -> Result<(bitcoin::secp256k1::SecretKey, PublicKey, ChainCode), MakerError>;

    /// Get the highest fidelity proof.
    fn get_fidelity_proof(&self) -> Result<FidelityProof, MakerError>;

    /// Get maker configuration values.
    fn get_config(&self) -> MakerConfig;

    /// Validate swap parameters.
    fn validate_swap_parameters(&self, details: &SwapDetails) -> Result<u16, MakerError>;

    /// Calculate the swap fee.
    fn calculate_swap_fee(&self, amount: Amount, timelock: u32) -> Amount;

    /// Create a funding transaction for Legacy (P2WSH) address.
    fn create_funding_transaction(
        &self,
        amount: Amount,
        address: bitcoin::Address,
        excluded_outpoints: Option<Vec<bitcoin::OutPoint>>,
    ) -> Result<(Transaction, u32), MakerError>;

    /// Broadcast a transaction.
    fn broadcast_transaction(&self, tx: &Transaction) -> Result<bitcoin::Txid, MakerError>;

    /// Whether the backend already knows this transaction (mempool or chain);
    /// used to tolerate duplicate-broadcast errors. `false` also covers
    /// "backend down". Core must run with `-txindex=1`.
    fn is_transaction_known(&self, txid: &bitcoin::Txid) -> bool;

    /// Save incoming swapcoin to wallet.
    fn save_incoming_swapcoin(&self, swapcoin: &IncomingSwapCoin) -> Result<(), MakerError>;

    /// Save outgoing swapcoin to wallet.
    fn save_outgoing_swapcoin(&self, swapcoin: &OutgoingSwapCoin) -> Result<(), MakerError>;

    /// Register outpoint for watching. Errs if the watcher is gone; a swap
    /// without breach detection must not proceed, so callers abort on failure.
    fn register_watch_outpoint(
        &self,
        outpoint: bitcoin::OutPoint,
        script_pubkey: bitcoin::ScriptBuf,
    ) -> Result<(), MakerError>;

    /// Unregister outpoint from watching (after swap completion).
    fn unwatch_outpoint(&self, outpoint: bitcoin::OutPoint, script_pubkey: bitcoin::ScriptBuf);

    /// Sync wallet with Bitcoin Core and save state to disk.
    fn sync_and_save_wallet(&self) -> Result<(), MakerError>;

    /// Sweep incoming swapcoins after successful swap.
    fn sweep_incoming_swapcoins(&self) -> Result<(), MakerError>;

    /// Store connection state for persistence across connections.
    /// `admission` is set only when storing from a fresh SwapDetails message.
    fn store_connection_state(
        &self,
        swap_id: &str,
        state: &ConnectionState,
        admission: bool,
    ) -> Result<(), MakerError>;

    /// Retrieve stored connection state.
    fn get_connection_state(&self, swap_id: &str) -> Result<Option<ConnectionState>, MakerError>;

    /// Remove connection state for a completed swap.
    fn remove_connection_state(&self, swap_id: &str) -> Result<(), MakerError>;

    /// Get the data directory path for saving reports.
    fn data_dir(&self) -> &std::path::Path;

    /// Get the active maker wallet file name.
    fn wallet_name(&self) -> &str;

    /// Collect reserved UTXOs from all other active swaps (for concurrent double-spend prevention).
    fn collect_excluded_utxos(
        &self,
        current_swap_id: &str,
    ) -> Result<Vec<bitcoin::OutPoint>, MakerError>;

    /// Get the current block height from the Bitcoin node.
    fn get_current_height(&self) -> Result<u32, MakerError>;

    /// Answered from the stored swap state, because the funding confirmation height
    /// a Legacy deadline needs is recorded there and not on the connection.
    fn swap_past_refund_deadline(&self, swap_id: &str) -> Result<bool, MakerError>;

    /// Wait until a peer's tx is confirmed to `required_confirms` depth. Both mempool
    /// arrival and the confirmation itself are bounded, so a peer's unconfirmable tx
    /// cannot park this thread; shutdown also breaks the wait.
    fn wait_for_tx_on_chain(
        &self,
        txid: &bitcoin::Txid,
        required_confirms: u32,
    ) -> Result<(), MakerError>;

    /// Verify and sign sender's contract transactions.
    fn verify_and_sign_sender_contract_txs(
        &self,
        txs_info: &[crate::protocol::legacy_messages::ContractTxInfoForSender],
        hashvalue: &crate::protocol::Hash160,
        locktime: u16,
    ) -> Result<Vec<bitcoin::ecdsa::Signature>, MakerError>;

    /// Verify proof of funding and return the hashvalue.
    fn verify_proof_of_funding(
        &self,
        message: &crate::protocol::legacy_messages::ProofOfFunding,
    ) -> Result<crate::protocol::Hash160, MakerError>;

    /// Initialize outgoing openswap.
    #[allow(clippy::too_many_arguments)]
    fn initialize_openswap(
        &self,
        send_amount: Amount,
        next_multisig_pubkeys: &[PublicKey],
        next_hashlock_pubkeys: &[PublicKey],
        hashvalue: crate::protocol::Hash160,
        locktime: u16,
        contract_feerate: f64,
        excluded_outpoints: Option<Vec<bitcoin::OutPoint>>,
    ) -> Result<(Vec<Transaction>, Vec<OutgoingSwapCoin>, Amount), MakerError>;

    /// Find outgoing swapcoin by its multisig redeemscript.
    fn find_outgoing_swapcoin(
        &self,
        multisig_redeemscript: &bitcoin::ScriptBuf,
    ) -> Option<OutgoingSwapCoin>;

    /// Get the test behavior override.
    #[cfg(feature = "integration-test")]
    fn behavior(&self) -> MakerBehavior;
}

/// Fail closed after admission; persistence limits the check-to-broadcast race.
pub(super) fn ensure_watchtower_alive(maker: &impl Maker) -> Result<(), MakerError> {
    if maker.is_watchtower_alive() {
        Ok(())
    } else {
        Err(MakerError::General(
            "watchtower is down, refusing to commit funds",
        ))
    }
}

/// Maker configuration values.
#[derive(Debug, Clone)]
pub struct MakerConfig {
    /// Base fee in satoshis.
    pub base_fee: u64,
    /// Amount-relative fee percentage.
    pub amount_relative_fee_pct: f64,
    /// Time-relative fee percentage.
    pub time_relative_fee_pct: f64,
    /// Minimum swap amount.
    pub min_swap_amount: u64,
    /// Maximum swap amount.
    pub max_swap_amount: u64,
    /// Required confirmations.
    pub required_confirms: u32,
    /// Supported protocol versions.
    pub supported_protocols: Vec<ProtocolVersion>,
}

/// Message handler
pub fn handle_message<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    message: TakerToMakerMessage,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    state.touch();

    log::debug!(
        "[{}] Handling message: {:?} (phase: {:?}, protocol: {:?})",
        Maker::network_port(maker.as_ref()),
        message,
        state.phase,
        state.protocol
    );

    match message {
        TakerToMakerMessage::TakerHello(hello) => handle_taker_hello(maker, state, hello),
        TakerToMakerMessage::GetOffer(get_offer) => handle_get_offer(maker, state, get_offer),
        TakerToMakerMessage::SwapDetails(details) => handle_swap_details(maker, state, details),

        TakerToMakerMessage::ReqContractSigsForSender(req) => handle_legacy_dispatch(
            maker,
            state,
            LegacyTakerMessage::ReqContractSigsForSender(req),
        ),
        TakerToMakerMessage::ProofOfFunding(pof) => {
            handle_legacy_dispatch(maker, state, LegacyTakerMessage::ProofOfFunding(pof))
        }
        TakerToMakerMessage::RespContractSigsForRecvrAndSender(resp) => handle_legacy_dispatch(
            maker,
            state,
            LegacyTakerMessage::RespContractSigsForRecvrAndSender(resp),
        ),
        TakerToMakerMessage::ReqContractSigsForRecvr(req) => handle_legacy_dispatch(
            maker,
            state,
            LegacyTakerMessage::ReqContractSigsForRecvr(req),
        ),
        TakerToMakerMessage::LegacyPrivateKeyHandover(handover) => handle_legacy_dispatch(
            maker,
            state,
            LegacyTakerMessage::PrivateKeyHandover(handover),
        ),
        TakerToMakerMessage::TaprootContractData(data) => {
            handle_taproot_dispatch(maker, state, TaprootTakerMessage::ContractData(data))
        }
        TakerToMakerMessage::TaprootPrivateKeyHandover(handover) => handle_taproot_dispatch(
            maker,
            state,
            TaprootTakerMessage::PrivateKeyHandover(handover),
        ),
        TakerToMakerMessage::WaitingFundingConfirmation(ref id) => {
            // This message resets the idle timer that starts recovery, so one
            // connection must not be able to keep another swap's timer alive.
            state.check_swap_id(id)?;
            // Staying alive cannot save a swap whose refund window is closing, and
            // refreshing the timer here would hold off the recovery that can.
            if maker.swap_past_refund_deadline(id)? {
                log::warn!(
                    "[{}] Swap {} is past its refund deadline; letting it go idle for recovery",
                    maker.network_port(),
                    id
                );
                return Ok(None);
            }
            log::info!(
                "[{}] Taker is waiting for funding confirmation (swap {}). Resetting timer.",
                maker.network_port(),
                id
            );
            if let Some(stored_state) = maker.get_connection_state(id)? {
                maker.store_connection_state(id, &stored_state, false)?;
            }
            state.touch();
            Ok(None)
        }
    }
}

/// Handle TakerHello message.
fn handle_taker_hello<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    _hello: TakerHello,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    state.expect_phase(&[SwapPhase::AwaitingHello])?;

    log::info!(
        "[{}] Received TakerHello",
        Maker::network_port(maker.as_ref()),
    );

    let config = maker.get_config();
    state.phase = SwapPhase::AwaitingOfferRequest;

    log::info!(
        "[{}] Supported protocols: {:?}",
        Maker::network_port(maker.as_ref()),
        config.supported_protocols
    );

    Ok(Some(MakerToTakerMessage::MakerHello(MakerHello {
        supported_protocols: config.supported_protocols,
    })))
}

/// Handle GetOffer message.
fn handle_get_offer<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    _get_offer: GetOffer,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    state.expect_phase(&[SwapPhase::AwaitingOfferRequest])?;

    log::info!(
        "[{}] Received GetOffer request",
        Maker::network_port(maker.as_ref())
    );

    let (_, tweakable_point, tweak_chain_code) = maker.get_tweakable_keypair()?;
    let fidelity = maker.get_fidelity_proof()?;
    let config = maker.get_config();

    state.phase = SwapPhase::AwaitingSwapDetails;

    let offer = Offer {
        base_fee: config.base_fee,
        amount_relative_fee_pct: config.amount_relative_fee_pct,
        time_relative_fee_pct: config.time_relative_fee_pct,
        required_confirms: config.required_confirms,
        minimum_locktime: MIN_CONTRACT_REACTION_TIME,
        max_size: config.max_swap_amount,
        min_size: config.min_swap_amount,
        tweakable_point,
        fidelity,
        tweak_chain_code,
        // `Some` tells the taker this maker reads `outgoing_tx_count`, up to the ceiling.
        #[cfg(not(feature = "integration-test"))]
        max_tx_splits: Some(crate::wallet::MAX_SPLITS as u32),
        // One test behavior suppresses this to emulate a pre-feature maker.
        #[cfg(feature = "integration-test")]
        max_tx_splits: if maker.behavior() == MakerBehavior::AdvertiseNoSplitSupport {
            None
        } else {
            Some(crate::wallet::MAX_SPLITS as u32)
        },
    };

    log::info!(
        "[{}] Sending offer: min={}, max={}",
        Maker::network_port(maker.as_ref()),
        offer.min_size,
        offer.max_size
    );

    Ok(Some(MakerToTakerMessage::Offer(Box::new(offer))))
}

/// Handle SwapDetails message.
fn handle_swap_details<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    details: SwapDetails,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    state.expect_phase(&[SwapPhase::AwaitingSwapDetails])?;

    if !maker.is_watchtower_alive() {
        log::error!(
            "[{}] Rejecting swap {} because the watchtower is down",
            Maker::network_port(maker.as_ref()),
            details.id
        );
        return Ok(Some(MakerToTakerMessage::AckSwapDetails(
            AckSwapDetails::reject(),
        )));
    }

    log::info!(
        "[{}] Received SwapDetails: amount={}, timelock={}, protocol={:?}",
        Maker::network_port(maker.as_ref()),
        details.amount,
        details.timelock,
        details.protocol_version
    );

    // The fee pays for how long our funds stay locked, so use the length derived from the
    // timelock. Otherwise the taker could ask for a long lock and pay for a short one.
    let refund_locktime_offset = maker.validate_swap_parameters(&details)?;

    state.swap_id = Some(details.id.clone());
    state.swap_amount = details.amount;
    state.tx_count = details.tx_count;
    state.timelock = details.timelock;
    state.refund_locktime_offset = refund_locktime_offset;
    state.outgoing_tx_count = details.outgoing_tx_count;
    state.protocol = details.protocol_version;
    state.swap_start_time = Instant::now();
    let swap_fee = maker.calculate_swap_fee(details.amount, state.refund_locktime_offset as u32);
    state.service_fee_sats = swap_fee.to_sat();
    state.phase = SwapPhase::AwaitingContractData;

    // An admission rejection must reach the taker as a message, not a dropped
    // connection, or it waits out a timeout before trying the next maker.
    match maker.store_connection_state(&details.id, state, true) {
        // A param mismatch means the id already belongs to a live swap; all
        // arms are terminal rejections and get the same reset.
        Err(
            MakerError::TooManySwaps
            | MakerError::SwapParamMismatch
            | MakerError::InsufficientLiquidity { .. },
        ) => {
            // A rejected admission must leave no live phase: with AwaitingContractData
            // still set, the taker could send ContractData and drive funding for a
            // swap we refused. Nothing was stored, so restore_state_if_needed stays a no-op.
            state.phase = SwapPhase::AwaitingSwapDetails;
            state.swap_id = None;
            state.swap_amount = Amount::ZERO;
            state.tx_count = 0;
            state.timelock = 0;
            state.refund_locktime_offset = 0;
            state.service_fee_sats = 0;
            return Ok(Some(MakerToTakerMessage::AckSwapDetails(
                AckSwapDetails::reject(),
            )));
        }
        result => result?,
    }

    let (_, tweakable_point, _) = maker.get_tweakable_keypair()?;

    log::info!(
        "[{}] Accepting swap (id: {})",
        Maker::network_port(maker.as_ref()),
        details.id
    );

    #[cfg(feature = "integration-test")]
    if maker.behavior() == MakerBehavior::CloseAfterAckResponse {
        log::warn!(
            "[{}] Test behavior: closing after AckSwapDetails",
            maker.network_port()
        );
        return Err(MakerError::General("Test: closing after ack response"));
    }

    Ok(Some(MakerToTakerMessage::AckSwapDetails(
        AckSwapDetails::accept(tweakable_point),
    )))
}

/// Restore connection state if this is a new/reconnected connection.
fn restore_state_if_needed<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    swap_id: &str,
) -> Result<(), MakerError> {
    if state.swap_amount == Amount::ZERO || state.outgoing_swapcoins.is_empty() {
        if let Some(stored) = maker.get_connection_state(swap_id)? {
            log::info!(
                "[{}] Restored state for {}: amount={}, timelock={}, phase={:?}, outgoing_count={}",
                maker.network_port(),
                swap_id,
                stored.swap_amount,
                stored.timelock,
                stored.phase,
                stored.outgoing_swapcoins.len()
            );
            state.swap_id = Some(swap_id.to_string());
            state.swap_amount = stored.swap_amount;
            state.tx_count = stored.tx_count;
            state.timelock = stored.timelock;
            state.protocol = stored.protocol;
            state.phase = stored.phase;
            state.incoming_swapcoins = stored.incoming_swapcoins;
            state.outgoing_swapcoins = stored.outgoing_swapcoins;
            state.pending_funding_txes = stored.pending_funding_txes;
            state.funding_broadcast = stored.funding_broadcast;
            state.contract_feerate = stored.contract_feerate;
            state.service_fee_sats = stored.service_fee_sats;
            state.swap_start_time = stored.swap_start_time;
            state.refund_locktime_offset = stored.refund_locktime_offset;
            state.outgoing_tx_count = stored.outgoing_tx_count;
        }
    }
    Ok(())
}

/// Ensure a protocol-specific message matches the protocol negotiated for this swap.
fn ensure_negotiated_protocol(
    state: &ConnectionState,
    message_protocol: ProtocolVersion,
) -> Result<(), MakerError> {
    if state.protocol != message_protocol {
        return Err(MakerError::UnexpectedMessage {
            expected: format!("{:?} protocol message", state.protocol),
            got: format!("{:?} protocol message", message_protocol),
        });
    }

    Ok(())
}

/// Dispatch to Legacy handlers.
fn handle_legacy_dispatch<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    legacy_msg: LegacyTakerMessage,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    let swap_id = legacy_msg.swap_id().to_string();

    log::info!(
        "[{}] Dispatching Legacy message: {} (swap_id: {})",
        maker.network_port(),
        legacy_msg,
        swap_id
    );

    restore_state_if_needed(maker, state, &swap_id)?;
    ensure_negotiated_protocol(state, ProtocolVersion::Legacy)?;

    super::legacy_handlers::handle_legacy_message(maker, state, legacy_msg)
}

/// Dispatch to Taproot handlers.
fn handle_taproot_dispatch<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    taproot_msg: TaprootTakerMessage,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    let swap_id = taproot_msg.swap_id().to_string();

    log::info!(
        "[{}] Dispatching Taproot message: {:?} (swap_id: {})",
        maker.network_port(),
        taproot_msg,
        swap_id
    );

    restore_state_if_needed(maker, state, &swap_id)?;
    ensure_negotiated_protocol(state, ProtocolVersion::Taproot)?;

    super::taproot_handlers::handle_taproot_message(maker, state, taproot_msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_below_reaction_time_is_rejected() {
        assert!(!offset_meets_reaction_time(0));
        assert!(!offset_meets_reaction_time(MIN_CONTRACT_REACTION_TIME - 1));
        assert!(offset_meets_reaction_time(MIN_CONTRACT_REACTION_TIME));
        assert!(offset_meets_reaction_time(500));
    }

    #[test]
    fn mismatched_swap_id_is_rejected() {
        let state = ConnectionState {
            swap_id: Some("swap-abc".to_string()),
            ..Default::default()
        };

        assert!(state.check_swap_id("swap-abc").is_ok());
        assert!(state.check_swap_id("swap-xyz").is_err());
    }

    #[test]
    fn incoming_above_negotiated_swap_amount_is_rejected() {
        let negotiated = Amount::from_sat(500_000);

        assert!(!incoming_within_swap_amount(
            negotiated + Amount::from_sat(1),
            negotiated
        ));
        assert!(incoming_within_swap_amount(negotiated, negotiated));
        // Earlier hops take their fee out, so a later hop's incoming is smaller.
        // This case is why the check is an upper bound and not equality.
        assert!(incoming_within_swap_amount(
            negotiated - Amount::from_sat(4_000),
            negotiated
        ));
    }

    /// The last height still inside the window, given an incoming deadline.
    fn last_safe_height(incoming_deadline: u32) -> u32 {
        incoming_deadline - MIN_CONTRACT_REACTION_TIME as u32
    }

    #[test]
    fn taproot_refund_deadline_is_exact_at_the_boundary() {
        let timelock = 1_000;
        let deadline = timelock + REFUND_LOCKTIME_STEP as u32;
        let safe = last_safe_height(deadline);

        let past = |height| past_refund_deadline(ProtocolVersion::Taproot, timelock, None, height);
        assert!(!past(safe));
        assert!(past(safe + 1));
    }

    #[test]
    fn legacy_refund_deadline_counts_from_funding_confirmation() {
        let timelock = 150;
        let confirmed_at = 800;
        let deadline = confirmed_at + timelock + REFUND_LOCKTIME_STEP as u32;
        let safe = last_safe_height(deadline);

        let past = |height| {
            past_refund_deadline(
                ProtocolVersion::Legacy,
                timelock,
                Some(confirmed_at),
                height,
            )
        };
        assert!(!past(safe));
        assert!(past(safe + 1));
    }

    #[test]
    fn legacy_without_funding_confirmation_has_no_deadline() {
        assert!(!past_refund_deadline(
            ProtocolVersion::Legacy,
            150,
            None,
            u32::MAX
        ));
    }
}
