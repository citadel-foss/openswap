//! Message handlers for the Maker.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex, PoisonError},
    time::Instant,
};

use bitcoin::{bip32::ChainCode, Amount, OutPoint, PublicKey, Transaction, Txid, XOnlyPublicKey};

use bitcoind::bitcoincore_rpc::{jsonrpc::error::Error as JsonRpcError, Error as BitcoinRpcError};

use super::error::MakerError;
use crate::{
    protocol::{
        common_messages::{
            AckSwapDetails, FidelityProof, GetOffer, Hello, MakerToTakerMessage, Offer,
            ProtocolVersion, SwapDetails, TakerToMakerMessage, UnsupportedMessage,
        },
        features::{check_bounds, check_pins, supported, unmet_at_hello},
        funding_bump::within_bump_shortfall,
        legacy_messages::LegacyTakerMessage,
        taproot_messages::TaprootTakerMessage,
    },
    taker::api::REFUND_LOCKTIME_STEP,
    wallet::{
        funding::SplitPlan,
        swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
        MakerReport, RecoveryOutcome, ReportUtxo, WalletError,
    },
};

/// True when the backend rejected a broadcast only because the tx is already
/// on-chain or in its mempool — safe to treat as "already sent, carry on".
/// Electrum wraps the same wording in its own error type, which this cannot
/// see; the callers fall back to `is_transaction_known` for that.
pub fn is_already_broadcast_error(e: &MakerError) -> bool {
    let MakerError::Wallet(WalletError::Rpc(BitcoinRpcError::JsonRpc(JsonRpcError::Rpc(
        rpc_error,
    )))) = e
    else {
        return false;
    };
    rpc_error.code == -27 || {
        let message = rpc_error.message.to_ascii_lowercase();
        message.contains("already in block chain")
            || message.contains("already in mempool")
            || message.contains("already in utxo set")
            || message.contains("txn-already-in-mempool")
    }
}

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
    /// Like [`MakerBehavior::SkipFundingBroadcast`], but leaves the broadcast
    /// record empty, so recovery reads the swap as never funded.
    SkipFundingBroadcastUnrecorded,
    /// Withhold the funding broadcast while answering normally, so the taker
    /// reaches its funding wait instead of seeing a dropped connection.
    WithholdFundingSilently,
    /// Advertise an offer whose minimum exceeds its maximum, so no amount can
    /// be priced against it.
    SendMalformedOffer,
    /// Sign the sender contracts with a key nobody agreed to, so the signatures
    /// are well formed and still wrong.
    SignSenderContractsWithWrongKey,
    /// Build the outgoing Taproot hashlock for a key the next hop never agreed
    /// to, keeping the contract otherwise consistent.
    WrongHashlockKey,
    /// Take the Taproot handover keys owed to us, then hand back a key that
    /// does not match the contract.
    SendWrongHandoverKey,
    /// Close connection when receiving ReqContractSigsForSender (abort2 scenarios).
    CloseAtReqContractSigsForSender,
    /// Close connection when receiving ProofOfFunding (abort2 scenario).
    CloseAtProofOfFunding,
    /// Hold each funding step open long enough for a test to race a
    /// duplicate of its message in on a second connection.
    PauseInFundingStep,
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
    /// Refuse every SwapDetails with a reject-ack. Arms a test to prove the
    /// taker never reaches negotiation: any contact fails the swap differently.
    RefuseSwapDetails,
    /// Close connection at private key handover phase (taproot maker abort).
    CloseAtPrivateKeyHandover,
    /// Process a handover but drop its first response.
    DropHandoverResponse,
    /// Close after sending the successful handover response, before sweeping
    /// incoming swapcoins.
    CloseAfterHandoverResponse,
    /// Close after sweeping incoming swapcoins, before finalizing the swap.
    CloseBeforeSwapFinalization,
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
    /// Return one more outgoing contract than was actually funded, exceeding
    /// the negotiated maximum split count.
    OverproduceContractData,
    /// Move one sat between two claimed Taproot amounts so count and total
    /// stay exact; only the taker's per-output amount binding can catch it.
    InflateContractAmount,
    /// Repeat one funded Taproot contract in place of another so count and
    /// total stay exact; only the duplicate-outpoint check can catch it.
    DuplicateContractOutpoint,
    /// Fail the batch's second funding broadcast so the first tx is on-chain
    /// while the handler errors; exercises partial-batch recovery.
    FailSecondBroadcast,
    /// Fail the batch's first funding send with nothing sent.
    FailFirstBroadcast,
    /// Send the first funding tx, then report the send as failed, as a
    /// lost backend reply would.
    BroadcastThenFailFirst,
    /// Build funding splits at the relay floor while the taker reimburses the
    /// negotiated rate (funding-fee underpayment rejection tests).
    UnderpayFundingFee,
    /// Ack one input more per split than the plan funds with, so the taker
    /// prices fees for inputs the maker never spends.
    OverreportFundingInputs,
    /// Claim the funding coins, then fail before building anything, leaving
    /// the claim behind as a crash would.
    AbandonFundingClaim,
    /// Fail the post-swap sweep, so the completed swap's state is put back.
    FailSweep,
    /// Hold the frozen plan's coins under a stand-in swap at funding, so the
    /// first pass must re-plan as if another swap had taken them.
    ForceReplan,
    /// Fail every lookup of a Lightning HTLC funding's confirmation height,
    /// as an unreachable chain backend would.
    FailFundingHeightLookup,
    /// Answer every lookup of a Lightning HTLC funding's confirmation height
    /// with no height, as after a reorg takes the funding's block away.
    NoFundingHeight,
    /// Keep our outgoing funding out of blocks once broadcast, as a fee spike
    /// would, so only a fee bump can get the hop confirmed.
    StallFunding,
    /// Never latch our funding as mined, the way a node that never saw an
    /// orphaned block would not, so a bump after a reorg goes through.
    SkipFundingLatch,
}

/// Minimum time required to react to contract broadcasts (in blocks).
pub const MIN_CONTRACT_REACTION_TIME: u16 = 10;

/// A funded swap pins liquidity and connection threads until it settles or
/// times out. Past this cap, reject new SwapDetails; admitted swaps still fund
/// past it, so a taker that funded the route is never stranded.
pub(crate) const MAX_CONCURRENT_SWAPS: usize = 30;

/// Unfunded admissions reserve nothing, so they get their own cap. Keeping it
/// full takes the whole connection rate budget (900s at 4/s), which a peer
/// could spend on a connection flood anyway.
#[cfg(not(feature = "integration-test"))]
pub(crate) const MAX_UNFUNDED_ADMISSIONS: usize = 3600;
/// Lowered so a test can reach it, while staying above the funded cap.
#[cfg(feature = "integration-test")]
pub(crate) const MAX_UNFUNDED_ADMISSIONS: usize = MAX_CONCURRENT_SWAPS + 2;

/// Swap ids are 8 random bytes in hex, as the taker generates them. Any other
/// id is refused before it is logged or stored: each resident id is held for
/// the idle window, and the frame limit alone would allow megabytes per id.
pub(crate) fn is_valid_swap_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The taker's declared offset is also its claimed reaction window. Too small a
/// value means neither side can act on the contract.
pub(crate) fn offset_meets_reaction_time(refund_locktime_offset: u16) -> bool {
    refund_locktime_offset >= MIN_CONTRACT_REACTION_TIME
}

/// Whether a swap's pins include funding bumps.
pub(crate) fn pins_funding_bump(features: &[String]) -> bool {
    features
        .iter()
        .any(|feature| feature == crate::protocol::funding_bump::FUNDING_BUMP_FEATURE)
}

/// The declared amount caps the incoming: more was never reserved. On a swap
/// that pinned funding bumps, less is what upstream bumps took, and only
/// within their bound: our fee stays the one admitted, so a smaller amount
/// short-changes nobody. Without them the hop arrives whole.
pub(crate) fn incoming_fits_swap_amount(
    total_incoming: Amount,
    swap_amount: Amount,
    bumps: bool,
) -> bool {
    if bumps {
        within_bump_shortfall(total_incoming, swap_amount)
    } else {
        total_incoming == swap_amount
    }
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
    /// Maximum contract transactions this hop agreed to forward — a ceiling.
    /// The exact count the taker will send is `incoming_count`.
    pub tx_count: u32,
    /// Exactly how many contracts the taker will send this hop.
    pub incoming_count: u32,
    /// Maximum inputs per forwarding tx whose fee the taker covers.
    pub max_input_budget: u32,
    /// Timelock value (Legacy: relative CSV, Taproot: absolute CLTV height).
    pub timelock: u32,
    /// Relative locktime offset for deterministic fee calculation.
    pub refund_locktime_offset: u16,
    /// Incoming swap coins (we receive).
    pub incoming_swapcoins: Vec<IncomingSwapCoin>,
    /// Outgoing swap coins (we send).
    pub outgoing_swapcoins: Vec<OutgoingSwapCoin>,
    /// Pending funding transactions (not yet broadcast).
    pub pending_funding_txes: Vec<Transaction>,
    /// Negotiated swap feerate; every transaction in the swap is built and
    /// priced at this rate.
    pub swap_feerate: f64,
    /// Maker service fee calculated from the accepted offer, excluding mining reimbursement.
    pub service_fee_sats: u64,
    /// Funding txids broadcast so far, one per tx as the batch progresses. A
    /// partial batch must not read as never broadcast, or recovery discards
    /// recovery material for transactions already on-chain.
    pub funding_broadcast_txids: Vec<Txid>,
    /// The funding plan frozen at admission; its input counts are what the Ack
    /// declared. Empty until admission succeeds.
    pub funding_plan: Vec<SplitPlan>,
    /// Key the taker signs funding bumps with, declared at admission.
    pub taker_auth_pubkey: Option<XOnlyPublicKey>,
    /// Fee bumps of our outgoing funding.
    pub funding_bump: FundingBumpState,
    /// Last activity timestamp.
    pub last_activity: Instant,
    /// Swap start time for duration tracking in reports.
    pub swap_start_time: Instant,
}

/// A Legacy bump built and held until the next hop signs its contracts:
/// without that signature a broadcast replacement could not be refunded.
#[derive(Debug, Clone)]
pub struct PendingFundingBump {
    /// The taker's sequence number for this bump.
    pub seq: u32,
    /// Feerate the replacements pay.
    pub feerate: u64,
    /// Split index and replacement version of each bumped outgoing swapcoin,
    /// its funding tx signed and its contract tx not yet countersigned.
    pub replacements: Vec<(usize, OutgoingSwapCoin)>,
}

/// Fee bumps of our outgoing hop's funding.
#[derive(Debug, Clone, Default)]
pub struct FundingBumpState {
    /// Highest sequence number the taker has used; a request must exceed it.
    pub seq: u32,
    /// Feerate the latest replacements pay; zero before the first bump.
    pub feerate: u64,
    /// Bumps broadcast so far.
    pub bumps: u32,
    /// Replacement versions of our outgoing swapcoins. Each spends the coins
    /// of one original, so one version per split confirms; all are kept,
    /// here and in the wallet, until it is known which.
    pub replacements: Vec<OutgoingSwapCoin>,
    /// Legacy: a bump awaiting the next hop's contract signatures.
    pub pending: Option<PendingFundingBump>,
    /// The next hop has built on whichever version confirmed. A later bump
    /// could only conflict with funding it already accepted, after a reorg,
    /// so none is taken.
    pub settled: bool,
}

impl FundingBumpState {
    /// Fold `newer`, one connection's view, into this stored one. Several
    /// connections of a swap each hold a snapshot, and one that predates
    /// another's bump must not undo it: every field only moves forward and
    /// replacements are only ever added. A version that became one of
    /// `outgoing`, the swap's settled coins, is no replacement any more.
    pub(crate) fn merge_from(&mut self, newer: &FundingBumpState, outgoing: &[OutgoingSwapCoin]) {
        // A pending proposal is the latest request's: a commit clears it.
        if newer.seq >= self.seq {
            self.pending = newer.pending.clone();
        }
        self.seq = self.seq.max(newer.seq);
        self.feerate = self.feerate.max(newer.feerate);
        self.bumps = self.bumps.max(newer.bumps);
        self.settled |= newer.settled;
        for version in &newer.replacements {
            let txid = version.contract_tx.compute_txid();
            if !self
                .replacements
                .iter()
                .any(|kept| kept.contract_tx.compute_txid() == txid)
            {
                self.replacements.push(version.clone());
            }
        }
        let settled: Vec<Txid> = outgoing
            .iter()
            .map(|coin| coin.contract_tx.compute_txid())
            .collect();
        self.replacements
            .retain(|version| !settled.contains(&version.contract_tx.compute_txid()));
    }
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
            incoming_count: 0,
            max_input_budget: 0,
            timelock: 0,
            refund_locktime_offset: 0,
            incoming_swapcoins: Vec::new(),
            outgoing_swapcoins: Vec::new(),
            pending_funding_txes: Vec::new(),
            swap_feerate: 0.0,
            service_fee_sats: 0,
            funding_broadcast_txids: Vec::new(),
            funding_plan: Vec::new(),
            taker_auth_pubkey: None,
            funding_bump: FundingBumpState::default(),
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

/// Funding steps entered per swap id, so a race test can wait for the guard.
#[cfg(feature = "integration-test")]
static FUNDING_STEPS_ENTERED: Mutex<Option<std::collections::HashMap<String, usize>>> =
    Mutex::new(None);

/// How many times a handler has entered `swap_id`'s funding step.
#[cfg(feature = "integration-test")]
pub(crate) fn funding_steps_entered(swap_id: &str) -> usize {
    FUNDING_STEPS_ENTERED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .and_then(|steps| steps.get(swap_id).copied())
        .unwrap_or(0)
}

/// Called beside, not inside, each funding guard, so a test that drops the
/// guard still has the window open for the duplicate to slip through.
#[cfg(feature = "integration-test")]
pub(crate) fn pause_in_funding_step<M: Maker>(maker: &M, swap_id: &str) {
    if maker.behavior() == MakerBehavior::PauseInFundingStep {
        log::warn!("Test behavior: holding the funding step open");
        *FUNDING_STEPS_ENTERED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert_with(Default::default)
            .entry(swap_id.to_string())
            .or_default() += 1;
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
}

/// Marks one swap's funding step as running, from claiming the coins through
/// the last persisted state. A second handler for the same swap is refused while
/// it is held, so two handlers never build different batches for one swap.
pub struct FundingGuard<'a> {
    running: &'a Mutex<HashSet<String>>,
    swap_id: String,
}

impl<'a> FundingGuard<'a> {
    /// Takes the mark for `swap_id`, or refuses if another handler holds it.
    pub fn acquire(running: &'a Mutex<HashSet<String>>, swap_id: &str) -> Result<Self, MakerError> {
        let mut swaps = running.lock().map_err(|_| MakerError::MutexPossion)?;
        if !swaps.insert(swap_id.to_string()) {
            return Err(MakerError::General(
                "Funding for this swap is already in progress",
            ));
        }
        Ok(Self {
            running,
            swap_id: swap_id.to_string(),
        })
    }
}

impl Drop for FundingGuard<'_> {
    fn drop(&mut self) {
        // Released on every path, a poisoned lock included, or the swap stays
        // refused for good.
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.swap_id);
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

    /// Lightning submarine-swap terms, when a Lightning backend is
    /// configured and reachable. Deliberately kept off [`MakerConfig`]:
    /// `get_config` runs on every coinswap message, and deriving these
    /// terms costs a round-trip to the Lightning sidecar. On-chain swaps
    /// must not wait on a service they do not use.
    fn lightning_offer(&self) -> Option<crate::protocol::lightning_messages::LightningOffer>;

    /// Validate swap parameters.
    fn validate_swap_parameters(&self, details: &SwapDetails) -> Result<u16, MakerError>;

    /// Calculate the swap fee.
    fn calculate_swap_fee(&self, amount: Amount, timelock: u32) -> Amount;

    /// Execute the funding plan frozen at admission, one transaction per
    /// split. `amount` is the plan's pre-netting total, or short of it only
    /// by what upstream funding bumps took off the incoming hop, which then
    /// comes out of the splits; a missing plan, or an amount above its total,
    /// is a protocol error. A planned coin another
    /// swap took is replaced by a re-plan of the same shape.
    /// The `Vec<u32>` is `payment_output_positions`: each split's payment
    /// output index in its funding tx.
    fn create_funding_transactions(
        &self,
        swap_id: &str,
        amount: Amount,
        addresses: &[bitcoin::Address],
        feerate: f64,
    ) -> Result<(Vec<Transaction>, Vec<u32>), MakerError>;

    /// Mark `swap_id`'s funding step as running for as long as the guard lives.
    /// Refuses while another handler holds it for the same swap.
    fn begin_funding(&self, swap_id: &str) -> Result<FundingGuard<'_>, MakerError>;

    /// Broadcast a transaction.
    fn broadcast_transaction(&self, tx: &Transaction) -> Result<bitcoin::Txid, MakerError>;

    /// Check every funding input's previous-output script against the blocklist.
    fn screen_funding_tx(&self, tx: &Transaction) -> Result<(), MakerError>;

    /// Whether the backend already knows this transaction (mempool or chain);
    /// used to tolerate duplicate-broadcast errors. A lock or backend failure
    /// is an error, never `false`. Core must run with `-txindex=1`.
    fn is_transaction_known(&self, txid: &Txid) -> Result<bool, MakerError>;

    /// Record one successfully broadcast funding txid, so a mid-batch failure
    /// is never read back as "never broadcast". Called per send, not at batch end.
    fn record_funding_broadcast(&self, swap_id: &str, txid: &Txid) -> Result<(), MakerError>;

    /// Whether the backend still reports this contract outpoint unspent
    /// (mempool spends count). A lock or backend failure is an error, never
    /// `false` — a spent contract output must not fund another hop.
    fn contract_output_unspent(&self, outpoint: &OutPoint) -> Result<bool, MakerError>;

    /// True if any other live swap or any wallet swapcoin already references
    /// this contract txid. Replayed contract data must not fund a second swap.
    fn contract_txid_seen(&self, txid: &Txid, except_swap_id: &str) -> Result<bool, MakerError>;

    /// Atomically claim incoming contract txids for this swap under the
    /// ongoing-swaps lock: a txid another live swap holds or claimed is a
    /// replay. Claiming before the confirmation wait is what makes a
    /// concurrent duplicate fail at claim time, not after both swaps funded.
    fn claim_incoming_contract_txids(
        &self,
        swap_id: &str,
        txids: &[Txid],
    ) -> Result<(), MakerError>;

    /// Save incoming swapcoin to wallet.
    fn save_incoming_swapcoin(&self, swapcoin: &IncomingSwapCoin) -> Result<(), MakerError>;

    /// Save outgoing swapcoin to wallet.
    fn save_outgoing_swapcoin(&self, swapcoin: &OutgoingSwapCoin) -> Result<(), MakerError>;

    /// Save a funding batch's swapcoins in one write, before its sends.
    fn save_funding_batch(
        &self,
        incoming: &[IncomingSwapCoin],
        outgoing: &[OutgoingSwapCoin],
    ) -> Result<(), MakerError>;

    /// Persist a fresh unbroadcast grace for `swap_id` just before one of its
    /// funding sends, so the grace counts from the last send attempt.
    fn restart_funding_grace(&self, swap_id: &str) -> Result<(), MakerError>;

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

    /// Fetch a transaction needed to resolve user-facing report UTXOs.
    fn get_raw_transaction(&self, txid: &bitcoin::Txid) -> Result<Transaction, MakerError>;

    /// Sweep incoming swapcoins after successful swap.
    fn sweep_incoming_swapcoins(
        &self,
        incoming_swapcoins: &[IncomingSwapCoin],
    ) -> Result<RecoveryOutcome, MakerError>;

    /// Persist the terminal maker state after every incoming contract has been
    /// swept. This must complete before a success report is emitted: otherwise
    /// a restart can mistake the already-delivered outgoing coins for an
    /// abandoned swap and launch recovery for them. The outgoing coins in
    /// `keep`, funding versions a bump left behind, stay persisted until they
    /// are retired.
    fn finalize_successful_swap(
        &self,
        swap_id: &str,
        expected_outgoing: usize,
        keep: &[Txid],
    ) -> Result<(), MakerError>;

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

    /// Refresh an existing swap's idle timer without creating state.
    fn touch_connection_state(&self, swap_id: &str) -> Result<(), MakerError>;

    /// Remove connection state for a completed swap.
    fn remove_connection_state(&self, swap_id: &str) -> Result<(), MakerError>;

    /// Store a swap report in the wallet and save it.
    fn save_report(&self, report: &MakerReport) -> Result<(), MakerError>;

    /// Get the current block height from the Bitcoin node.
    fn get_current_height(&self) -> Result<u32, MakerError>;

    /// Answered from the stored swap state, because the funding confirmation height
    /// a Legacy deadline needs is recorded there and not on the connection.
    fn swap_past_refund_deadline(&self, swap_id: &str) -> Result<bool, MakerError>;

    /// True when this swap has named its incoming funding txids (claimed at
    /// contract-data admission, or saved as incoming swapcoins) but the backend
    /// sees none of them, mempool included. Pre-evidence and unknown swaps
    /// return false: a later hop waits on upstream funding it cannot see.
    fn claimed_funding_unseen(&self, swap_id: &str) -> Result<bool, MakerError>;

    /// The spending txid when the watchtower saw a Legacy incoming funding
    /// outpoint of this swap spent, i.e. the previous hop broadcast its
    /// pre-signed contract. A failed query is an error, never "not breached".
    /// Taproot and unknown swaps: `None`.
    fn incoming_contract_breached(&self, swap_id: &str) -> Result<Option<Txid>, MakerError>;

    /// Wait until every peer tx in `txids` is confirmed to `required_confirms` depth.
    /// One deadline covers the whole batch, so a long transaction list cannot multiply
    /// the wait. Shutdown breaks it, and each poll refreshes the swap's stored
    /// activity, so the idle drain cannot kill a live wait.
    fn wait_for_txs_on_chain(
        &self,
        swap_id: &str,
        txids: &[bitcoin::Txid],
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

    /// Initialize outgoing swap by executing the funding plan frozen at
    /// admission. `send_amount` is the plan's pre-netting total, or short of
    /// it only by what upstream funding bumps took off the incoming hop, which
    /// then comes out of the splits; a missing plan, or an amount above its
    /// total, is a protocol error.
    #[allow(clippy::too_many_arguments)]
    fn initialize_swap(
        &self,
        swap_id: &str,
        send_amount: Amount,
        next_multisig_pubkeys: &[PublicKey],
        next_hashlock_pubkeys: &[PublicKey],
        hashvalue: crate::protocol::Hash160,
        locktime: u16,
        swap_feerate: f64,
    ) -> Result<(Vec<Transaction>, Vec<OutgoingSwapCoin>, Amount), MakerError>;

    /// Find outgoing swapcoin by its multisig redeemscript.
    fn find_outgoing_swapcoin(
        &self,
        multisig_redeemscript: &bitcoin::ScriptBuf,
    ) -> Option<OutgoingSwapCoin>;

    /// Whether this transaction is mined. A failed query is an error, never
    /// `false`: an unconfirmed funding is the only one we may replace.
    fn is_funding_confirmed(&self, txid: &Txid) -> Result<bool, MakerError>;

    /// Point our Taproot incoming coins of `swap_id` whose funding a bump
    /// replaced at the version that was mined, in the wallet and in
    /// `incoming`. A bump after a reorg could otherwise leave us claiming a
    /// contract that never exists.
    fn follow_replaced_incoming(
        &self,
        swap_id: &str,
        incoming: &mut [IncomingSwapCoin],
    ) -> Result<(), MakerError>;

    /// Whether `txid`, one of `swap_id`'s funding txs, is mined now or ever
    /// was: a mined one is latched, so a reorg cannot unconfirm it for us.
    fn funding_ever_confirmed(&self, swap_id: &str, txid: &Txid) -> Result<bool, MakerError>;

    /// Sign a replacement of funding split `split` of `swap_id`. It spends
    /// exactly that split's inputs, which the wallet's coin cache stops
    /// listing once the original is out, so the signing data is the build's.
    fn sign_funding_replacement(
        &self,
        swap_id: &str,
        split: usize,
        tx: &mut Transaction,
    ) -> Result<(), MakerError>;

    /// Feerate in sat/vB a replacement must add over what it replaces.
    fn replacement_increment_rate(&self) -> f64;

    /// Flag the outgoing swapcoins of these contract txids as funding
    /// versions a bump replaced: retired once beaten deep, recovered if a
    /// reorg mines one.
    fn mark_replaced_funding(&self, contract_txids: &[Txid]) -> Result<(), MakerError>;

    /// Test hook: keep one of our funding txs out of blocks, the way a fee
    /// spike would, so a test can bump it.
    #[cfg(feature = "integration-test")]
    fn stall_funding_for_test(&self, txid: &Txid);

    /// Get the test behavior override.
    #[cfg(feature = "integration-test")]
    fn behavior(&self) -> MakerBehavior;

    /// The Lightning backend, when configured. Default: none, which makes
    /// every Lightning request answer `Unsupported`.
    #[cfg(feature = "lightning")]
    fn lightning(&self) -> Option<std::sync::Arc<dyn crate::lightning::LightningBackend>> {
        None
    }

    /// The Lightning event router, when a backend is configured.
    #[cfg(feature = "lightning")]
    fn ln_router(&self) -> Option<std::sync::Arc<super::lightning_handlers::LnEventRouter>> {
        None
    }

    /// Store per-swap Lightning state.
    #[cfg(feature = "lightning")]
    fn store_ln_swap(
        &self,
        _swap_id: &str,
        _swap: super::lightning_handlers::LnMakerSwap,
    ) -> Result<(), MakerError> {
        Err(MakerError::General("lightning swaps not supported"))
    }

    /// Retrieve per-swap Lightning state.
    #[cfg(feature = "lightning")]
    fn get_ln_swap(
        &self,
        _swap_id: &str,
    ) -> Result<Option<super::lightning_handlers::LnMakerSwap>, MakerError> {
        Ok(None)
    }

    /// Remove per-swap Lightning state.
    #[cfg(feature = "lightning")]
    fn remove_ln_swap(&self, _swap_id: &str) -> Result<(), MakerError> {
        Ok(())
    }

    /// Store per-swap Lightning state, but only while the stored swap is still
    /// in `expected`. Returns whether it was stored. A handler that acts on a
    /// snapshot uses this so it cannot overwrite a state another connection
    /// has already moved the swap past.
    #[cfg(feature = "lightning")]
    fn store_ln_swap_if_phase(
        &self,
        _swap_id: &str,
        _expected: super::lightning_handlers::LnMakerPhase,
        _swap: super::lightning_handlers::LnMakerSwap,
    ) -> Result<bool, MakerError> {
        Err(MakerError::General("lightning swaps not supported"))
    }

    /// Remove per-swap Lightning state and its event mailbox, but only while
    /// the stored swap is still in `expected`. Returns whether it was removed.
    #[cfg(feature = "lightning")]
    fn remove_ln_swap_if_phase(
        &self,
        _swap_id: &str,
        _expected: super::lightning_handlers::LnMakerPhase,
    ) -> Result<bool, MakerError> {
        Ok(false)
    }

    /// Set a Lightning swap's `funding_height`, but only while the stored swap
    /// is still in `expected`, still funded at `outpoint` and still has no
    /// height. Only that field changes, so whatever else another writer has
    /// stored is kept. Returns whether the height was stored.
    #[cfg(feature = "lightning")]
    fn fill_ln_funding_height(
        &self,
        _swap_id: &str,
        _expected: super::lightning_handlers::LnMakerPhase,
        _outpoint: bitcoin::OutPoint,
        _height: u32,
    ) -> Result<bool, MakerError> {
        Err(MakerError::General("lightning swaps not supported"))
    }

    /// How many Lightning swaps are currently in flight.
    #[cfg(feature = "lightning")]
    fn ln_swap_count(&self) -> usize {
        0
    }

    /// Whether this specific transaction is confirmed.
    ///
    /// Distinguishing *which* transaction spent an HTLC needs this: knowing
    /// the outpoint has some confirmed spend does not say whose it was.
    #[cfg(feature = "lightning")]
    fn is_tx_confirmed(&self, _txid: &bitcoin::Txid) -> Result<bool, MakerError> {
        Err(MakerError::General("lightning swaps not supported"))
    }

    /// Height of the block that confirmed this transaction, or `None` while
    /// it is unconfirmed or unknown. A failed query is an error, never `None`.
    ///
    /// A swap-in's CSV refund window starts at this block, so it is what the
    /// maker records as the funding height.
    #[cfg(feature = "lightning")]
    fn tx_confirmation_height(&self, _txid: &bitcoin::Txid) -> Result<Option<u32>, MakerError> {
        Err(MakerError::General("lightning swaps not supported"))
    }

    /// Whether `outpoint` has a *confirmed* spend. A mempool-only spend
    /// reports false: it can still be evicted or reorged away, and dropping
    /// a swap's record on one would discard the only key that reaches the
    /// HTLC.
    #[cfg(feature = "lightning")]
    fn is_htlc_spend_confirmed(
        &self,
        _outpoint: &bitcoin::OutPoint,
        _script: &bitcoin::ScriptBuf,
    ) -> Result<bool, MakerError> {
        Err(MakerError::General("lightning swaps not supported"))
    }

    /// Whether `outpoint` is still unspent (mempool included), and how many
    /// blocks have passed since its transaction confirmed.
    ///
    /// A swap-in maker must know both before it pays: an already-spent
    /// output, or one whose CSV window has largely elapsed, means the taker
    /// can refund the HTLC the maker is about to pay for.
    #[cfg(feature = "lightning")]
    fn htlc_unspent_and_age(
        &self,
        _outpoint: &bitcoin::OutPoint,
    ) -> Result<(bool, u32), MakerError> {
        Err(MakerError::General("lightning swaps not supported"))
    }

    /// Waits for a Lightning HTLC funding transaction to reach
    /// `required_confirms`.
    ///
    /// Separate from [`wait_for_txs_on_chain`](Self::wait_for_txs_on_chain),
    /// whose keep-alive hook aborts the wait for any swap missing from
    /// `ongoing_swaps` — which every Lightning swap is, being tracked in its
    /// own map.
    #[cfg(feature = "lightning")]
    fn wait_for_htlc_confirmation(
        &self,
        _txid: &bitcoin::Txid,
        _required_confirms: u32,
    ) -> Result<(), MakerError> {
        Err(MakerError::General("lightning swaps not supported"))
    }

    /// Funds `address` with exactly `amount` for a Lightning HTLC, returning
    /// the transaction and the output's index.
    ///
    /// Separate from the coinswap funding path, which executes a plan frozen
    /// at admission: a Lightning HTLC is one exact output with no hop to
    /// reimburse, and its swap never enters `ongoing_swaps`.
    #[cfg(feature = "lightning")]
    fn fund_htlc(
        &self,
        _swap_id: &str,
        _amount: Amount,
        _address: bitcoin::Address,
    ) -> Result<(Transaction, u32), MakerError> {
        Err(MakerError::General("lightning swaps not supported"))
    }

    /// A fresh wallet receive address (Lightning HTLC sweeps/refunds land here).
    #[cfg(feature = "lightning")]
    fn get_receive_address(&self) -> Result<bitcoin::Address, MakerError> {
        Err(MakerError::General("lightning swaps not supported"))
    }

    /// Whether server shutdown was requested; bounds blocking waits.
    #[cfg(feature = "lightning")]
    fn shutdown_requested(&self) -> bool {
        false
    }
}

pub(super) fn emit_maker_success_report<M: Maker>(
    maker: &Arc<M>,
    state: &ConnectionState,
    swap_id: &str,
    swept: &RecoveryOutcome,
) {
    let network = maker.network();
    let mut seen_inputs = HashSet::new();
    let mut outgoing_utxos = Vec::new();

    for swapcoin in &state.outgoing_swapcoins {
        let funding_tx = match swapcoin.protocol {
            ProtocolVersion::Legacy => swapcoin.funding_tx.as_ref(),
            ProtocolVersion::Taproot => Some(&swapcoin.contract_tx),
        };
        let Some(funding_tx) = funding_tx else {
            log::warn!("Missing Legacy funding transaction for swap report");
            continue;
        };
        for input in &funding_tx.input {
            let outpoint = input.previous_output;
            if !seen_inputs.insert(outpoint) {
                continue;
            }
            let output = maker
                .get_raw_transaction(&outpoint.txid)
                .ok()
                .and_then(|transaction| transaction.output.get(outpoint.vout as usize).cloned());
            match output.and_then(|output| ReportUtxo::from_txout(&output, network)) {
                Some(utxo) => outgoing_utxos.push(utxo),
                None => log::warn!(
                    "Failed to resolve outgoing funding input {} for swap report",
                    outpoint
                ),
            }
        }
    }

    let incoming_contract_txids: HashSet<_> = state
        .incoming_swapcoins
        .iter()
        .map(|swapcoin| swapcoin.contract_tx.compute_txid())
        .collect();
    let incoming_utxos = swept
        .resolved
        .iter()
        .filter(|(contract_txid, _)| incoming_contract_txids.contains(contract_txid))
        .filter_map(
            |(_, sweep_txid)| match maker.get_raw_transaction(sweep_txid) {
                Ok(transaction) => Some(transaction),
                Err(error) => {
                    log::warn!(
                        "Failed to load sweep transaction {} for swap report: {:?}",
                        sweep_txid,
                        error
                    );
                    None
                }
            },
        )
        .flat_map(|transaction| transaction.output)
        .filter_map(|output| ReportUtxo::from_txout(&output, network))
        .collect();

    let incoming_total = state
        .incoming_swapcoins
        .iter()
        .map(|swapcoin| swapcoin.funding_amount.to_sat())
        .sum();
    let outgoing_total = state
        .outgoing_swapcoins
        .iter()
        .map(|swapcoin| swapcoin.funding_amount.to_sat())
        .sum();
    let timelock = state
        .outgoing_swapcoins
        .first()
        .and_then(|swapcoin| swapcoin.get_timelock())
        .unwrap_or(0);

    let report = MakerReport::success(
        swap_id.to_string(),
        state.swap_start_time,
        incoming_total,
        outgoing_total,
        state.service_fee_sats,
        incoming_utxos,
        outgoing_utxos,
        timelock,
        network.to_string(),
        state.incoming_swapcoins.first(),
        state.outgoing_swapcoins.first(),
    );
    report.print();
    if let Err(error) = maker.save_report(&report) {
        log::warn!("Failed to save maker success report: {error:?}");
    }
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
    /// Smallest swap we accept, worked out on every offer request.
    pub min_swap_amount: u64,
    /// Maximum swap amount.
    pub max_swap_amount: u64,
    /// Required confirmations.
    pub required_confirms: u32,
    /// Feature names a taker must support, each only in the swaps it applies to.
    pub require_features: Vec<String>,
    /// Public name sent in the offer.
    pub name: String,
    /// Highest feerate we replace our own funding at; zero refuses bumps.
    pub max_funding_bump_feerate: u64,
    /// Most extra fee one hop's funding may take across its bumps.
    pub max_funding_bump_sats: u64,
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
        TakerToMakerMessage::Hello(hello) => handle_hello(maker, state, hello),
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
            // A keepalive must not hold off recovery once the taker has broadcast
            // its contract: the swap cannot finish cooperatively any more.
            if maker.incoming_contract_breached(id)?.is_some() {
                return Ok(None);
            }
            // Once the swap has named its funding, a keepalive counts only while
            // the backend still sees it; otherwise a never-broadcast funding
            // could pin the reservation at zero on-chain cost.
            if maker.claimed_funding_unseen(id)? {
                log::warn!(
                    "[{}] Keepalive for swap {} names funding the backend cannot see; not refreshing",
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
            maker.touch_connection_state(id)?;
            state.touch();
            Ok(None)
        }
        TakerToMakerMessage::BumpFunding(request) => {
            restore_state_if_needed(maker, state, &request.id)?;
            super::funding_bump::handle_bump_funding(maker, state, request)
        }
        TakerToMakerMessage::BumpFundingCommit(commit) => {
            restore_state_if_needed(maker, state, &commit.id)?;
            ensure_negotiated_protocol(state, ProtocolVersion::Legacy)?;
            super::funding_bump::handle_bump_funding_commit(maker, state, commit)
        }
        TakerToMakerMessage::Lightning(ln_msg) => {
            #[cfg(feature = "lightning")]
            {
                super::lightning_handlers::handle_lightning_message(maker, state, *ln_msg)
            }
            #[cfg(not(feature = "lightning"))]
            {
                // Decline gracefully: a dropped connection would leave the
                // taker unable to distinguish "unsupported" from "down".
                log::info!(
                    "[{}] Declining Lightning message {} (built without lightning support)",
                    maker.network_port(),
                    ln_msg
                );
                Ok(Some(MakerToTakerMessage::Unsupported(UnsupportedMessage {
                    what: "Lightning".to_string(),
                    reason: "maker built without lightning support".to_string(),
                })))
            }
        }
        TakerToMakerMessage::Unsupported(unsupported) => {
            log::warn!(
                "[{}] Peer declined {}: {}",
                maker.network_port(),
                unsupported.what,
                unsupported.reason
            );
            Ok(None)
        }
    }
}

/// Handle the taker's Hello: it must list every unknown-family feature we
/// require. Known ones are checked per flow when the swap is pinned.
fn handle_hello<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    hello: Hello,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    state.expect_phase(&[SwapPhase::AwaitingHello])?;

    if let Err(reason) = check_bounds(&hello.features) {
        return Ok(Some(MakerToTakerMessage::Unsupported(UnsupportedMessage {
            what: "Hello".to_string(),
            reason,
        })));
    }

    let config = maker.get_config();
    if let Err(missing) = unmet_at_hello(&config.require_features, &hello.features) {
        log::info!(
            "[{}] Refusing a taker without required features {:?}",
            Maker::network_port(maker.as_ref()),
            missing
        );
        return Ok(Some(MakerToTakerMessage::Unsupported(UnsupportedMessage {
            what: "Hello".to_string(),
            reason: format!("missing required features: {missing:?}"),
        })));
    }

    state.phase = SwapPhase::AwaitingOfferRequest;
    Ok(Some(MakerToTakerMessage::Hello(Hello {
        features: supported().into_iter().map(String::from).collect(),
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
        name: config.name,
        // Fetched here rather than through `get_config`: this is one of the
        // two places that actually needs it.
        lightning: maker.lightning_offer(),
        max_funding_bump_feerate: config.max_funding_bump_feerate,
        max_funding_bump_sats: config.max_funding_bump_sats,
    };

    #[cfg(feature = "integration-test")]
    let offer = if maker.behavior() == MakerBehavior::SendMalformedOffer {
        log::warn!(
            "[{}] Test behavior: advertising an offer nobody can price",
            Maker::network_port(maker.as_ref())
        );
        Offer {
            min_size: offer.max_size.saturating_add(1),
            ..offer
        }
    } else {
        offer
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

    if !is_valid_swap_id(&details.id) {
        log::warn!(
            "[{}] Rejecting SwapDetails: swap id is not 16 hex characters ({} bytes)",
            Maker::network_port(maker.as_ref()),
            details.id.len()
        );
        return Ok(Some(MakerToTakerMessage::AckSwapDetails(
            AckSwapDetails::reject(),
        )));
    }

    #[cfg(feature = "integration-test")]
    if maker.behavior() == MakerBehavior::RefuseSwapDetails {
        log::warn!(
            "[{}] Test behavior: refusing SwapDetails for {}",
            Maker::network_port(maker.as_ref()),
            details.id
        );
        return Ok(Some(MakerToTakerMessage::AckSwapDetails(
            AckSwapDetails::reject(),
        )));
    }

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

    // The pins fix this swap's flow and features for every later reconnect.
    let pinned =
        check_pins(&details.features, &maker.get_config().require_features).and_then(|_| {
            details
                .protocol()
                .ok_or_else(|| "pins name no on-chain protocol".to_string())
        });
    let protocol = match pinned {
        Ok(protocol) => protocol,
        Err(reason) => {
            log::warn!(
                "[{}] Rejecting SwapDetails for {}: {}",
                Maker::network_port(maker.as_ref()),
                details.id,
                reason
            );
            return Ok(Some(MakerToTakerMessage::AckSwapDetails(
                AckSwapDetails::reject(),
            )));
        }
    };

    // A swap that pinned funding bumps needs the key its bumps are signed with.
    if pins_funding_bump(&details.features) && details.taker_auth_pubkey.is_none() {
        log::warn!(
            "[{}] Rejecting SwapDetails for {}: funding bumps pinned without the taker's key",
            Maker::network_port(maker.as_ref()),
            details.id,
        );
        return Ok(Some(MakerToTakerMessage::AckSwapDetails(
            AckSwapDetails::reject(),
        )));
    }

    log::info!(
        "[{}] Received SwapDetails: amount={}, timelock={}, pins={:?}",
        Maker::network_port(maker.as_ref()),
        details.amount,
        details.timelock,
        details.features
    );

    // The fee pays for how long our funds stay locked, so use the length derived from the
    // timelock. Otherwise the taker could ask for a long lock and pay for a short one.
    // A validation failure is a terminal refusal, so it goes back as a reject-Ack like
    // an admission failure below: a dropped connection would stall an honest taker.
    let refund_locktime_offset = match maker.validate_swap_parameters(&details) {
        Ok(offset) => offset,
        Err(e) => {
            log::warn!(
                "[{}] Rejecting SwapDetails for {}: parameter validation failed: {:?}",
                Maker::network_port(maker.as_ref()),
                details.id,
                e
            );
            return Ok(Some(MakerToTakerMessage::AckSwapDetails(
                AckSwapDetails::reject(),
            )));
        }
    };

    state.swap_id = Some(details.id.clone());
    state.swap_amount = details.amount;
    state.tx_count = details.tx_count;
    state.incoming_count = details.incoming_count;
    state.max_input_budget = details.max_input_budget;
    state.swap_feerate = details.feerate as f64;
    state.timelock = details.timelock;
    state.refund_locktime_offset = refund_locktime_offset;
    state.protocol = protocol;
    // Funding bumps only on a swap that pinned them; a key sent without the
    // pin authorizes nothing.
    state.taker_auth_pubkey = details
        .taker_auth_pubkey
        .filter(|_| pins_funding_bump(&details.features));
    state.swap_start_time = Instant::now();
    let swap_fee = maker.calculate_swap_fee(details.amount, state.refund_locktime_offset as u32);
    state.service_fee_sats = swap_fee.to_sat();
    state.phase = SwapPhase::AwaitingContractData;

    // An admission rejection must reach the taker as a message, not a dropped
    // connection, or it waits out a timeout before trying the next maker.
    // Every admission failure is a terminal rejection and gets the same
    // reset; nothing was stored, so restore_state_if_needed stays a no-op.
    if let Err(e) = maker.store_connection_state(&details.id, state, true) {
        log::warn!(
            "[{}] Rejecting SwapDetails for {}: admission failed: {:?}",
            Maker::network_port(maker.as_ref()),
            details.id,
            e
        );
        // A rejected admission must leave no live phase: with AwaitingContractData
        // still set, the taker could send ContractData and drive funding for a
        // swap we refused.
        state.phase = SwapPhase::AwaitingSwapDetails;
        state.swap_id = None;
        state.swap_amount = Amount::ZERO;
        state.tx_count = 0;
        state.incoming_count = 0;
        state.max_input_budget = 0;
        state.timelock = 0;
        state.refund_locktime_offset = 0;
        state.service_fee_sats = 0;
        state.swap_feerate = 0.0;
        state.funding_plan = Vec::new();
        state.taker_auth_pubkey = None;
        return Ok(Some(MakerToTakerMessage::AckSwapDetails(
            AckSwapDetails::reject(),
        )));
    }

    let (_, tweakable_point, _) = maker.get_tweakable_keypair()?;

    // The Ack reports the shape of the plan frozen at admission, so the taker
    // derives the next hop's amount and count from what we will fund.
    let stored = maker
        .get_connection_state(&details.id)?
        .ok_or(MakerError::General("Admission left no stored swap state"))?;
    let funding_splits: Vec<u32> = stored
        .funding_plan
        .iter()
        .map(|split| split.utxos.len() as u32)
        .collect();
    state.funding_plan = stored.funding_plan;
    #[cfg(feature = "integration-test")]
    let funding_splits = if maker.behavior() == MakerBehavior::OverreportFundingInputs {
        funding_splits.iter().map(|count| count + 1).collect()
    } else {
        funding_splits
    };
    // A resend for a live swap keeps that admission's identity, or this
    // connection's later stores would read as a stale admission.
    state.swap_start_time = stored.swap_start_time;

    log::info!(
        "[{}] Accepting swap (id: {}) with {} funding split(s)",
        Maker::network_port(maker.as_ref()),
        details.id,
        funding_splits.len()
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
        AckSwapDetails::accept(tweakable_point, funding_splits),
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
            // A connection already holding this swap keeps its own admission:
            // a newer admission of a reused id is not its to drive.
            if state.swap_id.as_deref() == Some(swap_id)
                && state.swap_start_time != stored.swap_start_time
            {
                return Err(MakerError::General(
                    "Swap plan expired; the taker must send new SwapDetails",
                ));
            }
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
            state.incoming_count = stored.incoming_count;
            state.max_input_budget = stored.max_input_budget;
            state.timelock = stored.timelock;
            state.protocol = stored.protocol;
            state.phase = stored.phase;
            state.incoming_swapcoins = stored.incoming_swapcoins;
            state.outgoing_swapcoins = stored.outgoing_swapcoins;
            state.pending_funding_txes = stored.pending_funding_txes;
            state.funding_broadcast_txids = stored.funding_broadcast_txids;
            state.swap_feerate = stored.swap_feerate;
            state.service_fee_sats = stored.service_fee_sats;
            state.funding_plan = stored.funding_plan;
            state.swap_start_time = stored.swap_start_time;
            state.refund_locktime_offset = stored.refund_locktime_offset;
            state.taker_auth_pubkey = stored.taker_auth_pubkey;
            state.funding_bump = stored.funding_bump;
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

    // That handler checks itself, after saving the signed swapcoins recovery needs.
    if !matches!(
        legacy_msg,
        LegacyTakerMessage::RespContractSigsForRecvrAndSender(_)
    ) {
        super::legacy_handlers::refuse_if_breached(maker.as_ref(), &swap_id)?;
    }

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
    use crate::maker::api::tests::compat_test_maker;

    #[test]
    fn compat_maker_rejects_invalid_pins_before_admission() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        for (i, (pins, required)) in [
            (vec![], vec![]),
            (vec!["legacy", "taproot"], vec![]),
            (vec!["taproot", "taproot"], vec![]),
            (vec!["taproot", "future-v1"], vec![]),
            (vec!["taproot"], vec!["future-v1"]),
            (vec!["taproot"], vec!["taproot-v1"]),
            (vec!["ln-swap-in"], vec![]),
            // Funding bumps pinned without the key that signs them.
            (vec!["taproot", "funding-bump-v1"], vec![]),
        ]
        .iter()
        .enumerate()
        {
            let maker = compat_test_maker(
                &dir.path().join(i.to_string()),
                required.iter().map(|s| s.to_string()).collect(),
            );
            let mut state = ConnectionState {
                phase: SwapPhase::AwaitingSwapDetails,
                ..Default::default()
            };
            let details = SwapDetails {
                id: "compat-pins".into(),
                features: pins.iter().map(|s| s.to_string()).collect(),
                amount: Amount::from_sat(123_456),
                tx_count: 1,
                incoming_count: 1,
                max_input_budget: 1,
                feerate: 1,
                timelock: 1_000,
                refund_locktime_offset: 60,
                taker_auth_pubkey: None,
            };
            let reply = handle_message(
                &maker,
                &mut state,
                TakerToMakerMessage::SwapDetails(details),
            )
            .unwrap();
            assert!(
                matches!(reply, Some(MakerToTakerMessage::AckSwapDetails(ack)) if ack.tweakable_point.is_none())
            );
            assert_eq!(state.phase, SwapPhase::AwaitingSwapDetails);
            assert!(state.swap_id.is_none());
            assert!(maker.get_connection_state("compat-pins").unwrap().is_none());
            maker.watch_service.shutdown();
        }
    }

    /// A funding version told apart by `value`.
    fn version(value: u64) -> OutgoingSwapCoin {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let key = bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
        let pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &key),
        };
        let contract_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint::new(bitcoin::hashes::Hash::from_byte_array([1; 32]), 0),
                ..Default::default()
            }],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(value),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        OutgoingSwapCoin::new_legacy(
            key,
            pubkey,
            contract_tx,
            bitcoin::ScriptBuf::new(),
            key,
            Amount::from_sat(value),
            1,
        )
    }

    /// Connection A bumped and stored its replacement; connection B, holding
    /// the snapshot from before, takes a later request and stores. B's store
    /// must keep A's replacement and count: recovery and the success
    /// cleanup both read every version from here.
    #[test]
    fn a_stale_connection_cannot_undo_another_connections_bump() {
        let original = version(50_000);
        let before = FundingBumpState::default();
        let mut stored = before.clone();
        let bumped_by_a = FundingBumpState {
            seq: 1,
            feerate: 4,
            bumps: 1,
            replacements: vec![version(49_000)],
            ..FundingBumpState::default()
        };
        stored.merge_from(&bumped_by_a, std::slice::from_ref(&original));

        let mut from_b = before;
        from_b.seq = 2;
        stored.merge_from(&from_b, std::slice::from_ref(&original));

        assert_eq!(stored.seq, 2);
        assert_eq!(stored.feerate, 4);
        assert_eq!(stored.bumps, 1);
        assert_eq!(stored.replacements.len(), 1);
        assert_eq!(
            stored.replacements[0].contract_tx.compute_txid(),
            bumped_by_a.replacements[0].contract_tx.compute_txid()
        );
    }

    /// Once the hop settles, the version that won is an outgoing coin and no
    /// replacement; the ones that lost stay replacements. A settled hop
    /// stays settled whoever stores next.
    #[test]
    fn a_settled_version_leaves_the_replacements() {
        let (original, winner) = (version(50_000), version(49_000));
        let mut stored = FundingBumpState {
            seq: 1,
            bumps: 1,
            replacements: vec![winner.clone()],
            ..FundingBumpState::default()
        };
        let resolved = FundingBumpState {
            seq: 1,
            bumps: 1,
            settled: true,
            replacements: vec![original.clone()],
            ..FundingBumpState::default()
        };
        stored.merge_from(&resolved, std::slice::from_ref(&winner));
        let txids: Vec<Txid> = stored
            .replacements
            .iter()
            .map(|coin| coin.contract_tx.compute_txid())
            .collect();
        assert_eq!(txids, vec![original.contract_tx.compute_txid()]);
        assert!(stored.settled);

        stored.merge_from(&FundingBumpState::default(), std::slice::from_ref(&winner));
        assert!(stored.settled);
    }

    /// A commit clears the pending proposal it consumed; a stale snapshot
    /// from before the proposal must not clear it.
    #[test]
    fn only_the_latest_request_sets_the_pending_proposal() {
        let pending = PendingFundingBump {
            seq: 3,
            feerate: 5,
            replacements: vec![(0, version(49_000))],
        };
        let mut stored = FundingBumpState {
            seq: 3,
            pending: Some(pending),
            ..FundingBumpState::default()
        };
        let stale = FundingBumpState {
            seq: 2,
            ..FundingBumpState::default()
        };
        stored.merge_from(&stale, &[]);
        assert!(stored.pending.is_some());

        let committed = FundingBumpState {
            seq: 3,
            ..FundingBumpState::default()
        };
        stored.merge_from(&committed, &[]);
        assert!(stored.pending.is_none());
    }

    /// A second handler for a swap whose funding is running is refused; the
    /// swap is free again once the first handler is done, on any exit path.
    #[test]
    fn funding_guard_admits_one_handler_per_swap() {
        let running = Mutex::new(HashSet::new());
        let first = FundingGuard::acquire(&running, "swap").unwrap();
        assert!(matches!(
            FundingGuard::acquire(&running, "swap"),
            Err(MakerError::General(_))
        ));
        // Other swaps fund independently.
        let other = FundingGuard::acquire(&running, "other").unwrap();
        drop(first);
        drop(FundingGuard::acquire(&running, "swap").unwrap());

        // A handler that panics mid-funding still frees its swap.
        let shared = Arc::new(Mutex::new(HashSet::new()));
        let held = Arc::clone(&shared);
        std::thread::spawn(move || {
            let _funding = FundingGuard::acquire(&held, "swap").unwrap();
            panic!("handler failed mid-funding");
        })
        .join()
        .unwrap_err();
        assert!(FundingGuard::acquire(&shared, "swap").is_ok());
        drop(other);
    }

    #[test]
    fn offset_below_reaction_time_is_rejected() {
        assert!(!offset_meets_reaction_time(0));
        assert!(!offset_meets_reaction_time(MIN_CONTRACT_REACTION_TIME - 1));
        assert!(offset_meets_reaction_time(MIN_CONTRACT_REACTION_TIME));
        assert!(offset_meets_reaction_time(500));
    }

    #[test]
    fn swap_id_must_be_16_hex_characters() {
        assert!(is_valid_swap_id(&format!("{:016x}", u64::MAX)));
        assert!(is_valid_swap_id("00000000000000ab"));
        assert!(!is_valid_swap_id(""));
        assert!(!is_valid_swap_id("0123456789abcde"));
        assert!(!is_valid_swap_id("0123456789abcdef0"));
        assert!(!is_valid_swap_id("0123456789abcdeg"));
        assert!(!is_valid_swap_id(&"a".repeat(1 << 20)));
        // Sixteen bytes, but not sixteen hex characters.
        assert!(!is_valid_swap_id("0123456789abcdé"));
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
    fn incoming_must_fit_the_declared_swap_amount() {
        let negotiated = Amount::from_sat(500_000);

        for bumps in [true, false] {
            assert!(incoming_fits_swap_amount(negotiated, negotiated, bumps));
            assert!(!incoming_fits_swap_amount(
                negotiated + Amount::from_sat(1),
                negotiated,
                bumps
            ));
            // Past the bump bound, a short hop is under-delivery, not a bump.
            assert!(!incoming_fits_swap_amount(
                negotiated - Amount::from_sat(50_001),
                negotiated,
                bumps
            ));
        }
        // Upstream funding bumps may leave the hop short; the fee was fixed
        // at admission, so the shortfall costs the maker nothing.
        assert!(incoming_fits_swap_amount(
            negotiated - Amount::from_sat(4_000),
            negotiated,
            true
        ));
        // A swap without funding bumps has nothing to explain a short hop.
        assert!(!incoming_fits_swap_amount(
            negotiated - Amount::from_sat(4_000),
            negotiated,
            false
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
