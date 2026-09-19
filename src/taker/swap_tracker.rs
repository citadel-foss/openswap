//! Persistent swap tracker for crash-resilient recovery.
//!
//! Stores swap state to `{data_dir}/swap_tracker.cbor` using atomic writes
//! (write-to-tmp then rename). This ensures the taker can resume recovery
//! after a crash at any point during a swap.
#![allow(missing_docs)]

use std::{
    collections::HashMap,
    convert::TryInto,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use bitcoin::{secp256k1::SecretKey, Txid};
use serde::{Deserialize, Serialize};

use crate::{lock_debug, protocol::common_messages::ProtocolVersion};

use super::error::TakerError;

/// Newtype wrapper for `SecretKey` that implements Serialize/Deserialize.
///
/// `SecretKey` doesn't implement serde traits, so we serialize as raw 32-byte array.
#[derive(Debug, Clone)]
pub struct SerializableSecretKey(pub SecretKey);

impl Serialize for SerializableSecretKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialize as a fixed-size array of 32 bytes for CBOR compatibility
        let bytes: [u8; 32] = self.0[..].try_into().expect("SecretKey is always 32 bytes");
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerializableSecretKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        let key = SecretKey::from_slice(&bytes).map_err(serde::de::Error::custom)?;
        Ok(SerializableSecretKey(key))
    }
}

impl From<SecretKey> for SerializableSecretKey {
    fn from(key: SecretKey) -> Self {
        SerializableSecretKey(key)
    }
}

impl From<SerializableSecretKey> for SecretKey {
    fn from(key: SerializableSecretKey) -> Self {
        key.0
    }
}

/// Tracks which phase of the swap lifecycle has been reached.
///
/// Derives `PartialOrd`/`Ord` so phase comparisons like `phase >= FundsBroadcast`
/// work naturally. Variant order matters — they must be listed in lifecycle order.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, Hash,
)]
pub enum SwapPhase {
    /// Makers selected from offerbook. Safe to abort.
    #[default]
    MakersDiscovered,
    /// Swap details negotiated with makers. Safe to abort.
    Negotiated,
    /// Outgoing swapcoins created, not yet broadcast. Safe to abort.
    FundingCreated,
    /// On-chain. Point of no return — recovery needed on failure.
    FundsBroadcast,
    /// All makers responded with contracts.
    ContractsExchanged,
    /// Privkey exchange in progress.
    Finalizing,
    /// Inter-maker privkey exchange done.
    PrivkeysForwarded,
    /// Swap finished, incoming swept.
    Completed,
    /// Swap failed (see `failed_at_phase` for context).
    Failed,
}

impl fmt::Display for SwapPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SwapPhase::MakersDiscovered => write!(f, "MakersDiscovered"),
            SwapPhase::Negotiated => write!(f, "Negotiated"),
            SwapPhase::FundingCreated => write!(f, "FundingCreated"),
            SwapPhase::FundsBroadcast => write!(f, "FundsBroadcast"),
            SwapPhase::ContractsExchanged => write!(f, "ContractsExchanged"),
            SwapPhase::Finalizing => write!(f, "Finalizing"),
            SwapPhase::PrivkeysForwarded => write!(f, "PrivkeysForwarded"),
            SwapPhase::Completed => write!(f, "Completed"),
            SwapPhase::Failed => write!(f, "Failed"),
        }
    }
}

/// Legacy per-maker exchange milestones.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LegacyExchangeProgress {
    /// TCP/Tor connection established.
    pub connected: bool,
    /// ReqContractSigsForSender sent to this maker.
    /// First maker: signs taker's outgoing contracts.
    /// Subsequent makers: signs previous maker's outgoing contracts.
    pub sender_sigs_requested: bool,
    /// RespContractSigsForSender received from this maker.
    pub sender_sigs_received: bool,
    /// Previous hop's funding tx broadcast to mempool.
    /// First maker: taker's funding. Subsequent makers: previous maker's funding.
    pub prev_funding_broadcast: bool,
    /// Previous hop's funding tx confirmed on-chain.
    pub prev_funding_confirmed: bool,
    /// ProofOfFunding sent to maker.
    pub proof_of_funding_sent: bool,
    /// Maker responded with ReqContractSigsAsRecvrAndSender.
    pub maker_contracts_received: bool,
    /// Sender sigs obtained from next maker (or self-signed if last hop).
    pub next_maker_sigs_obtained: bool,
    /// Receiver sigs obtained from prev maker (or self-signed if first hop).
    pub prev_maker_sigs_obtained: bool,
    /// RespContractSigsForRecvrAndSender sent to maker.
    pub combined_sigs_sent: bool,
    /// Maker's funding tx confirmed on-chain.
    pub maker_funding_confirmed: bool,
    /// Watch-only swapcoins created (intermediate hops only).
    pub watchonly_created: bool,
}

/// Taproot per-maker exchange milestones.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaprootExchangeProgress {
    /// TCP/Tor connection established.
    pub connected: bool,
    /// TaprootContractData sent to maker.
    pub contract_data_sent: bool,
    /// Maker's TaprootContractData received.
    pub maker_contract_received: bool,
    /// Incoming or watch-only swapcoins created from maker's response.
    pub swapcoins_created: bool,
    /// Maker's funding (contract) tx confirmed on-chain.
    #[serde(default)]
    pub maker_funding_confirmed: bool,
}

/// Protocol-specific exchange progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExchangeProgress {
    Legacy(LegacyExchangeProgress),
    Taproot(TaprootExchangeProgress),
}

/// Shared finalization milestones (both protocols).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FinalizationProgress {
    pub privkey_received: bool,
    pub privkey_forwarded: bool,
}

/// Per-maker milestone tracking within a swap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakerProgress {
    pub address: String,
    pub negotiated: bool,
    pub exchange: ExchangeProgress,
    pub finalization: FinalizationProgress,
}

/// How a contract UTXO was resolved.
///
/// Only encodes the spending path, not WHO spent it — the direction
/// (`incoming`/`outgoing`/`watchonly`) already tells us the actor.
/// E.g. `Hashlock` in `incoming` = we swept; `Hashlock` in `outgoing` = counterparty claimed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContractResolution {
    /// Script-path spend using hashlock (preimage + key).
    Hashlock,
    /// Script-path spend using timelock (CLTV matured + key).
    Timelock,
    /// Cooperative key-path spend (MuSig2 aggregate signature).
    KeyPath,
    /// Contract tx was never broadcast or UTXO was already spent before
    /// we could act. No recovery needed.
    Discarded,
    /// Still on-chain, unspent. Recovery pending.
    Unresolved,
}

impl fmt::Display for ContractResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractResolution::Hashlock => write!(f, "Hashlock"),
            ContractResolution::Timelock => write!(f, "Timelock"),
            ContractResolution::KeyPath => write!(f, "KeyPath"),
            ContractResolution::Discarded => write!(f, "Discarded"),
            ContractResolution::Unresolved => write!(f, "Unresolved"),
        }
    }
}

/// Per-contract resolution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractOutcome {
    /// The contract transaction's txid (the UTXO being tracked).
    pub contract_txid: Txid,
    /// How the contract was resolved.
    pub resolution: ContractResolution,
    /// The txid that spent this contract output (None if Discarded/Unresolved).
    pub spending_txid: Option<Txid>,
}

/// Tracks recovery progress across crashes.
///
/// Derives `PartialOrd`/`Ord` so recovery can skip completed phases with
/// `if recovery.phase < RecoveryPhase::PreimageStamped { ... }`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, Hash,
)]
pub enum RecoveryPhase {
    #[default]
    NotStarted,
    /// Phase 1 done: preimage set on incoming swapcoins in memory.
    PreimageStamped,
    /// Phase 2 done: swapcoins written to wallet on disk.
    SwapcoinsPersisted,
    /// Phase 3 done: hashlock sweep attempted for all incoming.
    IncomingRecovered,
    /// Phase 4 done: timelock recovery attempted for all outgoing.
    OutgoingRecovered,
    /// Phase 5 done: watch-only removed, swap state cleared.
    CleanedUp,
}

/// Tracks per-swapcoin recovery results.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecoveryState {
    pub phase: RecoveryPhase,
    /// Resolution of each incoming contract (taker is receiver).
    pub incoming: Vec<ContractOutcome>,
    /// Resolution of each outgoing contract (taker is sender).
    pub outgoing: Vec<ContractOutcome>,
    /// Resolution of each intermediate maker-to-maker contract (watch-only).
    pub watchonly: Vec<ContractOutcome>,
}

/// A persistent record of a single swap's state and progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRecord {
    pub swap_id: String,
    pub preimage: [u8; 32],
    pub protocol: ProtocolVersion,
    pub send_amount_sat: u64,
    pub maker_count: usize,
    pub phase: SwapPhase,
    pub failed_at_phase: Option<SwapPhase>,
    pub failure_reason: Option<String>,
    pub makers: Vec<MakerProgress>,
    pub outgoing_contract_txids: Vec<Txid>,
    pub incoming_contract_txids: Vec<Txid>,
    pub watchonly_contract_txids: Vec<Txid>,
    pub recovery: RecoveryState,
    /// Multisig nonces needed for ProofOfFunding during recovery (Legacy only).
    /// Empty for Taproot swaps.
    pub multisig_nonces: Vec<SerializableSecretKey>,
    /// Hashlock nonces for recovery (both Legacy and Taproot).
    /// Legacy: used in ProofOfFunding. Taproot: one per maker hop.
    pub hashlock_nonces: Vec<SerializableSecretKey>,
    /// PaySwap receiver address, informational — the binding copy lives on
    /// the wallet's incoming swapcoins.
    #[serde(default)]
    pub payment_address: Option<String>,
    /// Exact PaySwap amount for the receiver (satoshis).
    #[serde(default)]
    pub payment_amount_sat: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl fmt::Display for RecoveryPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Truncate a txid to its first 8 hex characters for compact display.
fn short_txid(txid: &Txid) -> String {
    let s = txid.to_string();
    s[..8.min(s.len())].to_string()
}

impl fmt::Display for MakerProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let neg = if self.negotiated { "N" } else { "-" };

        let exchange_str = match &self.exchange {
            ExchangeProgress::Legacy(l) => {
                let flags: &[(&str, bool)] = &[
                    ("c", l.connected),
                    ("q", l.sender_sigs_requested),
                    ("Q", l.sender_sigs_received),
                    ("b", l.prev_funding_broadcast),
                    ("B", l.prev_funding_confirmed),
                    ("p", l.proof_of_funding_sent),
                    ("M", l.maker_contracts_received),
                    ("n", l.next_maker_sigs_obtained),
                    ("r", l.prev_maker_sigs_obtained),
                    ("S", l.combined_sigs_sent),
                    ("m", l.maker_funding_confirmed),
                    ("w", l.watchonly_created),
                ];
                flags
                    .iter()
                    .map(|(c, ok)| if *ok { *c } else { "-" })
                    .collect::<String>()
            }
            ExchangeProgress::Taproot(t) => {
                let flags: &[(&str, bool)] = &[
                    ("c", t.connected),
                    ("s", t.contract_data_sent),
                    ("r", t.maker_contract_received),
                    ("w", t.swapcoins_created),
                    ("m", t.maker_funding_confirmed),
                ];
                flags
                    .iter()
                    .map(|(c, ok)| if *ok { *c } else { "-" })
                    .collect::<String>()
            }
        };

        let fin_flags: &[(&str, bool)] = &[
            ("K", self.finalization.privkey_received),
            ("F", self.finalization.privkey_forwarded),
        ];
        let fin_str: String = fin_flags
            .iter()
            .map(|(c, ok)| if *ok { *c } else { "-" })
            .collect();

        write!(f, "{}[{}|{}|{}]", self.address, neg, exchange_str, fin_str)
    }
}

impl fmt::Display for RecoveryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "phase={}", self.phase)?;
        for (label, outcomes) in [
            ("incoming", &self.incoming),
            ("outgoing", &self.outgoing),
            ("watchonly", &self.watchonly),
        ] {
            for (i, outcome) in outcomes.iter().enumerate() {
                let spending = match &outcome.spending_txid {
                    Some(txid) => format!(" (spending: {})", short_txid(txid)),
                    None => String::new(),
                };
                write!(
                    f,
                    "\n    {}[{}]: {} -> {}{}",
                    label,
                    i,
                    short_txid(&outcome.contract_txid),
                    outcome.resolution,
                    spending
                )?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for SwapRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] phase={} proto={:?} amt={} makers={}",
            self.swap_id, self.phase, self.protocol, self.send_amount_sat, self.maker_count,
        )?;
        if let Some(ref failed_at) = self.failed_at_phase {
            write!(f, " failed_at={}", failed_at)?;
        }
        write!(
            f,
            " out_txids={} in_txids={} wo_txids={}",
            self.outgoing_contract_txids.len(),
            self.incoming_contract_txids.len(),
            self.watchonly_contract_txids.len(),
        )?;
        if !self.makers.is_empty() {
            write!(f, "\n  makers:")?;
            for (i, m) in self.makers.iter().enumerate() {
                write!(f, "\n    [{}] {}", i, m)?;
            }
        }
        // Only show recovery details when recovery has started or the swap has failed.
        if self.phase == SwapPhase::Failed
            || self.failed_at_phase.is_some()
            || self.recovery.phase > RecoveryPhase::NotStarted
        {
            write!(f, "\n  recovery: {}", self.recovery)?;
        }
        Ok(())
    }
}

/// Internal storage format for the tracker.
#[derive(Serialize, Deserialize, Default)]
struct SwapTrackerData {
    swaps: HashMap<String, SwapRecord>,
}

/// Persistent swap tracker backed by a CBOR file with atomic writes.
/// Whether a coin's funding is already in a maker's hands, so recovery must
/// keep it rather than discard it. A coin with no swap id, or one the tracker
/// no longer knows, counts as shared: recovery never drops money it cannot
/// account for.
pub(crate) fn funding_shared(tracker: &Arc<Mutex<SwapTracker>>, coin_swap: Option<&str>) -> bool {
    coin_swap.is_none_or(|id| {
        lock_debug!(tracker.lock())
            .map(|tracker| tracker.legacy_proof_sent_for(id))
            .unwrap_or(true)
    })
}

pub struct SwapTracker {
    path: PathBuf,
    data: SwapTrackerData,
}

impl SwapTracker {
    /// Load tracker from disk or create a new empty one.
    pub fn load_or_create(data_dir: &Path) -> Result<Self, TakerError> {
        let path = data_dir.join("swap_tracker.cbor");
        let data = if path.exists() {
            match std::fs::read(&path) {
                Ok(bytes) => serde_cbor::from_slice(&bytes).unwrap_or_default(),
                Err(e) => {
                    log::warn!("Failed to read swap tracker at {:?}: {}", path, e);
                    SwapTrackerData::default()
                }
            }
        } else {
            SwapTrackerData::default()
        };

        #[cfg(debug_assertions)]
        log::debug!(
            "[SWAP_TRACKER] Source: taker::swap_tracker::load_or_create | Role: Taker | Action: load | Records: {} | Incomplete: {}",
            data.swaps.len(),
            data.swaps
                .values()
                .filter(|r| {
                    r.phase != SwapPhase::Completed
                        && !(r.phase == SwapPhase::Failed
                            && r.recovery.phase >= RecoveryPhase::CleanedUp)
                })
                .count()
        );

        Ok(Self { path, data })
    }

    /// Atomic flush: write to tmp file, then rename over original.
    fn flush(&self) -> Result<(), TakerError> {
        let tmp_path = self.path.with_extension("cbor.tmp");

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let bytes = serde_cbor::to_vec(&self.data)
            .map_err(|e| TakerError::General(format!("Failed to serialize swap tracker: {}", e)))?;

        std::fs::write(&tmp_path, &bytes)?;
        std::fs::rename(&tmp_path, &self.path)?;

        Ok(())
    }

    /// Upsert a swap record and flush to disk.
    pub fn save_record(&mut self, record: &SwapRecord) -> Result<(), TakerError> {
        #[cfg(debug_assertions)]
        if self.data.swaps.get(&record.swap_id).is_none_or(|old| {
            old.phase != record.phase
                || old.recovery.phase != record.recovery.phase
                || old.failed_at_phase != record.failed_at_phase
        }) {
            log::debug!(
                "[SWAP_TRACKER] Source: taker::swap_tracker::save_record | Role: Taker | SwapID: {} | Phase: {} | Recovery: {} | FailedAt: {:?} | Incoming: {} | Outgoing: {} | WatchOnly: {}",
                record.swap_id,
                record.phase,
                record.recovery.phase,
                record.failed_at_phase,
                record.incoming_contract_txids.len(),
                record.outgoing_contract_txids.len(),
                record.watchonly_contract_txids.len()
            );
        }
        self.data
            .swaps
            .insert(record.swap_id.clone(), record.clone());
        self.flush()
    }

    /// Remove a swap record and flush to disk.
    pub fn remove_record(&mut self, swap_id: &str) -> Result<(), TakerError> {
        self.data.swaps.remove(swap_id);
        self.flush()
    }

    /// Returns all non-Completed swap records.
    ///
    /// Includes `Failed` records where `recovery.phase < CleanedUp`
    /// (crash during recovery) so recovery can resume.
    pub fn incomplete_swaps(&self) -> Vec<&SwapRecord> {
        self.data
            .swaps
            .values()
            .filter(|r| {
                r.phase != SwapPhase::Completed
                    && !(r.phase == SwapPhase::Failed
                        && r.recovery.phase >= RecoveryPhase::CleanedUp)
            })
            .collect()
    }

    /// Get a reference to a swap record by ID.
    pub fn get_record(&self, swap_id: &str) -> Option<&SwapRecord> {
        self.data.swaps.get(swap_id)
    }

    /// True when this swap already sent a ProofOfFunding to any maker: its
    /// funding txs are in that maker's hands and can land on-chain at any time.
    pub(crate) fn legacy_proof_sent_for(&self, swap_id: &str) -> bool {
        self.get_record(swap_id).is_some_and(|record| {
            record.makers.iter().any(
                |m| matches!(&m.exchange, ExchangeProgress::Legacy(l) if l.proof_of_funding_sent),
            )
        })
    }

    /// Get a mutable reference to a swap record by ID.
    pub fn get_record_mut(&mut self, swap_id: &str) -> Option<&mut SwapRecord> {
        self.data.swaps.get_mut(swap_id)
    }

    /// Mutate a record in-place and atomically flush to disk.
    ///
    /// Returns `Ok(true)` if the record was found and updated, `Ok(false)` if not found.
    pub fn update_and_save<F>(&mut self, swap_id: &str, f: F) -> Result<bool, TakerError>
    where
        F: FnOnce(&mut SwapRecord),
    {
        let Some(record) = self.data.swaps.get_mut(swap_id) else {
            return Ok(false);
        };
        f(record);
        record.updated_at = now_secs();
        let clone = record.clone();
        self.save_record(&clone)?;
        Ok(true)
    }

    /// Clean up incomplete swap records from a previous session.
    ///
    /// - Early-phase swaps (Negotiating, FundingCreated) have no funds at risk — removes them.
    /// - Late-phase swaps (FundsBroadcast, ContractsExchanged, etc.) are marked as Failed
    ///   so wallet-driven recovery can handle them.
    /// - Completed swaps are left untouched.
    pub fn cleanup_incomplete(&mut self) {
        let incomplete_ids: Vec<String> = self
            .incomplete_swaps()
            .iter()
            .map(|r| r.swap_id.clone())
            .collect();

        if incomplete_ids.is_empty() {
            log::info!("No incomplete swaps found in tracker.");
            return;
        }

        for swap_id in &incomplete_ids {
            let phase = match self.get_record(swap_id) {
                Some(r) => r.phase,
                None => continue,
            };

            match phase {
                SwapPhase::MakersDiscovered | SwapPhase::Negotiated | SwapPhase::FundingCreated => {
                    log::info!(
                        "Swap {} was in phase {} — no funds at risk, cleaning up",
                        swap_id,
                        phase
                    );
                    if let Err(e) = self.remove_record(swap_id) {
                        log::error!("Failed to remove tracker record for {}: {:?}", swap_id, e);
                    }
                }
                SwapPhase::Completed => {}
                _ => {
                    log::warn!(
                        "Swap {} was in phase {} — marking as Failed, wallet recovery will handle it",
                        swap_id, phase
                    );
                    let _ = self.update_and_save(swap_id, |record| {
                        record.phase = SwapPhase::Failed;
                    });
                }
            }
        }
    }

    /// Log all swap records at INFO level.
    pub fn log_state(&self) {
        if self.data.swaps.is_empty() {
            log::info!("[SwapTracker] (empty — no records)");
            return;
        }
        for record in self.data.swaps.values() {
            for line in format!("{}", record).lines() {
                log::info!("[SwapTracker] {}", line);
            }
        }
    }
}

impl fmt::Display for SwapTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.data.swaps.is_empty() {
            return write!(f, "[SwapTracker] (empty)");
        }
        for (i, record) in self.data.swaps.values().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "[SwapTracker] {}", record)?;
        }
        Ok(())
    }
}

pub(crate) use crate::utill::now_secs;

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoind::tempfile::TempDir;

    fn make_test_record(swap_id: &str, phase: SwapPhase) -> SwapRecord {
        SwapRecord {
            swap_id: swap_id.to_string(),
            preimage: [0u8; 32],
            protocol: ProtocolVersion::Legacy,
            send_amount_sat: 100_000,
            maker_count: 2,
            phase,
            failed_at_phase: None,
            failure_reason: None,
            makers: vec![],
            outgoing_contract_txids: vec![],
            incoming_contract_txids: vec![],
            watchonly_contract_txids: vec![],
            recovery: RecoveryState::default(),
            multisig_nonces: vec![],
            hashlock_nonces: vec![],
            payment_address: None,
            payment_amount_sat: None,
            created_at: now_secs(),
            updated_at: now_secs(),
        }
    }

    #[test]
    fn test_load_or_create_empty() {
        let dir = TempDir::new().unwrap();
        let tracker = SwapTracker::load_or_create(dir.path()).unwrap();
        assert!(tracker.incomplete_swaps().is_empty());
    }

    #[test]
    fn legacy_proof_sent_only_for_a_legacy_swap_with_pof() {
        let dir = TempDir::new().unwrap();
        let mut tracker = SwapTracker::load_or_create(dir.path()).unwrap();
        assert!(!tracker.legacy_proof_sent_for("swap-missing"));

        let legacy_maker = |proof_of_funding_sent: bool| MakerProgress {
            address: String::new(),
            negotiated: true,
            exchange: ExchangeProgress::Legacy(LegacyExchangeProgress {
                proof_of_funding_sent,
                ..Default::default()
            }),
            finalization: FinalizationProgress::default(),
        };

        // Unsent proof: the funding is still ours alone.
        let mut record = make_test_record("swap-unsent", SwapPhase::FundsBroadcast);
        record.makers = vec![legacy_maker(false)];
        tracker.save_record(&record).unwrap();
        assert!(!tracker.legacy_proof_sent_for("swap-unsent"));

        // A sent proof: the maker holds the funding and can broadcast it
        // at any time.
        let mut record = make_test_record("swap-sent", SwapPhase::FundsBroadcast);
        record.makers = vec![legacy_maker(true)];
        tracker.save_record(&record).unwrap();
        assert!(tracker.legacy_proof_sent_for("swap-sent"));
        assert!(!tracker.legacy_proof_sent_for("swap-unsent"));

        // A sent proof stays sent once the swap completes, so the answer
        // does not change. Taproot never sends one.
        let mut record = make_test_record("swap-done", SwapPhase::Completed);
        record.makers = vec![legacy_maker(true)];
        tracker.save_record(&record).unwrap();
        assert!(tracker.legacy_proof_sent_for("swap-done"));

        let mut record = make_test_record("swap-taproot", SwapPhase::FundsBroadcast);
        record.makers = vec![MakerProgress {
            address: String::new(),
            negotiated: true,
            exchange: ExchangeProgress::Taproot(TaprootExchangeProgress::default()),
            finalization: FinalizationProgress::default(),
        }];
        tracker.save_record(&record).unwrap();
        assert!(!tracker.legacy_proof_sent_for("swap-taproot"));
    }

    #[test]
    fn test_save_and_reload() {
        let dir = TempDir::new().unwrap();

        {
            let mut tracker = SwapTracker::load_or_create(dir.path()).unwrap();
            let record = make_test_record("swap1", SwapPhase::FundsBroadcast);
            tracker.save_record(&record).unwrap();
        }

        let tracker = SwapTracker::load_or_create(dir.path()).unwrap();
        let incomplete = tracker.incomplete_swaps();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].swap_id, "swap1");
        assert_eq!(incomplete[0].phase, SwapPhase::FundsBroadcast);
    }

    #[test]
    fn test_remove_record() {
        let dir = TempDir::new().unwrap();
        let mut tracker = SwapTracker::load_or_create(dir.path()).unwrap();

        let record = make_test_record("swap1", SwapPhase::MakersDiscovered);
        tracker.save_record(&record).unwrap();
        assert_eq!(tracker.incomplete_swaps().len(), 1);

        tracker.remove_record("swap1").unwrap();
        assert!(tracker.incomplete_swaps().is_empty());
    }

    #[test]
    fn test_completed_not_in_incomplete() {
        let dir = TempDir::new().unwrap();
        let mut tracker = SwapTracker::load_or_create(dir.path()).unwrap();

        let record = make_test_record("swap1", SwapPhase::Completed);
        tracker.save_record(&record).unwrap();
        assert!(tracker.incomplete_swaps().is_empty());
    }

    #[test]
    fn test_failed_with_cleanup_not_in_incomplete() {
        let dir = TempDir::new().unwrap();
        let mut tracker = SwapTracker::load_or_create(dir.path()).unwrap();

        let mut record = make_test_record("swap1", SwapPhase::Failed);
        record.recovery.phase = RecoveryPhase::CleanedUp;
        tracker.save_record(&record).unwrap();
        assert!(tracker.incomplete_swaps().is_empty());
    }

    #[test]
    fn test_failed_without_cleanup_in_incomplete() {
        let dir = TempDir::new().unwrap();
        let mut tracker = SwapTracker::load_or_create(dir.path()).unwrap();

        let mut record = make_test_record("swap1", SwapPhase::Failed);
        record.recovery.phase = RecoveryPhase::PreimageStamped;
        tracker.save_record(&record).unwrap();
        assert_eq!(tracker.incomplete_swaps().len(), 1);
    }

    #[test]
    fn test_phase_ordering() {
        assert!(SwapPhase::MakersDiscovered < SwapPhase::FundingCreated);
        assert!(SwapPhase::FundingCreated < SwapPhase::FundsBroadcast);
        assert!(SwapPhase::FundsBroadcast < SwapPhase::ContractsExchanged);
        assert!(SwapPhase::ContractsExchanged < SwapPhase::Finalizing);
        assert!(SwapPhase::Finalizing < SwapPhase::PrivkeysForwarded);
        assert!(SwapPhase::PrivkeysForwarded < SwapPhase::Completed);
    }

    #[test]
    fn test_recovery_phase_ordering() {
        assert!(RecoveryPhase::NotStarted < RecoveryPhase::PreimageStamped);
        assert!(RecoveryPhase::PreimageStamped < RecoveryPhase::SwapcoinsPersisted);
        assert!(RecoveryPhase::SwapcoinsPersisted < RecoveryPhase::IncomingRecovered);
        assert!(RecoveryPhase::IncomingRecovered < RecoveryPhase::OutgoingRecovered);
        assert!(RecoveryPhase::OutgoingRecovered < RecoveryPhase::CleanedUp);
    }

    #[test]
    fn test_serializable_secret_key() {
        use bitcoin::secp256k1::rand::rngs::OsRng;

        let key = SecretKey::new(&mut OsRng);
        let serializable = SerializableSecretKey::from(key);

        let bytes = serde_cbor::to_vec(&serializable).unwrap();
        let deserialized: SerializableSecretKey = serde_cbor::from_slice(&bytes).unwrap();

        assert_eq!(key, deserialized.0);
    }

    #[test]
    fn test_atomic_write_creates_no_tmp_on_success() {
        let dir = TempDir::new().unwrap();
        let mut tracker = SwapTracker::load_or_create(dir.path()).unwrap();

        let record = make_test_record("swap1", SwapPhase::MakersDiscovered);
        tracker.save_record(&record).unwrap();

        let tmp_path = dir.path().join("swap_tracker.cbor.tmp");
        assert!(
            !tmp_path.exists(),
            "tmp file should be removed after rename"
        );
    }

    #[test]
    fn test_update_and_save() {
        let dir = TempDir::new().unwrap();
        let mut tracker = SwapTracker::load_or_create(dir.path()).unwrap();

        // Missing record returns Ok(false)
        let found = tracker.update_and_save("missing", |_| {}).unwrap();
        assert!(!found);

        // Insert a record and mutate it
        let record = make_test_record("swap1", SwapPhase::MakersDiscovered);
        tracker.save_record(&record).unwrap();

        let found = tracker
            .update_and_save("swap1", |r| {
                r.phase = SwapPhase::FundsBroadcast;
            })
            .unwrap();
        assert!(found);
        assert_eq!(
            tracker.get_record("swap1").unwrap().phase,
            SwapPhase::FundsBroadcast
        );

        // Reload from disk and verify persistence
        let tracker2 = SwapTracker::load_or_create(dir.path()).unwrap();
        assert_eq!(
            tracker2.get_record("swap1").unwrap().phase,
            SwapPhase::FundsBroadcast
        );
    }
}
