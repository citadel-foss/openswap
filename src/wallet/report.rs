#![allow(clippy::too_many_arguments)]
//! Swap reports for openswap participants, stored in the encrypted wallet.
//!
//! The wallet keeps four kinds, each a list of raw values:
//! - `taker`   – one entry per taker swap (success or failed)
//! - `maker`   – one entry per maker swap
//! - `recovery`– one entry per recovery event (hashlock or timelock)
//! - `deniability_proofs` – one proof per completed swap
//!
//! v0.2.3 wrote them to `{wallet_name}_swap_report.json` next to the wallet;
//! [`SwapReportFile`] still reads that file.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_cbor::{
    value::{from_value, to_value},
    Value,
};
use std::{collections::HashMap, path::Path, time::Instant};

use crate::utill::now_secs;

#[cfg(feature = "integration-test")]
use super::storage::WalletStore;
use super::{
    deniability::{proof_from_swapcoins, DeniabilityProof},
    swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
    Wallet, WalletError,
};

/// Keys of the wallet's report map. Frozen: renaming one orphans stored reports.
const TAKER_REPORTS: &str = "taker";
const MAKER_REPORTS: &str = "maker";
const RECOVERY_REPORTS: &str = "recovery";
const DENIABILITY_PROOFS: &str = "deniability_proofs";

impl Wallet {
    /// Appends `report` under `kind`. The caller saves the wallet.
    fn push_report(&mut self, kind: &str, report: &impl Serialize) -> Result<(), WalletError> {
        let value = to_value(report)?;
        self.store
            .reports
            .entry(kind.to_string())
            .or_default()
            .push(value);
        Ok(())
    }

    /// Decodes the stored reports of one kind. One this build can't read is
    /// skipped here but stays stored.
    fn decoded_reports<T: DeserializeOwned>(&self, kind: &str) -> Vec<T> {
        self.store
            .reports
            .get(kind)
            .into_iter()
            .flatten()
            .filter_map(|value| {
                from_value(value.clone())
                    .inspect_err(|e| {
                        log::warn!("Skipping a stored {kind} report this build can't read: {e}")
                    })
                    .ok()
            })
            .collect()
    }

    /// This wallet's swap reports. Maker reports are keyed by the wallet name.
    pub fn swap_reports(&self) -> SwapReportFile {
        let maker: Vec<MakerReport> = self.decoded_reports(MAKER_REPORTS);
        SwapReportFile {
            taker: self.decoded_reports(TAKER_REPORTS),
            maker: if maker.is_empty() {
                HashMap::new()
            } else {
                HashMap::from([(self.store.file_name.clone(), maker)])
            },
            recovery: self.decoded_reports(RECOVERY_REPORTS),
            deniability_proofs: self.decoded_reports(DENIABILITY_PROOFS),
        }
    }

    /// The deniability proofs in the saved file, so a test sees only what
    /// reached the disk. Reads a copy; the live store is left alone.
    #[cfg(feature = "integration-test")]
    pub fn saved_deniability_proofs(
        &self,
        password: &str,
    ) -> Result<Vec<DeniabilityProof>, WalletError> {
        let (store, _) =
            WalletStore::read_from_disk(&self.wallet_file_path, Some(password.to_string()))?;
        store
            .reports
            .get(DENIABILITY_PROOFS)
            .into_iter()
            .flatten()
            .map(|value| from_value(value.clone()).map_err(|e| WalletError::General(e.to_string())))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Shared enums
// ---------------------------------------------------------------------------

/// Role of the participant in the swap.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SwapRole {
    /// The initiator of the swap who sends coins first.
    Taker,
    /// The liquidity provider who responds to swap requests.
    Maker,
}

impl std::fmt::Display for SwapRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwapRole::Taker => write!(f, "Taker"),
            SwapRole::Maker => write!(f, "Maker"),
        }
    }
}

/// Final outcome of a swap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SwapStatus {
    /// Swap completed successfully via cooperative key exchange.
    Success,
    /// Swap recovered using the hashlock script path.
    RecoveryHashlock,
    /// Swap recovered using the timelock script path.
    RecoveryTimelock,
    /// Swap failed and could not be completed or recovered.
    Failed,
}

impl std::str::FromStr for SwapStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "success" => Ok(SwapStatus::Success),
            "recovery_hashlock" => Ok(SwapStatus::RecoveryHashlock),
            "recovery_timelock" => Ok(SwapStatus::RecoveryTimelock),
            "failed" => Ok(SwapStatus::Failed),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for SwapStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwapStatus::Success => write!(f, "\x1b[1;32m SUCCESS\x1b[0m"),
            SwapStatus::RecoveryHashlock => write!(f, "\x1b[1;33m RECOVERED (hashlock)\x1b[0m"),
            SwapStatus::RecoveryTimelock => write!(f, "\x1b[1;33m RECOVERED (timelock)\x1b[0m"),
            SwapStatus::Failed => write!(f, "\x1b[1;31m FAILED\x1b[0m"),
        }
    }
}

/// Per-maker fee breakdown stored in taker reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakerFeeInfo {
    /// Zero-based index of the maker in the swap route.
    pub maker_index: usize,
    /// Network address of the maker.
    pub maker_address: String,
    /// Fixed base fee charged by this maker (satoshis).
    pub base_fee: f64,
    /// Fee proportional to the swap amount (satoshis).
    pub amount_relative_fee: f64,
    /// Fee proportional to the timelock duration (satoshis).
    pub time_relative_fee: f64,
    /// Sum of all fee components for this maker (satoshis).
    pub total_fee: f64,
}

// ---------------------------------------------------------------------------
// Report structs
// ---------------------------------------------------------------------------

/// Outcome of a PaySwap payment. Reported confirmed only after every settlement
/// transaction has been mined with at least one confirmation — never merely
/// because private-key handover completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResult {
    /// Receiver address the payment was pinned to.
    pub receiver_address: String,
    /// Exact amount requested for the receiver (satoshis).
    pub requested_amount: u64,
    /// Amount actually delivered by settlement transactions confirmed on-chain
    /// (satoshis).
    pub delivered_amount: u64,
    /// Settlement transaction IDs paying the receiver.
    pub settlement_txids: Vec<String>,
    /// Whether every settlement transaction was mined with at least one confirmation
    /// and their outputs delivered the exact requested amount.
    pub confirmed: bool,
}

/// User-facing UTXO information recorded in a swap report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportUtxo {
    /// Address locking the reported output.
    pub address: String,
    /// Output value in satoshis.
    pub value: u64,
}

impl ReportUtxo {
    pub(crate) fn from_txout(output: &bitcoin::TxOut, network: bitcoin::Network) -> Option<Self> {
        let address = bitcoin::Address::from_script(&output.script_pubkey, network).ok()?;
        Some(Self {
            address: address.to_string(),
            value: output.value.to_sat(),
        })
    }
}

/// Taker-perspective record for one swap (success or failed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakerReport {
    /// Unique swap identifier derived from the preimage hash.
    pub swap_id: String,
    /// Final outcome of the swap.
    pub status: SwapStatus,
    /// Bitcoin network (mainnet, testnet, signet, regtest).
    pub network: String,
    /// Total duration of the swap in seconds.
    pub swap_duration_seconds: f64,
    /// Unix timestamp when the swap started.
    pub start_timestamp: u64,
    /// Unix timestamp when the swap completed.
    pub end_timestamp: u64,
    /// Error description if the swap failed.
    pub error_message: Option<String>,

    /// Amount the taker sent (satoshis).
    pub outgoing_amount: u64,
    /// Amount the taker received back after the swap (satoshis). Omitted for PaySwap.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub incoming_amount: u64,
    /// Total fee paid (outgoing − wallet outputs − settled PaySwap
    /// receiver payment, satoshis).
    pub fee_paid: u64,
    /// Mining fees paid for all transactions (satoshis).
    pub mining_fee: u64,
    /// Total fee as a percentage of the target amount.
    pub fee_percentage: f64,
    /// Total fees paid to all makers (satoshis).
    pub total_maker_fees: u64,

    /// Wallet UTXOs spent to fund the taker's outgoing contract transactions.
    pub outgoing_utxos: Vec<ReportUtxo>,
    /// Final wallet UTXOs created by sweeping the taker's incoming swapcoins.
    /// Omitted for PaySwap because its settlement outputs belong to the receiver.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incoming_utxos: Vec<ReportUtxo>,
    /// Funding transaction IDs organised by hop.
    pub funding_txids: Vec<Vec<String>>,

    /// Number of makers in the swap route.
    pub makers_count: usize,
    /// Addresses of all makers in route order.
    pub maker_addresses: Vec<String>,
    /// Detailed fee breakdown per maker.
    pub maker_fee_info: Vec<MakerFeeInfo>,

    /// Input UTXO amounts consumed by the swap (satoshis).
    pub input_utxos: Vec<u64>,
    /// Change output amounts returned to the regular wallet (satoshis).
    pub output_change_amounts: Vec<u64>,
    /// Swap output amounts received by the taker (satoshis).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_swap_amounts: Vec<u64>,
    /// Change UTXOs with amounts and addresses.
    pub output_change_utxos: Vec<(u64, String)>,
    /// Swap UTXOs received by the taker, with amounts and addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_swap_utxos: Vec<(u64, String)>,
    /// Deniability proof for this swap, if successfully generated.
    pub deniability_proof: Option<DeniabilityProof>,
    /// PaySwap outcome; present only when the swap paid a third-party receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment: Option<PaymentResult>,
}

impl TakerReport {
    /// Attach a deniability proof built from swapcoins. No-op if the swap did not succeed.
    pub fn with_proof(
        mut self,
        incoming: Option<&IncomingSwapCoin>,
        outgoing: Option<&OutgoingSwapCoin>,
    ) -> Self {
        if self.status == SwapStatus::Success {
            self.deniability_proof = proof_from_swapcoins(incoming, outgoing, SwapRole::Taker);
        }
        self
    }

    /// Stores this report, and its proof if any, in `wallet` and saves it.
    pub fn save_to_wallet(&self, wallet: &mut Wallet) -> Result<(), WalletError> {
        if let Some(proof) = &self.deniability_proof {
            wallet.push_report(DENIABILITY_PROOFS, proof)?;
        }
        wallet.push_report(TAKER_REPORTS, self)?;
        wallet.save_to_disk()
    }

    /// Print a human-readable summary to stdout.
    pub fn print(&self) {
        println!("\n\x1b[1;36m================================================================================");
        println!("                           TAKER SWAP REPORT");
        println!("================================================================================\x1b[0m\n");

        println!("\x1b[1;37mSwap ID           :\x1b[0m {}", self.swap_id);
        println!("\x1b[1;37mStatus            :\x1b[0m {}", self.status);
        if self.swap_duration_seconds > 0.0 {
            println!(
                "\x1b[1;37mDuration          :\x1b[0m {:.2} seconds",
                self.swap_duration_seconds
            );
        }

        println!("\n\x1b[1;36m--------------------------------------------------------------------------------");
        println!("                              Swap Details");
        println!("--------------------------------------------------------------------------------\x1b[0m");

        if let Some(ref payment) = self.payment {
            println!("\x1b[1;37mSwap Type         :\x1b[0m PaySwap");
            println!(
                "\x1b[1;37mRoute Amount      :\x1b[0m {} sats",
                self.outgoing_amount
            );
            println!(
                "\x1b[1;37mPayment To        :\x1b[0m {}",
                payment.receiver_address
            );
            println!(
                "\x1b[1;37mPayment Requested :\x1b[0m {} sats",
                payment.requested_amount
            );
            println!(
                "\x1b[1;37mPayment Delivered :\x1b[0m {} sats",
                payment.delivered_amount
            );
            println!(
                "\x1b[1;37mPayment Status    :\x1b[0m {}",
                if payment.confirmed {
                    "confirmed"
                } else {
                    "pending"
                }
            );
            println!(
                "\x1b[1;37mTotal Cost        :\x1b[0m {} sats",
                payment.delivered_amount.saturating_add(self.fee_paid)
            );
        } else {
            println!(
                "\x1b[1;37mTarget Amount     :\x1b[0m {} sats",
                self.outgoing_amount
            );
            println!(
                "\x1b[1;37mTotal Output      :\x1b[0m {} sats",
                self.incoming_amount
            );
        }
        println!(
            "\x1b[1;37mTotal Fee Paid    :\x1b[0m \x1b[1;31m{} sats\x1b[0m",
            self.fee_paid
        );
        println!(
            "\x1b[1;37mFee Percentage    :\x1b[0m {:.4}%",
            self.fee_percentage
        );
        if self.mining_fee > 0 {
            println!(
                "\x1b[1;37mMining Fee        :\x1b[0m {} sats",
                self.mining_fee
            );
        }
        println!("\x1b[1;37mNetwork           :\x1b[0m {}", self.network);
        if let Some(ref payment) = self.payment {
            for txid in &payment.settlement_txids {
                println!("  Settlement Tx   : {}", txid);
            }
        }
        println!("\x1b[1;37mMakers Used       :\x1b[0m {}", self.makers_count);
        for (i, addr) in self.maker_addresses.iter().enumerate() {
            println!("  Maker {}         : {}", i + 1, addr);
        }

        println!("\n\x1b[1;36m--------------------------------------------------------------------------------");
        println!("                              Swap UTXOs");
        println!("--------------------------------------------------------------------------------\x1b[0m");

        print_report_utxos("Outgoing UTXO", &self.outgoing_utxos);
        print_report_utxos("Incoming UTXO", &self.incoming_utxos);
        if !self.funding_txids.is_empty() {
            println!("\x1b[1;37mFunding Txs       :\x1b[0m");
            for (hop_idx, hop_txids) in self.funding_txids.iter().enumerate() {
                println!("  Hop {}:", hop_idx + 1);
                for (i, txid) in hop_txids.iter().enumerate() {
                    println!("    {}. {}", i + 1, txid);
                }
            }
        }

        if !self.maker_fee_info.is_empty() {
            println!("\n\x1b[1;36m--------------------------------------------------------------------------------");
            println!("                           Maker Fee Breakdown");
            println!("--------------------------------------------------------------------------------\x1b[0m");
            for info in &self.maker_fee_info {
                println!(
                    "\n\x1b[1;33mMaker {}:\x1b[0m {}",
                    info.maker_index + 1,
                    info.maker_address
                );
                println!("    Base Fee             : {} sats", info.base_fee);
                println!(
                    "    Amount Relative Fee  : {} sats",
                    info.amount_relative_fee
                );
                println!("    Time Relative Fee    : {} sats", info.time_relative_fee);
                println!("    Total Fee            : {} sats", info.total_fee);
            }
        }

        if !self.input_utxos.is_empty() || !self.output_swap_utxos.is_empty() {
            println!("\n\x1b[1;36m--------------------------------------------------------------------------------");
            println!("                              UTXO Information");
            println!("--------------------------------------------------------------------------------\x1b[0m");
            if !self.input_utxos.is_empty() {
                println!(
                    "\x1b[1;37mInput UTXOs       :\x1b[0m {:?}",
                    self.input_utxos
                );
            }
            if !self.output_change_utxos.is_empty() {
                println!(
                    "\x1b[1;37mChange UTXOs      :\x1b[0m {:?}",
                    self.output_change_utxos
                );
            }
            if !self.output_swap_utxos.is_empty() {
                println!(
                    "\x1b[1;37mSwap UTXOs        :\x1b[0m {:?}",
                    self.output_swap_utxos
                );
            }
        }

        if let Some(ref error) = self.error_message {
            println!("\n\x1b[1;31mError: {}\x1b[0m", error);
        }

        println!("\n\x1b[1;36m================================================================================");
        println!("                                END REPORT");
        println!("================================================================================\x1b[0m\n");
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn print_report_utxos(label: &str, utxos: &[ReportUtxo]) {
    for (index, utxo) in utxos.iter().enumerate() {
        println!(
            "  {:<19} {}. {} ({} sats)",
            label,
            index + 1,
            utxo.address,
            utxo.value
        );
    }
}

/// Maker-perspective record for one swap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakerReport {
    /// Unique swap identifier derived from the preimage hash.
    pub swap_id: String,
    /// Final outcome of the swap.
    pub status: SwapStatus,
    /// Bitcoin network (mainnet, testnet, signet, regtest).
    pub network: String,
    /// Total duration of the swap in seconds.
    pub swap_duration_seconds: f64,
    /// Unix timestamp when the swap started.
    pub start_timestamp: u64,
    /// Unix timestamp when the swap completed.
    pub end_timestamp: u64,

    /// Amount received in the incoming contract (satoshis).
    pub incoming_amount: u64,
    /// Amount sent in the outgoing contract (satoshis).
    pub outgoing_amount: u64,
    /// Maker service fee earned, excluding maker-side mining-fee reimbursement.
    pub fee_earned: u64,

    /// Final UTXOs created by sweeping the maker's incoming swapcoins.
    pub incoming_utxos: Vec<ReportUtxo>,
    /// Wallet UTXOs spent to fund the maker's outgoing contract transactions.
    pub outgoing_utxos: Vec<ReportUtxo>,
    /// Timelock value in blocks for the outgoing contract.
    pub timelock: u32,
    /// Deniability proof for this swap, if successfully generated.
    pub deniability_proof: Option<DeniabilityProof>,
}

impl MakerReport {
    /// Build a success report from raw swap state values.
    pub fn success(
        swap_id: String,
        start_time: Instant,
        incoming_amount: u64,
        outgoing_amount: u64,
        fee_earned: u64,
        incoming_utxos: Vec<ReportUtxo>,
        outgoing_utxos: Vec<ReportUtxo>,
        timelock: u32,
        network: String,
        incoming: Option<&IncomingSwapCoin>,
        outgoing: Option<&OutgoingSwapCoin>,
    ) -> Self {
        let swap_duration_seconds = start_time.elapsed().as_secs_f64();
        let end = now_secs();
        Self {
            swap_id,
            status: SwapStatus::Success,
            network,
            swap_duration_seconds,
            start_timestamp: end.saturating_sub(swap_duration_seconds as u64),
            end_timestamp: end,
            incoming_amount,
            outgoing_amount,
            fee_earned,
            incoming_utxos,
            outgoing_utxos,
            timelock,
            deniability_proof: proof_from_swapcoins(incoming, outgoing, SwapRole::Maker),
        }
    }

    /// Stores this report, and its proof if any, in `wallet` and saves it.
    pub fn save_to_wallet(&self, wallet: &mut Wallet) -> Result<(), WalletError> {
        if let Some(proof) = &self.deniability_proof {
            wallet.push_report(DENIABILITY_PROOFS, proof)?;
        }
        wallet.push_report(MAKER_REPORTS, self)?;
        wallet.save_to_disk()
    }

    /// Print a human-readable summary to stdout.
    pub fn print(&self) {
        println!("\n\x1b[1;36m================================================================================");
        println!("                           MAKER SWAP REPORT");
        println!("================================================================================\x1b[0m\n");

        println!("\x1b[1;37mSwap ID           :\x1b[0m {}", self.swap_id);
        println!("\x1b[1;37mStatus            :\x1b[0m {}", self.status);
        if self.swap_duration_seconds > 0.0 {
            println!(
                "\x1b[1;37mDuration          :\x1b[0m {:.2} seconds",
                self.swap_duration_seconds
            );
        }

        println!("\n\x1b[1;36m--------------------------------------------------------------------------------");
        println!("                              Swap Details");
        println!("--------------------------------------------------------------------------------\x1b[0m");

        println!(
            "\x1b[1;37mIncoming Amount   :\x1b[0m {} sats",
            self.incoming_amount
        );
        println!(
            "\x1b[1;37mOutgoing Amount   :\x1b[0m {} sats",
            self.outgoing_amount
        );
        println!(
            "\x1b[1;37mFee Earned        :\x1b[0m \x1b[1;32m{} sats\x1b[0m",
            self.fee_earned
        );
        println!(
            "\x1b[1;37mTimelock          :\x1b[0m {} blocks",
            self.timelock
        );
        println!("\x1b[1;37mNetwork           :\x1b[0m {}", self.network);

        println!("\n\x1b[1;36m--------------------------------------------------------------------------------");
        println!("                              Swap UTXOs");
        println!("--------------------------------------------------------------------------------\x1b[0m");

        print_report_utxos("Incoming UTXO", &self.incoming_utxos);
        print_report_utxos("Outgoing UTXO", &self.outgoing_utxos);

        println!("\n\x1b[1;36m================================================================================");
        println!("                                END REPORT");
        println!("================================================================================\x1b[0m\n");
    }
}

/// Recovery event record (written by whichever party performs the recovery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    /// Unique swap identifier derived from the preimage hash.
    pub swap_id: String,
    /// Role of the party that performed the recovery.
    pub role: SwapRole,
    /// Maker node name when role is Maker; None for Taker.
    pub node: Option<String>,
    /// Recovery path used: `"hashlock"` or `"timelock"`.
    pub recovery_type: String,
    /// Transaction IDs of the recovery transactions.
    pub recovery_txids: Vec<String>,
    /// Bitcoin network (mainnet, testnet, signet, regtest).
    pub network: String,
    /// Unix timestamp of the recovery event.
    pub timestamp: u64,
}

impl RecoveryReport {
    /// Emit a taker recovery report — prints to console and saves it in `wallet`.
    pub fn emit_taker(
        wallet: &mut Wallet,
        swap_id: String,
        recovery_type: String,
        recovery_txids: Vec<String>,
    ) {
        Self {
            swap_id,
            role: SwapRole::Taker,
            node: None,
            recovery_type,
            recovery_txids,
            network: wallet.store.network.to_string(),
            timestamp: now_secs(),
        }
        .emit(wallet);
    }

    /// Emit a maker recovery report — prints to console and saves it in `wallet`.
    /// The node is named after the maker's data directory.
    pub fn emit_maker(
        wallet: &mut Wallet,
        data_dir: &Path,
        swap_id: String,
        recovery_type: String,
        recovery_txids: Vec<String>,
    ) {
        Self {
            swap_id,
            role: SwapRole::Maker,
            node: data_dir
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string()),
            recovery_type,
            recovery_txids,
            network: wallet.store.network.to_string(),
            timestamp: now_secs(),
        }
        .emit(wallet);
    }

    pub(crate) fn store_in_wallet(&self, wallet: &mut Wallet) -> Result<(), WalletError> {
        self.print();
        wallet.push_report(RECOVERY_REPORTS, self)
    }

    fn emit(&self, wallet: &mut Wallet) {
        if let Err(e) = self
            .store_in_wallet(wallet)
            .and_then(|()| wallet.save_to_disk())
        {
            log::warn!("Failed to save {} recovery report: {:?}", self.role, e);
        }
    }

    fn print(&self) {
        println!("\n\x1b[1;33m================================================================================");
        println!("                           RECOVERY REPORT");
        println!("================================================================================\x1b[0m\n");
        println!("\x1b[1;37mSwap ID       :\x1b[0m {}", self.swap_id);
        println!("\x1b[1;37mRole          :\x1b[0m {}", self.role);
        if let Some(ref node) = self.node {
            println!("\x1b[1;37mNode          :\x1b[0m {}", node);
        }
        println!("\x1b[1;37mRecovery Type :\x1b[0m {}", self.recovery_type);
        println!("\x1b[1;37mNetwork       :\x1b[0m {}", self.network);
        println!("\x1b[1;37mRecovery Txs  :\x1b[0m {:?}", self.recovery_txids);
        println!("\n\x1b[1;33m================================================================================");
        println!("                              END REPORT");
        println!("================================================================================\x1b[0m\n");
    }
}

// ---------------------------------------------------------------------------
// Top-level file structure
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// All of a wallet's reports. Also the shape of the v0.2.3 report JSON file.
pub struct SwapReportFile {
    /// Taker-perspective swap reports.
    pub taker: Vec<TakerReport>,
    /// Maker-perspective swap reports keyed by maker node name.
    pub maker: HashMap<String, Vec<MakerReport>>,
    /// Recovery reports emitted after hashlock or timelock recovery.
    pub recovery: Vec<RecoveryReport>,
    /// Deniability proofs generated for swaps in this wallet.
    pub deniability_proofs: Vec<DeniabilityProof>,
}

impl SwapReportFile {
    /// The entries as the wallet stores them: raw values under each kind.
    pub(crate) fn into_values(self) -> Result<[(&'static str, Vec<Value>); 4], WalletError> {
        fn values<T: Serialize>(
            items: impl IntoIterator<Item = T>,
        ) -> Result<Vec<Value>, WalletError> {
            items.into_iter().map(|item| Ok(to_value(item)?)).collect()
        }
        Ok([
            (TAKER_REPORTS, values(self.taker)?),
            (MAKER_REPORTS, values(self.maker.into_values().flatten())?),
            (RECOVERY_REPORTS, values(self.recovery)?),
            (DENIABILITY_PROOFS, values(self.deniability_proofs)?),
        ])
    }
}

#[cfg(test)]
pub(crate) fn compat_reports() -> SwapReportFile {
    let proof: SwapReportFile = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/compat/v0.2.3/closed_swap_report.json"
    ))
    .unwrap();
    let proof = proof.deniability_proofs[0].clone();
    let utxo = ReportUtxo {
        address: "bcrt1-fixture".into(),
        value: 123_456,
    };
    let taker = TakerReport {
        swap_id: "fixture-swap".into(),
        status: SwapStatus::Success,
        network: "regtest".into(),
        swap_duration_seconds: 2.5,
        start_timestamp: 100,
        end_timestamp: 103,
        error_message: Some("fixture error".into()),
        outgoing_amount: 123_456,
        incoming_amount: 120_000,
        fee_paid: 3_456,
        mining_fee: 123,
        fee_percentage: 2.5,
        total_maker_fees: 3_333,
        outgoing_utxos: vec![utxo.clone()],
        incoming_utxos: vec![utxo.clone()],
        funding_txids: vec![vec!["funding-tx".into()]],
        makers_count: 1,
        maker_addresses: vec!["maker-fixture".into()],
        maker_fee_info: vec![MakerFeeInfo {
            maker_index: 1,
            maker_address: "maker-fixture".into(),
            base_fee: 1.5,
            amount_relative_fee: 2.5,
            time_relative_fee: 3.5,
            total_fee: 7.5,
        }],
        input_utxos: vec![123_456],
        output_change_amounts: vec![20_000],
        output_swap_amounts: vec![100_000],
        output_change_utxos: vec![(20_000, "change-address".into())],
        output_swap_utxos: vec![(100_000, "swap-address".into())],
        deniability_proof: Some(proof.clone()),
        payment: Some(PaymentResult {
            receiver_address: "receiver-address".into(),
            requested_amount: 120_000,
            delivered_amount: 120_000,
            settlement_txids: vec!["settlement-tx".into()],
            confirmed: true,
        }),
    };
    let maker = MakerReport {
        swap_id: "fixture-swap".into(),
        status: SwapStatus::Success,
        network: "regtest".into(),
        swap_duration_seconds: 2.5,
        start_timestamp: 100,
        end_timestamp: 103,
        incoming_amount: 123_456,
        outgoing_amount: 120_000,
        fee_earned: 3_456,
        incoming_utxos: vec![utxo.clone()],
        outgoing_utxos: vec![utxo],
        timelock: 20,
        deniability_proof: Some(proof.clone()),
    };
    let statuses = [
        SwapStatus::Success,
        SwapStatus::RecoveryHashlock,
        SwapStatus::RecoveryTimelock,
        SwapStatus::Failed,
    ];
    SwapReportFile {
        taker: statuses
            .iter()
            .map(|status| {
                let mut report = taker.clone();
                report.status = status.clone();
                report
            })
            .collect(),
        maker: HashMap::from([(
            "fixture-maker".into(),
            statuses
                .iter()
                .map(|status| {
                    let mut report = maker.clone();
                    report.status = status.clone();
                    report
                })
                .collect(),
        )]),
        recovery: [SwapRole::Maker, SwapRole::Taker]
            .iter()
            .map(|role| RecoveryReport {
                swap_id: "fixture-swap".into(),
                role: *role,
                node: Some("fixture-node".into()),
                recovery_type: "timelock".into(),
                recovery_txids: vec!["recovery-tx".into()],
                network: "regtest".into(),
                timestamp: 123,
            })
            .collect(),
        deniability_proofs: vec![proof],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::ProtocolVersion,
        wallet::{
            api::test_support::test_wallet,
            deniability::{DeniabilityProofData, LegacyDeniabilityProof},
            storage::WalletStore,
        },
    };
    use bitcoin::{
        ecdsa::Signature,
        hashes::Hash,
        secp256k1::{Message, Secp256k1, SecretKey},
        OutPoint, PublicKey, ScriptBuf, Txid,
    };
    use bitcoind::tempfile::tempdir;
    use serde_cbor::Value;
    use std::collections::BTreeMap;

    fn sample_taker_report() -> TakerReport {
        TakerReport {
            swap_id: "swap-1".to_string(),
            status: SwapStatus::Success,
            network: "regtest".to_string(),
            swap_duration_seconds: 1.0,
            start_timestamp: 10,
            end_timestamp: 11,
            error_message: None,
            outgoing_amount: 10_000,
            incoming_amount: 9_000,
            fee_paid: 1_000,
            mining_fee: 100,
            fee_percentage: 10.0,
            total_maker_fees: 900,
            outgoing_utxos: vec![],
            incoming_utxos: vec![],
            funding_txids: vec![],
            makers_count: 0,
            maker_addresses: vec![],
            maker_fee_info: vec![],
            input_utxos: vec![],
            output_change_amounts: vec![],
            output_swap_amounts: vec![],
            output_change_utxos: vec![],
            output_swap_utxos: vec![],
            deniability_proof: None,
            payment: None,
        }
    }

    #[test]
    fn compat_future_reports_and_nested_fields_survive_typed_views_and_saves() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.cbor");
        let mut wallet = test_wallet(&path);
        let mut report = sample_taker_report();
        report.outgoing_utxos.push(ReportUtxo {
            address: "bcrt1-known".into(),
            value: 10_000,
        });
        let mut known = to_value(&report).unwrap();
        let Value::Map(fields) = &mut known else {
            panic!()
        };
        let Value::Array(utxos) = fields
            .get_mut(&Value::Text("outgoing_utxos".into()))
            .unwrap()
        else {
            panic!()
        };
        let Value::Map(utxo) = &mut utxos[0] else {
            panic!()
        };
        utxo.insert(
            Value::Text("future_nested".into()),
            Value::Bytes(vec![1, 2, 3]),
        );
        let mut future = known.clone();
        let Value::Map(fields) = &mut future else {
            panic!()
        };
        fields.insert(
            Value::Text("status".into()),
            Value::Map(BTreeMap::from([(
                Value::Text("FutureStatus".into()),
                Value::Integer(7),
            )])),
        );
        let future_proof = Value::Map(BTreeMap::from([(
            Value::Text("FutureProof".into()),
            Value::Array(vec![Value::Bool(true)]),
        )]));
        wallet
            .store
            .reports
            .insert(TAKER_REPORTS.into(), vec![known.clone(), future.clone()]);
        for kind in [
            MAKER_REPORTS,
            RECOVERY_REPORTS,
            DENIABILITY_PROOFS,
            "future_kind",
        ] {
            wallet
                .store
                .reports
                .insert(kind.into(), vec![future_proof.clone()]);
        }
        let expected = wallet.store.reports.clone();
        wallet.save_to_disk().unwrap();
        for _ in 0..2 {
            wallet.store = WalletStore::read_from_disk(&path, Some("test-password".into()))
                .unwrap()
                .0;
            let view = wallet.swap_reports();
            assert_eq!(view.taker.len(), 1);
            assert_eq!(
                to_value(&view.taker[0]).unwrap(),
                to_value(&report).unwrap()
            );
            assert!(view.maker.is_empty());
            assert!(view.recovery.is_empty());
            assert!(view.deniability_proofs.is_empty());
            assert_eq!(wallet.store.reports, expected);
            wallet.save_to_disk().unwrap();
        }
        sample_taker_report().save_to_wallet(&mut wallet).unwrap();
        let store = WalletStore::read_from_disk(&path, Some("test-password".into()))
            .unwrap()
            .0;
        assert_eq!(&store.reports[TAKER_REPORTS][..2], &[known, future]);
        for (kind, values) in expected
            .iter()
            .filter(|(kind, _)| kind.as_str() != TAKER_REPORTS)
        {
            assert_eq!(&store.reports[kind], values);
        }
    }

    #[test]
    fn compat_report_writers_save_proofs_and_changes_in_the_wallet() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.cbor");
        let mut wallet = test_wallet(&path);
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[5; 32]).unwrap();
        let pubkey = PublicKey::new(secret.public_key(&secp));
        let signature = Signature::sighash_all(
            secp.sign_ecdsa(&Message::from_digest_slice(&[6; 32]).unwrap(), &secret),
        );
        let proof = DeniabilityProof {
            swap_id: "swap-1".into(),
            role: SwapRole::Taker,
            protocol: ProtocolVersion::Legacy,
            outgoing_swapcoin: None,
            created_at: 10,
            proof: DeniabilityProofData::Legacy(LegacyDeniabilityProof {
                funding_outpoint: OutPoint::new(Txid::all_zeros(), 1),
                htlc_redeemscript: ScriptBuf::from_bytes(vec![0x51]),
                multisig_redeemscript: ScriptBuf::from_bytes(vec![0x52]),
                pub_mine_multi: pubkey,
                pub_other_multi: pubkey,
                pub_mine_hashlock: pubkey,
                sig_multi: signature,
                sig_hashlock: signature,
            }),
        };
        let mut taker = sample_taker_report();
        taker.deniability_proof = Some(proof.clone());
        wallet.store.internal_index = 17;
        taker.save_to_wallet(&mut wallet).unwrap();
        let mut maker = MakerReport::success(
            "maker-swap".into(),
            Instant::now(),
            10_000,
            9_000,
            500,
            vec![],
            vec![],
            60,
            "regtest".into(),
            None,
            None,
        );
        let mut maker_proof = proof.clone();
        maker_proof.role = SwapRole::Maker;
        maker.deniability_proof = Some(maker_proof.clone());
        maker.save_to_wallet(&mut wallet).unwrap();
        RecoveryReport::emit_taker(
            &mut wallet,
            "recovery-taker".into(),
            "timelock".into(),
            vec!["tx-taker".into()],
        );
        RecoveryReport::emit_maker(
            &mut wallet,
            dir.path(),
            "recovery-maker".into(),
            "hashlock".into(),
            vec!["tx-maker".into()],
        );
        wallet.store = WalletStore::read_from_disk(&path, Some("test-password".into()))
            .unwrap()
            .0;
        let view = wallet.swap_reports();
        assert_eq!(wallet.store.internal_index, 17);
        assert_eq!(to_value(&view.taker[0]).unwrap(), to_value(&taker).unwrap());
        assert_eq!(
            to_value(&view.maker[wallet.get_name()][0]).unwrap(),
            to_value(&maker).unwrap()
        );
        assert_eq!(view.deniability_proofs, [proof, maker_proof]);
        assert_eq!(view.recovery.len(), 2);
        assert_eq!(view.recovery[0].swap_id, "recovery-taker");
        assert_eq!(view.recovery[1].swap_id, "recovery-maker");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn report_schema_uses_swap_boundary_utxos_without_contract_fields() {
        let mut report = sample_taker_report();
        report.outgoing_utxos.push(ReportUtxo {
            address: "bcrt1qoutgoing".to_string(),
            value: 10_000,
        });
        report.incoming_utxos.push(ReportUtxo {
            address: "bcrt1qincoming".to_string(),
            value: 9_500,
        });

        let serialized = serde_json::to_value(&report).unwrap();
        assert!(serialized.get("outgoing_contract_txid").is_none());
        assert!(serialized.get("incoming_contract_txid").is_none());
        assert!(serialized.get("outgoing_contract_utxos").is_none());
        assert!(serialized.get("incoming_contract_utxos").is_none());
        assert_eq!(serialized["outgoing_utxos"][0]["address"], "bcrt1qoutgoing");
        assert_eq!(serialized["incoming_utxos"][0]["value"], 9_500);
    }

    #[test]
    fn payswap_omits_taker_incoming_fields_and_round_trips() {
        let mut report = sample_taker_report();
        report.incoming_amount = 0;
        report.payment = Some(PaymentResult {
            receiver_address: "bcrt1qreceiver".to_string(),
            requested_amount: 9_000,
            delivered_amount: 9_000,
            settlement_txids: vec!["settlement-txid".to_string()],
            confirmed: true,
        });

        let serialized = serde_json::to_value(&report).unwrap();
        assert!(serialized.get("incoming_amount").is_none());
        assert!(serialized.get("incoming_utxos").is_none());
        assert!(serialized.get("output_swap_amounts").is_none());
        assert!(serialized.get("output_swap_utxos").is_none());
        assert!(serialized.get("outgoing_utxos").is_some());
        assert!(serialized.get("payment").is_some());

        let decoded: TakerReport = serde_json::from_value(serialized).unwrap();
        assert_eq!(decoded.incoming_amount, 0);
        assert!(decoded.incoming_utxos.is_empty());
        assert!(decoded.output_swap_amounts.is_empty());
        assert!(decoded.output_swap_utxos.is_empty());
    }

    #[test]
    fn reports_live_in_the_wallet_and_unreadable_ones_survive_a_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.cbor");
        let mut wallet = test_wallet(&path);
        sample_taker_report().save_to_wallet(&mut wallet).unwrap();

        // A newer build's report: a status and a nested field we don't know.
        let Value::Map(mut fields) = to_value(sample_taker_report()).unwrap() else {
            panic!("a report encodes as a map");
        };
        fields.insert(Value::Text("status".into()), Value::Text("Future".into()));
        fields.insert(
            Value::Text("future_detail".into()),
            Value::Array(vec![Value::Integer(1)]),
        );
        let future = Value::Map(fields);
        wallet
            .store
            .reports
            .entry(TAKER_REPORTS.to_string())
            .or_default()
            .push(future.clone());
        wallet.save_to_disk().unwrap();

        let (store, _) =
            WalletStore::read_from_disk(&path, Some("test-password".to_string())).unwrap();
        assert_eq!(store.reports[TAKER_REPORTS].get(1), Some(&future));
        wallet.store = store;
        let reports = wallet.swap_reports();
        assert_eq!(reports.taker.len(), 1);
        assert_eq!(reports.taker[0].swap_id, "swap-1");
    }
}
