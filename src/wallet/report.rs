#![allow(clippy::too_many_arguments)]
//! Per-wallet swap report files for openswap participants.
//!
//! Reports are appended to the swap report file next to the wallet that
//! participated in the swap:
//! `{data_dir}/wallets/{wallet_name}_swap_report.json`.
//!
//! The file has four sections:
//! - `taker`   – one entry per taker swap (success or failed)
//! - `maker`   – one array per maker node, keyed by node name
//! - `recovery`– one entry per recovery event (hashlock or timelock)
//! - `deniability_proofs` – one proof per completed swap

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    path::{Path, PathBuf},
    time::Instant,
};

use crate::utill::now_unix_secs;

use super::{
    deniability::{proof_from_swapcoins, DeniabilityProof},
    swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
};

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

    /// Save to the given wallet's report file, or the discovered/default taker wallet if none is given.
    pub fn save_for_wallet(
        &self,
        data_dir: &Path,
        wallet_file_name: Option<&str>,
    ) -> std::io::Result<()> {
        let report = self.clone();
        let file_path = report_file_path_for_wallet(data_dir, SwapRole::Taker, wallet_file_name);
        write_to_path(&file_path, |f| {
            if let Some(p) = report.deniability_proof.clone() {
                f.deniability_proofs.push(p);
            }
            f.taker.push(report);
        })
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
        let end = now_unix_secs();
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

    /// Save to the given wallet's report file, or the discovered/default maker wallet if none is given.
    pub fn save_for_wallet(
        &self,
        data_dir: &Path,
        wallet_file_name: Option<&str>,
    ) -> std::io::Result<()> {
        let node_name = data_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        let report = self.clone();
        let file_path = report_file_path_for_wallet(data_dir, SwapRole::Maker, wallet_file_name);
        write_to_path(&file_path, |f| {
            if let Some(p) = report.deniability_proof.clone() {
                f.deniability_proofs.push(p);
            }
            f.maker.entry(node_name).or_default().push(report);
        })
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
    /// Emit a taker recovery report — prints to console and saves to file.
    pub fn emit_taker(
        data_dir: &Path,
        swap_id: String,
        network: String,
        recovery_type: String,
        recovery_txids: Vec<String>,
    ) {
        let report = Self {
            swap_id,
            role: SwapRole::Taker,
            node: None,
            recovery_type,
            recovery_txids,
            network,
            timestamp: now_unix_secs(),
        };
        report.print();
        if let Err(e) = report.save_for_wallet(data_dir, None) {
            log::warn!("Failed to save taker recovery report: {:?}", e);
        }
        log::info!(
            "For full details, see: {}",
            report_file_path(data_dir, SwapRole::Taker).display()
        );
    }

    /// Emit a maker recovery report — prints to console and saves to file.
    pub fn emit_maker(
        data_dir: &Path,
        swap_id: String,
        network: String,
        recovery_type: String,
        recovery_txids: Vec<String>,
    ) {
        let node = data_dir
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());
        let report = Self {
            swap_id,
            role: SwapRole::Maker,
            node,
            recovery_type,
            recovery_txids,
            network,
            timestamp: now_unix_secs(),
        };
        report.print();
        if let Err(e) = report.save_for_wallet(data_dir, None) {
            log::warn!("Failed to save maker recovery report: {:?}", e);
        }
    }

    fn save_for_wallet(
        &self,
        data_dir: &Path,
        wallet_file_name: Option<&str>,
    ) -> std::io::Result<()> {
        let report = self.clone();
        let file_path = report_file_path_for_wallet(data_dir, self.role, wallet_file_name);
        write_to_path(&file_path, |f| f.recovery.push(report))
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
/// Top-level JSON structure stored in per-wallet swap report files.
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

// ---------------------------------------------------------------------------
// File I/O helpers
// ---------------------------------------------------------------------------

const REPORT_SUFFIX: &str = "_swap_report.json";

/// Return the wallet name component used in report filenames, or the role default.
fn wallet_name_for_report(
    data_dir: &Path,
    role: SwapRole,
    wallet_file_name: Option<&str>,
) -> String {
    let wallet_file_name = wallet_file_name
        .map(str::to_string)
        .unwrap_or_else(|| match role {
            SwapRole::Taker => "taker-wallet".to_string(),
            SwapRole::Maker => data_dir
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|name| !name.is_empty())
                .unwrap_or("maker-wallet")
                .to_string(),
        });
    let path = Path::new(&wallet_file_name);
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or(&wallet_file_name)
        .to_string()
}

/// Build the swap report filename for a wallet file.
fn wallet_report_file_name(
    data_dir: &Path,
    role: SwapRole,
    wallet_file_name: Option<&str>,
) -> String {
    format!(
        "{}{}",
        wallet_name_for_report(data_dir, role, wallet_file_name),
        REPORT_SUFFIX
    )
}

/// Discover the only wallet file in the wallets directory, falling back to the default name.
fn discover_wallet_name(data_dir: &Path, role: SwapRole) -> String {
    let wallets_dir = data_dir.join("wallets");
    let Ok(entries) = std::fs::read_dir(&wallets_dir) else {
        return wallet_name_for_report(data_dir, role, None);
    };

    let wallet_names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            if !file_type.is_file() {
                return None;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(REPORT_SUFFIX)
                || name.ends_with(".lock")
                || name.ends_with(".partial")
                || name.ends_with(".tmp")
            {
                None
            } else {
                Some(name)
            }
        })
        .collect();

    if wallet_names.len() == 1 {
        wallet_name_for_report(data_dir, role, Some(&wallet_names[0]))
    } else {
        wallet_name_for_report(data_dir, role, None)
    }
}

fn report_file_path(data_dir: &Path, role: SwapRole) -> PathBuf {
    let wallet_name = discover_wallet_name(data_dir, role);
    wallet_report_path(data_dir, role, Some(&wallet_name))
}

/// Build the report path for an explicit wallet, or discover/default one for the role.
fn report_file_path_for_wallet(
    data_dir: &Path,
    role: SwapRole,
    wallet_file_name: Option<&str>,
) -> PathBuf {
    match wallet_file_name {
        Some(wallet_file_name) => wallet_report_path(data_dir, role, Some(wallet_file_name)),
        None => report_file_path(data_dir, role),
    }
}

fn wallet_report_path(data_dir: &Path, role: SwapRole, wallet_file_name: Option<&str>) -> PathBuf {
    // TODO: Store swap reports inside the wallet data instead of writing a
    // separate `{wallet_name}_swap_report.json` file next to the wallet.
    data_dir
        .join("wallets")
        .join(wallet_report_file_name(data_dir, role, wallet_file_name))
}

struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn acquire_lock(lock_path: &Path) -> std::io::Result<LockGuard> {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let mut deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(lock_path)
        {
            Ok(_) => {
                return Ok(LockGuard {
                    path: lock_path.to_owned(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if std::time::Instant::now() > deadline {
                    let is_stale = std::fs::metadata(lock_path)
                        .and_then(|m| m.modified())
                        .map(|mtime| mtime.elapsed().unwrap_or_default() > TIMEOUT)
                        .unwrap_or(true);

                    if is_stale {
                        std::fs::remove_file(lock_path)?;
                    } else {
                        // Owner is still active — extend and keep waiting.
                        deadline = std::time::Instant::now() + TIMEOUT;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
}

fn write_to_path<F>(file_path: &Path, mutate: F) -> std::io::Result<()>
where
    F: FnOnce(&mut SwapReportFile),
{
    let report_dir = file_path
        .parent()
        .ok_or_else(|| std::io::Error::other("swap report path has no parent directory"))?;
    std::fs::create_dir_all(report_dir)?;

    let lock_path = file_path.with_extension("json.lock");

    let _lock = acquire_lock(&lock_path)?;

    let mut report_file: SwapReportFile = if file_path.exists() {
        let content = std::fs::read_to_string(file_path)?;
        serde_json::from_str(&content).map_err(std::io::Error::other)?
    } else {
        SwapReportFile::default()
    };

    mutate(&mut report_file);

    let json = serde_json::to_string_pretty(&report_file).map_err(std::io::Error::other)?;
    let tmp_path = file_path.with_extension("partial");
    {
        use std::io::Write;
        let mut tmp = std::fs::File::create(&tmp_path)?;
        tmp.write_all(json.as_bytes())?;
        tmp.sync_all()?;
    }
    std::fs::rename(&tmp_path, file_path)?;

    log::info!("Saved swap report to: {}", file_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_data_dir(test_name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "openswap_report_{test_name}_{}_{}",
            std::process::id(),
            nonce
        ));
        std::fs::create_dir_all(dir.join("wallets")).unwrap();
        dir
    }

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
    fn taker_report_is_written_next_to_named_wallet() {
        let data_dir = test_data_dir("taker_named_wallet");
        let report = sample_taker_report();

        report
            .save_for_wallet(&data_dir, Some("alice.wallet"))
            .unwrap();

        let expected_path = data_dir.join("wallets").join("alice_swap_report.json");
        assert!(expected_path.exists());
        assert!(!data_dir.join("swap_reports.json").exists());

        let saved: SwapReportFile =
            serde_json::from_str(&std::fs::read_to_string(expected_path).unwrap()).unwrap();
        assert_eq!(saved.taker.len(), 1);
        assert_eq!(saved.taker[0].swap_id, "swap-1");

        std::fs::remove_dir_all(data_dir).unwrap();
    }
}
