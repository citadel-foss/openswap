//! Legacy Protocol Messages

use bitcoin::{
    ecdsa::Signature as EcdsaSignature, secp256k1::SecretKey, Amount, PublicKey, ScriptBuf,
    Transaction,
};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

use super::common_messages::PrivateKeyHandover;

/// Contract transaction info for the Sender side of a hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractTxInfoForSender {
    /// Nonce for deriving the multisig pubkey.
    pub multisig_nonce: SecretKey,
    /// Nonce for deriving the hashlock pubkey.
    pub hashlock_nonce: SecretKey,
    /// Timelock pubkey for the contract.
    pub timelock_pubkey: PublicKey,
    /// The sender's contract transaction.
    pub senders_contract_tx: Transaction,
    /// The 2-of-2 multisig redeem script.
    pub multisig_redeemscript: ScriptBuf,
    /// The funding input value.
    pub funding_input_value: Amount,
}

/// Request for contract signatures FOR the Sender side of a hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReqContractSigsForSender {
    /// Unique swap ID.
    pub id: String,
    /// Contract transaction info for each UTXO.
    pub txs_info: Vec<ContractTxInfoForSender>,
    /// Hash value for the HTLC.
    pub hashvalue: bitcoin::hashes::hash160::Hash,
    /// Locktime for the contract.
    pub locktime: u16,
}

/// Response with contract signatures FOR the Sender side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespContractSigsForSender {
    /// Unique swap ID.
    pub id: String,
    /// Signatures for each contract transaction.
    pub sigs: Vec<EcdsaSignature>,
}

/// Confirmed funding transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundingTxInfo {
    /// The funding transaction.
    pub funding_tx: Transaction,
    /// The 2-of-2 multisig redeem script.
    pub multisig_redeemscript: ScriptBuf,
    /// Nonce for deriving the multisig pubkey.
    pub multisig_nonce: SecretKey,
    /// The HTLC contract redeem script.
    pub contract_redeemscript: ScriptBuf,
    /// Nonce for deriving the hashlock pubkey.
    pub hashlock_nonce: SecretKey,
}

/// Public key information for the next hop of a openswap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextHopInfo {
    /// Multisig pubkey for the next hop (derived from tweakable_point + nonce).
    pub next_multisig_pubkey: PublicKey,
    /// Hashlock pubkey for the next hop (derived from tweakable_point + nonce).
    pub next_hashlock_pubkey: PublicKey,
    /// Nonce used to derive next_multisig_pubkey from next hop's tweakable_point.
    pub next_multisig_nonce: SecretKey,
    /// Nonce used to derive next_hashlock_pubkey from next hop's tweakable_point.
    pub next_hashlock_nonce: SecretKey,
}

/// Proof that funding transaction has been confirmed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfFunding {
    /// Unique swap ID.
    pub id: String,
    /// Confirmed funding transactions with merkle proofs.
    pub confirmed_funding_txes: Vec<FundingTxInfo>,
    /// Information about the next hop (pubkeys for outgoing swap).
    pub next_openswap_info: Vec<NextHopInfo>,
    /// Refund locktime in blocks.
    pub refund_locktime: u16,
}

/// Contract transaction info for the Sender side (Maker's outgoing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderContractTxInfo {
    /// The funding transaction (sends to multisig).
    pub funding_tx: Transaction,
    /// The sender's contract transaction (spends from funding).
    pub contract_tx: Transaction,
    /// Timelock pubkey for the contract.
    pub timelock_pubkey: PublicKey,
    /// The 2-of-2 multisig redeem script.
    pub multisig_redeemscript: ScriptBuf,
    /// The contract redeem script (HTLC).
    pub contract_redeemscript: ScriptBuf,
    /// The funding amount.
    pub funding_amount: Amount,
    /// Multisig nonce used to derive the maker's pubkey.
    pub multisig_nonce: SecretKey,
    /// Hashlock nonce used to derive the hashlock pubkey.
    pub hashlock_nonce: SecretKey,
}

/// Request for contract signatures as BOTH Receiver and Sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReqContractSigsAsRecvrAndSender {
    /// Contract transactions for the Maker's incoming swap (as Receiver).
    pub receivers_contract_txs: Vec<Transaction>,
    /// Contract transaction info for the Maker's outgoing swap (as Sender).
    pub senders_contract_txs_info: Vec<SenderContractTxInfo>,
}

/// Response with contract signatures for BOTH Receiver and Sender sides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespContractSigsForRecvrAndSender {
    /// Unique swap ID.
    pub id: String,
    /// Signatures from the previous hop's Sender (for Maker's incoming contract).
    pub receivers_sigs: Vec<EcdsaSignature>,
    /// Signatures from the next hop's Receiver (for Maker's outgoing contract).
    pub senders_sigs: Vec<EcdsaSignature>,
}

/// Contract transaction info for the Receiver side of a hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractTxInfoForRecvr {
    /// The 2-of-2 multisig redeem script.
    pub multisig_redeemscript: ScriptBuf,
    /// The receiver's contract transaction.
    pub contract_tx: Transaction,
}

/// Request for contract signatures FOR the Receiver side of a hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReqContractSigsForRecvr {
    /// Unique swap ID.
    pub id: String,
    /// Contract transaction info for each UTXO.
    pub txs: Vec<ContractTxInfoForRecvr>,
}

/// Response with contract signatures FOR the Receiver side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespContractSigsForRecvr {
    /// Unique swap ID.
    pub id: String,
    /// Signatures for each contract transaction.
    pub sigs: Vec<EcdsaSignature>,
}

/// All Legacy-specific messages sent from Taker to Maker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LegacyTakerMessage {
    /// Request signatures for sender's contract (Taker is Sender).
    ReqContractSigsForSender(ReqContractSigsForSender),

    /// Proof that funding transaction is confirmed.
    ProofOfFunding(ProofOfFunding),

    /// Response with both receiver and sender signatures.
    RespContractSigsForRecvrAndSender(RespContractSigsForRecvrAndSender),

    /// Request signatures for receiver's contract.
    ReqContractSigsForRecvr(ReqContractSigsForRecvr),

    /// Private key handover.
    PrivateKeyHandover(PrivateKeyHandover),
}

impl Display for LegacyTakerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReqContractSigsForSender(_) => write!(f, "Legacy::ReqContractSigsForSender"),
            Self::ProofOfFunding(_) => write!(f, "Legacy::ProofOfFunding"),
            Self::RespContractSigsForRecvrAndSender(_) => {
                write!(f, "Legacy::RespContractSigsForRecvrAndSender")
            }
            Self::ReqContractSigsForRecvr(_) => write!(f, "Legacy::ReqContractSigsForRecvr"),
            Self::PrivateKeyHandover(_) => write!(f, "Legacy::PrivateKeyHandover"),
        }
    }
}

impl LegacyTakerMessage {
    /// Returns the swap ID.
    pub fn swap_id(&self) -> &str {
        match self {
            Self::ReqContractSigsForSender(req) => &req.id,
            Self::ProofOfFunding(pof) => &pof.id,
            Self::RespContractSigsForRecvrAndSender(resp) => &resp.id,
            Self::ReqContractSigsForRecvr(req) => &req.id,
            Self::PrivateKeyHandover(handover) => &handover.id,
        }
    }
}
