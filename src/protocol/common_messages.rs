//! Common OpenSwap Protocol Messages and Top-Level Message Enums.

use bitcoin::{bip32::ChainCode, hashes::sha256d::Hash, Amount, PublicKey};
use serde::{Deserialize, Serialize};

use super::{
    legacy_messages::{
        ProofOfFunding, ReqContractSigsAsRecvrAndSender, ReqContractSigsForRecvr,
        ReqContractSigsForSender, RespContractSigsForRecvr, RespContractSigsForRecvrAndSender,
        RespContractSigsForSender,
    },
    taproot_messages::TaprootContractData,
};
use crate::wallet::FidelityBond;

/// Well-known virtual port for the OpenSwap protocol over Tor.
pub const OPENSWAP_PORT: u16 = 21;

/// Hash preimage type used in HTLC contracts.
pub type Preimage = [u8; 32];

/// Contains proof data related to fidelity bond.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FidelityProof {
    /// Details for Fidelity Bond
    pub bond: FidelityBond,
    /// Double SHA256 hash of certificate message proving bond ownership and binding to maker address
    pub cert_hash: Hash,
    /// ECDSA signature over cert_hash using the bond's private key
    pub cert_sig: bitcoin::secp256k1::ecdsa::Signature,
}

/// Protocol version identifier for openswap operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ProtocolVersion {
    /// Legacy ECDSA-based protocol with script-evaluated HTLCs.
    #[default]
    Legacy,
    /// Taproot MuSig2-based protocol with scriptless contracts.
    Taproot,
}

/// Initial handshake from Taker to Maker.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TakerHello;

/// Handshake response from Maker to Taker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MakerHello {
    /// Protocol versions this maker supports.
    pub supported_protocols: Vec<ProtocolVersion>,
}

/// Request for offer from Taker to Maker.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GetOffer;

/// Maker's offer advertisement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Offer {
    /// Base fee charged per swap in satoshis (fixed cost component).
    pub base_fee: u64,
    /// Percentage fee relative to swap amount.
    pub amount_relative_fee_pct: f64,
    /// Percentage fee for time-locked funds.
    pub time_relative_fee_pct: f64,
    /// Minimum confirmations required before proceeding with swap.
    pub required_confirms: u32,
    /// Minimum timelock duration in blocks for contract transactions.
    pub minimum_locktime: u16,
    /// Maximum swap amount accepted in sats.
    pub max_size: u64,
    /// Minimum swap amount accepted in sats.
    pub min_size: u64,
    /// Tweakable public key for receiving swaps.
    /// Actual swap addresses are derived using unique nonces per swap.
    pub tweakable_point: PublicKey,
    /// Cryptographic proof of fidelity bond for Sybil resistance.
    pub fidelity: FidelityProof,
    /// Chain code for deterministic derivation of swap addresses from the tweakable point.
    pub tweak_chain_code: ChainCode,
    /// Max outgoing contract splits this maker will build per hop (Taproot).
    /// `None` = maker predates the feature; the taker must not send it an
    /// `outgoing_tx_count` differing from the incoming count.
    #[serde(default)]
    pub max_tx_splits: Option<u32>,
}

/// Swap details from Taker to Maker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapDetails {
    /// Unique 8-byte ID to identify this swap.
    pub id: String,
    /// Protocol version to use for this swap.
    pub protocol_version: ProtocolVersion,
    /// Amount to swap in satoshis.
    pub amount: Amount,
    /// Contracts the taker funds *into this maker* (this hop's incoming count).
    pub tx_count: u32,
    /// Outgoing contracts to build for this hop (Taproot per-hop splitting).
    /// `None` (wire default) = mirror the incoming count. Old peers ignore/omit it,
    /// so its presence activates the feature without a protocol version bump.
    #[serde(default)]
    pub outgoing_tx_count: Option<u32>,
    /// Timelock value.
    /// - Legacy: relative block count (CSV).
    /// - Taproot: absolute block height (CLTV).
    pub timelock: u32,
    /// Relative locktime offset (Taproot only). The time fee is priced on this negotiated
    /// offset, not the funding height, so it is fixed at negotiation and identical on both
    /// sides. Not bound to the real lock duration; assess the CSV transition as the real fix.
    pub refund_locktime_offset: u16,
}

/// Acknowledgment of swap details from Maker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AckSwapDetails {
    /// Whether the swap is accepted.
    /// If Some, contains the tweakable point for this swap.
    /// If None, swap is rejected.
    pub tweakable_point: Option<PublicKey>,
}

impl AckSwapDetails {
    /// Create an acceptance response.
    pub fn accept(tweakable_point: PublicKey) -> Self {
        AckSwapDetails {
            tweakable_point: Some(tweakable_point),
        }
    }

    /// Create a rejection response.
    pub fn reject() -> Self {
        AckSwapDetails {
            tweakable_point: None,
        }
    }
}

/// A private key exchanged during swap completion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapPrivkey {
    /// The redeemscript (ECDSA) or script identifier (Taproot) this key belongs to.
    pub identifier: bitcoin::ScriptBuf,
    /// The private key.
    pub key: bitcoin::secp256k1::SecretKey,
}

/// Private key handover for swap completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKeyHandover {
    /// Unique swap ID.
    pub id: String,
    /// Private keys for cooperative spending.
    pub privkeys: Vec<SwapPrivkey>,
}

/// All messages sent from Taker to Maker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TakerToMakerMessage {
    /// Initial handshake with version negotiation.
    TakerHello(TakerHello),
    /// Request maker's offer.
    GetOffer(GetOffer),
    /// Propose swap parameters (determines protocol path).
    SwapDetails(SwapDetails),
    /// Request signatures for sender's contract (initial hop setup).
    ReqContractSigsForSender(ReqContractSigsForSender),
    /// Proof that funding transaction is confirmed.
    ProofOfFunding(ProofOfFunding),
    /// Response with both receiver and sender signatures.
    RespContractSigsForRecvrAndSender(RespContractSigsForRecvrAndSender),
    /// Request signatures for receiver's contract.
    ReqContractSigsForRecvr(ReqContractSigsForRecvr),
    /// Legacy private key handover.
    LegacyPrivateKeyHandover(PrivateKeyHandover),
    /// Taproot contract data exchange (MuSig2).
    TaprootContractData(Box<TaprootContractData>),
    /// Taproot private key handover.
    TaprootPrivateKeyHandover(PrivateKeyHandover),
    /// Taker keepalive while waiting for funding confirmation.
    WaitingFundingConfirmation(String),
}

/// All messages sent from Maker to Taker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MakerToTakerMessage {
    /// Handshake response with version negotiation.
    MakerHello(MakerHello),
    /// Maker's offer (fees, limits, fidelity bond).
    Offer(Box<Offer>),
    /// Acknowledgment of swap parameters.
    AckSwapDetails(AckSwapDetails),
    /// Response with signatures for sender's contract.
    RespContractSigsForSender(RespContractSigsForSender),
    /// Request signatures for both receiver and sender contracts.
    ReqContractSigsAsRecvrAndSender(ReqContractSigsAsRecvrAndSender),
    /// Response with signatures for receiver's contract.
    RespContractSigsForRecvr(RespContractSigsForRecvr),
    /// Legacy private key handover.
    LegacyPrivateKeyHandover(PrivateKeyHandover),
    /// Taproot contract data exchange (MuSig2).
    TaprootContractData(Box<TaprootContractData>),
    /// Taproot private key handover.
    TaprootPrivateKeyHandover(PrivateKeyHandover),
}
