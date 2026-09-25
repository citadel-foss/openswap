//! Lightning submarine-swap wire messages.
//!
//! These are plain serializable data carried inside
//! `TakerToMakerMessage::Lightning` / `MakerToTakerMessage::Lightning`. They
//! are deliberately *not* feature-gated: a build without the `lightning`
//! feature can still decode them and answer with a graceful `Unsupported`
//! reply instead of dropping the connection.
//!
//! Swap identifier: the hex-encoded Lightning payment hash doubles as the
//! `swap_id`, mirroring how the other protocol families route messages to
//! per-swap state.
//!
//! Direction naming follows the taker's perspective:
//! - *swap-in*: taker pays on-chain BTC, receives Lightning balance.
//! - *swap-out*: taker pays Lightning balance, receives on-chain BTC.

use bitcoin::{hashes::sha256, Amount, OutPoint, PublicKey, Txid};
use serde::{Deserialize, Serialize};

/// Lightning submarine-swap terms advertised inside an offer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct LightningOffer {
    /// Whether the maker serves swap-ins (taker: on-chain -> Lightning).
    pub swap_in: bool,
    /// Whether the maker serves swap-outs (taker: Lightning -> on-chain).
    pub swap_out: bool,
    /// Flat fee per swap in satoshis.
    pub base_fee: u64,
    /// Percentage fee relative to the swap amount.
    pub amount_relative_fee_pct: f64,
    /// Minimum swap amount in satoshis, for either direction.
    pub min_size: u64,
    /// Largest swap-in in satoshis. The maker pays this over Lightning, so
    /// it is bounded by its outbound channel capacity.
    pub max_swap_in: u64,
    /// Largest swap-out in satoshis. The maker receives this over Lightning
    /// and pays it out on-chain, so it is bounded by its inbound channel
    /// capacity *and* its on-chain wallet — a different resource entirely
    /// from the swap-in limit.
    pub max_swap_out: u64,
}

impl LightningOffer {
    /// The advertised limits for one direction: whether it is served at all,
    /// and the largest amount it will take.
    pub fn direction_limits(&self, swap_in: bool) -> (bool, u64) {
        if swap_in {
            (self.swap_in, self.max_swap_in)
        } else {
            (self.swap_out, self.max_swap_out)
        }
    }
}

/// Taker -> Maker: propose a swap-in (on-chain BTC -> Lightning).
///
/// The taker has already created the hold invoice for `payment_hash` on its
/// own node; the maker recreates the on-chain HTLC script from these fields
/// alone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LnSwapInRequest {
    /// Swap identifier (hex payment hash).
    pub swap_id: String,
    /// BOLT11 hold invoice on the taker's node, over `amount`.
    pub invoice: String,
    /// The invoice payment hash `H = sha256(P)`.
    pub payment_hash: sha256::Hash,
    /// Lightning amount the taker receives.
    pub amount: Amount,
    /// Relative locktime (blocks, CSV) of the taker's on-chain refund branch.
    pub locktime: u16,
    /// Confirmations the maker requires on the HTLC funding output.
    pub min_confirmations: u32,
    /// Taker pubkey for the timelock (refund) branch of the HTLC script.
    pub taker_timelock_pubkey: PublicKey,
}

/// Maker -> Taker: acceptance of a [`LnSwapInRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LnSwapInAccept {
    /// Swap identifier (hex payment hash).
    pub swap_id: String,
    /// Maker pubkey for the hashlock (claim) branch of the HTLC script.
    pub maker_hashlock_pubkey: PublicKey,
    /// Total fee the maker charges, funded on top of the swap amount in the
    /// on-chain HTLC. Derived from the advertised [`LightningOffer`] terms.
    pub fee: Amount,
    /// Agreed refund locktime (echo of the requested terms).
    pub locktime: u16,
    /// Agreed confirmation requirement (echo of the requested terms).
    pub min_confirmations: u32,
}

/// Location of a confirmed on-chain HTLC funding output.
///
/// Taker -> Maker for swap-in; Maker -> Taker for swap-out.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LnHtlcFunded {
    /// Swap identifier (hex payment hash).
    pub swap_id: String,
    /// Outpoint of the P2WSH HTLC output.
    pub outpoint: OutPoint,
    /// Value of the HTLC output.
    pub value: Amount,
}

/// Maker -> Taker: the swap-in settled — the maker learned the preimage from
/// the Lightning settlement and swept the on-chain HTLC. Informational; the
/// taker's own claim already completed its side.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LnSwapInComplete {
    /// Swap identifier (hex payment hash).
    pub swap_id: String,
}

/// Taker -> Maker: propose a swap-out (Lightning -> on-chain BTC).
///
/// Only the taker knows the preimage; the maker answers with a hold invoice
/// for `payment_hash` that it cannot settle by itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LnSwapOutRequest {
    /// Swap identifier (hex payment hash).
    pub swap_id: String,
    /// The Lightning payment hash `H = sha256(P)`.
    pub payment_hash: sha256::Hash,
    /// On-chain amount the taker receives.
    pub amount: Amount,
    /// Relative locktime (blocks, CSV) of the maker's on-chain refund branch.
    pub locktime: u16,
    /// Confirmations the taker requires on the HTLC funding output.
    pub min_confirmations: u32,
    /// Taker pubkey for the hashlock (claim) branch of the HTLC script.
    pub taker_hashlock_pubkey: PublicKey,
}

/// Maker -> Taker: acceptance of a [`LnSwapOutRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LnSwapOutAccept {
    /// Swap identifier (hex payment hash).
    pub swap_id: String,
    /// BOLT11 hold invoice on the maker's node over `amount + fee`. The
    /// taker MUST verify this invoice commits to its own payment hash and
    /// the expected amount before paying.
    pub invoice: String,
    /// Total fee the maker charges on top of the on-chain amount.
    pub fee: Amount,
    /// Maker pubkey for the timelock (refund) branch of the HTLC script.
    pub maker_timelock_pubkey: PublicKey,
    /// Agreed refund locktime (echo of the requested terms).
    pub locktime: u16,
    /// Agreed confirmation requirement (echo of the requested terms).
    pub min_confirmations: u32,
}

/// Taker -> Maker: the taker has paid the maker's hold invoice. Prompts the
/// maker to verify the held payment arrived and fund the on-chain HTLC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LnSwapOutPaid {
    /// Swap identifier (hex payment hash).
    pub swap_id: String,
}

/// Maker -> Taker: the swap-out settled — the maker extracted the preimage
/// from the taker's on-chain claim and settled its held payment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LnSwapOutComplete {
    /// Swap identifier (hex payment hash).
    pub swap_id: String,
}

/// Taker -> Maker: courtesy notification that the taker's on-chain claim of
/// the swap-out HTLC was broadcast. Lets the maker settle its held payment
/// immediately instead of waiting for its own chain monitoring to spot the
/// spend. The maker MUST NOT rely on receiving this.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LnSwapOutClaimed {
    /// Swap identifier (hex payment hash).
    pub swap_id: String,
    /// Txid of the taker's hashlock claim transaction.
    pub claim_txid: Txid,
}

/// Maker -> Taker: the maker declines a Lightning swap request.
///
/// Distinct from the top-level `Unsupported` reply: this maker speaks the
/// Lightning family but rejects these specific terms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LnReject {
    /// Swap identifier (hex payment hash).
    pub swap_id: String,
    /// Human-readable reason.
    pub reason: String,
}

/// Lightning family messages sent from Taker to Maker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LightningTakerMessage {
    /// Propose a swap-in.
    SwapInRequest(LnSwapInRequest),
    /// Announce the confirmed swap-in HTLC funding output.
    SwapInFunded(LnHtlcFunded),
    /// Propose a swap-out.
    SwapOutRequest(LnSwapOutRequest),
    /// Announce that the hold invoice was paid.
    SwapOutPaid(LnSwapOutPaid),
    /// Announce the broadcast swap-out claim transaction.
    SwapOutClaimed(LnSwapOutClaimed),
}

impl LightningTakerMessage {
    /// The swap this message belongs to.
    pub fn swap_id(&self) -> &str {
        match self {
            LightningTakerMessage::SwapInRequest(m) => &m.swap_id,
            LightningTakerMessage::SwapInFunded(m) => &m.swap_id,
            LightningTakerMessage::SwapOutRequest(m) => &m.swap_id,
            LightningTakerMessage::SwapOutPaid(m) => &m.swap_id,
            LightningTakerMessage::SwapOutClaimed(m) => &m.swap_id,
        }
    }
}

impl std::fmt::Display for LightningTakerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            LightningTakerMessage::SwapInRequest(_) => "SwapInRequest",
            LightningTakerMessage::SwapInFunded(_) => "SwapInFunded",
            LightningTakerMessage::SwapOutRequest(_) => "SwapOutRequest",
            LightningTakerMessage::SwapOutPaid(_) => "SwapOutPaid",
            LightningTakerMessage::SwapOutClaimed(_) => "SwapOutClaimed",
        };
        write!(f, "{}", name)
    }
}

/// Lightning family messages sent from Maker to Taker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LightningMakerMessage {
    /// Accept a swap-in request.
    SwapInAccept(LnSwapInAccept),
    /// The swap-in settled on both layers.
    SwapInComplete(LnSwapInComplete),
    /// Accept a swap-out request (carries the hold invoice).
    SwapOutAccept(LnSwapOutAccept),
    /// Announce the confirmed swap-out HTLC funding output.
    SwapOutFunded(LnHtlcFunded),
    /// The swap-out settled on both layers.
    SwapOutComplete(LnSwapOutComplete),
    /// Decline a Lightning swap request.
    Reject(LnReject),
}

impl LightningMakerMessage {
    /// The swap this message belongs to.
    pub fn swap_id(&self) -> &str {
        match self {
            LightningMakerMessage::SwapInAccept(m) => &m.swap_id,
            LightningMakerMessage::SwapInComplete(m) => &m.swap_id,
            LightningMakerMessage::SwapOutAccept(m) => &m.swap_id,
            LightningMakerMessage::SwapOutFunded(m) => &m.swap_id,
            LightningMakerMessage::SwapOutComplete(m) => &m.swap_id,
            LightningMakerMessage::Reject(m) => &m.swap_id,
        }
    }
}

impl std::fmt::Display for LightningMakerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            LightningMakerMessage::SwapInAccept(_) => "SwapInAccept",
            LightningMakerMessage::SwapInComplete(_) => "SwapInComplete",
            LightningMakerMessage::SwapOutAccept(_) => "SwapOutAccept",
            LightningMakerMessage::SwapOutFunded(_) => "SwapOutFunded",
            LightningMakerMessage::SwapOutComplete(_) => "SwapOutComplete",
            LightningMakerMessage::Reject(_) => "Reject",
        };
        write!(f, "{}", name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::common_messages::{MakerToTakerMessage, TakerToMakerMessage};

    /// Old peers must keep decoding offers that carry the new optional
    /// lightning field, and new peers must decode offers without it. CBOR
    /// structs are maps, so both directions hinge on serde's
    /// ignore-unknown / default behavior — pin it here.
    #[test]
    fn lightning_offer_field_is_forward_and_backward_compatible() {
        #[derive(serde::Serialize)]
        struct OldOffer {
            base_fee: u64,
        }
        #[derive(Debug, serde::Deserialize)]
        struct NewOffer {
            base_fee: u64,
            #[serde(default)]
            lightning: Option<LightningOffer>,
        }

        // Missing field -> None (new reader, old writer).
        let old_bytes = serde_cbor::to_vec(&OldOffer { base_fee: 42 }).unwrap();
        let new: NewOffer = serde_cbor::from_slice(&old_bytes).unwrap();
        assert_eq!(new.base_fee, 42);
        assert!(new.lightning.is_none());

        // Unknown field -> ignored (old reader, new writer).
        #[derive(serde::Serialize)]
        struct NewOfferOut {
            base_fee: u64,
            lightning: Option<LightningOffer>,
        }
        #[derive(Debug, serde::Deserialize)]
        struct OldOfferIn {
            base_fee: u64,
        }
        let new_bytes = serde_cbor::to_vec(&NewOfferOut {
            base_fee: 7,
            lightning: Some(LightningOffer {
                swap_in: true,
                swap_out: false,
                base_fee: 100,
                amount_relative_fee_pct: 0.1,
                min_size: 10_000,
                max_swap_in: 1_000_000,
                max_swap_out: 0,
            }),
        })
        .unwrap();
        let old: OldOfferIn = serde_cbor::from_slice(&new_bytes).unwrap();
        assert_eq!(old.base_fee, 7);
    }

    /// The Lightning and Unsupported variants must round-trip through the
    /// top-level enums, and their variant names must not collide with (or
    /// perturb) existing ones — CBOR enum encoding is name-based.
    #[test]
    fn new_top_level_variants_round_trip() {
        let msg = TakerToMakerMessage::Lightning(Box::new(LightningTakerMessage::SwapOutClaimed(
            LnSwapOutClaimed {
                swap_id: "abc".to_string(),
                claim_txid: "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
                    .parse()
                    .unwrap(),
            },
        )));
        let bytes = serde_cbor::to_vec(&msg).unwrap();
        let back: TakerToMakerMessage = serde_cbor::from_slice(&bytes).unwrap();
        assert!(matches!(back, TakerToMakerMessage::Lightning(_)));

        let msg = MakerToTakerMessage::Unsupported(
            crate::protocol::common_messages::UnsupportedMessage {
                what: "Lightning".to_string(),
                reason: "no lightning backend configured".to_string(),
            },
        );
        let bytes = serde_cbor::to_vec(&msg).unwrap();
        let back: MakerToTakerMessage = serde_cbor::from_slice(&bytes).unwrap();
        assert!(matches!(back, MakerToTakerMessage::Unsupported(_)));
    }
}
