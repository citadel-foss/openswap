//! Common OpenSwap Protocol Messages and Top-Level Message Enums.

use bitcoin::{bip32::ChainCode, hashes::sha256d::Hash, Amount, PublicKey};
use serde::{Deserialize, Serialize};
use serde_cbor::Value;

use super::{
    legacy_messages::{
        ProofOfFunding, ReqContractSigsAsRecvrAndSender, ReqContractSigsForRecvr,
        ReqContractSigsForSender, RespContractSigsForRecvr, RespContractSigsForRecvrAndSender,
        RespContractSigsForSender,
    },
    lightning_messages::{LightningMakerMessage, LightningOffer, LightningTakerMessage},
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

impl ProtocolVersion {
    /// The feature name of this protocol's flow.
    pub fn feature_name(self) -> &'static str {
        match self {
            ProtocolVersion::Legacy => "legacy",
            ProtocolVersion::Taproot => "taproot",
        }
    }
}

/// First message on every connection, both ways. Frozen: it only ever gains
/// defaulted fields, because it is how peers learn what changed.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Hello {
    /// Feature names the sender supports.
    pub features: Vec<String>,
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
    /// Public name the maker chose. A label only: any maker can claim any name.
    #[serde(default)]
    pub name: String,
    /// Lightning submarine-swap terms, present only when the maker offers
    /// them. Optional with a serde default so peers that predate Lightning
    /// support keep (de)serializing offers unchanged: CBOR structs are maps,
    /// unknown keys are ignored and missing keys fall back to `None`.
    #[serde(default)]
    pub lightning: Option<LightningOffer>,
}

impl Offer {
    /// Checks the parts of an offer that are wrong whatever the swap amount is.
    /// A maker that fails this has published something nobody can price.
    pub(crate) fn validate_shape(&self) -> Result<(), String> {
        check_fee_pcts(self.amount_relative_fee_pct, self.time_relative_fee_pct)
            .map_err(|e| format!("offer has {e}"))?;

        if self.min_size > self.max_size {
            return Err(format!(
                "offer has min_size ({}) above max_size ({})",
                self.min_size, self.max_size
            ));
        }

        check_maker_name(&self.name)
    }
}

/// Fee percentages must be finite and in `0..100`. Takers refuse offers
/// outside this, so makers refuse to start with them.
pub(crate) fn check_fee_pcts(
    amount_relative_fee_pct: f64,
    time_relative_fee_pct: f64,
) -> Result<(), String> {
    for (name, pct) in [
        ("amount_relative_fee_pct", amount_relative_fee_pct),
        ("time_relative_fee_pct", time_relative_fee_pct),
    ] {
        if !pct.is_finite() || !(0.0..100.0).contains(&pct) {
            return Err(format!("invalid {name}: {pct}"));
        }
    }
    Ok(())
}

/// Longest maker name, in characters, that takers accept.
pub(crate) const MAX_MAKER_NAME_LEN: usize = 32;

/// Every maker must be named. Takers store the name and print it to the
/// terminal, so it must stay short and free of escape codes.
pub(crate) fn check_maker_name(name: &str) -> Result<(), String> {
    let len = name.chars().count();
    if len == 0 || len > MAX_MAKER_NAME_LEN || name.chars().any(char::is_control) {
        return Err(format!(
            "invalid maker name {name:?}: 1 to {MAX_MAKER_NAME_LEN} characters, no control characters"
        ));
    }
    Ok(())
}

/// Swap details from Taker to Maker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapDetails {
    /// Unique 8-byte ID to identify this swap.
    pub id: String,
    /// Exact feature names this swap uses: its protocol plus any feature that
    /// changes it. Both sides keep them for every reconnect of the swap.
    pub features: Vec<String>,
    /// Amount to swap in satoshis.
    pub amount: Amount,
    /// Maximum contract transactions this hop plans to send — a ceiling.
    /// The exact incoming count is `incoming_count`; one field cannot be both.
    pub tx_count: u32,
    /// Exactly how many contracts the taker will send this hop.
    /// Checked for equality, so it cannot double as the `tx_count` ceiling.
    pub incoming_count: u32,
    /// Maximum inputs per forwarding tx whose fee the taker covers.
    /// The maker may use more inputs; that is not a violation —
    /// the taker simply does not pay for the excess.
    pub max_input_budget: u32,
    /// Swap feerate in sats/vB for every transaction in this swap.
    /// Peer-supplied: recipients must reject values below the 1 sat/vB
    /// relay floor.
    pub feerate: u64,
    /// Timelock value.
    /// - Legacy: relative block count (CSV).
    /// - Taproot: absolute block height (CLTV).
    pub timelock: u32,
    /// Relative locktime offset (Taproot only). The time fee is priced on this negotiated
    /// offset, not the funding height, so it is fixed at negotiation and identical on both
    /// sides. Not bound to the real lock duration; assess the CSV transition as the real fix.
    pub refund_locktime_offset: u16,
}

impl SwapDetails {
    /// The on-chain protocol these details pin, if any.
    pub fn protocol(&self) -> Option<ProtocolVersion> {
        [ProtocolVersion::Legacy, ProtocolVersion::Taproot]
            .iter()
            .copied()
            .find(|p| self.features.iter().any(|f| f == p.feature_name()))
    }
}

/// Acknowledgment of swap details from Maker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AckSwapDetails {
    /// Whether the swap is accepted.
    /// If Some, contains the tweakable point for this swap.
    /// If None, swap is rejected.
    pub tweakable_point: Option<PublicKey>,
    /// The maker's frozen plan shape: one entry per planned funding tx,
    /// valued by that split's input count. Counts, not a fee total, so the
    /// taker derives the next hop's amount itself. Empty on rejection.
    pub funding_splits: Vec<u32>,
}

impl AckSwapDetails {
    /// Create an acceptance response carrying the frozen plan shape.
    pub fn accept(tweakable_point: PublicKey, funding_splits: Vec<u32>) -> Self {
        AckSwapDetails {
            tweakable_point: Some(tweakable_point),
            funding_splits,
        }
    }

    /// Create a rejection response.
    pub fn reject() -> Self {
        AckSwapDetails {
            tweakable_point: None,
            funding_splits: Vec::new(),
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateKeyHandover {
    /// Unique swap ID.
    pub id: String,
    /// Private keys for cooperative spending.
    pub privkeys: Vec<SwapPrivkey>,
}

/// All messages sent from Taker to Maker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TakerToMakerMessage {
    /// Handshake; must be the first message on every connection.
    Hello(Hello),
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
    /// Lightning submarine-swap message family. Send only to makers whose
    /// [`Offer::lightning`] advertised support; older peers fail to decode
    /// unknown variants and drop the connection.
    Lightning(Box<LightningTakerMessage>),
    /// The peer sent a message family this side does not support. Carries
    /// the rejected variant's name so the peer can log/report it. Added
    /// alongside the Lightning family so future extensions can be declined
    /// gracefully instead of by connection drop.
    Unsupported(UnsupportedMessage),
}

/// All messages sent from Maker to Taker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MakerToTakerMessage {
    /// Handshake reply, sent once the taker's Hello meets our requirements.
    Hello(Hello),
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
    /// Lightning submarine-swap message family.
    Lightning(Box<LightningMakerMessage>),
    /// The peer sent a message family this side does not support. See
    /// [`TakerToMakerMessage::Unsupported`].
    Unsupported(UnsupportedMessage),
}

/// The variant name of an externally tagged message: a one-entry map's key or
/// bare text. Lets a receiver name a message it can't decode.
fn variant_name(value: &Value) -> Option<(&str, Option<&Value>)> {
    match value {
        Value::Text(name) => Some((name, None)),
        Value::Map(map) if map.len() == 1 => match map.iter().next()? {
            (Value::Text(name), body) => Some((name, Some(body))),
            _ => None,
        },
        _ => None,
    }
}

/// Names a message we failed to decode, looking inside the `Lightning` family.
/// `None` when even the name is unreadable.
pub(crate) fn message_name(bytes: &[u8]) -> Option<String> {
    let value: Value = serde_cbor::from_slice(bytes).ok()?;
    let (name, body) = variant_name(&value)?;
    match body.and_then(variant_name) {
        Some((inner, _)) if name == "Lightning" => Some(format!("Lightning::{inner}")),
        _ => Some(name.to_string()),
    }
}

/// Graceful rejection of a message the receiver does not handle. Frozen like
/// [`Hello`]. The sender closes the connection after it, and it is never answered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsupportedMessage {
    /// Name of the message (family) that was rejected.
    pub what: String,
    /// Human-readable reason.
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utill::send_message;
    use serde_cbor::value::to_value;
    use std::{
        collections::BTreeMap,
        io::Read,
        net::{TcpListener, TcpStream},
    };

    fn tagged(name: &str, body: Value) -> Vec<u8> {
        serde_cbor::to_vec(&Value::Map(BTreeMap::from([(
            Value::Text(name.to_string()),
            body,
        )])))
        .unwrap()
    }

    #[test]
    fn undecodable_messages_are_named_by_their_tag() {
        let future = tagged("FutureThing", Value::Integer(7));
        assert!(serde_cbor::from_slice::<TakerToMakerMessage>(&future).is_err());
        assert_eq!(message_name(&future).as_deref(), Some("FutureThing"));

        let bare = serde_cbor::to_vec(&Value::Text("FutureUnit".to_string())).unwrap();
        assert_eq!(message_name(&bare).as_deref(), Some("FutureUnit"));

        let nested = tagged(
            "Lightning",
            serde_cbor::from_slice(&tagged("SwapX", Value::Null)).unwrap(),
        );
        assert_eq!(message_name(&nested).as_deref(), Some("Lightning::SwapX"));

        assert_eq!(message_name(&[0xff, 0x00]), None);
        assert_eq!(message_name(&serde_cbor::to_vec(&7u8).unwrap()), None);
    }

    #[test]
    fn hello_frame_starts_with_its_frozen_tag() {
        let bytes = serde_cbor::to_vec(&TakerToMakerMessage::Hello(Hello::default())).unwrap();
        assert_eq!(&bytes[..7], b"\xa1\x65Hello");
    }

    #[test]
    fn compat_hello_and_unsupported_accept_future_fields_both_ways() {
        for tag in ["Hello", "Unsupported"] {
            let mut fields = BTreeMap::new();
            if tag == "Hello" {
                fields.insert(
                    Value::Text("features".into()),
                    Value::Array(vec![Value::Text("taproot".into())]),
                );
            } else {
                fields.insert(
                    Value::Text("what".into()),
                    Value::Text("FutureThing".into()),
                );
                fields.insert(
                    Value::Text("reason".into()),
                    Value::Text("cannot decode".into()),
                );
            }
            let baseline = Value::Map(fields.clone());
            fields.insert(
                Value::Text("future".into()),
                Value::Map(BTreeMap::from([(
                    Value::Text("nested".into()),
                    Value::Bytes(vec![1, 2, 3]),
                )])),
            );
            let bytes = tagged(tag, Value::Map(fields));
            let taker: TakerToMakerMessage = serde_cbor::from_slice(&bytes).unwrap();
            let maker: MakerToTakerMessage = serde_cbor::from_slice(&bytes).unwrap();
            let frozen: Value = serde_cbor::from_slice(&tagged(tag, baseline)).unwrap();
            assert_eq!(to_value(&taker).unwrap(), frozen);
            assert_eq!(to_value(&maker).unwrap(), frozen);
            assert_eq!(message_name(&bytes).as_deref(), Some(tag));
        }
    }

    #[test]
    fn compat_hello_frame_keeps_length_prefix_and_tag_both_ways() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut reader, _) = listener.accept().unwrap();
        let hello = Hello {
            features: vec!["taproot".into(), "future-v1".into()],
        };
        let taker = TakerToMakerMessage::Hello(hello.clone());
        let maker = MakerToTakerMessage::Hello(hello.clone());
        for bytes in [
            serde_cbor::to_vec(&taker).unwrap(),
            serde_cbor::to_vec(&maker).unwrap(),
        ] {
            send_message(
                &mut sender,
                &serde_cbor::from_slice::<Value>(&bytes).unwrap(),
            )
            .unwrap();
            let mut prefix = [0; 4];
            reader.read_exact(&mut prefix).unwrap();
            assert_eq!(prefix, (bytes.len() as u32).to_be_bytes());
            let mut body = vec![0; bytes.len()];
            reader.read_exact(&mut body).unwrap();
            assert_eq!(&body[..7], b"\xa1\x65Hello");
            let TakerToMakerMessage::Hello(decoded) = serde_cbor::from_slice(&body).unwrap() else {
                panic!()
            };
            assert_eq!(decoded, hello);
        }
    }

    #[test]
    fn compat_swap_details_keep_bitcoin_fields_and_ignore_future_fields() {
        let details = SwapDetails {
            id: "swap-compat".into(),
            features: vec!["taproot".into()],
            amount: Amount::from_sat(123_456),
            tx_count: 3,
            incoming_count: 2,
            max_input_budget: 4,
            feerate: 5,
            timelock: 800_100,
            refund_locktime_offset: 60,
        };
        let mut value = to_value(TakerToMakerMessage::SwapDetails(details.clone())).unwrap();
        let Value::Map(outer) = &mut value else {
            panic!()
        };
        let Value::Map(body) = outer.get_mut(&Value::Text("SwapDetails".into())).unwrap() else {
            panic!()
        };
        assert!(!body.contains_key(&Value::Text("protocol_version".into())));
        body.insert(Value::Text("future".into()), Value::Bool(true));
        let TakerToMakerMessage::SwapDetails(decoded) =
            serde_cbor::from_slice(&serde_cbor::to_vec(&value).unwrap()).unwrap()
        else {
            panic!()
        };
        assert_eq!(decoded, details);
        assert_eq!(decoded.protocol(), Some(ProtocolVersion::Taproot));
    }
}
