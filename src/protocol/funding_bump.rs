//! Replace-by-fee of a stuck funding transaction.
//!
//! The taker asks the funder of a hop whose funding sits unconfirmed (itself
//! for hop 0, the previous maker for later hops) to replace it at a higher
//! feerate. The replacement spends the same inputs and returns the same
//! change; only the contract output shrinks, by the extra fee. The funder pays
//! nothing, every later hop forwards that much less, and so the taker pays.
//!
//! Both versions spend the same coins, so exactly one of them can confirm.
//! Until one does, every party keeps both: whichever confirms is the hop.

use bitcoin::{
    ecdsa::Signature as EcdsaSignature,
    hashes::{sha256, Hash, HashEngine},
    secp256k1::{schnorr::Signature, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey},
    Amount, OutPoint, Transaction,
};
use serde::{Deserialize, Serialize};

use super::error::ProtocolError;

/// Domain tag of the digest the taker signs, so a bump signature can never
/// be read as anything else.
const BUMP_DIGEST_TAG: &[u8] = b"openswap/funding-bump/v1";

/// The feature a swap pins to use funding bumps. Without it neither side
/// sends bump messages or the taker's auth key, and every hop arrives whole.
pub const FUNDING_BUMP_FEATURE: &str = "funding-bump-v1";

/// The most an incoming hop may arrive short of its admitted amount, in
/// percent. Upstream bumps are the only reason for a shortfall; the receiving
/// maker keeps its admitted fee either way, so the bound only caps how far a
/// route's amount can drift from what was agreed.
pub const MAX_BUMP_SHORTFALL_PCT: u64 = 10;

/// Most bumps one hop may take. Each one is a round of messages and, on
/// Legacy, a round of contract signatures, so the count stays small.
pub const MAX_FUNDING_BUMPS: u32 = 3;

/// Ask the funder of a hop to replace its unconfirmed funding at `feerate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BumpFunding {
    /// Unique swap ID.
    pub id: String,
    /// New feerate in sat/vB for every still unconfirmed funding tx of the hop.
    pub feerate: u64,
    /// Strictly increasing per swap, so an earlier request cannot be replayed.
    pub seq: u32,
    /// The taker's signature over the bump digest, made with the key it
    /// declared in `SwapDetails`. Every maker on the route knows the swap id,
    /// so the id alone must not move anyone's money.
    pub signature: Signature,
}

/// Legacy only: the next hop's signatures on the replacement sender
/// contracts, which let the funder broadcast its replacement funding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BumpFundingCommit {
    /// Unique swap ID.
    pub id: String,
    /// The feerate of the proposal being committed.
    pub feerate: u64,
    /// The sequence number of the proposal being committed.
    pub seq: u32,
    /// One signature per proposed contract, in proposal order.
    pub senders_sigs: Vec<EcdsaSignature>,
    /// The taker's signature over the bump digest of the commit step.
    pub signature: Signature,
}

/// One replaced funding transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BumpedFunding {
    /// Index of the funding split in the hop, in contract order.
    pub split: u32,
    /// The replacement. Taproot sends it signed and already broadcast; a
    /// Legacy proposal sends it without signatures, so the taker can check it
    /// but cannot broadcast it before the funder holds its contract signature.
    pub funding_tx: Transaction,
    /// Legacy only: the sender contract spending the replacement's contract
    /// output, for the next hop to sign. `None` on Taproot, where the funding
    /// tx is the contract.
    #[serde(default)]
    pub contract_tx: Option<Transaction>,
}

/// Legacy: the replacements the funder built, awaiting contract signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BumpFundingProposal {
    /// Unique swap ID.
    pub id: String,
    /// One entry per bumped split.
    pub replacements: Vec<BumpedFunding>,
}

/// The replacements are broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundingBumped {
    /// Unique swap ID.
    pub id: String,
    /// One entry per replacement that reached the backend.
    pub replacements: Vec<BumpedFunding>,
}

/// The digest the taker signs to authorize a bump (`commit == false`) or a
/// Legacy commit (`commit == true`) of one hop. `hop` is the first coin the
/// hop's funding spends, the same in every version and in no other hop: every
/// maker of the route knows the swap id, so a request signed for one maker
/// must not move another's funding.
pub(crate) fn bump_digest(
    swap_id: &str,
    hop: &OutPoint,
    feerate: u64,
    seq: u32,
    commit: bool,
) -> Message {
    let mut engine = sha256::Hash::engine();
    engine.input(BUMP_DIGEST_TAG);
    engine.input(&(swap_id.len() as u64).to_le_bytes());
    engine.input(swap_id.as_bytes());
    engine.input(hop.txid.as_byte_array());
    engine.input(&hop.vout.to_le_bytes());
    engine.input(&feerate.to_le_bytes());
    engine.input(&seq.to_le_bytes());
    engine.input(&[u8::from(commit)]);
    Message::from_digest(sha256::Hash::from_engine(engine).to_byte_array())
}

/// Sign a bump authorization with the swap's taker key.
pub(crate) fn sign_bump(
    key: &SecretKey,
    swap_id: &str,
    hop: &OutPoint,
    feerate: u64,
    seq: u32,
    commit: bool,
) -> Signature {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, key);
    secp.sign_schnorr(&bump_digest(swap_id, hop, feerate, seq, commit), &keypair)
}

/// Check a bump authorization against the taker key declared at admission.
pub(crate) fn verify_bump(
    taker_key: &XOnlyPublicKey,
    signature: &Signature,
    swap_id: &str,
    hop: &OutPoint,
    feerate: u64,
    seq: u32,
    commit: bool,
) -> Result<(), ProtocolError> {
    Secp256k1::verification_only()
        .verify_schnorr(
            signature,
            &bump_digest(swap_id, hop, feerate, seq, commit),
            taker_key,
        )
        .map_err(|_| ProtocolError::General("Funding bump is not signed by the swap's taker"))
}

/// Extra fee the version of a funding tx at `new_feerate` pays over the
/// signed `original`, built at `base_feerate`; its contract output is that
/// much lower. Every version is priced against the original, never against
/// the one it replaces, so both sides derive the same version from the rate
/// alone, however many bumps came before or went unanswered. One vbyte of
/// slack keeps the version relayable when a re-signed input comes out a byte
/// longer: the extra fee must cover the relay step on the replacement's own
/// size. The taker pays it, so a maker's fee is judged on its original, never
/// on a bumped version. `None` unless the rate rises.
pub(crate) fn bump_delta_sats(
    original: &Transaction,
    base_feerate: u64,
    new_feerate: u64,
) -> Option<u64> {
    let step = new_feerate
        .checked_sub(base_feerate)
        .filter(|step| *step > 0)?;
    step.checked_mul(original.vsize() as u64 + 1)
}

/// Rebuild a funding tx's `original` with output `contract_vout` lowered by
/// `delta` and no signatures. The inputs, change and every other field stay
/// as they were, so the funder spends the same coins and keeps the same change.
pub(crate) fn unsigned_replacement(
    original: &Transaction,
    contract_vout: usize,
    delta: u64,
    min_contract_value: u64,
) -> Result<Transaction, ProtocolError> {
    let mut replacement = original.clone();
    for input in &mut replacement.input {
        input.witness.clear();
    }
    let output = replacement
        .output
        .get_mut(contract_vout)
        .ok_or(ProtocolError::General(
            "Funding tx has no such contract output",
        ))?;
    output.value = output
        .value
        .checked_sub(Amount::from_sat(delta))
        .filter(|value| value.to_sat() >= min_contract_value)
        .ok_or(ProtocolError::General(
            "Funding bump pushes the contract below its floor",
        ))?;
    Ok(replacement)
}

/// True when `replacement` is `original` with only output `contract_vout`
/// lowered, by exactly `delta`. Signatures are not compared: the funder signs
/// the replacement anew, and a Legacy proposal carries none.
pub(crate) fn is_bumped_replacement(
    original: &Transaction,
    replacement: &Transaction,
    contract_vout: usize,
    delta: u64,
) -> bool {
    let same_inputs = original.input.len() == replacement.input.len()
        && original
            .input
            .iter()
            .zip(&replacement.input)
            .all(|(old, new)| {
                old.previous_output == new.previous_output
                    && old.sequence == new.sequence
                    && old.script_sig == new.script_sig
            });
    let same_outputs = original.output.len() == replacement.output.len()
        && original
            .output
            .iter()
            .zip(&replacement.output)
            .enumerate()
            .all(|(vout, (old, new))| {
                if vout != contract_vout {
                    return old == new;
                }
                old.script_pubkey == new.script_pubkey
                    && old.value.checked_sub(Amount::from_sat(delta)) == Some(new.value)
            });
    original.version == replacement.version
        && original.lock_time == replacement.lock_time
        && same_inputs
        && same_outputs
}

/// Whether an incoming hop that arrived `total` against an admitted `amount`
/// is short only by what upstream bumps can explain: never more than agreed,
/// and at most [`MAX_BUMP_SHORTFALL_PCT`] less.
pub(crate) fn within_bump_shortfall(total: Amount, admitted: Amount) -> bool {
    let Some(shortfall) = admitted.checked_sub(total) else {
        return false;
    };
    shortfall
        .to_sat()
        .checked_mul(100)
        .zip(admitted.to_sat().checked_mul(MAX_BUMP_SHORTFALL_PCT))
        .is_some_and(|(short, allowed)| short <= allowed)
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute::LockTime, hashes::Hash, transaction::Version, OutPoint, ScriptBuf, Sequence,
        TxIn, TxOut, Txid, Witness,
    };

    use super::*;

    fn funding_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_height(800_000).unwrap(),
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::all_zeros(), 1),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::from_slice(&[[7u8; 64]]),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
                },
            ],
        }
    }

    #[test]
    fn bump_delta_prices_the_step_on_the_original_size() {
        let tx = funding_tx();
        let vsize = tx.vsize() as u64;
        assert_eq!(bump_delta_sats(&tx, 2, 5), Some(3 * (vsize + 1)));
        // A rate that does not rise prices nothing.
        assert_eq!(bump_delta_sats(&tx, 5, 5), None);
        assert_eq!(bump_delta_sats(&tx, 5, 4), None);
    }

    #[test]
    fn a_replacement_lowers_only_the_contract_output() {
        let tx = funding_tx();
        let replacement = unsigned_replacement(&tx, 0, 1_000, 500).unwrap();
        assert_eq!(replacement.output[0].value, Amount::from_sat(99_000));
        assert_eq!(replacement.output[1], tx.output[1]);
        assert!(replacement.input[0].witness.is_empty());
        assert!(is_bumped_replacement(&tx, &replacement, 0, 1_000));
        // Any other delta, or a touched change output, is not this bump.
        assert!(!is_bumped_replacement(&tx, &replacement, 0, 999));
        let mut skimmed = replacement.clone();
        skimmed.output[1].value -= Amount::from_sat(1);
        assert!(!is_bumped_replacement(&tx, &skimmed, 0, 1_000));
        let mut other_coins = replacement;
        other_coins.input[0].previous_output.vout = 2;
        assert!(!is_bumped_replacement(&tx, &other_coins, 0, 1_000));
    }

    #[test]
    fn a_replacement_never_drops_the_contract_below_its_floor() {
        let tx = funding_tx();
        assert!(unsigned_replacement(&tx, 0, 99_600, 500).is_err());
        assert!(unsigned_replacement(&tx, 0, 99_500, 500).is_ok());
        assert!(unsigned_replacement(&tx, 0, 100_001, 0).is_err());
        assert!(unsigned_replacement(&tx, 2, 1, 0).is_err());
    }

    #[test]
    fn a_bump_is_authorized_only_by_the_declared_key_for_its_terms() {
        let key = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let other = SecretKey::from_slice(&[4u8; 32]).unwrap();
        let secp = Secp256k1::new();
        let pubkey = key.x_only_public_key(&secp).0;
        let hop = OutPoint::new(bitcoin::Txid::from_byte_array([1; 32]), 0);
        let sig = sign_bump(&key, "00000000000000ab", &hop, 5, 1, false);
        assert!(verify_bump(&pubkey, &sig, "00000000000000ab", &hop, 5, 1, false).is_ok());
        // Another swap, rate, sequence or step does not carry the signature.
        assert!(verify_bump(&pubkey, &sig, "00000000000000ac", &hop, 5, 1, false).is_err());
        assert!(verify_bump(&pubkey, &sig, "00000000000000ab", &hop, 6, 1, false).is_err());
        assert!(verify_bump(&pubkey, &sig, "00000000000000ab", &hop, 5, 2, false).is_err());
        assert!(verify_bump(&pubkey, &sig, "00000000000000ab", &hop, 5, 1, true).is_err());
        let forged = sign_bump(&other, "00000000000000ab", &hop, 5, 1, false);
        assert!(verify_bump(&pubkey, &forged, "00000000000000ab", &hop, 5, 1, false).is_err());
    }

    /// Every maker of the route knows the swap id: a request signed for one
    /// maker's hop must not move another maker's funding.
    #[test]
    fn a_bump_signed_for_one_maker_is_refused_by_another() {
        let key = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let pubkey = key.x_only_public_key(&Secp256k1::new()).0;
        let first = OutPoint::new(bitcoin::Txid::from_byte_array([1; 32]), 0);
        let second = OutPoint::new(bitcoin::Txid::from_byte_array([2; 32]), 0);
        let other_vout = OutPoint::new(first.txid, 1);
        for commit in [false, true] {
            let sig = sign_bump(&key, "00000000000000ab", &first, 5, 1, commit);
            assert!(verify_bump(&pubkey, &sig, "00000000000000ab", &first, 5, 1, commit).is_ok());
            for hop in [&second, &other_vout] {
                assert!(verify_bump(&pubkey, &sig, "00000000000000ab", hop, 5, 1, commit).is_err());
            }
        }
    }

    #[test]
    fn an_incoming_hop_may_fall_short_only_within_the_bound() {
        let admitted = Amount::from_sat(1_000_000);
        assert!(within_bump_shortfall(admitted, admitted));
        assert!(within_bump_shortfall(Amount::from_sat(900_000), admitted));
        assert!(!within_bump_shortfall(Amount::from_sat(899_999), admitted));
        // More than admitted was never reserved.
        assert!(!within_bump_shortfall(
            Amount::from_sat(1_000_001),
            admitted
        ));
    }
}
