//! Deniability proof generation and verification.
//!
//! A proof lets a wallet assert control of a swap contract without revealing
//! private keys, stored in the swap report file and verifiable against chain data.

use std::fmt;

use bitcoin::{
    ecdsa,
    hashes::{sha256, Hash},
    opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_DROP, OP_EQUALVERIFY, OP_SHA256},
    secp256k1::{self, ecdsa::Signature as SecpEcdsaSignature, Keypair, Secp256k1, SecretKey},
    OutPoint, PublicKey, ScriptBuf, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use crate::{
    protocol::{
        common_messages::ProtocolVersion,
        contract::{read_hashlock_pubkey_from_contract, read_pubkeys_from_multisig_redeemscript},
        contract2::create_taproot_script,
        musig_interface::get_aggregated_pubkey_compat,
    },
    utill::{now_secs, redeemscript_to_scriptpubkey},
};

use super::{
    blockchain::{AnyBlockchain, Blockchain},
    report::SwapRole,
    swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
    WalletError,
};

/// Deniability proof stored in the swap report file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeniabilityProof {
    /// Swap identifier.
    pub swap_id: String,
    /// Wallet role that created this proof.
    pub role: SwapRole,
    /// Protocol version used for this swap.
    pub protocol: ProtocolVersion,
    /// Outgoing contract outpoint linking this proof to the other side of the swap.
    pub outgoing_swapcoin: Option<OutPoint>,
    /// Protocol-specific proof payload.
    pub proof: DeniabilityProofData,
    /// Unix timestamp (seconds) when the proof was created.
    pub created_at: u64,
}

/// Protocol-specific proof payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeniabilityProofData {
    /// Taproot/MuSig2 proof variant.
    Taproot(TaprootDeniabilityProof),
    /// Legacy P2WSH proof variant.
    Legacy(LegacyDeniabilityProof),
}

/// Taproot/MuSig2 deniability proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaprootDeniabilityProof {
    /// On-chain outpoint of the P2TR contract output.
    pub contract_outpoint: OutPoint,
    /// Aggregate MuSig2 internal key of the contract output.
    pub internal_key: XOnlyPublicKey,
    /// Hashlock leaf script.
    pub hashlock_script: ScriptBuf,
    /// Timelock leaf script.
    pub timelock_script: ScriptBuf,
    /// Claimant's MuSig2 public key.
    pub pub_mine_musig: PublicKey,
    /// Counterparty's MuSig2 public key.
    pub pub_other_musig: PublicKey,
    /// Claimant's hashlock public key (x-only).
    pub pub_mine_hashlock: XOnlyPublicKey,
    /// Schnorr signature over the proof message using the MuSig2 key.
    pub sig_musig: secp256k1::schnorr::Signature,
    /// Schnorr signature over the proof message using the hashlock key.
    pub sig_hashlock: secp256k1::schnorr::Signature,
}

/// Legacy P2WSH deniability proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyDeniabilityProof {
    /// On-chain outpoint of the 2-of-2 multisig funding output.
    pub funding_outpoint: OutPoint,
    /// HTLC redeemscript (hashlock/timelock contract).
    pub htlc_redeemscript: ScriptBuf,
    /// 2-of-2 multisig redeemscript for the funding output.
    pub multisig_redeemscript: ScriptBuf,
    /// Claimant's multisig public key.
    pub pub_mine_multi: PublicKey,
    /// Counterparty's multisig public key.
    pub pub_other_multi: PublicKey,
    /// Claimant's hashlock public key.
    pub pub_mine_hashlock: PublicKey,
    /// ECDSA signature over the proof message using the multisig key.
    pub sig_multi: ecdsa::Signature,
    /// ECDSA signature over the proof message using the hashlock key.
    pub sig_hashlock: ecdsa::Signature,
}

/// One proof paired with its chain-verification result.
pub type ProofVerifyResult = (DeniabilityProof, Result<(), DeniabilityProofError>);

/// Proof verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeniabilityProofError {
    /// Proof data is internally inconsistent.
    InvalidProof(&'static str),
    /// On-chain output does not match the proof.
    ChainMismatch(&'static str),
    /// Signature failed verification.
    BadSignature(&'static str),
    /// RPC or other external failure.
    General(String),
}

impl fmt::Display for DeniabilityProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProof(msg) => write!(f, "invalid proof: {msg}"),
            Self::ChainMismatch(msg) => write!(f, "chain mismatch: {msg}"),
            Self::BadSignature(msg) => write!(f, "bad signature: {msg}"),
            Self::General(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for DeniabilityProofError {}

/// SHA256 message signed to assert control of a swap contract outpoint.
fn proof_message(protocol: ProtocolVersion, outpoint: OutPoint) -> secp256k1::Message {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"openswap-deniability-proof-v1");
    bytes.extend_from_slice(format!("{protocol:?}").as_bytes());
    bytes.extend_from_slice(outpoint.to_string().as_bytes());
    secp256k1::Message::from_digest_slice(sha256::Hash::hash(&bytes).as_byte_array())
        .expect("sha256 digest is always 32 bytes")
}

/// Schnorr-signs `msg` with `privkey`.
fn schnorr_sign(privkey: &SecretKey, msg: &secp256k1::Message) -> secp256k1::schnorr::Signature {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, privkey);
    secp.sign_schnorr(msg, &keypair)
}

/// ECDSA-signs `msg` with `privkey` using low-R and SIGHASH_ALL.
fn ecdsa_sign(privkey: &SecretKey, msg: &secp256k1::Message) -> ecdsa::Signature {
    let secp = Secp256k1::new();
    ecdsa::Signature {
        signature: secp.sign_ecdsa_low_r(msg, privkey),
        sighash_type: bitcoin::sighash::EcdsaSighashType::All,
    }
}

/// Derives a compressed `PublicKey` from a secret key.
fn secret_key_pubkey(privkey: &SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey {
        compressed: true,
        inner: secp256k1::PublicKey::from_secret_key(&secp, privkey),
    }
}

/// Derives an x-only public key from a secret key.
fn secret_key_xonly(privkey: &SecretKey) -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, privkey)).0
}

impl DeniabilityProof {
    /// Builds a proof from an incoming swapcoin, dispatching on protocol version.
    pub(crate) fn from_incoming_swapcoin(
        swapcoin: &IncomingSwapCoin,
        role: SwapRole,
        outgoing_swapcoin: Option<OutPoint>,
    ) -> Result<Self, WalletError> {
        let swap_id = swapcoin
            .swap_id
            .clone()
            .ok_or_else(|| WalletError::General("Missing swap_id for deniability proof".into()))?;

        match swapcoin.protocol {
            ProtocolVersion::Taproot => {
                let contract_outpoint = OutPoint {
                    txid: swapcoin.contract_tx.compute_txid(),
                    vout: swapcoin.get_contract_output_vout(),
                };
                let my_privkey = swapcoin.privkey()?;
                let hashlock_privkey = swapcoin.hashlock_privkey;
                let msg = proof_message(ProtocolVersion::Taproot, contract_outpoint);
                let data = TaprootDeniabilityProof {
                    contract_outpoint,
                    internal_key: swapcoin.internal_key()?,
                    hashlock_script: swapcoin.hashlock_script.clone().ok_or_else(|| {
                        WalletError::General("Missing Taproot hashlock script".into())
                    })?,
                    timelock_script: swapcoin.timelock_script.clone().ok_or_else(|| {
                        WalletError::General("Missing Taproot timelock script".into())
                    })?,
                    pub_mine_musig: swapcoin.pubkey()?,
                    pub_other_musig: swapcoin.other_pubkey()?,
                    pub_mine_hashlock: secret_key_xonly(&hashlock_privkey),
                    sig_musig: schnorr_sign(&my_privkey, &msg),
                    sig_hashlock: schnorr_sign(&hashlock_privkey, &msg),
                };
                Ok(Self {
                    swap_id,
                    role,
                    protocol: ProtocolVersion::Taproot,
                    outgoing_swapcoin,
                    proof: DeniabilityProofData::Taproot(data),
                    created_at: now_secs(),
                })
            }
            ProtocolVersion::Legacy => {
                let funding_outpoint = swapcoin
                    .contract_tx
                    .input
                    .first()
                    .map(|i| i.previous_output)
                    .ok_or_else(|| WalletError::General("Contract tx has no inputs".into()))?;
                let my_privkey = swapcoin.privkey()?;
                let hashlock_privkey = swapcoin.hashlock_privkey;
                let msg = proof_message(ProtocolVersion::Legacy, funding_outpoint);
                let data = LegacyDeniabilityProof {
                    funding_outpoint,
                    htlc_redeemscript: swapcoin.contract_redeemscript.clone().ok_or_else(|| {
                        WalletError::General("Missing legacy HTLC redeemscript".into())
                    })?,
                    multisig_redeemscript: swapcoin.multisig_redeemscript.clone().ok_or_else(
                        || WalletError::General("Missing multisig redeemscript".into()),
                    )?,
                    pub_mine_multi: swapcoin.pubkey()?,
                    pub_other_multi: swapcoin.other_pubkey()?,
                    pub_mine_hashlock: secret_key_pubkey(&hashlock_privkey),
                    sig_multi: ecdsa_sign(&my_privkey, &msg),
                    sig_hashlock: ecdsa_sign(&hashlock_privkey, &msg),
                };
                Ok(Self {
                    swap_id,
                    role,
                    protocol: ProtocolVersion::Legacy,
                    outgoing_swapcoin,
                    proof: DeniabilityProofData::Legacy(data),
                    created_at: now_secs(),
                })
            }
        }
    }

    /// Contract or funding outpoint to fetch from chain for verification.
    pub fn proven_outpoint(&self) -> OutPoint {
        match &self.proof {
            DeniabilityProofData::Taproot(d) => d.contract_outpoint,
            DeniabilityProofData::Legacy(d) => d.funding_outpoint,
        }
    }
}

/// Validates a proof against the confirmed on-chain script pubkey at its proven outpoint.
fn verify_proof(
    proof: &DeniabilityProof,
    chain_spk: &bitcoin::ScriptBuf,
) -> Result<(), DeniabilityProofError> {
    let expected_protocol = match &proof.proof {
        DeniabilityProofData::Taproot(_) => ProtocolVersion::Taproot,
        DeniabilityProofData::Legacy(_) => ProtocolVersion::Legacy,
    };
    if proof.protocol != expected_protocol {
        return Err(DeniabilityProofError::InvalidProof(
            "wrapper protocol does not match proof payload",
        ));
    }
    if proof.swap_id.is_empty() {
        return Err(DeniabilityProofError::InvalidProof("swap_id is missing"));
    }
    if proof.outgoing_swapcoin.is_none() {
        return Err(DeniabilityProofError::InvalidProof(
            "outgoing_swapcoin link is missing",
        ));
    }
    match &proof.proof {
        DeniabilityProofData::Taproot(data) => {
            let (script_pubkey, _) = create_taproot_script(
                data.hashlock_script.clone(),
                data.timelock_script.clone(),
                data.internal_key,
            )
            .map_err(|e| DeniabilityProofError::General(format!("{e:?}")))?;
            if *chain_spk != script_pubkey {
                return Err(DeniabilityProofError::ChainMismatch(
                    "chain output does not match Taproot scripts",
                ));
            }
            let mut ordered = [data.pub_mine_musig, data.pub_other_musig];
            ordered.sort_by_key(|k| k.inner.serialize());
            let aggregate = get_aggregated_pubkey_compat(ordered[0].inner, ordered[1].inner)
                .map_err(|e| DeniabilityProofError::General(format!("{e:?}")))?;
            if aggregate != data.internal_key {
                return Err(DeniabilityProofError::InvalidProof(
                    "MuSig aggregate does not match internal key",
                ));
            }
            let script_hashlock_key = parse_taproot_hashlock_script(&data.hashlock_script)?;
            if script_hashlock_key != data.pub_mine_hashlock {
                return Err(DeniabilityProofError::InvalidProof(
                    "hashlock script does not contain claimant key",
                ));
            }
            parse_taproot_timelock_script(&data.timelock_script)?;
            let msg = proof_message(ProtocolVersion::Taproot, data.contract_outpoint);
            let secp = Secp256k1::new();
            let (musig_xonly, _) = data.pub_mine_musig.inner.x_only_public_key();
            secp.verify_schnorr(&data.sig_musig, &msg, &musig_xonly)
                .map_err(|_| DeniabilityProofError::BadSignature("musig signature"))?;
            secp.verify_schnorr(&data.sig_hashlock, &msg, &data.pub_mine_hashlock)
                .map_err(|_| DeniabilityProofError::BadSignature("hashlock signature"))?;
            Ok(())
        }
        DeniabilityProofData::Legacy(data) => {
            let multisig_spk = redeemscript_to_scriptpubkey(&data.multisig_redeemscript)
                .map_err(|e| DeniabilityProofError::General(format!("{e:?}")))?;
            if *chain_spk != multisig_spk {
                return Err(DeniabilityProofError::ChainMismatch(
                    "chain output does not match multisig redeemscript",
                ));
            }
            let (multi_a, multi_b) =
                read_pubkeys_from_multisig_redeemscript(&data.multisig_redeemscript)
                    .map_err(|e| DeniabilityProofError::General(format!("{e:?}")))?;
            if !((data.pub_mine_multi == multi_a && data.pub_other_multi == multi_b)
                || (data.pub_mine_multi == multi_b && data.pub_other_multi == multi_a))
            {
                return Err(DeniabilityProofError::InvalidProof(
                    "multisig redeemscript does not contain expected keys",
                ));
            }
            let hashlock_key = read_hashlock_pubkey_from_contract(&data.htlc_redeemscript)
                .map_err(|e| DeniabilityProofError::General(format!("{e:?}")))?;
            if hashlock_key != data.pub_mine_hashlock {
                return Err(DeniabilityProofError::InvalidProof(
                    "HTLC redeemscript does not contain claimant hashlock key",
                ));
            }
            if data.sig_multi.sighash_type != bitcoin::sighash::EcdsaSighashType::All
                || data.sig_hashlock.sighash_type != bitcoin::sighash::EcdsaSighashType::All
            {
                return Err(DeniabilityProofError::InvalidProof(
                    "legacy proof signatures must use SIGHASH_ALL",
                ));
            }
            let msg = proof_message(ProtocolVersion::Legacy, data.funding_outpoint);
            let secp = Secp256k1::new();
            let multi_sig =
                SecpEcdsaSignature::from_compact(&data.sig_multi.signature.serialize_compact())
                    .map_err(|e| DeniabilityProofError::General(format!("{e:?}")))?;
            secp.verify_ecdsa(&msg, &multi_sig, &data.pub_mine_multi.inner)
                .map_err(|_| DeniabilityProofError::BadSignature("multisig signature"))?;
            let hashlock_sig =
                SecpEcdsaSignature::from_compact(&data.sig_hashlock.signature.serialize_compact())
                    .map_err(|e| DeniabilityProofError::General(format!("{e:?}")))?;
            secp.verify_ecdsa(&msg, &hashlock_sig, &data.pub_mine_hashlock.inner)
                .map_err(|_| DeniabilityProofError::BadSignature("hashlock signature"))?;
            Ok(())
        }
    }
}

/// Parses a Taproot hashlock leaf script and returns the embedded x-only pubkey.
fn parse_taproot_hashlock_script(
    script: &ScriptBuf,
) -> Result<XOnlyPublicKey, DeniabilityProofError> {
    let instructions: Vec<_> = script.instructions().collect();
    if instructions.len() != 5 {
        return Err(DeniabilityProofError::InvalidProof(
            "Taproot hashlock script has unexpected length",
        ));
    }
    if !matches!(
        instructions[0],
        Ok(bitcoin::script::Instruction::Op(OP_SHA256))
    ) || !matches!(
        instructions[2],
        Ok(bitcoin::script::Instruction::Op(OP_EQUALVERIFY))
    ) || !matches!(
        instructions[4],
        Ok(bitcoin::script::Instruction::Op(OP_CHECKSIG))
    ) {
        return Err(DeniabilityProofError::InvalidProof(
            "Taproot hashlock script has unexpected opcodes",
        ));
    }
    match (&instructions[1], &instructions[3]) {
        (
            Ok(bitcoin::script::Instruction::PushBytes(hash_bytes)),
            Ok(bitcoin::script::Instruction::PushBytes(pubkey_bytes)),
        ) if hash_bytes.len() == 32 && pubkey_bytes.len() == 32 => {
            XOnlyPublicKey::from_slice(pubkey_bytes.as_bytes()).map_err(|e| {
                DeniabilityProofError::General(format!("invalid hashlock pubkey: {e:?}"))
            })
        }
        _ => Err(DeniabilityProofError::InvalidProof(
            "Taproot hashlock script has unexpected pushes",
        )),
    }
}

/// Validates the structure of a Taproot timelock leaf script.
fn parse_taproot_timelock_script(script: &ScriptBuf) -> Result<(), DeniabilityProofError> {
    let instructions: Vec<_> = script.instructions().collect();
    if instructions.len() != 5 {
        return Err(DeniabilityProofError::InvalidProof(
            "Taproot timelock script has unexpected length",
        ));
    }
    if !matches!(
        instructions[1],
        Ok(bitcoin::script::Instruction::Op(OP_CLTV))
    ) || !matches!(
        instructions[2],
        Ok(bitcoin::script::Instruction::Op(OP_DROP))
    ) || !matches!(
        instructions[4],
        Ok(bitcoin::script::Instruction::Op(OP_CHECKSIG))
    ) {
        return Err(DeniabilityProofError::InvalidProof(
            "Taproot timelock script has unexpected opcodes",
        ));
    }
    match (&instructions[0], &instructions[3]) {
        (
            Ok(bitcoin::script::Instruction::PushBytes(locktime_bytes)),
            Ok(bitcoin::script::Instruction::PushBytes(pubkey_bytes)),
        ) if !locktime_bytes.is_empty() && pubkey_bytes.len() == 32 => Ok(()),
        _ => Err(DeniabilityProofError::InvalidProof(
            "Taproot timelock script has unexpected pushes",
        )),
    }
}

/// Builds a deniability proof from an incoming and optional outgoing swapcoin.
pub(crate) fn proof_from_swapcoins(
    incoming: Option<&IncomingSwapCoin>,
    outgoing: Option<&OutgoingSwapCoin>,
    role: SwapRole,
) -> Option<DeniabilityProof> {
    incoming.and_then(|inc| {
        let outgoing_outpoint = outgoing.map(|sc| OutPoint {
            txid: sc.contract_tx.compute_txid(),
            vout: sc.get_contract_output_vout(),
        });
        DeniabilityProof::from_incoming_swapcoin(inc, role, outgoing_outpoint).ok()
    })
}

/// Finds the proof for `swap_id` in the report file and verifies it against chain data.
///
/// Returns `Ok(true)` if the proof is valid, `Ok(false)` if it fails verification,
/// or an outer `Err` if the file cannot be read, parsed, or the swap_id is not found.
pub fn verify_deniability(
    report_path: &std::path::Path,
    blockchain: &AnyBlockchain,
    swap_id: &str,
) -> Result<bool, std::io::Error> {
    let content = std::fs::read_to_string(report_path)?;
    let report: super::report::SwapReportFile =
        serde_json::from_str(&content).map_err(std::io::Error::other)?;

    let proof = report
        .deniability_proofs
        .into_iter()
        .find(|p| p.swap_id == swap_id)
        .ok_or_else(|| {
            std::io::Error::other(format!("no deniability proof found for swap {swap_id}"))
        })?;

    let outpoint = proof.proven_outpoint();
    let tx_info = blockchain
        .get_raw_transaction_info(&outpoint.txid, None)
        .map_err(|e| std::io::Error::other(format!("RPC: {e}")))?;
    if tx_info.confirmations.unwrap_or(0) == 0 {
        return Err(std::io::Error::other(
            "transaction not yet confirmed; retry after more blocks",
        ));
    }
    let chain_spk = tx_info
        .vout
        .get(outpoint.vout as usize)
        .ok_or_else(|| std::io::Error::other("outpoint vout out of bounds"))?
        .script_pub_key
        .script()
        .map_err(|e| std::io::Error::other(format!("RPC script decode: {e}")))?;

    Ok(verify_proof(&proof, &chain_spk).is_ok())
}
