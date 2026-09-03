//! Taproot (MuSig2) message verification for the Taker.
//!
//! Verifies Taproot contract data received from makers during the swap flow.

use bitcoin::{
    hashes::{sha256, Hash},
    opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_DROP, OP_EQUALVERIFY, OP_SHA256},
    script::Instruction,
    secp256k1::{Secp256k1, XOnlyPublicKey},
    PublicKey,
};

use crate::{
    protocol::{
        common_messages::ProtocolVersion, contract::sum_claimed_amounts,
        contract2::extract_hash_from_hashlock, musig_interface::get_aggregated_pubkey_compat,
        taproot_messages::TaprootContractData,
    },
    utill::estimate_maker_reimbursable_fee_for_input_counts_sats,
};

use super::{api::Taker, error::TakerError};

fn verify_internal_key(
    claimed: XOnlyPublicKey,
    maker_pubkey: &PublicKey,
    next_hop_pubkey: &PublicKey,
    maker_idx: usize,
    contract_idx: usize,
) -> Result<(), TakerError> {
    let mut ordered_pubkeys = [maker_pubkey, next_hop_pubkey];
    ordered_pubkeys.sort_by_key(|pk| pk.inner.serialize());
    let expected = get_aggregated_pubkey_compat(ordered_pubkeys[0].inner, ordered_pubkeys[1].inner)
        .map_err(|e| {
            TakerError::General(format!(
                "Maker {} Taproot internal key {} aggregation failed: {:?}",
                maker_idx, contract_idx, e
            ))
        })?;
    if claimed != expected {
        return Err(TakerError::General(format!(
            "Maker {} Taproot internal key {} does not match the expected MuSig2 aggregate",
            maker_idx, contract_idx
        )));
    }
    Ok(())
}

impl Taker {
    /// Verify a maker's Taproot contract data response.
    pub(crate) fn verify_maker_taproot_contract(
        &self,
        contract: &TaprootContractData,
        maker_idx: usize,
        expected_next_hop_pubkey: PublicKey,
        expected_locktime: u32,
        expected_amount: Option<bitcoin::Amount>,
    ) -> Result<(), TakerError> {
        let params = &self.swap_state()?.params;
        let max_count = params.max_tx_count() as usize;
        let max_inputs_per_tx = params.max_utxos_per_tx() as usize;

        if contract.contract_txs.is_empty() || contract.contract_txs.len() > max_count {
            return Err(TakerError::General(format!(
                "Maker {} sent wrong Taproot contract count: expected 1..={}, got {}",
                maker_idx,
                max_count,
                contract.contract_txs.len()
            )));
        }
        // QA: Maker-controlled Taproot metadata must stay 1:1 with the actual
        // contract txs, otherwise later amount checks can read the wrong claim.
        if contract.contract_txs.len() != contract.amounts.len() {
            return Err(TakerError::General(format!(
                "Maker {} Taproot contract_txs count ({}) doesn't match amounts count ({})",
                maker_idx,
                contract.contract_txs.len(),
                contract.amounts.len()
            )));
        }

        // Amounts must be non-zero
        for (i, amount) in contract.amounts.iter().enumerate() {
            if *amount == bitcoin::Amount::ZERO {
                return Err(TakerError::General(format!(
                    "Maker {} Taproot contract amount {} is zero",
                    maker_idx, i
                )));
            }
        }

        // Verify hashlock script contains expected hash
        let expected_hash: [u8; 32] =
            sha256::Hash::hash(&self.swap_state()?.preimage).to_byte_array();
        let actual_hash = extract_hash_from_hashlock(&contract.hashlock_script).map_err(|e| {
            TakerError::General(format!(
                "Maker {} Taproot hashlock script is invalid: {:?}",
                maker_idx, e
            ))
        })?;

        if actual_hash != expected_hash {
            return Err(TakerError::General(format!(
                "Maker {} Taproot hashlock script has wrong hash",
                maker_idx
            )));
        }

        // QA: Count-only script checks accepted malformed Taproot leaves. Match
        // the full templates so recovery/cooperative spends use expected paths.
        // Verify hashlock script has expected format (5 instructions):
        // OP_SHA256 <hash> OP_EQUALVERIFY <pubkey> OP_CHECKSIG
        let hashlock_instruction_count = contract.hashlock_script.instructions().count();
        if hashlock_instruction_count != 5 {
            return Err(TakerError::General(format!(
                "Maker {} Taproot hashlock script has {} instructions, expected 5",
                maker_idx, hashlock_instruction_count
            )));
        }
        let hashlock_instructions = contract
            .hashlock_script
            .instructions()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                TakerError::General(format!(
                    "Maker {} Taproot hashlock script parse error: {:?}",
                    maker_idx, e
                ))
            })?;
        if !matches!(
            hashlock_instructions.as_slice(),
            [
                Instruction::Op(OP_SHA256),
                Instruction::PushBytes(hash),
                Instruction::Op(OP_EQUALVERIFY),
                Instruction::PushBytes(pubkey),
                Instruction::Op(OP_CHECKSIG),
            ] if hash.as_bytes() == expected_hash && pubkey.len() == 32
        ) {
            return Err(TakerError::General(format!(
                "Maker {} Taproot hashlock script has invalid template",
                maker_idx
            )));
        }

        // Per-contract vectors must all line up with contract_txs.
        if contract.timelock_scripts.len() != contract.contract_txs.len()
            || contract.pubkeys.len() != contract.contract_txs.len()
            || contract.internal_keys.len() != contract.contract_txs.len()
            || contract.tap_tweaks.len() != contract.contract_txs.len()
        {
            return Err(TakerError::General(format!(
                "Maker {} Taproot per-contract vectors have inconsistent lengths",
                maker_idx
            )));
        }

        let secp = Secp256k1::verification_only();

        // Each contract has its own timelock script, internal key and tap tweak,
        // so verify the timelock template, locktime value and P2TR output per contract.
        for (i, tx) in contract.contract_txs.iter().enumerate() {
            if tx.input.len() > max_inputs_per_tx {
                return Err(TakerError::General(format!(
                    "Maker {} Taproot contract tx {} uses {} inputs, above negotiated maximum {}",
                    maker_idx,
                    i,
                    tx.input.len(),
                    max_inputs_per_tx
                )));
            }
            let timelock_script = &contract.timelock_scripts[i];
            verify_internal_key(
                contract.internal_keys[i],
                &contract.pubkeys[i],
                &expected_next_hop_pubkey,
                maker_idx,
                i,
            )?;

            // Verify timelock script has expected format (5 instructions):
            // <locktime> OP_CLTV OP_DROP <pubkey> OP_CHECKSIG
            let timelock_instruction_count = timelock_script.instructions().count();
            if timelock_instruction_count != 5 {
                return Err(TakerError::General(format!(
                    "Maker {} Taproot timelock script {} has {} instructions, expected 5",
                    maker_idx, i, timelock_instruction_count
                )));
            }
            let timelock_instructions = timelock_script
                .instructions()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    TakerError::General(format!(
                        "Maker {} Taproot timelock script {} parse error: {:?}",
                        maker_idx, i, e
                    ))
                })?;
            if !matches!(
                timelock_instructions.as_slice(),
                [
                    _,
                    Instruction::Op(OP_CLTV),
                    Instruction::Op(OP_DROP),
                    Instruction::PushBytes(pubkey),
                    Instruction::Op(OP_CHECKSIG),
                ] if pubkey.len() == 32
            ) {
                return Err(TakerError::General(format!(
                    "Maker {} Taproot timelock script {} has invalid template",
                    maker_idx, i
                )));
            }

            let maker_locktime_val: u64 =
                if let Some(first) = timelock_script.instructions().next() {
                    match first.map_err(|e| {
                        TakerError::General(format!(
                            "Maker {} Taproot timelock script {} parse error: {:?}",
                            maker_idx, i, e
                        ))
                    })? {
                        bitcoin::script::Instruction::PushBytes(locktime_bytes) => {
                            let bytes = locktime_bytes.as_bytes();
                            if bytes.is_empty() {
                                return Err(TakerError::General(format!(
                                    "Maker {} Taproot timelock script {} has empty locktime",
                                    maker_idx, i
                                )));
                            }
                            match bytes.len() {
                                1 => bytes[0] as u64,
                                2 => u16::from_le_bytes([bytes[0], bytes[1]]) as u64,
                                3 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) as u64,
                                4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                                    as u64,
                                _ => {
                                    return Err(TakerError::General(format!(
                                    "Maker {} Taproot timelock {} has unexpected byte length {}",
                                    maker_idx, i,
                                    bytes.len()
                                )));
                                }
                            }
                        }
                        bitcoin::script::Instruction::Op(opcode) => {
                            if let bitcoin::opcodes::Class::PushNum(n) =
                                opcode.classify(bitcoin::opcodes::ClassifyContext::Legacy)
                            {
                                if n <= 0 {
                                    return Err(TakerError::General(format!(
                                        "Maker {} Taproot timelock {} value is non-positive ({})",
                                        maker_idx, i, n
                                    )));
                                }
                                n as u64
                            } else {
                                return Err(TakerError::General(format!(
                                "Maker {} Taproot timelock script {} doesn't start with a locktime",
                                maker_idx, i
                            )));
                            }
                        }
                    }
                } else {
                    return Err(TakerError::General(format!(
                        "Maker {} Taproot timelock script {} is empty",
                        maker_idx, i
                    )));
                };

            if maker_locktime_val == 0 {
                return Err(TakerError::General(format!(
                    "Maker {} Taproot timelock {} value is zero",
                    maker_idx, i
                )));
            }

            // Verify the Maker used exactly the absolute locktime we sent in SwapDetails.
            if maker_locktime_val != expected_locktime as u64 {
                return Err(TakerError::General(format!(
                    "Maker {} Taproot timelock {} value {} does not match expected {}",
                    maker_idx, i, maker_locktime_val, expected_locktime
                )));
            }

            // Reconstruct the expected Taproot output scriptpubkey from the verified
            // scripts and the maker's claimed internal key, then check every contract
            // tx output pays to that address.
            let builder = bitcoin::taproot::TaprootBuilder::new()
                .add_leaf(1, contract.hashlock_script.clone())
                .map_err(|e| {
                    TakerError::General(format!(
                        "Maker {} Taproot tree build failed (hashlock leaf): {:?}",
                        maker_idx, e
                    ))
                })?
                .add_leaf(1, timelock_script.clone())
                .map_err(|e| {
                    TakerError::General(format!(
                        "Maker {} Taproot tree build failed (timelock leaf): {:?}",
                        maker_idx, e
                    ))
                })?;
            let tap_info = builder
                .finalize(&secp, contract.internal_keys[i])
                .map_err(|e| {
                    TakerError::General(format!(
                        "Maker {} Taproot tree finalization failed: {:?}",
                        maker_idx, e
                    ))
                })?;

            // QA: The taker stores the maker-provided tweak for later spending,
            // so reject tweaks that do not match the verified script tree.
            let claimed_tweak = contract.tap_tweak_scalar(i).map_err(|e| {
                TakerError::General(format!(
                    "Maker {} Taproot tweak {} is invalid: {:?}",
                    maker_idx, i, e
                ))
            })?;
            if claimed_tweak != tap_info.tap_tweak().to_scalar() {
                return Err(TakerError::General(format!(
                    "Maker {} Taproot tweak {} does not match internal key and script tree",
                    maker_idx, i
                )));
            }
            let expected_spk = bitcoin::ScriptBuf::new_p2tr_tweaked(tap_info.output_key());

            if tx.input.is_empty() {
                return Err(TakerError::General(format!(
                    "Maker {} Taproot contract tx {} has no inputs",
                    maker_idx, i
                )));
            }
            if tx.output.is_empty() {
                return Err(TakerError::General(format!(
                    "Maker {} Taproot contract tx {} has no outputs",
                    maker_idx, i
                )));
            }
            if tx.output[0].script_pubkey != expected_spk {
                return Err(TakerError::General(format!(
                    "Maker {} Taproot contract tx {} output scriptpubkey does not match \
                     expected P2TR address derived from (internal_key, script_tree)",
                    maker_idx, i
                )));
            }
            if tx.output[0].value != contract.amounts[i] {
                // QA: Prevent underfunded incoming swapcoins where the maker
                // claims a larger amount than the confirmed contract output.
                return Err(TakerError::General(format!(
                    "Maker {} Taproot claimed amount {} for contract tx {} does not match output value {}",
                    maker_idx, contract.amounts[i], i, tx.output[0].value
                )));
            }
        }

        // The maker deducts a fee we can compute exactly from its advertised
        // schedule, so the total must match, not just clear a minimum.
        if let Some(expected) = expected_amount {
            let actual_fee =
                bitcoin::Amount::from_sat(estimate_maker_reimbursable_fee_for_input_counts_sats(
                    ProtocolVersion::Taproot,
                    contract.contract_txs.iter().map(|tx| tx.input.len()),
                ));
            let ceiling_fee =
                bitcoin::Amount::from_sat(estimate_maker_reimbursable_fee_for_input_counts_sats(
                    ProtocolVersion::Taproot,
                    std::iter::repeat_n(max_inputs_per_tx, max_count),
                ));
            let expected = expected
                .checked_add(ceiling_fee)
                .and_then(|amount| amount.checked_sub(actual_fee))
                .ok_or_else(|| {
                    TakerError::General("Failed to price maker Taproot contracts".to_string())
                })?;
            let total_amount =
                sum_claimed_amounts(contract.amounts.iter().copied()).map_err(|amount| {
                    TakerError::General(format!(
                        "Maker {} Taproot contract claims {} above the 21M cap",
                        maker_idx, amount
                    ))
                })?;
            if total_amount != expected {
                return Err(TakerError::General(format!(
                    "Maker {} Taproot contract total amount {} does not match expected {} \
                     (based on maker's advertised fee schedule)",
                    maker_idx, total_amount, expected
                )));
            }
        }

        log::info!(
            "Verified Taproot contract data from maker {}: {} contract txs (hash, timelock, structure, amounts)",
            maker_idx,
            contract.contract_txs.len()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Keypair, PublicKey as SecpPublicKey, Secp256k1, SecretKey};

    use super::*;

    fn pubkey(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
        PublicKey::new(SecpPublicKey::from_secret_key(&secp, &secret))
    }

    #[test]
    fn rejects_wrong_internal_key() {
        let wrong_key = Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[3u8; 32]).unwrap(),
        )
        .x_only_public_key()
        .0;

        let error = verify_internal_key(wrong_key, &pubkey(1), &pubkey(2), 4, 5).unwrap_err();
        assert!(matches!(
            error,
            TakerError::General(message)
                if message == "Maker 4 Taproot internal key 5 does not match the expected MuSig2 aggregate"
        ));
    }
}
