//! Legacy (ECDSA) message verification for the Maker.
//!
//! Verifies taker messages received during the Legacy swap flow, mirroring
//! the taker's `legacy_verification.rs` but from the maker's perspective.

use bitcoin::PublicKey;

use crate::{
    protocol::{
        contract::{
            calculate_pubkey_from_nonce, check_contract_sig_sighash, check_multisig_has_pubkey,
            check_reedemscript_is_multisig, create_multisig_redeemscript, is_contract_out_valid,
            verify_contract_tx_sig,
        },
        legacy_messages::ContractTxInfoForSender,
        Hash160,
    },
    taker::api::REFUND_LOCKTIME_STEP,
    wallet::swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
};

use super::error::MakerError;

/// Verify sender contract tx details before signing (ReqContractSigsForSender)
pub(crate) fn verify_req_contract_sigs_for_sender(
    txs_info: &[ContractTxInfoForSender],
    tweakable_pubkey: &PublicKey,
    hashvalue: &Hash160,
    locktime: u16,
    network_port: u16,
) -> Result<(), MakerError> {
    if txs_info.is_empty() {
        return Err(MakerError::General(
            "Empty sender contract txs info from taker",
        ));
    }

    // `locktime` comes straight off the wire, so a peer picking a value near
    // `u16::MAX` would otherwise panic this thread on overflow.
    let taker_locktime = locktime
        .checked_add(REFUND_LOCKTIME_STEP)
        .ok_or(MakerError::General(
            "Sender contract locktime overflows the refund step",
        ))?;

    for (i, txinfo) in txs_info.iter().enumerate() {
        // Validate multisig redeemscript is a 2-of-2 multisig
        check_reedemscript_is_multisig(&txinfo.multisig_redeemscript).map_err(|e| {
            MakerError::General(
                format!(
                    "Sender contract {} invalid multisig redeemscript: {:?}",
                    i, e
                )
                .leak(),
            )
        })?;

        // Verify maker's derived pubkey is in the multisig
        check_multisig_has_pubkey(
            &txinfo.multisig_redeemscript,
            tweakable_pubkey,
            &txinfo.multisig_nonce,
        )
        .map_err(|e| {
            MakerError::General(
                format!(
                    "Sender contract {} multisig doesn't contain maker's pubkey: {:?}",
                    i, e
                )
                .leak(),
            )
        })?;

        // Validate contract tx structure (1 input, 1 output)
        if txinfo.senders_contract_tx.input.len() != 1
            || txinfo.senders_contract_tx.output.len() != 1
        {
            return Err(MakerError::General(
                format!(
                    "Sender contract tx {} has invalid structure: {} inputs, {} outputs",
                    i,
                    txinfo.senders_contract_tx.input.len(),
                    txinfo.senders_contract_tx.output.len()
                )
                .leak(),
            ));
        }

        // Derive the hashlock pubkey from the nonce and maker's tweakable point
        let hashlock_pubkey = calculate_pubkey_from_nonce(tweakable_pubkey, &txinfo.hashlock_nonce)
            .map_err(|_| {
                MakerError::General(
                    format!("Sender contract {} hashlock key derivation failed", i).leak(),
                )
            })?;

        is_contract_out_valid(
            &txinfo.senders_contract_tx.output[0],
            &hashlock_pubkey,
            &txinfo.timelock_pubkey,
            hashvalue,
            &taker_locktime,
            &0,
        )
        .map_err(|e| {
            MakerError::General(format!("Sender contract {} output invalid: {:?}", i, e).leak())
        })?;
    }

    log::info!(
        "[{}] Verified {} sender contract txs (multisig, pubkeys, structure, P2WSH output)",
        network_port,
        txs_info.len()
    );
    Ok(())
}

/// Verify taker's contract signatures (RespContractSigsForRecvrAndSender).
pub(crate) fn verify_contract_sigs(
    receivers_sigs: &[bitcoin::ecdsa::Signature],
    senders_sigs: &[bitcoin::ecdsa::Signature],
    incoming_swapcoins: &[IncomingSwapCoin],
    outgoing_swapcoins: &[OutgoingSwapCoin],
    network_port: u16,
) -> Result<(), MakerError> {
    for (i, (sig, incoming)) in receivers_sigs
        .iter()
        .zip(incoming_swapcoins.iter())
        .enumerate()
    {
        // The other_pubkey is the taker's pubkey that should have signed this contract
        let other_pubkey = incoming.other_pubkey.ok_or(MakerError::General(
            "Incoming swapcoin missing other_pubkey for signature verification",
        ))?;

        // Build the multisig redeemscript to compute the correct sighash
        let my_pubkey = incoming
            .my_pubkey
            .ok_or(MakerError::General("Incoming swapcoin missing my_pubkey"))?;
        let multisig_redeemscript = create_multisig_redeemscript(&my_pubkey, &other_pubkey);

        check_contract_sig_sighash(sig).map_err(|_| {
            MakerError::General(format!("Receiver signature {} is not SIGHASH_ALL", i).leak())
        })?;
        verify_contract_tx_sig(
            &incoming.contract_tx,
            &multisig_redeemscript,
            incoming.funding_amount,
            &other_pubkey,
            &sig.signature,
        )
        .map_err(|e| {
            MakerError::General(
                format!("Receiver signature {} verification failed: {:?}", i, e).leak(),
            )
        })?;
    }

    // Verify sender signatures on outgoing swapcoins
    for (i, (sig, outgoing)) in senders_sigs
        .iter()
        .zip(outgoing_swapcoins.iter())
        .enumerate()
    {
        let other_pubkey = outgoing.other_pubkey.ok_or(MakerError::General(
            "Outgoing swapcoin missing other_pubkey for signature verification",
        ))?;

        let my_pubkey = outgoing
            .my_pubkey
            .ok_or(MakerError::General("Outgoing swapcoin missing my_pubkey"))?;
        let multisig_redeemscript = create_multisig_redeemscript(&my_pubkey, &other_pubkey);

        check_contract_sig_sighash(sig).map_err(|_| {
            MakerError::General(format!("Sender signature {} is not SIGHASH_ALL", i).leak())
        })?;
        verify_contract_tx_sig(
            &outgoing.contract_tx,
            &multisig_redeemscript,
            outgoing.funding_amount,
            &other_pubkey,
            &sig.signature,
        )
        .map_err(|e| {
            MakerError::General(
                format!("Sender signature {} verification failed: {:?}", i, e).leak(),
            )
        })?;
    }

    log::info!(
        "[{}] Verified {} receiver + {} sender contract signatures",
        network_port,
        receivers_sigs.len(),
        senders_sigs.len()
    );
    Ok(())
}

/// Verify Legacy private key handover from taker.
pub(crate) fn verify_legacy_privkey_handover(
    privkeys: &[crate::protocol::common_messages::SwapPrivkey],
    incoming_swapcoins: &[IncomingSwapCoin],
    network_port: u16,
) -> Result<(), MakerError> {
    if privkeys.len() != incoming_swapcoins.len() {
        return Err(MakerError::General(
            format!(
                "Privkey count {} doesn't match incoming swapcoin count {}",
                privkeys.len(),
                incoming_swapcoins.len()
            )
            .leak(),
        ));
    }

    let secp = bitcoin::secp256k1::Secp256k1::new();

    for (privkey_info, incoming) in privkeys.iter().zip(incoming_swapcoins.iter()) {
        // Derive the public key from the received private key
        let derived_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &privkey_info.key),
        };

        // Verify it matches the expected other_pubkey on the incoming swapcoin
        let expected_pubkey = incoming.other_pubkey.ok_or(MakerError::General(
            "Missing other_pubkey on incoming swapcoin during handover verification",
        ))?;
        if derived_pubkey != expected_pubkey {
            return Err(MakerError::General(
                "Privkey derives pubkey that doesn't match expected other_pubkey",
            ));
        }
    }

    log::info!(
        "[{}] Verified {} Legacy private keys (derived pubkey matches expected)",
        network_port,
        privkeys.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime,
        hashes::Hash,
        secp256k1::{Secp256k1, SecretKey},
        transaction, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };

    use crate::{
        protocol::contract::{create_contract_redeemscript, create_multisig_redeemscript},
        utill::redeemscript_to_scriptpubkey,
    };

    fn pubkey(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
        PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp, &secret,
        ))
    }

    /// One sender contract that passes every check, for the locktime the maker
    /// derives from `locktime` on the wire.
    fn sender_contract(locktime: u16) -> (Vec<ContractTxInfoForSender>, PublicKey, Hash160) {
        let tweakable_pubkey = pubkey(1);
        let multisig_nonce = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let hashlock_nonce = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let timelock_pubkey = pubkey(4);
        let hashvalue = Hash160::hash(&[5u8; 32]);

        let maker_multisig_pubkey =
            calculate_pubkey_from_nonce(&tweakable_pubkey, &multisig_nonce).unwrap();
        let multisig_redeemscript =
            create_multisig_redeemscript(&maker_multisig_pubkey, &pubkey(6));
        let hashlock_pubkey =
            calculate_pubkey_from_nonce(&tweakable_pubkey, &hashlock_nonce).unwrap();
        let contract_redeemscript = create_contract_redeemscript(
            &hashlock_pubkey,
            &timelock_pubkey,
            &hashvalue,
            &locktime.wrapping_add(REFUND_LOCKTIME_STEP),
        );

        let senders_contract_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: redeemscript_to_scriptpubkey(&contract_redeemscript).unwrap(),
            }],
        };

        (
            vec![ContractTxInfoForSender {
                multisig_nonce,
                hashlock_nonce,
                timelock_pubkey,
                senders_contract_tx,
                multisig_redeemscript,
                funding_input_value: Amount::from_sat(60_000),
            }],
            tweakable_pubkey,
            hashvalue,
        )
    }

    #[test]
    fn locktime_that_overflows_the_refund_step_is_rejected() {
        let (txs_info, tweakable_pubkey, hashvalue) = sender_contract(u16::MAX);

        let error = verify_req_contract_sigs_for_sender(
            &txs_info,
            &tweakable_pubkey,
            &hashvalue,
            u16::MAX,
            0,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            MakerError::General("Sender contract locktime overflows the refund step")
        ));
    }

    #[test]
    fn normal_locktime_is_accepted() {
        let locktime = 100;
        let (txs_info, tweakable_pubkey, hashvalue) = sender_contract(locktime);

        verify_req_contract_sigs_for_sender(&txs_info, &tweakable_pubkey, &hashvalue, locktime, 0)
            .unwrap();
    }
}
