//! Legacy (ECDSA) message verification for the Taker.
//!
//! Verifies every message received from makers during the legacy swap flow.
//! A malicious maker could send invalid signatures, wrong scripts, or
//! mismatched hash values — these checks catch all of those.

use bitcoin::{
    hashes::{hash160::Hash as Hash160, Hash},
    Amount, PublicKey, ScriptBuf, Transaction,
};

use crate::{
    protocol::{
        contract::{
            check_reedemscript_is_multisig, read_contract_locktime,
            read_hashlock_pubkey_from_contract, read_hashvalue_from_contract,
            read_pubkeys_from_multisig_redeemscript, sum_claimed_amounts, validate_contract_tx,
            verify_contract_tx_sig,
        },
        legacy_messages::SenderContractTxInfo,
    },
    utill::{get_taker_dir, redeemscript_to_scriptpubkey},
};

use super::{api::Taker, error::TakerError};

impl Taker {
    /// Verify sender contract signatures received from the first maker.
    ///
    /// Each signature must be valid against the corresponding outgoing swapcoin's
    /// contract tx, multisig redeemscript, funding amount, and the maker's pubkey.
    pub(crate) fn verify_sender_sigs(
        &self,
        sigs: &[bitcoin::ecdsa::Signature],
    ) -> Result<(), TakerError> {
        let outgoing = &self.swap_state()?.outgoing_swapcoins;

        for (i, (sig, swapcoin)) in sigs.iter().zip(outgoing.iter()).enumerate() {
            let other_pubkey = swapcoin.other_pubkey.ok_or_else(|| {
                TakerError::General(format!(
                    "Outgoing swapcoin {} missing other_pubkey for sig verification",
                    i
                ))
            })?;
            let my_pubkey = swapcoin.my_pubkey.ok_or_else(|| {
                TakerError::General(format!(
                    "Outgoing swapcoin {} missing my_pubkey for sig verification",
                    i
                ))
            })?;

            let multisig_redeemscript =
                crate::protocol::contract::create_multisig_redeemscript(&my_pubkey, &other_pubkey);

            verify_contract_tx_sig(
                &swapcoin.contract_tx,
                &multisig_redeemscript,
                swapcoin.funding_amount,
                &other_pubkey,
                &sig.signature,
            )
            .map_err(|e| {
                TakerError::General(format!(
                    "Invalid sender contract signature {} from maker: {:?}",
                    i, e
                ))
            })?;
        }

        log::info!(
            "Verified {} sender contract signatures from first maker",
            sigs.len()
        );
        Ok(())
    }

    /// Verify sender contract signatures received from a forwarded maker.
    ///
    /// Uses `SenderContractTxInfo` (from the current maker's response) rather than
    /// outgoing swapcoins (which only exist for the first hop).
    pub(crate) fn verify_sender_sigs_from_info(
        &self,
        sigs: &[bitcoin::ecdsa::Signature],
        senders_info: &[SenderContractTxInfo],
    ) -> Result<(), TakerError> {
        for (i, (sig, info)) in sigs.iter().zip(senders_info.iter()).enumerate() {
            let (pubkey1, pubkey2) =
                read_pubkeys_from_multisig_redeemscript(&info.multisig_redeemscript)?;

            // The signature must be valid for one of the two multisig pubkeys
            let valid = verify_contract_tx_sig(
                &info.contract_tx,
                &info.multisig_redeemscript,
                info.funding_amount,
                &pubkey1,
                &sig.signature,
            )
            .is_ok()
                || verify_contract_tx_sig(
                    &info.contract_tx,
                    &info.multisig_redeemscript,
                    info.funding_amount,
                    &pubkey2,
                    &sig.signature,
                )
                .is_ok();

            if !valid {
                return Err(TakerError::General(format!(
                    "Invalid forwarded sender contract signature {} from maker",
                    i
                )));
            }
        }

        log::info!(
            "Verified {} forwarded sender contract signatures",
            sigs.len()
        );
        Ok(())
    }

    /// Verify receiver contract signatures from a previous maker.
    ///
    /// The receiver contract tx is signed by the previous maker using one of the
    /// pubkeys from the multisig redeemscript.
    pub(crate) fn verify_receiver_sigs(
        &self,
        sigs: &[bitcoin::ecdsa::Signature],
        receivers_txs: &[Transaction],
        prev_senders_info: &[SenderContractTxInfo],
    ) -> Result<(), TakerError> {
        if sigs.len() != receivers_txs.len() || sigs.len() != prev_senders_info.len() {
            return Err(TakerError::General(format!(
                "Wrong number of receiver signatures: expected {}, got {}",
                receivers_txs.len(),
                sigs.len()
            )));
        }

        for (i, ((sig, tx), info)) in sigs
            .iter()
            .zip(receivers_txs.iter())
            .zip(prev_senders_info.iter())
            .enumerate()
        {
            let (pubkey1, pubkey2) =
                read_pubkeys_from_multisig_redeemscript(&info.multisig_redeemscript)?;

            let valid = verify_contract_tx_sig(
                tx,
                &info.multisig_redeemscript,
                info.funding_amount,
                &pubkey1,
                &sig.signature,
            )
            .is_ok()
                || verify_contract_tx_sig(
                    tx,
                    &info.multisig_redeemscript,
                    info.funding_amount,
                    &pubkey2,
                    &sig.signature,
                )
                .is_ok();

            if !valid {
                return Err(TakerError::General(format!(
                    "Invalid receiver contract signature {} from maker",
                    i
                )));
            }
        }

        log::info!("Verified {} receiver contract signatures", sigs.len());
        Ok(())
    }

    /// Verify the maker's sender contract data from `ReqContractSigsAsRecvrAndSender`.
    pub(crate) fn verify_maker_sender_contracts(
        &self,
        senders_info: &[SenderContractTxInfo],
        maker_idx: usize,
        next_multisig_pubkeys: &[PublicKey],
        next_hashlock_pubkeys: &[PublicKey],
        refund_locktime: u16,
        expected_amount: Option<Amount>,
    ) -> Result<(), TakerError> {
        let expected_count = self.swap_state()?.params.tx_count as usize;
        if senders_info.len() != expected_count {
            return Err(TakerError::General(format!(
                "Wrong number of maker sender contracts: expected {}, got {}",
                expected_count,
                senders_info.len()
            )));
        }

        let expected_hashvalue = Hash160::hash(&self.swap_state()?.preimage);

        // The taker receives only the final maker's outgoing contracts.
        let is_final_maker = maker_idx + 1 == self.swap_state()?.makers.len();
        let blocklist_data_dir = if self.config.check_blocklist.unwrap_or(false) && is_final_maker {
            Some(
                self.config
                    .data_dir
                    .clone()
                    .map(Ok)
                    .unwrap_or_else(get_taker_dir)?,
            )
        } else {
            None
        };

        for (i, info) in senders_info.iter().enumerate() {
            if let Some(data_dir) = &blocklist_data_dir {
                let wallet = self.read_wallet()?;
                crate::blocklist::screen_funding_tx(
                    data_dir,
                    wallet.store.network,
                    &wallet,
                    &info.funding_tx,
                )?;
            }

            // Validate 2-of-2 multisig format
            check_reedemscript_is_multisig(&info.multisig_redeemscript).map_err(|e| {
                TakerError::General(format!(
                    "Sender contract {} has invalid multisig redeemscript: {:?}",
                    i, e
                ))
            })?;

            // Verify contract tx spends from the provided funding tx
            if info.contract_tx.input.is_empty() {
                return Err(TakerError::General(format!(
                    "Sender contract {} contract_tx has no inputs",
                    i
                )));
            }
            let contract_input_txid = info.contract_tx.input[0].previous_output.txid;
            let expected_funding_txid = info.funding_tx.compute_txid();
            if contract_input_txid != expected_funding_txid {
                return Err(TakerError::General(format!(
                    "Sender contract {} contract_tx references wrong funding tx: expected {}, got {}",
                    i, expected_funding_txid, contract_input_txid
                )));
            }
            // QA: A malicious Legacy maker can provide a real funding tx while
            // making the contract spend a different output than the advertised
            // 2-of-2 multisig. Bind the contract input to the exact funding
            // output script and value before accepting maker sender data.
            let funding_vout = info.contract_tx.input[0].previous_output.vout as usize;
            let funding_output = info.funding_tx.output.get(funding_vout).ok_or_else(|| {
                TakerError::General(format!(
                    "Sender contract {} references missing funding output {}",
                    i, funding_vout
                ))
            })?;
            let expected_multisig_spk = redeemscript_to_scriptpubkey(&info.multisig_redeemscript)?;
            if funding_output.script_pubkey != expected_multisig_spk {
                return Err(TakerError::General(format!(
                    "Sender contract {} funding output does not pay to advertised multisig",
                    i
                )));
            }
            if funding_output.value != info.funding_amount {
                return Err(TakerError::General(format!(
                    "Sender contract {} funding output value {} does not match advertised amount {}",
                    i, funding_output.value, info.funding_amount
                )));
            }

            // Validate contract tx structure (1-in, 1-out, output pays to P2WSH of contract redeemscript)
            validate_contract_tx(&info.contract_tx, None, &info.contract_redeemscript).map_err(
                |e| {
                    TakerError::General(format!(
                        "Sender contract {} has invalid contract tx: {:?}",
                        i, e
                    ))
                },
            )?;

            // Verify hash in contract redeemscript matches our preimage
            let hashvalue =
                read_hashvalue_from_contract(&info.contract_redeemscript).map_err(|e| {
                    TakerError::General(format!(
                        "Sender contract {} has unreadable hashvalue: {:?}",
                        i, e
                    ))
                })?;
            if hashvalue != expected_hashvalue {
                return Err(TakerError::General(format!(
                    "Sender contract {} has wrong hashvalue: expected {:?}, got {:?}",
                    i, expected_hashvalue, hashvalue
                )));
            }

            // Verify locktime is positive
            let locktime = read_contract_locktime(&info.contract_redeemscript).map_err(|e| {
                TakerError::General(format!(
                    "Sender contract {} has unreadable locktime: {:?}",
                    i, e
                ))
            })?;
            if locktime == 0 {
                return Err(TakerError::General(format!(
                    "Sender contract {} has zero locktime",
                    i
                )));
            }

            // Verify maker used exactly the locktime the taker requested.
            // For legacy (CSV relative locktime), any deviation is invalid:
            // higher delays recovery, lower could enable early sweeps.
            if locktime != refund_locktime {
                return Err(TakerError::General(format!(
                    "Sender contract {} locktime {} does not match requested refund locktime {}",
                    i, locktime, refund_locktime
                )));
            }

            // Verify multisig contains the expected next-hop pubkey
            if !next_multisig_pubkeys.is_empty() {
                let expected_pubkey = next_multisig_pubkeys[i % next_multisig_pubkeys.len()];
                let (pubkey1, pubkey2) =
                    read_pubkeys_from_multisig_redeemscript(&info.multisig_redeemscript)?;
                if pubkey1 != expected_pubkey && pubkey2 != expected_pubkey {
                    return Err(TakerError::General(format!(
                        "Sender contract {} multisig does not contain expected next-hop pubkey",
                        i
                    )));
                }
            }

            // Verify hashlock pubkey matches what we provided for the next hop
            if !next_hashlock_pubkeys.is_empty() {
                let expected_hashlock = next_hashlock_pubkeys[i % next_hashlock_pubkeys.len()];
                let contract_hashlock = read_hashlock_pubkey_from_contract(
                    &info.contract_redeemscript,
                )
                .map_err(|e| {
                    TakerError::General(format!(
                        "Sender contract {} has unreadable hashlock pubkey: {:?}",
                        i, e
                    ))
                })?;
                if contract_hashlock != expected_hashlock {
                    return Err(TakerError::General(format!(
                        "Sender contract {} hashlock pubkey does not match expected next-hop key",
                        i
                    )));
                }
            }
        }

        // The maker deducts a fee we can compute exactly from its advertised
        // schedule, so the total must match, not just clear a minimum.
        if let Some(expected) = expected_amount {
            let total_funding = sum_claimed_amounts(senders_info.iter().map(|i| i.funding_amount))
                .map_err(|amount| {
                    TakerError::General(format!(
                        "Maker sender contract claims {} above the 21M cap",
                        amount
                    ))
                })?;
            if total_funding != expected {
                return Err(TakerError::General(format!(
                    "Maker sender contracts total funding {} does not match expected {} \
                     (based on maker's advertised fee schedule)",
                    total_funding, expected
                )));
            }
        }

        log::info!(
            "Verified {} maker sender contracts (structure, hashvalue, locktime, pubkeys, amounts)",
            senders_info.len()
        );
        Ok(())
    }

    /// Verify the maker's receiver contract transactions from `ReqContractSigsAsRecvrAndSender`.
    pub(crate) fn verify_maker_receiver_contracts(
        &self,
        receivers_contract_txs: &[Transaction],
        funding_txs: &[Transaction],
        contract_redeemscripts: &[ScriptBuf],
    ) -> Result<(), TakerError> {
        let funding_txids: Vec<_> = funding_txs.iter().map(|tx| tx.compute_txid()).collect();

        for (i, tx) in receivers_contract_txs.iter().enumerate() {
            // Verify basic structure
            if tx.input.len() != 1 || tx.output.len() != 1 {
                return Err(TakerError::General(format!(
                    "Receiver contract tx {} has invalid input/output count: {} inputs, {} outputs",
                    i,
                    tx.input.len(),
                    tx.output.len()
                )));
            }

            // Verify the receiver contract spends from one of the funding transactions
            let input_txid = tx.input[0].previous_output.txid;
            if !funding_txids.contains(&input_txid) {
                return Err(TakerError::General(format!(
                    "Receiver contract tx {} does not spend from expected funding tx (spends from {})",
                    i, input_txid
                )));
            }

            // Verify output pays to P2WSH of the expected contract redeemscript
            if let Some(expected_rs) = contract_redeemscripts.get(i) {
                validate_contract_tx(tx, None, expected_rs).map_err(|e| {
                    TakerError::General(format!(
                        "Receiver contract tx {} output does not pay to expected P2WSH: {:?}",
                        i, e
                    ))
                })?;
            }
        }

        log::info!(
            "Verified {} maker receiver contract txs (structure, funding reference, scriptpubkey, amounts)",
            receivers_contract_txs.len()
        );
        Ok(())
    }
}
