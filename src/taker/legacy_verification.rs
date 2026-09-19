//! Legacy (ECDSA) message verification for the Taker.
//!
//! Verifies every message received from makers during the legacy swap flow.
//! A malicious maker could send invalid signatures, wrong scripts, or
//! mismatched hash values — these checks catch all of those.

use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    convert::TryFrom,
    thread::sleep,
    time::Duration,
};

use bitcoin::{
    hashes::{hash160::Hash as Hash160, Hash},
    Amount, PublicKey, ScriptBuf, Transaction, Txid,
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
    utill::{fee_at_rate_sats, get_taker_dir, redeemscript_to_scriptpubkey},
    wallet::{Blockchain, WalletError},
};

use super::{
    api::Taker,
    error::TakerError,
    offers::{BanReason, MakerAddress},
};

/// Prevout lookups before the funding-fee check gives up. A backend blip must
/// not abort a swap the taker has already funded.
const MAX_PREVOUT_LOOKUP_ATTEMPTS: u32 = 3;

/// Delay between prevout lookup attempts.
const PREVOUT_LOOKUP_RETRY_DELAY: Duration = Duration::from_secs(2);

impl Taker {
    /// Record a proven maker violation in the offerbook. A persistence
    /// failure is only logged: it must not mask the verification error
    /// that proves the violation.
    pub(crate) fn note_proven_violation(&self, maker_idx: usize) {
        self.note_violation(maker_idx, BanReason::ProvenViolation);
    }

    /// Record a violation that carries its own reason.
    pub(crate) fn note_violation(&self, maker_idx: usize, reason: BanReason) {
        let Ok(swap) = self.swap_state() else {
            return;
        };
        let Some(maker) = swap.makers.get(maker_idx) else {
            return;
        };
        if let Err(e) = self
            .offerbook
            .record_proven_violation(&maker.address, reason)
        {
            log::warn!("Failed to record maker {maker_idx} violation: {e:?}");
        }
    }

    /// Record a proven violation against a maker we know only by address.
    /// Same policy as [`Taker::note_proven_violation`]: a persistence failure
    /// is logged, never raised over the proof itself.
    pub(crate) fn note_proven_violation_at(&self, maker_address: &str) {
        let Ok(address) = MakerAddress::try_from(maker_address.to_string()) else {
            log::warn!("Cannot record a violation for unreadable address {maker_address}");
            return;
        };
        if let Err(e) = self
            .offerbook
            .record_proven_violation(&address, BanReason::ProvenViolation)
        {
            log::warn!("Failed to record violation for {maker_address}: {e:?}");
        }
    }

    /// Ban a maker whose funding never arrived. The backend's definite "I have
    /// none of these" is taken at its word, whichever backend answered.
    pub(crate) fn note_withheld_funding(&self, maker_idx: usize, error: &TakerError) {
        if matches!(error, TakerError::Wallet(WalletError::TxNeverBroadcast(_))) {
            self.note_violation(maker_idx, BanReason::FundingWithheld);
        }
    }

    /// Require every maker funding tx to pay the agreed feerate, priced from
    /// its prevouts and the transaction's own vsize. Backend failure retries
    /// then aborts; a shortfall is recorded as a proven violation.
    pub(crate) fn verify_maker_funding_feerate(
        &self,
        funding_txs: &[Transaction],
        maker_idx: usize,
    ) -> Result<(), TakerError> {
        let feerate = self.swap_state()?.params.swap_feerate();
        let chain = self.read_wallet()?.blockchain.new_connection()?;
        let mut prev_txs: HashMap<Txid, Transaction> = HashMap::new();
        for (i, tx) in funding_txs.iter().enumerate() {
            let mut input_sum = Amount::ZERO;
            for input in &tx.input {
                let prev_outpoint = input.previous_output;
                if let Entry::Vacant(e) = prev_txs.entry(prev_outpoint.txid) {
                    // Fail closed: an unverifiable prevout must never skip the
                    // fee check, but a transient backend error is not the
                    // maker's fault, so retry before giving up.
                    let mut fetched = None;
                    for attempt in 1..=MAX_PREVOUT_LOOKUP_ATTEMPTS {
                        match chain.get_raw_transaction(&prev_outpoint.txid, None) {
                            Ok(prev_tx) => {
                                fetched = Some(prev_tx);
                                break;
                            }
                            Err(err) => {
                                log::warn!(
                                    "Maker {maker_idx} funding tx {i} prevout {} lookup {attempt}/{MAX_PREVOUT_LOOKUP_ATTEMPTS} failed: {err:?}",
                                    prev_outpoint.txid
                                );
                                if attempt < MAX_PREVOUT_LOOKUP_ATTEMPTS {
                                    sleep(PREVOUT_LOOKUP_RETRY_DELAY);
                                }
                            }
                        }
                    }
                    let prev_tx = fetched.ok_or_else(|| {
                        TakerError::General(format!(
                            "Maker {maker_idx} funding tx {i} prevout {} is unavailable; \
                             cannot verify its funding fee",
                            prev_outpoint.txid
                        ))
                    })?;
                    e.insert(prev_tx);
                }
                let prevout = prev_txs[&prev_outpoint.txid]
                    .output
                    .get(prev_outpoint.vout as usize)
                    .ok_or_else(|| {
                        TakerError::General(format!(
                            "Maker {maker_idx} funding tx {i} spends a nonexistent prevout"
                        ))
                    })?;
                input_sum = input_sum.checked_add(prevout.value).ok_or_else(|| {
                    TakerError::General(format!("Maker {maker_idx} funding tx {i} input overflow"))
                })?;
            }
            let output_sum = tx
                .output
                .iter()
                .try_fold(Amount::ZERO, |acc, out| acc.checked_add(out.value))
                .ok_or_else(|| {
                    TakerError::General(format!("Maker {maker_idx} funding tx {i} output overflow"))
                })?;
            let fee = input_sum.checked_sub(output_sum).ok_or_else(|| {
                TakerError::General(format!(
                    "Maker {maker_idx} funding tx {i} outputs exceed its inputs"
                ))
            })?;
            // Price the real transaction: a witness-size estimate can be
            // exceeded by a larger valid witness, quietly dropping the
            // effective feerate below what was negotiated.
            let vsize = tx.vsize() as u64;
            let expected = fee_at_rate_sats(vsize, feerate)
                .ok_or_else(|| TakerError::General("funding fee overflow".to_string()))?;
            // One-sided bound: overpaying costs only the maker. A dropped
            // dust change output lands in the fee, so honest makers sit at or
            // above the bound, never below it.
            if fee.to_sat() < expected {
                self.note_proven_violation(maker_idx);
                return Err(TakerError::General(format!(
                    "Maker {maker_idx} funding tx {i} pays {} sats, below the {expected} sats \
                     the agreed feerate requires",
                    fee.to_sat()
                )));
            }
        }
        Ok(())
    }

    /// Verify sender contract signatures received from the first maker.
    ///
    /// Each signature must be valid against the corresponding outgoing swapcoin's
    /// contract tx, multisig redeemscript, funding amount, and the maker's pubkey.
    pub(crate) fn verify_sender_sigs(
        &self,
        maker_address: &str,
        sigs: &[bitcoin::ecdsa::Signature],
    ) -> Result<(), TakerError> {
        let outgoing = &self.swap_state()?.outgoing_swapcoins;
        // `zip` stops at the shorter side, so a short reply would leave later
        // contracts unsigned and still pass.
        if sigs.len() != outgoing.len() {
            self.note_proven_violation_at(maker_address);
            return Err(TakerError::General(format!(
                "Maker sent {} sender signatures for {} outgoing contracts",
                sigs.len(),
                outgoing.len()
            )));
        }

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
                self.note_proven_violation_at(maker_address);
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
        maker_address: &str,
        sigs: &[bitcoin::ecdsa::Signature],
        senders_info: &[SenderContractTxInfo],
    ) -> Result<(), TakerError> {
        // `zip` stops at the shorter side, so a short reply would leave later
        // contracts unsigned and still pass.
        if sigs.len() != senders_info.len() {
            self.note_proven_violation_at(maker_address);
            return Err(TakerError::General(format!(
                "Maker sent {} sender signatures for {} forwarded contracts",
                sigs.len(),
                senders_info.len()
            )));
        }

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
                self.note_proven_violation_at(maker_address);
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
        next_multisig_pubkeys: &[PublicKey],
        next_hashlock_pubkeys: &[PublicKey],
        refund_locktime: u16,
        expected_amount: Option<Amount>,
        maker_idx: usize,
    ) -> Result<(), TakerError> {
        // The maker reported its frozen plan shape in the Ack; it must
        // deliver exactly that many sender contracts — no more, no fewer.
        let expected_count = self.swap_state()?.makers[maker_idx].funding_splits.len();
        if senders_info.len() != expected_count {
            self.note_proven_violation(maker_idx);
            return Err(TakerError::General(format!(
                "Maker {} sent {} sender contracts, but its reported plan has {} splits",
                maker_idx,
                senders_info.len(),
                expected_count
            )));
        }

        // Each delivered funding tx must use the input count its split was
        // declared with: the next hop's amount was priced from that shape, so
        // a quiet change aborts the swap a hop later.
        for (index, (info, declared)) in senders_info
            .iter()
            .zip(self.swap_state()?.makers[maker_idx].funding_splits.iter())
            .enumerate()
        {
            if info.funding_tx.input.len() as u32 != *declared {
                self.note_proven_violation(maker_idx);
                return Err(TakerError::General(format!(
                    "Maker {} funded split {} with {} inputs, but its reported plan declared {}",
                    maker_idx,
                    index,
                    info.funding_tx.input.len(),
                    declared
                )));
            }
        }

        // One funded output must never back two claims: duplicates would let a
        // single output satisfy the total-amount check more than once.
        let mut seen_outpoints = HashSet::with_capacity(senders_info.len());
        for info in senders_info {
            if let Some(input) = info.contract_tx.input.first() {
                if !seen_outpoints.insert(input.previous_output) {
                    self.note_proven_violation(maker_idx);
                    return Err(TakerError::General(format!(
                        "Maker {} sent a duplicate sender contract for funding outpoint {}",
                        maker_idx, input.previous_output
                    )));
                }
            }
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
                self.note_proven_violation(maker_idx);
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

        // The deduction must equal the policy price of the actual funding
        // txs: the swap fee and sweep price are already in `expected_amount`,
        // so the funding fee is priced per real input count, capped at the
        // negotiated budget. Exact equality, not a minimum.
        if let Some(forwardable) = expected_amount {
            let expected = self.expected_hop_total(
                forwardable,
                senders_info.iter().map(|i| i.funding_tx.input.len()),
            )?;
            let total_funding = sum_claimed_amounts(senders_info.iter().map(|i| i.funding_amount))
                .map_err(|amount| {
                    TakerError::General(format!(
                        "Maker sender contract claims {} above the 21M cap",
                        amount
                    ))
                })?;
            if total_funding != expected {
                self.note_proven_violation(maker_idx);
                return Err(TakerError::General(format!(
                    "Maker {maker_idx} sender contracts total funding {total_funding} does not \
                     match the negotiated hop total {expected}"
                )));
            }
        }

        let maker_funding_txs: Vec<Transaction> = senders_info
            .iter()
            .map(|info| info.funding_tx.clone())
            .collect();
        self.verify_maker_funding_feerate(&maker_funding_txs, maker_idx)?;

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
