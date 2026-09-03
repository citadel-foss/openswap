//! Legacy (ECDSA) Protocol Handlers for the Maker.

use std::sync::Arc;

use bitcoin::{secp256k1::SecretKey, Amount, PublicKey, ScriptBuf};
use bitcoind::bitcoincore_rpc::{jsonrpc::error::Error as JsonRpcError, Error as BitcoinRpcError};

use super::{
    error::MakerError,
    handlers::{incoming_within_swap_amount, ConnectionState, Maker, SwapPhase},
};
use crate::{
    protocol::{
        common_messages::{MakerToTakerMessage, PrivateKeyHandover, SwapPrivkey},
        contract::{
            create_multisig_redeemscript, create_receivers_contract_tx,
            read_pubkeys_from_multisig_redeemscript,
        },
        legacy_messages::{FundingTxInfo, LegacyTakerMessage},
    },
    utill::{
        estimate_funding_tx_fee_sats, estimate_maker_reimbursable_fee_for_input_counts_sats,
        redeemscript_to_scriptpubkey,
    },
    wallet::{swapcoin::IncomingSwapCoin, MakerReport, WalletError},
};

/// Handle a Legacy protocol message.
pub fn handle_legacy_message<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    message: LegacyTakerMessage,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    log::debug!(
        "[{}] Handling Legacy message: {} (swap_id: {:?})",
        maker.network_port(),
        message,
        state.swap_id
    );

    match message {
        // Multi-hop coordination messages
        LegacyTakerMessage::ReqContractSigsForSender(req) => {
            process_req_contract_sigs_for_sender(maker, state, req)
        }
        LegacyTakerMessage::ProofOfFunding(pof) => process_proof_of_funding(maker, state, pof),
        LegacyTakerMessage::RespContractSigsForRecvrAndSender(resp) => {
            process_resp_contract_sigs_for_recvr_and_sender(maker, state, resp)
        }
        LegacyTakerMessage::ReqContractSigsForRecvr(req) => {
            process_req_contract_sigs_for_recvr(maker, state, req)
        }

        // Finalization messages
        LegacyTakerMessage::PrivateKeyHandover(handover) => {
            process_legacy_handover(maker, state, handover)
        }
    }
}

// MULTI-HOP COORDINATION HANDLERS

/// Process request for contract signatures for sender.
fn process_req_contract_sigs_for_sender<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    req: crate::protocol::legacy_messages::ReqContractSigsForSender,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    // Allow re-processing in AwaitingSignaturesOrPreimage: when the taker retries
    // after substituting a failed next-hop maker, it reconnects and re-sends this
    // message. The re-signing is safe since no funding has been broadcast yet.
    state.expect_phase(&[
        SwapPhase::AwaitingContractData,
        SwapPhase::AwaitingSignaturesOrPreimage,
    ])?;
    state.check_swap_id(&req.id)?;

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::CloseAtReqContractSigsForSender {
            log::warn!(
                "[{}] Test behavior: closing at ReqContractSigsForSender",
                maker.network_port()
            );
            return Err(MakerError::General(
                "Test: closing at ReqContractSigsForSender",
            ));
        }
    }

    // The contracts we sign here must use the locktime we agreed in SwapDetails;
    // anything else is a taker rewriting the deal after we priced it.
    if req.locktime as u32 != state.timelock {
        log::error!(
            "[{}] ReqContractSigsForSender locktime {} does not match negotiated timelock {}",
            maker.network_port(),
            req.locktime,
            state.timelock
        );
        return Err(MakerError::General(
            "Sender contract locktime does not match the negotiated timelock",
        ));
    }

    log::info!(
        "[{}] Processing ReqContractSigsForSender for swap {} with {} contracts",
        maker.network_port(),
        req.id,
        req.txs_info.len()
    );

    // Verify and sign the sender's contract transactions
    let sigs =
        maker.verify_and_sign_sender_contract_txs(&req.txs_info, &req.hashvalue, req.locktime)?;

    log::info!(
        "[{}] Generated {} signatures for sender contracts",
        maker.network_port(),
        sigs.len()
    );

    // Store connection state for persistence
    maker.store_connection_state(&req.id, state, false)?;

    let response = crate::protocol::legacy_messages::RespContractSigsForSender { id: req.id, sigs };

    Ok(Some(MakerToTakerMessage::RespContractSigsForSender(
        response,
    )))
}

/// Process proof of funding.
fn process_proof_of_funding<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    pof: crate::protocol::legacy_messages::ProofOfFunding,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    // Allow re-processing in AwaitingSignaturesOrPreimage: when the taker retries
    // after substituting a failed next-hop maker, it reconnects and re-sends
    // ProofOfFunding so the Maker creates new outgoing swapcoins with the spare's keys.
    // This is safe since no funding has been broadcast yet at this stage.
    state.expect_phase(&[
        SwapPhase::AwaitingContractData,
        SwapPhase::AwaitingSignaturesOrPreimage,
    ])?;
    state.check_swap_id(&pof.id)?;

    // The fee is charged on `pof.refund_locktime`, so a taker could shrink it here
    // and pay less than what it agreed to. Reject before we build anything from it.
    if pof.refund_locktime as u32 != state.timelock {
        log::error!(
            "[{}] ProofOfFunding refund_locktime {} does not match negotiated timelock {}",
            maker.network_port(),
            pof.refund_locktime,
            state.timelock
        );
        return Err(MakerError::General(
            "ProofOfFunding refund locktime does not match the negotiated timelock",
        ));
    }

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::CloseAtProofOfFunding {
            log::warn!(
                "[{}] Test behavior: closing at ProofOfFunding",
                maker.network_port()
            );
            return Err(MakerError::General("Test: closing at ProofOfFunding"));
        }
    }

    log::info!(
        "[{}] Processing ProofOfFunding for swap {} with {} funding txs",
        maker.network_port(),
        pof.id,
        pof.confirmed_funding_txes.len()
    );

    // Contract count was agreed in SwapDetails and drives how many outgoing
    // contracts we fund, so the taker must not change it here.
    if pof.confirmed_funding_txes.len() != state.tx_count[0] as usize {
        log::error!(
            "[{}] ProofOfFunding tx count {} does not match negotiated {}",
            maker.network_port(),
            pof.confirmed_funding_txes.len(),
            state.tx_count[0]
        );
        return Err(MakerError::General(
            "ProofOfFunding tx count does not match the negotiated tx count",
        ));
    }

    // Checked before the confirmation wait so a bad proof costs us no time.
    // Amounts are peer-supplied, so sum them without panicking.
    let mut declared_incoming = bitcoin::Amount::ZERO;
    for funding_info in &pof.confirmed_funding_txes {
        let funding_output_index = find_funding_output_index(funding_info)?;
        let funding_output = funding_info
            .funding_tx
            .output
            .get(funding_output_index as usize)
            .ok_or(MakerError::General("Funding output not found"))?;
        declared_incoming = declared_incoming
            .checked_add(funding_output.value)
            .ok_or(MakerError::General("Funding output amounts overflow"))?;
    }
    if !incoming_within_swap_amount(declared_incoming, state.swap_amount) {
        log::error!(
            "[{}] ProofOfFunding incoming amount {} exceeds negotiated swap amount {}",
            maker.network_port(),
            declared_incoming,
            state.swap_amount
        );
        return Err(MakerError::General(
            "ProofOfFunding incoming amount exceeds the negotiated swap amount",
        ));
    }

    let hashvalue = maker.verify_proof_of_funding(&pof)?;
    #[cfg(debug_assertions)]
    log::debug!(
        "[CONTRACT_STATE] Role: Maker | Protocol: Legacy | SwapID: {} | ProofFundingTxs: {} | NextHopKeys: {} | RefundLocktime: {} | Status: verified",
        pof.id,
        pof.confirmed_funding_txes.len(),
        pof.next_openswap_info.len(),
        pof.refund_locktime
    );

    log::info!(
        "[{}] Verified proof of funding, hashvalue: {:?}",
        maker.network_port(),
        hashvalue
    );

    state.contract_feerate = pof.contract_feerate;

    let (tweakable_privkey, _, _) = maker.get_tweakable_keypair()?;
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let mut incoming_swapcoins = Vec::new();
    let mut incoming_amount = bitcoin::Amount::ZERO;

    for funding_info in &pof.confirmed_funding_txes {
        let (pubkey1, pubkey2) =
            read_pubkeys_from_multisig_redeemscript(&funding_info.multisig_redeemscript)?;

        let funding_output_index = find_funding_output_index(funding_info)?;
        let funding_output = funding_info
            .funding_tx
            .output
            .get(funding_output_index as usize)
            .ok_or(MakerError::General("Funding output not found"))?;

        let multisig_privkey = tweakable_privkey.add_tweak(&funding_info.multisig_nonce.into())?;
        let multisig_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &multisig_privkey),
        };

        let other_pubkey = if multisig_pubkey == pubkey1 {
            pubkey2
        } else {
            pubkey1
        };

        let hashlock_privkey = tweakable_privkey.add_tweak(&funding_info.hashlock_nonce.into())?;

        let receiver_contract_tx = create_receivers_contract_tx(
            bitcoin::OutPoint {
                txid: funding_info.funding_tx.compute_txid(),
                vout: funding_output_index,
            },
            funding_output.value,
            &funding_info.contract_redeemscript,
        )?;

        let mut incoming_swapcoin = IncomingSwapCoin::new_legacy(
            multisig_privkey,
            other_pubkey,
            receiver_contract_tx,
            funding_info.contract_redeemscript.clone(),
            hashlock_privkey,
            funding_output.value,
        );
        incoming_swapcoin.swap_id = Some(pof.id.clone());

        incoming_swapcoins.push(incoming_swapcoin);
        incoming_amount += funding_output.value;
    }

    state.incoming_swapcoins = incoming_swapcoins;

    // Register incoming contract outputs with watchtower so we detect
    // if the taker broadcasts the maker's incoming contract tx.
    for incoming in &state.incoming_swapcoins {
        let txid = incoming.contract_tx.compute_txid();
        for (vout, txout) in incoming.contract_tx.output.iter().enumerate() {
            maker.register_watch_outpoint(
                bitcoin::OutPoint {
                    txid,
                    vout: vout as u32,
                },
                txout.script_pubkey.clone(),
            )?;
        }
    }

    log::info!(
        "[{}] Created {} incoming swapcoins, total amount: {}",
        maker.network_port(),
        state.incoming_swapcoins.len(),
        incoming_amount
    );

    let swap_fee = maker.calculate_swap_fee(incoming_amount, pof.refund_locktime as u32);
    // The fee stored at swap-details time was computed from the proposed
    // amount; overwrite with the fee on the actual incoming amount so
    // success reports match what was really earned.
    state.service_fee_sats = swap_fee.to_sat();
    let mut mining_fee =
        Amount::from_sat(estimate_funding_tx_fee_sats() * pof.next_openswap_info.len() as u64);
    let mut outgoing_amount = incoming_amount
        .checked_sub(swap_fee)
        .and_then(|amt| amt.checked_sub(mining_fee))
        .ok_or(MakerError::General("Swap fee exceeds incoming amount"))?;
    log::info!(
        "[{}] Incoming: {}, Fee: {}, MiningFee: {}, Outgoing: {}",
        maker.network_port(),
        incoming_amount,
        swap_fee,
        mining_fee,
        outgoing_amount
    );

    // Sync wallet before creating outgoing swaps to get fresh UTXO state.
    log::info!(
        "[{}] Sync at:----process_proof_of_funding----",
        maker.network_port()
    );
    maker.sync_and_save_wallet()?;

    let next_multisig_pubkeys: Vec<PublicKey> = pof
        .next_openswap_info
        .iter()
        .map(|info| info.next_multisig_pubkey)
        .collect();
    let next_hashlock_pubkeys: Vec<PublicKey> = pof
        .next_openswap_info
        .iter()
        .map(|info| info.next_hashlock_pubkey)
        .collect();
    let next_multisig_nonces: Vec<SecretKey> = pof
        .next_openswap_info
        .iter()
        .map(|info| info.next_multisig_nonce)
        .collect();
    let next_hashlock_nonces: Vec<SecretKey> = pof
        .next_openswap_info
        .iter()
        .map(|info| info.next_hashlock_nonce)
        .collect();

    // Reserve UTXOs for this swap to prevent double-spending across concurrent swaps.
    let excluded_utxos = maker.collect_excluded_utxos(&pof.id)?;
    if !excluded_utxos.is_empty() {
        log::info!(
            "[{}] Excluding {} UTXOs from other active swaps",
            maker.network_port(),
            excluded_utxos.len()
        );
    }

    let mut fee_iterations = 0;
    let (funding_txes, mut outgoing_swapcoins, _mining_fees) = loop {
        fee_iterations += 1;
        #[cfg(feature = "integration-test")]
        let funding_amount = if maker.behavior() == super::handlers::MakerBehavior::FeeSkimming {
            outgoing_amount
                .checked_sub(Amount::from_sat(1))
                .ok_or(MakerError::General("Test fee skim exceeds outgoing amount"))?
        } else {
            outgoing_amount
        };
        #[cfg(not(feature = "integration-test"))]
        let funding_amount = outgoing_amount;

        let result = maker.initialize_openswap(
            funding_amount,
            &next_multisig_pubkeys,
            &next_hashlock_pubkeys,
            hashvalue,
            pof.refund_locktime,
            pof.contract_feerate,
            Some(excluded_utxos.clone()),
            state.tx_count[1] as usize,
        )?;
        let actual_mining_fee =
            Amount::from_sat(estimate_maker_reimbursable_fee_for_input_counts_sats(
                state.protocol,
                result.0.iter().map(|tx| tx.input.len()),
            ));
        if actual_mining_fee == mining_fee {
            break result;
        }
        if fee_iterations >= 3 {
            return Err(MakerError::General(
                "Maker funding fee did not converge within input limit",
            ));
        }
        mining_fee = actual_mining_fee;
        outgoing_amount = incoming_amount
            .checked_sub(swap_fee)
            .and_then(|amt| amt.checked_sub(mining_fee))
            .ok_or(MakerError::General("Swap fee exceeds incoming amount"))?;
    };
    for outgoing in &mut outgoing_swapcoins {
        outgoing.swap_id = Some(pof.id.clone());
    }

    // Store reserved outpoints from the funding transactions.
    state.reserve_utxo = funding_txes
        .iter()
        .flat_map(|tx| {
            (0..tx.output.len()).map(move |vout| bitcoin::OutPoint {
                txid: tx.compute_txid(),
                vout: vout as u32,
            })
        })
        .collect();

    state.outgoing_swapcoins = outgoing_swapcoins.clone();
    state.pending_funding_txes = funding_txes.clone();

    let receivers_contract_txs: Vec<bitcoin::Transaction> = state
        .incoming_swapcoins
        .iter()
        .map(|isc| isc.contract_tx.clone())
        .collect();

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut senders_contract_txs_info: Vec<crate::protocol::legacy_messages::SenderContractTxInfo> =
        Vec::new();
    for (i, osc) in outgoing_swapcoins.iter().enumerate() {
        let timelock_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &osc.timelock_privkey),
        };

        let multisig_redeemscript =
            if let (Some(my_pub), Some(other_pub)) = (osc.my_pubkey, osc.other_pubkey) {
                create_multisig_redeemscript(&my_pub, &other_pub)
            } else {
                osc.contract_redeemscript.clone().unwrap_or_default()
            };

        let funding_tx = funding_txes[i].clone();
        #[cfg(not(feature = "integration-test"))]
        let contract_tx = osc.contract_tx.clone();
        #[cfg(feature = "integration-test")]
        let mut contract_tx = osc.contract_tx.clone();

        #[cfg(feature = "integration-test")]
        if maker.behavior() == super::handlers::MakerBehavior::MalformedLegacyFundingOutput {
            let multisig_spk =
                redeemscript_to_scriptpubkey(&multisig_redeemscript).map_err(|e| {
                    MakerError::General(format!("Failed to convert redeemscript: {:?}", e).leak())
                })?;
            if let Some((bad_vout, _)) = funding_tx
                .output
                .iter()
                .enumerate()
                .find(|(_, output)| output.script_pubkey != multisig_spk)
            {
                contract_tx.input[0].previous_output = bitcoin::OutPoint {
                    txid: funding_tx.compute_txid(),
                    vout: bad_vout as u32,
                };
                log::warn!(
                    "[{}] Test behavior: legacy sender contract spends non-multisig funding output",
                    maker.network_port()
                );
            }
        }

        senders_contract_txs_info.push(crate::protocol::legacy_messages::SenderContractTxInfo {
            funding_tx,
            contract_tx,
            timelock_pubkey,
            multisig_redeemscript,
            contract_redeemscript: osc.contract_redeemscript.clone().unwrap_or_default(),
            funding_amount: osc.funding_amount,
            multisig_nonce: next_multisig_nonces[i],
            hashlock_nonce: next_hashlock_nonces[i],
        });
    }

    state.phase = SwapPhase::AwaitingSignaturesOrPreimage;
    maker.store_connection_state(&pof.id, state, false)?;

    log::info!(
        "[{}] Created {} outgoing swapcoins, requesting signatures",
        maker.network_port(),
        outgoing_swapcoins.len()
    );

    #[cfg(feature = "integration-test")]
    if maker.behavior() == super::handlers::MakerBehavior::OverproduceContractData {
        if let Some(extra) = senders_contract_txs_info.first().cloned() {
            senders_contract_txs_info.push(extra);
        }
    }

    #[cfg(feature = "integration-test")]
    if maker.behavior() == super::handlers::MakerBehavior::OverconsumeFundingInputs {
        if let Some(info) = senders_contract_txs_info.first_mut() {
            while info.funding_tx.input.len() <= state.tx_count[1] as usize {
                info.funding_tx.input.push(bitcoin::TxIn::default());
            }
        }
    }

    let response = crate::protocol::legacy_messages::ReqContractSigsAsRecvrAndSender {
        receivers_contract_txs,
        senders_contract_txs_info,
    };

    Ok(Some(MakerToTakerMessage::ReqContractSigsAsRecvrAndSender(
        response,
    )))
}

fn process_resp_contract_sigs_for_recvr_and_sender<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    resp: crate::protocol::legacy_messages::RespContractSigsForRecvrAndSender,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    state.expect_phase(&[SwapPhase::AwaitingSignaturesOrPreimage])?;
    state.check_swap_id(&resp.id)?;

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::CloseAtContractSigsForRecvrAndSender {
            log::warn!(
                "[{}] Test behavior: closing at RespContractSigsForRecvrAndSender",
                maker.network_port()
            );
            return Err(MakerError::General(
                "Test: closing at ContractSigsForRecvrAndSender",
            ));
        }
    }

    log::info!(
        "[{}] Processing RespContractSigsForRecvrAndSender for swap {} ({} receiver sigs, {} sender sigs)",
        maker.network_port(),
        resp.id,
        resp.receivers_sigs.len(),
        resp.senders_sigs.len()
    );

    if resp.receivers_sigs.len() != state.incoming_swapcoins.len() {
        return Err(MakerError::General("Invalid number of receiver signatures"));
    }

    if resp.senders_sigs.len() != state.outgoing_swapcoins.len() {
        return Err(MakerError::General("Invalid number of sender signatures"));
    }

    // Verify all contract signatures before storing them
    super::legacy_verification::verify_contract_sigs(
        &resp.receivers_sigs,
        &resp.senders_sigs,
        &state.incoming_swapcoins,
        &state.outgoing_swapcoins,
        maker.network_port(),
    )?;
    #[cfg(debug_assertions)]
    log::debug!(
        "[CONTRACT_STATE] Role: Maker | Protocol: Legacy | SwapID: {} | ReceiverSigs: {} | SenderSigs: {} | Status: verified",
        resp.id,
        resp.receivers_sigs.len(),
        resp.senders_sigs.len()
    );

    for (sig, incoming) in resp
        .receivers_sigs
        .iter()
        .zip(state.incoming_swapcoins.iter_mut())
    {
        incoming.others_contract_sig = Some(*sig);
    }

    for (sig, outgoing) in resp
        .senders_sigs
        .iter()
        .zip(state.outgoing_swapcoins.iter_mut())
    {
        outgoing.others_contract_sig = Some(*sig);
    }

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::SkipFundingBroadcast {
            log::warn!(
                "[{}] Test behavior: skipping funding broadcast",
                maker.network_port()
            );
            state.phase = SwapPhase::AwaitingPrivateKeyHandover;
            for incoming in &state.incoming_swapcoins {
                maker.save_incoming_swapcoin(incoming)?;
            }
            for outgoing in &state.outgoing_swapcoins {
                maker.save_outgoing_swapcoin(outgoing)?;
            }
            maker.store_connection_state(&resp.id, state, false)?;
            return Err(MakerError::General("Test: skipped funding broadcast"));
        }
    }

    // Arm the watches before anything is committed. Failing here aborts with
    // nothing on-chain; failing after a broadcast would leave funding txs live
    // while recovery still reads `funding_broadcast == false` and discards them.
    for outgoing in &state.outgoing_swapcoins {
        let contract_txid = outgoing.contract_tx.compute_txid();
        for (vout, txout) in outgoing.contract_tx.output.iter().enumerate() {
            maker.register_watch_outpoint(
                bitcoin::OutPoint {
                    txid: contract_txid,
                    vout: vout as u32,
                },
                txout.script_pubkey.clone(),
            )?;
        }
    }
    super::handlers::ensure_watchtower_alive(maker.as_ref())?;

    // Persist swapcoins (now carrying contract signatures) to the wallet
    // store BEFORE broadcasting funding txs. Without this, a crash after
    // broadcast leaves the wallet with no record of these swapcoins,
    // making timelock recovery impossible.
    for incoming in &state.incoming_swapcoins {
        maker.save_incoming_swapcoin(incoming)?;
    }
    for outgoing in &state.outgoing_swapcoins {
        maker.save_outgoing_swapcoin(outgoing)?;
    }

    log::info!(
        "[{}] SECURITY: Broadcasting {} funding txs after receiving signatures",
        maker.network_port(),
        state.pending_funding_txes.len()
    );

    for funding_tx in &state.pending_funding_txes {
        match maker.broadcast_transaction(funding_tx) {
            Ok(txid) => {
                log::info!(
                    "[{}] Broadcast Legacy funding tx: {}",
                    maker.network_port(),
                    txid
                );
            }
            Err(MakerError::Wallet(WalletError::Rpc(BitcoinRpcError::JsonRpc(
                JsonRpcError::Rpc(rpc_error),
            )))) if rpc_error.code == -27 || {
                let message = rpc_error.message.to_ascii_lowercase();
                message.contains("already in block chain")
                    || message.contains("already in mempool")
                    || message.contains("already in utxo set")
                    || message.contains("txn-already-in-mempool")
            } =>
            {
                let txid = funding_tx.compute_txid();
                log::info!(
                    "[{}] Legacy funding tx {} for swap {} was already broadcast",
                    maker.network_port(),
                    txid,
                    resp.id,
                );
            }
            Err(e) => {
                // This captures the Electrum counterpart of the rebroadcast error.
                // Electrum doesn't throw a reliable error. So we manually check if the transaction
                // is already broadcasted. An error here means the backend connection is down.
                let txid = funding_tx.compute_txid();
                if maker.is_transaction_known(&txid) {
                    log::info!(
                        "[{}] Legacy funding tx {} for swap {} was already broadcast",
                        maker.network_port(),
                        txid,
                        resp.id,
                    );
                } else {
                    return Err(e);
                }
            }
        }
    }

    state.pending_funding_txes.clear();
    state.funding_broadcast = true;
    state.phase = SwapPhase::AwaitingPrivateKeyHandover;

    maker.store_connection_state(&resp.id, state, false)?;

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::BroadcastContractAfterSetup {
            log::warn!(
                "[{}] Test behavior: broadcasting contract txs after setup, then closing",
                maker.network_port()
            );
            for outgoing in &state.outgoing_swapcoins {
                // The raw contract_tx is unsigned; a broadcast only relays with
                // both multisig sigs applied. Fail loudly — a silent reject
                // makes breach tests pass on nothing.
                let signed = outgoing
                    .create_signed_contract_tx()
                    .expect("test: contract sigs must be stored by now");
                maker
                    .broadcast_transaction(&signed)
                    .expect("test: malicious contract broadcast must succeed");
            }
            // Remove stored state so taker can't reconnect and complete the swap
            maker.remove_connection_state(&resp.id)?;
            return Err(MakerError::General("Test: broadcast contract after setup"));
        }
    }

    log::info!(
        "[{}] Funding broadcast complete for swap {}",
        maker.network_port(),
        resp.id
    );

    Ok(None)
}

/// Process request for contract signatures for receiver.
fn process_req_contract_sigs_for_recvr<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    req: crate::protocol::legacy_messages::ReqContractSigsForRecvr,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    state.expect_phase(&[SwapPhase::AwaitingPrivateKeyHandover])?;
    state.check_swap_id(&req.id)?;

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::CloseAtContractSigsForRecvr {
            log::warn!(
                "[{}] Test behavior: closing at ReqContractSigsForRecvr",
                maker.network_port()
            );
            return Err(MakerError::General("Test: closing at ContractSigsForRecvr"));
        }
    }

    log::info!(
        "[{}] Processing ReqContractSigsForRecvr for swap {} with {} txs",
        maker.network_port(),
        req.id,
        req.txs.len()
    );

    let mut sigs = Vec::new();
    for (i, txinfo) in req.txs.iter().enumerate() {
        // Validate contract tx structure before signing
        if txinfo.contract_tx.input.len() != 1 || txinfo.contract_tx.output.len() != 1 {
            return Err(MakerError::General(
                format!(
                    "Receiver contract tx {} has invalid structure: {} inputs, {} outputs",
                    i,
                    txinfo.contract_tx.input.len(),
                    txinfo.contract_tx.output.len()
                )
                .leak(),
            ));
        }

        if let Some(outgoing) = maker.find_outgoing_swapcoin(&txinfo.multisig_redeemscript) {
            // Verify the contract tx spends from our funding tx
            if let Some(ref funding_tx) = outgoing.funding_tx {
                let expected_txid = funding_tx.compute_txid();
                let actual_txid = txinfo.contract_tx.input[0].previous_output.txid;
                if actual_txid != expected_txid {
                    return Err(MakerError::General(
                        format!(
                            "Receiver contract tx {} spends from {} but expected {}",
                            i, actual_txid, expected_txid
                        )
                        .leak(),
                    ));
                }
            }

            if let Some(privkey) = outgoing.my_privkey {
                match crate::protocol::contract::sign_contract_tx(
                    &txinfo.contract_tx,
                    &txinfo.multisig_redeemscript,
                    outgoing.funding_amount,
                    &privkey,
                ) {
                    Ok(sig) => {
                        sigs.push(sig);
                        log::debug!("[{}] Signed receiver contract tx", maker.network_port());
                    }
                    Err(e) => {
                        log::warn!(
                            "[{}] Failed to sign receiver contract tx: {:?}",
                            maker.network_port(),
                            e
                        );
                        return Err(MakerError::General("Failed to sign receiver contract tx"));
                    }
                }
            } else {
                log::warn!(
                    "[{}] No private key in outgoing swapcoin",
                    maker.network_port()
                );
                return Err(MakerError::General("No private key in outgoing swapcoin"));
            }
        } else {
            log::warn!(
                "[{}] Could not find matching outgoing swapcoin for multisig",
                maker.network_port()
            );
            return Err(MakerError::General(
                "Could not find matching outgoing swapcoin",
            ));
        }
    }

    log::info!(
        "[{}] Generated {} signatures for receiver contracts",
        maker.network_port(),
        sigs.len()
    );

    let response = crate::protocol::legacy_messages::RespContractSigsForRecvr { id: req.id, sigs };

    Ok(Some(MakerToTakerMessage::RespContractSigsForRecvr(
        response,
    )))
}

/// Process Legacy private key handover.
/// Stores the received privkey on incoming swapcoins, extracts outgoing privkeys
/// as a response, then sweeps.
fn process_legacy_handover<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    handover: PrivateKeyHandover,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    state.expect_phase(&[SwapPhase::AwaitingPrivateKeyHandover])?;
    state.check_swap_id(&handover.id)?;

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::CloseAtHashPreimage {
            log::warn!(
                "[{}] Test behavior: closing at hash preimage / private key handover",
                maker.network_port()
            );
            return Err(MakerError::General("Test: closing at hash preimage"));
        }
    }

    log::info!(
        "[{}] Processing Legacy private key handover for swap {} with {} key(s)",
        maker.network_port(),
        handover.id,
        handover.privkeys.len()
    );

    if state.outgoing_swapcoins.is_empty() {
        return Err(MakerError::General("No outgoing swapcoin found"));
    }

    // Verify the received private keys before proceeding
    super::legacy_verification::verify_legacy_privkey_handover(
        &handover.privkeys,
        &state.incoming_swapcoins,
        maker.network_port(),
    )?;

    // Extract outgoing privkeys for response
    let mut privkeys = Vec::new();
    for outgoing in &state.outgoing_swapcoins {
        let privkey = outgoing
            .my_privkey
            .ok_or(MakerError::General("No private key in outgoing swapcoin"))?;
        privkeys.push(SwapPrivkey {
            identifier: ScriptBuf::new(),
            key: privkey,
        });
    }

    // Store received privkey on incoming swapcoins
    for (i, incoming) in state.incoming_swapcoins.iter_mut().enumerate() {
        if let Some(privkey) = handover.privkeys.get(i) {
            incoming.other_privkey = Some(privkey.key);
        }
    }
    for incoming in &state.incoming_swapcoins {
        maker.save_incoming_swapcoin(incoming)?;
    }

    // Mark swap as completed — sweep happens in the server loop after the
    // response is delivered to the taker.
    state.phase = SwapPhase::Completed;
    #[cfg(debug_assertions)]
    log::debug!(
        "[SWAP_STATE] Source: maker::legacy_handlers::process_legacy_handover | SwapID: {} | Protocol: Legacy | Phase: Completed | Incoming: {} | Outgoing: {}",
        handover.id,
        state.incoming_swapcoins.len(),
        state.outgoing_swapcoins.len()
    );

    // Generate and save maker success report
    emit_maker_success_report(maker, state, &handover.id);

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::CloseAfterSweep {
            // Sweep here rather than letting the error skip the server loop's
            // sweep block, or the preimage only reaches the chain 30s later via
            // idle recovery and the behavior's name is a lie.
            if let Err(e) = maker.sweep_incoming_swapcoins() {
                log::error!("[{}] Test sweep failed: {e:?}", maker.network_port());
            }
            log::warn!(
                "[{}] Test behavior: swept, now closing before handover",
                maker.network_port()
            );
            return Err(MakerError::General("Test: closing after sweep"));
        }
    }

    log::info!(
        "[{}] Legacy swap {} completed successfully, returning {} private key(s)",
        maker.network_port(),
        handover.id,
        privkeys.len()
    );

    let response = PrivateKeyHandover {
        id: handover.id,
        privkeys,
    };

    Ok(Some(MakerToTakerMessage::LegacyPrivateKeyHandover(
        response,
    )))
}

/// Find the index of the funding output in the funding transaction.
fn find_funding_output_index(funding_tx_info: &FundingTxInfo) -> Result<u32, MakerError> {
    let multisig_spk = redeemscript_to_scriptpubkey(&funding_tx_info.multisig_redeemscript)
        .map_err(|e| {
            MakerError::General(format!("Failed to convert redeemscript: {:?}", e).leak())
        })?;
    funding_tx_info
        .funding_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == multisig_spk)
        .map(|index| index as u32)
        .ok_or(MakerError::General(
            "Funding output doesn't match with multisig redeem script",
        ))
}

/// Emit a maker success report after private key handover.
fn emit_maker_success_report<M: Maker>(maker: &Arc<M>, state: &ConnectionState, swap_id: &str) {
    let incoming_total: u64 = state
        .incoming_swapcoins
        .iter()
        .map(|s| s.funding_amount.to_sat())
        .sum();
    let outgoing_total: u64 = state
        .outgoing_swapcoins
        .iter()
        .map(|s| s.funding_amount.to_sat())
        .sum();
    let incoming_txid = state
        .incoming_swapcoins
        .first()
        .map(|s| s.contract_tx.compute_txid().to_string())
        .unwrap_or_else(|| "N/A".to_string());
    let outgoing_txid = state
        .outgoing_swapcoins
        .first()
        .map(|s| s.contract_tx.compute_txid().to_string())
        .unwrap_or_else(|| "N/A".to_string());
    let timelock = state
        .outgoing_swapcoins
        .first()
        .and_then(|s| s.get_timelock())
        .unwrap_or(0);
    let network = maker.network().to_string();

    let report = MakerReport::success(
        swap_id.to_string(),
        state.swap_start_time,
        incoming_total,
        outgoing_total,
        state.service_fee_sats,
        incoming_txid,
        outgoing_txid,
        timelock,
        network,
        state.incoming_swapcoins.first(),
        state.outgoing_swapcoins.first(),
    );
    report.print();
    if let Err(e) = report.save_for_wallet(maker.data_dir(), Some(maker.wallet_name())) {
        log::warn!("Failed to save maker success report: {:?}", e);
    }
}
