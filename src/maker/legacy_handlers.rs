//! Legacy (ECDSA) Protocol Handlers for the Maker.

use std::sync::Arc;

use bitcoin::{secp256k1::SecretKey, Amount, PublicKey, ScriptBuf};

use super::{
    error::MakerError,
    handlers::{
        incoming_matches_swap_amount, is_already_broadcast_error, ConnectionState, Maker, SwapPhase,
    },
};
#[cfg(feature = "integration-test")]
use crate::protocol::contract::sign_contract_tx;
#[cfg(feature = "integration-test")]
use crate::wallet::WalletError;
use crate::{
    protocol::{
        common_messages::{MakerToTakerMessage, PrivateKeyHandover, ProtocolVersion, SwapPrivkey},
        contract::{
            create_multisig_redeemscript, create_receivers_contract_tx,
            read_pubkeys_from_multisig_redeemscript,
        },
        legacy_messages::{FundingTxInfo, LegacyTakerMessage},
    },
    utill::{redeemscript_to_scriptpubkey, sweep_fee_policy_sats},
    wallet::swapcoin::IncomingSwapCoin,
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

    // Well formed signatures over the right contracts, made with a key the
    // taker never agreed to: only its own verification can catch this.
    #[cfg(feature = "integration-test")]
    let sigs =
        if maker.behavior() == super::handlers::MakerBehavior::SignSenderContractsWithWrongKey {
            log::warn!(
                "[{}] Test behavior: signing sender contracts with the wrong key",
                maker.network_port()
            );
            let wrong_key = SecretKey::from_slice(&[7u8; 32]).expect("valid test key");
            req.txs_info
                .iter()
                .map(|info| {
                    sign_contract_tx(
                        &info.senders_contract_tx,
                        &info.multisig_redeemscript,
                        info.funding_input_value,
                        &wrong_key,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            sigs
        };

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

    // The declared incoming count is exact: no under-delivery, no excess.
    if pof.confirmed_funding_txes.len() != state.incoming_count as usize {
        log::error!(
            "[{}] ProofOfFunding tx count {} != declared incoming count {}",
            maker.network_port(),
            pof.confirmed_funding_txes.len(),
            state.incoming_count
        );
        return Err(MakerError::General(
            "ProofOfFunding tx count differs from the declared incoming count",
        ));
    }

    // One next-hop key bundle per frozen split: the taker derived them from
    // the plan shape we reported in the Ack.
    if pof.next_openswap_info.len() != state.funding_plan.len() {
        log::error!(
            "[{}] ProofOfFunding next-hop info count {} != frozen plan splits {}",
            maker.network_port(),
            pof.next_openswap_info.len(),
            state.funding_plan.len()
        );
        return Err(MakerError::General(
            "ProofOfFunding next-hop contract count differs from the frozen plan",
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
    if !incoming_matches_swap_amount(declared_incoming, state.swap_amount) {
        log::error!(
            "[{}] ProofOfFunding incoming amount {} != declared swap amount {}",
            maker.network_port(),
            declared_incoming,
            state.swap_amount
        );
        return Err(MakerError::General(
            "ProofOfFunding incoming amount differs from the declared swap amount",
        ));
    }

    // Claim the incoming contract txids before the confirmation wait inside
    // `verify_proof_of_funding`, matching the Taproot order: a concurrent
    // duplicate is rejected here, not after parking a handler for a full
    // confirmation window. A same-swap retry re-claims its own txids. An
    // error after this point leaves the claim to the swap drain.
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
            state.swap_feerate,
        )?;

        // One incoming contract must never fund two outgoing hops: the receiver
        // contract is derived from the funding outpoint, so a txid another swap
        // already holds is a replay (mirror of the taproot guard).
        if maker.contract_txid_seen(&receiver_contract_tx.compute_txid(), &pof.id)? {
            return Err(MakerError::General("Legacy contract txid already in use"));
        }

        let mut incoming_swapcoin = IncomingSwapCoin::new_legacy(
            multisig_privkey,
            other_pubkey,
            receiver_contract_tx,
            funding_info.contract_redeemscript.clone(),
            hashlock_privkey,
            funding_output.value,
            state.swap_feerate as u64,
        );
        incoming_swapcoin.swap_id = Some(pof.id.clone());

        incoming_swapcoins.push(incoming_swapcoin);
        incoming_amount += funding_output.value;
    }

    state.incoming_swapcoins = incoming_swapcoins;

    let incoming_txids: Vec<bitcoin::Txid> = state
        .incoming_swapcoins
        .iter()
        .map(|sc| sc.contract_tx.compute_txid())
        .collect();
    maker.claim_incoming_contract_txids(&pof.id, &incoming_txids)?;

    let hashvalue = maker.verify_proof_of_funding(&pof)?;

    for funding_info in &pof.confirmed_funding_txes {
        maker.screen_funding_tx(&funding_info.funding_tx)?;
    }

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

        // Also watch the funding outpoint itself. The output watch above only
        // fires once the contract's own output is later spent (hashlock claim
        // or refund); it never fires on the contract broadcast itself. A spend
        // of the funding outpoint by this exact contract txid is the taker
        // forcing the contract on-chain early — see `legacy_swap_breached`.
        if let (Some(funding_input), Some(multisig_redeemscript)) = (
            incoming.contract_tx.input.first(),
            incoming.multisig_redeemscript.as_ref(),
        ) {
            let funding_spk = redeemscript_to_scriptpubkey(multisig_redeemscript)?;
            maker.register_watch_outpoint(funding_input.previous_output, funding_spk)?;
        }
    }

    log::info!(
        "[{}] Created {} incoming swapcoins, total amount: {}",
        maker.network_port(),
        state.incoming_swapcoins.len(),
        incoming_amount
    );

    let swap_fee = maker.calculate_swap_fee(incoming_amount, pof.refund_locktime as u32);
    // The sweep reimbursement prices each incoming contract's cooperative
    // spend; the funding fee comes out in the split plan, not here.
    // The feerate is negotiated with the peer; an overflowing product would
    // panic this connection thread, so fail the swap instead.
    let sweep_fee = Amount::from_sat(
        sweep_fee_policy_sats(ProtocolVersion::Legacy, state.swap_feerate)
            .and_then(|per_contract| {
                per_contract.checked_mul(pof.confirmed_funding_txes.len() as u64)
            })
            .ok_or(MakerError::General("Sweep fee overflow"))?,
    );
    // Incoming amount and count are exact now, so this equals the forwardable
    // the admission plan was frozen on; `initialize_swap` rejects any drift.
    let forwardable = incoming_amount
        .checked_sub(swap_fee)
        .and_then(|amt| amt.checked_sub(sweep_fee))
        .ok_or(MakerError::General("Swap fee exceeds incoming amount"))?;

    log::info!(
        "[{}] Incoming: {}, Fee: {}, SweepFee: {}, Forwardable: {}",
        maker.network_port(),
        incoming_amount,
        swap_fee,
        sweep_fee,
        forwardable
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

    // Executes the plan frozen at admission; its inputs are already reserved
    // under the swap id.
    let (funding_txes, mut outgoing_swapcoins, _mining_fees) = maker.initialize_swap(
        &pof.id,
        forwardable,
        &next_multisig_pubkeys,
        &next_hashlock_pubkeys,
        hashvalue,
        pof.refund_locktime,
        state.swap_feerate,
    )?;
    for outgoing in &mut outgoing_swapcoins {
        outgoing.swap_id = Some(pof.id.clone());
    }

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

    // QA: a response carrying more contracts than the negotiated maximum must
    // be caught by the taker's count check.
    #[cfg(feature = "integration-test")]
    if maker.behavior() == super::handlers::MakerBehavior::OverproduceContractData {
        if let Some(extra) = senders_contract_txs_info.first().cloned() {
            senders_contract_txs_info.push(extra);
        }
    }

    // QA: repeating one funded contract in place of another keeps count and
    // total exact, so only the taker's duplicate-outpoint check can catch it.
    #[cfg(feature = "integration-test")]
    if maker.behavior() == super::handlers::MakerBehavior::DuplicateContractOutpoint
        && senders_contract_txs_info.len() > 1
    {
        let last = senders_contract_txs_info.len() - 1;
        senders_contract_txs_info[last].contract_tx =
            senders_contract_txs_info[0].contract_tx.clone();
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

    // The taker may have already forced the incoming contract on-chain while
    // this response was in flight. Broadcasting our own outgoing funding on
    // top of that would commit funds we cannot get back through the normal
    // swap path — abort into recovery instead.
    if maker.legacy_swap_breached(&resp.id)? {
        log::error!(
            "[{}] Aborting swap {} before funding broadcast: incoming funding was breached",
            maker.network_port(),
            resp.id
        );
        return Err(MakerError::General(
            "Legacy swap breached before funding broadcast",
        ));
    }

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

    // The sync, persistence and broadcast loop below can outlive the idle
    // timeout; refresh the stored activity so the idle checker does not drain
    // a live swap mid-broadcast.
    maker.store_connection_state(&resp.id, state, false)?;

    // Verify all contract signatures before storing them
    if let Err(e) = super::legacy_verification::verify_contract_sigs(
        &resp.receivers_sigs,
        &resp.senders_sigs,
        &state.incoming_swapcoins,
        &state.outgoing_swapcoins,
        maker.network_port(),
    ) {
        // Bad sigs kill the swap: drop the persisted state and free the
        // admission reservation, or a failing taker holds our inputs by
        // reconnecting and repeating the request.
        if let Err(cleanup) = maker.remove_connection_state(&resp.id) {
            log::error!(
                "[{}] failed to drop swap {} after bad signatures: {:?}",
                maker.network_port(),
                resp.id,
                cleanup
            );
        }
        return Err(e);
    }
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
    // nothing on-chain; failing after the first broadcast would leave a live
    // funding tx the watchtower does not watch.
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

    for (send_index, funding_tx) in state.pending_funding_txes.iter().enumerate() {
        // The index only feeds the test hook below; touch it so production
        // builds have no unused binding.
        let _ = send_index;
        #[cfg(feature = "integration-test")]
        {
            use super::handlers::MakerBehavior;
            if maker.behavior() == MakerBehavior::FailSecondBroadcast && send_index == 1 {
                log::warn!(
                    "[{}] Test behavior: failing the second funding broadcast",
                    maker.network_port()
                );
                return Err(MakerError::Wallet(WalletError::General(
                    "Test: failing the second funding broadcast".to_string(),
                )));
            }
        }

        let txid = funding_tx.compute_txid();
        // Answer normally but send nothing, so the taker waits on funding that
        // never arrives rather than on a closed connection.
        #[cfg(feature = "integration-test")]
        if maker.behavior() == super::handlers::MakerBehavior::WithholdFundingSilently {
            log::warn!(
                "[{}] Test behavior: withholding Legacy funding tx {}",
                maker.network_port(),
                txid
            );
            continue;
        }
        match maker.broadcast_transaction(funding_tx) {
            Ok(txid) => {
                log::info!(
                    "[{}] Broadcast Legacy funding tx: {}",
                    maker.network_port(),
                    txid
                );
            }
            Err(e) if is_already_broadcast_error(&e) => {
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
                if maker.is_transaction_known(&txid)? {
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

        // Record each send before the next one can fail, so a mid-batch
        // failure never reads back as "never broadcast".
        if !state.funding_broadcast_txids.contains(&txid) {
            state.funding_broadcast_txids.push(txid);
        }
        maker.record_funding_broadcast(&resp.id, &txid)?;
    }

    state.pending_funding_txes.clear();
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

    // Signing here commits our outgoing side further; a breach means the
    // taker already forced the incoming contract on-chain, so stop and let
    // recovery run instead of continuing to cooperate.
    if maker.legacy_swap_breached(&req.id)? {
        log::error!(
            "[{}] Aborting swap {} before signing receiver contracts: incoming funding was breached",
            maker.network_port(),
            req.id
        );
        return Err(MakerError::General(
            "Legacy swap breached before receiver contract signing",
        ));
    }

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

    // The actual loss scenario: handing over our outgoing privkey after the
    // incoming contract is already on-chain lets the breach be turned into a
    // theft immediately, with no recourse. Refuse and let recovery run.
    if maker.legacy_swap_breached(&handover.id)? {
        log::error!(
            "[{}] Aborting swap {} before private key handover: incoming funding was breached",
            maker.network_port(),
            handover.id
        );
        return Err(MakerError::General(
            "Legacy swap breached before private key handover",
        ));
    }

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

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::CloseAfterSweep {
            // Sweep here rather than letting the error skip the server loop's
            // sweep block, or the preimage only reaches the chain 30s later via
            // idle recovery and the behavior's name is a lie.
            if let Err(e) = maker.sweep_incoming_swapcoins(&state.incoming_swapcoins) {
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
