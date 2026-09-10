//! Taproot (MuSig2) Protocol Handlers for the Maker.

use std::sync::Arc;

use bitcoin::{Amount, OutPoint, PublicKey, Txid};
use bitcoind::bitcoincore_rpc::{jsonrpc::error::Error as JsonRpcError, Error as BitcoinRpcError};

#[cfg(feature = "integration-test")]
use super::handlers::MakerBehavior;
use super::{
    error::MakerError,
    handlers::{
        incoming_matches_swap_amount, ConnectionState, Maker, SwapPhase, MIN_CONTRACT_REACTION_TIME,
    },
};
use crate::{
    protocol::{
        common_messages::{MakerToTakerMessage, PrivateKeyHandover, ProtocolVersion, SwapPrivkey},
        contract::calculate_pubkey_from_nonce,
        contract2::{
            check_taproot_hashlock_has_pubkey, create_hashlock_script, create_timelock_script,
            extract_hash_from_hashlock,
        },
        taproot_messages::{SerializableScalar, TaprootContractData, TaprootTakerMessage},
    },
    taker::api::REFUND_LOCKTIME_STEP,
    utill::sweep_fee_policy_sats,
    wallet::{
        swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
        MakerReport, WalletError,
    },
};
#[cfg(feature = "integration-test")]
use bitcoind::bitcoincore_rpc::jsonrpc::error::RpcError;

/// Handle a Taproot protocol message.
pub fn handle_taproot_message<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    message: TaprootTakerMessage,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    log::debug!(
        "[{}] Handling Taproot message: {:?} (swap_id: {:?})",
        maker.network_port(),
        message,
        state.swap_id
    );

    match message {
        TaprootTakerMessage::ContractData(data) => process_taproot_contract(maker, state, *data),
        TaprootTakerMessage::PrivateKeyHandover(handover) => {
            process_taproot_handover(maker, state, handover)
        }
    }
}

/// We can only sweep our incoming contract until `timelock + REFUND_LOCKTIME_STEP`.
/// The taker controls when it sends contract data and how fast its funding confirms,
/// so re-check before every commitment: too little left and we fund the next hop underwater.
fn check_sweep_margin<M: Maker>(maker: &Arc<M>, timelock: u32) -> Result<(), MakerError> {
    let current_height = maker.get_current_height()?;
    if timelock.saturating_add(REFUND_LOCKTIME_STEP as u32)
        < current_height.saturating_add(MIN_CONTRACT_REACTION_TIME as u32)
    {
        log::warn!(
            "[{}] Too little time left to sweep safely: timelock {} at height {}",
            maker.network_port(),
            timelock,
            current_height
        );
        return Err(MakerError::General(
            "Taproot contract data arrived too late to sweep safely",
        ));
    }
    Ok(())
}

/// Process Taproot contract data.
fn process_taproot_contract<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    data: TaprootContractData,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    state.expect_phase(&[SwapPhase::AwaitingContractData])?;
    state.check_swap_id(&data.id)?;

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::CloseAtContractSigsExchange {
            log::warn!(
                "[{}] Test behavior: closing at taproot contract sigs exchange",
                maker.network_port()
            );
            return Err(MakerError::General(
                "Test: closing at contract sigs exchange",
            ));
        }
    }

    log::info!(
        "[{}] Processing Taproot contract data for swap {}",
        maker.network_port(),
        data.id
    );

    let (tweakable_privkey, tweakable_pubkey, _) = maker.get_tweakable_keypair()?;
    let secp = bitcoin::secp256k1::Secp256k1::new();

    // Use the nonce from the received message to reconstruct hashlock_privkey.
    let hashlock_nonce = data.hashlock_nonce.ok_or(MakerError::General(
        "Missing hashlock_nonce in TaprootContractData",
    ))?;
    let hashlock_privkey = tweakable_privkey
        .add_tweak(&hashlock_nonce.into())
        .map_err(|_| MakerError::General("Hashlock key derivation failed"))?;

    // Verify: derived pubkey matches the pubkey in the hashlock script.
    check_taproot_hashlock_has_pubkey(&data.hashlock_script, &tweakable_pubkey, &hashlock_nonce)
        .map_err(|e| MakerError::General(format!("Hashlock pubkey mismatch: {:?}", e).leak()))?;

    // Full verification: script formats, timelock, P2TR output, amounts, array consistency
    super::taproot_verification::verify_taproot_contract_data(
        &data,
        &tweakable_pubkey,
        state.timelock,
        maker.network_port(),
    )?;

    // The declared incoming count is exact: the sweep fee and the next hop's
    // plan were priced on it, so anything else short-changes one side.
    if data.contract_txs.len() != state.incoming_count as usize {
        log::error!(
            "[{}] Taproot contract count {} != declared incoming count {}",
            maker.network_port(),
            data.contract_txs.len(),
            state.incoming_count
        );
        return Err(MakerError::General(
            "Taproot contract count does not match the declared incoming count",
        ));
    }

    // Amounts are peer-supplied, so sum them without panicking.
    let mut total_incoming = Amount::ZERO;
    for amount in &data.amounts {
        total_incoming = total_incoming
            .checked_add(*amount)
            .ok_or(MakerError::General("Taproot contract amounts overflow"))?;
    }
    if !incoming_matches_swap_amount(total_incoming, state.swap_amount) {
        log::error!(
            "[{}] Taproot incoming amount {} does not match negotiated swap amount {}",
            maker.network_port(),
            total_incoming,
            state.swap_amount
        );
        return Err(MakerError::General(
            "Taproot incoming amount does not match the negotiated swap amount",
        ));
    }

    check_sweep_margin(maker, state.timelock)?;
    #[cfg(debug_assertions)]
    log::debug!(
        "[CONTRACT_STATE] Role: Maker | Protocol: Taproot | SwapID: {} | ContractTxs: {} | Amounts: {} | Timelock: {} | Status: verified",
        data.id,
        data.contract_txs.len(),
        data.amounts.len(),
        state.timelock
    );

    let n = data.contract_txs.len();
    let mut incoming_swapcoins = Vec::with_capacity(n);
    let required_confirms = maker.get_config().required_confirms;
    // Claim every incoming contract txid under the swaps lock before the
    // confirmation wait: a concurrent swap carrying the same contract tx fails
    // here, not after both waited and both funded the next hop. A same-swap
    // reconnect re-claims its own txids and passes.
    let incoming_txids: Vec<Txid> = data
        .contract_txs
        .iter()
        .map(|tx| tx.compute_txid())
        .collect();
    maker.claim_incoming_contract_txids(&data.id, &incoming_txids)?;
    for j in 0..n {
        let incoming_contract_tx = data.contract_txs[j].clone();
        let contract_txid = incoming_contract_tx.compute_txid();
        // A mempool-only contract may be replaced via RBF after we fund the next hop,
        // so require confirmations before proceeding.
        maker.wait_for_tx_on_chain(&data.id, &contract_txid, required_confirms)?;
        // One incoming contract must never fund two outgoing hops: an already
        // spent output, or a txid another swap already holds, is a replay.
        if !maker.contract_output_unspent(&OutPoint::new(contract_txid, 0))? {
            return Err(MakerError::General("Taproot contract output already spent"));
        }
        if maker.contract_txid_seen(&contract_txid, &data.id)? {
            return Err(MakerError::General("Taproot contract txid already in use"));
        }
        // Blocks passed while we waited. We have broadcast nothing yet, so aborting
        // here costs only the reserved UTXOs.
        check_sweep_margin(maker, state.timelock)?;

        let incoming_funding_amount = data.amounts[j];

        let other_pubkey = data.pubkeys.get(j).cloned().unwrap_or(data.next_hop_point);

        let mut incoming_swapcoin = IncomingSwapCoin::new_taproot(
            hashlock_privkey,
            data.hashlock_script.clone(),
            data.timelock_scripts[j].clone(),
            incoming_contract_tx,
            incoming_funding_amount,
            state.swap_feerate as u64,
        );
        incoming_swapcoin.swap_id = Some(data.id.clone());

        incoming_swapcoin.my_privkey = Some(tweakable_privkey);
        incoming_swapcoin.my_pubkey = Some(PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &tweakable_privkey),
        });
        incoming_swapcoin.other_pubkey = Some(other_pubkey);
        incoming_swapcoin.internal_key = Some(data.internal_keys[j]);
        incoming_swapcoin.tap_tweak = Some(data.tap_tweak_scalar(j)?);
        incoming_swapcoins.push(incoming_swapcoin);
    }

    // The fee is priced on the negotiated offset, so it is fixed at negotiation
    // and matches the taker's mirror. The offset is not bound to the real lock
    // duration; assess the CSV transition (binding it in the script) later.
    let swap_fee = maker.calculate_swap_fee(total_incoming, state.refund_locktime_offset as u32);
    // The fee stored at swap-details time was computed from the proposed
    // amount; overwrite with the fee on the actual incoming amount so
    // success reports match what was really earned.
    state.service_fee_sats = swap_fee.to_sat();
    // The sweep reimbursement prices each incoming contract's cooperative
    // spend; the funding fee comes out in the split plan, not here.
    // The feerate is negotiated with the peer; an overflowing product would
    // panic this connection thread, so fail the swap instead.
    let sweep_fee = Amount::from_sat(
        sweep_fee_policy_sats(ProtocolVersion::Taproot, state.swap_feerate)
            .and_then(|per_contract| per_contract.checked_mul(n as u64))
            .ok_or(MakerError::General("Sweep fee overflow"))?,
    );
    let forwardable = total_incoming
        .checked_sub(swap_fee)
        .and_then(|amt| amt.checked_sub(sweep_fee))
        .ok_or(MakerError::General("Fee exceeds incoming amount"))?;

    log::info!(
        "[{}] Fee calculation: incoming_total={}, swap_fee={}, sweep_fee={}, forwardable={}",
        maker.network_port(),
        total_incoming,
        swap_fee,
        sweep_fee,
        forwardable
    );

    let hash = extract_hash_from_hashlock(&data.hashlock_script)
        .map_err(|e| MakerError::General(format!("Invalid hashlock script: {:?}", e).leak()))?;
    // If next_hashlock_nonce is provided, tweak the next hop's pubkey.
    // Otherwise (last maker → taker), use the un-tweaked next_hop_point.
    // The hashlock script (next hop's hashlock key) is shared across all contracts.
    let next_hop_hashlock_pubkey = if let Some(ref nonce) = data.next_hashlock_nonce {
        calculate_pubkey_from_nonce(&data.next_hop_point, nonce)
            .map_err(|e| MakerError::General(format!("Next hop key derivation: {:?}", e).leak()))?
    } else {
        data.next_hop_point
    };
    let next_hop_xonly = bitcoin::key::XOnlyPublicKey::from(next_hop_hashlock_pubkey.inner);
    let hashlock_script = create_hashlock_script(&hash, &next_hop_xonly);

    // Derive keys, scripts and addresses for exactly the splits in the frozen
    // plan: admission already sized it, so the peer's requested ceiling never
    // sizes an allocation or a loop here.
    let mut contract_params = Vec::with_capacity(state.funding_plan.len());
    for _ in 0..state.funding_plan.len() {
        let outgoing_nonce =
            bitcoin::secp256k1::SecretKey::new(&mut bitcoin::secp256k1::rand::thread_rng());
        let outgoing_privkey = tweakable_privkey
            .add_tweak(&outgoing_nonce.into())
            .map_err(|_| MakerError::General("Outgoing key derivation failed"))?;
        let outgoing_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &outgoing_privkey),
        };

        let timelock_privkey =
            bitcoin::secp256k1::SecretKey::new(&mut bitcoin::secp256k1::rand::thread_rng());
        let timelock_keypair =
            bitcoin::secp256k1::Keypair::from_secret_key(&secp, &timelock_privkey);
        let timelock_xonly = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&timelock_keypair).0;
        let timelock_script = {
            // For Taproot, state.timelock is already an absolute block height.
            let locktime = bitcoin::absolute::LockTime::from_height(state.timelock)
                .map_err(|_| MakerError::General("Invalid locktime height"))?;
            create_timelock_script(locktime, &timelock_xonly)
        };

        let builder = bitcoin::taproot::TaprootBuilder::new()
            .add_leaf(1, hashlock_script.clone())
            .map_err(|e| {
                MakerError::General(format!("Failed to add hashlock leaf: {:?}", e).leak())
            })?
            .add_leaf(1, timelock_script.clone())
            .map_err(|e| {
                MakerError::General(format!("Failed to add timelock leaf: {:?}", e).leak())
            })?;

        let mut ordered_pubkeys = [outgoing_pubkey, data.next_hop_point];
        ordered_pubkeys.sort_by_key(|a| a.inner.serialize());
        let internal_key = crate::protocol::musig_interface::get_aggregated_pubkey_compat(
            ordered_pubkeys[0].inner,
            ordered_pubkeys[1].inner,
        )
        .map_err(|e| {
            MakerError::General(format!("Failed to create aggregated pubkey: {:?}", e).leak())
        })?;

        let tap_info = builder.finalize(&secp, internal_key).map_err(|e| {
            MakerError::General(format!("Failed to finalize taproot: {:?}", e).leak())
        })?;
        let taproot_address =
            bitcoin::Address::p2tr_tweaked(tap_info.output_key(), maker.network());
        let tap_tweak = tap_info.tap_tweak().to_scalar();

        contract_params.push((
            outgoing_privkey,
            outgoing_pubkey,
            internal_key,
            timelock_privkey,
            timelock_script,
            taproot_address,
            tap_tweak,
        ));
    }

    let contract_addresses: Vec<_> = contract_params
        .iter()
        .map(|params| params.5.clone())
        .collect();
    let (contract_txs, output_positions) = maker.create_funding_transactions(
        &data.id,
        forwardable,
        &contract_addresses,
        state.swap_feerate,
    )?;

    // Build one outgoing contract per funded split; amounts come from the
    // actual funding outputs, so the response can never claim more than was
    // funded.
    let mut outgoing_swapcoins = Vec::with_capacity(contract_txs.len());
    let mut response_pubkeys = Vec::with_capacity(contract_txs.len());
    let mut response_internal_keys = Vec::with_capacity(contract_txs.len());
    let mut response_tap_tweaks = Vec::with_capacity(contract_txs.len());
    let mut response_timelock_scripts = Vec::with_capacity(contract_txs.len());
    let mut response_contract_txs = Vec::with_capacity(contract_txs.len());
    let mut response_amounts = Vec::with_capacity(contract_txs.len());
    let mut reserved = Vec::with_capacity(contract_txs.len());

    for ((contract_tx, &output_pos), params) in contract_txs
        .iter()
        .zip(output_positions.iter())
        .zip(contract_params.iter())
    {
        let (
            outgoing_privkey,
            outgoing_pubkey,
            internal_key,
            timelock_privkey,
            timelock_script,
            _,
            tap_tweak,
        ) = params;
        let contract_outpoint = OutPoint {
            txid: contract_tx.compute_txid(),
            vout: output_pos,
        };
        reserved.push(contract_outpoint);
        let contract_output_amount = contract_tx.output[output_pos as usize].value;

        let mut outgoing_swapcoin = OutgoingSwapCoin::new_taproot(
            *timelock_privkey,
            hashlock_script.clone(),
            timelock_script.clone(),
            contract_tx.clone(),
            contract_output_amount,
            state.swap_feerate as u64,
        );
        outgoing_swapcoin.swap_id = Some(data.id.clone());
        outgoing_swapcoin.set_taproot_params(
            *outgoing_privkey,
            *outgoing_pubkey,
            data.next_hop_point,
            *internal_key,
            *tap_tweak,
        );

        response_pubkeys.push(*outgoing_pubkey);
        response_internal_keys.push(*internal_key);
        response_tap_tweaks.push(SerializableScalar::from_bytes(
            tap_tweak.to_be_bytes().to_vec(),
        ));
        response_timelock_scripts.push(timelock_script.clone());
        response_contract_txs.push(contract_tx.clone());
        response_amounts.push(contract_output_amount);
        outgoing_swapcoins.push(outgoing_swapcoin);
    }

    state.incoming_swapcoins = incoming_swapcoins.clone();
    state.outgoing_swapcoins = outgoing_swapcoins.clone();
    #[cfg(debug_assertions)]
    log::debug!(
        "[CONTRACT_STATE] Role: Maker | Protocol: Taproot | SwapID: {} | Contracts: {} | IncomingTotal: {} | ReservedUtxos: {}",
        data.id,
        n,
        total_incoming.to_sat(),
        reserved.len()
    );

    // Persist before the first broadcast: past that point recovery reads the
    // stored state, not the copy in this handler.
    maker.store_connection_state(&data.id, state, false)?;

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::SkipFundingBroadcast {
            log::warn!(
                "[{}] Test behavior: skipping Taproot funding broadcast",
                maker.network_port()
            );
            state.funding_broadcast_txids = outgoing_swapcoins
                .iter()
                .map(|outgoing| outgoing.contract_tx.compute_txid())
                .collect();
            state.phase = SwapPhase::AwaitingPrivateKeyHandover;
            for incoming in &incoming_swapcoins {
                maker.save_incoming_swapcoin(incoming)?;
            }
            for outgoing in &outgoing_swapcoins {
                maker.save_outgoing_swapcoin(outgoing)?;
            }
            maker.store_connection_state(&data.id, state, false)?;
            return Err(MakerError::General("Test: skipped funding broadcast"));
        }
    }

    // Arm the watches before anything is committed. Failing here aborts with
    // nothing on-chain; after the first send, recovery needs them for the
    // contract txs recorded as broadcast.
    for (outgoing, contract_outpoint) in outgoing_swapcoins.iter().zip(reserved.iter()) {
        maker.register_watch_outpoint(
            *contract_outpoint,
            outgoing.contract_tx.output[contract_outpoint.vout as usize]
                .script_pubkey
                .clone(),
        )?;
    }
    super::handlers::ensure_watchtower_alive(maker.as_ref())?;

    // Persist swapcoins before broadcasting contract txs. A later broadcast
    // failure can leave earlier Taproot contract txs on-chain, and the wallet
    // needs these records for timelock recovery after a restart.
    for incoming in &incoming_swapcoins {
        maker.save_incoming_swapcoin(incoming)?;
    }
    for outgoing in &outgoing_swapcoins {
        maker.save_outgoing_swapcoin(outgoing)?;
    }

    for (index, outgoing) in outgoing_swapcoins.iter().enumerate() {
        // The index only feeds the test hook below; touch it so production
        // builds have no unused binding.
        let _ = index;
        // QA: a mid-batch failure must leave the earlier sends recorded, or
        // recovery discards contract txs already on the wire. Inert for
        // single-tx batches.
        #[cfg(feature = "integration-test")]
        if index == 1 && maker.behavior() == MakerBehavior::FailSecondBroadcast {
            log::warn!(
                "[{}] Test behavior: failing the second Taproot funding broadcast",
                maker.network_port()
            );
            return Err(MakerError::Wallet(WalletError::Rpc(
                BitcoinRpcError::JsonRpc(JsonRpcError::Rpc(RpcError {
                    code: -26,
                    message: "Test: second funding broadcast rejected".to_string(),
                    data: None,
                })),
            )));
        }
        let txid = outgoing.contract_tx.compute_txid();
        match maker.broadcast_transaction(&outgoing.contract_tx) {
            Ok(_) => {
                log::info!(
                    "[{}] Broadcast Taproot contract tx {} for swap {}",
                    maker.network_port(),
                    txid,
                    data.id
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
                log::info!(
                    "[{}] Taproot contract tx {} for swap {} was already broadcast",
                    maker.network_port(),
                    txid,
                    data.id
                );
            }
            Err(e) => {
                // This captures the Electrum counterpart of the rebroadcast error.
                // Electrum doesn't throw a reliable error. So we manually check if the transaction
                // is already broadcasted. An error here means the backend connection is down.
                if maker.is_transaction_known(&txid)? {
                    log::info!(
                        "[{}] Taproot contract tx {} for swap {} was already broadcast",
                        maker.network_port(),
                        txid,
                        data.id
                    );
                } else {
                    return Err(e);
                }
            }
        }
        // Record each send before the next one, so a mid-batch failure never
        // reads back as "never broadcast".
        maker.record_funding_broadcast(&data.id, &txid)?;
        if !state.funding_broadcast_txids.contains(&txid) {
            state.funding_broadcast_txids.push(txid);
        }
    }

    state.phase = SwapPhase::AwaitingPrivateKeyHandover;

    maker.store_connection_state(&data.id, state, false)?;

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::BroadcastContractAfterSetup {
            log::warn!(
                "[{}] Test behavior: broadcasting contract tx after taproot setup, then closing",
                maker.network_port()
            );
            if let Some(outgoing) = outgoing_swapcoins.first() {
                let _ = maker.broadcast_transaction(&outgoing.contract_tx);
            }
            return Err(MakerError::General("Test: broadcast contract after setup"));
        }
    }

    log::info!(
        "[{}] Created {} Taproot swapcoins for swap {}",
        maker.network_port(),
        n,
        data.id
    );

    // QA: a response carrying more contracts than the negotiated maximum must
    // be caught by the taker's count check; all per-contract arrays stay 1:1.
    #[cfg(feature = "integration-test")]
    if maker.behavior() == MakerBehavior::OverproduceContractData {
        if let Some(first) = response_pubkeys.first().copied() {
            response_pubkeys.push(first);
            response_internal_keys.push(response_internal_keys[0]);
            response_tap_tweaks.push(response_tap_tweaks[0].clone());
            response_timelock_scripts.push(response_timelock_scripts[0].clone());
            response_contract_txs.push(response_contract_txs[0].clone());
            response_amounts.push(response_amounts[0]);
        }
    }

    // QA: moving one sat between two claims keeps count and total exact, so
    // only the taker's per-output amount binding can catch the lie.
    #[cfg(feature = "integration-test")]
    if maker.behavior() == MakerBehavior::InflateContractAmount && response_amounts.len() > 1 {
        response_amounts[0] += Amount::from_sat(1);
        response_amounts[1] -= Amount::from_sat(1);
    }

    // QA: repeating one funded contract keeps count and total exact, so only
    // the taker's duplicate-outpoint check can catch the double claim.
    #[cfg(feature = "integration-test")]
    if maker.behavior() == MakerBehavior::DuplicateContractOutpoint
        && response_contract_txs.len() > 1
    {
        let last = response_contract_txs.len() - 1;
        response_contract_txs[last] = response_contract_txs[0].clone();
    }

    let response = TaprootContractData::new(
        data.id.clone(),
        response_pubkeys,
        tweakable_pubkey,
        response_internal_keys,
        response_tap_tweaks,
        hashlock_script,
        response_timelock_scripts,
        response_contract_txs,
        response_amounts,
        None, // hashlock_nonce: taker already knows
        None, // next_hashlock_nonce: taker manages all nonces
    );

    Ok(Some(MakerToTakerMessage::TaprootContractData(Box::new(
        response,
    ))))
}

/// Process Taproot private key handover.
/// Stores the received privkey on incoming swapcoins, extracts outgoing privkey
/// as a response. Sweep and state cleanup happen in the server loop after the
/// response has been sent to the taker, to avoid blocking delivery.
fn process_taproot_handover<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    handover: PrivateKeyHandover,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    state.expect_phase(&[SwapPhase::AwaitingPrivateKeyHandover])?;
    state.check_swap_id(&handover.id)?;

    #[cfg(feature = "integration-test")]
    {
        use super::handlers::MakerBehavior;
        if maker.behavior() == MakerBehavior::CloseAtPrivateKeyHandover {
            log::warn!(
                "[{}] Test behavior: closing at taproot private key handover",
                maker.network_port()
            );
            return Err(MakerError::General("Test: closing at private key handover"));
        }
    }

    log::info!(
        "[{}] Processing Taproot private key handover for swap {}",
        maker.network_port(),
        handover.id
    );

    // Verify the received private keys before proceeding
    super::taproot_verification::verify_taproot_privkey_handover(
        &handover.privkeys,
        &state.incoming_swapcoins,
        maker.network_port(),
    )?;

    if state.outgoing_swapcoins.is_empty() {
        return Err(MakerError::General("No outgoing swapcoin found"));
    }
    let mut privkeys = Vec::with_capacity(state.outgoing_swapcoins.len());
    for outgoing in &state.outgoing_swapcoins {
        privkeys.push(SwapPrivkey {
            identifier: bitcoin::ScriptBuf::new(),
            key: outgoing
                .my_privkey
                .ok_or(MakerError::General("No private key in outgoing swapcoin"))?,
        });
    }

    // Store received privkey on incoming swapcoins
    for (i, incoming) in state.incoming_swapcoins.iter_mut().enumerate() {
        if let Some(pk) = handover.privkeys.get(i) {
            incoming.other_privkey = Some(pk.key);
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
        "[SWAP_STATE] Source: maker::taproot_handlers::process_taproot_handover | SwapID: {} | Protocol: Taproot | Phase: Completed | Incoming: {} | Outgoing: {}",
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
        "[{}] Taproot swap {} completed successfully, returning private key",
        maker.network_port(),
        handover.id
    );

    let response = PrivateKeyHandover {
        id: handover.id,
        privkeys,
    };

    Ok(Some(MakerToTakerMessage::TaprootPrivateKeyHandover(
        response,
    )))
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
