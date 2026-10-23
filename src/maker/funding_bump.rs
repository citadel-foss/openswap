//! Funding bumps on the maker side: replacing our own outgoing funding at a
//! higher feerate when the taker asks.
//!
//! The replacement spends the same coins and returns the same change; only the
//! contract output shrinks, by the extra fee. We pay nothing on success, since
//! the next hop forwards that much less and the taker receives less. If the
//! swap fails we refund the smaller contract, which is why we cap the bump.

use std::sync::Arc;

use bitcoin::{OutPoint, Transaction, Txid};

use super::{
    error::MakerError,
    handlers::{
        ensure_watchtower_alive, is_already_broadcast_error, ConnectionState, Maker,
        PendingFundingBump, SwapPhase,
    },
};
use crate::{
    protocol::{
        common_messages::{MakerToTakerMessage, ProtocolVersion},
        contract::{
            create_multisig_redeemscript, create_senders_contract_tx, verify_contract_tx_sig,
        },
        funding_bump::{
            bump_delta_sats, unsigned_replacement, verify_bump, BumpFunding, BumpFundingCommit,
            BumpFundingProposal, BumpedFunding, FundingBumped, MAX_FUNDING_BUMPS,
        },
    },
    wallet::{min_contract_value_sats, swapcoin::OutgoingSwapCoin},
};

/// The funding tx of one outgoing version: Taproot's contract tx is its
/// funding, Legacy's spends it.
fn funding_tx(coin: &OutgoingSwapCoin) -> Option<&Transaction> {
    match coin.protocol {
        ProtocolVersion::Taproot => Some(&coin.contract_tx),
        ProtocolVersion::Legacy => coin.funding_tx.as_ref(),
    }
}

/// Index of the contract output in a version's funding tx.
fn contract_vout(coin: &OutgoingSwapCoin) -> Option<usize> {
    match coin.protocol {
        ProtocolVersion::Taproot => Some(coin.get_contract_output_vout() as usize),
        ProtocolVersion::Legacy => coin
            .contract_tx
            .input
            .first()
            .map(|input| input.previous_output.vout as usize),
    }
}

/// Whether two versions fund from the same coins, i.e. one replaced the other.
fn same_coins(a: &OutgoingSwapCoin, b: &OutgoingSwapCoin) -> bool {
    match (funding_tx(a), funding_tx(b)) {
        (Some(a), Some(b)) => {
            a.input.len() == b.input.len()
                && a.input
                    .iter()
                    .zip(&b.input)
                    .all(|(a, b)| a.previous_output == b.previous_output)
        }
        _ => false,
    }
}

/// Every version of split `split`'s funding, oldest first.
fn versions(state: &ConnectionState, split: usize) -> Vec<&OutgoingSwapCoin> {
    let Some(original) = state.outgoing_swapcoins.get(split) else {
        return Vec::new();
    };
    std::iter::once(original)
        .chain(
            state
                .funding_bump
                .replacements
                .iter()
                .filter(|replacement| same_coins(original, replacement)),
        )
        .collect()
}

/// Reject a request the swap's taker did not sign.
fn authorize(
    state: &ConnectionState,
    swap_id: &str,
    feerate: u64,
    seq: u32,
    commit: bool,
    signature: &bitcoin::secp256k1::schnorr::Signature,
) -> Result<(), MakerError> {
    let taker_key = state.taker_auth_pubkey.ok_or(MakerError::General(
        "Swap has no taker key to authorize a bump",
    ))?;
    // Signed for this hop: the first coin our funding spends, in every version.
    let hop = state
        .outgoing_swapcoins
        .first()
        .and_then(funding_tx)
        .and_then(|funding| funding.input.first())
        .map(|input| input.previous_output)
        .ok_or(MakerError::General("No funded hop to authorize a bump for"))?;
    verify_bump(&taker_key, signature, swap_id, &hop, feerate, seq, commit)?;
    Ok(())
}

/// Whether any version of a split's funding is mined, or ever was: the next
/// hop may have built on it, and a bump after a reorg would conflict with it.
fn any_confirmed<M: Maker>(
    maker: &Arc<M>,
    swap_id: &str,
    versions: &[&OutgoingSwapCoin],
) -> Result<bool, MakerError> {
    for version in versions {
        let txid = funding_tx(version)
            .ok_or(MakerError::General("Outgoing swapcoin has no funding tx"))?
            .compute_txid();
        if maker.funding_ever_confirmed(swap_id, &txid)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What the version of `original` at `feerate` takes out of its contract.
fn delta_at(
    state: &ConnectionState,
    original: &OutgoingSwapCoin,
    feerate: u64,
) -> Result<u64, MakerError> {
    let original_tx =
        funding_tx(original).ok_or(MakerError::General("Outgoing swapcoin has no funding tx"))?;
    bump_delta_sats(original_tx, state.swap_feerate as u64, feerate).ok_or(MakerError::General(
        "Funding bump does not raise the feerate",
    ))
}

/// Build, and sign, the version at `feerate` of every still unconfirmed
/// funding split. Each is built from the split's original, so its contract
/// gives up exactly what the rate prices, whatever earlier bumps did.
/// Returns each bumped split with its new version.
fn build_replacements<M: Maker>(
    maker: &Arc<M>,
    state: &ConnectionState,
    swap_id: &str,
    feerate: u64,
) -> Result<Vec<(usize, OutgoingSwapCoin)>, MakerError> {
    let floor = min_contract_value_sats(state.protocol, feerate as f64)
        .ok_or(MakerError::General("Contract floor cannot be priced"))?;
    let mut replacements = Vec::new();
    // What the contracts give up: the bumped splits at the new rate, and the
    // lowest version of every split that already confirmed.
    let mut taken = 0u64;
    for (split, original) in state.outgoing_swapcoins.iter().enumerate() {
        let versions = versions(state, split);
        if any_confirmed(maker, swap_id, &versions)? {
            let lowest = versions
                .iter()
                .map(|version| version.funding_amount)
                .min()
                .unwrap_or(original.funding_amount);
            taken = taken
                .checked_add(
                    original
                        .funding_amount
                        .to_sat()
                        .saturating_sub(lowest.to_sat()),
                )
                .ok_or(MakerError::General("Funding bump total overflows"))?;
            continue;
        }

        let original_tx = funding_tx(original)
            .ok_or(MakerError::General("Outgoing swapcoin has no funding tx"))?;
        let vout = contract_vout(original).ok_or(MakerError::General(
            "Outgoing swapcoin has no contract output",
        ))?;
        let delta = delta_at(state, original, feerate)?;
        let mut tx = unsigned_replacement(original_tx, vout, delta, floor)?;
        maker.sign_funding_replacement(swap_id, split, &mut tx)?;
        let new_amount = tx.output[vout].value;
        taken = taken
            .checked_add(delta)
            .ok_or(MakerError::General("Funding bump total overflows"))?;

        let mut version = original.clone();
        version.funding_amount = new_amount;
        match state.protocol {
            ProtocolVersion::Taproot => version.contract_tx = tx,
            ProtocolVersion::Legacy => {
                let redeemscript =
                    original
                        .contract_redeemscript
                        .as_ref()
                        .ok_or(MakerError::General(
                            "Outgoing swapcoin has no contract script",
                        ))?;
                // The contract tx is priced at the negotiated rate, whatever
                // the funding pays: only recovery ever broadcasts it.
                version.contract_tx = create_senders_contract_tx(
                    OutPoint::new(tx.compute_txid(), vout as u32),
                    new_amount,
                    redeemscript,
                    state.swap_feerate,
                )?;
                version.funding_tx = Some(tx);
                version.others_contract_sig = None;
            }
        }
        replacements.push((split, version));
    }

    if taken > maker.get_config().max_funding_bump_sats {
        log::warn!(
            "[{}] Refusing funding bump of swap {}: it would take {} sats, above our {} cap",
            maker.network_port(),
            swap_id,
            taken,
            maker.get_config().max_funding_bump_sats
        );
        return Err(MakerError::General(
            "Funding bump takes more than our cap from the contracts",
        ));
    }
    Ok(replacements)
}

/// The versions at `feerate` already built for splits still unconfirmed,
/// for a taker whose copy of our answer went missing. Each is sent again,
/// and only those the backend knows are handed back.
fn broadcast_at<M: Maker>(
    maker: &Arc<M>,
    state: &ConnectionState,
    swap_id: &str,
    feerate: u64,
) -> Result<Vec<BumpedFunding>, MakerError> {
    let mut out = Vec::new();
    for (split, original) in state.outgoing_swapcoins.iter().enumerate() {
        let versions = versions(state, split);
        if any_confirmed(maker, swap_id, &versions)? {
            continue;
        }
        let amount = original
            .funding_amount
            .checked_sub(bitcoin::Amount::from_sat(delta_at(
                state, original, feerate,
            )?))
            .ok_or(MakerError::General("Funding bump exceeds the contract"))?;
        let Some(version) = versions
            .iter()
            .skip(1)
            .find(|version| version.funding_amount == amount)
        else {
            continue;
        };
        let tx = funding_tx(version)
            .ok_or(MakerError::General("Outgoing swapcoin has no funding tx"))?;
        // A refusal says nothing for sure; the backend's view decides.
        if let Err(e) = maker.broadcast_transaction(tx) {
            log::debug!(
                "[{}] Resending replacement funding {}: {:?}",
                maker.network_port(),
                tx.compute_txid(),
                e
            );
        }
        if !maker.is_transaction_known(&tx.compute_txid())? {
            continue;
        }
        out.push(BumpedFunding {
            split: split as u32,
            funding_tx: tx.clone(),
            contract_tx: (version.protocol == ProtocolVersion::Legacy)
                .then(|| version.contract_tx.clone()),
        });
    }
    Ok(out)
}

/// A Legacy proposal as handed to the taker: without signatures, since
/// until the next hop signs its contract a broadcast replacement would be a
/// funding we could never refund.
fn unsigned_proposal(
    replacements: &[(usize, OutgoingSwapCoin)],
) -> Result<Vec<BumpedFunding>, MakerError> {
    replacements
        .iter()
        .map(|(split, version)| {
            let mut funding_tx = funding_tx(version)
                .ok_or(MakerError::General("Outgoing swapcoin has no funding tx"))?
                .clone();
            for input in &mut funding_tx.input {
                input.witness.clear();
            }
            Ok(BumpedFunding {
                split: *split as u32,
                funding_tx,
                contract_tx: Some(version.contract_tx.clone()),
            })
        })
        .collect()
}

/// The feerate our latest funding versions pay.
fn current_feerate(state: &ConnectionState) -> u64 {
    (state.swap_feerate as u64).max(state.funding_bump.feerate)
}

/// Persist the replacements, arm their watches, then broadcast them. Returns
/// the ones that reached the backend.
fn commit_and_broadcast<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    swap_id: &str,
    replacements: Vec<(usize, OutgoingSwapCoin)>,
) -> Result<Vec<BumpedFunding>, MakerError> {
    // Recorded before anything is sent: once a replacement may be out,
    // recovery must hold every version of its split.
    state
        .funding_bump
        .replacements
        .extend(replacements.iter().map(|(_, version)| version.clone()));
    maker.store_connection_state(swap_id, state, false)?;
    for (_, version) in &replacements {
        let txid = version.contract_tx.compute_txid();
        match version.protocol {
            ProtocolVersion::Taproot => {
                let vout = version.get_contract_output_vout();
                maker.register_watch_outpoint(
                    OutPoint::new(txid, vout),
                    version.contract_tx.output[vout as usize]
                        .script_pubkey
                        .clone(),
                )?;
            }
            ProtocolVersion::Legacy => {
                for (vout, txout) in version.contract_tx.output.iter().enumerate() {
                    maker.register_watch_outpoint(
                        OutPoint::new(txid, vout as u32),
                        txout.script_pubkey.clone(),
                    )?;
                }
            }
        }
    }
    ensure_watchtower_alive(maker.as_ref())?;
    for (_, version) in &replacements {
        maker.save_outgoing_swapcoin(version)?;
    }

    let mut sent = Vec::with_capacity(replacements.len());
    for (split, version) in replacements {
        let tx = funding_tx(&version)
            .ok_or(MakerError::General("Outgoing swapcoin has no funding tx"))?;
        let txid = tx.compute_txid();
        match maker.broadcast_transaction(tx) {
            Ok(_) => {}
            Err(e) if is_already_broadcast_error(&e) => {}
            Err(e) => {
                // The original may have confirmed meanwhile, or the backend
                // refused the fee; either way that split keeps its versions.
                if !maker.is_transaction_known(&txid)? {
                    log::warn!(
                        "[{}] Replacement funding {} of swap {} was not accepted: {:?}",
                        maker.network_port(),
                        txid,
                        swap_id,
                        e
                    );
                    continue;
                }
            }
        }
        log::info!(
            "[{}] Broadcast replacement funding {} for split {} of swap {}",
            maker.network_port(),
            txid,
            split,
            swap_id
        );
        maker.record_funding_broadcast(swap_id, &txid)?;
        if !state.funding_broadcast_txids.contains(&txid) {
            state.funding_broadcast_txids.push(txid);
        }
        sent.push(BumpedFunding {
            split: split as u32,
            funding_tx: tx.clone(),
            contract_tx: (version.protocol == ProtocolVersion::Legacy)
                .then(|| version.contract_tx.clone()),
        });
    }
    maker.store_connection_state(swap_id, state, false)?;
    if sent.is_empty() {
        return Err(MakerError::General("No replacement funding was accepted"));
    }
    Ok(sent)
}

/// Replace our unconfirmed outgoing funding at the taker's feerate.
///
/// Taproot broadcasts at once. Legacy first hands back the replacement
/// unsigned, with the sender contracts the next hop must countersign: the
/// broadcast waits for [`handle_bump_funding_commit`].
pub(super) fn handle_bump_funding<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    request: BumpFunding,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    state.check_swap_id(&request.id)?;
    // Only a funded hop has anything to replace, a completed one nothing left.
    state.expect_phase(&[SwapPhase::AwaitingPrivateKeyHandover])?;
    authorize(
        state,
        &request.id,
        request.feerate,
        request.seq,
        false,
        &request.signature,
    )?;
    // Held from here through the broadcast: a concurrent bump must not build
    // a second set of replacements from the same versions, and the checks
    // below read the stored state, which another connection may have moved.
    let _funding = maker.begin_funding(&request.id)?;
    reload_funding_bump(maker, state)?;
    if request.seq <= state.funding_bump.seq {
        return Err(MakerError::General(
            "Funding bump replays an earlier request",
        ));
    }
    if state.funding_bump.settled {
        return Err(MakerError::General(
            "This hop's funding is settled; the next hop built on it",
        ));
    }

    // Asked again at the rate already out: our answer went missing, so hand
    // back the same versions rather than build new ones from them.
    if state.funding_bump.bumps > 0 && request.feerate == state.funding_bump.feerate {
        let replacements = broadcast_at(maker, state, &request.id, request.feerate)?;
        state.funding_bump.seq = request.seq;
        maker.store_connection_state(&request.id, state, false)?;
        return Ok(Some(MakerToTakerMessage::FundingBumped(FundingBumped {
            id: request.id,
            replacements,
        })));
    }
    if let Some(pending) = state
        .funding_bump
        .pending
        .as_mut()
        .filter(|pending| pending.feerate == request.feerate)
    {
        pending.seq = request.seq;
        let replacements = unsigned_proposal(&pending.replacements)?;
        state.funding_bump.seq = request.seq;
        maker.store_connection_state(&request.id, state, false)?;
        return Ok(Some(MakerToTakerMessage::BumpFundingProposal(
            BumpFundingProposal {
                id: request.id,
                replacements,
            },
        )));
    }

    let config = maker.get_config();
    if config.max_funding_bump_feerate == 0 {
        return Err(MakerError::General("This maker does not bump its funding"));
    }
    if request.feerate > config.max_funding_bump_feerate {
        return Err(MakerError::General("Funding bump feerate is above our cap"));
    }
    if state.funding_bump.bumps >= MAX_FUNDING_BUMPS {
        return Err(MakerError::General("This hop's funding was bumped enough"));
    }
    // A replacement must add the relay step on its own size, or no node
    // relays it in place of the original.
    let step = (maker.replacement_increment_rate().ceil() as u64).max(1);
    if request.feerate < current_feerate(state).saturating_add(step) {
        return Err(MakerError::General(
            "Funding bump does not outbid the current funding",
        ));
    }

    log::info!(
        "[{}] Bumping funding of swap {} to {} sat/vB",
        maker.network_port(),
        request.id,
        request.feerate
    );

    let replacements = build_replacements(maker, state, &request.id, request.feerate)?;
    if replacements.is_empty() {
        return Err(MakerError::General(
            "Every funding tx of this hop has confirmed",
        ));
    }
    state.funding_bump.seq = request.seq;

    match state.protocol {
        ProtocolVersion::Taproot => {
            state.funding_bump.feerate = request.feerate;
            state.funding_bump.bumps += 1;
            let sent = commit_and_broadcast(maker, state, &request.id, replacements)?;
            Ok(Some(MakerToTakerMessage::FundingBumped(FundingBumped {
                id: request.id,
                replacements: sent,
            })))
        }
        ProtocolVersion::Legacy => {
            let proposal = unsigned_proposal(&replacements)?;
            state.funding_bump.pending = Some(PendingFundingBump {
                seq: request.seq,
                feerate: request.feerate,
                replacements,
            });
            maker.store_connection_state(&request.id, state, false)?;
            Ok(Some(MakerToTakerMessage::BumpFundingProposal(
                BumpFundingProposal {
                    id: request.id,
                    replacements: proposal,
                },
            )))
        }
    }
}

/// Bring this connection's funding-bump state up to the stored one, which
/// another connection of the swap may have moved since this one last read
/// it. Called under the funding guard, so it stays current until stored.
fn reload_funding_bump<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
) -> Result<(), MakerError> {
    let Some(swap_id) = state.swap_id.clone() else {
        return Ok(());
    };
    if let Some(stored) = maker.get_connection_state(&swap_id)? {
        let mut current = stored.funding_bump;
        current.merge_from(&state.funding_bump, &state.outgoing_swapcoins);
        state.funding_bump = current;
    }
    Ok(())
}

/// Legacy: take the next hop's signatures on a proposal's sender contracts,
/// then broadcast the replacements.
pub(super) fn handle_bump_funding_commit<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    commit: BumpFundingCommit,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    state.check_swap_id(&commit.id)?;
    state.expect_phase(&[SwapPhase::AwaitingPrivateKeyHandover])?;
    authorize(
        state,
        &commit.id,
        commit.feerate,
        commit.seq,
        true,
        &commit.signature,
    )?;
    let _funding = maker.begin_funding(&commit.id)?;
    reload_funding_bump(maker, state)?;
    let pending = state
        .funding_bump
        .pending
        .take()
        .filter(|pending| pending.seq == commit.seq && pending.feerate == commit.feerate)
        .ok_or(MakerError::General("No funding bump proposal to commit"))?;
    if commit.senders_sigs.len() != pending.replacements.len() {
        return Err(MakerError::General(
            "Wrong number of contract signatures for the funding bump",
        ));
    }

    let mut replacements = pending.replacements;
    for ((_, version), sig) in replacements.iter_mut().zip(&commit.senders_sigs) {
        let (Some(my_pubkey), Some(other_pubkey)) = (version.my_pubkey, version.other_pubkey)
        else {
            return Err(MakerError::General("Outgoing swapcoin is missing its keys"));
        };
        verify_contract_tx_sig(
            &version.contract_tx,
            &create_multisig_redeemscript(&my_pubkey, &other_pubkey),
            version.funding_amount,
            &other_pubkey,
            &sig.signature,
        )
        .map_err(|_| MakerError::General("Invalid contract signature for the funding bump"))?;
        crate::protocol::contract::check_contract_sig_sighash(sig)?;
        version.others_contract_sig = Some(*sig);
    }

    state.funding_bump.feerate = pending.feerate;
    state.funding_bump.bumps += 1;
    let sent = commit_and_broadcast(maker, state, &commit.id, replacements)?;
    Ok(Some(MakerToTakerMessage::FundingBumped(FundingBumped {
        id: commit.id,
        replacements: sent,
    })))
}

/// Settle our hop on whichever version of each split confirmed: it becomes
/// the outgoing swapcoin the swap goes on with. The others keep their
/// swapcoins and watches until the swap ends, since a reorg can still confirm
/// one of them and recovery then needs it to refund. From here on the next
/// hop builds on the winner, so no further bump is taken. Fails while a
/// bumped split has no confirmed version, since nothing can be signed for it
/// yet.
pub(super) fn resolve_funding_versions<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
) -> Result<(), MakerError> {
    let swap_id = state
        .swap_id
        .clone()
        .ok_or(MakerError::General("No swap to resolve"))?;
    if state.funding_bump.replacements.is_empty() {
        state.funding_bump.pending = None;
        if !state.funding_bump.settled {
            state.funding_bump.settled = true;
            maker.store_connection_state(&swap_id, state, false)?;
        }
        return Ok(());
    }
    state.funding_bump.settled = true;

    let mut winners = Vec::with_capacity(state.outgoing_swapcoins.len());
    let mut losers: Vec<OutgoingSwapCoin> = Vec::new();
    for split in 0..state.outgoing_swapcoins.len() {
        let versions: Vec<OutgoingSwapCoin> = versions(state, split).into_iter().cloned().collect();
        if versions.len() == 1 {
            winners.push(versions[0].clone());
            continue;
        }
        let mut winner = None;
        for version in &versions {
            let txid: Txid = funding_tx(version)
                .ok_or(MakerError::General("Outgoing swapcoin has no funding tx"))?
                .compute_txid();
            if maker.is_funding_confirmed(&txid)? {
                winner = Some(version.clone());
                break;
            }
        }
        let winner = winner.ok_or(MakerError::General(
            "No version of a bumped funding has confirmed yet",
        ))?;
        let winning_txid = winner.contract_tx.compute_txid();
        losers.extend(
            versions
                .into_iter()
                .filter(|version| version.contract_tx.compute_txid() != winning_txid),
        );
        winners.push(winner);
    }

    for loser in &mut losers {
        loser.replaced = true;
    }
    maker.mark_replaced_funding(
        &losers
            .iter()
            .map(|loser| loser.contract_tx.compute_txid())
            .collect::<Vec<_>>(),
    )?;
    for loser in &losers {
        log::info!(
            "[{}] Funding version {} of swap {} lost to another; kept until the swap ends",
            maker.network_port(),
            loser.contract_tx.compute_txid(),
            swap_id
        );
    }
    state.outgoing_swapcoins = winners;
    state.funding_bump.replacements = losers;
    state.funding_bump.pending = None;
    maker.store_connection_state(&swap_id, state, false)
}
