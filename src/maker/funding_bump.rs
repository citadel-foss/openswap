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
    for sig in &commit.senders_sigs {
        crate::protocol::contract::check_contract_sig_sighash(sig)?;
    }
    let _funding = maker.begin_funding(&commit.id)?;
    reload_funding_bump(maker, state)?;
    // Checked again under the guard, on the stored state: since the proposal
    // the hop may have settled on another connection, or a version of a split
    // it replaces been mined, and the next hop built on it.
    if state.funding_bump.settled {
        return Err(MakerError::General(
            "This hop's funding is settled; the next hop built on it",
        ));
    }
    if let Some(pending) = state.funding_bump.pending.as_ref() {
        for (split, _) in &pending.replacements {
            if any_confirmed(maker, &commit.id, &versions(state, *split))? {
                return Err(MakerError::General(
                    "A funding tx of this bump's split has confirmed",
                ));
            }
        }
    }
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
    // Held through resolution and storage, and decided on the stored state:
    // another connection may have bumped since this one's snapshot, and the
    // settle decision and next hop's contract must be for the right version.
    let _funding = maker.begin_funding(&swap_id)?;
    if let Some(stored) = maker.get_connection_state(&swap_id)? {
        if stored.outgoing_swapcoins.len() == state.outgoing_swapcoins.len() {
            state.outgoing_swapcoins = stored.outgoing_swapcoins;
        }
        let mut current = stored.funding_bump;
        current.merge_from(&state.funding_bump, &state.outgoing_swapcoins);
        state.funding_bump = current;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        maker::{api::tests::compat_test_maker, handlers::PendingFundingBump},
        protocol::funding_bump::sign_bump,
    };
    use bitcoin::{
        hashes::Hash,
        secp256k1::{Message, Secp256k1, SecretKey},
        Amount, PublicKey, ScriptBuf, TxIn, TxOut,
    };

    const SWAP: &str = "bump-race";

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn tx(input: OutPoint, value: u64) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: input,
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    /// A Legacy version of our one split's funding, told apart by `value`:
    /// every version spends the same coin.
    fn version(value: u64) -> OutgoingSwapCoin {
        let secp = Secp256k1::new();
        let pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &key(7)),
        };
        let funding = tx(OutPoint::new(Txid::from_byte_array([9; 32]), 0), value);
        let contract = tx(OutPoint::new(funding.compute_txid(), 0), value - 500);
        let mut coin = OutgoingSwapCoin::new_legacy(
            key(7),
            pubkey,
            contract,
            ScriptBuf::new(),
            key(8),
            Amount::from_sat(value),
            1,
        );
        coin.funding_tx = Some(funding);
        coin.swap_id = Some(SWAP.to_string());
        coin
    }

    /// One connection's view of a funded Legacy hop awaiting the handover.
    fn connection(original: &OutgoingSwapCoin) -> ConnectionState {
        ConnectionState {
            swap_id: Some(SWAP.to_string()),
            phase: SwapPhase::AwaitingPrivateKeyHandover,
            protocol: ProtocolVersion::Legacy,
            taker_auth_pubkey: Some(key(5).x_only_public_key(&Secp256k1::new()).0),
            outgoing_swapcoins: vec![original.clone()],
            swap_feerate: 1.0,
            ..Default::default()
        }
    }

    fn proposal(seq: u32) -> PendingFundingBump {
        PendingFundingBump {
            seq,
            feerate: 5,
            replacements: vec![(0, version(49_000))],
        }
    }

    /// The taker's commit of the proposal at `seq`, properly signed.
    fn commit(original: &OutgoingSwapCoin, seq: u32) -> BumpFundingCommit {
        let hop = original.funding_tx.as_ref().unwrap().input[0].previous_output;
        let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest([1; 32]), &key(9));
        BumpFundingCommit {
            id: SWAP.to_string(),
            feerate: 5,
            seq,
            senders_sigs: vec![bitcoin::ecdsa::Signature::sighash_all(sig)],
            signature: sign_bump(&key(5), SWAP, &hop, 5, seq, true),
        }
    }

    /// The original is mined after the proposal was built, and the next hop
    /// builds on it: the commit must not put out the conflicting replacement.
    #[test]
    fn a_commit_is_refused_once_a_version_of_its_split_confirmed() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let maker = compat_test_maker(dir.path(), Vec::new());
        let original = version(50_000);
        let mut state = connection(&original);
        state.funding_bump.seq = 1;
        state.funding_bump.pending = Some(proposal(1));
        let mined = funding_tx(&original).unwrap().compute_txid();
        maker.seed_swap_for_test(SWAP, &state, &[mined]).unwrap();

        let err = handle_bump_funding_commit(&maker, &mut state, commit(&original, 1)).unwrap_err();
        assert!(format!("{:?}", err).contains("has confirmed"), "{:?}", err);
        maker.watch_service.shutdown();
    }

    /// Connection B settled the hop and cleared the proposal; A still holds
    /// it at the same sequence. A's commit must find the hop settled, not
    /// bring the cleared proposal back.
    #[test]
    fn a_commit_is_refused_once_another_connection_settled_the_hop() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let maker = compat_test_maker(dir.path(), Vec::new());
        let original = version(50_000);
        let mut a = connection(&original);
        a.funding_bump.seq = 3;
        a.funding_bump.pending = Some(proposal(3));
        let mut b = a.clone();
        b.funding_bump.pending = None;
        b.funding_bump.settled = true;
        maker.seed_swap_for_test(SWAP, &b, &[]).unwrap();

        let err = handle_bump_funding_commit(&maker, &mut a, commit(&original, 3)).unwrap_err();
        assert!(format!("{:?}", err).contains("settled"), "{:?}", err);
        let stored = maker.get_connection_state(SWAP).unwrap().unwrap();
        assert!(stored.funding_bump.pending.is_none());
        maker.watch_service.shutdown();
    }

    /// A valid contract signature under another sighash flag would put a
    /// refund in the witness that script evaluation rejects: the commit is
    /// refused before anything is stored or broadcast.
    #[test]
    fn a_commit_with_a_non_sighash_all_contract_sig_is_refused() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let maker = compat_test_maker(dir.path(), Vec::new());
        let original = version(50_000);
        let mut state = connection(&original);
        state.funding_bump.seq = 1;
        state.funding_bump.pending = Some(proposal(1));
        maker.seed_swap_for_test(SWAP, &state, &[]).unwrap();

        let replacement = &proposal(1).replacements[0].1;
        let (my_pubkey, other_pubkey) = (
            replacement.my_pubkey.unwrap(),
            replacement.other_pubkey.unwrap(),
        );
        let mut sig = crate::protocol::contract::sign_contract_tx(
            &replacement.contract_tx,
            &create_multisig_redeemscript(&my_pubkey, &other_pubkey),
            replacement.funding_amount,
            &key(7),
        )
        .unwrap();
        verify_contract_tx_sig(
            &replacement.contract_tx,
            &create_multisig_redeemscript(&my_pubkey, &other_pubkey),
            replacement.funding_amount,
            &other_pubkey,
            &sig.signature,
        )
        .expect("the signature itself is valid");
        sig.sighash_type = bitcoin::sighash::EcdsaSighashType::SinglePlusAnyoneCanPay;
        let mut bad = commit(&original, 1);
        bad.senders_sigs = vec![sig];

        let err = handle_bump_funding_commit(&maker, &mut state, bad).unwrap_err();
        assert!(format!("{:?}", err).contains("SIGHASH_ALL"), "{:?}", err);
        assert!(state.funding_bump.pending.is_some());
        assert_eq!(state.funding_bump.bumps, 0);
        let stored = maker.get_connection_state(SWAP).unwrap().unwrap();
        assert_eq!(stored.outgoing_swapcoins.len(), 1);
        assert!(stored.funding_bump.replacements.is_empty());
        maker.watch_service.shutdown();
    }

    /// B stored a replacement while A's snapshot still has none. A resolving
    /// must decide on B's replacement too, never settle on the original
    /// alone. The test maker has no node, so it stops at the confirmation
    /// lookup, which the original-only path never reaches.
    #[test]
    fn settlement_resolves_on_another_connections_replacement() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let maker = compat_test_maker(dir.path(), Vec::new());
        let original = version(50_000);
        let mut a = connection(&original);
        let mut b = a.clone();
        b.funding_bump.seq = 1;
        b.funding_bump.bumps = 1;
        b.funding_bump.replacements = vec![version(49_000)];
        maker.seed_swap_for_test(SWAP, &b, &[]).unwrap();

        let resolved = resolve_funding_versions(&maker, &mut a);
        assert_eq!(a.funding_bump.replacements.len(), 1, "{:?}", resolved);
        assert!(resolved.is_err(), "no node answers which version is mined");
        maker.watch_service.shutdown();
    }
}
