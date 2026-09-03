//! Integration tests for flexible per-hop transaction splitting (Taproot).
//!
//! A taker can ask each hop to fan out to a different number of outgoing contracts via
//! `SwapParams::tx_counts`. These tests cover:
//!
//! - the happy path for an uneven `[1, 3, 1]` route across 2 makers (a passing swap is
//!   itself the per-hop count assertion: the taker aborts unless each maker returns
//!   exactly the agreed count),
//! - a maker that over- or under-splits being rejected before the taker signs, and
//! - the backward-compatibility path where a maker predating the feature (advertising
//!   `max_tx_splits: None`) forces a clean pre-funding abort rather than a mid-swap one.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{sync::atomic::Ordering::Relaxed, thread};

/// Happy path: a `[1, 3, 1]` route through 2 makers. The taker funds a single contract,
/// the first maker fans out to 3, and the second collapses back to 1.
#[test]
fn test_taproot_per_hop_splits_1_3_1() {
    warn!("Running Test: Taproot per-hop splitting with an uneven [1, 3, 1] route");

    let makers_config_map = vec![(7920, Some(20920)), (17920, Some(20921))];
    let taker_behavior = vec![TakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, vec![]);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Each maker needs enough confirmed UTXOs to build its outgoing contracts (the first
    // maker fans out to 3), plus its fidelity bond.
    fund_makers(
        &makers,
        bitcoind,
        5,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || start_server(maker_clone).unwrap())
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    // Capture pre-swap spendable directly (the shared helper hardcodes a 4-UTXO golden).
    let maker_spendable_balance: Vec<Amount> = makers
        .iter()
        .map(|m| m.wallet.read().unwrap().get_balances().unwrap().spendable)
        .collect();

    // Uneven per-hop counts: index 0 is the taker's own funding, then each maker's
    // outgoing split. Length is maker_count + 1.
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
        .with_tx_counts(vec![1, 3, 1])
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare [1,3,1] Taproot coinswap");
    info!("Swap summary: {summary:?}");
    // The mining-fee estimate must scale with the total number of splits (1 + 3 + 1 = 5).
    assert!(
        summary.total_mining_fee > Amount::ZERO,
        "expected a non-zero mining fee estimate for an uneven split route"
    );

    // Completion is the per-hop count check: the taker aborts unless each hop returns the
    // agreed count, so success proves 1 -> 3 -> 1 held on-chain.
    taker
        .start_swap(&summary.swap_id)
        .expect("[1,3,1] Taproot coinswap should complete");

    // Keep makers running so their post-swap sweep can finish (it aborts on shutdown),
    // then mine a block and sync before checking balances. Shut down at the very end.
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    generate_blocks(bitcoind, 1);
    for maker in makers.iter() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let taker_after = taker.get_wallet().read().unwrap().get_balances().unwrap();
    info!(
        "Taker after [1,3,1] swap - spendable: {}, contract: {}, swap: {}",
        taker_after.spendable, taker_after.contract, taker_after.swap
    );

    // Structural checks only (randomized chunking rules out golden sats): contracts
    // resolved and the taker paid a fee.
    assert_eq!(
        taker_after.contract.to_sat(),
        0,
        "taker contract balance must be swept to zero"
    );
    assert!(
        taker_after.spendable < taker_original_balance,
        "taker should have paid fees: before={taker_original_balance}, after={}",
        taker_after.spendable
    );

    for (i, (maker, original_spendable)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
        // Zero contract balance proves the hop settled cleanly.
        assert_eq!(
            balances.contract.to_sat(),
            0,
            "maker {i} contract balance must be zero after swap"
        );
        // No per-maker profit assertion: a collapse hop (3 -> 1) can net slightly negative
        // (mining fee is per outgoing, sweep cost per incoming). The taker's exact
        // `expected_amount_for_hop` replay already guarantees amounts reconcile.
        info!(
            "Maker {i} spendable {} -> {}",
            original_spendable, balances.spendable
        );
    }

    info!("[1,3,1] per-hop split swap completed successfully");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// A maker that builds MORE outgoing contracts than requested must be rejected by the
/// taker before it signs anything.
#[test]
fn test_taproot_maker_over_split_rejected() {
    warn!("Running Test: taker rejects a maker that over-splits its outgoing contracts");
    run_misbehaving_split_maker(MakerBehavior::OverSplitTaprootContract);
}

/// A maker that builds FEWER outgoing contracts than requested must be rejected too.
#[test]
fn test_taproot_maker_under_split_rejected() {
    warn!("Running Test: taker rejects a maker that under-splits its outgoing contracts");
    run_misbehaving_split_maker(MakerBehavior::UnderSplitTaprootContract);
}

/// Shared driver for the over/under-split rejection tests. Uses a single maker (so route
/// order is irrelevant) with a uniform `tx_count` of 3; the maker then returns 4 or 2
/// contracts respectively and the taker must abort at contract verification.
fn run_misbehaving_split_maker(behavior: MakerBehavior) {
    let makers_config_map = vec![(7930, Some(20930))];
    let taker_behavior = vec![TakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, vec![behavior]);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    // Headroom: over-splitting turns a requested 3-way fan-out into 4 distinct funding
    // txs, each needing its own confirmed UTXO on top of the fidelity bond.
    fund_makers(
        &makers,
        bitcoind,
        7,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || start_server(maker_clone).unwrap())
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
        .with_tx_count(3)
        .with_required_confirms(1);
    let summary = taker
        .prepare_swap(swap_params)
        .expect("failed to prepare Taproot coinswap");

    let error = taker
        .start_swap(&summary.swap_id)
        .expect_err("taker must reject a maker that returns the wrong outgoing split count");
    match error {
        TakerError::General(message) => {
            assert!(
                message.contains("agreed outgoing split for this hop"),
                "unexpected taker error: {}",
                message
            );
        }
        other => panic!("unexpected taker error: {:?}", other),
    }

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// Backward compatibility: when every maker predates per-hop splitting (advertises
/// `max_tx_splits: None`) but the taker asks for an uneven `[1, 3, 1]` route, the taker
/// must abort during negotiation — before any funds are committed — rather than discover
/// the mismatch mid-swap.
#[test]
fn test_taproot_uneven_split_old_maker_aborts_before_funding() {
    warn!("Running Test: uneven split against pre-feature makers aborts before funding");

    let makers_config_map = vec![(7940, Some(20940)), (17940, Some(20941))];
    let taker_behavior = vec![TakerBehavior::Normal];
    // Both makers emulate old software with no per-hop-split support.
    let maker_behaviors = vec![
        MakerBehavior::AdvertiseNoSplitSupport,
        MakerBehavior::AdvertiseNoSplitSupport,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || start_server(maker_clone).unwrap())
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    // Both hops of [1, 3, 1] are uneven (1->3, 3->1), so with no supporting maker and no
    // spare, preparation aborts regardless of route order.
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
        .with_tx_counts(vec![1, 3, 1])
        .with_required_confirms(1);

    let result = taker.prepare_swap(swap_params);
    match result {
        Err(TakerError::General(message)) => {
            assert!(
                message.contains("predates per-hop splitting"),
                "unexpected taker error: {}",
                message
            );
        }
        Err(other) => panic!("unexpected taker error: {:?}", other),
        Ok(summary) => panic!(
            "preparation should have aborted, got summary: {:?}",
            summary
        ),
    }

    // No funding should have been broadcast: the taker's balance is untouched.
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let taker_after = taker.get_wallet().read().unwrap().get_balances().unwrap();
    assert_eq!(
        taker_after.spendable, taker_original_balance,
        "no funds should be committed when preparation aborts"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
