//! Electrum-only openswap tests.
//!
//! - The watch-tower uses `ElectrumNotifier` + `electrum_chain_name`/`electrum_block_count` instead of ZMQ + Bitcoin Core REST.
//! - The offer-sync and Nostr discovery use `electrum_block_count`/`electrum_get_raw_tx`.
//!   Bitcoind is still spawned because it is the source of regtest funds and mines blocks, but the openswap code itself talks only to electrs.

use super::test_framework::*;
use bitcoin::Amount;
use log::info;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    wallet::AddressType,
};
use std::{sync::atomic::Ordering::Relaxed, thread};

/// Exact post-swap balances for one protocol run. Legacy and taproot spend
/// different transaction shapes, so each protocol pins its own values.
struct ExpectedBalances {
    taker_regular: u64,
    taker_swap: u64,
    taker_fee: u64,
    maker_regular: [u64; 2],
    maker_swap: [u64; 2],
    maker_earnings: [u64; 2],
}

const TAPROOT_EXPECTED: ExpectedBalances = ExpectedBalances {
    taker_regular: 14_499_076,
    taker_swap: 494_815,
    taker_fee: 6_109,
    maker_regular: [14_500_865, 14_503_103],
    maker_swap: [499_328, 497_053],
    maker_earnings: [679, 642],
};

const LEGACY_EXPECTED: ExpectedBalances = ExpectedBalances {
    taker_regular: 14_499_076,
    taker_swap: 494_587,
    taker_fee: 6_337,
    maker_regular: [14_500_865, 14_503_103],
    maker_swap: [499_100, 496_825],
    maker_earnings: [451, 414],
};

/// Run an Electrum-only openswap with the given protocol version and assert the
/// exact post-swap taker / maker balances.
fn run_electrum_swap(protocol: ProtocolVersion, expected: &ExpectedBalances) {
    info!("Running Test: Electrum OpenSwap Procedure ({protocol:?})");
    let makers_config_map = vec![(6102, Some(19051)), (16102, Some(19052))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<ElectrumBackend>(makers_config_map, taker_behavior, maker_behaviors);
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
    info!("Initiating Maker servers");
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 180);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    let swap_params = SwapParams::new(protocol, Amount::from_sat(500_000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);
    generate_blocks(bitcoind, 1);
    // The taker's pre-swap sync must see the funding blocks, not a stale index.
    test_framework.wait_for_electrs_tip();
    let summary = taker.prepare_swap(swap_params).unwrap();
    taker.start_swap(&summary.swap_id).unwrap();
    // electrs indexes asynchronously; let it reach the tip before the
    // post-swap syncs so the asserted balances aren't computed from a
    // stale index.
    test_framework.wait_for_electrs_tip();
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    generate_blocks(bitcoind, 1);
    test_framework.wait_for_electrs_tip();
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .expect("Taker spendable balance should not exceed original");
    let maker_balances = makers
        .iter()
        .map(|maker| maker.wallet.read().unwrap().get_balances().unwrap())
        .collect::<Vec<_>>();
    info!(
        "Electrum {protocol:?} taker: regular {}, swap {}, contract {}, spendable {}, fee {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
        balance_diff,
    );
    for (i, balances) in maker_balances.iter().enumerate() {
        info!(
            "Electrum {protocol:?} maker {i}: regular {}, swap {}, contract {}, fidelity {}, spendable {}, earned {}",
            balances.regular,
            balances.swap,
            balances.contract,
            balances.fidelity,
            balances.spendable,
            balances
                .spendable
                .checked_sub(maker_spendable_balance[i])
                .unwrap_or(Amount::ZERO),
        );
    }

    assert_eq!(
        taker_balances.regular.to_sat(),
        expected.taker_regular,
        "Taker regular balance mismatch"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        expected.taker_swap,
        "Taker swap balance mismatch"
    );
    assert_eq!(
        taker_balances.contract,
        Amount::ZERO,
        "All contract outputs should be resolved post-swap"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);
    assert_eq!(
        balance_diff.to_sat(),
        expected.taker_fee,
        "Taker fee mismatch"
    );
    for (i, balances) in maker_balances.iter().enumerate() {
        assert_eq!(
            balances.regular.to_sat(),
            expected.maker_regular[i],
            "Maker {i} regular balance mismatch"
        );
        assert_eq!(
            balances.swap.to_sat(),
            expected.maker_swap[i],
            "Maker {i} swap balance mismatch"
        );
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "Maker {} contract balance should be zero",
            i
        );
        assert_eq!(
            balances.fidelity,
            Amount::from_btc(0.05).unwrap(),
            "Maker {} should still hold its fidelity bond",
            i
        );
        let earned = balances
            .spendable
            .checked_sub(maker_spendable_balance[i])
            .unwrap_or(Amount::ZERO);
        assert_eq!(
            earned.to_sat(),
            expected.maker_earnings[i],
            "Maker {i} earnings mismatch"
        );
    }
    info!("Electrum-only openswap test ({protocol:?}) completed successfully!");
    drop(takers);
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads.into_iter().for_each(|t| t.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn test_taproot_openswap_electrum() {
    run_electrum_swap(ProtocolVersion::Taproot, &TAPROOT_EXPECTED);
}

#[test]
fn test_legacy_openswap_electrum() {
    run_electrum_swap(ProtocolVersion::Legacy, &LEGACY_EXPECTED);
}
