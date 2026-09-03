//! Concurrent mixed-protocol integration test.
//!
//! Two takers use the same two makers at the same time: one swap uses Legacy
//! and the other uses Taproot. This verifies that makers keep protocol state
//! isolated per swap instead of treating the negotiated protocol as a
//! maker-wide setting.

use bitcoin::Amount;
use openswap::{
    maker::start_server,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc, Barrier,
    },
    thread,
};

#[test]
fn test_concurrent_legacy_and_taproot_swaps() {
    warn!("Running Test: Concurrent Legacy and Taproot swaps through the same makers");

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(8002, Some(21001)), (18002, Some(21002))],
            vec![TakerBehavior::Normal, TakerBehavior::Normal],
            vec![],
        );
    let bitcoind = &test_framework.bitcoind;

    let taker_original_balances = takers
        .iter()
        .map(|taker| {
            fund_taker(
                taker,
                bitcoind,
                3,
                Amount::from_btc(0.05).unwrap(),
                AddressType::P2TR,
            )
        })
        .collect::<Vec<_>>();
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
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
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
    let maker_original_balances = verify_maker_pre_swap_balances(&makers);
    generate_blocks(bitcoind, 1);

    let start = Arc::new(Barrier::new(2));
    let legacy_succeeded = AtomicBool::new(false);
    let taproot_succeeded = AtomicBool::new(false);

    thread::scope(|scope| {
        let (legacy_takers, taproot_takers) = takers.split_at_mut(1);
        let legacy_taker = &mut legacy_takers[0];
        let taproot_taker = &mut taproot_takers[0];

        let legacy_start = start.clone();
        let legacy_result = &legacy_succeeded;
        scope.spawn(move || {
            legacy_start.wait();
            info!("Starting Legacy swap concurrently");

            let params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 2)
                .with_tx_count([3, 3])
                .with_required_confirms(1);
            let result = legacy_taker
                .prepare_swap(params)
                .and_then(|summary| legacy_taker.start_swap(&summary.swap_id));

            match result {
                Ok(report) => {
                    info!("Concurrent Legacy swap completed: {:?}", report);
                    legacy_result.store(true, Relaxed);
                }
                Err(error) => warn!("Concurrent Legacy swap failed: {:?}", error),
            }
        });

        let taproot_start = start.clone();
        let taproot_result = &taproot_succeeded;
        scope.spawn(move || {
            taproot_start.wait();
            info!("Starting Taproot swap concurrently");

            let params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(700_000), 2)
                .with_tx_count([3, 3])
                .with_required_confirms(1);
            let result = taproot_taker
                .prepare_swap(params)
                .and_then(|summary| taproot_taker.start_swap(&summary.swap_id));

            match result {
                Ok(report) => {
                    info!("Concurrent Taproot swap completed: {:?}", report);
                    taproot_result.store(true, Relaxed);
                }
                Err(error) => warn!("Concurrent Taproot swap failed: {:?}", error),
            }
        });
    });

    assert!(
        legacy_succeeded.load(Relaxed),
        "Legacy swap should succeed while the makers also process a Taproot swap"
    );
    assert!(
        taproot_succeeded.load(Relaxed),
        "Taproot swap should succeed while the makers also process a Legacy swap"
    );

    let expected_taker_regular = [14_499_076, 14_299_076];
    let expected_taker_swap = [494_587, 694_730];
    let expected_taker_fees = [6_337, 6_194];

    for (i, (taker, original_balance)) in takers
        .iter()
        .zip(taker_original_balances.iter())
        .enumerate()
    {
        taker
            .get_wallet()
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let balances = taker.get_wallet().read().unwrap().get_balances().unwrap();

        info!(
            "Taker {} final balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i,
            balances.regular,
            balances.swap,
            balances.contract,
            balances.fidelity,
            balances.spendable,
        );

        assert_eq!(
            balances.regular.to_sat(),
            expected_taker_regular[i],
            "Taker {} regular balance mismatch",
            i
        );
        assert_eq!(
            balances.swap.to_sat(),
            expected_taker_swap[i],
            "Taker {i} swap balance"
        );
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "Taker {} contract balance mismatch",
            i
        );
        assert_eq!(
            balances.fidelity,
            Amount::ZERO,
            "Taker {} fidelity balance mismatch",
            i
        );
        assert_eq!(
            original_balance
                .checked_sub(balances.spendable)
                .unwrap()
                .to_sat(),
            expected_taker_fees[i],
            "Taker {i} spendable balance change"
        );
    }

    generate_blocks(bitcoind, 1);
    let expected_maker_regular = [13_802_266, 13_806_777];
    let expected_maker_swap = [1_198_428, 1_193_828];
    let expected_maker_earnings = [1_180, 1_091];

    for (i, (maker, original_balance)) in makers
        .iter()
        .zip(maker_original_balances.iter())
        .enumerate()
    {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();

        info!(
            "Maker {} final balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i,
            balances.regular,
            balances.swap,
            balances.contract,
            balances.fidelity,
            balances.spendable,
        );

        assert_eq!(
            balances.regular.to_sat(),
            expected_maker_regular[i],
            "Maker {i} regular balance"
        );
        assert_eq!(
            balances.swap.to_sat(),
            expected_maker_swap[i],
            "Maker {i} swap balance"
        );
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(
            balances.fidelity,
            Amount::from_btc(0.05).unwrap(),
            "Maker {} fidelity balance mismatch",
            i
        );
        assert_eq!(
            balances
                .spendable
                .checked_sub(*original_balance)
                .unwrap()
                .to_sat(),
            expected_maker_earnings[i],
            "Maker {i} earnings"
        );
    }

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|handle| handle.join().unwrap());
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
