//! Maker admission must fail closed after its watcher thread exits.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, SwapParams, TakerBehavior},
    wallet::AddressType,
};
use std::{sync::atomic::Ordering::Relaxed, thread};

use super::test_framework::*;

#[test]
fn maker_rejects_new_swaps_after_watcher_exit() {
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(7902, Some(20901))],
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
        );
    let bitcoind = &test_framework.bitcoind;

    let taker = &mut takers[0];
    fund_taker(
        taker,
        bitcoind,
        2,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        2,
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

    let maker = &makers[0];
    assert!(maker.watch_service.is_alive());
    maker.watch_service.stop_watcher_for_test();
    assert!(!maker.watch_service.is_alive());

    for protocol in [ProtocolVersion::Legacy, ProtocolVersion::Taproot] {
        let result = taker.prepare_swap(
            SwapParams::new(protocol, Amount::from_sat(500_000), 1)
                .with_tx_count([1, 3])
                .with_required_confirms(1),
        );
        match result {
            Err(TakerError::General(message)) => assert!(
                message.contains("Maker 0 rejected swap"),
                "unexpected admission error: {}",
                message
            ),
            other => panic!("unexpected admission result: {:?}", other),
        }
    }

    drop(takers);
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|handle| handle.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn taker_refuses_swap_before_funding_after_watcher_exit() {
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(7903, Some(20902))],
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = &mut takers[0];

    fund_taker(
        taker,
        bitcoind,
        2,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        2,
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

    let summary = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
                .with_tx_count([1, 3])
                .with_required_confirms(1),
        )
        .unwrap();
    taker.behavior = TakerBehavior::StopWatcherBeforeSwap;
    let error = taker.start_swap(&summary.swap_id).unwrap_err();
    assert!(format!("{error:?}").contains("watchtower is down"));
    assert_eq!(
        taker
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count(),
        0
    );

    drop(takers);
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|handle| handle.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn funded_maker_restarts_recovery_only_without_watcher() {
    super::reboot_recovery::run_reboot_recovery_without_watcher::<BitcoindBackend>();
}

#[test]
fn funded_legacy_maker_reaches_timelock_recovery_without_watcher() {
    super::skip_funding_recovery::run_legacy_timelock_recovery_without_watcher();
}
