//! Funding-source blocklist rejection through the real Legacy and Taproot swap paths.

use bitcoin::{Amount, Network};
use openswap::{
    blocklist::BlocklistError,
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use std::{sync::atomic::Ordering::Relaxed, thread};

#[test]
fn maker_rejects_legacy_funding_from_blocked_address() {
    run_maker_rejection(ProtocolVersion::Legacy);
}

#[test]
fn maker_rejects_taproot_funding_from_blocked_address() {
    run_maker_rejection(ProtocolVersion::Taproot);
}

#[test]
fn taker_rejects_legacy_funding_from_blocked_address() {
    run_taker_rejection(ProtocolVersion::Legacy);
}

#[test]
fn taker_rejects_taproot_funding_from_blocked_address() {
    run_taker_rejection(ProtocolVersion::Taproot);
}

#[test]
fn populated_blocklist_is_ignored_when_disabled() {
    let makers_config_map = vec![(6102, None)];
    let taker_behaviors = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal];
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behaviors, maker_behaviors);
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    let blocked_taker_address = taker
        .get_wallet()
        .write()
        .unwrap()
        .get_next_external_address(AddressType::P2TR)
        .unwrap();
    for _ in 0..3 {
        send_to_address(
            bitcoind,
            &blocked_taker_address,
            Amount::from_btc(0.05).unwrap(),
        );
    }
    generate_blocks(bitcoind, 1);
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    let maker_deposit_address = makers[0]
        .wallet
        .write()
        .unwrap()
        .get_next_external_address(AddressType::P2TR)
        .unwrap();
    for _ in 0..4 {
        send_to_address(
            bitcoind,
            &maker_deposit_address,
            Amount::from_btc(0.05).unwrap(),
        );
    }
    generate_blocks(bitcoind, 1);
    makers[0]
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    taker
        .add_blocklist_entry(
            blocked_taker_address.to_string(),
            Some("disabled maker-side check".to_string()),
        )
        .unwrap();

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    makers[0]
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    let maker_regular_utxos = makers[0]
        .wallet
        .read()
        .unwrap()
        .list_descriptor_utxo_spend_info();
    assert_eq!(maker_regular_utxos.len(), 1);
    let blocked_maker_address = bitcoin::Address::from_script(
        maker_regular_utxos[0].0.script_pub_key.as_script(),
        Network::Regtest,
    )
    .unwrap();
    taker
        .add_blocklist_entry(
            blocked_maker_address.to_string(),
            Some("disabled taker-side check".to_string()),
        )
        .unwrap();

    let params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
        .with_tx_count(1)
        .with_required_confirms(1);
    let summary = taker
        .prepare_swap(params)
        .expect("prepare_swap should succeed");
    taker
        .start_swap(&summary.swap_id)
        .expect("a populated blocklist must be ignored when checking is disabled");

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

fn run_maker_rejection(protocol: ProtocolVersion) {
    let makers_config_map = vec![(6102, None), (16102, None)];
    let taker_behaviors = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_blocklist::<BitcoindBackend>(
            makers_config_map,
            taker_behaviors,
            maker_behaviors,
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Every spendable taker UTXO comes from this address, so whichever coins
    // funding selects must trigger the maker's source-address check.
    let blocked_address = taker
        .get_wallet()
        .write()
        .unwrap()
        .get_next_external_address(AddressType::P2TR)
        .unwrap();
    for _ in 0..3 {
        send_to_address(bitcoind, &blocked_address, Amount::from_btc(0.05).unwrap());
    }
    generate_blocks(bitcoind, 1);
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    assert_eq!(
        taker
            .get_wallet()
            .read()
            .unwrap()
            .get_balances()
            .unwrap()
            .regular,
        Amount::from_btc(0.15).unwrap()
    );

    let outcome = taker
        .add_blocklist_entry(
            blocked_address.to_string(),
            Some("integration test source".to_string()),
        )
        .unwrap();
    assert_eq!(outcome.added, 1);
    assert_eq!(outcome.updated, 0);

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
    let maker_spendable_before = verify_maker_pre_swap_balances(&makers);

    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 2)
        .with_tx_count(1)
        .with_required_confirms(1);
    let summary = taker
        .prepare_swap(params)
        .expect("prepare_swap should succeed");
    assert!(
        taker.start_swap(&summary.swap_id).is_err(),
        "the first maker must reject funding from the blocked source address"
    );

    for (maker, spendable_before) in makers.iter().zip(maker_spendable_before) {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        assert_eq!(
            maker
                .wallet
                .read()
                .unwrap()
                .get_balances()
                .unwrap()
                .spendable,
            spendable_before,
            "blocklist rejection must happen before maker liquidity is spent"
        );
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

fn run_taker_rejection(protocol: ProtocolVersion) {
    let makers_config_map = vec![(6102, None)];
    let taker_behaviors = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal];
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_blocklist::<BitcoindBackend>(
            makers_config_map,
            taker_behaviors,
            maker_behaviors,
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Reuse one maker address for the initial deposits. Fidelity setup later
    // consolidates them into the regular UTXO used for swap funding.
    let maker_deposit_address = makers[0]
        .wallet
        .write()
        .unwrap()
        .get_next_external_address(AddressType::P2TR)
        .unwrap();
    for _ in 0..4 {
        send_to_address(
            bitcoind,
            &maker_deposit_address,
            Amount::from_btc(0.05).unwrap(),
        );
    }
    generate_blocks(bitcoind, 1);
    makers[0]
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    assert_eq!(
        makers[0]
            .wallet
            .read()
            .unwrap()
            .get_balances()
            .unwrap()
            .regular,
        Amount::from_btc(0.20).unwrap()
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    makers[0]
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    // Fidelity creation spends the deposits above. Block the resulting
    // regular change UTXO, which is the actual input to maker swap funding.
    let maker_regular_utxos = makers[0]
        .wallet
        .read()
        .unwrap()
        .list_descriptor_utxo_spend_info();
    assert_eq!(maker_regular_utxos.len(), 1);
    let blocked_address = bitcoin::Address::from_script(
        maker_regular_utxos[0].0.script_pub_key.as_script(),
        Network::Regtest,
    )
    .unwrap();
    let outcome = taker
        .add_blocklist_entry(
            blocked_address.to_string(),
            Some("integration test maker source".to_string()),
        )
        .unwrap();
    assert_eq!(outcome.added, 1);
    assert_eq!(outcome.updated, 0);

    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 1)
        .with_tx_count(1)
        .with_required_confirms(1);
    let summary = taker
        .prepare_swap(params)
        .expect("prepare_swap should succeed");
    match taker.start_swap(&summary.swap_id) {
        Err(TakerError::Blocklist(BlocklistError::BlockedAddress { entry, .. })) => {
            assert_eq!(entry.address, blocked_address.to_string());
        }
        Err(other) => panic!("expected blocked-address error, got {:?}", other),
        Ok(_) => panic!("the taker accepted funding from the maker's blocked source address"),
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
