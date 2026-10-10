//! Funding-source blocklist rejection through the real Legacy and Taproot swap paths.

use bitcoin::{Amount, Network};
use openswap::{
    blocklist::BlocklistError,
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, BanReason, BanRecord, MakerState, SwapParams, TakerBehavior},
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
    run_taker_rejection(ProtocolVersion::Legacy, 1, 0);
}

#[test]
fn taker_rejects_taproot_funding_from_blocked_address() {
    run_taker_rejection(ProtocolVersion::Taproot, 1, 0);
}

#[test]
fn taker_rejects_legacy_intermediate_funding_from_blocked_address() {
    run_taker_rejection(ProtocolVersion::Legacy, 2, 0);
}

#[test]
fn taker_rejects_taproot_intermediate_funding_from_blocked_address() {
    run_taker_rejection(ProtocolVersion::Taproot, 2, 0);
}

#[test]
fn legacy_proven_violation_precedes_blocklist_screen() {
    run_violation_with_blocked_funding(ProtocolVersion::Legacy);
}

#[test]
fn taproot_proven_violation_precedes_blocklist_screen() {
    run_violation_with_blocked_funding(ProtocolVersion::Taproot);
}

#[test]
fn legacy_populated_blocklist_is_ignored_when_disabled() {
    run_disabled_blocklist(ProtocolVersion::Legacy);
}

#[test]
fn taproot_populated_blocklist_is_ignored_when_disabled() {
    run_disabled_blocklist(ProtocolVersion::Taproot);
}

fn run_disabled_blocklist(protocol: ProtocolVersion) {
    let maker_count = 1;
    let taker_behaviors = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal];
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(maker_count, taker_behaviors, maker_behaviors);
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

    let maker_threads = spawn_makers(&makers);
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

    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 1)
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
    let maker_count = 2;
    let taker_behaviors = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_blocklist::<BitcoindBackend>(
            maker_count,
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

    fund_makers_default(&makers, bitcoind);

    let maker_threads = spawn_makers(&makers);
    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);
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

/// The maker skims a sat from its funding, which the taker can prove, and
/// funds from a listed address. The taker must reject on the violation and
/// ban the maker before it spends any backend queries screening that funding.
fn run_violation_with_blocked_funding(protocol: ProtocolVersion) {
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_blocklist::<BitcoindBackend>(
            1,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::FeeSkimming],
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker_default(taker, bitcoind, 3);
    fund_maker_from_one_address(
        &makers[0],
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = spawn_makers(&makers);
    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);

    // The same funding source the blocklist-only tests refuse.
    let blocked_address = sole_regular_utxo_address(&makers[0]);
    let outcome = taker
        .add_blocklist_entry(
            blocked_address.to_string(),
            Some("integration test maker source".to_string()),
        )
        .unwrap();
    assert_eq!(outcome.added, 1);

    let log_path = test_framework.taker_log_path();
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 1)
        .with_tx_count(1)
        .with_required_confirms(1);
    let summary = taker
        .prepare_swap(params)
        .expect("prepare_swap should succeed");
    match taker.start_swap(&summary.swap_id) {
        Err(TakerError::General(message)) => assert!(
            message.contains("does not match the negotiated hop total"),
            "unexpected taker error: {}",
            message
        ),
        Err(other) => panic!("expected the proven fee skim, got {:?}", other),
        Ok(_) => panic!("the taker accepted a fee-skimming maker's funding"),
    }

    // The screen logs every match. Its funding input is listed, so a screen
    // that ran would have logged this one.
    let contents = std::fs::read_to_string(&log_path).unwrap();
    let screened = contents
        .get(log_offset as usize..)
        .unwrap_or_default()
        .lines()
        .any(|line| line.contains(&format!("uses blocked address {}", blocked_address)));
    assert!(
        !screened,
        "the taker screened funding it had already proven invalid"
    );

    let address = format!("127.0.0.1:{}", makers[0].config.network_port);
    let standing = taker
        .fetch_offers()
        .unwrap()
        .all_makers()
        .into_iter()
        .find(|m| m.address.to_string() == address)
        .expect("the maker must be in the offerbook");
    assert!(
        matches!(
            standing.state,
            MakerState::Banned(BanRecord {
                reason: BanReason::ProvenViolation,
                ..
            })
        ),
        "a proven contract violation must ban the maker, got {:?}",
        standing.state
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

/// Route `maker_count` makers and list the funding source of the maker at
/// route position `blocked_maker`. The taker sees every maker's funding while
/// verifying it, so it must refuse whichever hop is listed, final or not.
fn run_taker_rejection(protocol: ProtocolVersion, maker_count: usize, blocked_maker: usize) {
    let taker_behaviors = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal; maker_count];
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_blocklist::<BitcoindBackend>(
            maker_count,
            taker_behaviors,
            maker_behaviors,
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker_default(taker, bitcoind, 3);

    // Reuse one address per maker for the initial deposits. Fidelity setup
    // later consolidates them into the regular UTXO used for swap funding.
    for maker in &makers {
        fund_maker_from_one_address(
            maker,
            bitcoind,
            4,
            Amount::from_btc(0.05).unwrap(),
            AddressType::P2TR,
        );
    }

    let maker_threads = spawn_makers(&makers);
    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);

    // Fidelity creation spends the deposits above. Block the resulting
    // regular change UTXO, which is the actual input to maker swap funding.
    // With every role screening the same list, a later maker would refuse an
    // intermediate hop too, but the taker sees each hop's funding first.
    let blocked_address = sole_regular_utxo_address(&makers[blocked_maker]);
    let outcome = taker
        .add_blocklist_entry(
            blocked_address.to_string(),
            Some("integration test maker source".to_string()),
        )
        .unwrap();
    assert_eq!(outcome.added, 1);
    assert_eq!(outcome.updated, 0);

    let params = SwapParams::new(protocol, Amount::from_sat(500_000), maker_count)
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

    // Every hop funded before the rejection stays locked in a contract until
    // its timelock matures and its funder sweeps it back. Rejecting must not
    // strand anyone's funds.
    thread::sleep(timelock_recovery_wait::<BitcoindBackend>());

    for (i, maker) in makers.iter().enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let maker_balances = maker.wallet.read().unwrap().get_balances().unwrap();
        println!(
            "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i,
            maker_balances.regular,
            maker_balances.swap,
            maker_balances.contract,
            maker_balances.spendable,
        );
        assert_eq!(
            maker_balances.contract.to_sat(),
            0,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(
            maker_balances.swap.to_sat(),
            0,
            "Maker {} swap balance mismatch",
            i
        );
        assert_eq!(maker_balances.fidelity, Amount::from_btc(0.05).unwrap());
    }

    assert!(
        taker.wait_for_recovery(),
        "the taker must recover its own funding after the rejection"
    );
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    assert_eq!(
        taker_balances.contract,
        Amount::ZERO,
        "Taker contract balance mismatch"
    );

    // A listed source is local policy, never proof of misbehaviour: no maker
    // on the route may be banned for it.
    let offerbook = taker.fetch_offers().unwrap().all_makers();
    for maker in &makers {
        let address = format!("127.0.0.1:{}", maker.config.network_port);
        let standing = offerbook
            .iter()
            .find(|m| m.address.to_string() == address)
            .expect("every route maker must be in the offerbook");
        assert!(
            !matches!(standing.state, MakerState::Banned(_)),
            "maker {} was banned for a blocklist refusal: {:?}",
            address,
            standing.state
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
