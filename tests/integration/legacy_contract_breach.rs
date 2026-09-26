//! Legacy breach: the taker broadcasts its maker-signed contract mid-swap.
//!
//! The taker holds its contract tx fully signed from `ReqContractSigsForSender`.
//! Broadcasting it spends the funding maker 0 is receiving, so maker 0 must stop
//! committing funds the moment the watchtower sees that spend:
//! 1. Before maker 0 funds: it never broadcasts its funding.
//! 2. After full setup: it refuses the key handover and recovers on-chain.

use bitcoin::Amount;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use super::test_framework::*;

use log::{info, warn};
use std::{thread, time::Duration};

/// Breach before maker 0 funds: maker 0 must not broadcast its funding txs.
#[test]
fn test_legacy_breach_before_maker_funding() {
    warn!("Running Test: Legacy breach before maker funding");

    let maker_count = 2;
    let taker_behavior = vec![TakerBehavior::BroadcastContractBeforeMakerFunding];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(maker_count, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker_default(taker, bitcoind, 3);
    fund_makers_default(&makers, bitcoind);

    let maker_threads = spawn_makers(&makers);

    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);
    verify_maker_pre_swap_balances(&makers);
    let regular_before: Vec<Amount> = makers
        .iter()
        .map(|m| m.wallet.read().unwrap().get_balances().unwrap().regular)
        .collect();

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);
    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(swap_result.is_err(), "Swap must fail: maker 0 never funds");
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

    // The first maker reached its funding step and saved the signed swapcoins,
    // then refused because of the breach rather than for any other reason.
    assert!(
        makers.iter().any(|m| m
            .has_unfinished_outgoing_swapcoin(&summary.swap_id)
            .unwrap()),
        "No maker saved the swap's outgoing swapcoins"
    );

    // Let any stray maker broadcast confirm before comparing balances.
    thread::sleep(Duration::from_secs(20));
    sync_maker_wallets(&makers);
    assert_breach_refused(&test_framework);

    for (i, maker) in makers.iter().enumerate() {
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.spendable
        );
        assert_eq!(
            balances.regular, regular_before[i],
            "Maker {i} regular balance changed: its funding must not have been broadcast"
        );
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "Maker {i} contract balance"
        );
    }

    shutdown_makers(&makers, maker_threads);
    test_framework.finish(takers, block_generation_handle);
}

/// Breach after full setup: maker 0 must refuse the key handover and recover.
#[test]
fn test_legacy_breach_before_handover() {
    warn!("Running Test: Legacy breach before key handover");

    let maker_count = 2;
    let taker_behavior = vec![TakerBehavior::BroadcastContractBeforeHandover];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(maker_count, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker_default(taker, bitcoind, 3);
    fund_makers_default(&makers, bitcoind);

    let maker_threads = spawn_makers(&makers);

    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);
    verify_maker_pre_swap_balances(&makers);

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);
    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap must fail: maker 0 refuses the handover"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

    info!("Waiting for makers to recover on-chain...");
    thread::sleep(timelock_recovery_wait::<BitcoindBackend>());
    sync_maker_wallets(&makers);
    assert_breach_refused(&test_framework);

    for (i, maker) in makers.iter().enumerate() {
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.spendable
        );
        // Observed in a real run: each maker swept its incoming contract via the
        // hashlock. A maker that had handed over its outgoing leg would be ~500k short.
        let expected_regular = [14500865u64, 14502398][i];
        let expected_swap = [499100u64, 497530][i];
        assert_eq!(
            balances.regular.to_sat(),
            expected_regular,
            "Maker {i} regular balance"
        );
        assert_eq!(
            balances.swap.to_sat(),
            expected_swap,
            "Maker {i} swap balance"
        );
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "Maker {i} contract balance"
        );
    }

    shutdown_makers(&makers, maker_threads);
    test_framework.finish(takers, block_generation_handle);
}

/// The maker refused because of the breach, not for any other reason.
fn assert_breach_refused(test_framework: &TestFramework) {
    let log_path = test_framework.taker_log_path();
    test_framework.assert_log("ContractBroadcast", &log_path);
}
