//! Integration test for multi-taker concurrent openswap with Taproot protocol.
//!
//! Setup: 2 takers with Normal behavior, 2 makers with Normal behavior.
//! Protocol: Taproot (MuSig2), AddressType::P2TR.
//! Both takers run swaps sequentially through the same pair of makers.

use bitcoin::Amount;
use openswap::{
    maker::start_server,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{sync::atomic::Ordering::Relaxed, thread};

#[test]
fn test_taproot_multi_taker_openswap() {
    // ---- Setup ----
    warn!("Running Test: Multi-Taker OpenSwap with Taproot (MuSig2) Protocol");

    let makers_config_map = vec![(7702, Some(20701)), (17702, Some(20702))];
    let taker_behavior = vec![TakerBehavior::Normal, TakerBehavior::Normal];

    // Initialize test framework with 2 takers and 2 makers
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, vec![]);

    let bitcoind = &test_framework.bitcoind;

    // Fund each taker thrice with one 0.05 BTC UTXO (0.15 total), one per call so
    // each lands on a distinct address and coin_select doesn't group them.
    let mut taker1_original_balance = Amount::ZERO;
    let mut taker2_original_balance = Amount::ZERO;
    for _ in 0..3 {
        taker1_original_balance = fund_taker(
            &takers[0],
            bitcoind,
            1,
            Amount::from_btc(0.05).unwrap(),
            AddressType::P2TR,
        );
        taker2_original_balance = fund_taker(
            &takers[1],
            bitcoind,
            1,
            Amount::from_btc(0.05).unwrap(),
            AddressType::P2TR,
        );
    }

    // Fund the makers with 4 UTXOs of 0.05 BTC each, one per call (distinct addresses).
    for _ in 0..4 {
        fund_makers(
            &makers,
            bitcoind,
            1,
            Amount::from_btc(0.05).unwrap(),
            AddressType::P2TR,
        );
    }

    // Start the maker server threads
    log::info!("Starting Maker servers...");

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    // Wait for makers to complete setup
    wait_for_makers_setup(&makers, 120);

    // Sync wallets after setup to ensure fidelity bonds are accounted for
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);

    // ---- Swap 1: First taker ----
    log::info!("Starting swap for Taker 1 (Taproot protocol)...");

    let swap_params1 = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    let taker1 = &mut takers[0];
    let summary1 = taker1
        .prepare_swap(swap_params1)
        .expect("Failed to prepare Taproot openswap for Taker 1");
    log::info!("Taker 1 swap summary: {:?}", summary1);

    match taker1.start_swap(&summary1.swap_id) {
        Ok(report) => {
            log::info!("Taker 1 openswap (Taproot) completed successfully!");
            log::info!("Taker 1 swap report: {:?}", report);
        }
        Err(e) => {
            log::error!("Taker 1 openswap (Taproot) failed: {:?}", e);
            panic!("Taker 1 openswap (Taproot) failed: {:?}", e);
        }
    }

    // Mine blocks between swaps to confirm transactions
    generate_blocks(bitcoind, 5);

    // Sync maker wallets between swaps
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    // ---- Swap 2: Second taker ----
    log::info!("Starting swap for Taker 2 (Taproot protocol)...");

    let swap_params2 = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    let taker2 = &mut takers[1];
    let summary2 = taker2
        .prepare_swap(swap_params2)
        .expect("Failed to prepare Taproot openswap for Taker 2");
    log::info!("Taker 2 swap summary: {:?}", summary2);

    match taker2.start_swap(&summary2.swap_id) {
        Ok(report) => {
            log::info!("Taker 2 openswap (Taproot) completed successfully!");
            log::info!("Taker 2 swap report: {:?}", report);
        }
        Err(e) => {
            log::error!("Taker 2 openswap (Taproot) failed: {:?}", e);
            panic!("Taker 2 openswap (Taproot) failed: {:?}", e);
        }
    }

    log::info!("All openswaps processed successfully. Transactions complete.");

    // Sync all wallets
    for taker in takers.iter() {
        taker
            .get_wallet()
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    generate_blocks(bitcoind, 1);

    for maker in makers.iter() {
        let mut wallet = maker.wallet.write().unwrap();
        wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    }

    // ---- Verify Taker 1 ----
    let taker1_balances_after = takers[0]
        .get_wallet()
        .read()
        .unwrap()
        .get_balances()
        .unwrap();
    info!("Taker 1 balance after swap (Taproot):");

    let balance_diff1 = taker1_original_balance - taker1_balances_after.spendable;
    info!(
        "Taker 1 balance verification passed. Original: {}, After: {} (fees paid: {})",
        taker1_original_balance, taker1_balances_after.spendable, balance_diff1
    );

    assert_eq!(
        taker1_balances_after.spendable.to_sat(),
        14993891,
        "Taker 1 spendable balance mismatch"
    );
    assert_eq!(
        taker1_balances_after.contract.to_sat(),
        0,
        "Taker 1 contract balance mismatch"
    );
    assert_eq!(taker1_balances_after.fidelity, Amount::ZERO);
    assert_eq!(balance_diff1.to_sat(), 6109, "Taker 1 fee paid mismatch");

    // ---- Verify Taker 2 ----
    let taker2_balances_after = takers[1]
        .get_wallet()
        .read()
        .unwrap()
        .get_balances()
        .unwrap();
    info!("Taker 2 balance after swap (Taproot):");

    let balance_diff2 = taker2_original_balance - taker2_balances_after.spendable;
    info!(
        "Taker 2 balance verification passed. Original: {}, After: {} (fees paid: {})",
        taker2_original_balance, taker2_balances_after.spendable, balance_diff2
    );

    assert_eq!(
        taker2_balances_after.spendable.to_sat(),
        14993891,
        "Taker 2 spendable balance mismatch"
    );
    assert_eq!(
        taker2_balances_after.contract.to_sat(),
        0,
        "Taker 2 contract balance mismatch"
    );
    assert_eq!(taker2_balances_after.fidelity, Amount::ZERO);
    assert_eq!(balance_diff2.to_sat(), 6109, "Taker 2 fee paid mismatch");

    // ---- Verify Makers earned fees ----
    let expected_regular = [14002216, 14006692];
    let expected_swap = [998656, 994106];
    let expected_fee = [1358, 1284];
    for (i, (maker, original_spendable)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        let wallet = maker.wallet.read().unwrap();
        let balances = wallet.get_balances().unwrap();

        info!(
            "Maker {} final balances - Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.fidelity, balances.spendable,
        );
        assert_eq!(
            balances.regular.to_sat(),
            expected_regular[i],
            "Maker {} regular balance mismatch",
            i
        );
        assert_eq!(
            balances.swap.to_sat(),
            expected_swap[i],
            "Maker {} swap balance mismatch",
            i
        );
        assert_eq!(
            balances.contract.to_sat(),
            0,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());

        let maker_fee = balances
            .spendable
            .checked_sub(original_spendable)
            .unwrap_or(Amount::ZERO);

        info!("Maker {} fee earned: {} sats", i, maker_fee.to_sat());

        assert_eq!(
            maker_fee.to_sat(),
            expected_fee[i],
            "Maker {} fee earned mismatch",
            i
        );
    }

    info!("All multi-taker swap tests (Taproot) completed successfully!");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    test_framework.stop();
    block_generation_handle.join().unwrap();
}
