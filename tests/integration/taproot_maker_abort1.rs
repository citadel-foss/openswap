//! Integration test: Taproot maker abort1 - Not enough makers.
//!
//! Only 1 maker is available, but the swap requires 2 makers (maker_count: 2).
//! prepare_swap should FAIL because there are not enough makers.
//! No recovery is needed - balances should remain unchanged.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{sync::atomic::Ordering::Relaxed, thread};

/// Test: Not enough makers for Taproot swap.
///
/// Scenario:
/// 1. Only 1 maker is available but swap requires 2 (maker_count: 2).
/// 2. prepare_swap should fail because it cannot find enough makers.
/// 3. No funds are broadcast, so no recovery is needed.
/// 4. Verify balances are unchanged.
#[test]
fn test_taproot_maker_abort1() {
    // ---- Setup ----
    warn!("Running Test: Taproot Maker Abort1 - Not Enough Makers");

    // Only 1 maker available
    let makers_config_map = vec![(7102, Some(20101))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Taproot)
    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

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

    // Sync wallets after setup
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let _maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    log::info!("Starting Taproot maker abort1 test (not enough makers)...");

    // Swap params: Taproot, requires 2 makers but only 1 is available
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    // prepare_swap should FAIL because only 1 maker is available for a 2-maker swap
    let prepare_result = taker.prepare_swap(swap_params);
    assert!(
        prepare_result.is_err(),
        "prepare_swap should fail because only 1 maker is available for a 2-maker swap"
    );
    info!(
        "Prepare failed as expected: {:?}",
        prepare_result.err().unwrap()
    );

    // Sync taker wallet and verify balance is unchanged
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();

    info!(
        "Taker balances after failed prepare: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    // Balance should be unchanged since no funds were broadcast
    assert_eq!(
        taker_balances.spendable, taker_original_balance,
        "Taker balance should be unchanged. Original: {}, After: {}",
        taker_original_balance, taker_balances.spendable,
    );

    assert_eq!(
        taker_balances.contract,
        Amount::ZERO,
        "Taker should have no contract balance"
    );

    info!("Taproot maker abort1 test completed successfully!");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    test_framework.stop();
    block_generation_handle.join().unwrap();
}
