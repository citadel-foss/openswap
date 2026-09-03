//! Taproot taker abort test 1: Taker closes at AckSwapDetails response.
//!
//! Scenario:
//! 1. Taker initiates a Taproot openswap with 2 makers.
//! 2. Taker closes the connection immediately after receiving AckSwapDetails
//!    from a maker (CloseAtAckResponse behavior).
//! 3. This is an early abort -- no funding transactions are broadcast.
//! 4. No recovery is needed since no funds are on-chain.
//! 5. Verify: taker balance is approximately unchanged (no fund loss).

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{sync::atomic::Ordering::Relaxed, thread, time::Duration};

/// Test: Taker aborts at AckSwapDetails response (Taproot).
///
/// The taker closes the connection right after the Maker acknowledges the
/// swap details. No funding transactions have been broadcast at this point,
/// so no recovery is needed. Balances should remain unchanged.
#[test]
fn test_taproot_taker_abort1() {
    // ---- Setup ----
    warn!("Running Test: Taproot Taker Abort1 - Close at AckResponse");

    let makers_config_map = vec![(6802, Some(19801)), (16802, Some(19802))];
    let taker_behavior = vec![TakerBehavior::CloseAtAckResponse];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

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
    log::info!("Starting taproot taker abort1 test...");

    // Swap params for openswap (Taproot)
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    // Prepare should fail at AckResponse — the taker closes the connection
    // right after receiving AckSwapDetails, before any funding is broadcast.
    let prepare_result = taker.prepare_swap(swap_params.clone());
    assert!(
        prepare_result.is_err(),
        "Prepare should fail due to CloseAtAckResponse behavior"
    );
    info!(
        "Prepare failed as expected: {:?}",
        prepare_result.err().unwrap()
    );
    taker.log_tracker_state();

    // The accepted-but-unfunded reservation must expire without requiring a restart.
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    wait_for_log(
        &log_path,
        "Released idle unfunded reservation",
        Duration::from_secs(60),
    );
    let release_deadline = std::time::Instant::now() + Duration::from_secs(15);
    while makers
        .iter()
        .any(|maker| maker.has_ongoing_swaps().unwrap())
    {
        assert!(
            std::time::Instant::now() < release_deadline,
            "Early-abort reservations should be released after the idle timeout"
        );
        thread::sleep(Duration::from_secs(1));
    }

    // With the stale reservation gone, the makers must be back at full capacity:
    // a fresh swap request has to be accepted again. The maker only sends
    // AckSwapDetails after storing a new reservation, and the taker only emits
    // the CloseAtAckResponse test error after receiving that ack — so hitting
    // that exact error proves the makers accepted the retry.
    let retry_result = taker.prepare_swap(swap_params);
    let retry_err = format!(
        "{:?}",
        retry_result.expect_err("Retry should still abort at AckSwapDetails")
    );
    assert!(
        retry_err.contains("closing at ack response"),
        "Retry should have been accepted up to AckSwapDetails, got: {}",
        retry_err
    );
    assert!(
        makers
            .iter()
            .any(|maker| maker.has_ongoing_swaps().unwrap()),
        "Accepted retry should hold a fresh reservation on a maker"
    );

    // Sync taker wallet and verify balance
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();

    info!(
        "Taker balances after abort: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    // Contract balance should be 0 (no contracts were created on-chain)
    assert_eq!(
        taker_balances.contract,
        Amount::ZERO,
        "Taker should have no contract balance after early abort"
    );

    // Balance diff should be 0 or very small (no funds were spent on-chain)
    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap_or(Amount::ZERO);

    info!(
        "Taker balance diff: {} sats (original: {}, current: {})",
        balance_diff.to_sat(),
        taker_original_balance,
        taker_balances.spendable,
    );

    // No funds should have been lost since no transactions were broadcast
    assert_eq!(
        balance_diff.to_sat(),
        0,
        "Taker should not have lost funds on early abort. Lost {} sats",
        balance_diff.to_sat(),
    );

    taker.log_tracker_state();
    info!("Taproot taker abort1 test completed successfully!");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    test_framework.stop();
    block_generation_handle.join().unwrap();
}
