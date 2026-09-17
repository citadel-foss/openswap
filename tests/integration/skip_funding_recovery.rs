//! Integration tests for Taker timelock-only recovery.
//!
//! These tests verify recovery when the last maker skips broadcasting
//! its funding transaction, forcing timelock-only recovery (hashlock
//! recovery is impossible since the funding is never on-chain).

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    thread,
    time::{Duration, Instant},
};

/// Test: Timelock-only recovery when last maker skips funding broadcast.
///
/// Route: Taker → Maker1 → Maker2 → Taker
///
/// Scenario:
/// 1. Maker2 (last hop) receives contract sigs and saves swapcoins, but
///    skips broadcasting its outgoing funding transaction and closes the connection.
/// 2. Taker gets a connection error, calls `recover_active_swap()`.
/// 3. Hashlock recovery fails because Maker2's funding is not on-chain,
///    so the contract tx can't be broadcast.
/// 4. Everyone falls back to timelock recovery:
///    - Taker recovers outgoing (to Maker1) via timelock.
///    - Maker1 recovers outgoing (to Maker2) via timelock.
///    - Maker2 has nothing to recover (outgoing was never broadcast).
fn run_legacy_timelock_only_recovery(stop_watcher: bool) {
    // ---- Setup ----
    warn!("Running Test: Legacy Timelock-Only Recovery");

    let makers_config_map = vec![(15102, Some(19151)), (25102, Some(19152))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::SkipFundingBroadcast];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Legacy)
    let taker_original_balance = fund_taker_default(taker, bitcoind, 3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    fund_makers_default(&makers, bitcoind);

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
    sync_maker_wallets(&makers);

    // Use post-fidelity, pre-swap balances as the correct baseline
    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    log::info!("Starting Legacy timelock-only recovery test...");

    // Start periodic swap tracker logging (every 10s)
    let tracker_logger = spawn_tracker_logger(
        test_framework.temp_dir.join("taker1"),
        Duration::from_secs(10),
    );

    // Swap params for openswap (Legacy)
    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);
    test_framework.wait_for_electrs_tip();

    // Prepare should succeed; execution should fail because Maker2 closes the connection
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to Maker2 skipping funding broadcast"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    taker.log_tracker_state();

    // Maker2 planned a funding it never sent, but the taker already holds it
    // fully signed: exposure came with the contract-sig request, one message
    // before the skip. Recovery must keep the swapcoins — discarding them
    // would strand the funds if the taker ever broadcasts.
    let victim_held = makers[1]
        .wallet
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count()
        + makers[1]
            .wallet
            .read()
            .unwrap()
            .get_incoming_swapcoins_count();
    assert!(
        victim_held > 0,
        "Maker2 must keep its swapcoins when the swap fails"
    );

    if stop_watcher {
        assert!(
            makers[0]
                .has_unfinished_outgoing_swapcoin(&summary.swap_id)
                .unwrap(),
            "Maker1 must have an outgoing swapcoin for the funded swap before watcher shutdown"
        );
        makers[0].watch_service.stop_watcher_for_test();
        assert!(!makers[0].watch_service.is_alive());
    }

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    // Exposed funding is never discarded: no grace wait, no drop. The taker's
    // timelock recovery still resolves the on-chain side (checked below).
    let log_path = test_framework.taker_log_path();
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log.contains("nothing to recover. Discarding swapcoins."),
        "an exposed funding must never read as never-broadcast"
    );
    makers[1]
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let victim_outgoing = makers[1]
        .wallet
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count();
    assert_eq!(
        victim_outgoing, 3,
        "Maker2 must keep the swapcoins for its exposed funding"
    );

    // Verify maker balances after recovery
    for (i, maker) in makers.iter().enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let maker_balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i,
            maker_balances.regular,
            maker_balances.swap,
            maker_balances.contract,
            maker_balances.spendable,
        );
        assert_eq!(
            maker_balances.contract,
            Amount::ZERO,
            "Maker {} should have no contract balance after recovery",
            i
        );
    }

    info!("Makers shut down. Waiting for background recovery loop to complete...");

    // The background recovery loop (spawned by recover_active_swap) periodically
    // retries timelock recovery. Wait for it to finish.
    let recovery_timeout = Duration::from_secs(120);
    let recovery_start = Instant::now();
    while !taker.is_recovery_complete() {
        if recovery_start.elapsed() > recovery_timeout {
            panic!("Background recovery did not complete within timeout");
        }
        thread::sleep(Duration::from_secs(5));
    }
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    generate_blocks(bitcoind, 1);
    test_framework.wait_for_electrs_tip();
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    // Verify taker balance
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();

    info!(
        "Taker balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    // Contract balance should be 0
    assert_eq!(
        taker_balances.contract,
        Amount::ZERO,
        "Taker should have no contract balance after recovery"
    );

    // Balance diff should be small (timelock recovery fees only)
    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap_or(Amount::ZERO);

    info!(
        "Taker balance diff: {} sats (original: {}, current: {})",
        balance_diff.to_sat(),
        taker_original_balance,
        taker_balances.spendable,
    );

    assert!(
        balance_diff.to_sat() < 10000,
        "Taker should have recovered most funds. Lost {} sats (expected < 10000)",
        balance_diff.to_sat(),
    );

    // Verify maker balances are close to pre-swap (post-fidelity) balances
    for (i, maker) in makers.iter().enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let maker_balances = maker.wallet.read().unwrap().get_balances().unwrap();
        let original = maker_spendable_balance[i];

        let maker_diff = original
            .checked_sub(maker_balances.spendable)
            .unwrap_or(Amount::ZERO);

        info!(
            "Maker {} balance diff: {} sats (pre-swap: {}, current: {})",
            i,
            maker_diff.to_sat(),
            original,
            maker_balances.spendable,
        );

        // Makers should recover most of their funds (small loss from tx fees)
        assert!(
            maker_diff.to_sat() < 10000,
            "Maker {} should have recovered most funds. Lost {} sats (expected < 10000)",
            i,
            maker_diff.to_sat(),
        );
    }

    taker.log_tracker_state();
    info!("Legacy timelock-only recovery test completed successfully!");

    shutdown_makers(&makers, maker_threads);

    tracker_logger.stop();
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn test_legacy_timelock_only_recovery() {
    run_legacy_timelock_only_recovery(false);
}

pub(crate) fn run_legacy_timelock_recovery_without_watcher() {
    run_legacy_timelock_only_recovery(true);
}

/// Test: Timelock-only recovery when last maker skips Taproot funding broadcast.
///
/// Route: Taker → Maker1 → Maker2 → Taker
///
/// Scenario:
/// 1. Maker2 (last hop) creates Taproot contract and saves swapcoins, but
///    skips broadcasting its outgoing funding transaction and closes the connection.
/// 2. Taker gets a connection error, calls `recover_active_swap()`.
/// 3. Hashlock recovery fails because Maker2's funding is not on-chain,
///    so the contract tx can't be broadcast.
/// 4. Everyone falls back to timelock recovery:
///    - Taker recovers outgoing (to Maker1) via timelock.
///    - Maker1 recovers outgoing (to Maker2) via timelock.
///    - Maker2 has nothing to recover (outgoing was never broadcast).
#[test]
fn test_taproot_timelock_only_recovery() {
    run_taproot_timelock_only_recovery::<BitcoindBackend>((16102, 19161), (26102, 19162));
}

/// Same timelock-only recovery on Electrum: the grace and discard decisions
/// read the indexer rather than the maker's own node.
#[test]
fn test_taproot_timelock_only_recovery_electrum() {
    run_taproot_timelock_only_recovery::<ElectrumBackend>((16103, 19163), (26103, 19164));
}

fn run_taproot_timelock_only_recovery<B: TestBackend>(maker1: (u16, u16), maker2: (u16, u16)) {
    // ---- Setup ----
    warn!("Running Test: Taproot Timelock-Only Recovery");

    let makers_config_map = vec![(maker1.0, Some(maker1.1)), (maker2.0, Some(maker2.1))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![
        MakerBehavior::Normal,
        MakerBehavior::SkipFundingBroadcastUnrecorded,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<B>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Taproot)
    let taker_original_balance = fund_taker_default(taker, bitcoind, 3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    fund_makers_default(&makers, bitcoind);

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
    sync_maker_wallets(&makers);

    // Use post-fidelity, pre-swap balances as the correct baseline
    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    log::info!("Starting Taproot timelock-only recovery test...");

    // Start periodic swap tracker logging (every 10s)
    let tracker_logger = spawn_tracker_logger(
        test_framework.temp_dir.join("taker1"),
        Duration::from_secs(10),
    );

    // Swap params for openswap (Taproot)
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);
    test_framework.wait_for_electrs_tip();

    // Prepare should succeed; execution should fail because Maker2 closes the connection
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to Maker2 skipping funding broadcast"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    taker.log_tracker_state();

    // Maker2 planned a funding it never sent. Its swapcoins must still be
    // there: only the grace may release them, never the failure itself.
    let victim_held = makers[1]
        .wallet
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count()
        + makers[1]
            .wallet
            .read()
            .unwrap()
            .get_incoming_swapcoins_count();
    assert!(
        victim_held > 0,
        "Maker2 must keep its swapcoins when the swap fails"
    );

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    // Maker2 left its broadcast unrecorded, so recovery must wait out the
    // grace before dropping the swapcoins rather than trusting one backend
    // answer. Both lines must appear, in that order.
    let log_path = test_framework.taker_log_path();
    test_framework.assert_log("shows no funding broadcast after", &log_path);
    test_framework.assert_log("nothing to recover. Discarding swapcoins.", &log_path);

    // Order matters: the wait has to come before the drop, or the grace did
    // nothing. And once it expires the swapcoins really are released.
    let log = std::fs::read_to_string(&log_path).unwrap();
    let waited = log.find("shows no funding broadcast after").unwrap();
    let dropped = log
        .find("nothing to recover. Discarding swapcoins.")
        .unwrap();
    assert!(
        waited < dropped,
        "the maker must wait out the grace before dropping the swapcoins"
    );
    makers[1]
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let victim_after = makers[1]
        .wallet
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count()
        + makers[1]
            .wallet
            .read()
            .unwrap()
            .get_incoming_swapcoins_count();
    assert_eq!(
        victim_after, 0,
        "Maker2 must release its swapcoins once the grace has run out"
    );

    // Verify maker balances after recovery
    for (i, maker) in makers.iter().enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let maker_balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i,
            maker_balances.regular,
            maker_balances.swap,
            maker_balances.contract,
            maker_balances.spendable,
        );
        assert_eq!(
            maker_balances.contract,
            Amount::ZERO,
            "Maker {} should have no contract balance after recovery",
            i
        );
    }

    info!("Makers shut down. Waiting for background recovery loop to complete...");

    // The background recovery loop (spawned by recover_active_swap) periodically
    // retries timelock recovery; the sleep above already matured the timelocks,
    // so this only waits for the loop to notice and broadcast.
    let recovery_timeout = Duration::from_secs(120);
    let recovery_start = Instant::now();
    while !taker.is_recovery_complete() {
        if recovery_start.elapsed() > recovery_timeout {
            panic!("Background recovery did not complete within timeout");
        }
        thread::sleep(Duration::from_secs(5));
    }
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    generate_blocks(bitcoind, 1);
    test_framework.wait_for_electrs_tip();
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    // Verify taker balance
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();

    info!(
        "Taker balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    // Contract balance should be 0
    assert_eq!(
        taker_balances.contract,
        Amount::ZERO,
        "Taker should have no contract balance after recovery"
    );

    // Balance diff should be small (timelock recovery fees only)
    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap_or(Amount::ZERO);

    info!(
        "Taker balance diff: {} sats (original: {}, current: {})",
        balance_diff.to_sat(),
        taker_original_balance,
        taker_balances.spendable,
    );

    assert!(
        balance_diff.to_sat() < 10000,
        "Taker should have recovered most funds. Lost {} sats (expected < 10000)",
        balance_diff.to_sat(),
    );

    // Verify maker balances are close to pre-swap (post-fidelity) balances
    for (i, maker) in makers.iter().enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let maker_balances = maker.wallet.read().unwrap().get_balances().unwrap();
        let original = maker_spendable_balance[i];

        let maker_diff = original
            .checked_sub(maker_balances.spendable)
            .unwrap_or(Amount::ZERO);

        info!(
            "Maker {} balance diff: {} sats (pre-swap: {}, current: {})",
            i,
            maker_diff.to_sat(),
            original,
            maker_balances.spendable,
        );

        // Makers should recover most of their funds (small loss from tx fees)
        assert!(
            maker_diff.to_sat() < 10000,
            "Maker {} should have recovered most funds. Lost {} sats (expected < 10000)",
            i,
            maker_diff.to_sat(),
        );
    }

    taker.log_tracker_state();
    info!("Taproot timelock-only recovery test completed successfully!");

    shutdown_makers(&makers, maker_threads);

    tracker_logger.stop();
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
