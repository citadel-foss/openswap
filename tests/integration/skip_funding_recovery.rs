//! Integration tests for Taker timelock-only recovery.
//!
//! These tests verify recovery when the last maker skips broadcasting
//! its funding transaction, forcing timelock-only recovery (hashlock
//! recovery is impossible since the funding is never on-chain).

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    protocol::common_messages::ProtocolVersion,
    taker::{BanReason, SwapParams},
};

use super::test_framework::*;

use log::info;
use std::{
    thread,
    time::{Duration, Instant},
};

/// This swap's recovery must wait out the grace before discarding its
/// never-broadcast funding. Lines are matched by swap id, since one log file
/// can hold several swaps.
fn assert_grace_then_discard(log_path: &str, swap_id: &str) {
    let log = std::fs::read_to_string(log_path).unwrap();
    let waited = log
        .find(&format!("Swap {swap_id} shows no funding broadcast after"))
        .expect("the maker must wait on the grace for this swap");
    let dropped = log
        .find(&format!("Funding was never broadcast for swap {swap_id}"))
        .expect("the maker must discard this swap's never-broadcast funding");
    assert!(
        waited < dropped,
        "the maker must wait out the grace before dropping the swapcoins"
    );
}

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
pub(crate) fn run_legacy_timelock_only_recovery(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
    params: SwapParams,
    stop_watcher: bool,
) {
    // Start periodic swap tracker logging (every 10s)
    let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

    world.mine(1);
    world.framework().wait_for_electrs_tip();

    // Prepare should succeed; execution should fail because Maker2 closes the connection
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to Maker2 skipping funding broadcast"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    world.taker().inner().log_tracker_state();

    // Maker2 planned a funding it never sent, and handed it out unsigned, so
    // only it could broadcast. Its swapcoins must still be there: only the
    // grace may release them, never the failure itself.
    let victim_held = world.makers()[1]
        .inner()
        .wallet
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count()
        + world.makers()[1]
            .inner()
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
            world.makers()[0]
                .inner()
                .has_unfinished_outgoing_swapcoin(&summary.swap_id)
                .unwrap(),
            "Maker1 must have an outgoing swapcoin for the funded swap before watcher shutdown"
        );
        world.makers()[0]
            .inner()
            .watch_service
            .stop_watcher_for_test();
        assert!(!world.makers()[0].inner().watch_service.is_alive());
    }

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    // Recovery waits out the grace before dropping the never-broadcast
    // funding, then releases the swapcoins, exactly as for Taproot.
    assert_grace_then_discard(&world.taker_log_path(), &summary.swap_id);
    world.makers()[1].sync();
    let victim_after = {
        let wallet = world.makers()[1].inner().wallet.read().unwrap();
        wallet.get_outgoing_swapcoins_count() + wallet.get_incoming_swapcoins_count()
    };
    assert_eq!(
        victim_after, 0,
        "Maker2 must release its swapcoins once the grace has run out"
    );

    // Verify maker balances after recovery
    for (i, maker) in world.makers().iter().enumerate() {
        maker.sync();
        let maker_balances = maker.balances();
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
    while !world.taker().inner().is_recovery_complete() {
        if recovery_start.elapsed() > recovery_timeout {
            panic!("Background recovery did not complete within timeout");
        }
        thread::sleep(Duration::from_secs(5));
    }
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.framework().wait_for_electrs_tip();
    world.taker().sync();

    // Verify taker balance
    let taker_balances = world.taker().balances();

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
    for (i, maker) in world.makers().iter().enumerate() {
        maker.sync();
        let maker_balances = maker.balances();
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

    world.taker().inner().log_tracker_state();
    info!("Legacy timelock-only recovery test completed successfully!");

    world.shutdown_makers();

    tracker_logger.stop();
}

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, SkipFundingBroadcast],
    takers = [Normal],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        start_makers(120),
        // Post-fidelity, pre-swap balances are the baseline.
        verify_maker_pre_swap_balances() as maker_spendable_balance,
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn test_legacy_timelock_only_recovery(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
    params: SwapParams,
) {
    run_legacy_timelock_only_recovery(
        world,
        taker_original_balance,
        maker_spendable_balance,
        params,
        false,
    );
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
#[world_test(
    maker_behaviors = [Normal, SkipFundingBroadcastUnrecorded],
    takers = [Normal],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        start_makers(120),
        // Post-fidelity, pre-swap balances are the baseline.
        verify_maker_pre_swap_balances() as maker_spendable_balance,
    ],
    swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 3),
    cases = [
        test_taproot_timelock_only_recovery(backend = BitcoindBackend),
        /// Same timelock-only recovery on Electrum: the grace and discard decisions
        /// read the indexer rather than the maker's own node.
        test_taproot_timelock_only_recovery_electrum(backend = ElectrumBackend),
    ],
)]
fn run_taproot_timelock_only_recovery(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
    params: SwapParams,
) {
    // Start periodic swap tracker logging (every 10s)
    let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

    world.mine(1);
    world.framework().wait_for_electrs_tip();

    // Prepare should succeed; execution should fail because Maker2 closes the connection
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to Maker2 skipping funding broadcast"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    world.taker().inner().log_tracker_state();

    // Maker2 planned a funding it never sent. Its swapcoins must still be
    // there: only the grace may release them, never the failure itself.
    let victim_held = world.makers()[1]
        .inner()
        .wallet
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count()
        + world.makers()[1]
            .inner()
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
    assert_grace_then_discard(&world.taker_log_path(), &summary.swap_id);
    world.makers()[1].sync();
    let victim_after = {
        let wallet = world.makers()[1].inner().wallet.read().unwrap();
        wallet.get_outgoing_swapcoins_count() + wallet.get_incoming_swapcoins_count()
    };
    assert_eq!(
        victim_after, 0,
        "Maker2 must release its swapcoins once the grace has run out"
    );

    // Verify maker balances after recovery
    for (i, maker) in world.makers().iter().enumerate() {
        maker.sync();
        let maker_balances = maker.balances();
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
    while !world.taker().inner().is_recovery_complete() {
        if recovery_start.elapsed() > recovery_timeout {
            panic!("Background recovery did not complete within timeout");
        }
        thread::sleep(Duration::from_secs(5));
    }
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.framework().wait_for_electrs_tip();
    world.taker().sync();

    // Verify taker balance
    let taker_balances = world.taker().balances();

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
    for (i, maker) in world.makers().iter().enumerate() {
        maker.sync();
        let maker_balances = maker.balances();
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

    world.taker().inner().log_tracker_state();
    info!("Taproot timelock-only recovery test completed successfully!");

    world.shutdown_makers();

    tracker_logger.stop();
}

/// A maker that answers normally but never sends its funding is not a dropped
/// connection: the taker waits, our own node confirms every tx is absent, and
/// that maker alone is banned.
#[world_test(
    maker_behaviors = [Normal, WithholdFundingSilently],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120)],
    swap(protocol = protocol, sats = 500_000, makers = 2, tx_count = 3),
    cases = [
        withheld_taproot_funding_bans_only_its_own_maker(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Taproot,
        ),
        withheld_legacy_funding_bans_only_its_own_maker(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Legacy,
        ),
        /// Same policy on Electrum: the indexer's definite "no such transaction" is
        /// taken at its word, exactly as our own node's would be.
        withheld_taproot_funding_bans_only_its_own_maker_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Taproot,
        ),
    ],
)]
fn run_withheld_funding_bans_its_maker(world: &mut World, params: SwapParams) {
    world.mine(1);
    world.framework().wait_for_electrs_tip();

    let error = world
        .taker_mut()
        .swap_fails(params, "Swap must fail when a maker withholds its funding");
    info!("Swap failed as expected: {error:?}");

    assert_eq!(
        world.maker_ban_reason(1),
        Some(BanReason::FundingWithheld),
        "the maker that withheld funding must be banned"
    );

    assert_eq!(
        world.maker_ban_reason(0),
        None,
        "the honest maker must not be blamed"
    );

    info!("Withheld funding test completed successfully!");
}

/// A refund settles the swap one way. The last maker publishes the taker's
/// incoming contract only after the taker refunded its outgoing: sweeping it
/// now would reveal the preimage and take both sides, so no sweep may follow.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, WithholdFundingSilently],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120)],
    swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 3),
)]
fn late_incoming_after_refund_is_never_swept(world: &mut World, params: SwapParams) {
    world.mine(1);

    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");

    // The last maker's withheld contracts are the taker's incoming side. Grab
    // them mid-swap: its recovery drops them once the swap fails.
    let withheld = {
        let (maker, swap_id) = (world.makers()[1].inner().clone(), summary.swap_id.clone());
        let deadline = Instant::now() + Duration::from_secs(300);
        thread::spawn(move || loop {
            let txs = maker.outgoing_contract_txs(&swap_id).unwrap();
            if !txs.is_empty() || Instant::now() > deadline {
                return txs;
            }
            thread::sleep(Duration::from_millis(200));
        })
    };
    assert!(
        world.taker_mut().start(&summary.swap_id).is_err(),
        "Swap must fail when the last maker withholds its funding"
    );
    let withheld = withheld.join().unwrap();
    assert!(
        !withheld.is_empty(),
        "the last maker never saved the contracts it withheld"
    );

    // The taker drops an outgoing coin once its timelock refund is mined.
    let deadline = Instant::now() + Duration::from_secs(400);
    while world
        .taker()
        .inner()
        .get_wallet()
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count()
        != 0
    {
        assert!(
            Instant::now() < deadline,
            "taker did not refund its outgoing within 400s"
        );
        thread::sleep(Duration::from_secs(2));
    }

    info!("Taker refunded; publishing the withheld incoming contracts");
    for tx in &withheld {
        world.bitcoind().client.send_raw_transaction(tx).unwrap();
    }
    world.mine(1);

    // Several recovery passes, each of which would sweep a claimable coin.
    thread::sleep(Duration::from_secs(40));
    for tx in &withheld {
        let txid = tx.compute_txid();
        for vout in 0..tx.output.len() as u32 {
            assert!(
                world
                    .bitcoind()
                    .client
                    .get_tx_out(&txid, vout, Some(false))
                    .unwrap()
                    .is_some(),
                "the taker swept {}:{} after refunding its outgoing",
                txid,
                vout
            );
        }
    }

    let deadline = Instant::now() + Duration::from_secs(60);
    while !world.taker().inner().is_recovery_complete() {
        assert!(
            Instant::now() < deadline,
            "recovery kept waiting on an incoming it gave up"
        );
        thread::sleep(Duration::from_secs(2));
    }
    assert_eq!(
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_incoming_swapcoins_count(),
        0,
        "the given-up incoming coins must be cleaned up"
    );
}
