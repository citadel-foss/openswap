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

use crate::test_framework::*;

use log::info;
use std::{
    thread,
    time::{Duration, Instant},
};

/// Maker2 never sent its funding. Past the grace its inputs are the wallet's
/// again, while it keeps the swap's keys in case that funding still lands.
/// It watches them for good, so it is stopped here.
fn assert_unsent_released(world: &mut World, swap_id: &str) {
    wait_for_release(&world.taker_log_path(), swap_id);
    world.shutdown_maker(1);
    let victim = world.makers()[1].inner();
    assert_eq!(
        victim.reserved_inputs().unwrap(),
        0,
        "Maker2 must free the inputs of its unsent funding"
    );
    assert!(
        victim.has_unfinished_outgoing_swapcoin(swap_id).unwrap(),
        "Maker2 must keep its unsent swap's keys"
    );
}

/// The balances a timelock-only recovery settles at. Losses are measured from
/// the taker's funded balance and the makers' post-fidelity, pre-swap ones.
struct TimelockOnlyExpect {
    taker_regular: u64,
    taker_swap: u64,
    taker_loss: u64,
    maker_regular: [u64; 2],
    maker_swap: [u64; 2],
    /// Maker2 never broadcast its funding, so it must end exactly where it began.
    maker_loss: [u64; 2],
}

/// Also what `restart::watchtower_liveness` settles at with Maker1's watcher stopped.
const LEGACY_TIMELOCK_ONLY: TimelockOnlyExpect = TimelockOnlyExpect {
    taker_regular: 14998629,
    taker_swap: 0,
    taker_loss: 1371,
    maker_regular: [14998419, 14999757],
    maker_swap: [0, 0],
    maker_loss: [1338, 0],
};

const TAPROOT_TIMELOCK_ONLY: TimelockOnlyExpect = TimelockOnlyExpect {
    taker_regular: 14999085,
    taker_swap: 0,
    taker_loss: 915,
    maker_regular: [14998875, 14999757],
    maker_swap: [0, 0],
    maker_loss: [882, 0],
};

const TAPROOT_TIMELOCK_ONLY_ELECTRUM: TimelockOnlyExpect = TimelockOnlyExpect {
    taker_regular: 14999085,
    taker_swap: 0,
    taker_loss: 915,
    maker_regular: [14998875, 14999757],
    maker_swap: [0, 0],
    maker_loss: [882, 0],
};

/// Syncs the makers and asserts every wallet against `expected`. The taker
/// must already be synced past its confirmed recovery txs.
fn assert_timelock_only_balances(
    world: &World,
    taker_original_balance: Amount,
    maker_spendable_balance: &[Amount],
    expected: &TimelockOnlyExpect,
) {
    world.sync_makers();
    let maker_spendable: Vec<Amount> = maker_spendable_balance
        .iter()
        .zip(expected.maker_loss)
        .map(|(before, loss)| *before - Amount::from_sat(loss))
        .collect();
    assert_balances!(world; {
        taker: {
            regular: expected.taker_regular,
            swap: expected.taker_swap,
            contract: 0,
            fidelity: 0,
            spendable: taker_original_balance - Amount::from_sat(expected.taker_loss),
        },
        makers: {
            regular: expected.maker_regular,
            swap: expected.maker_swap,
            contract: 0,
            fidelity: BOND,
            spendable: maker_spendable,
        },
    });
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

    // Recovery waits out the 30s maker idle timeout (test builds), the 225-block
    // outer-hop timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers), about
    // 135s at 5 blocks/3s, and the unbroadcast grace before Maker2 frees its inputs.
    info!("Waiting for the grace release and the makers' timelock recovery...");
    assert_unsent_released(world, &summary.swap_id);
    // Maker1 stops itself once recovered; let it finish before syncing.
    world.wait_makers_settled(Duration::from_secs(300));

    // Every maker recovered its contracts
    world.sync_makers();
    assert_balances!(world; { makers: { contract: 0 } });

    info!("Makers shut down. Waiting for background recovery loop to complete...");

    // The background recovery loop (spawned by recover_active_swap) periodically
    // retries timelock recovery. Wait for it to finish.
    wait_until!(
        Duration::from_secs(420),
        every Duration::from_secs(5),
        "the background recovery to complete",
        world.taker().inner().is_recovery_complete()
    );
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.framework().wait_for_electrs_tip();
    world.taker().sync();

    assert_timelock_only_balances(
        world,
        taker_original_balance,
        &maker_spendable_balance,
        &LEGACY_TIMELOCK_ONLY,
    );

    world.taker().inner().log_tracker_state();
    info!("Legacy timelock-only recovery test completed successfully!");

    world.shutdown_makers();
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
fn legacy_timelock_only_recovery(
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
        taproot_timelock_only_recovery(
            backend = BitcoindBackend,
            expected = &TAPROOT_TIMELOCK_ONLY,
        ),
        /// Same timelock-only recovery on Electrum: recovery reads the indexer.
        taproot_timelock_only_recovery_electrum(
            backend = ElectrumBackend,
            expected = &TAPROOT_TIMELOCK_ONLY_ELECTRUM,
        ),
    ],
)]
fn run_taproot_timelock_only_recovery(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
    params: SwapParams,
    expected: &TimelockOnlyExpect,
) {
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

    // Recovery waits out the 30s maker idle timeout (test builds), the 225-block
    // outer-hop timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers), about
    // 135s at 5 blocks/3s, and the unbroadcast grace before Maker2 frees its inputs.
    info!("Waiting for the grace release and the makers' timelock recovery...");
    assert_unsent_released(world, &summary.swap_id);
    // Maker1 stops itself once recovered; let it finish before syncing.
    world.wait_makers_settled(Duration::from_secs(300));

    // Every maker recovered its contracts
    world.sync_makers();
    assert_balances!(world; { makers: { contract: 0 } });

    info!("Makers shut down. Waiting for background recovery loop to complete...");

    // The background recovery loop (spawned by recover_active_swap) periodically
    // retries timelock recovery until it has refunded everything it can.
    wait_until!(
        Duration::from_secs(420),
        every Duration::from_secs(5),
        "the background recovery to complete",
        world.taker().inner().is_recovery_complete()
    );
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.framework().wait_for_electrs_tip();
    world.taker().sync();

    assert_timelock_only_balances(
        world,
        taker_original_balance,
        &maker_spendable_balance,
        expected,
    );

    world.taker().inner().log_tracker_state();
    info!("Taproot timelock-only recovery test completed successfully!");

    world.shutdown_makers();
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
/// That maker kept its keys and would refund them, so it is stopped first.
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
    // them mid-swap, as the taker sees them.
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
    wait_until!(
        Duration::from_secs(400),
        every Duration::from_secs(2),
        "the taker to refund its outgoing",
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count()
            == 0
    );

    // The last maker kept its keys and would refund the published contracts
    // itself, spending them before the taker's passes could prove anything.
    // Stop it, so only the taker can touch them.
    world.shutdown_maker(1);

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

    // Recovery must not keep waiting on an incoming it gave up.
    wait_until!(
        Duration::from_secs(60),
        every Duration::from_secs(2),
        "recovery to complete without the given-up incoming",
        world.taker().inner().is_recovery_complete()
    );
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
