//! Taker recovers from persisted swapcoins after its process restarts.
//!
//! `recover_active_swap` has two branches. Every other abort test takes the
//! `ongoing_swap == Some` one, where the swap is still in memory. The other
//! branch (`taker/api.rs:2403`) reads the swap id back off disk via
//! `find_unfinished_swapcoins`, and nothing exercised it — which is exactly the
//! path a crashed taker depends on to get its money back.
//!
//! Scenario:
//! 1. Swap fails at the private-key handover, so the taker persists swapcoins
//!    and starts its in-process recovery loop.
//! 2. The taker is dropped before that loop can finish — recovery needs the
//!    timelocks to mature, so there is a wide window to die in.
//! 3. A fresh `Taker` is built from the same data dir, with nothing in memory.
//! 4. `recover_active_swap` must find the swap on disk and finish the job.
//! 5. A crash before the tracker records the cleanup leaves nothing to recover;
//!    the next startup must still finish the swap instead of retrying it forever.

use bitcoin::Amount;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{
        swap_tracker::{RecoveryPhase, SwapTracker},
        SwapParams, Taker,
    },
};

use crate::test_framework::*;

use log::info;
use std::{thread, time::Duration};

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, last_maker],
    takers = [Normal],
    cases = [
        legacy_recovers_after_restart(
            protocol = ProtocolVersion::Legacy,
            last_maker = MakerBehavior::CloseAtHashPreimage,
        ),
        taproot_recovers_after_restart(
            protocol = ProtocolVersion::Taproot,
            last_maker = MakerBehavior::CloseAtPrivateKeyHandover,
        ),
    ],
)]
fn run_taker_restart_recovery(world: &mut World, protocol: ProtocolVersion) {
    // Owned, not borrowed: this taker gets dropped mid-test.
    let mut taker = world.take_taker();

    let taker_original_balance = fund_taker_default(taker.inner(), world.bitcoind(), 3);
    world.fund_makers_default();

    info!("Starting Maker servers...");
    world.start_makers(120);

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    let summary = taker.prepare(swap_params).expect("Prepare should succeed");
    let swap_result = taker.start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail at the private key handover"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    world.framework().set_block_gen_paused(true);

    taker.sync();
    let before_outgoing = taker
        .inner()
        .get_wallet()
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count();
    let before_incoming = taker
        .inner()
        .get_wallet()
        .read()
        .unwrap()
        .get_incoming_swapcoins_count();
    info!(
        "Before restart: incoming={}, outgoing={}",
        before_incoming, before_outgoing
    );
    assert!(
        before_outgoing > 0,
        "taker should have persisted outgoing swapcoins before the restart"
    );
    assert!(
        before_incoming > 0,
        "taker should have persisted incoming swapcoins before the restart"
    );

    let taker_dir = world.temp_dir().join("taker1");
    let wallet_path = taker_dir.join("wallets").join("taker1");
    let tracker_path = taker_dir.join("swap_tracker.cbor");
    let wallet_snapshot = taker_dir.join("wallet.snapshot");
    let tracker_snapshot = taker_dir.join("tracker.snapshot");
    std::fs::copy(&wallet_path, &wallet_snapshot).unwrap();
    std::fs::copy(&tracker_path, &tracker_snapshot).unwrap();

    world.framework().set_block_gen_paused(false);
    wait_until!(
        Duration::from_secs(120),
        "the post-snapshot recovery sweep to clear incoming swapcoins",
        taker
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_incoming_swapcoins_count()
            == 0
    );

    info!("Restoring the pre-sweep state to simulate a crash before cleanup");
    drop(taker);
    std::fs::copy(wallet_snapshot, wallet_path).unwrap();
    std::fs::copy(&tracker_snapshot, &tracker_path).unwrap();
    thread::sleep(Duration::from_secs(5));

    world.adopt_taker(
        Taker::init(world.framework().taker_init_config::<BitcoindBackend>(0))
            .expect("restarted taker should open the same wallet"),
    );

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for timelocks to mature...");
    thread::sleep(Duration::from_secs(300));

    world.shutdown_makers();

    info!("Waiting for the restarted taker's recovery loop to finish...");
    wait_until!(
        Duration::from_secs(120),
        every Duration::from_secs(5),
        "recovery after restart to complete",
        world.taker().inner().is_recovery_complete()
    );

    world.mine(1);
    world.taker().sync();

    let balances = world.taker().balances();
    let balance_diff = taker_original_balance
        .checked_sub(balances.spendable)
        .unwrap_or(Amount::ZERO);
    info!(
        "Taker balance diff: {} sats (original: {}, current: {})",
        balance_diff.to_sat(),
        taker_original_balance,
        balances.spendable,
    );

    // Everything the failed swap cost the taker is fees, pinned per protocol
    // from real runs. A recovery that dropped the swapcoins without returning
    // the funds would still pass the zero-balance asserts, but not this one.
    let expected_diff = match protocol {
        ProtocolVersion::Legacy => 4465,
        ProtocolVersion::Taproot => 3802,
    };
    assert_eq!(
        balance_diff.to_sat(),
        expected_diff,
        "taker did not get its funds back after restart recovery"
    );

    // The taker's contract balance must be cleared after recovery.
    world.sync_makers();
    assert_balances!(world; { taker: { contract: 0, fidelity: 0 } });

    let wallet = world.taker().inner().get_wallet();
    let wallet = wallet.read().unwrap();
    assert_eq!(
        wallet.get_incoming_swapcoins_count(),
        0,
        "restarted taker still holds incoming swapcoins; before={before_incoming}"
    );
    assert_eq!(
        wallet.get_outgoing_swapcoins_count(),
        0,
        "restarted taker still holds outgoing swapcoins; before={before_outgoing}"
    );
    drop(wallet);

    // If the cross-session lookup had come up empty, recover_active_swap would
    // have bailed with this instead of recovering.
    assert_log!(world; {
        // Present means the restarted taker failed to read the swap back off disk.
        lacks "No persisted swapcoins found for recovery",
    });

    // Crash again before the tracker saw the cleanup: the chain and wallet are
    // settled, so startup has nothing to recover but must still finish the swap.
    world.drop_takers();
    std::fs::copy(&tracker_snapshot, &tracker_path).unwrap();
    world.adopt_taker(
        Taker::init(world.framework().taker_init_config::<BitcoindBackend>(0))
            .expect("settled taker should open the same wallet"),
    );
    wait_until!(
        Duration::from_secs(60),
        every Duration::from_secs(1),
        "the settled swap to be finished",
        world.taker().inner().is_recovery_complete()
    );
    let tracker = SwapTracker::load_or_create(&taker_dir).unwrap();
    assert_eq!(
        tracker.get_record(&summary.swap_id).unwrap().recovery.phase,
        RecoveryPhase::CleanedUp,
        "startup left a settled swap for every restart to retry"
    );

    info!("Taker restart recovery test completed successfully!");
}
