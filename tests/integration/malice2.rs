//! Malice test 2: Maker broadcasts contract transactions maliciously after setup.
//!
//! Scenario:
//! 1. Taker initiates a Legacy openswap with 2 makers.
//! 2. Maker[1] (second maker) broadcasts its outgoing contract txs after setup
//!    and closes the connection (BroadcastContractAfterSetup behavior).
//! 3. Taker detects the failure and triggers recovery (recover_active_swap).
//! 4. The taker sweeps its incoming contract with the swap preimage. Having
//!    claimed it, the taker never refunds its outgoing: a swap settles one way.
//! 5. Maker[1] comes back online, reads the preimage off the taker's sweep and
//!    claims its incoming. That spend hands the preimage to Maker[0], which then
//!    claims the taker's outgoing. Nobody refunds; the swap settles in full.
//! 6. If Maker[1] never returns, Maker[0] never learns the preimage and refunds
//!    its outgoing. The taker's outgoing then dangles: nobody else can ever
//!    claim it, so the taker refunds it once its own timelock expires.
//! 7. If Maker[0] sleeps past the taker's timelock, the taker holds its refund
//!    and Maker[0] still claims by hashlock when it wakes.
//! 8. With three makers, a dead middle maker leaves Maker[0] refunding while the
//!    last maker claims: the taker refunds, judging by Maker[0]'s contracts alone.

use bitcoin::Amount;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    thread,
    time::{Duration, Instant},
};

/// How the swap ends after the last maker broadcasts and drops out.
#[derive(Clone, Copy, PartialEq)]
enum Ending {
    /// The faulty maker returns and every maker claims by hashlock.
    FaultyReturns,
    /// The faulty maker never returns: Maker[0] refunds, then the taker.
    FaultyGone,
    /// The faulty maker returns while Maker[0] sleeps past the taker's timelock.
    FirstMakerLate,
    /// Three makers: the middle one dies and the faulty last one returns.
    MiddleMakerDies,
}

/// Test: Maker maliciously broadcasts contract txs after setup.
///
/// Maker[1] completes the contract exchange, then broadcasts its outgoing
/// contract transactions and closes the connection. The taker sweeps its
/// incoming via the preimage; once Maker[1] returns, both makers claim by
/// hashlock. Generic over the backend so `electrum_tor.rs` can reuse the body
/// over Tor.
/// This is the only scenario driving the taker's breach detector.
pub(crate) fn run_malice2<B: TestBackend>() {
    run_malice2_with_taker_behavior::<B>(TakerBehavior::Normal, false, Ending::FaultyReturns);
}

fn run_malice2_with_taker_behavior<B: TestBackend>(
    taker_behavior: TakerBehavior,
    expect_direct_breach_detection: bool,
    ending: Ending,
) {
    // ---- Setup ----
    warn!("Running Test: Malice2 - Maker Broadcasts Contract After Setup");

    let maker_count = if ending == Ending::MiddleMakerDies {
        3
    } else {
        2
    };
    let last = maker_count - 1;
    let taker_behavior = vec![taker_behavior];
    let mut maker_behaviors = vec![MakerBehavior::Normal; last];
    maker_behaviors.push(MakerBehavior::BroadcastContractAfterSetup);

    let mut world = World::builder::<B>()
        .makers(maker_count)
        .maker_behaviors(maker_behaviors)
        .takers(taker_behavior)
        .build();

    // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Legacy)
    let taker_original_balance = world.fund_taker_default(3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    world.fund_makers_default();

    // Start the makers, wait for their setup, then sync their wallets
    log::info!("Starting Maker servers...");
    world.start_makers(120);

    world.verify_maker_pre_swap_balances();
    log::info!("Starting malice2 test...");

    // Start periodic swap tracker logging (every 10s)
    let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

    // Swap params for openswap (Legacy)
    let swap_params = SwapParams::new(
        ProtocolVersion::Legacy,
        Amount::from_sat(500000),
        maker_count,
    )
    .with_tx_count(1)
    .with_required_confirms(1);

    world.mine(1);

    // Prepare should succeed; execution should fail because maker broadcasts contracts
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to maker BroadcastContractAfterSetup behavior"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    if expect_direct_breach_detection {
        wait_for_log(
            &world.taker_log_path(),
            "Breach detector: contract tx",
            Duration::from_secs(30),
        );
    }
    world.taker().log_tracker_state();

    let log_path = world.taker_log_path();
    // A dead maker stays offline: it must never learn the preimage.
    let dead = (ending == Ending::MiddleMakerDies).then_some(1);
    if ending == Ending::FaultyGone {
        // Maker[0] never learns the preimage: its outgoing matures and it refunds.
        info!("Waiting for makers to timeout and blocks to mature timelocks...");
        thread::sleep(timelock_recovery_wait::<B>());
    } else {
        if let Some(i) = dead {
            world.shutdown_maker(i);
        }
        if ending == Ending::FirstMakerLate {
            world.shutdown_maker(0);
        }
        world.restart_maker(last, 120);
        if ending == Ending::FirstMakerLate {
            // Our timelock matures while Maker[0] sleeps: the coin stays its to claim.
            wait_for_log(
                &log_path,
                "Holding refund of",
                timelock_recovery_wait::<B>() * 2,
            );
            world.restart_maker(0, 120);
        }
        if ending == Ending::MiddleMakerDies {
            wait_for_log(
                &log_path,
                "First maker refunded its outgoing by timelock",
                timelock_recovery_wait::<B>() * 2,
            );
        }

        // Every live maker settles and drops its swapcoins.
        info!("Waiting for the live makers to settle...");
        let settle_start = Instant::now();
        while world.makers().iter().enumerate().any(|(i, maker)| {
            let wallet = maker.inner().wallet.read().unwrap();
            Some(i) != dead
                && wallet.get_incoming_swapcoins_count() + wallet.get_outgoing_swapcoins_count() > 0
        }) {
            assert!(
                settle_start.elapsed() < timelock_recovery_wait::<B>(),
                "makers did not settle"
            );
            thread::sleep(Duration::from_secs(5));
        }
        // A hashlock claim and a timelock refund never both happen: no refund at all.
        if ending != Ending::MiddleMakerDies {
            assert!(
                !std::fs::read_to_string(&log_path)
                    .unwrap()
                    .contains("Timelock recovery tx "),
                "nobody may refund a swap that settled by hashlock"
            );
        }
    }

    info!("Waiting for background recovery loop to complete...");

    // The background recovery loop (spawned by recover_active_swap) periodically
    // retries hashlock sweeps and timelock recovery. Wait for it to finish.
    world.taker().await_recovery(Duration::from_secs(120));
    info!("Background recovery loop completed.");
    if ending == Ending::FaultyGone {
        wait_for_log(
            &log_path,
            "First maker refunded its outgoing by timelock",
            Duration::from_secs(30),
        );
    }

    // (regular, swap) per live maker, then the taker's (regular, swap, spendable).
    // Settled by hashlock, the taker paid its outgoing as in a completed swap;
    // dangling, it refunded it on top of its claim.
    let (expected_makers, expected_taker) = match ending {
        Ending::FaultyReturns | Ending::FirstMakerLate => (
            vec![(14500543, 499700), (14501446, 498760)],
            (14499846, 497857, 14997703),
        ),
        Ending::FaultyGone => (
            vec![(14999311, 0), (14501446, 0)],
            (14999554, 497857, 15497411),
        ),
        Ending::MiddleMakerDies => (
            vec![(14999311, 0), (14502424, 497782)],
            (14999554, 496879, 15496433),
        ),
    };

    let mut maker_balances = Vec::new();
    for (i, maker) in world
        .makers()
        .iter()
        .enumerate()
        .filter(|(i, _)| Some(*i) != dead)
    {
        maker.sync();
        let balances = maker.balances();
        info!("Maker {} balances after recovery: {:?}", i, balances);
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "Maker {} contract balance",
            i
        );
        assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());
        maker_balances.push((balances.regular.to_sat(), balances.swap.to_sat()));
    }
    assert_eq!(maker_balances, expected_makers, "maker balances mismatch");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.taker().sync();
    let balances = world.taker().balances();
    info!(
        "Taker balances after recovery: {:?} (original: {})",
        balances, taker_original_balance
    );
    assert_eq!(balances.contract, Amount::ZERO, "Taker contract balance");
    assert_eq!(balances.fidelity, Amount::ZERO);
    assert_eq!(
        (
            balances.regular.to_sat(),
            balances.swap.to_sat(),
            balances.spendable.to_sat()
        ),
        expected_taker,
        "taker balances mismatch"
    );

    world.taker().log_tracker_state();
    info!("Malice2 test completed successfully!");

    world.shutdown_makers();

    tracker_logger.stop();
    world.finish();
}

#[test]
fn test_malice2_maker_broadcast_contract() {
    run_malice2::<BitcoindBackend>();
}

#[test]
fn test_malice2_detects_breach_after_watcher_exit() {
    run_malice2_with_taker_behavior::<BitcoindBackend>(
        TakerBehavior::StopWatcherAfterSentinels,
        true,
        Ending::FaultyReturns,
    );
}

/// Maker[1] never returns. The taker refunds its outgoing only after proving
/// Maker[0] refunded its own, so nobody else could ever claim it.
#[test]
fn test_malice2_taker_refunds_dangling_outgoing() {
    run_malice2_with_taker_behavior::<BitcoindBackend>(
        TakerBehavior::Normal,
        false,
        Ending::FaultyGone,
    );
}

/// Maker[0] sleeps past the taker's timelock. The taker holds its refund, so
/// Maker[0] still claims by hashlock when it wakes.
#[test]
fn test_malice2_taker_holds_refund_for_late_first_maker() {
    run_malice2_with_taker_behavior::<BitcoindBackend>(
        TakerBehavior::Normal,
        false,
        Ending::FirstMakerLate,
    );
}

/// Three makers, and the middle one dies after the last one claims from it.
/// Only Maker[0]'s refund matters: the taker refunds its dangling outgoing.
#[test]
fn test_malice2_taker_refunds_past_dead_middle_maker() {
    run_malice2_with_taker_behavior::<BitcoindBackend>(
        TakerBehavior::Normal,
        false,
        Ending::MiddleMakerDies,
    );
}
