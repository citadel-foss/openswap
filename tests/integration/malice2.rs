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
    maker::{start_server, MakerBehavior, MakerServer},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    sync::{atomic::Ordering::Relaxed, Arc},
    thread::{self, JoinHandle},
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

/// Stops maker `i`: an orderly shutdown, so the test covers an offline maker, not a crash.
fn stop_maker(makers: &[Arc<MakerServer>], threads: &mut [Option<JoinHandle<()>>], i: usize) {
    makers[i].shutdown.store(true, Relaxed);
    if let Some(thread) = threads[i].take() {
        thread.join().unwrap();
    }
}

/// Brings maker `i` back the way a restarted daemon would. The first init
/// consumed the passphrase, so re-supply it.
fn restart_maker(
    makers: &mut [Arc<MakerServer>],
    threads: &mut [Option<JoinHandle<()>>],
    i: usize,
) {
    stop_maker(makers, threads, i);
    let mut config = makers[i].config.clone();
    config.password = Some("integration-test".to_string());
    makers[i] = Arc::new(MakerServer::init(config).unwrap());
    let maker = makers[i].clone();
    threads[i] = Some(thread::spawn(move || start_server(maker).unwrap()));
    wait_for_makers_setup(&makers[i..=i], 120);
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

    let (test_framework, mut takers, mut makers, block_generation_handle) =
        TestFramework::init::<B>(maker_count, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Legacy)
    let taker_original_balance = fund_taker_default(taker, bitcoind, 3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    fund_makers_default(&makers, bitcoind);

    // Start the maker server threads
    log::info!("Starting Maker servers...");

    let mut maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            Some(thread::spawn(move || {
                start_server(maker_clone).unwrap();
            }))
        })
        .collect::<Vec<_>>();

    // Wait for makers to complete setup
    wait_for_makers_setup(&makers, 120);

    // Sync wallets after setup
    sync_maker_wallets(&makers);

    let _maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    log::info!("Starting malice2 test...");

    // Start periodic swap tracker logging (every 10s)
    let tracker_logger = spawn_tracker_logger(
        test_framework.temp_dir.join("taker1"),
        Duration::from_secs(10),
    );

    // Swap params for openswap (Legacy)
    let swap_params = SwapParams::new(
        ProtocolVersion::Legacy,
        Amount::from_sat(500000),
        maker_count,
    )
    .with_tx_count(1)
    .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    // Prepare should succeed; execution should fail because maker broadcasts contracts
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to maker BroadcastContractAfterSetup behavior"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    if expect_direct_breach_detection {
        wait_for_log(
            &test_framework.taker_log_path(),
            "Breach detector: contract tx",
            Duration::from_secs(30),
        );
    }
    taker.log_tracker_state();

    let log_path = test_framework.taker_log_path();
    // A dead maker stays offline: it must never learn the preimage.
    let dead = (ending == Ending::MiddleMakerDies).then_some(1);
    if ending == Ending::FaultyGone {
        // Maker[0] never learns the preimage: its outgoing matures and it refunds.
        info!("Waiting for makers to timeout and blocks to mature timelocks...");
        thread::sleep(timelock_recovery_wait::<B>());
    } else {
        if let Some(i) = dead {
            stop_maker(&makers, &mut maker_threads, i);
        }
        if ending == Ending::FirstMakerLate {
            stop_maker(&makers, &mut maker_threads, 0);
        }
        restart_maker(&mut makers, &mut maker_threads, last);
        if ending == Ending::FirstMakerLate {
            // Our timelock matures while Maker[0] sleeps: the coin stays its to claim.
            wait_for_log(
                &log_path,
                "Holding refund of",
                timelock_recovery_wait::<B>() * 2,
            );
            restart_maker(&mut makers, &mut maker_threads, 0);
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
        while makers.iter().enumerate().any(|(i, maker)| {
            let wallet = maker.wallet.read().unwrap();
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
    let recovery_timeout = Duration::from_secs(120);
    let recovery_start = Instant::now();
    while !taker.is_recovery_complete() {
        if recovery_start.elapsed() > recovery_timeout {
            panic!("Background recovery did not complete within timeout");
        }
        thread::sleep(Duration::from_secs(5));
    }
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
            vec![(14500708, 499535), (14501611, 498595)],
            (14500000, 497692, 14997692),
        ),
        Ending::FaultyGone => (
            vec![(14999311, 0), (14501611, 0)],
            (14999543, 497692, 15497235),
        ),
        Ending::MiddleMakerDies => (
            vec![(14999311, 0), (14502589, 497617)],
            (14999543, 496714, 15496257),
        ),
    };

    let mut maker_balances = Vec::new();
    for (i, maker) in makers.iter().enumerate().filter(|(i, _)| Some(*i) != dead) {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
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
    generate_blocks(bitcoind, 1);
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
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

    taker.log_tracker_state();
    info!("Malice2 test completed successfully!");

    shutdown_makers(&makers, maker_threads.into_iter().flatten().collect());

    tracker_logger.stop();
    test_framework.stop();
    block_generation_handle.join().unwrap();
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
