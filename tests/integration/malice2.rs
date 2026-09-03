//! Malice test 2: Maker broadcasts contract transactions maliciously after setup.
//!
//! Scenario:
//! 1. Taker initiates a Legacy openswap with 2 makers.
//! 2. Maker[1] (second maker) broadcasts its outgoing contract txs after setup
//!    and closes the connection (BroadcastContractAfterSetup behavior).
//! 3. Taker detects the failure and triggers recovery (recover_active_swap).
//! 4. The taker sweeps its incoming contract with the swap preimage — its right,
//!    the contract pays it — and later timelock-refunds its own outgoing when no
//!    hashlock claim arrives. Ending up with both is the intended deterrence:
//!    the double cost lands on the maker that broadcast and vanished.
//! 5. The honest maker timelock-refunds and stays whole; the faulty maker's
//!    funds stay locked until it returns.
//!
//! Missing coverage, to be added later: a broadcaster that stays online and
//! relays the cascade (settlement instead of refund), and a middle maker that
//! broadcasts then dies.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    sync::atomic::Ordering::Relaxed,
    thread,
    time::{Duration, Instant},
};

/// Test: Maker maliciously broadcasts contract txs after setup.
///
/// Maker[1] completes the contract exchange, then broadcasts its outgoing
/// contract transactions and closes the connection. The taker sweeps its
/// incoming contract via the preimage and timelock-refunds its outgoing;
/// the faulty maker's funds stay locked. Generic over the backend so
/// `electrum_tor.rs` can reuse the body over Tor.
/// This is the only scenario driving the taker's breach detector.
pub(crate) fn run_malice2<B: TestBackend>() {
    run_malice2_with_taker_behavior::<B>(TakerBehavior::Normal, false);
}

fn run_malice2_with_taker_behavior<B: TestBackend>(
    taker_behavior: TakerBehavior,
    expect_direct_breach_detection: bool,
) {
    // ---- Setup ----
    warn!("Running Test: Malice2 - Maker Broadcasts Contract After Setup");

    let makers_config_map = vec![(6702, Some(19701)), (16702, Some(19702))];
    let taker_behavior = vec![taker_behavior];
    let maker_behaviors = vec![
        MakerBehavior::Normal,
        MakerBehavior::BroadcastContractAfterSetup,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<B>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Legacy)
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
    log::info!("Starting malice2 test...");

    // Start periodic swap tracker logging (every 10s)
    let tracker_logger = spawn_tracker_logger(
        test_framework.temp_dir.join("taker1"),
        Duration::from_secs(10),
    );

    // Swap params for openswap (Legacy)
    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count([1, 3])
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
            &format!("{}/taker/debug.log", test_framework.temp_dir.display()),
            "Breach detector: contract tx",
            Duration::from_secs(30),
        );
    }
    taker.log_tracker_state();

    // Wait for makers to detect the drop and the outer timelock to mature;
    // slower-cadence backends (Tor) wait proportionally longer.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(timelock_recovery_wait::<B>());

    // Verify maker balances -- makers should have recovered their outgoing funds via timelock
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
        let expected_regular = [14998622u64, 14501519][i];
        assert_eq!(
            maker_balances.regular.to_sat(),
            expected_regular,
            "Maker {} regular balance mismatch",
            i
        );
        assert_eq!(
            maker_balances.swap.to_sat(),
            0,
            "Maker {} swap balance mismatch",
            i
        );
        assert_eq!(
            maker_balances.contract.to_sat(),
            0,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(maker_balances.fidelity, Amount::from_btc(0.05).unwrap());
    }

    info!("Makers shut down. Waiting for background recovery loop to complete...");

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

    // Mine a block to confirm recovery txs, then sync wallet
    generate_blocks(bitcoind, 1);
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

    assert_eq!(
        taker_balances.regular.to_sat(),
        14999108,
        "Taker regular balance mismatch"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        497087,
        "Taker swap balance mismatch"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    // The taker swept its incoming AND refunded its outgoing, so it ends the
    // failed swap ahead of where it started — the dark maker pays the difference.
    info!(
        "Taker spendable after recovery: {} sats (original: {})",
        taker_balances.spendable.to_sat(),
        taker_original_balance,
    );
    assert_eq!(
        taker_balances.spendable.to_sat(),
        15496195,
        "Taker spendable balance mismatch"
    );

    taker.log_tracker_state();
    info!("Malice2 test completed successfully!");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

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
    );
}
