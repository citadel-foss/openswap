//! Malice test 3: Maker breach detection for a Legacy contract broadcast
//! while the swap is still in progress.
//!
//! Scenario (citadel-foss/openswap#1040):
//! 1. Taker initiates a Legacy openswap with 2 makers.
//! 2. Maker1 signs the taker's sender contract tx and the taker funds it.
//! 3. Instead of disconnecting (malice1's scenario), the taker broadcasts its
//!    own signed contract tx — spending the funding outpoint Maker1 is
//!    receiving from — and keeps the connection open, still talking to
//!    Maker1 as if nothing happened (`BroadcastContractDuringSwap`).
//! 4. Maker1 must detect the breach itself, on its own funding-outpoint
//!    watch, well before the idle-connection timeout would otherwise have
//!    caught a dropped connection. It must refuse to hand over its outgoing
//!    private key and recover instead.

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

/// Test: Maker detects a Legacy contract broadcast mid-swap and recovers
/// without waiting for the idle-connection timeout.
#[test]
fn test_malice3_maker_detects_legacy_breach_during_swap() {
    // ---- Setup ----
    warn!("Running Test: Malice3 - Maker Breach Detection During Swap");

    let maker_count = 2;
    let taker_behavior = vec![TakerBehavior::BroadcastContractDuringSwap];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(maker_count, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Legacy)
    fund_taker_default(taker, bitcoind, 3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    fund_makers_default(&makers, bitcoind);

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

    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    log::info!("Starting malice3 test...");

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    // Prepare should succeed; execution should fail once Maker1 refuses to
    // continue past the breach.
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail once the maker detects the mid-swap contract broadcast"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    taker.log_tracker_state();

    // Maker1's funding outpoint watch must catch this on the heartbeat
    // cadence (`HEART_BEAT_INTERVAL`, a few seconds), not the idle-connection
    // timeout (30s in integration-test builds). A generous but still tight
    // bound proves it is the breach path, not the idle-drop path.
    let maker1_log_path = makers[0].config.data_dir.join("debug.log");
    let maker1_log_path = maker1_log_path.to_string_lossy().to_string();
    wait_for_log(
        &maker1_log_path,
        "breached: taker forced the contract on-chain before the swap finished",
        Duration::from_secs(20),
    );
    info!("Maker1 detected the breach without waiting for the idle timeout");

    // The idle-drop path must not be what fired instead.
    let log_contents = std::fs::read_to_string(&maker1_log_path).unwrap();
    assert!(
        !log_contents.contains("Potential dropped connection from taker"),
        "the breach must be caught on its own path, not read as a dropped connection"
    );

    // The behavior this test actually exists to prove: Maker1 must have
    // refused the private key handover, not merely logged the breach and
    // handed the key over anyway. `wait_for_log` above only proves the
    // heartbeat drain ran; this proves the synchronous gate fired too.
    assert!(
        log_contents.contains("Aborting swap")
            && log_contents.contains("before private key handover"),
        "Maker1 must refuse the private key handover once breached, found no matching log line"
    );

    // Sleep budget: 30s idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining is scheduling margin, matching malice1.
    info!("Waiting for blocks to mature timelocks and recovery to complete...");
    thread::sleep(Duration::from_secs(300));

    // Verify maker balances -- Maker1 must not have lost its outgoing funds
    // to a theft enabled by handing over its private key after the breach.
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
            maker_balances.contract.to_sat(),
            0,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(maker_balances.fidelity, Amount::from_btc(0.05).unwrap());

        // Recovery via timelock costs mining fees, but nothing beyond that:
        // a stolen outgoing contract would cost the whole hop's swap amount,
        // several orders of magnitude more than fees on a couple of txs.
        let original = maker_spendable_balance[i];
        let maker_diff = original
            .checked_sub(maker_balances.spendable)
            .unwrap_or(Amount::ZERO);
        info!(
            "Maker {} lost {} sats (pre-swap: {}, current: {})",
            i,
            maker_diff.to_sat(),
            original,
            maker_balances.spendable,
        );
        assert!(
            maker_diff < Amount::from_sat(50_000),
            "Maker {} lost {} sats, far more than recovery fees — private key handover may not have been refused",
            i,
            maker_diff.to_sat()
        );
    }

    // Wait for taker's background recovery loop to finish.
    info!("Waiting for background recovery loop to complete...");
    let recovery_timeout = Duration::from_secs(120);
    let recovery_start = Instant::now();
    while !taker.is_recovery_complete() {
        if recovery_start.elapsed() > recovery_timeout {
            panic!("Background recovery did not complete within timeout");
        }
        thread::sleep(Duration::from_secs(5));
    }
    info!("Background recovery loop completed.");

    generate_blocks(bitcoind, 1);
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    taker.log_tracker_state();
    info!("Malice3 test completed successfully!");

    shutdown_makers(&makers, maker_threads);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
