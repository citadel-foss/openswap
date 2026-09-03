//! Legacy counterpart of `taproot_hashlock_recovery`: maker sweeps, then drops.
//!
//! Route: Taker -> Maker1 (Normal) -> Maker2 (CloseAfterSweep) -> Taker
//!
//! Maker2 completes the handover — which reveals the preimage — and then drops
//! instead of replying. The taker must follow that preimage and sweep via the
//! hashlock branch rather than sit out the much longer timelock.
//!
//! Legacy was previously covered here only indirectly, through `malice2`'s
//! recovery loop. The `CloseAfterSweep` hook existed for Taproot only; the
//! Legacy arm in `legacy_handlers.rs` was added alongside this test.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    utill::NO_SHUTDOWN,
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    sync::atomic::Ordering::Relaxed,
    thread,
    time::{Duration, Instant},
};

#[test]
fn test_legacy_hashlock_recovery() {
    warn!("Running Test: Legacy Hashlock Recovery - CloseAfterSweep");

    let makers_config_map = vec![(9402, Some(21701)), (19402, Some(21702))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::CloseAfterSweep];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    info!("Starting Maker servers...");
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

    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);

    let tracker_logger = spawn_tracker_logger(
        test_framework.temp_dir.join("taker1"),
        Duration::from_secs(10),
    );

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to Maker2 closing after sweep"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    taker.log_tracker_state();

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    for (i, maker) in makers.iter().enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
        let mb = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i, mb.regular, mb.swap, mb.contract, mb.spendable,
        );
        assert_eq!(
            mb.contract,
            Amount::ZERO,
            "Maker {} should have no contract balance after recovery",
            i
        );
    }

    info!("Waiting for background recovery loop to complete...");
    let deadline = Instant::now() + Duration::from_secs(120);
    while !taker.is_recovery_complete() {
        assert!(
            Instant::now() < deadline,
            "Background recovery did not complete within 120s"
        );
        thread::sleep(Duration::from_secs(5));
    }
    info!("Background recovery loop completed.");

    generate_blocks(bitcoind, 1);
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();

    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    info!(
        "Taker balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap_or(Amount::ZERO);
    info!(
        "Taker balance diff: {} sats (original: {}, current: {})",
        balance_diff.to_sat(),
        taker_original_balance,
        taker_balances.spendable,
    );

    // The point of the test: the preimage was on-chain, so recovery must have
    // gone through the hashlock branch, not the timelock one.
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("Signing legacy hashlock spend with preimage", &log_path);

    // The hashlock sweep is a separate tx per contract, so the taker pays more
    // than the 6337 sats a clean legacy swap costs.
    assert_eq!(
        taker_balances.regular.to_sat(),
        14499076,
        "Taker regular balance mismatch"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        493687,
        "Taker swap balance mismatch"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);
    assert_eq!(
        balance_diff.to_sat(),
        7237,
        "Taker spendable balance change mismatch"
    );

    // Both makers still earn their full fee: maker 1 completed the swap and
    // maker 2 swept before dropping.
    let expected_regular = [14500865u64, 14503103];
    let expected_swap = [499100u64, 496825];
    let expected_fee = [451u64, 414];
    for (i, maker) in makers.iter().enumerate() {
        let mb = maker.wallet.read().unwrap().get_balances().unwrap();
        let original = maker_spendable_balance[i];
        info!(
            "Maker {} balance diff: pre-swap: {}, current: {}",
            i, original, mb.spendable,
        );
        assert_eq!(
            mb.regular.to_sat(),
            expected_regular[i],
            "Maker {} regular balance mismatch",
            i
        );
        assert_eq!(
            mb.swap.to_sat(),
            expected_swap[i],
            "Maker {} swap balance mismatch",
            i
        );
        assert_eq!(
            mb.contract.to_sat(),
            0,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(mb.fidelity, Amount::from_btc(0.05).unwrap());
        assert_eq!(
            mb.spendable
                .checked_sub(original)
                .unwrap_or(Amount::ZERO)
                .to_sat(),
            expected_fee[i],
            "Maker {} fee earned mismatch",
            i
        );
    }

    taker.log_tracker_state();
    info!("Legacy hashlock recovery test completed successfully!");

    tracker_logger.stop();
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
