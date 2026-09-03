//! Taproot taker aborts at and after the contract-data exchange.
//!
//! Two drop points, one recovery flow:
//! 1. `abort3`: the taker drops on receiving a maker's contract data response,
//!    mid-setup (CloseAtSendersContractFromMaker) — funding is on-chain but
//!    the incoming coin set is incomplete, so timelock recovery runs on a
//!    partial set.
//! 2. Full setup: the taker drops after every contract is verified, before
//!    the private-key handover (BroadcastContractAfterFullSetup) — the full
//!    coin set is on disk, so the taker eats the whole swap amount plus fees
//!    while both makers recover whole. In taproot the funding tx IS the
//!    contract tx, so this hook's re-broadcast is a no-op; the drop point and
//!    its persisted state are the difference that matters.
//!
//! Both cases force timelock recovery for every party and share one runner.

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

/// Test: Taker aborts after receiving maker's contract response (Taproot).
///
/// The taker drops the connection after receiving the maker's contract data
/// response. Funding transactions are already on-chain, so timelock recovery
/// is required.
#[test]
fn test_taproot_taker_abort3() {
    run_taproot_taker_abort(
        "close at maker's contract data response",
        TakerBehavior::CloseAtSendersContractFromMaker,
        vec![(7002, Some(20001)), (17002, Some(20002))],
        [14997750, 14999514],
        [1764, 0],
        14998236,
        1764,
    );
}

/// Test: Taker drops after full setup, before the private-key handover.
///
/// Recovery starts from the complete outgoing + incoming coin set: both
/// makers timelock-refund whole, and the taker absorbs the swap amount plus
/// every funding fee.
#[test]
fn test_taproot_taker_abort_after_full_setup() {
    run_taproot_taker_abort(
        "drop after full setup",
        TakerBehavior::BroadcastContractAfterFullSetup,
        vec![(8502, Some(21101)), (18502, Some(21102))],
        [14997750, 14997750],
        [1764, 1764],
        14499076,
        500924,
    );
}

/// Drives one taker-drop case through timelock recovery and asserts the
/// golden balances that pin how that drop point settles.
fn run_taproot_taker_abort(
    case: &str,
    behavior: TakerBehavior,
    makers_config_map: Vec<(u16, Option<u16>)>,
    expected_maker_regular: [u64; 2],
    expected_maker_diff: [u64; 2],
    expected_taker_regular: u64,
    expected_taker_diff: u64,
) {
    // ---- Setup ----
    warn!("Running Test: Taproot Taker Abort - {case}");

    let taker_behavior = vec![behavior];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

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
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);

    let tracker_logger = spawn_tracker_logger(
        test_framework.temp_dir.join("taker1"),
        Duration::from_secs(10),
    );

    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    // Prepare should succeed; execution should fail at the case's drop point.
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to {:?} behavior",
        behavior
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    taker.log_tracker_state();

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    // Verify maker balances -- makers should have recovered their outgoing
    // funds via timelock.
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
            maker_balances.regular.to_sat(),
            expected_maker_regular[i],
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

        let maker_diff = maker_spendable_balance[i]
            .checked_sub(maker_balances.spendable)
            .unwrap_or(Amount::ZERO);
        info!("Maker {} lost {} sats to recovery", i, maker_diff.to_sat());
        assert_eq!(
            maker_diff.to_sat(),
            expected_maker_diff[i],
            "Maker {} spendable balance change mismatch",
            i
        );
    }

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
        expected_taker_regular,
        "Taker regular balance mismatch"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        0,
        "Taker swap balance mismatch"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap_or(Amount::ZERO);
    info!(
        "Taker balance diff: {} sats (original: {}, current: {})",
        balance_diff.to_sat(),
        taker_original_balance,
        taker_balances.spendable,
    );
    assert_eq!(
        balance_diff.to_sat(),
        expected_taker_diff,
        "Taker spendable balance change mismatch"
    );

    taker.log_tracker_state();
    info!("Taproot taker abort ({case}) completed successfully!");

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
