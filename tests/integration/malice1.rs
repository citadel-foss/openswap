//! Malice test 1: Taker broadcasts contract transactions maliciously after full setup.
//!
//! Scenario:
//! 1. Taker initiates a Legacy openswap with 2 makers.
//! 2. Full setup completes (funding broadcast, contract sigs exchanged).
//! 3. Taker broadcasts outgoing contract txs maliciously (BroadcastContractAfterFullSetup).
//! 4. Swap fails. Makers detect the broadcast contracts and recover via timelock.
//! 5. After recovery, verify: makers recovered funds (contract == 0, small fee loss).

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

/// Test: Taker maliciously broadcasts contract txs after full setup.
///
/// The taker completes the full contract exchange, then broadcasts contract
/// transactions and closes. Makers detect the on-chain contracts and recover
/// their funds via timelock spending.
#[test]
fn test_malice1_taker_broadcast_contract() {
    // ---- Setup ----
    warn!("Running Test: Malice1 - Taker Broadcasts Contract After Full Setup");

    let makers_config_map = vec![(6602, Some(19601)), (16602, Some(19602))];
    let taker_behavior = vec![TakerBehavior::BroadcastContractAfterFullSetup];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

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

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    log::info!("Starting malice1 test...");

    // Swap params for openswap (Legacy)
    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    // Prepare should succeed; execution should fail with BroadcastContractAfterFullSetup
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to BroadcastContractAfterFullSetup behavior"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    taker.log_tracker_state();

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

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
        let expected_regular = [14996838u64, 14996838][i];
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

        // Makers lost some funds due to taker maliciously broadcasting contracts
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
    }

    // Wait for taker's background recovery loop to finish
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

    taker.log_tracker_state();
    info!("Malice1 test completed successfully!");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    test_framework.stop();
    block_generation_handle.join().unwrap();
}
