//! Taproot counterpart of malice2: maker vanishes after locking funds on-chain.
//!
//! In Taproot the maker broadcasts its contract (funding) tx as part of normal
//! setup, so BroadcastContractAfterSetup re-broadcasts it and closes before
//! sending its contract-data response. The malice is that the maker's funds
//! stay locked on-chain while the taker never receives contract data.
//!
//! Scenario:
//! 1. Taker initiates a Taproot openswap with 2 makers.
//! 2. Maker[1] (second maker) broadcasts its contract tx after setup and
//!    closes the connection (BroadcastContractAfterSetup behavior).
//! 3. Taker detects the failure and triggers recovery (recover_active_swap).
//! 4. After timelocks mature, all parties recover their funds.
//! 5. Verify: taker and makers recovered funds (contract == 0, small fee loss).

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

/// Test: Maker locks its funds on-chain after setup, then closes.
///
/// Maker[1] broadcasts its contract transaction and closes without sending
/// its contract-data response. The taker detects the failure and all parties
/// recover via timelock.
#[test]
fn test_taproot_malice_maker_broadcast_contract() {
    // ---- Setup ----
    warn!("Running Test: Taproot Malice - Maker Broadcasts Contract After Setup");

    let makers_config_map = vec![(8602, Some(21201)), (18602, Some(21202))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![
        MakerBehavior::Normal,
        MakerBehavior::BroadcastContractAfterSetup,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 3 UTXOs of 0.05 BTC each
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
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    log::info!("Starting taproot maker malice test...");

    // Start periodic swap tracker logging (every 10s)
    let tracker_logger = spawn_tracker_logger(
        test_framework.temp_dir.join("taker1"),
        Duration::from_secs(10),
    );

    // Swap params for openswap (Taproot)
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
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
    taker.log_tracker_state();

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    // Shut down makers
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));

    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    // Log all maker balances before asserting so one run reports every value.
    let mut maker_balances_all = Vec::new();
    for (i, maker) in makers.iter().enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
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
        maker_balances_all.push(maker_balances);
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

    // Verify maker balances -- makers should have recovered their outgoing funds via timelock
    for (i, maker_balances) in maker_balances_all.iter().enumerate() {
        let expected_regular = [14998926u64, 14998926][i];
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

        // Nobody earns a fee here; each maker only pays for its own recovery.
        let maker_diff = maker_spendable_balance[i]
            .checked_sub(maker_balances.spendable)
            .unwrap_or(Amount::ZERO);
        info!(
            "Maker {} lost {} sats (pre-swap: {}, current: {})",
            i, maker_diff, maker_spendable_balance[i], maker_balances.spendable,
        );
        assert_eq!(
            maker_diff.to_sat(),
            588,
            "Maker {} spendable balance change mismatch",
            i
        );
    }

    // Verify taker balance
    assert_eq!(
        taker_balances.regular.to_sat(),
        14999412,
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

    // The taker recovered its own funding, so it only pays the recovery fees.
    assert_eq!(
        balance_diff.to_sat(),
        588,
        "Taker spendable balance change mismatch"
    );

    // TODO: the maker that broadcasts its contract is never banned. The swap
    // aborts on the transport error before the ContractsBroadcasted ban site, and
    // the breach detector fires on the taker's OWN recovery broadcast, so its
    // signal cannot attribute the breach to a maker.
    // assert_only_makers_banned(taker, &makers, &[1]);

    taker.log_tracker_state();
    info!("Taproot maker malice test completed successfully!");

    tracker_logger.stop();
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
