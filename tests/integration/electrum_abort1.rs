//! Abort 1 (Electrum backend): TAKER Drops After Full Setup.
//!
//! Same scenario as `abort1.rs`, but every participant runs on the Electrum
//! backend, and the scenario runs over both protocols (Taproot and Legacy).
//! This is the most Electrum-critical abort case: the taker vanishes after
//! broadcasting the funding transactions, so the makers must detect the
//! failure autonomously and recover via the preimage/hashlock cascade or
//! timelock. On Electrum that detection path has no ZMQ and no mempool scan —
//! it depends entirely on script subscriptions (`subscribe_script`/`poll_event`),
//! `get_tx_out` confirmation gating, and header-by-hash resolution.
//!
//! The Taker drops the connection after broadcasting all the funding transactions.
//! The Makers identify this and wait for a timeout (60s in test) for the Taker to come back.
//! If the Taker doesn't return, the Makers broadcast the contract transactions and reclaim
//! their funds via timelock.
//!
//! The Taker after coming live again will see unfinished openswaps in its wallet.
//! It can reclaim funds via broadcasting contract transactions and claiming via timelock.

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

/// Exact post-recovery balances for one protocol run. Fees differ between the
/// Legacy and Taproot transaction shapes (and locktime values), so each
/// protocol pins its own values.
pub(crate) struct ExpectedBalances {
    taker_regular: u64,
    taker_swap: u64,
    taker_spendable_diff: u64,
    maker_regular: [u64; 2],
    maker_swap: [u64; 2],
    maker_spendable: [u64; 2],
}

pub(crate) const LEGACY_EXPECTED: ExpectedBalances = ExpectedBalances {
    taker_regular: 14499076,
    taker_swap: 493687,
    taker_spendable_diff: 7237,
    maker_regular: [14500865, 14503103],
    maker_swap: [498200, 495925],
    maker_spendable: [14999065, 14999028],
};

pub(crate) const TAPROOT_EXPECTED: ExpectedBalances = ExpectedBalances {
    taker_regular: 14499076,
    taker_swap: 494557,
    taker_spendable_diff: 6367,
    maker_regular: [14500865, 14503103],
    maker_swap: [499070, 496795],
    maker_spendable: [14999935, 14999898],
};

/// Run the abort1 scenario (taker drops after funds broadcast) with the given
/// protocol and assert the exact recovery balances.
///
/// Generic over the backend so `electrum_tor.rs` can run the identical body over
/// Tor and assert the same balances.
pub(crate) fn run_abort1<B: TestBackend>(protocol: ProtocolVersion, expected: &ExpectedBalances) {
    // ---- Setup ----
    warn!("Running Test: Taker Drops After Full Setup (Electrum backend, {protocol:?})");

    let makers_config_map = vec![(6102, None), (16102, None)];
    let taker_behavior = vec![TakerBehavior::DropAfterFundsBroadcast];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<B>(makers_config_map, taker_behavior, maker_behaviors);

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
    log::info!("Initiating Maker servers");

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

    verify_maker_pre_swap_balances(&makers);

    // Initiate OpenSwap
    info!("Initiating openswap protocol");

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    // Start periodic swap tracker logging
    let tracker_logger = spawn_tracker_logger(
        test_framework.temp_dir.join("taker1"),
        Duration::from_secs(10),
    );

    // Prepare should succeed; execution should fail with DropAfterFundsBroadcast
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    let swap_error = swap_result.expect_err("Swap should fail due to test behavior");
    assert!(
        matches!(
            &swap_error,
            openswap::taker::error::TakerError::General(message)
                if message == "Test: dropped after contract exchange"
        ),
        "Swap failed before the injected abort: {:?}",
        swap_error
    );
    info!("Swap failed as expected: {swap_error:?}");
    taker.log_tracker_state();

    // Wait for makers to detect the drop and the outer timelock to mature;
    // slower-cadence backends (Tor) wait proportionally longer.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(timelock_recovery_wait::<B>());

    // Verify maker balances after recovery
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
            maker_balances.contract,
            Amount::ZERO,
            "Maker {} should have no contract balance after recovery",
            i
        );
    }

    info!("Makers shut down. Waiting for background recovery loop to complete...");

    // Wait for taker's background recovery loop to finish
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
    // electrs indexes asynchronously; without the wait the sync can read a
    // stale tip and the exact balance assertions below flake.
    test_framework.wait_for_electrs_tip();
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
        expected.taker_regular,
        "Taker regular balance mismatch"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        expected.taker_swap,
        "Taker swap balance"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap();

    info!(
        "Taker balance diff: {} sats (original: {}, current: {})",
        balance_diff.to_sat(),
        taker_original_balance,
        taker_balances.spendable,
    );

    assert_eq!(
        balance_diff.to_sat(),
        expected.taker_spendable_diff,
        "Taker spendable balance change"
    );

    // Verify maker balances - makers should have recovered via timelock
    for (i, maker) in makers.iter().enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let maker_balances = maker.wallet.read().unwrap().get_balances().unwrap();

        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i,
            maker_balances.regular,
            maker_balances.swap,
            maker_balances.contract,
            maker_balances.fidelity,
            maker_balances.spendable,
        );

        assert_eq!(
            maker_balances.regular.to_sat(),
            expected.maker_regular[i],
            "Maker {i} regular balance"
        );
        assert_eq!(
            maker_balances.swap.to_sat(),
            expected.maker_swap[i],
            "Maker {i} swap balance"
        );
        assert_eq!(
            maker_balances.contract.to_sat(),
            0,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(maker_balances.fidelity, Amount::from_btc(0.05).unwrap());

        assert_eq!(
            maker_balances.spendable.to_sat(),
            expected.maker_spendable[i],
            "Maker {i} spendable balance"
        );
    }

    taker.log_tracker_state();
    info!("Electrum abort1 test ({protocol:?}) completed successfully!");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    tracker_logger.stop();
    // Drop the taker while relay, electrs, and bitcoind are still up, so its
    // background services shut down against live servers instead of dead ones.
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn taker_abort_1_taproot_electrum() {
    run_abort1::<ElectrumBackend>(ProtocolVersion::Taproot, &TAPROOT_EXPECTED);
}

#[test]
fn taker_abort_1_legacy_electrum() {
    run_abort1::<ElectrumBackend>(ProtocolVersion::Legacy, &LEGACY_EXPECTED);
}

/// A breached taker recovers all its incoming coins once the contracts
/// confirm; recovery never blocks on an unconfirmed contract.
///
/// The last maker broadcasts the taker's incoming contract txs and closes.
/// Recovery skips each contract while it is unconfirmed and sweeps it on a
/// later cycle, well inside the timelock window. This test asserts the
/// outcome — every incoming coin swept, no hang.
#[test]
fn electrum_sweeps_after_breach() {
    let makers_config_map = vec![(6102, None), (16102, None)];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![
        MakerBehavior::Normal,
        MakerBehavior::BroadcastContractAfterSetup,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<ElectrumBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
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

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
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

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        // Zero confirms: the taker hits the closed connection at once instead
        // of sitting in a confirmation wait while the contract mines.
        .with_required_confirms(0);

    generate_blocks(bitcoind, 1);

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");

    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail once the last maker closes"
    );

    // Three incoming contracts, all swept: the loop tallies them in one line.
    wait_for_log(
        &log_path,
        "Recovery loop: swept 3 incoming swapcoins",
        Duration::from_secs(180),
    );
    // The log line only proves the sweeps were broadcast. Confirm them and
    // check the money actually landed, otherwise a wrong-amount sweep passes.
    generate_blocks(bitcoind, 1);
    test_framework.wait_for_electrs_tip();
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    let swapcoins_left = taker
        .get_wallet()
        .read()
        .unwrap()
        .get_incoming_swapcoins_count();
    info!(
        "Sweeps-after-breach taker: regular {}, swap {}, contract {}, spendable {}, incoming swapcoins {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
        swapcoins_left,
    );
    assert_eq!(
        swapcoins_left, 0,
        "Every incoming swapcoin should be swept out of the wallet"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        493_687,
        "Swept swap balance mismatch"
    );
    assert_eq!(
        taker_balances.regular.to_sat(),
        14_499_076,
        "Taker regular balance mismatch"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// Plan A4: a swapcoin whose contract output is spent only in the mempool
/// must survive recovery; once that spend confirms, the coin is discarded.
///
/// The abort1 cascade makes maker 0 sweep the taker's outgoing contracts
/// with the hashlock preimage. Mining is paused while that sweep is a
/// mempool tx: the taker's recovery must keep its outgoing coins (a mempool
/// spend can be evicted). After the sweep confirms, they are discarded.
#[test]
fn electrum_discards_only_on_confirmed_spend() {
    let makers_config_map = vec![(6102, None), (16102, None)];
    let taker_behavior = vec![TakerBehavior::DropAfterFundsBroadcast];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<ElectrumBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
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

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
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

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(0);

    generate_blocks(bitcoind, 1);

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");

    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail once the last maker closes"
    );

    // The cascade: taker sweeps its incoming, maker 1 extracts the preimage
    // and sweeps its incoming, then maker 0 announces it will sweep too.
    wait_for_log(
        &log_path,
        "All preimages known, recovering via hashlock path",
        Duration::from_secs(300),
    );

    // Hold the chain still: maker 0's hashlock sweep of the taker's outgoing
    // contracts now sits in the mempool as an unconfirmed spend.
    test_framework.set_block_gen_paused(true);
    thread::sleep(Duration::from_secs(10));

    let surviving = taker
        .get_wallet()
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count();
    assert_eq!(
        surviving, 3,
        "Outgoing swapcoins must survive a mempool-only spend of their contracts"
    );

    // Let the sweep confirm; the next recovery cycles must discard the coins.
    test_framework.set_block_gen_paused(false);
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let remaining = taker
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count();
        if remaining == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Outgoing swapcoins were not discarded after the spend confirmed"
        );
        thread::sleep(Duration::from_secs(5));
    }

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
