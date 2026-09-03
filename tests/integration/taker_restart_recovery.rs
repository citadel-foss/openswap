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

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, Taker, TakerBehavior},
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
fn test_legacy_taker_restart_recovery() {
    warn!("Running Test: Legacy Taker Restart Recovery");
    run_taker_restart_recovery(ProtocolVersion::Legacy, MakerBehavior::CloseAtHashPreimage);
}

#[test]
fn test_taproot_taker_restart_recovery() {
    warn!("Running Test: Taproot Taker Restart Recovery");
    run_taker_restart_recovery(
        ProtocolVersion::Taproot,
        MakerBehavior::CloseAtPrivateKeyHandover,
    );
}

fn run_taker_restart_recovery(protocol: ProtocolVersion, last_maker: MakerBehavior) {
    let makers_config_map = vec![(9302, Some(21601)), (19302, Some(21602))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, last_maker];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    // Owned, not borrowed: this taker gets dropped mid-test.
    let mut taker = takers.remove(0);

    let taker_original_balance = fund_taker(
        &taker,
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

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail at the private key handover"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();
    let before_outgoing = taker
        .get_wallet()
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count();
    let before_incoming = taker
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

    // Kill the taker. Its Drop shuts down the in-process recovery loop, so from
    // here on nothing but the persisted wallet knows about this swap.
    info!("Dropping the taker mid-recovery");
    drop(taker);
    thread::sleep(Duration::from_secs(5));

    let restarted = Taker::init(test_framework.taker_init_config::<BitcoindBackend>(0))
        .expect("restarted taker should open the same wallet");

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for timelocks to mature...");
    thread::sleep(Duration::from_secs(300));

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    info!("Waiting for the restarted taker's recovery loop to finish...");
    let deadline = Instant::now() + Duration::from_secs(120);
    while !restarted.is_recovery_complete() {
        assert!(
            Instant::now() < deadline,
            "recovery after restart did not complete within 120s"
        );
        thread::sleep(Duration::from_secs(5));
    }

    generate_blocks(bitcoind, 1);
    restarted
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();

    let balances = restarted
        .get_wallet()
        .read()
        .unwrap()
        .get_balances()
        .unwrap();
    info!(
        "Taker balances after restart recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        balances.regular, balances.swap, balances.contract, balances.spendable,
    );
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
        ProtocolVersion::Legacy => 7237,
        ProtocolVersion::Taproot => 6367,
    };
    assert_eq!(
        balance_diff.to_sat(),
        expected_diff,
        "taker did not get its funds back after restart recovery"
    );

    for (i, maker) in makers.iter().enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
        let mb = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i, mb.regular, mb.swap, mb.contract, mb.spendable,
        );
    }

    assert_eq!(
        balances.contract.to_sat(),
        0,
        "Taker contract balance must be cleared after recovery"
    );
    assert_eq!(balances.fidelity, Amount::ZERO);

    let wallet = restarted.get_wallet();
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
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("No persisted swapcoins found for recovery"),
        "restarted taker failed to read the swap back off disk"
    );

    info!("Taker restart recovery test completed successfully!");

    test_framework.stop();
    block_generation_handle.join().unwrap();
}
