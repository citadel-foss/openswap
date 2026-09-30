use bitcoin::Amount;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use super::test_framework::*;

use log::{info, warn};
use std::{thread, time::Duration};

#[test]
fn test_legacy_hashlock_recovery() {
    warn!("Running Test: Legacy Hashlock Recovery - CloseAfterSweep");

    let mut world = World::builder::<BitcoindBackend>()
        .makers(2)
        .maker_behaviors([MakerBehavior::Normal, MakerBehavior::CloseAfterSweep])
        .takers([TakerBehavior::Normal])
        .build();

    let taker_original_balance = world.fund_taker_default(3);
    world.fund_makers_default();

    info!("Starting Maker servers...");
    world.start_makers(120);

    let maker_spendable_balance = world.verify_maker_pre_swap_balances();

    let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to Maker2 closing after sweep"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    world.taker().log_tracker_state();

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    world.shutdown_makers();

    world.assert_makers_contract_zero();

    info!("Waiting for background recovery loop to complete...");
    world.taker().await_recovery(Duration::from_secs(120));
    info!("Background recovery loop completed.");

    world.mine(1);
    world.taker().sync();

    let taker_balances = world.taker().balances();
    info!(
        "Taker balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    // The point of the test: the preimage was on-chain, so recovery must have
    // gone through the hashlock branch, not the timelock one.
    let log_path = world.taker_log_path();
    world
        .framework()
        .assert_log("Signing legacy hashlock spend with preimage", &log_path);

    // The hashlock sweep is a separate tx per contract, so the taker pays more
    // than the 4339 sats a clean legacy swap costs.
    BalanceExpect {
        regular: Some(Is::Sats(14499538)),
        swap: Some(Is::Sats(495997)),
        contract: Some(Is::Sats(0)),
        fidelity: Some(Is::Amount(Amount::ZERO)),
        spendable: None,
        delta: Some(Delta::Loss {
            baseline: taker_original_balance,
            style: DiffStyle::UnwrapOrZero,
            sats: 4465,
        }),
    }
    .assert("Taker", &taker_balances);

    // Both makers still earn their full fee: maker 1 completed the swap and
    // maker 2 swept before dropping. Their wallets were synced after the
    // shutdown above and are read as they stand.
    let expected_regular = [14500865, 14502398];
    let expected_swap = [499550, 497980];
    let expected_fee = [658, 621];
    for (i, (maker, original)) in world
        .makers()
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        let balances = maker.balances();
        info!(
            "Maker {} balance diff: pre-swap: {}, current: {}",
            i, original, balances.spendable,
        );
        BalanceExpect {
            regular: Some(Is::Sats(expected_regular[i])),
            swap: Some(Is::Sats(expected_swap[i])),
            contract: Some(Is::Sats(0)),
            fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
            spendable: None,
            delta: Some(Delta::Gain {
                baseline: original,
                style: DiffStyle::UnwrapOrZero,
                sats: expected_fee[i],
            }),
        }
        .assert(&format!("Maker {i}"), &balances);
    }

    world.taker().log_tracker_state();
    info!("Legacy hashlock recovery test completed successfully!");

    tracker_logger.stop();
    world.finish();
}
