use bitcoin::Amount;
use openswap::taker::SwapParams;

use super::test_framework::*;

use log::info;
use std::{thread, time::Duration};

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [DropAfterFundsBroadcast],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn taker_abort_1_legacy_corerpc(
    world: &mut World,
    taker_original_balance: Amount,
    params: SwapParams,
) {
    world.mine(1);

    // Start periodic swap tracker logging
    let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

    // Prepare should succeed; execution should fail with DropAfterFundsBroadcast
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to DropAfterFundsBroadcast behavior"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    world.taker().log_tracker_state();

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    world.assert_makers_contract_zero();

    // Wait for taker's background recovery loop to finish
    world.taker().await_recovery(Duration::from_secs(120));
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.taker().sync();

    // Verify taker balance
    let taker_balances = world.taker().balances();

    info!(
        "Taker balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    BalanceExpect {
        regular: Some(Is::Sats(14499538)),
        swap: Some(Is::Sats(495997)),
        contract: Some(Is::Sats(0)),
        fidelity: Some(Is::Amount(Amount::ZERO)),
        spendable: None,
        delta: Some(Delta::Loss {
            baseline: taker_original_balance,
            style: DiffStyle::CheckedUnwrap,
            sats: 4465,
        }),
    }
    .assert("Taker", &taker_balances);

    // Verify maker balances - makers should have recovered via timelock
    let expected_regular = [14500865, 14502398];
    let expected_swap = [499100, 497530];
    let expected_spendable = [14999965, 14999928];
    for (i, maker) in world.makers().iter().enumerate() {
        maker.sync();
        let balances = maker.balances();

        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i,
            balances.regular,
            balances.swap,
            balances.contract,
            balances.fidelity,
            balances.spendable,
        );

        BalanceExpect {
            regular: Some(Is::Sats(expected_regular[i])),
            swap: Some(Is::Sats(expected_swap[i])),
            contract: Some(Is::Sats(0)),
            fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
            spendable: Some(Is::Sats(expected_spendable[i])),
            delta: None,
        }
        .assert(&format!("Maker {i}"), &balances);
    }

    world.taker().log_tracker_state();
    info!("Abort1 test completed successfully!");

    world.shutdown_makers();
    tracker_logger.stop();
}

/// A taker that never goes quiet must still not outlive the swap's locktime. Here the
/// taker keeps the route warm with keepalives while the miner pushes the tip past the
/// maker's refund deadline. The maker must stop honouring the keepalives and recover,
/// even though the connection was never dropped and the idle timeout never fired.
///
/// One maker on purpose: a single hop is funded with the full negotiated amount, so
/// the swap reaches the maker's outgoing funding without depending on route fees.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [StallAfterProofOfFunding],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    // Legacy so the deadline is counted from the funding confirmation height the
    // maker records, which is the arm this test exists to prove.
    swap(protocol = Legacy, sats = 500_000, makers = 1, tx_count = 1),
)]
fn maker_recovers_swap_past_refund_deadline(world: &mut World, params: SwapParams) {
    world
        .taker_mut()
        .swap_fails(params, "The swap must fail once the maker gives up on it");

    let log_path = world.taker_log_path();
    let framework = world.framework();
    framework.assert_log(
        "Test behavior: stalling 180s so the maker's refund deadline passes",
        &log_path,
    );
    // The deadline, not a dropped connection, is what ended this swap. Keepalives were
    // still arriving every 5s, so the idle timeout could not have drained it.
    framework.assert_log("reached its refund deadline; recovering now", &log_path);
    framework.assert_log("Recovering from swap", &log_path);
}
