//! Two Normal makers; the taker drops at a given step once funding is on-chain,
//! and every party timelock-recovers.
//!
//! Serves `taproot_taker_abort2` and both tests in `taproot_taker_abort3`.

use bitcoin::Amount;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use crate::test_framework::*;

use log::info;
use std::{thread, time::Duration};

/// The balances one taker-abort test asserts once recovery is done.
pub(crate) struct TakerAbortExpect {
    pub maker_regular: [u64; 2],
    /// Each maker's pre-swap spendable balance minus its final one; `None`
    /// where the test does not assert it.
    pub maker_loss: Option<[u64; 2]>,
    pub taker_regular: u64,
    /// Taker funding minus its final spendable balance.
    pub taker_loss: u64,
}

/// Drives one taker-drop case through timelock recovery and asserts the
/// golden balances that pin how that drop point settles.
pub(crate) fn run_taproot_taker_abort(behavior: TakerBehavior, expected: &TakerAbortExpect) {
    let mut world = World::builder::<BitcoindBackend>()
        .makers(2)
        .maker_behaviors([MakerBehavior::Normal, MakerBehavior::Normal])
        .takers([behavior])
        .build();

    let taker_original_balance = world.fund_taker_default(3);
    world.fund_makers_default();

    info!("Starting Maker servers...");
    world.start_makers(120);

    let maker_spendable_balance = world.verify_maker_pre_swap_balances();

    let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    // Prepare should succeed; execution should fail at the case's drop point.
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to {:?} behavior",
        behavior
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    world.taker().log_tracker_state();

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    // Verify maker balances -- makers should have recovered their outgoing
    // funds via timelock.
    for (i, (maker, original)) in world
        .makers()
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        maker.sync();
        let balances = maker.balances();
        info!(
            "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.spendable,
        );
        BalanceExpect {
            regular: Some(Is::Sats(expected.maker_regular[i])),
            swap: Some(Is::Sats(0)),
            contract: Some(Is::Sats(0)),
            fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
            spendable: None,
            delta: expected.maker_loss.map(|loss| Delta::Loss {
                baseline: original,
                style: DiffStyle::UnwrapOrZero,
                sats: loss[i],
            }),
        }
        .assert(&format!("Maker {i}"), &balances);
    }

    // The background recovery loop (spawned by recover_active_swap) periodically
    // retries hashlock sweeps and timelock recovery. Wait for it to finish.
    world.taker().await_recovery(Duration::from_secs(120));
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
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
    BalanceExpect {
        regular: Some(Is::Sats(expected.taker_regular)),
        swap: Some(Is::Sats(0)),
        contract: Some(Is::Sats(0)),
        fidelity: Some(Is::Amount(Amount::ZERO)),
        spendable: None,
        delta: Some(Delta::Loss {
            baseline: taker_original_balance,
            style: DiffStyle::UnwrapOrZero,
            sats: expected.taker_loss,
        }),
    }
    .assert("Taker", &taker_balances);

    world.taker().log_tracker_state();

    world.shutdown_makers();
    tracker_logger.stop();
    world.finish();
}
