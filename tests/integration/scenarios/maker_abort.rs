//! Two makers; the second closes at a given step once funding is on-chain, and
//! every party falls back to on-chain recovery.
//!
//! [`run_maker_abort_recovery`] serves `abort2_case3`, `abort3_case1`,
//! `abort3_case2`, `abort3_case3` and `taproot_hashlock_recovery`.
//! `taproot_maker_abort2` and `taproot_timelock_recovery` run the same three
//! [`MakerAbort`] stages with their own checks in between.

use bitcoin::Amount;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use crate::test_framework::*;

use log::info;
use std::{thread, time::Duration};

/// The balances one maker-abort test asserts once recovery is done.
pub(crate) struct MakerAbortExpect {
    pub taker_regular: u64,
    pub taker_swap: u64,
    /// Taker funding minus its final spendable balance.
    pub taker_loss: u64,
    pub maker_regular: [u64; 2],
    pub maker_swap: [u64; 2],
    /// `None` where the test asserts nothing about the makers' spendable balance.
    pub maker_spendable: Option<[u64; 2]>,
}

/// Runs the three [`MakerAbort`] stages back to back.
pub(crate) fn run_maker_abort_recovery(
    protocol: ProtocolVersion,
    behavior: MakerBehavior,
    failure: &str,
    expected: &MakerAbortExpect,
) {
    let abort = MakerAbort::fail_swap(protocol, behavior, failure);
    abort.recover();
    abort.assert_recovered(expected);
}

/// A world whose swap Maker2 has just broken off.
pub(crate) struct MakerAbort {
    world: World,
    taker_original_balance: Amount,
    tracker_logger: TrackerLoggerHandle,
}

impl MakerAbort {
    /// Runs a Taker -> Maker1 (Normal) -> Maker2 (`behavior`) swap over
    /// `protocol` and asserts it fails, with `failure` as the message.
    pub(crate) fn fail_swap(
        protocol: ProtocolVersion,
        behavior: MakerBehavior,
        failure: &str,
    ) -> Self {
        let mut world = World::builder::<BitcoindBackend>()
            .makers(2)
            .maker_behaviors([MakerBehavior::Normal, behavior])
            .takers([TakerBehavior::Normal])
            .build();

        // Fund the taker with 3 UTXOs of 0.05 BTC each
        let taker_original_balance = world.fund_taker_default(3);

        // Fund the makers with 4 UTXOs of 0.05 BTC each
        world.fund_makers_default();

        log::info!("Starting Maker servers...");
        world.start_makers(120);

        // Use post-fidelity, pre-swap balances as the correct baseline
        world.verify_maker_pre_swap_balances();

        // Start periodic swap tracker logging (every 10s)
        let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

        let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
            .with_tx_count(3)
            .with_required_confirms(1);

        world.mine(1);

        // Prepare should succeed; execution should fail because Maker2 drops
        let summary = world
            .taker_mut()
            .prepare(swap_params)
            .expect("Prepare should succeed");
        let swap_result = world.taker_mut().start(&summary.swap_id);
        assert!(swap_result.is_err(), "{}", failure);
        info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

        MakerAbort {
            world,
            taker_original_balance,
            tracker_logger,
        }
    }

    pub(crate) fn world(&self) -> &World {
        &self.world
    }

    /// Waits out the timelocks, asserts both makers recovered their
    /// contracts, then waits for the taker's recovery loop.
    pub(crate) fn recover(&self) {
        let world = &self.world;
        world.taker().log_tracker_state();

        // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
        // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
        // 5 blocks/3s; remaining ~105s is scheduling margin.
        info!("Waiting for makers to timeout and blocks to mature timelocks...");
        thread::sleep(Duration::from_secs(300));

        world.assert_makers_contract_zero();

        // The background recovery loop (spawned by recover_active_swap) periodically
        // retries hashlock sweeps and timelock recovery. Wait for it to finish.
        info!("Waiting for background recovery loop to complete...");
        world.taker().await_recovery(Duration::from_secs(120));
        info!("Background recovery loop completed.");
    }

    /// Mines the recovery txs, asserts the taker's and then each maker's
    /// balances, and tears the world down.
    pub(crate) fn assert_recovered(self, expected: &MakerAbortExpect) {
        let MakerAbort {
            mut world,
            taker_original_balance,
            tracker_logger,
        } = self;

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
            swap: Some(Is::Sats(expected.taker_swap)),
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
                regular: Some(Is::Sats(expected.maker_regular[i])),
                swap: Some(Is::Sats(expected.maker_swap[i])),
                contract: Some(Is::Sats(0)),
                fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
                spendable: expected
                    .maker_spendable
                    .map(|spendable| Is::Sats(spendable[i])),
                delta: None,
            }
            .assert(&format!("Maker {i}"), &balances);
        }

        world.taker().log_tracker_state();

        world.shutdown_makers();
        tracker_logger.stop();
        world.finish();
    }
}
