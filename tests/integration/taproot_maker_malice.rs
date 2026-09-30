use bitcoin::Amount;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use super::test_framework::*;

use log::{info, warn};
use std::{thread, time::Duration};

/// Test: Maker locks its funds on-chain after setup, then closes.
///
/// Maker[1] broadcasts its contract transaction and closes without sending
/// its contract-data response. The taker detects the failure and all parties
/// recover via timelock.
#[test]
fn test_taproot_malice_maker_broadcast_contract() {
    // ---- Setup ----
    warn!("Running Test: Taproot Malice - Maker Broadcasts Contract After Setup");

    let mut world = World::builder::<BitcoindBackend>()
        .makers(2)
        .maker_behaviors([
            MakerBehavior::Normal,
            MakerBehavior::BroadcastContractAfterSetup,
        ])
        .takers([TakerBehavior::Normal])
        .build();

    // Fund the taker with 3 UTXOs of 0.05 BTC each
    let taker_original_balance = world.fund_taker_default(3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    world.fund_makers_default();

    log::info!("Starting Maker servers...");
    world.start_makers(120);

    let maker_spendable_balance = world.verify_maker_pre_swap_balances();
    log::info!("Starting taproot maker malice test...");

    // Start periodic swap tracker logging (every 10s)
    let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

    // Swap params for openswap (Taproot)
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count(1)
        .with_required_confirms(1);

    world.mine(1);

    // Prepare should succeed; execution should fail because maker broadcasts contracts
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to maker BroadcastContractAfterSetup behavior"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    world.taker().log_tracker_state();

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    // Shut down makers
    world.shutdown_makers();

    // Log all maker balances before asserting so one run reports every value.
    let mut maker_balances_all = Vec::new();
    for (i, maker) in world.makers().iter().enumerate() {
        maker.sync();
        let maker_balances = maker.balances();
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

    // Verify maker balances -- makers should have recovered their outgoing funds via timelock.
    // Nobody earns a fee here; each maker only pays for its own recovery.
    let expected_regular = [14999463, 14999463];
    for (i, (maker_balances, original)) in maker_balances_all
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        BalanceExpect {
            regular: Some(Is::Sats(expected_regular[i])),
            swap: Some(Is::Sats(0)),
            contract: Some(Is::Sats(0)),
            fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
            spendable: None,
            delta: Some(Delta::Loss {
                baseline: original,
                style: DiffStyle::UnwrapOrZero,
                sats: 294,
            }),
        }
        .assert(&format!("Maker {i}"), maker_balances);
    }

    // Verify taker balance. The taker recovered its own funding, so it only
    // pays the recovery fees.
    BalanceExpect {
        regular: Some(Is::Sats(14999706)),
        swap: Some(Is::Sats(0)),
        contract: Some(Is::Sats(0)),
        fidelity: Some(Is::Amount(Amount::ZERO)),
        spendable: None,
        delta: Some(Delta::Loss {
            baseline: taker_original_balance,
            style: DiffStyle::UnwrapOrZero,
            sats: 294,
        }),
    }
    .assert("Taker", &taker_balances);

    // TODO: the maker that broadcasts its contract is never banned. The swap
    // aborts on the transport error before the ContractsBroadcasted ban site, and
    // the breach detector fires on the taker's OWN recovery broadcast, so its
    // signal cannot attribute the breach to a maker.
    // assert_only_makers_banned(taker, &makers, &[1]);

    world.taker().log_tracker_state();
    info!("Taproot maker malice test completed successfully!");

    tracker_logger.stop();
    world.finish();
}
