use bitcoin::Amount;
use openswap::{protocol::common_messages::ProtocolVersion, taker::SwapParams};

use crate::test_framework::*;

use log::info;
use std::{thread, time::Duration};

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAfterSweep],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
)]
fn maker_drops_after_sweep(world: &mut World) {
    let before = world.balances();
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

    // The point of the test: the preimage was on-chain, so recovery must have
    // gone through the hashlock branch, not the timelock one.
    assert_log!(world; { has "Signing legacy hashlock spend with preimage" });

    // The hashlock sweep is a separate tx per contract, so the taker pays more
    // than the 4339 sats a clean legacy swap costs.
    //
    // Both makers still earn their full fee: maker 1 completed the swap and
    // maker 2 swept before dropping. Their wallets were synced after the
    // shutdown above and are read as they stand.
    assert_balances!(world, since before; {
        taker: { regular: 14_499_538, swap: 495_997, contract: 0, fidelity: 0, loss: 4_465 },
        makers: {
            regular: [14_500_865, 14_502_398],
            swap: [499_550, 497_980],
            contract: 0,
            fidelity: BOND,
            gain: [658, 621],
        },
    });

    world.taker().log_tracker_state();
    info!("Legacy hashlock recovery test completed successfully!");

    tracker_logger.stop();
}
