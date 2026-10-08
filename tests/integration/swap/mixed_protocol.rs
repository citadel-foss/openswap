//! Concurrent mixed-protocol integration test.
//!
//! Two takers use the same two makers at the same time: one swap uses Legacy
//! and the other uses Taproot. This verifies that makers keep protocol state
//! isolated per swap instead of treating the negotiated protocol as a
//! maker-wide setting.

use bitcoin::Amount;
use openswap::{
    protocol::common_messages::ProtocolVersion, taker::SwapParams, wallet::AddressType,
};

use crate::test_framework::*;

use log::{info, warn};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc, Barrier,
    },
    thread,
};

#[world_test(
    backend = BitcoindBackend,
    // Admission reserves nothing, so both plans form over the same pool.
    makers = 2,
    takers = [Normal, Normal],
)]
fn legacy_and_taproot_swaps_run_together(world: &mut World) {
    for i in 0..world.takers().len() {
        world.fund_nth_taker_default(i, 3);
    }
    // Both admissions plan over the same pool, so the protocols' split sizes
    // keep the plans apart: legacy splits (~167k) fit the 200k coins, taproot
    // splits (~233k) need the 300k ones. The bond takes its exact UTXO and
    // leaves no change in the pool.
    world.fund_makers(1, Amount::from_sat(5_000_243), AddressType::P2TR);
    world.fund_makers(3, Amount::from_sat(200_000), AddressType::P2TR);
    world.fund_makers(3, Amount::from_sat(300_000), AddressType::P2TR);

    world.start_makers(120);
    // Not verify_maker_pre_swap_balances: that helper pins the 4-UTXO funding
    // shape, and this test needs more UTXOs for two concurrent frozen plans.
    let before = world.balances();
    world.mine(1);

    let start = Arc::new(Barrier::new(2));
    let legacy_succeeded = AtomicBool::new(false);
    let taproot_succeeded = AtomicBool::new(false);

    thread::scope(|scope| {
        let (legacy_takers, taproot_takers) = world.takers_mut().split_at_mut(1);
        let legacy_taker = &mut legacy_takers[0];
        let taproot_taker = &mut taproot_takers[0];

        let legacy_start = start.clone();
        let legacy_result = &legacy_succeeded;
        scope.spawn(move || {
            legacy_start.wait();
            info!("Starting Legacy swap concurrently");

            let params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 2)
                .with_tx_count(3)
                .with_required_confirms(1);
            let result = legacy_taker
                .prepare(params)
                .and_then(|summary| legacy_taker.start(&summary.swap_id));

            match result {
                Ok(report) => {
                    info!("Concurrent Legacy swap completed: {:?}", report);
                    legacy_result.store(true, Relaxed);
                }
                Err(error) => warn!("Concurrent Legacy swap failed: {:?}", error),
            }
        });

        let taproot_start = start.clone();
        let taproot_result = &taproot_succeeded;
        scope.spawn(move || {
            taproot_start.wait();
            info!("Starting Taproot swap concurrently");

            let params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(700_000), 2)
                .with_tx_count(3)
                .with_required_confirms(1);
            let result = taproot_taker
                .prepare(params)
                .and_then(|summary| taproot_taker.start(&summary.swap_id));

            match result {
                Ok(report) => {
                    info!("Concurrent Taproot swap completed: {:?}", report);
                    taproot_result.store(true, Relaxed);
                }
                Err(error) => warn!("Concurrent Taproot swap failed: {:?}", error),
            }
        });
    });

    assert!(
        legacy_succeeded.load(Relaxed),
        "Legacy swap should succeed while the makers also process a Taproot swap"
    );
    assert!(
        taproot_succeeded.load(Relaxed),
        "Taproot swap should succeed while the makers also process a Legacy swap"
    );

    for taker in world.takers() {
        taker.sync();
    }
    world.mine(1);
    world.sync_makers();

    assert_balances!(world, since before; {
        takers: {
            regular: [14_499_538, 14_299_538],
            swap: [496_447, 696_704],
            contract: 0,
            fidelity: 0,
            loss: [4_015, 3_758],
        },
        makers: {
            regular: [302_152, 305_139],
            swap: [1_199_214, 1_196_138],
            contract: 0,
            fidelity: BOND,
            gain: [1_366, 1_277],
        },
    });
}
