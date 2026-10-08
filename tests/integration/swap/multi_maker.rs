use bitcoin::Amount;
use openswap::{protocol::common_messages::ProtocolVersion, taker::SwapParams};

use crate::test_framework::*;

use log::info;

#[world_test(
    backend = BitcoindBackend,
    makers = 4,
    takers = [Normal],
    setup = [
        // Fund the taker with 5 UTXOs of 0.05 BTC each (P2TR for Taproot)
        // Need more UTXOs for a 4-maker route
        fund_taker_default(5),
        // Fund makers with 4 UTXOs of 0.05 BTC each
        fund_makers_default(),
        // Start the makers, wait for their setup, then sync their wallets so the
        // fidelity bonds are accounted for
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
)]
fn taproot_four_maker_swap_completes(world: &mut World) {
    let before = world.balances();

    // Swap params for openswap (Taproot) with 4 makers
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 4)
        .with_tx_count(3)
        .with_required_confirms(1);

    // Mine some blocks before the swap to ensure wallet is ready
    world.mine(1);

    // Prepare the swap (negotiate with makers, get fee summary)
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Failed to prepare Taproot openswap with 4 makers");
    log::info!("Swap summary: {:?}", summary);

    // Execute the swap
    match world.taker_mut().start(&summary.swap_id) {
        Ok(report) => {
            log::info!("OpenSwap (Taproot, 4 makers) completed successfully!");
            log::info!("Swap report: {:?}", report);
        }
        Err(e) => {
            log::error!("OpenSwap (Taproot, 4 makers) failed: {:?}", e);
            panic!("OpenSwap (Taproot, 4 makers) failed: {:?}", e);
        }
    }

    log::info!("All openswaps processed successfully. Transaction complete.");

    // Sync wallets and verify results
    world.taker().sync();

    // Mine a block to confirm the sweep transactions
    world.mine(1);

    world.sync_makers();

    // Verify all 4 makers earned fees.
    assert_balances!(world, since before; {
        taker: { spendable: 24_993_303, contract: 0, fidelity: 0, loss: 6_697 },
        makers: {
            regular: [14_500_826, 14_502_320, 14_503_776, 14_505_194],
            swap: [499_664, 498_133, 496_639, 495_183],
            contract: 0,
            fidelity: BOND,
            gain: [733, 696, 658, 620],
        },
    });

    info!("All multi-maker swap tests (Taproot, 4 makers) completed successfully!");
}
