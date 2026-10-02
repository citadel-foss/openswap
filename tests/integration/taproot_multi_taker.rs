use openswap::protocol::common_messages::ProtocolVersion;

use super::scenarios::multi_taker::{run_sequential_multi_taker, MultiTakerExpect};

use super::test_framework::*;

use log::warn;

#[world_test(
    backend = BitcoindBackend,
    makers = 2,
    takers = [Normal, Normal],
)]
fn test_taproot_multi_taker_openswap(world: &mut World) {
    // ---- Setup ----
    warn!("Running Test: Multi-Taker OpenSwap with Taproot (MuSig2) Protocol");

    run_sequential_multi_taker(
        world,
        ProtocolVersion::Taproot,
        &MultiTakerExpect {
            taker_spendable: [14996327, 14996327],
            taker_fee: [3673, 3673],
            maker_regular: [14001745, 14004583],
            maker_swap: [999328, 996416],
            maker_fee: [1316, 1242],
        },
    );
}
