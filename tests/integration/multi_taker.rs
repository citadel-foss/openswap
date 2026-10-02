use openswap::protocol::common_messages::ProtocolVersion;

use super::scenarios::multi_taker::{run_sequential_multi_taker, MultiTakerExpect};

use super::test_framework::*;

use log::warn;

#[world_test(
    backend = BitcoindBackend,
    makers = 2,
    takers = [Normal, Normal],
)]
fn test_multi_taker_openswap(world: &mut World) {
    // ---- Setup ----
    warn!("Running Test: Multi-Taker OpenSwap with Legacy (ECDSA) Protocol");

    run_sequential_multi_taker(
        world,
        ProtocolVersion::Legacy,
        &MultiTakerExpect {
            taker_spendable: [14995985, 14995985],
            taker_fee: [4015, 4015],
            maker_regular: [14001973, 14005039],
            maker_swap: [999100, 995960],
            maker_fee: [1316, 1242],
        },
    );
}
