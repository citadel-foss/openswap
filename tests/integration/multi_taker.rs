use openswap::protocol::common_messages::ProtocolVersion;

use super::scenarios::multi_taker::{run_sequential_multi_taker, MultiTakerExpect};

use log::warn;

#[test]
fn test_multi_taker_openswap() {
    // ---- Setup ----
    warn!("Running Test: Multi-Taker OpenSwap with Legacy (ECDSA) Protocol");

    run_sequential_multi_taker(
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
