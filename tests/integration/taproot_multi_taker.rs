use openswap::protocol::common_messages::ProtocolVersion;

use super::scenarios::multi_taker::{run_sequential_multi_taker, MultiTakerExpect};

use log::warn;

#[test]
fn test_taproot_multi_taker_openswap() {
    // ---- Setup ----
    warn!("Running Test: Multi-Taker OpenSwap with Taproot (MuSig2) Protocol");

    run_sequential_multi_taker(
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
