use openswap::protocol::common_messages::ProtocolVersion;

use super::scenarios::spare_maker::{complete_with_spare, SpareMakerExpect};

use super::test_framework::*;

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [CloseAtReqContractSigsForSender, Normal, Normal],
    takers = [Normal],
)]
fn maker_abort2_case2(world: &mut World) {
    complete_with_spare(
        world,
        ProtocolVersion::Legacy,
        "Failed to prepare openswap",
        &SpareMakerExpect {
            taker_spendable: 14995985,
            maker_spendable: [14999757, 15000378, 15000415],
        },
    );
}
