use openswap::{maker::MakerBehavior, protocol::common_messages::ProtocolVersion};

use super::scenarios::spare_maker::{run_spare_maker_swap, SpareMakerExpect};

use log::warn;

#[test]
fn maker_abort2_case2() {
    warn!("Running Test: First maker drops before sending sender's sigs. Taker continues with remaining makers.");

    run_spare_maker_swap(
        ProtocolVersion::Legacy,
        [
            MakerBehavior::CloseAtReqContractSigsForSender,
            MakerBehavior::Normal,
            MakerBehavior::Normal,
        ],
        "Failed to prepare openswap",
        &SpareMakerExpect {
            taker_spendable: 14995985,
            maker_spendable: [14999757, 15000378, 15000415],
        },
    );
}
