use openswap::{maker::MakerBehavior, protocol::common_messages::ProtocolVersion};

use super::scenarios::spare_maker::{run_spare_maker_swap, SpareMakerExpect};

use log::warn;

/// Test: Maker drops after sending AckSwapDetails (Taproot). Taker finds spare maker.
///
/// Scenario:
/// 1. Taker initiates a Taproot openswap requiring 2 makers, 3 are available.
/// 2. maker[1] drops after sending AckSwapDetails (before funding broadcast).
/// 3. Taker detects the failure and retries with the spare maker (maker[2]).
/// 4. Swap completes successfully with maker[0] and maker[2].
/// 5. Verify: taker lost fees, makers gained fees.
#[test]
fn test_taproot_maker_abort3() {
    warn!("Running Test: Taproot Maker Abort3 - CloseAfterAckResponse, spare maker available");

    run_spare_maker_swap(
        ProtocolVersion::Taproot,
        [
            MakerBehavior::Normal,
            MakerBehavior::CloseAfterAckResponse,
            MakerBehavior::Normal,
        ],
        "Failed to prepare Taproot openswap",
        &SpareMakerExpect {
            taker_spendable: 14996327,
            maker_spendable: [15000415, 14999757, 15000378],
        },
    );
}
