use openswap::taker::TakerBehavior;

use super::scenarios::taker_abort::{run_taproot_taker_abort, TakerAbortExpect};

use log::warn;

/// Test: Taker aborts after receiving maker's contract response (Taproot).
///
/// The taker drops the connection after receiving the maker's contract data
/// response. Funding transactions are already on-chain, so timelock recovery
/// is required.
#[test]
fn test_taproot_taker_abort3() {
    warn!("Running Test: Taproot Taker Abort - close at maker's contract data response");

    run_taproot_taker_abort(
        TakerBehavior::CloseAtSendersContractFromMaker,
        &TakerAbortExpect {
            maker_regular: [14998875, 14999757],
            maker_loss: Some([882, 0]),
            taker_regular: 14999118,
            taker_loss: 882,
        },
    );
}

/// Test: Taker drops after full setup, before the private-key handover.
///
/// Recovery starts from the complete outgoing + incoming coin set: both
/// makers timelock-refund whole, and the taker absorbs the swap amount plus
/// every funding fee.
#[test]
fn test_taproot_taker_abort_after_full_setup() {
    warn!("Running Test: Taproot Taker Abort - drop after full setup");

    run_taproot_taker_abort(
        TakerBehavior::BroadcastContractAfterFullSetup,
        &TakerAbortExpect {
            maker_regular: [14998875, 14998875],
            maker_loss: Some([882, 882]),
            taker_regular: 14499538,
            taker_loss: 500462,
        },
    );
}
