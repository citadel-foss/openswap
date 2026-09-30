use openswap::taker::TakerBehavior;

use super::scenarios::taker_abort::{run_taproot_taker_abort, TakerAbortExpect};

use log::warn;

/// Test: Taker aborts at sender's contract exchange (Taproot).
///
/// The taker drops the connection when about to send sender's contract data
/// to a maker. Funding transactions are already on-chain, so timelock
/// recovery is required for all parties to reclaim their funds.
#[test]
fn test_taproot_taker_abort2() {
    warn!("Running Test: Taproot Taker Abort2 - Close at Sender's Contract");

    run_taproot_taker_abort(
        TakerBehavior::CloseAtSendersContract,
        &TakerAbortExpect {
            maker_regular: [14999757; 2],
            maker_loss: None,
            taker_regular: 14999118,
            taker_loss: 882,
        },
    );
}
