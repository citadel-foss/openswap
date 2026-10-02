use super::scenarios::taker_abort::{run_taproot_taker_abort, TakerAbortExpect};

use super::test_framework::*;

/// Test: Taker aborts at sender's contract exchange (Taproot).
///
/// The taker drops the connection when about to send sender's contract data
/// to a maker. Funding transactions are already on-chain, so timelock
/// recovery is required for all parties to reclaim their funds.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [CloseAtSendersContract],
)]
fn test_taproot_taker_abort2(world: &mut World) {
    run_taproot_taker_abort(
        world,
        &TakerAbortExpect {
            maker_regular: [14999757; 2],
            maker_loss: None,
            taker_regular: 14999118,
            taker_loss: 882,
        },
    );
}
