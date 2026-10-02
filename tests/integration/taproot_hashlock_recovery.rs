//! Integration test: Taproot hashlock recovery - Maker drops after sweep.
//!
//! Route: Taker -> Maker1 (Normal) -> Maker2 (CloseAfterSweep) -> Taker
//!
//! Scenario:
//! 1. Taker initiates a Taproot openswap with 2 makers.
//! 2. Funding transactions are broadcast and confirmed.
//! 3. Maker2 drops the connection after completing its sweep.
//! 4. Taker detects the failure and calls `recover_active_swap()`.
//! 5. Recovery proceeds (may partially complete via hashlock or timelock).
//! 6. After blocks mature, verify: taker recovered funds (minus fees), no contract balance.

use openswap::protocol::common_messages::ProtocolVersion;

use super::scenarios::maker_abort::{run_maker_abort_recovery, MakerAbortExpect};

use super::test_framework::*;

/// Test: Maker drops after sweep (Taproot). Recovery via hashlock/timelock.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAfterSweep],
    takers = [Normal],
)]
fn test_taproot_hashlock_recovery(world: &mut World) {
    run_maker_abort_recovery(
        world,
        ProtocolVersion::Taproot,
        "Swap should fail due to Maker2 closing after sweep",
        &MakerAbortExpect {
            taker_regular: 14499538,
            taker_swap: 496660,
            taker_loss: 3802,
            maker_regular: [14500751, 14502170],
            maker_swap: [499664, 498208],
            maker_spendable: Some([15000415, 15000378]),
        },
    );
}
