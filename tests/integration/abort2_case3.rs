//! Integration test: Maker abort2 case 3 (Legacy).
//!
//! Maker drops at ProofOfFunding after funding is on-chain.
//! Recovery via timelock.
//!
//! Route: Taker -> Maker1 (Normal) -> Maker2 (CloseAtProofOfFunding) -> Taker
//!
//! Scenario:
//! 1. Taker initiates a Legacy openswap with 2 makers.
//! 2. Funding transactions are broadcast and confirmed.
//! 3. Maker2 drops the connection at ProofOfFunding.
//! 4. Taker detects the failure and triggers recovery.
//! 5. Everyone falls back to timelock recovery.
//! 6. After blocks mature, verify: taker recovered funds (minus fees), no contract balance.

use openswap::protocol::common_messages::ProtocolVersion;

use super::scenarios::maker_abort::{run_maker_abort_recovery, MakerAbortExpect};

use super::test_framework::*;

/// Test: Maker drops at ProofOfFunding after funding. Recovery via timelock.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAtProofOfFunding],
    takers = [Normal],
)]
fn maker_abort2_case3(world: &mut World) {
    run_maker_abort_recovery(
        world,
        ProtocolVersion::Legacy,
        "Swap should fail due to Maker2 closing at ProofOfFunding",
        &MakerAbortExpect {
            taker_regular: 14998662,
            taker_swap: 0,
            taker_loss: 1338,
            maker_regular: [14998419, 14999757],
            maker_swap: [0, 0],
            maker_spendable: None,
        },
    );
}
