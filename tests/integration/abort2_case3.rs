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

use openswap::{maker::MakerBehavior, protocol::common_messages::ProtocolVersion};

use super::scenarios::maker_abort::{run_maker_abort_recovery, MakerAbortExpect};

use log::warn;

/// Test: Maker drops at ProofOfFunding after funding. Recovery via timelock.
#[test]
fn maker_abort2_case3() {
    warn!("Running Test: Maker Abort2 Case 3 - CloseAtProofOfFunding (recovery)");

    run_maker_abort_recovery(
        ProtocolVersion::Legacy,
        MakerBehavior::CloseAtProofOfFunding,
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
