//! Integration test: Maker abort3 case 3 (Legacy).
//!
//! Maker drops at hash preimage handover after funding is on-chain.
//! Recovery via timelock.
//!
//! Route: Taker -> Maker1 (Normal) -> Maker2 (CloseAtHashPreimage) -> Taker
//!
//! Scenario:
//! 1. Taker initiates a Legacy openswap with 2 makers.
//! 2. Funding transactions are broadcast and confirmed.
//! 3. Maker2 drops the connection at hash preimage handover.
//! 4. Taker detects the failure and calls `recover_active_swap()`.
//! 5. Everyone falls back to timelock recovery.
//! 6. After blocks mature, verify: taker recovered funds (minus fees), no contract balance.

use openswap::{maker::MakerBehavior, protocol::common_messages::ProtocolVersion};

use super::scenarios::maker_abort::{run_maker_abort_recovery, MakerAbortExpect};

use log::warn;

/// Test: Maker drops at hash preimage handover. Recovery via timelock.
#[test]
fn maker_abort3_case3() {
    warn!("Running Test: Maker Abort3 Case 3 - CloseAtHashPreimage");

    run_maker_abort_recovery(
        ProtocolVersion::Legacy,
        MakerBehavior::CloseAtHashPreimage,
        "Swap should fail due to Maker2 closing at hash preimage handover",
        &MakerAbortExpect {
            taker_regular: 14499538,
            taker_swap: 495997,
            taker_loss: 4465,
            maker_regular: [14500865, 14502398],
            maker_swap: [499550, 497530],
            maker_spendable: Some([15000415, 14999928]),
        },
    );
}
