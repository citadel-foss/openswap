//! Integration test: Maker abort3 case 2 (Legacy).
//!
//! Maker drops at ReqContractSigsForRecvr after funding is on-chain.
//! Recovery via timelock.
//!
//! Route: Taker -> Maker1 (Normal) -> Maker2 (CloseAtContractSigsForRecvr) -> Taker
//!
//! Scenario:
//! 1. Taker initiates a Legacy openswap with 2 makers.
//! 2. Funding transactions are broadcast and confirmed.
//! 3. Maker2 drops the connection at ReqContractSigsForRecvr.
//! 4. Taker detects the failure and calls `recover_active_swap()`.
//! 5. Everyone falls back to timelock recovery.
//! 6. After blocks mature, verify: taker recovered funds (minus fees), no contract balance.

use openswap::protocol::common_messages::ProtocolVersion;

use super::scenarios::maker_abort::{run_maker_abort_recovery, MakerAbortExpect};

use super::test_framework::*;

/// Test: Maker drops at ReqContractSigsForRecvr after funding. Recovery via timelock.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAtContractSigsForRecvr],
    takers = [Normal],
)]
fn maker_abort3_case2(world: &mut World) {
    run_maker_abort_recovery(
        world,
        ProtocolVersion::Legacy,
        "Swap should fail due to Maker2 closing at ReqContractSigsForRecvr",
        &MakerAbortExpect {
            taker_regular: 14499538,
            taker_swap: 495997,
            taker_loss: 4465,
            maker_regular: [14500865, 14502398],
            maker_swap: [499100, 497530],
            maker_spendable: Some([14999965, 14999928]),
        },
    );
}
