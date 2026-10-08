//! Regression: the route heartbeat must cover finalization for both protocols.
//!
//! The first two makers complete normally. The taker then waits longer than
//! the maker idle timeout before handing the key to the final maker. Without a
//! heartbeat spanning finalization, that maker drains its live state into
//! recovery and rejects the later private-key handover.

use openswap::{protocol::common_messages::ProtocolVersion, taker::SwapParams};

use crate::test_framework::*;

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal, DropHandoverResponse],
    takers = [StallBeforeLastHandover],
    setup = [fund_taker_default(4), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = protocol, sats = 500_000, makers = 3, tx_count = 1),
    cases = [
        taproot_last_maker_survives_finalization_idle_window(protocol = ProtocolVersion::Taproot),
        legacy_last_maker_survives_finalization_idle_window(protocol = ProtocolVersion::Legacy),
    ],
)]
fn run_last_maker_survives_finalization_idle_window(
    world: &mut World,
    protocol: ProtocolVersion,
    params: SwapParams,
) {
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("prepare should succeed");

    world
        .taker_mut()
        .start(&summary.swap_id)
        .expect("the route heartbeat must keep the last maker live through finalization");

    world.mine(1);
    world.sync_makers();

    assert_balances!(world; { makers: { contract: 0 } });

    assert_log!(world; {
        has "Test behavior: stalling",
        has "Test behavior: dropping completed handover response",
        // The last maker did not time out while the taker was still finalizing.
        lacks format!("Swap {} idle", summary.swap_id),
        // Each maker processed exactly one private-key handover.
        count(format!("Processing {protocol:?} private key handover")) == 3,
    });
    if protocol == ProtocolVersion::Taproot {
        // A completed/missing Taproot swap did not fall back to the
        // connection's Legacy default.
        assert_log!(world; {
            lacks "UnexpectedMessage { expected: \"Legacy protocol message\", got: \"Taproot protocol message\" }",
        });
    }
}
