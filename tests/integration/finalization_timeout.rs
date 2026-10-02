//! Regression: the route heartbeat must cover finalization for both protocols.
//!
//! The first two makers complete normally. The taker then waits longer than
//! the maker idle timeout before handing the key to the final maker. Without a
//! heartbeat spanning finalization, that maker drains its live state into
//! recovery and rejects the later private-key handover.

use bitcoin::Amount;
use openswap::{protocol::common_messages::ProtocolVersion, taker::SwapParams};

use super::test_framework::*;

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

    for (index, maker) in world.makers().iter().enumerate() {
        let balances = maker.balances();
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "maker {index} retained contract balance after finalization"
        );
    }

    let log = std::fs::read_to_string(world.taker_log_path()).unwrap();
    assert!(log.contains("Test behavior: stalling"));
    assert!(log.contains("Test behavior: dropping completed handover response"));
    assert!(
        !log.contains(&format!("Swap {} idle", summary.swap_id)),
        "the last maker timed out while the taker was still finalizing"
    );
    if protocol == ProtocolVersion::Taproot {
        assert!(
            !log.contains(
                "UnexpectedMessage { expected: \"Legacy protocol message\", got: \"Taproot protocol message\" }"
            ),
            "a completed/missing Taproot swap fell back to the connection's Legacy default"
        );
    }
    assert_eq!(
        log.matches(&format!("Processing {protocol:?} private key handover"))
            .count(),
        3,
        "each maker should process exactly one private-key handover"
    );
}
