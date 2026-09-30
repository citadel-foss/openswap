//! Regression: the route heartbeat must cover finalization for both protocols.
//!
//! The first two makers complete normally. The taker then waits longer than
//! the maker idle timeout before handing the key to the final maker. Without a
//! heartbeat spanning finalization, that maker drains its live state into
//! recovery and rejects the later private-key handover.

use bitcoin::Amount;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use super::test_framework::*;

#[test]
fn taproot_last_maker_survives_finalization_idle_window() {
    let maker_count = 3;
    let taker_behaviors = vec![TakerBehavior::StallBeforeLastHandover];
    let maker_behaviors = vec![
        MakerBehavior::Normal,
        MakerBehavior::Normal,
        MakerBehavior::DropHandoverResponse,
    ];

    let mut world = World::builder::<BitcoindBackend>()
        .makers(maker_count)
        .maker_behaviors(maker_behaviors)
        .takers(taker_behaviors)
        .build();

    world.fund_taker_default(4);
    world.fund_makers_default();

    world.start_makers(120);
    world.mine(1);

    let params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 3)
        .with_tx_count(1)
        .with_required_confirms(1);
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
    assert!(
        !log.contains(
            "UnexpectedMessage { expected: \"Legacy protocol message\", got: \"Taproot protocol message\" }"
        ),
        "a completed/missing Taproot swap fell back to the connection's Legacy default"
    );
    assert_eq!(
        log.matches("Processing Taproot private key handover")
            .count(),
        3,
        "each maker should process exactly one private-key handover"
    );

    world.shutdown_makers();
    world.finish();
}

#[test]
fn legacy_last_maker_survives_finalization_idle_window() {
    let maker_count = 3;
    let taker_behaviors = vec![TakerBehavior::StallBeforeLastHandover];
    let maker_behaviors = vec![
        MakerBehavior::Normal,
        MakerBehavior::Normal,
        MakerBehavior::DropHandoverResponse,
    ];

    let mut world = World::builder::<BitcoindBackend>()
        .makers(maker_count)
        .maker_behaviors(maker_behaviors)
        .takers(taker_behaviors)
        .build();

    world.fund_taker_default(4);
    world.fund_makers_default();

    world.start_makers(120);
    world.mine(1);

    let params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 3)
        .with_tx_count(1)
        .with_required_confirms(1);
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("prepare should succeed");

    world
        .taker_mut()
        .start(&summary.swap_id)
        .expect("the route heartbeat must keep the last Legacy maker live through finalization");

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
        "the last Legacy maker timed out while the taker was still finalizing"
    );
    assert_eq!(
        log.matches("Processing Legacy private key handover")
            .count(),
        3,
        "each Legacy maker should process exactly one private-key handover"
    );

    world.shutdown_makers();
    world.finish();
}
