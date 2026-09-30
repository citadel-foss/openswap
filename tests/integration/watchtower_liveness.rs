//! Maker admission must fail closed after its watcher thread exits.

use bitcoin::Amount;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

#[test]
fn maker_rejects_new_swaps_after_watcher_exit() {
    let mut world = World::builder::<BitcoindBackend>()
        .makers(1)
        .maker_behaviors(vec![MakerBehavior::Normal])
        .takers(vec![TakerBehavior::Normal])
        .build();

    world.fund_taker_default(2);
    world.fund_makers(2, Amount::from_btc(0.05).unwrap(), AddressType::P2TR);

    world.start_makers_without_sync(120);

    let maker = world.makers()[0].inner();
    assert!(maker.watch_service.is_alive());
    maker.watch_service.stop_watcher_for_test();
    assert!(!maker.watch_service.is_alive());

    for protocol in [ProtocolVersion::Legacy, ProtocolVersion::Taproot] {
        let result = world.taker_mut().prepare(
            SwapParams::new(protocol, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_required_confirms(1),
        );
        match result {
            Err(TakerError::General(message)) => assert!(
                message.contains("Maker 0 rejected swap"),
                "unexpected admission error: {}",
                message
            ),
            other => panic!("unexpected admission result: {:?}", other),
        }
    }

    world.finish();
}

#[test]
fn taker_refuses_swap_before_funding_after_watcher_exit() {
    let mut world = World::builder::<BitcoindBackend>()
        .makers(1)
        .maker_behaviors(vec![MakerBehavior::Normal])
        .takers(vec![TakerBehavior::Normal])
        .build();

    world.fund_taker_default(2);
    world.fund_makers(2, Amount::from_btc(0.05).unwrap(), AddressType::P2TR);

    world.start_makers_without_sync(120);

    let summary = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_required_confirms(1),
        )
        .unwrap();
    world
        .taker_mut()
        .set_behavior(TakerBehavior::StopWatcherBeforeSwap);
    let error = world.taker_mut().start(&summary.swap_id).unwrap_err();
    assert!(format!("{error:?}").contains("watchtower is down"));
    assert_eq!(
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count(),
        0
    );

    world.finish();
}

#[test]
fn funded_maker_restarts_recovery_only_without_watcher() {
    super::reboot_recovery::run_reboot_recovery_without_watcher::<BitcoindBackend>();
}

#[test]
fn funded_legacy_maker_reaches_timelock_recovery_without_watcher() {
    super::skip_funding_recovery::run_legacy_timelock_recovery_without_watcher();
}
