//! Successful swaps are terminal across maker restarts.
//!
//! A completed maker has already swept every incoming contract and handed its
//! outgoing keys to the taker. Persisting those outgoing swapcoins makes the
//! next startup misclassify the successful swap as abandoned and launch
//! recovery. Exercise the complete protocol, restart both makers from the same
//! wallets, and prove that neither protocol leaves recovery material behind.

use bitcoin::Amount;
use openswap::{
    maker::{MakerBehavior, MakerServer},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use super::test_framework::*;

use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn run_successful_swap_restart(protocol: ProtocolVersion) {
    let mut world = World::builder::<BitcoindBackend>()
        .makers(2)
        .maker_behaviors(vec![MakerBehavior::Normal, MakerBehavior::Normal])
        .takers(vec![TakerBehavior::Normal])
        .build();

    world.fund_nth_taker_default(0, 3);
    world.fund_makers_default();

    world.start_makers(120);

    world.mine(1);
    let summary = world.takers_mut()[0]
        .prepare(
            SwapParams::new(protocol, Amount::from_sat(500_000), 2)
                .with_tx_count(2)
                .with_required_confirms(1),
        )
        .expect("prepare successful swap");
    world.takers_mut()[0]
        .start(&summary.swap_id)
        .expect("swap must complete successfully");

    // The taker can return just before the maker handler finishes its durable
    // cleanup. Wait for that cleanup, not for an arbitrary sleep.
    let deadline = Instant::now() + Duration::from_secs(120);
    while world.makers().iter().any(|maker| {
        let wallet = maker.inner().wallet.read().unwrap();
        wallet.get_incoming_swapcoins_count() != 0 || wallet.get_outgoing_swapcoins_count() != 0
    }) {
        assert!(
            Instant::now() < deadline,
            "successful {:?} swap left maker swapcoins on disk",
            protocol
        );
        thread::sleep(Duration::from_millis(250));
    }

    let configs = world
        .makers()
        .iter()
        .map(|maker| {
            let mut config = maker.inner().config.clone();
            // Initialization consumes the configured passphrase.
            config.password = Some("integration-test".to_string());
            config
        })
        .collect::<Vec<_>>();
    world.drop_takers();
    world.shutdown_makers();
    world.drop_makers();

    world.adopt_makers(
        configs
            .into_iter()
            .map(|config| Arc::new(MakerServer::init(config).unwrap())),
    );
    world.start_makers_without_sync(120);

    for maker in world.makers() {
        let wallet = maker.inner().wallet.read().unwrap();
        assert_eq!(
            wallet.get_incoming_swapcoins_count(),
            0,
            "restarted maker retained incoming swapcoins for a successful {protocol:?} swap"
        );
        assert_eq!(
            wallet.get_outgoing_swapcoins_count(),
            0,
            "restarted maker retained outgoing swapcoins for a successful {protocol:?} swap"
        );
    }

    world.shutdown_makers();
    world.finish();
}

fn run_interrupted_restart(
    protocol: ProtocolVersion,
    behavior: MakerBehavior,
    incoming_remains: bool,
) {
    let mut world = World::builder::<BitcoindBackend>()
        .makers(2)
        .maker_behaviors(vec![behavior, behavior])
        .takers(vec![TakerBehavior::Normal])
        .build();

    world.fund_nth_taker_default(0, 3);
    world.fund_makers_default();

    world.start_makers(120);

    world.mine(1);
    let summary = world.takers_mut()[0]
        .prepare(
            SwapParams::new(protocol, Amount::from_sat(500_000), 2)
                .with_tx_count(2)
                .with_required_confirms(1),
        )
        .expect("prepare interrupted swap");
    world.takers_mut()[0]
        .start(&summary.swap_id)
        .expect("handover must complete before maker interruption");

    let deadline = Instant::now() + Duration::from_secs(120);
    while world.makers().iter().any(|maker| {
        let wallet = maker.inner().wallet.read().unwrap();
        wallet.get_outgoing_swapcoins_count() == 0
            || incoming_remains != (wallet.get_incoming_swapcoins_count() != 0)
    }) {
        assert!(
            Instant::now() < deadline,
            "test hook did not leave the expected persisted swapcoins"
        );
        thread::sleep(Duration::from_millis(250));
    }

    let configs = world
        .makers()
        .iter()
        .map(|maker| {
            let mut config = maker.inner().config.clone();
            config.password = Some("integration-test".to_string());
            config
        })
        .collect::<Vec<_>>();
    world.drop_takers();
    world.shutdown_makers();
    world.drop_makers();

    world.adopt_makers(
        configs
            .into_iter()
            .map(|config| Arc::new(MakerServer::init(config).unwrap())),
    );
    world.start_makers_without_sync(120);

    let deadline = Instant::now() + Duration::from_secs(120);
    while world.makers().iter().any(|maker| {
        let wallet = maker.inner().wallet.read().unwrap();
        wallet.get_incoming_swapcoins_count() != 0 || wallet.get_outgoing_swapcoins_count() != 0
    }) {
        assert!(
            Instant::now() < deadline,
            "restart did not finish the interrupted successful swap"
        );
        thread::sleep(Duration::from_millis(250));
    }

    world.shutdown_makers();
    world.finish();
}

#[test]
fn successful_legacy_swap_stays_complete_after_maker_restart() {
    run_successful_swap_restart(ProtocolVersion::Legacy);
}

#[test]
fn successful_taproot_swap_stays_complete_after_maker_restart() {
    run_successful_swap_restart(ProtocolVersion::Taproot);
}

#[test]
fn restart_sweeps_handed_over_incoming_swapcoins() {
    run_interrupted_restart(
        ProtocolVersion::Taproot,
        MakerBehavior::CloseAfterHandoverResponse,
        true,
    );
}

#[test]
fn restart_removes_spent_outgoing_swapcoins() {
    for protocol in [ProtocolVersion::Legacy, ProtocolVersion::Taproot] {
        run_interrupted_restart(protocol, MakerBehavior::CloseBeforeSwapFinalization, false);
    }
}
