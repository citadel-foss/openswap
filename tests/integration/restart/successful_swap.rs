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
    taker::SwapParams,
};

use crate::test_framework::*;

use std::{sync::Arc, time::Duration};

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    cases = [
        successful_legacy_swap_stays_complete_after_maker_restart(protocol = ProtocolVersion::Legacy),
        successful_taproot_swap_stays_complete_after_maker_restart(protocol = ProtocolVersion::Taproot),
    ],
)]
fn run_successful_swap_restart(world: &mut World, protocol: ProtocolVersion) {
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
    wait_until!(
        Duration::from_secs(120),
        format!(
            "the successful {:?} swap to clear the maker swapcoins on disk",
            protocol
        ),
        world.makers().iter().all(|maker| {
            let wallet = maker.inner().wallet.read().unwrap();
            wallet.get_incoming_swapcoins_count() == 0 && wallet.get_outgoing_swapcoins_count() == 0
        })
    );

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
}

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [behavior, behavior],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = protocol, sats = 500_000, makers = 2),
    cases = [
        restart_sweeps_handed_over_incoming_swapcoins(
            protocol = ProtocolVersion::Taproot,
            behavior = MakerBehavior::CloseAfterHandoverResponse,
            incoming_remains = true,
        ),
        restart_removes_spent_outgoing_swapcoins_legacy(
            protocol = ProtocolVersion::Legacy,
            behavior = MakerBehavior::CloseBeforeSwapFinalization,
            incoming_remains = false,
        ),
        restart_removes_spent_outgoing_swapcoins_taproot(
            protocol = ProtocolVersion::Taproot,
            behavior = MakerBehavior::CloseBeforeSwapFinalization,
            incoming_remains = false,
        ),
    ],
)]
fn run_interrupted_restart(world: &mut World, incoming_remains: bool, params: SwapParams) {
    let summary = world.takers_mut()[0]
        .prepare(params)
        .expect("prepare interrupted swap");
    world.takers_mut()[0]
        .start(&summary.swap_id)
        .expect("handover must complete before maker interruption");

    wait_until!(
        Duration::from_secs(120),
        "the test hook to leave the expected persisted swapcoins",
        !world.makers().iter().any(|maker| {
            let wallet = maker.inner().wallet.read().unwrap();
            wallet.get_outgoing_swapcoins_count() == 0
                || incoming_remains != (wallet.get_incoming_swapcoins_count() != 0)
        })
    );

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

    wait_until!(
        Duration::from_secs(120),
        "the restart to finish the interrupted successful swap",
        world.makers().iter().all(|maker| {
            let wallet = maker.inner().wallet.read().unwrap();
            wallet.get_incoming_swapcoins_count() == 0 && wallet.get_outgoing_swapcoins_count() == 0
        })
    );
}
