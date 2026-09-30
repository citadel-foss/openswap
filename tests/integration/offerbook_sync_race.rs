//! Stress and race-oriented tests for offerbook sync behavior (taker path).

use super::test_framework::*;
use bitcoin::Amount;
use log::warn;
use openswap::{
    maker::MakerBehavior,
    taker::{MakerProtocol, MakerState, TakerBehavior},
    wallet::AddressType,
};

const STAGED_MAKER_SETUP_TIMEOUT_SECS: u64 = 180;

fn good_maker_count(taker: &openswap::taker::Taker) -> usize {
    taker
        .fetch_offers()
        .unwrap()
        .all_makers()
        .into_iter()
        .filter(|m| m.state == MakerState::Good)
        .filter(|m| {
            m.protocol
                .as_ref()
                .map(|p| p.supports(&MakerProtocol::Legacy))
                .unwrap_or(false)
        })
        .count()
}

#[test]
fn test_repeated_manual_sync_is_bounded() {
    warn!("Running Test: Staged maker discovery across repeated syncs ");

    let expected_makers = 11usize;
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors: Vec<MakerBehavior> = (0..expected_makers)
        .map(|_| MakerBehavior::Normal)
        .collect();

    let mut world = World::builder::<BitcoindBackend>()
        .makers(expected_makers)
        .maker_behaviors(maker_behaviors)
        .takers(taker_behavior)
        .build();

    // Fund all makers
    world.fund_makers(3, Amount::from_btc(0.05).unwrap(), AddressType::P2TR);

    // Spawn makers in stages: 2, 1, 3, 5
    let stage_plan = [2usize, 1usize, 3usize, 5usize];
    let mut spawned = 0usize;
    let syncs_per_stage = 5usize;

    for stage_size in stage_plan {
        let stage_end = spawned + stage_size;
        log::info!(
            "Starting maker stage: launching makers {}..{}",
            spawned,
            stage_end
        );
        for index in spawned..stage_end {
            world.spawn_maker(index);
        }

        world.wait_for_first_makers_setup(stage_end, STAGED_MAKER_SETUP_TIMEOUT_SECS);

        for _ in 0..syncs_per_stage {
            world
                .taker()
                .inner()
                .sync_offerbook_and_wait()
                .expect("manual sync call should complete");
        }

        spawned = stage_end;
    }

    let good = good_maker_count(world.taker().inner());
    assert_eq!(
        good, expected_makers,
        "expected {expected_makers} good makers after staged syncs, got {good}"
    );

    // Shutdown
    world.shutdown_makers();
    world.finish();
}
