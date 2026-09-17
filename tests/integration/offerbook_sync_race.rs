//! Stress and race-oriented tests for offerbook sync behavior (taker path).

use bitcoin::Amount;
use log::warn;
use openswap::{
    maker::{start_server, MakerBehavior},
    taker::{MakerProtocol, MakerState, TakerBehavior},
    wallet::AddressType,
};
use std::{
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
};

use super::test_framework::*;

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

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(expected_makers, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = &mut takers[0];

    // Fund all makers
    fund_makers(
        &makers,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Spawn makers in stages: 2, 1, 3, 5
    let stage_plan = [2usize, 1usize, 3usize, 5usize];
    let mut maker_threads = Vec::new();
    let mut spawned = 0usize;
    let syncs_per_stage = 5usize;

    for stage_size in stage_plan {
        let stage_end = spawned + stage_size;
        log::info!(
            "Starting maker stage: launching makers {}..{}",
            spawned,
            stage_end
        );
        for maker in &makers[spawned..stage_end] {
            let maker_clone = Arc::clone(maker);
            maker_threads.push(thread::spawn(move || {
                start_server(maker_clone).unwrap();
            }));
        }

        wait_for_makers_setup(&makers[..stage_end], STAGED_MAKER_SETUP_TIMEOUT_SECS);

        for _ in 0..syncs_per_stage {
            taker
                .sync_offerbook_and_wait()
                .expect("manual sync call should complete");
        }

        spawned = stage_end;
    }

    let good = good_maker_count(taker);
    assert_eq!(
        good, expected_makers,
        "expected {expected_makers} good makers after staged syncs, got {good}"
    );

    // Shutdown
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads.into_iter().for_each(|t| t.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
