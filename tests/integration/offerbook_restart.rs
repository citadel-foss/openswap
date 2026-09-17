//! Offerbook reload and manual removal survive a taker restart.
//!
//! The disk read path (`taker/offers.rs:362`) runs at every ordinary restart,
//! and no other test touches it: a broken read path silently reselects makers
//! the user removed, and the parse-failure fallback (`taker/offers.rs:371`)
//! rewrites a corrupted book over the old file.
//!
//! Scenario:
//! 1. Two makers announce; the taker syncs and holds both in its offerbook.
//! 2. The relay goes down; the taker removes maker 0 and is dropped,
//!    persisting the book. (With the relay up, the periodic sync re-upserts
//!    the removed maker before the drop.)
//! 3. A fresh `Taker` opens the same data dir with the relay still down, so
//!    the startup sync cannot re-upsert the removed maker before the check.
//! 4. The removal must hold; a direct poll then rediscovers maker 0 without
//!    the relay. A corrupted offerbook.json must be reset and rewritten.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    taker::{Taker, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{sync::atomic::Ordering::Relaxed, thread, time::Duration};

/// Maker addresses currently in the taker's offerbook, as strings.
fn listed_addresses(taker: &Taker) -> Vec<String> {
    taker
        .fetch_offers()
        .expect("offerbook snapshot")
        .all_makers()
        .iter()
        .map(|m| m.address.to_string())
        .collect()
}

#[test]
fn test_offerbook_removal_survives_restart() {
    warn!("Running Test: Offerbook Removal Survives Restart");

    let maker_count = 2;
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(maker_count, taker_behavior, maker_behaviors);

    fund_makers(
        &makers,
        &test_framework.bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    info!("Starting Maker servers...");
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);

    let maker_addrs: Vec<String> = makers
        .iter()
        .map(|m| format!("127.0.0.1:{}", m.config.network_port))
        .collect();

    // ---- 1. Discover both makers into the offerbook ----
    let taker = takers.remove(0);
    taker
        .sync_offerbook_and_wait()
        .expect("initial offerbook sync");
    let listed = listed_addresses(&taker);
    assert!(
        maker_addrs.iter().all(|a| listed.contains(a)),
        "both makers must be discovered, got {:?}",
        listed
    );

    // ---- 2. Kill the relay, remove maker 0, persist by dropping the taker ----
    // The relay goes first: with it up, the periodic sync re-upserts a removed
    // maker within milliseconds and the drop would persist the wrong book.
    test_framework.kill_relay();
    assert!(
        taker.remove_maker(maker_addrs[0].clone()).unwrap(),
        "remove_maker must find the entry"
    );
    drop(taker);

    // ---- 3. Restart with the relay still down ----
    let restarted = Taker::init(test_framework.taker_init_config::<BitcoindBackend>(0))
        .expect("restarted taker should open the same data dir");
    // Give the startup sync time to fail against the dead relay, so a pass
    // here cannot be credited to a sync that merely had not run yet.
    thread::sleep(Duration::from_secs(5));

    // ---- 4a. The removal holds across the restart ----
    let listed = listed_addresses(&restarted);
    assert!(
        listed.contains(&maker_addrs[1]),
        "surviving maker must reload from disk, got {:?}",
        listed
    );
    assert!(
        !listed.contains(&maker_addrs[0]),
        "manual removal must survive the restart, got {:?}",
        listed
    );

    // ---- 4b. A direct poll rediscovers the removed maker without a relay ----
    restarted
        .poll_maker(maker_addrs[0].clone())
        .expect("poll must reach the maker directly");
    let listed = listed_addresses(&restarted);
    assert!(
        listed.contains(&maker_addrs[0]),
        "removed maker must be rediscoverable by poll, got {:?}",
        listed
    );

    // ---- 5. A corrupted book is reset and rewritten ----
    let book_path = test_framework
        .temp_dir
        .join("taker1")
        .join("offerbook.json");
    drop(restarted);
    std::fs::write(&book_path, b"not json").unwrap();
    let after_corruption = Taker::init(test_framework.taker_init_config::<BitcoindBackend>(0))
        .expect("taker should start over a corrupted offerbook");
    let listed = listed_addresses(&after_corruption);
    assert!(
        listed.is_empty(),
        "corrupted book must reset to empty, got {:?}",
        listed
    );
    let raw = std::fs::read_to_string(&book_path).unwrap();
    assert!(
        raw.trim_start().starts_with('{'),
        "the fallback must rewrite the corrupted file, got: {}",
        raw
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    info!("Offerbook restart test completed successfully!");

    test_framework.stop();
    block_generation_handle.join().unwrap();
}
