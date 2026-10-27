//! Offerbook reload and manual removal survive a taker restart.
//!
//! The disk read path (`taker/offers.rs:362`) runs at every ordinary restart,
//! and no other test touches it: a broken read path silently reselects makers
//! the user removed, and an unreadable book must stop the taker rather than
//! start empty and forgive every ban.
//!
//! Scenario:
//! 1. Two makers announce; the taker syncs and holds both in its offerbook.
//! 2. The relay goes down; the taker removes maker 0 and is dropped,
//!    persisting the book. (With the relay up, the periodic sync re-upserts
//!    the removed maker before the drop.)
//! 3. A fresh `Taker` opens the same data dir with the relay still down, so
//!    the startup sync cannot re-upsert the removed maker before the check.
//! 4. The removal must hold; a direct poll then rediscovers maker 0 without
//!    the relay. A corrupted offerbook.json must stop the taker untouched.

use bitcoin::Amount;
use openswap::{
    taker::{MakerState, Taker},
    wallet::AddressType,
};

use crate::test_framework::*;

use log::info;
use std::{
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    setup = [
        fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2TR),
        start_makers_without_sync(120),
    ],
)]
fn long_idle_restart_refreshes_cached_and_missing_offers(world: &mut World) {
    let taker = world.take_taker();
    taker.inner().sync_offerbook_and_wait().unwrap();
    let cached_address = world.makers()[0].address();
    let missing_address = world.makers()[1].address();
    let listed = listed_addresses(taker.inner());
    assert!(listed.contains(&cached_address));
    assert!(listed.contains(&missing_address));
    drop(taker);

    // Model a taker that has not run for longer than the stale-maker age.
    let book_path = world.temp_dir().join("taker1").join("offerbook.json");
    let mut book: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&book_path).unwrap()).unwrap();
    let stale_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 3 * 24 * 60 * 60;
    let makers = book["makers"].as_array_mut().unwrap();
    makers.retain(|maker| maker["address"] == cached_address);
    assert_eq!(makers.len(), 1);
    makers[0]["last_offer_update_ts"] = stale_ts.into();
    makers[0]["first_seen_ts"] = stale_ts.into();
    std::fs::write(&book_path, serde_json::to_vec_pretty(&book).unwrap()).unwrap();

    let restarted = Taker::init(world.framework().taker_init_config::<BitcoindBackend>(0))
        .expect("restart after a long idle period");
    restarted.sync_offerbook_and_wait().unwrap();
    assert!(
        restarted.initial_market_sync_complete(),
        "discovery and the initial offer refresh must complete after restart"
    );
    let refreshed_book = restarted.fetch_offers().unwrap();
    let refreshed_makers = refreshed_book.all_makers();
    let refreshed = refreshed_makers
        .iter()
        .find(|maker| maker.address.to_string() == cached_address)
        .expect("cached live maker must remain visible after a long idle period");
    assert_eq!(refreshed.state, MakerState::Good);
    assert!(refreshed.last_offer_update_ts.unwrap() > stale_ts);
    assert!(
        refreshed_makers
            .iter()
            .any(|maker| maker.address.to_string() == missing_address
                && maker.state == MakerState::Good),
        "a live maker absent from the saved offerbook must be discovered"
    );

    drop(restarted);
    world.shutdown_makers();
}

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

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    setup = [
        fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2TR),
        start_makers_without_sync(120),
    ],
)]
fn removal_survives_restart(world: &mut World) {
    let maker_addrs: Vec<String> = world.makers().iter().map(|m| m.address()).collect();

    // ---- 1. Discover both makers into the offerbook ----
    // The taker is dropped and reopened below, so it leaves the world here.
    let taker = world.take_taker();
    taker
        .inner()
        .sync_offerbook_and_wait()
        .expect("initial offerbook sync");
    let listed = listed_addresses(taker.inner());
    assert!(
        maker_addrs.iter().all(|a| listed.contains(a)),
        "both makers must be discovered, got {:?}",
        listed
    );

    // ---- 2. Kill the relay, remove maker 0, persist by dropping the taker ----
    // The relay goes first: with it up, the periodic sync re-upserts a removed
    // maker within milliseconds and the drop would persist the wrong book.
    world.framework().kill_relay();
    // The sync service can evict the entry as the relay goes down, in which
    // case remove_maker correctly reports false. What must hold is its absence.
    taker.inner().remove_maker(maker_addrs[0].clone()).unwrap();
    assert!(
        !listed_addresses(taker.inner()).contains(&maker_addrs[0]),
        "maker must be absent before restart"
    );
    drop(taker);

    // ---- 3. Restart with the relay still down ----
    let restarted = Taker::init(world.framework().taker_init_config::<BitcoindBackend>(0))
        .expect("restarted taker should open the same data dir");
    // Give the startup sync time to fail against the dead relay, so a pass
    // here cannot be credited to a sync that merely had not run yet.
    thread::sleep(Duration::from_secs(5));
    restarted.sync_offerbook_and_wait().unwrap();
    assert!(
        !restarted.initial_market_sync_complete(),
        "an unavailable relay must leave initial market sync incomplete"
    );

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
    // The maker's name arrives in its offer and is saved with it.
    let names: Vec<String> = restarted
        .fetch_offers()
        .expect("offerbook snapshot")
        .all_makers()
        .iter()
        .filter_map(|m| m.offer.as_ref().map(|o| o.name.clone()))
        .collect();
    assert_eq!(
        names,
        [format!(
            "maker{}",
            world.makers()[1].inner().config.network_port
        )]
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

    // ---- 5. A corrupted book stops the taker and stays on disk ----
    let book_path = world.temp_dir().join("taker1").join("offerbook.json");
    drop(restarted);
    std::fs::write(&book_path, b"not json").unwrap();
    assert!(
        Taker::init(world.framework().taker_init_config::<BitcoindBackend>(0)).is_err(),
        "a corrupted book must stop the taker, not forgive every ban"
    );
    assert_eq!(std::fs::read(&book_path).unwrap(), b"not json");

    world.shutdown_makers();

    info!("Offerbook restart test completed successfully!");
}
