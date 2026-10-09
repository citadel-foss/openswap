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
use openswap::{taker::Taker, wallet::AddressType};

use crate::test_framework::*;

use log::info;
use std::{thread, time::Duration};

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

    // ---- 5. A corrupted book is reset and rewritten ----
    let book_path = world.temp_dir().join("taker1").join("offerbook.json");
    drop(restarted);
    std::fs::write(&book_path, b"not json").unwrap();
    let after_corruption = Taker::init(world.framework().taker_init_config::<BitcoindBackend>(0))
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

    // The world drops the last taker at teardown, before stopping the framework.
    world.adopt_taker(after_corruption);

    world.shutdown_makers();

    info!("Offerbook restart test completed successfully!");
}
