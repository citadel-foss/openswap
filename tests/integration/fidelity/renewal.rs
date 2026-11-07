//! Integration tests for automatic fidelity bond renewal using the API.
//!
//! These tests verify that the Maker server automatically renews fidelity bonds
//! when they expire while the server is running.

use bitcoin::{absolute::LockTime, Amount};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{maker::start_server, utill::MIN_RELAY_FEE_RATE, wallet::AddressType};

use crate::test_framework::*;

use std::{
    fs,
    sync::atomic::Ordering::Relaxed,
    thread,
    time::{Duration, Instant},
};

/// Test automatic fidelity bond renewal for the maker server.
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
    takers = [Normal],
)]
fn bond_auto_renewal(world: &mut World) {
    let bitcoind = world.bitcoind();
    let maker = world.makers()[0].inner().clone();

    // Fund the Maker
    world.fund_makers(4, Amount::from_btc(0.20).unwrap(), AddressType::P2TR);

    // Start the Maker server. The thread hands back start_server's result
    // unchecked and the join at the end ignores it, so this maker is shut
    // down here rather than by the world.
    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || start_server(maker_clone));

    // Wait for setup to complete
    wait_for_makers_setup(std::slice::from_ref(&maker), 120);

    // Verify initial bond was created and get its locktime
    let (initial_bond_index, bond_locktime) = {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let wallet_read = maker.wallet.read().unwrap();

        let highest_index = wallet_read.get_highest_fidelity_index().unwrap();
        assert!(
            highest_index.is_some(),
            "Initial fidelity bond should be created"
        );

        let idx = highest_index.unwrap();
        let bond = wallet_read.get_fidelity_bonds().get(idx as usize).unwrap();
        let locktime = bond.lock_time.to_consensus_u32();

        log::info!(
            "Initial bond created - Index: {}, Amount: {} sats, Locktime: {} blocks",
            idx,
            bond.amount.to_sat(),
            locktime
        );

        (idx, locktime)
    };

    // Calculate blocks to mine to expire the bond
    let current_height = bitcoind.client.get_block_count().unwrap() as u32;
    let blocks_to_mine = if bond_locktime > current_height {
        (bond_locktime - current_height) + 10
    } else {
        10
    };

    log::info!(
        "Mining blocks to expire bond. Current: {}, Bond locktime: {}, Blocks to mine: {}",
        current_height,
        bond_locktime,
        blocks_to_mine
    );

    // Mine blocks to expire the bond (in batches to avoid RPC timeout)
    let address = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();

    let batch_size = 100u64;
    let mut remaining = blocks_to_mine as u64;
    while remaining > 0 {
        let to_mine = std::cmp::min(remaining, batch_size);
        bitcoind
            .client
            .generate_to_address(to_mine, &address)
            .unwrap();
        remaining -= to_mine;
        if remaining > 0 {
            log::info!("Mined {} blocks, {} remaining...", to_mine, remaining);
        }
    }

    let new_height = bitcoind.client.get_block_count().unwrap();
    log::info!(
        "Mined {} blocks. New height: {}",
        blocks_to_mine,
        new_height
    );

    log::info!("Waiting for automatic fidelity bond renewal (up to 90 seconds)...");

    wait_until!(
        Duration::from_secs(90),
        every Duration::from_secs(5),
        "the maker to renew its expired fidelity bond",
        {
            maker
                .wallet
                .write()
                .unwrap()
                .sync_and_save(&openswap::utill::NO_SHUTDOWN)
                .unwrap();
            let wallet_read = maker.wallet.read().unwrap();

            // The original bond was redeemed (marked as spent) ...
            let original_spent = wallet_read
                .get_fidelity_bonds()
                .get(initial_bond_index as usize)
                .unwrap()
                .is_spent();

            // ... and a new highest bond with a different index exists.
            let new_bond_created = wallet_read
                .get_highest_fidelity_index()
                .unwrap()
                .map(|idx| idx == initial_bond_index + 1)
                .unwrap_or(false);

            original_spent && new_bond_created
        }
    );
    log::info!("Fidelity bond renewal detected");

    let log_file = world.temp_dir().join("taker/debug.log");
    let log_path = log_file.to_str().unwrap();
    assert_log!(log_path; {
        has "Fidelity Bond at index: 0 expired | Redeeming it.",
        has "Successfully created fidelity bond",
    });

    // ---- Regression check for issue #702 (fixed in #769, regressed in #758) ----
    // The nostr broadcast thread must pick up the renewed bond instead of
    // re-announcing the stale one it captured at startup.
    let new_bond_outpoint = {
        let wallet_read = maker.wallet.read().unwrap();
        let idx = wallet_read
            .get_highest_fidelity_index()
            .unwrap()
            .expect("renewed bond must exist");
        wallet_read
            .get_fidelity_bonds()
            .get(idx as usize)
            .unwrap()
            .outpoint()
    };

    let expected_broadcast_log = format!(
        "Publishing fidelity bond to Nostr | outpoint={}",
        new_bond_outpoint
    );
    log::info!(
        "Waiting for nostr re-broadcast of renewed bond {} (up to 90 seconds)...",
        new_bond_outpoint
    );

    // A stale announcement means the nostr thread kept the bond it captured
    // at startup (issue #702 regression).
    wait_until!(
        Duration::from_secs(90),
        every Duration::from_secs(5),
        format!(
            "the nostr re-broadcast of renewed bond {}",
            new_bond_outpoint
        ),
        std::fs::read_to_string(log_path)
            .unwrap()
            .contains(&expected_broadcast_log)
    );
    log::info!("Nostr re-broadcast of renewed bond detected");

    // Shutdown
    maker.shutdown.store(true, Relaxed);
    let _ = maker_thread.join();
}

/// A bond that confirmed too late is never advertised, and with no other
/// coins startup then waits for swap liquidity before the renewal loop runs.
/// Once the bond's lock ends, that wait must redeem it, so its coins come back
/// and setup completes without an outside deposit.
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
)]
fn late_bond_is_redeemed_during_the_liquidity_wait(world: &mut World) {
    let bitcoind = world.bitcoind();
    let maker = world.makers()[0].inner().clone();

    // Almost every sat goes into the bond, leaving less than the minimum swap
    // amount spendable.
    world.fund_makers(1, Amount::from_sat(100_000), AddressType::P2TR);
    world.framework().set_block_gen_paused(true);
    // Far below the minimum timelock, so takers reject it once it confirms.
    let lock_blocks = 50u32;
    let lock_height = bitcoind.client.get_block_count().unwrap() as u32 + lock_blocks;
    let (bond_index, _) = maker
        .wallet
        .write()
        .unwrap()
        .create_fidelity(
            Amount::from_sat(99_000),
            LockTime::from_height(lock_height).unwrap(),
            None,
            MIN_RELAY_FEE_RATE,
            AddressType::P2TR,
        )
        .unwrap();
    world.mine(1);

    let log_path = world.taker_log_path();
    let mark = log_mark(&log_path);
    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || {
        let _ = start_server(maker_clone);
    });

    // Read before stopping, assert after: a failed assert must not leave the
    // maker running.
    let in_new_log = |needle: &str| {
        fs::read_to_string(&log_path)
            .unwrap_or_default()
            .get(mark as usize..)
            .is_some_and(|new| new.contains(needle))
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    while !in_new_log("Low Swap Liquidity") && Instant::now() < deadline {
        thread::sleep(POLL);
    }
    let waiting_for_liquidity =
        in_new_log("Low Swap Liquidity") && !maker.is_setup_complete.load(Relaxed);

    // End the bond's lock, then let the redemption confirm.
    world.mine(u64::from(lock_blocks) + 1);
    world.framework().set_block_gen_paused(false);
    let deadline = Instant::now() + Duration::from_secs(120);
    while !maker.is_setup_complete.load(Relaxed) && Instant::now() < deadline {
        thread::sleep(POLL);
    }
    let setup_complete = maker.is_setup_complete.load(Relaxed);
    let bond_spent =
        maker.wallet.read().unwrap().get_fidelity_bonds()[bond_index as usize].is_spent();
    maker.shutdown.store(true, Relaxed);
    let _ = maker_thread.join();

    assert!(
        waiting_for_liquidity,
        "startup must skip the late bond and wait for swap liquidity"
    );
    assert!(
        bond_spent,
        "the liquidity wait must redeem the bond once its lock ends"
    );
    assert!(
        setup_complete,
        "setup must complete once the redeemed bond's coins come back"
    );
    assert_log!(log_path, since mark; {
        has format!("Fidelity bond {bond_index} confirmed at height"),
        has format!("Fidelity Bond at index: {bond_index} expired | Redeeming it."),
    });
}
