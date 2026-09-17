//! Integration tests for automatic fidelity bond renewal using the API.
//!
//! These tests verify that the Maker server automatically renews fidelity bonds
//! when they expire while the server is running.

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{maker::start_server, taker::TakerBehavior, wallet::AddressType};

use super::test_framework::*;

use std::{sync::atomic::Ordering::Relaxed, thread, time::Duration};

/// Test automatic fidelity bond renewal for the maker server.
#[test]
fn test_fidelity_auto_renewal() {
    // ---- Setup ----
    let maker_count = 1;
    let taker_behavior = vec![TakerBehavior::Normal];

    let (test_framework, _takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(maker_count, taker_behavior, vec![]);

    log::info!("Running Test: Fidelity Bond Auto-Renewal ");

    let bitcoind = &test_framework.bitcoind;
    let maker = makers.first().unwrap();

    // Fund the Maker
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.20).unwrap(),
        AddressType::P2TR,
    );

    // Start the Maker server
    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || start_server(maker_clone));

    // Wait for setup to complete
    wait_for_makers_setup(std::slice::from_ref(maker), 120);

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

    let mut renewal_detected = false;
    for i in 0..18 {
        thread::sleep(Duration::from_secs(5));

        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let wallet_read = maker.wallet.read().unwrap();

        // Check if original bond was redeemed (marked as spent)
        let original_bond = wallet_read
            .get_fidelity_bonds()
            .get(initial_bond_index as usize)
            .unwrap();
        let original_spent = original_bond.is_spent();

        // Check if there's a new highest bond with different index
        let highest_index = wallet_read.get_highest_fidelity_index().unwrap();
        let new_bond_created = highest_index
            .map(|idx| idx == initial_bond_index + 1)
            .unwrap_or(false);

        if original_spent && new_bond_created {
            log::info!(
                "Fidelity bond renewal detected at iteration {}! Original spent: {}, New bond index: {:?}",
                i,
                original_spent,
                highest_index
            );
            renewal_detected = true;
            break;
        }

        log::info!("Check {}/18 - Bond not yet renewed", i + 1);
    }

    assert!(
        renewal_detected,
        "Fidelity bond should have been automatically renewed"
    );

    let log_file = test_framework.temp_dir.join("taker/debug.log");
    let log_path = log_file.to_str().unwrap();
    test_framework.assert_log(
        "Fidelity Bond at index: 0 expired | Redeeming it.",
        log_path,
    );
    test_framework.assert_log("Successfully created fidelity bond", log_path);

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

    let mut rebroadcast_detected = false;
    for i in 0..18 {
        thread::sleep(Duration::from_secs(5));
        let log_contents = std::fs::read_to_string(log_path).unwrap();
        if log_contents.contains(&expected_broadcast_log) {
            log::info!("Nostr re-broadcast of renewed bond detected at check {}", i);
            rebroadcast_detected = true;
            break;
        }
    }
    assert!(
        rebroadcast_detected,
        "Nostr thread kept broadcasting a stale fidelity bond — renewed bond {} was never announced (issue #702 regression)",
        new_bond_outpoint
    );

    // Shutdown
    maker.shutdown.store(true, Relaxed);
    let _ = maker_thread.join();
    test_framework.stop();
    block_generation_handle.join().unwrap();

    log::info!("Fidelity bond auto-renewal test  completed successfully");
}
