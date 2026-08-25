//! Integration test for Fidelity Bond Creation and Redemption using the API.
//!
//! This test covers the full lifecycle of Fidelity Bonds, including creation, valuation, and redemption:
//!
//! - The Maker starts with insufficient funds to create a fidelity bond (0.04 BTC),
//!   triggering log messages requesting more funds.
//! - Once provided with sufficient funds (1 BTC), the Maker creates the first fidelity bond (0.05 BTC).
//! - A second fidelity bond (0.08 BTC) is created and its higher value is verified.
//! - The test simulates bond maturity by advancing the blockchain height and redeems them sequentially,
//!   verifying correct balances and proper bond status updates after redemption.
//! - A second sub-test verifies that expired fidelity bond UTXOs are properly isolated from
//!   regular transactions: regular sends never select expired fidelity UTXOs, but redemption
//!   and new bond creation can properly consume them.

use bitcoin::{absolute::LockTime, Amount, Txid};
use bitcoind::bitcoincore_rpc::{Auth, RpcApi};
use openswap::{
    maker::{start_server, MakerServer, MakerServerConfig},
    taker::TakerBehavior,
    utill::MIN_FEE_RATE,
    wallet::{AddressType, Blockchain, CoreRPC, CoreRpcConfig, Destination, ElectrumConfig},
};

use super::test_framework::*;

use log::info;
use std::{
    path::PathBuf,
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::Duration,
};
/// Pins the two backend answers the maker's funding check rests on: `None` sees a
/// mempool-only spend, while `Some(false)` — the argument it used to pass — reports
/// that output live on Core. Pins the backend, not the maker's call site.
#[test]
fn test_mempool_only_spend_reads_as_spent() {
    // Its own bitcoind: nothing mines in the background, so the spend cannot
    // confirm while the assertions run.
    let temp_dir =
        std::env::temp_dir().join(format!("openswap-mempool-spend-{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    // Ask the OS for the zmq port rather than guessing one in a range.
    let zmq_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bitcoind = init_bitcoind(&temp_dir, format!("tcp://127.0.0.1:{}", zmq_port));

    let rpc_config = CoreRpcConfig {
        url: bitcoind.rpc_url().split_at(7).1.to_string(),
        auth: Auth::CookieFile(bitcoind.params.cookie_file.clone()),
        ..Default::default()
    };
    let backend = CoreRPC::new(&rpc_config).expect("connect Core backend");

    let address = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let spend_txid = send_to_address(&bitcoind, &address, Amount::ONE_BTC);
    let spend = bitcoind
        .client
        .get_raw_transaction(&spend_txid, None)
        .unwrap();
    let funding = spend.input[0].previous_output;

    assert!(
        bitcoind.client.get_mempool_entry(&spend_txid).is_ok(),
        "spend {} must still be unconfirmed for this case to mean anything",
        spend_txid
    );
    assert!(
        backend
            .get_tx_out(&funding.txid, funding.vout, Some(false))
            .unwrap()
            .is_some(),
        "Some(false) hides a mempool spend on Core - that is the hole being closed"
    );
    assert!(
        backend
            .get_tx_out(&funding.txid, funding.vout, None)
            .unwrap()
            .is_none(),
        "the maker's None query must see the mempool spend and reject the funding"
    );

    info!("Mempool-only spend reads as spent on the Core backend");
    drop(bitcoind);
    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// Test Fidelity Bond Creation and Redemption
#[test]
fn test_fidelity_creation() {
    // ---- Setup ----
    let makers_config_map = vec![(8102, None)];
    let taker_behavior = vec![TakerBehavior::Normal];

    let (test_framework, _takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, vec![]);

    log::info!("Running Test: Fidelity Bond Creation and Redemption ");

    let bitcoind = &test_framework.bitcoind;
    let maker = makers.first().unwrap();

    // ----- Test -----

    log::info!("Providing insufficient funds to trigger funding request");
    // Provide insufficient funds to the Maker and start the server.
    // This will continuously log about insufficient funds and request BTC to create a fidelity bond.
    fund_makers(
        &makers,
        bitcoind,
        1,
        Amount::from_btc(0.04).unwrap(),
        AddressType::P2TR,
    );

    let maker_clone = maker.clone();

    log::info!("Starting maker server with insufficient funds");
    let maker_thread = thread::spawn(move || start_server(maker_clone));

    thread::sleep(Duration::from_secs(6));

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("Send at least 0.01000222 BTC to", &log_path);

    log::info!("Adding sufficient funds for fidelity bond creation");
    // Provide the Maker with more funds.
    fund_makers(&makers, bitcoind, 1, Amount::ONE_BTC, AddressType::P2TR);

    // Wait for the Maker to complete setup (fidelity bond creation + confirmation).
    // The API's wait_for_tx_confirmation has a 10s polling interval, so
    // a fixed sleep(6) is not enough. Use the proper setup-complete flag instead.
    wait_for_makers_setup(std::slice::from_ref(maker), 120);

    // stop the Maker server
    maker.shutdown.store(true, Relaxed);

    let _ = maker_thread.join().unwrap();

    // Assert that successful fidelity bond creation is logged
    test_framework.assert_log("Successfully created fidelity bond", &log_path);

    log::info!("Verifying first fidelity bond creation");
    // Verify that the fidelity bond is created correctly.
    let first_maturity_height = {
        let wallet_read = maker.wallet.read().unwrap();

        // Get the index of the bond with the highest value,
        // which should be 0 as there is only one fidelity bond.
        let highest_bond_index = wallet_read.get_highest_fidelity_index().unwrap().unwrap();
        assert_eq!(highest_bond_index, 0);

        let bond = wallet_read
            .get_fidelity_bonds()
            .get(highest_bond_index as usize)
            .unwrap();
        let (tip_height, tip_time) = wallet_read.chain_tip().unwrap();
        let bond_value = wallet_read
            .calculate_bond_value(bond, tip_height, tip_time)
            .unwrap();
        // Bond value depends on wall-clock time and regtest block timing,
        // so it varies between runs. Just sanity-check it's in a reasonable range.
        assert!(
            bond_value.to_sat() > 9000 && bond_value.to_sat() < 15000,
            "unexpected bond_value: {} SAT (expected ~10000-12000)",
            bond_value.to_sat()
        );

        let bond = wallet_read
            .get_fidelity_bonds()
            .get(highest_bond_index as usize)
            .unwrap();
        assert_eq!(bond.amount, Amount::from_sat(5000000));
        assert!(!bond.is_spent());
        // Log the bond details for debugging
        log::info!(
            "First bond created - Amount: {}, Value: {}, Maturity Height: {}",
            bond.amount.to_sat(),
            bond_value.to_sat(),
            bond.lock_time.to_consensus_u32()
        );

        bond.lock_time.to_consensus_u32()
    };

    log::info!("Creating second fidelity bond with higher amount");
    // Create another fidelity bond of 0.08 BTC and validate it.
    let second_maturity_height = {
        log::info!("Creating another fidelity bond using the `create_fidelity` API");
        let (index, txid) = maker
            .wallet
            .write()
            .unwrap()
            .create_fidelity(
                Amount::from_sat(8000000),
                LockTime::from_height((bitcoind.client.get_block_count().unwrap() as u32) + 950)
                    .unwrap(),
                None,
                MIN_FEE_RATE,
                AddressType::P2TR,
            )
            .unwrap();
        let conf_height = maker
            .wallet
            .read()
            .unwrap()
            .wait_for_tx_confirmation(&[txid], 1, None, None)
            .unwrap();
        maker
            .wallet
            .write()
            .unwrap()
            .update_fidelity_bond_conf_details(index, conf_height)
            .unwrap();

        let wallet_read = maker.wallet.read().unwrap();

        // Since this bond has a larger amount than the first, it should now be the highest value bond.
        let highest_bond_index = wallet_read.get_highest_fidelity_index().unwrap().unwrap();
        assert_eq!(highest_bond_index, index);

        let bond = wallet_read
            .get_fidelity_bonds()
            .get(index as usize)
            .unwrap();
        assert_eq!(bond.amount, Amount::from_sat(8000000));
        assert!(!bond.is_spent());

        bond.lock_time.to_consensus_u32()
    };

    log::info!("Verifying balances with both fidelity bonds");
    // Verify balances
    {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let wallet_read = maker.wallet.read().unwrap();

        let balances = wallet_read.get_balances().unwrap();
        info!("Maker balances after creating fidelity bonds: Regular: {}, Swap: {}, Contract: {}, Spendable: {}, Fidelity: {}",
            balances.regular,
            balances.swap,
            balances.contract,
            balances.spendable,
            balances.fidelity
        );
        assert_eq!(balances.fidelity.to_sat(), 13000000);
        assert_eq!(balances.regular.to_sat(), 90999322);
    }

    log::info!("Waiting for fidelity bonds to mature and testing redemption");
    // Wait for the bonds to mature, redeem them, and validate the process.
    let mut required_height = first_maturity_height;

    loop {
        let current_height = bitcoind.client.get_block_count().unwrap() as u32;

        if current_height < required_height {
            log::info!(
                "Waiting for bond maturity. Current height: {current_height}, required height: {required_height}",
            );
            thread::sleep(Duration::from_secs(10));
        } else {
            let mut wallet_write = maker.wallet.write().unwrap();

            if required_height == first_maturity_height {
                log::info!("First Fidelity Bond is matured. Sending redemption transaction");

                wallet_write
                    .redeem_fidelity(0, MIN_FEE_RATE, AddressType::P2TR)
                    .unwrap();

                log::info!("First Fidelity Bond is successfully redeemed");

                // The second bond should now be the highest value bond.
                let highest_bond_index =
                    wallet_write.get_highest_fidelity_index().unwrap().unwrap();
                assert_eq!(highest_bond_index, 1);

                // Wait for the second bond to mature.
                required_height = second_maturity_height;
            } else {
                log::info!("Second Fidelity Bond is matured. Sending redemption transaction");

                wallet_write
                    .redeem_fidelity(1, MIN_FEE_RATE, AddressType::P2TR)
                    .unwrap();

                log::info!("Second Fidelity Bond is successfully redeemed");

                // There should now be no unspent bonds left.
                let index = wallet_write.get_highest_fidelity_index().unwrap();
                assert_eq!(index, None);
                break;
            }
        }
    }

    thread::sleep(Duration::from_secs(10));

    log::info!("Syncing wallet after redemptions");
    let sync_handle = thread::spawn({
        let maker = maker.clone();
        move || {
            let mut maker_write_wallet = maker.wallet.write().unwrap();
            maker_write_wallet
                .sync_and_save(&openswap::utill::NO_SHUTDOWN)
                .unwrap();
        }
    });

    // Wait for the sync thread to finish.
    sync_handle.join().unwrap();

    log::info!("Verifying final balances after all bonds redeemed");
    // Verify the balances again after all bonds are redeemed.
    {
        let wallet_read = maker.wallet.read().unwrap();
        let balances = wallet_read.get_balances().unwrap();

        assert_eq!(balances.fidelity.to_sat(), 0);
        assert_eq!(balances.regular.to_sat(), 103998826);
    }

    thread::sleep(Duration::from_secs(10));

    test_framework.stop();
    block_generation_handle.join().unwrap();

    log::info!("Fidelity bond lifecycle test completed successfully");
}

/// This test verifies that expired fidelity bond UTXOs are properly isolated from regular transactions:
///
/// - Creates a fidelity bond and lets it expire by advancing blockchain height
/// - Verifies that regular transactions never select expired fidelity bond UTXOs for spending
/// - Confirms that new fidelity bond creation can properly consume expired fidelity bond UTXOs
#[test]
fn test_fidelity_spending() {
    const TIMELOCK_DURATION: u32 = 50;
    const FIDELITY_AMOUNT: u64 = 5_000_000;
    const REGULAR_TX_AMOUNT: u64 = 100_000;

    let makers_config_map = vec![(8102, None)];
    let taker_behavior = vec![TakerBehavior::Normal];

    let (test_framework, _takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, vec![]);

    log::info!("Running Test: Assert Fidelity Spending Behavior ");

    let bitcoind = &test_framework.bitcoind;
    let maker = makers.first().unwrap();

    fund_makers(
        &makers,
        bitcoind,
        1,
        Amount::from_btc(2.0).unwrap(),
        AddressType::P2TR,
    );

    // Create fidelity bond
    let short_timelock_height =
        (bitcoind.client.get_block_count().unwrap() as u32) + TIMELOCK_DURATION;
    let fidelity_amount = Amount::from_sat(FIDELITY_AMOUNT);

    let fidelity_index = {
        let (index, txid) = maker
            .wallet
            .write()
            .unwrap()
            .create_fidelity(
                fidelity_amount,
                LockTime::from_height(short_timelock_height).unwrap(),
                None,
                MIN_FEE_RATE,
                AddressType::P2TR,
            )
            .unwrap();
        let conf_height = maker
            .wallet
            .read()
            .unwrap()
            .wait_for_tx_confirmation(&[txid], 1, None, None)
            .unwrap();
        maker
            .wallet
            .write()
            .unwrap()
            .update_fidelity_bond_conf_details(index, conf_height)
            .unwrap();
        index
    };

    generate_blocks(bitcoind, 1);
    maker
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    // Make fidelity bond expire
    while (bitcoind.client.get_block_count().unwrap() as u32) < short_timelock_height {
        generate_blocks(bitcoind, 10);
    }
    generate_blocks(bitcoind, 5);
    maker
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    // Assert UTXO shows up in list and track the specific fidelity UTXO
    let fidelity_utxo_info = {
        let wallet = maker.wallet.read().unwrap();
        let all_utxos = wallet.list_all_utxo();

        // Find the specific fidelity bond UTXO by amount
        let fidelity_utxo = all_utxos
            .iter()
            .find(|utxo| utxo.amount == fidelity_amount)
            .expect("Fidelity bond UTXO should be in the list");

        log::info!(
            "Found fidelity bond UTXO: txid={}, vout={}, amount={} sats",
            fidelity_utxo.txid,
            fidelity_utxo.vout,
            fidelity_utxo.amount.to_sat()
        );
        log::info!("Total UTXOs in wallet: {}", all_utxos.len());

        (fidelity_utxo.txid, fidelity_utxo.vout, fidelity_utxo.amount)
    };

    let check_fidelity_utxo_integrity = |iteration: usize| {
        let wallet = maker.wallet.read().unwrap();
        let all_utxos = wallet.list_all_utxo();

        let fidelity_utxo_still_exists = all_utxos.iter().any(|utxo| {
            utxo.txid == fidelity_utxo_info.0
                && utxo.vout == fidelity_utxo_info.1
                && utxo.amount == fidelity_utxo_info.2
        });

        if !fidelity_utxo_still_exists {
            panic!(
                "FAILED: Fidelity bond UTXO ({}:{}) was consumed by regular transaction #{}!",
                fidelity_utxo_info.0, fidelity_utxo_info.1, iteration
            );
        }

        let bond = wallet
            .get_fidelity_bonds()
            .get(fidelity_index as usize)
            .unwrap();
        if bond.is_spent() {
            panic!(
                "FAILED: Fidelity bond was marked as consumed by regular transaction #{}!",
                iteration
            );
        }

        log::info!(
            "Fidelity UTXO {}:{} ({} sats) still exists after regular transaction #{}",
            fidelity_utxo_info.0,
            fidelity_utxo_info.1,
            fidelity_utxo_info.2.to_sat(),
            iteration
        );
    };

    // Try 3 regular transactions and verify fidelity bond UTXO is never selected
    log::info!("Testing regular transactions avoid fidelity bond UTXO");

    for i in 0..3 {
        let external_addr = bitcoind
            .client
            .get_new_address(None, None)
            .unwrap()
            .assume_checked();
        let tx_result = {
            let mut wallet = maker.wallet.write().unwrap();
            let selected_utxos = wallet
                .coin_select(
                    Amount::from_sat(REGULAR_TX_AMOUNT),
                    MIN_FEE_RATE,
                    AddressType::P2TR,
                    None,
                    None,
                )
                .unwrap();

            for (_utxo, spend_info) in &selected_utxos {
                if spend_info.to_string().contains("fidelity-bond") {
                    panic!("FAILED: Coin selection returned a fidelity bond UTXO!");
                }
            }

            if selected_utxos.is_empty() {
                Ok(None)
            } else {
                let destination = Destination::Multi {
                    outputs: vec![(external_addr, Amount::from_sat(REGULAR_TX_AMOUNT))],
                    op_return_data: None,
                    change_address_type: AddressType::P2TR,
                };
                match wallet.spend_from_wallet(MIN_FEE_RATE, destination, &selected_utxos) {
                    Ok(tx) => Ok(Some(tx)),
                    Err(e) => Err(e),
                }
            }
        };

        match tx_result {
            Ok(Some(tx)) => {
                bitcoind.client.send_raw_transaction(&tx).unwrap();
                generate_blocks(bitcoind, 1);
                maker
                    .wallet
                    .write()
                    .unwrap()
                    .sync_and_save(&openswap::utill::NO_SHUTDOWN)
                    .unwrap();
                log::info!("Regular transaction #{} completed successfully", i + 1);
            }
            Ok(None) => {
                log::info!("Regular transaction #{} - no UTXOs selected", i + 1);
            }
            Err(e) => {
                log::warn!("Regular transaction #{} failed: {:?}", i + 1, e);
            }
        }

        // Check fidelity UTXO integrity after each transaction attempt
        check_fidelity_utxo_integrity(i + 1);
    }

    // Test fidelity bond redemption - verify UTXO consumption
    log::info!(
        "Redeeming fidelity bond - should consume UTXO {}:{}",
        fidelity_utxo_info.0,
        fidelity_utxo_info.1
    );

    {
        let mut wallet = maker.wallet.write().unwrap();
        wallet
            .redeem_fidelity(fidelity_index, MIN_FEE_RATE, AddressType::P2TR)
            .unwrap();
    }

    generate_blocks(bitcoind, 1);
    maker
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    // Verify the specific UTXO is now consumed and bond is spent
    {
        let wallet = maker.wallet.read().unwrap();
        let all_utxos = wallet.list_all_utxo();

        let fidelity_utxo_still_exists = all_utxos.iter().any(|utxo| {
            utxo.txid == fidelity_utxo_info.0
                && utxo.vout == fidelity_utxo_info.1
                && utxo.amount == fidelity_utxo_info.2
        });

        if fidelity_utxo_still_exists {
            panic!(
                "FAILED: Fidelity bond UTXO {}:{} still exists after redemption!",
                fidelity_utxo_info.0, fidelity_utxo_info.1
            );
        }

        let bond = wallet
            .get_fidelity_bonds()
            .get(fidelity_index as usize)
            .unwrap();
        assert!(
            bond.is_spent(),
            "Fidelity bond should be spent after redemption"
        );

        log::info!(
            "Fidelity UTXO {}:{} successfully consumed by redemption",
            fidelity_utxo_info.0,
            fidelity_utxo_info.1
        );
        log::info!("UTXOs after redemption: {}", all_utxos.len());
    }

    let new_fidelity_index = {
        let (index, txid) = maker
            .wallet
            .write()
            .unwrap()
            .create_fidelity(
                Amount::from_sat(6_000_000),
                LockTime::from_height((bitcoind.client.get_block_count().unwrap() as u32) + 100)
                    .unwrap(),
                None,
                MIN_FEE_RATE,
                AddressType::P2TR,
            )
            .unwrap();
        let conf_height = maker
            .wallet
            .read()
            .unwrap()
            .wait_for_tx_confirmation(&[txid], 1, None, None)
            .unwrap();
        maker
            .wallet
            .write()
            .unwrap()
            .update_fidelity_bond_conf_details(index, conf_height)
            .unwrap();
        index
    };

    generate_blocks(bitcoind, 1);
    maker
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    {
        let wallet = maker.wallet.read().unwrap();
        let new_bond = wallet
            .get_fidelity_bonds()
            .get(new_fidelity_index as usize)
            .unwrap();
        assert!(!new_bond.is_spent(), "New fidelity bond should be unspent");
    }

    log::info!("SUCCESS: All fidelity spending behavior requirements verified!");
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

// ---- Shared scaffolding for the maker-restart fidelity tests ----

/// Wait for run 1's bond-broadcast log line and parse the txid out of it.
fn wait_for_bond_broadcast(log_path: &str) -> Txid {
    wait_for_log(
        log_path,
        "Fidelity bond broadcast, waiting for confirmation",
        Duration::from_secs(120),
    );
    let line = std::fs::read_to_string(log_path)
        .unwrap()
        .lines()
        .find(|l| l.contains("Fidelity bond broadcast, waiting for confirmation"))
        .expect("run 1 must log the bond broadcast line")
        .to_string();
    line.rsplit(": ")
        .next()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or_else(|| panic!("could not parse bond txid from log line: {}", line))
}

/// Clone a stopped maker's config for a simulated restart. The first init
/// consumed the passphrase (`config.password.take()`), so re-supply it the
/// way an operator would.
fn maker_restart_config(maker: &MakerServer) -> MakerServerConfig {
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    config
}

/// Spawn a replacement bitcoind on an existing datadir. The old node releases
/// the datadir lock and ZMQ ports asynchronously, so retry until the
/// replacement can take them over.
fn spawn_replacement_bitcoind(staticdir: PathBuf, extra_args: &[&str]) -> bitcoind::BitcoinD {
    let mut conf = bitcoind::Conf::default();
    conf.args.push("-txindex=1");
    conf.args.push("-deprecatedrpc=warnings");
    conf.args.extend_from_slice(extra_args);
    conf.p2p = bitcoind::P2P::Yes;
    conf.staticdir = Some(staticdir);

    let exe_path = bitcoind::exe_path().unwrap();
    let mut attempt = 0;
    loop {
        match bitcoind::BitcoinD::with_conf(exe_path.clone(), &conf) {
            Ok(node) => break node,
            Err(e) if attempt < 30 => {
                attempt += 1;
                log::warn!("replacement bitcoind not ready yet ({}); retrying", e);
                thread::sleep(Duration::from_secs(2));
            }
            Err(e) => panic!("replacement bitcoind failed to start: {}", e),
        }
    }
}

/// The end state every restart test pins: exactly one bond, with the original
/// txid, and its confirmation recorded (valuation requires it).
fn assert_single_adopted_bond(maker: &MakerServer, bond_txid: Txid) {
    let wallet_read = maker.wallet.read().unwrap();
    let bonds = wallet_read.get_fidelity_bonds();
    assert_eq!(bonds.len(), 1, "restart must not create a second bond");
    assert_eq!(
        bonds[0].outpoint().txid,
        bond_txid,
        "restart must keep the original bond txid"
    );
    assert_eq!(
        wallet_read.get_highest_fidelity_index().unwrap(),
        Some(0),
        "adopted bond must be valuated, i.e. its confirmation was recorded"
    );
}

/// Regression test for <https://github.com/citadel-foss/openswap/issues/990>
///
/// A maker stopped after broadcasting its fidelity bond but before it confirms
/// restarts with a pending bond (`conf_height: None`) in the wallet. The
/// restart must adopt that bond - wait for its confirmation and use it -
/// instead of silently discarding it and creating a second bond, which would
/// doubly lock funds.
///
/// The behaviour is pinned on exact log lines:
/// - run 1 takes the create branch once and broadcasts the bond,
/// - run 2 must log the adopt-a-pending-bond lines and take the
///   existing-bond branch ("Highest bond at outpoint"),
/// - across both runs "No active Fidelity Bonds found. Creating one." appears
///   exactly once, and "Successfully created fidelity bond" never appears
///   (it only logs when a new bond is created, which the restart must not do).
#[test]
fn test_unconfirmed_fidelity_bond_not_duplicated() {
    // ---- Setup ----
    let makers_config_map = vec![(8102, None)];
    let taker_behavior = vec![TakerBehavior::Normal];

    let (test_framework, _takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, vec![]);

    log::info!("Running Test: Unconfirmed Fidelity Bond Survives Maker Restart");

    let bitcoind = &test_framework.bitcoind;
    let maker = makers.first().unwrap();
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());

    fund_makers(&makers, bitcoind, 1, Amount::ONE_BTC, AddressType::P2TR);

    // ----- Run 1: maker broadcasts a bond, then stops before it confirms -----

    // Pause the background miner so the bond tx cannot confirm while run 1 is up.
    test_framework.set_block_gen_paused(true);

    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || {
        // The shutdown below interrupts setup mid-wait and surfaces as an
        // error; that partial run is the point of the test, so don't unwrap.
        let _ = start_server(maker_clone);
    });

    let bond_txid = wait_for_bond_broadcast(&log_path);

    // Pin the preconditions: the bond tx is still unconfirmed on-chain ...
    assert!(
        bitcoind.client.get_mempool_entry(&bond_txid).is_ok(),
        "bond tx {} must still be unconfirmed for this test to mean anything",
        bond_txid
    );

    // ... and the create branch ran exactly once.
    assert_eq!(
        std::fs::read_to_string(&log_path)
            .unwrap()
            .matches("No active Fidelity Bonds found. Creating one.")
            .count(),
        1,
        "run 1 should have created exactly one bond candidate"
    );

    // Stop the maker while the bond is still unconfirmed.
    maker.shutdown.store(true, Relaxed);
    let _ = maker_thread.join();

    // ----- Run 2: the restart must adopt the pending bond, not create a new one -----

    // Resume mining so the restarted maker can wait out the confirmation.
    test_framework.set_block_gen_paused(false);

    let restarted = Arc::new(MakerServer::init(maker_restart_config(maker)).unwrap());
    let restarted_clone = restarted.clone();
    let restarted_thread = thread::spawn(move || {
        let _ = start_server(restarted_clone);
    });

    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    assert_single_adopted_bond(&restarted, bond_txid);

    restarted.shutdown.store(true, Relaxed);
    let _ = restarted_thread.join();

    // ----- Assertions on the log of both runs -----
    let log = std::fs::read_to_string(&log_path).unwrap();

    assert!(
        log.contains("waiting for confirmation instead of creating a new one"),
        "restart must detect the pending bond and wait for it"
    );
    assert!(
        log.contains("confirmed at height"),
        "restart must record the pending bond's confirmation"
    );
    assert!(
        log.contains("Highest bond at outpoint"),
        "restart must take the existing-bond branch with the adopted bond"
    );
    assert_eq!(
        log.matches("No active Fidelity Bonds found. Creating one.")
            .count(),
        1,
        "restart must not take the create-new-bond branch (would doubly lock funds)"
    );
    assert!(
        !log.contains("Successfully created fidelity bond"),
        "restart must not create a second fidelity bond"
    );

    test_framework.stop();
    block_generation_handle.join().unwrap();

    log::info!("Unconfirmed fidelity bond restart test completed successfully");
}

/// Eviction path: if the unconfirmed bond tx falls out of the mempool while
/// the maker is offline, the restart must rebroadcast the stored raw
/// transaction — keeping the original txid and creating no second bond.
///
/// Regtest has no "evict from mempool" RPC, so the eviction is simulated by
/// restarting bitcoind with `-persistmempool=0` on the same datadir: the
/// chain (and every confirmed coin) survives, the mempool does not.
///
/// Anchored to `test_unconfirmed_fidelity_bond_not_duplicated`, which covers
/// the mempool-present early return; this test covers the rebroadcast branch
/// of `ensure_fidelity_bond_broadcast`.
#[test]
fn test_evicted_fidelity_bond_rebroadcast_on_restart() {
    // ---- Setup ----
    let makers_config_map = vec![(8104, None)];

    let (test_framework, _takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, vec![], vec![]);

    log::info!("Running Test: Evicted Fidelity Bond Rebroadcast On Restart");

    let bitcoind = &test_framework.bitcoind;
    let maker = makers.first().unwrap();
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());

    fund_makers(&makers, bitcoind, 1, Amount::ONE_BTC, AddressType::P2TR);

    // ----- Run 1: maker broadcasts a bond, then stops before it confirms -----

    // Pause the background miner so the bond tx cannot confirm while run 1 is up.
    test_framework.set_block_gen_paused(true);

    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || {
        let _ = start_server(maker_clone);
    });

    let bond_txid = wait_for_bond_broadcast(&log_path);
    assert!(
        bitcoind.client.get_mempool_entry(&bond_txid).is_ok(),
        "bond tx {} must be in the mempool before the eviction",
        bond_txid
    );

    // Stop the maker while the bond is still unconfirmed.
    maker.shutdown.store(true, Relaxed);
    let _ = maker_thread.join();

    // ----- Evict the bond: restart bitcoind without mempool persistence -----

    let (wallet_name, zmq_addr) = match &maker.config.backend {
        openswap::wallet::BackendConfig::CoreRpc(cfg) => {
            (cfg.wallet_name.clone(), cfg.zmq_addr.clone())
        }
        _ => panic!("expected a CoreRpc backend"),
    };

    // Clean stop writes mempool.dat; the replacement node must not load it.
    let _ = test_framework.bitcoind.client.stop();

    // `-persistmempool=0` is the eviction: the mempool is not reloaded from
    // mempool.dat. `-walletbroadcast=0` stops the node wallet resurrecting
    // the evicted tx: Core rebroadcasts the wallet's unconfirmed
    // transactions on startup, which would put the bond right back.
    let raw_tx = format!("-zmqpubrawtx={zmq_addr}");
    let block_hash = format!("-zmqpubrawblock={zmq_addr}");
    let new_bitcoind = spawn_replacement_bitcoind(
        test_framework.temp_dir.join(".bitcoin"),
        &[
            "-persistmempool=0",
            "-walletbroadcast=0",
            &raw_tx,
            &block_hash,
        ],
    );

    assert!(
        new_bitcoind.client.get_mempool_entry(&bond_txid).is_err(),
        "bond tx {} must be evicted after the mempool reset",
        bond_txid
    );

    // ----- Run 2: the restart must rebroadcast the stored bond tx -----

    // Point the backend at the replacement node.
    let mut restart_config = maker_restart_config(maker);
    restart_config.backend = openswap::wallet::BackendConfig::CoreRpc(CoreRpcConfig {
        url: new_bitcoind.rpc_url().split_at(7).1.to_string(),
        auth: Auth::CookieFile(new_bitcoind.params.cookie_file.clone()),
        wallet_name,
        zmq_addr,
    });

    let restarted = Arc::new(MakerServer::init(restart_config).unwrap());
    let restarted_clone = restarted.clone();
    let restarted_thread = thread::spawn(move || {
        let _ = start_server(restarted_clone);
    });

    // The restart must detect the eviction and rebroadcast the stored raw
    // transaction, which reproduces the original txid.
    wait_for_log(
        &log_path,
        "evicted from mempool?); rebroadcasting",
        Duration::from_secs(120),
    );
    assert!(
        new_bitcoind.client.get_mempool_entry(&bond_txid).is_ok(),
        "rebroadcast must put the original bond tx {} back in the mempool",
        bond_txid
    );

    // Confirm the rebroadcast tx so finalization completes (the background
    // miner stays paused: it talks to the dead node).
    generate_blocks(&new_bitcoind, 1);
    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    assert_single_adopted_bond(&restarted, bond_txid);

    restarted.shutdown.store(true, Relaxed);
    let _ = restarted_thread.join();

    // ----- Assertions on the log of both runs -----
    let log = std::fs::read_to_string(&log_path).unwrap();

    assert!(
        log.contains("not visible to the backend (evicted from mempool?); rebroadcasting"),
        "restart must take the rebroadcast branch for the evicted bond"
    );
    assert!(
        log.contains("confirmed at height"),
        "restart must record the rebroadcast bond's confirmation"
    );
    assert_eq!(
        log.matches("No active Fidelity Bonds found. Creating one.")
            .count(),
        1,
        "restart must not take the create-new-bond branch (would doubly lock funds)"
    );
    assert!(
        !log.contains("Successfully created fidelity bond"),
        "restart must not create a second fidelity bond"
    );

    // Teardown: stop the replacement node first; the framework's original
    // node is already down (TestFramework::stop tolerates that).
    let _ = new_bitcoind.client.stop();
    test_framework.stop();
    block_generation_handle.join().unwrap();

    log::info!("Evicted fidelity bond rebroadcast test completed successfully");
}

/// Electrum variant of `test_unconfirmed_fidelity_bond_not_duplicated`:
/// a maker that shuts down with an unconfirmed bond must adopt it on restart
/// instead of creating a second one, this time over the Electrum backend.
#[test]
fn test_unconfirmed_fidelity_bond_not_duplicated_electrum() {
    // ---- Setup ----
    let makers_config_map = vec![(8105, None)];

    let (test_framework, _takers, makers, block_generation_handle) =
        TestFramework::init::<ElectrumBackend>(makers_config_map, vec![], vec![]);

    log::info!("Running Test: Unconfirmed Fidelity Bond Survives Maker Restart (Electrum)");

    let bitcoind = &test_framework.bitcoind;
    let maker = makers.first().unwrap();
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());

    fund_makers(&makers, bitcoind, 1, Amount::ONE_BTC, AddressType::P2TR);

    // ----- Run 1: maker broadcasts a bond, then stops before it confirms -----

    test_framework.set_block_gen_paused(true);

    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || {
        let _ = start_server(maker_clone);
    });

    let bond_txid = wait_for_bond_broadcast(&log_path);
    assert!(
        bitcoind.client.get_mempool_entry(&bond_txid).is_ok(),
        "bond tx {} must still be unconfirmed for this test to mean anything",
        bond_txid
    );

    maker.shutdown.store(true, Relaxed);
    let _ = maker_thread.join();

    // ----- Run 2: the restart must adopt the pending bond, not create a new one -----

    // Resume mining so the restarted maker can wait out the confirmation.
    test_framework.set_block_gen_paused(false);

    // The Electrum backend is untouched: electrs keeps running throughout.
    let restarted = Arc::new(MakerServer::init(maker_restart_config(maker)).unwrap());
    let restarted_clone = restarted.clone();
    let restarted_thread = thread::spawn(move || {
        let _ = start_server(restarted_clone);
    });

    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    assert_single_adopted_bond(&restarted, bond_txid);

    restarted.shutdown.store(true, Relaxed);
    let _ = restarted_thread.join();

    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        log.contains("waiting for confirmation instead of creating a new one"),
        "restart must detect the pending bond and wait for it"
    );
    assert!(
        log.contains("confirmed at height"),
        "restart must record the pending bond's confirmation"
    );
    assert_eq!(
        log.matches("No active Fidelity Bonds found. Creating one.")
            .count(),
        1,
        "restart must not take the create-new-bond branch (would doubly lock funds)"
    );
    assert!(
        !log.contains("Successfully created fidelity bond"),
        "restart must not create a second fidelity bond"
    );

    test_framework.stop();
    block_generation_handle.join().unwrap();

    log::info!("Unconfirmed fidelity bond restart test (Electrum) completed successfully");
}

/// Electrum variant of `test_evicted_fidelity_bond_rebroadcast_on_restart`:
/// the unconfirmed bond is evicted while the maker is offline (bitcoind
/// restarted with `-persistmempool=0`), and the restart must rebroadcast the
/// stored raw transaction over Electrum, keeping the original txid.
///
/// electrs follows bitcoind's mempool, so it must be restarted against the
/// replacement node as well; its mempool view is in-memory, so a fresh
/// electrs reflects the empty mempool immediately.
#[test]
fn test_evicted_fidelity_bond_rebroadcast_on_restart_electrum() {
    // ---- Setup ----
    let makers_config_map = vec![(8106, None)];

    let (test_framework, _takers, makers, block_generation_handle) =
        TestFramework::init::<ElectrumBackend>(makers_config_map, vec![], vec![]);

    log::info!("Running Test: Evicted Fidelity Bond Rebroadcast On Restart (Electrum)");

    let bitcoind = &test_framework.bitcoind;
    let maker = makers.first().unwrap();
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());

    fund_makers(&makers, bitcoind, 1, Amount::ONE_BTC, AddressType::P2TR);

    // ----- Run 1: maker broadcasts a bond, then stops before it confirms -----

    test_framework.set_block_gen_paused(true);

    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || {
        let _ = start_server(maker_clone);
    });

    let bond_txid = wait_for_bond_broadcast(&log_path);
    assert!(
        bitcoind.client.get_mempool_entry(&bond_txid).is_ok(),
        "bond tx {} must be in the mempool before the eviction",
        bond_txid
    );

    maker.shutdown.store(true, Relaxed);
    let _ = maker_thread.join();

    // ----- Evict the bond: restart bitcoind without mempool persistence -----

    let electrum_cfg = match &maker.config.backend {
        openswap::wallet::BackendConfig::Electrum(cfg) => cfg.clone(),
        _ => panic!("expected an Electrum backend"),
    };

    // electrs polls bitcoind, so it goes down before the node does.
    drop(test_framework.electrsd.lock().unwrap().take());
    // Clean stop writes mempool.dat; the replacement node must not load it.
    let _ = test_framework.bitcoind.client.stop();

    // `-persistmempool=0` is the eviction: the mempool is not reloaded from
    // mempool.dat. (No `-walletbroadcast=0` needed here: with the Electrum
    // backend no node-side wallet tracks the bond tx. No ZMQ args either:
    // electrs talks to the node over RPC/p2p only.)
    let new_bitcoind = spawn_replacement_bitcoind(
        test_framework.temp_dir.join(".bitcoin"),
        &["-persistmempool=0"],
    );

    assert!(
        new_bitcoind.client.get_mempool_entry(&bond_txid).is_err(),
        "bond tx {} must be evicted after the mempool reset",
        bond_txid
    );

    // Fresh electrs against the replacement node (same db dir: the indexed
    // chain survives, the mempool view is rebuilt empty).
    thread::sleep(Duration::from_secs(2));
    let new_electrsd = init_electrsd(&new_bitcoind, &test_framework.temp_dir);
    let new_electrum_cfg = ElectrumConfig {
        url: format!("tcp://{}", new_electrsd.electrum_url),
        ..electrum_cfg
    };
    wait_for_electrs_tip(&new_bitcoind, &new_electrsd, &new_electrum_cfg);

    // ----- Run 2: the restart must rebroadcast the stored bond tx -----

    // Point the backend at the replacement electrs.
    let mut restart_config = maker_restart_config(maker);
    restart_config.backend = openswap::wallet::BackendConfig::Electrum(new_electrum_cfg.clone());

    let restarted = Arc::new(MakerServer::init(restart_config).unwrap());
    let restarted_clone = restarted.clone();
    let restarted_thread = thread::spawn(move || {
        let _ = start_server(restarted_clone);
    });

    wait_for_log(
        &log_path,
        "evicted from mempool?); rebroadcasting",
        Duration::from_secs(120),
    );
    assert!(
        new_bitcoind.client.get_mempool_entry(&bond_txid).is_ok(),
        "rebroadcast must put the original bond tx {} back in the mempool",
        bond_txid
    );

    // Confirm the rebroadcast tx so finalization completes, and nudge electrs
    // to index the block (the background miner stays paused: it talks to the
    // dead node).
    generate_blocks(&new_bitcoind, 1);
    let _ = new_electrsd.trigger();
    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    assert_single_adopted_bond(&restarted, bond_txid);

    restarted.shutdown.store(true, Relaxed);
    let _ = restarted_thread.join();

    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        log.contains("not visible to the backend (evicted from mempool?); rebroadcasting"),
        "restart must take the rebroadcast branch for the evicted bond"
    );
    assert!(
        log.contains("confirmed at height"),
        "restart must record the rebroadcast bond's confirmation"
    );
    assert_eq!(
        log.matches("No active Fidelity Bonds found. Creating one.")
            .count(),
        1,
        "restart must not take the create-new-bond branch (would doubly lock funds)"
    );
    assert!(
        !log.contains("Successfully created fidelity bond"),
        "restart must not create a second fidelity bond"
    );

    // Teardown: electrs first (its datadir sits inside temp_dir), then the
    // replacement node; the framework's original node is already down.
    drop(new_electrsd);
    let _ = new_bitcoind.client.stop();
    test_framework.stop();
    block_generation_handle.join().unwrap();

    log::info!("Evicted fidelity bond rebroadcast test (Electrum) completed successfully");
}
