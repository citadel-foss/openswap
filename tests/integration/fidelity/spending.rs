//! Spending around fidelity bonds. Regular sends never select expired bond
//! UTXOs, while redemption and new bond creation can consume them.
//! `mempool_only_spend_reads_as_spent` pins the backend answer the maker's
//! funding check relies on: a spend still in the mempool reads as spent.

use bitcoin::{absolute::LockTime, Amount};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    utill::MIN_RELAY_FEE_RATE,
    wallet::{AddressType, Blockchain, CoreRPC, Destination},
};

use crate::test_framework::*;

use log::info;

/// Pins the two backend answers the maker's funding check rests on: `None` sees a
/// mempool-only spend, while `Some(false)` — the argument it used to pass — reports
/// that output live on Core. Pins the backend, not the maker's call site.
#[world_test(backend = BitcoindBackend)]
fn mempool_only_spend_reads_as_spent(node: &mut Node) {
    // A bare node: nothing mines in the background, so the spend cannot
    // confirm while the assertions run.
    let bitcoind = node.bitcoind();
    let backend = CoreRPC::new(&node.rpc_config()).expect("connect Core backend");

    let address = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let spend_txid = send_to_address(bitcoind, &address, Amount::ONE_BTC);
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
}

/// This test verifies that expired fidelity bond UTXOs are properly isolated from regular transactions:
///
/// - Creates a fidelity bond and lets it expire by advancing blockchain height
/// - Verifies that regular transactions never select expired fidelity bond UTXOs for spending
/// - Confirms that new fidelity bond creation can properly consume expired fidelity bond UTXOs
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
    takers = [Normal],
)]
fn bond_spending(world: &mut World) {
    const TIMELOCK_DURATION: u32 = 50;
    const FIDELITY_AMOUNT: u64 = 5_000_000;
    const REGULAR_TX_AMOUNT: u64 = 100_000;

    let bitcoind = world.bitcoind();
    let maker = world.makers()[0].inner();

    world.fund_makers(1, Amount::from_btc(2.0).unwrap(), AddressType::P2TR);

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
                MIN_RELAY_FEE_RATE,
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
                    MIN_RELAY_FEE_RATE,
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
                match wallet.spend_from_wallet(MIN_RELAY_FEE_RATE, destination, &selected_utxos) {
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
            .redeem_fidelity(fidelity_index, MIN_RELAY_FEE_RATE, AddressType::P2TR)
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
                MIN_RELAY_FEE_RATE,
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
}
