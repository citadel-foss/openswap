//! Fidelity bond creation and redemption through the maker API.
//!
//! - The maker starts with insufficient funds for a bond (0.04 BTC) and logs a
//!   request for more.
//! - Once given enough (1 BTC), it creates its first bond (0.05 BTC).
//! - The maker is restored from a seed-only backup and must find that bond again.
//! - A second bond (0.08 BTC) is created and its higher value is verified.
//! - Bond maturity is simulated by advancing the chain, and the bonds are
//!   redeemed one by one, checking balances and bond status after each.

use bitcoin::{absolute::LockTime, Amount};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    maker::{start_server, MakerServer},
    security::KeyMaterial,
    utill::MIN_RELAY_FEE_RATE,
    wallet::{AddressType, Wallet, WalletBackup},
};

use crate::test_framework::*;

use std::{
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::Duration,
};

use super::{assert_single_adopted_bond, maker_restart_config};

/// Test Fidelity Bond Creation and Redemption
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
    takers = [Normal],
)]
fn bond_creation_and_redemption(world: &mut World) {
    let bitcoind = world.bitcoind();
    let maker = world.makers()[0].inner();

    // ----- Test -----

    log::info!("Providing insufficient funds to trigger funding request");
    // Provide insufficient funds to the Maker and start the server.
    // This will continuously log about insufficient funds and request BTC to create a fidelity bond.
    world.fund_makers(1, Amount::from_btc(0.04).unwrap(), AddressType::P2TR);

    let maker_clone = maker.clone();

    log::info!("Starting maker server with insufficient funds");
    let maker_thread = thread::spawn(move || start_server(maker_clone));

    thread::sleep(Duration::from_secs(6));

    assert_log!(world; {
        has "Send at least 0.01001909 BTC to",
        has "(fidelity bond + fees + minimum swap liquidity) to be visible in the market",
    });

    log::info!("Sending exactly the quoted amount");
    // Setup completes only after the bond is made and the leftover passes the
    // swap liquidity check, so this proves one deposit of the quote is enough.
    world.fund_makers(1, Amount::from_sat(1_001_909), AddressType::P2TR);
    wait_for_makers_setup(std::slice::from_ref(maker), 120);

    // stop the Maker server
    maker.shutdown.store(true, Relaxed);

    let _ = maker_thread.join().unwrap();

    // Assert that successful fidelity bond creation is logged
    assert_log!(world; { has "Successfully created fidelity bond" });

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

    // ----- Restore the maker from a backup and restart it -----
    // A backup holds only the seed, so the restarted maker must find its bond
    // on-chain instead of locking a second one.
    let bond_txid = maker.wallet.read().unwrap().get_fidelity_bonds()[0]
        .outpoint()
        .txid;
    let backup = WalletBackup::from(&*maker.wallet.read().unwrap());
    let config = maker_restart_config(maker);
    let wallet_path = config.data_dir.join("wallets").join(&config.wallet_name);
    std::fs::remove_file(&wallet_path).unwrap();
    Wallet::restore(
        &backup,
        &wallet_path,
        &config.backend,
        KeyMaterial::new_from_password(Some("integration-test".to_string())).unwrap(),
    )
    .unwrap();
    let restarted = Arc::new(MakerServer::init(config).unwrap());
    let restarted_clone = restarted.clone();
    let restarted_thread = thread::spawn(move || start_server(restarted_clone));
    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);
    assert_single_adopted_bond(&restarted, bond_txid);
    restarted.shutdown.store(true, Relaxed);
    let _ = restarted_thread.join().unwrap();
    // The restored maker must not create a second bond.
    assert_log!(world; { count("No active Fidelity Bonds found. Creating one.") == 1 });

    log::info!("Creating second fidelity bond with higher amount");
    world.fund_makers(1, Amount::ONE_BTC, AddressType::P2TR);
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
    world.makers()[0].sync();
    assert_balances!(world; { maker: { regular: 92_001_512, fidelity: 13_000_000 } });

    log::info!("Waiting for fidelity bonds to mature and testing redemption");
    // Wait for the bonds to mature, redeem them, and validate the process.
    let mut required_height = first_maturity_height;
    // Set by the wrapper redemption below; the loop's only exit assigns it.
    let redemption_proof;

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
                    .redeem_fidelity(0, MIN_RELAY_FEE_RATE, AddressType::P2TR)
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

                // The wrapper's expiry check is strict (`tip > lock_time`),
                // and this branch runs at the boundary — mine one block past it.
                generate_blocks(bitcoind, 1);
                // Hold the mempool still so the probe below can find the tx.
                world.framework().set_block_gen_paused(true);
                // Through the wrapper at a distinct rate: proves the caller's
                // feerate reaches the broadcast tx rather than a fixed fallback.
                let bond_outpoint = wallet_write.get_fidelity_bonds()[1].outpoint();
                wallet_write
                    .redeem_expired_fidelity_bonds(3.0, AddressType::P2TR)
                    .unwrap();
                redemption_proof = Some(bond_outpoint);

                log::info!("Second Fidelity Bond is successfully redeemed");

                // There should now be no unspent bonds left.
                let index = wallet_write.get_highest_fidelity_index().unwrap();
                assert_eq!(index, None);
                break;
            }
        }
    }

    // Locate the wrapper's redemption tx by its bond input and measure what it
    // really pays: the fee must be the requested 3 sat/vB over the real vsize.
    let bond_outpoint = redemption_proof.expect("the second redemption ran");
    let redemption_txid = bitcoind
        .client
        .get_raw_mempool()
        .unwrap()
        .into_iter()
        .find(|txid| {
            bitcoind
                .client
                .get_raw_transaction(txid, None)
                .unwrap()
                .input
                .iter()
                .any(|input| input.previous_output == bond_outpoint)
        })
        .expect("the redemption tx must be in the mempool");
    let (fee, vsize) = tx_fee_and_vsize(bitcoind, &redemption_txid);
    // The builder prices its witness estimate, which can overshoot the real
    // vsize by a byte: never below the requested rate, at most 1 vB above it.
    assert!(
        fee >= 3 * vsize as u64 && fee <= 3 * (vsize as u64 + 1),
        "the redemption must pay the requested 3 sat/vB, not a fallback: fee {:?} for {:?} vB",
        fee,
        vsize
    );
    world.framework().set_block_gen_paused(false);

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
    assert_balances!(world; { maker: { regular: 105_001_016, fidelity: 0 } });

    thread::sleep(Duration::from_secs(10));
}
