//! Integration test for concurrent taker openswap with limited maker liquidity.
//!
//! Setup: 2 takers with Normal behavior, 2 makers with Normal behavior.
//! Both takers run swaps concurrently via `thread::scope`, once per protocol.
//! Makers have limited liquidity (only enough for ~1 swap), so one taker
//! should succeed and the other should fail due to insufficient funds.
//! This exercises the UTXO reservation mechanism that prevents double-spend.

use bitcoin::Amount;
use openswap::{
    maker::start_server,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    sync::atomic::{AtomicU8, Ordering::Relaxed},
    thread,
    time::Duration,
};

// Result codes for atomic tracking
const RESULT_PENDING: u8 = 0;
const RESULT_SUCCESS: u8 = 1;
const RESULT_FAILED: u8 = 2;

#[test]
fn test_concurrent_takers_legacy() {
    concurrent_takers(
        ProtocolVersion::Legacy,
        vec![(7802, Some(20801)), (17802, Some(20802))],
        [1250081, 1250044],
    );
}

#[test]
fn test_concurrent_takers_taproot() {
    concurrent_takers(
        ProtocolVersion::Taproot,
        vec![(7902, Some(20901)), (17902, Some(20902))],
        [1250309, 1250272],
    );
}

fn concurrent_takers(
    protocol: ProtocolVersion,
    makers_config_map: Vec<(u16, Option<u16>)>,
    expected_maker_spendable: [u64; 2],
) {
    // ---- Setup ----
    warn!(
        "Running Test: Concurrent Takers with {:?} Protocol - Limited Liquidity",
        protocol
    );

    let taker_behavior = vec![TakerBehavior::Normal, TakerBehavior::Normal];

    // Initialize test framework with 2 takers and 2 makers
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, vec![]);

    let bitcoind = &test_framework.bitcoind;

    // Fund each taker thrice with one 0.05 BTC UTXO (0.15 total), one per call so
    // each lands on a distinct address.
    let mut taker1_original_balance = Amount::ZERO;
    let mut taker2_original_balance = Amount::ZERO;
    for _ in 0..3 {
        taker1_original_balance = fund_taker(
            &takers[0],
            bitcoind,
            1,
            Amount::from_btc(0.05).unwrap(),
            AddressType::P2TR,
        );
        taker2_original_balance = fund_taker(
            &takers[1],
            bitcoind,
            1,
            Amount::from_btc(0.05).unwrap(),
            AddressType::P2TR,
        );
    }
    fund_makers(
        &makers,
        bitcoind,
        1,
        Amount::from_sat(5_500_000),
        AddressType::P2TR,
    );
    for _ in 0..3 {
        fund_makers(
            &makers,
            bitcoind,
            1,
            Amount::from_sat(250_000),
            AddressType::P2TR,
        );
    }

    // Start the maker server threads
    log::info!("Starting Maker servers...");

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    // Wait for makers to complete setup
    wait_for_makers_setup(&makers, 120);

    // Sync wallets after setup to ensure fidelity bonds are accounted for
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    // Collect pre-swap spendable balances (skip standard assertions since we use limited liquidity)
    let maker_spendable_balance: Vec<Amount> = makers
        .iter()
        .enumerate()
        .map(|(i, maker)| {
            let wallet = maker.wallet.read().unwrap();
            let balances = wallet.get_balances().unwrap();
            info!(
                "Maker {} pre-swap: Regular: {}, Fidelity: {}, Spendable: {}",
                i, balances.regular, balances.fidelity, balances.spendable
            );
            balances.spendable
        })
        .collect();

    // ---- Concurrent Swaps ----
    log::info!(
        "Starting concurrent swaps for both takers ({:?} protocol)...",
        protocol
    );

    generate_blocks(bitcoind, 1);

    // Use atomics for thread-safe result tracking
    let result1 = AtomicU8::new(RESULT_PENDING);
    let result2 = AtomicU8::new(RESULT_PENDING);

    thread::scope(|s| {
        let (taker1_slice, taker2_slice) = takers.split_at_mut(1);
        let taker1 = &mut taker1_slice[0];
        let taker2 = &mut taker2_slice[0];

        let r1 = &result1;
        let r2 = &result2;

        s.spawn(move || {
            info!("Taker 1 starting concurrent {:?} openswap", protocol);
            let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
                .with_tx_count([3, 3])
                .with_required_confirms(1);

            match taker1.prepare_swap(swap_params) {
                Ok(summary) => match taker1.start_swap(&summary.swap_id) {
                    Ok(report) => {
                        info!("Taker 1 {:?} openswap completed successfully!", protocol);
                        info!("Taker 1 swap report: {:?}", report);
                        r1.store(RESULT_SUCCESS, Relaxed);
                    }
                    Err(e) => {
                        warn!("Taker 1 {:?} openswap failed: {:?}", protocol, e);
                        r1.store(RESULT_FAILED, Relaxed);
                    }
                },
                Err(e) => {
                    warn!("Taker 1 {:?} prepare failed: {:?}", protocol, e);
                    r1.store(RESULT_FAILED, Relaxed);
                }
            }
        });

        // Small delay to stagger the start
        thread::sleep(Duration::from_secs(3));

        s.spawn(move || {
            info!("Taker 2 starting concurrent {:?} openswap", protocol);
            let swap_params = SwapParams::new(protocol, Amount::from_sat(900000), 2)
                .with_tx_count([3, 3])
                .with_required_confirms(1);

            match taker2.prepare_swap(swap_params) {
                Ok(summary) => match taker2.start_swap(&summary.swap_id) {
                    Ok(report) => {
                        info!("Taker 2 {:?} openswap completed successfully!", protocol);
                        info!("Taker 2 swap report: {:?}", report);
                        r2.store(RESULT_SUCCESS, Relaxed);
                    }
                    Err(e) => {
                        warn!("Taker 2 {:?} openswap failed: {:?}", protocol, e);
                        r2.store(RESULT_FAILED, Relaxed);
                    }
                },
                Err(e) => {
                    warn!("Taker 2 {:?} prepare failed: {:?}", protocol, e);
                    r2.store(RESULT_FAILED, Relaxed);
                }
            }
        });
    });

    info!("All concurrent {:?} openswaps processed.", protocol);

    let r1 = result1.load(Relaxed);
    let r2 = result2.load(Relaxed);
    let success_count = [r1, r2].iter().filter(|&&r| r == RESULT_SUCCESS).count();
    let completed_count = [r1, r2].iter().filter(|&&r| r != RESULT_PENDING).count();

    info!(
        "Results: {} succeeded, {} failed",
        success_count,
        completed_count - success_count
    );

    // With limited liquidity, we expect one to succeed and one to fail
    // The UTXO reservation mechanism prevents double-spend of maker UTXOs
    assert!(success_count >= 1, "At least one taker should succeed");
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    // Maker-side log: the maker refused the second swap for liquidity.
    test_framework.assert_log("Rejecting swap ", &log_path);
    // Taker-side log: the losing taker got the rejection as a message and
    // failed fast, not sat out a timeout on a dropped connection.
    test_framework.assert_log("rejected swap", &log_path);
    assert_eq!(
        completed_count, 2,
        "Both takers should have completed (success or failure)"
    );

    log::info!("All openswaps processed. Transactions complete.");

    // Sync all wallets
    for taker in takers.iter() {
        taker
            .get_wallet()
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    generate_blocks(bitcoind, 1);

    for maker in makers.iter() {
        let mut wallet = maker.wallet.write().unwrap();
        wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    }

    // ---- Verify balances ----
    let results = [r1, r2];
    for (i, taker) in takers.iter().enumerate() {
        let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
        let original = if i == 0 {
            taker1_original_balance
        } else {
            taker2_original_balance
        };
        info!(
            "Taker {} balance: Original: {}, After: {}, Contract: {}",
            i, original, taker_balances.spendable, taker_balances.contract
        );

        if results[i] == RESULT_SUCCESS {
            assert_eq!(
                taker_balances.contract,
                Amount::ZERO,
                "Taker {}: Successful swap should have no contract balance",
                i
            );
        } else {
            // Failed taker may have outgoing contract UTXOs on-chain if the
            // failure occurred after contract broadcast. These are the taker's
            // own funds, recoverable via timelock.
            info!(
                "Taker {}: Failed swap has {} contract balance (recoverable via timelock)",
                i, taker_balances.contract
            );
        }
    }

    // Verify maker balances
    for (i, (maker, original_spendable)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        let wallet = maker.wallet.read().unwrap();
        let balances = wallet.get_balances().unwrap();

        info!(
            "Maker {} final balances - Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.fidelity, balances.spendable,
        );

        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "Maker {}: Contract balance should be zero after swaps",
            i
        );

        // With the lower fee schedule, the earned maker fee does not fully
        // offset on-chain spend costs in this limited-liquidity scenario.
        if success_count > 0 {
            assert_eq!(
                balances.spendable.to_sat(),
                expected_maker_spendable[i],
                "Maker {}: Unexpected spendable balance",
                i
            );
        } else {
            assert_eq!(
                balances.spendable, original_spendable,
                "Maker {}: Spendable balance should be unchanged",
                i
            );
        }
    }

    info!(
        "All concurrent taker swap tests ({:?}) completed successfully!",
        protocol
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    // Drop takers before stopping the framework so their background services
    // shut down while bitcoind is still running.
    drop(takers);

    test_framework.stop();
    block_generation_handle.join().unwrap();
}
