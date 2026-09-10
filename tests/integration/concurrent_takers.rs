//! Integration test for concurrent taker openswap with limited maker liquidity.
//!
//! Setup: 2 takers with Normal behavior, 2 makers with Normal behavior.
//! Both takers run swaps concurrently via `thread::scope`, once per protocol.
//! Makers have limited liquidity (only enough for ~1 swap), so one taker
//! should succeed and the other should fail due to insufficient funds.
//! This exercises the UTXO reservation mechanism that prevents double-spend.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    sync::{
        atomic::{AtomicU8, Ordering::Relaxed},
        Arc, Barrier,
    },
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
        [1250635, 1250598],
    );
}

#[test]
fn test_concurrent_takers_taproot() {
    concurrent_takers(
        ProtocolVersion::Taproot,
        vec![(7902, Some(20901)), (17902, Some(20902))],
        [1250635, 1250598],
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
                .with_tx_count(3)
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
                .with_tx_count(3)
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

/// Two takers race ONE maker whose liquidity funds exactly one swap, both
/// declaring the identical shape so the maker's deterministic planner draws
/// the same inputs for each admission. Exactly one admission may win: the
/// loser is rejected at admission and fails cleanly, and no reservation leaks
/// — the maker still serves the losing taker's later swap.
#[test]
fn test_concurrent_admission_reservation_conflict() {
    warn!("Running Test: Concurrent admission reservation conflict - identical plans on one maker");

    let taker_behavior = vec![TakerBehavior::Normal, TakerBehavior::Normal];
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(8102, Some(20811))],
            taker_behavior,
            vec![MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;

    for taker in takers.iter() {
        fund_taker(
            taker,
            bitcoind,
            1,
            Amount::from_btc(0.05).unwrap(),
            AddressType::P2TR,
        );
    }
    // The 0.05 BTC UTXO covers the fidelity bond; what remains plus the 250k
    // funds exactly one 500k swap, so a second admission can never fit.
    fund_makers(
        &makers,
        bitcoind,
        1,
        Amount::from_sat(5_500_000),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        1,
        Amount::from_sat(250_000),
        AddressType::P2TR,
    );

    log::info!("Starting Maker server...");
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
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    let maker_spendable = makers[0]
        .wallet
        .read()
        .unwrap()
        .get_balances()
        .unwrap()
        .spendable;
    info!("Maker spendable before the race: {}", maker_spendable);
    generate_blocks(bitcoind, 1);

    // 400k twice would not fit the ~750k pool; one always fits, even after
    // the winner's swap shrinks the maker's offer max below the race amount.
    let maker_address = format!("127.0.0.1:{}", makers[0].config.network_port);
    let swap_params = || {
        SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(400_000), 1)
            .with_tx_count(3)
            .with_required_confirms(1)
            .with_preferred_makers(vec![maker_address.clone()])
    };

    // Barrier-start both takers: the tightest sequencing the framework
    // offers, so both admissions plan before either reserves.
    let start = Arc::new(Barrier::new(2));
    let results = [AtomicU8::new(RESULT_PENDING), AtomicU8::new(RESULT_PENDING)];

    thread::scope(|s| {
        for (i, taker) in takers.iter_mut().enumerate() {
            let barrier = start.clone();
            let result = &results[i];
            let params = swap_params();
            s.spawn(move || {
                barrier.wait();
                info!("Taker {} entering the admission race", i + 1);
                let outcome = taker
                    .prepare_swap(params)
                    .and_then(|summary| taker.start_swap(&summary.swap_id));
                match outcome {
                    Ok(report) => {
                        info!("Taker {} won the race: {:?}", i + 1, report);
                        result.store(RESULT_SUCCESS, Relaxed);
                    }
                    Err(e) => {
                        warn!("Taker {} lost the admission race: {:?}", i + 1, e);
                        result.store(RESULT_FAILED, Relaxed);
                    }
                }
            });
        }
    });

    let outcomes: Vec<u8> = results.iter().map(|r| r.load(Relaxed)).collect();
    let success_count = outcomes.iter().filter(|&&r| r == RESULT_SUCCESS).count();
    info!("Race results: {:?} ({} winner)", outcomes, success_count);
    assert_eq!(
        success_count, 1,
        "exactly one admission may win the reservation race: {:?}",
        outcomes
    );
    let loser = outcomes
        .iter()
        .position(|&r| r == RESULT_FAILED)
        .expect("the losing taker must fail cleanly, not hang");

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    // Maker-side: the losing admission was refused. Taker-side: the refusal
    // arrived as a message and failed the swap fast.
    test_framework.assert_log("Rejecting swap ", &log_path);
    test_framework.assert_log("rejected swap", &log_path);

    // No reservation may leak from the rejected admission: the same maker
    // still serves the losing taker's later swap. The amount must fit the
    // post-race offer max: that tracks max(swap, regular), and the winner's
    // unswept incoming coin caps it just under the race amount.
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    generate_blocks(bitcoind, 1);

    let loser_taker = takers.get_mut(loser).unwrap();
    let retry_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(300_000), 1)
        .with_tx_count(3)
        .with_required_confirms(1)
        .with_preferred_makers(vec![maker_address.clone()]);
    let retry_summary = loser_taker
        .prepare_swap(retry_params)
        .expect("the losing taker's later swap must prepare");
    let retry_report = loser_taker
        .start_swap(&retry_summary.swap_id)
        .expect("the maker must serve a later swap after the rejected admission");
    info!(
        "Losing taker's later swap completed: {:?}",
        retry_report.swap_id
    );

    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker final balances - Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            balances.regular, balances.swap, balances.contract, balances.spendable
        );
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "Maker must hold no contract balance after both swaps settle"
        );
    }

    info!("Concurrent admission reservation conflict test completed successfully!");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
