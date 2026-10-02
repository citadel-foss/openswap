//! Integration test for concurrent taker openswap with limited maker liquidity.
//!
//! Setup: 2 takers with Normal behavior, 2 makers with Normal behavior.
//! Both takers run swaps concurrently via `thread::scope`, once per protocol.
//! Makers have limited liquidity (only enough for ~1 swap), so one taker
//! should succeed and the other should fail due to insufficient funds.
//! Coins are claimed at funding, so the loser fails there, never double-spends.

use bitcoin::Amount;
use openswap::{
    protocol::common_messages::ProtocolVersion, taker::SwapParams, wallet::AddressType,
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

#[world_test(
    backend = BitcoindBackend,
    makers = maker_count,
    takers = [Normal, Normal],
    cases = [
        legacy_limited_liquidity(
            protocol = ProtocolVersion::Legacy,
            maker_count = 2,
            expected_maker_spendable = [1250473, 1250436],
        ),
        taproot_limited_liquidity(
            protocol = ProtocolVersion::Taproot,
            maker_count = 2,
            expected_maker_spendable = [1250473, 1250436],
        ),
    ],
)]
fn concurrent_takers(
    world: &mut World,
    protocol: ProtocolVersion,
    expected_maker_spendable: [u64; 2],
) {
    // Fund each taker thrice with one 0.05 BTC UTXO (0.15 total), one per call so
    // each lands on a distinct address.
    let mut taker1_original_balance = Amount::ZERO;
    let mut taker2_original_balance = Amount::ZERO;
    for _ in 0..3 {
        taker1_original_balance = world.fund_nth_taker_default(0, 1);
        taker2_original_balance = world.fund_nth_taker_default(1, 1);
    }
    world.fund_makers(1, Amount::from_sat(5_500_000), AddressType::P2TR);
    for _ in 0..3 {
        world.fund_makers(1, Amount::from_sat(250_000), AddressType::P2TR);
    }

    // Start the makers, wait for their setup, then sync their wallets so the
    // fidelity bonds are accounted for
    log::info!("Starting Maker servers...");
    world.start_makers(120);

    // Collect pre-swap spendable balances (skip standard assertions since we use limited liquidity)
    let maker_spendable_balance: Vec<Amount> = world
        .makers()
        .iter()
        .enumerate()
        .map(|(i, maker)| {
            let balances = maker.balances();
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

    world.mine(1);

    // Use atomics for thread-safe result tracking
    let result1 = AtomicU8::new(RESULT_PENDING);
    let result2 = AtomicU8::new(RESULT_PENDING);

    thread::scope(|s| {
        let (taker1_slice, taker2_slice) = world.takers_mut().split_at_mut(1);
        let taker1 = &mut taker1_slice[0];
        let taker2 = &mut taker2_slice[0];

        let r1 = &result1;
        let r2 = &result2;

        s.spawn(move || {
            info!("Taker 1 starting concurrent {:?} openswap", protocol);
            let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
                .with_tx_count(3)
                .with_required_confirms(1);

            match taker1.prepare(swap_params) {
                Ok(summary) => match taker1.start(&summary.swap_id) {
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

            match taker2.prepare(swap_params) {
                Ok(summary) => match taker2.start(&summary.swap_id) {
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

    // With limited liquidity, we expect one to succeed and one to fail.
    // Both are admitted; the loser's maker runs out of coins at funding.
    assert_eq!(success_count, 1, "Exactly one taker should succeed");
    world
        .framework()
        .assert_log("InsufficientLiquidity", &world.taker_log_path());
    assert_eq!(
        completed_count, 2,
        "Both takers should have completed (success or failure)"
    );

    log::info!("All openswaps processed. Transactions complete.");

    // Sync all wallets
    for taker in world.takers() {
        taker.sync();
    }

    world.mine(1);

    for maker in world.makers() {
        maker.sync();
    }

    // ---- Verify balances ----
    let results = [r1, r2];
    for (i, taker) in world.takers().iter().enumerate() {
        let taker_balances = taker.balances();
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
    for (i, (maker, original_spendable)) in world
        .makers()
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        let balances = maker.balances();

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

    world.shutdown_makers();

    // `finish` drops the takers before stopping the framework, so their
    // background services shut down while bitcoind is still running.
}

/// Two takers race ONE maker whose liquidity funds exactly one swap, both
/// declaring the identical shape so the maker's deterministic planner draws
/// the same inputs for each admission. Both are admitted; exactly one may fund.
/// The loser finds no free coins at funding and fails cleanly, and no
/// reservation leaks — the maker still serves the losing taker's later swap.
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
    takers = [Normal, Normal],
    setup = [
        fund_nth_taker_default(0, 1),
        fund_nth_taker_default(1, 1),
        // The 0.05 BTC UTXO covers the fidelity bond; what remains plus the 250k
        // funds exactly one 500k swap, so a second admission can never fit.
        fund_makers(1, Amount::from_sat(5_500_000), AddressType::P2TR),
        fund_makers(1, Amount::from_sat(250_000), AddressType::P2TR),
        start_makers(120),
    ],
)]
fn funding_race_has_one_winner(world: &mut World) {
    let maker_spendable = world.makers()[0].balances().spendable;
    info!("Maker spendable before the race: {}", maker_spendable);
    world.mine(1);

    // 400k twice would not fit the ~750k pool; one always fits, even after
    // the winner's swap shrinks the maker's offer max below the race amount.
    let maker_address = world.makers()[0].address();
    let swap_params = || {
        SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(400_000), 1)
            .with_tx_count(3)
            .with_required_confirms(1)
            .with_preferred_makers(vec![maker_address.clone()])
    };

    // Barrier-start both takers: the tightest sequencing the framework
    // offers, so both admissions plan over the same coins.
    let start = Arc::new(Barrier::new(2));
    let results = [AtomicU8::new(RESULT_PENDING), AtomicU8::new(RESULT_PENDING)];

    thread::scope(|s| {
        for (i, taker) in world.takers_mut().iter_mut().enumerate() {
            let barrier = start.clone();
            let result = &results[i];
            let params = swap_params();
            s.spawn(move || {
                barrier.wait();
                info!("Taker {} entering the admission race", i + 1);
                let outcome = taker
                    .prepare(params)
                    .and_then(|summary| taker.start(&summary.swap_id));
                match outcome {
                    Ok(report) => {
                        info!("Taker {} won the race: {:?}", i + 1, report);
                        result.store(RESULT_SUCCESS, Relaxed);
                    }
                    Err(e) => {
                        warn!("Taker {} lost the funding race: {:?}", i + 1, e);
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
        "exactly one swap may win the funding race: {:?}",
        outcomes
    );
    let loser = outcomes
        .iter()
        .position(|&r| r == RESULT_FAILED)
        .expect("the losing taker must fail cleanly, not hang");

    // Maker-side: the loser's planned coin was taken and no free coin could
    // replace it, proving both swaps raced on identical plans.
    world
        .framework()
        .assert_log("InsufficientLiquidity", &world.taker_log_path());

    // No reservation may leak from the lost funding race: the same maker
    // still serves the losing taker's later swap. The amount must fit the
    // post-race offer max: that tracks max(swap, regular), and the winner's
    // unswept incoming coin caps it just under the race amount.
    world.sync_makers();
    world.mine(1);

    let loser_taker = &mut world.takers_mut()[loser];
    let retry_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(300_000), 1)
        .with_tx_count(3)
        .with_required_confirms(1)
        .with_preferred_makers(vec![maker_address.clone()]);
    let retry_summary = loser_taker
        .prepare(retry_params)
        .expect("the losing taker's later swap must prepare");
    let retry_report = loser_taker
        .start(&retry_summary.swap_id)
        .expect("the maker must serve a later swap after the lost funding race");
    info!(
        "Losing taker's later swap completed: {:?}",
        retry_report.swap_id
    );

    for maker in world.makers() {
        maker.sync();
        let balances = maker.balances();
        info!(
            "Maker final balances - Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            balances.regular, balances.swap, balances.contract, balances.spendable
        );
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "Maker must hold no contract balance after both swaps settle"
        );
        // The retry only proves the maker can serve again. A reservation that
        // leaked on inputs the retry never needed would still let it through.
        assert_eq!(
            maker.inner().reserved_inputs().unwrap(),
            0,
            "the lost funding race must leave no reserved input behind"
        );
    }

    info!("Concurrent funding race test completed successfully!");
}

/// Two takers are admitted on the same maker coins, which the deterministic
/// planner gives both swaps. The first to fund claims them; the second maker
/// re-plans onto its other coin instead of failing, so both swaps complete.
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
    takers = [Normal, Normal],
    setup = [
        fund_nth_taker_default(0, 1),
        fund_nth_taker_default(1, 1),
        // The bond takes the 0.05 BTC coin. Two equal 500k coins remain: each
        // funds one swap alone, and a one-split plan picks the same one for both.
        fund_makers(1, Amount::from_sat(5_000_243), AddressType::P2TR),
        fund_makers(2, Amount::from_sat(500_000), AddressType::P2TR),
        start_makers(120),
        mine(1),
    ],
)]
fn funding_conflict_replans_onto_free_coins(world: &mut World) {
    let maker_address = world.makers()[0].address();
    let params = || {
        SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(300_000), 1)
            .with_tx_count(1)
            .with_required_confirms(1)
            .with_preferred_makers(vec![maker_address.clone()])
    };
    // Admit both before either funds, so both plans name the same coin.
    let summaries: Vec<_> = world
        .takers_mut()
        .iter_mut()
        .map(|taker| taker.prepare(params()).expect("admission must succeed"))
        .collect();

    let results = [AtomicU8::new(RESULT_PENDING), AtomicU8::new(RESULT_PENDING)];
    thread::scope(|s| {
        for ((taker, summary), result) in
            world.takers_mut().iter_mut().zip(&summaries).zip(&results)
        {
            s.spawn(move || match taker.start(&summary.swap_id) {
                Ok(_) => result.store(RESULT_SUCCESS, Relaxed),
                Err(e) => {
                    warn!("Swap {} failed: {:?}", summary.swap_id, e);
                    result.store(RESULT_FAILED, Relaxed);
                }
            });
        }
    });

    assert!(
        results.iter().all(|r| r.load(Relaxed) == RESULT_SUCCESS),
        "both swaps must complete: the second maker re-plans onto its free coin"
    );
    assert_logged!(world, "a planned coin went to another swap");
    assert_eq!(
        world.makers()[0].inner().reserved_inputs().unwrap(),
        0,
        "both settled swaps must have released their coins"
    );
}
