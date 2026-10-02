//! Contract breach: a party broadcasts its contract transactions mid-swap.
//!
//! The scenario below is the maker's breach; the tests after it cover a
//! Taproot maker's, and a taker breaching before maker funding, before the
//! key handover, and after full setup.
//!
//! The maker's breach in detail:
//!
//! Scenario:
//! 1. Taker initiates a Legacy openswap with 2 makers.
//! 2. Maker[1] (second maker) broadcasts its outgoing contract txs after setup
//!    and closes the connection (BroadcastContractAfterSetup behavior).
//! 3. Taker detects the failure and triggers recovery (recover_active_swap).
//! 4. The taker sweeps its incoming contract with the swap preimage. Having
//!    claimed it, the taker never refunds its outgoing: a swap settles one way.
//! 5. Maker[1] comes back online, reads the preimage off the taker's sweep and
//!    claims its incoming. That spend hands the preimage to Maker[0], which then
//!    claims the taker's outgoing. Nobody refunds; the swap settles in full.
//! 6. If Maker[1] never returns, Maker[0] never learns the preimage and refunds
//!    its outgoing. The taker's outgoing then dangles: nobody else can ever
//!    claim it, so the taker refunds it once its own timelock expires.
//! 7. If Maker[0] sleeps past the taker's timelock, the taker holds its refund
//!    and Maker[0] still claims by hashlock when it wakes.
//! 8. With three makers, a dead middle maker leaves Maker[0] refunding while the
//!    last maker claims: the taker refunds, judging by Maker[0]'s contracts alone.

use bitcoin::Amount;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use crate::test_framework::*;

use log::info;
use std::{
    thread,
    time::{Duration, Instant},
};

/// How the swap ends after the last maker broadcasts and drops out.
#[derive(Clone, Copy, PartialEq)]
enum Ending {
    /// The faulty maker returns and every maker claims by hashlock.
    FaultyReturns,
    /// The faulty maker never returns: Maker[0] refunds, then the taker.
    FaultyGone,
    /// The faulty maker returns while Maker[0] sleeps past the taker's timelock.
    FirstMakerLate,
    /// Three makers: the middle one dies and the faulty last one returns.
    MiddleMakerDies,
}

/// Test: Maker maliciously broadcasts contract txs after setup.
///
/// The last maker completes the contract exchange, then broadcasts its outgoing
/// contract transactions and closes the connection; each case's ending decides
/// how the swap settles from there. This is the only scenario driving the
/// taker's breach detector, so `tor_maker_broadcasts_contract` runs it over Tor too.
#[world_test(
    makers = behaviors.len(),
    maker_behaviors = behaviors,
    takers = [taker_behavior],
    cases = [
        maker_broadcasts_contract(
            backend = BitcoindBackend,
            behaviors = [
                MakerBehavior::Normal,
                MakerBehavior::BroadcastContractAfterSetup,
            ],
            taker_behavior = TakerBehavior::Normal,
            expect_direct_breach_detection = false,
            ending = Ending::FaultyReturns,
        ),
        breach_detected_after_watcher_exit(
            backend = BitcoindBackend,
            behaviors = [
                MakerBehavior::Normal,
                MakerBehavior::BroadcastContractAfterSetup,
            ],
            taker_behavior = TakerBehavior::StopWatcherAfterSentinels,
            expect_direct_breach_detection = true,
            ending = Ending::FaultyReturns,
        ),
        /// Maker[1] never returns. The taker refunds its outgoing only after proving
        /// Maker[0] refunded its own, so nobody else could ever claim it.
        taker_refunds_dangling_outgoing(
            backend = BitcoindBackend,
            behaviors = [
                MakerBehavior::Normal,
                MakerBehavior::BroadcastContractAfterSetup,
            ],
            taker_behavior = TakerBehavior::Normal,
            expect_direct_breach_detection = false,
            ending = Ending::FaultyGone,
        ),
        /// Maker[0] sleeps past the taker's timelock. The taker holds its refund, so
        /// Maker[0] still claims by hashlock when it wakes.
        taker_holds_refund_for_late_first_maker(
            backend = BitcoindBackend,
            behaviors = [
                MakerBehavior::Normal,
                MakerBehavior::BroadcastContractAfterSetup,
            ],
            taker_behavior = TakerBehavior::Normal,
            expect_direct_breach_detection = false,
            ending = Ending::FirstMakerLate,
        ),
        /// Three makers, and the middle one dies after the last one claims from it.
        /// Only Maker[0]'s refund matters: the taker refunds its dangling outgoing.
        taker_refunds_past_dead_middle_maker(
            backend = BitcoindBackend,
            behaviors = [
                MakerBehavior::Normal,
                MakerBehavior::Normal,
                MakerBehavior::BroadcastContractAfterSetup,
            ],
            taker_behavior = TakerBehavior::Normal,
            expect_direct_breach_detection = false,
            ending = Ending::MiddleMakerDies,
        ),
        /// Malicious contract broadcast over Tor, exercising the taker's breach detector.
        #[ignore = "requires a bootstrapped tor and OPENSWAP_TOR_IT=1"]
        tor_maker_broadcasts_contract(
            backend = TorElectrumBackend,
            skip_unless = tor_it_enabled(),
            behaviors = [
                MakerBehavior::Normal,
                MakerBehavior::BroadcastContractAfterSetup,
            ],
            taker_behavior = TakerBehavior::Normal,
            expect_direct_breach_detection = false,
            ending = Ending::FaultyReturns,
        ),
    ],
)]
fn run_contract_breach<B: TestBackend>(
    world: &mut World,
    expect_direct_breach_detection: bool,
    ending: Ending,
) {
    let maker_count = world.makers().len();
    let last = maker_count - 1;

    // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Legacy)
    let taker_original_balance = world.fund_taker_default(3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    world.fund_makers_default();

    // Start the makers, wait for their setup, then sync their wallets
    log::info!("Starting Maker servers...");
    world.start_makers(120);

    world.verify_maker_pre_swap_balances();
    log::info!("Starting contract breach test...");

    // Start periodic swap tracker logging (every 10s)
    let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

    // Swap params for openswap (Legacy)
    let swap_params = SwapParams::new(
        ProtocolVersion::Legacy,
        Amount::from_sat(500000),
        maker_count,
    )
    .with_tx_count(1)
    .with_required_confirms(1);

    world.mine(1);

    // Prepare should succeed; execution should fail because maker broadcasts contracts
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to maker BroadcastContractAfterSetup behavior"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    if expect_direct_breach_detection {
        wait_for_log(
            &world.taker_log_path(),
            "Breach detector: contract tx",
            Duration::from_secs(30),
        );
    }
    world.taker().log_tracker_state();

    let log_path = world.taker_log_path();
    // A dead maker stays offline: it must never learn the preimage.
    let dead = (ending == Ending::MiddleMakerDies).then_some(1);
    if ending == Ending::FaultyGone {
        // Maker[0] never learns the preimage: its outgoing matures and it refunds.
        info!("Waiting for makers to timeout and blocks to mature timelocks...");
        thread::sleep(timelock_recovery_wait::<B>());
    } else {
        if let Some(i) = dead {
            world.shutdown_maker(i);
        }
        if ending == Ending::FirstMakerLate {
            world.shutdown_maker(0);
        }
        world.restart_maker(last, 120);
        if ending == Ending::FirstMakerLate {
            // Our timelock matures while Maker[0] sleeps: the coin stays its to claim.
            wait_for_log(
                &log_path,
                "Holding refund of",
                timelock_recovery_wait::<B>() * 2,
            );
            world.restart_maker(0, 120);
        }
        if ending == Ending::MiddleMakerDies {
            wait_for_log(
                &log_path,
                "First maker refunded its outgoing by timelock",
                timelock_recovery_wait::<B>() * 2,
            );
        }

        // Every live maker settles and drops its swapcoins.
        info!("Waiting for the live makers to settle...");
        let settle_start = Instant::now();
        while world.makers().iter().enumerate().any(|(i, maker)| {
            let wallet = maker.inner().wallet.read().unwrap();
            Some(i) != dead
                && wallet.get_incoming_swapcoins_count() + wallet.get_outgoing_swapcoins_count() > 0
        }) {
            assert!(
                settle_start.elapsed() < timelock_recovery_wait::<B>(),
                "makers did not settle"
            );
            thread::sleep(Duration::from_secs(5));
        }
        // A hashlock claim and a timelock refund never both happen: no refund at all.
        if ending != Ending::MiddleMakerDies {
            assert!(
                !std::fs::read_to_string(&log_path)
                    .unwrap()
                    .contains("Timelock recovery tx "),
                "nobody may refund a swap that settled by hashlock"
            );
        }
    }

    info!("Waiting for background recovery loop to complete...");

    // The background recovery loop (spawned by recover_active_swap) periodically
    // retries hashlock sweeps and timelock recovery. Wait for it to finish.
    world.taker().await_recovery(Duration::from_secs(120));
    info!("Background recovery loop completed.");
    if ending == Ending::FaultyGone {
        wait_for_log(
            &log_path,
            "First maker refunded its outgoing by timelock",
            Duration::from_secs(30),
        );
    }

    // (regular, swap) per live maker, then the taker's (regular, swap, spendable).
    // Settled by hashlock, the taker paid its outgoing as in a completed swap;
    // dangling, it refunded it on top of its claim.
    let (expected_makers, expected_taker) = match ending {
        Ending::FaultyReturns | Ending::FirstMakerLate => (
            vec![(14500543, 499700), (14501446, 498760)],
            (14499846, 497857, 14997703),
        ),
        Ending::FaultyGone => (
            vec![(14999311, 0), (14501446, 0)],
            (14999554, 497857, 15497411),
        ),
        Ending::MiddleMakerDies => (
            vec![(14999311, 0), (14502424, 497782)],
            (14999554, 496879, 15496433),
        ),
    };

    let mut maker_balances = Vec::new();
    for (i, maker) in world
        .makers()
        .iter()
        .enumerate()
        .filter(|(i, _)| Some(*i) != dead)
    {
        maker.sync();
        let balances = maker.balances();
        info!("Maker {} balances after recovery: {:?}", i, balances);
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "Maker {} contract balance",
            i
        );
        assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());
        maker_balances.push((balances.regular.to_sat(), balances.swap.to_sat()));
    }
    assert_eq!(maker_balances, expected_makers, "maker balances mismatch");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.taker().sync();
    let balances = world.taker().balances();
    info!(
        "Taker balances after recovery: {:?} (original: {})",
        balances, taker_original_balance
    );
    assert_eq!(balances.contract, Amount::ZERO, "Taker contract balance");
    assert_eq!(balances.fidelity, Amount::ZERO);
    assert_eq!(
        (
            balances.regular.to_sat(),
            balances.swap.to_sat(),
            balances.spendable.to_sat()
        ),
        expected_taker,
        "taker balances mismatch"
    );

    world.taker().log_tracker_state();
    info!("Malice2 test completed successfully!");

    world.shutdown_makers();

    tracker_logger.stop();
}

/// Test: Taker maliciously broadcasts contract txs after full setup.
///
/// The taker completes the full contract exchange, then broadcasts contract
/// transactions and closes. Makers detect the on-chain contracts and recover
/// their funds via timelock spending.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [BroadcastContractAfterFullSetup],
    setup = [
        // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Legacy)
        fund_taker_default(3) as taker_original_balance,
        // Fund the makers with 4 UTXOs of 0.05 BTC each
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances() as maker_spendable_balance,
    ],
)]
fn taker_broadcasts_contract_after_full_setup(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
) {
    // Swap params for openswap (Legacy)
    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    // Prepare should succeed; execution should fail with BroadcastContractAfterFullSetup
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to BroadcastContractAfterFullSetup behavior"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    world.taker().log_tracker_state();

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    // Verify maker balances -- makers should have recovered their outgoing funds via timelock
    let expected_regular = [14998419, 14998419];
    for (i, (maker, original)) in world
        .makers()
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        maker.sync();
        let balances = maker.balances();
        info!(
            "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.spendable,
        );
        BalanceExpect {
            regular: Some(Is::Sats(expected_regular[i])),
            swap: Some(Is::Sats(0)),
            contract: Some(Is::Sats(0)),
            fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
            spendable: None,
            delta: None,
        }
        .assert(&format!("Maker {i}"), &balances);

        // Makers lost some funds due to taker maliciously broadcasting contracts
        let maker_diff = original
            .checked_sub(balances.spendable)
            .unwrap_or(Amount::ZERO);
        info!(
            "Maker {} lost {} sats (pre-swap: {}, current: {})",
            i,
            maker_diff.to_sat(),
            original,
            balances.spendable,
        );
    }

    // Wait for taker's background recovery loop to finish
    info!("Waiting for background recovery loop to complete...");
    world.taker().await_recovery(Duration::from_secs(120));
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.taker().sync();

    // Verify taker balance
    let taker_balances = world.taker().balances();

    info!(
        "Taker balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    // Only the contract and fidelity balances are asserted here.
    BalanceExpect {
        regular: None,
        swap: None,
        contract: Some(Is::Sats(0)),
        fidelity: Some(Is::Amount(Amount::ZERO)),
        spendable: None,
        delta: None,
    }
    .assert("Taker", &taker_balances);

    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap_or(Amount::ZERO);

    info!(
        "Taker balance diff: {} sats (original: {}, current: {})",
        balance_diff.to_sat(),
        taker_original_balance,
        taker_balances.spendable,
    );

    world.taker().log_tracker_state();
    info!("Malice1 test completed successfully!");
}

/// Test: Maker locks its funds on-chain after setup, then closes.
///
/// Maker[1] broadcasts its contract transaction and closes without sending
/// its contract-data response. The taker detects the failure and all parties
/// recover via timelock.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, BroadcastContractAfterSetup],
    takers = [Normal],
    setup = [
        // Fund the taker with 3 UTXOs of 0.05 BTC each
        fund_taker_default(3) as taker_original_balance,
        // Fund the makers with 4 UTXOs of 0.05 BTC each
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances() as maker_spendable_balance,
    ],
)]
fn taproot_maker_broadcasts_contract(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
) {
    // Start periodic swap tracker logging (every 10s)
    let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

    // Swap params for openswap (Taproot)
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count(1)
        .with_required_confirms(1);

    world.mine(1);

    // Prepare should succeed; execution should fail because maker broadcasts contracts
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to maker BroadcastContractAfterSetup behavior"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    world.taker().log_tracker_state();

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    // Shut down makers
    world.shutdown_makers();

    // Log all maker balances before asserting so one run reports every value.
    let mut maker_balances_all = Vec::new();
    for (i, maker) in world.makers().iter().enumerate() {
        maker.sync();
        let maker_balances = maker.balances();
        info!(
            "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i,
            maker_balances.regular,
            maker_balances.swap,
            maker_balances.contract,
            maker_balances.spendable,
        );
        maker_balances_all.push(maker_balances);
    }

    info!("Makers shut down. Waiting for background recovery loop to complete...");

    // The background recovery loop (spawned by recover_active_swap) periodically
    // retries hashlock sweeps and timelock recovery. Wait for it to finish.
    world.taker().await_recovery(Duration::from_secs(120));
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.taker().sync();

    let taker_balances = world.taker().balances();

    info!(
        "Taker balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    // Verify maker balances -- makers should have recovered their outgoing funds via timelock.
    // Nobody earns a fee here; each maker only pays for its own recovery.
    let expected_regular = [14999463, 14999463];
    for (i, (maker_balances, original)) in maker_balances_all
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        BalanceExpect {
            regular: Some(Is::Sats(expected_regular[i])),
            swap: Some(Is::Sats(0)),
            contract: Some(Is::Sats(0)),
            fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
            spendable: None,
            delta: Some(Delta::Loss {
                baseline: original,
                style: DiffStyle::UnwrapOrZero,
                sats: 294,
            }),
        }
        .assert(&format!("Maker {i}"), maker_balances);
    }

    // Verify taker balance. The taker recovered its own funding, so it only
    // pays the recovery fees.
    BalanceExpect {
        regular: Some(Is::Sats(14999706)),
        swap: Some(Is::Sats(0)),
        contract: Some(Is::Sats(0)),
        fidelity: Some(Is::Amount(Amount::ZERO)),
        spendable: None,
        delta: Some(Delta::Loss {
            baseline: taker_original_balance,
            style: DiffStyle::UnwrapOrZero,
            sats: 294,
        }),
    }
    .assert("Taker", &taker_balances);

    // TODO: the maker that broadcasts its contract is never banned. The swap
    // aborts on the transport error before the ContractsBroadcasted ban site, and
    // the breach detector fires on the taker's OWN recovery broadcast, so its
    // signal cannot attribute the breach to a maker.
    // assert_only_makers_banned(taker, &makers, &[1]);

    world.taker().log_tracker_state();
    info!("Taproot maker malice test completed successfully!");

    tracker_logger.stop();
}

/// Breach before maker 0 funds: maker 0 must not broadcast its funding txs.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [BroadcastContractBeforeMakerFunding],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn taker_broadcasts_contract_before_maker_funding(world: &mut World, params: SwapParams) {
    let regular_before: Vec<Amount> = world
        .makers()
        .iter()
        .map(|m| m.balances().regular)
        .collect();

    world.mine(1);

    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(swap_result.is_err(), "Swap must fail: maker 0 never funds");
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

    // The first maker reached its funding step and saved the signed swapcoins,
    // then refused because of the breach rather than for any other reason.
    assert!(
        world.makers().iter().any(|m| m
            .inner()
            .has_unfinished_outgoing_swapcoin(&summary.swap_id)
            .unwrap()),
        "No maker saved the swap's outgoing swapcoins"
    );

    // Let any stray maker broadcast confirm before comparing balances.
    thread::sleep(Duration::from_secs(20));
    world.sync_makers();
    assert_breach_refused(world);

    for (i, maker) in world.makers().iter().enumerate() {
        let balances = maker.balances();
        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.spendable
        );
        assert_eq!(
            balances.regular, regular_before[i],
            "Maker {i} regular balance changed: its funding must not have been broadcast"
        );
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "Maker {i} contract balance"
        );
    }
}

/// Breach after full setup: maker 0 must refuse the key handover and recover.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [BroadcastContractBeforeHandover],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn taker_broadcasts_contract_before_handover(world: &mut World, params: SwapParams) {
    world.mine(1);

    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap must fail: maker 0 refuses the handover"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

    info!("Waiting for makers to recover on-chain...");
    thread::sleep(timelock_recovery_wait::<BitcoindBackend>());
    world.sync_makers();
    assert_breach_refused(world);

    // Observed in a real run: each maker swept its incoming contract via the
    // hashlock. A maker that had handed over its outgoing leg would be ~500k short.
    let expected_regular = [14500865, 14502398];
    let expected_swap = [499100, 497530];
    for (i, maker) in world.makers().iter().enumerate() {
        let balances = maker.balances();
        info!(
            "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.spendable
        );
        BalanceExpect {
            regular: Some(Is::Sats(expected_regular[i])),
            swap: Some(Is::Sats(expected_swap[i])),
            contract: Some(Is::Amount(Amount::ZERO)),
            fidelity: None,
            spendable: None,
            delta: None,
        }
        .assert(&format!("Maker {i}"), &balances);
    }
}

/// The maker refused because of the breach, not for any other reason.
fn assert_breach_refused(world: &World) {
    assert_logged!(world, "ContractBroadcast");
}
