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
use std::{thread, time::Duration};

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
    world.fund_taker_default(3);

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
    // Over Tor the offers can still be under verification here.
    world
        .taker()
        .wait_for_good_makers(maker_count, Duration::from_secs(300));

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
        info!("Waiting for maker 0 to refund its outgoing by timelock...");
        wait_for_log(
            &log_path,
            "First maker refunded its outgoing by timelock",
            timelock_recovery_wait::<B>(),
        );
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
        wait_until!(
            timelock_recovery_wait::<B>(),
            every Duration::from_secs(5),
            "the live makers to settle",
            !world.makers().iter().enumerate().any(|(i, maker)| {
                let wallet = maker.inner().wallet.read().unwrap();
                Some(i) != dead
                    && wallet.get_incoming_swapcoins_count() + wallet.get_outgoing_swapcoins_count()
                        > 0
            })
        );
        // A hashlock claim and a timelock refund never both happen: no refund at all.
        if ending != Ending::MiddleMakerDies {
            // Nobody may refund a swap that settled by hashlock.
            assert_log!(log_path; { lacks "Timelock recovery tx " });
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
    let (expected_makers, (taker_regular, taker_swap, taker_spendable)) = match ending {
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
        assert_eq!(balances.fidelity, BOND);
        maker_balances.push((balances.regular.to_sat(), balances.swap.to_sat()));
    }
    assert_eq!(maker_balances, expected_makers, "maker balances mismatch");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.taker().sync();
    assert_balances!(world; {
        taker: {
            regular: taker_regular,
            swap: taker_swap,
            contract: 0,
            fidelity: 0,
            spendable: taker_spendable,
        },
    });

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
        fund_taker_default(3),
        // Fund the makers with 4 UTXOs of 0.05 BTC each
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
)]
fn taker_broadcasts_contract_after_full_setup(world: &mut World) {
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

    // Recovery takes the 60s maker idle timeout (test builds) plus the 225-block
    // outer-hop timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers), about
    // 135s at 5 blocks/3s; 300s bounds the wait.
    // Makers recover their outgoing funds via timelock, losing some to the taker
    // maliciously broadcasting contracts.
    info!("Waiting for makers to recover their outgoing funds via timelock...");
    world.wait_makers_settled(Duration::from_secs(300));
    world.sync_makers();
    assert_balances!(world; {
        makers: { regular: [14998419, 14998419], swap: 0, contract: 0, fidelity: BOND },
    });

    // Wait for taker's background recovery loop to finish
    info!("Waiting for background recovery loop to complete...");
    world.taker().await_recovery(Duration::from_secs(420));
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.taker().sync();

    // Only the contract and fidelity balances are asserted here.
    assert_balances!(world; { taker: { contract: 0, fidelity: 0 } });

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
        fund_taker_default(3),
        // Fund the makers with 4 UTXOs of 0.05 BTC each
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
)]
fn taproot_maker_broadcasts_contract(world: &mut World) {
    let before = world.balances();

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

    // Recovery takes the 60s maker idle timeout (test builds) plus the 225-block
    // outer-hop timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers), about
    // 135s at 5 blocks/3s; 300s bounds the wait.
    info!("Waiting for makers to recover their contracts...");
    world.wait_makers_settled(Duration::from_secs(300));
    world.sync_makers();
    assert_balances!(world; { makers: { contract: 0 } });

    // Shut down makers
    world.shutdown_makers();

    world.sync_makers();

    info!("Makers shut down. Waiting for background recovery loop to complete...");

    // The background recovery loop (spawned by recover_active_swap) periodically
    // retries hashlock sweeps and timelock recovery. Wait for it to finish.
    world.taker().await_recovery(Duration::from_secs(420));
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.taker().sync();

    // Makers should have recovered their outgoing funds via timelock. Nobody
    // earns a fee here; each maker only pays for its own recovery. The taker
    // recovered its own funding, so it only pays the recovery fees too.
    assert_balances!(world, since before; {
        taker: { regular: 14999706, swap: 0, contract: 0, fidelity: 0, loss: 294 },
        makers: { regular: [14999463, 14999463], swap: 0, contract: 0, fidelity: BOND, loss: 294 },
    });

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

    assert_balances!(world; { makers: { contract: 0 } });
    for (i, maker) in world.makers().iter().enumerate() {
        assert_eq!(
            maker.balances().regular,
            regular_before[i],
            "Maker {i} regular balance changed: its funding must not have been broadcast"
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

    assert_breach_refused(world);

    // Observed in a real run: each maker swept its incoming contract via the
    // hashlock. A maker that had handed over its outgoing leg would be ~500k short.
    info!("Waiting for makers to recover on-chain...");
    world.wait_makers_settled(timelock_recovery_wait::<BitcoindBackend>());
    world.sync_makers();
    assert_balances!(world; {
        makers: { regular: [14500865, 14502398], swap: [499100, 497530], contract: 0 },
    });
}

/// The maker refused because of the breach, not for any other reason.
fn assert_breach_refused(world: &World) {
    assert_log!(world; { has "ContractBroadcast" });
}
