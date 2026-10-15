//! Two Normal makers; the taker drops at a given step once funding is on-chain,
//! and every party timelock-recovers. Each case's taker behavior sets its drop
//! point, and its golden balances pin how that drop point settles.
//! `taproot_drop_at_ack_response` drops before any funding, so nothing needs
//! recovering; `maker_recovers_swap_past_refund_deadline` has the taker stall
//! instead. The input-claim tests check that a dropped or refused swap's coins
//! stay out of the next plan.

use bitcoin::{Amount, OutPoint};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, Taker, TakerBehavior},
};

use crate::test_framework::*;

use log::info;
use std::time::Duration;

/// The balances one taker-abort test asserts once recovery is done.
struct TakerAbortExpect {
    maker_regular: [u64; 2],
    /// Each maker's pre-swap spendable balance minus its final one; `None`
    /// where the test does not assert it.
    maker_loss: Option<[u64; 2]>,
    taker_regular: u64,
    /// Taker funding minus its final spendable balance.
    taker_loss: u64,
}

/// Drives one taker-drop case through timelock recovery and asserts the
/// golden balances that pin how that drop point settles.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [behavior],
    cases = [
        /// Taker aborts at sender's contract exchange (Taproot).
        ///
        /// The taker drops the connection when about to send sender's contract data
        /// to a maker. Funding transactions are already on-chain, so timelock
        /// recovery is required for all parties to reclaim their funds.
        taproot_drop_at_senders_contract(
            behavior = TakerBehavior::CloseAtSendersContract,
            expected = &TakerAbortExpect {
                maker_regular: [14999757; 2],
                maker_loss: None,
                taker_regular: 14999085,
                taker_loss: 915,
            },
        ),
        /// Taker aborts after receiving maker's contract response (Taproot).
        ///
        /// The taker drops the connection after receiving the maker's contract data
        /// response. Funding transactions are already on-chain, so timelock recovery
        /// is required.
        taproot_drop_after_makers_contract_response(
            behavior = TakerBehavior::CloseAtSendersContractFromMaker,
            expected = &TakerAbortExpect {
                maker_regular: [14998875, 14999757],
                maker_loss: Some([882, 0]),
                taker_regular: 14999085,
                taker_loss: 915,
            },
        ),
        /// Taker drops after full setup, before the private-key handover (Taproot).
        ///
        /// Recovery starts from the complete outgoing + incoming coin set: both
        /// makers timelock-refund whole, and the taker absorbs the swap amount plus
        /// every funding fee.
        taproot_drop_after_full_setup(
            behavior = TakerBehavior::BroadcastContractAfterFullSetup,
            expected = &TakerAbortExpect {
                maker_regular: [14998875, 14998875],
                maker_loss: Some([882, 882]),
                taker_regular: 14500000,
                taker_loss: 500000,
            },
        ),
    ],
)]
fn run_taproot_taker_abort(world: &mut World, expected: &TakerAbortExpect) {
    world.fund_taker_default(3);
    world.fund_makers_default();

    info!("Starting Maker servers...");
    world.start_makers(120);

    world.verify_maker_pre_swap_balances();
    let before = world.balances();

    let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    // Prepare should succeed; execution should fail at the case's drop point.
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to {:?} behavior",
        world.taker().inner().behavior
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    world.taker().log_tracker_state();

    // Recovery takes the 60s maker idle timeout (test builds) plus the 225-block
    // outer-hop timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers), about
    // 135s at 5 blocks/3s; 300s bounds the wait.
    info!("Waiting for makers to recover their outgoing funds via timelock...");
    world.wait_makers_settled(Duration::from_secs(300));
    world.sync_makers();
    assert_balances!(world, since before; {
        makers: {
            regular: expected.maker_regular,
            swap: 0,
            contract: 0,
            fidelity: BOND,
            loss: expected.maker_loss,
        },
    });

    // The background recovery loop (spawned by recover_active_swap) periodically
    // retries hashlock sweeps and timelock recovery. Wait for it to finish.
    world.taker().await_recovery(Duration::from_secs(420));
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.taker().sync();

    assert_balances!(world, since before; {
        taker: {
            regular: expected.taker_regular,
            swap: 0,
            contract: 0,
            fidelity: 0,
            loss: expected.taker_loss,
        },
    });

    world.taker().log_tracker_state();

    world.shutdown_makers();
    tracker_logger.stop();
}

/// Legacy on Core RPC: the taker drops right after broadcasting its funding.
/// The makers wait out their timeout, then everyone recovers via timelock.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [DropAfterFundsBroadcast],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn legacy_drop_after_funding(world: &mut World, params: SwapParams) {
    let before = world.balances();
    world.mine(1);

    // Start periodic swap tracker logging
    let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

    // Prepare should succeed; execution should fail with DropAfterFundsBroadcast
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to DropAfterFundsBroadcast behavior"
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

    // Wait for taker's background recovery loop to finish
    world.taker().await_recovery(Duration::from_secs(420));
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    world.taker().sync();

    // Makers should have recovered via timelock
    world.sync_makers();
    assert_balances!(world, since before; {
        taker: { regular: 14_500_000, swap: 495_502, contract: 0, fidelity: 0, loss: 4_498 },
        makers: {
            regular: [14_501_360, 14_502_893],
            swap: [498_605, 497_035],
            contract: 0,
            fidelity: BOND,
            spendable: [14_999_965, 14_999_928],
        },
    });

    world.taker().log_tracker_state();
    info!("Abort1 test completed successfully!");

    world.shutdown_makers();
    tracker_logger.stop();
}

/// A taker that never goes quiet must still not outlive the swap's locktime. Here the
/// taker keeps the route warm with keepalives while the miner pushes the tip past the
/// maker's refund deadline. The maker must stop honouring the keepalives and recover,
/// even though the connection was never dropped and the idle timeout never fired.
///
/// One maker on purpose: a single hop is funded with the full negotiated amount, so
/// the swap reaches the maker's outgoing funding without depending on route fees.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [StallAfterProofOfFunding],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    // Legacy so the deadline is counted from the funding confirmation height the
    // maker records, which is the arm this test exists to prove.
    swap(protocol = Legacy, sats = 500_000, makers = 1, tx_count = 1),
)]
fn maker_recovers_swap_past_refund_deadline(world: &mut World, params: SwapParams) {
    world
        .taker_mut()
        .swap_fails(params, "The swap must fail once the maker gives up on it");

    assert_log!(world; {
        has "Test behavior: stalling 180s so the maker's refund deadline passes",
        // The deadline, not a dropped connection, is what ended this swap. Keepalives
        // were still arriving every 5s, so the idle timeout could not have drained it.
        has "reached its refund deadline; recovering now",
        has "Recovering from swap",
    });
}

/// Test: Taker aborts at AckSwapDetails response (Taproot).
///
/// The taker closes the connection right after the Maker acknowledges the
/// swap details. No funding transactions have been broadcast at this point,
/// so no recovery is needed. Balances should remain unchanged.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [CloseAtAckResponse],
    setup = [
        // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Taproot)
        fund_taker_default(3),
        // Fund the makers with 4 UTXOs of 0.05 BTC each
        fund_makers_default(),
        // Start the maker server threads
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
)]
fn taproot_drop_at_ack_response(world: &mut World) {
    let before = world.balances();

    // Swap params for openswap (Taproot)
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    // Prepare should fail at AckResponse — the taker closes the connection
    // right after receiving AckSwapDetails, before any funding is broadcast.
    let prepare_result = world.taker_mut().prepare(swap_params.clone());
    assert!(
        prepare_result.is_err(),
        "Prepare should fail due to CloseAtAckResponse behavior"
    );
    info!(
        "Prepare failed as expected: {:?}",
        prepare_result.err().unwrap()
    );
    world.taker().inner().log_tracker_state();

    // The accepted-but-unfunded swap must be dropped without requiring a restart.
    wait_logged!(
        world,
        "Released idle unfunded swap",
        Duration::from_secs(60)
    );
    wait_until!(
        Duration::from_secs(15),
        every Duration::from_secs(1),
        "the early-abort reservations to be released after the idle timeout",
        !world
            .makers()
            .iter()
            .any(|maker| maker.inner().has_ongoing_swaps().unwrap())
    );

    // With the stale reservation gone, the makers must be back at full capacity:
    // a fresh swap request has to be accepted again. The maker only sends
    // AckSwapDetails after storing a new reservation, and the taker only emits
    // the CloseAtAckResponse test error after receiving that ack — so hitting
    // that exact error proves the makers accepted the retry.
    let retry_result = world.taker_mut().prepare(swap_params);
    let retry_err = format!(
        "{:?}",
        retry_result.expect_err("Retry should still abort at AckSwapDetails")
    );
    assert!(
        retry_err.contains("closing at ack response"),
        "Retry should have been accepted up to AckSwapDetails, got: {}",
        retry_err
    );
    assert!(
        world
            .makers()
            .iter()
            .any(|maker| maker.inner().has_ongoing_swaps().unwrap()),
        "Accepted retry should hold a fresh reservation on a maker"
    );

    // Sync taker wallet and verify balance
    world.taker().sync();

    // No contracts were created on-chain and no funds were lost, since no
    // transactions were broadcast.
    assert_balances!(world, since before; { taker: { contract: 0, loss: 0 } });

    world.taker().inner().log_tracker_state();
    info!("Taproot drop-at-ack-response test completed successfully!");
}

/// A dropped swap's funding inputs are spent, but the wallet's coin cache only
/// learns that at the next sync. Until then, a new plan must skip them.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [DropAfterFundsBroadcast],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    cases = [
        legacy_new_plan_skips_inputs_of_a_dropped_swap(protocol = ProtocolVersion::Legacy),
        taproot_new_plan_skips_inputs_of_a_dropped_swap(protocol = ProtocolVersion::Taproot),
    ],
)]
fn new_plan_skips_inputs_of_a_dropped_swap(world: &mut World, protocol: ProtocolVersion) {
    // One split, so the dropped swap spends one coin and leaves two.
    let amount = Amount::from_sat(500_000);
    let params = SwapParams::new(protocol, amount, 2)
        .with_tx_count(1)
        .with_required_confirms(1);
    let summary = world.taker_mut().prepare(params).expect("prepare");
    world
        .taker_mut()
        .start(&summary.swap_id)
        .expect_err("the taker drops after funding");

    // Same planner, same pool: without the lock it picks the coin just spent.
    let plan = world
        .taker()
        .inner()
        .get_wallet()
        .read()
        .unwrap()
        .plan_funding(amount, 1, 1.0, u32::MAX, None, None, None, protocol)
        .expect("two coins are still unspent");
    for outpoint in plan.iter().flat_map(|split| &split.utxos) {
        let unspent = world
            .bitcoind()
            .client
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))
            .unwrap();
        assert!(
            unspent.is_some(),
            "planned {}, already spent by the dropped swap",
            outpoint
        );
    }
}

/// Another swap claims the planned coins after `prepare_swap`. `start_swap`
/// must refuse before signing: nothing spent, no claim added, the other claim
/// untouched. That claim has no swap behind it, so a restart frees it.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    cases = [
        legacy_start_refuses_planned_coins_another_swap_claimed(protocol = ProtocolVersion::Legacy),
        taproot_start_refuses_planned_coins_another_swap_claimed(protocol = ProtocolVersion::Taproot),
    ],
)]
fn start_refuses_planned_coins_another_swap_claimed(world: &mut World, protocol: ProtocolVersion) {
    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 2)
        .with_tx_count(1)
        .with_required_confirms(1);
    let summary = world.taker_mut().prepare(params).expect("prepare");

    // Claim every coin, so whichever ones the plan took are held.
    let wallet = world.taker().inner().get_wallet().clone();
    let coins: Vec<OutPoint> = wallet
        .read()
        .unwrap()
        .list_descriptor_utxo_spend_info()
        .iter()
        .map(|(utxo, _)| OutPoint::new(utxo.txid, utxo.vout))
        .collect();
    wallet
        .write()
        .unwrap()
        .reserve_swap_locks_for_test("other-swap", &coins)
        .unwrap();

    let err = world
        .taker_mut()
        .start(&summary.swap_id)
        .expect_err("a planned coin another swap holds must stop the swap");
    assert!(
        format!("{err:?}").contains("no longer free"),
        "unexpected refusal: {:?}",
        err
    );
    assert_eq!(
        world.taker().inner().reserved_inputs().unwrap(),
        coins.len(),
        "the refusal must claim nothing and leave the other claim as it was"
    );
    assert_eq!(
        wallet.read().unwrap().get_outgoing_swapcoins_count(),
        0,
        "nothing may be signed for a refused swap"
    );
    for outpoint in &coins {
        let unspent = world
            .bitcoind()
            .client
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))
            .unwrap();
        assert!(
            unspent.is_some(),
            "{} was spent by a refused swap",
            outpoint
        );
    }

    drop(wallet);
    world.drop_takers();
    let restarted = Taker::init(world.framework().taker_init_config::<BitcoindBackend>(0))
        .expect("restarted taker should open the same wallet");
    assert_eq!(
        restarted.reserved_inputs().unwrap(),
        0,
        "a claim no unfinished swap owns must not survive a restart"
    );
    world.adopt_taker(restarted);
}
