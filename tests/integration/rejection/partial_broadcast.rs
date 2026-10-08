//! Partial funding broadcasts: a batch that is half on-chain must recover
//! instead of reading as never broadcast, and a restarted maker must not reuse
//! or misread the swap it left unfinished.

use bitcoin::Amount;
use openswap::{
    maker::{
        start_server,
        swap_tracker::{MakerSwapRecord, MakerSwapTracker},
        MakerServer,
    },
    protocol::common_messages::ProtocolVersion,
    taker::{
        swap_tracker::{ExchangeProgress, SwapTracker},
        SwapParams,
    },
};

use crate::test_framework::*;

use std::{
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::{Duration, Instant},
};

/// Poll the maker's swap tracker until the swap's timelock recovery has
/// reclaimed an outgoing contract; panics after `timeout`.
/// The phase field regresses to TimelockWaiting on later passes, so the
/// recovered-txid list is the durable signal.
fn wait_for_maker_timelock_recovery(
    data_dir: &std::path::Path,
    swap_id: &str,
    timeout: Duration,
) -> MakerSwapRecord {
    let start = Instant::now();
    loop {
        if let Ok(tracker) = MakerSwapTracker::load_or_create(data_dir) {
            if let Some(record) = tracker.get_record(swap_id) {
                if !record.recovery.outgoing_recovered.is_empty() {
                    return record.clone();
                }
            }
        }
        assert!(
            start.elapsed() <= timeout,
            "timed out waiting for maker timelock recovery of {}",
            swap_id
        );
        thread::sleep(Duration::from_secs(5));
    }
}

/// The maker's second funding broadcast fails with the first tx already sent.
/// The partial batch must not read as never broadcast: recovery keeps the
/// swap's material and reclaims the on-chain split via timelock.
#[world_test(
    maker_behaviors = [FailSecondBroadcast],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = protocol, sats = 500_000, makers = 1),
    cases = [
        maker_recovers_partial_broadcast_legacy(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Legacy,
            expected_spendable = 14_999_311,
        ),
        maker_recovers_partial_broadcast_taproot(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Taproot,
            expected_spendable = 14_999_463,
        ),
        maker_recovers_partial_broadcast_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
            expected_spendable = 14_999_311,
        ),
    ],
)]
fn run_maker_partial_broadcast<B: TestBackend>(
    world: &mut World,
    expected_spendable: u64,
    params: SwapParams,
) {
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();
    let swap_result = world.taker_mut().start(&swap_id);
    assert!(
        swap_result.is_err(),
        "the swap must fail when the maker's second broadcast fails"
    );

    let log_path = world.taker_log_path();
    assert_logged!(world, "Test behavior: failing the second");

    // The 30s idle timeout starts recovery; the timelock path then needs the
    // maker's outgoing timelock (150 CSV blocks from the contract broadcast).
    let record = wait_for_maker_timelock_recovery(
        &world.makers()[0].inner().data_dir,
        &swap_id,
        timelock_recovery_wait::<B>() + Duration::from_secs(120),
    );

    // One tx of the two-tx batch was recorded before the failure — per-tx
    // state, not a single end-of-batch flag.
    assert_eq!(
        record.funding_broadcast_txids.len(),
        1,
        "exactly the first funding tx may be recorded as broadcast"
    );
    assert_eq!(
        record.recovery.outgoing_recovered.len(),
        1,
        "the on-chain split must be timelock-recovered"
    );

    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("nothing to recover. Discarding swapcoins"),
        "a partial batch must never be discarded as never broadcast"
    );

    // The unsent split's inputs must return to the pool without a restart.
    let deadline = Instant::now() + Duration::from_secs(180);
    while world.makers()[0].inner().reserved_inputs().unwrap() != 0 {
        assert!(
            Instant::now() < deadline,
            "recovery left the unsent split's inputs reserved"
        );
        thread::sleep(Duration::from_secs(2));
    }

    // Finished recovery stops the maker, and its exit rearms the wallet backend.
    // Join without sending another stop, which would cancel our sync again.
    world.join_makers();

    world.mine(1);
    world.framework().wait_for_electrs_tip();
    world.makers()[0].sync();
    // Spendable after reclaiming the on-chain split.
    assert_balances!(world; {
        maker: { swap: 0, contract: 0, fidelity: BOND, spendable: expected_spendable },
    });
}

/// The taker's second funding broadcast fails with the first split already in
/// the mempool and a spare maker available. Substitution would delete the
/// on-chain split's recovery material, so the recorded phase — not the
/// backend's answer — must route the taker to recovery instead.
#[world_test(
    maker_behaviors = [Normal, Normal],
    takers = [FailSecondFundingBroadcast],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        spawn_ready_makers_and_mine(),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 1),
    cases = [
        taker_recovers_partial_broadcast_with_spare_maker(
            backend = BitcoindBackend,
            expected_spendable = 14_999_554,
        ),
        /// The same partial batch on Electrum: the backend can lag the session's own
        /// broadcast, so only the recorded phase keeps the spare maker unused and
        /// the recovery material intact.
        taker_recovers_partial_broadcast_with_spare_maker_electrum(
            backend = ElectrumBackend,
            expected_spendable = 14_999_554,
        ),
    ],
)]
fn run_taker_recovers_partial_broadcast_with_spare_maker(
    world: &mut World,
    expected_spendable: u64,
    params: SwapParams,
) {
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();
    let swap_result = world.taker_mut().start(&swap_id);
    assert!(
        swap_result.is_err(),
        "the swap must fail at the taker's second funding broadcast"
    );

    let log_path = world.taker_log_path();
    assert_logged!(world, "Test behavior: failing the second funding broadcast");

    // The chain check found split 1 in the mempool, so the spare maker must
    // stay unused and the recovery material must survive.
    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("substituting maker 0 with spare"),
        "substitution would delete the on-chain split's recovery material"
    );
    assert!(
        !log_contents.contains("Re-initializing funding after maker substitution"),
        "funding reinitialize destroys the on-chain split's swapcoins"
    );

    let tracker = SwapTracker::load_or_create(&world.temp_dir().join("taker1")).unwrap();
    let record = tracker
        .get_record(&swap_id)
        .expect("swap record must exist");
    assert_eq!(
        record.phase,
        openswap::taker::swap_tracker::SwapPhase::Failed
    );
    assert_eq!(
        record.failed_at_phase,
        Some(openswap::taker::swap_tracker::SwapPhase::FundsBroadcast),
        "the phase must be persisted before the broadcast loop"
    );
    assert!(
        matches!(
            record.makers[0].exchange,
            ExchangeProgress::Legacy(ref legacy) if legacy.prev_funding_broadcast
        ),
        "the broadcast milestone must be recorded before the loop, not after it"
    );
    assert_eq!(
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count(),
        2,
        "both splits' swapcoins must survive — no substitution cleanup"
    );

    // Recovery reclaims the on-chain split once its timelock matures.
    let recovery_start = Instant::now();
    while !world.taker().inner().is_recovery_complete() {
        assert!(
            recovery_start.elapsed() <= Duration::from_secs(360),
            "taker recovery did not complete in time"
        );
        thread::sleep(Duration::from_secs(5));
    }

    world.mine(1);
    world.framework().wait_for_electrs_tip();
    world.taker().sync();
    // Spendable after recovering the partial batch.
    assert_balances!(world; { taker: { swap: 0, contract: 0, spendable: expected_spendable } });
}

/// After a partial broadcast, the taker re-admits the same swap; the maker
/// must re-process its own contracts via the same-swap exemption in
/// `contract_txid_seen` instead of rejecting them as a replay.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [FailSecondBroadcast],
    takers = [ResumeAfterMakerDrop],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn maker_reprocesses_own_contracts_after_partial_broadcast(world: &mut World) {
    let preferred = vec![world.makers()[0].address()];
    let summary = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(2)
                .with_required_confirms(1)
                .with_preferred_makers(preferred),
        )
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();
    let swap_result = world.taker_mut().start(&swap_id);
    assert!(
        swap_result.is_err(),
        "the swap must fail: the resumed pass cannot re-fund the frozen plan"
    );

    let log_path = world.taker_log_path();
    assert_logged!(world, "Test behavior: maker 0 dropped mid-exchange");

    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !contents.contains("already in use"),
        "the maker's own persisted contracts must not read as a replay"
    );
    // Two passes over the same contract data: the resume re-entered contract
    // processing and crossed the replay check (the fee log sits behind it).
    assert_eq!(
        contents
            .matches(&format!(
                "Processing Taproot contract data for swap {swap_id}"
            ))
            .count(),
        2,
        "the resumed pass must re-enter contract processing"
    );
    assert_eq!(
        contents.matches("Fee calculation: incoming_total").count(),
        2,
        "the resumed pass must cross the same-swap replay check"
    );
    // Only the first pass's first tx made it on the wire; the resumed pass
    // funds nothing.
    assert_eq!(
        contents.matches("Broadcast Taproot contract tx").count(),
        1,
        "the resumed pass must not broadcast new funding"
    );
    assert!(
        !contents.contains("completed successfully"),
        "the swap must not complete"
    );
}

/// A maker restarted mid-swap must refuse a SwapDetails whose id belongs
/// to the unfinished swap its wallet still holds — re-admission would
/// double-fund it.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [SkipFundingBroadcast],
    // CrashBeforeRecovery keeps the taker's negotiated state after the failed
    // swap, so the test can resend the same SwapDetails afterwards.
    takers = [CrashBeforeRecovery],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn maker_refuses_unfinished_swap_id_after_restart(world: &mut World) {
    let preferred = vec![world.makers()[0].address()];
    let summary = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(preferred),
        )
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();

    // The maker persists both sides' swapcoins, then dies before funding: the
    // swap stays unfinished in its wallet.
    let swap_result = world.taker_mut().start(&swap_id);
    assert!(
        swap_result.is_err(),
        "the swap must fail when the maker skips its funding broadcast"
    );
    assert!(
        world.makers()[0]
            .inner()
            .wallet
            .read()
            .unwrap()
            .get_incoming_swapcoins_count()
            > 0,
        "the maker must hold unfinished swapcoins before the restart"
    );

    // Hold the timelocks still so the restarted maker's recovery cannot
    // resolve the swapcoins before the resend lands.
    world.framework().set_block_gen_paused(true);

    // Restart the maker the way the reboot tests do: the first init consumed
    // the passphrase, so re-supply it.
    let mut victim_config = world.makers()[0].inner().config.clone();
    victim_config.password = Some("integration-test".to_string());
    world.shutdown_makers();
    world.drop_makers();

    let restarted = Arc::new(MakerServer::init(victim_config).unwrap());
    let restarted_thread = {
        let maker = restarted.clone();
        thread::spawn(move || start_server(maker).unwrap())
    };
    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    // The taker reconnects with the same swap id. Admission must refuse it:
    // the id belongs to the unfinished swap on disk.
    let response = world
        .taker()
        .inner()
        .test_resend_swap_details(0)
        .expect("the resend itself must get an answer");
    match response {
        openswap::protocol::common_messages::MakerToTakerMessage::AckSwapDetails(ack) => {
            assert!(
                ack.tweakable_point.is_none(),
                "the restarted maker must reject the unfinished swap's id"
            );
        }
        other => panic!("expected AckSwapDetails, got {:?}", other),
    }

    assert_logged!(world, "Swap id belongs to an unfinished swap");

    world.framework().set_block_gen_paused(false);

    restarted.shutdown.store(true, Relaxed);
    restarted_thread.join().unwrap();
}
