//! Partial funding broadcasts: a batch that is half on-chain must recover
//! instead of reading as never broadcast, and a restarted maker must not reuse
//! or misread the swap it left unfinished.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerServer},
    protocol::common_messages::ProtocolVersion,
    taker::SwapParams,
};

use crate::test_framework::*;

use std::{
    collections::HashSet,
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::Duration,
};

/// Wait until the maker's timelock recovery reports, summed over all passes,
/// hold `expected` refund txids and its outgoing swapcoins are down to `left`.
fn wait_for_maker_timelock_recovery(
    maker: &MakerServer,
    swap_id: &str,
    expected: usize,
    left: usize,
    timeout: Duration,
) -> Vec<String> {
    wait_for!(
        timeout,
        every Duration::from_secs(5),
        format!("maker timelock recovery of {}", swap_id),
        {
            let reports = maker.wallet.read().unwrap().swap_reports();
            let txids: Vec<_> = reports
                .recovery
                .iter()
                .filter(|report| report.swap_id == swap_id && report.recovery_type == "timelock")
                .flat_map(|report| report.recovery_txids.clone())
                .collect();
            let cleaned = maker.wallet.read().unwrap().get_outgoing_swapcoins_count() == left;
            (txids.len() >= expected && cleaned).then_some(txids)
        }
    )
}

/// The maker's second funding broadcast fails with the first tx already sent.
/// The partial batch must not read as never broadcast: recovery keeps the
/// swap's material, sends the unsent split and reclaims both via timelock.
#[world_test(
    maker_behaviors = [FailSecondBroadcast],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = protocol, sats = 500_000, makers = 1),
    cases = [
        /// The unsent split is sent, locked and refunded too: 446 sats of fees.
        maker_recovers_partial_broadcast_legacy(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Legacy,
            expected_spendable = 14_998_865,
        ),
        /// The committed unsent split is sent and refunded too: 154 + 140 sats of fees.
        maker_recovers_partial_broadcast_taproot(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Taproot,
            expected_spendable = 14_999_169,
        ),
        maker_recovers_partial_broadcast_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
            expected_spendable = 14_998_865,
        ),
    ],
)]
fn run_maker_partial_broadcast<B: TestBackend>(
    world: &mut World,
    protocol: ProtocolVersion,
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

    assert_log!(world; { has "Test behavior: failing the second" });

    // The 30s idle timeout starts recovery; the timelock path then needs the
    // maker's outgoing timelock (150 CSV blocks from the contract broadcast).
    // Recovery sends the unsent split too. Legacy contracts both go out when
    // recovery starts, but a block between the two broadcasts can give them
    // different maturity, so their refunds may land in separate passes. A
    // Taproot split went out with the swap, so the resent one comes back later.
    let splits_left = match protocol {
        ProtocolVersion::Legacy => 0,
        ProtocolVersion::Taproot => 1,
    };
    let recovered = wait_for_maker_timelock_recovery(
        world.makers()[0].inner(),
        &swap_id,
        2 - splits_left,
        splits_left,
        timelock_recovery_wait::<B>() + Duration::from_secs(120),
    );

    assert_eq!(
        recovered.len(),
        2 - splits_left,
        "every sent split must be timelock-recovered"
    );

    // A partial batch must never be discarded as never broadcast.
    assert_log!(world; { lacks "nothing to recover. Discarding swapcoins" });

    let maker = world.makers()[0].inner();
    assert_eq!(
        maker.wallet.read().unwrap().get_outgoing_swapcoins_count(),
        splits_left
    );
    assert_eq!(maker.reserved_inputs().unwrap() > 0, splits_left > 0);
    world.shutdown_makers();

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
/// on-chain split's recovery material, so the saved committed flag must
/// route the taker to recovery even if the backend has not seen the funding.
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
        /// The unsent split is sent, locked and refunded too: 457 sats of fees.
        taker_recovers_partial_broadcast_with_spare_maker(
            backend = BitcoindBackend,
            expected_spendable = 14_999_086,
        ),
        /// The same partial batch on Electrum: the backend can lag the session's own
        /// broadcast, so only the committed flag keeps the spare maker unused and
        /// the recovery material intact.
        taker_recovers_partial_broadcast_with_spare_maker_electrum(
            backend = ElectrumBackend,
            expected_spendable = 14_999_086,
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

    assert_log!(world; {
        has "Test behavior: failing the second funding broadcast",
        // The chain check found split 1 in the mempool, so the spare maker must
        // stay unused and the recovery material must survive: substitution
        // would delete the on-chain split's recovery material ...
        lacks "substituting maker 0 with spare",
        // ... and a funding reinitialize destroys its swapcoins.
        lacks "Re-initializing funding after maker substitution",
    });

    assert!(
        !world
            .temp_dir()
            .join("taker1")
            .join("swap_tracker.cbor")
            .exists(),
        "funding and recovery must only write the wallet"
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
    // Split 1 was accepted, so its inputs are free; split 2 failed and might
    // still land, so its inputs stay claimed until recovery settles the swap.
    assert!(
        world.taker().inner().reserved_inputs().unwrap() > 0,
        "a failed broadcast must keep its inputs claimed"
    );

    // Recovery sends the unsent split too; the refunds may come in separate
    // passes, so the reports are summed below.
    wait_until!(
        Duration::from_secs(360),
        every Duration::from_secs(5),
        "the splits to be recovered",
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count()
            == 0
    );
    assert_eq!(
        world.taker().inner().reserved_inputs().unwrap(),
        0,
        "recovery must release the claim of the swap it settled"
    );

    let refunds: HashSet<_> = world
        .taker()
        .inner()
        .get_wallet()
        .read()
        .unwrap()
        .swap_reports()
        .recovery
        .iter()
        .filter(|report| report.swap_id == swap_id && report.recovery_type == "timelock")
        .flat_map(|report| report.recovery_txids.clone())
        .collect();
    assert_eq!(
        refunds.len(),
        2,
        "the confirmed refunds must be stored with the coin removal"
    );
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

    assert_log!(world; {
        has "Test behavior: maker 0 dropped mid-exchange",
        // The maker's own persisted contracts must not read as a replay.
        lacks "already in use",
        // Two passes over the same contract data: the resume re-entered contract
        // processing and crossed the replay check (the fee log sits behind it).
        count(format!("Processing Taproot contract data for swap {swap_id}")) == 2,
        count("Fee calculation: incoming_total") == 2,
        // Only the first pass's first tx made it on the wire; the resumed pass
        // funds nothing.
        count("Broadcast Taproot contract tx") == 1,
        lacks "completed successfully",
    });
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

    assert_log!(world; { has "Swap id belongs to an unfinished swap" });

    world.framework().set_block_gen_paused(false);

    restarted.shutdown.store(true, Relaxed);
    restarted_thread.join().unwrap();
}
