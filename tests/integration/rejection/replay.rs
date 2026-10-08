//! Replayed contract data: a swap's funding presented again under a fresh swap
//! id, after completion or while the first swap's claim is live, must be refused
//! before the maker funds anything.

use bitcoin::Amount;
use openswap::{
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use crate::test_framework::*;

use std::{thread, time::Duration};

use super::wait_for_log_after;

/// One replay-guard scenario: swap 1 either completes or dies with the maker's
/// claim live, then swap 2 replays its funding under a fresh id and must be
/// rejected before the maker funds anything.
struct ReplayScenario {
    behavior: TakerBehavior,
    protocol: ProtocolVersion,
    taker_utxos: u32,
    pin_maker: bool,
    swap1_completes: bool,
    sync_after_swap1: bool,
    swapcoins_before: Option<(usize, &'static str)>,
    swap2_reject_msg: &'static str,
    needle: &'static str,
    needle_timeout_secs: u64,
    /// Needles that must not appear in the log once swap 2 starts.
    forbidden_in_tail: &'static [&'static str],
    swapcoins_after: Option<(usize, &'static str)>,
}

const REPLAYED_TAPROOT_AFTER_COMPLETION: ReplayScenario = ReplayScenario {
    behavior: TakerBehavior::ReplayTaprootContractData,
    protocol: ProtocolVersion::Taproot,
    taker_utxos: 3,
    pin_maker: false,
    swap1_completes: true,
    sync_after_swap1: false,
    swapcoins_before: None,
    swap2_reject_msg: "the maker must reject replayed contract data",
    needle: "Taproot contract output already spent",
    needle_timeout_secs: 120,
    // The maker must not fund the replayed swap.
    forbidden_in_tail: &["Broadcast Taproot contract tx"],
    swapcoins_after: Some((0, "the replay must not leave new incoming swapcoins behind")),
};

const REPLAYED_LEGACY_POF_IN_FLIGHT: ReplayScenario = ReplayScenario {
    behavior: TakerBehavior::ReplayLegacyProofOfFunding,
    protocol: ProtocolVersion::Legacy,
    taker_utxos: 4,
    pin_maker: true,
    swap1_completes: false,
    sync_after_swap1: true,
    swapcoins_before: None,
    swap2_reject_msg: "the maker must reject the replayed proof of funding",
    needle: "Legacy contract txid already in use",
    needle_timeout_secs: 60,
    // The maker must not fund the replayed swap.
    forbidden_in_tail: &["SECURITY: Broadcasting"],
    swapcoins_after: None,
};

const REPLAYED_TAPROOT_IN_FLIGHT: ReplayScenario = ReplayScenario {
    behavior: TakerBehavior::ReplayTaprootContractDataInFlight,
    protocol: ProtocolVersion::Taproot,
    taker_utxos: 4,
    pin_maker: true,
    swap1_completes: false,
    sync_after_swap1: false,
    swapcoins_before: Some((1, "swap 1's incoming swapcoin must be live on the maker")),
    swap2_reject_msg: "the maker must reject the in-flight replayed contract data",
    needle: "Contract txid already in use",
    needle_timeout_secs: 60,
    forbidden_in_tail: &[
        // The atomic claim must fire before the per-contract seen-check ...
        "Taproot contract txid already in use",
        // ... and the maker must not fund the replayed swap.
        "Broadcast Taproot contract tx",
    ],
    swapcoins_after: Some((1, "the replay must not add incoming swapcoins")),
};

#[world_test(
    maker_behaviors = [Normal],
    takers = [s.behavior],
    setup = [
        fund_taker_default(s.taker_utxos),
        fund_makers_default(),
        spawn_ready_makers_and_mine(),
    ],
    cases = [
        /// A completed swap's Taproot contract data re-presented under a fresh swap id
        /// must be rejected: the outputs are already spent by the maker's sweep.
        /// The taker behavior resends its first swap's contract data verbatim.
        maker_rejects_replayed_taproot_contract_data(
            backend = BitcoindBackend,
            s = REPLAYED_TAPROOT_AFTER_COMPLETION,
        ),
        /// Same replay on Electrum: the spent-output answer comes from the indexer,
        /// not the wallet's own view of the mempool and chain.
        maker_rejects_replayed_taproot_contract_data_electrum(
            backend = ElectrumBackend,
            s = REPLAYED_TAPROOT_AFTER_COMPLETION,
        ),
        /// The Legacy mirror of the Taproot replay: one confirmed funding's proof
        /// re-presented under a fresh swap id must be rejected while the first
        /// swap's claim is still live.
        maker_rejects_replayed_legacy_contract_data(
            backend = BitcoindBackend,
            s = REPLAYED_LEGACY_POF_IN_FLIGHT,
        ),
        /// Same replay on Electrum: the confirmation and seen answers come from the
        /// indexer, which lags the session's own view of the chain.
        maker_rejects_replayed_legacy_contract_data_electrum(
            backend = ElectrumBackend,
            s = REPLAYED_LEGACY_POF_IN_FLIGHT,
        ),
        /// The in-flight arm of the Taproot replay guard: swap 2 presents swap 1's
        /// contract while swap 1's claim is still live on the maker — before any
        /// sweep, so only the atomic claim (not the spent check) can refuse it.
        /// The behavior hook dies right after the maker answers swap 1's contract
        /// data, then replays that data under swap 2's fresh id.
        maker_rejects_replayed_taproot_contract_data_in_flight(
            backend = BitcoindBackend,
            s = REPLAYED_TAPROOT_IN_FLIGHT,
        ),
        /// Same in-flight replay on Electrum: the claim is in-memory, but the
        /// confirmation wait it protects runs against the indexer.
        maker_rejects_replayed_taproot_contract_data_in_flight_electrum(
            backend = ElectrumBackend,
            s = REPLAYED_TAPROOT_IN_FLIGHT,
        ),
    ],
)]
fn run_replay_guard(world: &mut World, s: ReplayScenario) {
    let preferred = vec![world.makers()[0].address()];
    let params = || {
        let p = SwapParams::new(s.protocol, Amount::from_sat(500_000), 1).with_tx_count(1);
        if s.pin_maker {
            p.with_preferred_makers(preferred.clone())
        } else {
            p
        }
    };

    let summary1 = world
        .taker_mut()
        .prepare(params())
        .expect("prepare 1 must succeed");
    if s.swap1_completes {
        // Swap 1 completes normally; its contract data is cached for the replay.
        world
            .taker_mut()
            .start(&summary1.swap_id)
            .expect("swap 1 must succeed");

        // Wait until the maker's sweep is confirmed and the swap-1 swapcoin
        // has left the store, so only the chain can answer the replay.
        wait_until!(
            Duration::from_secs(120),
            every Duration::from_secs(2),
            "the maker to sweep and drop the swap-1 incoming swapcoin",
            world.makers()[0]
                .inner()
                .wallet
                .read()
                .unwrap()
                .get_incoming_swapcoins_count()
                == 0
        );
    } else {
        // Swap 1 dies right after the maker processed its funding, so the
        // maker's claim on the incoming contracts is still live.
        let swap1 = world.taker_mut().start(&summary1.swap_id);
        assert!(
            swap1.is_err(),
            "the behavior hook must abort swap 1 with the maker's claim in flight"
        );
        if let Some((count, msg)) = s.swapcoins_before {
            assert_eq!(
                world.makers()[0]
                    .inner()
                    .wallet
                    .read()
                    .unwrap()
                    .get_incoming_swapcoins_count(),
                count,
                "{}",
                msg
            );
        }
        // With recovery suppressed nothing syncs the wallet between swaps;
        // swap 2's funding must not re-pick swap 1's spent UTXOs.
        if s.sync_after_swap1 {
            world.taker().sync();
        }
        // Hold the chain still so the replay lands inside the claim's window.
        world.framework().set_block_gen_paused(true);
    }

    // Swap 2: fresh id, replayed funding. The maker must reject before
    // funding anything.
    let log_path = world.taker_log_path();
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    let summary2 = world
        .taker_mut()
        .prepare(params())
        .expect("prepare 2 must succeed");
    assert_ne!(summary1.swap_id, summary2.swap_id);
    let swap2 = world.taker_mut().start(&summary2.swap_id);
    assert!(swap2.is_err(), "{}", s.swap2_reject_msg);

    wait_logged!(world, s.needle, Duration::from_secs(s.needle_timeout_secs));

    // The scenario's needle list is data, so build the rows `assert_log!` would.
    let forbidden: Vec<LogCheck> = s
        .forbidden_in_tail
        .iter()
        .map(|needle| LogCheck::Lacks(needle.to_string()))
        .collect();
    assert_log(&log_path, Some(log_offset), &forbidden);
    if let Some((count, msg)) = s.swapcoins_after {
        assert_eq!(
            world.makers()[0]
                .inner()
                .wallet
                .read()
                .unwrap()
                .get_incoming_swapcoins_count(),
            count,
            "{}",
            msg
        );
    }

    if !s.swap1_completes {
        world.framework().set_block_gen_paused(false);
    }
}

/// The step both concurrent-replay tests share once their maker is up: both
/// takers leave the world, and mining pauses so every swap stalls in the
/// confirmation wait. Returns the takers, the maker's address, the log path
/// and the log length at the pause.
fn concurrent_replay_setup(world: &mut World) -> (TakerHandle, TakerHandle, String, String, u64) {
    // Both takers run on their own threads, so they leave the world here.
    let taker1 = world.take_taker();
    let taker2 = world.take_taker();

    let maker_address = world.makers()[0].address();
    let log_path = world.taker_log_path();

    // Hold the swaps' funding unconfirmed: each maker handler blocks in the
    // confirmation wait.
    world.framework().set_block_gen_paused(true);
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    (taker1, taker2, maker_address, log_path, log_offset)
}

/// The genuinely concurrent arm of the Taproot replay guard: swap 1's
/// contract txs sit unconfirmed, so the seen-check has nothing to see and
/// the atomic claim must reject taker 2's replayed contract data.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [ReplayTaprootContractData, ReplayTaprootContractData],
    setup = [
        fund_nth_taker_default(0, 3),
        fund_nth_taker_default(1, 3),
        fund_makers_default(),
        spawn_ready_makers_and_mine(),
    ],
)]
fn maker_rejects_concurrent_replayed_taproot_contract_data(world: &mut World) {
    let (mut taker1, mut taker2, maker_address, log_path, log_offset) =
        concurrent_replay_setup(world);

    let params = |address: &str| {
        SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
            .with_tx_count(1)
            .with_preferred_makers(vec![address.to_string()])
    };

    // Swap 1 runs on its own thread: it sends real contract data, then waits
    // on a maker response that cannot arrive while mining is paused.
    let swap1_address = maker_address.clone();
    let swap1 = thread::spawn(move || {
        let summary = taker1
            .prepare(params(&swap1_address))
            .expect("prepare 1 must succeed");
        taker1.start(&summary.swap_id)
    });

    // Barrier: the maker claimed swap 1's incoming txids and is inside the
    // confirmation wait.
    wait_for_log_after(
        &log_path,
        log_offset,
        "confirmation(s) on tx",
        1,
        Duration::from_secs(120),
    );

    // Swap 2 replays swap 1's contract data under a fresh id. The atomic
    // claim is the only guard that can refuse it this early.
    let summary2 = taker2
        .prepare(params(&maker_address))
        .expect("prepare 2 must succeed");
    let swap2 = taker2.start(&summary2.swap_id);
    assert!(
        swap2.is_err(),
        "the maker must reject the concurrent replayed contract data"
    );

    wait_for_log_after(
        &log_path,
        log_offset,
        "Contract txid already in use",
        1,
        Duration::from_secs(60),
    );
    assert_log!(log_path, since log_offset; {
        // The per-contract seen-check has nothing to see while swap 1 is unconfirmed.
        lacks "Taproot contract txid already in use",
        // The maker must not fund anything while both swaps wait.
        lacks "Broadcast Taproot contract tx",
    });

    // Mining resumes: swap 1's handler wakes and funds exactly one hop.
    world.framework().set_block_gen_paused(false);
    wait_for_log_after(
        &log_path,
        log_offset,
        "Broadcast Taproot contract tx",
        1,
        Duration::from_secs(240),
    );
    // The maker must fund exactly one hop across both swaps.
    assert_log!(log_path, since log_offset; { count("Broadcast Taproot contract tx") == 1 });

    let _ = swap1.join().expect("swap 1 thread panicked");

    world.shutdown_makers();
    drop(taker2);
}

/// The genuinely concurrent Legacy arm: swap 1's handler parks in the proof's
/// confirmation wait holding the claim, so swap 2's replay is rejected at the
/// claim without ever waiting. Exactly one swap may be funded.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [ReplayLegacyProofOfFunding, ReplayLegacyProofOfFunding],
    setup = [
        fund_nth_taker_default(0, 4),
        fund_nth_taker_default(1, 4),
        fund_makers_default(),
        spawn_ready_makers_and_mine(),
    ],
)]
fn maker_rejects_concurrent_replayed_legacy_proof_of_funding(world: &mut World) {
    let (taker1, taker2, maker_address, log_path, log_offset) = concurrent_replay_setup(world);

    let params = |address: &str| {
        SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
            .with_tx_count(1)
            .with_preferred_makers(vec![address.to_string()])
    };

    let run_swap = |mut taker: TakerHandle, address: String| {
        thread::spawn(move || {
            let summary = taker
                .prepare(params(&address))
                .expect("prepare must succeed");
            taker.start(&summary.swap_id)
        })
    };
    let swap1 = run_swap(taker1, maker_address.clone());

    // Barrier: swap 1's handler is inside the confirmation wait.
    wait_for_log_after(
        &log_path,
        log_offset,
        "confirmation(s) on tx",
        1,
        Duration::from_secs(120),
    );

    let swap2 = run_swap(taker2, maker_address.clone());

    // The claim sits before the confirmation wait: swap 2's replay is
    // rejected while swap 1 is still parked — no block is needed for it.
    wait_for_log_after(
        &log_path,
        log_offset,
        "already in use",
        1,
        Duration::from_secs(120),
    );

    world.framework().set_block_gen_paused(false);

    // Swap 1's wait observes the confirmation and funds exactly one hop.
    wait_for_log_after(
        &log_path,
        log_offset,
        "outgoing swapcoins, requesting signatures",
        1,
        Duration::from_secs(180),
    );
    // The maker must fund exactly one hop across both swaps.
    assert_log!(log_path, since log_offset; {
        count("outgoing swapcoins, requesting signatures") == 1,
    });

    let swap1_result = swap1.join().expect("swap 1 thread panicked");
    let swap2_result = swap2.join().expect("swap 2 thread panicked");
    assert!(
        swap1_result.is_err() && swap2_result.is_err(),
        "neither swap may complete: the loser is rejected, the winner's counterpart is gone"
    );
}
