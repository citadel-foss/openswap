//! Three makers for a two-hop route; one drops before any funding is on-chain,
//! the taker substitutes the spare, and the swap completes.
//!
//! `legacy_middle_maker_drops_before_sender_sigs` runs [`complete_with_spare`]
//! too, then checks that nobody was blamed for the drop.

use std::{thread, time::Duration};

use bitcoin::{Amount, Txid};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    maker::{server::IDLE_CONNECTION_TIMEOUT, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{MakerState, SwapParams},
};

use crate::test_framework::*;

/// The balances one spare-maker test asserts after the swap.
struct SpareMakerExpect {
    taker_spendable: u64,
    maker_spendable: [u64; 3],
}

/// Swaps over `protocol` on a world of three makers and one taker, expects the
/// swap to complete, and asserts the balances. The makers keep running.
#[world_test(
    backend = BitcoindBackend,
    makers = 3,
    maker_behaviors = behaviors,
    takers = [Normal],
    cases = [
        /// The first maker drops before sending the sender's sigs; the taker
        /// continues with the remaining makers.
        legacy_first_maker_drops_before_sender_sigs(
            behaviors = [
                MakerBehavior::CloseAtReqContractSigsForSender,
                MakerBehavior::Normal,
                MakerBehavior::Normal,
            ],
            protocol = ProtocolVersion::Legacy,
            prepare_failure = "Failed to prepare openswap",
            expected = &SpareMakerExpect {
                taker_spendable: 14995952,
                maker_spendable: [14999757, 15000378, 15000415],
            },
        ),
        /// Maker drops after sending AckSwapDetails (Taproot). Taker finds spare maker.
        ///
        /// Scenario:
        /// 1. Taker initiates a Taproot openswap requiring 2 makers, 3 are available.
        /// 2. maker[1] drops after sending AckSwapDetails (before funding broadcast).
        /// 3. Taker detects the failure and retries with the spare maker (maker[2]).
        /// 4. Swap completes successfully with maker[0] and maker[2].
        /// 5. Verify: taker lost fees, makers gained fees.
        taproot_middle_maker_drops_after_ack(
            behaviors = [
                MakerBehavior::Normal,
                MakerBehavior::CloseAfterAckResponse,
                MakerBehavior::Normal,
            ],
            protocol = ProtocolVersion::Taproot,
            prepare_failure = "Failed to prepare Taproot openswap",
            expected = &SpareMakerExpect {
                taker_spendable: 14996294,
                maker_spendable: [15000415, 14999757, 15000378],
            },
        ),
    ],
)]
fn complete_with_spare(
    world: &mut World,
    protocol: ProtocolVersion,
    prepare_failure: &str,
    expected: &SpareMakerExpect,
) {
    // Fund the taker with 3 UTXOs of 0.05 BTC each
    world.fund_taker_default(3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    world.fund_makers_default();

    // Start the makers, wait for their setup, then sync their wallets so the
    // fidelity bonds are accounted for
    log::info!("Starting Maker servers...");
    world.start_makers(120);

    world.verify_maker_pre_swap_balances();

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    // Prepare and execute the swap — taker should retry with the spare maker
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect(prepare_failure);
    world
        .taker_mut()
        .start(&summary.swap_id)
        .expect("Swap should succeed with spare maker");

    // Sync wallets and verify results
    world.taker().sync();

    world.mine(1);

    world.sync_makers();

    assert_balances!(world; {
        taker: { spendable: expected.taker_spendable, contract: 0, fidelity: 0 },
        makers: { spendable: expected.maker_spendable, contract: 0, fidelity: BOND },
    });
}

/// The middle maker drops before sending the sender's sigs; the taker
/// substitutes the spare, completes, and blames nobody for the drop.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAtReqContractSigsForSender, Normal],
    takers = [Normal],
)]
fn legacy_middle_maker_drops_before_sender_sigs(world: &mut World) {
    complete_with_spare(
        world,
        ProtocolVersion::Legacy,
        "Failed to prepare openswap",
        &SpareMakerExpect {
            taker_spendable: 14995952,
            maker_spendable: [15000415, 14999757, 15000378],
        },
    );

    // Maker 1 dropped the connection. We cannot tell its failure from our own
    // link failing, so nothing about it may be recorded as its fault. A
    // recoverable mark is allowed; a ban is not. `maker_standing` panics if a
    // maker is missing from the offerbook, so the check cannot be skipped.
    for index in 0..world.makers().len() {
        let standing = world.maker_standing(index);
        assert!(
            !matches!(standing, MakerState::Banned(_)),
            "a dropped connection must blame nobody, but maker {} is {:?}",
            index,
            standing
        );
    }
}

/// The middle maker drops and the spare takes its place, then maker 0's funding
/// is slow to confirm. The spare holds an unfunded swap through that wait, and
/// only the route heartbeat stops it from dropping the swap as idle.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAtReqContractSigsForSender, Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn legacy_spare_survives_slow_funding_confirm(world: &mut World) {
    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);
    // The swap runs on its own thread, so the taker leaves the world here.
    let mut taker = world.take_taker();
    let summary = taker.prepare(swap_params).expect("prepare swap");

    // Stop background blocks before the swap starts and mine the one block the
    // swap needs by hand. Maker 0's funding then stays unconfirmed and the
    // taker parks in its wait, as on a slow block.
    let test_framework = world.framework().clone();
    let bitcoind = &test_framework.bitcoind;
    test_framework.set_block_gen_paused(true);
    // Let any in-flight mining tick finish before the swap starts.
    thread::sleep(Duration::from_secs(4));
    // Resume mining even if a check below fails, so the swap thread cannot
    // stay blocked in its confirmation wait.
    struct ResumeMining<'a>(&'a TestFramework);
    impl Drop for ResumeMining<'_> {
        fn drop(&mut self) {
            self.0.set_block_gen_paused(false);
        }
    }
    let resume_mining = ResumeMining(&test_framework);

    let log_offset = log_mark(&world);
    let log_path = world.taker_log_path();
    // This swap's part of the log, read fresh on each call.
    let swap_log = || {
        let log = std::fs::read_to_string(&log_path).unwrap();
        let from = (log_offset as usize..=log.len())
            .find(|&i| log.is_char_boundary(i))
            .unwrap_or(log.len());
        log[from..].to_string()
    };
    let swap_handle = thread::spawn(move || {
        let result = taker.start(&summary.swap_id);
        (taker, result)
    });

    // The taker logs its confirmation wait only after every funding send has
    // returned, so one block now confirms all of its funding. Makers log the
    // same wording, but only after the ProofOfFunding that follows this wait,
    // so the first match after the taker's broadcast line is the taker's.
    wait_until!(
        Duration::from_secs(120),
        "the taker waiting on its own funding",
        {
            let log = swap_log();
            log.find("Broadcasting funding transactions")
                .is_some_and(|at| log[at..].contains("Waiting for 1 confirmation(s) on"))
        }
    );
    world.mine(1);

    // No block is mined from here until the hold ends. The middle maker drops,
    // the spare joins (the mid-exchange line, not the negotiation-time one),
    // and maker 0 broadcasts its funding.
    let maker0_port = world.makers()[0].inner().config.network_port;
    let broadcast_done = format!("[{}] Funding broadcast complete", maker0_port);
    wait_until!(
        Duration::from_secs(120),
        "the spare to join and maker 0 to fund",
        {
            let log = swap_log();
            log.find("Substituting with spare at")
                .is_some_and(|at| log[at..].contains(&broadcast_done))
        }
    );
    // Maker 0 logs every funding txid it broadcasts, so take them from the log.
    let funding_line = format!("[{}] Broadcast Legacy funding tx: ", maker0_port);
    let maker0_funding: Vec<Txid> = swap_log()
        .lines()
        .filter_map(|line| line.split_once(funding_line.as_str()))
        .map(|(_, txid)| txid.trim().parse().unwrap())
        .collect();
    assert!(!maker0_funding.is_empty(), "maker 0 logged no funding txid");
    let spare_port = world.makers()[2].inner().config.network_port;
    let height = bitcoind.client.get_block_count().unwrap();
    let hold_mark = log_mark(&world);
    // Tied to the timeout, so raising it cannot turn this into a silent pass.
    // The extra 10 s covers the idle drain, which runs every 3 s.
    thread::sleep(IDLE_CONNECTION_TIMEOUT + Duration::from_secs(10));
    // The hold proves nothing if maker 0's funding confirmed, so check that
    // nothing was mined and the funding is still waiting.
    assert_eq!(
        bitcoind.client.get_block_count().unwrap(),
        height,
        "no block may be mined during the hold"
    );
    let mempool = bitcoind.client.get_raw_mempool().unwrap();
    assert!(
        maker0_funding.iter().all(|txid| mempool.contains(txid)),
        "maker 0's funding must still be unconfirmed at the end of the hold"
    );
    // The heartbeat reached the spare during the hold, not only after it.
    assert_log!(world, since hold_mark; {
        has format!("[{}] Taker is waiting for funding confirmation", spare_port),
    });
    drop(resume_mining);

    let (_taker, result) = swap_handle.join().expect("swap thread panicked");
    result.expect("the spare must keep the swap through a slow confirmation");

    assert_log!(world, since log_offset; {
        lacks format!("[{}] Released idle unfunded swap", spare_port),
    });
}

/// Maker 0 has to re-plan its funding, then rebuild it for the spare's keys
/// after maker 1 drops. The rebuild must reuse the coins the re-plan claimed,
/// not the frozen plan's, or the substitution fails.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [ForceReplan, CloseAtReqContractSigsForSender, Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 1),
)]
fn rebuild_after_replan_uses_the_claimed_coins(world: &mut World, params: SwapParams) {
    world
        .taker_mut()
        .swap(params)
        .expect("the rebuild must reuse the re-planned coins");

    assert_log!(world; {
        // Only the first pass re-plans; the rebuild reuses its claim.
        count("Re-planned funding for swap") == 1,
        // Maker 0 rebuilt its funding for the spare.
        has "Substituting maker 1 with spare",
    });
    assert_eq!(world.makers()[0].inner().reserved_inputs().unwrap(), 0);
}
