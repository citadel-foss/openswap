//! Partial funding broadcasts: a batch that is half on-chain must recover
//! instead of reading as never broadcast, and a restarted maker must not reuse
//! or misread the swap it left unfinished.

use bitcoin::{
    secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey},
    Address, Amount, Network, OutPoint, Transaction,
};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    maker::{start_server, MakerServer},
    protocol::common_messages::ProtocolVersion,
    taker::SwapParams,
    utill::MIN_RELAY_FEE_RATE,
    wallet::{AddressType, Destination},
};

use crate::test_framework::*;

use std::{
    collections::HashSet,
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::Duration,
};

/// The inputs of the maker's funding txs.
fn funding_inputs(funding: &[Transaction]) -> Vec<OutPoint> {
    funding
        .iter()
        .flat_map(|tx| tx.input.iter().map(|input| input.previous_output))
        .collect()
}

/// Mines a block that leaves every mempool tx out.
fn mine_empty_block(world: &World) {
    let client = &world.bitcoind().client;
    let miner = client.get_new_address(None, None).unwrap().assume_checked();
    let _: serde_json::Value = client
        .call(
            "generateblock",
            &[serde_json::json!(miner.to_string()), serde_json::json!([])],
        )
        .unwrap();
}

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
/// The partial batch must not read as never broadcast: recovery reclaims the
/// on-chain split via timelock, and frees the unsent split's inputs after the
/// grace while keeping its keys.
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
    let protocol = params.protocol;
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

    // One tx of the two-tx batch was recorded before the failure — per-tx
    // state, not a single end-of-batch flag. The send loop logs each accepted
    // send; recovery never writes that line, so it cannot race the record.
    // Exactly the first funding tx may be recorded as broadcast.
    let sent = match protocol {
        ProtocolVersion::Legacy => "Broadcast Legacy funding tx",
        ProtocolVersion::Taproot => "Broadcast Taproot contract tx",
    };
    assert_log!(world; { count(sent) == 1 });

    // The 30s idle timeout starts recovery; the timelock path then needs the
    // maker's outgoing timelock (150 CSV blocks from the contract broadcast).
    // The unsent split is never sent and stays, keys and all.
    let recovered = wait_for_maker_timelock_recovery(
        world.makers()[0].inner(),
        &swap_id,
        1,
        1,
        timelock_recovery_wait::<B>() + Duration::from_secs(120),
    );

    assert_eq!(
        recovered.len(),
        1,
        "the on-chain split must be timelock-recovered"
    );

    // Past the grace the unsent split's inputs go back to the wallet.
    wait_for_release(&world.taker_log_path(), &swap_id);
    assert_log!(world; { lacks "nothing to recover. Discarding swapcoins" });

    // The kept split never settles on its own, so stop the maker.
    world.shutdown_makers();
    let maker = world.makers()[0].inner();
    assert_eq!(
        maker.wallet.read().unwrap().get_outgoing_swapcoins_count(),
        1,
        "the unsent split's keys must be kept"
    );
    assert_eq!(
        maker.reserved_inputs().unwrap(),
        0,
        "recovery must release the unsent split's inputs"
    );

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
/// on-chain split's recovery material, so the first split's saved committed
/// flag must route the taker to recovery even if the backend has not seen the
/// funding.
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
            expected_spendable = 14_999_543,
        ),
        /// The same partial batch on Electrum: the backend can lag the session's own
        /// broadcast, so only the committed flag keeps the spare maker unused and
        /// the recovery material intact.
        taker_recovers_partial_broadcast_with_spare_maker_electrum(
            backend = ElectrumBackend,
            expected_spendable = 14_999_543,
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
    // Hold the chain still while the intermediate state is read: the committed
    // split's refund needs its timelock to mature, so no refund can land and
    // the swap's input claim stays until block generation resumes below.
    world.framework().set_block_gen_paused(true);

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
    // Both splits' swapcoins must survive — no substitution cleanup. Recovery
    // runs from the failure on and may already have dropped the unsent split,
    // but it logs that drop before removing the coin, so a count read first
    // can only be short by a drop the log already shows.
    let held = world
        .taker()
        .inner()
        .get_wallet()
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count();
    if held != 2 {
        assert_eq!(held, 1, "only recovery may drop a swapcoin");
        assert_log!(world; {
            count("was never broadcast and its inputs are unspent, discarding swapcoin") == 1,
        });
    }
    // The first split was committed before its send, so the partial batch never
    // reads as unfunded; the failed split was never recorded as sent. The
    // committed split leaves only with its refund, which needs 150 blocks on a
    // contract recovery sends after the failure, and the chain is held still.
    assert_eq!(
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .committed_outgoing_swapcoins_count(&swap_id),
        1,
        "only the sent split may be recorded as broadcast"
    );
    // Split 1 was accepted, so its inputs are free; split 2 failed and might
    // still land, so its inputs stay claimed until recovery settles the swap,
    // which waits for the committed split's refund (blocked while paused).
    assert!(
        world.taker().inner().reserved_inputs().unwrap() > 0,
        "a failed broadcast must keep its inputs claimed"
    );

    // Recovery drops the unsent split without sending it and reclaims the
    // on-chain split once its timelock matures.
    world.framework().set_block_gen_paused(false);
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
        1,
        "the on-chain split's confirmed refund must be stored with the coin removal"
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

/// Runs a swap whose single maker fails its first funding send, and returns
/// the swap id with the funding txs the maker stored.
fn fail_first_send(world: &mut World, params: SwapParams) -> (String, Vec<Transaction>) {
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();
    assert!(
        world.taker_mut().start(&swap_id).is_err(),
        "the swap must fail at the maker's first funding send"
    );
    assert_log!(world; { has "Test behavior: failing the first" });
    let funding = world.makers()[0]
        .inner()
        .outgoing_funding_txs(&swap_id)
        .unwrap();
    assert!(!funding.is_empty(), "the maker must keep its funding txs");
    (swap_id, funding)
}

/// The maker's first funding send fails with nothing sent. Recovery never
/// sends it: after the grace it frees the inputs for reuse and keeps the
/// keys. Only a block spending a freed input elsewhere ends the swap.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [FailFirstBroadcast],
    takers = [CrashBeforeRecovery],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    swap(protocol = protocol, sats = 500_000, makers = 1, tx_count = 1),
    cases = [
        failed_first_send_frees_inputs_and_keeps_keys(protocol = ProtocolVersion::Legacy),
        failed_first_send_frees_inputs_and_keeps_keys_taproot(protocol = ProtocolVersion::Taproot),
    ],
)]
fn run_failed_first_send_frees_inputs(world: &mut World, params: SwapParams) {
    let protocol = params.protocol;
    let (swap_id, funding) = fail_first_send(world, params);
    let maker = world.makers()[0].inner().clone();
    let contracts = maker.outgoing_contract_txs(&swap_id).unwrap();
    let inputs = funding_inputs(&funding);
    let select = |maker: &MakerServer| {
        maker.wallet.read().unwrap().coin_select(
            Amount::from_sat(10_000),
            MIN_RELAY_FEE_RATE,
            AddressType::P2TR,
            Some(inputs.clone()),
            None,
        )
    };
    world.makers()[0].sync();
    assert!(
        select(&maker).is_err(),
        "inside the grace the failed send keeps its inputs reserved"
    );

    wait_for_release(&world.taker_log_path(), &swap_id);
    assert_eq!(maker.reserved_inputs().unwrap(), 0);
    assert!(maker.has_unfinished_outgoing_swapcoin(&swap_id).unwrap());
    assert!(maker.wallet.read().unwrap().get_incoming_swapcoins_count() > 0);
    let client = &world.bitcoind().client;
    for tx in funding.iter().chain(&contracts) {
        assert!(
            client
                .get_raw_transaction(&tx.compute_txid(), None)
                .is_err(),
            "recovery must never send {}",
            tx.compute_txid()
        );
    }

    // The freed inputs are the wallet's again.
    world.makers()[0].sync();
    let coins = select(&maker).expect("released inputs must be selectable");
    let secp = Secp256k1::new();
    let keypair = bitcoin::key::Keypair::from_secret_key(&secp, &SecretKey::new(&mut OsRng));
    let sink = Address::p2tr(&secp, keypair.x_only_public_key().0, None, Network::Regtest);
    let spend = maker
        .wallet
        .write()
        .unwrap()
        .spend_from_wallet(MIN_RELAY_FEE_RATE, Destination::Sweep(sink), &coins)
        .unwrap();
    world.framework().set_block_gen_paused(true);
    world
        .bitcoind()
        .client
        .send_raw_transaction(&spend)
        .unwrap();

    // A mempool spend may still be evicted: a pass on each block without it
    // keeps the swap.
    let mark = log_mark(&world.taker_log_path());
    for _ in 0..2 {
        mine_empty_block(world);
        let height = world.bitcoind().client.get_block_count().unwrap();
        wait_for_log(
            &world.taker_log_path(),
            &format!("Swap {swap_id} checked its unsent funding at height {height}"),
            Duration::from_secs(60),
        );
    }
    // Legacy's refund pass also runs every block, after the settle pass.
    if protocol == ProtocolVersion::Legacy {
        assert_log!(world, since mark; { has "recover_timelocked" });
    }
    assert!(maker.has_unfinished_outgoing_swapcoin(&swap_id).unwrap());

    // Dropped once the spend is buried past reorg depth (6 blocks).
    world.mine(6);
    wait_until!(
        Duration::from_secs(60),
        every Duration::from_secs(2),
        "the kept swap to be dropped",
        {
            let wallet = maker.wallet.read().unwrap();
            wallet.get_outgoing_swapcoins_count() + wallet.get_incoming_swapcoins_count() == 0
        }
    );
    assert_log!(world; {
        has format!("Swap {swap_id} is settled: its unsent funding can never confirm"),
    });
    world.framework().set_block_gen_paused(false);
}

/// Recovery's refunds of `swap_id`, once its outgoing coins are gone.
fn wait_for_single_refund(world: &World, swap_id: &str) {
    let refunds = wait_for_maker_timelock_recovery(
        world.makers()[0].inner(),
        swap_id,
        1,
        0,
        timelock_recovery_wait::<BitcoindBackend>() + Duration::from_secs(120),
    );
    assert_eq!(refunds.len(), 1, "exactly one timelock refund");
}

/// The failed first send's funding confirms after the grace freed its inputs.
/// The maker records it as sent and takes it back by timelock, once.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [FailFirstBroadcast],
    takers = [CrashBeforeRecovery],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    swap(protocol = protocol, sats = 500_000, makers = 1, tx_count = 1),
    cases = [
        released_funding_that_confirms_is_refunded(
            protocol = ProtocolVersion::Legacy,
            expected_spendable = 14_999_311,
        ),
        released_funding_that_confirms_is_refunded_taproot(
            protocol = ProtocolVersion::Taproot,
            expected_spendable = 14_999_463,
        ),
    ],
)]
fn run_released_funding_that_confirms(
    world: &mut World,
    expected_spendable: u64,
    params: SwapParams,
) {
    let (swap_id, funding) = fail_first_send(world, params);
    wait_for_release(&world.taker_log_path(), &swap_id);

    for tx in &funding {
        world.bitcoind().client.send_raw_transaction(tx).unwrap();
    }
    world.mine(1);
    wait_for_single_refund(world, &swap_id);

    // Finished recovery stops the maker; join it before the sync.
    world.join_makers();
    world.mine(1);
    world.makers()[0].sync();
    // 14_999_757 before the swap, less the funding (154) and the refund; Legacy
    // also pays a contract tx. Same txs as the partial-broadcast split.
    assert_balances!(world; {
        maker: { swap: 0, contract: 0, fidelity: BOND, spendable: expected_spendable },
    });
}

/// The first send went out but reported a failure. The backend has seen the
/// funding, so it is never released or dropped: the maker refunds it.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [BroadcastThenFailFirst],
    takers = [CrashBeforeRecovery],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    swap(protocol = protocol, sats = 500_000, makers = 1, tx_count = 1),
    cases = [
        seen_failed_send_is_refunded_never_released(
            protocol = ProtocolVersion::Legacy,
            expected_spendable = 14_999_311,
        ),
        seen_failed_send_is_refunded_never_released_taproot(
            protocol = ProtocolVersion::Taproot,
            expected_spendable = 14_999_463,
        ),
    ],
)]
fn run_seen_failed_send_is_refunded(
    world: &mut World,
    expected_spendable: u64,
    params: SwapParams,
) {
    let (swap_id, _) = fail_first_send(world, params);
    wait_for_single_refund(world, &swap_id);
    assert_log!(world; {
        lacks release_line(&swap_id),
        lacks "can never confirm",
    });

    world.join_makers();
    world.mine(1);
    world.makers()[0].sync();
    // 14_999_757 before the swap, less the funding (154) and the refund; Legacy
    // also pays a contract tx. The coin comes back once, less only those fees.
    assert_balances!(world; {
        maker: { swap: 0, contract: 0, fidelity: BOND, spendable: expected_spendable },
    });
}
