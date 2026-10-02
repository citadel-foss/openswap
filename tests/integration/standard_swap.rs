//! Standard openswap test: normal swap between a Taker and 2 Makers.
//! Nothing goes wrong and the openswap completes successfully.
//! Also asserts a 3-hop request is rejected up front when only 2 makers exist.

use bitcoin::Amount;
use openswap::{
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, SwapParams},
};

use super::test_framework::*;

use log::info;
use std::{fs, thread, time::Duration};

/// This test demonstrates a standard openswap round between a Taker and 2 Makers. Nothing goes wrong
/// and the openswap completes successfully.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances() as maker_spendable_balance,
    ],
)]
fn legacy_two_maker_swap_completes(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
) {
    // Only 2 makers are running, so a 3-hop route must fail at discovery
    // before any funds are committed.
    let too_many_hops = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 3)
        .with_tx_count(3)
        .with_required_confirms(1);
    let err = world
        .taker_mut()
        .prepare(too_many_hops)
        .expect_err("prepare_swap must fail with only 2 makers for a 3-hop swap");
    assert!(
        matches!(err, TakerError::NotEnoughMakersInOfferBook),
        "Expected NotEnoughMakersInOfferBook, got: {:?}",
        err
    );

    // Initiate OpenSwap
    info!("Initiating openswap protocol");

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);
    let swap_start_height = chain_tip(world.bitcoind()) + 1;

    world
        .taker_mut()
        .swap(swap_params)
        .expect("OpenSwap should complete successfully");

    info!("All openswaps processed successfully. Transaction complete.");

    // Sync wallets
    world.taker().sync();

    world.mine(1);

    for maker in world.makers() {
        maker.sync();
    }

    // Verify taker balances
    info!("Verifying swap results");
    let taker_balances = world.taker().balances();

    info!(
        "Taker balances: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    BalanceExpect {
        regular: Some(Is::Sats(14499538)),
        swap: Some(Is::Sats(496447)),
        contract: Some(Is::Sats(0)),
        fidelity: Some(Is::Amount(Amount::ZERO)),
        spendable: None,
        delta: Some(Delta::Loss {
            baseline: taker_original_balance,
            style: DiffStyle::CheckedUnwrap,
            sats: 4015,
        }),
    }
    .assert("Taker", &taker_balances);

    // Verify maker balances
    let expected_regular = [14500865u64, 14502398];
    let expected_swap = [499550u64, 497980];
    let expected_fee = [658u64, 621];
    for (i, (maker, original)) in world
        .makers()
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        maker.sync();
        let balances = maker.balances();

        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i,
            balances.regular,
            balances.swap,
            balances.contract,
            balances.fidelity,
            balances.spendable,
        );

        BalanceExpect {
            regular: Some(Is::Sats(expected_regular[i])),
            swap: Some(Is::Sats(expected_swap[i])),
            contract: Some(Is::Sats(0)),
            fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
            spendable: None,
            delta: Some(Delta::Gain {
                baseline: original,
                style: DiffStyle::UnwrapOrZero,
                sats: expected_fee[i],
            }),
        }
        .assert(&format!("Maker {i}"), &balances);
    }

    // Every swap tx must pay the negotiated 1 sat/vB: funding txs price their
    // real vsize; sweeps pay the 150 vB legacy spend model they were built at.
    // A completed swap mines 9 funding txs (3 splits x 3 parties) and 9 sweeps.
    let bitcoind = world.bitcoind();
    let depths = wait_for_tx_depths(bitcoind, swap_start_height, &[9, 9]);
    for txid in &depths[0] {
        let (fee, vsize) = tx_fee_and_vsize(bitcoind, txid);
        assert_eq!(
            fee, vsize as u64,
            "funding tx {txid} must pay exactly 1 sat/vB"
        );
    }
    for txid in &depths[1] {
        let (fee, vsize) = tx_fee_and_vsize(bitcoind, txid);
        assert_eq!(fee, 150, "sweep tx {txid} must pay the 150 vB model");
        assert!(vsize <= 150, "sweep tx {} exceeds its 150 vB model", txid);
    }

    info!("Standard openswap test completed successfully!");

    let taker_report_path = world
        .temp_dir()
        .join("taker1")
        .join("wallets")
        .join("taker1_swap_report.json");
    assert_report_has_deniability_proofs(&taker_report_path, "taker", bitcoind, 1);

    for (i, maker) in world.makers().iter().enumerate() {
        assert_report_has_deniability_proofs(
            &maker.report_path(),
            &format!("maker {i}"),
            bitcoind,
            1,
        );
    }
}

/// A swap at 3 sats/vB: every swap transaction is built and priced at the
/// negotiated rate, so the taker pays more than at the 1 sat/vB floor and the
/// swap still completes.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        spawn_ready_makers_and_mine(),
    ],
    cases = [
        taproot_swap_at_custom_feerate(
            protocol = ProtocolVersion::Taproot,
            expected_fee_paid = 3846,
            sweep_vsize_model = 112,
        ),
        /// Same 3 sats/vB swap on Legacy: funding txs price their real vsize and the
        /// multisig contract sweeps pay the 150 vB model at the negotiated rate.
        legacy_swap_at_custom_feerate(
            protocol = ProtocolVersion::Legacy,
            expected_fee_paid = 4302,
            sweep_vsize_model = 150,
        ),
    ],
)]
fn run_swap_with_custom_feerate(
    world: &mut World,
    taker_original_balance: Amount,
    protocol: ProtocolVersion,
    expected_fee_paid: u64,
    sweep_vsize_model: u64,
) {
    let swap_start_height = chain_tip(world.bitcoind()) + 1;

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500_000), 1)
        .with_tx_count(2)
        .with_feerate(3)
        .with_required_confirms(1);
    world
        .taker_mut()
        .swap(swap_params)
        .expect("swap at a custom feerate must complete");

    world.mine(1);
    world.taker().sync();
    let balances = world.taker().balances();
    let fee_paid = taker_original_balance
        .checked_sub(balances.spendable)
        .unwrap();
    info!("Taker fee at 3 sats/vB: {} sats", fee_paid.to_sat());
    // Pinned from a real run: the two cooperative sweeps pay the bare sweep
    // vsize model at the negotiated 3 sats/vB rate.
    assert_eq!(
        fee_paid.to_sat(),
        expected_fee_paid,
        "custom feerate cost mismatch"
    );
    assert!(
        fee_paid.to_sat() > 2_000,
        "a 3 sat/vB swap must cost clearly more than the floor rate"
    );

    // Same per-kind check at the negotiated 3 sat/vB: funding txs price their
    // real vsize; the sweeps pay the protocol's fixed vsize model.
    // 1 maker x 2 splits: 4 funding txs (2 taker + 2 maker), 4 sweeps.
    let bitcoind = world.bitcoind();
    let depths = wait_for_tx_depths(bitcoind, swap_start_height, &[4, 4]);
    for txid in &depths[0] {
        let (fee, vsize) = tx_fee_and_vsize(bitcoind, txid);
        assert_eq!(
            fee,
            vsize as u64 * 3,
            "funding tx {txid} must pay exactly 3 sat/vB"
        );
    }
    for txid in &depths[1] {
        let (fee, vsize) = tx_fee_and_vsize(bitcoind, txid);
        assert_eq!(
            fee,
            sweep_vsize_model * 3,
            "sweep tx {txid} must pay the {sweep_vsize_model} vB model at 3"
        );
        assert!(
            vsize as u64 <= sweep_vsize_model,
            "sweep tx {} exceeds its {} vB model",
            txid,
            sweep_vsize_model
        );
    }
}

/// A maker blocked in its contract-confirmation wait refreshes the swap's
/// stored activity on every poll, so a contract tx sitting unconfirmed past
/// the 30s idle timeout is not drained mid-wait. Mining is paused before the
/// swap starts so the maker blocks in `wait_for_tx_on_chain`; the 40s hold
/// crosses an idle-drain pass, and the +60s poll slot catches the confirming
/// block inside the taker's 180s response window.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [SkipFundingConfirmWait],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances() as maker_spendable_balance,
        mine(1),
    ],
)]
fn taproot_swap_survives_unconfirmed_confirmation_wait(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
) {
    // The taker skips its own confirmation wait, so its contract data reaches
    // the maker unconfirmed and parks the maker in its wait.
    let swap_params =
        SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1).with_tx_count(2);
    // The swap runs on its own thread, so the taker leaves the world here.
    let mut taker = world.take_taker();
    let summary = taker.prepare(swap_params).expect("prepare swap");

    let log_path = world.taker_log_path();
    let log_offset = fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    // Hold every contract tx unconfirmed: the maker claims them and blocks in
    // the confirmation wait instead of answering.
    world.framework().set_block_gen_paused(true);
    let swap_handle = thread::spawn(move || {
        let result = taker.start(&summary.swap_id);
        (taker, result)
    });

    // "confirmation(s) on tx" is logged only by the maker's wait_for_tx_on_chain.
    wait_logged!(world, "confirmation(s) on tx", Duration::from_secs(120));

    // Hold the block past the maker's 30s idle timeout so an idle-drain pass
    // (every 3s) fires while the handler is parked: only the wait's activity
    // refresh keeps the swap alive. The next poll after mining (+60s backoff)
    // then sees the block, well inside the taker's 180s response window.
    thread::sleep(Duration::from_secs(40));
    world.framework().set_block_gen_paused(false);
    world.mine(1);

    let (taker, result) = swap_handle.join().expect("swap thread panicked");
    result.expect("the swap must complete across the idle timeout");

    // The waiting handler kept the swap alive: no idle drain fired.
    let log_contents = fs::read_to_string(&log_path).unwrap();
    let tail = log_contents
        .get(log_offset as usize..)
        .unwrap_or(log_contents.as_str());
    assert!(
        !tail.contains("Released idle unfunded swap"),
        "the waiting swap must not be drained as an idle unfunded swap"
    );
    assert!(
        !tail.contains("Potential dropped connection from taker"),
        "the waiting swap must not be drained into recovery"
    );

    world.mine(1);
    taker.sync();
    let taker_balances = taker.balances();
    let fee_paid = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap();
    info!(
        "Taker after paused swap: spendable={}, fee paid={}",
        taker_balances.spendable, fee_paid
    );
    // Pinned from a real run: one maker, two splits, all at the 1 sat/vB floor.
    // Spendable is checked ahead of contract and fidelity here, which is not
    // BalanceExpect's field order, so these stay plain asserts.
    assert_eq!(
        taker_balances.spendable.to_sat(),
        14998326,
        "Taker spendable balance mismatch"
    );
    assert_eq!(
        taker_balances.contract,
        Amount::ZERO,
        "Taker contract balance mismatch"
    );
    assert_eq!(
        taker_balances.fidelity,
        Amount::ZERO,
        "Taker fidelity balance mismatch"
    );

    let maker = &world.makers()[0];
    maker.sync();
    let maker_balances = maker.balances();
    let maker_fee = maker_balances
        .spendable
        .checked_sub(maker_spendable_balance[0])
        .unwrap_or(Amount::ZERO);
    info!("Maker fee earned across the pause: {} sats", maker_fee);
    // Pinned from a real run: pre-swap 14999757 + the 610 sats hop fee.
    assert_eq!(
        maker_balances.spendable.to_sat(),
        15000367,
        "Maker spendable balance mismatch"
    );
    assert_eq!(
        maker_balances.contract,
        Amount::ZERO,
        "Maker contract balance mismatch"
    );
    assert_eq!(
        maker_balances.fidelity,
        Amount::from_btc(0.05).unwrap(),
        "Maker fidelity balance mismatch"
    );

    info!("taproot_swap_survives_unconfirmed_confirmation_wait completed successfully!");

    // The taker left the world above; dropping it first keeps the world's
    // teardown order.
    drop(taker);
}
