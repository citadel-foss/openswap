//! Standard openswap test: normal swap between a Taker and 2 Makers.
//! Nothing goes wrong and the openswap completes successfully.
//! Also asserts a 3-hop request is rejected up front when only 2 makers exist.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{fs, sync::atomic::Ordering::Relaxed, thread, time::Duration};

/// This test demonstrates a standard openswap round between a Taker and 2 Makers. Nothing goes wrong
/// and the openswap completes successfully.
#[test]
fn test_standard_openswap() {
    // ---- Setup ----
    warn!("Running Test: Standard OpenSwap Procedure");

    let makers_config_map = vec![(6102, Some(19051)), (16102, Some(19052))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 3 UTXOs of 0.05 BTC each
    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Start the maker server threads
    log::info!("Initiating Maker servers");

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    // Wait for makers to complete setup
    wait_for_makers_setup(&makers, 120);

    // Sync wallets after setup
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);

    // Only 2 makers are running, so a 3-hop route must fail at discovery
    // before any funds are committed.
    let too_many_hops = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 3)
        .with_tx_count(3)
        .with_required_confirms(1);
    let err = taker
        .prepare_swap(too_many_hops)
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

    generate_blocks(bitcoind, 1);
    let swap_start_height = chain_tip(bitcoind) + 1;

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare openswap");
    taker
        .start_swap(&summary.swap_id)
        .expect("OpenSwap should complete successfully");

    info!("All openswaps processed successfully. Transaction complete.");

    // Sync wallets
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    generate_blocks(bitcoind, 1);

    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    // Verify taker balances
    info!("Verifying swap results");
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();

    info!(
        "Taker balances: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    assert_eq!(
        taker_balances.regular.to_sat(),
        14499538,
        "Taker regular balance mismatch"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        496123,
        "Taker swap balance mismatch"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap();

    info!("Taker fees paid: {} sats", balance_diff.to_sat());

    assert_eq!(
        balance_diff.to_sat(),
        4339,
        "Taker spendable balance change mismatch"
    );

    // Verify maker balances
    for (i, (maker, original)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();

        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i,
            balances.regular,
            balances.swap,
            balances.contract,
            balances.fidelity,
            balances.spendable,
        );

        let expected_regular = [14501027u64, 14502722][i];
        let expected_swap = [499550u64, 497818][i];
        assert_eq!(
            balances.regular.to_sat(),
            expected_regular,
            "Maker {} regular balance mismatch",
            i
        );
        assert_eq!(
            balances.swap.to_sat(),
            expected_swap,
            "Maker {} swap balance mismatch",
            i
        );
        assert_eq!(
            balances.contract.to_sat(),
            0,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());

        let maker_fee = balances
            .spendable
            .checked_sub(original)
            .unwrap_or(Amount::ZERO);

        info!("Maker {} fee earned: {} sats", i, maker_fee.to_sat());

        let expected_fee = [820u64, 783][i];
        assert_eq!(
            maker_fee.to_sat(),
            expected_fee,
            "Maker {} fee earned mismatch",
            i
        );
    }

    // Every swap tx must pay the negotiated 1 sat/vB: funding txs price their
    // real vsize; sweeps pay the 150 vB legacy spend model they were built at.
    // A completed swap mines 9 funding txs (3 splits x 3 parties) and 9 sweeps.
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

    let temp_dir = makers[0]
        .data_dir
        .parent()
        .expect("maker data dir should live under test temp dir");
    let taker_report_path = temp_dir
        .join("taker1")
        .join("wallets")
        .join("taker1_swap_report.json");
    assert_report_has_deniability_proofs(&taker_report_path, "taker", bitcoind, 1);

    for (i, maker) in makers.iter().enumerate() {
        let maker_report_path = maker
            .data_dir
            .join("wallets")
            .join(format!("{}_swap_report.json", maker.config.wallet_name));
        assert_report_has_deniability_proofs(
            &maker_report_path,
            &format!("maker {i}"),
            bitcoind,
            1,
        );
    }

    drop(takers);
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// A swap at 3 sats/vB: every swap transaction is built and priced at the
/// negotiated rate, so the taker pays more than at the 1 sat/vB floor and the
/// swap still completes.
#[test]
fn test_swap_with_custom_feerate() {
    warn!("Running Test: OpenSwap with a custom feerate");

    let makers_config_map = vec![(9203, Some(21503))];
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            makers_config_map,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);
    let swap_start_height = chain_tip(bitcoind) + 1;

    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
        .with_tx_count(2)
        .with_feerate(3)
        .with_required_confirms(1);
    let summary = taker.prepare_swap(swap_params).expect("prepare swap");
    taker
        .start_swap(&summary.swap_id)
        .expect("swap at a custom feerate must complete");

    generate_blocks(bitcoind, 1);
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    let fee_paid = taker_original_balance
        .checked_sub(balances.spendable)
        .unwrap();
    info!("Taker fee at 3 sats/vB: {} sats", fee_paid.to_sat());
    // Pinned from a real run: 3722 at the old floor-priced sweeps, +448 because
    // the two cooperative sweeps now pay the negotiated rate (2 x 112 vB x (3-1)).
    assert_eq!(fee_paid.to_sat(), 4170, "custom feerate cost mismatch");
    assert!(
        fee_paid.to_sat() > 2_000,
        "a 3 sat/vB swap must cost clearly more than the floor rate"
    );

    // Same per-kind check at the negotiated 3 sat/vB: funding txs price their
    // real vsize; the taproot key-path sweeps pay the 112 vB model (3 x 112).
    // 1 maker x 2 splits: 4 funding txs (2 taker + 2 maker), 4 sweeps.
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
        assert_eq!(fee, 336, "sweep tx {txid} must pay the 112 vB model at 3");
        assert!(vsize <= 112, "sweep tx {} exceeds its 112 vB model", txid);
    }

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// A maker blocked in its contract-confirmation wait refreshes the swap's
/// stored activity on every poll, so a contract tx sitting unconfirmed past
/// the 30s idle timeout is not drained mid-wait. Mining is paused before the
/// swap starts so the maker blocks in `wait_for_tx_on_chain`; the resume is
/// timed against the maker's wait-start log line so its ~30s poll slot catches
/// the confirming block inside the taker's 60s response window.
#[test]
fn taproot_swap_survives_unconfirmed_confirmation_wait() {
    warn!("Running Test: maker confirmation wait survives the idle timeout");

    let makers_config_map = vec![(9203, Some(21503))];
    let (test_framework, takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            makers_config_map,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;
    let mut taker = takers.into_iter().next().unwrap();
    let taker_original_balance = fund_taker(
        &taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    generate_blocks(bitcoind, 1);

    // required_confirms 0 skips the taker's own confirmation wait, so its
    // contract data reaches the maker unconfirmed; the maker's own floor of 1
    // confirmation is what parks it in the wait.
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
        .with_tx_count(2)
        .with_required_confirms(0);
    let summary = taker.prepare_swap(swap_params).expect("prepare swap");

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let log_offset = fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    // Hold every contract tx unconfirmed: the maker claims them and blocks in
    // the confirmation wait instead of answering.
    test_framework.set_block_gen_paused(true);
    let swap_handle = thread::spawn(move || {
        let result = taker.start_swap(&summary.swap_id);
        (taker, result)
    });

    // "confirmation(s) on tx" is logged only by the maker's wait_for_tx_on_chain.
    wait_for_log(&log_path, "confirmation(s) on tx", Duration::from_secs(120));

    // The wait's poll backoff is 10s, 20s, 30s: resume and mine so the +30s
    // poll sees the block, well inside the taker's 60s response window. By
    // then the maker has been in the wait past the 30s idle timeout.
    thread::sleep(Duration::from_secs(25));
    test_framework.set_block_gen_paused(false);
    generate_blocks(bitcoind, 1);

    let (taker, result) = swap_handle.join().expect("swap thread panicked");
    result.expect("the swap must complete across the idle timeout");

    // The waiting handler kept the swap alive: no idle drain fired.
    let log_contents = fs::read_to_string(&log_path).unwrap();
    let tail = &log_contents[log_offset as usize..];
    assert!(
        !tail.contains("Released idle unfunded reservation"),
        "the waiting swap must not be drained as an idle unfunded reservation"
    );
    assert!(
        !tail.contains("Potential dropped connection from taker"),
        "the waiting swap must not be drained into recovery"
    );

    generate_blocks(bitcoind, 1);
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    let fee_paid = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap();
    info!(
        "Taker after paused swap: spendable={}, fee paid={}",
        taker_balances.spendable, fee_paid
    );
    // Pinned from a real run: one maker, two splits, all at the 1 sat/vB floor.
    assert_eq!(
        taker_balances.spendable.to_sat(),
        14998218,
        "Taker spendable balance mismatch"
    );
    assert_eq!(taker_balances.contract, Amount::ZERO);
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    let maker = &makers[0];
    maker
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let maker_balances = maker.wallet.read().unwrap().get_balances().unwrap();
    let maker_fee = maker_balances
        .spendable
        .checked_sub(maker_spendable_balance[0])
        .unwrap_or(Amount::ZERO);
    info!("Maker fee earned across the pause: {} sats", maker_fee);
    // Pinned from a real run: pre-swap 14999757 + the 718 sats hop fee.
    assert_eq!(
        maker_balances.spendable.to_sat(),
        15000475,
        "Maker spendable balance mismatch"
    );
    assert_eq!(maker_balances.contract, Amount::ZERO);
    assert_eq!(maker_balances.fidelity, Amount::from_btc(0.05).unwrap());

    info!("taproot_swap_survives_unconfirmed_confirmation_wait completed successfully!");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(taker);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
