//! Integration test for Taproot OpenSwap implementation.
//!
//! This test demonstrates a taproot-based openswap between a Taker and 2 Makers using
//! the Taproot protocol with MuSig2 signatures.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    sync::atomic::Ordering::Relaxed,
    thread,
    time::{Duration, Instant},
};

/// Test taproot openswap
#[test]
fn test_taproot_openswap() {
    // ---- Setup ----
    warn!("Running Test: Taproot OpenSwap Basic Functionality");

    let makers_config_map = vec![(7102, Some(19061)), (17102, Some(19062))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the Taproot Taker with 3 UTXOs of 0.05 BTC each (P2TR)
    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Fund the Taproot Makers with 4 UTXOs of 0.05 BTC each
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Start the maker server threads
    log::info!("Initiating Taproot Makers...");

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

    // Sync wallets after setup to ensure fidelity bonds are accounted for
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    log::info!("Starting end-to-end taproot swap test...");

    // Swap params for taproot openswap
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    // Mine some blocks before the swap to ensure wallet is ready
    generate_blocks(bitcoind, 1);

    // Prepare and execute the swap
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare Taproot openswap");
    taker
        .start_swap(&summary.swap_id)
        .expect("Taproot openswap should complete successfully");
    log::info!("Taproot openswap completed successfully!");

    // Sync wallets and verify results
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    // Maker sweeps run after the final protocol response. Mine until all of
    // them confirm so balance assertions include the maker-paid sweep fees.
    let sweep_deadline = Instant::now() + Duration::from_secs(30);
    while makers
        .iter()
        .any(|maker| maker.wallet.read().unwrap().get_incoming_swapcoins_count() > 0)
    {
        assert!(
            Instant::now() < sweep_deadline,
            "maker sweeps did not settle before timeout"
        );
        generate_blocks(bitcoind, 1);
        thread::sleep(Duration::from_millis(250));
    }

    for maker in makers.iter() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();

    info!(
        "Taproot Taker balance after swap: Regular: {}, Contract: {}, Spendable: {}, Swap: {}",
        taker_balances.regular,
        taker_balances.contract,
        taker_balances.spendable,
        taker_balances.swap,
    );

    assert_eq!(
        taker_balances.regular.to_sat(),
        14499076,
        "Taker regular balance mismatch"
    );
    assert_eq!(taker_balances.swap.to_sat(), 496279, "Taker swap balance");
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap();

    info!("Taproot Taker fees paid: {} sats", balance_diff.to_sat());

    assert_eq!(
        balance_diff.to_sat(),
        4645,
        "Taker spendable balance change"
    );

    // Verify makers earned fees
    let expected_regular_and_swap = [14999461, 14999424];
    let expected_fee = [0, 0];
    for (i, (maker, original_spendable)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();

        info!(
            "Taproot Maker {} final balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.fidelity, balances.spendable,
        );

        // Randomized contract sizes can move a change output between the regular
        // and swap buckets, but must not change the maker's total holdings.
        assert_eq!(
            (balances.regular + balances.swap).to_sat(),
            expected_regular_and_swap[i],
            "Maker {i} regular and swap balance"
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
            .checked_sub(original_spendable)
            .unwrap_or(Amount::ZERO);

        info!(
            "Taproot Maker {} fee earned: {} sats",
            i,
            maker_fee.to_sat()
        );

        assert_eq!(maker_fee.to_sat(), expected_fee[i], "Maker {i} fee earned");
    }

    info!("All taproot swap tests completed successfully!");

    let temp_dir = makers[0]
        .data_dir
        .parent()
        .expect("maker data dir should live under test temp dir");
    let taker_report_path = temp_dir
        .join("taker1")
        .join("wallets")
        .join("taker1_swap_report.json");
    assert_report_has_deniability_proofs(&taker_report_path, "taproot taker", bitcoind, 1);

    for (i, maker) in makers.iter().enumerate() {
        let maker_report_path = maker
            .data_dir
            .join("wallets")
            .join(format!("{}_swap_report.json", maker.config.wallet_name));
        assert_report_has_deniability_proofs(
            &maker_report_path,
            &format!("taproot maker {i}"),
            bitcoind,
            1,
        );
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
