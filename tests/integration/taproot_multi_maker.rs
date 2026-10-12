//! Integration test for multi-maker openswap with Taproot protocol.
//!
//! Setup: 1 taker with Normal behavior, 4 makers with Normal behavior.
//! Protocol: Taproot (MuSig2), AddressType::P2TR.
//! The taker routes the swap through all 4 makers.

use bitcoin::Amount;
use openswap::{
    maker::start_server,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use super::test_framework::*;

use log::{info, warn};
use std::thread;

#[test]
fn test_taproot_multi_maker_openswap() {
    // ---- Setup ----
    warn!("Running Test: Multi-Maker OpenSwap with Taproot (MuSig2) Protocol - 4 Makers");

    let maker_count = 4;
    let taker_behavior = vec![TakerBehavior::Normal];

    // Initialize test framework with 1 taker and 4 makers
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(maker_count, taker_behavior, vec![]);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 5 UTXOs of 0.05 BTC each (P2TR for Taproot)
    // Need more UTXOs for a 4-maker route
    let taker_original_balance = fund_taker_default(taker, bitcoind, 5);

    // Fund makers with 4 UTXOs of 0.05 BTC each
    fund_makers_default(&makers, bitcoind);

    // Start the maker server threads
    log::info!("Starting Maker servers...");

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    // Wait for all makers to complete setup
    wait_for_makers_setup(&makers, 120);

    // Sync wallets after setup to ensure fidelity bonds are accounted for
    sync_maker_wallets(&makers);

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    log::info!("Starting end-to-end swap test with Taproot protocol and 4 makers...");

    // Swap params for openswap (Taproot) with 4 makers
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 4)
        .with_tx_count(3)
        .with_required_confirms(1);

    // Mine some blocks before the swap to ensure wallet is ready
    generate_blocks(bitcoind, 1);

    // Prepare the swap (negotiate with makers, get fee summary)
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare Taproot openswap with 4 makers");
    log::info!("Swap summary: {:?}", summary);

    // Execute the swap
    match taker.start_swap(&summary.swap_id) {
        Ok(report) => {
            log::info!("OpenSwap (Taproot, 4 makers) completed successfully!");
            log::info!("Swap report: {:?}", report);
        }
        Err(e) => {
            log::error!("OpenSwap (Taproot, 4 makers) failed: {:?}", e);
            panic!("OpenSwap (Taproot, 4 makers) failed: {:?}", e);
        }
    }

    log::info!("All openswaps processed successfully. Transaction complete.");

    // Sync wallets and verify results
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    // Mine a block to confirm the sweep transactions
    generate_blocks(bitcoind, 1);

    // Synchronize each maker's wallet
    for maker in makers.iter() {
        let mut wallet = maker.wallet.write().unwrap();
        wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    }

    let taker_balances_after = taker.get_wallet().read().unwrap().get_balances().unwrap();
    info!("Taker balance after completing swap (Taproot, 4 makers):");
    info!(
        "  Regular: {}, Contract: {}, Spendable: {}, Swap: {}",
        taker_balances_after.regular,
        taker_balances_after.contract,
        taker_balances_after.spendable,
        taker_balances_after.swap,
    );

    // Verify swap results
    let balance_diff = taker_original_balance - taker_balances_after.spendable;
    info!(
        "Taker (Taproot, 4 makers) balance verification passed. Original spendable: {}, After spendable: {} (fees paid: {})",
        taker_original_balance,
        taker_balances_after.spendable,
        balance_diff
    );

    assert_eq!(
        taker_balances_after.spendable.to_sat(),
        24993271,
        "Taker spendable balance mismatch"
    );
    assert_eq!(
        taker_balances_after.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances_after.fidelity, Amount::ZERO);
    assert_eq!(balance_diff.to_sat(), 6729, "Taker fee paid mismatch");

    // Verify all 4 makers earned fees
    let expected_regular = [14501321, 14502814, 14504270, 14505688];
    let expected_swap = [499169, 497638, 496145, 494689];
    let expected_fees = [733, 695, 658, 620];
    for (i, (maker, original_spendable)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        let wallet = maker.wallet.read().unwrap();
        let balances = wallet.get_balances().unwrap();

        info!(
            "Maker {} final balances - Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.fidelity, balances.spendable,
        );

        assert_eq!(
            balances.regular.to_sat(),
            expected_regular[i],
            "Maker {} regular balance mismatch",
            i
        );
        assert_eq!(
            balances.swap.to_sat(),
            expected_swap[i],
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
            .checked_sub(original_spendable)
            .unwrap_or(Amount::ZERO);

        info!("Maker {} fee earned: {} sats", i, maker_fee.to_sat());

        assert_eq!(
            maker_fee.to_sat(),
            expected_fees[i],
            "Maker {} fee earned mismatch",
            i
        );
    }

    info!("All multi-maker swap tests (Taproot, 4 makers) completed successfully!");

    shutdown_makers(&makers, maker_threads);

    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// Each maker's fee in the summary and in the report must be priced on that
/// maker's own negotiated amount. A running amount seeded from maker 0 misses
/// the funding and sweep fees each hop loses, so it overprices later makers.
#[test]
fn test_taproot_multi_maker_fees_priced_on_each_makers_amount() {
    warn!("Running Test: Taproot multi-maker fee breakdown uses each maker's amount");

    // A 1% amount fee on the second maker turns a basis error of a few hundred
    // sats into a visible fee error.
    let fee_overrides = vec![
        None,
        Some(MakerFeeOverride {
            base_fee: 500,
            amount_relative_fee_pct: 1.0,
        }),
    ];
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_fee_overrides::<BitcoindBackend>(
            vec![(0, None); 2],
            fee_overrides,
            vec![TakerBehavior::Normal],
            vec![],
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker_default(taker, bitcoind, 3);
    fund_makers_default(&makers, bitcoind);

    let maker_threads = spawn_makers(&makers);
    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);

    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_required_confirms(1);
    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare Taproot swap with 2 makers");
    let report = taker
        .start_swap(&summary.swap_id)
        .expect("Taproot swap with 2 makers failed");

    assert_eq!(summary.makers.len(), 2);
    assert_eq!(report.maker_fee_info.len(), 2);
    for (i, quoted) in summary.makers.iter().enumerate() {
        let maker = makers
            .iter()
            .find(|maker| {
                quoted
                    .address
                    .ends_with(&format!(":{}", maker.config.network_port))
            })
            .unwrap_or_else(|| panic!("no maker serves route address {}", quoted.address));

        // The maker records what it was declared and the fee it charged on it.
        let report_path = maker
            .data_dir
            .join("wallets")
            .join(format!("{}_swap_report.json", maker.config.wallet_name));
        let maker_report = wait_for_maker_report(&report_path, &summary.swap_id);
        let negotiated = maker_report["incoming_amount"].as_u64().unwrap();
        let fee_earned = maker_report["fee_earned"].as_u64().unwrap();
        info!("Maker {i}: negotiated {negotiated} sats, fee earned {fee_earned} sats");

        assert_eq!(
            quoted.estimated_fee_sats, fee_earned,
            "Maker {} summary fee is not priced on its negotiated amount",
            i
        );

        let priced = |pct: f64| (pct * negotiated as f64 / 100.0).ceil();
        let reported = &report.maker_fee_info[i];
        assert_eq!(
            reported.amount_relative_fee,
            priced(quoted.amount_relative_fee_pct),
            "Maker {} report amount fee is not priced on its negotiated amount",
            i
        );
        assert_eq!(
            reported.time_relative_fee,
            priced(quoted.time_relative_fee_pct * quoted.locktime as f64),
            "Maker {} report time fee is not priced on its negotiated amount",
            i
        );
    }

    shutdown_makers(&makers, maker_threads);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// Waits for the maker's success report for `swap_id`; the maker writes it
/// after its own sweep, which can land after the taker returns.
fn wait_for_maker_report(path: &std::path::Path, swap_id: &str) -> serde_json::Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let report = std::fs::read_to_string(path)
            .ok()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
            .and_then(|file| {
                file["maker"]
                    .as_object()?
                    .values()
                    .filter_map(|reports| reports.as_array())
                    .flatten()
                    .find(|report| report["swap_id"] == swap_id)
                    .cloned()
            });
        if let Some(report) = report {
            return report;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "maker report for {} never appeared at {}",
            swap_id,
            path.display()
        );
        thread::sleep(std::time::Duration::from_secs(1));
    }
}
