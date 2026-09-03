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
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{sync::atomic::Ordering::Relaxed, thread};

#[test]
fn test_taproot_multi_maker_openswap() {
    // ---- Setup ----
    warn!("Running Test: Multi-Maker OpenSwap with Taproot (MuSig2) Protocol - 4 Makers");

    let makers_config_map = vec![
        (7802, Some(20801)),
        (17802, Some(20802)),
        (27802, Some(20803)),
        (37802, Some(20804)),
    ];
    let taker_behavior = vec![TakerBehavior::Normal];

    // Initialize test framework with 1 taker and 4 makers
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, vec![]);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 5 UTXOs of 0.05 BTC each (P2TR for Taproot)
    // Need more UTXOs for a 4-maker route
    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        5,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Fund makers with 4 UTXOs of 0.05 BTC each
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

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
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    log::info!("Starting end-to-end swap test with Taproot protocol and 4 makers...");

    // Swap params for openswap (Taproot) with 4 makers
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 4)
        .with_tx_count([3, 3])
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
        24989231,
        "Taker spendable balance mismatch"
    );
    assert_eq!(
        taker_balances_after.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances_after.fidelity, Amount::ZERO);
    assert_eq!(balance_diff.to_sat(), 10769, "Taker fee paid mismatch");

    // Verify all 4 makers earned fees
    let expected_regular = [14500940, 14503252, 14505526, 14507763];
    let expected_swap = [499328, 496978, 494666, 492392];
    let expected_fees = [754, 716, 678, 641];
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

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    test_framework.stop();
    block_generation_handle.join().unwrap();
}
