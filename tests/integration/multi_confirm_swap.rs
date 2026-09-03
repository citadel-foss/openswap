//! Swaps that wait for more than one funding confirmation.
//!
//! Every other test passes `with_required_confirms(1)`, so the confirmation-wait
//! loop and the `WaitingFundingConfirmation` keepalive never run. Without the
//! keepalive a maker would mistake a long funding wait for a dropped taker and
//! start recovering contracts mid-swap.
//!
//! Both protocols are covered: the wait sites differ (`legacy_swap.rs` vs
//! `taproot_swap.rs`) even though the keepalive message is shared.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    utill::NO_SHUTDOWN,
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{sync::atomic::Ordering::Relaxed, thread};

/// Confirmations to wait for on every funding tx.
///
/// This has to beat the ~3 blocks mined during `MAKER_BROADCAST_DELAY`, or the
/// first poll already sees enough confirmations, returns immediately, and the
/// keepalive never gets sent. At 15 the wait sleeps once (10s) and fires one
/// keepalive per hop, which is all this test needs.
const REQUIRED_CONFIRMS: u32 = 15;

#[test]
fn test_legacy_multi_confirm_swap() {
    warn!("Running Test: Legacy Swap With required_confirms > 1");
    run_multi_confirm_swap(
        ProtocolVersion::Legacy,
        vec![(9102, Some(21401)), (19102, Some(21402))],
    );
}

#[test]
fn test_taproot_multi_confirm_swap() {
    warn!("Running Test: Taproot Swap With required_confirms > 1");
    run_multi_confirm_swap(
        ProtocolVersion::Taproot,
        vec![(9202, Some(21501)), (19202, Some(21502))],
    );
}

fn run_multi_confirm_swap(protocol: ProtocolVersion, makers_config_map: Vec<(u16, Option<u16>)>) {
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

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

    info!("Starting Maker servers...");
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);

    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(REQUIRED_CONFIRMS);

    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare openswap");
    taker
        .start_swap(&summary.swap_id)
        .expect("OpenSwap should complete successfully despite the longer funding wait");

    info!("OpenSwap completed with required_confirms = {REQUIRED_CONFIRMS}");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();
    generate_blocks(bitcoind, 1);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
    }

    // The swap succeeding is not enough: without these two lines it could have
    // taken the single-confirmation path and proved nothing.
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log(
        &format!("Waiting for {REQUIRED_CONFIRMS} confirmation(s)"),
        &log_path,
    );
    test_framework.assert_log("Taker is waiting for funding confirmation", &log_path);

    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    info!(
        "Taker balances: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    let expected_taker_regular = 14499076;
    let expected_taker_swap = match protocol {
        ProtocolVersion::Legacy => 494587,
        ProtocolVersion::Taproot => 494815,
    };
    assert_eq!(
        taker_balances.regular.to_sat(),
        expected_taker_regular,
        "Taker regular balance mismatch"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        expected_taker_swap,
        "Taker swap balance mismatch"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    // Waiting longer must not change what the swap costs.
    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap();
    info!("Taker fees paid: {} sats", balance_diff.to_sat());
    let expected_diff = match protocol {
        ProtocolVersion::Legacy => 6337,
        ProtocolVersion::Taproot => 6109,
    };
    assert_eq!(
        balance_diff.to_sat(),
        expected_diff,
        "Taker spendable balance change mismatch"
    );

    let expected_regular = [14500865u64, 14503103];
    let expected_swap = match protocol {
        ProtocolVersion::Legacy => [499100u64, 496825],
        ProtocolVersion::Taproot => [499328u64, 497053],
    };
    let expected_fee = match protocol {
        ProtocolVersion::Legacy => [451u64, 414],
        ProtocolVersion::Taproot => [679u64, 642],
    };

    for (i, (maker, original)) in makers.iter().zip(maker_spendable_balance).enumerate() {
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
            .checked_sub(original)
            .unwrap_or(Amount::ZERO);
        info!("Maker {} fee earned: {} sats", i, maker_fee.to_sat());
        assert_eq!(
            maker_fee.to_sat(),
            expected_fee[i],
            "Maker {} fee earned mismatch",
            i
        );
    }

    info!("Multi-confirmation swap test completed successfully!");

    test_framework.stop();
    block_generation_handle.join().unwrap();
}
