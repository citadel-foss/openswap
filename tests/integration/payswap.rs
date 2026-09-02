//! PaySwap integration tests: settling a openswap to a third-party receiver
//! for an exact amount.
//!
//! The receiver is the regtest node's wallet — a genuine third party whose
//! received total can be queried. Verifies the exact receipt, that the taker
//! owns no swap output, the confirmed payment result in the report,
//! wrong-network rejection, and per-output rounding across multiple final
//! swapcoins (`tx_count > 1`).

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    wallet::AddressType,
};

use bitcoind::bitcoincore_rpc::RpcApi;

use super::test_framework::*;

use log::{info, warn};
use std::{sync::atomic::Ordering::Relaxed, thread};

/// Taproot PaySwap with multiple final swapcoins (`tx_count = 3`), so the
/// settlement splits the receiver amount across several exact outputs.
#[test]
fn test_taproot_payswap() {
    // ---- Setup ----
    warn!("Running Test: Taproot PaySwap - exact payment to third-party receiver");

    let makers_config_map = vec![(6012, Some(19011)), (16012, Some(19012))];
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

    wait_for_makers_setup(&makers, 120);

    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    verify_maker_pre_swap_balances(&makers);

    let receiver_address = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let payment_amount = Amount::from_sat(500_000);

    generate_blocks(bitcoind, 1);

    // A wrong-network receiver address must be rejected up front.
    let mainnet_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        .parse()
        .unwrap();
    let wrong_network_result = taker.prepare_swap(
        SwapParams::new(ProtocolVersion::Taproot, payment_amount, 2)
            .with_tx_count(3)
            .with_required_confirms(1)
            .with_payment_address(mainnet_address),
    );
    let wrong_network_err = format!(
        "{:?}",
        wrong_network_result.expect_err("mainnet receiver address must be rejected")
    );
    assert!(
        wrong_network_err.contains("not valid for the wallet network"),
        "Unexpected wrong-network error: {}",
        wrong_network_err
    );

    // ---- The actual payment swap ----
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, payment_amount, 2)
        .with_tx_count(3)
        .with_required_confirms(1)
        .with_payment_address(receiver_address.as_unchecked().clone());

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare Taproot payment swap");

    let quote = summary
        .payment
        .as_ref()
        .expect("payment swap summary must carry a payment quote");
    info!(
        "Payment quote: amount={}, settlement_budget={}, route_amount={}",
        quote.amount, quote.settlement_budget, summary.send_amount
    );
    assert_eq!(quote.amount, payment_amount);
    assert_eq!(quote.address, receiver_address);
    assert!(quote.settlement_budget > Amount::ZERO);
    assert_eq!(
        quote.settlement_budget.to_sat() % 3,
        0,
        "settlement budget must divide exactly across all final swapcoins"
    );
    assert!(
        summary.send_amount > payment_amount + quote.settlement_budget,
        "gross route amount must cover the receiver amount, settlement budget, and maker fees"
    );

    let report = taker
        .start_swap(&summary.swap_id)
        .expect("Taproot payment swap should complete successfully");

    // ---- Verify the exact payment ----
    generate_blocks(bitcoind, 1);

    let received = bitcoind
        .client
        .get_received_by_address(&receiver_address, Some(1))
        .unwrap();
    assert_eq!(
        received, payment_amount,
        "Receiver must get exactly the requested amount"
    );

    let payment_result = report
        .payment
        .as_ref()
        .expect("payment swap report must carry a payment result");
    assert!(payment_result.confirmed, "payment must report confirmed");
    assert_eq!(payment_result.requested_amount, payment_amount.to_sat());
    assert_eq!(payment_result.delivered_amount, payment_amount.to_sat());
    assert_eq!(report.incoming_amount, 0);
    assert!(report.incoming_utxos.is_empty());
    assert!(report.output_swap_amounts.is_empty());
    assert!(report.output_swap_utxos.is_empty());
    assert!(
        !report.outgoing_utxos.is_empty(),
        "PaySwap must still report the taker funding inputs"
    );
    assert!(
        report.fee_paid < payment_amount.to_sat(),
        "receiver payment principal must not be reported as a fee"
    );
    assert_eq!(
        report.mining_fee,
        report.fee_paid.saturating_sub(report.total_maker_fees),
        "mining fee must be derived after excluding the receiver payment"
    );
    assert_eq!(
        payment_result.settlement_txids.len(),
        3,
        "one settlement tx per final swapcoin"
    );

    // The taker must own no output of the settlement.
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    info!(
        "Taker balances after payment swap: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );
    assert_eq!(
        taker_balances.swap,
        Amount::ZERO,
        "Taker must not own any swap output after a payment swap"
    );
    assert_eq!(taker_balances.contract, Amount::ZERO);

    let spendable_decrease = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .expect("payment swap must cost the taker its route amount");
    info!(
        "Taker wallet cost: {} sats (route amount {} sats)",
        spendable_decrease.to_sat(),
        summary.send_amount.to_sat()
    );
    assert!(
        spendable_decrease >= summary.send_amount,
        "wallet cost must cover the gross route amount"
    );
    assert_eq!(
        spendable_decrease.to_sat(),
        payment_result.delivered_amount + report.fee_paid,
        "wallet cost must equal the delivered payment plus reported fees"
    );

    info!("Taproot PaySwap test completed successfully!");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// Legacy PaySwap: the settlement budget covers both contract publication and
/// the contract spend, and the cooperative sweep delivers the exact amount.
/// Cooperative path only — recovery is not exercised here.
#[test]
fn test_legacy_payswap() {
    // ---- Setup ----
    warn!("Running Test: Legacy PaySwap - exact payment to third-party receiver");

    let makers_config_map = vec![(7012, Some(19021)), (17012, Some(19022))];
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

    wait_for_makers_setup(&makers, 120);

    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    verify_maker_pre_swap_balances(&makers);

    let receiver_address = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let payment_amount = Amount::from_sat(500_000);

    generate_blocks(bitcoind, 1);

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, payment_amount, 2)
        .with_required_confirms(1)
        .with_payment_address(receiver_address.as_unchecked().clone());

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare Legacy payment swap");
    let quote = summary
        .payment
        .as_ref()
        .expect("payment swap summary must carry a payment quote");
    info!(
        "Payment quote: amount={}, settlement_budget={}, route_amount={}",
        quote.amount, quote.settlement_budget, summary.send_amount
    );
    assert_eq!(quote.amount, payment_amount);
    assert_eq!(quote.address, receiver_address);
    assert!(quote.settlement_budget > Amount::ZERO);
    assert!(
        summary.send_amount > payment_amount + quote.settlement_budget,
        "gross route amount must cover the receiver amount, settlement budget, and maker fees"
    );

    let report = taker
        .start_swap(&summary.swap_id)
        .expect("Legacy payment swap should complete successfully");

    // ---- Verify the exact payment ----
    generate_blocks(bitcoind, 1);

    let received = bitcoind
        .client
        .get_received_by_address(&receiver_address, Some(1))
        .unwrap();
    assert_eq!(
        received, payment_amount,
        "Receiver must get exactly the requested amount"
    );

    let payment_result = report
        .payment
        .as_ref()
        .expect("payment swap report must carry a payment result");
    assert!(payment_result.confirmed);
    assert_eq!(payment_result.delivered_amount, payment_amount.to_sat());
    assert_eq!(report.incoming_amount, 0);
    assert!(report.incoming_utxos.is_empty());
    assert!(report.output_swap_amounts.is_empty());
    assert!(report.output_swap_utxos.is_empty());
    assert!(
        !report.outgoing_utxos.is_empty(),
        "PaySwap must still report the taker funding inputs"
    );
    assert_eq!(
        payment_result.settlement_txids.len(),
        1,
        "one settlement tx per final swapcoin"
    );
    assert!(
        report.fee_paid < payment_amount.to_sat(),
        "receiver payment principal must not be reported as a fee"
    );
    assert_eq!(
        report.mining_fee,
        report.fee_paid.saturating_sub(report.total_maker_fees),
        "mining fee must be derived after excluding the receiver payment"
    );

    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    assert_eq!(
        taker_balances.swap,
        Amount::ZERO,
        "Taker must not own any swap output after a payment swap"
    );
    assert_eq!(taker_balances.contract, Amount::ZERO);

    let spendable_decrease = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .expect("payment swap must cost the taker its route amount");
    assert!(
        spendable_decrease >= summary.send_amount,
        "wallet cost must cover the gross route amount"
    );
    assert_eq!(
        spendable_decrease.to_sat(),
        payment_result.delivered_amount + report.fee_paid,
        "wallet cost must equal the delivered payment plus reported fees"
    );

    info!("Legacy PaySwap test completed successfully!");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// A PaySwap quote is bound to its selected makers. Negotiation failure must
/// not substitute a spare, and a changed offer must abort before funding.
#[test]
fn test_payswap_negotiation_guards_abort_before_funding() {
    warn!("Running Test: PaySwap negotiation guards abort before funding");

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(8012, Some(19031)), (18012, Some(19032))],
            vec![
                TakerBehavior::Normal,
                TakerBehavior::AlterPaymentQuoteBeforeNegotiation,
            ],
            vec![MakerBehavior::CloseAfterAckResponse, MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;
    for taker in &mut takers {
        fund_taker(
            taker,
            bitcoind,
            1,
            Amount::from_btc(0.05).unwrap(),
            AddressType::P2TR,
        );
    }
    fund_makers(
        &makers,
        bitcoind,
        2,
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
    generate_blocks(bitcoind, 1);

    let failing_maker = format!("127.0.0.1:{}", makers[0].config.network_port);
    let spare_maker = format!("127.0.0.1:{}", makers[1].config.network_port);
    let payment_amount = Amount::from_sat(100_000);
    let mempool_before = bitcoind.client.get_raw_mempool().unwrap();

    let receiver = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let negotiation_err = takers[0]
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, payment_amount, 1)
                .with_required_confirms(1)
                .with_preferred_makers(vec![failing_maker, spare_maker.clone()])
                .with_payment_address(receiver.as_unchecked().clone()),
        )
        .expect_err("PaySwap must not substitute a spare after negotiation failure");
    assert!(
        format!("{negotiation_err:?}").contains("failed during payment swap negotiation"),
        "unexpected negotiation error: {:?}",
        negotiation_err
    );
    assert!(
        !makers[1].has_ongoing_swaps().unwrap(),
        "the spare maker must not be negotiated"
    );

    let receiver = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let repricing_err = takers[1]
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, payment_amount, 1)
                .with_required_confirms(1)
                .with_preferred_makers(vec![spare_maker])
                .with_payment_address(receiver.as_unchecked().clone()),
        )
        .expect_err("PaySwap must reject a changed maker offer");
    assert!(
        format!("{repricing_err:?}").contains("repriced its offer"),
        "unexpected repricing error: {:?}",
        repricing_err
    );
    assert_eq!(
        bitcoind.client.get_raw_mempool().unwrap(),
        mempool_before,
        "negotiation guards must abort before any funding transaction is broadcast"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
