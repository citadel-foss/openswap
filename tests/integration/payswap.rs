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
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{MakerState, SwapParams, TakerBehavior},
    wallet::AddressType,
};

use bitcoind::bitcoincore_rpc::RpcApi;

use super::test_framework::*;

use log::{info, warn};

/// Taproot PaySwap with multiple final swapcoins (`tx_count = 3`), so the
/// settlement splits the receiver amount across several exact outputs.
#[test]
fn test_taproot_payswap() {
    // ---- Setup ----
    warn!("Running Test: Taproot PaySwap - exact payment to third-party receiver");

    let maker_count = 2;
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let mut world = World::builder::<BitcoindBackend>()
        .makers(maker_count)
        .maker_behaviors(maker_behaviors)
        .takers(taker_behavior)
        .build();

    let taker_original_balance = world.fund_taker_default(3);

    world.fund_makers_default();

    log::info!("Starting Maker servers...");
    world.start_makers(120);
    world.verify_maker_pre_swap_balances();

    let receiver_address = world
        .bitcoind()
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let payment_amount = Amount::from_sat(500_000);

    world.mine(1);

    // A wrong-network receiver address must be rejected up front.
    let mainnet_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        .parse()
        .unwrap();
    let wrong_network_result = world.taker_mut().prepare(
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

    let summary = world
        .taker_mut()
        .prepare(swap_params)
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

    let report = world
        .taker_mut()
        .start(&summary.swap_id)
        .expect("Taproot payment swap should complete successfully");

    // ---- Verify the exact payment ----
    world.mine(1);

    let received = world
        .bitcoind()
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
    world.taker().sync();
    let taker_balances = world.taker().balances();
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

    world.shutdown_makers();
    world.finish();
}

/// Legacy PaySwap: the settlement budget covers both contract publication and
/// the contract spend, and the cooperative sweep delivers the exact amount.
/// Cooperative path only — recovery is not exercised here.
#[test]
fn test_legacy_payswap() {
    // ---- Setup ----
    warn!("Running Test: Legacy PaySwap - exact payment to third-party receiver");

    let maker_count = 2;
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let mut world = World::builder::<BitcoindBackend>()
        .makers(maker_count)
        .maker_behaviors(maker_behaviors)
        .takers(taker_behavior)
        .build();

    let taker_original_balance = world.fund_taker_default(3);

    world.fund_makers_default();

    log::info!("Starting Maker servers...");
    world.start_makers(120);
    world.verify_maker_pre_swap_balances();

    let receiver_address = world
        .bitcoind()
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let payment_amount = Amount::from_sat(500_000);

    world.mine(1);

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, payment_amount, 2)
        .with_tx_count(1)
        .with_required_confirms(1)
        .with_payment_address(receiver_address.as_unchecked().clone());

    let summary = world
        .taker_mut()
        .prepare(swap_params)
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

    let report = world
        .taker_mut()
        .start(&summary.swap_id)
        .expect("Legacy payment swap should complete successfully");

    // ---- Verify the exact payment ----
    world.mine(1);

    let received = world
        .bitcoind()
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

    world.taker().sync();
    let taker_balances = world.taker().balances();
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

    world.shutdown_makers();
    world.finish();
}

/// A payment below the dust floor times the declared `tx_count` ceiling must
/// be refused at quote time — before any maker negotiation or funding —
/// instead of aborting after every hop is funded. Uses a non-default feerate,
/// which no other PaySwap test exercises.
#[test]
fn test_payswap_dust_floor_rejects_before_funding() {
    warn!("Running Test: PaySwap below the dust floor - refused at quote time");

    let taker_behavior = vec![TakerBehavior::Normal];
    // Armed to refuse SwapDetails: if the dust check ever ran after walk_route,
    // the refusal error would replace the dust error and this test fails.
    let maker_behaviors = vec![MakerBehavior::RefuseSwapDetails];

    let fee_overrides = vec![None];

    let mut world = World::builder::<BitcoindBackend>()
        .makers(1)
        .fee_overrides(fee_overrides)
        .maker_behaviors(maker_behaviors)
        .takers(taker_behavior)
        .build();

    let taker_original_balance = world.fund_taker_default(1);

    world.fund_makers(2, Amount::from_btc(0.05).unwrap(), AddressType::P2TR);

    log::info!("Starting Maker server...");
    world.start_makers_without_sync(120);

    let receiver_address = world
        .bitcoind()
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    world.mine(1);

    // One sat below the 546 * 10 ceiling: ten settlement outputs could never
    // each clear dust. The refusal must come back from `prepare_swap` itself.
    let payment_amount = Amount::from_sat(5459);
    let mempool_before = world.bitcoind().client.get_raw_mempool().unwrap();
    let maker_address = format!(
        "127.0.0.1:{}",
        world.makers()[0].inner().config.network_port
    );

    let dust_err = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, payment_amount, 1)
                .with_tx_count(10)
                .with_feerate(3)
                .with_required_confirms(1)
                .with_preferred_makers(vec![maker_address])
                .with_payment_address(receiver_address.as_unchecked().clone()),
        )
        .expect_err("a payment below the dust floor must be refused at quote time");
    info!("Quote-time refusal: {:?}", dust_err);
    assert!(
        format!("{dust_err:?}").contains("5460 sat minimum for 10 settlement outputs"),
        "unexpected refusal error: {:?}",
        dust_err
    );

    // Nothing was negotiated, funded, or spent: the refusal precedes the
    // route, so the maker never hears about the swap.
    assert!(
        !world.makers()[0].inner().has_ongoing_swaps().unwrap(),
        "the maker must not be negotiated for a refused quote"
    );
    assert_eq!(
        world.bitcoind().client.get_raw_mempool().unwrap(),
        mempool_before,
        "a refused quote must not broadcast any funding transaction"
    );
    world.taker().sync();
    let taker_balances = world.taker().balances();
    assert_eq!(
        taker_balances.spendable, taker_original_balance,
        "a refused quote must not cost the taker anything"
    );

    info!("PaySwap dust-floor refusal test completed successfully!");

    world.shutdown_makers();
    world.finish();
}

/// A PaySwap quote is bound to its selected makers. Negotiation failure must
/// not substitute a spare, and a changed offer must abort before funding.
#[test]
fn test_payswap_negotiation_guards_abort_before_funding() {
    warn!("Running Test: PaySwap negotiation guards abort before funding");

    let mut world = World::builder::<BitcoindBackend>()
        .makers(2)
        .maker_behaviors(vec![
            MakerBehavior::CloseAfterAckResponse,
            MakerBehavior::Normal,
        ])
        .takers(vec![
            TakerBehavior::Normal,
            TakerBehavior::AlterPaymentQuoteBeforeNegotiation,
        ])
        .build();

    for i in 0..world.takers().len() {
        world.fund_nth_taker_default(i, 1);
    }
    world.fund_makers(2, Amount::from_btc(0.05).unwrap(), AddressType::P2TR);

    world.start_makers(120);
    world.mine(1);

    let failing_maker = format!(
        "127.0.0.1:{}",
        world.makers()[0].inner().config.network_port
    );
    let spare_maker = format!(
        "127.0.0.1:{}",
        world.makers()[1].inner().config.network_port
    );
    let payment_amount = Amount::from_sat(100_000);
    let mempool_before = world.bitcoind().client.get_raw_mempool().unwrap();

    let receiver = world
        .bitcoind()
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let negotiation_err = world.takers_mut()[0]
        .prepare(
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
        !world.makers()[1].inner().has_ongoing_swaps().unwrap(),
        "the spare maker must not be negotiated"
    );

    // The quoted maker closed a connection. Refusing to substitute it is a
    // routing decision, not a verdict, so neither maker may be blamed.
    let standings = world.takers()[0]
        .inner()
        .fetch_offers()
        .unwrap()
        .all_makers();
    for standing in &standings {
        assert!(
            !matches!(standing.state, MakerState::Banned(_)),
            "aborting a payment swap must blame nobody, but {} is {:?}",
            standing.address,
            standing.state
        );
    }

    let receiver = world
        .bitcoind()
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let repricing_err = world.takers_mut()[1]
        .prepare(
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
        world.bitcoind().client.get_raw_mempool().unwrap(),
        mempool_before,
        "negotiation guards must abort before any funding transaction is broadcast"
    );

    world.shutdown_makers();
    world.finish();
}
