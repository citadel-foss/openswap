//! End-to-end Lightning submarine swaps through the real maker server and
//! taker client: real regtest bitcoind, real wire messages over TCP, real
//! wallet funding and HTLC spends. Only the Lightning nodes are mocked — a
//! paired `MockLightningBackend` whose two handles behave like two separate
//! nodes sharing a payment network.

use std::{sync::Arc, thread, time::Duration};

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    lightning::{LightningBackend, MockLightningBackend},
    taker::lightning_swap::LnSwapParams,
    wallet::AddressType,
};

use crate::test_framework::*;

/// Two mock Lightning nodes over one shared ledger: the maker's first, the
/// taker's second. The maker serves both directions, so its channel needs
/// outbound capacity (to pay swap-in invoices) and inbound capacity (to receive
/// swap-out payments) — different sides of the same channel.
fn maker_and_taker_nodes() -> (Arc<MockLightningBackend>, Arc<MockLightningBackend>) {
    let (maker_ln, taker_ln) = MockLightningBackend::new_pair();
    open_ready_channel(
        &maker_ln,
        taker_ln.node_info().unwrap().node_id,
        Some(500_000_000),
    );
    (maker_ln, taker_ln)
}

/// One maker, one taker; a swap-in followed by a swap-out over the same
/// maker, asserting both layers settle and no recovery records remain.
#[world_test(
    backend = BitcoindBackend,
    bind = [(maker_ln, taker_ln) = maker_and_taker_nodes()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [maker_ln],
    taker_lightning = [taker_ln],
    setup = [
        fund_taker(3, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH),
        fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH),
        start_makers(120),
    ],
)]
fn lightning_submarine_swaps_e2e(world: &mut World) {
    // A handle of its own, so the node stays reachable while the taker is borrowed.
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker_address = world.makers()[0].address();
    let taker = world.taker_mut().inner_mut();

    // ---- Swap-in: taker pays on-chain, gains Lightning balance ----
    let swap_in = taker
        .lightning_swap_in(LnSwapParams {
            amount: Amount::from_sat(50_000),
            maker_address: Some(maker_address.clone()),
            locktime: None,
            min_confirmations: 1,
        })
        .expect("swap-in must complete");
    log::info!("swap-in report: {swap_in:?}");
    assert!(
        swap_in.fee.to_sat() >= 500,
        "fee must include the maker's base fee"
    );

    // The maker learned the preimage and swept the HTLC: its claim spends
    // the funding outpoint. Give the sweep a moment to reach the chain.
    let mut swept = false;
    for _ in 0..60 {
        let outpoint_unspent = bitcoind
            .client
            .get_tx_out(
                &swap_in.funding_outpoint.txid,
                swap_in.funding_outpoint.vout,
                Some(false),
            )
            .unwrap()
            .is_some();
        if !outpoint_unspent {
            swept = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    assert!(swept, "maker must sweep the swap-in HTLC via the hashlock");

    // ---- Swap-out: taker pays Lightning, gains on-chain BTC ----
    let swap_out = taker
        .lightning_swap_out(LnSwapParams {
            amount: Amount::from_sat(40_000),
            maker_address: Some(maker_address),
            locktime: Some(30),
            min_confirmations: 1,
        })
        .expect("swap-out must complete");
    log::info!("swap-out report: {swap_out:?}");
    let claim_txid = swap_out.claim_txid.expect("swap-out produces a claim tx");

    // The taker's claim must confirm (the framework mines continuously).
    let mut confirmed = false;
    for _ in 0..60 {
        let confs = bitcoind
            .client
            .get_raw_transaction_info(&claim_txid, None)
            .ok()
            .and_then(|info| info.confirmations)
            .unwrap_or(0);
        if confs >= 1 {
            confirmed = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    assert!(confirmed, "taker's swap-out claim must confirm");

    // Both swaps fully resolved: no taker-side recovery records remain.
    let outcomes = taker.recover_lightning_swaps().unwrap();
    assert!(
        outcomes.is_empty(),
        "no pending lightning swaps should remain, got: {:?}",
        outcomes
    );
}
