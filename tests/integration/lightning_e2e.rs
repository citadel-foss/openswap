//! End-to-end Lightning submarine swaps through the real maker server and
//! taker client: real regtest bitcoind, real wire messages over TCP, real
//! wallet funding and HTLC spends. Only the Lightning nodes are mocked — a
//! paired `MockLightningBackend` whose two handles behave like two separate
//! nodes sharing a payment network.

use std::{sync::Arc, thread, time::Duration};

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    lightning::{LightningBackend, MockLightningBackend, OpenChannelRequest},
    maker::{start_server, MakerBehavior},
    taker::{lightning_swap::LnSwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use std::sync::atomic::Ordering::Relaxed;

/// One maker, one taker; a swap-in followed by a swap-out over the same
/// maker, asserting both layers settle and no recovery records remain.
#[test]
fn lightning_submarine_swaps_e2e() {
    log::warn!("Running Test: Lightning submarine swaps end-to-end");

    // Two mock Lightning nodes over one shared ledger: node 0 = maker's,
    // node 1 = taker's. The maker needs outbound liquidity to pay swap-in
    // invoices, so give it a funded, ready channel towards the taker.
    let (maker_ln, taker_ln) = MockLightningBackend::new_pair();
    maker_ln.set_onchain_balance(Amount::from_btc(0.02).unwrap());
    let channel = maker_ln
        .open_channel(OpenChannelRequest {
            node_pubkey: taker_ln.node_info().unwrap().node_id,
            address: "127.0.0.1:9736".to_string(),
            channel_amount: Amount::from_sat(1_000_000),
            push_to_counterparty_msat: None,
            announce_channel: false,
        })
        .unwrap();
    maker_ln.simulate_channel_ready(&channel);
    // Drain the channel event so later polls only see swap events.
    let _ = maker_ln.poll_event().unwrap();

    LN_MAKER_INJECT
        .lock()
        .unwrap()
        .push(maker_ln.clone() as Arc<dyn LightningBackend>);

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(7102, None)],
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    taker.set_lightning_backend(taker_ln.clone() as Arc<dyn LightningBackend>);

    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2WPKH,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2WPKH,
    );

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

    let maker_address = format!("127.0.0.1:{}", makers[0].config.network_port);

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
    let taker = takers.get_mut(0).unwrap();
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
