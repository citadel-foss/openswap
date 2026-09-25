//! End-to-end routed Lightning swap: the taker pays on-chain to maker 1,
//! maker 1 forwards over Lightning to maker 2, and maker 2 pays the taker
//! back on-chain.
//!
//! The taker is deliberately given **no Lightning backend** — the whole point
//! of the routed topology is that Lightning is the makers' settlement rail,
//! not something the taker needs to run. Both makers get one node of a paired
//! `MockLightningBackend`, so maker 1's payment really parks at maker 2 and
//! its settlement really releases the preimage back to maker 1.

use std::{sync::Arc, thread, time::Duration};

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    lightning::{LightningBackend, MockLightningBackend, OpenChannelRequest},
    maker::{start_server, MakerBehavior},
    taker::{lightning_swap::LnRoutedSwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use std::sync::atomic::Ordering::Relaxed;

/// Gives a mock node a ready channel so it advertises Lightning capacity.
fn with_ready_channel(node: &Arc<MockLightningBackend>, peer: &Arc<MockLightningBackend>) {
    node.set_onchain_balance(Amount::from_btc(0.02).unwrap());
    let channel = node
        .open_channel(OpenChannelRequest {
            node_pubkey: peer.node_info().unwrap().node_id,
            address: "127.0.0.1:9735".to_string(),
            channel_amount: Amount::from_sat(1_000_000),
            // Push half to the peer so the channel has inbound capacity too:
            // swap-outs are bounded by inbound, and a freshly opened channel
            // has none.
            push_to_counterparty_msat: Some(500_000_000),
            announce_channel: false,
        })
        .unwrap();
    node.simulate_channel_ready(&channel);
    // Drain the channel event so swap polls only see swap events.
    let _ = node.poll_event().unwrap();
}

#[test]
fn lightning_routed_swap_e2e() {
    log::warn!("Running Test: Routed Lightning swap (on-chain -> LN -> on-chain)");

    // node 0 = maker 1's node (pays), node 1 = maker 2's node (receives).
    let (ln1, ln2) = MockLightningBackend::new_pair();
    with_ready_channel(&ln1, &ln2);
    with_ready_channel(&ln2, &ln1);

    // maker[0] pays over Lightning (ln1), maker[1] receives (ln2).
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_lightning::<BitcoindBackend>(
            vec![(7302, None), (7303, None)],
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal, MakerBehavior::Normal],
            vec![
                ln1.clone() as Arc<dyn LightningBackend>,
                ln2.clone() as Arc<dyn LightningBackend>,
            ],
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    // No `set_lightning_backend` here on purpose: a routed swap must work
    // with a taker that has no Lightning node.

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

    let first_maker = format!("127.0.0.1:{}", makers[0].config.network_port);
    let second_maker = format!("127.0.0.1:{}", makers[1].config.network_port);

    let report = taker
        .lightning_swap_routed(LnRoutedSwapParams {
            amount: Amount::from_sat(40_000),
            first_maker: Some(first_maker),
            second_maker: Some(second_maker),
            locktime: Some(60),
            min_confirmations: 1,
        })
        .expect("routed swap must complete");
    log::info!("routed swap report: {report:?}");

    // The taker funded amount + both fees and received exactly `amount`.
    assert_eq!(report.received, Amount::from_sat(40_000));
    assert_eq!(
        report.sent,
        report.received + report.first_fee + report.second_fee,
        "funded amount must be the payout plus both makers' fees"
    );
    assert!(report.first_fee.to_sat() >= 500 && report.second_fee.to_sat() >= 500);

    // The taker's claim of hop 2 must confirm.
    let mut confirmed = false;
    for _ in 0..60 {
        let confs = bitcoind
            .client
            .get_raw_transaction_info(&report.claim_txid, None)
            .ok()
            .and_then(|info| info.confirmations)
            .unwrap_or(0);
        if confs >= 1 {
            confirmed = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    assert!(confirmed, "taker's hop-2 claim must confirm");

    // Maker 1 learned the preimage over Lightning and swept hop 1: its
    // funding outpoint stops being spendable. This is the proof the three
    // legs shared one preimage.
    let mut swept = false;
    for _ in 0..90 {
        let unspent = bitcoind
            .client
            .get_tx_out(
                &report.funding_outpoint.txid,
                report.funding_outpoint.vout,
                Some(false),
            )
            .unwrap()
            .is_some();
        if !unspent {
            swept = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    assert!(
        swept,
        "first maker must sweep hop 1 with the learned preimage"
    );

    // Maker 1 must have bounded the Lightning route's CLTV budget rather
    // than paying with LDK's 1008-block default: its own refund window is
    // only `locktime` blocks away.
    let bound = ln1
        .last_pay_cltv_bound()
        .expect("first maker must bound its route CLTV");
    assert!(
        bound < 1008 && bound > 0,
        "route CLTV bound {} must be derived from the hop's locktime",
        bound
    );

    // Both hops resolved: no recovery records left behind.
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
