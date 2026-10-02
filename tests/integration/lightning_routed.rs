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
    lightning::{LightningBackend, MockLightningBackend},
    taker::lightning_swap::LnRoutedSwapParams,
    wallet::AddressType,
};

use super::test_framework::*;

/// One node per maker over a shared ledger, each with a ready channel to the
/// other: maker 0's node pays over Lightning, maker 1's receives.
fn routed_nodes() -> (Arc<MockLightningBackend>, Arc<MockLightningBackend>) {
    let (ln1, ln2) = MockLightningBackend::new_pair();
    open_ready_channel(&ln1, ln2.node_info().unwrap().node_id, Some(500_000_000));
    open_ready_channel(&ln2, ln1.node_info().unwrap().node_id, Some(500_000_000));
    (ln1, ln2)
}

#[world_test(
    backend = BitcoindBackend,
    bind = [(ln1, ln2) = routed_nodes()],
    maker_behaviors = [Normal, Normal],
    // No `taker_lightning` on purpose: a routed swap must work with a taker
    // that has no Lightning node.
    takers = [Normal],
    maker_lightning = [ln1.clone(), ln2],
    setup = [
        fund_taker(3, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH),
        fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH),
        start_makers(120),
    ],
)]
fn lightning_routed_swap_e2e(world: &mut World, ln1: Arc<MockLightningBackend>) {
    // A handle of its own, so the node stays reachable while the taker is borrowed.
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let first_maker = world.makers()[0].address();
    let second_maker = world.makers()[1].address();
    let taker = world.taker_mut().inner_mut();

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
}
