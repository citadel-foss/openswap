//! End-to-end Lightning submarine swaps through the real maker server and
//! taker client: real regtest bitcoind, real wire messages over TCP, real
//! wallet funding and HTLC spends. Only the Lightning nodes are mocked — a
//! paired `MockLightningBackend` whose two handles behave like two separate
//! nodes sharing a payment network.

use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    blocklist::BlocklistError,
    lightning::{LightningBackend, MockLightningBackend, OpenChannelRequest},
    maker::{start_server, MakerBehavior},
    taker::{error::TakerError, lightning_swap::LnSwapParams, Taker, TakerBehavior},
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
    // node 1 = taker's. The maker serves both directions, so its channel
    // needs outbound capacity (to pay swap-in invoices) and inbound capacity
    // (to receive swap-out payments) — different sides of the same channel.
    let (maker_ln, taker_ln) = MockLightningBackend::new_pair();
    maker_ln.set_onchain_balance(Amount::from_btc(0.02).unwrap());
    let channel = maker_ln
        .open_channel(OpenChannelRequest {
            node_pubkey: taker_ln.node_info().unwrap().node_id,
            address: "127.0.0.1:9736".to_string(),
            channel_amount: Amount::from_sat(1_000_000),
            // Push half to the peer so the channel has inbound capacity too:
            // swap-outs are bounded by inbound, and a freshly opened channel
            // has none.
            push_to_counterparty_msat: Some(500_000_000),
            announce_channel: false,
        })
        .unwrap();
    maker_ln.simulate_channel_ready(&channel);
    // Drain the channel event so later polls only see swap events.
    let _ = maker_ln.poll_event().unwrap();

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_lightning::<BitcoindBackend>(
            1,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
            vec![maker_ln.clone() as Arc<dyn LightningBackend>],
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

/// A maker node and a taker node joined by one ready channel with capacity
/// both ways, as set up in [`lightning_submarine_swaps_e2e`].
fn ready_channel_pair() -> (Arc<MockLightningBackend>, Arc<MockLightningBackend>) {
    let (maker_ln, taker_ln) = MockLightningBackend::new_pair();
    maker_ln.set_onchain_balance(Amount::from_btc(0.02).unwrap());
    let channel = maker_ln
        .open_channel(OpenChannelRequest {
            node_pubkey: taker_ln.node_info().unwrap().node_id,
            address: "127.0.0.1:9736".to_string(),
            channel_amount: Amount::from_sat(1_000_000),
            push_to_counterparty_msat: Some(500_000_000),
            announce_channel: false,
        })
        .unwrap();
    maker_ln.simulate_channel_ready(&channel);
    let _ = maker_ln.poll_event().unwrap();
    (maker_ln, taker_ln)
}

/// Runs Lightning recovery until no record remains and returns every
/// outcome line seen on the way.
fn recover_all_lightning_swaps(taker: &mut Taker, timeout: Duration) -> Vec<String> {
    let deadline = Instant::now() + timeout;
    let mut history = Vec::new();
    loop {
        let outcomes = taker.recover_lightning_swaps().unwrap();
        if outcomes.is_empty() {
            return history;
        }
        history.extend(outcomes);
        assert!(
            Instant::now() < deadline,
            "lightning swaps still pending: {:?}",
            history
        );
        thread::sleep(Duration::from_secs(5));
    }
}

/// With screening on, a maker must refuse a swap-in whose on-chain funding
/// spends from a listed address, and must never pay the taker's invoice.
#[test]
fn lightning_swap_in_refuses_blocklisted_funding() {
    let (maker_ln, taker_ln) = ready_channel_pair();
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_lightning_and_blocklist::<BitcoindBackend>(
            1,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
            vec![maker_ln.clone() as Arc<dyn LightningBackend>],
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    taker.set_lightning_backend(taker_ln.clone() as Arc<dyn LightningBackend>);

    // Every taker coin comes from this address, so whichever coins fund the
    // HTLC trip the maker's source-address check.
    let blocked_address = taker
        .get_wallet()
        .write()
        .unwrap()
        .get_next_external_address(AddressType::P2WPKH)
        .unwrap();
    for _ in 0..3 {
        send_to_address(bitcoind, &blocked_address, Amount::from_btc(0.05).unwrap());
    }
    generate_blocks(bitcoind, 1);
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    taker
        .add_blocklist_entry(
            blocked_address.to_string(),
            Some("swap-in source".to_string()),
        )
        .unwrap();

    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2WPKH,
    );
    let maker_threads = spawn_makers(&makers);
    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);

    // Maker and taker share the process logger, so the maker's lines land in
    // the taker's debug.log. Only lines past this offset belong to the swap.
    let log_path = test_framework.taker_log_path();
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    let maker_address = format!("127.0.0.1:{}", makers[0].config.network_port);
    let result = taker.lightning_swap_in(LnSwapParams {
        amount: Amount::from_sat(50_000),
        maker_address: Some(maker_address),
        locktime: None,
        min_confirmations: 1,
    });
    assert!(
        result.is_err(),
        "the maker completed a swap-in funded from a blocked address: {:?}",
        result
    );
    assert_eq!(
        maker_ln.last_pay_cltv_bound(),
        None,
        "the maker paid the invoice of a refused swap-in"
    );

    // The maker never paid, so it never learned the preimage: only the
    // taker's refund branch can resolve the HTLC.
    let history = recover_all_lightning_swaps(taker, Duration::from_secs(300));
    assert!(
        history
            .iter()
            .any(|line| line.contains("recovered via") || line.contains("already resolved")),
        "the taker must refund its swap-in HTLC, got: {:?}",
        history
    );

    // The swap failing is not enough: the maker must have refused this swap's
    // funding because its blocklist matched the listed address. Recovery
    // outcomes start with the swap id, which the maker logs too.
    let swap_id = history
        .iter()
        .find_map(|line| line.split_once(": ").map(|(id, _)| id.to_string()))
        .expect("recovery reports the swap id");
    let needle = format!("Swap-in {swap_id}: funding refused: Blocklist(BlockedAddress");
    let listed = blocked_address.to_string();
    wait_for_log(&log_path, &needle, Duration::from_secs(30));
    // wait_for_log echoes the needle into the log, but not the address, so
    // requiring both skips the echo.
    let contents = std::fs::read_to_string(&log_path).unwrap();
    let refusals: Vec<&str> = contents
        .get(log_offset as usize..)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains(&needle) && line.contains(&listed))
        .collect();
    assert_eq!(
        refusals.len(),
        1,
        "the maker must refuse swap-in {} once, for the listed address {}",
        swap_id,
        blocked_address
    );

    drop(takers);
    shutdown_makers(&makers, maker_threads);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// With screening on, a taker must refuse to claim a swap-out HTLC whose
/// funding spends from a listed address, and keep nothing that could claim
/// it later.
#[test]
fn lightning_swap_out_refuses_blocklisted_funding() {
    let (maker_ln, taker_ln) = ready_channel_pair();
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_lightning_and_blocklist::<BitcoindBackend>(
            1,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
            vec![maker_ln.clone() as Arc<dyn LightningBackend>],
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    taker.set_lightning_backend(taker_ln.clone() as Arc<dyn LightningBackend>);

    fund_maker_from_one_address(
        &makers[0],
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2WPKH,
    );
    let maker_threads = spawn_makers(&makers);
    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);

    let blocked_address = sole_regular_utxo_address(&makers[0]);
    taker
        .add_blocklist_entry(
            blocked_address.to_string(),
            Some("swap-out source".to_string()),
        )
        .unwrap();

    let maker_address = format!("127.0.0.1:{}", makers[0].config.network_port);
    match taker.lightning_swap_out(LnSwapParams {
        amount: Amount::from_sat(40_000),
        maker_address: Some(maker_address),
        locktime: Some(30),
        min_confirmations: 1,
    }) {
        Err(TakerError::Blocklist(BlocklistError::BlockedAddress { entry, .. })) => {
            assert_eq!(entry.address, blocked_address.to_string());
        }
        Err(other) => panic!("expected blocked-address error, got {:?}", other),
        Ok(report) => panic!(
            "the taker claimed swap-out funding from a blocked address: {:?}",
            report
        ),
    }

    // Refused before the outpoint was recorded, so recovery holds nothing
    // that could claim the listed coins later.
    let outcomes = taker.recover_lightning_swaps().unwrap();
    assert_eq!(outcomes.len(), 1, "{:?}", outcomes);
    assert!(
        outcomes[0].contains("no on-chain commitment"),
        "{:?}",
        outcomes
    );

    drop(takers);
    shutdown_makers(&makers, maker_threads);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
