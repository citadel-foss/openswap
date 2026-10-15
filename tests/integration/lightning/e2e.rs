//! End-to-end Lightning submarine swaps through the real maker server and
//! taker client: real regtest bitcoind, real wire messages over TCP, real
//! wallet funding and HTLC spends. Only the Lightning nodes are mocked — a
//! paired `MockLightningBackend` whose two handles behave like two separate
//! nodes sharing a payment network.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    thread,
    time::Duration,
};

use bitcoin::{Amount, Network, TxOut};
use bitcoind::bitcoincore_rpc::{json::ScanTxOutRequest, RpcApi};
use openswap::{
    blocklist::BlocklistError,
    lightning::{LightningBackend, MockLightningBackend},
    maker::lightning_handlers::LnMakerPhase,
    taker::{error::TakerError, lightning_swap::LnSwapParams},
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
    wait_until!(
        Duration::from_secs(60),
        every Duration::from_secs(1),
        "the maker to sweep the swap-in HTLC via the hashlock",
        bitcoind
            .client
            .get_tx_out(
                &swap_in.funding_outpoint.txid,
                swap_in.funding_outpoint.vout,
                Some(false),
            )
            .unwrap()
            .is_none()
    );

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
    wait_until!(
        Duration::from_secs(60),
        every Duration::from_secs(1),
        "the taker's swap-out claim to confirm",
        bitcoind
            .client
            .get_raw_transaction_info(&claim_txid, None)
            .ok()
            .and_then(|info| info.confirmations)
            .unwrap_or(0)
            >= 1
    );

    // Both swaps fully resolved: no taker-side recovery records remain.
    let outcomes = taker.recover_lightning_swaps().unwrap();
    assert!(
        outcomes.is_empty(),
        "no pending lightning swaps should remain, got: {:?}",
        outcomes
    );
}

/// With screening on, a maker must refuse a swap-in whose on-chain funding
/// spends from a listed address, and must never pay the taker's invoice.
#[world_test(
    backend = BitcoindBackend,
    bind = [(maker_ln, taker_ln) = maker_and_taker_nodes()],
    maker_behaviors = [Normal],
    takers = [Normal],
    check_blocklist,
    maker_lightning = [maker_ln.clone()],
    taker_lightning = [taker_ln],
)]
fn lightning_swap_in_refuses_blocklisted_funding(
    world: &mut World,
    maker_ln: Arc<MockLightningBackend>,
) {
    // Every taker coin comes from this address, so whichever coins fund the
    // HTLC trip the maker's source-address check.
    let blocked_address = world
        .taker()
        .inner()
        .get_wallet()
        .write()
        .unwrap()
        .get_next_external_address(AddressType::P2WPKH)
        .unwrap();
    for _ in 0..3 {
        send_to_address(
            world.bitcoind(),
            &blocked_address,
            Amount::from_btc(0.05).unwrap(),
        );
    }
    world.mine(1);
    world.taker().sync();
    world
        .taker()
        .inner()
        .add_blocklist_entry(
            blocked_address.to_string(),
            Some("swap-in source".to_string()),
        )
        .unwrap();

    world.fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH);
    world.start_makers(120);

    // Maker and taker share the process logger, so the maker's lines land in
    // the taker's debug.log. Only lines past this mark belong to the swap.
    let log_path = world.taker_log_path();
    let mark = log_mark(&log_path);
    let maker = world.makers()[0].inner().clone();
    let maker_address = world.makers()[0].address();
    let taker = world.taker_mut().inner_mut();
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
    // The maker forgets the swap before it replies. The watchdog only looks
    // at swaps idle for minutes, so a record left here would still be held.
    assert!(
        maker.ln_swaps.lock().unwrap().is_empty(),
        "the refused swap-in still holds a maker swap slot"
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
    let refusals = || {
        std::fs::read_to_string(&log_path)
            .unwrap_or_default()
            .get(mark as usize..)
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains(&needle) && line.contains(&listed))
            .count()
    };
    wait_until!(
        Duration::from_secs(30),
        "the maker's blocklist refusal in the log",
        refusals() > 0
    );
    assert_eq!(
        refusals(),
        1,
        "the maker must refuse swap-in {} once, for the listed address {}",
        swap_id,
        blocked_address
    );
}

/// A maker must refuse a swap-in whose funding message announces a value the
/// funded output does not hold. Until the output is validated the message
/// could come from anyone who knows the swap id, so the maker must keep the
/// accepted swap rather than forget it.
#[world_test(
    backend = BitcoindBackend,
    bind = [(maker_ln, taker_ln) = maker_and_taker_nodes()],
    maker_behaviors = [Normal],
    takers = [ForgeSwapInFundedValue],
    maker_lightning = [maker_ln.clone()],
    taker_lightning = [taker_ln],
    setup = [
        fund_taker(3, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH),
        fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH),
        start_makers(120),
    ],
)]
fn lightning_swap_in_refuses_announced_value_mismatch(
    world: &mut World,
    maker_ln: Arc<MockLightningBackend>,
) {
    // A handle of its own, so the node stays reachable while the taker is borrowed.
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    // Maker and taker share the process logger, so the maker's lines land in
    // the taker's debug.log. Only lines past this mark belong to the swap.
    let log_path = world.taker_log_path();
    let mark = log_mark(&log_path);
    let maker = world.makers()[0].inner().clone();
    let maker_address = world.makers()[0].address();
    let taker = world.taker_mut().inner_mut();

    // The funding itself is honest: only the announced value is one sat off,
    // so the value check is the one that refuses.
    //
    // The taker announces only once its funding has confirmed, so the maker
    // checks the value as soon as the message arrives. The taker then waits
    // minutes for a payment that never comes, long enough for the watchdog
    // to expire the swap the maker kept. Stop the blocks once the message
    // is in, so the record checked below is the one the refusal left.
    let dispatched = "Dispatching Lightning message: SwapInFunded";
    let swap_done = AtomicBool::new(false);
    let (result, paused) = thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            while !swap_done.load(Relaxed) {
                let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
                if contents
                    .get(mark as usize..)
                    .is_some_and(|new| new.contains(dispatched))
                {
                    framework.set_block_gen_paused(true);
                    return true;
                }
                thread::sleep(Duration::from_millis(200));
            }
            false
        });
        let result = taker.lightning_swap_in(LnSwapParams {
            amount: Amount::from_sat(50_000),
            maker_address: Some(maker_address),
            locktime: None,
            min_confirmations: 1,
        });
        swap_done.store(true, Relaxed);
        (result, watcher.join().unwrap())
    });
    assert!(paused, "the maker never received the funding message");
    assert!(
        result.is_err(),
        "the maker completed a swap-in with a misannounced value: {:?}",
        result
    );
    assert_eq!(
        maker_ln.last_pay_cltv_bound(),
        None,
        "the maker paid the invoice of a refused swap-in"
    );
    let kept: Vec<_> = maker.ln_swaps.lock().unwrap().values().cloned().collect();
    assert_eq!(
        kept.len(),
        1,
        "the refusal of an unvalidated announcement deleted the accepted swap"
    );
    let kept = &kept[0];
    assert_eq!(kept.phase, LnMakerPhase::InAccepted);
    assert_eq!(kept.funding, None);

    // Only the value check can have refused: the funding the taker
    // broadcast passes the maker's own output check for this swap, and no
    // check after it refused.
    // The HTLC remains unspent: the maker has not paid the invoice
    // or learned the preimage needed to sweep, and paused blocks
    // prevent the taker's CSV refund from becoming spendable.
    let htlc_address = kept.htlc.address(Network::Regtest).unwrap();
    let scan = bitcoind
        .client
        .scan_tx_out_set_blocking(&[ScanTxOutRequest::Single(format!("addr({htlc_address})"))])
        .unwrap();
    let [funding] = scan.unspents.as_slice() else {
        panic!("expected one funded HTLC output, found {:?}", scan.unspents);
    };
    kept.htlc
        .validate_funding_output(
            &TxOut {
                value: funding.amount,
                script_pubkey: funding.script_pub_key.clone(),
            },
            kept.amount + kept.fee,
        )
        .expect("the taker's funding is valid for this swap");
    // The value-mismatch `reject` logs no ": refused: " line, so none is expected.
    assert_log!(log_path, since mark; { lacks ": refused: " });

    framework.set_block_gen_paused(false);
}

/// With screening on, a taker must refuse to claim a swap-out HTLC whose
/// funding spends from a listed address, and keep nothing that could claim
/// it later.
#[world_test(
    backend = BitcoindBackend,
    bind = [(maker_ln, taker_ln) = maker_and_taker_nodes()],
    maker_behaviors = [Normal],
    takers = [Normal],
    check_blocklist,
    maker_lightning = [maker_ln],
    taker_lightning = [taker_ln],
    setup = [
        fund_maker_from_one_address(0, 4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH),
        start_makers(120),
    ],
)]
fn lightning_swap_out_refuses_blocklisted_funding(world: &mut World) {
    let blocked_address = world.sole_regular_utxo_address(0);
    world
        .taker()
        .inner()
        .add_blocklist_entry(
            blocked_address.to_string(),
            Some("swap-out source".to_string()),
        )
        .unwrap();

    let maker_address = world.makers()[0].address();
    let taker = world.taker_mut().inner_mut();
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
}
