//! A maker that restarts mid-swap must still be able to reach the money it
//! already committed. Maker-side swap state lives in the encrypted wallet
//! store for exactly this reason: without it a restarted swap-out maker has
//! no branch key for the HTLC it funded, and those coins are stuck.
//!
//! This drives the maker's handlers directly — no taker, no server threads —
//! so the restart happens at a precisely controlled point: right after the
//! maker has funded the on-chain HTLC.

use std::{
    collections::HashMap,
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{Secp256k1, SecretKey},
    Amount, Network, OutPoint, PublicKey, Txid,
};
use bitcoind::{
    bitcoincore_rpc::{
        json::{CreateRawTransactionInput, SignRawTransactionInput},
        RpcApi,
    },
    BitcoinD,
};
use openswap::{
    lightning::{
        invoice::verify_invoice, swap::SPEND_FEE_RATE_FLOOR, InvoiceParams, LightningBackend,
        LnEvent, MockLightningBackend, PaymentId, PaymentOutcome, Preimage, SwapHtlc,
    },
    maker::{
        handlers::{handle_message, ConnectionState, Maker},
        lightning_handlers::{
            ln_watchdog_tick_now, refuse_swap_in_after_wait, watchdog_expire_swap_in_snapshot,
            watchdog_finish_swap_in_snapshot, watchdog_resolve_swap_out_snapshot, LnDirection,
            LnMakerPhase, LnMakerSwap, ADMIT_NEW_SWAP_OUTS, FAIL_PENDING_SPEND_LOOKUP,
            FAIL_REFUND_FAMILY_LOOKUP, HIDE_HTLC_SPENDS,
        },
        MakerBehavior, MakerError, MakerServer,
    },
    protocol::{
        common_messages::{Hello, MakerToTakerMessage, TakerToMakerMessage},
        lightning_messages::{
            LightningMakerMessage, LightningTakerMessage, LnHtlcFunded, LnSwapInRequest,
            LnSwapOutPaid, LnSwapOutRequest,
        },
    },
    wallet::AddressType,
};

use super::SpendFeerate;
use crate::test_framework::*;

use std::sync::atomic::{
    AtomicBool,
    Ordering::{Relaxed, SeqCst},
};

fn ln_message(msg: LightningTakerMessage) -> TakerToMakerMessage {
    TakerToMakerMessage::Lightning(Box::new(msg))
}

fn expect_ln(response: Option<MakerToTakerMessage>) -> LightningMakerMessage {
    match response {
        Some(MakerToTakerMessage::Lightning(ln)) => *ln,
        other => panic!("expected a Lightning reply, got {:?}", other),
    }
}

/// A standalone mock node with a ready channel, so the maker advertises
/// Lightning terms and can hold an invoice.
fn maker_node() -> Arc<MockLightningBackend> {
    let ln = Arc::new(MockLightningBackend::new());
    let peer = SecretKey::from_slice(&[0x21; 32]).unwrap();
    open_ready_channel(&ln, peer.public_key(&Secp256k1::new()), Some(500_000_000));
    ln
}

/// [`maker_node`] on a ledger shared with a payee node, so the maker's
/// payments reach the payee and stay held until it claims or fails them.
fn maker_node_pair() -> (Arc<MockLightningBackend>, Arc<MockLightningBackend>) {
    let (ln, payee) = MockLightningBackend::new_pair();
    let peer = SecretKey::from_slice(&[0x21; 32]).unwrap();
    open_ready_channel(&ln, peer.public_key(&Secp256k1::new()), Some(500_000_000));
    (ln, payee)
}

/// Drives `maker` through a swap-out for `payment_hash` until it has funded
/// the on-chain HTLC: request, the taker's held payment, then `SwapOutPaid`.
/// The taker never claims, so only the maker's timelock branch remains.
///
/// Only the request runs with swap-out admission open, as on a maker built
/// before #1239 closed it. Everything after, funding included, runs with
/// admission closed: the swap is one already on record, which an upgraded
/// maker must still fund, settle and refund.
fn fund_swap_out(
    maker: &Arc<MakerServer>,
    ln: &MockLightningBackend,
    payment_hash: sha256::Hash,
    amount: Amount,
    locktime: u16,
) -> LnHtlcFunded {
    let swap_id = payment_hash.to_string();
    let taker_hashlock_pubkey = PublicKey::new(
        SecretKey::from_slice(&[0x31; 32])
            .unwrap()
            .public_key(&Secp256k1::new()),
    );

    let mut state = ConnectionState::default();
    handle_message(
        maker,
        &mut state,
        TakerToMakerMessage::Hello(Hello::default()),
    )
    .unwrap();

    let admitted = Switch::on(&ADMIT_NEW_SWAP_OUTS);
    let accept = match expect_ln(
        handle_message(
            maker,
            &mut state,
            ln_message(LightningTakerMessage::SwapOutRequest(LnSwapOutRequest {
                swap_id: swap_id.clone(),
                payment_hash,
                amount,
                locktime,
                min_confirmations: 1,
                taker_hashlock_pubkey,
                features: vec!["ln-swap-out".to_string()],
            })),
        )
        .unwrap(),
    ) {
        LightningMakerMessage::SwapOutAccept(accept) => accept,
        other => panic!("expected SwapOutAccept, got {}", other),
    };
    drop(admitted);

    // The taker's payment lands at the maker and is routed to its mailbox.
    ln.simulate_htlc_arrival(payment_hash, (amount + accept.fee).to_sat() * 1000);
    assert_eq!(
        maker.ln_router.as_ref().unwrap().pump_once(),
        1,
        "the held payment must reach the swap's mailbox"
    );

    match expect_ln(
        handle_message(
            maker,
            &mut state,
            ln_message(LightningTakerMessage::SwapOutPaid(LnSwapOutPaid {
                swap_id: swap_id.clone(),
            })),
        )
        .unwrap(),
    ) {
        LightningMakerMessage::SwapOutFunded(funded) => funded,
        other => panic!("expected SwapOutFunded, got {}", other),
    }
}

#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_restart_recovers_funded_swap(world: &mut World, ln: Arc<MockLightningBackend>) {
    // A handle of its own: the makers are dropped mid-test, the node is not.
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    // Must clear the maker's floor: enough window must remain after the
    // confirmations it waits for.
    let locktime: u16 = 30;
    let amount = Amount::from_sat(40_000);

    // The taker's secret; the maker never learns the preimage.
    let preimage = Preimage([0x77; 32]);
    let payment_hash = preimage.payment_hash();
    let swap_id = payment_hash.to_string();

    let funded = fund_swap_out(&maker, &ln, payment_hash, amount, locktime);
    log::info!("maker funded the HTLC at {}", funded.outpoint);

    // ---- Restart: everything in memory is lost ----
    let mut config = maker.config.clone();
    // `init` consumes the passphrase, so a restart has to supply it again.
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();

    let mut restarted = MakerServer::init(config).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);

    let restored = restarted
        .ln_swaps
        .lock()
        .unwrap()
        .get(&swap_id)
        .cloned()
        .expect("the in-flight swap must be restored from the wallet");
    assert_eq!(
        restored.funding,
        Some((funded.outpoint, funded.value)),
        "the restored swap must point at the HTLC the old process funded"
    );
    assert_eq!(restored.payment_hash, payment_hash);
    assert_eq!(restored.locktime, locktime);

    // ---- The restored state alone must reach the money ----
    // The taker never claimed, so the maker's way out is the timelock
    // branch. Signing it needs the branch key, which only persistence could
    // have carried across the restart.
    let destination = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked()
        .script_pubkey();
    let refund = restored
        .htlc
        .create_timelock_spend(
            funded.outpoint,
            funded.value,
            &restored.privkey,
            destination,
            SPEND_FEE_RATE_FLOOR,
        )
        .expect("refund builds from restored state");

    // CSV counts from the funding's confirmation.
    generate_blocks(bitcoind, locktime as u64 + 2);
    let refund_txid = bitcoind
        .client
        .send_raw_transaction(&refund)
        .expect("the restored maker's refund must be valid");
    generate_blocks(bitcoind, 1);
    let confirmations = bitcoind
        .client
        .get_raw_transaction_info(&refund_txid, None)
        .unwrap()
        .confirmations
        .unwrap_or(0);
    assert!(confirmations >= 1, "refund must confirm");

    restarted.shutdown.store(true, Relaxed);
    restarted.watch_service.shutdown();
}

/// The server's watchdog skips swaps touched within its five-minute idle
/// window (`WATCHDOG_MIN_IDLE`). Backdates `swap_id`'s last phase change past
/// it, so the next 30-second tick acts on the swap instead of a test waiting
/// out the window.
fn backdate_past_watchdog_idle(maker: &MakerServer, swap_id: &str) {
    let mut swaps = maker.ln_swaps.lock().unwrap();
    let swap = swaps.get_mut(swap_id).expect("the swap is still held");
    swap.updated_at = Instant::now()
        .checked_sub(Duration::from_secs(300))
        .expect("the monotonic clock reaches five minutes back");
}

/// After a restart, the maker's own server must refund a funded swap-out the
/// taker never claimed: once the CSV window passes, the watchdog broadcasts
/// the timelock spend, the coins come back to the maker's wallet, and the
/// swap closes with its held payment failed back.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_restart_refunds_unclaimed_swap_out(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    // A handle of its own: the makers are dropped mid-test, the node is not.
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;
    let amount = Amount::from_sat(40_000);
    let _market = SpendFeerate::set(10.0);

    // The taker pays but never claims, so the preimage stays private.
    let preimage = Preimage([0x78; 32]);
    let payment_hash = preimage.payment_hash();
    let swap_id = payment_hash.to_string();
    let funded = fund_swap_out(&maker, &ln, payment_hash, amount, locktime);
    log::info!("maker funded the HTLC at {}", funded.outpoint);

    // ---- Restart from the wallet store, then start the server ----
    let mut config = maker.config.clone();
    // `init` consumes the passphrase, so a restart has to supply it again.
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();

    let mut restarted = MakerServer::init(config).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);
    assert!(
        restarted.ln_swaps.lock().unwrap().contains_key(&swap_id),
        "the in-flight swap must be restored from the wallet"
    );
    backdate_past_watchdog_idle(&restarted, &swap_id);
    let log_path = world.taker_log_path();
    world.adopt_makers([Arc::new(restarted)]);
    world.start_makers(120);
    let maker = world.makers()[0].inner().clone();

    // CSV counts from the funding's confirmation.
    generate_blocks(bitcoind, locktime as u64 + 2);

    // ---- The watchdog refunds on its own ----
    wait_for_log(
        &log_path,
        &format!("Swap-out {swap_id} refund broadcast"),
        Duration::from_secs(180),
    );
    // The record keeps the swap, and its key, until the refund confirms.
    let mut refund_txid = None;
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_secs(1),
        "the maker to record its refund txid",
        {
            refund_txid = maker
                .ln_swaps
                .lock()
                .unwrap()
                .get(&swap_id)
                .and_then(|swap| swap.refund_txid);
            refund_txid.is_some()
        }
    );
    let refund_txid = refund_txid.unwrap();
    wait_until!(
        Duration::from_secs(60),
        every Duration::from_secs(1),
        "the maker's refund to confirm",
        confirmations(bitcoind, &refund_txid) >= 1
    );
    let refund = raw_tx_with_retry(bitcoind, &refund_txid);
    assert_eq!(
        refund
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect::<Vec<_>>(),
        vec![funded.outpoint],
        "the refund must spend exactly the swap's HTLC"
    );
    assert_eq!(
        funded.value
            - refund
                .output
                .iter()
                .map(|output| output.value)
                .sum::<Amount>(),
        Amount::from_sat(1_500),
        "the refund must pay the market rate, 10 sat/vB for 150 vB"
    );

    // The refunded coins are back in the maker's wallet.
    world.makers()[0].sync();
    assert!(
        maker
            .wallet
            .read()
            .unwrap()
            .list_all_utxo()
            .iter()
            .any(|utxo| utxo.txid == refund_txid),
        "the maker's wallet must hold the refund output"
    );

    // ---- A later tick closes the swap ----
    // Broadcasting touched the record, so backdate it again for the tick
    // that sees the confirmed refund.
    backdate_past_watchdog_idle(&maker, &swap_id);
    wait_until!(
        Duration::from_secs(120),
        every Duration::from_secs(1),
        "the maker to close the refunded swap",
        !maker.ln_swaps.lock().unwrap().contains_key(&swap_id)
    );
    // Closing failed the held payment back, so it can no longer be claimed.
    assert!(
        ln.claim_held_payment(&preimage).is_err(),
        "the refunded swap's held payment must be failed back"
    );
}

/// The maker's refund can leave the mempool while the watcher still has it
/// on record as the HTLC's spend. Waiting for that spend to confirm would
/// wait forever, so the watchdog sends the recorded refund again, and the
/// swap closes, failing its held payment, only once the refund is final.
///
/// The eviction is real: unwinding the chain below the refund's CSV height
/// makes bitcoind drop it as no longer final, and restoring the chain does
/// not bring it back. The market has risen meanwhile: with nothing pending,
/// the refund goes out again at the new rate under a new txid, and the one
/// it supersedes stays on record.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_rebroadcasts_an_evicted_refund(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    use openswap::watch_tower::watcher::WatcherEvent;

    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;
    // The test mines every block itself. A background block could confirm
    // the refund between the mempool checks below and close the swap early.
    pause_block_generation(&framework);

    let preimage = Preimage([0x79; 32]);
    let swap_id = preimage.payment_hash().to_string();
    let funded = fund_swap_out(
        &maker,
        &ln,
        preimage.payment_hash(),
        Amount::from_sat(40_000),
        locktime,
    );
    generate_blocks(bitcoind, 1);
    let funded_at = bitcoind.client.get_block_count().unwrap()
        - confirmations(bitcoind, &funded.outpoint.txid) as u64
        + 1;
    // Past the CSV with a block to spare, so the refund is final.
    mine_to(bitcoind, funded_at + locktime as u64 + 1);

    // ---- The watchdog refunds, and the watcher records the refund ----
    ln_watchdog_tick_now(&maker);
    let refund_txid = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .and_then(|swap| swap.refund_txid)
        .expect("the watchdog broadcast a refund");
    let in_mempool = |txid: &Txid| bitcoind.client.get_mempool_entry(txid).is_ok();
    assert!(in_mempool(&refund_txid));
    let recorded_spend = || match maker.watch_service.watch_request(funded.outpoint) {
        Ok(WatcherEvent::UtxoSpent { spending_tx, .. }) => spending_tx.map(|tx| tx.compute_txid()),
        other => panic!("unexpected watcher answer: {:?}", other),
    };
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the watcher to record the refund",
        recorded_spend() == Some(refund_txid)
    );

    // ---- Evict it: below the CSV height it is no longer final ----
    let tip = bitcoind.client.get_block_count().unwrap();
    let unwound = bitcoind
        .client
        .get_block_hash(funded_at + locktime as u64 - 1)
        .unwrap();
    bitcoind.client.invalidate_block(&unwound).unwrap();
    assert!(
        !in_mempool(&refund_txid),
        "the unwound chain kept the refund"
    );
    bitcoind.client.reconsider_block(&unwound).unwrap();
    assert_eq!(bitcoind.client.get_block_count().unwrap(), tip);
    assert!(
        !in_mempool(&refund_txid),
        "restoring the chain restored the refund"
    );
    // The watcher still names the evicted refund as the spend.
    assert_eq!(recorded_spend(), Some(refund_txid));

    // ---- While the lookup of what spends the HTLC fails, nothing is sent ----
    let _market = SpendFeerate::set(40.0);
    {
        let _failing = Switch::on(&FAIL_PENDING_SPEND_LOOKUP);
        ln_watchdog_tick_now(&maker);
    }
    assert!(
        bitcoind
            .client
            .get_tx_out(&funded.outpoint.txid, funded.outpoint.vout, Some(true))
            .unwrap()
            .is_some(),
        "a failed lookup must send nothing"
    );
    let swap = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .expect("the swap stays open");
    assert_eq!(swap.refund_txid, Some(refund_txid));
    assert!(swap.earlier_refund_txids.is_empty());

    // ---- The watchdog sends it again, at the risen rate ----
    ln_watchdog_tick_now(&maker);
    let swap = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .expect("the swap stays open");
    let resent = swap.refund_txid.expect("the resend is recorded");
    assert_ne!(resent, refund_txid, "the refund went out at its old rate");
    assert_eq!(swap.earlier_refund_txids, vec![refund_txid]);
    assert!(
        in_mempool(&resent),
        "the evicted refund was never sent again"
    );
    assert_eq!(
        mempool_spend_fee(bitcoind, funded.outpoint, funded.value),
        Amount::from_sat(6_000),
        "the resend must pay the new rate, 40 sat/vB for 150 vB"
    );
    // Further passes change nothing until it confirms.
    ln_watchdog_tick_now(&maker);
    let swap = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .expect("the swap stays open");
    assert_eq!(swap.phase, LnMakerPhase::OutFunded);
    assert_eq!(swap.refund_txid, Some(resent));
    assert_eq!(swap.earlier_refund_txids, vec![refund_txid]);
    assert!(in_mempool(&resent));

    // ---- Once it is final, the swap closes and the payment fails back ----
    generate_blocks(bitcoind, REFUND_FINALITY_DEPTH);
    assert!(confirmations(bitcoind, &resent) as u64 >= REFUND_FINALITY_DEPTH);
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the maker to close the refunded swap",
        {
            ln_watchdog_tick_now(&maker);
            maker.get_ln_swap(&swap_id).unwrap().is_none()
        }
    );
    assert!(
        ln.claim_held_payment(&preimage).is_err(),
        "the refunded swap's held payment must be failed back"
    );
    framework.set_block_gen_paused(false);
}

/// A pending refund is bumped once the market rises by the replacement
/// step, while nothing spends its output. The refund it replaced stays on
/// record, so whichever of them confirms closes the swap.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_bumps_a_pending_refund(world: &mut World, ln: Arc<MockLightningBackend>) {
    use openswap::watch_tower::watcher::WatcherEvent;

    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;
    // The test mines every block itself, so the refund stays pending.
    pause_block_generation(&framework);
    let market = SpendFeerate::set(10.0);

    let preimage = Preimage([0x7b; 32]);
    let swap_id = preimage.payment_hash().to_string();
    let funded = fund_swap_out(
        &maker,
        &ln,
        preimage.payment_hash(),
        Amount::from_sat(40_000),
        locktime,
    );
    generate_blocks(bitcoind, 1);
    let funded_at = bitcoind.client.get_block_count().unwrap()
        - confirmations(bitcoind, &funded.outpoint.txid) as u64
        + 1;
    mine_to(bitcoind, funded_at + locktime as u64 + 1);

    // ---- The watchdog refunds at the market rate ----
    ln_watchdog_tick_now(&maker);
    let first = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .and_then(|swap| swap.refund_txid)
        .expect("the watchdog broadcast a refund");
    assert_eq!(
        mempool_spend_fee(bitcoind, funded.outpoint, funded.value),
        Amount::from_sat(1_500),
        "the refund must pay the market rate, 10 sat/vB for 150 vB"
    );
    let recorded_spend = || match maker.watch_service.watch_request(funded.outpoint) {
        Ok(WatcherEvent::UtxoSpent { spending_tx, .. }) => spending_tx.map(|tx| tx.compute_txid()),
        other => panic!("unexpected watcher answer: {:?}", other),
    };
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the watcher to record the refund",
        recorded_spend() == Some(first)
    );

    // ---- The market rises, and the pending refund is bumped ----
    market.set_rate(40.0);
    ln_watchdog_tick_now(&maker);
    let swap = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .expect("the swap stays open");
    let bumped = swap.refund_txid.expect("the bump is recorded");
    assert_ne!(bumped, first, "the refund was not bumped");
    assert_eq!(swap.earlier_refund_txids, vec![first]);
    assert_eq!(swap.refund_feerate, Some(40.0));
    assert_eq!(
        mempool_spend_fee(bitcoind, funded.outpoint, funded.value),
        Amount::from_sat(6_000),
        "the bump must pay the new rate, 40 sat/vB for 150 vB"
    );
    assert!(
        bitcoind.client.get_mempool_entry(&first).is_err(),
        "the bump must replace the first refund"
    );
    // At that rate, the next pass resends the bump unchanged.
    ln_watchdog_tick_now(&maker);
    let swap = maker.get_ln_swap(&swap_id).unwrap().unwrap();
    assert_eq!(swap.refund_txid, Some(bumped));
    assert_eq!(swap.earlier_refund_txids, vec![first]);
    assert_eq!(
        mempool_spend_fee(bitcoind, funded.outpoint, funded.value),
        Amount::from_sat(6_000)
    );

    // ---- The bumped refund is final, so the swap closes ----
    generate_blocks(bitcoind, REFUND_FINALITY_DEPTH);
    assert!(confirmations(bitcoind, &bumped) as u64 >= REFUND_FINALITY_DEPTH);
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the maker to close the refunded swap",
        {
            ln_watchdog_tick_now(&maker);
            maker.get_ln_swap(&swap_id).unwrap().is_none()
        }
    );
    assert!(
        ln.claim_held_payment(&preimage).is_err(),
        "the refunded swap's held payment must be failed back"
    );
    framework.set_block_gen_paused(false);
}

/// A bump can be the refund on record while an earlier refund is the one
/// that confirms. That refund is still ours, so the swap closes at finality
/// and the held payment fails back.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_closes_on_an_earlier_refund(world: &mut World, ln: Arc<MockLightningBackend>) {
    use openswap::watch_tower::watcher::WatcherEvent;

    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;
    pause_block_generation(&framework);

    let preimage = Preimage([0x7c; 32]);
    let swap_id = preimage.payment_hash().to_string();
    let funded = fund_swap_out(
        &maker,
        &ln,
        preimage.payment_hash(),
        Amount::from_sat(40_000),
        locktime,
    );
    generate_blocks(bitcoind, 1);
    let funded_at = bitcoind.client.get_block_count().unwrap()
        - confirmations(bitcoind, &funded.outpoint.txid) as u64
        + 1;
    mine_to(bitcoind, funded_at + locktime as u64 + 1);

    ln_watchdog_tick_now(&maker);
    let mut swap = maker.get_ln_swap(&swap_id).unwrap().unwrap();
    let first = swap.refund_txid.expect("the watchdog broadcast a refund");
    // As after a bump the chain never took: a later refund is on record,
    // and the first one is what confirms.
    swap.earlier_refund_txids = vec![first];
    swap.refund_txid = Some(Txid::from_byte_array([0x5b; 32]));
    maker.store_ln_swap(&swap_id, swap).unwrap();

    // ---- One block short of final: still open ----
    generate_blocks(bitcoind, REFUND_FINALITY_DEPTH - 1);
    assert_eq!(
        confirmations(bitcoind, &first) as u64,
        REFUND_FINALITY_DEPTH - 1
    );
    // Only once the watcher holds the earlier refund does a pass reach the
    // depth check; before that it waits on the unseen spend instead.
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the watcher to record the earlier refund",
        matches!(
            maker.watch_service.watch_request(funded.outpoint),
            Ok(WatcherEvent::UtxoSpent { spending_tx: Some(tx), .. })
                if tx.compute_txid() == first
        )
    );
    ln_watchdog_tick_now(&maker);
    assert!(
        maker.get_ln_swap(&swap_id).unwrap().is_some(),
        "the maker closed the swap before its earlier refund was final"
    );

    // ---- At the finality depth the swap closes ----
    generate_blocks(bitcoind, 1);
    assert!(confirmations(bitcoind, &first) as u64 >= REFUND_FINALITY_DEPTH);

    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the maker to close the swap on its earlier refund",
        {
            ln_watchdog_tick_now(&maker);
            maker.get_ln_swap(&swap_id).unwrap().is_none()
        }
    );
    assert!(
        ln.claim_held_payment(&preimage).is_err(),
        "the refunded swap's held payment must be failed back"
    );
    framework.set_block_gen_paused(false);
}

/// A swept swap-in whose sweep never reached the mempool, or was evicted
/// from it, goes out again at the market rate once that has risen past
/// the recorded one. Nothing is pending, so nothing is replaced. While the
/// lookup of what spends the HTLC fails, nothing goes out.
#[world_test(
    backend = BitcoindBackend,
    bind = [pair = MockLightningBackend::new_pair(), ln = pair.0.clone()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn swap_in_sweep_never_sent_goes_out_at_the_market_rate(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let _ = &ln;
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    pause_block_generation(&framework);
    let _market = SpendFeerate::set(20.0);

    let preimage = Preimage([0xb2; 32]);
    let id = preimage.payment_hash().to_string();
    let swap = accepted_swap_in(&preimage);
    let funding = fund_htlc(bitcoind, &swap);
    generate_blocks(bitcoind, 1);
    let mut swept = paid_without_height(&swap, funding);
    swept.funding_height = Some(confirmation_height(bitcoind, &funding.txid) as u32);
    swept.phase = LnMakerPhase::InSwept;
    swept.preimage = Some(preimage);
    swept.sweep_feerate = Some(5.0);
    maker.store_ln_swap(&id, swept).unwrap();

    {
        let _failing = Switch::on(&FAIL_PENDING_SPEND_LOOKUP);
        ln_watchdog_tick_now(&maker);
    }
    assert!(
        bitcoind
            .client
            .get_tx_out(&funding.txid, funding.vout, Some(true))
            .unwrap()
            .is_some(),
        "a failed lookup must send nothing"
    );
    assert_eq!(
        maker.get_ln_swap(&id).unwrap().unwrap().sweep_feerate,
        Some(5.0)
    );

    ln_watchdog_tick_now(&maker);
    let value = swap.amount + swap.fee;
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        Amount::from_sat(3_000),
        "the sweep must go out at the market rate, 20 sat/vB for 150 vB"
    );
    assert_eq!(
        maker.get_ln_swap(&id).unwrap().unwrap().sweep_feerate,
        Some(20.0),
        "the new rate must be recorded"
    );

    framework.set_block_gen_paused(false);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// A swept swap-in whose sweep was saved at 20 sat/vB keeps that rate
/// through a restart. The sweep is not in the mempool, as after an
/// eviction, and the market falls to 5 sat/vB while the maker is down: the
/// restarted maker sends it at 20 sat/vB, not at the market rate or the
/// 2 sat/vB floor a lost record would read as.
#[world_test(
    backend = BitcoindBackend,
    bind = [pair = MockLightningBackend::new_pair(), ln = pair.0.clone()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn swap_in_sweep_keeps_its_rate_across_a_restart(world: &mut World, ln: Arc<MockLightningBackend>) {
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    pause_block_generation(&framework);
    let market = SpendFeerate::set(20.0);

    let preimage = Preimage([0xb3; 32]);
    let id = preimage.payment_hash().to_string();
    let swap = accepted_swap_in(&preimage);
    let funding = fund_htlc(bitcoind, &swap);
    generate_blocks(bitcoind, 1);
    let mut swept = paid_without_height(&swap, funding);
    swept.funding_height = Some(confirmation_height(bitcoind, &funding.txid) as u32);
    swept.phase = LnMakerPhase::InSwept;
    swept.preimage = Some(preimage);
    swept.sweep_feerate = Some(20.0);
    maker.store_ln_swap(&id, swept).unwrap();

    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();
    let mut restarted = MakerServer::init(config).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);
    world.adopt_makers([Arc::new(restarted)]);
    let maker = world.makers()[0].inner().clone();
    assert_eq!(
        maker.get_ln_swap(&id).unwrap().unwrap().sweep_feerate,
        Some(20.0),
        "the saved sweep rate must survive the reload"
    );

    market.set_rate(5.0);
    ln_watchdog_tick_now(&maker);
    let value = swap.amount + swap.fee;
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        Amount::from_sat(3_000),
        "the sweep must keep the 20 sat/vB it was built at, not the 5 sat/vB market"
    );
    assert_eq!(
        maker.get_ln_swap(&id).unwrap().unwrap().sweep_feerate,
        Some(20.0)
    );

    framework.set_block_gen_paused(false);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// When what spends from the taker's refund cannot be read, the sweep still
/// contests it, bidding against the refund alone. The rate is recorded only
/// once the node takes the sweep, so a rebuild gives the same transaction.
/// A rejected bid records nothing, and the next pass bids on what it reads
/// then.
#[world_test(
    backend = BitcoindBackend,
    bind = [pair = MockLightningBackend::new_pair(), ln = pair.0.clone()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn watchdog_contests_a_taker_refund_whose_family_it_cannot_read(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let _ = &ln;
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    pause_block_generation(&framework);
    let _market = SpendFeerate::set(SPEND_FEE_RATE_FLOOR);

    let preimage = Preimage([0xb8; 32]);
    let id = preimage.payment_hash().to_string();
    let (swap, funding) = swept_past_its_refund_window(bitcoind, &maker, &preimage);
    let recorded = maker.get_ln_swap(&id).unwrap().unwrap().sweep_feerate;
    let refund = broadcast_taker_refund(bitcoind, &swap, funding);
    let value = swap.amount + swap.fee;
    let refund_vsize = bitcoind.client.get_mempool_entry(&refund).unwrap().vsize;
    let rate = (300.0 / refund_vsize as f64 + 1.0).max(3.0);
    let fee = Amount::from_sat((rate * 150.0).ceil() as u64);

    {
        let _unread = Switch::on(&FAIL_REFUND_FAMILY_LOOKUP);
        ln_watchdog_tick_now(&maker);
    }
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        fee,
        "the sweep must outbid the refund alone"
    );
    assert!(
        bitcoind.client.get_mempool_entry(&refund).is_err(),
        "the taker's refund must be out of the mempool"
    );
    let taken = maker
        .get_ln_swap(&id)
        .unwrap()
        .unwrap()
        .sweep_feerate
        .expect("a sweep rate is on record");
    assert_ne!(Some(taken), recorded, "the accepted bid must be recorded");
    assert_eq!(
        Amount::from_sat((taken * 150.0).ceil() as u64),
        fee,
        "the recorded rate must rebuild the sweep the node took"
    );
    // The pending spend is now our sweep: the next pass resends it.
    ln_watchdog_tick_now(&maker);
    assert_eq!(mempool_spend_fee(bitcoind, funding, value), fee);

    framework.set_block_gen_paused(false);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// The taker's refund of a swept swap-in can reach the mempool first. The
/// invoice is already paid, so the watchdog contests it: the sweep pays
/// what the refund pays plus the replacement step, at a higher feerate than
/// the refund's own. Here the market sits at the same 2 sat/vB floor the
/// refund pays, where a sweep at the market rate would only tie it and be
/// rejected.
#[world_test(
    backend = BitcoindBackend,
    bind = [pair = MockLightningBackend::new_pair(), ln = pair.0.clone()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn watchdog_contests_a_taker_refund_of_a_swept_swap_in(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let _ = &ln;
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    pause_block_generation(&framework);
    let _market = SpendFeerate::set(SPEND_FEE_RATE_FLOOR);

    let preimage = Preimage([0xb4; 32]);
    let id = preimage.payment_hash().to_string();
    let (swap, funding) = swept_past_its_refund_window(bitcoind, &maker, &preimage);
    let refund = broadcast_taker_refund(bitcoind, &swap, funding);
    let value = swap.amount + swap.fee;
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        Amount::from_sat(300)
    );

    // The refund is smaller than the 150 vB the sweep is priced for, so its
    // own feerate, plus the 1 sat/vB step, sets the rate.
    let refund_vsize = bitcoind.client.get_mempool_entry(&refund).unwrap().vsize;
    let rate = (300.0 / refund_vsize as f64 + 1.0).max(3.0);
    let fee = Amount::from_sat((rate * 150.0).ceil() as u64);

    ln_watchdog_tick_now(&maker);
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        fee,
        "the sweep must outbid the refund's 300 sats by fee and by feerate"
    );
    assert!(
        bitcoind.client.get_mempool_entry(&refund).is_err(),
        "the taker's refund must be out of the mempool"
    );
    assert_eq!(
        maker.get_ln_swap(&id).unwrap().unwrap().sweep_feerate,
        Some(rate),
        "the contested rate must be recorded"
    );
    // The pending spend is now our sweep: the next pass resends it.
    ln_watchdog_tick_now(&maker);
    assert_eq!(mempool_spend_fee(bitcoind, funding, value), fee);

    framework.set_block_gen_paused(false);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// The same contest with a transaction spending the taker's refund.
/// Replacing the refund evicts that child too, so the sweep pays both
/// their fees plus the replacement step.
#[world_test(
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    cases = [
        watchdog_outbids_a_taker_refund_and_its_child(backend = BitcoindBackend),
        /// Same on Electrum, where the family is read from the server's
        /// script histories.
        watchdog_outbids_a_taker_refund_and_its_child_on_electrum(backend = ElectrumBackend),
    ],
)]
fn run_watchdog_outbids_a_taker_refund_and_its_child(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let _ = &ln;
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    pause_block_generation(&framework);
    let _market = SpendFeerate::set(SPEND_FEE_RATE_FLOOR);

    let preimage = Preimage([0xb5; 32]);
    let (swap, funding) = swept_past_its_refund_window(bitcoind, &maker, &preimage);
    let refund = broadcast_taker_refund(bitcoind, &swap, funding);
    let child = spend_with_fee(bitcoind, refund, Amount::from_sat(1_500));

    // An Electrum server sees new mempool transactions shortly after the
    // node does, so the watchdog may take a few passes.
    let gone = |txid: &Txid| bitcoind.client.get_mempool_entry(txid).is_err();
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(500),
        "the sweep to replace the taker's refund and its child",
        {
            ln_watchdog_tick_now(&maker);
            gone(&refund) && gone(&child)
        }
    );
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, swap.amount + swap.fee),
        Amount::from_sat(1_950),
        "the sweep must pay the refund's 300 sats and the child's 1,500 plus the 1 sat/vB step,          13 sat/vB for 150 vB"
    );

    framework.set_block_gen_paused(false);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// A swap can hold the output of our pending sweep to fund itself before
/// its funding is broadcast, where the node cannot see it. While a swap
/// holds it, the sweep is not bumped, since a replacement would invalidate
/// that funding. Once the hold is released, the sweep is bumped.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn swap_in_sweep_is_not_bumped_while_a_swap_holds_its_output(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let _ = &ln;
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    pause_block_generation(&framework);
    let market = SpendFeerate::set(5.0);

    let preimage = Preimage([0xb7; 32]);
    let id = preimage.payment_hash().to_string();
    let swap = accepted_swap_in(&preimage);
    let funding = fund_htlc(bitcoind, &swap);
    generate_blocks(bitcoind, 1);
    let mut swept = paid_without_height(&swap, funding);
    swept.funding_height = Some(confirmation_height(bitcoind, &funding.txid) as u32);
    swept.phase = LnMakerPhase::InSwept;
    swept.preimage = Some(preimage);
    swept.sweep_feerate = Some(5.0);
    maker.store_ln_swap(&id, swept).unwrap();
    ln_watchdog_tick_now(&maker);
    let value = swap.amount + swap.fee;
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        Amount::from_sat(750)
    );
    let sweep = bitcoind
        .client
        .get_raw_mempool()
        .unwrap()
        .into_iter()
        .find(|txid| {
            bitcoind
                .client
                .get_raw_transaction(txid, None)
                .unwrap()
                .input
                .iter()
                .any(|input| input.previous_output == funding)
        })
        .expect("the sweep is in the mempool");

    // A swap holds the sweep's output, as one building its funding would.
    maker
        .wallet
        .write()
        .unwrap()
        .reserve_swap_locks_for_test("a-coinswap", &[OutPoint::new(sweep, 0)])
        .unwrap();
    market.set_rate(20.0);
    ln_watchdog_tick_now(&maker);
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        Amount::from_sat(750),
        "a sweep whose output a swap holds must not be bumped"
    );
    assert_eq!(
        maker.get_ln_swap(&id).unwrap().unwrap().sweep_feerate,
        Some(5.0)
    );

    // Released, it is bumped to the market rate, 20 sat/vB.
    maker
        .wallet
        .write()
        .unwrap()
        .release_swap_locks_for_test("a-coinswap")
        .unwrap();
    ln_watchdog_tick_now(&maker);
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        Amount::from_sat(3_000)
    );

    framework.set_block_gen_paused(false);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// The taker's refund can spread over many outputs, each to its own
/// address, so reading what spends from it touches as many scripts. The
/// sweep still replaces it and a child of one of its outputs, on Core and on
/// Electrum, where the outputs' histories are read in one batch.
#[world_test(
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    cases = [
        watchdog_outbids_a_wide_taker_refund(backend = BitcoindBackend),
        /// Same on Electrum.
        watchdog_outbids_a_wide_taker_refund_on_electrum(backend = ElectrumBackend),
    ],
)]
fn run_watchdog_outbids_a_wide_taker_refund(world: &mut World, ln: Arc<MockLightningBackend>) {
    let _ = &ln;
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    pause_block_generation(&framework);
    let _market = SpendFeerate::set(SPEND_FEE_RATE_FLOOR);

    let preimage = Preimage([0xb6; 32]);
    let (swap, funding) = swept_past_its_refund_window(bitcoind, &maker, &preimage);
    let value = swap.amount + swap.fee;
    let refund = broadcast_wide_taker_refund(bitcoind, &swap, funding, 50);
    let refund_tx = bitcoind.client.get_raw_transaction(&refund, None).unwrap();
    let refund_fee = value
        - refund_tx
            .output
            .iter()
            .map(|output| output.value)
            .sum::<Amount>();
    // A child of one output, so only a read of the whole family prices the
    // sweep high enough: bidding against the refund alone would be refused.
    let child_fee = Amount::from_sat(300);
    let child = spend_with_fee(bitcoind, refund, child_fee);
    // It pays both fees plus the 1 sat/vB step for 150 vB, and more per
    // vbyte than the refund by that step.
    let to_beat = refund_fee + child_fee;
    let rate = (to_beat.to_sat() as f64 / 150.0 + 1.0)
        .max(refund_fee.to_sat() as f64 / refund_tx.vsize() as f64 + 1.0)
        .max(SPEND_FEE_RATE_FLOOR);

    let gone = |txid: &Txid| bitcoind.client.get_mempool_entry(txid).is_err();
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(500),
        "the sweep to replace the wide taker refund and its child",
        {
            ln_watchdog_tick_now(&maker);
            gone(&refund) && gone(&child)
        }
    );
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        Amount::from_sat((rate * 150.0).ceil() as u64),
        "the sweep must outbid the {} sat refund and its {} sat child",
        refund_fee.to_sat(),
        child_fee.to_sat()
    );

    framework.set_block_gen_paused(false);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// Broadcasts the taker's refund of `swap`'s HTLC spread over `outputs`
/// outputs, each to its own address of the node's wallet, paying 3 sat/vB
/// on its real size. Signed with the taker's key like
/// [`broadcast_taker_refund`].
fn broadcast_wide_taker_refund(
    bitcoind: &BitcoinD,
    swap: &LnMakerSwap,
    funding: OutPoint,
    outputs: usize,
) -> Txid {
    use bitcoin::{
        secp256k1::Message,
        sighash::{EcdsaSighashType, SighashCache},
        ScriptBuf, TxOut, Witness,
    };
    let timelock_privkey = SecretKey::from_slice(&[0x42; 32]).unwrap();
    let value = swap.amount + swap.fee;
    let mut refund = swap
        .htlc
        .create_timelock_spend(
            funding,
            value,
            &timelock_privkey,
            ScriptBuf::new(),
            SPEND_FEE_RATE_FLOOR,
        )
        .unwrap();
    refund.output = (0..outputs)
        .map(|_| TxOut {
            value: Amount::ZERO,
            script_pubkey: bitcoind
                .client
                .get_new_address(None, None)
                .unwrap()
                .require_network(Network::Regtest)
                .unwrap()
                .script_pubkey(),
        })
        .collect();
    let fee = Amount::from_sat(3 * refund.vsize() as u64);
    let each = (value - fee) / outputs as u64;
    for output in &mut refund.output {
        output.value = each;
    }
    let paid = each * outputs as u64;
    refund.output[0].value += value - fee - paid;
    let sighash = SighashCache::new(&refund)
        .p2wsh_signature_hash(0, swap.htlc.redeemscript(), value, EcdsaSighashType::All)
        .unwrap();
    let signature = bitcoin::ecdsa::Signature {
        signature: Secp256k1::new().sign_ecdsa_low_r(
            &Message::from_digest(sighash.to_byte_array()),
            &timelock_privkey,
        ),
        sighash_type: EcdsaSighashType::All,
    };
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(Vec::<u8>::new());
    witness.push(swap.htlc.redeemscript().to_bytes());
    refund.input[0].witness = witness;
    bitcoind.client.send_raw_transaction(&refund).unwrap()
}

/// Stores a swept swap-in for `preimage` on confirmed funding, then mines
/// past its 10-block refund window so the taker's refund is valid.
fn swept_past_its_refund_window(
    bitcoind: &BitcoinD,
    maker: &MakerServer,
    preimage: &Preimage,
) -> (LnMakerSwap, OutPoint) {
    let swap = accepted_swap_in_with_locktime(preimage, 10);
    let funding = fund_htlc(bitcoind, &swap);
    generate_blocks(bitcoind, 1);
    let mut swept = paid_without_height(&swap, funding);
    swept.funding_height = Some(confirmation_height(bitcoind, &funding.txid) as u32);
    swept.phase = LnMakerPhase::InSwept;
    swept.preimage = Some(*preimage);
    maker
        .store_ln_swap(&preimage.payment_hash().to_string(), swept)
        .unwrap();
    generate_blocks(bitcoind, 10);
    (swap, funding)
}

/// Spends output 0 of mempool transaction `parent`, which pays the node's
/// wallet, back to the wallet with `fee`.
fn spend_with_fee(bitcoind: &BitcoinD, parent: Txid, fee: Amount) -> Txid {
    let prevout = bitcoind
        .client
        .get_raw_transaction(&parent, None)
        .unwrap()
        .output[0]
        .clone();
    let address = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    let unsigned = bitcoind
        .client
        .create_raw_transaction(
            &[CreateRawTransactionInput {
                txid: parent,
                vout: 0,
                sequence: None,
            }],
            &HashMap::from([(address.to_string(), prevout.value - fee)]),
            None,
            None,
        )
        .unwrap();
    let signed = bitcoind
        .client
        .sign_raw_transaction_with_wallet(
            &unsigned,
            Some(&[SignRawTransactionInput {
                txid: parent,
                vout: 0,
                script_pub_key: prevout.script_pubkey,
                redeem_script: None,
                amount: Some(prevout.value),
            }]),
            None,
        )
        .unwrap();
    assert!(signed.complete, "the wallet could not sign the child");
    bitcoind
        .client
        .send_raw_transaction(&signed.transaction().unwrap())
        .unwrap()
}

/// A test that panics while holding a [`Switch`] still leaves it off.
#[test]
fn switch_resets_on_panic() {
    static FLAG: AtomicBool = AtomicBool::new(false);
    let _ = std::panic::catch_unwind(|| {
        let _on = Switch::on(&FLAG);
        panic!("held");
    });
    assert!(!FLAG.load(SeqCst));
}

/// A crash in the middle of the watchdog's refund, between recording it and
/// broadcasting it, must leave a restarted maker able to finish it: send the
/// refund, recognise it as its own, and close the swap once it is final.
/// Broadcasting first could leave a refund that confirmed while the maker
/// was down and that the restarted maker did not know was its own, so the
/// swap never closed. The market falls while it is down, and a refund is
/// never rebuilt below the rate it was recorded at, so the restarted maker
/// sends the recorded refund.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_restart_recovers_an_interrupted_refund(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    use openswap::maker::lightning_handlers::INTERRUPT_REFUND;

    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;
    // The test mines every block itself, so a refund sent early cannot
    // confirm unseen before the checks below.
    pause_block_generation(&framework);
    let market = SpendFeerate::set(10.0);

    let preimage = Preimage([0x7a; 32]);
    let swap_id = preimage.payment_hash().to_string();
    let funded = fund_swap_out(
        &maker,
        &ln,
        preimage.payment_hash(),
        Amount::from_sat(40_000),
        locktime,
    );
    generate_blocks(bitcoind, 1);
    let funded_at = bitcoind.client.get_block_count().unwrap()
        - confirmations(bitcoind, &funded.outpoint.txid) as u64
        + 1;
    mine_to(bitcoind, funded_at + locktime as u64 + 1);

    // ---- The refund is interrupted, and the maker goes down ----
    let interrupted = Switch::on(&INTERRUPT_REFUND);
    ln_watchdog_tick_now(&maker);
    drop(interrupted);
    let recorded = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .and_then(|swap| swap.refund_txid)
        .expect("the refund was recorded before the crash");
    // Nothing reached the network before it was recorded: the HTLC is spent
    // neither in the mempool nor in a block, before or after the maker is
    // down long enough for anything it sent to confirm. A failed lookup
    // fails the test rather than reading as nothing sent.
    let unspent = || {
        bitcoind
            .client
            .get_tx_out(&funded.outpoint.txid, funded.outpoint.vout, Some(true))
            .expect("the node answers gettxout")
            .is_some()
    };
    assert!(unspent(), "the interrupted refund was sent");
    generate_blocks(bitcoind, 1);
    assert!(unspent(), "the interrupted refund was mined");

    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();
    let mut restarted = MakerServer::init(config).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);
    world.adopt_makers([Arc::new(restarted)]);
    let maker = world.makers()[0].inner().clone();

    // ---- The restarted maker refunds and closes the swap ----
    // Nothing was sent, so it rebuilds the refund from its record.
    market.set_rate(5.0);
    ln_watchdog_tick_now(&maker);
    generate_blocks(bitcoind, REFUND_FINALITY_DEPTH);
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the restarted maker to close the refunded swap",
        {
            ln_watchdog_tick_now(&maker);
            maker.get_ln_swap(&swap_id).unwrap().is_none()
        }
    );
    assert!(
        ln.claim_held_payment(&preimage).is_err(),
        "the refunded swap's held payment must be failed back"
    );

    // The txid recorded before the crash named the refund that confirmed.
    assert!(confirmations(bitcoind, &recorded) >= 1);
    let refund = raw_tx_with_retry(bitcoind, &recorded);
    assert_eq!(
        refund
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect::<Vec<_>>(),
        vec![funded.outpoint]
    );
    assert_eq!(
        funded.value
            - refund
                .output
                .iter()
                .map(|output| output.value)
                .sum::<Amount>(),
        Amount::from_sat(1_500),
        "the refund must keep the 10 sat/vB it was recorded at, not the 5 sat/vB market"
    );
    framework.set_block_gen_paused(false);
}

/// The same crash, with the market risen while the maker was down. Nothing
/// was sent and nothing spends the HTLC, so the restarted maker refunds at
/// the new rate under a new txid. The interrupted refund stays on record in
/// case it is the one that confirms, and the swap closes on the new refund.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_refunds_at_a_risen_rate_after_an_interrupted_refund(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    use openswap::maker::lightning_handlers::INTERRUPT_REFUND;

    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;
    pause_block_generation(&framework);
    let market = SpendFeerate::set(10.0);

    let preimage = Preimage([0x7d; 32]);
    let swap_id = preimage.payment_hash().to_string();
    let funded = fund_swap_out(
        &maker,
        &ln,
        preimage.payment_hash(),
        Amount::from_sat(40_000),
        locktime,
    );
    generate_blocks(bitcoind, 1);
    let funded_at = bitcoind.client.get_block_count().unwrap()
        - confirmations(bitcoind, &funded.outpoint.txid) as u64
        + 1;
    mine_to(bitcoind, funded_at + locktime as u64 + 1);

    // ---- The refund is interrupted, and the maker goes down ----
    let interrupted = Switch::on(&INTERRUPT_REFUND);
    ln_watchdog_tick_now(&maker);
    drop(interrupted);
    let recorded = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .and_then(|swap| swap.refund_txid)
        .expect("the refund was recorded before the crash");

    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();
    let mut restarted = MakerServer::init(config).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);
    world.adopt_makers([Arc::new(restarted)]);
    let maker = world.makers()[0].inner().clone();

    // ---- The restarted maker refunds at the risen rate ----
    market.set_rate(40.0);
    ln_watchdog_tick_now(&maker);
    let swap = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .expect("the swap stays open");
    let refund_txid = swap.refund_txid.expect("the new refund is recorded");
    assert_ne!(refund_txid, recorded, "the refund kept its old rate");
    assert_eq!(swap.earlier_refund_txids, vec![recorded]);
    assert_eq!(swap.refund_feerate, Some(40.0));
    assert_eq!(
        mempool_spend_fee(bitcoind, funded.outpoint, funded.value),
        Amount::from_sat(6_000),
        "the refund must pay the risen rate, 40 sat/vB for 150 vB"
    );

    // ---- The new refund is final, so the swap closes ----
    generate_blocks(bitcoind, REFUND_FINALITY_DEPTH);
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the restarted maker to close the refunded swap",
        {
            ln_watchdog_tick_now(&maker);
            maker.get_ln_swap(&swap_id).unwrap().is_none()
        }
    );
    assert!(confirmations(bitcoind, &refund_txid) as u64 >= REFUND_FINALITY_DEPTH);
    assert!(
        ln.claim_held_payment(&preimage).is_err(),
        "the refunded swap's held payment must be failed back"
    );
    framework.set_block_gen_paused(false);
}

/// Confirmations the maker's swap-out refund needs before the swap closes.
/// Mirrors the maker's `REFUND_FINALITY_DEPTH`.
const REFUND_FINALITY_DEPTH: u64 = 6;

/// A refund with one confirmation can still be reorged out, and the taker's
/// hashlock claim, which never expires, can confirm in its place. Failing the
/// held payment then would leave the maker with neither side, and dropping
/// the record would lose the only copy of the refund key. So the swap stays
/// open, across a restart, while the refund is shallow, and when a reorg
/// replaces it with the taker's claim the maker settles from its preimage.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_keeps_a_shallow_refund_through_a_reorg(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    use openswap::watch_tower::watcher::WatcherEvent;

    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;
    // The test mines every block itself, so it controls the refund's depth.
    pause_block_generation(&framework);

    let preimage = Preimage([0x90; 32]);
    let swap_id = preimage.payment_hash().to_string();
    let funded = fund_swap_out(
        &maker,
        &ln,
        preimage.payment_hash(),
        Amount::from_sat(40_000),
        locktime,
    );
    generate_blocks(bitcoind, 1);
    let funded_at = bitcoind.client.get_block_count().unwrap()
        - confirmations(bitcoind, &funded.outpoint.txid) as u64
        + 1;
    mine_to(bitcoind, funded_at + locktime as u64 + 1);

    // ---- The refund confirms once, and the watcher records it ----
    ln_watchdog_tick_now(&maker);
    let refund_txid = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .and_then(|swap| swap.refund_txid)
        .expect("the watchdog broadcast a refund");
    generate_blocks(bitcoind, 1);
    assert_eq!(confirmations(bitcoind, &refund_txid), 1);
    let refund_block = bitcoind.client.get_best_block_hash().unwrap();
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the watcher to record the refund",
        matches!(
            maker.watch_service.watch_request(funded.outpoint),
            Ok(WatcherEvent::UtxoSpent { spending_tx: Some(tx), .. })
                if tx.compute_txid() == refund_txid
        )
    );

    // ---- One confirmation is not final: the swap stays open ----
    let still_open = |maker: &Arc<MakerServer>, when: &str| {
        let swap = maker
            .get_ln_swap(&swap_id)
            .unwrap()
            .unwrap_or_else(|| panic!("the maker closed the swap {}", when));
        assert_eq!(swap.phase, LnMakerPhase::OutFunded);
        assert_eq!(swap.refund_txid, Some(refund_txid));
    };
    ln_watchdog_tick_now(&maker);
    still_open(&maker, "on a refund with one confirmation");

    // ---- A restart keeps the shallow refund's record ----
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();
    let mut restarted = MakerServer::init(config).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);
    world.adopt_makers([Arc::new(restarted)]);
    let maker = world.makers()[0].inner().clone();
    ln_watchdog_tick_now(&maker);
    still_open(&maker, "after a restart on a refund with one confirmation");

    // ---- A reorg replaces the refund with the taker's claim ----
    let swap = maker.get_ln_swap(&swap_id).unwrap().unwrap();
    let (_, value) = swap.funding.expect("the swap is funded");
    let destination = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    let claim = swap
        .htlc
        .create_hashlock_spend(
            funded.outpoint,
            value,
            &SecretKey::from_slice(&[0x31; 32]).unwrap(),
            &preimage,
            destination.script_pubkey(),
            SPEND_FEE_RATE_FLOOR,
        )
        .unwrap();
    bitcoind.client.invalidate_block(&refund_block).unwrap();
    // Mined directly: the disconnected refund is back in the mempool, and
    // the block that confirms the claim evicts it.
    bitcoind
        .client
        .call::<serde_json::Value>(
            "generateblock",
            &[
                serde_json::json!(destination.to_string()),
                serde_json::json!([bitcoin::consensus::encode::serialize_hex(&claim)]),
            ],
        )
        .unwrap();
    // Deep enough that the replaced block would count as final.
    generate_blocks(bitcoind, REFUND_FINALITY_DEPTH);
    assert!(confirmations(bitcoind, &claim.compute_txid()) >= 1);
    // Core's txindex still names the replaced block for the refund, so its
    // depth must come from the active chain, where it has none.
    let refund_info = bitcoind
        .client
        .get_raw_transaction_info(&refund_txid, None)
        .unwrap();
    assert_eq!(refund_info.blockhash, Some(refund_block));
    assert_eq!(refund_info.confirmations.unwrap_or(0), 0);
    assert_eq!(
        maker.tx_confirmations(&refund_txid).unwrap(),
        None,
        "the maker counted a reorged-out refund as confirmed"
    );

    // ---- The held payment was kept, so the claim's preimage settles it ----
    wait_until!(
        Duration::from_secs(60),
        every Duration::from_millis(200),
        "the maker to settle from the taker's claim",
        {
            ln_watchdog_tick_now(&maker);
            maker.get_ln_swap(&swap_id).unwrap().is_none()
        }
    );
    let mut released = None;
    while let Some(event) = ln.poll_event().unwrap() {
        if let LnEvent::PaymentSuccessful {
            preimage: Some(preimage),
            ..
        } = event
        {
            released = Some(preimage);
        }
    }
    assert_eq!(
        released,
        Some(preimage),
        "the held payment must be settled with the claim's preimage"
    );
    framework.set_block_gen_paused(false);
}

/// A swap-out refund that has reached `REFUND_FINALITY_DEPTH` closes the
/// swap and fails the held payment back; one block short of it does not.
#[world_test(
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
    cases = [
        lightning_maker_closes_a_refund_at_finality_depth(backend = BitcoindBackend),
        /// Same on Electrum, where the maker counts the refund's depth from
        /// its block height and the server's tip.
        lightning_maker_closes_a_refund_at_finality_depth_on_electrum(backend = ElectrumBackend),
    ],
)]
fn run_lightning_maker_closes_a_refund_at_finality_depth(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    use openswap::watch_tower::watcher::WatcherEvent;

    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;
    pause_block_generation(&framework);

    let preimage = Preimage([0x91; 32]);
    let swap_id = preimage.payment_hash().to_string();
    let funded = fund_swap_out(
        &maker,
        &ln,
        preimage.payment_hash(),
        Amount::from_sat(40_000),
        locktime,
    );
    generate_blocks(bitcoind, 1);
    let funded_at = bitcoind.client.get_block_count().unwrap()
        - confirmations(bitcoind, &funded.outpoint.txid) as u64
        + 1;
    mine_to(bitcoind, funded_at + locktime as u64 + 1);
    // On Electrum the maker reads the chain through electrs. No-op on Core.
    framework.wait_for_electrs_tip();

    ln_watchdog_tick_now(&maker);
    let refund_txid = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .and_then(|swap| swap.refund_txid)
        .expect("the watchdog broadcast a refund");

    // ---- One block short of final: still open, payment still held ----
    generate_blocks(bitcoind, REFUND_FINALITY_DEPTH - 1);
    assert_eq!(
        confirmations(bitcoind, &refund_txid) as u64,
        REFUND_FINALITY_DEPTH - 1
    );
    framework.wait_for_electrs_tip();
    assert_eq!(
        maker.tx_confirmations(&refund_txid).unwrap(),
        Some(REFUND_FINALITY_DEPTH as u32 - 1),
        "the maker's backend must see the refund one block short of final"
    );
    // Only once the watcher holds the refund does a pass reach the depth
    // check; before that it waits on the unseen spend instead.
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the watcher to record the refund",
        matches!(
            maker.watch_service.watch_request(funded.outpoint),
            Ok(WatcherEvent::UtxoSpent { spending_tx: Some(tx), .. })
                if tx.compute_txid() == refund_txid
        )
    );
    ln_watchdog_tick_now(&maker);
    assert!(
        maker.get_ln_swap(&swap_id).unwrap().is_some(),
        "the maker closed the swap before its refund was final"
    );

    // ---- At the finality depth the swap closes ----
    generate_blocks(bitcoind, 1);
    framework.wait_for_electrs_tip();
    assert_eq!(
        maker.tx_confirmations(&refund_txid).unwrap(),
        Some(REFUND_FINALITY_DEPTH as u32)
    );
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the maker to close the refunded swap",
        {
            ln_watchdog_tick_now(&maker);
            maker.get_ln_swap(&swap_id).unwrap().is_none()
        }
    );
    assert!(
        ln.claim_held_payment(&preimage).is_err(),
        "the refunded swap's held payment must be failed back"
    );
    framework.set_block_gen_paused(false);
}

/// While a Core re-check after lost notifications is pending, the watcher
/// answers "no spend" for an HTLC the taker may already have claimed. Past
/// the CSV that answer must not send the maker's refund, which the chain
/// would reject anyway; the chain decides, here and after a restart. Once
/// the watcher has the claim, the maker settles the held payment from its
/// preimage.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_does_not_refund_a_claim_its_watcher_has_not_seen(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;

    let preimage = Preimage([0x7b; 32]);
    let swap_id = preimage.payment_hash().to_string();
    let funded = fund_swap_out(
        &maker,
        &ln,
        preimage.payment_hash(),
        Amount::from_sat(40_000),
        locktime,
    );
    generate_blocks(bitcoind, 1);
    let funded_at = bitcoind.client.get_block_count().unwrap()
        - confirmations(bitcoind, &funded.outpoint.txid) as u64
        + 1;
    // Past the CSV, so only the chain stands between the watchdog and a refund.
    mine_to(bitcoind, funded_at + locktime as u64 + 1);

    // ---- The taker claims, and the watcher does not say so ----
    let hidden = Switch::on(&HIDE_HTLC_SPENDS);
    let swap = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .expect("the swap is open");
    let (_, value) = swap.funding.expect("the swap is funded");
    let destination = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey();
    let claim = swap
        .htlc
        .create_hashlock_spend(
            funded.outpoint,
            value,
            &SecretKey::from_slice(&[0x31; 32]).unwrap(),
            &preimage,
            destination,
            SPEND_FEE_RATE_FLOOR,
        )
        .unwrap();
    let claim_txid = bitcoind.client.send_raw_transaction(&claim).unwrap();
    generate_blocks(bitcoind, 1);
    assert!(confirmations(bitcoind, &claim_txid) >= 1);

    let no_refund = |maker: &Arc<MakerServer>| {
        let swap = maker
            .get_ln_swap(&swap_id)
            .unwrap()
            .expect("the swap stays open");
        assert_eq!(swap.phase, LnMakerPhase::OutFunded);
        assert_eq!(
            swap.refund_txid, None,
            "the maker refunded an HTLC the taker had claimed"
        );
    };
    ln_watchdog_tick_now(&maker);
    no_refund(&maker);

    // ---- Still unseen after a restart ----
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();
    let mut restarted = MakerServer::init(config).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);
    world.adopt_makers([Arc::new(restarted)]);
    let maker = world.makers()[0].inner().clone();
    ln_watchdog_tick_now(&maker);
    no_refund(&maker);

    // ---- Once the watcher has the claim, the preimage settles the swap ----
    drop(hidden);
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the maker to settle from the taker's claim",
        {
            ln_watchdog_tick_now(&maker);
            maker.get_ln_swap(&swap_id).unwrap().is_none()
        }
    );
    let mut released = None;
    while let Some(event) = ln.poll_event().unwrap() {
        if let LnEvent::PaymentSuccessful {
            preimage: Some(preimage),
            ..
        } = event
        {
            released = Some(preimage);
        }
    }
    assert_eq!(
        released,
        Some(preimage),
        "the held payment must be settled with the claim's preimage"
    );
}

/// Stores `swap_id` as `handle_swap_out_paid` does when its tip read fails:
/// funded, with no `funding_height`.
fn drop_funding_height(maker: &MakerServer, swap_id: &str) {
    let mut swap = maker
        .get_ln_swap(swap_id)
        .unwrap()
        .expect("the swap is open");
    swap.funding_height = None;
    maker.store_ln_swap(swap_id, swap).unwrap();
}

/// A swap-out stored without its funding height must still be refunded once
/// the taker leaves it unclaimed. The watchdog reads the height from the
/// funding's confirmation and saves it. It refunds only once the CSV has
/// passed, never while the funding is unconfirmed, and a restart on either
/// side of the recovery changes none of that.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_refunds_a_swap_out_stored_without_funding_height(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;
    pause_block_generation(&framework);

    let preimage = Preimage([0x7c; 32]);
    let swap_id = preimage.payment_hash().to_string();
    let funded = fund_swap_out(
        &maker,
        &ln,
        preimage.payment_hash(),
        Amount::from_sat(40_000),
        locktime,
    );
    drop_funding_height(&maker, &swap_id);

    // ---- Unconfirmed: there is no height to recover, nor a refund ----
    assert_eq!(confirmations(bitcoind, &funded.outpoint.txid), 0);
    ln_watchdog_tick_now(&maker);
    let swap = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .expect("the swap stays open");
    assert_eq!(swap.phase, LnMakerPhase::OutFunded);
    assert_eq!(
        swap.funding_height, None,
        "a height was stored for an unconfirmed funding"
    );
    assert_eq!(swap.refund_txid, None);

    // ---- Restart before the height is recovered ----
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();
    let mut restarted = MakerServer::init(config).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);
    world.adopt_makers([Arc::new(restarted)]);
    let maker = world.makers()[0].inner().clone();
    assert_eq!(
        maker.get_ln_swap(&swap_id).unwrap().unwrap().funding_height,
        None
    );

    // ---- Confirmed: the height is recovered, short of the CSV ----
    generate_blocks(bitcoind, 1);
    let confirmed_at = confirmation_height(bitcoind, &funded.outpoint.txid);
    let refundable_at = confirmed_at + locktime as u64;
    mine_to(bitcoind, refundable_at - 1);
    ln_watchdog_tick_now(&maker);
    let swap = maker.get_ln_swap(&swap_id).unwrap().unwrap();
    assert_eq!(
        swap.funding_height,
        Some(confirmed_at as u32),
        "the watchdog did not recover the funding's confirmation height"
    );
    assert_eq!(swap.refund_txid, None, "refunded before the CSV passed");

    // ---- The recovered height survives a restart ----
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();
    let mut restarted = MakerServer::init(config).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);
    world.adopt_makers([Arc::new(restarted)]);
    let maker = world.makers()[0].inner().clone();
    assert_eq!(
        maker.get_ln_swap(&swap_id).unwrap().unwrap().funding_height,
        Some(confirmed_at as u32),
        "the recovered funding height was not saved"
    );

    // ---- Past the CSV the watchdog refunds ----
    mine_to(bitcoind, refundable_at);
    ln_watchdog_tick_now(&maker);
    let swap = maker.get_ln_swap(&swap_id).unwrap().unwrap();
    let refund_txid = swap.refund_txid.expect("the watchdog never refunded");
    assert_eq!(
        swap.funding_height,
        Some(confirmed_at as u32),
        "recording the refund lost the recovered height"
    );
    assert!(bitcoind.client.get_mempool_entry(&refund_txid).is_ok());
    assert_eq!(
        raw_tx_with_retry(bitcoind, &refund_txid)
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect::<Vec<_>>(),
        vec![funded.outpoint]
    );

    // ---- Once it is final, the swap closes and the payment fails back ----
    generate_blocks(bitcoind, REFUND_FINALITY_DEPTH);
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the maker to close the refunded swap",
        {
            ln_watchdog_tick_now(&maker);
            maker.get_ln_swap(&swap_id).unwrap().is_none()
        }
    );
    assert!(
        ln.claim_held_payment(&preimage).is_err(),
        "the refunded swap's held payment must be failed back"
    );
    framework.set_block_gen_paused(false);
}

/// A failed height lookup is no answer: the watchdog keeps a swap-out stored
/// without its funding height and does not refund it, even past the CSV. A
/// later pass that can read the height, here after a restart, refunds it.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [FailFundingHeightLookup],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_keeps_a_swap_out_while_its_funding_height_is_unknown(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;
    pause_block_generation(&framework);

    let preimage = Preimage([0x7d; 32]);
    let swap_id = preimage.payment_hash().to_string();
    let funded = fund_swap_out(
        &maker,
        &ln,
        preimage.payment_hash(),
        Amount::from_sat(40_000),
        locktime,
    );
    drop_funding_height(&maker, &swap_id);
    generate_blocks(bitcoind, 1);
    let confirmed_at = confirmation_height(bitcoind, &funded.outpoint.txid);
    mine_to(bitcoind, confirmed_at + locktime as u64 + 1);

    ln_watchdog_tick_now(&maker);
    let kept = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .expect("a failed height lookup dropped the swap");
    assert_eq!(kept.phase, LnMakerPhase::OutFunded);
    assert_eq!(kept.funding, Some((funded.outpoint, funded.value)));
    assert_eq!(kept.funding_height, None);
    assert_eq!(kept.refund_txid, None, "refunded on a failed height lookup");

    // ---- Restart with a working backend ----
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();
    let mut restarted = MakerServer::init(config).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);
    world.adopt_makers([Arc::new(restarted)]);
    let maker = world.makers()[0].inner().clone();

    // Recovered and refunded in one pass: the refund's record must keep the
    // height the pass recovered.
    ln_watchdog_tick_now(&maker);
    let swap = maker.get_ln_swap(&swap_id).unwrap().unwrap();
    assert_eq!(
        swap.funding_height,
        Some(confirmed_at as u32),
        "recording the refund lost the recovered height"
    );
    let refund_txid = swap
        .refund_txid
        .expect("the watchdog never refunded once it could read the height");
    assert!(bitcoind.client.get_mempool_entry(&refund_txid).is_ok());
    framework.set_block_gen_paused(false);
}

/// The watchdog acts on a snapshot of each swap-out. Recovering a missing
/// funding height or recording a refund must not bring back a swap removed
/// since, nor overwrite a height another writer stored, nor refund on the
/// snapshot's account.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_stale_snapshot_keeps_newer_swap_out_state(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;
    pause_block_generation(&framework);

    let preimages = [
        Preimage([0x7e; 32]),
        Preimage([0x7f; 32]),
        Preimage([0x80; 32]),
    ];
    let ids: Vec<String> = preimages
        .iter()
        .map(|preimage| preimage.payment_hash().to_string())
        .collect();
    let fundings: Vec<LnHtlcFunded> = preimages
        .iter()
        .map(|preimage| {
            fund_swap_out(
                &maker,
                &ln,
                preimage.payment_hash(),
                Amount::from_sat(40_000),
                locktime,
            )
        })
        .collect();
    generate_blocks(bitcoind, 1);
    let confirmed_at = confirmation_height(bitcoind, &fundings[0].outpoint.txid);
    assert_eq!(
        confirmation_height(bitcoind, &fundings[1].outpoint.txid),
        confirmed_at
    );
    let mut snapshots: Vec<LnMakerSwap> = ids
        .iter()
        .map(|id| {
            drop_funding_height(&maker, id);
            maker.get_ln_swap(id).unwrap().unwrap()
        })
        .collect();

    // 0: removed since the snapshot.
    maker.remove_ln_swap(&ids[0]).unwrap();
    // 1: another writer stored a later height.
    let mut filled = snapshots[1].clone();
    filled.funding_height = Some(confirmed_at as u32 + 3);
    maker.store_ln_swap(&ids[1], filled).unwrap();
    // 2: removed since a snapshot that had its height, so the pass goes
    // straight to the refund.
    snapshots[2].funding_height = Some(confirmed_at as u32);
    maker.remove_ln_swap(&ids[2]).unwrap();

    // Past the CSV counted from the real confirmation, not from swap 1's
    // stored height: a pass that went on the snapshots would refund both.
    mine_to(bitcoind, confirmed_at + locktime as u64 + 1);
    for (id, snapshot) in ids.iter().zip(&snapshots) {
        watchdog_resolve_swap_out_snapshot(&maker, id, snapshot).unwrap();
    }

    let check = |swaps: &dyn Fn(&str) -> Option<LnMakerSwap>, when: &str| {
        for id in [&ids[0], &ids[2]] {
            assert!(
                swaps(id).is_none(),
                "{}: a removed swap was brought back",
                when
            );
        }
        let filled = swaps(&ids[1]).unwrap_or_else(|| panic!("{}: swap 1 was deleted", when));
        assert_eq!(filled.phase, LnMakerPhase::OutFunded, "{when}");
        assert_eq!(
            filled.funding_height,
            Some(confirmed_at as u32 + 3),
            "{when}: another writer's height was overwritten"
        );
        assert_eq!(
            filled.refund_txid, None,
            "{when}: refunded from a stale snapshot"
        );
    };
    check(&|id| maker.get_ln_swap(id).unwrap(), "in memory");

    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();
    let restarted = MakerServer::init(config).expect("maker restarts");
    let restored = restarted.ln_swaps.lock().unwrap().clone();
    check(&|id| restored.get(id).cloned(), "after a restart");

    framework.set_block_gen_paused(false);
    restarted.shutdown.store(true, Relaxed);
    restarted.watch_service.shutdown();
}

/// A swap-out stored without its funding height whose HTLC the taker has
/// claimed must not be refunded once the height is recovered, even while the
/// watcher has not seen the claim. Once it has, the claim's preimage settles
/// the held payment.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn lightning_maker_does_not_refund_a_claimed_swap_out_without_funding_height(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let locktime: u16 = 30;
    pause_block_generation(&framework);

    let preimage = Preimage([0x80; 32]);
    let swap_id = preimage.payment_hash().to_string();
    let funded = fund_swap_out(
        &maker,
        &ln,
        preimage.payment_hash(),
        Amount::from_sat(40_000),
        locktime,
    );
    drop_funding_height(&maker, &swap_id);
    generate_blocks(bitcoind, 1);
    let confirmed_at = confirmation_height(bitcoind, &funded.outpoint.txid);
    mine_to(bitcoind, confirmed_at + locktime as u64 + 1);

    // ---- The taker claims, and the watcher does not say so ----
    let hidden = Switch::on(&HIDE_HTLC_SPENDS);
    let swap = maker.get_ln_swap(&swap_id).unwrap().unwrap();
    let destination = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey();
    let claim = swap
        .htlc
        .create_hashlock_spend(
            funded.outpoint,
            funded.value,
            &SecretKey::from_slice(&[0x31; 32]).unwrap(),
            &preimage,
            destination,
            SPEND_FEE_RATE_FLOOR,
        )
        .unwrap();
    let claim_txid = bitcoind.client.send_raw_transaction(&claim).unwrap();
    generate_blocks(bitcoind, 1);
    assert!(confirmations(bitcoind, &claim_txid) >= 1);

    ln_watchdog_tick_now(&maker);
    let swap = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .expect("the swap stays open");
    assert_eq!(swap.phase, LnMakerPhase::OutFunded);
    assert_eq!(
        swap.refund_txid, None,
        "the maker refunded an HTLC the taker had claimed"
    );

    // ---- Once the watcher has the claim, the preimage settles the swap ----
    drop(hidden);
    wait_until!(
        Duration::from_secs(30),
        every Duration::from_millis(200),
        "the maker to settle from the taker's claim",
        {
            ln_watchdog_tick_now(&maker);
            maker.get_ln_swap(&swap_id).unwrap().is_none()
        }
    );
    let mut released = None;
    while let Some(event) = ln.poll_event().unwrap() {
        if let LnEvent::PaymentSuccessful {
            preimage: Some(preimage),
            ..
        } = event
        {
            released = Some(preimage);
        }
    }
    assert_eq!(released, Some(preimage));
    framework.set_block_gen_paused(false);
}

/// An unfunded swap-in as the maker stores it on acceptance.
fn accepted_swap_in(preimage: &Preimage) -> LnMakerSwap {
    accepted_swap_in_with_locktime(preimage, 144)
}

/// [`accepted_swap_in`] with a chosen refund locktime.
fn accepted_swap_in_with_locktime(preimage: &Preimage, locktime: u16) -> LnMakerSwap {
    let secp = Secp256k1::new();
    let hashlock_privkey = SecretKey::from_slice(&[0x41; 32]).unwrap();
    let hashlock_pubkey = PublicKey::new(hashlock_privkey.public_key(&secp));
    let timelock_pubkey = PublicKey::new(
        SecretKey::from_slice(&[0x42; 32])
            .unwrap()
            .public_key(&secp),
    );
    let payment_hash = preimage.payment_hash();
    LnMakerSwap {
        direction: LnDirection::SwapIn,
        phase: LnMakerPhase::InAccepted,
        payment_hash,
        amount: Amount::from_sat(40_000),
        fee: Amount::from_sat(500),
        locktime,
        min_confirmations: 1,
        htlc: SwapHtlc::new(&hashlock_pubkey, &timelock_pubkey, &payment_hash, locktime),
        privkey: hashlock_privkey,
        invoice: "lnbcrt-test".to_string(),
        preimage: None,
        refund_txid: None,
        refund_feerate: None,
        earlier_refund_txids: Vec::new(),
        sweep_feerate: None,
        accepted_height: None,
        payout_script: None,
        funding: None,
        funding_height: None,
        updated_at: Instant::now(),
    }
}

/// Whether the maker's mailbox for `payment_hash` is still open: an event
/// for it reaches the mailbox only if it is. The probe event is pushed
/// straight onto the node's queue, so the node records no payment for it.
fn mailbox_open(maker: &MakerServer, ln: &MockLightningBackend, preimage: &Preimage) -> bool {
    let payment_hash = preimage.payment_hash();
    ln.push_event(LnEvent::PaymentClaimable {
        payment_id: PaymentId(payment_hash.to_string()),
        payment_hash: Some(payment_hash),
        amount_msat: Some(40_000_000),
        claim_deadline: None,
    });
    let router = maker.ln_router.as_ref().unwrap();
    router.pump_once();
    matches!(
        router.take_event(&payment_hash),
        Some(LnEvent::PaymentClaimable { .. })
    )
}

/// A swap-in refusal is decided on a copy of the swap read before the
/// confirmation wait. If another connection paid the swap during that wait,
/// the refusal must keep the paid record, which holds the HTLC key, and the
/// mailbox the preimage arrives in. A swap still awaiting funding is
/// forgotten as before.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = Arc::new(MockLightningBackend::new())],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn stale_swap_in_refusal_keeps_paid_swap(world: &mut World, ln: Arc<MockLightningBackend>) {
    let maker = world.makers()[0].inner().clone();
    let router = maker.ln_router.clone().unwrap();

    // Both swaps are accepted, so both hold a record and a mailbox.
    let paid_preimage = Preimage([0x51; 32]);
    let paid_id = paid_preimage.payment_hash().to_string();
    let unfunded_preimage = Preimage([0x52; 32]);
    let unfunded_id = unfunded_preimage.payment_hash().to_string();
    for preimage in [&paid_preimage, &unfunded_preimage] {
        router.subscribe(preimage.payment_hash());
        maker
            .store_ln_swap(
                &preimage.payment_hash().to_string(),
                accepted_swap_in(preimage),
            )
            .unwrap();
    }

    // While the refusing handler waited, another connection funded and paid
    // the first swap.
    let mut paid = accepted_swap_in(&paid_preimage);
    let funding = (OutPoint::default(), Amount::from_sat(40_500));
    paid.phase = LnMakerPhase::InPaid;
    paid.funding = Some(funding);
    paid.funding_height = Some(101);
    maker.store_ln_swap(&paid_id, paid).unwrap();

    for swap_id in [&paid_id, &unfunded_id] {
        let reply = refuse_swap_in_after_wait(&maker, swap_id, "funding refused")
            .expect("the refusal still answers the taker");
        match expect_ln(reply) {
            LightningMakerMessage::Reject(reject) => assert_eq!(&reject.swap_id, swap_id),
            other => panic!("expected a Reject, got {}", other),
        }
    }

    let kept = maker
        .get_ln_swap(&paid_id)
        .unwrap()
        .expect("the stale refusal deleted a paid swap");
    assert_eq!(kept.phase, LnMakerPhase::InPaid);
    assert_eq!(kept.funding, Some(funding));
    assert!(
        mailbox_open(&maker, &ln, &paid_preimage),
        "the stale refusal closed the mailbox of a paid swap"
    );

    assert!(
        maker.get_ln_swap(&unfunded_id).unwrap().is_none(),
        "the refused unfunded swap still holds a maker swap slot"
    );
    assert!(
        !mailbox_open(&maker, &ln, &unfunded_preimage),
        "the refused unfunded swap kept its mailbox"
    );

    // Restart: only what reached the wallet store comes back.
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(router);
    drop(maker);
    world.drop_makers();

    let restarted = MakerServer::init(config).expect("maker restarts");
    let restored = restarted.ln_swaps.lock().unwrap().clone();
    let restored_paid = restored
        .get(&paid_id)
        .expect("the paid swap's durable record was lost");
    assert_eq!(restored_paid.phase, LnMakerPhase::InPaid);
    assert_eq!(restored_paid.funding, Some(funding));
    assert!(
        !restored.contains_key(&unfunded_id),
        "the refused unfunded swap came back after a restart"
    );

    restarted.shutdown.store(true, Relaxed);
    restarted.watch_service.shutdown();
}

/// Until the announced output is shown to pay the swap's HTLC, a funded
/// message could come from anyone who knows the swap id, such as the next
/// maker on a routed swap. A forged announcement must be rejected without
/// forgetting the swap, so the honest taker's funding can still complete it.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = Arc::new(MockLightningBackend::new())],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn forged_swap_in_funding_keeps_accepted_swap(world: &mut World, ln: Arc<MockLightningBackend>) {
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let router = maker.ln_router.clone().unwrap();

    let preimage = Preimage([0x71; 32]);
    let swap_id = preimage.payment_hash().to_string();
    router.subscribe(preimage.payment_hash());
    maker
        .store_ln_swap(&swap_id, accepted_swap_in(&preimage))
        .unwrap();

    // The forger's own confirmed transaction, which pays an address of its
    // own rather than the swap's HTLC.
    let forger_address = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    let forged_txid = send_to_address(bitcoind, &forger_address, Amount::from_sat(40_500));
    generate_blocks(bitcoind, 1);
    let forged_tx = bitcoind
        .client
        .get_raw_transaction(&forged_txid, None)
        .unwrap();
    let vout = forged_tx
        .output
        .iter()
        .position(|output| output.script_pubkey == forger_address.script_pubkey())
        .unwrap();
    let outpoint = OutPoint {
        txid: forged_txid,
        vout: vout as u32,
    };
    let value = forged_tx.output[vout].value;

    // A wrong value trips the value check, the right one the output check.
    for (announced, reason) in [
        (value + Amount::from_sat(1), "announced value mismatch"),
        (value, "bad funding output"),
    ] {
        let mut state = ConnectionState::default();
        handle_message(
            &maker,
            &mut state,
            TakerToMakerMessage::Hello(Hello::default()),
        )
        .unwrap();
        let reply = handle_message(
            &maker,
            &mut state,
            ln_message(LightningTakerMessage::SwapInFunded(LnHtlcFunded {
                swap_id: swap_id.clone(),
                outpoint,
                value: announced,
            })),
        )
        .unwrap();
        match expect_ln(reply) {
            LightningMakerMessage::Reject(reject) => {
                assert_eq!(reject.swap_id, swap_id);
                assert!(
                    reject.reason.starts_with(reason),
                    "expected a refusal for {reason}, got {}",
                    reject.reason
                );
            }
            other => panic!("expected a Reject, got {}", other),
        }
        let kept = maker
            .get_ln_swap(&swap_id)
            .unwrap()
            .unwrap_or_else(|| panic!("a forged announcement ({}) deleted the swap", reason));
        assert_eq!(kept.phase, LnMakerPhase::InAccepted);
        assert_eq!(kept.funding, None);
    }
    assert!(
        mailbox_open(&maker, &ln, &preimage),
        "a forged announcement closed the swap's mailbox"
    );
    assert_eq!(
        ln.last_pay_cltv_bound(),
        None,
        "the maker paid against a forged announcement"
    );

    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// The watchdog expires an unfunded swap-in from a snapshot taken before it
/// acts. If a handler paid the swap after that snapshot, the expiry must keep
/// the paid record and its mailbox. A swap still awaiting funding is
/// forgotten as before.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = Arc::new(MockLightningBackend::new())],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn stale_watchdog_expiry_keeps_paid_swap(world: &mut World, ln: Arc<MockLightningBackend>) {
    let maker = world.makers()[0].inner().clone();
    let router = maker.ln_router.clone().unwrap();

    // Accepted at height 0, so on a regtest chain past 100 blocks both are
    // long past their funding budget when the watchdog looks.
    let paid_preimage = Preimage([0x61; 32]);
    let paid_id = paid_preimage.payment_hash().to_string();
    let unfunded_preimage = Preimage([0x62; 32]);
    let unfunded_id = unfunded_preimage.payment_hash().to_string();
    let mut snapshots = Vec::new();
    for preimage in [&paid_preimage, &unfunded_preimage] {
        let mut accepted = accepted_swap_in(preimage);
        accepted.accepted_height = Some(0);
        router.subscribe(preimage.payment_hash());
        maker
            .store_ln_swap(&preimage.payment_hash().to_string(), accepted.clone())
            .unwrap();
        snapshots.push(accepted);
    }

    // After the watchdog's snapshot, a handler funded and paid the first swap.
    let mut paid = snapshots[0].clone();
    let funding = (OutPoint::default(), Amount::from_sat(40_500));
    paid.phase = LnMakerPhase::InPaid;
    paid.funding = Some(funding);
    paid.funding_height = Some(101);
    maker.store_ln_swap(&paid_id, paid).unwrap();

    watchdog_expire_swap_in_snapshot(&maker, &paid_id, &snapshots[0]).unwrap();
    watchdog_expire_swap_in_snapshot(&maker, &unfunded_id, &snapshots[1]).unwrap();

    let kept = maker
        .get_ln_swap(&paid_id)
        .unwrap()
        .expect("the stale watchdog expiry deleted a paid swap");
    assert_eq!(kept.phase, LnMakerPhase::InPaid);
    assert_eq!(kept.funding, Some(funding));
    assert!(
        mailbox_open(&maker, &ln, &paid_preimage),
        "the stale watchdog expiry closed the mailbox of a paid swap"
    );

    assert!(
        maker.get_ln_swap(&unfunded_id).unwrap().is_none(),
        "the watchdog kept an expired unfunded swap"
    );
    assert!(
        !mailbox_open(&maker, &ln, &unfunded_preimage),
        "the expired unfunded swap kept its mailbox"
    );

    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// The funded-message handler moves a swap-in to InPaid with
/// `store_ln_swap_if_phase`, from a copy read before its confirmation wait.
/// That store must refuse the copy once another connection has moved the
/// swap to InPaid, or once the swap is gone, and must store it while the
/// swap is still InAccepted. This covers the store itself, not whether the
/// handler calls it.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = Arc::new(MockLightningBackend::new())],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn conditional_paid_store_refuses_stale_copy(world: &mut World) {
    let maker = world.makers()[0].inner().clone();

    // The InPaid state a handler builds from its copy and its own funding.
    let paid = |accepted: &LnMakerSwap, funding: (OutPoint, Amount)| {
        let mut paid = accepted.clone();
        paid.phase = LnMakerPhase::InPaid;
        paid.funding = Some(funding);
        paid.funding_height = Some(101);
        paid
    };
    let first_funding = (OutPoint::default(), Amount::from_sat(40_500));
    let stale_funding = (
        OutPoint {
            vout: 1,
            ..OutPoint::default()
        },
        Amount::from_sat(40_500),
    );

    // Stale copy: another connection pays the swap after this copy was read.
    let stale_preimage = Preimage([0x71; 32]);
    let stale_id = stale_preimage.payment_hash().to_string();
    let stale_copy = accepted_swap_in(&stale_preimage);
    maker.store_ln_swap(&stale_id, stale_copy.clone()).unwrap();
    maker
        .store_ln_swap(&stale_id, paid(&stale_copy, first_funding))
        .unwrap();
    let stored = maker
        .store_ln_swap_if_phase(
            &stale_id,
            LnMakerPhase::InAccepted,
            paid(&stale_copy, stale_funding),
        )
        .unwrap();
    assert!(!stored, "a stale copy was stored over a paid swap");
    let live = maker.get_ln_swap(&stale_id).unwrap().unwrap();
    assert_eq!(live.phase, LnMakerPhase::InPaid);
    assert_eq!(
        live.funding,
        Some(first_funding),
        "a stale copy overwrote the paid swap"
    );

    // Removed swap: the copy outlives the swap it was read from.
    let removed_preimage = Preimage([0x72; 32]);
    let removed_id = removed_preimage.payment_hash().to_string();
    let removed_copy = accepted_swap_in(&removed_preimage);
    maker
        .store_ln_swap(&removed_id, removed_copy.clone())
        .unwrap();
    maker.remove_ln_swap(&removed_id).unwrap();
    let stored = maker
        .store_ln_swap_if_phase(
            &removed_id,
            LnMakerPhase::InAccepted,
            paid(&removed_copy, stale_funding),
        )
        .unwrap();
    assert!(!stored, "a stale copy recreated a removed swap");
    assert!(
        maker.get_ln_swap(&removed_id).unwrap().is_none(),
        "a stale copy recreated a removed swap in memory"
    );

    // Current copy: the swap is still InAccepted, so the move goes through.
    let current_preimage = Preimage([0x73; 32]);
    let current_id = current_preimage.payment_hash().to_string();
    let current_copy = accepted_swap_in(&current_preimage);
    maker
        .store_ln_swap(&current_id, current_copy.clone())
        .unwrap();
    let stored = maker
        .store_ln_swap_if_phase(
            &current_id,
            LnMakerPhase::InAccepted,
            paid(&current_copy, first_funding),
        )
        .unwrap();
    assert!(stored, "a current copy was refused");
    let live = maker.get_ln_swap(&current_id).unwrap().unwrap();
    assert_eq!(live.phase, LnMakerPhase::InPaid);
    assert_eq!(live.funding, Some(first_funding));

    // The wallet store is private to the crate, so check what reached disk by
    // restarting: init rebuilds the swaps from the stored records.
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();

    let restarted = MakerServer::init(config).expect("maker restarts");
    let restored = restarted.ln_swaps.lock().unwrap().clone();
    let restored_stale = restored
        .get(&stale_id)
        .expect("the paid swap's record was lost");
    assert_eq!(restored_stale.phase, LnMakerPhase::InPaid);
    assert_eq!(
        restored_stale.funding,
        Some(first_funding),
        "a stale copy overwrote the paid swap's record"
    );
    assert!(
        !restored.contains_key(&removed_id),
        "a stale copy recreated a removed swap's record"
    );
    let restored_current = restored
        .get(&current_id)
        .expect("the current copy's InPaid record was not saved");
    assert_eq!(restored_current.phase, LnMakerPhase::InPaid);
    assert_eq!(restored_current.funding, Some(first_funding));

    restarted.shutdown.store(true, Relaxed);
    restarted.watch_service.shutdown();
}

/// handle_swap_in_funded reads the swap, waits for the funding to confirm and
/// only then moves it to InPaid and pays. If another connection pays the swap
/// during that wait, the waiting handler must stop: it must neither overwrite
/// the paid record nor pay the invoice.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn swap_in_funded_handler_yields_to_swap_paid_during_wait(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    // The taker's node only issues the hold invoice. It shares no ledger with
    // the maker's node, so a payment attempt fails at once instead of
    // blocking the handler on a preimage that never comes.
    let taker_ln = MockLightningBackend::new();

    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();

    let amount = Amount::from_sat(40_000);
    let preimage = Preimage([0x81; 32]);
    let payment_hash = preimage.payment_hash();
    let swap_id = payment_hash.to_string();
    let invoice = taker_ln
        .create_hold_invoice(
            payment_hash,
            InvoiceParams {
                amount_msat: Some(amount.to_sat() * 1000),
                description: format!("swap-in {swap_id}"),
                expiry_secs: 3600,
            },
        )
        .unwrap();
    // Clear the invoice's CLTV window the way the taker does.
    let cltv_delta = verify_invoice(&invoice.invoice, &payment_hash, amount.to_sat() * 1000)
        .unwrap()
        .min_final_cltv_expiry_delta;
    let locktime = (cltv_delta + 48) as u16;
    let taker_timelock_pubkey = PublicKey::new(
        SecretKey::from_slice(&[0x82; 32])
            .unwrap()
            .public_key(&Secp256k1::new()),
    );

    let mut state = ConnectionState::default();
    handle_message(
        &maker,
        &mut state,
        TakerToMakerMessage::Hello(Hello::default()),
    )
    .unwrap();
    let accept = match expect_ln(
        handle_message(
            &maker,
            &mut state,
            ln_message(LightningTakerMessage::SwapInRequest(LnSwapInRequest {
                swap_id: swap_id.clone(),
                invoice: invoice.invoice,
                payment_hash,
                amount,
                locktime,
                min_confirmations: 1,
                taker_timelock_pubkey,
                features: vec!["ln-swap-in".to_string()],
            })),
        )
        .unwrap(),
    ) {
        LightningMakerMessage::SwapInAccept(accept) => accept,
        other => panic!("expected SwapInAccept, got {}", other),
    };

    // Fund the HTLC with no blocks coming, so the handler stays in its wait.
    framework.set_block_gen_paused(true);
    let htlc = SwapHtlc::new(
        &accept.maker_hashlock_pubkey,
        &taker_timelock_pubkey,
        &payment_hash,
        locktime,
    );
    let htlc_address = htlc.address(Network::Regtest).unwrap();
    let funding_txid = send_to_address(bitcoind, &htlc_address, amount + accept.fee);
    let funding_tx = bitcoind
        .client
        .get_raw_transaction(&funding_txid, None)
        .unwrap();
    let vout = funding_tx
        .output
        .iter()
        .position(|output| output.script_pubkey == htlc_address.script_pubkey())
        .unwrap();
    let outpoint = OutPoint {
        txid: funding_txid,
        vout: vout as u32,
    };
    let value = funding_tx.output[vout].value;

    // The funding message arrives on a second connection, whose handler
    // reads the swap and then blocks until the funding confirms.
    let log_path = framework.taker_log_path();
    let mark = log_mark(&log_path);
    let (result_tx, result_rx) = mpsc::channel();
    let handler_maker = maker.clone();
    let funded_id = swap_id.clone();
    thread::spawn(move || {
        let mut state = ConnectionState::default();
        let result = handle_message(
            &handler_maker,
            &mut state,
            TakerToMakerMessage::Hello(Hello::default()),
        )
        .and_then(|_| {
            handle_message(
                &handler_maker,
                &mut state,
                ln_message(LightningTakerMessage::SwapInFunded(LnHtlcFunded {
                    swap_id: funded_id,
                    outpoint,
                    value,
                })),
            )
        });
        let _ = result_tx.send(format!("{result:?}"));
    });

    // The confirmation wait logs its first sight of the funding, which comes
    // after the handler has read the swap. Wait for that line rather than for
    // a fixed time.
    let waiting = format!("Tx {funding_txid} seen in mempool");
    wait_until!(
        Duration::from_secs(60),
        every Duration::from_millis(200),
        "the handler to reach its confirmation wait",
        std::fs::read_to_string(&log_path)
            .unwrap_or_default()
            .get(mark as usize..)
            .is_some_and(|new| new.contains(&waiting))
    );

    // Meanwhile another connection funds and pays the swap.
    let mut paid = maker.get_ln_swap(&swap_id).unwrap().unwrap();
    assert_eq!(paid.phase, LnMakerPhase::InAccepted);
    let other_funding = (OutPoint::default(), value);
    paid.phase = LnMakerPhase::InPaid;
    paid.funding = Some(other_funding);
    paid.funding_height = Some(101);
    maker.store_ln_swap(&swap_id, paid).unwrap();

    // The funding confirms and the waiting handler resumes on its old copy.
    generate_blocks(bitcoind, 1);
    let result = result_rx
        .recv_timeout(Duration::from_secs(120))
        .expect("the handler did not return after the funding confirmed");
    assert!(
        result.starts_with("Err") && result.contains("swap-in no longer awaiting funding"),
        "the handler did not stop on its stale copy: {}",
        result
    );
    let kept = maker.get_ln_swap(&swap_id).unwrap().unwrap();
    assert_eq!(kept.phase, LnMakerPhase::InPaid);
    assert_eq!(
        kept.funding,
        Some(other_funding),
        "the handler overwrote the paid swap"
    );
    assert_eq!(
        ln.last_pay_cltv_bound(),
        None,
        "the handler paid a swap another connection had paid"
    );

    framework.set_block_gen_paused(false);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// Blocks past the taker's refund maturity before the maker drops a swap-in
/// it never settled. Mirrors the maker's `REFUND_GRACE_BLOCKS`.
const REFUND_GRACE_BLOCKS: u64 = 12;

/// Stops the framework's block generation and waits out a round that may
/// already be mining, so the heights a test reads stay put.
pub(super) fn pause_block_generation(framework: &TestFramework) {
    framework.set_block_gen_paused(true);
    let bitcoind = &framework.bitcoind;
    let mut height = bitcoind.client.get_block_count().unwrap();
    loop {
        thread::sleep(Duration::from_secs(1));
        let now = bitcoind.client.get_block_count().unwrap();
        if now == height {
            return;
        }
        height = now;
    }
}

/// Mines until the tip is exactly `height`.
fn mine_to(bitcoind: &BitcoinD, height: u64) {
    let tip = bitcoind.client.get_block_count().unwrap();
    assert!(tip <= height, "the chain is already past height {}", height);
    if tip < height {
        generate_blocks(bitcoind, height - tip);
    }
    assert_eq!(bitcoind.client.get_block_count().unwrap(), height);
}

/// Pays `swap`'s HTLC its amount plus fee from the node's wallet. The
/// funding is left unconfirmed.
fn fund_htlc(bitcoind: &BitcoinD, swap: &LnMakerSwap) -> OutPoint {
    let address = swap.htlc.address(Network::Regtest).unwrap();
    let txid = send_to_address(bitcoind, &address, swap.amount + swap.fee);
    let tx = bitcoind.client.get_raw_transaction(&txid, None).unwrap();
    let vout = tx
        .output
        .iter()
        .position(|output| output.script_pubkey == address.script_pubkey())
        .unwrap();
    OutPoint {
        txid,
        vout: vout as u32,
    }
}

/// Broadcasts the taker's refund of `swap`'s HTLC through the timelock
/// branch, signed with the taker's key. Valid once `swap.locktime` blocks
/// have passed since the funding confirmed.
fn broadcast_taker_refund(bitcoind: &BitcoinD, swap: &LnMakerSwap, funding: OutPoint) -> Txid {
    let timelock_privkey = SecretKey::from_slice(&[0x42; 32]).unwrap();
    let destination = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey();
    let refund = swap
        .htlc
        .create_timelock_spend(
            funding,
            swap.amount + swap.fee,
            &timelock_privkey,
            destination,
            SPEND_FEE_RATE_FLOOR,
        )
        .unwrap();
    bitcoind.client.send_raw_transaction(&refund).unwrap()
}

/// Height of the block that confirmed `txid`.
fn confirmation_height(bitcoind: &BitcoinD, txid: &Txid) -> u64 {
    let info = bitcoind
        .client
        .get_raw_transaction_info(txid, None)
        .unwrap();
    let hash = info.blockhash.expect("the funding is confirmed");
    bitcoind.client.get_block_header_info(&hash).unwrap().height as u64
}

/// `swap` moved to InPaid on `funding` with no `funding_height`: the record a
/// maker stored when its height lookup failed as it paid the swap.
fn paid_without_height(swap: &LnMakerSwap, funding: OutPoint) -> LnMakerSwap {
    let mut paid = swap.clone();
    paid.phase = LnMakerPhase::InPaid;
    paid.funding = Some((funding, swap.amount + swap.fee));
    paid.funding_height = None;
    paid
}

/// Has `ln` pay a hold invoice for `preimage`'s hash and fail it back, so the
/// node records a payment that can no longer settle. Returns the invoice,
/// for the swap that paid it. A standalone mock node plays both ends.
fn failed_payment_invoice(ln: &MockLightningBackend, preimage: &Preimage) -> String {
    let invoice = ln
        .create_hold_invoice(
            preimage.payment_hash(),
            InvoiceParams {
                amount_msat: Some(40_000_000),
                ..Default::default()
            },
        )
        .unwrap()
        .invoice;
    ln.pay_invoice(&invoice, None, Some(100)).unwrap();
    ln.fail_held_payment(preimage.payment_hash()).unwrap();
    assert_eq!(
        ln.payment_outcome(preimage.payment_hash()).unwrap(),
        PaymentOutcome::Failed
    );
    invoice
}

/// A swap-in whose height lookup failed as the maker paid it is stored as
/// InPaid with funding but no `funding_height`. If its payment failed, the
/// watchdog must still drop it once the taker's refund window has passed,
/// measured from the funding's confirmation, as it does any other swap-in
/// whose payment failed. Otherwise the record holds one of the maker's swap
/// slots for good.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = Arc::new(MockLightningBackend::new())],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn watchdog_releases_swap_in_missing_funding_height(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let router = maker.ln_router.clone().unwrap();
    pause_block_generation(&framework);

    // Three paid swap-ins on real HTLC funding, confirmed in one block, each
    // with a payment the node reports failed.
    // - `control` kept its funding height, as a healthy handler stores it.
    // - `missing` lost it.
    // - `longer` lost it too, but its longer locktime keeps it inside its
    //   refund window when the other two leave theirs.
    let preimages = [
        Preimage([0x91; 32]),
        Preimage([0x92; 32]),
        Preimage([0x93; 32]),
    ];
    let ids: Vec<String> = preimages
        .iter()
        .map(|preimage| preimage.payment_hash().to_string())
        .collect();
    let mut accepted = [
        accepted_swap_in_with_locktime(&preimages[0], 144),
        accepted_swap_in_with_locktime(&preimages[1], 144),
        accepted_swap_in_with_locktime(&preimages[2], 160),
    ];
    for (swap, preimage) in accepted.iter_mut().zip(&preimages) {
        swap.invoice = failed_payment_invoice(&ln, preimage);
    }
    let fundings: Vec<OutPoint> = accepted
        .iter()
        .map(|swap| fund_htlc(bitcoind, swap))
        .collect();
    generate_blocks(bitcoind, 1);
    let confirmed_at = confirmation_height(bitcoind, &fundings[0].txid);
    for funding in &fundings {
        assert_eq!(confirmation_height(bitcoind, &funding.txid), confirmed_at);
    }
    let mut control = paid_without_height(&accepted[0], fundings[0]);
    control.funding_height = Some(confirmed_at as u32);
    let stored = [
        control,
        paid_without_height(&accepted[1], fundings[1]),
        paid_without_height(&accepted[2], fundings[2]),
    ];
    for (id, swap) in ids.iter().zip(stored) {
        router.subscribe(swap.payment_hash);
        maker.store_ln_swap(id, swap).unwrap();
    }

    // Rule out the other reasons a swap could stay: every HTLC is unspent
    // and every payment failed.
    for (funding, preimage) in fundings.iter().zip(&preimages) {
        assert!(bitcoind
            .client
            .get_tx_out(&funding.txid, funding.vout, Some(true))
            .unwrap()
            .is_some());
        assert_eq!(
            ln.payment_outcome(preimage.payment_hash()).unwrap(),
            PaymentOutcome::Failed
        );
    }

    // At the last height inside the 144-block refund window plus grace,
    // every swap stays.
    let last_kept = confirmed_at + 144 + REFUND_GRACE_BLOCKS;
    mine_to(bitcoind, last_kept);
    ln_watchdog_tick_now(&maker);
    for id in &ids {
        assert!(
            maker.get_ln_swap(id).unwrap().is_some(),
            "the watchdog dropped swap {} inside its refund window",
            id
        );
    }

    // One block later the 144-block swaps are past it.
    mine_to(bitcoind, last_kept + 1);
    ln_watchdog_tick_now(&maker);
    assert!(
        maker.get_ln_swap(&ids[0]).unwrap().is_none(),
        "the watchdog kept an unsettled swap that has its funding height"
    );
    assert!(
        maker.get_ln_swap(&ids[1]).unwrap().is_none(),
        "the watchdog never released a swap missing its funding height"
    );
    let kept = maker
        .get_ln_swap(&ids[2])
        .unwrap()
        .expect("the watchdog dropped a swap still inside its refund window");
    assert_eq!(kept.phase, LnMakerPhase::InPaid);
    assert_eq!(
        kept.funding_height,
        Some(confirmed_at as u32),
        "the watchdog did not recover the funding's confirmation height"
    );
    assert_eq!(
        maker.ln_swap_count(),
        1,
        "the released swaps kept their slots"
    );
    assert!(!mailbox_open(&maker, &ln, &preimages[1]));
    assert!(mailbox_open(&maker, &ln, &preimages[2]));

    // Restart: the released swaps are gone from disk, and the recovered
    // height was saved.
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(router);
    drop(maker);
    world.drop_makers();
    let mut restarted = MakerServer::init(config).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);
    let restarted = Arc::new(restarted);
    let restored = restarted.ln_swaps.lock().unwrap().clone();
    assert!(
        !restored.contains_key(&ids[0]) && !restored.contains_key(&ids[1]),
        "a released swap came back after a restart"
    );
    assert_eq!(
        restored
            .get(&ids[2])
            .expect("the kept swap's record was lost")
            .funding_height,
        Some(confirmed_at as u32),
        "the recovered funding height was not saved"
    );

    // The restarted maker drops the longer swap once its own window passes.
    let last_kept = confirmed_at + 160 + REFUND_GRACE_BLOCKS;
    mine_to(bitcoind, last_kept);
    ln_watchdog_tick_now(&restarted);
    assert!(restarted.get_ln_swap(&ids[2]).unwrap().is_some());
    mine_to(bitcoind, last_kept + 1);
    ln_watchdog_tick_now(&restarted);
    assert!(
        restarted.get_ln_swap(&ids[2]).unwrap().is_none(),
        "the restarted watchdog kept a swap past its refund window"
    );
    assert_eq!(restarted.ln_swap_count(), 0);

    framework.set_block_gen_paused(false);
    restarted.shutdown.store(true, Relaxed);
    restarted.watch_service.shutdown();
}

/// The watchdog must not read a failed or empty height lookup as a sign that
/// the refund window has passed. A backend failure keeps the swap and its
/// mailbox, and so does a funding with no confirmation height. A later pass,
/// here after a restart, recovers the height and releases the swap.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = Arc::new(MockLightningBackend::new())],
    maker_behaviors = [FailFundingHeightLookup],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn watchdog_keeps_swap_in_while_funding_height_is_unknown(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    pause_block_generation(&framework);

    // A paid swap-in whose payment failed, on confirmed funding, stored
    // without a funding height, and already past its refund window.
    let preimage = Preimage([0xb1; 32]);
    let swap_id = preimage.payment_hash().to_string();
    let mut accepted = accepted_swap_in(&preimage);
    accepted.invoice = failed_payment_invoice(&ln, &preimage);
    let funding = fund_htlc(bitcoind, &accepted);
    generate_blocks(bitcoind, 1);
    let confirmed_at = confirmation_height(bitcoind, &funding.txid);
    maker
        .ln_router
        .as_ref()
        .unwrap()
        .subscribe(preimage.payment_hash());
    maker
        .store_ln_swap(&swap_id, paid_without_height(&accepted, funding))
        .unwrap();
    mine_to(bitcoind, confirmed_at + 144 + REFUND_GRACE_BLOCKS + 1);

    // The height lookup fails, so the watchdog cannot tell and keeps it.
    ln_watchdog_tick_now(&maker);
    let kept = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .expect("a failed height lookup dropped the swap");
    assert_eq!(kept.phase, LnMakerPhase::InPaid);
    assert_eq!(
        kept.funding,
        Some((funding, accepted.amount + accepted.fee))
    );
    assert_eq!(kept.funding_height, None);
    assert!(
        mailbox_open(&maker, &ln, &preimage),
        "a failed height lookup closed the swap's mailbox"
    );

    // Restart with a working backend, and add a swap whose funding has no
    // confirmation height: no node knows its transaction.
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();
    let mut restarted = MakerServer::init(config.clone()).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);
    let restarted = Arc::new(restarted);
    assert_eq!(
        restarted
            .get_ln_swap(&swap_id)
            .unwrap()
            .unwrap()
            .funding_height,
        None
    );
    let unknown_preimage = Preimage([0xb2; 32]);
    let unknown_id = unknown_preimage.payment_hash().to_string();
    restarted
        .ln_router
        .as_ref()
        .unwrap()
        .subscribe(unknown_preimage.payment_hash());
    restarted
        .store_ln_swap(
            &unknown_id,
            paid_without_height(&accepted_swap_in(&unknown_preimage), OutPoint::default()),
        )
        .unwrap();

    ln_watchdog_tick_now(&restarted);
    assert!(
        restarted.get_ln_swap(&swap_id).unwrap().is_none(),
        "the watchdog did not release the swap once it could read its funding height"
    );
    let unknown = restarted
        .get_ln_swap(&unknown_id)
        .unwrap()
        .expect("a funding with no confirmation height was taken as expired");
    assert_eq!(unknown.phase, LnMakerPhase::InPaid);
    assert_eq!(unknown.funding_height, None);
    assert!(mailbox_open(&restarted, &ln, &unknown_preimage));
    assert_eq!(restarted.ln_swap_count(), 1);

    // What reached disk matches.
    restarted.shutdown.store(true, Relaxed);
    restarted.watch_service.shutdown();
    drop(restarted);
    let reloaded = MakerServer::init(config).expect("maker restarts");
    let restored = reloaded.ln_swaps.lock().unwrap().clone();
    assert!(
        !restored.contains_key(&swap_id),
        "the released swap came back after a restart"
    );
    assert_eq!(
        restored
            .get(&unknown_id)
            .expect("the unconfirmed swap's record was lost")
            .funding_height,
        None
    );

    framework.set_block_gen_paused(false);
    reloaded.shutdown.store(true, Relaxed);
    reloaded.watch_service.shutdown();
}

/// The watchdog acts on a snapshot of each swap. If the stored swap has
/// changed since, recovering a missing funding height must not overwrite the
/// newer record or bring back a removed one. Dropping a swap past its refund
/// window must not delete one that has moved on either, such as a swap swept
/// with its preimage, whose record is what reaches the money.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = Arc::new(MockLightningBackend::new())],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn stale_watchdog_snapshot_keeps_newer_swap_in_state(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let router = maker.ln_router.clone().unwrap();
    pause_block_generation(&framework);

    // Five paid swap-ins on confirmed funding, each with a payment that
    // failed. Each snapshot is the swap as the watchdog read it; the live
    // record then changes under it.
    let preimages: Vec<Preimage> = (0xc1..=0xc5).map(|byte| Preimage([byte; 32])).collect();
    let ids: Vec<String> = preimages
        .iter()
        .map(|preimage| preimage.payment_hash().to_string())
        .collect();
    let accepted: Vec<LnMakerSwap> = preimages
        .iter()
        .map(|preimage| {
            let mut swap = accepted_swap_in(preimage);
            swap.invoice = failed_payment_invoice(&ln, preimage);
            swap
        })
        .collect();
    let fundings: Vec<OutPoint> = accepted
        .iter()
        .map(|swap| fund_htlc(bitcoind, swap))
        .collect();
    // A second funding of the fourth swap's HTLC, for the outpoint case.
    let other_funding = fund_htlc(bitcoind, &accepted[3]);
    generate_blocks(bitcoind, 1);
    let confirmed_at = confirmation_height(bitcoind, &fundings[0].txid);
    let value = accepted[0].amount + accepted[0].fee;

    let mut snapshots: Vec<LnMakerSwap> = accepted
        .iter()
        .zip(&fundings)
        .map(|(swap, funding)| paid_without_height(swap, *funding))
        .collect();
    // The last snapshot already has its height, so this pass would drop it.
    snapshots[4].funding_height = Some(confirmed_at as u32);
    for (id, snapshot) in ids.iter().zip(&snapshots) {
        router.subscribe(snapshot.payment_hash);
        maker.store_ln_swap(id, snapshot.clone()).unwrap();
    }

    let swept = |snapshot: &LnMakerSwap, preimage: &Preimage| {
        let mut swept = snapshot.clone();
        swept.phase = LnMakerPhase::InSwept;
        swept.preimage = Some(*preimage);
        swept
    };
    // 0: swept with the preimage since the snapshot.
    maker
        .store_ln_swap(&ids[0], swept(&snapshots[0], &preimages[0]))
        .unwrap();
    // 1: removed since the snapshot.
    maker.remove_ln_swap(&ids[1]).unwrap();
    // 2: another writer stored a different height.
    let mut filled = snapshots[2].clone();
    filled.funding_height = Some(confirmed_at as u32 + 3);
    maker.store_ln_swap(&ids[2], filled).unwrap();
    // 3: now funded at another outpoint.
    let mut refunded = snapshots[3].clone();
    refunded.funding = Some((other_funding, value));
    maker.store_ln_swap(&ids[3], refunded).unwrap();
    // 4: swept with the preimage since a snapshot that has its height.
    maker
        .store_ln_swap(&ids[4], swept(&snapshots[4], &preimages[4]))
        .unwrap();

    // Past the refund window of every snapshot, but not of swap 2's live
    // height: a pass that used the snapshots' state would drop them.
    mine_to(bitcoind, confirmed_at + 144 + REFUND_GRACE_BLOCKS + 1);
    for (id, snapshot) in ids.iter().zip(&snapshots) {
        watchdog_finish_swap_in_snapshot(&maker, id, snapshot).unwrap();
    }

    let check = |swaps: &dyn Fn(&str) -> Option<LnMakerSwap>, when: &str| {
        for i in [0, 4] {
            let swap =
                swaps(&ids[i]).unwrap_or_else(|| panic!("{}: a swept swap was deleted", when));
            assert_eq!(swap.phase, LnMakerPhase::InSwept, "{when}");
            assert_eq!(swap.preimage, Some(preimages[i]), "{when}: preimage lost");
            assert_eq!(swap.funding, Some((fundings[i], value)), "{when}");
        }
        assert_eq!(
            swaps(&ids[0]).unwrap().funding_height,
            None,
            "{when}: the swept record was overwritten"
        );
        assert!(
            swaps(&ids[1]).is_none(),
            "{}: a removed swap was brought back",
            when
        );
        let filled = swaps(&ids[2]).unwrap_or_else(|| panic!("{}: swap 2 was deleted", when));
        assert_eq!(filled.phase, LnMakerPhase::InPaid, "{when}");
        assert_eq!(
            filled.funding_height,
            Some(confirmed_at as u32 + 3),
            "{when}: another writer's height was overwritten"
        );
        let refunded = swaps(&ids[3]).unwrap_or_else(|| panic!("{}: swap 3 was deleted", when));
        assert_eq!(refunded.phase, LnMakerPhase::InPaid, "{when}");
        assert_eq!(refunded.funding, Some((other_funding, value)), "{when}");
        assert_eq!(
            refunded.funding_height, None,
            "{when}: a height was stored for an outpoint the swap no longer has"
        );
    };
    check(&|id| maker.get_ln_swap(id).unwrap(), "in memory");
    for i in [0, 2, 3, 4] {
        assert!(
            mailbox_open(&maker, &ln, &preimages[i]),
            "the stale pass closed swap {}'s mailbox",
            i
        );
    }

    // The wallet store is private to the crate, so check what reached disk by
    // restarting.
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(router);
    drop(maker);
    world.drop_makers();
    let restarted = MakerServer::init(config).expect("maker restarts");
    let restored = restarted.ln_swaps.lock().unwrap().clone();
    check(&|id| restored.get(id).cloned(), "after a restart");

    framework.set_block_gen_paused(false);
    restarted.shutdown.store(true, Relaxed);
    restarted.watch_service.shutdown();
}

/// The fee the mempool's spend of `funding` pays out of `value`.
fn mempool_spend_fee(bitcoind: &BitcoinD, funding: OutPoint, value: Amount) -> Amount {
    let spend = bitcoind
        .client
        .get_raw_mempool()
        .unwrap()
        .into_iter()
        .map(|txid| bitcoind.client.get_raw_transaction(&txid, None).unwrap())
        .find(|tx| {
            tx.input
                .iter()
                .any(|input| input.previous_output == funding)
        })
        .expect("the HTLC has a spend in the mempool");
    value
        - spend
            .output
            .iter()
            .map(|output| output.value)
            .sum::<Amount>()
}

/// The swap-in sweep pays the market rate. While it is pending and nothing
/// spends its output, the watchdog bumps it once the market rises by the
/// replacement step, and resends it unchanged otherwise. A second sweep
/// from the paid phase sends nothing.
#[world_test(
    backend = BitcoindBackend,
    bind = [pair = MockLightningBackend::new_pair(), ln = pair.0.clone(), payee_ln = pair.1.clone()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn swap_in_sweep_is_bumped_once_the_market_rises(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
    payee_ln: Arc<MockLightningBackend>,
) {
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let router = maker.ln_router.clone().unwrap();
    pause_block_generation(&framework);
    let market = SpendFeerate::set(5.0);

    let preimage = Preimage([0xb1; 32]);
    let id = preimage.payment_hash().to_string();
    let mut swap = accepted_swap_in(&preimage);
    swap.invoice = payee_ln
        .create_hold_invoice(
            preimage.payment_hash(),
            InvoiceParams {
                amount_msat: Some(swap.amount.to_sat() * 1000),
                ..Default::default()
            },
        )
        .unwrap()
        .invoice;
    let funding = fund_htlc(bitcoind, &swap);
    generate_blocks(bitcoind, 1);
    let mut paid = paid_without_height(&swap, funding);
    paid.funding_height = Some(confirmation_height(bitcoind, &funding.txid) as u32);
    router.subscribe(paid.payment_hash);
    maker.store_ln_swap(&id, paid.clone()).unwrap();
    ln.pay_invoice(&swap.invoice, None, Some(100)).unwrap();
    payee_ln.claim_held_payment(&preimage).unwrap();

    ln_watchdog_tick_now(&maker);
    let value = swap.amount + swap.fee;
    assert_eq!(
        maker.get_ln_swap(&id).unwrap().unwrap().phase,
        LnMakerPhase::InSwept
    );
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        Amount::from_sat(750),
        "the sweep must pay the market rate, 5 sat/vB for 150 vB"
    );

    market.set_rate(20.0);
    ln_watchdog_tick_now(&maker);
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        Amount::from_sat(3_000),
        "the watchdog must bump a pending sweep to the new rate, 20 sat/vB"
    );
    assert_eq!(
        maker.get_ln_swap(&id).unwrap().unwrap().sweep_feerate,
        Some(20.0),
        "the bump's rate must be recorded"
    );
    // At that rate, the next pass resends the bump unchanged.
    ln_watchdog_tick_now(&maker);
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        Amount::from_sat(3_000)
    );

    // The inline handler and the watchdog both sweep from the paid phase.
    // Whichever comes second, here on the paid snapshot, must not send a
    // sweep of its own.
    watchdog_finish_swap_in_snapshot(&maker, &id, &paid).unwrap();
    assert_eq!(
        mempool_spend_fee(bitcoind, funding, value),
        Amount::from_sat(3_000),
        "a second sweep from the paid phase must not replace the first"
    );

    framework.set_block_gen_paused(false);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// A swap-in's payment can still be in flight after the taker's refund
/// window. An HTLC that outlives its expiry is resolved on-chain, and the
/// payee can claim it with the preimage until that resolution confirms.
/// While the node reports the payment pending, the watchdog must keep the
/// swap, whose record holds the key that sweeps the HTLC with that preimage.
#[world_test(
    backend = BitcoindBackend,
    bind = [pair = MockLightningBackend::new_pair(), ln = pair.0.clone(), payee_ln = pair.1.clone()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn watchdog_keeps_swap_in_while_payment_is_in_flight(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
    payee_ln: Arc<MockLightningBackend>,
) {
    // The payee shares the maker node's ledger, so the maker's payments reach
    // it and stay held until it claims or fails them.
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let router = maker.ln_router.clone().unwrap();
    pause_block_generation(&framework);

    // Two paid swap-ins on HTLCs confirmed in one block, each stored with its
    // funding height, and each paid to a hold invoice of the payee's.
    // - `held` stays in flight.
    // - `failed` is failed back by the payee, so it can no longer settle.
    let preimages = [Preimage([0xa1; 32]), Preimage([0xa2; 32])];
    let ids: Vec<String> = preimages
        .iter()
        .map(|preimage| preimage.payment_hash().to_string())
        .collect();
    let accepted: Vec<LnMakerSwap> = preimages
        .iter()
        .map(|preimage| {
            let mut swap = accepted_swap_in(preimage);
            swap.invoice = payee_ln
                .create_hold_invoice(
                    preimage.payment_hash(),
                    InvoiceParams {
                        amount_msat: Some(swap.amount.to_sat() * 1000),
                        ..Default::default()
                    },
                )
                .unwrap()
                .invoice;
            swap
        })
        .collect();
    let fundings: Vec<OutPoint> = accepted
        .iter()
        .map(|swap| fund_htlc(bitcoind, swap))
        .collect();
    generate_blocks(bitcoind, 1);
    let confirmed_at = confirmation_height(bitcoind, &fundings[0].txid);
    assert_eq!(
        confirmation_height(bitcoind, &fundings[1].txid),
        confirmed_at
    );
    for ((id, swap), funding) in ids.iter().zip(&accepted).zip(&fundings) {
        let mut paid = paid_without_height(swap, *funding);
        paid.funding_height = Some(confirmed_at as u32);
        router.subscribe(paid.payment_hash);
        maker.store_ln_swap(id, paid).unwrap();
        ln.pay_invoice(&swap.invoice, None, Some(100)).unwrap();
    }
    payee_ln
        .fail_held_payment(preimages[1].payment_hash())
        .unwrap();

    // Past the 144-block refund window plus grace, the swap whose payment
    // failed goes. The one in flight stays, however long it is held.
    let past_window = confirmed_at + 144 + REFUND_GRACE_BLOCKS + 1;
    for height in [past_window, past_window + 24] {
        mine_to(bitcoind, height);
        ln_watchdog_tick_now(&maker);
        assert!(
            maker.get_ln_swap(&ids[1]).unwrap().is_none(),
            "the watchdog kept a swap whose payment failed"
        );
        let kept = maker
            .get_ln_swap(&ids[0])
            .unwrap()
            .expect("the watchdog dropped a swap whose payment is still in flight");
        assert_eq!(kept.phase, LnMakerPhase::InPaid);
        assert_eq!(
            kept.funding.map(|(outpoint, _)| outpoint),
            Some(fundings[0])
        );
    }
    assert_eq!(maker.ln_swap_count(), 1);

    // The payee claims at last. The kept record sweeps the HTLC.
    payee_ln.claim_held_payment(&preimages[0]).unwrap();
    ln_watchdog_tick_now(&maker);
    let swept = maker
        .get_ln_swap(&ids[0])
        .unwrap()
        .expect("the settled swap was dropped");
    assert_eq!(swept.phase, LnMakerPhase::InSwept);
    assert_eq!(swept.preimage, Some(preimages[0]));
    assert!(
        bitcoind
            .client
            .get_tx_out(&fundings[0].txid, fundings[0].vout, Some(true))
            .unwrap()
            .is_none(),
        "the sweep did not reach the mempool"
    );

    framework.set_block_gen_paused(false);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// A swap-in stored without its funding height is released or settled by
/// what the node reports for its payment, across a restart. Once the refund
/// window has passed, a failed payment releases the swap and one in flight
/// keeps it. A payment that settles while the maker is down, its event lost,
/// is found in the node's payment store, and the restarted maker sweeps.
#[world_test(
    backend = BitcoindBackend,
    bind = [pair = MockLightningBackend::new_pair(), ln = pair.0.clone(), payee_ln = pair.1.clone()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn restarted_watchdog_follows_payment_of_swap_in_missing_funding_height(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
    payee_ln: Arc<MockLightningBackend>,
) {
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let router = maker.ln_router.clone().unwrap();
    pause_block_generation(&framework);

    // Three swap-ins on HTLCs confirmed in one block, each stored without
    // its funding height and paid to a hold invoice of the payee's.
    // - `settled` is claimed while the maker is down.
    // - `failed` is failed back before its window passes.
    // - `held` stays in flight until after the restart.
    let preimages = [
        Preimage([0xb1; 32]),
        Preimage([0xb2; 32]),
        Preimage([0xb3; 32]),
    ];
    let ids: Vec<String> = preimages
        .iter()
        .map(|preimage| preimage.payment_hash().to_string())
        .collect();
    let accepted: Vec<LnMakerSwap> = preimages
        .iter()
        .map(|preimage| {
            let mut swap = accepted_swap_in(preimage);
            swap.invoice = payee_ln
                .create_hold_invoice(
                    preimage.payment_hash(),
                    InvoiceParams {
                        amount_msat: Some(swap.amount.to_sat() * 1000),
                        ..Default::default()
                    },
                )
                .unwrap()
                .invoice;
            swap
        })
        .collect();
    let fundings: Vec<OutPoint> = accepted
        .iter()
        .map(|swap| fund_htlc(bitcoind, swap))
        .collect();
    generate_blocks(bitcoind, 1);
    let confirmed_at = confirmation_height(bitcoind, &fundings[0].txid);
    for funding in &fundings {
        assert_eq!(confirmation_height(bitcoind, &funding.txid), confirmed_at);
    }
    for ((id, swap), funding) in ids.iter().zip(&accepted).zip(&fundings) {
        router.subscribe(swap.payment_hash);
        maker
            .store_ln_swap(id, paid_without_height(swap, *funding))
            .unwrap();
        ln.pay_invoice(&swap.invoice, None, Some(100)).unwrap();
    }
    payee_ln
        .fail_held_payment(preimages[1].payment_hash())
        .unwrap();
    let outcome = |i: usize| ln.payment_outcome(preimages[i].payment_hash()).unwrap();
    assert_eq!(outcome(0), PaymentOutcome::Pending);
    assert_eq!(outcome(1), PaymentOutcome::Failed);
    assert_eq!(outcome(2), PaymentOutcome::Pending);

    // Past the 144-block refund window plus grace, the failed swap goes. The
    // two in flight stay, with the height recovered from the chain.
    let past_window = confirmed_at + 144 + REFUND_GRACE_BLOCKS + 1;
    mine_to(bitcoind, past_window);
    ln_watchdog_tick_now(&maker);
    assert!(
        maker.get_ln_swap(&ids[1]).unwrap().is_none(),
        "the watchdog kept a swap whose payment failed"
    );
    for i in [0, 2] {
        let kept = maker.get_ln_swap(&ids[i]).unwrap().unwrap_or_else(|| {
            panic!(
                "the watchdog dropped swap {} while its payment is in flight",
                i
            )
        });
        assert_eq!(kept.phase, LnMakerPhase::InPaid);
        assert_eq!(
            kept.funding_height,
            Some(confirmed_at as u32),
            "the watchdog did not recover swap {}'s funding height",
            i
        );
    }

    // The maker goes down. Meanwhile the payee claims `settled`, and the
    // event carrying the preimage is lost, as it is to a maker that is not
    // connected to its node.
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(router);
    drop(maker);
    world.drop_makers();
    payee_ln.claim_held_payment(&preimages[0]).unwrap();
    while ln.poll_event().unwrap().is_some() {}
    assert_eq!(outcome(0), PaymentOutcome::Settled(preimages[0]));
    let mut restarted = MakerServer::init(config).expect("maker restarts");
    restarted.set_lightning_backend(ln.clone() as Arc<dyn LightningBackend>);
    let restarted = Arc::new(restarted);

    // The restarted maker sweeps `settled` with the preimage from the node's
    // payment store, and keeps `held`.
    mine_to(bitcoind, past_window + 24);
    ln_watchdog_tick_now(&restarted);
    let swept = restarted
        .get_ln_swap(&ids[0])
        .unwrap()
        .expect("the restarted watchdog dropped a settled swap");
    assert_eq!(swept.phase, LnMakerPhase::InSwept);
    assert_eq!(swept.preimage, Some(preimages[0]));
    assert!(
        bitcoind
            .client
            .get_tx_out(&fundings[0].txid, fundings[0].vout, Some(true))
            .unwrap()
            .is_none(),
        "the sweep did not reach the mempool"
    );
    let kept = restarted
        .get_ln_swap(&ids[2])
        .unwrap()
        .expect("the restarted watchdog dropped a swap whose payment is still in flight");
    assert_eq!(kept.phase, LnMakerPhase::InPaid);
    assert!(
        restarted.get_ln_swap(&ids[1]).unwrap().is_none(),
        "a released swap came back after a restart"
    );

    // Once `held` fails, it goes too.
    payee_ln
        .fail_held_payment(preimages[2].payment_hash())
        .unwrap();
    assert_eq!(outcome(2), PaymentOutcome::Failed);
    ln_watchdog_tick_now(&restarted);
    assert!(
        restarted.get_ln_swap(&ids[2]).unwrap().is_none(),
        "the restarted watchdog kept a swap whose payment failed"
    );
    assert_eq!(restarted.ln_swap_count(), 1);

    framework.set_block_gen_paused(false);
    restarted.shutdown.store(true, Relaxed);
    restarted.watch_service.shutdown();
}

/// A node can lose the record of a payment it has already sent: ldk-node
/// records a payment only after LDK has taken it on. So past the refund
/// window, a swap-in whose payment the node has no record of, or still
/// reports pending, must stay: the payment can still settle, and only this
/// record holds the key that sweeps the HTLC with its preimage. The swap goes
/// once the taker's refund confirms, which leaves that key nothing to reach.
#[world_test(
    backend = BitcoindBackend,
    bind = [pair = MockLightningBackend::new_pair(), ln = pair.0.clone(), payee_ln = pair.1.clone()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn watchdog_keeps_swap_in_without_payment_record_until_refunded(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
    payee_ln: Arc<MockLightningBackend>,
) {
    // The payee shares the maker node's ledger, so the maker's payments reach
    // it and stay held until it claims them.
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    let router = maker.ln_router.clone().unwrap();
    pause_block_generation(&framework);

    // Three swap-ins on HTLCs confirmed in one block, with a hold invoice of
    // the payee's.
    // - `lost` is paid, and the maker's node then loses the payment's record.
    // - `unpaid` is never paid, as when the maker stopped before paying, and
    //   is stored without its funding height.
    // - `held` is paid and held by the payee.
    let preimages = [
        Preimage([0xe1; 32]),
        Preimage([0xe2; 32]),
        Preimage([0xe3; 32]),
    ];
    let ids: Vec<String> = preimages
        .iter()
        .map(|preimage| preimage.payment_hash().to_string())
        .collect();
    let accepted: Vec<LnMakerSwap> = preimages
        .iter()
        .map(|preimage| {
            let mut swap = accepted_swap_in(preimage);
            swap.invoice = payee_ln
                .create_hold_invoice(
                    preimage.payment_hash(),
                    InvoiceParams {
                        amount_msat: Some(swap.amount.to_sat() * 1000),
                        ..Default::default()
                    },
                )
                .unwrap()
                .invoice;
            swap
        })
        .collect();
    let fundings: Vec<OutPoint> = accepted
        .iter()
        .map(|swap| fund_htlc(bitcoind, swap))
        .collect();
    generate_blocks(bitcoind, 1);
    let confirmed_at = confirmation_height(bitcoind, &fundings[0].txid);
    for funding in &fundings {
        assert_eq!(confirmation_height(bitcoind, &funding.txid), confirmed_at);
    }
    for (i, ((id, swap), funding)) in ids.iter().zip(&accepted).zip(&fundings).enumerate() {
        let mut paid = paid_without_height(swap, *funding);
        if i != 1 {
            paid.funding_height = Some(confirmed_at as u32);
        }
        router.subscribe(paid.payment_hash);
        maker.store_ln_swap(id, paid).unwrap();
    }
    for i in [0, 2] {
        ln.pay_invoice(&accepted[i].invoice, None, Some(100))
            .unwrap();
    }
    ln.lose_payment_record(preimages[0].payment_hash());
    let outcome = |i: usize| ln.payment_outcome(preimages[i].payment_hash()).unwrap();
    assert_eq!(outcome(0), PaymentOutcome::NotFound);
    assert_eq!(outcome(1), PaymentOutcome::NotFound);
    assert_eq!(outcome(2), PaymentOutcome::Pending);

    // Past the 144-block refund window plus grace, and long after, all stay.
    let past_window = confirmed_at + 144 + REFUND_GRACE_BLOCKS + 1;
    for height in [past_window, past_window + 24] {
        mine_to(bitcoind, height);
        ln_watchdog_tick_now(&maker);
        for (i, id) in ids.iter().enumerate() {
            let kept = maker.get_ln_swap(id).unwrap().unwrap_or_else(|| {
                panic!(
                    "the watchdog dropped swap {} while its payment could still settle",
                    i
                )
            });
            assert_eq!(kept.phase, LnMakerPhase::InPaid);
            assert_eq!(
                kept.funding_height,
                Some(confirmed_at as u32),
                "the watchdog did not recover swap {}'s funding height",
                i
            );
        }
    }

    // The taker refunds `unpaid` and `held`. A refund in the mempool can
    // still be evicted, so both stay until it confirms.
    let refunds: Vec<Txid> = [1, 2]
        .iter()
        .map(|&i| broadcast_taker_refund(bitcoind, &accepted[i], fundings[i]))
        .collect();
    ln_watchdog_tick_now(&maker);
    for i in [1, 2] {
        assert!(
            maker.get_ln_swap(&ids[i]).unwrap().is_some(),
            "the watchdog dropped swap {} on a refund still in the mempool",
            i
        );
    }
    generate_blocks(bitcoind, 1);
    for refund in &refunds {
        assert!(bitcoind
            .client
            .get_raw_transaction_info(refund, None)
            .unwrap()
            .blockhash
            .is_some());
    }
    ln_watchdog_tick_now(&maker);
    for i in [1, 2] {
        assert!(
            maker.get_ln_swap(&ids[i]).unwrap().is_none(),
            "the watchdog kept swap {} after the taker's refund confirmed",
            i
        );
    }
    assert!(!mailbox_open(&maker, &ln, &preimages[1]));
    assert_eq!(maker.ln_swap_count(), 1);

    // The payee claims the payment whose record was lost. The node still
    // has no record of it, but the settlement event carries the preimage,
    // and the kept record sweeps the HTLC with it.
    payee_ln.claim_held_payment(&preimages[0]).unwrap();
    assert_eq!(outcome(0), PaymentOutcome::NotFound);
    router.pump_once();
    ln_watchdog_tick_now(&maker);
    let swept = maker
        .get_ln_swap(&ids[0])
        .unwrap()
        .expect("the watchdog dropped the swap whose payment record was lost");
    assert_eq!(swept.phase, LnMakerPhase::InSwept);
    assert_eq!(swept.preimage, Some(preimages[0]));
    assert!(
        bitcoind
            .client
            .get_tx_out(&fundings[0].txid, fundings[0].vout, Some(true))
            .unwrap()
            .is_none(),
        "the sweep did not reach the mempool"
    );

    framework.set_block_gen_paused(false);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// Has `maker` accept a 40k-sat swap-in for `preimage`'s payment hash. The
/// hold invoice comes from `taker_ln`, which shares no ledger with the
/// maker's node, so the maker's payment attempt fails at once.
fn accept_swap_in(maker: &Arc<MakerServer>, taker_ln: &MockLightningBackend, preimage: &Preimage) {
    match request_swap_in(maker, taker_ln, preimage) {
        LightningMakerMessage::SwapInAccept(_) => {}
        other => panic!("expected SwapInAccept, got {}", other),
    }
}

/// Asks `maker` for a 40k-sat swap-in for `preimage`'s payment hash, with a
/// hold invoice from `taker_ln`, and returns the maker's reply.
fn request_swap_in(
    maker: &Arc<MakerServer>,
    taker_ln: &MockLightningBackend,
    preimage: &Preimage,
) -> LightningMakerMessage {
    expect_ln(send_swap_in_request(maker, swap_in_request(taker_ln, preimage)).unwrap())
}

/// A valid request for a 40k-sat swap-in on `preimage`'s payment hash, with
/// a hold invoice from `taker_ln` and 48 blocks of locktime to spare.
fn swap_in_request(taker_ln: &MockLightningBackend, preimage: &Preimage) -> LnSwapInRequest {
    let amount = Amount::from_sat(40_000);
    let payment_hash = preimage.payment_hash();
    let swap_id = payment_hash.to_string();
    let invoice = taker_ln
        .create_hold_invoice(
            payment_hash,
            InvoiceParams {
                amount_msat: Some(amount.to_sat() * 1000),
                description: format!("swap-in {swap_id}"),
                expiry_secs: 3600,
            },
        )
        .unwrap();
    let cltv_delta = verify_invoice(&invoice.invoice, &payment_hash, amount.to_sat() * 1000)
        .unwrap()
        .min_final_cltv_expiry_delta;
    LnSwapInRequest {
        swap_id,
        invoice: invoice.invoice,
        payment_hash,
        amount,
        locktime: (cltv_delta + 48) as u16,
        min_confirmations: 1,
        taker_timelock_pubkey: PublicKey::new(
            SecretKey::from_slice(&[0x82; 32])
                .unwrap()
                .public_key(&Secp256k1::new()),
        ),
        features: vec!["ln-swap-in".to_string()],
    }
}

/// Sends `req` to `maker` on a fresh connection and returns the handler's
/// result.
fn send_swap_in_request(
    maker: &Arc<MakerServer>,
    req: LnSwapInRequest,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    let mut state = ConnectionState::default();
    handle_message(
        maker,
        &mut state,
        TakerToMakerMessage::Hello(Hello::default()),
    )
    .unwrap();
    handle_message(
        maker,
        &mut state,
        ln_message(LightningTakerMessage::SwapInRequest(req)),
    )
}

/// Sends `SwapInFunded` on a fresh connection and returns the handler's
/// result, formatted.
fn announce_funding(
    maker: &Arc<MakerServer>,
    swap_id: &str,
    funding: OutPoint,
    value: Amount,
) -> String {
    let mut state = ConnectionState::default();
    let result = handle_message(
        maker,
        &mut state,
        TakerToMakerMessage::Hello(Hello::default()),
    )
    .and_then(|_| {
        handle_message(
            maker,
            &mut state,
            ln_message(LightningTakerMessage::SwapInFunded(LnHtlcFunded {
                swap_id: swap_id.to_string(),
                outpoint: funding,
                value,
            })),
        )
    });
    format!("{result:?}")
}

/// The taker's CSV refund window starts at the block that confirmed its
/// funding, so that block, not the tip when the handler runs, is what
/// handle_swap_in_funded must record as the funding height.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn swap_in_funded_handler_records_confirmation_height(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let taker_ln = MockLightningBackend::new();
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    pause_block_generation(&framework);

    let preimage = Preimage([0xd1; 32]);
    let swap_id = preimage.payment_hash().to_string();
    accept_swap_in(&maker, &taker_ln, &preimage);
    let accepted = maker.get_ln_swap(&swap_id).unwrap().unwrap();
    let value = accepted.amount + accepted.fee;
    let funding = fund_htlc(bitcoind, &accepted);
    generate_blocks(bitcoind, 1);
    let confirmed_at = confirmation_height(bitcoind, &funding.txid);
    // The taker announces two blocks after its funding confirmed.
    mine_to(bitcoind, confirmed_at + 2);

    let result = announce_funding(&maker, &swap_id, funding, value);
    assert!(
        result.starts_with("Err") && result.contains("pay_invoice failed"),
        "the handler did not reach the payment: {}",
        result
    );
    assert!(
        ln.last_pay_cltv_bound().is_some(),
        "the handler never tried to pay"
    );
    let paid = maker.get_ln_swap(&swap_id).unwrap().unwrap();
    assert_eq!(paid.phase, LnMakerPhase::InPaid);
    assert_eq!(paid.funding, Some((funding, value)));
    assert_eq!(
        paid.funding_height,
        Some(confirmed_at as u32),
        "the handler did not record the funding's confirmation height"
    );

    framework.set_block_gen_paused(false);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// Announces a confirmed funding to a maker whose height lookup `behavior`
/// breaks, and checks that the handler stopped with `expected_error` before
/// paying, leaving the swap as it was.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [behavior],
    takers = [Normal],
    maker_lightning = [ln.clone()],
    cases = [
        /// If the funding's confirmation height cannot be read,
        /// handle_swap_in_funded must stop before the swap moves to InPaid. It
        /// must not pay, and the swap must stay InAccepted, unfunded and with
        /// its mailbox, so the unfunded expiry can still free it.
        swap_in_funded_handler_stops_without_funding_height(
            behavior = MakerBehavior::FailFundingHeightLookup,
            expected_error = "funding height lookup failed",
            preimage = Preimage([0xd2; 32]),
        ),
        /// The handler waits for the funding to confirm, but the block can be
        /// reorged away before it reads the height. A lookup that answers with
        /// no height must stop the handler just as a failed one does.
        swap_in_funded_handler_stops_when_funding_has_no_height(
            behavior = MakerBehavior::NoFundingHeight,
            expected_error = "swap-in funding has no confirmation height",
            preimage = Preimage([0xd3; 32]),
        ),
    ],
)]
fn handler_stops_without_funding_height(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
    expected_error: &str,
    preimage: Preimage,
) {
    let taker_ln = MockLightningBackend::new();
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let maker = world.makers()[0].inner().clone();
    pause_block_generation(&framework);

    let swap_id = preimage.payment_hash().to_string();
    accept_swap_in(&maker, &taker_ln, &preimage);
    let accepted = maker.get_ln_swap(&swap_id).unwrap().unwrap();
    let value = accepted.amount + accepted.fee;
    let funding = fund_htlc(bitcoind, &accepted);
    generate_blocks(bitcoind, 1);

    let result = announce_funding(&maker, &swap_id, funding, value);
    assert!(
        result.starts_with("Err") && result.contains(expected_error),
        "the handler did not stop without a funding height: {}",
        result
    );
    assert_eq!(
        ln.last_pay_cltv_bound(),
        None,
        "the handler paid without a funding height"
    );
    let kept = maker
        .get_ln_swap(&swap_id)
        .unwrap()
        .expect("the handler deleted the swap");
    assert_eq!(kept.phase, LnMakerPhase::InAccepted);
    assert_eq!(kept.funding, None);
    assert_eq!(kept.funding_height, None);
    assert!(mailbox_open(&maker, &ln, &preimage));

    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    drop(maker);
    world.drop_makers();
    let restarted = MakerServer::init(config).expect("maker restarts");
    let restored = restarted
        .get_ln_swap(&swap_id)
        .unwrap()
        .expect("the swap's record was lost");
    assert_eq!(restored.phase, LnMakerPhase::InAccepted);
    assert_eq!(restored.funding, None);

    framework.set_block_gen_paused(false);
    restarted.shutdown.store(true, Relaxed);
    restarted.watch_service.shutdown();
}

/// The maker's node keeps a payment's record under its hash after the swap
/// that made it is gone, and ldk-node will not pay that hash again. So a
/// swap-in on a hash the node already has a record of must be refused before
/// anything is stored. Otherwise the old record's preimage reads as the new
/// swap's settlement, and the maker sweeps the taker's HTLC without paying.
#[world_test(
    backend = BitcoindBackend,
    bind = [pair = maker_node_pair(), ln = pair.0.clone(), payee_ln = pair.1.clone()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn swap_in_request_refuses_payment_hash_already_on_record(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
    payee_ln: Arc<MockLightningBackend>,
) {
    // The payee shares the maker node's ledger, so the maker can pay it.
    let taker_ln = MockLightningBackend::new();
    let maker = world.makers()[0].inner().clone();

    // `paid`: the maker's node paid an invoice for this hash, as for an
    // earlier swap-in, and the payment settled.
    let paid = Preimage([0xf1; 32]);
    let invoice = payee_ln
        .create_hold_invoice(
            paid.payment_hash(),
            InvoiceParams {
                amount_msat: Some(40_000_000),
                ..Default::default()
            },
        )
        .unwrap();
    ln.pay_invoice(&invoice.invoice, None, None).unwrap();
    payee_ln.claim_held_payment(&paid).unwrap();
    // The old payment's preimage is what a new swap on this hash would find.
    assert_eq!(
        ln.payment_outcome(paid.payment_hash()).unwrap(),
        PaymentOutcome::Settled(paid)
    );

    // `received`: the maker's node created an invoice for this hash, as for
    // an earlier swap-out.
    let received = Preimage([0xf2; 32]);
    ln.create_hold_invoice(received.payment_hash(), InvoiceParams::default())
        .unwrap();

    for preimage in [&paid, &received] {
        let swap_id = preimage.payment_hash().to_string();
        match request_swap_in(&maker, &taker_ln, preimage) {
            LightningMakerMessage::Reject(reject) => {
                assert_eq!(reject.swap_id, swap_id);
                assert_eq!(reject.reason, "payment hash already used");
            }
            other => panic!("expected a Reject, got {}", other),
        }
        assert!(
            maker.get_ln_swap(&swap_id).unwrap().is_none(),
            "the maker stored a swap on a payment hash already on record"
        );
    }

    // A hash the node has no record of is still accepted.
    let fresh = Preimage([0xf3; 32]);
    accept_swap_in(&maker, &taker_ln, &fresh);
    assert!(maker
        .get_ln_swap(&fresh.payment_hash().to_string())
        .unwrap()
        .is_some());

    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// The payment-record lookup is a call to the node. A swap-in request that
/// fails the maker's own checks on its terms or invoice must be refused
/// before that call is made, and must store nothing.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn swap_in_request_checks_terms_and_invoice_before_payment_record_lookup(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let taker_ln = MockLightningBackend::new();
    let maker = world.makers()[0].inner().clone();

    let base = swap_in_request(&taker_ln, &Preimage([0xa1; 32]));
    let other = swap_in_request(&taker_ln, &Preimage([0xa2; 32]));
    let cltv_delta = base.locktime - 48;
    let expect_reject = |req: LnSwapInRequest, what: &str, reason: &str| {
        let swap_id = req.swap_id.clone();
        match expect_ln(send_swap_in_request(&maker, req).unwrap()) {
            LightningMakerMessage::Reject(reject) => {
                assert_eq!(reject.swap_id, swap_id);
                assert!(
                    reject.reason.contains(reason),
                    "{}: refused for another reason: {}",
                    what,
                    reject.reason
                );
            }
            other => panic!("{}: expected a Reject, got {}", what, other),
        }
        assert!(
            maker.get_ln_swap(&swap_id).unwrap().is_none(),
            "{}: the maker stored the swap",
            what
        );
        assert_eq!(
            ln.payment_record_lookups(),
            0,
            "{}: the maker looked up the payment record",
            what
        );
    };

    // Terms.
    expect_reject(
        LnSwapInRequest {
            amount: Amount::from_sat(1),
            ..base.clone()
        },
        "amount below the minimum",
        "outside the swap-in range",
    );
    expect_reject(
        LnSwapInRequest {
            locktime: 1,
            ..base.clone()
        },
        "locktime below the reaction time",
        "below minimum reaction time",
    );
    // Invoice.
    expect_reject(
        LnSwapInRequest {
            invoice: other.invoice.clone(),
            ..base.clone()
        },
        "invoice for another hash",
        "",
    );
    expect_reject(
        LnSwapInRequest {
            amount: base.amount + Amount::from_sat(1),
            ..base.clone()
        },
        "invoice for another amount",
        "",
    );
    expect_reject(
        LnSwapInRequest {
            locktime: cltv_delta + 11,
            ..base.clone()
        },
        "locktime inside the invoice's CLTV window",
        "too short for invoice cltv delta",
    );

    // The same request with valid terms and invoice is looked up once and
    // accepted.
    let swap_id = base.swap_id.clone();
    match expect_ln(send_swap_in_request(&maker, base).unwrap()) {
        LightningMakerMessage::SwapInAccept(_) => {}
        other => panic!("expected SwapInAccept, got {}", other),
    }
    assert_eq!(ln.payment_record_lookups(), 1);
    assert!(maker.get_ln_swap(&swap_id).unwrap().is_some());

    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}

/// A payment-record lookup that fails says nothing about the hash. The
/// swap-in request must fail with it, not go ahead as if the hash were
/// unused, and nothing may be stored or subscribed.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = maker_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln.clone()],
)]
fn swap_in_request_fails_when_payment_record_lookup_fails(
    world: &mut World,
    ln: Arc<MockLightningBackend>,
) {
    let taker_ln = MockLightningBackend::new();
    let maker = world.makers()[0].inner().clone();

    let preimage = Preimage([0xa3; 32]);
    let req = swap_in_request(&taker_ln, &preimage);
    let swap_id = req.swap_id.clone();

    ln.fail_payment_record_lookups(true);
    let result = send_swap_in_request(&maker, req.clone());
    assert!(
        matches!(result, Err(MakerError::General(reason)) if reason == "payment record lookup failed"),
        "the request did not fail with the lookup: {:?}",
        result
    );
    assert_eq!(ln.payment_record_lookups(), 1);
    assert!(
        maker.get_ln_swap(&swap_id).unwrap().is_none(),
        "the maker stored a swap without knowing the hash was unused"
    );
    assert!(
        !mailbox_open(&maker, &ln, &preimage),
        "the maker opened a mailbox for the swap"
    );

    // Once the node answers again, the same request goes through.
    ln.fail_payment_record_lookups(false);
    match expect_ln(send_swap_in_request(&maker, req).unwrap()) {
        LightningMakerMessage::SwapInAccept(_) => {}
        other => panic!("expected SwapInAccept, got {}", other),
    }
    assert!(maker.get_ln_swap(&swap_id).unwrap().is_some());

    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
}
