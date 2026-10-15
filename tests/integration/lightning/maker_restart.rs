//! A maker that restarts mid-swap must still be able to reach the money it
//! already committed. Maker-side swap state lives in the encrypted wallet
//! store for exactly this reason: without it a restarted swap-out maker has
//! no branch key for the HTLC it funded, and those coins are stuck.
//!
//! This drives the maker's handlers directly — no taker, no server threads —
//! so the restart happens at a precisely controlled point: right after the
//! maker has funded the on-chain HTLC.

use std::{
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

use bitcoin::{
    secp256k1::{Secp256k1, SecretKey},
    Amount, Network, OutPoint, PublicKey, Txid,
};
use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};
use openswap::{
    lightning::{
        invoice::verify_invoice, InvoiceParams, LightningBackend, LnEvent, MockLightningBackend,
        PaymentId, PaymentOutcome, Preimage, SwapHtlc,
    },
    maker::{
        handlers::{handle_message, ConnectionState, Maker},
        lightning_handlers::{
            ln_watchdog_tick_now, refuse_swap_in_after_wait, watchdog_expire_swap_in_snapshot,
            watchdog_finish_swap_in_snapshot, LnDirection, LnMakerPhase, LnMakerSwap,
        },
        MakerBehavior, MakerError, MakerServer,
    },
    protocol::{
        common_messages::{MakerToTakerMessage, TakerHello, TakerToMakerMessage},
        lightning_messages::{
            LightningMakerMessage, LightningTakerMessage, LnHtlcFunded, LnSwapInRequest,
            LnSwapOutPaid, LnSwapOutRequest,
        },
    },
    wallet::AddressType,
};

use crate::test_framework::*;

use std::sync::atomic::Ordering::Relaxed;

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

    // The taker's secret and claim key; the maker never learns the preimage.
    let preimage = Preimage([0x77; 32]);
    let payment_hash = preimage.payment_hash();
    let swap_id = payment_hash.to_string();
    let taker_hashlock_pubkey = PublicKey::new(
        SecretKey::from_slice(&[0x31; 32])
            .unwrap()
            .public_key(&Secp256k1::new()),
    );

    // ---- Drive the maker to a funded swap-out ----
    let mut state = ConnectionState::default();
    handle_message(
        &maker,
        &mut state,
        TakerToMakerMessage::TakerHello(TakerHello),
    )
    .unwrap();

    let accept = match expect_ln(
        handle_message(
            &maker,
            &mut state,
            ln_message(LightningTakerMessage::SwapOutRequest(LnSwapOutRequest {
                swap_id: swap_id.clone(),
                payment_hash,
                amount,
                locktime,
                min_confirmations: 1,
                taker_hashlock_pubkey,
            })),
        )
        .unwrap(),
    ) {
        LightningMakerMessage::SwapOutAccept(accept) => accept,
        other => panic!("expected SwapOutAccept, got {}", other),
    };

    // The taker's payment lands at the maker and is routed to its mailbox.
    ln.simulate_htlc_arrival(payment_hash, (amount + accept.fee).to_sat() * 1000);
    assert_eq!(
        maker.ln_router.as_ref().unwrap().pump_once(),
        1,
        "the held payment must reach the swap's mailbox"
    );

    let funded = match expect_ln(
        handle_message(
            &maker,
            &mut state,
            ln_message(LightningTakerMessage::SwapOutPaid(LnSwapOutPaid {
                swap_id: swap_id.clone(),
            })),
        )
        .unwrap(),
    ) {
        LightningMakerMessage::SwapOutFunded(funded) => funded,
        other => panic!("expected SwapOutFunded, got {}", other),
    };
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
            TakerToMakerMessage::TakerHello(TakerHello),
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
        TakerToMakerMessage::TakerHello(TakerHello),
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
            TakerToMakerMessage::TakerHello(TakerHello),
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
fn pause_block_generation(framework: &TestFramework) {
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
        TakerToMakerMessage::TakerHello(TakerHello),
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
        TakerToMakerMessage::TakerHello(TakerHello),
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
