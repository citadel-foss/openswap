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
    Amount, Network, OutPoint, PublicKey,
};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    lightning::{
        invoice::verify_invoice, InvoiceParams, LightningBackend, LnEvent, MockLightningBackend,
        OpenChannelRequest, Preimage, SwapHtlc,
    },
    maker::{
        handlers::{handle_message, ConnectionState, Maker},
        lightning_handlers::{
            refuse_swap_in_after_wait, watchdog_expire_swap_in_snapshot, LnDirection, LnMakerPhase,
            LnMakerSwap,
        },
        MakerBehavior, MakerServer,
    },
    protocol::{
        common_messages::{MakerToTakerMessage, TakerHello, TakerToMakerMessage},
        lightning_messages::{
            LightningMakerMessage, LightningTakerMessage, LnHtlcFunded, LnSwapInRequest,
            LnSwapOutPaid, LnSwapOutRequest,
        },
    },
    taker::TakerBehavior,
    wallet::AddressType,
};

use super::test_framework::*;

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

#[test]
fn lightning_maker_restart_recovers_funded_swap() {
    log::warn!("Running Test: maker restart recovers a funded Lightning swap");

    // A standalone mock node with capacity, so the maker advertises
    // Lightning terms and can hold an invoice.
    let ln: Arc<MockLightningBackend> = Arc::new(MockLightningBackend::new());
    ln.set_onchain_balance(Amount::from_btc(0.02).unwrap());
    let peer = SecretKey::from_slice(&[0x21; 32]).unwrap();
    let channel = ln
        .open_channel(OpenChannelRequest {
            node_pubkey: peer.public_key(&Secp256k1::new()),
            address: "127.0.0.1:9735".to_string(),
            channel_amount: Amount::from_sat(1_000_000),
            // Push half to the peer so the channel has inbound capacity too:
            // swap-outs are bounded by inbound, and a freshly opened channel
            // has none.
            push_to_counterparty_msat: Some(500_000_000),
            announce_channel: false,
        })
        .unwrap();
    ln.simulate_channel_ready(&channel);
    let _ = ln.poll_event().unwrap();

    let (test_framework, takers, makers, block_generation_handle) =
        TestFramework::init_with_lightning::<BitcoindBackend>(
            1,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
            vec![ln.clone() as Arc<dyn LightningBackend>],
        );
    let bitcoind = &test_framework.bitcoind;
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2WPKH,
    );

    let maker = makers[0].clone();
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
    drop(makers);

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

    drop(takers);
    restarted.shutdown.store(true, Relaxed);
    restarted.watch_service.shutdown();
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// An unfunded swap-in as the maker stores it on acceptance.
fn accepted_swap_in(preimage: &Preimage) -> LnMakerSwap {
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
        locktime: 144,
        min_confirmations: 1,
        htlc: SwapHtlc::new(&hashlock_pubkey, &timelock_pubkey, &payment_hash, 144),
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
/// for it reaches the mailbox only if it is.
fn mailbox_open(maker: &MakerServer, ln: &MockLightningBackend, preimage: &Preimage) -> bool {
    let payment_hash = preimage.payment_hash();
    ln.create_hold_invoice(
        payment_hash,
        InvoiceParams {
            amount_msat: Some(40_000_000),
            ..Default::default()
        },
    )
    .unwrap();
    ln.simulate_htlc_arrival(payment_hash, 40_000_000);
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
#[test]
fn stale_swap_in_refusal_keeps_paid_swap() {
    log::warn!("Running Test: stale swap-in refusal keeps a paid swap");

    let ln: Arc<MockLightningBackend> = Arc::new(MockLightningBackend::new());
    let (test_framework, takers, makers, block_generation_handle) =
        TestFramework::init_with_lightning::<BitcoindBackend>(
            1,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
            vec![ln.clone() as Arc<dyn LightningBackend>],
        );
    let maker = makers[0].clone();
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
    drop(makers);

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

    drop(takers);
    restarted.shutdown.store(true, Relaxed);
    restarted.watch_service.shutdown();
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// Until the announced output is shown to pay the swap's HTLC, a funded
/// message could come from anyone who knows the swap id, such as the next
/// maker on a routed swap. A forged announcement must be rejected without
/// forgetting the swap, so the honest taker's funding can still complete it.
#[test]
fn forged_swap_in_funding_keeps_accepted_swap() {
    log::warn!("Running Test: forged swap-in funding keeps the accepted swap");

    let ln: Arc<MockLightningBackend> = Arc::new(MockLightningBackend::new());
    let (test_framework, takers, makers, block_generation_handle) =
        TestFramework::init_with_lightning::<BitcoindBackend>(
            1,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
            vec![ln.clone() as Arc<dyn LightningBackend>],
        );
    let bitcoind = &test_framework.bitcoind;
    let maker = makers[0].clone();
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

    drop(takers);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// The watchdog expires an unfunded swap-in from a snapshot taken before it
/// acts. If a handler paid the swap after that snapshot, the expiry must keep
/// the paid record and its mailbox. A swap still awaiting funding is
/// forgotten as before.
#[test]
fn stale_watchdog_expiry_keeps_paid_swap() {
    log::warn!("Running Test: stale watchdog expiry keeps a paid swap");

    let ln: Arc<MockLightningBackend> = Arc::new(MockLightningBackend::new());
    let (test_framework, takers, makers, block_generation_handle) =
        TestFramework::init_with_lightning::<BitcoindBackend>(
            1,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
            vec![ln.clone() as Arc<dyn LightningBackend>],
        );
    let maker = makers[0].clone();
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

    drop(takers);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// The funded-message handler moves a swap-in to InPaid with
/// `store_ln_swap_if_phase`, from a copy read before its confirmation wait.
/// That store must refuse the copy once another connection has moved the
/// swap to InPaid, or once the swap is gone, and must store it while the
/// swap is still InAccepted. This covers the store itself, not whether the
/// handler calls it.
#[test]
fn conditional_paid_store_refuses_stale_copy() {
    log::warn!("Running Test: conditional InPaid store refuses a stale copy");

    let ln: Arc<MockLightningBackend> = Arc::new(MockLightningBackend::new());
    let (test_framework, takers, makers, block_generation_handle) =
        TestFramework::init_with_lightning::<BitcoindBackend>(
            1,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
            vec![ln.clone() as Arc<dyn LightningBackend>],
        );
    let maker = makers[0].clone();

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
    drop(makers);

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

    drop(takers);
    restarted.shutdown.store(true, Relaxed);
    restarted.watch_service.shutdown();
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// handle_swap_in_funded reads the swap, waits for the funding to confirm and
/// only then moves it to InPaid and pays. If another connection pays the swap
/// during that wait, the waiting handler must stop: it must neither overwrite
/// the paid record nor pay the invoice.
#[test]
fn swap_in_funded_handler_yields_to_swap_paid_during_wait() {
    log::warn!("Running Test: swap-in funded handler yields to a swap paid during its wait");

    // The maker's node needs outbound capacity to serve swap-ins.
    let ln: Arc<MockLightningBackend> = Arc::new(MockLightningBackend::new());
    ln.set_onchain_balance(Amount::from_btc(0.02).unwrap());
    let peer = SecretKey::from_slice(&[0x21; 32]).unwrap();
    let channel = ln
        .open_channel(OpenChannelRequest {
            node_pubkey: peer.public_key(&Secp256k1::new()),
            address: "127.0.0.1:9735".to_string(),
            channel_amount: Amount::from_sat(1_000_000),
            push_to_counterparty_msat: Some(500_000_000),
            announce_channel: false,
        })
        .unwrap();
    ln.simulate_channel_ready(&channel);
    let _ = ln.poll_event().unwrap();
    // The taker's node only issues the hold invoice. It shares no ledger with
    // the maker's node, so a payment attempt fails at once instead of
    // blocking the handler on a preimage that never comes.
    let taker_ln = MockLightningBackend::new();

    let (test_framework, takers, makers, block_generation_handle) =
        TestFramework::init_with_lightning::<BitcoindBackend>(
            1,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
            vec![ln.clone() as Arc<dyn LightningBackend>],
        );
    let bitcoind = &test_framework.bitcoind;
    let maker = makers[0].clone();

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
    test_framework.set_block_gen_paused(true);
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
    let log_path = test_framework.taker_log_path();
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
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
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
        if contents
            .get(log_offset as usize..)
            .is_some_and(|new| new.contains(&waiting))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the handler never reached its confirmation wait"
        );
        thread::sleep(Duration::from_millis(200));
    }

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

    test_framework.set_block_gen_paused(false);
    drop(takers);
    maker.shutdown.store(true, Relaxed);
    maker.watch_service.shutdown();
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
