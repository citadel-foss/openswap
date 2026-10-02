//! A maker that restarts mid-swap must still be able to reach the money it
//! already committed. Maker-side swap state lives in the encrypted wallet
//! store for exactly this reason: without it a restarted swap-out maker has
//! no branch key for the HTLC it funded, and those coins are stuck.
//!
//! This drives the maker's handlers directly — no taker, no server threads —
//! so the restart happens at a precisely controlled point: right after the
//! maker has funded the on-chain HTLC.

use std::sync::Arc;

use bitcoin::{
    secp256k1::{Secp256k1, SecretKey},
    Amount, PublicKey,
};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    lightning::{LightningBackend, MockLightningBackend, Preimage},
    maker::{
        handlers::{handle_message, ConnectionState},
        MakerServer,
    },
    protocol::{
        common_messages::{MakerToTakerMessage, TakerHello, TakerToMakerMessage},
        lightning_messages::{
            LightningMakerMessage, LightningTakerMessage, LnSwapOutPaid, LnSwapOutRequest,
        },
    },
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

/// A standalone mock node with a ready channel, so the maker advertises
/// Lightning terms and can hold an invoice.
fn maker_node() -> Arc<MockLightningBackend> {
    let ln = Arc::new(MockLightningBackend::new());
    let peer = SecretKey::from_slice(&[0x21; 32]).unwrap();
    open_ready_channel(&ln, peer.public_key(&Secp256k1::new()), Some(500_000_000));
    ln
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
