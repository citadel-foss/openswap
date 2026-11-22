//! A maker that `maker-cli stop` is draining refuses new Lightning swaps, in
//! both directions: it would break them when it shuts down, so the taker should
//! pick another maker now. It does not wait for a Lightning swap already in
//! progress. That swap is saved and comes back after the restart.

use std::{sync::Arc, time::Duration};

use bitcoin::{
    secp256k1::{Secp256k1, SecretKey},
    Amount, PublicKey,
};
use openswap::{
    lightning::{InvoiceParams, LightningBackend, MockLightningBackend, Preimage},
    maker::handlers::{handle_message, ConnectionState, Maker as _},
    protocol::{
        common_messages::{Hello, MakerToTakerMessage, TakerToMakerMessage},
        lightning_messages::{
            LightningMakerMessage, LightningTakerMessage, LnSwapInRequest, LnSwapOutRequest,
        },
    },
    wallet::AddressType,
};

use crate::test_framework::*;

fn test_pubkey(byte: u8) -> PublicKey {
    PublicKey::new(
        SecretKey::from_slice(&[byte; 32])
            .unwrap()
            .public_key(&Secp256k1::new()),
    )
}

/// A mock node with an all-outbound channel: it serves swap-ins.
fn outbound_only_node() -> Arc<MockLightningBackend> {
    let ln = Arc::new(MockLightningBackend::new());
    open_ready_channel(&ln, test_pubkey(0x21).inner, None);
    ln
}

/// What the maker answers to `request`, which must be a Lightning reply.
fn ln_reply(
    maker: &Arc<openswap::maker::MakerServer>,
    request: LightningTakerMessage,
) -> LightningMakerMessage {
    let mut state = ConnectionState::default();
    handle_message(
        maker,
        &mut state,
        TakerToMakerMessage::Hello(Hello::default()),
    )
    .unwrap();
    match handle_message(
        maker,
        &mut state,
        TakerToMakerMessage::Lightning(Box::new(request)),
    )
    .unwrap()
    {
        Some(MakerToTakerMessage::Lightning(reply)) => *reply,
        other => panic!("expected a Lightning reply, got {:?}", other),
    }
}

fn swap_in_request(amount: Amount, preimage: Preimage) -> LightningTakerMessage {
    let payment_hash = preimage.payment_hash();
    let invoice = MockLightningBackend::new()
        .create_hold_invoice(
            payment_hash,
            InvoiceParams {
                amount_msat: Some(amount.to_sat() * 1000),
                description: "swap-in".to_string(),
                expiry_secs: 3600,
            },
        )
        .unwrap();
    LightningTakerMessage::SwapInRequest(LnSwapInRequest {
        swap_id: payment_hash.to_string(),
        invoice: invoice.invoice,
        payment_hash,
        amount,
        locktime: 60,
        min_confirmations: 1,
        taker_timelock_pubkey: test_pubkey(0x41),
        features: vec!["ln-swap-in".to_string()],
    })
}

fn swap_out_request(amount: Amount, preimage: Preimage) -> LightningTakerMessage {
    let payment_hash = preimage.payment_hash();
    LightningTakerMessage::SwapOutRequest(LnSwapOutRequest {
        swap_id: payment_hash.to_string(),
        payment_hash,
        amount,
        locktime: 60,
        min_confirmations: 1,
        taker_hashlock_pubkey: test_pubkey(0x31),
        features: vec!["ln-swap-out".to_string()],
    })
}

#[world_test(
    backend = BitcoindBackend,
    bind = [ln = outbound_only_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn a_draining_maker_refuses_new_lightning_swaps(world: &mut World) {
    let maker = world.makers()[0].inner().clone();
    let amount = Amount::from_sat(40_000);

    // Before the drain the maker takes a swap-in, so the refusals below are
    // down to the drain and nothing else.
    let before = Preimage([0x61; 32]);
    match ln_reply(&maker, swap_in_request(amount, before)) {
        LightningMakerMessage::SwapInAccept(_) => {}
        other => panic!("a running maker must accept the swap-in, got {}", other),
    }
    assert_eq!(maker.ln_swap_count(), 1);

    maker.start_drain();

    for (direction, request, preimage) in [
        (
            "swap-in",
            swap_in_request(amount, Preimage([0x62; 32])),
            Preimage([0x62; 32]),
        ),
        (
            "swap-out",
            swap_out_request(amount, Preimage([0x63; 32])),
            Preimage([0x63; 32]),
        ),
    ] {
        match ln_reply(&maker, request) {
            LightningMakerMessage::Reject(reject) => assert_eq!(
                reject.reason, "the maker is stopping and takes no new swaps",
                "a draining maker must refuse a {}",
                direction
            ),
            other => panic!("expected a {direction} rejection, got {}", other),
        }
        assert!(
            maker
                .get_ln_swap(&preimage.payment_hash().to_string())
                .unwrap()
                .is_none(),
            "a refused {} must leave no record",
            direction
        );
    }

    // The swap that was already running is untouched.
    assert_eq!(maker.ln_swap_count(), 1);
    assert!(maker
        .get_ln_swap(&before.payment_hash().to_string())
        .unwrap()
        .is_some());
}

/// With the maker running, a drain does not wait for a Lightning swap in
/// progress: the maker stops at once, and the swap's record, which holds the
/// only copy of its branch key, is still there after the restart.
#[world_test(
    backend = BitcoindBackend,
    bind = [ln = outbound_only_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln],
    setup = [
        fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH),
        start_makers(120),
    ],
)]
fn a_lightning_swap_in_progress_does_not_hold_the_drain(world: &mut World) {
    let maker = world.makers()[0].inner().clone();
    let preimage = Preimage([0x64; 32]);
    let swap_id = preimage.payment_hash().to_string();
    match ln_reply(&maker, swap_in_request(Amount::from_sat(40_000), preimage)) {
        LightningMakerMessage::SwapInAccept(_) => {}
        other => panic!("a running maker must accept the swap-in, got {}", other),
    }
    assert_eq!(maker.ln_swap_count(), 1);

    maker.start_drain();
    wait_until!(
        Duration::from_secs(30),
        "the drain not to wait for a Lightning swap",
        maker.shutdown.load(std::sync::atomic::Ordering::Relaxed)
    );

    world.restart_maker(0, 120);
    let restarted = world.makers()[0].inner().clone();
    assert!(
        restarted.get_ln_swap(&swap_id).unwrap().is_some(),
        "the Lightning swap comes back after the restart"
    );
    assert_eq!(restarted.ln_swap_count(), 1);
    world.shutdown_makers();
}
