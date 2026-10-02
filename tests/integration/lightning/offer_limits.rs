//! A maker's two swap directions draw on opposite sides of its channels, so
//! it can be able to serve one and not the other. This checks that an
//! all-outbound maker — the state of any freshly opened channel — accepts
//! swap-ins and refuses swap-outs, rather than advertising capacity it does
//! not have and failing the taker later.

use std::sync::Arc;

use bitcoin::{
    secp256k1::{Secp256k1, SecretKey},
    Amount, PublicKey,
};
use openswap::{
    lightning::{InvoiceParams, LightningBackend, MockLightningBackend, Preimage},
    maker::handlers::{handle_message, ConnectionState},
    protocol::{
        common_messages::{MakerToTakerMessage, TakerHello, TakerToMakerMessage},
        lightning_messages::{
            LightningMakerMessage, LightningTakerMessage, LnSwapInRequest, LnSwapOutRequest,
        },
    },
    wallet::AddressType,
};

use crate::test_framework::*;

fn ln_message(msg: LightningTakerMessage) -> TakerToMakerMessage {
    TakerToMakerMessage::Lightning(Box::new(msg))
}

fn expect_ln(response: Option<MakerToTakerMessage>) -> LightningMakerMessage {
    match response {
        Some(MakerToTakerMessage::Lightning(ln)) => *ln,
        other => panic!("expected a Lightning reply, got {:?}", other),
    }
}

fn test_pubkey(byte: u8) -> PublicKey {
    PublicKey::new(
        SecretKey::from_slice(&[byte; 32])
            .unwrap()
            .public_key(&Secp256k1::new()),
    )
}

/// A standalone mock node whose fresh channel is all outbound: it can pay over
/// Lightning (swap-in) but has nothing to receive with (swap-out).
fn outbound_only_node() -> Arc<MockLightningBackend> {
    let ln = Arc::new(MockLightningBackend::new());
    open_ready_channel(&ln, test_pubkey(0x21).inner, None);
    ln
}

#[world_test(
    backend = BitcoindBackend,
    bind = [ln = outbound_only_node()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [ln],
    setup = [fund_makers(4, Amount::from_btc(0.05).unwrap(), AddressType::P2WPKH)],
)]
fn maker_serves_only_the_direction_it_has_capacity_for(world: &mut World) {
    let maker = world.makers()[0].inner().clone();
    let amount = Amount::from_sat(40_000);
    let preimage = Preimage([0x55; 32]);
    let payment_hash = preimage.payment_hash();
    let swap_id = payment_hash.to_string();

    let mut state = ConnectionState::default();
    handle_message(
        &maker,
        &mut state,
        TakerToMakerMessage::TakerHello(TakerHello),
    )
    .unwrap();

    // Swap-out needs inbound capacity, which this maker has none of.
    let reply = expect_ln(
        handle_message(
            &maker,
            &mut state,
            ln_message(LightningTakerMessage::SwapOutRequest(LnSwapOutRequest {
                swap_id: swap_id.clone(),
                payment_hash,
                amount,
                locktime: 60,
                min_confirmations: 1,
                taker_hashlock_pubkey: test_pubkey(0x31),
            })),
        )
        .unwrap(),
    );
    match reply {
        LightningMakerMessage::Reject(reject) => assert!(
            reject.reason.contains("swap-out"),
            "rejection should name the direction, got: {}",
            reject.reason
        ),
        other => panic!("expected a swap-out rejection, got {}", other),
    }

    // The same maker still serves swap-ins, which its outbound capacity
    // covers — the refusal above is per-direction, not a blanket one.
    let taker_node = MockLightningBackend::new();
    let invoice = taker_node
        .create_hold_invoice(
            payment_hash,
            InvoiceParams {
                amount_msat: Some(amount.to_sat() * 1000),
                description: "swap-in".to_string(),
                expiry_secs: 3600,
            },
        )
        .unwrap();
    let reply = expect_ln(
        handle_message(
            &maker,
            &mut state,
            ln_message(LightningTakerMessage::SwapInRequest(LnSwapInRequest {
                swap_id: swap_id.clone(),
                invoice: invoice.invoice,
                payment_hash,
                amount,
                locktime: 60,
                min_confirmations: 1,
                taker_timelock_pubkey: test_pubkey(0x41),
            })),
        )
        .unwrap(),
    );
    match reply {
        LightningMakerMessage::SwapInAccept(accept) => assert_eq!(accept.swap_id, swap_id),
        other => panic!("expected SwapInAccept, got {}", other),
    }

    // ---- Hostile terms are refused ----
    // A peer that asks for zero confirmations wants the maker to act on a
    // funding it can still double-spend; one that asks for a huge number
    // would pin the connection thread and burn the refund window.
    for (confirmations, label) in [(0u32, "zero"), (u32::MAX, "absurd")] {
        let preimage = Preimage([0x60 + confirmations as u8 % 8; 32]);
        let reply = expect_ln(
            handle_message(
                &maker,
                &mut ConnectionState::default(),
                TakerToMakerMessage::TakerHello(TakerHello),
            )
            .and_then(|_| {
                let mut state = ConnectionState::default();
                handle_message(
                    &maker,
                    &mut state,
                    TakerToMakerMessage::TakerHello(TakerHello),
                )?;
                handle_message(
                    &maker,
                    &mut state,
                    ln_message(LightningTakerMessage::SwapInRequest(LnSwapInRequest {
                        swap_id: preimage.payment_hash().to_string(),
                        invoice: taker_node
                            .create_hold_invoice(
                                preimage.payment_hash(),
                                InvoiceParams {
                                    amount_msat: Some(amount.to_sat() * 1000),
                                    description: "hostile".to_string(),
                                    expiry_secs: 3600,
                                },
                            )
                            .unwrap()
                            .invoice,
                        payment_hash: preimage.payment_hash(),
                        amount,
                        locktime: 60,
                        min_confirmations: confirmations,
                        taker_timelock_pubkey: test_pubkey(0x42),
                    })),
                )
            })
            .unwrap(),
        );
        match reply {
            LightningMakerMessage::Reject(reject) => assert!(
                reject.reason.contains("min_confirmations"),
                "{label} confirmations should be refused by range, got: {}",
                reject.reason
            ),
            other => panic!(
                "expected a rejection for {} confirmations, got {}",
                label, other
            ),
        }
    }

    // A second request reusing a live swap's id must not replace it: the
    // stored record holds the only copy of that swap's branch key.
    let mut state2 = ConnectionState::default();
    handle_message(
        &maker,
        &mut state2,
        TakerToMakerMessage::TakerHello(TakerHello),
    )
    .unwrap();
    let reply = expect_ln(
        handle_message(
            &maker,
            &mut state2,
            ln_message(LightningTakerMessage::SwapOutRequest(LnSwapOutRequest {
                swap_id: swap_id.clone(),
                payment_hash,
                amount,
                locktime: 60,
                min_confirmations: 1,
                taker_hashlock_pubkey: test_pubkey(0x31),
            })),
        )
        .unwrap(),
    );
    match reply {
        LightningMakerMessage::Reject(reject) => assert!(
            reject.reason.contains("already in progress"),
            "a duplicate swap id should be refused, got: {}",
            reject.reason
        ),
        other => panic!("expected a duplicate-id rejection, got {}", other),
    }
}
