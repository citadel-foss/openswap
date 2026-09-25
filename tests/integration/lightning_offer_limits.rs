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
    lightning::{
        InvoiceParams, LightningBackend, MockLightningBackend, OpenChannelRequest, Preimage,
    },
    maker::{
        handlers::{handle_message, ConnectionState},
        MakerBehavior,
    },
    protocol::{
        common_messages::{MakerToTakerMessage, TakerHello, TakerToMakerMessage},
        lightning_messages::{
            LightningMakerMessage, LightningTakerMessage, LnSwapInRequest, LnSwapOutRequest,
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

fn test_pubkey(byte: u8) -> PublicKey {
    PublicKey::new(
        SecretKey::from_slice(&[byte; 32])
            .unwrap()
            .public_key(&Secp256k1::new()),
    )
}

#[test]
fn maker_serves_only_the_direction_it_has_capacity_for() {
    log::warn!("Running Test: per-direction Lightning offer limits");

    // A freshly opened channel is all outbound: the maker can pay over
    // Lightning (swap-in) but has nothing to receive with (swap-out).
    let ln: Arc<MockLightningBackend> = Arc::new(MockLightningBackend::new());
    ln.set_onchain_balance(Amount::from_btc(0.02).unwrap());
    let channel = ln
        .open_channel(OpenChannelRequest {
            node_pubkey: test_pubkey(0x21).inner,
            address: "127.0.0.1:9735".to_string(),
            channel_amount: Amount::from_sat(1_000_000),
            push_to_counterparty_msat: None,
            announce_channel: false,
        })
        .unwrap();
    ln.simulate_channel_ready(&channel);
    let _ = ln.poll_event().unwrap();

    let (test_framework, takers, makers, block_generation_handle) =
        TestFramework::init_with_lightning::<BitcoindBackend>(
            vec![(7502, None)],
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
            vec![ln.clone() as Arc<dyn LightningBackend>],
        );
    fund_makers(
        &makers,
        &test_framework.bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2WPKH,
    );

    let maker = makers[0].clone();
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

    drop(takers);
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
