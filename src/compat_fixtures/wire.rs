//! Frozen samples of every wire message, including its foreign field types.

#[cfg(feature = "lightning")]
use std::time::Duration;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    net::{TcpListener, TcpStream},
    path::Path,
    thread,
};

use bitcoin::{
    absolute::LockTime,
    bip32::ChainCode,
    constants::genesis_block,
    ecdsa::Signature as BitcoinSignature,
    hashes::{hash160, sha256, sha256d, Hash},
    secp256k1::{Message, Scalar, Secp256k1, SecretKey},
    Amount, Network, OutPoint, PublicKey,
};
#[cfg(feature = "lightning")]
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};

use crate::{
    protocol::{
        common_messages::{
            AckSwapDetails, FidelityProof, GetOffer, Hello, MakerToTakerMessage, Offer,
            PrivateKeyHandover, ProtocolVersion, SwapDetails, SwapPrivkey, TakerToMakerMessage,
            UnsupportedMessage,
        },
        contract::{create_contract_redeemscript, create_multisig_redeemscript},
        legacy_messages::{
            ContractTxInfoForRecvr, ContractTxInfoForSender, FundingTxInfo, LegacyTakerMessage,
            NextHopInfo, ProofOfFunding, ReqContractSigsAsRecvrAndSender, ReqContractSigsForRecvr,
            ReqContractSigsForSender, RespContractSigsForRecvr, RespContractSigsForRecvrAndSender,
            RespContractSigsForSender, SenderContractTxInfo,
        },
        lightning_messages::{
            LightningMakerMessage, LightningOffer, LightningTakerMessage, LnHtlcFunded, LnReject,
            LnSwapInAccept, LnSwapInComplete, LnSwapInRequest, LnSwapOutAccept, LnSwapOutClaimed,
            LnSwapOutComplete, LnSwapOutPaid, LnSwapOutRequest,
        },
        taproot_messages::{SerializableScalar, TaprootContractData, TaprootTakerMessage},
    },
    utill::send_message,
    wallet::FidelityBond,
};

use super::{check, write};

const TAKER: &[&str] = &[
    "hello",
    "get-offer",
    "swap-details",
    "sender-request",
    "funding-proof",
    "both-response",
    "recvr-request",
    "legacy-handover",
    "taproot-data",
    "taproot-handover",
    "waiting-funding",
    "unsupported",
    "lightning-swap-in-request",
    "lightning-swap-in-funded",
    "lightning-swap-out-request",
    "lightning-swap-out-paid",
    "lightning-swap-out-claimed",
];
const MAKER: &[&str] = &[
    "hello",
    "offer",
    "ack",
    "ack-rejected",
    "sender-response",
    "both-request",
    "recvr-response",
    "legacy-handover",
    "taproot-data",
    "taproot-handover",
    "unsupported",
    "lightning-swap-in-accept",
    "lightning-swap-in-complete",
    "lightning-swap-out-accept",
    "lightning-swap-out-funded",
    "lightning-swap-out-complete",
    "lightning-reject",
];
const LEGACY: &[&str] = &[
    "sender-request",
    "funding-proof",
    "both-response",
    "recvr-request",
    "handover",
];
const TAPROOT: &[&str] = &["data", "handover"];
const LN_TAKER: &[&str] = &[
    "swap-in-request",
    "swap-in-funded",
    "swap-out-request",
    "swap-out-paid",
    "swap-out-claimed",
];
const LN_MAKER: &[&str] = &[
    "swap-in-accept",
    "swap-in-complete",
    "swap-out-accept",
    "swap-out-funded",
    "swap-out-complete",
    "reject",
];

pub(super) fn generate(release: &Path) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let nonce = SecretKey::from_slice(&[2; 32]).unwrap();
    let pubkey = PublicKey::new(secret.public_key(&secp));
    let next_pubkey = PublicKey::new(nonce.public_key(&secp));
    let preimage = [7; 32];
    let payment_hash = sha256::Hash::hash(&preimage);
    let swap_id = payment_hash.to_string();
    let tx = genesis_block(Network::Regtest).txdata[0].clone();
    let outpoint = OutPoint::new(tx.compute_txid(), 0);
    let amount = Amount::from_sat(50_000);
    let contract_script =
        create_contract_redeemscript(&pubkey, &next_pubkey, &hash160::Hash::hash(&preimage), &144);
    let multisig_script = create_multisig_redeemscript(&pubkey, &next_pubkey);
    let bond = FidelityBond {
        outpoint,
        amount,
        lock_time: LockTime::from_height(800_000).unwrap(),
        pubkey,
        conf_height: Some(700_000),
        is_spent: false,
        bond_index: 1,
        tx: Some(tx.clone()),
        extra: BTreeMap::new(),
    };
    let cert_hash = bond.generate_cert_hash("fixture-maker.onion:21", &next_pubkey);
    let signature = secp.sign_ecdsa(&Message::from_digest(cert_hash.to_byte_array()), &secret);
    let fidelity = FidelityProof {
        bond,
        cert_hash,
        cert_sig: signature,
    };
    write(release, "wire-cert-hash", &cert_hash);
    write(release, "wire-fidelity-proof", &fidelity);
    let sig = BitcoinSignature::sighash_all(signature);
    let lightning_offer = LightningOffer {
        swap_in: true,
        swap_out: true,
        base_fee: 100,
        amount_relative_fee_pct: 0.1,
        min_size: 10_000,
        max_swap_in: 100_000,
        max_swap_out: 200_000,
    };
    let offer = Offer {
        base_fee: 100,
        amount_relative_fee_pct: 0.1,
        time_relative_fee_pct: 0.01,
        required_confirms: 1,
        minimum_locktime: 144,
        max_size: 1_000_000,
        min_size: 10_000,
        tweakable_point: next_pubkey,
        fidelity,
        tweak_chain_code: ChainCode::from([3; 32]),
        name: "fixture-maker".into(),
        lightning: Some(lightning_offer),
    };
    let hello = Hello {
        features: vec![
            "legacy".into(),
            "taproot".into(),
            "ln-swap-in".into(),
            "ln-swap-out".into(),
        ],
    };
    let details = SwapDetails {
        id: swap_id.clone(),
        features: vec!["legacy".into()],
        amount,
        tx_count: 2,
        incoming_count: 1,
        max_input_budget: 3,
        feerate: 2,
        timelock: 144,
        refund_locktime_offset: 144,
    };
    let handover = PrivateKeyHandover {
        id: swap_id.clone(),
        privkeys: vec![SwapPrivkey {
            identifier: multisig_script.clone(),
            key: secret,
        }],
    };
    let sender = ReqContractSigsForSender {
        id: swap_id.clone(),
        txs_info: vec![ContractTxInfoForSender {
            multisig_nonce: secret,
            hashlock_nonce: nonce,
            timelock_pubkey: next_pubkey,
            senders_contract_tx: tx.clone(),
            multisig_redeemscript: multisig_script.clone(),
            funding_input_value: amount,
        }],
        hashvalue: hash160::Hash::hash(&preimage),
        locktime: 144,
    };
    let proof = ProofOfFunding {
        id: swap_id.clone(),
        confirmed_funding_txes: vec![FundingTxInfo {
            funding_tx: tx.clone(),
            multisig_redeemscript: multisig_script.clone(),
            multisig_nonce: secret,
            contract_redeemscript: contract_script.clone(),
            hashlock_nonce: nonce,
        }],
        next_openswap_info: vec![NextHopInfo {
            next_multisig_pubkey: pubkey,
            next_hashlock_pubkey: next_pubkey,
            next_multisig_nonce: secret,
            next_hashlock_nonce: nonce,
        }],
        refund_locktime: 144,
    };
    let both_response = RespContractSigsForRecvrAndSender {
        id: swap_id.clone(),
        receivers_sigs: vec![sig],
        senders_sigs: vec![sig],
    };
    let recvr = ReqContractSigsForRecvr {
        id: swap_id.clone(),
        txs: vec![ContractTxInfoForRecvr {
            multisig_redeemscript: multisig_script.clone(),
            contract_tx: tx.clone(),
        }],
    };
    let taproot = TaprootContractData {
        id: swap_id.clone(),
        pubkeys: vec![pubkey, next_pubkey],
        next_hop_point: next_pubkey,
        internal_keys: vec![pubkey.inner.x_only_public_key().0],
        tap_tweaks: vec![SerializableScalar::from(Scalar::ONE)],
        hashlock_script: contract_script.clone(),
        timelock_scripts: vec![contract_script.clone()],
        contract_txs: vec![tx.clone()],
        amounts: vec![amount],
        hashlock_nonce: Some(secret),
        next_hashlock_nonce: Some(nonce),
    };
    #[cfg(feature = "lightning")]
    let invoice = InvoiceBuilder::new(Currency::Regtest)
        .description("compatibility fixture".into())
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret([4; 32]))
        .duration_since_epoch(Duration::from_secs(1_700_000_000))
        .min_final_cltv_expiry_delta(144)
        .amount_milli_satoshis(amount.to_sat() * 1_000)
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &secret))
        .unwrap()
        .to_string();
    #[cfg(not(feature = "lightning"))]
    let invoice = include_str!("../../tests/fixtures/compat/v0.3.0/wire-invoice.txt")
        .trim()
        .to_string();
    fs::write(release.join("wire-invoice.txt"), &invoice).unwrap();
    let funded = LnHtlcFunded {
        swap_id: swap_id.clone(),
        outpoint,
        value: amount,
    };
    let ln_taker = vec![
        (
            "swap-in-request",
            LightningTakerMessage::SwapInRequest(LnSwapInRequest {
                swap_id: swap_id.clone(),
                invoice: invoice.clone(),
                payment_hash,
                amount,
                locktime: 144,
                min_confirmations: 1,
                taker_timelock_pubkey: pubkey,
                features: vec!["ln-swap-in".into()],
            }),
        ),
        (
            "swap-in-funded",
            LightningTakerMessage::SwapInFunded(funded.clone()),
        ),
        (
            "swap-out-request",
            LightningTakerMessage::SwapOutRequest(LnSwapOutRequest {
                swap_id: swap_id.clone(),
                payment_hash,
                amount,
                locktime: 144,
                min_confirmations: 1,
                taker_hashlock_pubkey: pubkey,
                features: vec!["ln-swap-out".into()],
            }),
        ),
        (
            "swap-out-paid",
            LightningTakerMessage::SwapOutPaid(LnSwapOutPaid {
                swap_id: swap_id.clone(),
            }),
        ),
        (
            "swap-out-claimed",
            LightningTakerMessage::SwapOutClaimed(LnSwapOutClaimed {
                swap_id: swap_id.clone(),
                claim_txid: tx.compute_txid(),
            }),
        ),
    ];
    let ln_maker = vec![
        (
            "swap-in-accept",
            LightningMakerMessage::SwapInAccept(LnSwapInAccept {
                swap_id: swap_id.clone(),
                maker_hashlock_pubkey: next_pubkey,
                fee: Amount::from_sat(100),
                locktime: 144,
                min_confirmations: 1,
            }),
        ),
        (
            "swap-in-complete",
            LightningMakerMessage::SwapInComplete(LnSwapInComplete {
                swap_id: swap_id.clone(),
            }),
        ),
        (
            "swap-out-accept",
            LightningMakerMessage::SwapOutAccept(LnSwapOutAccept {
                swap_id: swap_id.clone(),
                invoice,
                fee: Amount::from_sat(100),
                maker_timelock_pubkey: next_pubkey,
                locktime: 144,
                min_confirmations: 1,
            }),
        ),
        (
            "swap-out-funded",
            LightningMakerMessage::SwapOutFunded(funded),
        ),
        (
            "swap-out-complete",
            LightningMakerMessage::SwapOutComplete(LnSwapOutComplete {
                swap_id: swap_id.clone(),
            }),
        ),
        (
            "reject",
            LightningMakerMessage::Reject(LnReject {
                swap_id: swap_id.clone(),
                reason: "fixture rejection".into(),
            }),
        ),
    ];
    let unsupported = UnsupportedMessage {
        what: "future-flow".into(),
        reason: "unsupported fixture".into(),
    };
    let taker = vec![
        ("hello", TakerToMakerMessage::Hello(hello.clone())),
        ("get-offer", TakerToMakerMessage::GetOffer(GetOffer)),
        ("swap-details", TakerToMakerMessage::SwapDetails(details)),
        (
            "sender-request",
            TakerToMakerMessage::ReqContractSigsForSender(sender.clone()),
        ),
        (
            "funding-proof",
            TakerToMakerMessage::ProofOfFunding(proof.clone()),
        ),
        (
            "both-response",
            TakerToMakerMessage::RespContractSigsForRecvrAndSender(both_response.clone()),
        ),
        (
            "recvr-request",
            TakerToMakerMessage::ReqContractSigsForRecvr(recvr.clone()),
        ),
        (
            "legacy-handover",
            TakerToMakerMessage::LegacyPrivateKeyHandover(handover.clone()),
        ),
        (
            "taproot-data",
            TakerToMakerMessage::TaprootContractData(Box::new(taproot.clone())),
        ),
        (
            "taproot-handover",
            TakerToMakerMessage::TaprootPrivateKeyHandover(handover.clone()),
        ),
        (
            "waiting-funding",
            TakerToMakerMessage::WaitingFundingConfirmation(swap_id.clone()),
        ),
        (
            "unsupported",
            TakerToMakerMessage::Unsupported(unsupported.clone()),
        ),
    ];
    let maker = vec![
        ("hello", MakerToTakerMessage::Hello(hello)),
        ("offer", MakerToTakerMessage::Offer(Box::new(offer))),
        (
            "ack",
            MakerToTakerMessage::AckSwapDetails(AckSwapDetails::accept(pubkey, vec![1, 2])),
        ),
        (
            "sender-response",
            MakerToTakerMessage::RespContractSigsForSender(RespContractSigsForSender {
                id: swap_id.clone(),
                sigs: vec![sig],
            }),
        ),
        (
            "both-request",
            MakerToTakerMessage::ReqContractSigsAsRecvrAndSender(ReqContractSigsAsRecvrAndSender {
                receivers_contract_txs: vec![tx.clone()],
                senders_contract_txs_info: vec![SenderContractTxInfo {
                    funding_tx: tx.clone(),
                    contract_tx: tx,
                    timelock_pubkey: next_pubkey,
                    multisig_redeemscript: multisig_script,
                    contract_redeemscript: contract_script,
                    funding_amount: amount,
                    multisig_nonce: secret,
                    hashlock_nonce: nonce,
                }],
            }),
        ),
        (
            "recvr-response",
            MakerToTakerMessage::RespContractSigsForRecvr(RespContractSigsForRecvr {
                id: swap_id,
                sigs: vec![sig],
            }),
        ),
        (
            "legacy-handover",
            MakerToTakerMessage::LegacyPrivateKeyHandover(handover.clone()),
        ),
        (
            "taproot-data",
            MakerToTakerMessage::TaprootContractData(Box::new(taproot.clone())),
        ),
        (
            "taproot-handover",
            MakerToTakerMessage::TaprootPrivateKeyHandover(handover.clone()),
        ),
        ("unsupported", MakerToTakerMessage::Unsupported(unsupported)),
    ];
    for (name, message) in taker {
        write(release, &format!("wire-taker-{name}"), &message);
    }
    for (name, message) in maker {
        write(release, &format!("wire-maker-{name}"), &message);
    }
    for (name, message) in ln_taker {
        write(release, &format!("wire-ln-taker-{name}"), &message);
        write(
            release,
            &format!("wire-taker-lightning-{name}"),
            &TakerToMakerMessage::Lightning(Box::new(message)),
        );
    }
    for (name, message) in ln_maker {
        write(release, &format!("wire-ln-maker-{name}"), &message);
        write(
            release,
            &format!("wire-maker-lightning-{name}"),
            &MakerToTakerMessage::Lightning(Box::new(message)),
        );
    }
    for (name, message) in [
        (
            "sender-request",
            LegacyTakerMessage::ReqContractSigsForSender(sender),
        ),
        ("funding-proof", LegacyTakerMessage::ProofOfFunding(proof)),
        (
            "both-response",
            LegacyTakerMessage::RespContractSigsForRecvrAndSender(both_response),
        ),
        (
            "recvr-request",
            LegacyTakerMessage::ReqContractSigsForRecvr(recvr),
        ),
        (
            "handover",
            LegacyTakerMessage::PrivateKeyHandover(handover.clone()),
        ),
    ] {
        write(release, &format!("wire-legacy-{name}"), &message);
    }
    write(
        release,
        "wire-taproot-data",
        &TaprootTakerMessage::ContractData(Box::new(taproot)),
    );
    write(
        release,
        "wire-taproot-handover",
        &TaprootTakerMessage::PrivateKeyHandover(handover),
    );
    write(release, "wire-protocol-legacy", &ProtocolVersion::Legacy);
    write(release, "wire-protocol-taproot", &ProtocolVersion::Taproot);
    write(
        release,
        "wire-maker-ack-rejected",
        &MakerToTakerMessage::AckSwapDetails(AckSwapDetails::reject()),
    );
}

pub(super) fn check_release(release: &Path) {
    let old = release.file_name().unwrap() == "v0.2.3";
    for name in TAKER {
        let file = format!("wire-taker-{name}");
        if old
            && [
                "hello",
                "swap-details",
                "lightning-swap-in-request",
                "lightning-swap-out-request",
            ]
            .contains(name)
        {
            let bytes = fs::read(release.join(format!("{file}.cbor"))).unwrap();
            assert!(
                serde_cbor::from_slice::<TakerToMakerMessage>(&bytes).is_err(),
                "the approved handshake break unexpectedly changed: {}",
                file
            );
        } else {
            check::<TakerToMakerMessage>(release, &file);
        }
    }
    for name in MAKER {
        let file = format!("wire-maker-{name}");
        if old && *name == "hello" {
            let bytes = fs::read(release.join(format!("{file}.cbor"))).unwrap();
            assert!(serde_cbor::from_slice::<MakerToTakerMessage>(&bytes).is_err());
        } else {
            check::<MakerToTakerMessage>(release, &file);
        }
    }
    for name in LEGACY {
        check::<LegacyTakerMessage>(release, &format!("wire-legacy-{name}"));
    }
    for name in TAPROOT {
        check::<TaprootTakerMessage>(release, &format!("wire-taproot-{name}"));
    }
    for name in LN_TAKER {
        let file = format!("wire-ln-taker-{name}");
        if old && ["swap-in-request", "swap-out-request"].contains(name) {
            let bytes = fs::read(release.join(format!("{file}.cbor"))).unwrap();
            assert!(serde_cbor::from_slice::<LightningTakerMessage>(&bytes).is_err());
        } else {
            check::<LightningTakerMessage>(release, &file);
        }
    }
    for name in LN_MAKER {
        check::<LightningMakerMessage>(release, &format!("wire-ln-maker-{name}"));
    }
    for name in ["legacy", "taproot"] {
        check::<ProtocolVersion>(release, &format!("wire-protocol-{name}"));
    }
    let proof: FidelityProof = check(release, "wire-fidelity-proof");
    assert!(proof.bond.extra.is_empty());
    Secp256k1::new()
        .verify_ecdsa(
            &Message::from_digest(proof.cert_hash.to_byte_array()),
            &proof.cert_sig,
            &proof.bond.pubkey.inner,
        )
        .unwrap();
    let taproot: TakerToMakerMessage = check(release, "wire-taker-taproot-data");
    let TakerToMakerMessage::TaprootContractData(data) = taproot else {
        panic!("taproot fixture changed variant")
    };
    assert_eq!(data.tap_tweak_scalar(0).unwrap(), Scalar::ONE);
    let message: MakerToTakerMessage = check(release, "wire-maker-offer");
    let MakerToTakerMessage::Offer(offer) = message else {
        panic!("offer fixture changed variant")
    };
    assert!(offer.fidelity.bond.extra.is_empty());
    let cert_hash: sha256d::Hash = check(release, "wire-cert-hash");
    assert_eq!(
        offer
            .fidelity
            .bond
            .generate_cert_hash("fixture-maker.onion:21", &offer.tweakable_point),
        cert_hash
    );
}

#[test]
fn compat_fixtures_wire_frame_and_hello_prefix_are_frozen() {
    let release = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compat/v0.3.0");
    let body = fs::read(release.join("wire-taker-hello.cbor")).unwrap();
    assert_eq!(&body[..7], b"\xa1\x65Hello");
    let hello: TakerToMakerMessage = serde_cbor::from_slice(&body).unwrap();
    let current_body = serde_cbor::to_vec(&hello).unwrap();
    let expected_length = current_body.len();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut writer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let reader = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut prefix = [0; 4];
        socket.read_exact(&mut prefix).unwrap();
        assert_eq!(u32::from_be_bytes(prefix) as usize, expected_length);
        let mut payload = vec![0; expected_length];
        socket.read_exact(&mut payload).unwrap();
        (prefix, payload)
    });
    send_message(&mut writer, &hello).unwrap();
    let (prefix, payload) = reader.join().unwrap();
    assert_eq!(prefix, (current_body.len() as u32).to_be_bytes());
    assert_eq!(&payload[..7], &body[..7]);
    let hello: MakerToTakerMessage = serde_cbor::from_slice(&body).unwrap();
    let maker_bytes = serde_cbor::to_vec(&hello).unwrap();
    assert_eq!(&maker_bytes[..7], &body[..7]);
}
