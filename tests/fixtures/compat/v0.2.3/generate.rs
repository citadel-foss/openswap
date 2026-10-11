#[cfg(test)]
mod compat_fixture_generation {
    use super::*;
    use crate::{
        maker::swap_tracker::{
            MakerRecoveryPhase, MakerRecoveryState, MakerSwapPhase, MakerSwapRecord,
            MakerSwapTracker,
        },
        protocol::{
            contract::{create_contract_redeemscript, create_multisig_redeemscript},
            ProtocolVersion,
        },
        taker::swap_tracker::{RecoveryPhase, RecoveryState, SwapPhase, SwapRecord, SwapTracker},
        utill::redeemscript_to_scriptpubkey,
        wallet::{
            deniability::{verify_proof, DeniabilityProof},
            report::{SwapReportFile, SwapRole},
        },
    };
    use bitcoin::{
        absolute::LockTime,
        hashes::{hash160, Hash},
        secp256k1::{Secp256k1, SecretKey},
        transaction::Version,
        Amount, PublicKey, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    #[test]
    fn generate_v023_fixtures() {
        let directory = std::env::var("OPENSWAP_COMPAT_FIXTURES")
            .expect("set OPENSWAP_COMPAT_FIXTURES to an empty output directory");
        let out = Path::new(&directory);
        std::fs::create_dir_all(out).unwrap();
        let key = KeyMaterial::new_from_password(Some("compat-v023".into())).unwrap();
        let master = Xpriv::new_master(Network::Regtest, &[42; 32]).unwrap();
        let mut store = WalletStore::init(
            "closed.wallet".into(),
            &out.join("closed.wallet"),
            Network::Regtest,
            master,
            Some(100),
            &key,
        )
        .unwrap();
        store.external_index = 7;
        store.internal_index = 9;
        store.last_synced_height = Some(200);
        store
            .write_to_disk(&out.join("closed.wallet"), &key)
            .unwrap();
        store.external_index = 11;
        store
            .write_to_disk(&out.join("closed-newer.wallet"), &key)
            .unwrap();
        store.external_index = 7;
        let secp = Secp256k1::new();
        let multi = SecretKey::from_slice(&[1; 32]).unwrap();
        let other = SecretKey::from_slice(&[2; 32]).unwrap();
        let hashkey = SecretKey::from_slice(&[3; 32]).unwrap();
        let otherpub = PublicKey::new(other.public_key(&secp));
        let multisig =
            create_multisig_redeemscript(&PublicKey::new(multi.public_key(&secp)), &otherpub);
        let htlc = create_contract_redeemscript(
            &PublicKey::new(hashkey.public_key(&secp)),
            &otherpub,
            &hash160::Hash::hash(&[4; 32]),
            &20,
        );
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([5; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: redeemscript_to_scriptpubkey(&htlc).unwrap(),
            }],
        };
        let mut coin = IncomingSwapCoin::new_legacy(
            multi,
            otherpub,
            tx,
            htlc,
            hashkey,
            Amount::from_sat(100_000),
            1,
        );
        coin.swap_id = Some("v023-proof-swap".into());
        let mut proof = DeniabilityProof::from_incoming_swapcoin(
            &coin,
            SwapRole::Taker,
            Some(OutPoint::new(Txid::from_byte_array([6; 32]), 0)),
        )
        .unwrap();
        proof.created_at = 123;
        let chain_spk = redeemscript_to_scriptpubkey(&multisig).unwrap();
        verify_proof(&proof, &chain_spk).unwrap();
        std::fs::write(
            out.join("proof-chain-script.cbor"),
            serde_cbor::to_vec(&chain_spk).unwrap(),
        )
        .unwrap();
        std::fs::write(
            out.join("closed_swap_report.json"),
            serde_json::to_vec_pretty(&SwapReportFile {
                deniability_proofs: vec![proof],
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        store.incoming_swapcoins.insert("incoming".into(), coin);
        store.file_name = "open.wallet".into();
        store.write_to_disk(&out.join("open.wallet"), &key).unwrap();
        WalletStore::init(
            "sibling.wallet".into(),
            &out.join("sibling.wallet"),
            Network::Regtest,
            Xpriv::new_master(Network::Regtest, &[43; 32]).unwrap(),
            Some(110),
            &key,
        )
        .unwrap();
        std::fs::write(out.join("bad_swap_report.json"), b"{\"taker\":[").unwrap();
        let maker_dir = out.join("maker-tmp");
        std::fs::create_dir(&maker_dir).unwrap();
        let mut maker = MakerSwapTracker::load_or_create(&maker_dir).unwrap();
        let mut mr = MakerSwapRecord {
            swap_id: "maker-old".into(),
            protocol: ProtocolVersion::Legacy,
            phase: MakerSwapPhase::Completed,
            swap_amount_sat: 100_000,
            incoming_count: 1,
            outgoing_count: 1,
            funding_broadcast_txids: vec![],
            recovery: MakerRecoveryState::default(),
            created_at: 1,
            updated_at: 2,
        };
        mr.recovery.phase = MakerRecoveryPhase::CleanedUp;
        maker.save_record(&mr).unwrap();
        std::fs::rename(
            maker_dir.join("maker_swap_tracker.cbor"),
            out.join("maker-completed.cbor"),
        )
        .unwrap();
        mr.recovery.phase = MakerRecoveryPhase::Monitoring;
        maker.save_record(&mr).unwrap();
        std::fs::rename(
            maker_dir.join("maker_swap_tracker.cbor"),
            out.join("maker-incomplete.cbor"),
        )
        .unwrap();
        std::fs::remove_dir(maker_dir).unwrap();
        let taker_dir = out.join("taker-tmp");
        std::fs::create_dir(&taker_dir).unwrap();
        let mut taker = SwapTracker::load_or_create(&taker_dir).unwrap();
        let mut tr = SwapRecord {
            swap_id: "taker-old".into(),
            preimage: [4; 32],
            protocol: ProtocolVersion::Legacy,
            send_amount_sat: 100_000,
            maker_count: 1,
            phase: SwapPhase::Failed,
            failed_at_phase: None,
            failure_reason: None,
            makers: vec![],
            outgoing_contract_txids: vec![],
            incoming_contract_txids: vec![],
            watchonly_contract_txids: vec![],
            recovery: RecoveryState::default(),
            multisig_nonces: vec![],
            hashlock_nonces: vec![],
            payment_address: None,
            payment_amount_sat: None,
            created_at: 1,
            updated_at: 2,
        };
        tr.recovery.phase = RecoveryPhase::CleanedUp;
        taker.save_record(&tr).unwrap();
        std::fs::rename(
            taker_dir.join("swap_tracker.cbor"),
            out.join("taker-completed.cbor"),
        )
        .unwrap();
        tr.recovery.phase = RecoveryPhase::IncomingRecovered;
        taker.save_record(&tr).unwrap();
        std::fs::rename(
            taker_dir.join("swap_tracker.cbor"),
            out.join("taker-incomplete.cbor"),
        )
        .unwrap();
        std::fs::remove_dir(taker_dir).unwrap();

        for (original, filename, field, bad, is_maker) in [
            (
                "taker-completed.cbor",
                "taker-malformed.cbor",
                "recovery",
                serde_cbor::Value::Map(std::collections::BTreeMap::from([(
                    serde_cbor::Value::Text("phase".into()),
                    serde_cbor::Value::Integer(7),
                )])),
                false,
            ),
            (
                "maker-completed.cbor",
                "maker-malformed.cbor",
                "phase",
                serde_cbor::Value::Integer(7),
                true,
            ),
        ] {
            let mut data: serde_cbor::Value =
                serde_cbor::from_slice(&std::fs::read(out.join(original)).unwrap()).unwrap();
            let serde_cbor::Value::Map(fields) = &mut data else {
                panic!()
            };
            let serde_cbor::Value::Map(swaps) = fields
                .get_mut(&serde_cbor::Value::Text("swaps".into()))
                .unwrap()
            else {
                panic!()
            };
            let record = swaps.values_mut().next().unwrap();
            let serde_cbor::Value::Map(fields) = record else {
                panic!()
            };
            fields.insert(serde_cbor::Value::Text(field.into()), bad);
            if is_maker {
                assert!(serde_cbor::value::from_value::<MakerSwapRecord>(record.clone()).is_err());
            } else {
                assert!(serde_cbor::value::from_value::<SwapRecord>(record.clone()).is_err());
            }
            std::fs::write(out.join(filename), serde_cbor::to_vec(&data).unwrap()).unwrap();
        }
    }
}
