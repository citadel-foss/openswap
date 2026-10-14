#[cfg(test)]
mod compat_storage_fixture_generation {
    use super::*;
    use crate::{
        protocol::ProtocolVersion,
        wallet::{
            backup::WalletBackup,
            deniability::DeniabilityProof,
            report::{
                MakerFeeInfo, MakerReport, PaymentResult, RecoveryReport, ReportUtxo,
                SwapReportFile, SwapRole, SwapStatus, TakerReport,
            },
            swapcoin::PaymentTarget,
        },
    };
    use bitcoin::{
        absolute::LockTime,
        hashes::{sha256, Hash},
        secp256k1::{Message, Scalar, Secp256k1, SecretKey},
        Amount, CompressedPublicKey, PublicKey, Txid,
    };
    use std::collections::BTreeMap;
    fn populated_store() -> WalletStore {
        let dir = tempfile::tempdir().unwrap();
        let key = KeyMaterial::new_from_password(Some("fixture-password".into())).unwrap();
        let mut store = WalletStore::init(
            "fixture.wallet".into(),
            &dir.path().join("fixture.wallet"),
            Network::Regtest,
            Xpriv::new_master(Network::Regtest, &[42; 32]).unwrap(),
            Some(101),
            &key,
        )
        .unwrap();
        let (old, _) = WalletStore::read_from_disk(
            &Path::new(env!("OPENSWAP_V023_UPGRADE_FIXTURES")).join("open.wallet"),
            Some("compat-v023".into()),
        )
        .unwrap();
        let incoming = old.incoming_swapcoins.into_values().next().unwrap();
        let tx = incoming.contract_tx.clone();
        let script = incoming.contract_redeemscript.clone().unwrap();
        let mine = incoming.my_privkey.unwrap();
        let other = incoming.other_pubkey.unwrap();
        let secp = Secp256k1::new();
        let pubkey = PublicKey::new(mine.public_key(&secp));
        let point = OutPoint::new(tx.compute_txid(), 0);
        let signature = bitcoin::ecdsa::Signature::sighash_all(
            secp.sign_ecdsa(&Message::from_digest([7; 32]), &mine),
        );
        store.external_index = 7;
        store.internal_index = 11;
        store.offer_maxsize = 123_456;
        store.wallet_birthday = Some(101);
        store.last_synced_height = Some(202);
        store.prevout_to_contract_map.insert(point, script.clone());
        store.swept_incoming_swapcoins.insert(script.clone());
        store.fidelity_bond.push(FidelityBond {
            outpoint: point,
            amount: Amount::from_sat(100_000),
            lock_time: LockTime::from_height(900_000).unwrap(),
            pubkey,
            conf_height: Some(800_000),
            is_spent: true,
            bond_index: 7,
            tx: Some(tx.clone()),
        });
        store.swap_locks.insert(
            "fixture-swap".into(),
            SwapReservation {
                outpoints: HashSet::from([point]),
                reserved_at: 123,
            },
        );
        for protocol in [ProtocolVersion::Legacy, ProtocolVersion::Taproot] {
            let name = format!("{protocol:?}");
            let mut incoming = incoming.clone();
            incoming.protocol = protocol;
            incoming.other_privkey = Some(SecretKey::from_slice(&[2; 32]).unwrap());
            incoming.contract_txid = Some(tx.compute_txid());
            incoming.hash_preimage = Some([4; 32]);
            incoming.swap_id = Some(name.clone());
            incoming.hashlock_script = Some(script.clone());
            incoming.timelock_script = Some(script.clone());
            incoming.others_contract_sig = Some(signature);
            incoming.tap_tweak = Some(Scalar::ONE);
            incoming.internal_key = Some(pubkey.inner.x_only_public_key().0);
            incoming.spending_tx = Some(tx.clone());
            incoming.payment_target = Some(PaymentTarget {
                script_pubkey: script.clone(),
                amount: Amount::from_sat(90_000),
            });
            incoming.negotiated_feerate = 3;
            let mut outgoing = OutgoingSwapCoin::new_legacy(
                mine,
                other,
                tx.clone(),
                script.clone(),
                mine,
                Amount::from_sat(100_000),
                3,
            );
            outgoing.protocol = protocol;
            outgoing.other_privkey = incoming.other_privkey;
            outgoing.funding_tx = Some(tx.clone());
            outgoing.hash_preimage = Some([4; 32]);
            outgoing.swap_id = Some(name.clone());
            outgoing.hashlock_script = Some(script.clone());
            outgoing.timelock_script = Some(script.clone());
            outgoing.others_contract_sig = Some(signature);
            outgoing.tap_tweak = Some(Scalar::ONE);
            outgoing.internal_key = incoming.internal_key;
            outgoing.recovery_address = Some(
                bitcoin::Address::p2wpkh(&CompressedPublicKey(pubkey.inner), Network::Regtest)
                    .as_unchecked()
                    .clone(),
            );
            let mut watchonly = WatchOnlySwapCoin::new_legacy(
                pubkey,
                other,
                tx.clone(),
                script.clone(),
                Amount::from_sat(100_000),
            );
            watchonly.protocol = protocol;
            watchonly.hashlock_script = Some(script.clone());
            watchonly.timelock_script = Some(script.clone());
            store.incoming_swapcoins.insert(name.clone(), incoming);
            store.outgoing_swapcoins.insert(name.clone(), outgoing);
            store.watchonly_swapcoins.insert(name, vec![watchonly]);
        }
        for (index, info) in [
            UTXOSpendInfo::SeedCoin {
                path: "m/84'/1'/0'/0/7".into(),
                input_value: Amount::from_sat(100_000),
                address_type: AddressType::P2WPKH,
            },
            UTXOSpendInfo::SeedCoin {
                path: "m/86'/1'/0'/0/7".into(),
                input_value: Amount::from_sat(100_000),
                address_type: AddressType::P2TR,
            },
            UTXOSpendInfo::IncomingSwapCoin {
                multisig_redeemscript: script.clone(),
            },
            UTXOSpendInfo::OutgoingSwapCoin {
                multisig_redeemscript: script.clone(),
            },
            UTXOSpendInfo::TimelockContract {
                swapcoin_multisig_redeemscript: script.clone(),
                input_value: Amount::from_sat(100_000),
            },
            UTXOSpendInfo::HashlockContract {
                swapcoin_multisig_redeemscript: script.clone(),
                input_value: Amount::from_sat(100_000),
            },
            UTXOSpendInfo::FidelityBondCoin {
                index: 7,
                input_value: Amount::from_sat(100_000),
            },
            UTXOSpendInfo::SweptCoin {
                path: "m/84'/1'/0'/0/7".into(),
                input_value: Amount::from_sat(100_000),
                address_type: AddressType::P2WPKH,
            },
            UTXOSpendInfo::SweptCoin {
                path: "m/86'/1'/0'/0/7".into(),
                input_value: Amount::from_sat(100_000),
                address_type: AddressType::P2TR,
            },
        ]
        .iter()
        .enumerate()
        {
            let point = OutPoint::new(Txid::from_byte_array([5; 32]), index as u32);
            let entry = ListUnspentResultEntry {
                txid: point.txid,
                vout: point.vout,
                address: Some(
                    bitcoin::Address::p2wpkh(&CompressedPublicKey(pubkey.inner), Network::Regtest)
                        .as_unchecked()
                        .clone(),
                ),
                label: Some("fixture".into()),
                redeem_script: Some(script.clone()),
                witness_script: Some(script.clone()),
                script_pub_key: script.clone(),
                amount: Amount::from_sat(100_000),
                confirmations: 7,
                spendable: true,
                solvable: true,
                descriptor: Some("fixture-descriptor".into()),
                safe: true,
            };
            store.utxo_cache.insert(point, (entry, info.clone()));
        }
        for is_swap_in in [true, false] {
            store.ln_pending_swaps.insert(
                format!("pending-{is_swap_in}"),
                LnPendingSwap {
                    is_swap_in,
                    preimage: Some([4; 32]),
                    redeemscript: script.clone(),
                    locktime: 20,
                    privkey: mine,
                    outpoint: Some(point),
                    value: Some(Amount::from_sat(100_000)),
                },
            );
        }
        for (direction, phase) in [
            (LnMakerDirection::SwapIn, LnMakerPhase::InAccepted),
            (LnMakerDirection::SwapIn, LnMakerPhase::InPaid),
            (LnMakerDirection::SwapIn, LnMakerPhase::InSwept),
            (LnMakerDirection::SwapOut, LnMakerPhase::OutAccepted),
            (LnMakerDirection::SwapOut, LnMakerPhase::OutFunded),
        ] {
            store.ln_maker_swaps.insert(
                format!("{phase:?}"),
                LnMakerSwapRecord {
                    direction,
                    phase,
                    payment_hash: sha256::Hash::hash(&[4; 32]),
                    amount: Amount::from_sat(100_000),
                    fee: Amount::from_sat(1_000),
                    locktime: 20,
                    min_confirmations: 3,
                    redeemscript: script.clone(),
                    privkey: mine,
                    invoice: "fixture-invoice".into(),
                    preimage: Some([4; 32]),
                    refund_txid: Some(point.txid),
                    accepted_height: Some(123),
                    payout_script: Some(script.clone()),
                    funding_outpoint: Some(point),
                    funding_value: Some(Amount::from_sat(101_000)),
                    funding_height: Some(125),
                },
            );
        }
        store
    }

    fn reports() -> SwapReportFile {
        let proof: SwapReportFile = serde_json::from_slice(include_bytes!(concat!(
            env!("OPENSWAP_V023_UPGRADE_FIXTURES"),
            "/closed_swap_report.json"
        )))
        .unwrap();
        let proof = proof.deniability_proofs[0].clone();
        let utxo = ReportUtxo {
            address: "bcrt1-fixture".into(),
            value: 123_456,
        };
        let taker = TakerReport {
            swap_id: "fixture-swap".into(),
            status: SwapStatus::Success,
            network: "regtest".into(),
            swap_duration_seconds: 2.5,
            start_timestamp: 100,
            end_timestamp: 103,
            error_message: Some("fixture error".into()),
            outgoing_amount: 123_456,
            incoming_amount: 120_000,
            fee_paid: 3_456,
            mining_fee: 123,
            fee_percentage: 2.5,
            total_maker_fees: 3_333,
            outgoing_utxos: vec![utxo.clone()],
            incoming_utxos: vec![utxo.clone()],
            funding_txids: vec![vec!["funding-tx".into()]],
            makers_count: 1,
            maker_addresses: vec!["maker-fixture".into()],
            maker_fee_info: vec![MakerFeeInfo {
                maker_index: 1,
                maker_address: "maker-fixture".into(),
                base_fee: 1.5,
                amount_relative_fee: 2.5,
                time_relative_fee: 3.5,
                total_fee: 7.5,
            }],
            input_utxos: vec![123_456],
            output_change_amounts: vec![20_000],
            output_swap_amounts: vec![100_000],
            output_change_utxos: vec![(20_000, "change-address".into())],
            output_swap_utxos: vec![(100_000, "swap-address".into())],
            deniability_proof: Some(proof.clone()),
            payment: Some(PaymentResult {
                receiver_address: "receiver-address".into(),
                requested_amount: 120_000,
                delivered_amount: 120_000,
                settlement_txids: vec!["settlement-tx".into()],
                confirmed: true,
            }),
        };
        let maker = MakerReport {
            swap_id: "fixture-swap".into(),
            status: SwapStatus::Success,
            network: "regtest".into(),
            swap_duration_seconds: 2.5,
            start_timestamp: 100,
            end_timestamp: 103,
            incoming_amount: 123_456,
            outgoing_amount: 120_000,
            fee_earned: 3_456,
            incoming_utxos: vec![utxo.clone()],
            outgoing_utxos: vec![utxo],
            timelock: 20,
            deniability_proof: Some(proof.clone()),
        };
        let statuses = [
            SwapStatus::Success,
            SwapStatus::RecoveryHashlock,
            SwapStatus::RecoveryTimelock,
            SwapStatus::Failed,
        ];
        SwapReportFile {
            taker: statuses
                .iter()
                .map(|status| {
                    let mut report = taker.clone();
                    report.status = status.clone();
                    report
                })
                .collect(),
            maker: HashMap::from([(
                "fixture-maker".into(),
                statuses
                    .iter()
                    .map(|status| {
                        let mut report = maker.clone();
                        report.status = status.clone();
                        report
                    })
                    .collect(),
            )]),
            recovery: [SwapRole::Maker, SwapRole::Taker]
                .iter()
                .map(|role| RecoveryReport {
                    swap_id: "fixture-swap".into(),
                    role: *role,
                    node: Some("fixture-node".into()),
                    recovery_type: "timelock".into(),
                    recovery_txids: vec!["recovery-tx".into()],
                    network: "regtest".into(),
                    timestamp: 123,
                })
                .collect(),
            deniability_proofs: vec![proof],
        }
    }

    fn write<T: Serialize>(release: &Path, name: &str, value: &T) {
        std::fs::write(
            release.join(format!("{name}.cbor")),
            serde_cbor::to_vec(value).unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn generate_storage_release_v023() {
        let directory =
            std::env::var("OPENSWAP_COMPAT_FIXTURES").expect("set the fixture output directory");
        let release = Path::new(&directory);
        let store = populated_store();
        write(release, "wallet-store", &store);
        let (closed, key) = WalletStore::read_from_disk(
            &Path::new(env!("OPENSWAP_V023_UPGRADE_FIXTURES")).join("closed.wallet"),
            Some("compat-v023".into()),
        )
        .unwrap();
        write(release, "wallet-closed", &closed);
        let (open, _) = WalletStore::read_from_disk(
            &Path::new(env!("OPENSWAP_V023_UPGRADE_FIXTURES")).join("open.wallet"),
            Some("compat-v023".into()),
        )
        .unwrap();
        write(release, "wallet-open", &open);
        let backup = WalletBackup {
            network: Network::Regtest,
            master_key: closed.master_key.plaintext_with(&key.unwrap()).unwrap(),
            wallet_birthday: Some(101),
            file_name: "fixture.wallet".into(),
        };
        write(release, "backup-wallet", &backup);
        write(release, "bond-fidelity", &store.fidelity_bond[0]);
        write(
            release,
            "storage-reservation",
            &store.swap_locks["fixture-swap"],
        );
        for (name, coin) in &store.incoming_swapcoins {
            write(release, &format!("coin-incoming-{name}"), coin);
        }
        for (name, coin) in &store.outgoing_swapcoins {
            write(release, &format!("coin-outgoing-{name}"), coin);
        }
        for (name, coins) in &store.watchonly_swapcoins {
            write(release, &format!("coin-watchonly-{name}"), &coins[0]);
        }
        for (name, record) in &store.ln_maker_swaps {
            write(release, &format!("storage-ln-maker-{name}"), record);
        }
        for (name, record) in &store.ln_pending_swaps {
            write(release, &format!("storage-ln-{name}"), record);
        }
        for (point, entry) in &store.utxo_cache {
            write(release, &format!("storage-cache-{}", point.vout), entry);
        }
        let mut report = reports();
        report.deniability_proofs.push(
            DeniabilityProof::from_incoming_swapcoin(
                &store.incoming_swapcoins["Taproot"],
                SwapRole::Taker,
                Some(OutPoint::new(Txid::from_byte_array([6; 32]), 0)),
            )
            .unwrap(),
        );
        write(release, "report-file", &report);
        for (i, r) in report.taker.iter().enumerate() {
            write(release, &format!("report-taker-{i}"), r);
        }
        for (i, r) in report.maker.values().flatten().enumerate() {
            write(release, &format!("report-maker-{i}"), r);
        }
        for (i, r) in report.recovery.iter().enumerate() {
            write(release, &format!("report-recovery-{i}"), r);
        }
        for (i, r) in report.deniability_proofs.iter().enumerate() {
            write(release, &format!("report-proof-{i}"), r);
        }
        write(
            release,
            "report-payment",
            report.taker[0].payment.as_ref().unwrap(),
        );
        write(release, "report-utxo", &report.taker[0].outgoing_utxos[0]);
        write(release, "report-fee", &report.taker[0].maker_fee_info[0]);
    }
}
