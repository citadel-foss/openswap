use super::*;

#[cfg(test)]
mod utxo_corroboration_tests {
    use super::*;
    use bitcoin::{absolute::LockTime, hashes::Hash, transaction::Version};
    use bitcoind::tempfile::tempdir;

    fn entry_for(
        tx: &Transaction,
        vout: u32,
        spk: ScriptBuf,
        amount: Amount,
    ) -> ListUnspentResultEntry {
        ListUnspentResultEntry {
            txid: tx.compute_txid(),
            vout,
            address: None,
            label: None,
            redeem_script: None,
            witness_script: None,
            script_pub_key: spk,
            amount,
            confirmations: 1,
            spendable: true,
            solvable: true,
            descriptor: None,
            safe: true,
        }
    }

    #[test]
    fn fabricated_utxo_fails_corroboration() {
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let value = Amount::from_sat(1000);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value,
                script_pubkey: spk.clone(),
            }],
        };

        // Honest report passes.
        assert!(utxo_matches_tx(&tx, &entry_for(&tx, 0, spk.clone(), value)));
        // Wrong value.
        assert!(!utxo_matches_tx(
            &tx,
            &entry_for(&tx, 0, spk.clone(), Amount::from_sat(2000))
        ));
        // Wrong script.
        assert!(!utxo_matches_tx(
            &tx,
            &entry_for(&tx, 0, ScriptBuf::from_bytes(vec![0x52]), value)
        ));
        // Non-existent output index.
        assert!(!utxo_matches_tx(
            &tx,
            &entry_for(&tx, 1, spk.clone(), value)
        ));
        // Txid that does not hash to the fetched transaction.
        let mut lying = entry_for(&tx, 0, spk, value);
        lying.txid = Txid::all_zeros();
        assert!(!utxo_matches_tx(&tx, &lying));
    }

    #[test]
    fn cached_utxo_refresh_preserves_transaction_value_and_script() {
        let dir = tempdir().unwrap();
        let mut wallet = super::test_support::test_wallet(&dir.path().join("cache-test-wallet"));
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let amount = Amount::from_sat(1_000);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: amount,
                script_pubkey: script.clone(),
            }],
        };
        let original = entry_for(&tx, 0, script.clone(), amount);
        let outpoint = OutPoint::new(original.txid, original.vout);
        wallet.store.utxo_cache.insert(
            outpoint,
            (
                original.clone(),
                UTXOSpendInfo::SeedCoin {
                    path: "m/0/0".into(),
                    input_value: amount,
                    address_type: AddressType::P2WPKH,
                },
            ),
        );
        let mut refreshed = original;
        refreshed.amount = Amount::from_sat(2_000);
        refreshed.script_pub_key = ScriptBuf::from_bytes(vec![0x52]);
        refreshed.confirmations = 6;

        wallet.update_utxo_cache(vec![refreshed]).unwrap();

        let (cached, _) = &wallet.store.utxo_cache[&outpoint];
        assert_eq!(cached.amount, amount);
        assert_eq!(cached.script_pub_key, script);
        assert_eq!(cached.confirmations, 6);
    }
}

/// Fixtures shared by unit tests that never reach the backend.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::wallet::blockchain::{BackendConfig, CoreRpcConfig};

    /// Regtest wallet with an empty UTXO cache, so coin selection fails
    /// locally instead of calling out to a node.
    pub(crate) fn test_wallet(path: &Path) -> Wallet {
        test_wallet_with_key(
            path,
            Xpriv::new_master(bitcoin::Network::Regtest, &[42; 32]).unwrap(),
        )
    }

    /// Like [`test_wallet`], with `master_key` and no stored seed phrase.
    pub(crate) fn test_wallet_with_key(path: &Path, master_key: Xpriv) -> Wallet {
        let enc_material =
            KeyMaterial::new_from_password(Some("test-password".to_string())).unwrap();
        let store = WalletStore::init(
            "prevout-contract-test".to_string(),
            path,
            bitcoin::Network::Regtest,
            master_key,
            None,
            None,
            &enc_material,
        )
        .unwrap();

        let blockchain =
            AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default())).unwrap();

        Wallet {
            blockchain,
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material: enc_material,
            locked_utxos: HashSet::new(),
            _in_use: None,
        }
    }
}

#[cfg(test)]
mod coin_select_cap_tests {
    use super::{test_support::test_wallet, *};
    use crate::utill::MIN_RELAY_FEE_RATE;
    use bitcoind::tempfile::tempdir;

    #[test]
    fn coin_select_rejects_amounts_above_the_cap() {
        let dir = tempdir().unwrap();
        let wallet = test_wallet(&dir.path().join("cap-test-wallet"));

        // `target + fee` inside coin_select is plain u64 arithmetic.
        for amount in [
            Amount::from_sat(u64::MAX),
            Amount::MAX_MONEY + Amount::ONE_SAT,
        ] {
            let err = wallet
                .coin_select(amount, MIN_RELAY_FEE_RATE, AddressType::P2WPKH, None, None)
                .unwrap_err();
            assert!(
                format!("{:?}", err).contains("21M"),
                "{} sats must trip the cap: {:?}",
                amount.to_sat(),
                err
            );
        }

        // The cap itself is spendable as far as this check is concerned, so a
        // `>=` here would be wrong; it fails later for want of funds.
        let err = wallet
            .coin_select(
                Amount::MAX_MONEY,
                MIN_RELAY_FEE_RATE,
                AddressType::P2WPKH,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, WalletError::InsufficientFund { .. }),
            "the cap itself must reach coin selection, not the guard: {:?}",
            err
        );
    }
}

#[cfg(test)]
mod swap_reservation_tests {
    use super::{test_support::test_wallet, *};
    use bitcoin::hashes::Hash;
    use bitcoind::tempfile::tempdir;

    fn outpoint(n: u8) -> OutPoint {
        OutPoint::new(Txid::from_slice(&[n; 32]).unwrap(), 0)
    }

    #[test]
    fn a_reservation_survives_a_wallet_reload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.cbor");
        let reserved = outpoint(1);

        {
            let mut wallet = test_wallet(&path);
            wallet.reserve_swap_locks("swap-1", &[reserved]);
            assert!(wallet.is_swap_reserved(&reserved));
            wallet.save_to_disk().unwrap();
        }

        // A restarted maker must still refuse these inputs to another swap:
        // the funding it planned them for can still reach the network.
        let (store, _) =
            WalletStore::read_from_disk(&path, Some("test-password".to_string())).unwrap();
        let locks = store
            .swap_locks
            .get("swap-1")
            .expect("the reservation must outlive the process that took it");
        assert!(locks.outpoints.contains(&reserved));
        assert!(!locks.outpoints.contains(&outpoint(2)));
        assert!(locks.reserved_at > 0, "the lock time must be persisted too");
    }

    #[test]
    fn only_a_spendable_coin_no_swap_holds_can_be_claimed() {
        let dir = tempdir().unwrap();
        let mut wallet = test_wallet(&dir.path().join("wallet.cbor"));
        let coin = outpoint(3);
        let amount = Amount::from_sat(50_000);
        wallet.store.utxo_cache.insert(
            coin,
            (
                ListUnspentResultEntry {
                    txid: coin.txid,
                    vout: coin.vout,
                    address: None,
                    label: None,
                    redeem_script: None,
                    witness_script: None,
                    script_pub_key: ScriptBuf::from_bytes(vec![0x51]),
                    amount,
                    confirmations: 1,
                    spendable: true,
                    solvable: true,
                    descriptor: None,
                    safe: true,
                },
                UTXOSpendInfo::SeedCoin {
                    path: "m/0/0".into(),
                    input_value: amount,
                    address_type: AddressType::P2WPKH,
                },
            ),
        );

        assert!(
            !wallet.claim_swap_inputs("swap-a", &[outpoint(4)]),
            "not a wallet coin"
        );
        assert_eq!(wallet.plannable_balance(), amount);
        assert!(wallet.claim_swap_inputs("swap-a", &[coin]));
        assert_eq!(
            wallet.plannable_balance(),
            Amount::ZERO,
            "a claimed coin is not available to plan"
        );
        assert!(
            !wallet.claim_swap_inputs("swap-b", &[coin]),
            "held by another swap"
        );
        assert!(!wallet.store.swap_locks.contains_key("swap-b"));

        assert!(
            wallet.claim_or_hold_swap_inputs("swap-a", &[coin]),
            "a swap's own claim does not block it"
        );
        assert!(
            !wallet.claim_or_hold_swap_inputs("swap-b", &[coin]),
            "another swap's claim does"
        );
        assert!(
            !wallet.claim_or_hold_swap_inputs("swap-a", &[coin, outpoint(4)]),
            "a claim that does not cover every input is not held"
        );
        assert!(
            !wallet.store.swap_locks["swap-a"]
                .outpoints
                .contains(&outpoint(4)),
            "a refused claim reserves nothing"
        );
        assert!(!wallet.store.swap_locks.contains_key("swap-b"));
    }
}

#[cfg(test)]
mod prevout_contract_tests {
    use super::{test_support::test_wallet, *};
    use bitcoind::tempfile::tempdir;

    #[test]
    fn proof_of_funding_rejects_missing_cached_contract() {
        let temp_dir = tempdir().unwrap();
        let wallet = test_wallet(&temp_dir.path().join("wallet.cbor"));

        let error = wallet
            .ensure_prevout_matches_cached_contract(
                &OutPoint::null(),
                ScriptBuf::from_bytes(vec![0x51]).as_script(),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            WalletError::General(message) if message.contains("No cached sender contract")
        ));
    }

    #[test]
    fn cached_contract_matches_only_the_approved_script() {
        let temp_dir = tempdir().unwrap();
        let mut wallet = test_wallet(&temp_dir.path().join("wallet.cbor"));
        let prevout = OutPoint::null();
        let approved_contract = ScriptBuf::from_bytes(vec![0x51]);
        let different_contract = ScriptBuf::from_bytes(vec![0x52]);

        wallet
            .cache_prevout_to_contract(&[(prevout, approved_contract.clone())])
            .unwrap();

        wallet
            .ensure_prevout_matches_cached_contract(&prevout, approved_contract.as_script())
            .unwrap();
        assert!(wallet
            .ensure_prevout_matches_cached_contract(&prevout, different_contract.as_script())
            .is_err());
    }

    #[test]
    fn cached_contract_is_idempotent_immutable_and_persistent() {
        let temp_dir = tempdir().unwrap();
        let wallet_path = temp_dir.path().join("wallet.cbor");
        let mut wallet = test_wallet(&wallet_path);
        let prevout = OutPoint::null();
        let new_prevout = OutPoint {
            txid: prevout.txid,
            vout: 1,
        };
        let approved_contract = ScriptBuf::from_bytes(vec![0x51]);

        wallet
            .cache_prevout_to_contract(&[(prevout, approved_contract.clone())])
            .unwrap();
        wallet
            .cache_prevout_to_contract(&[(prevout, approved_contract.clone())])
            .unwrap();
        assert!(wallet
            .cache_prevout_to_contract(&[
                (new_prevout, ScriptBuf::from_bytes(vec![0x53])),
                (prevout, ScriptBuf::from_bytes(vec![0x52])),
            ])
            .is_err());
        assert!(!wallet
            .store
            .prevout_to_contract_map
            .contains_key(&new_prevout));

        let (reloaded_store, _) =
            WalletStore::read_from_disk(&wallet_path, Some("test-password".to_string())).unwrap();
        assert_eq!(
            reloaded_store.prevout_to_contract_map.get(&prevout),
            Some(&approved_contract)
        );
    }
}

#[cfg(test)]
mod restore_history_probe_tests {
    use super::*;
    use crate::{
        security::{load_sensitive_struct, SerdeJson},
        wallet::{
            blockchain::Electrum, ffi::restore_wallet_from_backup_gui_app, storage::SecretEntropy,
            BackendConfig, WalletBackup,
        },
    };
    use bitcoin::{
        consensus::encode::serialize_hex,
        hashes::{sha256, Hash},
    };
    use bitcoind::tempfile::tempdir;
    use std::{
        collections::HashSet as StdHashSet,
        io::{BufRead, BufReader, Write as IoWrite},
        net::TcpListener,
    };
    use zeroize::Zeroizing;

    const MASTER_SEED: [u8; 32] = [42; 32];

    fn scripthash_hex(script: &Script) -> String {
        let mut hash = sha256::Hash::hash(script.as_bytes()).to_byte_array();
        hash.reverse();
        hash.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The smallest Electrum server that `Electrum::new` and a history probe need:
    /// a handshake, plus a scripted `get_history` answer per scripthash.
    fn start_stub(with_history: StdHashSet<String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = genesis.block_hash().to_string();
        let header_hex = serialize_hex(&genesis.header);
        // Restore lists the history's transactions, so the stub must serve one.
        let history_tx = genesis.txdata[0].clone();
        let history_txid = history_tx.compute_txid().to_string();
        let history_tx_hex = serialize_hex(&history_tx);

        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { continue };
                // Each probe is one tiny request/reply, so Nagle would add its
                // delay to every single one of them.
                let _ = stream.set_nodelay(true);
                let (hash, header) = (genesis_hash.clone(), header_hex.clone());
                let (txid, tx_hex) = (history_txid.clone(), history_tx_hex.clone());
                let known = with_history.clone();
                thread::spawn(move || {
                    let mut out = stream.try_clone().expect("clone stub stream");
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { return };
                        let req: Value = match serde_json::from_str(&line) {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        let id = req["id"].clone();
                        let result = match req["method"].as_str().unwrap_or_default() {
                            "server.features" => json!({
                                "server_version": "stub",
                                "genesis_hash": hash,
                                "protocol_min": "1.4",
                                "protocol_max": "1.4",
                                "hash_function": "sha256",
                                "pruning": Value::Null,
                            }),
                            "blockchain.headers.subscribe" => {
                                json!({"height": 0, "hex": header})
                            }
                            "blockchain.scripthash.get_history" => {
                                let sh = req["params"][0].as_str().unwrap_or_default();
                                if known.contains(sh) {
                                    json!([{"height": 1, "tx_hash": txid}])
                                } else {
                                    json!([])
                                }
                            }
                            "blockchain.scripthash.listunspent" => json!([]),
                            "blockchain.transaction.get" => json!(tx_hex),
                            _ => json!(Value::Null),
                        };
                        let resp = json!({"jsonrpc": "2.0", "id": id, "result": result});
                        if writeln!(out, "{resp}").is_err() {
                            return;
                        }
                    }
                });
            }
        });

        url
    }

    fn account_for(seed: &[u8], address_type: AddressType) -> Xpub {
        let secp = crate::utill::global_secp();
        let master = Xpriv::new_master(bitcoin::Network::Regtest, seed).unwrap();
        let account = master
            .derive_priv(
                secp,
                &Wallet::get_derivation_path(address_type, bitcoin::Network::Regtest),
            )
            .unwrap();
        Xpub::from_priv(secp, &account)
    }

    fn electrum_config(url: String) -> crate::wallet::ElectrumConfig {
        crate::wallet::ElectrumConfig {
            url,
            ..Default::default()
        }
    }

    fn stub_wallet(path: &Path, url: String) -> Wallet {
        let master_key = Xpriv::new_master(bitcoin::Network::Regtest, &MASTER_SEED).unwrap();
        let enc_material = KeyMaterial::new_ephemeral();
        let store = WalletStore::init(
            "restore-probe-test".to_string(),
            path,
            bitcoin::Network::Regtest,
            master_key,
            None,
            Some(RestoreOptions::default()),
            &enc_material,
        )
        .unwrap();
        let electrum = Electrum::new(&electrum_config(url)).expect("connect to stub");

        Wallet {
            blockchain: AnyBlockchain::Electrum(electrum),
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material: enc_material,
            locked_utxos: HashSet::new(),
            _in_use: None,
        }
    }

    /// A restored wallet holds no UTXOs and no hand-out counters, so only script
    /// history can reveal index 60. The gap between it and index 0 is far wider
    /// than the regular 20, and the two indices use different address types.
    #[test]
    fn restore_probe_bridges_a_long_run_of_emptied_addresses() {
        let temp_dir = tempdir().unwrap();
        let external = KeychainKind::External;
        let funded = |address_type, index| {
            let account = account_for(&MASTER_SEED, address_type);
            let script =
                derive_child_script(&account, address_type, external, index).expect("derive");
            scripthash_hex(&script)
        };
        let with_history = StdHashSet::from([
            funded(AddressType::P2WPKH, 0),
            funded(AddressType::P2TR, 60),
        ]);

        let url = start_stub(with_history);
        let mut wallet = stub_wallet(&temp_dir.path().join("wallet.cbor"), url);

        assert_eq!(
            wallet.find_hd_next_index(external).unwrap(),
            61,
            "history probing must reach the P2TR-only index past the hole"
        );

        // The hole is 59 unused addresses: a gap of 60 bridges it, 59 does not.
        for (address_gap, expected) in [(60, 61), (59, 1)] {
            wallet.store.pending_restore = Some(RestoreOptions {
                address_gap,
                ..Default::default()
            });
            let next = wallet.find_hd_next_index(external).unwrap();
            assert_eq!(next, expected, "gap {address_gap}");
        }

        // Without the restore flag the probe is off and the empty UTXO set decides.
        wallet.store.pending_restore = None;
        assert_eq!(wallet.find_hd_next_index(external).unwrap(), 0);
    }

    /// The probe stops at the cap. A full empty run ending exactly on it passes;
    /// one address short, it reports the cap instead of missing coins past it.
    /// A cached coin starts the probe near the cap, so the run stays short.
    #[test]
    fn restore_probe_reports_a_window_cut_off_by_the_cap() {
        let temp_dir = tempdir().unwrap();
        let external = KeychainKind::External;
        let gap = ADDRESS_IMPORT_COUNT;
        for (next, expected) in [
            (MAX_WATCH_WINDOW - gap + 1, Ok(MAX_WATCH_WINDOW - gap + 1)),
            (MAX_WATCH_WINDOW - gap + 2, Err(MAX_WATCH_WINDOW + 1)),
        ] {
            let url = start_stub(StdHashSet::new());
            let mut wallet = stub_wallet(&temp_dir.path().join(format!("w{next}")), url);
            wallet.store.pending_restore = Some(RestoreOptions {
                address_gap: gap,
                ..Default::default()
            });
            let coin = ListUnspentResultEntry {
                txid: bitcoin::Txid::all_zeros(),
                vout: 0,
                address: None,
                label: None,
                redeem_script: None,
                witness_script: None,
                script_pub_key: ScriptBuf::new(),
                amount: Amount::from_sat(1_000),
                confirmations: 1,
                spendable: true,
                solvable: true,
                descriptor: Some(format!("wpkh([00000000/0/{}])", next - 1)),
                safe: true,
            };
            let spend = UTXOSpendInfo::SeedCoin {
                path: format!("m/0/{}", next - 1),
                input_value: coin.amount,
                address_type: AddressType::P2WPKH,
            };
            wallet
                .store
                .utxo_cache
                .insert(OutPoint::new(coin.txid, 0), (coin, spend));
            match (wallet.find_hd_next_index(external), expected) {
                (Ok(got), Ok(want)) => assert_eq!(got, want),
                (Err(WalletError::WatchWindowCap { window, cap }), Err(want)) => {
                    assert_eq!((window, cap), (want, MAX_WATCH_WINDOW))
                }
                (got, want) => panic!("next {}: got {:?}, want {:?}", next, got, want),
            }
        }
    }

    /// A restore resumed from a file never passed the start check, so the
    /// first sync pass must reject a window already past the cap.
    #[test]
    fn resumed_restore_checks_the_window_before_syncing() {
        let temp_dir = tempdir().unwrap();
        let url = start_stub(StdHashSet::new());
        let mut wallet = stub_wallet(&temp_dir.path().join("wallet.cbor"), url);
        wallet.store.external_index = MAX_WATCH_WINDOW - 50;
        assert!(matches!(
            wallet.sync_no_rescan(&crate::utill::NO_SHUTDOWN),
            Err(WalletError::WatchWindowCap { window, .. }) if window == MAX_WATCH_WINDOW + 49
        ));
    }

    /// A window past the cap or a too-old Core is final: `sync_no_fail` must
    /// not retry it forever.
    #[test]
    fn window_cap_and_old_core_are_not_retried() {
        let cap = WalletError::WatchWindowCap {
            window: MAX_WATCH_WINDOW + 1,
            cap: MAX_WATCH_WINDOW,
        };
        assert!(Wallet::sync_error_is_final(&cap));
        assert!(Wallet::sync_error_is_final(&WalletError::CoreTooOld));
        assert!(!Wallet::sync_error_is_final(&WalletError::General(
            "rpc down".into()
        )));
    }

    /// A file from an older restore has no saved options and resumes at the
    /// default gap of 100, which misses index 150; the saved gap of 200 finds it.
    #[test]
    fn interrupted_restore_finishes_before_wallet_is_loaded() {
        let script = derive_child_script(
            &account_for(&MASTER_SEED, AddressType::P2TR),
            AddressType::P2TR,
            KeychainKind::External,
            150,
        )
        .unwrap();
        let wider = RestoreOptions {
            address_gap: 200,
            ..Default::default()
        };
        for (pending_restore, expected) in [(None, 0), (Some(wider), 151)] {
            let temp_dir = tempdir().unwrap();
            let path = temp_dir.path().join("restore-probe-test");
            let url = start_stub(StdHashSet::from([scripthash_hex(&script)]));
            let password = "restore-test-password".to_string();
            let material = KeyMaterial::new_from_password(Some(password.clone())).unwrap();
            let master = Xpriv::new_master(bitcoin::Network::Regtest, &MASTER_SEED).unwrap();
            // This is the on-disk state after restore created the file but before
            // its first scan saved a height.
            WalletStore::init(
                path.file_name().unwrap().to_str().unwrap().to_string(),
                &path,
                bitcoin::Network::Regtest,
                master,
                None,
                pending_restore,
                &material,
            )
            .unwrap();

            let backend = AnyBlockchain::Electrum(Electrum::new(&electrum_config(url)).unwrap());
            let wallet = Wallet::load_or_init(&path, backend, Some(password.clone())).unwrap();
            assert_eq!(wallet.store.external_index, expected);

            let (saved, _) = WalletStore::read_from_disk(&path, Some(password)).unwrap();
            assert_eq!(saved.external_index, expected);
            assert!(saved.last_synced_height.is_some());
            assert!(saved.pending_restore.is_none());
        }
    }

    /// `init-wallet` on an existing wallet must reject a wrong passphrase
    /// instead of exiting 0, without needing a backend.
    #[test]
    fn init_interactive_checks_the_passphrase_of_an_existing_wallet() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("init-existing");
        let material = KeyMaterial::new_from_password(Some("right".to_string())).unwrap();
        let master = Xpriv::new_master(bitcoin::Network::Regtest, &MASTER_SEED).unwrap();
        WalletStore::init(
            "init-existing".to_string(),
            &path,
            bitcoin::Network::Regtest,
            master,
            None,
            None,
            &material,
        )
        .unwrap();
        // Unreachable, so a backend call would fail the right-passphrase case.
        let backend = BackendConfig::Electrum(electrum_config("tcp://127.0.0.1:1".to_string()));

        Wallet::init_interactive(&path, &backend, Some("right".to_string())).unwrap();
        let err = Wallet::init_interactive(&path, &backend, Some("wrong".to_string()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("already exists"), "{}", err);
    }

    /// The passphrase check of `init-wallet` upgrades an older file only
    /// when no process holds the wallet, and never on a wrong passphrase.
    #[test]
    fn init_interactive_upgrades_an_older_wallet_only_when_idle() {
        let temp_dir = tempdir().unwrap();
        let backend = BackendConfig::Electrum(electrum_config("tcp://127.0.0.1:1".to_string()));

        let v023 = temp_dir.path().join("closed.wallet");
        let v023_source = include_bytes!("../../tests/fixtures/compat/v0.2.3/closed.wallet");
        std::fs::write(&v023, v023_source).unwrap();

        let unmarked = temp_dir.path().join("unmarked");
        let material = KeyMaterial::new_from_password(Some("right".to_string())).unwrap();
        let master = Xpriv::new_master(bitcoin::Network::Regtest, &MASTER_SEED).unwrap();
        WalletStore::init(
            "unmarked".to_string(),
            &unmarked,
            bitcoin::Network::Regtest,
            master,
            None,
            None,
            &material,
        )
        .unwrap();
        let (store, material) =
            WalletStore::read_from_disk(&unmarked, Some("right".to_string())).unwrap();
        let unmarked_source = serde_cbor::to_vec(
            &crate::security::encrypt_struct_v2(&store, &material, Vec::new()).unwrap(),
        )
        .unwrap();
        std::fs::write(&unmarked, &unmarked_source).unwrap();

        for (path, source, password, suffix) in [
            (&v023, &v023_source[..], "compat-v023", ".v023"),
            (&unmarked, &unmarked_source[..], "right", ".v2pre"),
        ] {
            let mut archive = path.as_os_str().to_os_string();
            archive.push(suffix);
            let archive = std::path::PathBuf::from(archive);

            let holder = WalletInUse::shared(path).unwrap();
            let err = Wallet::init_interactive(path, &backend, Some(password.to_string()))
                .unwrap_err()
                .to_string();
            assert!(err.contains(IN_USE_MESSAGE), "{}", err);
            assert_eq!(std::fs::read(path).unwrap(), source);
            assert!(!archive.exists());
            drop(holder);

            let err = Wallet::init_interactive(path, &backend, Some("wrong".to_string()))
                .unwrap_err()
                .to_string();
            assert!(err.contains("already exists"), "{}", err);
            assert_eq!(std::fs::read(path).unwrap(), source);
            assert!(!archive.exists());

            Wallet::init_interactive(path, &backend, Some(password.to_string())).unwrap();
            assert_eq!(std::fs::read(&archive).unwrap(), source);
            assert!(
                WalletStore::read_without_upgrade(path, Some(password.to_string()))
                    .unwrap()
                    .is_some()
            );
        }
    }

    /// The phrase alone must give the key and, with a wide enough gap, the
    /// coins at index 150 that the default gap of 100 cannot reach.
    #[test]
    fn restore_from_mnemonic_uses_the_phrase_key_and_gap() {
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::parse(PHRASE).unwrap();
        let script = derive_child_script(
            &account_for(&mnemonic.to_seed(""), AddressType::P2TR),
            AddressType::P2TR,
            KeychainKind::External,
            150,
        )
        .unwrap();
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("mnemonic-wallet");
        let backend = BackendConfig::Electrum(electrum_config(start_stub(StdHashSet::from([
            scripthash_hex(&script),
        ]))));

        // The stub's tip is the genesis block, height 0.
        let err = Wallet::restore_from_mnemonic(
            Zeroizing::new(PHRASE.to_string()),
            &path,
            &backend,
            RestoreOptions {
                birthday: Some(1),
                ..Default::default()
            },
            Zeroizing::new("test-password".to_string()),
        )
        .expect_err("a birthday above the tip is rejected");
        assert!(err.to_string().contains("above the chain tip"), "{}", err);
        assert!(!path.exists());

        let wallet = Wallet::restore_from_mnemonic(
            Zeroizing::new(PHRASE.to_string()),
            &path,
            &backend,
            RestoreOptions {
                address_gap: 200,
                ..Default::default()
            },
            Zeroizing::new("test-password".to_string()),
        )
        .unwrap();
        assert_eq!(wallet.store.external_index, 151);
        assert_eq!(
            wallet.with_master_key(|key| Ok(*key)).unwrap(),
            Wallet::master_key_from_mnemonic(&mnemonic, bitcoin::Network::Regtest).unwrap()
        );
    }

    /// A new wallet's phrase is in its first write: a restart reads it back,
    /// even if nothing after `Wallet::init` ever ran.
    #[test]
    fn new_wallet_seals_its_phrase_in_the_first_write() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("new-wallet");
        let url = start_stub(StdHashSet::new());
        let backend =
            || AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
        let password = || Zeroizing::new("test-password".to_string());

        let err = Wallet::init(&path, backend(), Zeroizing::default()).unwrap_err();
        assert!(
            err.to_string().contains("passphrase is required"),
            "{}",
            err
        );
        assert!(!path.exists());

        let created = Wallet::init(&path, backend(), password()).unwrap();
        let first_words = created.get_wallet_mnemonic(password()).unwrap().words();
        assert_eq!(first_words.split(' ').count(), 12);
        drop(created);

        let (saved, _) =
            WalletStore::read_from_disk(&path, Some("test-password".to_string())).unwrap();
        assert!(saved.sealed_mnemonic.is_some());
        assert!(!saved.seed_backed_up);

        let loaded =
            Wallet::load_or_init(&path, backend(), Some("test-password".to_string())).unwrap();
        let words = loaded.get_wallet_mnemonic(password()).unwrap().words();
        assert_eq!(words, first_words);
        let mnemonic = Mnemonic::parse(words.as_str()).unwrap();
        assert_eq!(
            loaded.with_master_key(|key| Ok(*key)).unwrap(),
            Wallet::master_key_from_mnemonic(&mnemonic, bitcoin::Network::Regtest).unwrap()
        );
        assert!(!loaded.seed_backed_up());
    }

    /// A library load never migrates an older file while another process
    /// holds the wallet; it migrates once the wallet is idle.
    #[test]
    fn library_load_migrates_only_when_no_process_holds_the_wallet() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("closed.wallet");
        let original = include_bytes!("../../tests/fixtures/compat/v0.2.3/closed.wallet");
        std::fs::write(&path, original).unwrap();
        let url = start_stub(StdHashSet::new());
        let backend =
            || AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
        let password = || Some("compat-v023".to_string());

        let holder = WalletInUse::shared(&path).unwrap();
        for error in [
            Wallet::load(&path, backend(), password()).err().unwrap(),
            Wallet::load_or_init(&path, backend(), password())
                .err()
                .unwrap(),
        ] {
            assert!(matches!(error, WalletError::General(ref message)
                if message == crate::wallet::seed_cli::IN_USE_MESSAGE));
        }
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(!path.with_file_name("closed.wallet.v023").exists());
        drop(holder);

        Wallet::load(&path, backend(), password()).unwrap();
        assert_eq!(
            std::fs::read(path.with_file_name("closed.wallet.v023")).unwrap(),
            original
        );
    }

    /// Every library owner holds the wallet lock while it lives, so the seed
    /// commands refuse to write under it. The offline reader holds nothing.
    #[test]
    fn live_library_wallet_blocks_seed_command_writes() {
        use crate::wallet::seed_cli::WalletInUse;

        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("wallet");
        let url = start_stub(StdHashSet::new());
        let backend =
            || AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
        let password = || Zeroizing::new("test-password".to_string());
        let idle = || WalletInUse::exclusive_if_idle(&path).unwrap().is_some();

        let created = Wallet::init(&path, backend(), password()).unwrap();
        assert!(!idle());
        drop(created);
        assert!(idle());

        let loaded =
            Wallet::load_or_init(&path, backend(), Some("test-password".to_string())).unwrap();
        assert!(!idle());
        let offline = Wallet::open_offline(&path, password()).unwrap();
        drop(loaded);
        assert!(idle());
        drop(offline);

        let phrase = Mnemonic::generate(12).unwrap().to_string();
        let restored_path = temp_dir.path().join("restored");
        let restored = Wallet::restore_from_mnemonic(
            Zeroizing::new(phrase),
            &restored_path,
            &BackendConfig::Electrum(electrum_config(url.clone())),
            RestoreOptions::default(),
            password(),
        )
        .unwrap();
        assert!(WalletInUse::exclusive_if_idle(&restored_path)
            .unwrap()
            .is_none());
        drop(restored);
        assert!(WalletInUse::exclusive_if_idle(&restored_path)
            .unwrap()
            .is_some());
    }

    /// Use a subprocess with a deadline: a second flock on the owner's fd
    /// path would hang forever, rather than fail an ordinary assertion.
    #[test]
    fn owner_process_creates_and_loads_wallet_without_self_deadlock() {
        use std::{
            fs::{OpenOptions, TryLockError},
            process::{Child, Command},
            sync::mpsc,
            time::{Duration, Instant},
        };

        const CHILD_ENV: &str = "OPENSWAP_OWNER_WALLET_CHILD";
        if let Some(path) = std::env::var_os(CHILD_ENV) {
            let path = PathBuf::from(path);
            let url = start_stub(StdHashSet::new());
            let password = || Zeroizing::new("test-password".to_string());
            let mut first_words = None;
            for _ in 0..2 {
                let owner = WalletInUse::owner(&path).unwrap();
                let blockchain =
                    AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
                // The same entry point used by maker and taker, with a real
                // exclusive owner even in integration-test builds.
                let mut wallet =
                    Wallet::load_or_init_with_lock(&path, blockchain, Some(password()), owner)
                        .unwrap();
                let words = wallet.get_wallet_mnemonic(password()).unwrap().words();
                assert_eq!(first_words.get_or_insert_with(|| words.clone()), &words);
                // show-seed's confirmation and attach-seed share this gate.
                assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_none());
                let mut sentinel = path.as_os_str().to_os_string();
                sentinel.push(".lock");
                let reader = OpenOptions::new().write(true).open(sentinel).unwrap();
                assert!(matches!(
                    reader.try_lock_shared(),
                    Err(TryLockError::WouldBlock)
                ));
                // A save replaces the wallet inode; ownership must survive it.
                wallet.store.last_synced_height = Some(0);
                wallet.save_to_disk().unwrap();
                assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_none());
                drop(wallet);
                assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_some());
            }

            // An ordinary library load must wait before reading the file;
            // otherwise its later save could erase this owner's final state.
            let blockchain =
                AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
            let mut owner_wallet = Wallet::load_or_init_with_lock(
                &path,
                blockchain,
                Some(password()),
                WalletInUse::owner(&path).unwrap(),
            )
            .unwrap();
            let (started_tx, started_rx) = mpsc::channel();
            let (loaded_tx, loaded_rx) = mpsc::channel();
            let reader_path = path.clone();
            let reader_url = url.clone();
            let reader = std::thread::spawn(move || {
                let blockchain =
                    AnyBlockchain::Electrum(Electrum::new(&electrum_config(reader_url)).unwrap());
                started_tx.send(()).unwrap();
                loaded_tx
                    .send(Wallet::load(
                        &reader_path,
                        blockchain,
                        Some("test-password".into()),
                    ))
                    .unwrap();
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(matches!(
                loaded_rx.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            owner_wallet.store.external_index = 37;
            owner_wallet.save_to_disk().unwrap();
            drop(owner_wallet);
            let loaded = loaded_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            assert_eq!(loaded.store.external_index, 37);
            assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_none());
            drop(loaded);
            reader.join().unwrap();
            assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_some());

            // An unmarked, seed-bearing V2 file must also migrate while
            // consuming the daemon's one owner guard, without a second flock.
            let blockchain =
                AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
            let mut original = Wallet::load_or_init_with_lock(
                &path,
                blockchain,
                Some(password()),
                WalletInUse::owner(&path).unwrap(),
            )
            .unwrap();
            original.store.seed_backed_up = true;
            let seed_bytes = serde_cbor::to_vec(&original.store.sealed_mnemonic).unwrap();
            let master_bytes = serde_cbor::to_vec(&original.store.master_key).unwrap();
            let unmarked = crate::security::encrypt_struct_v2(
                &original.store,
                &original.store_enc_material,
                Vec::new(),
            )
            .unwrap();
            let source = serde_cbor::to_vec(&unmarked).unwrap();
            std::fs::write(&path, &source).unwrap();
            let error = Wallet::open_offline(&path, password()).unwrap_err();
            assert!(matches!(error, WalletError::General(ref message)
                if message == crate::wallet::seed_cli::IN_USE_MESSAGE));
            assert_eq!(std::fs::read(&path).unwrap(), source);
            assert!(!path.with_file_name("wallet.v2pre").exists());
            drop(original);
            let blockchain =
                AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
            let migrated = Wallet::load_or_init_with_lock(
                &path,
                blockchain,
                Some(password()),
                WalletInUse::owner(&path).unwrap(),
            )
            .unwrap();
            assert_eq!(
                std::fs::read(path.with_file_name("wallet.v2pre")).unwrap(),
                source
            );
            assert_eq!(
                serde_cbor::to_vec(&migrated.store.sealed_mnemonic).unwrap(),
                seed_bytes
            );
            assert_eq!(
                serde_cbor::to_vec(&migrated.store.master_key).unwrap(),
                master_bytes
            );
            assert!(migrated.seed_backed_up());
            assert_eq!(
                migrated.get_wallet_mnemonic(password()).unwrap().words(),
                first_words.unwrap()
            );
            let header: crate::security::EncryptedDataV2 =
                serde_cbor::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(header.requires, [crate::security::WALLET_STORE_FORMAT]);
            assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_none());
            drop(migrated);
            assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_some());

            // The legacy migration branch must consume the same owner guard,
            // rather than acquiring another handle while rewriting the file.
            for (name, original, closed) in [
                (
                    "closed.wallet",
                    include_bytes!("../../tests/fixtures/compat/v0.2.3/closed.wallet").as_slice(),
                    true,
                ),
                (
                    "open.wallet",
                    include_bytes!("../../tests/fixtures/compat/v0.2.3/open.wallet").as_slice(),
                    false,
                ),
            ] {
                let legacy = path.with_file_name(name);
                std::fs::write(&legacy, original).unwrap();
                let blockchain =
                    AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
                let result = Wallet::load_or_init_with_lock(
                    &legacy,
                    blockchain,
                    Some(Zeroizing::new("compat-v023".to_string())),
                    WalletInUse::owner(&legacy).unwrap(),
                );
                let archive = path.with_file_name(format!("{name}.v023"));
                if closed {
                    let wallet = result.unwrap();
                    assert_eq!(std::fs::read(&archive).unwrap(), original);
                    assert!(WalletInUse::exclusive_if_idle(&legacy).unwrap().is_none());
                    assert!(matches!(
                        wallet.get_wallet_mnemonic(Zeroizing::new("compat-v023".to_string())),
                        Err(WalletError::MnemonicUnavailable)
                    ));
                    drop(wallet);
                } else {
                    assert!(result.unwrap_err().to_string().contains("open swaps"));
                    assert_eq!(std::fs::read(&legacy).unwrap(), original);
                    assert!(!archive.exists());
                }
                assert!(WalletInUse::exclusive_if_idle(&legacy).unwrap().is_some());
            }
            return;
        }

        struct ChildProcess(Child);
        impl Drop for ChildProcess {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let dir = tempdir().unwrap();
        let mut child = ChildProcess(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "wallet::api::tests::restore_history_probe_tests::owner_process_creates_and_loads_wallet_without_self_deadlock",
                    "--nocapture",
                ])
                .env(CHILD_ENV, dir.path().join("wallet"))
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "owner process failed: {}", status);
                break;
            }
            assert!(Instant::now() < deadline, "owner wallet startup deadlocked");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn failed_wallet_load_or_creation_releases_owner_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let url = start_stub(StdHashSet::new());
        let backend =
            || AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
        let open = |password| {
            Wallet::load_or_init_with_lock(
                &path,
                backend(),
                Some(Zeroizing::new(password)),
                WalletInUse::owner(&path).unwrap(),
            )
        };
        assert!(open(String::new()).is_err());
        assert!(!path.exists());
        assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_some());
        drop(open("test-password".to_string()).unwrap());
        let original = std::fs::read(&path).unwrap();
        assert!(matches!(
            open("wrong-password".to_string()),
            Err(WalletError::Security(SecurityError::Decryption))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_some());
    }

    /// A malformed blocklist aborts `Taker::init` immediately after the
    /// wallet's first write. Its seed must survive that failed startup.
    #[test]
    fn seed_is_readable_after_taker_init_fails() {
        use crate::{
            blocklist::{blocklist_path, BlocklistError},
            taker::{error::TakerError, Taker, TakerInitConfig},
        };

        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("taker");
        let path = data_dir.join("wallets").join("new-wallet");
        let url = start_stub(StdHashSet::new());
        let password = || Zeroizing::new("test-password".to_string());
        std::fs::write(blocklist_path(&data_dir), "{not valid json").unwrap();
        assert!(!path.exists());

        let err = Taker::init(TakerInitConfig {
            data_dir: Some(data_dir),
            wallet_name: "new-wallet".to_string(),
            backend: BackendConfig::Electrum(electrum_config(url)),
            password: Some("test-password".to_string()),
            check_blocklist: Some(true),
            ..Default::default()
        })
        .err()
        .expect("the blocklist must abort startup after the wallet was created");
        assert!(matches!(err, TakerError::Blocklist(BlocklistError::IO(_))));

        let first_write = std::fs::read(&path).unwrap();
        let offline = Wallet::open_offline(&path, password()).unwrap();
        let words = offline.get_wallet_mnemonic(password()).unwrap().words();
        assert_eq!(words.split(' ').count(), 12);
        let mnemonic = Mnemonic::parse(words.as_str()).unwrap();
        assert_eq!(
            offline.with_master_key(|key| Ok(*key)).unwrap(),
            Wallet::master_key_from_mnemonic(&mnemonic, bitcoin::Network::Regtest).unwrap()
        );
        assert!(!offline.seed_backed_up());
        assert_eq!(std::fs::read(&path).unwrap(), first_write);
    }

    /// Restore stores the phrase it was given, whatever its length.
    #[test]
    fn restore_from_mnemonic_seals_the_phrase() {
        let url = start_stub(StdHashSet::new());
        let backend = BackendConfig::Electrum(electrum_config(url.clone()));
        for words in [12, 24] {
            let temp_dir = tempdir().unwrap();
            let path = temp_dir.path().join("restored");
            let phrase = Mnemonic::generate(words).unwrap().to_string();
            let password = || Zeroizing::new("test-password".to_string());
            let err = Wallet::restore_from_mnemonic(
                Zeroizing::new(phrase.clone()),
                &path,
                &backend,
                RestoreOptions::default(),
                Zeroizing::default(),
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("passphrase is required"),
                "{}",
                err
            );
            assert!(!path.exists());

            Wallet::restore_from_mnemonic(
                Zeroizing::new(phrase.clone()),
                &path,
                &backend,
                RestoreOptions::default(),
                password(),
            )
            .unwrap();
            let blockchain =
                AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
            let loaded =
                Wallet::load_or_init(&path, blockchain, Some("test-password".to_string())).unwrap();
            let read = loaded.get_wallet_mnemonic(password()).unwrap().words();
            assert_eq!(read.as_str(), phrase);
        }
    }

    /// A nameless backup restore into a fresh data dir lands under `wallets/`,
    /// instead of taking `wallets` itself as the wallet file.
    #[test]
    fn backup_restore_into_a_fresh_data_dir() {
        let temp_dir = tempdir().unwrap();
        let wallet = test_support::test_wallet(&temp_dir.path().join("source"));
        let password = "backup password".to_string();
        let backup = temp_dir.path().join("backup.json");
        let km = KeyMaterial::new_from_password(Some(password.clone())).unwrap();
        wallet
            .write_backup(&backup, Zeroizing::new("test-password".to_string()), km)
            .unwrap();

        let data_dir = temp_dir.path().join("fresh");
        restore_wallet_from_backup_gui_app(
            Some(data_dir.clone()),
            None,
            BackendConfig::Electrum(electrum_config(start_stub(StdHashSet::new()))),
            backup,
            Some(password),
            RestoreOptions::default(),
        )
        .unwrap();
        assert!(data_dir
            .join("wallets")
            .join(&wallet.store.file_name)
            .is_file());
    }

    #[test]
    fn v023_and_pre_port_backups_restore_to_marked_v2() {
        use crate::security::{EncryptedData, EncryptedDataV2, WALLET_STORE_FORMAT};

        let dir = tempdir().unwrap();
        let backend = BackendConfig::Electrum(electrum_config(start_stub(StdHashSet::new())));
        let v023: WalletBackup = serde_cbor::from_slice(include_bytes!(
            "../../tests/fixtures/compat/v0.2.3/backup-wallet.cbor"
        ))
        .unwrap();
        let source = Wallet::init(
            &dir.path().join("source"),
            AnyBlockchain::from_config(&backend).unwrap(),
            Zeroizing::new("source-password".into()),
        )
        .unwrap();
        let words = source
            .get_wallet_mnemonic(Zeroizing::new("source-password".into()))
            .unwrap()
            .words();
        let pre_port =
            WalletBackup::new(&source, Zeroizing::new("source-password".into())).unwrap();
        // #1165's backup predates `requires`; preserve its seed payload.
        let serde_cbor::Value::Map(mut payload) = serde_cbor::value::to_value(&pre_port).unwrap()
        else {
            panic!("backup is a map")
        };
        payload.remove(&serde_cbor::Value::Text("requires".into()));
        let pre_port: WalletBackup =
            serde_cbor::value::from_value(serde_cbor::Value::Map(payload)).unwrap();

        for (name, backup, has_seed) in [("v023", v023, false), ("pre-port", pre_port, true)] {
            assert!(backup.requires.is_empty());
            let path = dir.path().join(name);
            let restored = Wallet::restore_with(
                &backup,
                &path,
                &backend,
                Zeroizing::new("restored-password".into()),
                RestoreOptions::default(),
            )
            .unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let container: EncryptedDataV2 = serde_cbor::from_slice(&bytes).unwrap();
            assert_eq!(container.requires, [WALLET_STORE_FORMAT]);
            assert!(serde_cbor::from_slice::<EncryptedData>(&bytes).is_err());
            let seed = restored.get_wallet_mnemonic(Zeroizing::new("restored-password".into()));
            if has_seed {
                assert_eq!(seed.unwrap().words(), words);
            } else {
                assert!(matches!(seed, Err(WalletError::MnemonicUnavailable)));
            }
        }
    }

    /// A backup takes the phrase only past the current wallet password, and a
    /// restore seals it again under the new wallet's own password. A backup
    /// without one restores with none; one whose phrase doesn't derive its
    /// key is refused before any file is written.
    #[test]
    fn backup_carries_the_phrase_to_the_restored_wallet() {
        let temp_dir = tempdir().unwrap();
        let backend = BackendConfig::Electrum(electrum_config(start_stub(StdHashSet::new())));
        let password = |text: &str| Zeroizing::new(text.to_string());
        let wallet = Wallet::init(
            &temp_dir.path().join("source"),
            AnyBlockchain::from_config(&backend).unwrap(),
            password("test-password"),
        )
        .unwrap();
        let phrase = wallet
            .get_wallet_mnemonic(password("test-password"))
            .unwrap()
            .words();

        let backup_file = temp_dir.path().join("backup.json");
        let backup_gui = |wallet_password: Option<&str>| {
            wallet.backup_wallet_gui_app(
                backup_file.display().to_string(),
                Some("backup password".to_string()),
                wallet_password.map(str::to_string),
            )
        };
        for wrong in [None, Some(""), Some("wrong-password")] {
            let err = backup_gui(wrong).unwrap_err();
            assert!(matches!(err, WalletError::WrongPassword), "{}", err);
        }
        assert!(!backup_file.exists());
        backup_gui(Some("test-password")).unwrap();
        let (mut backup, _) = load_sensitive_struct::<WalletBackup, SerdeJson>(
            &backup_file,
            Some("backup password".to_string()),
        )
        .unwrap();

        let restore = |backup: &WalletBackup, name: &str| {
            Wallet::restore_with(
                backup,
                &temp_dir.path().join(name),
                &backend,
                password("new-password"),
                RestoreOptions::default(),
            )
        };
        let restored = restore(&backup, "restored").unwrap();
        let read = restored.get_wallet_mnemonic(password("new-password"));
        assert_eq!(read.unwrap().words(), phrase);
        assert!(matches!(
            restored.get_wallet_mnemonic(password("test-password")),
            Err(WalletError::WrongPassword)
        ));
        let (saved, _) = WalletStore::read_from_disk(
            &temp_dir.path().join("restored"),
            Some("new-password".to_string()),
        )
        .unwrap();
        assert_eq!(saved.sealed_mnemonic, restored.store.sealed_mnemonic);
        assert_ne!(saved.sealed_mnemonic, wallet.store.sealed_mnemonic);

        let other = Mnemonic::generate(12).unwrap();
        backup.mnemonic = Some(SecretEntropy::from_mnemonic(&other).unwrap());
        let err = restore(&backup, "mismatched").unwrap_err();
        assert!(matches!(err, WalletError::MnemonicMismatch), "{}", err);
        assert!(!temp_dir.path().join("mismatched").exists());

        backup.mnemonic = None;
        let old = restore(&backup, "old").unwrap();
        assert!(matches!(
            old.get_wallet_mnemonic(password("new-password")),
            Err(WalletError::MnemonicUnavailable)
        ));
    }

    /// Proves a stopped sync returns before making its first backend request.
    #[test]
    fn sync_does_not_enter_the_backend_after_shutdown() {
        let temp_dir = tempdir().unwrap();
        let url = start_stub(StdHashSet::new());
        let mut wallet = stub_wallet(&temp_dir.path().join("wallet.cbor"), url);
        let shutdown = std::sync::atomic::AtomicBool::new(true);

        assert!(matches!(
            wallet.sync_and_save(&shutdown),
            Err(WalletError::Interrupted("Shutdown requested"))
        ));
    }
}

/// A recovery pass that finds our own timelock recovery already confirmed must
/// record it as resolved with its txid, drop the swapcoin, persist that, and
/// leave nothing for the next pass. Run against stubbed backends.
#[cfg(test)]
mod timelock_reconcile_tests {
    use super::*;
    use crate::{
        protocol::contract::{create_contract_redeemscript, Hash160},
        wallet::{blockchain::Electrum, swapcoin::OutgoingSwapCoin, test_wallet},
    };
    use bitcoin::{
        consensus::encode::serialize_hex, hashes::Hash, locktime::absolute::LockTime, BlockHash,
        TxIn,
    };
    use bitcoind::tempfile::tempdir;
    use serde_cbor::{value::to_value as to_cbor_value, Value as CborValue};
    use std::{
        io::{BufRead, BufReader, Write as IoWrite},
        net::TcpListener,
        sync::{atomic::AtomicBool, Arc, RwLock},
    };

    const CONTRACT_HEIGHT: i64 = 5;
    const RECOVERY_HEIGHT: i64 = 6;
    const TIP: i64 = 10;
    pub(super) const PASSWORD: &str = "test-password";

    pub(super) fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    pub(super) fn pubkey(byte: u8) -> PublicKey {
        PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            crate::utill::global_secp(),
            &key(byte),
        ))
    }

    pub(super) fn tx(
        previous_output: OutPoint,
        value: u64,
        script_pubkey: ScriptBuf,
    ) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            }],
        }
    }

    /// A Legacy outgoing swapcoin with a confirmed contract, and our own signed
    /// timelock recovery of it.
    fn legacy_coin_and_recovery() -> (OutgoingSwapCoin, Transaction) {
        let (coin, recovery, _) = legacy_coin_and_recoveries();
        (coin, recovery)
    }

    /// Also returns a second, differently priced recovery: one it replaced.
    fn legacy_coin_and_recoveries() -> (OutgoingSwapCoin, Transaction, Transaction) {
        let redeemscript =
            create_contract_redeemscript(&pubkey(2), &pubkey(3), &Hash160::all_zeros(), &20);
        let contract_tx = tx(
            OutPoint::new(Txid::from_byte_array([9; 32]), 0),
            50_000,
            redeemscript.to_p2wsh(),
        );
        let mut coin = OutgoingSwapCoin::new_legacy(
            key(1),
            pubkey(4),
            contract_tx,
            redeemscript,
            key(3),
            Amount::from_sat(50_000),
            1,
        );
        coin.committed = true;
        let recovery_spk = ScriptBuf::new_p2wpkh(&pubkey(5).wpubkey_hash().unwrap());
        let recovery_at = |value| {
            let unsigned = tx(
                OutPoint::new(coin.contract_tx.compute_txid(), 0),
                value,
                recovery_spk.clone(),
            );
            coin.sign_timelock_recovery(unsigned).unwrap()
        };
        let (recovery, replaced) = (recovery_at(49_000), recovery_at(49_500));
        (coin, recovery, replaced)
    }

    pub(super) fn scripthash(script: &Script) -> String {
        use bitcoin::hex::DisplayHex;
        use electrum_client::ToElectrumScriptHash;
        script.to_electrum_scripthash().to_lower_hex_string()
    }

    /// Electrum server knowing the contract (mined at `CONTRACT_HEIGHT`) and
    /// our recovery spending it (mined at `RECOVERY_HEIGHT`). Every other
    /// script is empty and every other txid unknown.
    fn start_electrum_stub(contract: Transaction, recovery: Transaction) -> String {
        start_electrum_stub_with(contract, recovery, None)
    }

    /// As [`start_electrum_stub`], with `stale` (never mined, also spending the
    /// contract) listed in the contract's history ahead of `recovery`.
    fn start_electrum_stub_with(
        contract: Transaction,
        recovery: Transaction,
        stale: Option<Transaction>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = genesis.block_hash().to_string();
        let header_hex = serialize_hex(&genesis.header);
        let entry = |tx: &Transaction, height: i64| json!({"tx_hash": tx.compute_txid().to_string(), "height": height});
        let mut contract_history = vec![entry(&contract, CONTRACT_HEIGHT)];
        let mut recovery_history = Vec::new();
        let mut txs = HashMap::from([
            (
                contract.compute_txid().to_string(),
                serialize_hex(&contract),
            ),
            (
                recovery.compute_txid().to_string(),
                serialize_hex(&recovery),
            ),
        ]);
        if let Some(stale) = &stale {
            contract_history.push(entry(stale, 0));
            recovery_history.push(entry(stale, 0));
            txs.insert(stale.compute_txid().to_string(), serialize_hex(stale));
        }
        contract_history.push(entry(&recovery, RECOVERY_HEIGHT));
        recovery_history.push(entry(&recovery, RECOVERY_HEIGHT));
        let history = HashMap::from([
            (
                scripthash(&contract.output[0].script_pubkey),
                Value::Array(contract_history),
            ),
            (
                scripthash(&recovery.output[0].script_pubkey),
                Value::Array(recovery_history),
            ),
        ]);

        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { continue };
                let _ = stream.set_nodelay(true);
                let (genesis_hash, header_hex) = (genesis_hash.clone(), header_hex.clone());
                let (history, txs) = (history.clone(), txs.clone());
                thread::spawn(move || {
                    let answer = |req: &Value| -> Value {
                        let param = req["params"][0].as_str().unwrap_or_default();
                        let result = match req["method"].as_str().unwrap_or_default() {
                            "server.features" => json!({
                                "server_version": "stub",
                                "genesis_hash": genesis_hash,
                                "protocol_min": "1.4",
                                "protocol_max": "1.4",
                                "hash_function": "sha256",
                                "pruning": Value::Null,
                            }),
                            "blockchain.headers.subscribe" => {
                                json!({"height": TIP, "hex": header_hex})
                            }
                            "blockchain.block.header" => json!(header_hex),
                            "blockchain.scripthash.get_history" => {
                                history.get(param).cloned().unwrap_or(json!([]))
                            }
                            "blockchain.scripthash.listunspent" => json!([]),
                            "blockchain.transaction.get" => match txs.get(param) {
                                Some(hex) => json!(hex),
                                None => {
                                    return json!({"jsonrpc": "2.0", "id": req["id"], "error": {
                                        "code": 2,
                                        "message": "No such mempool or blockchain transaction",
                                    }})
                                }
                            },
                            _ => Value::Null,
                        };
                        json!({"jsonrpc": "2.0", "id": req["id"], "result": result})
                    };
                    let mut out = stream.try_clone().expect("clone stub stream");
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { return };
                        let Ok(req) = serde_json::from_str::<Value>(&line) else {
                            return;
                        };
                        let resp = match req.as_array() {
                            Some(batch) => Value::Array(batch.iter().map(answer).collect()),
                            None => answer(&req),
                        };
                        if writeln!(out, "{resp}").is_err() {
                            return;
                        }
                    }
                });
            }
        });
        url
    }

    pub(super) fn electrum(url: &str) -> AnyBlockchain {
        AnyBlockchain::Electrum(
            Electrum::new(&crate::wallet::ElectrumConfig {
                url: url.to_string(),
                ..Default::default()
            })
            .expect("connect to stub"),
        )
    }

    pub(super) fn stub_wallet(path: &Path, blockchain: AnyBlockchain) -> Wallet {
        let master_key = Xpriv::new_master(bitcoin::Network::Regtest, &[42; 32]).unwrap();
        let enc_material = KeyMaterial::new_from_password(Some(PASSWORD.to_string())).unwrap();
        let store = WalletStore::init(
            "timelock-reconcile-test".to_string(),
            path,
            bitcoin::Network::Regtest,
            master_key,
            None,
            None,
            &enc_material,
        )
        .unwrap();
        Wallet {
            blockchain,
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material: enc_material,
            locked_utxos: HashSet::new(),
            _in_use: None,
        }
    }

    /// Fails the pass instead of hanging if the stub cannot satisfy a sync:
    /// `sync_no_fail` retries forever until shutdown.
    pub(super) fn shutdown_after(secs: u64) -> Arc<AtomicBool> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(secs));
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        shutdown
    }

    /// Runs two recovery passes over a wallet holding `coin` and checks the
    /// first records `recovery` as resolved, persists the removal, and the
    /// second finds nothing.
    fn assert_reconciles(
        wallet: Wallet,
        chain: &AnyBlockchain,
        coin: &OutgoingSwapCoin,
        recovery: &Transaction,
    ) {
        let wallet_path = wallet.wallet_file_path.clone();
        let wallet = RwLock::new(wallet);
        let shutdown = shutdown_after(60);
        let contract_txid = coin.contract_tx.compute_txid();

        let first =
            Wallet::recover_timelocked_swapcoins(&wallet, chain, &shutdown, None, &|_| true)
                .unwrap();
        assert_eq!(
            first.resolved,
            vec![(contract_txid, recovery.compute_txid())]
        );
        assert!(first.discarded.is_empty());
        assert!(wallet.read().unwrap().store.outgoing_swapcoins.is_empty());

        let (reloaded, _) =
            WalletStore::read_from_disk(&wallet_path, Some(PASSWORD.to_string())).unwrap();
        assert!(reloaded.outgoing_swapcoins.is_empty());

        let second =
            Wallet::recover_timelocked_swapcoins(&wallet, chain, &shutdown, None, &|_| true)
                .unwrap();
        assert!(second.is_empty());
    }

    #[test]
    fn compat_coin_flags_default_to_safe_values_and_preserve_fresh_values() {
        let (reference, _) = legacy_coin_and_recovery();
        let legacy = OutgoingSwapCoin::new_legacy(
            key(1),
            pubkey(4),
            reference.contract_tx.clone(),
            reference.contract_redeemscript.clone().unwrap(),
            key(3),
            Amount::from_sat(50_000),
            1,
        );
        let taproot = OutgoingSwapCoin::new_taproot(
            key(3),
            ScriptBuf::new(),
            ScriptBuf::new(),
            reference.contract_tx,
            Amount::from_sat(50_000),
            1,
        );
        for coin in [legacy, taproot] {
            assert!(!coin.committed && !coin.incoming_claimed);
            let current: OutgoingSwapCoin =
                serde_cbor::from_slice(&serde_cbor::to_vec(&coin).unwrap()).unwrap();
            assert_eq!(current, coin);
            for omitted in [
                vec!["committed"],
                vec!["incoming_claimed"],
                vec!["committed", "incoming_claimed"],
            ] {
                let mut old = to_cbor_value(&coin).unwrap();
                let CborValue::Map(fields) = &mut old else {
                    panic!("coin must serialize as a map")
                };
                for field in &omitted {
                    fields.remove(&CborValue::Text((*field).into()));
                }
                let decoded: OutgoingSwapCoin =
                    serde_cbor::from_slice(&serde_cbor::to_vec(&old).unwrap()).unwrap();
                assert_eq!(decoded.committed, omitted.contains(&"committed"));
                assert_eq!(
                    decoded.incoming_claimed,
                    omitted.contains(&"incoming_claimed")
                );
                assert_eq!(decoded.contract_tx, coin.contract_tx);
            }
        }
    }

    #[test]
    fn compat_coin_flags_stay_monotonic_after_stale_reinsert_and_reload() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.cbor");
        let mut wallet = test_wallet(&path);
        let (mut original, _) = legacy_coin_and_recovery();
        original.swap_id = Some("swap".into());
        original.committed = false;
        original.incoming_claimed = false;
        wallet.add_outgoing_swapcoin(&original);
        for ((committed, incoming_claimed), expected) in [
            ((true, false), (true, false)),
            ((false, true), (true, true)),
            ((false, false), (true, true)),
        ] {
            let mut update = original.clone();
            update.committed = committed;
            update.incoming_claimed = incoming_claimed;
            wallet.add_outgoing_swapcoin(&update);
            wallet.save_to_disk().unwrap();
            let (store, material) =
                WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
            let coin = &store.outgoing_swapcoins[&original.contract_tx.compute_txid().to_string()];
            assert_eq!((coin.committed, coin.incoming_claimed), expected);
            wallet.store = store;
            wallet.store_enc_material = material;
        }
        let saved =
            &wallet.store.outgoing_swapcoins[&original.contract_tx.compute_txid().to_string()];
        assert!(saved.committed && saved.incoming_claimed);
    }

    #[test]
    fn cleanup_save_failure_preserves_coins_and_monotonic_flags() {
        let (mut coin, recovery) = legacy_coin_and_recovery();
        coin.swap_id = Some("swap".into());
        let mut stale = coin.clone();
        stale.committed = false;
        coin.incoming_claimed = true;
        coin.hash_preimage = Some([7; 32]);
        let url = start_electrum_stub(coin.contract_tx.clone(), recovery);
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.cbor");
        let mut wallet = stub_wallet(&path, electrum(&url));
        wallet.add_outgoing_swapcoin(&coin);
        wallet.add_outgoing_swapcoin(&stale);
        let (_, outgoing) = wallet.find_unfinished_swapcoins();
        assert_eq!(outgoing.len(), 1);
        assert!(outgoing[0].committed && outgoing[0].incoming_claimed);
        wallet.save_to_disk().unwrap();

        // A directory at the destination forces the atomic replacement to fail.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(wallet
            .remove_swap_coins_and_save("swap", true, true)
            .is_err());
        let (_, outgoing) = wallet.find_unfinished_swapcoins();
        assert_eq!(outgoing.len(), 1);
        assert!(outgoing[0].committed && outgoing[0].incoming_claimed);
    }

    #[test]
    fn electrum_records_our_confirmed_recovery_as_resolved() {
        let (coin, recovery) = legacy_coin_and_recovery();
        let url = start_electrum_stub(coin.contract_tx.clone(), recovery.clone());
        let temp_dir = tempdir().unwrap();
        let mut wallet = stub_wallet(&temp_dir.path().join("wallet.cbor"), electrum(&url));
        wallet.add_outgoing_swapcoin(&coin);
        wallet.save_to_disk().unwrap();

        assert_reconciles(wallet, &electrum(&url), &coin, &recovery);
    }

    /// Electrum can list a replaced, never-mined recovery ahead of the one that
    /// confirmed. Classification must skip it and record the mined recovery.
    #[test]
    fn electrum_skips_an_unconfirmed_spend_listed_first() {
        let (coin, recovery, replaced) = legacy_coin_and_recoveries();
        let url =
            start_electrum_stub_with(coin.contract_tx.clone(), recovery.clone(), Some(replaced));
        let state = Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin).unwrap();
        assert_eq!(
            state,
            ContractChainState::RecoveredByTimelock(recovery.compute_txid())
        );
    }

    /// The next hop's claim of our contract can carry the preimage the maker
    /// still needs for its incoming, so the coin stays until the swap settles.
    #[test]
    fn electrum_keeps_a_contract_the_other_side_claimed() {
        let (coin, _) = legacy_coin_and_recovery();
        let claim = tx(
            OutPoint::new(coin.contract_tx.compute_txid(), 0),
            49_000,
            ScriptBuf::new_p2wpkh(&pubkey(6).wpubkey_hash().unwrap()),
        );
        let url = start_electrum_stub(coin.contract_tx.clone(), claim);
        let state = Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin).unwrap();
        assert_eq!(state, ContractChainState::NotYet);
    }

    /// A Taproot outgoing swapcoin whose contract output commits to both
    /// leaves, and our own signed timelock recovery of it.
    pub(super) fn taproot_coin_and_recovery() -> (OutgoingSwapCoin, Transaction) {
        use crate::protocol::contract2::{create_hashlock_script, create_timelock_script};
        use bitcoin::{key::Keypair, secp256k1::Scalar, taproot::TaprootBuilder, XOnlyPublicKey};

        let secp = crate::utill::global_secp();
        let xonly = |byte| -> XOnlyPublicKey {
            Keypair::from_secret_key(secp, &key(byte))
                .x_only_public_key()
                .0
        };
        let hashlock_script = create_hashlock_script(&[7; 32], &xonly(2));
        let timelock_script =
            create_timelock_script(LockTime::from_height(500).unwrap(), &xonly(3));
        let merkle_root = TaprootBuilder::new()
            .add_leaf(1, hashlock_script.clone())
            .unwrap()
            .add_leaf(1, timelock_script.clone())
            .unwrap()
            .finalize(secp, xonly(5))
            .unwrap()
            .merkle_root();
        let contract_tx = tx(
            OutPoint::new(Txid::from_byte_array([9; 32]), 0),
            50_000,
            ScriptBuf::new_p2tr(secp, xonly(5), merkle_root),
        );
        let mut coin = OutgoingSwapCoin::new_taproot(
            key(3),
            hashlock_script,
            timelock_script,
            contract_tx,
            Amount::from_sat(50_000),
            1,
        );
        coin.committed = true;
        coin.internal_key = Some(xonly(5));
        coin.tap_tweak = Some(Scalar::ZERO);
        let unsigned = tx(
            OutPoint::new(coin.contract_tx.compute_txid(), 0),
            49_000,
            ScriptBuf::new_p2wpkh(&pubkey(5).wpubkey_hash().unwrap()),
        );
        let recovery = coin.sign_timelock_recovery(unsigned).unwrap();
        (coin, recovery)
    }

    #[test]
    fn electrum_classifies_our_confirmed_taproot_recovery_as_recovered() {
        let (coin, recovery) = taproot_coin_and_recovery();
        let url = start_electrum_stub(coin.contract_tx.clone(), recovery.clone());
        let state = Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin).unwrap();
        assert_eq!(
            state,
            ContractChainState::RecoveredByTimelock(recovery.compute_txid())
        );
    }

    /// Hand-rolled Bitcoin Core JSON-RPC over HTTP: the contract is mined at
    /// `CONTRACT_HEIGHT`, our recovery at `RECOVERY_HEIGHT`, and the contract
    /// output is spent. Only the calls classification makes are answered.
    fn start_core_stub(contract: Transaction, recovery: Transaction) -> String {
        start_core_stub_with(contract, recovery, true)
    }

    /// As [`start_core_stub`]. With `recovery_mined` unset the recovery sits in
    /// the mempool: the confirmed view still holds the contract output.
    fn start_core_stub_with(
        contract: Transaction,
        recovery: Transaction,
        recovery_mined: bool,
    ) -> String {
        use std::io::Read;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let addr = listener.local_addr().unwrap().to_string();
        let header = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
        let block_hash = |height: i64| BlockHash::from_byte_array([height as u8; 32]);
        let mut mined =
            HashMap::from([(contract.compute_txid(), (contract.clone(), CONTRACT_HEIGHT))]);
        if recovery_mined {
            mined.insert(recovery.compute_txid(), (recovery.clone(), RECOVERY_HEIGHT));
        }
        let mined = Arc::new(mined);

        let answer = move |method: &str, params: &Value| -> Result<Value, Value> {
            let unknown =
                || json!({"code": -5, "message": "No such mempool or blockchain transaction"});
            Ok(match method {
                "getblockcount" => json!(TIP),
                "getblockhash" => json!(block_hash(params[0].as_i64().unwrap())),
                "getblockheader" => {
                    let hash = params[0].as_str().unwrap();
                    let height = (0..=TIP)
                        .find(|h| block_hash(*h).to_string() == hash)
                        .ok_or_else(unknown)?;
                    json!({
                        "hash": hash, "confirmations": TIP - height + 1, "height": height,
                        "version": 1, "merkleroot": header.merkle_root, "time": 0,
                        "mediantime": 0, "nonce": 0, "bits": "207fffff", "difficulty": 1.0,
                        "chainwork": "00", "nTx": 1,
                    })
                }
                "getblock" => {
                    let hash = params[0].as_str().unwrap();
                    let txdata = mined
                        .values()
                        .filter(|(_, h)| block_hash(*h).to_string() == hash)
                        .map(|(tx, _)| tx.clone())
                        .collect();
                    json!(serialize_hex(&bitcoin::Block { header, txdata }))
                }
                "getrawtransaction" => {
                    let txid: Txid = params[0].as_str().unwrap().parse().unwrap();
                    if !recovery_mined && txid == recovery.compute_txid() {
                        return Ok(json!(serialize_hex(&recovery)));
                    }
                    let (tx, height) = mined.get(&txid).ok_or_else(unknown)?;
                    if !params[1].as_bool().unwrap_or(false) {
                        json!(serialize_hex(tx))
                    } else {
                        let vin: Vec<Value> = tx
                            .input
                            .iter()
                            .map(|i| {
                                json!({
                                    "txid": i.previous_output.txid,
                                    "vout": i.previous_output.vout,
                                    "scriptSig": {"asm": "", "hex": ""},
                                    "sequence": i.sequence.0,
                                })
                            })
                            .collect();
                        let vout: Vec<Value> = tx
                            .output
                            .iter()
                            .enumerate()
                            .map(|(n, o)| {
                                json!({
                                    "value": o.value.to_btc(),
                                    "n": n,
                                    "scriptPubKey": {
                                        "asm": "",
                                        "hex": o.script_pubkey.to_hex_string(),
                                        "type": null,
                                    },
                                })
                            })
                            .collect();
                        json!({
                            "hex": serialize_hex(tx), "txid": txid, "hash": tx.compute_wtxid(),
                            "size": tx.total_size(), "vsize": tx.vsize(), "version": 2,
                            "locktime": 0, "blockhash": block_hash(*height),
                            "confirmations": TIP - height + 1, "vin": vin, "vout": vout,
                        })
                    }
                }
                // A mempool spend leaves the output in the confirmed view only.
                "gettxout" if !recovery_mined && params[2] == json!(false) => json!({
                    "bestblock": block_hash(TIP),
                    "confirmations": TIP - CONTRACT_HEIGHT + 1,
                    "value": contract.output[0].value.to_btc(),
                    "scriptPubKey": {
                        "asm": "",
                        "hex": contract.output[0].script_pubkey.to_hex_string(),
                        "type": null,
                    },
                    "coinbase": false,
                }),
                "gettxout" => Value::Null,
                "getmempoolinfo" => json!({
                    "loaded": true, "size": 1, "bytes": 1, "usage": 1, "maxmempool": 1,
                    "mempoolminfee": 0.00001, "minrelaytxfee": 0.00001,
                    "incrementalrelayfee": 0.00005,
                }),
                "gettxspendingprevout" => {
                    let spender = (!recovery_mined).then(|| recovery.compute_txid());
                    json!([{
                        "txid": params[0][0]["txid"], "vout": params[0][0]["vout"],
                        "spendingtxid": spender,
                    }])
                }
                other => panic!("core stub: unexpected call {}", other),
            })
        };
        let answer = Arc::new(answer);

        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { continue };
                let answer = answer.clone();
                thread::spawn(move || {
                    let mut out = stream.try_clone().expect("clone stub stream");
                    let mut reader = BufReader::new(stream);
                    loop {
                        let mut body_len = 0;
                        let mut line = String::new();
                        loop {
                            line.clear();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                return;
                            }
                            if line.trim().is_empty() {
                                break;
                            }
                            if let Some(n) = line.to_lowercase().strip_prefix("content-length:") {
                                body_len = n.trim().parse().unwrap();
                            }
                        }
                        let mut body = vec![0; body_len];
                        if reader.read_exact(&mut body).is_err() {
                            return;
                        }
                        let req: Value = serde_json::from_slice(&body).unwrap();
                        let (result, error) =
                            match answer(req["method"].as_str().unwrap(), &req["params"]) {
                                Ok(result) => (result, Value::Null),
                                Err(error) => (Value::Null, error),
                            };
                        let reply = json!({
                            "jsonrpc": "2.0", "id": req["id"], "result": result, "error": error,
                        })
                        .to_string();
                        let written = write!(
                            out,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{reply}",
                            reply.len()
                        );
                        if written.and_then(|_| out.flush()).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    fn core(url: String) -> AnyBlockchain {
        AnyBlockchain::CoreRPC(
            crate::wallet::CoreRPC::new(&crate::wallet::CoreRpcConfig {
                url,
                ..Default::default()
            })
            .unwrap(),
        )
    }

    #[test]
    fn core_classifies_our_confirmed_recovery_as_recovered() {
        let (coin, recovery) = legacy_coin_and_recovery();
        let url = start_core_stub(coin.contract_tx.clone(), recovery.clone());
        let state = Wallet::ensure_contract_on_chain(&core(url), "swap", &coin).unwrap();
        assert_eq!(
            state,
            ContractChainState::RecoveredByTimelock(recovery.compute_txid())
        );
    }

    /// Core still lists a contract output that our unconfirmed recovery spends,
    /// so the mempool has to be asked before the coin reads as untouched.
    #[test]
    fn core_classifies_our_unconfirmed_recovery_as_pending() {
        let (coin, recovery) = legacy_coin_and_recovery();
        let url = start_core_stub_with(coin.contract_tx.clone(), recovery.clone(), false);
        let state = Wallet::ensure_contract_on_chain(&core(url), "swap", &coin).unwrap();
        assert_eq!(state, ContractChainState::RecoveryPending(recovery));
    }

    /// The next hop's unconfirmed claim leaves the output in Core's confirmed
    /// view too. Reading that as untouched would send a conflicting refund.
    #[test]
    fn core_waits_on_an_unconfirmed_claim_by_the_other_side() {
        let (coin, _) = legacy_coin_and_recovery();
        let claim = tx(
            OutPoint::new(coin.contract_tx.compute_txid(), 0),
            49_000,
            ScriptBuf::new_p2wpkh(&pubkey(6).wpubkey_hash().unwrap()),
        );
        let url = start_core_stub_with(coin.contract_tx.clone(), claim, false);
        let state = Wallet::ensure_contract_on_chain(&core(url), "swap", &coin).unwrap();
        assert_eq!(state, ContractChainState::NotYet);
    }

    /// A replacement must add the node's own increment, which an operator can
    /// set above the relay floor. Electrum cannot report one.
    #[test]
    fn replacement_increment_comes_from_the_backend() {
        let (coin, recovery) = legacy_coin_and_recovery();
        let core_url = start_core_stub(coin.contract_tx.clone(), recovery.clone());
        assert_eq!(core(core_url).replacement_increment_rate(), 5.0);
        let electrum_url = start_electrum_stub(coin.contract_tx, recovery);
        assert_eq!(
            electrum(&electrum_url).replacement_increment_rate(),
            MIN_RELAY_FEE_RATE
        );
    }
}

/// Recovery against the mempool: an incoming contract still there is swept on
/// a later pass, and our own stuck refund is replaced once fees outbid it.
#[cfg(test)]
mod mempool_deferral_tests {
    use super::{
        timelock_reconcile_tests::{
            electrum, key, pubkey, scripthash, shutdown_after, stub_wallet,
            taproot_coin_and_recovery, tx, PASSWORD,
        },
        *,
    };
    use crate::{
        protocol::contract::{create_contract_redeemscript, Hash160},
        wallet::{
            blockchain::SCRIPT_CACHE_TTL,
            swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
        },
    };
    use bitcoin::{
        consensus::encode::{deserialize_hex, serialize_hex},
        hashes::Hash,
        Witness,
    };
    use bitcoind::tempfile::tempdir;
    use std::{
        io::{BufRead, BufReader, Write as IoWrite},
        net::TcpListener,
        sync::{Arc, Mutex, RwLock},
    };

    /// Past the 500-block CLTV of the Taproot fixture.
    const TIP: i64 = 600;
    /// Leaves the outgoing contract's 20-block CSV matured at `TIP`.
    const OUTGOING_HEIGHT: i64 = 50;
    const SWAP: &str = "swap";

    /// What the stub server knows. A height of `0` is the mempool.
    struct StubChain {
        txs: HashMap<Txid, (Transaction, i64)>,
        broadcast: Vec<Txid>,
        reject_broadcast: bool,
        /// Lookups of these txs fail as a down backend would, never as "unknown".
        fail_lookups: HashSet<Txid>,
        /// Every fee estimate, in sat/vB.
        feerate: f64,
    }

    impl StubChain {
        fn with(txs: &[(&Transaction, i64)]) -> Arc<Mutex<Self>> {
            Arc::new(Mutex::new(StubChain {
                txs: txs
                    .iter()
                    .map(|(tx, height)| (tx.compute_txid(), ((*tx).clone(), *height)))
                    .collect(),
                broadcast: Vec::new(),
                reject_broadcast: false,
                fail_lookups: HashSet::new(),
                feerate: 1.0,
            }))
        }

        fn script_of(&self, outpoint: &OutPoint) -> Option<&ScriptBuf> {
            self.txs
                .get(&outpoint.txid)
                .and_then(|(tx, _)| tx.output.get(outpoint.vout as usize))
                .map(|output| &output.script_pubkey)
        }

        fn is_spent(&self, outpoint: &OutPoint) -> bool {
            self.txs
                .values()
                .any(|(tx, _)| tx.input.iter().any(|i| i.previous_output == *outpoint))
        }

        /// Every tx paying to or spending from the script.
        fn history(&self, scripthash_hex: &str) -> Value {
            let matches = |script: &ScriptBuf| scripthash(script) == scripthash_hex;
            self.txs
                .iter()
                .filter(|(_, (tx, _))| {
                    tx.output.iter().any(|o| matches(&o.script_pubkey))
                        || tx
                            .input
                            .iter()
                            .any(|i| self.script_of(&i.previous_output).is_some_and(matches))
                })
                .map(|(txid, (_, height))| json!({"tx_hash": txid.to_string(), "height": height}))
                .collect()
        }

        fn unspent(&self, scripthash_hex: &str) -> Value {
            let mut entries = Vec::new();
            for (txid, (tx, height)) in &self.txs {
                for (vout, output) in tx.output.iter().enumerate() {
                    let outpoint = OutPoint::new(*txid, vout as u32);
                    if scripthash(&output.script_pubkey) == scripthash_hex
                        && !self.is_spent(&outpoint)
                    {
                        entries.push(json!({
                            "tx_hash": txid.to_string(), "tx_pos": vout, "height": height,
                            "value": output.value.to_sat(),
                        }));
                    }
                }
            }
            Value::Array(entries)
        }
    }

    /// Electrum server over `chain`. A broadcast tx is mined at `TIP` at once,
    /// so a pass's confirmation wait returns on its first poll.
    fn start_electrum_stub(chain: Arc<Mutex<StubChain>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = genesis.block_hash().to_string();
        let header_hex = serialize_hex(&genesis.header);

        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { continue };
                let _ = stream.set_nodelay(true);
                let (genesis_hash, header_hex) = (genesis_hash.clone(), header_hex.clone());
                let chain = chain.clone();
                thread::spawn(move || {
                    let answer = |req: &Value| -> Value {
                        let param = req["params"][0].as_str().unwrap_or_default();
                        let mut chain = chain.lock().unwrap();
                        let result = match req["method"].as_str().unwrap_or_default() {
                            "server.features" => json!({
                                "server_version": "stub",
                                "genesis_hash": genesis_hash,
                                "protocol_min": "1.4",
                                "protocol_max": "1.4",
                                "hash_function": "sha256",
                                "pruning": Value::Null,
                            }),
                            "blockchain.headers.subscribe" => {
                                json!({"height": TIP, "hex": header_hex})
                            }
                            "blockchain.block.header" => json!(header_hex),
                            "blockchain.estimatefee" => json!(chain.feerate / 100_000.0),
                            "blockchain.scripthash.get_history" => chain.history(param),
                            "blockchain.scripthash.listunspent" => chain.unspent(param),
                            "blockchain.transaction.get"
                                if param
                                    .parse::<Txid>()
                                    .is_ok_and(|txid| chain.fail_lookups.contains(&txid)) =>
                            {
                                return json!({"jsonrpc": "2.0", "id": req["id"], "error": {
                                    "code": -32603, "message": "backend unavailable",
                                }});
                            }
                            "blockchain.transaction.get" => {
                                match param.parse::<Txid>().ok().and_then(|t| chain.txs.get(&t)) {
                                    Some((tx, _)) => json!(serialize_hex(tx)),
                                    None => {
                                        return json!({"jsonrpc": "2.0", "id": req["id"], "error": {
                                            "code": 2,
                                            "message": "No such mempool or blockchain transaction",
                                        }})
                                    }
                                }
                            }
                            "blockchain.transaction.broadcast" => {
                                if chain.reject_broadcast {
                                    return json!({"jsonrpc": "2.0", "id": req["id"], "error": {
                                        "code": -26, "message": "transaction temporarily rejected",
                                    }});
                                }
                                let tx: Transaction = deserialize_hex(param).unwrap();
                                let txid = tx.compute_txid();
                                chain.txs.insert(txid, (tx, TIP));
                                chain.broadcast.push(txid);
                                json!(txid.to_string())
                            }
                            _ => Value::Null,
                        };
                        json!({"jsonrpc": "2.0", "id": req["id"], "result": result})
                    };
                    let mut out = stream.try_clone().expect("clone stub stream");
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { return };
                        let Ok(req) = serde_json::from_str::<Value>(&line) else {
                            return;
                        };
                        let resp = match req.as_array() {
                            Some(batch) => Value::Array(batch.iter().map(answer).collect()),
                            None => answer(&req),
                        };
                        if writeln!(out, "{resp}").is_err() {
                            return;
                        }
                    }
                });
            }
        });
        url
    }

    /// Our Legacy incoming coin, claimable by hashlock: we hold the preimage.
    fn incoming_coin() -> IncomingSwapCoin {
        let preimage = [7; 32];
        let redeemscript =
            create_contract_redeemscript(&pubkey(2), &pubkey(3), &Hash160::hash(&preimage), &20);
        let contract_tx = tx(
            OutPoint::new(Txid::from_byte_array([8; 32]), 0),
            50_000,
            redeemscript.to_p2wsh(),
        );
        let mut coin = IncomingSwapCoin::new_legacy(
            key(1),
            pubkey(4),
            contract_tx,
            redeemscript,
            key(2),
            Amount::from_sat(50_000),
            1,
        );
        coin.hash_preimage = Some(preimage);
        coin.swap_id = Some(SWAP.to_string());
        coin
    }

    /// Our Legacy outgoing coin of the same swap.
    fn outgoing_coin() -> OutgoingSwapCoin {
        let redeemscript =
            create_contract_redeemscript(&pubkey(5), &pubkey(6), &Hash160::all_zeros(), &20);
        let contract_tx = tx(
            OutPoint::new(Txid::from_byte_array([9; 32]), 0),
            50_000,
            redeemscript.to_p2wsh(),
        );
        let mut coin = OutgoingSwapCoin::new_legacy(
            key(1),
            pubkey(4),
            contract_tx,
            redeemscript,
            key(6),
            Amount::from_sat(50_000),
            1,
        );
        coin.swap_id = Some(SWAP.to_string());
        coin.committed = true;
        coin
    }

    fn wallet_with(
        path: &Path,
        url: &str,
        incoming: &IncomingSwapCoin,
        outgoing: Option<&OutgoingSwapCoin>,
    ) -> RwLock<Wallet> {
        let mut wallet = stub_wallet(path, electrum(url));
        wallet.add_incoming_swapcoin(incoming);
        if let Some(outgoing) = outgoing {
            wallet.add_outgoing_swapcoin(outgoing);
        }
        wallet.save_to_disk().unwrap();
        RwLock::new(wallet)
    }

    /// The first pass meets the contract in the mempool: it holds the swap as
    /// claimed and broadcasts nothing. Once the contract is mined, the next
    /// pass sweeps it.
    #[test]
    fn mempool_contract_is_swept_on_a_later_pass() {
        let incoming = incoming_coin();
        let contract_txid = incoming.contract_tx.compute_txid();
        let chain = StubChain::with(&[(&incoming.contract_tx, 0)]);
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = wallet_with(&temp_dir.path().join("wallet.cbor"), &url, &incoming, None);
        let backend = electrum(&url);
        let shutdown = shutdown_after(60);

        let (sweeps, claiming) =
            Wallet::broadcast_incoming_sweeps(&wallet, &backend, &shutdown, None, &mut false)
                .unwrap();
        assert!(sweeps.is_empty());
        assert_eq!(claiming, HashSet::from([SWAP.to_string()]));
        assert!(chain.lock().unwrap().broadcast.is_empty());

        chain.lock().unwrap().txs.get_mut(&contract_txid).unwrap().1 = TIP;
        // Passes run a block apart, long after the backend stops reusing its
        // answers about the contract.
        thread::sleep(SCRIPT_CACHE_TTL);
        let outcome = Wallet::sweep_incoming_swapcoins(&wallet, &backend, &shutdown, None).unwrap();
        let chain = chain.lock().unwrap();
        let [sweep] = chain.broadcast[..] else {
            panic!("expected one sweep, got {:?}", chain.broadcast);
        };
        assert_eq!(
            chain.txs[&sweep].0.input[0].previous_output,
            OutPoint::new(contract_txid, 0)
        );
        assert_eq!(outcome.resolved, vec![(contract_txid, sweep)]);
        assert!(wallet.read().unwrap().store.incoming_swapcoins.is_empty());
    }

    /// Txs one recovery pass broadcasts for a swap whose outgoing timelock has
    /// matured, with the incoming contract at `incoming_height` (`None`: never
    /// broadcast).
    fn broadcast_by_recovery(incoming_height: Option<i64>) -> Vec<Transaction> {
        let (incoming, outgoing) = (incoming_coin(), outgoing_coin());
        let chain = StubChain::with(&[(&outgoing.contract_tx, OUTGOING_HEIGHT)]);
        if let Some(height) = incoming_height {
            let contract = &incoming.contract_tx;
            chain
                .lock()
                .unwrap()
                .txs
                .insert(contract.compute_txid(), (contract.clone(), height));
        }
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = wallet_with(
            &temp_dir.path().join("wallet.cbor"),
            &url,
            &incoming,
            Some(&outgoing),
        );

        Wallet::recover_swapcoins(
            &wallet,
            &electrum(&url),
            &shutdown_after(60),
            &HashSet::from([incoming.contract_tx.compute_txid()]),
            &HashSet::from([SWAP.to_string()]),
            &|_| true,
            &|_| false,
        )
        .unwrap();
        let chain = chain.lock().unwrap();
        chain
            .broadcast
            .iter()
            .map(|txid| chain.txs[txid].0.clone())
            .collect()
    }

    #[test]
    fn compat_committed_taproot_survives_absence_until_confirmation() {
        let parent = tx(
            OutPoint::null(),
            100_000,
            ScriptBuf::new_p2wpkh(&pubkey(9).wpubkey_hash().unwrap()),
        );
        let contract = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            ScriptBuf::new_p2tr(
                crate::utill::global_secp(),
                pubkey(7).inner.x_only_public_key().0,
                None,
            ),
        );
        let mut coin = OutgoingSwapCoin::new_taproot(
            key(6),
            ScriptBuf::new(),
            ScriptBuf::new(),
            contract.clone(),
            Amount::from_sat(50_000),
            1,
        );
        coin.committed = false;
        let chain = StubChain::with(&[(&parent, 50)]);
        let url = start_electrum_stub(chain.clone());
        let backend = electrum(&url);
        // A split whose send failed is dropped, never sent by recovery.
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::Discarded
        );
        assert!(chain.lock().unwrap().broadcast.is_empty());
        coin.committed = true;
        chain.lock().unwrap().reject_broadcast = true;
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::NotYet
        );
        assert!(chain.lock().unwrap().broadcast.is_empty());
        chain.lock().unwrap().reject_broadcast = false;
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::OnChain
        );
        {
            let chain = chain.lock().unwrap();
            let txid = contract.compute_txid();
            assert_eq!(chain.broadcast, vec![txid]);
            assert_eq!(chain.txs[&txid].0, contract);
        }
        // A failed send that reached the network anyway is still reclaimed:
        // funding the backend knows outweighs the missing flag.
        coin.committed = false;
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::OnChain
        );
        let txid = contract.compute_txid();
        assert!(chain
            .lock()
            .unwrap()
            .broadcast
            .iter()
            .all(|sent| *sent == txid));
    }

    #[test]
    fn committed_legacy_resends_unknown_funding_before_its_contract() {
        let parent = tx(OutPoint::null(), 100_000, ScriptBuf::new());
        let funding = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            ScriptBuf::new(),
        );
        let mut coin = outgoing_coin();
        coin.contract_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        coin.funding_tx = Some(funding.clone());
        let chain = StubChain::with(&[(&parent, 50)]);
        let url = start_electrum_stub(chain.clone());
        let backend = electrum(&url);
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::NotYet
        );
        assert!(chain.lock().unwrap().broadcast.is_empty());

        let digest = secp256k1::Message::from_digest([1; 32]);
        coin.others_contract_sig = Some(bitcoin::ecdsa::Signature::sighash_all(
            crate::utill::global_secp().sign_ecdsa(&digest, &key(3)),
        ));
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::OnChain
        );
        assert_eq!(
            chain.lock().unwrap().broadcast,
            vec![funding.compute_txid(), coin.contract_tx.compute_txid()]
        );
    }

    #[test]
    fn uncommitted_legacy_is_dropped_unless_its_funding_is_seen() {
        let parent = tx(OutPoint::null(), 100_000, ScriptBuf::new());
        let funding = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            ScriptBuf::new(),
        );
        let mut coin = outgoing_coin();
        coin.committed = false;
        coin.contract_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        coin.funding_tx = Some(funding.clone());
        let digest = secp256k1::Message::from_digest([1; 32]);
        coin.others_contract_sig = Some(bitcoin::ecdsa::Signature::sighash_all(
            crate::utill::global_secp().sign_ecdsa(&digest, &key(3)),
        ));
        let chain = StubChain::with(&[(&parent, 50)]);
        let url = start_electrum_stub(chain.clone());
        let backend = electrum(&url);
        // A split whose send failed: recovery sends neither its funding nor
        // its contract, and drops it.
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::Discarded
        );
        assert!(chain.lock().unwrap().broadcast.is_empty());

        // The failed send reached the mempool anyway: the split is kept and
        // its contract goes out so the timelock can reclaim it.
        chain
            .lock()
            .unwrap()
            .txs
            .insert(funding.compute_txid(), (funding.clone(), 0));
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::OnChain
        );
        assert_eq!(
            chain.lock().unwrap().broadcast,
            vec![coin.contract_tx.compute_txid()]
        );
    }

    #[test]
    fn uncommitted_split_is_kept_until_its_funding_is_dead() {
        let parent = tx(OutPoint::null(), 100_000, ScriptBuf::new());
        let funding = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            ScriptBuf::new(),
        );
        let conflict = tx(
            OutPoint::new(parent.compute_txid(), 0),
            40_000,
            ScriptBuf::new(),
        );
        let mut coin = outgoing_coin();
        coin.committed = false;
        coin.contract_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        coin.funding_tx = Some(funding);
        let chain = StubChain::with(&[(&parent, 50), (&conflict, 0)]);
        let url = start_electrum_stub(chain.clone());
        let backend = electrum(&url);
        // An unconfirmed spend of its input may still be evicted, and the
        // funding could then confirm: keep the coin, and send nothing.
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::NotYet
        );
        assert!(chain.lock().unwrap().broadcast.is_empty());

        // Once that spend confirms, the funding can never confirm.
        chain
            .lock()
            .unwrap()
            .txs
            .insert(conflict.compute_txid(), (conflict.clone(), 50));
        assert_eq!(
            Wallet::ensure_contract_on_chain(&electrum(&url), SWAP, &coin).unwrap(),
            ContractChainState::Discarded
        );
        assert!(chain.lock().unwrap().broadcast.is_empty());
    }

    /// A mined parent, our unsent Legacy funding spending it, and the coin
    /// whose contract spends that funding. `seed` keeps each coin distinct.
    fn unsent_coin(seed: u8) -> (Transaction, Transaction, OutgoingSwapCoin) {
        let parent = tx(
            OutPoint::new(Txid::from_byte_array([seed; 32]), 0),
            100_000,
            ScriptBuf::new(),
        );
        let funding = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            ScriptBuf::new(),
        );
        let mut coin = outgoing_coin();
        coin.committed = false;
        coin.contract_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        coin.funding_tx = Some(funding.clone());
        (parent, funding, coin)
    }

    /// The swap's incoming coin and `outgoing`, each unsent coin's funding
    /// inputs reserved for the swap.
    fn unsent_wallet(path: &Path, url: &str, outgoing: &[&OutgoingSwapCoin]) -> RwLock<Wallet> {
        let mut wallet = stub_wallet(path, electrum(url));
        wallet.add_incoming_swapcoin(&incoming_coin());
        for coin in outgoing {
            wallet.add_outgoing_swapcoin(coin);
            if let Some(funding) = coin.funding_tx.as_ref().filter(|_| !coin.committed) {
                let inputs: Vec<_> = funding.input.iter().map(|i| i.previous_output).collect();
                wallet.reserve_swap_locks(SWAP, &inputs);
            }
        }
        wallet.save_to_disk().unwrap();
        RwLock::new(wallet)
    }

    /// Fresh connection per pass: passes run a block apart, past any cache.
    fn settle(wallet: &RwLock<Wallet>, url: &str, grace_over: bool) -> UnsentPass {
        Wallet::settle_unsent_funding(wallet, &electrum(url), SWAP, grace_over).unwrap()
    }

    fn coin_counts(wallet: &RwLock<Wallet>) -> (usize, usize, usize) {
        let w = wallet.read().unwrap();
        (
            w.get_incoming_swapcoins_count(),
            w.get_outgoing_swapcoins_count(),
            w.store.swap_locks.values().map(|l| l.outpoints.len()).sum(),
        )
    }

    #[test]
    fn unsent_funding_waits_out_the_grace_then_frees_only_its_inputs() {
        let (parent, _, coin) = unsent_coin(1);
        let chain = StubChain::with(&[(&parent, 50)]);
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = unsent_wallet(&temp_dir.path().join("wallet.cbor"), &url, &[&coin]);

        let waiting = UnsentPass {
            waiting: true,
            ..UnsentPass::default()
        };
        assert_eq!(settle(&wallet, &url, false), waiting);
        assert_eq!(coin_counts(&wallet), (1, 1, 1));

        let released = UnsentPass {
            released: true,
            ..UnsentPass::default()
        };
        assert_eq!(settle(&wallet, &url, true), released);
        // Keys and contract data stay: the funding could still confirm.
        assert_eq!(coin_counts(&wallet), (1, 1, 0));
        assert_eq!(settle(&wallet, &url, true), UnsentPass::default());
        assert_eq!(coin_counts(&wallet), (1, 1, 0));

        // The maker's refund pass neither sends nor drops the kept coin.
        Wallet::recover_timelocked_swapcoins(
            &wallet,
            &electrum(&url),
            &shutdown_after(60),
            None,
            &|_| false,
        )
        .unwrap();
        assert_eq!(coin_counts(&wallet), (1, 1, 0));
        assert!(chain.lock().unwrap().broadcast.is_empty());
    }

    #[test]
    fn unsent_funding_seen_after_release_is_recorded_as_sent() {
        let (parent, funding, coin) = unsent_coin(2);
        let chain = StubChain::with(&[(&parent, 50)]);
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = unsent_wallet(&temp_dir.path().join("wallet.cbor"), &url, &[&coin]);
        assert!(settle(&wallet, &url, true).released);

        chain
            .lock()
            .unwrap()
            .txs
            .insert(funding.compute_txid(), (funding.clone(), 0));
        assert_eq!(settle(&wallet, &url, true), UnsentPass::default());
        let key = coin.contract_tx.compute_txid().to_string();
        assert!(wallet.read().unwrap().store.outgoing_swapcoins[&key].committed);
        assert!(!wallet.read().unwrap().has_unsent_funding(SWAP));
        // Recording it sends nothing: the refund pass takes it from here.
        assert!(chain.lock().unwrap().broadcast.is_empty());
    }

    #[test]
    fn unsent_funding_is_dropped_only_once_its_input_spend_confirms() {
        let (parent, _, coin) = unsent_coin(3);
        let conflict = tx(
            OutPoint::new(parent.compute_txid(), 0),
            40_000,
            ScriptBuf::new(),
        );
        let chain = StubChain::with(&[(&parent, 50), (&conflict, 0)]);
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = unsent_wallet(&temp_dir.path().join("wallet.cbor"), &url, &[&coin]);

        // A mempool spend may still be evicted: keep everything.
        assert!(!settle(&wallet, &url, true).finished);
        assert_eq!(coin_counts(&wallet), (1, 1, 0));

        chain
            .lock()
            .unwrap()
            .txs
            .insert(conflict.compute_txid(), (conflict.clone(), 50));
        let finished = UnsentPass {
            finished: true,
            ..UnsentPass::default()
        };
        assert_eq!(settle(&wallet, &url, true), finished);
        assert_eq!(coin_counts(&wallet), (0, 0, 0));
        assert!(chain.lock().unwrap().broadcast.is_empty());
    }

    #[test]
    fn dead_unsent_split_leaves_the_rest_of_the_swap() {
        let (parent, _, unsent) = unsent_coin(4);
        let conflict = tx(
            OutPoint::new(parent.compute_txid(), 0),
            40_000,
            ScriptBuf::new(),
        );
        let (_, _, mut sent) = unsent_coin(5);
        sent.committed = true;
        let chain = StubChain::with(&[(&parent, 50), (&conflict, 50)]);
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = unsent_wallet(
            &temp_dir.path().join("wallet.cbor"),
            &url,
            &[&unsent, &sent],
        );

        assert_eq!(settle(&wallet, &url, false), UnsentPass::default());
        assert_eq!(coin_counts(&wallet), (1, 1, 0));
        let key = sent.contract_tx.compute_txid().to_string();
        assert!(wallet
            .read()
            .unwrap()
            .store
            .outgoing_swapcoins
            .contains_key(&key));
    }

    #[test]
    fn failed_lookup_keeps_unsent_funding_reserved() {
        let (parent, _, coin) = unsent_coin(6);
        let chain = StubChain::with(&[(&parent, 50)]);
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = unsent_wallet(&temp_dir.path().join("wallet.cbor"), &url, &[&coin]);

        chain
            .lock()
            .unwrap()
            .fail_lookups
            .insert(coin.contract_tx.compute_txid());
        assert!(Wallet::settle_unsent_funding(&wallet, &electrum(&url), SWAP, true).is_err());
        assert_eq!(coin_counts(&wallet), (1, 1, 1));
    }

    /// One coin's failed lookup must not cost another coin's proof that its
    /// funding was seen: once that funding is evicted it would read as unsent.
    #[test]
    fn seen_funding_is_saved_even_when_another_lookup_fails() {
        let (parent_a, funding_a, seen) = unsent_coin(7);
        let (parent_b, _, failing) = unsent_coin(8);
        let chain = StubChain::with(&[(&parent_a, 50), (&parent_b, 50), (&funding_a, 0)]);
        chain
            .lock()
            .unwrap()
            .fail_lookups
            .insert(failing.contract_tx.compute_txid());
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = unsent_wallet(
            &temp_dir.path().join("wallet.cbor"),
            &url,
            &[&seen, &failing],
        );

        assert!(Wallet::settle_unsent_funding(&wallet, &electrum(&url), SWAP, true).is_err());
        let key = seen.contract_tx.compute_txid().to_string();
        assert!(wallet.read().unwrap().store.outgoing_swapcoins[&key].committed);
        // Nothing is freed while a lookup fails.
        assert_eq!(coin_counts(&wallet), (1, 2, 2));

        // The seen funding is evicted and the backend recovers: the failing
        // coin's inputs are freed, the committed one's stay reserved.
        {
            let mut chain = chain.lock().unwrap();
            chain.txs.remove(&funding_a.compute_txid());
            chain.fail_lookups.clear();
        }
        assert!(settle(&wallet, &url, true).released);
        assert_eq!(coin_counts(&wallet), (1, 2, 1));
        let held = OutPoint::new(parent_a.compute_txid(), 0);
        assert!(wallet.read().unwrap().store.swap_locks[SWAP]
            .outpoints
            .contains(&held));
    }

    /// The batch is saved whole before its sends: a failed save leaves none
    /// of it, so a later save cannot persist half a batch.
    #[test]
    fn funding_batch_saves_whole_or_not_at_all() {
        let (parent, _, coin) = unsent_coin(9);
        let url = start_electrum_stub(StubChain::with(&[(&parent, 50)]));
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("wallet.cbor");
        let mut wallet = stub_wallet(&path, electrum(&url));
        wallet.save_to_disk().unwrap();
        let incoming = incoming_coin();

        // A directory at the destination forces the atomic replacement to fail.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(wallet
            .save_funding_batch(std::slice::from_ref(&incoming), std::slice::from_ref(&coin))
            .is_err());
        assert_eq!(wallet.get_incoming_swapcoins_count(), 0);
        assert_eq!(wallet.get_outgoing_swapcoins_count(), 0);

        std::fs::remove_dir(&path).unwrap();
        wallet
            .save_funding_batch(std::slice::from_ref(&incoming), &[coin])
            .unwrap();
        let (store, _) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
        assert_eq!(store.incoming_swapcoins.len(), 1);
        assert_eq!(store.outgoing_swapcoins.len(), 1);
    }

    /// Each funding send restarts the grace on disk: slow earlier sends, or
    /// a claim made long before, must not let a restart free the inputs of a
    /// send that may still be in flight.
    #[test]
    fn each_send_attempt_persists_a_fresh_grace_origin() {
        let (parent, _, _) = unsent_coin(10);
        let url = start_electrum_stub(StubChain::with(&[(&parent, 50)]));
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("wallet.cbor");
        let mut wallet = stub_wallet(&path, electrum(&url));
        wallet.reserve_swap_locks(SWAP, &[OutPoint::new(parent.compute_txid(), 0)]);
        wallet.store.swap_locks.get_mut(SWAP).unwrap().reserved_at = 1;
        wallet.save_to_disk().unwrap();
        let saved_at = || {
            let (store, _) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
            store.swap_locks[SWAP].reserved_at
        };

        let before = now_secs();
        wallet.restart_funding_grace(SWAP).unwrap();
        let first = saved_at();
        assert!(first >= before, "the first send restarts the grace on disk");

        // Origins are whole seconds; wait for the next one.
        thread::sleep(Duration::from_millis(1_100));
        wallet.restart_funding_grace(SWAP).unwrap();
        assert!(
            saved_at() > first,
            "each later send moves the origin forward"
        );
    }

    #[test]
    fn compat_incoming_claim_report_and_removal_save_together() {
        for role in [SwapRole::Maker, SwapRole::Taker] {
            let incoming = incoming_coin();
            let outgoing = outgoing_coin();
            let chain = StubChain::with(&[
                (&incoming.contract_tx, 50),
                (&outgoing.contract_tx, OUTGOING_HEIGHT),
            ]);
            let url = start_electrum_stub(chain.clone());
            let directory = tempdir().unwrap();
            let path = directory.path().join("wallet.cbor");
            let wallet = wallet_with(&path, &url, &incoming, Some(&outgoing));
            let mut other = outgoing.clone();
            other.swap_id = Some("other".into());
            other.contract_tx.output[0].value = Amount::from_sat(49_999);
            wallet.write().unwrap().add_outgoing_swapcoin(&other);
            let swept = Wallet::sweep_incoming_swapcoins_for_role(
                &wallet,
                &electrum(&url),
                &shutdown_after(60),
                None,
                role,
            )
            .unwrap();
            assert_eq!(swept.resolved.len(), 1);
            let (saved, _) =
                WalletStore::read_from_disk(&path, Some("test-password".into())).unwrap();
            assert!(saved.incoming_swapcoins.is_empty());
            assert!(
                saved.outgoing_swapcoins[&outgoing.contract_tx.compute_txid().to_string()]
                    .incoming_claimed
            );
            assert!(
                !saved.outgoing_swapcoins[&other.contract_tx.compute_txid().to_string()]
                    .incoming_claimed
            );
            let mut snapshot = wallet.write().unwrap();
            snapshot.store = saved;
            let reports = snapshot.swap_reports();
            assert_eq!(reports.recovery.len(), 1);
            let report = &reports.recovery[0];
            assert_eq!(report.swap_id, SWAP);
            assert_eq!(report.role, role);
            assert_eq!(report.recovery_type, "hashlock");
            assert_eq!(report.recovery_txids, vec![swept.resolved[0].1.to_string()]);
        }
    }

    #[test]
    fn compat_failed_recovery_save_rolls_back_then_retries() {
        let incoming = incoming_coin();
        let outgoing = outgoing_coin();
        let chain = StubChain::with(&[(&incoming.contract_tx, 50)]);
        let url = start_electrum_stub(chain);
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.cbor");
        let wallet = wallet_with(&path, &url, &incoming, Some(&outgoing));
        let backend = electrum(&url);
        let shutdown = shutdown_after(60);
        let (sweeps, _) =
            Wallet::broadcast_incoming_sweeps(&wallet, &backend, &shutdown, None, &mut false)
                .unwrap();
        assert_eq!(sweeps.len(), 1);
        let before = {
            let wallet = wallet.read().unwrap();
            (
                wallet.store.incoming_swapcoins.clone(),
                wallet.store.outgoing_swapcoins.clone(),
                wallet.store.reports.clone(),
            )
        };
        let original_bytes = std::fs::read(&path).unwrap();
        let saved_path = path.with_extension("saved");
        std::fs::rename(&path, &saved_path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(Wallet::finish_recoveries(
            &wallet,
            &backend,
            &shutdown,
            sweeps.clone(),
            Vec::new(),
            Vec::new(),
            Some(SwapRole::Taker)
        )
        .is_err());
        {
            let wallet = wallet.read().unwrap();
            assert_eq!(wallet.store.incoming_swapcoins, before.0);
            assert_eq!(wallet.store.outgoing_swapcoins, before.1);
            assert_eq!(wallet.store.reports, before.2);
        }
        assert_eq!(std::fs::read(&saved_path).unwrap(), original_bytes);
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&saved_path, &path).unwrap();
        let recovered = Wallet::finish_recoveries(
            &wallet,
            &backend,
            &shutdown,
            sweeps,
            Vec::new(),
            Vec::new(),
            Some(SwapRole::Taker),
        )
        .unwrap();
        assert_eq!(recovered.0.resolved.len(), 1);
        let (saved, _) = WalletStore::read_from_disk(&path, Some("test-password".into())).unwrap();
        assert!(saved.incoming_swapcoins.is_empty());
        assert!(saved
            .outgoing_swapcoins
            .values()
            .all(|coin| coin.incoming_claimed));
        let mut wallet = wallet.write().unwrap();
        wallet.store = saved;
        assert_eq!(wallet.swap_reports().recovery.len(), 1);
    }

    /// The taker side: its incoming contract is still in the mempool when its
    /// outgoing timelock matures. It will sweep that coin, so a refund now
    /// would settle the swap both ways; the refund waits.
    #[test]
    fn mempool_incoming_holds_the_matured_refund() {
        assert!(broadcast_by_recovery(Some(0)).is_empty());

        // With no incoming contract anywhere, the same pass refunds, so the
        // hold above comes from the mempool contract.
        let refunds = broadcast_by_recovery(None);
        let outgoing_contract = OutPoint::new(outgoing_coin().contract_tx.compute_txid(), 0);
        assert_eq!(refunds.len(), 1);
        assert_eq!(refunds[0].input[0].previous_output, outgoing_contract);
    }

    /// Where our refunds go: the address saved with the coin.
    fn recovery_address() -> Address {
        let script = ScriptBuf::new_p2wpkh(&pubkey(7).wpubkey_hash().unwrap());
        Address::from_script(&script, bitcoin::Network::Regtest).unwrap()
    }

    fn with_recovery_address(mut coin: OutgoingSwapCoin) -> OutgoingSwapCoin {
        coin.recovery_address = Some(recovery_address().into_unchecked());
        coin
    }

    fn legacy_coin() -> OutgoingSwapCoin {
        with_recovery_address(outgoing_coin())
    }

    fn taproot_coin() -> OutgoingSwapCoin {
        let mut coin = taproot_coin_and_recovery().0;
        // Recovery only considers a coin holding its own key.
        coin.my_privkey = Some(key(1));
        with_recovery_address(coin)
    }

    /// Our recovery of `coin`, priced at 1 sat/vB.
    fn pending_recovery(coin: &OutgoingSwapCoin) -> Transaction {
        Wallet::create_timelock_recovery_tx(coin, &[1.0], recovery_address()).unwrap()
    }

    /// The first maker's Legacy hop and its confirmed timelock refund.
    fn refunded_first_maker_hop() -> (WatchOnlySwapCoin, Transaction) {
        let redeemscript =
            create_contract_redeemscript(&pubkey(2), &pubkey(3), &Hash160::all_zeros(), &20);
        let contract_tx = tx(
            OutPoint::new(Txid::from_byte_array([6; 32]), 0),
            50_000,
            redeemscript.to_p2wsh(),
        );
        let mut refund = tx(
            OutPoint::new(contract_tx.compute_txid(), 0),
            49_000,
            recovery_address().script_pubkey(),
        );
        refund.input[0].witness =
            Witness::from_slice(&[vec![1; 72], Vec::new(), redeemscript.to_bytes()]);
        let hop = WatchOnlySwapCoin::new_legacy(
            pubkey(3),
            pubkey(2),
            contract_tx,
            redeemscript,
            Amount::from_sat(50_000),
        );
        (hop, refund)
    }

    /// One refund pass over `coin`, with `pending` spending its contract from
    /// the mempool and every fee estimate at `feerate`.
    struct Pass {
        coin: OutgoingSwapCoin,
        pending: Transaction,
        feerate: f64,
        /// The swap's incoming coin is being claimed by hashlock.
        claimed: bool,
        /// The first maker took its own outgoing back by timelock.
        first_maker_refunded: bool,
    }

    impl Pass {
        fn over(coin: OutgoingSwapCoin, feerate: f64) -> Self {
            Pass {
                pending: pending_recovery(&coin),
                coin,
                feerate,
                claimed: false,
                first_maker_refunded: false,
            }
        }

        /// Returns the refunds the pass sent and the txs it broadcast.
        fn run(self) -> (Vec<SentSpend>, Vec<Transaction>) {
            let chain = StubChain::with(&[
                (&self.coin.contract_tx, OUTGOING_HEIGHT),
                (&self.pending, 0),
            ]);
            chain.lock().unwrap().feerate = self.feerate;
            let url = start_electrum_stub(chain.clone());
            let temp_dir = tempdir().unwrap();
            let mut wallet = stub_wallet(&temp_dir.path().join("wallet.cbor"), electrum(&url));
            wallet.add_outgoing_swapcoin(&self.coin);
            if self.first_maker_refunded {
                let (hop, refund) = refunded_first_maker_hop();
                let mut chain = chain.lock().unwrap();
                for tx in [&hop.contract_tx, &refund] {
                    chain
                        .txs
                        .insert(tx.compute_txid(), (tx.clone(), OUTGOING_HEIGHT));
                }
                wallet
                    .store
                    .watchonly_swapcoins
                    .insert(SWAP.to_string(), vec![hop]);
            }
            wallet.save_to_disk().unwrap();

            let claimed = self.claimed;
            let (refunds, discarded) = Wallet::broadcast_timelock_recoveries(
                &RwLock::new(wallet),
                &electrum(&url),
                &shutdown_after(60),
                None,
                &|swap_id| claimed && swap_id == SWAP,
                &|_| false,
                &mut false,
                false,
            )
            .unwrap();
            assert!(discarded.is_empty());
            let chain = chain.lock().unwrap();
            let broadcast = chain
                .broadcast
                .iter()
                .map(|txid| chain.txs[txid].0.clone())
                .collect();
            (refunds, broadcast)
        }
    }

    /// Checks `pass` sent exactly one replacement of its pending tx: ours, to
    /// the stored address, at a higher fee.
    fn assert_replaces(pass: Pass) {
        let (coin, pending) = (pass.coin.clone(), pass.pending.clone());
        let contract_txid = coin.contract_tx.compute_txid();
        let (refunds, broadcast) = pass.run();
        let [replacement] = &broadcast[..] else {
            panic!("expected one replacement, got {:?}", broadcast);
        };
        assert_eq!(
            refunds,
            vec![(
                contract_txid.to_string(),
                contract_txid,
                replacement.compute_txid()
            )]
        );
        assert!(coin.is_own_timelock_spend(replacement));
        assert_eq!(replacement.output.len(), 1);
        assert_eq!(
            replacement.output[0].script_pubkey,
            recovery_address().script_pubkey()
        );
        assert!(replacement.output[0].value < pending.output[0].value);
        // The fee is priced on the size estimate, so the signed tx must fit it.
        assert!(
            replacement.vsize() as u64
                <= contract_and_timelock_vsize(coin.protocol, SpendKind::Timelock)
        );
    }

    /// Electrum hides a mempool-spent output, which used to read as "nothing
    /// to do". Our own recovery spending it must be told apart from that.
    #[test]
    fn electrum_classifies_our_unconfirmed_recovery_as_pending() {
        for coin in [legacy_coin(), taproot_coin()] {
            let pending = pending_recovery(&coin);
            let chain = StubChain::with(&[(&coin.contract_tx, OUTGOING_HEIGHT), (&pending, 0)]);
            let url = start_electrum_stub(chain);
            let state = Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin).unwrap();
            assert_eq!(state, ContractChainState::RecoveryPending(pending));
        }
    }

    /// The other side's unconfirmed claim is not ours to replace.
    #[test]
    fn electrum_leaves_an_unconfirmed_claim_by_the_other_side() {
        let coin = legacy_coin();
        let mut claim = pending_recovery(&coin);
        // A hashlock claim carries the preimage where a refund leaves it empty.
        claim.input[0].witness = Witness::from_slice(&[
            vec![1; 72],
            vec![2; 32],
            coin.contract_redeemscript.clone().unwrap().into_bytes(),
        ]);
        let chain = StubChain::with(&[(&coin.contract_tx, OUTGOING_HEIGHT), (&claim, 0)]);
        let url = start_electrum_stub(chain);
        let state = Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin).unwrap();
        assert_eq!(state, ContractChainState::NotYet);
    }

    /// Legacy refunds lock by CSV `nSequence`, Taproot ones by `nLockTime`, and
    /// each has its own size estimate behind the fee.
    #[test]
    fn stuck_recovery_is_replaced_when_fees_rise() {
        assert_replaces(Pass::over(legacy_coin(), 10.0));
        assert_replaces(Pass::over(taproot_coin(), 10.0));
    }

    /// A backend can hand us any unconfirmed tx shaped like our refund. Its
    /// output must never choose where the replacement pays.
    #[test]
    fn forged_pending_tx_cannot_redirect_the_refund() {
        let mut pass = Pass::over(legacy_coin(), 10.0);
        pass.pending.output[0].script_pubkey =
            ScriptBuf::new_p2wpkh(&pubkey(9).wpubkey_hash().unwrap());
        pass.pending.input[0].witness = Witness::from_slice(&[
            vec![0x30; 72],
            Vec::new(),
            pass.coin
                .contract_redeemscript
                .clone()
                .unwrap()
                .into_bytes(),
        ]);
        assert!(pass.coin.is_own_timelock_spend(&pass.pending));
        assert_replaces(pass);
    }

    /// A coin with no stored address never sent a refund of ours.
    #[test]
    fn pending_tx_is_not_replaced_without_a_stored_address() {
        let mut pass = Pass::over(legacy_coin(), 10.0);
        pass.coin.recovery_address = None;
        assert_eq!(pass.run(), (Vec::new(), Vec::new()));
    }

    #[test]
    fn stuck_recovery_stays_when_a_replacement_is_not_due() {
        // The market has not moved.
        assert_eq!(
            Pass::over(legacy_coin(), 1.0).run(),
            (Vec::new(), Vec::new())
        );
        // It moved by less than the 1 sat/vB a replacement must add.
        assert_eq!(
            Pass::over(legacy_coin(), 1.5).run(),
            (Vec::new(), Vec::new())
        );
    }

    /// We refund a claimed swap once its outgoing dangles, and the first maker
    /// can still claim that outgoing by hashlock. A stuck refund there races
    /// the claim, so it is bumped like any other.
    #[test]
    fn stuck_refund_of_a_claimed_swap_is_replaced() {
        assert_replaces(Pass {
            claimed: true,
            first_maker_refunded: true,
            ..Pass::over(legacy_coin(), 10.0)
        });
    }

    /// The replacement must add `increment_rate` sat/vB over its own size.
    #[test]
    fn outbids_needs_the_full_increment() {
        let fee = Amount::from_sat;
        assert!(outbids(fee(100), fee(250), 150, 1.0));
        assert!(!outbids(fee(100), fee(249), 150, 1.0));
        // A node with a higher increment rejects what the default accepts.
        assert!(!outbids(fee(100), fee(250), 150, 5.0));
        assert!(outbids(fee(100), fee(850), 150, 5.0));
    }
}

#[cfg(test)]
mod recovery_address_tests {
    use super::*;

    fn address() -> Address<NetworkUnchecked> {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        Address::p2tr(&secp, keypair.x_only_public_key().0, None, Network::Regtest).into_unchecked()
    }

    #[test]
    fn retry_reuses_the_stored_recovery_address() {
        let stored = address();
        let (selected, created) = recovery_address_or_else(Some(stored.clone()), || {
            panic!("a retry must not allocate another address")
        })
        .unwrap();

        assert_eq!(selected, stored);
        assert!(!created);
    }

    #[test]
    fn first_recovery_creates_an_address() {
        let expected = address();
        let (selected, created) = recovery_address_or_else(None, || Ok(expected.clone())).unwrap();

        assert_eq!(selected, expected);
        assert!(created);
    }
}

#[cfg(test)]
mod legacy_recovery_tests {
    use super::{timelock_reconcile_tests::tx, *};
    use crate::wallet::{
        blockchain::{CoreRPC, CoreRpcConfig, Electrum},
        swapcoin::OutgoingSwapCoin,
    };
    use bitcoin::{
        consensus::encode::serialize_hex, hashes::Hash, secp256k1::SecretKey, Amount, OutPoint,
        PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use serde_json::{json, Value};
    use std::{
        io::{BufRead, BufReader, Read, Write as IoWrite},
        net::TcpListener,
    };

    fn start_electrum_recovery_stub(
        known_txs: Vec<(Transaction, Option<u64>, bool)>,
        aliases: Vec<(Txid, Transaction)>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = genesis.block_hash().to_string();
        let header_hex = serialize_hex(&genesis.header);

        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { continue };
                let _ = stream.set_nodelay(true);
                let (hash, header) = (genesis_hash.clone(), header_hex.clone());
                let txs = known_txs.clone();
                let aliases = aliases.clone();
                std::thread::spawn(move || {
                    let mut out = stream.try_clone().expect("clone stub stream");
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { return };
                        let req: serde_json::Value = match serde_json::from_str(&line) {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        let id = req["id"].clone();
                        let method = req["method"].as_str().unwrap_or_default();
                        let resp = match method {
                            "server.features" => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "server_version": "stub",
                                    "genesis_hash": hash,
                                    "protocol_min": "1.4",
                                    "protocol_max": "1.4",
                                    "hash_function": "sha256",
                                    "pruning": serde_json::Value::Null,
                                }
                            }),
                            "blockchain.headers.subscribe" => {
                                json!({"jsonrpc": "2.0", "id": id, "result": {"height": 100, "hex": header}})
                            }
                            "blockchain.block.header" => {
                                json!({"jsonrpc": "2.0", "id": id, "result": header})
                            }
                            "blockchain.scripthash.listunspent" => {
                                let mut unspent = Vec::new();
                                for (tx, height, is_unspent) in &txs {
                                    let is_spent_by_known = txs.iter().any(|(t, _, _)| {
                                        t.input.iter().any(|i| {
                                            i.previous_output.txid == tx.compute_txid()
                                                && i.previous_output.vout == 0
                                        })
                                    });
                                    if *is_unspent && !is_spent_by_known {
                                        let h = height.map(|h| h as i64).unwrap_or(0);
                                        unspent.push(json!({
                                            "height": h,
                                            "tx_hash": tx.compute_txid().to_string(),
                                            "tx_pos": 0,
                                            "value": tx.output[0].value.to_sat(),
                                        }));
                                    }
                                }
                                json!({"jsonrpc": "2.0", "id": id, "result": unspent})
                            }
                            "blockchain.scripthash.get_history" => {
                                let mut history = Vec::new();
                                for (tx, height, _) in &txs {
                                    let h = height.map(|h| h as i64).unwrap_or(0);
                                    history.push(json!({
                                        "height": h,
                                        "tx_hash": tx.compute_txid().to_string(),
                                    }));
                                }
                                json!({"jsonrpc": "2.0", "id": id, "result": history})
                            }
                            "blockchain.transaction.get" => {
                                let txid_requested = req["params"][0].as_str().unwrap_or_default();
                                if let Some((tx, _, _)) = txs.iter().find(|(tx, _, _)| {
                                    tx.compute_txid().to_string() == txid_requested
                                }) {
                                    json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "result": serialize_hex(tx)
                                    })
                                } else if let Some((_, tx)) =
                                    aliases.iter().find(|(alias_txid, _)| {
                                        alias_txid.to_string() == txid_requested
                                    })
                                {
                                    json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "result": serialize_hex(tx)
                                    })
                                } else {
                                    json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "error": {
                                            "code": 1,
                                            "message": "No such mempool or blockchain transaction"
                                        }
                                    })
                                }
                            }
                            _ => {
                                json!({"jsonrpc": "2.0", "id": id, "result": serde_json::Value::Null})
                            }
                        };
                        if writeln!(out, "{resp}").is_err() {
                            return;
                        }
                    }
                });
            }
        });

        url
    }

    fn start_core_recovery_stub(
        known_txs: Vec<(Transaction, Option<u64>, bool)>,
        aliases: Vec<(Txid, Transaction)>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind core stub");
        let addr = listener.local_addr().unwrap();
        let url = format!("{}:{}", addr.ip(), addr.port());

        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else { continue };
                let _ = stream.set_nodelay(true);
                let txs = known_txs.clone();
                let aliases = aliases.clone();
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().expect("clone core stream"));
                    loop {
                        let mut content_length = 0;
                        let mut line = String::new();
                        loop {
                            line.clear();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                return;
                            }
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                break;
                            }
                            if let Some((k, v)) = trimmed.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    content_length = v.trim().parse::<usize>().unwrap_or(0);
                                }
                            }
                        }

                        if content_length == 0 {
                            return;
                        }

                        let mut body_buf = vec![0u8; content_length];
                        if reader.read_exact(&mut body_buf).is_err() {
                            return;
                        }

                        let Ok(req): Result<serde_json::Value, _> =
                            serde_json::from_slice(&body_buf)
                        else {
                            return;
                        };
                        let id = req["id"].clone();
                        let method = req["method"].as_str().unwrap_or_default();
                        let params = &req["params"];

                        let (status_code, resp_body) = match method {
                            "gettxspendingprevout" => {
                                let requested = &params[0][0];
                                let spending = txs
                                    .iter()
                                    .find(|(tx, height, _)| {
                                        height.is_none()
                                            && tx.input.iter().any(|input| {
                                                input.previous_output.txid.to_string()
                                                    == requested["txid"]
                                                        .as_str()
                                                        .unwrap_or_default()
                                                    && u64::from(input.previous_output.vout)
                                                        == requested["vout"].as_u64().unwrap_or(0)
                                            })
                                    })
                                    .map(|(tx, _, _)| tx.compute_txid());
                                (
                                    200,
                                    json!({"id": id, "result": [{"txid": requested["txid"], "vout": requested["vout"], "spendingtxid": spending}], "error": null}),
                                )
                            }
                            "getblockcount" => {
                                let height = txs
                                    .iter()
                                    .filter_map(|(_, height, _)| *height)
                                    .max()
                                    .unwrap_or(0);
                                (200, json!({"id": id, "result": height, "error": null}))
                            }
                            "getblockhash" => (
                                200,
                                json!({"id": id, "result": format!("{:064x}", params[0].as_u64().unwrap()), "error": null}),
                            ),
                            "getblock" => {
                                let height =
                                    u64::from_str_radix(params[0].as_str().unwrap(), 16).unwrap();
                                let block = bitcoin::Block {
                                    header: bitcoin::constants::genesis_block(
                                        bitcoin::Network::Regtest,
                                    )
                                    .header,
                                    txdata: txs
                                        .iter()
                                        .filter(|(_, h, _)| *h == Some(height))
                                        .map(|(tx, _, _)| tx.clone())
                                        .collect(),
                                };
                                (
                                    200,
                                    json!({"id": id, "result": serialize_hex(&block), "error": null}),
                                )
                            }
                            "getrawtransaction" => {
                                let txid_req = params[0].as_str().unwrap_or_default();
                                let verbose = params
                                    .get(1)
                                    .map(|v| {
                                        v.as_bool().unwrap_or(false)
                                            || v.as_i64().unwrap_or(0) != 0
                                            || v.as_u64().unwrap_or(0) != 0
                                    })
                                    .unwrap_or(false);
                                if let Some((tx, height, _)) = txs
                                    .iter()
                                    .find(|(t, _, _)| t.compute_txid().to_string() == txid_req)
                                {
                                    if verbose {
                                        let blockhash = height.map(|h| format!("{:064x}", h));
                                        let vin: Vec<Value> = tx
                                            .input
                                            .iter()
                                            .map(|i| {
                                                json!({
                                                    "txid": i.previous_output.txid.to_string(),
                                                    "vout": i.previous_output.vout,
                                                    "scriptSig": {"asm": "", "hex": serialize_hex(&i.script_sig)},
                                                    "sequence": i.sequence.0,
                                                })
                                            })
                                            .collect();
                                        let vout: Vec<Value> = tx
                                            .output
                                            .iter()
                                            .enumerate()
                                            .map(|(n, o)| {
                                                json!({
                                                    "value": o.value.to_btc(),
                                                    "n": n,
                                                    "scriptPubKey": {
                                                        "asm": "",
                                                        "hex": serialize_hex(&o.script_pubkey),
                                                        "type": null,
                                                    }
                                                })
                                            })
                                            .collect();
                                        let result = json!({
                                            "in_active_chain": null,
                                            "hex": serialize_hex(tx),
                                            "txid": txid_req,
                                            "hash": tx.compute_wtxid().to_string(),
                                            "size": tx.total_size(),
                                            "vsize": tx.vsize(),
                                            "version": tx.version.0 as u32,
                                            "locktime": tx.lock_time.to_consensus_u32(),
                                            "vin": vin,
                                            "vout": vout,
                                            "blockhash": blockhash,
                                            "confirmations": if height.is_some() { 1 } else { 0 },
                                            "time": 100,
                                            "blocktime": 100,
                                        });
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": result, "error": Value::Null}),
                                        )
                                    } else {
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": serialize_hex(tx), "error": Value::Null}),
                                        )
                                    }
                                } else if let Some((_, tx)) = aliases
                                    .iter()
                                    .find(|(alias_txid, _)| alias_txid.to_string() == txid_req)
                                {
                                    if verbose {
                                        let vin: Vec<Value> = tx
                                            .input
                                            .iter()
                                            .map(|i| {
                                                json!({
                                                    "txid": i.previous_output.txid.to_string(),
                                                    "vout": i.previous_output.vout,
                                                    "scriptSig": {"asm": "", "hex": serialize_hex(&i.script_sig)},
                                                    "sequence": i.sequence.0,
                                                })
                                            })
                                            .collect();
                                        let vout: Vec<Value> = tx
                                            .output
                                            .iter()
                                            .enumerate()
                                            .map(|(n, o)| {
                                                json!({
                                                    "value": o.value.to_btc(),
                                                    "n": n,
                                                    "scriptPubKey": {
                                                        "asm": "",
                                                        "hex": serialize_hex(&o.script_pubkey),
                                                        "type": null,
                                                    }
                                                })
                                            })
                                            .collect();
                                        let result = json!({
                                            "in_active_chain": null,
                                            "hex": serialize_hex(tx),
                                            "txid": txid_req,
                                            "hash": tx.compute_wtxid().to_string(),
                                            "size": tx.total_size(),
                                            "vsize": tx.vsize(),
                                            "version": tx.version.0 as u32,
                                            "locktime": tx.lock_time.to_consensus_u32(),
                                            "vin": vin,
                                            "vout": vout,
                                            "blockhash": Value::Null,
                                            "confirmations": 0,
                                            "time": 100,
                                            "blocktime": 100,
                                        });
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": result, "error": Value::Null}),
                                        )
                                    } else {
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": serialize_hex(tx), "error": Value::Null}),
                                        )
                                    }
                                } else {
                                    (
                                        500,
                                        json!({
                                            "jsonrpc": "1.0",
                                            "id": id,
                                            "result": Value::Null,
                                            "error": {
                                                "code": -5,
                                                "message": "No such mempool or blockchain transaction"
                                            }
                                        }),
                                    )
                                }
                            }
                            "getblockheader" => {
                                let hash_req = params[0].as_str().unwrap_or_default();
                                let height =
                                    u64::from_str_radix(hash_req.trim_start_matches('0'), 16)
                                        .unwrap_or(1);
                                let result = json!({
                                    "hash": hash_req,
                                    "confirmations": 1,
                                    "height": height as usize,
                                    "version": 1,
                                    "versionHex": "00000001",
                                    "merkleroot": "0000000000000000000000000000000000000000000000000000000000000000",
                                    "time": 100,
                                    "mediantime": 100,
                                    "nonce": 0,
                                    "bits": "1d00ffff",
                                    "difficulty": 1.0,
                                    "chainwork": "0000000000000000000000000000000000000000000000000000000000000001",
                                    "nTx": 1,
                                    "previousblockhash": Value::Null,
                                    "nextblockhash": Value::Null,
                                });
                                (
                                    200,
                                    json!({"jsonrpc": "1.0", "id": id, "result": result, "error": Value::Null}),
                                )
                            }
                            "getmempoolentry" => {
                                let txid_req = params[0].as_str().unwrap_or_default();
                                if let Some((tx, height, _)) = txs
                                    .iter()
                                    .find(|(t, _, _)| t.compute_txid().to_string() == txid_req)
                                {
                                    if height.is_none() {
                                        let result = json!({
                                            "vsize": tx.vsize(),
                                            "weight": tx.weight().to_wu() as usize,
                                            "time": 100,
                                            "height": 0,
                                            "descendantcount": 1,
                                            "descendantsize": 100,
                                            "ancestorcount": 1,
                                            "ancestorsize": 100,
                                            "wtxid": tx.compute_wtxid().to_string(),
                                            "fees": {
                                                "base": 0.00001,
                                                "modified": 0.00001,
                                                "ancestor": 0.00001,
                                                "descendant": 0.00001
                                            },
                                            "depends": [],
                                            "spentby": [],
                                            "bip125-replaceable": true,
                                            "unbroadcast": false
                                        });
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": result, "error": Value::Null}),
                                        )
                                    } else {
                                        (
                                            500,
                                            json!({
                                                "jsonrpc": "1.0",
                                                "id": id,
                                                "result": Value::Null,
                                                "error": {
                                                    "code": -5,
                                                    "message": "Transaction not in mempool"
                                                }
                                            }),
                                        )
                                    }
                                } else {
                                    (
                                        500,
                                        json!({
                                            "jsonrpc": "1.0",
                                            "id": id,
                                            "result": Value::Null,
                                            "error": {
                                                "code": -5,
                                                "message": "Transaction not in mempool"
                                            }
                                        }),
                                    )
                                }
                            }
                            "gettxout" => {
                                let txid_req = params[0].as_str().unwrap_or_default();
                                let vout_req = params[1].as_u64().unwrap_or(0) as u32;
                                let include_mempool = params[2].as_bool().unwrap_or(true);
                                if let Some((tx, height, is_unspent)) = txs
                                    .iter()
                                    .find(|(t, _, _)| t.compute_txid().to_string() == txid_req)
                                {
                                    let is_confirmed_spent = txs.iter().any(|(t, h, _)| {
                                        h.is_some()
                                            && t.input.iter().any(|i| {
                                                i.previous_output.txid == tx.compute_txid()
                                                    && i.previous_output.vout == vout_req
                                            })
                                    });
                                    let is_mempool_spent = txs.iter().any(|(t, h, _)| {
                                        h.is_none()
                                            && t.input.iter().any(|i| {
                                                i.previous_output.txid == tx.compute_txid()
                                                    && i.previous_output.vout == vout_req
                                            })
                                    });
                                    let is_spent = if include_mempool {
                                        is_confirmed_spent || is_mempool_spent
                                    } else {
                                        is_confirmed_spent
                                    };
                                    if *is_unspent
                                        && !is_spent
                                        && (height.is_some() || include_mempool)
                                    {
                                        let result = json!({
                                            "bestblock": "0000000000000000000000000000000000000000000000000000000000000000",
                                            "confirmations": if height.is_some() { 1 } else { 0 },
                                            "value": tx.output[vout_req as usize].value.to_btc(),
                                            "scriptPubKey": {
                                                "asm": "",
                                                "hex": serialize_hex(&tx.output[vout_req as usize].script_pubkey),
                                                "type": null,
                                            },
                                            "coinbase": false
                                        });
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": result, "error": Value::Null}),
                                        )
                                    } else {
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": Value::Null, "error": Value::Null}),
                                        )
                                    }
                                } else {
                                    (
                                        200,
                                        json!({"jsonrpc": "1.0", "id": id, "result": Value::Null, "error": Value::Null}),
                                    )
                                }
                            }
                            _ => (
                                200,
                                json!({"jsonrpc": "1.0", "id": id, "result": Value::Null, "error": Value::Null}),
                            ),
                        };

                        let resp_str = resp_body.to_string();
                        let status_text = if status_code == 200 {
                            "200 OK"
                        } else {
                            "500 Internal Server Error"
                        };
                        let http_resp = format!(
                            "HTTP/1.1 {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{resp_str}",
                            resp_str.len()
                        );
                        if stream.write_all(http_resp.as_bytes()).is_err() {
                            return;
                        }
                    }
                });
            }
        });

        url
    }

    fn for_both_backends_with_aliases<F: Fn(AnyBlockchain)>(
        known_txs: Vec<(Transaction, Option<u64>, bool)>,
        aliases: Vec<(Txid, Transaction)>,
        test_fn: F,
    ) {
        let electrum_url = start_electrum_recovery_stub(known_txs.clone(), aliases.clone());
        let electrum = Electrum::new(&crate::wallet::ElectrumConfig {
            url: electrum_url,
            ..Default::default()
        })
        .expect("connect to electrum stub");
        test_fn(AnyBlockchain::Electrum(electrum));

        let core_url = start_core_recovery_stub(known_txs, aliases);
        let core = CoreRPC::new(&CoreRpcConfig {
            url: core_url,
            ..Default::default()
        })
        .expect("connect to core stub");
        test_fn(AnyBlockchain::CoreRPC(core));
    }

    fn for_both_backends<F: Fn(AnyBlockchain)>(
        known_txs: Vec<(Transaction, Option<u64>, bool)>,
        test_fn: F,
    ) {
        for_both_backends_with_aliases(known_txs, vec![], test_fn);
    }

    fn make_legacy_outgoing_swapcoin(funding_tx: Option<Transaction>) -> OutgoingSwapCoin {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let my_privkey = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let other_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let other_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_privkey),
        };
        let timelock_privkey = SecretKey::from_slice(&[4u8; 32]).unwrap();

        let dummy_contract_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([10u8; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut sc = OutgoingSwapCoin::new_legacy(
            my_privkey,
            other_pubkey,
            dummy_contract_tx,
            ScriptBuf::new(),
            timelock_privkey,
            Amount::from_sat(50_000),
            1,
        );
        sc.committed = true;
        sc.funding_tx = funding_tx;
        sc.others_contract_sig = None;
        sc
    }

    #[test]
    fn compat_funding_inputs_distinguish_confirmed_conflicts_from_own_funding() {
        let parent = tx(OutPoint::null(), 100_000, ScriptBuf::from_bytes(vec![0x51]));
        let funding = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            ScriptBuf::from_bytes(vec![0x52]),
        );
        let conflict = tx(
            OutPoint::new(parent.compute_txid(), 0),
            49_000,
            ScriptBuf::from_bytes(vec![0x53]),
        );
        let mut coin = make_legacy_outgoing_swapcoin(Some(funding.clone()));
        coin.contract_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        for (spender, height, expected) in [
            (&funding, Some(11), ContractChainState::NotYet),
            (&funding, None, ContractChainState::NotYet),
            (&conflict, None, ContractChainState::NotYet),
            (&conflict, Some(11), ContractChainState::Discarded),
        ] {
            for_both_backends(
                vec![
                    (parent.clone(), Some(10), false),
                    (spender.clone(), height, true),
                ],
                |chain| {
                    assert_eq!(
                        Wallet::ensure_contract_on_chain(&chain, "committed", &coin).unwrap(),
                        expected
                    );
                },
            );
        }
    }

    #[test]
    fn compat_legacy_contract_funding_output_requires_a_confirmed_conflict() {
        let funding = tx(OutPoint::null(), 100_000, ScriptBuf::from_bytes(vec![0x51]));
        let conflict = tx(
            OutPoint::new(funding.compute_txid(), 0),
            49_000,
            ScriptBuf::from_bytes(vec![0x53]),
        );
        for stored_funding in [None, Some(funding.clone())] {
            let mut coin = make_legacy_outgoing_swapcoin(stored_funding);
            coin.contract_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
            for (height, expected) in [
                (None, ContractChainState::NotYet),
                (Some(11), ContractChainState::Discarded),
            ] {
                for_both_backends(
                    vec![
                        (funding.clone(), Some(10), false),
                        (conflict.clone(), height, true),
                    ],
                    |chain| {
                        assert_eq!(
                            Wallet::ensure_contract_on_chain(&chain, "committed", &coin).unwrap(),
                            expected
                        );
                    },
                );
            }
        }
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_spent_wallet_inputs_is_discarded() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let sc = make_legacy_outgoing_swapcoin(Some(funding_tx));
        for_both_backends(
            vec![(parent_tx, Some(10), false), (spending_tx, Some(11), true)],
            |blockchain| {
                let res = Wallet::ensure_contract_on_chain(&blockchain, "swap-spent", &sc).unwrap();
                assert_eq!(res, ContractChainState::Discarded);
            },
        );
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_no_funding_tx_and_spent_parent_is_discarded() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let dummy_contract_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let my_privkey = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let other_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let other_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_privkey),
        };
        let timelock_privkey = SecretKey::from_slice(&[4u8; 32]).unwrap();

        let mut sc = OutgoingSwapCoin::new_legacy(
            my_privkey,
            other_pubkey,
            dummy_contract_tx,
            ScriptBuf::new(),
            timelock_privkey,
            Amount::from_sat(50_000),
            1,
        );
        sc.committed = true;
        sc.funding_tx = None;
        sc.others_contract_sig = None;

        for_both_backends(
            vec![(parent_tx, Some(10), false), (spending_tx, Some(11), true)],
            |blockchain| {
                let res =
                    Wallet::ensure_contract_on_chain(&blockchain, "swap-no-funding-spent", &sc)
                        .unwrap();
                assert_eq!(res, ContractChainState::Discarded);
            },
        );
    }

    #[test]
    fn test_ensure_contract_uncommitted_legacy_is_discarded() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut sc = make_legacy_outgoing_swapcoin(Some(funding_tx));
        sc.committed = false;
        for_both_backends(vec![(parent_tx, Some(10), true)], |blockchain| {
            let res = Wallet::ensure_contract_on_chain(&blockchain, "swap-unspent", &sc).unwrap();
            assert_eq!(res, ContractChainState::Discarded);
        });
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_unspent_wallet_inputs_and_shared_funding_is_not_yet(
    ) {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let sc = make_legacy_outgoing_swapcoin(Some(funding_tx));
        for_both_backends(vec![(parent_tx, Some(10), true)], |blockchain| {
            let res =
                Wallet::ensure_contract_on_chain(&blockchain, "swap-unspent-shared", &sc).unwrap();
            assert_eq!(res, ContractChainState::NotYet);
        });
    }

    /// A coin the maker signed may have had its funding broadcast, and an
    /// evicted funding tx can still confirm elsewhere. Unknown funding with
    /// unspent inputs is no proof otherwise, so it must be kept even when the
    /// contract still cannot be signed for another reason.
    #[test]
    fn test_ensure_contract_maker_signed_legacy_with_unknown_funding_is_not_yet() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut sc = make_legacy_outgoing_swapcoin(Some(funding_tx));
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let msg = bitcoin::secp256k1::Message::from_digest([1u8; 32]);
        sc.others_contract_sig = Some(bitcoin::ecdsa::Signature::sighash_all(
            secp.sign_ecdsa(&msg, &SecretKey::from_slice(&[3u8; 32]).unwrap()),
        ));
        // Signing still fails, so the coin takes the unsignable path.
        sc.other_pubkey = None;
        for_both_backends(vec![(parent_tx, Some(10), true)], |blockchain| {
            let res =
                Wallet::ensure_contract_on_chain(&blockchain, "swap-maker-signed", &sc).unwrap();
            assert_eq!(res, ContractChainState::NotYet);
        });
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_no_funding_tx_and_no_onchain_input_is_not_yet() {
        let sc = make_legacy_outgoing_swapcoin(None);
        for_both_backends(vec![], |blockchain| {
            let res = Wallet::ensure_contract_on_chain(&blockchain, "swap-no-input", &sc).unwrap();
            assert_eq!(res, ContractChainState::NotYet);
        });
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_funding_tx_in_mempool_is_not_yet() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let sc = make_legacy_outgoing_swapcoin(Some(funding_tx.clone()));
        for_both_backends(
            vec![(parent_tx, Some(10), true), (funding_tx, None, true)],
            |blockchain| {
                let res =
                    Wallet::ensure_contract_on_chain(&blockchain, "swap-mempool-funding", &sc)
                        .unwrap();
                assert_eq!(res, ContractChainState::NotYet);
            },
        );
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_no_funding_tx_and_parent_in_mempool_is_not_yet() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };

        let dummy_contract_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_tx.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let my_privkey = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let other_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let other_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_privkey),
        };
        let timelock_privkey = SecretKey::from_slice(&[4u8; 32]).unwrap();

        let mut sc = OutgoingSwapCoin::new_legacy(
            my_privkey,
            other_pubkey,
            dummy_contract_tx,
            ScriptBuf::new(),
            timelock_privkey,
            Amount::from_sat(50_000),
            1,
        );
        sc.committed = true;
        sc.funding_tx = None;
        sc.others_contract_sig = None;

        for_both_backends(vec![(parent_tx, None, true)], |blockchain| {
            let res =
                Wallet::ensure_contract_on_chain(&blockchain, "swap-mempool-parent", &sc).unwrap();
            assert_eq!(res, ContractChainState::NotYet);
        });
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_mismatched_parent_tx_is_not_yet() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let mismatched_txid = Txid::from_byte_array([99u8; 32]);

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_tx.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(mismatched_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let sc = make_legacy_outgoing_swapcoin(Some(funding_tx));
        for_both_backends_with_aliases(
            vec![
                (parent_tx.clone(), Some(10), false),
                (spending_tx, Some(11), true),
            ],
            vec![(mismatched_txid, parent_tx)],
            |blockchain| {
                let res = Wallet::ensure_contract_on_chain(&blockchain, "swap-mismatched", &sc);
                // Electrum validates the returned txid and rejects the
                // mismatch; that failure must reach the caller, not read as
                // "nothing to check, keep waiting". Core's stub has no such
                // guard and returns the wrong transaction transparently, so
                // the mismatch there is caught downstream by the plain txid
                // comparison instead, and normal NotYet still applies.
                if matches!(blockchain, AnyBlockchain::Electrum(_)) {
                    res.unwrap_err();
                } else {
                    assert_eq!(res.unwrap(), ContractChainState::NotYet);
                }
            },
        );
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_no_funding_tx_and_mismatched_parent_tx_is_not_yet()
    {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let mismatched_txid = Txid::from_byte_array([99u8; 32]);

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_tx.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let dummy_contract_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(mismatched_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let my_privkey = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let other_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let other_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_privkey),
        };
        let timelock_privkey = SecretKey::from_slice(&[4u8; 32]).unwrap();

        let mut sc = OutgoingSwapCoin::new_legacy(
            my_privkey,
            other_pubkey,
            dummy_contract_tx,
            ScriptBuf::new(),
            timelock_privkey,
            Amount::from_sat(50_000),
            1,
        );
        sc.committed = true;
        sc.funding_tx = None;
        sc.others_contract_sig = None;

        for_both_backends_with_aliases(
            vec![
                (parent_tx.clone(), Some(10), false),
                (spending_tx, Some(11), true),
            ],
            vec![(mismatched_txid, parent_tx)],
            |blockchain| {
                let res = Wallet::ensure_contract_on_chain(
                    &blockchain,
                    "swap-no-funding-mismatched",
                    &sc,
                );
                // Same split as the funded-mismatch case: Electrum's
                // txid-validating fetch rejects the wrong transaction and
                // that must propagate, while Core's stub returns it
                // transparently and the plain txid comparison downstream
                // catches the mismatch, leaving NotYet.
                if matches!(blockchain, AnyBlockchain::Electrum(_)) {
                    res.unwrap_err();
                } else {
                    assert_eq!(res.unwrap(), ContractChainState::NotYet);
                }
            },
        );
    }

    #[test]
    fn test_electrum_tx_block_height_rejects_mismatched_txid() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let mismatched_txid = Txid::from_byte_array([99u8; 32]);

        for_both_backends_with_aliases(
            vec![(parent_tx.clone(), Some(10), true)],
            vec![(mismatched_txid, parent_tx)],
            |blockchain| {
                if let AnyBlockchain::Electrum(ref electrum) = blockchain {
                    let res = electrum.tx_block_height(&mismatched_txid);
                    assert!(
                        res.is_err(),
                        "Electrum::tx_block_height must reject txid mismatch"
                    );
                }
            },
        );
    }
}
