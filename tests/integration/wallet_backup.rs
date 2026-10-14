use std::{
    fs,
    path::{Path, PathBuf},
};

use bip39::rand;
use bitcoin::{absolute::LockTime, Address, Amount};
use bitcoind::{
    bitcoincore_rpc::{self, Auth, RpcApi},
    BitcoinD,
};
use electrsd::ElectrsD;
use serde_json::{json, Value};

use openswap::wallet::{
    AddressType, AnyBlockchain, BackendConfig, Blockchain, BondHint, CoreRPC, CoreRpcConfig,
    Destination, Electrum, ElectrumConfig, RestoreOptions, Wallet, WalletBackup,
};

use openswap::{
    security::{load_sensitive_struct, KeyMaterial, SecurityError, SerdeCbor, SerdeJson},
    utill::MIN_RELAY_FEE_RATE,
};

use super::test_framework::{
    generate_blocks, init_bitcoind, init_electrsd, send_to_address, wait_for_electrs_tip,
};

fn setup(test_name: String) -> (PathBuf, CoreRpcConfig, PathBuf, BitcoinD, PathBuf, PathBuf) {
    let root_dir = std::env::temp_dir().join(format!("openswap-{}", rand::random::<u64>()));
    let temp_dir = root_dir.join("wallet-tests").join(test_name);
    let wallets_dir = temp_dir.join("");

    let original_wallet_name = "original-wallet".to_string();
    let original_wallet = wallets_dir.join(&original_wallet_name);
    let wallet_backup_file = wallets_dir.join("wallet-backup.json");
    let restored_wallet_name = "restored-wallet".to_string();
    let restored_wallet_file = wallets_dir.join(&restored_wallet_name);
    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    let port_zmq = 28332 + rand::random::<u16>() % 1000;

    let zmq_addr = format!("tcp://127.0.0.1:{port_zmq}");

    // Core pads every imported range with its keypool (1000 by default),
    // which would hide a restore that stops short.
    fs::create_dir_all(temp_dir.join(".bitcoin")).unwrap();
    fs::write(temp_dir.join(".bitcoin/bitcoin.conf"), "keypool=1\n").unwrap();
    let bitcoind = init_bitcoind(&temp_dir, zmq_addr).expect("bitcoind failed to start");

    let url = bitcoind.rpc_url().split_at(7).1.to_string();
    let auth = Auth::CookieFile(bitcoind.params.cookie_file.clone());

    let rpc_config = CoreRpcConfig {
        url,
        auth,
        wallet_name: original_wallet_name.clone(),
        ..CoreRpcConfig::default()
    };
    (
        original_wallet,
        rpc_config,
        wallet_backup_file,
        bitcoind,
        restored_wallet_file,
        root_dir,
    )
}

fn cleanup(bitcoind: &mut BitcoinD, root_dir: &Path) {
    bitcoind.stop().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(2));
    if root_dir.exists() {
        let _ = fs::remove_dir_all(root_dir);
    }
}

fn send_and_mine(
    bitcoind: &mut BitcoinD,
    address: &Address,
    btc_amount: f64,
    blocks_to_generate: u64,
) -> Result<(), bitcoincore_rpc::Error> {
    send_to_address(bitcoind, address, Amount::from_btc(btc_amount)?);
    generate_blocks(bitcoind, blocks_to_generate);
    Ok(())
}

/// Locks a bond the way a maker does, OP_RETURN included. A backup holds only
/// the seed, so the restore must find this bond on-chain.
fn create_maker_bond(wallet: &mut Wallet, blocks: u32) {
    let (tip, _) = wallet.chain_tip().unwrap();
    wallet
        .create_fidelity(
            Amount::from_btc(0.02).unwrap(),
            LockTime::from_height(tip as u32 + blocks).unwrap(),
            Some("127.0.0.1:6102"),
            MIN_RELAY_FEE_RATE,
            AddressType::P2TR,
        )
        .unwrap();
}

/// Pays external addresses 0..150 and sweeps them, then pays index 150 and,
/// after 150 never-used addresses, index 301. `wait` lets the backend catch up.
fn fund_past_address_gaps(wallet: &mut Wallet, bitcoind: &BitcoinD, wait: impl Fn()) {
    let addrs: Vec<Address> = (0..302)
        .map(|_| wallet.get_next_external_address(AddressType::P2TR).unwrap())
        .collect();
    let outputs = addrs[..150]
        .iter()
        .map(|addr| (addr.to_string(), json!(0.001)))
        .collect();
    let _: Value = bitcoind
        .client
        .call("sendmany", &[json!(""), Value::Object(outputs)])
        .unwrap();
    generate_blocks(bitcoind, 1);
    wait();
    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();

    let coins = wallet.list_descriptor_utxo_spend_info();
    assert_eq!(coins.len(), 150);
    let sink = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let sweep = wallet
        .spend_from_wallet(MIN_RELAY_FEE_RATE, Destination::Sweep(sink), &coins)
        .unwrap();
    wallet.send_tx(&sweep).unwrap();
    send_to_address(bitcoind, &addrs[150], Amount::from_btc(0.01).unwrap());
    send_to_address(bitcoind, &addrs[301], Amount::from_btc(0.02).unwrap());
    generate_blocks(bitcoind, 1);
    wait();
}

/// The default gap bridges the 150 emptied addresses but not the unused run
/// before index 301; a gap of 200 reaches it.
fn assert_restores_past_address_gaps(
    backup: &WalletBackup,
    dir: &Path,
    backend: &BackendConfig,
    km: &KeyMaterial,
) {
    let wide = RestoreOptions {
        address_gap: 200,
        ..Default::default()
    };
    for (name, options, next_index, balance) in [
        ("restored-default-gap", RestoreOptions::default(), 151, 0.01),
        ("restored-wide-gap", wide, 302, 0.03),
    ] {
        let restored =
            Wallet::restore_with(backup, &dir.join(name), backend, km.clone(), options).unwrap();
        assert_eq!(*restored.get_external_index(), next_index, "{name}");
        assert_eq!(
            restored.get_balances().unwrap().spendable,
            Amount::from_btc(balance).unwrap(),
            "{name}"
        );
    }
}

/// Locks a bare bond at index 0, as an API user can, then a maker's at index 1,
/// both maturing in 10 blocks. Returns the hint that finds bond 0.
fn create_sparse_bonds(wallet: &mut Wallet, bitcoind: &BitcoinD, wait: impl Fn()) -> BondHint {
    let addr = wallet.get_next_external_address(AddressType::P2TR).unwrap();
    send_to_address(bitcoind, &addr, Amount::from_btc(0.1).unwrap());
    generate_blocks(bitcoind, 1);
    wait();
    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    let (tip, _) = wallet.chain_tip().unwrap();
    let locktime = LockTime::from_height(tip as u32 + 10).unwrap();
    wallet
        .create_fidelity(
            Amount::from_btc(0.02).unwrap(),
            locktime,
            None,
            MIN_RELAY_FEE_RATE,
            AddressType::P2TR,
        )
        .unwrap();
    generate_blocks(bitcoind, 1);
    wait();
    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    create_maker_bond(wallet, 10);
    generate_blocks(bitcoind, 1);
    wait();
    BondHint { index: 0, locktime }
}

/// A plain restore must look past bare bond 0 to bond 1 and redeem it by its
/// index; only the hint brings bond 0 back.
fn assert_restores_sparse_bonds(
    backup: &WalletBackup,
    hint: BondHint,
    dir: &Path,
    backend: &BackendConfig,
    km: &KeyMaterial,
    bitcoind: &BitcoinD,
    wait: impl Fn(),
) {
    let indexes = |wallet: &Wallet| -> Vec<u32> {
        wallet
            .get_fidelity_bonds()
            .iter()
            .map(|bond| bond.bond_index)
            .collect()
    };
    let hinted = RestoreOptions {
        bond_hints: vec![hint],
        ..Default::default()
    };
    let with_hint = Wallet::restore_with(
        backup,
        &dir.join("restored-hint"),
        backend,
        km.clone(),
        hinted,
    )
    .unwrap();
    assert_eq!(indexes(&with_hint), [0, 1]);

    let mut restored =
        Wallet::restore(backup, &dir.join("restored-no-hint"), backend, km.clone()).unwrap();
    assert_eq!(indexes(&restored), [1]);
    assert_eq!(
        restored.get_balances().unwrap().fidelity,
        Amount::from_btc(0.02).unwrap()
    );

    generate_blocks(bitcoind, 10);
    wait();
    restored
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    restored
        .redeem_fidelity(1, MIN_RELAY_FEE_RATE, AddressType::P2TR)
        .unwrap();
    generate_blocks(bitcoind, 1);
    wait();
    restored
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    assert_eq!(restored.get_balances().unwrap().fidelity, Amount::ZERO);
}

/// Asserts the wallet file on disk is genuinely encrypted with the given
/// passphrase: it must be an encrypted container, reject a wrong password,
/// and open with the correct one. (The missing-password `PasswordRequired`
/// path is covered by wallet storage unit tests, which have the concrete
/// `WalletStore` type available.)
fn assert_wallet_file_encrypted(path: &Path, password: &str) {
    assert!(
        Wallet::is_wallet_encrypted(path).unwrap(),
        "restored wallet file must be encrypted"
    );

    let err = load_sensitive_struct::<serde_cbor::Value, SerdeCbor>(
        path,
        Some("definitely-wrong-password".to_string()),
    )
    .expect_err("encrypted wallet file must reject a wrong password");
    assert!(matches!(err, SecurityError::Decryption));

    let (_, material) =
        load_sensitive_struct::<serde_cbor::Value, SerdeCbor>(path, Some(password.to_string()))
            .expect("the restore password must open the restored wallet file");
    assert!(material.is_some());
}

#[test]
fn encwallet_encbackup_encrestore() {
    let (
        original_wallet,
        rpc_config,
        wallet_backup_file,
        mut bitcoind,
        restored_wallet_file,
        root_dir,
    ) = setup("encwallet_encbackup_encrestore".to_string());

    let km = KeyMaterial::new_from_password(Some("integration-test".to_string())).unwrap();

    let mut wallet = Wallet::init(
        &original_wallet,
        AnyBlockchain::CoreRPC(CoreRPC::new(&rpc_config).unwrap()),
        km.clone(),
    )
    .unwrap();

    let addr = wallet.get_next_external_address(AddressType::P2TR).unwrap();
    send_and_mine(&mut bitcoind, &addr, 0.05, 1).unwrap();

    let _ = wallet.backup(&wallet_backup_file, km.clone());

    // Bond 0 expires at once and is redeemed, so the restore must see it spent.
    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    create_maker_bond(&mut wallet, 1);
    generate_blocks(&bitcoind, 2);
    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    create_maker_bond(&mut wallet, 950);
    wallet
        .redeem_fidelity(0, MIN_RELAY_FEE_RATE, AddressType::P2TR)
        .unwrap();
    generate_blocks(&bitcoind, 1);

    let addr = wallet.get_next_external_address(AddressType::P2TR).unwrap();
    send_and_mine(&mut bitcoind, &addr, 0.05, 1).unwrap();

    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();

    let (backup, _) = load_sensitive_struct::<WalletBackup, SerdeJson>(
        &wallet_backup_file,
        Some("integration-test".to_string()),
    )
    .unwrap();

    let restored_wallet = Wallet::restore(
        &backup,
        &restored_wallet_file,
        &BackendConfig::CoreRpc(rpc_config.clone()),
        km.clone(),
    )
    .unwrap();

    assert!(
        wallet == restored_wallet, // only compares .store!
        "restored wallet does not match the original"
    );
    let spent: Vec<bool> = restored_wallet
        .get_fidelity_bonds()
        .iter()
        .map(|b| b.is_spent())
        .collect();
    assert_eq!(spent, [true, false]);

    // The restore must have written an *encrypted* wallet file, keyed by the
    // restore passphrase.
    assert_wallet_file_encrypted(&restored_wallet_file, "integration-test");

    // A nameless restore path resolves to the backup's original filename
    // instead of colliding with the wallets directory itself.
    let nameless_dir = root_dir.join("nameless-restore");
    std::fs::create_dir_all(&nameless_dir).unwrap();
    Wallet::restore(
        &backup,
        &nameless_dir,
        &BackendConfig::CoreRpc(rpc_config.clone()),
        km.clone(),
    )
    .unwrap();
    assert_wallet_file_encrypted(&nameless_dir.join("original-wallet"), "integration-test");

    cleanup(&mut bitcoind, &root_dir);
}

#[test]
fn restore_finds_funds_past_address_gaps() {
    let (original_wallet, rpc_config, backup_file, mut bitcoind, restored_wallet_file, root_dir) =
        setup("restore_finds_funds_past_address_gaps".to_string());
    let km = KeyMaterial::new_from_password(Some("integration-test".to_string())).unwrap();
    let mut wallet = Wallet::init(
        &original_wallet,
        AnyBlockchain::CoreRPC(CoreRPC::new(&rpc_config).unwrap()),
        km.clone(),
    )
    .unwrap();

    fund_past_address_gaps(&mut wallet, &bitcoind, || {});
    wallet.backup(&backup_file, km.clone()).unwrap();
    let (backup, _) = load_sensitive_struct::<WalletBackup, SerdeJson>(
        &backup_file,
        Some("integration-test".to_string()),
    )
    .unwrap();
    assert_restores_past_address_gaps(
        &backup,
        restored_wallet_file.parent().unwrap(),
        &BackendConfig::CoreRpc(rpc_config.clone()),
        &km,
    );

    // Core reports a rejected descriptor in its result, not as an RPC error.
    let err = CoreRPC::new(&rpc_config)
        .unwrap()
        .import_descriptors(&[json!({"desc": "raw(00)", "timestamp": "now"})])
        .unwrap_err();
    assert!(format!("{err:?}").contains("Missing checksum"), "{:?}", err);

    cleanup(&mut bitcoind, &root_dir);
}

#[test]
fn restore_recovers_sparse_and_hinted_bonds() {
    let (original_wallet, rpc_config, _, mut bitcoind, restored_wallet_file, root_dir) =
        setup("restore_recovers_sparse_and_hinted_bonds".to_string());
    let km = KeyMaterial::new_from_password(Some("integration-test".to_string())).unwrap();
    let mut wallet = Wallet::init(
        &original_wallet,
        AnyBlockchain::CoreRPC(CoreRPC::new(&rpc_config).unwrap()),
        km.clone(),
    )
    .unwrap();

    let hint = create_sparse_bonds(&mut wallet, &bitcoind, || {});
    assert_restores_sparse_bonds(
        &WalletBackup::from(&wallet),
        hint,
        restored_wallet_file.parent().unwrap(),
        &BackendConfig::CoreRpc(rpc_config.clone()),
        &km,
        &bitcoind,
        || {},
    );

    cleanup(&mut bitcoind, &root_dir);
}

/// Setup state for the Electrum-backed backup/restore tests.
struct ElectrumSetup {
    original_wallet: PathBuf,
    restored_wallet: PathBuf,
    backup_file: PathBuf,
    electrum_cfg: ElectrumConfig,
    bitcoind: BitcoinD,
    /// Owns the electrs child process for the lifetime of the test.
    electrsd: ElectrsD,
    root_dir: PathBuf,
}

fn setup_electrum(test_name: &str) -> ElectrumSetup {
    let root_dir = std::env::temp_dir().join(format!("openswap-elec-{}", rand::random::<u64>()));
    let temp_dir = root_dir.join("wallet-tests").join(test_name);
    let wallets_dir = temp_dir.join("");
    let original_wallet_name = "original-wallet".to_string();
    let restored_wallet_name = "restored-wallet".to_string();

    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    // bitcoind still mines and funds; electrs indexes for the wallet.
    let port_zmq = 28332 + rand::random::<u16>() % 1000;
    let zmq_addr = format!("tcp://127.0.0.1:{port_zmq}");
    let bitcoind = init_bitcoind(&temp_dir, zmq_addr).expect("bitcoind failed to start");
    let electrsd = init_electrsd(&bitcoind, &temp_dir);
    let electrum_url = format!("tcp://{}", electrsd.electrum_url);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let _ = electrsd.trigger();

    ElectrumSetup {
        original_wallet: wallets_dir.join(&original_wallet_name),
        restored_wallet: wallets_dir.join(&restored_wallet_name),
        backup_file: wallets_dir.join("wallet-backup.json"),
        electrum_cfg: ElectrumConfig {
            url: electrum_url,
            ..Default::default()
        },
        bitcoind,
        electrsd,
        root_dir,
    }
}

#[test]
fn encwallet_encbackup_encrestore_electrum() {
    let mut s = setup_electrum("encwallet_encbackup_encrestore_electrum");

    let km = KeyMaterial::new_from_password(Some("integration-test".to_string())).unwrap();

    let mut wallet = Wallet::init(
        &s.original_wallet,
        AnyBlockchain::Electrum(Electrum::new(&s.electrum_cfg).unwrap()),
        km.clone(),
    )
    .unwrap();

    let addr = wallet.get_next_external_address(AddressType::P2TR).unwrap();
    send_and_mine(&mut s.bitcoind, &addr, 0.05, 1).unwrap();
    wait_for_electrs_tip(&s.bitcoind, &s.electrsd, &s.electrum_cfg);

    wallet.backup(&s.backup_file, km.clone()).unwrap();

    // Bond 0 expires at once and is redeemed, so the restore must see it spent.
    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    create_maker_bond(&mut wallet, 1);
    generate_blocks(&s.bitcoind, 2);
    wait_for_electrs_tip(&s.bitcoind, &s.electrsd, &s.electrum_cfg);
    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    create_maker_bond(&mut wallet, 950);
    wallet
        .redeem_fidelity(0, MIN_RELAY_FEE_RATE, AddressType::P2TR)
        .unwrap();
    generate_blocks(&s.bitcoind, 1);

    let addr = wallet.get_next_external_address(AddressType::P2TR).unwrap();
    send_and_mine(&mut s.bitcoind, &addr, 0.05, 1).unwrap();
    wait_for_electrs_tip(&s.bitcoind, &s.electrsd, &s.electrum_cfg);

    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();

    let (backup, _) = load_sensitive_struct::<WalletBackup, SerdeJson>(
        &s.backup_file,
        Some("integration-test".to_string()),
    )
    .unwrap();

    let restored_wallet = Wallet::restore(
        &backup,
        &s.restored_wallet,
        &BackendConfig::Electrum(s.electrum_cfg.clone()),
        km.clone(),
    )
    .unwrap();

    assert_eq!(wallet, restored_wallet);
    let spent: Vec<bool> = restored_wallet
        .get_fidelity_bonds()
        .iter()
        .map(|b| b.is_spent())
        .collect();
    assert_eq!(spent, [true, false]);

    // The restore must have written an *encrypted* wallet file, keyed by the
    // restore passphrase.
    assert_wallet_file_encrypted(&s.restored_wallet, "integration-test");

    // Kill electrs before cleanup wipes root_dir, which holds its datadir.
    drop(s.electrsd);
    cleanup(&mut s.bitcoind, &s.root_dir);
}

#[test]
fn restore_finds_funds_past_address_gaps_electrum() {
    let mut s = setup_electrum("restore_finds_funds_past_address_gaps_electrum");
    let km = KeyMaterial::new_from_password(Some("integration-test".to_string())).unwrap();
    let mut wallet = Wallet::init(
        &s.original_wallet,
        AnyBlockchain::Electrum(Electrum::new(&s.electrum_cfg).unwrap()),
        km.clone(),
    )
    .unwrap();

    fund_past_address_gaps(&mut wallet, &s.bitcoind, || {
        wait_for_electrs_tip(&s.bitcoind, &s.electrsd, &s.electrum_cfg)
    });
    wallet.backup(&s.backup_file, km.clone()).unwrap();
    let (backup, _) = load_sensitive_struct::<WalletBackup, SerdeJson>(
        &s.backup_file,
        Some("integration-test".to_string()),
    )
    .unwrap();
    assert_restores_past_address_gaps(
        &backup,
        s.restored_wallet.parent().unwrap(),
        &BackendConfig::Electrum(s.electrum_cfg.clone()),
        &km,
    );

    drop(s.electrsd);
    cleanup(&mut s.bitcoind, &s.root_dir);
}

#[test]
fn restore_recovers_sparse_and_hinted_bonds_electrum() {
    let mut s = setup_electrum("restore_recovers_sparse_and_hinted_bonds_electrum");
    let km = KeyMaterial::new_from_password(Some("integration-test".to_string())).unwrap();
    let mut wallet = Wallet::init(
        &s.original_wallet,
        AnyBlockchain::Electrum(Electrum::new(&s.electrum_cfg).unwrap()),
        km.clone(),
    )
    .unwrap();

    let wait = || wait_for_electrs_tip(&s.bitcoind, &s.electrsd, &s.electrum_cfg);
    let hint = create_sparse_bonds(&mut wallet, &s.bitcoind, wait);
    assert_restores_sparse_bonds(
        &WalletBackup::from(&wallet),
        hint,
        s.restored_wallet.parent().unwrap(),
        &BackendConfig::Electrum(s.electrum_cfg.clone()),
        &km,
        &s.bitcoind,
        wait,
    );

    drop(s.electrsd);
    cleanup(&mut s.bitcoind, &s.root_dir);
}
