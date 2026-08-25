use std::{
    fs,
    path::{Path, PathBuf},
};

use bip39::rand;
use bitcoin::{Address, Amount};
use bitcoind::{
    bitcoincore_rpc::{self, Auth},
    BitcoinD,
};
use electrsd::ElectrsD;

use openswap::wallet::{
    AddressType, AnyBlockchain, BackendConfig, CoreRPC, CoreRpcConfig, Electrum, ElectrumConfig,
    Wallet, WalletBackup,
};

use openswap::security::{load_sensitive_struct, KeyMaterial, SecurityError, SerdeCbor, SerdeJson};

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

    let bitcoind = init_bitcoind(&temp_dir, zmq_addr);

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
    let bitcoind = init_bitcoind(&temp_dir, zmq_addr);
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

    // The restore must have written an *encrypted* wallet file, keyed by the
    // restore passphrase.
    assert_wallet_file_encrypted(&s.restored_wallet, "integration-test");

    // Kill electrs before cleanup wipes root_dir, which holds its datadir.
    drop(s.electrsd);
    cleanup(&mut s.bitcoind, &s.root_dir);
}
