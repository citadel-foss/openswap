use std::path::Path;

use bitcoin::{absolute::LockTime, Address, Amount};
use bitcoind::{
    bitcoincore_rpc::{self},
    BitcoinD,
};

use openswap::wallet::{
    AddressType, AnyBlockchain, BackendConfig, CoreRPC, CoreRpcConfig, Electrum, Wallet,
    WalletBackup,
};

use openswap::{
    security::{load_sensitive_struct, KeyMaterial, SecurityError, SerdeCbor, SerdeJson},
    utill::MIN_RELAY_FEE_RATE,
};

use super::test_framework::*;

fn send_and_mine(
    bitcoind: &BitcoinD,
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

#[world_test(backend = BitcoindBackend)]
fn encwallet_encbackup_encrestore(node: &mut Node) {
    let wallets = node.temp_dir().join("wallets");
    let original_wallet = wallets.join("original-wallet");
    let wallet_backup_file = wallets.join("wallet-backup.json");
    let restored_wallet_file = wallets.join("restored-wallet");
    let rpc_config = CoreRpcConfig {
        wallet_name: "original-wallet".to_string(),
        ..node.rpc_config()
    };
    let bitcoind = node.bitcoind();

    let km = KeyMaterial::new_from_password(Some("integration-test".to_string())).unwrap();

    let mut wallet = Wallet::init(
        &original_wallet,
        AnyBlockchain::CoreRPC(CoreRPC::new(&rpc_config).unwrap()),
        km.clone(),
    )
    .unwrap();

    let addr = wallet.get_next_external_address(AddressType::P2TR).unwrap();
    send_and_mine(bitcoind, &addr, 0.05, 1).unwrap();

    let _ = wallet.backup(&wallet_backup_file, km.clone());

    // Bond 0 expires at once and is redeemed, so the restore must see it spent.
    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    create_maker_bond(&mut wallet, 1);
    generate_blocks(bitcoind, 2);
    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    create_maker_bond(&mut wallet, 950);
    wallet
        .redeem_fidelity(0, MIN_RELAY_FEE_RATE, AddressType::P2TR)
        .unwrap();
    generate_blocks(bitcoind, 1);

    let addr = wallet.get_next_external_address(AddressType::P2TR).unwrap();
    send_and_mine(bitcoind, &addr, 0.05, 1).unwrap();

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
    let nameless_dir = node.temp_dir().join("nameless-restore");
    std::fs::create_dir_all(&nameless_dir).unwrap();
    Wallet::restore(
        &backup,
        &nameless_dir,
        &BackendConfig::CoreRpc(rpc_config.clone()),
        km.clone(),
    )
    .unwrap();
    assert_wallet_file_encrypted(&nameless_dir.join("original-wallet"), "integration-test");
}

#[world_test(backend = ElectrumBackend)]
fn encwallet_encbackup_encrestore_electrum(node: &mut Node) {
    let wallets = node.temp_dir().join("wallets");
    let original_wallet = wallets.join("original-wallet");
    let backup_file = wallets.join("wallet-backup.json");
    let restored_wallet_file = wallets.join("restored-wallet");
    let electrum_cfg = node.electrum_config();
    let bitcoind = node.bitcoind();

    let km = KeyMaterial::new_from_password(Some("integration-test".to_string())).unwrap();

    let mut wallet = Wallet::init(
        &original_wallet,
        AnyBlockchain::Electrum(Electrum::new(&electrum_cfg).unwrap()),
        km.clone(),
    )
    .unwrap();

    let addr = wallet.get_next_external_address(AddressType::P2TR).unwrap();
    send_and_mine(bitcoind, &addr, 0.05, 1).unwrap();
    wait_for_electrs_tip(bitcoind, node.electrsd(), &electrum_cfg);

    wallet.backup(&backup_file, km.clone()).unwrap();

    // Bond 0 expires at once and is redeemed, so the restore must see it spent.
    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    create_maker_bond(&mut wallet, 1);
    generate_blocks(bitcoind, 2);
    wait_for_electrs_tip(bitcoind, node.electrsd(), &electrum_cfg);
    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    create_maker_bond(&mut wallet, 950);
    wallet
        .redeem_fidelity(0, MIN_RELAY_FEE_RATE, AddressType::P2TR)
        .unwrap();
    generate_blocks(bitcoind, 1);

    let addr = wallet.get_next_external_address(AddressType::P2TR).unwrap();
    send_and_mine(bitcoind, &addr, 0.05, 1).unwrap();
    wait_for_electrs_tip(bitcoind, node.electrsd(), &electrum_cfg);

    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();

    let (backup, _) = load_sensitive_struct::<WalletBackup, SerdeJson>(
        &backup_file,
        Some("integration-test".to_string()),
    )
    .unwrap();

    let restored_wallet = Wallet::restore(
        &backup,
        &restored_wallet_file,
        &BackendConfig::Electrum(electrum_cfg.clone()),
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
    assert_wallet_file_encrypted(&restored_wallet_file, "integration-test");
}
