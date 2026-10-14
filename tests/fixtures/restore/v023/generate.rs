//! Makes `fixtures.json` and `backup.json` with the v0.2.3 library. Run as an
//! example inside a v0.2.3 checkout; see README.md.
use std::{env, fs, path::PathBuf};

use bitcoind::{
    bitcoincore_rpc::{Auth, RpcApi},
    BitcoinD,
};
use openswap::{
    security::KeyMaterial,
    utill::MIN_RELAY_FEE_RATE,
    wallet::{AddressType, AnyBlockchain, BackendConfig, CoreRPC, CoreRpcConfig, Wallet},
};
use serde_json::{json, Value};

const PASSWORD: &str = "v023-fixture";
const INDEXES: [usize; 4] = [0, 1, 25, 150];

fn main() {
    let out = PathBuf::from(env::args().nth(1).expect("usage: generate <out-dir>"));
    let tmp = tempfile::tempdir().unwrap();
    let mut conf = bitcoind::Conf::default();
    conf.args.push("-txindex=1");
    let node = BitcoinD::with_conf(bitcoind::exe_path().unwrap(), &conf).unwrap();
    let config = |name: &str| CoreRpcConfig {
        url: node.rpc_url().split_at(7).1.to_string(),
        auth: Auth::CookieFile(node.params.cookie_file.clone()),
        wallet_name: name.to_string(),
        ..CoreRpcConfig::default()
    };
    let km = || KeyMaterial::new_from_password(Some(PASSWORD.to_string())).unwrap();

    // Born at height 0, so the birthday is valid on any test chain.
    let mut w1 = Wallet::init(
        &tmp.path().join("w1"),
        AnyBlockchain::CoreRPC(CoreRPC::new(&config("w1")).unwrap()),
        km(),
    )
    .unwrap();
    let phrase = w1.take_new_mnemonic().unwrap().words();
    w1.backup(&out.join("backup"), km()).unwrap();

    // The counters are shared by both address types, so each type gets its
    // own wallet restored from the same phrase.
    let mut w2 = Wallet::restore_from_mnemonic(
        &phrase,
        &tmp.path().join("w2"),
        &BackendConfig::CoreRpc(config("w2")),
        Some(0),
        km(),
    )
    .unwrap();
    let mut addresses = json!({});
    for (kind, wallet, address_type) in [
        ("p2wpkh", &mut w1, AddressType::P2WPKH),
        ("p2tr", &mut w2, AddressType::P2TR),
    ] {
        let external: Vec<String> = (0..=150)
            .map(|_| {
                wallet
                    .get_next_external_address(address_type)
                    .unwrap()
                    .to_string()
            })
            .collect();
        let internal: Vec<String> = wallet
            .get_next_internal_addresses(151, address_type)
            .unwrap()
            .iter()
            .map(|a| a.to_string())
            .collect();
        let pick = |all: &Vec<String>| -> Value {
            INDEXES
                .iter()
                .map(|&i| (i.to_string(), json!(all[i])))
                .collect()
        };
        addresses[kind] = json!({"external": pick(&external), "internal": pick(&internal)});
    }

    // Three bonds at indexes 0-2; only the keys are kept.
    let miner = node
        .client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    node.client.generate_to_address(101, &miner).unwrap();
    let funding = w1.get_next_external_address(AddressType::P2WPKH).unwrap();
    node.client
        .send_to_address(
            &funding,
            bitcoin::Amount::from_btc(1.0).unwrap(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    for _ in 0..3 {
        node.client.generate_to_address(1, &miner).unwrap();
        w1.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
        let (tip, _) = w1.chain_tip().unwrap();
        let lock = bitcoin::absolute::LockTime::from_height(tip as u32 + 1000).unwrap();
        w1.create_fidelity(
            bitcoin::Amount::from_btc(0.01).unwrap(),
            lock,
            None,
            MIN_RELAY_FEE_RATE,
            AddressType::P2WPKH,
        )
        .unwrap();
    }
    let bond_pubkeys: Vec<Value> = w1
        .get_fidelity_bonds()
        .iter()
        .map(|b| serde_json::to_value(b).unwrap()["pubkey"].clone())
        .collect();

    let fixtures = json!({
        "phrase": phrase,
        "backup_password": PASSWORD,
        "addresses": addresses,
        "bond_pubkeys": bond_pubkeys,
    });
    fs::write(
        out.join("fixtures.json"),
        serde_json::to_string_pretty(&fixtures).unwrap() + "\n",
    )
    .unwrap();
}
