//! Frozen offerbook enums and populated persistent blocklist records.

use super::{assert_subset, check, fixture_root, write};
use crate::{
    blocklist::{blocklist_path, AddressBlocklist, BlocklistEntry},
    taker::offers::{
        tests::{compat_assert_empty_book_extras, compat_sample_offerbook, compat_v023_round_trip},
        OfferBook,
    },
};
use bitcoin::{
    absolute::LockTime,
    address::NetworkUnchecked,
    hashes::Hash,
    secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey},
    transaction::Version,
    Address, Amount, CompressedPublicKey, Network, OutPoint, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use serde::{Deserialize, Serialize};
use serde_cbor::{value::to_value, Value};
use std::{fs, path::Path};

#[derive(Serialize, Deserialize)]
struct BlocklistFixture {
    #[serde(default)]
    requires: Vec<String>,
    entries: Vec<BlocklistEntry>,
}

fn populated_book() -> OfferBook {
    let book = compat_sample_offerbook();
    let mut value = serde_json::to_value(book).unwrap();
    let transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(500).unwrap(),
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_slice(&[19; 32]).unwrap(), 7),
            script_sig: ScriptBuf::from_bytes(vec![0x51]),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::from_slice(&[vec![1, 2, 3], vec![4, 5]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    for (index, maker) in value["makers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        maker["protocol"] = serde_json::json!(["Legacy", "Taproot", "Unified"][index % 3]);
        maker["offer"]["fidelity"]["bond"]["tx"] = serde_json::to_value(&transaction).unwrap();
    }
    serde_json::from_value(value).unwrap()
}

pub(super) fn generate(release: &Path) {
    write(release, "offerbook-all-states", &populated_book());
    let key = SecretKey::from_slice(&[1; 32]).unwrap();
    let pubkey = PublicKey::new(SecpPublicKey::from_secret_key(&Secp256k1::new(), &key));
    let entries = vec![
        BlocklistEntry::new(
            Address::p2pkh(pubkey, Network::Regtest).to_string(),
            Some("funding source".into()),
        ),
        BlocklistEntry::new(
            Address::p2wpkh(&CompressedPublicKey(pubkey.inner), Network::Regtest).to_string(),
            None,
        ),
    ];
    write(
        release,
        "blocklist-empty-requires",
        &BlocklistFixture {
            requires: Vec::new(),
            entries: entries.clone(),
        },
    );
    write(
        release,
        "blocklist-known-requires",
        &BlocklistFixture {
            requires: vec!["legacy".into(), "taproot".into()],
            entries,
        },
    );
}

pub(super) fn check_release(release: &Path) {
    let mut found_book = false;
    let mut found_blocklist = false;
    for entry in fs::read_dir(release).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "cbor") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap();
        if name.starts_with("offerbook-") {
            found_book = true;
            let book: OfferBook = check(release, name);
            compat_assert_empty_book_extras(&book);
            let before = serde_json::to_value(&book).unwrap();
            assert_eq!(before["makers"].as_array().unwrap().len(), 13);
            for maker in before["makers"].as_array().unwrap() {
                let fidelity = &maker["offer"]["fidelity"];
                assert!(!fidelity["cert_sig"].is_null());
            }
            let old_bytes = compat_v023_round_trip(&serde_cbor::to_vec(&book).unwrap());
            let restored: OfferBook = serde_cbor::from_slice(&old_bytes).unwrap();
            let mut expected = before;
            for maker in expected["makers"].as_array_mut().unwrap() {
                maker["features"] = serde_json::json!([]);
            }
            assert_eq!(serde_json::to_value(restored).unwrap(), expected);
        } else if name.starts_with("blocklist-") {
            found_blocklist = true;
            let blocklist: BlocklistFixture = check(release, name);
            let dir = tempfile::tempdir().unwrap();
            let data_dir = dir.path().join("taker");
            fs::write(
                blocklist_path(&data_dir),
                serde_json::to_vec(&blocklist).unwrap(),
            )
            .unwrap();
            let loaded = AddressBlocklist::load(&data_dir, Network::Regtest).unwrap();
            assert!(
                !loaded.is_empty(),
                "{} loaded no blocklist entries",
                path.display()
            );
            for entry in blocklist.entries {
                let address: Address<NetworkUnchecked> = entry.address.parse().unwrap();
                let address = address.require_network(Network::Regtest).unwrap();
                assert_eq!(
                    loaded.matching(address.script_pubkey().as_script()),
                    Some(&entry)
                );
            }
        }
    }
    assert!(found_book, "{} has no offerbook fixture", release.display());
    assert!(
        found_blocklist,
        "{} has no blocklist fixture",
        release.display()
    );
}

#[test]
fn compat_fixtures_offerbook_keeps_future_bond_fields_on_downgrade() {
    let release = fixture_root().join("v0.3.0");
    let book: OfferBook = check(&release, "offerbook-all-states");
    let mut future = serde_json::to_value(book).unwrap();
    future["makers"][0]["offer"]["fidelity"]["bond"]["future_policy"] =
        serde_json::json!({"nested": {"limit": 17, "evidence": [1, 2, 3]}, "enabled": true});
    let downgraded: OfferBook = serde_json::from_value(future.clone()).unwrap();
    let old_bytes = serde_cbor::to_vec(&downgraded).unwrap();
    let read_back: OfferBook = serde_cbor::from_slice(&old_bytes).unwrap();
    let expected: Value = to_value(&future).unwrap();
    let actual = serde_json::to_value(read_back).unwrap();
    assert_subset(&expected, &to_value(&actual).unwrap());
}
