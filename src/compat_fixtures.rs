//! Release samples protect serialized names, nested values, and unknown data.

mod offerbook;
mod storage;
mod wire;

use crate::security::{encrypt_struct_v2, header_aad, EncryptedDataV2, KeyMaterial};
use pbkdf2::pbkdf2_hmac_array;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_cbor::{value::to_value, Value};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub(super) fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compat")
}

pub(super) fn assert_subset(old: &Value, current: &Value) {
    match (old, current) {
        (Value::Map(old), Value::Map(current)) => {
            for (key, value) in old {
                let new = current
                    .get(key)
                    .unwrap_or_else(|| panic!("lost fixture field {:?}", key));
                assert_subset(value, new);
            }
        }
        (Value::Array(old), Value::Array(current)) => {
            assert_eq!(old.len(), current.len(), "changed fixture array length");
            for (old, current) in old.iter().zip(current) {
                assert_subset(old, current);
            }
        }
        _ => assert_eq!(old, current, "changed fixture value"),
    }
}

pub(super) fn check<T: DeserializeOwned + Serialize>(release: &Path, name: &str) -> T {
    let path = release.join(format!("{name}.cbor"));
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
    let old: Value = serde_cbor::from_slice(&bytes).unwrap();
    let current: T =
        serde_cbor::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
    assert_subset(&old, &to_value(&current).unwrap());
    current
}

pub(super) fn write<T: Serialize>(release: &Path, name: &str, value: &T) {
    fs::create_dir_all(release).unwrap();
    fs::write(
        release.join(format!("{name}.cbor")),
        serde_cbor::to_vec(value).unwrap(),
    )
    .unwrap();
}

#[test]
fn compat_fixtures_every_release_decodes_without_losing_fields() {
    let mut releases: Vec<_> = fs::read_dir(fixture_root())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    releases.sort();
    assert!(releases
        .iter()
        .any(|path| path.file_name().unwrap() == "v0.2.3"));
    assert!(releases
        .iter()
        .any(|path| path.file_name().unwrap() == "v0.3.0"));
    for release in releases {
        wire::check_release(&release);
        storage::check_release(&release);
        offerbook::check_release(&release);
    }
}

#[test]
fn compat_fixtures_subset_guard_rejects_renamed_fields() {
    let original = Value::Map(BTreeMap::from([(
        Value::Text("internal_index".into()),
        Value::Integer(9),
    )]));
    let renamed = Value::Map(BTreeMap::from([(
        Value::Text("renamed_index".into()),
        Value::Integer(9),
    )]));
    assert!(std::panic::catch_unwind(|| assert_subset(&original, &renamed)).is_err());
}

#[test]
fn compat_fixtures_flatten_rejects_integers_below_i64() {
    #[derive(Debug, Deserialize)]
    struct Container {
        #[serde(flatten)]
        _extra: BTreeMap<String, Value>,
    }
    let value = Value::Map(BTreeMap::from([(
        Value::Text("future".into()),
        Value::Integer(i128::from(i64::MIN) - 1),
    )]));
    let bytes = serde_cbor::to_vec(&value).unwrap();
    assert!(serde_cbor::from_slice::<Container>(&bytes).is_err());
}

#[derive(Serialize, Deserialize)]
struct ProductionVector {
    password: String,
    iterations: u32,
    salt: [u8; 16],
    key: Vec<u8>,
    aad: Vec<u8>,
    plaintext: String,
    encrypted: EncryptedDataV2,
}

#[test]
fn compat_fixtures_production_kdf_and_aad_vectors_are_frozen() {
    let vector: ProductionVector = serde_cbor::from_slice(include_bytes!(
        "../tests/fixtures/compat/v0.3.0/production-kdf.cbor"
    ))
    .unwrap();
    assert_eq!(vector.iterations, 600_000);
    assert_eq!(
        pbkdf2_hmac_array::<Sha256, 32>(
            vector.password.as_bytes(),
            &vector.salt,
            vector.iterations,
        )
        .as_slice(),
        vector.key
    );
    assert_eq!(
        header_aad(2, &vector.encrypted.requires).unwrap(),
        vector.aad
    );
    assert_eq!(
        vector.aad,
        b"\x82\x02\x83\x66legacy\x67taproot\x6ewallet-store-2"
    );
    assert_eq!(header_aad(2, &[]).unwrap(), b"\x82\x02\x80");
}

fn generate_production_vector(release: &Path) {
    // Retain the production KDF inputs when changing the container/AAD vector.
    #[derive(Deserialize)]
    struct Inputs {
        password: String,
        iterations: u32,
        salt: [u8; 16],
        plaintext: String,
    }
    let input: Inputs =
        serde_cbor::from_slice(&fs::read(release.join("production-kdf.cbor")).unwrap()).unwrap();
    let key =
        pbkdf2_hmac_array::<Sha256, 32>(input.password.as_bytes(), &input.salt, input.iterations);
    let material = KeyMaterial {
        key,
        nonce: [0; 12],
        pbkdf2_salt: input.salt,
    };
    let requires = vec!["legacy".into(), "taproot".into(), "wallet-store-2".into()];
    let aad = header_aad(2, &requires).unwrap();
    let encrypted = encrypt_struct_v2(&input.plaintext, &material, requires).unwrap();
    write(
        release,
        "production-kdf",
        &ProductionVector {
            password: input.password,
            iterations: input.iterations,
            salt: input.salt,
            key: key.to_vec(),
            aad,
            plaintext: input.plaintext,
            encrypted,
        },
    );
}

#[test]
#[ignore = "writes the next release's storage fixtures; run explicitly with lightning"]
fn generate_storage_compat_fixtures() {
    if !cfg!(feature = "lightning") {
        panic!("generate every Lightning sample too");
    }
    let release = fixture_root().join("v0.3.0");
    storage::generate(&release);
    generate_production_vector(&release);
}

#[test]
#[ignore = "writes the next release's fixtures; run explicitly with lightning"]
fn generate_compat_fixtures() {
    if !cfg!(feature = "lightning") {
        panic!("generate every Lightning sample too");
    }
    let release = fixture_root().join("v0.3.0");
    wire::generate(&release);
    storage::generate(&release);
    generate_production_vector(&release);
    offerbook::generate(&release);
}
