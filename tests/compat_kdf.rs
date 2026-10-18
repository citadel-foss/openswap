//! Checks the normal library build's password derivation against a fixed vector.
#![cfg(not(feature = "integration-test"))]

use openswap::security::{load_sensitive_struct, EncryptedDataV2, SecurityError, SerdeCbor};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    password: String,
    plaintext: String,
    encrypted: EncryptedDataV2,
}

#[test]
fn compat_production_kdf_opens_the_frozen_ciphertext() {
    let vector: Vector =
        serde_cbor::from_slice(include_bytes!("fixtures/compat/v0.3.0/production-kdf.cbor"))
            .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet");
    std::fs::write(&path, serde_cbor::to_vec(&vector.encrypted).unwrap()).unwrap();
    let (plaintext, _) =
        load_sensitive_struct::<String, SerdeCbor>(&path, Some(vector.password.clone())).unwrap();
    assert_eq!(plaintext, vector.plaintext);
    let mut stripped = serde_cbor::value::to_value(&vector.encrypted).unwrap();
    let serde_cbor::Value::Map(ref mut fields) = stripped else {
        panic!("container is a map")
    };
    fields.insert(
        serde_cbor::Value::Text("requires".into()),
        serde_cbor::Value::Array(Vec::new()),
    );
    std::fs::write(&path, serde_cbor::to_vec(&stripped).unwrap()).unwrap();
    assert!(matches!(
        load_sensitive_struct::<String, SerdeCbor>(&path, Some(vector.password)),
        Err(SecurityError::Decryption)
    ));
}
