//! Checks the normal library build's password derivation against a fixed vector.
#![cfg(not(feature = "integration-test"))]

use openswap::security::{decrypt_struct_with_aad, EncryptedData, KeyMaterial};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    password: String,
    nonce: [u8; 12],
    salt: [u8; 16],
    aad: Vec<u8>,
    plaintext: String,
    encrypted: EncryptedData,
}

#[test]
fn compat_production_kdf_opens_the_frozen_ciphertext() {
    let vector: Vector =
        serde_cbor::from_slice(include_bytes!("fixtures/compat/v0.3.0/production-kdf.cbor"))
            .unwrap();
    let material = KeyMaterial::existing(vector.password.clone(), vector.nonce, vector.salt);
    let plaintext: String =
        decrypt_struct_with_aad(vector.encrypted.clone(), &material, &vector.aad).unwrap();
    assert_eq!(plaintext, vector.plaintext);
    assert!(decrypt_struct_with_aad::<String>(vector.encrypted, &material, &[]).is_err());
}
