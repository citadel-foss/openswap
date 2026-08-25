//! Generic crate for securely loading and storing sensitive data from disk.
//!
//! This module provides utilities for encrypting and decrypting serializable Rust structs,
//! using AES-256-GCM encryption and CBOR/JSON serialization formats.
//!
//! The main focus is securely storing wallet-related or sensitive data structures,
//! allowing seamless support for both encrypted and unencrypted files.

use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit,
};
use bip39::rand::random;
use pbkdf2::pbkdf2_hmac_array;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::utill;
use std::{fs, path::Path};

/// Errors returned while loading or decrypting sensitive data.
#[derive(Debug)]
pub enum SecurityError {
    /// The sensitive file could not be read.
    Io(std::io::Error),
    /// The file did not match the required serialization format.
    Format(String),
    /// Authentication or decryption failed.
    Decryption,
    /// The decrypted CBOR payload was invalid.
    Cbor(serde_cbor::Error),
    /// The file is encrypted but no password was supplied. The caller is
    /// responsible for obtaining a password (e.g. by prompting the user)
    /// and retrying with `Some(password)`.
    PasswordRequired,
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Format(err) => write!(f, "format error: {err}"),
            Self::Decryption => write!(f, "decryption failed; wrong password or corrupted data"),
            Self::Cbor(err) => write!(f, "CBOR error: {err}"),
            Self::PasswordRequired => write!(f, "file is encrypted but no password was supplied"),
        }
    }
}

impl std::error::Error for SecurityError {}

impl From<std::io::Error> for SecurityError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_cbor::Error> for SecurityError {
    fn from(err: serde_cbor::Error) -> Self {
        Self::Cbor(err)
    }
}

/// Errors that can occur during the encryption process.
///
/// This enum covers serialization errors from CBOR encoding as well as
/// encryption failures.
#[derive(Debug)]
pub enum EncryptError {
    /// Error occurred during CBOR serialization of the input struct.
    Serialization(serde_cbor::Error),
    /// Error occurred during AES-GCM encryption.
    ///
    /// Note: This error type carries no additional information because
    /// the underlying AES-GCM error is a zero-sized marker.
    Encryption,
}

impl From<serde_cbor::Error> for EncryptError {
    fn from(err: serde_cbor::Error) -> Self {
        EncryptError::Serialization(err)
    }
}

impl From<aes_gcm::Error> for EncryptError {
    fn from(_: aes_gcm::Error) -> Self {
        EncryptError::Encryption
    }
}

/// Represents a deserialization format used for loading wallet files from disk.
///
/// This trait abstracts over format-specific parsing logic to allow runtime
/// switching between JSON and CBOR.
///
/// It is specifically used by [`load_sensitive_struct`] to try parsing
/// the file in both formats.
///
/// **Note on CBOR:**  
/// Due to potential trailing bytes left by `serde_cbor`, the CBOR variant delegates
/// parsing to [`utill::deserialize_from_cbor`] that strips extra data before deserialization.
///
/// This trait is **not** intended for general-purpose serialization or format negotiation.
pub trait SerdeFormat {
    /// Errors that can occur while parsing or deserializing data
    /// using this serialization format.
    ///
    /// Implementors should use a concrete error type that describes
    /// failures specific to their format (e.g., `serde_json::Error`).
    type Error: std::error::Error + Send + Sync + 'static;

    #[allow(missing_docs)]
    fn from_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, Self::Error>;
}
/// JSON implementation of `SerdeFormat`, using `serde_json`.
///
/// Used for loading plain or encrypted wallet files that were serialized as JSON.
pub struct SerdeJson;

impl SerdeFormat for SerdeJson {
    type Error = serde_json::Error;
    fn from_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(input)
    }
}
/// CBOR implementation of `SerdeFormat`, using a utility wrapper
/// that handles CBOR trailing data properly.
///
/// `serde_cbor` may leave trailing data behind, which can cause
/// parsing errors.
/// This wrapper [`utill::deserialize_from_cbor`] utility method to cleanly deserialize.
pub struct SerdeCbor;

impl SerdeFormat for SerdeCbor {
    type Error = serde_cbor::Error;
    fn from_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, Self::Error> {
        utill::deserialize_from_cbor::<T>(input)
    }
}
/// A 16-byte (128-bit) salt used with PBKDF2 to derive encryption keys.
///
/// This salt is randomly generated each time new encryption is performed, ensuring that
/// even if two users choose the same password, their derived keys will be unique.
/// The combination of the user’s password and this salt produces a unique encryption key.
///
/// 16 bytes (128 bits) is recommended to provide sufficient entropy to prevent precomputation attacks.
/// See:
/// - <https://datatracker.ietf.org/doc/html/rfc2898#section-5.2>
/// - <https://docs.rs/password-hash/0.5.0/password_hash/struct.Salt.html#associatedconstant.RECOMMENDED_LENGTH>
type PBKDF2Salt = [u8; 16];
/// A 12-byte (96-bit) nonce used as the Initialization Vector (IV) for AES-GCM encryption.
type EncryptionNonce = [u8; 12];
/// A 32-byte (256-bit) key derived from a passphrase via PBKDF2,
/// used as the symmetric encryption key with AES-GCM.
type EncryptionKey = [u8; 32];

/// Number of PBKDF2 iterations to strengthen passphrase-derived keys.
///
/// In production, this is set to **600,000 iterations**, following
/// modern password security guidance from the
/// [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
///
/// During testing or integration tests, the iteration count is reduced to 1
/// for performance.
#[cfg(any(feature = "integration-test", test))]
const PBKDF2_ITERATIONS: u32 = 1;
#[cfg(not(any(feature = "integration-test", test)))]
const PBKDF2_ITERATIONS: u32 = 600_000;

/// Holds derived cryptographic key material used for encrypting and decrypting wallet data.
///
/// Zeroized on drop; `Debug` is redacted so the key never reaches logs.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    /// A 256-bit key derived from the user’s passphrase via PBKDF2.
    /// This key is used with AES-GCM for encryption/decryption.
    pub key: EncryptionKey,
    /// Nonce loaded or generated with this material. Encryption always uses a
    /// fresh nonce and stores it alongside the ciphertext.
    pub nonce: EncryptionNonce,
    /// Key derivation salt, randomly generated to ensure unique keys per password.
    pub pbkdf2_salt: PBKDF2Salt,
}

/// Redacted: key material must never reach logs.
impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyMaterial(<redacted>)")
    }
}

impl KeyMaterial {
    /// Creates new key material from a password, with a freshly random generated nonce and salt.
    ///
    /// The passphrase string is zeroized after key derivation.
    pub fn new_from_password(enc_password: Option<String>) -> Option<Self> {
        enc_password.map(|mut pwd| {
            let pbkdf2_salt = random::<PBKDF2Salt>();
            let key =
                pbkdf2_hmac_array::<Sha256, 32>(pwd.as_bytes(), &pbkdf2_salt, PBKDF2_ITERATIONS);
            pwd.zeroize();
            KeyMaterial {
                key,
                nonce: Aes256Gcm::generate_nonce(&mut OsRng).into(),
                pbkdf2_salt,
            }
        })
    }
    /// Prompts the user interactively for a new encryption passphrase.
    ///
    /// If the user enters an empty string, returns `None`; callers decide
    /// whether that is acceptable (wallet and backup encryption require a
    /// non-empty passphrase).
    pub fn new_interactive(prompt: Option<String>) -> Result<Option<Self>, SecurityError> {
        let enc_password = utill::prompt_password(
            prompt.unwrap_or("Enter new encryption passphrase: ".to_string()),
        )?;

        if enc_password.is_empty() {
            Ok(None)
        } else {
            let pbkdf2_salt = random::<PBKDF2Salt>();
            let mut enc_password = enc_password;
            let key = pbkdf2_hmac_array::<Sha256, 32>(
                enc_password.as_bytes(),
                &pbkdf2_salt,
                PBKDF2_ITERATIONS,
            );
            enc_password.zeroize();
            Ok(Some(KeyMaterial {
                key,
                nonce: Aes256Gcm::generate_nonce(&mut OsRng).into(),
                pbkdf2_salt,
            }))
        }
    }

    /// Creates ephemeral key material with a random key, nonce, and salt.
    ///
    /// The key is never persisted, so anything sealed with it is
    /// unrecoverable once the process exits. Only used by tests — wallets
    /// always seal with passphrase-derived material.
    #[cfg(test)]
    pub(crate) fn new_ephemeral() -> Self {
        KeyMaterial {
            key: random::<EncryptionKey>(),
            nonce: Aes256Gcm::generate_nonce(&mut OsRng).into(),
            pbkdf2_salt: random::<PBKDF2Salt>(),
        }
    }

    /// Creates a complete `KeyMaterial` from a password, a known nonce and a known salt.
    ///
    /// This is used when decrypting existing wallet data, where the nonce
    /// and the salt have already been read from disk and are available.
    /// The passphrase string is zeroized after key derivation.
    pub fn existing(mut password: String, nonce: EncryptionNonce, pbkdf2_salt: PBKDF2Salt) -> Self {
        let key =
            pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), &pbkdf2_salt, PBKDF2_ITERATIONS);
        password.zeroize();
        KeyMaterial {
            key,
            nonce,
            pbkdf2_salt,
        }
    }
}

/// Wrapper struct for storing an encrypted data on disk.
///
/// The plaintext struct containing the data to encrypt is first serialized to CBOR, then encrypted using
/// [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode).
///
/// The resulting ciphertext is stored in `encrypted_payload`, and the AES-GCM
/// nonce used for encryption is stored in `nonce`.
///
/// Note: The term “IV” (Initialization Vector) used in AES-GCM — including in the linked Wikipedia page —
/// refers to the same value as the nonce. They are conceptually the same in this context.
///
/// This wrapper itself is then serialized to CBOR and written to disk.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct EncryptedData {
    /// Nonce used for AES-GCM encryption (must match during decryption).
    nonce: EncryptionNonce,
    /// AES-GCM-encrypted CBOR-serialized plaintext struct data.
    encrypted_payload: Vec<u8>,
    /// Salt for the PBKDF2 key generation
    pbkdf2_salt: PBKDF2Salt,
}

/// Encrypts a serializable struct using AES-256-GCM encryption and CBOR serialization.
///
/// This function applies the following transformation pipeline:
/// `Struct -> serde_cbor::ser::to_vec(Struct) -> AES-GCM(encrypted_bytes) = encrypted_payload -> EncryptedData { encrypted_payload, nonce }`
///
///
/// The struct is first serialized into CBOR bytes, then encrypted using AES-GCM
/// with the key provided in [`KeyMaterial`] and a freshly generated nonce. The
/// resulting ciphertext is bundled with the nonce in an [`EncryptedData`] struct
/// for storage.
///
/// The resulting `EncryptedData` can be serialized and stored to disk. To decrypt it later,
/// use [`decrypt_struct`].
pub fn encrypt_struct<T: Serialize>(
    plain_struct: T,
    enc_material: &KeyMaterial,
) -> Result<EncryptedData, EncryptError> {
    // Serialize wallet data to bytes. `Zeroizing` wipes the plaintext buffer
    // on drop so no serialized copy of the secret survives in freed heap.
    let packed_store = Zeroizing::new(serde_cbor::ser::to_vec(&plain_struct)?);

    // QA: AES-GCM nonce reuse across wallet saves or backup restoration leaks
    // relationships between plaintexts encrypted under the same key.
    let material_nonce = Aes256Gcm::generate_nonce(&mut OsRng).into();
    let pbkdf2_salt = enc_material.pbkdf2_salt;
    let nonce = aes_gcm::Nonce::from(material_nonce);
    let key = Key::<Aes256Gcm>::from(enc_material.key);

    // Create AES-GCM cipher instance.
    let cipher = Aes256Gcm::new(&key);

    // Encrypt the serialized wallet bytes.
    let encrypted_payload = cipher.encrypt(&nonce, packed_store.as_ref())?;

    // Package encrypted data with nonce for storage.
    Ok(EncryptedData {
        nonce: material_nonce,
        encrypted_payload,
        pbkdf2_salt,
    })
}

/// Decrypts an [`EncryptedData`] struct and deserializes the inner struct.
///
/// This function reverses the encryption pipeline:
/// `EncryptedData -> AES-GCM Decryption -> CBOR -> Struct`
///
/// It uses the AES-256-GCM key and nonce in [`KeyMaterial`] to decrypt the
/// encrypted CBOR payload, then deserializes it into the original struct.
pub fn decrypt_struct<T: DeserializeOwned>(
    encrypted_struct: EncryptedData,
    enc_material: &KeyMaterial,
) -> Result<T, SecurityError> {
    // Deserialize the outer EncryptedWalletStore wrapper.

    let nonce_vec = encrypted_struct.nonce;

    // Reconstruct AES-GCM cipher from the provided key and stored nonce.
    let key = Key::<Aes256Gcm>::from(enc_material.key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = aes_gcm::Nonce::from(nonce_vec);

    // Decrypt the inner CBOR bytes. `Zeroizing` wipes the plaintext buffer on
    // drop so no serialized copy of the secret survives in freed heap.
    let plaintext_cbor = Zeroizing::new(
        cipher
            .decrypt(&nonce, encrypted_struct.encrypted_payload.as_ref())
            .map_err(|_| SecurityError::Decryption)?,
    );

    // Deserialize the inner CBOR into the original type (borrows the
    // `Zeroizing` buffer, so no un-wiped copy is made).
    Ok(utill::deserialize_from_cbor::<T>(&plaintext_cbor)?)
}
/// Loads a sensitive struct from a file, supporting both encrypted and plaintext formats.
///
/// When a non-empty password is supplied, this function requires the file to
/// deserialize as [`EncryptedData`] and never attempts a plaintext fallback.
/// Without a password, it tries to deserialize the file contents in two steps:
///
/// 1. **Unencrypted:** Attempts to deserialize the file directly as `T`.
/// 2. **Encrypted:** If that fails, attempts to deserialize as [`EncryptedData`].
///    If no password was supplied, returns [`SecurityError::PasswordRequired`]
///    so the caller can obtain one (e.g. by prompting the user) and retry.
///
/// The deserialization format (CBOR or JSON) is defined by the [`SerdeFormat`] trait
/// implementation passed via the type parameter `F`.
///
/// # Type Parameters
/// - `T`: The struct type to load.
/// - `F`: A type implementing [`SerdeFormat`] (`SerdeCbor` or `SerdeJson`).
pub fn load_sensitive_struct<T: DeserializeOwned, F: SerdeFormat>(
    file: &Path,
    password: Option<String>,
) -> Result<(T, Option<KeyMaterial>), SecurityError> {
    let content = fs::read(file)?;

    let password = match password {
        Some(encryption_password) if !encryption_password.is_empty() => {
            let encrypted_struct = F::from_slice::<EncryptedData>(&content).map_err(|err| {
                SecurityError::Format(format!(
                    "expected encrypted file {file:?} because a password was supplied: {err}"
                ))
            })?;
            let enc_material = KeyMaterial::existing(
                encryption_password,
                encrypted_struct.nonce,
                encrypted_struct.pbkdf2_salt,
            );
            let decrypted = decrypt_struct::<T>(encrypted_struct, &enc_material)?;

            return Ok((decrypted, Some(enc_material)));
        }
        password => password,
    };

    let (sensitive_struct, encryption_material) = match F::from_slice::<T>(&content) {
        Ok(unencrypted_struct) => (unencrypted_struct, None),
        Err(unencrypted_err) => match F::from_slice::<EncryptedData>(&content) {
            Ok(encrypted_struct) => {
                let encryption_password = match password {
                    Some(p) => p,
                    None => return Err(SecurityError::PasswordRequired),
                };
                let enc_material = KeyMaterial::existing(
                    encryption_password,
                    encrypted_struct.nonce,
                    encrypted_struct.pbkdf2_salt,
                );

                let decrypted = decrypt_struct::<T>(encrypted_struct, &enc_material)?;

                (decrypted, Some(enc_material))
            }
            Err(encrypted_err) => {
                return Err(SecurityError::Format(format!(
                    "failed to deserialize file {file:?}; as plaintext: {unencrypted_err}; as encrypted: {encrypted_err}"
                )));
            }
        },
    };

    Ok((sensitive_struct, encryption_material))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_rotates_nonce_for_same_key_material() {
        let material = KeyMaterial::new_from_password(Some("test password".to_string())).unwrap();
        let first = encrypt_struct("wallet state", &material).unwrap();
        let second = encrypt_struct("wallet state", &material).unwrap();

        assert_ne!(first.nonce, second.nonce);
        assert_eq!(
            decrypt_struct::<String>(first, &material).unwrap(),
            "wallet state"
        );
        assert_eq!(
            decrypt_struct::<String>(second, &material).unwrap(),
            "wallet state"
        );
    }

    #[test]
    fn decrypts_legacy_ciphertext_using_material_nonce() {
        let material = KeyMaterial::new_from_password(Some("test password".to_string())).unwrap();
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(material.key));
        let encrypted = EncryptedData {
            nonce: material.nonce,
            encrypted_payload: cipher
                .encrypt(
                    &aes_gcm::Nonce::from(material.nonce),
                    serde_cbor::to_vec(&"legacy wallet state").unwrap().as_ref(),
                )
                .unwrap(),
            pbkdf2_salt: material.pbkdf2_salt,
        };

        assert_eq!(
            decrypt_struct::<String>(encrypted, &material).unwrap(),
            "legacy wallet state"
        );
    }
}
