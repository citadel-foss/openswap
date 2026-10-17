//! Generic crate for securely loading and storing sensitive data from disk.
//!
//! This module provides utilities for encrypting and decrypting serializable Rust structs,
//! using AES-256-GCM encryption and CBOR/JSON serialization formats.
//!
//! The main focus is securely storing wallet-related or sensitive data structures,
//! allowing seamless support for both encrypted and unencrypted files.

use aes_gcm::{
    aead::{Aead, OsRng, Payload},
    AeadCore, Aes256Gcm, Key, KeyInit,
};
use bip39::rand::random;
use pbkdf2::pbkdf2_hmac_array;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::utill;
use std::{fs, io, path::Path};

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
        enc_password.map(|pwd| {
            let pwd = Zeroizing::new(pwd);
            let pbkdf2_salt = random::<PBKDF2Salt>();
            let key =
                pbkdf2_hmac_array::<Sha256, 32>(pwd.as_bytes(), &pbkdf2_salt, PBKDF2_ITERATIONS);
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
            let key = pbkdf2_hmac_array::<Sha256, 32>(
                enc_password.as_bytes(),
                &pbkdf2_salt,
                PBKDF2_ITERATIONS,
            );
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
    pub fn existing(password: String, nonce: EncryptionNonce, pbkdf2_salt: PBKDF2Salt) -> Self {
        let password = Zeroizing::new(password);
        let key =
            pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), &pbkdf2_salt, PBKDF2_ITERATIONS);
        KeyMaterial {
            key,
            nonce,
            pbkdf2_salt,
        }
    }

    /// Whether `password` derives this key, as trial-decrypting the file would.
    pub(crate) fn matches_password(&self, password: &str) -> bool {
        let key = Zeroizing::new(pbkdf2_hmac_array::<Sha256, 32>(
            password.as_bytes(),
            &self.pbkdf2_salt,
            PBKDF2_ITERATIONS,
        ));
        // Constant time, so the comparison leaks nothing about the key.
        key.iter()
            .zip(self.key.iter())
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
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

/// The only [`EncryptedDataV2`] version this build reads and writes.
const ENCRYPTED_DATA_VERSION: u32 = 2;

/// Version 2 container. It has no `encrypted_payload`, so older readers refuse
/// it instead of loading it and saving back a copy without the fields they
/// don't know. `version` and `requires` are cleartext, bound to the ciphertext.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedDataV2 {
    version: u32,
    /// Features a reader must support before it may open the file.
    requires: Vec<String>,
    nonce: EncryptionNonce,
    pbkdf2_salt: PBKDF2Salt,
    ciphertext: Vec<u8>,
}

/// Reads just the version, so a newer container is refused whatever its shape.
#[derive(Deserialize)]
struct ContainerVersion {
    version: u32,
}

/// The cleartext header as authenticated data: editing it fails decryption.
fn header_aad(version: u32, requires: &[String]) -> Result<Vec<u8>, serde_cbor::Error> {
    serde_cbor::to_vec(&(version, requires))
}

/// Settings of the key that sealed a [`SealedSecret`], stored next to it.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
enum Kdf {
    Pbkdf2Sha256 { iterations: u32, salt: PBKDF2Salt },
}

/// A secret sealed under its own key, derived from the password on every call
/// and never kept. Holding the unlocked wallet is not enough to open it.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct SealedSecret {
    kdf: Kdf,
    nonce: EncryptionNonce,
    ciphertext: Vec<u8>,
}

/// Redacted: nothing about the sealed secret belongs in logs.
impl std::fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealedSecret(<sealed>)")
    }
}

impl SealedSecret {
    /// Seals `secret` under a key derived from `password` with a fresh salt.
    pub fn seal<T: Serialize>(secret: &T, password: &str) -> Result<Self, EncryptError> {
        let salt = random::<PBKDF2Salt>();
        let key = Zeroizing::new(pbkdf2_hmac_array::<Sha256, 32>(
            password.as_bytes(),
            &salt,
            PBKDF2_ITERATIONS,
        ));
        let (nonce, ciphertext) = seal_cbor(secret, &key, &[])?;
        Ok(Self {
            kdf: Kdf::Pbkdf2Sha256 {
                iterations: PBKDF2_ITERATIONS,
                salt,
            },
            nonce,
            ciphertext,
        })
    }

    /// Opens the secret with `password`. A wrong password fails authentication.
    pub fn open<T: DeserializeOwned>(&self, password: &str) -> Result<T, SecurityError> {
        let Kdf::Pbkdf2Sha256 { iterations, salt } = &self.kdf;
        // Above our own count a hand-edited file could stall the process.
        if !(1..=PBKDF2_ITERATIONS).contains(iterations) {
            return Err(SecurityError::Format(format!(
                "sealed secret uses {iterations} PBKDF2 iterations; this build accepts 1 to {PBKDF2_ITERATIONS}"
            )));
        }
        let key = Zeroizing::new(pbkdf2_hmac_array::<Sha256, 32>(
            password.as_bytes(),
            salt,
            *iterations,
        ));
        open_cbor(&self.nonce, &self.ciphertext, &key, &[])
    }
}

/// Whether CBOR `content` is an encrypted container of any version.
pub fn is_encrypted_cbor(content: &[u8]) -> bool {
    serde_cbor::from_slice::<ContainerVersion>(content).is_ok()
        || serde_cbor::from_slice::<EncryptedData>(content).is_ok()
}

/// Counts the bytes written to it, to size a buffer before filling it.
struct ByteCount(usize);

impl io::Write for ByteCount {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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
    let (nonce, encrypted_payload) = seal_cbor(&plain_struct, &enc_material.key, &[])?;
    Ok(EncryptedData {
        nonce,
        encrypted_payload,
        pbkdf2_salt: enc_material.pbkdf2_salt,
    })
}

/// Like [`encrypt_struct`], but writes the version 2 container.
pub fn encrypt_struct_v2<T: Serialize>(
    plain_struct: &T,
    enc_material: &KeyMaterial,
) -> Result<EncryptedDataV2, EncryptError> {
    let requires = Vec::new();
    let aad = header_aad(ENCRYPTED_DATA_VERSION, &requires)?;
    let (nonce, ciphertext) = seal_cbor(plain_struct, &enc_material.key, &aad)?;
    Ok(EncryptedDataV2 {
        version: ENCRYPTED_DATA_VERSION,
        requires,
        nonce,
        pbkdf2_salt: enc_material.pbkdf2_salt,
        ciphertext,
    })
}

/// CBOR-encodes `plain` and encrypts it with AES-256-GCM under a fresh nonce.
fn seal_cbor<T: Serialize>(
    plain: &T,
    key: &EncryptionKey,
    aad: &[u8],
) -> Result<(EncryptionNonce, Vec<u8>), EncryptError> {
    // `Zeroizing` wipes the plaintext buffer on drop, and sizing it first
    // means no growth frees an unwiped copy.
    let mut size = ByteCount(0);
    serde_cbor::to_writer(&mut size, plain)?;
    let mut packed = Zeroizing::new(Vec::with_capacity(size.0));
    serde_cbor::to_writer(&mut *packed, plain)?;

    // QA: AES-GCM nonce reuse across wallet saves or backup restoration leaks
    // relationships between plaintexts encrypted under the same key.
    let nonce: EncryptionNonce = Aes256Gcm::generate_nonce(&mut OsRng).into();
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let payload = Payload {
        msg: packed.as_ref(),
        aad,
    };
    let ciphertext = cipher.encrypt(&aes_gcm::Nonce::from(nonce), payload)?;
    Ok((nonce, ciphertext))
}

/// Reverses [`seal_cbor`]. Fails on a wrong key or edited `aad`.
fn open_cbor<T: DeserializeOwned>(
    nonce: &EncryptionNonce,
    ciphertext: &[u8],
    key: &EncryptionKey,
    aad: &[u8],
) -> Result<T, SecurityError> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    // `Zeroizing` wipes the plaintext buffer on drop so no serialized copy of
    // the secret survives in freed heap.
    let plaintext_cbor = Zeroizing::new(
        cipher
            .decrypt(&aes_gcm::Nonce::from(*nonce), payload)
            .map_err(|_| SecurityError::Decryption)?,
    );
    // Borrows the `Zeroizing` buffer, so no un-wiped copy is made.
    Ok(utill::deserialize_from_cbor::<T>(&plaintext_cbor)?)
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
    open_cbor(
        &encrypted_struct.nonce,
        &encrypted_struct.encrypted_payload,
        &enc_material.key,
        &[],
    )
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
/// A versioned [`EncryptedDataV2`] file is recognised first and always needs a
/// password; unknown versions or required features are refused.
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
    let content = Zeroizing::new(fs::read(file)?);

    let password = password.map(Zeroizing::new);
    // Checked before the plaintext attempt: a versioned file is never plaintext.
    if let Ok(ContainerVersion { version }) = F::from_slice::<ContainerVersion>(&content) {
        return decrypt_v2::<T, F>(&content, file, version, password);
    }
    let password = match password {
        Some(mut encryption_password) if !encryption_password.is_empty() => {
            let encrypted_struct = F::from_slice::<EncryptedData>(&content).map_err(|err| {
                SecurityError::Format(format!(
                    "expected encrypted file {file:?} because a password was supplied: {err}"
                ))
            })?;
            let enc_material = KeyMaterial::existing(
                std::mem::take(&mut *encryption_password),
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
                let mut encryption_password = match password {
                    Some(p) => p,
                    None => return Err(SecurityError::PasswordRequired),
                };
                let enc_material = KeyMaterial::existing(
                    std::mem::take(&mut *encryption_password),
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

/// Opens a versioned container, refusing versions and features this build lacks.
fn decrypt_v2<T: DeserializeOwned, F: SerdeFormat>(
    content: &[u8],
    file: &Path,
    version: u32,
    password: Option<Zeroizing<String>>,
) -> Result<(T, Option<KeyMaterial>), SecurityError> {
    if version != ENCRYPTED_DATA_VERSION {
        return Err(SecurityError::Format(format!(
            "{file:?} has format version {version}; this build reads version \
             {ENCRYPTED_DATA_VERSION}, so it may need a newer openswap"
        )));
    }
    let data = F::from_slice::<EncryptedDataV2>(content)
        .map_err(|err| SecurityError::Format(format!("invalid encrypted file {file:?}: {err}")))?;
    if !data.requires.is_empty() {
        return Err(SecurityError::Format(format!(
            "{file:?} needs features this build lacks: {:?}",
            data.requires
        )));
    }
    let Some(mut password) = password.filter(|p| !p.is_empty()) else {
        return Err(SecurityError::PasswordRequired);
    };
    let enc_material =
        KeyMaterial::existing(std::mem::take(&mut *password), data.nonce, data.pbkdf2_salt);
    let aad = header_aad(data.version, &data.requires)?;
    let decrypted = open_cbor(&data.nonce, &data.ciphertext, &enc_material.key, &aad)?;
    Ok((decrypted, Some(enc_material)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoind::tempfile::tempdir;

    #[test]
    fn v2_container_is_refused_by_old_readers() {
        let material = KeyMaterial::new_from_password(Some("test password".to_string())).unwrap();
        let v2 =
            serde_cbor::to_vec(&encrypt_struct_v2(&"wallet state", &material).unwrap()).unwrap();
        let v1 = serde_cbor::to_vec(&encrypt_struct("wallet state", &material).unwrap()).unwrap();

        // Older builds parse wallet files only as `EncryptedData`.
        assert!(serde_cbor::from_slice::<EncryptedData>(&v2).is_err());
        assert!(is_encrypted_cbor(&v2));
        assert!(is_encrypted_cbor(&v1));
        assert!(!is_encrypted_cbor(
            &serde_cbor::to_vec(&"wallet state").unwrap()
        ));

        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        for bytes in [&v1, &v2] {
            fs::write(&path, bytes).unwrap();
            let (read, read_material) =
                load_sensitive_struct::<String, SerdeCbor>(&path, Some("test password".into()))
                    .unwrap();
            assert_eq!(read, "wallet state");
            assert_eq!(read_material.unwrap().key, material.key);
        }
        let wrong = load_sensitive_struct::<String, SerdeCbor>(&path, Some("wrong".into()));
        assert!(matches!(wrong, Err(SecurityError::Decryption)));
        for password in [None, Some(String::new())] {
            let missing = load_sensitive_struct::<String, SerdeCbor>(&path, password);
            assert!(matches!(missing, Err(SecurityError::PasswordRequired)));
        }
    }

    #[test]
    fn v2_container_refuses_unknown_versions_and_edited_headers() {
        let material = KeyMaterial::new_from_password(Some("test password".to_string())).unwrap();
        let data = encrypt_struct_v2(&"wallet state", &material).unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let load = |data: &EncryptedDataV2| {
            fs::write(&path, serde_cbor::to_vec(data).unwrap()).unwrap();
            load_sensitive_struct::<String, SerdeCbor>(&path, Some("test password".into()))
        };

        let newer = EncryptedDataV2 {
            version: 3,
            ..data.clone()
        };
        assert!(matches!(load(&newer), Err(SecurityError::Format(e)) if e.contains("version 3")));
        // A newer layout is refused by its version alone, whatever else it holds.
        fs::write(
            &path,
            serde_cbor::to_vec(&ContainerVersionOnly { version: 3 }).unwrap(),
        )
        .unwrap();
        let shapeless = load_sensitive_struct::<String, SerdeCbor>(&path, Some("x".into()));
        assert!(matches!(shapeless, Err(SecurityError::Format(e)) if e.contains("version 3")));

        let needs_more = EncryptedDataV2 {
            requires: vec!["future-feature".to_string()],
            ..data.clone()
        };
        assert!(
            matches!(load(&needs_more), Err(SecurityError::Format(e)) if e.contains("future-feature"))
        );

        // The header is authenticated: a requirement stripped by hand fails decryption.
        let aad = header_aad(2, &["future-feature".to_string()]).unwrap();
        let (nonce, ciphertext) = seal_cbor(&"wallet state", &material.key, &aad).unwrap();
        let stripped = EncryptedDataV2 {
            nonce,
            ciphertext,
            ..data
        };
        assert!(matches!(load(&stripped), Err(SecurityError::Decryption)));
    }

    #[derive(Serialize)]
    struct ContainerVersionOnly {
        version: u32,
    }

    #[test]
    fn sealed_secret_needs_the_password_on_every_open() {
        let sealed = SealedSecret::seal(&"seed entropy", "wallet password").unwrap();
        assert_eq!(
            sealed.open::<String>("wallet password").unwrap(),
            "seed entropy"
        );
        for wrong in ["wrong", ""] {
            assert!(matches!(
                sealed.open::<String>(wrong),
                Err(SecurityError::Decryption)
            ));
        }
        assert_eq!(format!("{sealed:?}"), "SealedSecret(<sealed>)");

        // Every seal draws its own salt and nonce.
        let again = SealedSecret::seal(&"seed entropy", "wallet password").unwrap();
        let (Kdf::Pbkdf2Sha256 { salt: a, .. }, Kdf::Pbkdf2Sha256 { salt: b, .. }) =
            (&sealed.kdf, &again.kdf);
        assert_ne!(a, b);
        assert_ne!(sealed.nonce, again.nonce);

        // The stored iteration count survives a serde round trip and is bounded.
        let read: SealedSecret =
            serde_cbor::from_slice(&serde_cbor::to_vec(&sealed).unwrap()).unwrap();
        assert_eq!(read, sealed);
        for iterations in [0, PBKDF2_ITERATIONS + 1] {
            let Kdf::Pbkdf2Sha256 { salt, .. } = sealed.kdf;
            let edited = SealedSecret {
                kdf: Kdf::Pbkdf2Sha256 { iterations, salt },
                ..sealed.clone()
            };
            assert!(matches!(
                edited.open::<String>("wallet password"),
                Err(SecurityError::Format(_))
            ));
        }
    }

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
