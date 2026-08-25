# Wallet Key Security

This document describes how openswap protects wallet keys — at rest and in
memory — the exact threat model, and the known limitations. It reflects the
design implemented in `src/security.rs` and `src/wallet/storage.rs`
(`MasterKey`).

## Design overview

### At rest (always encrypted, no opt-out)

- Wallet files are **always** encrypted. There is no cleartext-on-disk wallet
  format: `WalletStore::write_to_disk` requires key material, and serializing
  a plaintext master key is a hard error at the serde layer.
- Encryption is AES-256-GCM. The key is derived from the wallet passphrase
  with PBKDF2-HMAC-SHA256 (600,000 iterations, per-encryption 16-byte salt,
  fresh 12-byte nonce per write), following the OWASP password-storage
  guidance.
- Wallet **backups** (`*.json`) contain the master key and are likewise always
  encrypted; the taker CLI backup command always prompts for a passphrase.
- Writes are atomic: the encrypted payload goes to a tempfile in the same
  directory, is fsynced, and is renamed over the target — a crash mid-save
  cannot truncate the only copy of the wallet. Tempfiles are created
  mode `0600` on Unix.

### The master key is individually sealed

On top of whole-file encryption, the BIP32 master key (`MasterKey` in
`src/wallet/storage.rs`) is stored as its own AES-256-GCM blob:

- **On disk**, the sealed blob is what gets serialized, so the frequent
  wallet-state saves (`save_to_disk` runs on every swap state transition)
  never decrypt the master key.
- **In memory**, the key stays sealed for the whole process lifetime and is
  only decrypted inside `Wallet::with_master_key` / `with_account_key`
  closures — i.e. for the duration of a single signature or derivation — then
  the plaintext copy is erased.
- Watch/sync code paths (`watch_wallet_scripts`, restore history probing,
  prevout construction) derive account **xpubs** inside the key closure and
  hold no secret material at all.

### Passphrase hygiene

- The passphrase is consumed at wallet load and zeroized; the long-lived
  `Taker`/`MakerServer` configs hold `None` afterwards.
- Every KDF boundary (`KeyMaterial::new_from_password`, `existing`,
  `new_interactive`) zeroizes the passphrase string after derivation.
- `KeyMaterial` (the derived key) is zeroized on drop and its `Debug` output
  is redacted. `MasterKey`'s `Debug` is likewise redacted — before this
  change, `{:?}` on a wallet printed the master xpriv to logs.
- The passphrase is supplied via `-p`/`--PASSWORD` on every start. There is
  no environment-variable fallback and nothing is persisted: a restart
  always requires an operator to present the passphrase.

## Threat model

### What this defends against

- **Theft of the wallet file or backups** (disk, cloud sync, stolen server):
  everything is AES-256-GCM ciphertext with a strong KDF.
- **Reduced plaintext exposure in leaked memory**: the plaintext master
  key's in-memory lifetime shrinks from the whole process lifetime to
  milliseconds per signature, so incidental disclosures — swap/page files,
  hibernation images, cold-boot reads, accidental `Debug` logging — are far
  less likely to contain it. Note that a **core dump of the live process is
  still fatal**: it contains both the long-lived `KeyMaterial` and the
  sealed master-key blob, and the `KeyMaterial` unseals it (see the
  live-attacker limitation below). Sealing narrows the plaintext window; it
  does not protect against dumps that capture the `KeyMaterial`.
- **Accidental plaintext persistence**: the type system refuses to serialize
  a plaintext master key, and there is no code path that writes an
  unencrypted wallet file.

### What it does **not** defend against

- **A live attacker reading the process's memory.** A hot wallet must sign
  autonomously, so the passphrase-derived `KeyMaterial` stays in memory and
  can be used to unseal the master key. This is inherent to hot wallets;
  real mitigation requires signer isolation (a separate signing process) or
  a hardware signer, neither of which is implemented.
- **Per-swap secrets are not sealed yet.** `IncomingSwapCoin` /
  `OutgoingSwapCoin` hold `my_privkey`, `other_privkey` and `hash_preimage`
  in plaintext in memory for the lifetime of an active swap (they *are*
  encrypted at rest inside the wallet file). An in-memory reader during a
  swap can steal in-flight swap funds, though not the HD wallet itself.
  Sealing these is a planned follow-up.
- **Erasure is best-effort, not guaranteed.** `Xpriv` is `Copy`, so earlier
  copies may persist on the stack/in registers; `non_secure_erase` explicitly
  permits the compiler to leave copies; a panic inside a key closure skips
  the wipe; the extended key's `chain_code` is never erased (not
  fund-critical: all wallet derivation below the master key is hardened).
- **Passphrase theft** (keyloggers, phishing the prompt, reading the
  environment of the process) is out of scope — an attacker with the
  passphrase has the wallet.

## Operational notes

- **Mandatory passphrase**: `makerd`/`taker` require a wallet passphrase
  (`-p`/`--PASSWORD`) both to create a new wallet and to open an existing
  one. Running without one fails with a clear error, and a restart always
  requires an operator to supply it again.
- **No cleartext formats**: unencrypted wallet files and unencrypted backups
  are rejected, not migrated. The project is pre-launch, so no legacy
  plaintext compatibility path exists.
- **The BIP39 mnemonic** is shown once at wallet creation and is the ultimate
  backup — record it offline. It is kept in memory until the CLI displays it
  (`take_new_mnemonic`) and is not zeroized.
- **Test builds** (`cfg(test)` / the `integration-test` feature) reduce
  PBKDF2 to 1 iteration for speed. Never use such a build with real funds.
- **FFI**: `backup_wallet_gui_app` and `restore_wallet_gui_app` both require
  a password; `is_wallet_encrypted` reports whether a file is encrypted.

## File formats

Wallet file (CBOR, the only supported form):

```
EncryptedData {                       // outer: whole-store encryption
    nonce, pbkdf2_salt,
    encrypted_payload: WalletStore {
        ...
        master_key: EncryptedData {   // inner: individually sealed master key
            nonce, pbkdf2_salt,
            encrypted_payload: Xpriv
        },
        ...
    }
}
```

