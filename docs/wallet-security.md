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
- The passphrase is supplied via `--password-file <path>` (or `-p`/`--PASSWORD`)
  on every start. Prefer the file: an argv password is visible to other users
  in `/proc/<pid>/cmdline`. The Docker setup passes its 0600 Compose secret
  this way. There is no environment-variable fallback and nothing is
  persisted: a restart always requires an operator to present the passphrase.

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
- **Erasure is best-effort, not guaranteed.** Copied keys, their chain
  codes and signing key pairs are wiped when they go out of scope, also on
  errors. But `Xpriv` is `Copy`, so earlier copies may persist on the
  stack/in registers, and `non_secure_erase` explicitly permits the compiler
  to leave copies. Library internals (key derivation, base58 decoding, AES)
  keep their own.
- **Passphrase theft** (keyloggers, phishing the prompt, reading the
  environment of the process) is out of scope — an attacker with the
  passphrase has the wallet.

## Operational notes

- **Mandatory passphrase**: `makerd`/`taker` require a wallet passphrase
  (`--password-file <path>` or `-p`/`--PASSWORD`) both to create a new wallet and to open an existing
  one. Running without one fails with a clear error, and a restart always
  requires an operator to supply it again.
- **No cleartext formats**: unencrypted wallet files and unencrypted backups
  are rejected, not migrated. The project is pre-launch, so no legacy
  plaintext compatibility path exists.
- **The BIP39 seed phrase** is sealed in the wallet file, in the same first
  write that creates it. Nothing prints it at creation. Until you confirm a
  backup, every start and CLI command warns "seed not backed up". Read it
  with `show-seed` (see "The seed phrase" below). It is a backup of your
  keys, not of your whole wallet state. See "What a restore brings back" below.
- **Test builds** (`cfg(test)` / the `integration-test` feature) reduce
  PBKDF2 to 1 iteration for speed. Never use such a build with real funds.
- **FFI**: `backup_wallet_gui_app`, `restore_wallet_gui_app` and the
  `Result`-returning `restore_wallet_from_backup_gui_app` and
  `restore_wallet_from_mnemonic_gui_app` all require a password; `is_wallet_encrypted` reports whether a file is encrypted.
  `get_wallet_mnemonic_gui_app`, `attach_wallet_mnemonic_gui_app` and
  `confirm_seed_backup_gui_app` are the GUI's seed calls. A GUI should force
  show-and-confirm right after it creates a wallet.

## The seed phrase

- **Stored sealed.** The phrase is kept as BIP39 entropy, encrypted under its
  own key from the wallet password: a second blob next to the sealed master
  key. Loading a wallet never opens it.
- **`show-seed`.** `taker show-seed` and `makerd show-seed` read the wallet
  file offline. No backend is needed, nothing syncs and the file is written
  only by the confirmation step below. The password comes from a hidden
  prompt, never from `-p` or `--password-file`. The command prints only when
  stdout is a terminal and
  refuses a pipe or a redirect. It then asks you to re-type a few random
  words before it records the backup as confirmed. Showing the words alone
  does not count. Only that last step writes, and only while nothing else has
  the wallet open: every open wallet (`makerd`, `taker`, the GUI or any
  library caller) holds a shared lock on `<wallet>.lock`, and the write takes
  the exclusive one on a fresh read of the file. A running process would
  otherwise overwrite the change with its older state. `attach-seed` is
  refused for the same reason.
- **The lock file.** Creating, loading or restoring a wallet creates an
  empty `<wallet>.lock` next to it. The one exception is
  `Wallet::open_offline`, the read-only open the seed commands use: it takes
  no lock, and only their write step takes the exclusive one. So the wallets
  directory must be writable and on a filesystem with file locks (some
  network mounts have none). Otherwise the wallet refuses to open and names the lock file: running without the lock would let a seed
  command overwrite a running wallet. Tools that list the wallets directory
  should skip `*.lock` files. Don't delete one while a process uses the wallet.
- **Docker.** The container prints no seed. Use `exec` to see the words:
  `docker exec -it openswap-makerd makerd -w <wallet> show-seed`, where
  `<wallet>` is your `BITCOIN_WALLET_NAME` (default `openswap-maker`). To
  record the confirmation or attach a phrase, run `./docker-setup show-seed`
  or `./docker-setup attach-seed`. The script stops the maker, runs the
  command with Docker's logging off, and starts the maker again. A plain
  `docker compose run` would copy every word into Docker's logs.
- **Per-call password (library).** `Wallet::get_wallet_mnemonic` takes the
  current wallet password on every call. A wrong or empty one fails. The
  phrase is opened just in time and nothing is cached. `take_new_mnemonic` is
  gone: nothing hands out the phrase at creation. Library callers show it
  with `get_wallet_mnemonic`, then call `confirm_seed_backup`.
- **Limits of wiping.** The words come back in a `Zeroizing<String>` that is
  wiped on drop. Copies outside Rust are not wiped: a GUI string, terminal
  scrollback, the clipboard, a screenshot, a core dump or swap. Dispose of
  them once the user has written the words down.
- **No RPC.** No maker RPC message carries the seed, so a stolen RPC cookie
  cannot read it.
- **`MnemonicUnavailable`.** A wallet with no stored phrase returns this
  error. That covers wallets made before this change, v0.2.3 wallets and
  wallets restored from a backup that has none. OpenSwap never generates a
  phrase for an existing key. Run `attach-seed` with the original phrase,
  keep an encrypted backup, or sweep the coins to a new wallet.
- **Attach.** `attach-seed` (and `attach_wallet_mnemonic`) accepts a phrase
  only if it derives the wallet's master key. It refuses a wrong phrase and
  never overwrites a stored one.
- **Backups.** A backup of a wallet with a stored phrase carries it inside
  the backup's own encryption. Making the backup needs the current wallet
  password. A restore seals the phrase again under the new wallet's password.
  Old backups still restore, with the phrase unavailable.

## Wallet file format version 2

Storing the phrase needs a new file format. Older builds ignore fields they
do not know, and would delete the sealed phrase on their next save. So the
wallet file now uses a version 2 container that older builds cannot parse.
They fail at load and never save.

- The new build reads version 1 and version 2 files and refuses a higher
  version. Loading never writes. The first save after a load writes version 2.
- **Downgrade is not supported.** Once a new build has saved a wallet, an
  older build refuses it. Keep an encrypted backup before you upgrade. To go
  back, restore that backup with the older build.
- A future password-change feature must re-encrypt the store and the sealed
  phrase in one atomic write.

## What a restore brings back

The seed phrase and the encrypted backup file both rebuild the wallet from
keys. A restore searches the chain for what those keys own.

**A restore finds:**

- Coins on addresses within the address gap (default 100 unused addresses in
  a row; set it with `--address-gap`) and after the birthday block.
- Fidelity bonds the maker announced, and bonds listed in a backup file.
  Bonds made without an announcement need `--bond-hint INDEX:LOCKTIME`.
  The restore checks each hint against the chain.

**A restore does not find:**

- Swaps still in progress, on either side. Their keys are random and live
  only in the wallet file.
- Pending refunds from failed swaps.
- Lightning swaps in progress. A restored wallet does not know about them.
- Swap reports and deniability proofs. Copy the `<wallet>_swap_report.json`
  file by hand.
- Tags on swept coins. A backup file carries them. A seed phrase does not.
- A BIP39 passphrase. OpenSwap has none, so a restore uses an empty one.

**Before you restore:**

1. Finish or refund every swap on the old wallet.
2. Stop every process that uses the old wallet.
3. Keep the old wallet files. Do not delete them.
4. Pick an early birthday block. A late one skips older coins.
5. Raise the address gap if you used more than 100 addresses in a row
   without receiving coins.

A restore refuses to overwrite an existing wallet file. Restore under a new
name or move the old file first.

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

