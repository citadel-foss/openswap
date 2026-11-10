//! Persistent funding-source address blocklist.
//!
//! Funding transactions are screened by resolving each input's previous output
//! and comparing its script pubkey with the scripts derived from listed addresses.

use crate::{
    atomic_file::{write_json_atomically, FileLock},
    protocol::features::{check_requires, supported},
    utill::parse_checked_address,
    wallet::{Wallet, WalletError},
};
use bitcoin::{Network, OutPoint, Script, ScriptBuf, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::HashMap,
    fmt, io,
    path::{Path, PathBuf},
};

const BLOCKLIST_FILE: &str = "blocklist.json";

/// Maximum number of funding inputs screened per transaction.
/// Each input's previous output is fetched from the node, so an unbounded
/// count on a counterparty-supplied transaction can take arbitrarily long.
const MAX_FUNDING_INPUTS: usize = 25;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// A Bitcoin address to reject as a funding source.
pub struct BlocklistEntry {
    /// Address string supplied when the entry was added.
    pub address: String,
    /// Optional note describing why the address is blocked.
    #[serde(default)]
    pub label: Option<String>,
    /// Fields a newer build wrote; kept so a rewrite does not drop them.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
/// Counts produced by an add operation.
pub struct AddOutcome {
    /// Number of addresses that were not previously present.
    pub added: usize,
    /// Number of existing addresses whose entries were replaced.
    pub updated: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BlocklistFile {
    /// Feature names a reader needs. A writer adds one when it stores an entry
    /// an older build would read more loosely, so that build refuses instead
    /// of blocking less.
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    entries: Vec<BlocklistEntry>,
    /// Top-level fields a newer build wrote; kept so a rewrite does not drop them.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// Only the names, read before any entry is decoded.
#[derive(Default, Deserialize)]
struct BlocklistHeader {
    #[serde(default)]
    requires: Vec<String>,
}

/// Reads the blocklist, refusing it when it needs a name this build can't serve.
fn read_blocklist(path: &Path) -> Result<BlocklistFile, BlocklistError> {
    if !path.exists() {
        return Ok(BlocklistFile::default());
    }
    // One read: the header check and the entries must see the same bytes.
    let content = std::fs::read_to_string(path)?;
    let header: BlocklistHeader = serde_json::from_str(&content).map_err(io::Error::other)?;
    check_requires(&header.requires, &supported()).map_err(|missing| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "blocklist {} needs a newer build: it uses {missing:?}",
                path.display()
            ),
        )
    })?;
    Ok(serde_json::from_str(&content).map_err(io::Error::other)?)
}

/// Errors produced while storing or applying the funding-source blocklist.
#[derive(Debug)]
pub enum BlocklistError {
    /// Reading, locking, or writing the blocklist file failed.
    IO(io::Error),
    /// One or more supplied addresses were malformed or for the wrong network.
    ///
    /// Each tuple contains the rejected address and its validation error.
    InvalidAddresses(Vec<(String, String)>),
    /// A funding transaction input's previous output could not be resolved.
    InputResolution(WalletError),
    /// A funding input spends an output associated with a listed address.
    BlockedAddress {
        /// Previous output spent by the rejected funding input.
        outpoint: OutPoint,
        /// Blocklist entry matching that previous output's script pubkey.
        entry: BlocklistEntry,
    },
}

impl fmt::Display for BlocklistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IO(error) => write!(f, "blocklist file error: {error}"),
            Self::InvalidAddresses(rejected) => {
                write!(f, "{} address rejected, nothing written", rejected.len())?;

                for (address, reason) in rejected {
                    write!(f, "\n {address} - {reason}")?;
                }

                Ok(())
            }
            Self::InputResolution(error) => {
                write!(f, "could not resolve funding transaction inputs: {error}")
            }
            Self::BlockedAddress { outpoint, entry } => {
                write!(
                    f,
                    "funding input {outpoint} uses blocked address {}",
                    entry.address
                )?;
                if let Some(label) = &entry.label {
                    write!(f, " ({label})")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for BlocklistError {}

impl From<io::Error> for BlocklistError {
    fn from(error: io::Error) -> Self {
        Self::IO(error)
    }
}

impl From<WalletError> for BlocklistError {
    fn from(error: WalletError) -> Self {
        Self::InputResolution(error)
    }
}

impl BlocklistEntry {
    /// Construct an address entry with an optional explanatory label.
    pub fn new(address: String, label: Option<String>) -> Self {
        Self {
            address,
            label,
            extra: Map::new(),
        }
    }
}

/// Resolve the shared blocklist path from a maker or taker data directory.
///
/// The file is placed in the data directory's parent so sibling maker and
/// taker directories use the same `blocklist.json` file.
pub fn blocklist_path(data_dir: &Path) -> PathBuf {
    data_dir.parent().unwrap_or(data_dir).join(BLOCKLIST_FILE)
}

/// Reject a funding transaction when any input comes from a listed address.
///
/// The current blocklist file is loaded for every call. If it is empty, this
/// returns without querying the blockchain backend. Otherwise, every input's
/// previous-output script is resolved through the wallet and checked.
pub fn screen_funding_tx(
    data_dir: &Path,
    network: Network,
    wallet: &Wallet,
    tx: &Transaction,
) -> Result<(), BlocklistError> {
    let blocklist = AddressBlocklist::load(data_dir, network)?;

    if blocklist.is_empty() {
        if blocklist.path().exists() {
            log::warn!(
                "Blocklist {} holds no entries usable on {network}, skipping funding screen",
                blocklist.path().display()
            );
        } else {
            log::debug!("No blocklist file, skipping funding screen");
        }
        return Ok(());
    }

    if tx.input.len() > MAX_FUNDING_INPUTS {
        return Err(BlocklistError::InputResolution(WalletError::General(
            format!(
                "funding transaction has {} inputs, limit is {MAX_FUNDING_INPUTS}",
                tx.input.len()
            ),
        )));
    }

    for (outpoint, script) in wallet.resolve_input_scripts(tx)? {
        if let Some(entry) = blocklist.matching(script.as_script()) {
            log::warn!(
                "Funding input {outpoint} uses blocked address {} (label: {:?})",
                entry.address,
                entry.label
            );
            return Err(BlocklistError::BlockedAddress {
                outpoint,
                entry: entry.clone(),
            });
        }
    }

    Ok(())
}

/// Index entries by script pubkey, returning the ones that do not parse apart.
///
/// The skipped entries may belong to another network sharing the file, so a
/// rewrite must keep them.
fn index_entries(
    entries: Vec<BlocklistEntry>,
    network: Network,
) -> (HashMap<ScriptBuf, BlocklistEntry>, Vec<BlocklistEntry>) {
    let mut indexed = HashMap::with_capacity(entries.len());
    let mut skipped = Vec::new();

    for entry in entries {
        match parse_checked_address(&entry.address, network) {
            Ok(address) => {
                if indexed
                    .insert(address.script_pubkey(), entry.clone())
                    .is_some()
                {
                    log::warn!(
                        "Blocklist lists {} more than once, keeping the last entry",
                        entry.address
                    );
                }
            }
            Err(error) => {
                log::warn!(
                    "Skipping unusable blocklist entry {}: {error}",
                    entry.address
                );
                skipped.push(entry);
            }
        }
    }
    (indexed, skipped)
}

/// In-memory script index backed by a shared JSON file.
pub struct AddressBlocklist {
    inner: HashMap<ScriptBuf, BlocklistEntry>,
    path: PathBuf,
    network: Network,
}

impl AddressBlocklist {
    /// Load the blocklist associated with `data_dir` for `network`.
    ///
    /// A missing file produces an empty blocklist. An unreadable or malformed
    /// file returns an error so enabled funding screening fails closed. Entries
    /// that cannot be parsed are skipped.
    pub fn load(data_dir: &Path, network: Network) -> Result<Self, BlocklistError> {
        let path = blocklist_path(data_dir);
        let file = read_blocklist(&path)?;
        let (inner, _) = index_entries(file.entries, network);

        Ok(Self {
            inner,
            path,
            network,
        })
    }

    fn validate_all<'a>(
        &self,
        addresses: impl Iterator<Item = &'a str>,
    ) -> Result<Vec<ScriptBuf>, BlocklistError> {
        let mut scripts = Vec::new();
        let mut rejected = Vec::new();

        for address in addresses {
            match parse_checked_address(address, self.network) {
                Ok(parsed) => scripts.push(parsed.script_pubkey()),
                Err(error) => rejected.push((address.to_string(), error.to_string())),
            }
        }

        if rejected.is_empty() {
            Ok(scripts)
        } else {
            Err(BlocklistError::InvalidAddresses(rejected))
        }
    }

    fn read_current(
        &self,
    ) -> Result<(BlocklistFile, HashMap<ScriptBuf, BlocklistEntry>), BlocklistError> {
        let mut file = read_blocklist(&self.path)?;
        let (entries, skipped) = index_entries(std::mem::take(&mut file.entries), self.network);
        // Entries this network can't parse stay in the file as they are.
        file.entries = skipped;
        Ok((file, entries))
    }

    fn commit(
        &mut self,
        _lock: &FileLock,
        mut file: BlocklistFile,
        entries: HashMap<ScriptBuf, BlocklistEntry>,
    ) -> Result<(), BlocklistError> {
        file.entries.extend(entries.values().cloned());

        write_json_atomically(&self.path, &file)?;
        self.inner = entries;
        Ok(())
    }

    /// Atomically add new entries or replace existing entries for the same scripts.
    ///
    /// All addresses are validated before the file is changed. The persisted
    /// file is re-read while holding its cross-process lock so another process's
    /// completed changes are preserved.
    pub fn add(&mut self, entries: Vec<BlocklistEntry>) -> Result<AddOutcome, BlocklistError> {
        let scripts = self.validate_all(entries.iter().map(|entry| entry.address.as_str()))?;

        let lock_path = self.path.with_extension("lock");
        let lock = FileLock::acquire(&lock_path)?;
        let (file, mut current) = self.read_current()?;
        let mut outcome = AddOutcome::default();

        for (mut entry, script) in entries.into_iter().zip(scripts) {
            match current.remove(&script) {
                // A relabel must not drop fields a newer build wrote.
                Some(old) => {
                    for (key, value) in old.extra {
                        entry.extra.entry(key).or_insert(value);
                    }
                    outcome.updated += 1;
                }
                None => outcome.added += 1,
            }
            current.insert(script, entry);
        }
        self.commit(&lock, file, current)?;
        Ok(outcome)
    }

    /// Atomically remove addresses and return the number of entries removed.
    ///
    /// All addresses are validated before the file is changed. Addresses not
    /// currently present do not contribute to the returned count.
    pub fn remove(&mut self, addresses: Vec<String>) -> Result<usize, BlocklistError> {
        let scripts = self.validate_all(addresses.iter().map(String::as_str))?;

        let lock_path = self.path.with_extension("lock");
        let lock = FileLock::acquire(&lock_path)?;
        let (file, mut current) = self.read_current()?;

        let removed = scripts
            .into_iter()
            .filter(|script| current.remove(script).is_some())
            .count();

        self.commit(&lock, file, current)?;
        Ok(removed)
    }

    /// Return the blocklist entry matching `script`, if one exists.
    pub fn matching(&self, script: &Script) -> Option<&BlocklistEntry> {
        self.inner.get(script)
    }

    /// Return whether the in-memory script index contains no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Return the path of the JSON file backing this blocklist.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        key::Keypair,
        secp256k1::{Secp256k1, SecretKey},
        Address,
    };
    use bitcoind::tempfile::tempdir;

    use super::*;
    use crate::atomic_file::read_json;
    #[cfg(unix)]
    use std::{fs::OpenOptions, io::Write, process::Command, thread};

    #[derive(Deserialize)]
    struct CompatV023Blocklist {
        entries: Vec<BlocklistEntry>,
    }

    #[cfg(unix)]
    #[test]
    fn compat_blocklist_header_and_entries_use_one_snapshot() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blocklist.json");
        assert!(Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success());
        let replacement = path.clone();
        // Opening the writer proves the first read holds the pipe. Replace
        // its pathname before releasing EOF, so any second read sees new bytes.
        let writer = thread::spawn(move || {
            let mut first = OpenOptions::new().write(true).open(&replacement).unwrap();
            std::fs::rename(&replacement, replacement.with_extension("first")).unwrap();
            std::fs::write(&replacement, br#"{"requires":["future-v1"],"entries":[]}"#).unwrap();
            first.write_all(br#"{"requires":[],"entries":[]}"#).unwrap();
        });
        let read = read_blocklist(&path);
        writer.join().unwrap();
        let file = read.unwrap();
        assert!(
            file.requires.is_empty(),
            "entry snapshot escaped its header check: {:?}",
            file.requires
        );
    }

    fn test_address(secret_byte: u8, network: Network) -> Address {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        Address::p2tr(&secp, keypair.x_only_public_key().0, None, network)
    }

    #[test]
    fn compat_blocklist_requirements_are_checked_before_entry_shapes() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("maker");
        let path = blocklist_path(&data_dir);
        for entries in ["true", "[{}]", "[\"future entry\"]"] {
            let raw = format!(r#"{{"requires":["future-v1"],"entries":{}}}"#, entries);
            std::fs::write(&path, &raw).unwrap();
            let error = AddressBlocklist::load(&data_dir, Network::Regtest)
                .err()
                .expect("unknown requirement must refuse");
            assert!(
                error.to_string().contains("needs a newer build"),
                "{}",
                error
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), raw);
        }
    }

    #[test]
    fn compat_blocklist_mutations_recheck_requirements_without_data_loss() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("maker");
        let address = test_address(1, Network::Regtest).to_string();
        let mut book = AddressBlocklist::load(&data_dir, Network::Regtest).unwrap();
        let entry = BlocklistEntry::new(address.clone(), Some("keep".into()));
        book.add(vec![entry.clone()]).unwrap();
        let raw = format!(
            r#"{{"requires":["future-v1"],"entries":[{}]}}"#,
            serde_json::to_string(&entry).unwrap()
        );
        std::fs::write(book.path(), &raw).unwrap();
        assert!(book
            .add(vec![entry.clone()])
            .unwrap_err()
            .to_string()
            .contains("needs a newer build"));
        assert!(book
            .remove(vec![address])
            .unwrap_err()
            .to_string()
            .contains("needs a newer build"));
        assert_eq!(std::fs::read_to_string(book.path()).unwrap(), raw);
        assert_eq!(book.inner.values().collect::<Vec<_>>(), [&entry]);
    }

    #[test]
    fn compat_blocklist_old_files_and_known_headers_survive_writes() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("maker");
        let path = blocklist_path(&data_dir);
        let entry = BlocklistEntry::new(
            test_address(1, Network::Regtest).to_string(),
            Some("old".into()),
        );
        let entries = vec![entry.clone()];
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({"entries": entries})).unwrap(),
        )
        .unwrap();
        let mut book = AddressBlocklist::load(&data_dir, Network::Regtest).unwrap();
        assert_eq!(book.inner.values().collect::<Vec<_>>(), [&entry]);
        let requires = vec!["taproot".to_string(), "legacy".into(), "taproot".into()];
        std::fs::write(
            &path,
            serde_json::to_vec(&BlocklistFile {
                requires: requires.clone(),
                entries,
                extra: Map::new(),
            })
            .unwrap(),
        )
        .unwrap();
        let added = BlocklistEntry::new(test_address(2, Network::Regtest).to_string(), None);
        book.add(vec![added.clone()]).unwrap();
        let saved: BlocklistFile = read_json(&path).unwrap();
        assert_eq!(saved.requires, requires);
        // v0.2.3 ignores the header and reads the same address list.
        let old: CompatV023Blocklist =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(old.entries.len(), 2);
        assert!(old.entries.contains(&entry));
        book.remove(vec![added.address]).unwrap();
        let saved: BlocklistFile = read_json(&path).unwrap();
        assert_eq!(saved.requires, requires);
        assert_eq!(saved.entries, [entry]);
    }

    #[test]
    fn add_update_remove_round_trip() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("maker");
        let address = test_address(1, Network::Regtest);
        let script = address.script_pubkey();
        let address = address.to_string();

        let mut blocklist = AddressBlocklist::load(&data_dir, Network::Regtest).unwrap();
        assert!(blocklist.is_empty());
        assert_eq!(
            blocklist
                .add(vec![BlocklistEntry::new(
                    address.clone(),
                    Some("first label".to_string()),
                )])
                .unwrap(),
            AddOutcome {
                added: 1,
                updated: 0,
            }
        );
        assert_eq!(
            blocklist
                .add(vec![BlocklistEntry::new(
                    address.clone(),
                    Some("updated label".to_string()),
                )])
                .unwrap(),
            AddOutcome {
                added: 0,
                updated: 1,
            }
        );

        let mut reloaded = AddressBlocklist::load(&data_dir, Network::Regtest).unwrap();
        assert_eq!(
            reloaded.matching(script.as_script()),
            Some(&BlocklistEntry::new(
                address.clone(),
                Some("updated label".to_string()),
            ))
        );

        assert_eq!(
            reloaded
                .remove(vec![test_address(2, Network::Regtest).to_string()])
                .unwrap(),
            0
        );
        assert_eq!(reloaded.remove(vec![address]).unwrap(), 1);
        assert!(AddressBlocklist::load(&data_dir, Network::Regtest)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn add_rejects_all_entries_when_any_address_is_invalid() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("taker");
        let mut blocklist = AddressBlocklist::load(&data_dir, Network::Regtest).unwrap();
        let valid = test_address(3, Network::Regtest).to_string();
        let wrong_network = test_address(4, Network::Bitcoin).to_string();

        let error = blocklist
            .add(vec![
                BlocklistEntry::new(valid, None),
                BlocklistEntry::new("not-an-address".to_string(), None),
                BlocklistEntry::new(wrong_network, None),
            ])
            .unwrap_err();

        match error {
            BlocklistError::InvalidAddresses(rejected) => assert_eq!(rejected.len(), 2),
            other => panic!("unexpected error: {}", other),
        }
        assert!(AddressBlocklist::load(&data_dir, Network::Regtest)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn concurrent_adds_preserve_every_entry() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("maker");
        let addresses: Vec<_> = (10..18)
            .map(|secret_byte| test_address(secret_byte, Network::Regtest))
            .collect();

        let handles: Vec<_> = addresses
            .iter()
            .map(ToString::to_string)
            .map(|address| {
                let data_dir = data_dir.clone();
                std::thread::spawn(move || {
                    AddressBlocklist::load(&data_dir, Network::Regtest)
                        .unwrap()
                        .add(vec![BlocklistEntry::new(address, None)])
                        .unwrap()
                })
            })
            .collect();

        for handle in handles {
            assert_eq!(
                handle.join().unwrap(),
                AddOutcome {
                    added: 1,
                    updated: 0,
                }
            );
        }

        let reloaded = AddressBlocklist::load(&data_dir, Network::Regtest).unwrap();
        for address in addresses {
            assert_eq!(
                reloaded.matching(address.script_pubkey().as_script()),
                Some(&BlocklistEntry::new(address.to_string(), None))
            );
        }
    }

    #[test]
    fn malformed_file_returns_error_instead_of_empty_blocklist() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("maker");
        let path = blocklist_path(&data_dir);
        std::fs::write(&path, "{not valid json").unwrap();

        match AddressBlocklist::load(&data_dir, Network::Regtest) {
            Err(BlocklistError::IO(_)) => {}
            Err(other) => panic!("unexpected error: {}", other),
            Ok(_) => panic!("malformed blocklist must not be treated as empty"),
        }
    }

    #[test]
    fn rewrites_keep_fields_this_build_does_not_know() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("taker");
        let path = blocklist_path(&data_dir);
        let kept = test_address(1, Network::Regtest).to_string();
        std::fs::write(
            &path,
            format!(r#"{{"future":7,"entries":[{{"address":"{kept}","note":"x"}}]}}"#),
        )
        .unwrap();
        let mut book = AddressBlocklist::load(&data_dir, Network::Regtest).unwrap();
        let added = BlocklistEntry::new(test_address(2, Network::Regtest).to_string(), None);
        book.add(vec![added.clone()]).unwrap();
        book.remove(vec![added.address]).unwrap();
        let saved: Value = read_json(&path).unwrap();
        assert_eq!(saved["future"], 7);
        assert_eq!(saved["entries"][0]["note"], "x");

        // Relabelling the same address keeps the unknown field too.
        book.add(vec![BlocklistEntry::new(kept, Some("new".into()))])
            .unwrap();
        let saved: Value = read_json(&path).unwrap();
        assert_eq!(saved["entries"][0]["label"], "new");
        assert_eq!(saved["entries"][0]["note"], "x");
    }

    #[test]
    fn rewrites_keep_entries_for_other_networks() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("taker");
        let path = blocklist_path(&data_dir);
        let mainnet = test_address(1, Network::Bitcoin);
        let mainnet_entry = BlocklistEntry::new(mainnet.to_string(), Some("listed".into()));
        let malformed = BlocklistEntry::new("not-an-address".to_string(), None);
        let entries = vec![mainnet_entry.clone(), malformed.clone()];
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({"entries": entries})).unwrap(),
        )
        .unwrap();

        // A regtest node sharing the file can't use either entry.
        let mut book = AddressBlocklist::load(&data_dir, Network::Regtest).unwrap();
        assert!(book.is_empty());
        let added = BlocklistEntry::new(test_address(2, Network::Regtest).to_string(), None);
        book.add(vec![added.clone()]).unwrap();
        let saved: BlocklistFile = read_json(&path).unwrap();
        assert_eq!(
            saved.entries,
            [mainnet_entry.clone(), malformed.clone(), added.clone()]
        );

        book.remove(vec![added.address]).unwrap();
        let saved: BlocklistFile = read_json(&path).unwrap();
        assert_eq!(saved.entries, [mainnet_entry.clone(), malformed]);

        // The mainnet node still blocks its address.
        let mainnet_book = AddressBlocklist::load(&data_dir, Network::Bitcoin).unwrap();
        assert_eq!(
            mainnet_book.matching(mainnet.script_pubkey().as_script()),
            Some(&mainnet_entry)
        );
    }

    #[test]
    fn unserved_requires_refuse_before_entries_and_writes() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("maker");
        let path = blocklist_path(&data_dir);
        // The entry shape is newer too; the header alone must decide.
        let raw = r#"{"requires":["future-v1"],"entries":[{"future":true}]}"#;
        std::fs::write(&path, raw).unwrap();

        assert!(AddressBlocklist::load(&data_dir, Network::Regtest).is_err());

        let mut blocklist = AddressBlocklist {
            inner: HashMap::new(),
            path: path.clone(),
            network: Network::Regtest,
        };
        let entry = BlocklistEntry::new(test_address(1, Network::Regtest).to_string(), None);
        assert!(blocklist.add(vec![entry]).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), raw);
    }
}
