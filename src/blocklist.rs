//! Persistent funding-source address blocklist.
//!
//! Funding transactions are screened by resolving each input's previous output
//! and comparing its script pubkey with the scripts derived from listed addresses.

use crate::{
    atomic_file::{read_json, write_json_atomically, FileLock},
    utill::parse_checked_address,
    wallet::{Wallet, WalletError},
};
use bitcoin::{Network, OutPoint, Script, ScriptBuf, Transaction};
use serde::{Deserialize, Serialize};
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
    #[serde(default)]
    entries: Vec<BlocklistEntry>,
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
        Self { address, label }
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

/// Index entries by script pubkey, skipping any that do not parse.
fn index_entries(
    entries: Vec<BlocklistEntry>,
    network: Network,
) -> HashMap<ScriptBuf, BlocklistEntry> {
    let mut indexed = HashMap::with_capacity(entries.len());

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
            }
        }
    }
    indexed
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
        let file = read_json::<BlocklistFile>(&path)?;

        Ok(Self {
            inner: index_entries(file.entries, network),
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

    fn read_current(&self) -> Result<HashMap<ScriptBuf, BlocklistEntry>, BlocklistError> {
        let file: BlocklistFile = read_json(&self.path)?;
        Ok(index_entries(file.entries, self.network))
    }

    fn commit(
        &mut self,
        _lock: &FileLock,
        entries: HashMap<ScriptBuf, BlocklistEntry>,
    ) -> Result<(), BlocklistError> {
        let file = BlocklistFile {
            entries: entries.values().cloned().collect(),
        };

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
        let mut current = self.read_current()?;
        let mut outcome = AddOutcome::default();

        for (entry, script) in entries.into_iter().zip(scripts) {
            match current.insert(script, entry) {
                Some(_) => outcome.updated += 1,
                None => outcome.added += 1,
            }
        }
        self.commit(&lock, current)?;
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
        let mut current = self.read_current()?;

        let removed = scripts
            .into_iter()
            .filter(|script| current.remove(script).is_some())
            .count();

        self.commit(&lock, current)?;
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

    fn test_address(secret_byte: u8, network: Network) -> Address {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        Address::p2tr(&secp, keypair.x_only_public_key().0, None, network)
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
}
