//! In-memory registry for watch requests and fidelity bonds.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};

use crate::{
    lock_debug,
    watch_tower::{
        utils::{is_valid_maker_address, FidelityAnnouncement},
        watcher_error::WatcherError,
    },
};

/// Represents a UTXO being watched and records when it gets spent.
#[derive(Debug, Clone)]
pub struct WatchRequest {
    /// UTXO being watched.
    pub outpoint: OutPoint,
    /// `scriptPubKey` of the watched UTXO, used to arm the Electrum per-script
    /// subscription and to re-check a recorded spend against the chain.
    pub script_pubkey: ScriptBuf,
    /// Whether the spend was seen in a block (`true`) or only in the mempool.
    pub in_block: bool,
    /// Optional full transaction that spent the outpoint.
    pub spent_tx: Option<Transaction>,
}

/// Fidelity records used to discover Makers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fidelity {
    /// Transaction ID of the maker's fidelity bond.
    pub txid: Txid,
    /// Maker's advertised onion address.
    pub onion_address: String,
    /// Fidelity expiry height used later for pruning.
    pub expire_height: u32,
}

/// Nostr cursors and fidelity records are per-boot by design: the relays are the
/// source of truth and refill both at EOSE, so a stale copy would only make us
/// skip events we still need.
#[derive(Default)]
struct RegistryData {
    watches: HashMap<OutPoint, WatchRequest>,
    fidelity: HashSet<Fidelity>,
    nostr_cursors: HashMap<String, u64>,
}

/// Registry used by the watcher. Memory-only: watch state is rebuilt from the
/// wallet at startup, so a crash cannot leave a stale or corrupt copy behind.
#[derive(Clone, Default)]
pub struct FileRegistry {
    data: Arc<Mutex<RegistryData>>,
}

impl FileRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a watch request, replacing any entry the outpoint already has.
    pub fn upsert_watch(&mut self, req: &WatchRequest) -> Result<(), WatcherError> {
        self.with_data(
            |data| match data.watches.insert(req.outpoint, req.clone()) {
                #[cfg(debug_assertions)]
                None => log::debug!(
                    "[WATCH_STATE] Source: watch_tower::registry_storage::upsert_watch | Action: register | Outpoint: {} | ActiveWatches: {}",
                    req.outpoint,
                    data.watches.len()
                ),
                _ => {}
            },
        )?;
        Ok(())
    }

    /// Registers a watch, merging into any entry the outpoint already has.
    /// A re-registration must never wipe a recorded `spent_tx`: it carries the
    /// preimage, and no second notification ever arrives to record it again.
    pub fn register_watch(
        &mut self,
        outpoint: OutPoint,
        script_pubkey: ScriptBuf,
    ) -> Result<(), WatcherError> {
        self.with_data(|data| {
            let entry = data.watches.entry(outpoint).or_insert(WatchRequest {
                outpoint,
                script_pubkey: script_pubkey.clone(),
                in_block: false,
                spent_tx: None,
            });
            entry.script_pubkey = script_pubkey;
        })?;
        Ok(())
    }

    /// Removes the watch request for the given outpoint.
    pub fn remove_watch(&mut self, outpoint: OutPoint) -> Result<(), WatcherError> {
        self.with_data(|data| match data.watches.remove(&outpoint) {
            #[cfg(debug_assertions)]
            Some(_) => log::debug!(
                "[WATCH_STATE] Source: watch_tower::registry_storage::remove_watch | Action: unregister | Outpoint: {} | ActiveWatches: {}",
                outpoint,
                data.watches.len()
            ),
            _ => {}
        })?;
        Ok(())
    }

    /// Returns all current watch requests.
    pub fn list_watches(&self) -> Result<Vec<WatchRequest>, WatcherError> {
        self.with_data(|data| data.watches.values().cloned().collect())
    }

    /// Returns all stored maker fidelity records.
    pub fn list_fidelity(&self, height: u32) -> Result<HashSet<Fidelity>, WatcherError> {
        self.with_data(|data| {
            data.fidelity = data
                .fidelity
                .iter()
                .filter(|v| v.expire_height > height && is_valid_maker_address(&v.onion_address))
                .cloned()
                .collect();
            data.fidelity.clone()
        })
    }

    /// Inserts a new fidelity record.
    pub fn insert_fidelity(
        &self,
        txid: Txid,
        fidelity_announcement: FidelityAnnouncement,
    ) -> Result<bool, WatcherError> {
        if !is_valid_maker_address(&fidelity_announcement.onion) {
            log::warn!("Rejected fidelity record with invalid maker address");
            return Ok(false);
        }
        let fidelity = Fidelity {
            txid,
            onion_address: fidelity_announcement.onion,
            expire_height: fidelity_announcement.expires_at_height,
        };
        let is_in = self.with_data(|data| data.fidelity.insert(fidelity))?;
        Ok(is_in)
    }

    /// Removes fidelity records matching the given txid.
    pub fn remove_fidelity(&mut self, txid: Txid) -> Result<(), WatcherError> {
        self.with_data(|data| data.fidelity.retain(|f| f.txid != txid))?;
        Ok(())
    }

    /// Returns the latest processed Nostr event timestamp for a relay.
    pub fn load_nostr_cursor(&self, relay_url: &str) -> Result<Option<u64>, WatcherError> {
        let cursor = self.with_data(|data| data.nostr_cursors.get(relay_url).copied())?;
        log::debug!(
            "Nostr cursor load | relay={} | cursor={:?}",
            relay_url,
            cursor
        );
        Ok(cursor)
    }

    /// Records the latest processed Nostr event timestamp for a relay.
    pub fn save_nostr_cursor(
        &self,
        relay_url: &str,
        created_at_secs: u64,
    ) -> Result<(), WatcherError> {
        let (prev, next, updated) = self.with_data(|data| {
            let entry = data.nostr_cursors.entry(relay_url.to_string()).or_insert(0);
            let prev = *entry;
            if created_at_secs > *entry {
                *entry = created_at_secs;
            }
            let next = *entry;
            (prev, next, next != prev)
        })?;
        log::debug!(
            "Nostr cursor save | relay={} | incoming={} | previous={} | stored={} | advanced={}",
            relay_url,
            created_at_secs,
            prev,
            next,
            updated
        );
        Ok(())
    }

    fn with_data<F, T>(&self, f: F) -> Result<T, WatcherError>
    where
        F: FnOnce(&mut RegistryData) -> T,
    {
        let mut data = lock_debug!(self.data.lock())?;
        Ok(f(&mut data))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use bitcoin::{OutPoint, Txid};

    fn dummy_txid(_n: u8) -> Txid {
        Txid::from_str("a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7").unwrap()
    }

    fn dummy_outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: dummy_txid(n),
            vout: n as u32,
        }
    }

    fn maker_address(_label: char, _port: u16) -> String {
        #[cfg(not(feature = "integration-test"))]
        return "aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaea37ead.onion".to_string();
        #[cfg(feature = "integration-test")]
        return format!("127.0.0.1:{_port}");
    }

    #[test]
    fn test_watch_upsert_and_list() {
        let mut reg = FileRegistry::new();

        let outpoint = dummy_outpoint(1);
        reg.upsert_watch(&WatchRequest {
            outpoint,
            script_pubkey: ScriptBuf::new(),
            in_block: false,
            spent_tx: None,
        })
        .unwrap();

        let watches = reg.list_watches().unwrap();
        assert_eq!(watches.len(), 1);
        assert_eq!(watches[0].outpoint, outpoint);
        assert_eq!(watches[0].script_pubkey, ScriptBuf::new());
    }

    #[test]
    fn test_watch_remove() {
        let mut reg = FileRegistry::new();
        let outpoint = dummy_outpoint(2);

        reg.upsert_watch(&WatchRequest {
            outpoint,
            script_pubkey: ScriptBuf::new(),
            in_block: true,
            spent_tx: None,
        })
        .unwrap();
        reg.remove_watch(outpoint).unwrap();

        assert!(reg.list_watches().unwrap().is_empty());
    }

    #[test]
    fn test_register_watch_keeps_recorded_spend() {
        let mut reg = FileRegistry::new();
        let outpoint = dummy_outpoint(3);
        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };

        reg.register_watch(outpoint, ScriptBuf::new()).unwrap();
        // The watcher records the spend carrying the preimage.
        reg.upsert_watch(&WatchRequest {
            outpoint,
            script_pubkey: ScriptBuf::new(),
            in_block: true,
            spent_tx: Some(spending_tx.clone()),
        })
        .unwrap();

        reg.register_watch(outpoint, ScriptBuf::new()).unwrap();

        let watches = reg.list_watches().unwrap();
        assert_eq!(watches.len(), 1);
        assert_eq!(watches[0].spent_tx, Some(spending_tx));
        assert!(watches[0].in_block);
    }

    #[test]
    fn test_fidelity_insert_and_remove() {
        let mut reg = FileRegistry::new();

        let txid1 = dummy_txid(1);
        let txid2 = dummy_txid(2);

        let fidelity_announcement_1 = FidelityAnnouncement {
            onion: maker_address('a', 6102),
            expires_at_height: 212,
        };

        let fidelity_announcement_2 = FidelityAnnouncement {
            onion: maker_address('b', 6103),
            expires_at_height: 232,
        };

        reg.insert_fidelity(txid1, fidelity_announcement_1).unwrap();
        reg.insert_fidelity(txid2, fidelity_announcement_2).unwrap();

        let list = reg.list_fidelity(0).unwrap();
        assert_eq!(list.len(), 2);

        reg.remove_fidelity(txid1).unwrap();

        let list2 = reg.list_fidelity(0).unwrap();
        assert_eq!(list2.len(), 0);
    }

    #[test]
    fn test_fidelity_rejects_invalid_address() {
        let reg = FileRegistry::new();
        let inserted = reg
            .insert_fidelity(
                dummy_txid(1),
                FidelityAnnouncement {
                    onion: "<script>alert(1)</script>.onion".to_string(),
                    expires_at_height: 500,
                },
            )
            .unwrap();
        assert!(!inserted);
        assert!(reg.list_fidelity(0).unwrap().is_empty());

        reg.with_data(|data| {
            data.fidelity.insert(Fidelity {
                txid: dummy_txid(2),
                onion_address: "malformed.onion".to_string(),
                expire_height: 500,
            });
        })
        .unwrap();
        assert!(reg.list_fidelity(0).unwrap().is_empty());
    }

    #[test]
    fn test_nostr_cursor_only_moves_forward() {
        let reg = FileRegistry::new();
        let relay = "ws://localhost:7000";

        assert_eq!(reg.load_nostr_cursor(relay).unwrap(), None);

        reg.save_nostr_cursor(relay, 100).unwrap();
        assert_eq!(reg.load_nostr_cursor(relay).unwrap(), Some(100));

        // A reconnect mid-process must not rewind and replay old events.
        reg.save_nostr_cursor(relay, 99).unwrap();
        assert_eq!(reg.load_nostr_cursor(relay).unwrap(), Some(100));

        reg.save_nostr_cursor(relay, 101).unwrap();
        assert_eq!(reg.load_nostr_cursor(relay).unwrap(), Some(101));
    }
}
