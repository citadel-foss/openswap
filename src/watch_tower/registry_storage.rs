//! In-memory registry for watch requests and fidelity bonds.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};

use crate::{
    lock_debug,
    watch_tower::{utils::FidelityAnnouncement, watcher_error::WatcherError},
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
    /// Creation time of the newest verified Nostr announcement for this bond.
    /// Chain-only discovery has no announcement timestamp.
    pub last_announcement_ts: Option<u64>,
}

/// Nostr cursors and fidelity records are per-boot by design: the relays are the
/// source of truth and refill both at EOSE, so a stale copy would only make us
/// skip events we still need.
#[derive(Default)]
struct RegistryData {
    watches: HashMap<OutPoint, WatchRequest>,
    fidelity: HashSet<Fidelity>,
    fidelity_announcement_ts: HashMap<Txid, u64>,
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
            data.fidelity
                .retain(|fidelity| fidelity.expire_height > height);
            let active_txids: HashSet<_> =
                data.fidelity.iter().map(|fidelity| fidelity.txid).collect();
            data.fidelity_announcement_ts
                .retain(|txid, _| active_txids.contains(txid));

            data.fidelity
                .iter()
                .cloned()
                .map(|mut fidelity| {
                    fidelity.last_announcement_ts =
                        data.fidelity_announcement_ts.get(&fidelity.txid).copied();
                    fidelity
                })
                .collect()
        })
    }

    /// Inserts a fidelity record learned directly from the chain.
    pub fn insert_fidelity(
        &self,
        txid: Txid,
        fidelity_announcement: FidelityAnnouncement,
    ) -> Result<bool, WatcherError> {
        self.insert_fidelity_inner(txid, fidelity_announcement, None)
    }

    /// Inserts a fidelity record from a verified Nostr event and records the
    /// event creation time used by offerbook stale-maker recovery.
    pub fn insert_fidelity_announcement(
        &self,
        txid: Txid,
        fidelity_announcement: FidelityAnnouncement,
        announced_at_ts: u64,
    ) -> Result<bool, WatcherError> {
        self.insert_fidelity_inner(txid, fidelity_announcement, Some(announced_at_ts))
    }

    fn insert_fidelity_inner(
        &self,
        txid: Txid,
        fidelity_announcement: FidelityAnnouncement,
        announced_at_ts: Option<u64>,
    ) -> Result<bool, WatcherError> {
        let fidelity = Fidelity {
            txid,
            onion_address: fidelity_announcement.onion,
            expire_height: fidelity_announcement.expires_at_height,
            last_announcement_ts: None,
        };
        let is_in = self.with_data(|data| {
            if let Some(timestamp) = announced_at_ts {
                let latest = data.fidelity_announcement_ts.entry(txid).or_default();
                *latest = (*latest).max(timestamp);
            }
            data.fidelity.insert(fidelity)
        })?;
        Ok(is_in)
    }

    /// Advances the announcement time for an already-verified fidelity record.
    /// Returns `false` when the txid is not present in the registry.
    pub fn touch_fidelity_announcement(
        &self,
        txid: Txid,
        announced_at_ts: u64,
    ) -> Result<bool, WatcherError> {
        self.with_data(|data| {
            let Some(latest) = data.fidelity_announcement_ts.get_mut(&txid) else {
                return false;
            };

            *latest = (*latest).max(announced_at_ts);
            true
        })
    }

    /// Removes fidelity records matching the given txid.
    pub fn remove_fidelity(&mut self, txid: Txid) -> Result<(), WatcherError> {
        self.with_data(|data| {
            data.fidelity.retain(|fidelity| fidelity.txid != txid);
            data.fidelity_announcement_ts.remove(&txid);
        })?;
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
            onion: "abc.onion".to_string(),
            expires_at_height: 212,
        };

        let fidelity_announcement_2 = FidelityAnnouncement {
            onion: "def.onion".to_string(),
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
    fn fidelity_announcement_timestamp_only_moves_forward() {
        let mut reg = FileRegistry::new();
        let txid = dummy_txid(1);
        let announcement = FidelityAnnouncement {
            onion: "abc.onion".to_string(),
            expires_at_height: 212,
        };

        assert!(reg
            .insert_fidelity_announcement(txid, announcement, 100)
            .unwrap());
        assert_eq!(
            reg.list_fidelity(0)
                .unwrap()
                .iter()
                .find(|fidelity| fidelity.txid == txid)
                .unwrap()
                .last_announcement_ts,
            Some(100)
        );

        assert!(reg.touch_fidelity_announcement(txid, 99).unwrap());
        assert!(reg.touch_fidelity_announcement(txid, 101).unwrap());
        assert_eq!(
            reg.list_fidelity(0)
                .unwrap()
                .iter()
                .find(|fidelity| fidelity.txid == txid)
                .unwrap()
                .last_announcement_ts,
            Some(101)
        );

        reg.remove_fidelity(txid).unwrap();
        assert!(!reg.touch_fidelity_announcement(txid, 102).unwrap());
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
