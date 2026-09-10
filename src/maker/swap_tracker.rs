//! Persistent swap tracker for maker recovery progress.
//!
//! Stores maker swap state to `{data_dir}/maker_swap_tracker.cbor` using
//! atomic writes (write-to-tmp then rename). This lets the Maker track
//! recovery progress across restarts.
#![allow(missing_docs)]

use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use bitcoin::Txid;
use serde::{Deserialize, Serialize};

use crate::protocol::common_messages::ProtocolVersion;

use super::error::MakerError;

/// Maker swap lifecycle phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum MakerSwapPhase {
    #[default]
    Active,
    TakerDropped,
    Recovering,
    Recovered,
    Completed,
}

impl fmt::Display for MakerSwapPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MakerSwapPhase::Active => write!(f, "Active"),
            MakerSwapPhase::TakerDropped => write!(f, "TakerDropped"),
            MakerSwapPhase::Recovering => write!(f, "Recovering"),
            MakerSwapPhase::Recovered => write!(f, "Recovered"),
            MakerSwapPhase::Completed => write!(f, "Completed"),
        }
    }
}

/// Maker recovery progress within a swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum MakerRecoveryPhase {
    #[default]
    NotStarted,
    Monitoring,
    HashlockRecovered,
    TimelockWaiting,
    TimelockRecovered,
    CleanedUp,
}

impl fmt::Display for MakerRecoveryPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MakerRecoveryPhase::NotStarted => write!(f, "NotStarted"),
            MakerRecoveryPhase::Monitoring => write!(f, "Monitoring"),
            MakerRecoveryPhase::HashlockRecovered => write!(f, "HashlockRecovered"),
            MakerRecoveryPhase::TimelockWaiting => write!(f, "TimelockWaiting"),
            MakerRecoveryPhase::TimelockRecovered => write!(f, "TimelockRecovered"),
            MakerRecoveryPhase::CleanedUp => write!(f, "CleanedUp"),
        }
    }
}

/// Truncate each txid to its first 8 hex characters for compact display.
fn short_txids(txids: &[Txid]) -> Vec<String> {
    txids
        .iter()
        .map(|txid| {
            let s = txid.to_string();
            s[..8.min(s.len())].to_string()
        })
        .collect()
}

/// Per-swap recovery state tracking.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MakerRecoveryState {
    pub phase: MakerRecoveryPhase,
    pub incoming_swept: Vec<Txid>,
    pub outgoing_recovered: Vec<Txid>,
    pub outgoing_discarded: Vec<Txid>,
}

impl fmt::Display for MakerRecoveryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "phase={}", self.phase)?;
        if !self.incoming_swept.is_empty() {
            write!(f, " in_swept={:?}", short_txids(&self.incoming_swept))?;
        }
        if !self.outgoing_recovered.is_empty() {
            write!(
                f,
                " out_recovered={:?}",
                short_txids(&self.outgoing_recovered)
            )?;
        }
        if !self.outgoing_discarded.is_empty() {
            write!(
                f,
                " out_discarded={:?}",
                short_txids(&self.outgoing_discarded)
            )?;
        }
        Ok(())
    }
}

/// A persistent record of a single maker swap's state and progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakerSwapRecord {
    pub swap_id: String,
    pub protocol: ProtocolVersion,
    pub phase: MakerSwapPhase,
    pub swap_amount_sat: u64,
    pub incoming_count: usize,
    pub outgoing_count: usize,
    /// Funding txids broadcast so far, one per tx as the batch progresses.
    /// Empty means nothing is on-chain and recovery material can be discarded.
    #[serde(default)]
    pub funding_broadcast_txids: Vec<Txid>,
    pub recovery: MakerRecoveryState,
    pub created_at: u64,
    pub updated_at: u64,
}

impl fmt::Display for MakerSwapRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] phase={} proto={:?} amt={} in={} out={} funded={:?}",
            self.swap_id,
            self.phase,
            self.protocol,
            self.swap_amount_sat,
            self.incoming_count,
            self.outgoing_count,
            short_txids(&self.funding_broadcast_txids),
        )?;
        write!(f, "\n  recovery: {}", self.recovery)?;
        Ok(())
    }
}

/// Internal storage format for the tracker.
#[derive(Serialize, Deserialize, Default)]
struct MakerSwapTrackerData {
    swaps: HashMap<String, MakerSwapRecord>,
}

/// Persistent maker swap tracker backed by a CBOR file with atomic writes.
pub struct MakerSwapTracker {
    path: PathBuf,
    data: MakerSwapTrackerData,
}

impl MakerSwapTracker {
    /// Load tracker from disk or create a new empty one.
    pub fn load_or_create(data_dir: &Path) -> Result<Self, MakerError> {
        let path = data_dir.join("maker_swap_tracker.cbor");
        let data = if path.exists() {
            match std::fs::read(&path) {
                Ok(bytes) => serde_cbor::from_slice(&bytes).unwrap_or_default(),
                Err(e) => {
                    log::warn!("Failed to read maker swap tracker at {:?}: {}", path, e);
                    MakerSwapTrackerData::default()
                }
            }
        } else {
            MakerSwapTrackerData::default()
        };

        #[cfg(debug_assertions)]
        log::debug!(
            "[SWAP_TRACKER] Source: maker::swap_tracker::load_or_create | Role: Maker | Action: load | Records: {} | Incomplete: {}",
            data.swaps.len(),
            data.swaps
                .values()
                .filter(|r| {
                    !matches!(
                        r.phase,
                        MakerSwapPhase::Recovered | MakerSwapPhase::Completed
                    ) || r.recovery.phase < MakerRecoveryPhase::CleanedUp
                })
                .count()
        );

        Ok(Self { path, data })
    }

    /// Atomic flush: write to tmp file, then rename over original.
    fn flush(&self) -> Result<(), MakerError> {
        let tmp_path = self.path.with_extension("cbor.tmp");

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let bytes = serde_cbor::to_vec(&self.data).map_err(|e| {
            MakerError::IO(std::io::Error::other(format!(
                "Failed to serialize maker swap tracker: {}",
                e
            )))
        })?;

        std::fs::write(&tmp_path, &bytes)?;
        std::fs::rename(&tmp_path, &self.path)?;

        Ok(())
    }

    /// Upsert a swap record and flush to disk.
    pub fn save_record(&mut self, record: &MakerSwapRecord) -> Result<(), MakerError> {
        #[cfg(debug_assertions)]
        if self.data.swaps.get(&record.swap_id).is_none_or(|old| {
            old.phase != record.phase
                || old.recovery.phase != record.recovery.phase
                || old.funding_broadcast_txids != record.funding_broadcast_txids
        }) {
            log::debug!(
                "[SWAP_TRACKER] Source: maker::swap_tracker::save_record | Role: Maker | SwapID: {} | Phase: {} | Recovery: {} | FundingBroadcastTxids: {:?} | Incoming: {} | Outgoing: {}",
                record.swap_id,
                record.phase,
                record.recovery.phase,
                short_txids(&record.funding_broadcast_txids),
                record.incoming_count,
                record.outgoing_count
            );
        }
        self.data
            .swaps
            .insert(record.swap_id.clone(), record.clone());
        self.flush()
    }

    /// Get a reference to a swap record by ID.
    pub fn get_record(&self, swap_id: &str) -> Option<&MakerSwapRecord> {
        self.data.swaps.get(swap_id)
    }

    /// Get a mutable reference to a swap record by ID.
    pub fn get_record_mut(&mut self, swap_id: &str) -> Option<&mut MakerSwapRecord> {
        self.data.swaps.get_mut(swap_id)
    }

    /// Returns all swap records not yet fully resolved.
    ///
    /// Includes records where phase is not `Recovered`/`Completed` or
    /// recovery phase has not reached `CleanedUp`.
    pub fn incomplete_swaps(&self) -> Vec<&MakerSwapRecord> {
        self.data
            .swaps
            .values()
            .filter(|r| {
                !matches!(
                    r.phase,
                    MakerSwapPhase::Recovered | MakerSwapPhase::Completed
                ) || r.recovery.phase < MakerRecoveryPhase::CleanedUp
            })
            .collect()
    }

    /// Log all swap records at INFO level.
    pub fn log_state(&self) {
        if self.data.swaps.is_empty() {
            log::info!("[MakerSwapTracker] (empty — no records)");
            return;
        }
        for record in self.data.swaps.values() {
            for line in format!("{}", record).lines() {
                log::info!("[MakerSwapTracker] {}", line);
            }
        }
    }
}

impl fmt::Display for MakerSwapTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.data.swaps.is_empty() {
            return write!(f, "[MakerSwapTracker] (empty)");
        }
        for (i, record) in self.data.swaps.values().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "[MakerSwapTracker] {}", record)?;
        }
        Ok(())
    }
}

/// Current time as seconds since UNIX epoch.
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoind::tempfile::TempDir;

    fn make_test_record(swap_id: &str, phase: MakerSwapPhase) -> MakerSwapRecord {
        MakerSwapRecord {
            swap_id: swap_id.to_string(),
            protocol: ProtocolVersion::Legacy,
            phase,
            swap_amount_sat: 100_000,
            incoming_count: 2,
            outgoing_count: 2,
            funding_broadcast_txids: Vec::new(),
            recovery: MakerRecoveryState::default(),
            created_at: now_secs(),
            updated_at: now_secs(),
        }
    }

    #[test]
    fn test_load_or_create_empty() {
        let dir = TempDir::new().unwrap();
        let tracker = MakerSwapTracker::load_or_create(dir.path()).unwrap();
        assert!(tracker.incomplete_swaps().is_empty());
    }

    #[test]
    fn test_save_and_reload() {
        let dir = TempDir::new().unwrap();

        {
            let mut tracker = MakerSwapTracker::load_or_create(dir.path()).unwrap();
            let record = make_test_record("swap1", MakerSwapPhase::Recovering);
            tracker.save_record(&record).unwrap();
        }

        let tracker = MakerSwapTracker::load_or_create(dir.path()).unwrap();
        let incomplete = tracker.incomplete_swaps();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].swap_id, "swap1");
        assert_eq!(incomplete[0].phase, MakerSwapPhase::Recovering);
    }

    #[test]
    fn test_recovered_with_cleanup_not_in_incomplete() {
        let dir = TempDir::new().unwrap();
        let mut tracker = MakerSwapTracker::load_or_create(dir.path()).unwrap();

        let mut record = make_test_record("swap1", MakerSwapPhase::Recovered);
        record.recovery.phase = MakerRecoveryPhase::CleanedUp;
        tracker.save_record(&record).unwrap();
        assert!(tracker.incomplete_swaps().is_empty());
    }

    #[test]
    fn test_recovered_without_cleanup_in_incomplete() {
        let dir = TempDir::new().unwrap();
        let mut tracker = MakerSwapTracker::load_or_create(dir.path()).unwrap();

        let mut record = make_test_record("swap1", MakerSwapPhase::Recovered);
        record.recovery.phase = MakerRecoveryPhase::HashlockRecovered;
        tracker.save_record(&record).unwrap();
        assert_eq!(tracker.incomplete_swaps().len(), 1);
    }

    #[test]
    fn test_phase_ordering() {
        assert!(MakerSwapPhase::Active < MakerSwapPhase::TakerDropped);
        assert!(MakerSwapPhase::TakerDropped < MakerSwapPhase::Recovering);
        assert!(MakerSwapPhase::Recovering < MakerSwapPhase::Recovered);
        assert!(MakerSwapPhase::Recovered < MakerSwapPhase::Completed);
    }

    #[test]
    fn test_recovery_phase_ordering() {
        assert!(MakerRecoveryPhase::NotStarted < MakerRecoveryPhase::Monitoring);
        assert!(MakerRecoveryPhase::Monitoring < MakerRecoveryPhase::HashlockRecovered);
        assert!(MakerRecoveryPhase::HashlockRecovered < MakerRecoveryPhase::TimelockWaiting);
        assert!(MakerRecoveryPhase::TimelockWaiting < MakerRecoveryPhase::TimelockRecovered);
        assert!(MakerRecoveryPhase::TimelockRecovered < MakerRecoveryPhase::CleanedUp);
    }

    #[test]
    fn test_atomic_write_creates_no_tmp_on_success() {
        let dir = TempDir::new().unwrap();
        let mut tracker = MakerSwapTracker::load_or_create(dir.path()).unwrap();

        let record = make_test_record("swap1", MakerSwapPhase::Active);
        tracker.save_record(&record).unwrap();

        let tmp_path = dir.path().join("maker_swap_tracker.cbor.tmp");
        assert!(
            !tmp_path.exists(),
            "tmp file should be removed after rename"
        );
    }
}
