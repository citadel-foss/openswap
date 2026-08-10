//! Download, process and store Maker offers from the directory-server.
//!
//! It defines structures like [`OfferAndAddress`] and [`MakerAddress`] for representing maker offers and addresses.
//! The [`OfferBook`] struct keeps track of good and bad makers, and it provides methods for managing offers.
//! The module handles the syncing of the offer book with addresses obtained from directory servers and local configurations.
//! It uses asynchronous channels for concurrent processing of maker offers.

use std::{
    convert::TryFrom,
    fmt,
    io::BufWriter,
    net::TcpStream,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex, RwLock,
    },
    thread::{sleep, Builder, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bitcoin::{OutPoint, Txid};
use serde::{Deserialize, Serialize};

use crate::{
    lock_debug,
    protocol::{
        common_messages::{
            FidelityProof, GetOffer as RouterGetOffer,
            MakerToTakerMessage as RouterMakerToTakerMessage, Offer,
            TakerHello as RouterTakerHello, TakerToMakerMessage as RouterTakerToMakerMessage,
        },
        error::ProtocolError,
    },
    utill::{read_message, send_message},
    wallet::{verify_fidelity_checks, AnyBlockchain, Blockchain, WalletError},
    watch_tower::registry_storage::FileRegistry,
};

#[cfg(not(feature = "integration-test"))]
use crate::utill::socks5_connect;

/// Maximum number of attempts to connect to a maker.
const FIRST_CONNECT_ATTEMPTS: u32 = 3;
/// Timeout in seconds for each connection attempt.
const FIRST_CONNECT_ATTEMPT_TIMEOUT_SEC: u64 = 30;
/// Sleep delay in milliseconds between connection retry attempts.
const FIRST_CONNECT_SLEEP_DELAY_SEC: u64 = 1000;

use super::error::TakerError;

enum SyncCommand {
    SyncNow(mpsc::Sender<()>),
    PollMaker {
        address: MakerAddress,
        done: mpsc::Sender<Option<MakerOfferCandidate>>,
    },
}

#[cfg(not(feature = "integration-test"))]
const OFFER_SYNC_INTERVAL: Duration = Duration::from_secs(10 * 60);

#[cfg(feature = "integration-test")]
const OFFER_SYNC_INTERVAL: Duration = Duration::from_secs(10);

#[cfg(not(feature = "integration-test"))]
const OFFER_MAX_AGE_BEFORE_REFRESH: Duration = Duration::from_secs(30 * 60);

#[cfg(feature = "integration-test")]
const OFFER_MAX_AGE_BEFORE_REFRESH: Duration = Duration::from_secs(10);

#[cfg(not(feature = "integration-test"))]
const UNRESPONSIVE_MAKER_BACKOFF_STEP: Duration = Duration::from_secs(30 * 60);

#[cfg(feature = "integration-test")]
const UNRESPONSIVE_MAKER_BACKOFF_STEP: Duration = Duration::from_secs(10);

#[cfg(not(feature = "integration-test"))]
const DISCOVERY_WAIT_MAX: Duration = Duration::from_secs(150);

#[cfg(feature = "integration-test")]
const DISCOVERY_WAIT_MAX: Duration = Duration::from_secs(10);

const OFFER_SYNC_WAIT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Represents an offer along with the corresponding maker address.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OfferAndAddress {
    /// Details for Maker Offer
    pub offer: Offer,
    /// Maker address (hostname)
    pub address: MakerAddress,
    /// Current state of maker
    pub state: MakerState,
    /// Supporting protocol (Legacy or Taproot)
    pub protocol: MakerProtocol,
}

/// Canonical maker record.
/// A maker may or may not currently have an offer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MakerOfferCandidate {
    /// Maker address (hostname)
    pub address: MakerAddress,

    /// Fidelity bond outpoint (txid from registry, vout is always 0).
    pub fidelity_outpoint: Option<OutPoint>,

    /// Latest offer, if successfully fetched
    pub offer: Option<Offer>,

    /// Current state of maker
    pub state: MakerState,

    /// Supporting protocol (Legacy or Taproot), if known
    pub protocol: Option<MakerProtocol>,

    /// Timestamp(secs) of last successful offer download, used to avoid re-downloading offers too frequently.
    pub last_offer_update_ts: Option<u64>,

    /// Timestamp (secs) after which we will attempt the next offer download, used to back off to makers that are repeatedly unresponsive.
    pub next_offer_check_ts: Option<u64>,
}

impl MakerOfferCandidate {
    fn mark_success(&mut self, offer: Offer, protocol: MakerProtocol, now_ts: u64) {
        #[cfg(debug_assertions)]
        if self.state != MakerState::Good {
            log::debug!(
                "[MAKER_STATE] Source: taker::offers::MakerOfferCandidate::mark_success | Address: {} | State: {:?} -> Good",
                self.address,
                self.state
            );
        }
        self.fidelity_outpoint = Some(offer.fidelity.bond.outpoint());
        self.offer = Some(offer);
        self.protocol = Some(protocol);
        self.last_offer_update_ts = Some(now_ts);
        self.next_offer_check_ts = None;
        self.state = MakerState::Good;
    }

    fn mark_failure(&mut self, now_ts: u64) {
        let step_secs = UNRESPONSIVE_MAKER_BACKOFF_STEP.as_secs();
        let base = self.next_offer_check_ts.unwrap_or(now_ts).max(now_ts);
        self.next_offer_check_ts = Some(base.saturating_add(step_secs));

        let previous_state = self.state.clone();
        self.state = match &previous_state {
            MakerState::Good => MakerState::Unresponsive { retries: 1 },
            MakerState::Unresponsive { retries } if *retries < 10 => MakerState::Unresponsive {
                retries: *retries + 1,
            },
            MakerState::Unresponsive { .. } => MakerState::Bad,
            MakerState::Bad => MakerState::Bad,
        };
        #[cfg(debug_assertions)]
        if previous_state != self.state {
            log::debug!(
                "[MAKER_STATE] Source: taker::offers::MakerOfferCandidate::mark_failure | Address: {} | State: {:?} -> {:?} | NextCheck: {:?}",
                self.address,
                previous_state,
                self.state,
                self.next_offer_check_ts
            );
        }
    }

    fn as_offer_and_address(&self) -> Option<OfferAndAddress> {
        match (&self.offer, &self.protocol) {
            (Some(offer), Some(protocol)) => Some(OfferAndAddress {
                offer: offer.clone(),
                address: self.address.clone(),
                state: self.state.clone(),
                protocol: protocol.clone(),
            }),
            _ => None,
        }
    }
}

/// Represents the Maker connection state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MakerState {
    /// Maker is responding to offer calls.
    Good,
    /// Maker is not responding to offer calls.
    Unresponsive {
        /// We allow only 10 retries before marking
        /// a maker as bad.
        retries: u8,
    },
    /// Maker either explicitly or because not responding
    /// is marked bad.
    Bad,
}

/// Protocol which maker follows
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MakerProtocol {
    /// Legacy
    Legacy,
    /// Taproot
    Taproot,
    /// Unified - supports both Legacy and Taproot
    Unified,
}

impl MakerProtocol {
    /// Check if this protocol supports the requested protocol.
    /// Makers support both Legacy and Taproot.
    pub fn supports(&self, requested: &MakerProtocol) -> bool {
        match self {
            MakerProtocol::Unified => true, // Unified supports both
            MakerProtocol::Legacy => *requested == MakerProtocol::Legacy,
            MakerProtocol::Taproot => *requested == MakerProtocol::Taproot,
        }
    }
}

impl fmt::Display for MakerProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MakerProtocol::Legacy => f.write_str("Legacy"),
            MakerProtocol::Taproot => f.write_str("Taproot"),
            MakerProtocol::Unified => f.write_str("Unified"),
        }
    }
}

/// Maker address: just the hostname (e.g. `"xyz.onion"`).
/// In integration tests (clearnet), this is `"ip:port"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct MakerAddress(String);

impl fmt::Display for MakerAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&mut TcpStream> for MakerAddress {
    type Error = std::io::Error;
    fn try_from(value: &mut TcpStream) -> Result<Self, Self::Error> {
        let socket_addr = value.peer_addr()?;
        Ok(MakerAddress(format!(
            "{}:{}",
            socket_addr.ip(),
            socket_addr.port()
        )))
    }
}

/// OfferBookHandle, api interface to interact with
/// offerbook
#[derive(Clone)]
pub struct OfferBookHandle {
    pub(crate) inner: Arc<RwLock<OfferBook>>,
    path: PathBuf,
    is_syncing: Arc<AtomicBool>,
    last_sync_ts: Arc<AtomicU64>,
}

impl OfferBookHandle {
    /// Returns true if the offerbook sync is currently running.
    pub fn is_syncing(&self) -> bool {
        self.is_syncing.load(Ordering::Relaxed)
    }

    /// Returns the timestamp (unix secs) of the last completed sync, or 0 if never synced.
    pub fn last_sync_ts(&self) -> u64 {
        self.last_sync_ts.load(Ordering::Relaxed)
    }

    /// Gets the current snapshot of whole offerbook
    pub fn snapshot(&self) -> Result<OfferBook, TakerError> {
        Ok(lock_debug!(self.inner.read())
            .map_err(|_| TakerError::General("offerbook lock poisoned".into()))?
            .clone())
    }

    /// Tag a maker as bad
    pub fn add_bad_maker(&self, maker: &OfferAndAddress) -> Result<(), TakerError> {
        log::info!("Bad Maker added: {}", maker.address);
        lock_debug!(self.inner.write())
            .map_err(|_| TakerError::General("offerbook lock poisoned".into()))?
            .mark_bad(&maker.address);
        Ok(())
    }

    /// All current good makers
    pub fn active_makers(
        &self,
        protocol: &MakerProtocol,
    ) -> Result<Vec<OfferAndAddress>, TakerError> {
        Ok(lock_debug!(self.inner.read())
            .map_err(|_| TakerError::General("offerbook lock poisoned".into()))?
            .active_makers(protocol))
    }

    /// Fetch all good makers
    pub fn good_makers(&self) -> Result<Vec<OfferAndAddress>, TakerError> {
        Ok(lock_debug!(self.inner.read())
            .map_err(|_| TakerError::General("offerbook lock poisoned".into()))?
            .good_makers())
    }

    /// All bad makers
    pub fn get_bad_makers(
        &self,
        protocol: &MakerProtocol,
    ) -> Result<Vec<OfferAndAddress>, TakerError> {
        Ok(lock_debug!(self.inner.read())
            .map_err(|_| TakerError::General("offerbook lock poisoned".into()))?
            .get_bad_makers(protocol))
    }

    /// Fetch all makers good, bad, and unresponsive
    pub fn all_makers(&self) -> Result<Vec<MakerOfferCandidate>, TakerError> {
        Ok(lock_debug!(self.inner.read())
            .map_err(|_| TakerError::General("offerbook lock poisoned".into()))?
            .all_makers())
    }

    /// Checks if an address is bad or not
    pub fn is_bad_maker(&self, offer_and_address: &OfferAndAddress) -> Result<bool, TakerError> {
        let offerbook = lock_debug!(self.inner.read())
            .map_err(|_| TakerError::General("offerbook lock poisoned".into()))?;
        let value = offerbook
            .makers
            .iter()
            .find(|offer| offer.address == offer_and_address.address);

        if let Some(offer) = value {
            return Ok(offer.state == MakerState::Bad);
        }
        Ok(true)
    }

    /// Persist offerbook on disk
    pub fn persist(&self) -> Result<(), TakerError> {
        lock_debug!(self.inner.read())
            .map_err(|_| TakerError::General("offerbook lock poisoned".into()))?
            .write_to_disk(&self.path)
    }

    /// Remove a maker from the offerbook by address.
    /// Returns `true` if an entry was removed, `false` if no matching address was found.
    pub fn remove(&self, address: &MakerAddress) -> Result<bool, TakerError> {
        let mut book = lock_debug!(self.inner.write())
            .map_err(|_| TakerError::General("offerbook lock poisoned".into()))?;
        let before = book.makers.len();
        book.makers.retain(|m| &m.address != address);
        let removed = book.makers.len() < before;
        if removed {
            book.write_to_disk(&self.path)?;
        }
        Ok(removed)
    }

    /// Create or load offerbook on disk
    pub fn load_or_create(data_dir: &Path) -> Result<Self, TakerError> {
        let path = data_dir.join("offerbook.json");

        let offerbook = if path.exists() {
            match OfferBook::read_from_disk(&path) {
                Ok(book) => {
                    log::info!("Successfully loaded offerbook at {path:?}");
                    book
                }
                Err(e) => {
                    log::error!("Offerbook corrupted at {path:?}. Recreating. Error: {e:?}");
                    let book = OfferBook::default();
                    book.write_to_disk(&path)?;
                    book
                }
            }
        } else {
            log::info!("Offerbook not found. Creating new at {path:?}");
            let empty_book = OfferBook::default();
            let file = std::fs::File::create(&path)?;
            let writer = BufWriter::new(file);
            serde_json::to_writer_pretty(writer, &empty_book)?;
            empty_book
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(offerbook)),
            path,
            is_syncing: Arc::new(AtomicBool::new(false)),
            last_sync_ts: Arc::new(AtomicU64::new(0)),
        })
    }
}

/// RAII guard that resets an `AtomicBool` to `false` when dropped.
/// Used to ensure `OfferBookHandle::is_syncing` is reliably cleared on every
/// exit path of `OfferSyncService::run_once`, including early returns and panics.
struct SyncGuard<'a> {
    flag: &'a AtomicBool,
}

impl Drop for SyncGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Relaxed);
    }
}

/// Service run on taker to check if the offerbook makers are active or not.
pub struct OfferSyncService {
    offerbook: OfferBookHandle,
    registry: FileRegistry,
    socks_port: u16,
    /// Shared so per-maker offer-fetch workers can each hold a handle.
    blockchain: Arc<AnyBlockchain>,
    /// Set to `true` by Nostr discovery after the first EOSE is received.
    initial_sync_complete: Arc<AtomicBool>,
    /// Shared with the handle and the fetch workers so shutdown stops new
    /// fetches; in-flight ones abort via the backend's own flag.
    shutdown: Arc<AtomicBool>,
}

/// OfferSync handle, use for shutting down OfferSyncService
pub struct OfferSyncHandle {
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    cmd_tx: mpsc::Sender<SyncCommand>,
}

/// Lightweight clone-able client for triggering offer sync operations from
/// other threads without owning the join handle / shutdown flag.
#[derive(Clone)]
pub struct OfferSyncClient {
    cmd_tx: mpsc::Sender<SyncCommand>,
}

impl OfferSyncClient {
    /// Trigger an offerbook sync and wait up to ten minutes for completion.
    pub fn sync_and_wait(&self) -> Result<(), TakerError> {
        sync_and_wait(&self.cmd_tx, OFFER_SYNC_WAIT_TIMEOUT)
    }

    /// Run a single-maker offer fetch + fidelity verification cycle for `address`
    /// and block until it completes. If the address is not already in the offerbook
    /// it is inserted. Returns the maker's final state after the poll, or an error
    /// if a concurrent `remove_maker` evicted the entry before its state could be
    /// captured.
    pub fn poll_maker(&self, address: MakerAddress) -> Result<MakerOfferCandidate, TakerError> {
        let (done_tx, done_rx) = mpsc::channel();
        let address_str = address.to_string();
        self.cmd_tx.send(SyncCommand::PollMaker {
            address,
            done: done_tx,
        })?;
        done_rx.recv()?.ok_or_else(|| {
            TakerError::General(format!(
                "Maker {address_str} was removed before the poll could record a result"
            ))
        })
    }
}

impl OfferSyncHandle {
    /// Shutdown handler
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);

        if let Some(join) = self.join.take() {
            let thread = join.thread().clone();
            crate::utill::log_shutdown_join_start("offer_sync", &thread);
            let result = join.join();
            crate::utill::log_shutdown_join_done(
                "offer_sync",
                &thread,
                if result.is_ok() { "ok" } else { "panic" },
            );
        }
    }

    /// Return a clone-able client that can trigger sync operations without
    /// requiring access to the owning `OfferSyncHandle`.
    pub fn client(&self) -> OfferSyncClient {
        OfferSyncClient {
            cmd_tx: self.cmd_tx.clone(),
        }
    }

    /// Trigger an offerbook sync and wait up to ten minutes for completion.
    pub fn sync_and_wait(&self) -> Result<(), TakerError> {
        sync_and_wait(&self.cmd_tx, OFFER_SYNC_WAIT_TIMEOUT)
    }

    /// Run a single-maker offer fetch + fidelity verification cycle for `address`
    /// and block until it completes. If the address is not already in the offerbook
    /// it is inserted. Returns the maker's final state after the poll, or an error
    /// if a concurrent `remove_maker` evicted the entry before its state could be
    /// captured.
    pub fn poll_maker(&self, address: MakerAddress) -> Result<MakerOfferCandidate, TakerError> {
        let (done_tx, done_rx) = mpsc::channel();
        let address_str = address.to_string();
        self.cmd_tx.send(SyncCommand::PollMaker {
            address,
            done: done_tx,
        })?;
        done_rx.recv()?.ok_or_else(|| {
            TakerError::General(format!(
                "Maker {address_str} was removed before the poll could record a result"
            ))
        })
    }
}

fn sync_and_wait(cmd_tx: &mpsc::Sender<SyncCommand>, timeout: Duration) -> Result<(), TakerError> {
    let (done_tx, done_rx) = mpsc::channel();
    cmd_tx.send(SyncCommand::SyncNow(done_tx))?;
    match done_rx.recv_timeout(timeout) {
        Ok(()) => Ok(()),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            log::warn!("Offer sync exceeded {timeout:?}; using the current offerbook");
            Ok(())
        }
        Err(e @ mpsc::RecvTimeoutError::Disconnected) => Err(e.into()),
    }
}

impl OfferSyncService {
    /// Constructor method
    pub fn new(
        offerbook: OfferBookHandle,
        registry: FileRegistry,
        socks_port: u16,
        blockchain: Arc<AnyBlockchain>,
        initial_sync_complete: Arc<AtomicBool>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            offerbook,
            registry,
            socks_port,
            blockchain,
            initial_sync_complete,
            shutdown,
        }
    }

    fn run_once(&self) -> Result<(), TakerError> {
        self.offerbook.is_syncing.store(true, Ordering::Relaxed);
        let _guard = SyncGuard {
            flag: &self.offerbook.is_syncing,
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let height = match self.blockchain.get_block_count() {
            Ok(h) => h as u32,
            Err(e) => {
                log::warn!("get_block_count failed; skipping fidelity prune this cycle: {e:?}");
                0
            }
        };
        let fidelities = self.registry.list_fidelity(height)?;
        {
            let mut book = lock_debug!(self.offerbook.inner.write())
                .map_err(|_| TakerError::General("offerbook lock poisoned".into()))?;
            for fidelity in fidelities {
                match MakerAddress::try_from(fidelity.onion_address) {
                    Ok(parsed) => book.upsert_address(parsed, Some(fidelity.txid)),
                    Err(e) => {
                        log::warn!("Skipping invalid maker address from registry: {e}");
                    }
                }
            }
        }

        let to_poll = lock_debug!(self.offerbook.inner.read())
            .map_err(|_| TakerError::General("offerbook lock poisoned".into()))?
            .makers_to_poll(now);

        if !to_poll.is_empty() {
            let handles = self.spawn_offer_workers(to_poll)?;
            Self::join_offer_workers(handles);
        }

        let finished_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.offerbook
            .last_sync_ts
            .store(finished_at, Ordering::Relaxed);

        Ok(())
    }

    /// Downloads and verifies one maker's offer with no lock held, then takes the
    /// write guard once to record the result and persist. Shared by the periodic
    /// worker pool and the manual `poll_one` path. Returns the recorded maker, or
    /// `None` if no entry exists for `addr` after the update (e.g. a concurrent
    /// `remove` raced the poll).
    fn fetch_and_record_one(
        addr: MakerAddress,
        socks_port: u16,
        blockchain: &AnyBlockchain,
        offerbook: &Arc<RwLock<OfferBook>>,
        offerbook_path: &Path,
        now: u64,
        shutdown: &AtomicBool,
    ) -> Option<MakerOfferCandidate> {
        if shutdown.load(Ordering::Relaxed) {
            return None;
        }
        let downloaded = addr
            .clone()
            .download_offer_with_retries(socks_port, shutdown);
        // Verify before taking the guard. The backend calls in here can block on a
        // slow server, which would serialize every worker in the pool behind it.
        let outcome = downloaded.map(|oa| {
            let verdict = verify_fidelity_with_backend(
                blockchain,
                &oa.offer.fidelity,
                &oa.address.to_string(),
                &oa.offer.tweakable_point,
                &oa.offer.tweak_chain_code,
            );
            (oa, verdict)
        });
        // Poison means a worker panicked mid-update; skip this maker instead
        // of panicking the whole worker pool.
        let mut book = match lock_debug!(offerbook.write()) {
            Ok(book) => book,
            Err(_) => {
                log::error!("offerbook lock poisoned; skipping maker {addr}");
                return None;
            }
        };
        match outcome {
            Some((oa, Ok(_))) => book.mark_success(&oa.address, oa.offer, oa.protocol, now),
            Some((oa, Err(e))) => book.record_fidelity_failure(&oa.address, &e, now),
            None => book.mark_failure(&addr, now),
        }
        // Capture the maker's final state while we still hold the write lock so
        // a concurrent `remove` can't yank it out from under the caller.
        let captured = book.makers.iter().find(|m| m.address == addr).cloned();
        if let Err(e) = book.write_to_disk(offerbook_path) {
            log::warn!("Failed to persist offerbook: {:?}", e);
        }
        captured
    }

    /// Performs a single offer fetch + fidelity verification cycle for one maker,
    /// updating the offerbook with the result. The maker is inserted if absent.
    /// Returns the maker's final state after the poll, or `None` if a concurrent
    /// `remove` evicted the entry before the recorded state could be captured.
    fn poll_one(&self, address: MakerAddress) -> Option<MakerOfferCandidate> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        // Ensure the maker is present in the offerbook before polling.
        // Same poison policy as fetch_and_record_one: skip this poll.
        match lock_debug!(self.offerbook.inner.write()) {
            Ok(mut book) => book.upsert_address(address.clone(), None),
            Err(_) => {
                log::error!("offerbook lock poisoned; skipping poll of {address}");
                return None;
            }
        }

        Self::fetch_and_record_one(
            address,
            self.socks_port,
            &self.blockchain,
            &self.offerbook.inner,
            &self.offerbook.path,
            now,
            &self.shutdown,
        )
    }

    /// Spawns worker threads that fetch offers from makers and update the offerbook
    /// as each result arrives. Returns join handles.
    fn spawn_offer_workers(
        &self,
        makers: Vec<MakerAddress>,
    ) -> Result<Vec<JoinHandle<()>>, TakerError> {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(makers.len());

        let queue = Arc::new(Mutex::new(makers.into_iter()));
        let offerbook = self.offerbook.inner.clone();
        let offerbook_path = self.offerbook.path.clone();
        let socks_port = self.socks_port;
        let blockchain = self.blockchain.clone();
        let shutdown = self.shutdown.clone();

        let mut handles = Vec::with_capacity(workers);

        for i in 0..workers {
            let queue = Arc::clone(&queue);
            let offerbook = Arc::clone(&offerbook);
            let offerbook_path = offerbook_path.clone();
            let blockchain = blockchain.clone();
            let shutdown = shutdown.clone();

            let handle = match Builder::new()
                .name(format!("offer-fetch-worker-{i}"))
                .spawn(move || {
                    // Electrum's client is fully synchronous: two workers calling
                    // it at once can wedge it and hang taker shutdown forever.
                    // Each worker gets its own connection.
                    let backend = match blockchain.new_connection() {
                        Ok(b) => b,
                        Err(e) => {
                            log::warn!(
                                "offer-fetch-worker-{i}: backend connect failed: {e:?}; skipping this cycle"
                            );
                            return;
                        }
                    };
                    loop {
                        if shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        let addr = {
                            let Ok(mut guard) = lock_debug!(queue.lock()) else {
                                break;
                            };
                            guard.next()
                        };
                        let Some(addr) = addr else { break };

                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or(Duration::ZERO)
                            .as_secs();

                        let _ = Self::fetch_and_record_one(
                            addr,
                            socks_port,
                            &backend,
                            &offerbook,
                            &offerbook_path,
                            now,
                            &shutdown,
                        );
                    }
                }) {
                Ok(handle) => handle,
                Err(e) => {
                    self.shutdown.store(true, Ordering::Relaxed);
                    Self::join_offer_workers(handles);
                    return Err(TakerError::General(format!(
                        "failed to spawn offer-fetch-worker: {e}"
                    )));
                }
            };

            handles.push(handle);
        }

        Ok(handles)
    }

    /// Joins every fetch worker so partial startup and normal polling share cleanup.
    fn join_offer_workers(handles: Vec<JoinHandle<()>>) {
        for handle in handles {
            let thread = handle.thread().clone();
            crate::utill::log_shutdown_join_start("offer_sync", &thread);
            let result = handle.join();
            crate::utill::log_shutdown_join_done(
                "offer_sync",
                &thread,
                if result.is_ok() { "ok" } else { "panic" },
            );
        }
    }

    /// Starts the offerbook service
    pub fn start(self) -> Result<OfferSyncHandle, TakerError> {
        let shutdown = self.shutdown.clone();
        let shutdown_flag = shutdown.clone();
        let (cmd_tx, cmd_rx) = mpsc::channel::<SyncCommand>();

        let join = std::thread::Builder::new()
            .name("offer-sync-service".to_string())
            .spawn(move || {
                log::info!("Offer sync service started");

                while !shutdown_flag.load(Ordering::Relaxed) {
                    log::info!("Running offerbook sync");
                    if let Err(e) = self.run_once() {
                        log::warn!("Offer sync iteration failed: {e:?}");
                    }
                    log::debug!("Running offerbook sync completed");
                    let mut slept = Duration::ZERO;
                    while slept < OFFER_SYNC_INTERVAL && !shutdown_flag.load(Ordering::Relaxed) {
                        match cmd_rx.try_recv() {
                            Ok(SyncCommand::SyncNow(done_tx)) => {
                                log::info!("Manual offerbook sync requested");
                                // Shutdown trumps a queued sync; still ack so a
                                // waiting caller is not left blocking on recv.
                                if shutdown_flag.load(Ordering::Relaxed) {
                                    let _ = done_tx.send(());
                                    break;
                                }
                                self.wait_for_discovery(&shutdown_flag);
                                if let Err(e) = self.run_once() {
                                    log::warn!("Manual offer sync failed: {e:?}");
                                }
                                let _ = done_tx.send(());
                                Self::drain_and_ack(&cmd_rx);
                                break;
                            }
                            Ok(SyncCommand::PollMaker { address, done }) => {
                                log::info!("Manual maker poll requested: {}", address);
                                let result = self.poll_one(address);
                                let _ = done.send(result);
                            }
                            Err(mpsc::TryRecvError::Empty) => {}
                            Err(mpsc::TryRecvError::Disconnected) => return,
                        }
                        std::thread::sleep(Duration::from_secs(1));
                        slept += Duration::from_secs(1);
                    }
                }

                log::debug!("Offer sync service stopped");
            })
            .map_err(|e| TakerError::General(format!("failed to spawn offer sync service: {e}")))?;

        Ok(OfferSyncHandle {
            shutdown,
            join: Some(join),
            cmd_tx,
        })
    }

    /// Waits up to DISCOVERY_WAIT_MAX for initial Nostr EOSE before running a manual sync.
    fn wait_for_discovery(&self, shutdown_flag: &AtomicBool) {
        if self.initial_sync_complete.load(Ordering::SeqCst) {
            return;
        }

        let wait_start = std::time::Instant::now();
        while !self.initial_sync_complete.load(Ordering::SeqCst)
            && !shutdown_flag.load(Ordering::Relaxed)
        {
            if wait_start.elapsed() >= DISCOVERY_WAIT_MAX {
                log::warn!(
                    "Initial Nostr discovery did not complete in {:?}; proceeding with manual sync",
                    DISCOVERY_WAIT_MAX
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// This is used while periodic sync is running and on-demand syncs are initiated, then, acknowledge and discardall queued sync requests.
    fn drain_and_ack(rx: &mpsc::Receiver<SyncCommand>) {
        while let Ok(SyncCommand::SyncNow(done_tx)) = rx.try_recv() {
            let _ = done_tx.send(());
        }
    }
}

/// Why a fidelity check failed. Only `BadBond` is the maker's doing; a backend
/// outage is ours and must not count against them.
#[derive(Debug)]
enum FidelityCheckError {
    BackendDown(TakerError),
    BadBond(TakerError),
}

/// Verifies a fidelity proof against the blockchain.
fn verify_fidelity_with_backend(
    blockchain: &AnyBlockchain,
    proof: &FidelityProof,
    onion_addr: &str,
    tweakable_point: &bitcoin::PublicKey,
    tweak_chain_code: &bitcoin::bip32::ChainCode,
) -> Result<(), FidelityCheckError> {
    let backend_down = |e: WalletError| FidelityCheckError::BackendDown(TakerError::Wallet(e));

    let txid = proof.bond.outpoint.txid;
    let vout = proof.bond.outpoint.vout;
    let transaction = blockchain
        .get_raw_transaction(&txid, None)
        .map_err(backend_down)?;
    // The bond output must still be unspent. `Ok(None)` is the backend
    // answering "spent or absent", so it is the maker's problem, not ours.
    if blockchain
        .get_tx_out(&txid, vout, Some(true))
        .map_err(backend_down)?
        .is_none()
    {
        return Err(FidelityCheckError::BadBond(TakerError::General(format!(
            "Fidelity bond output {txid}:{vout} is spent or does not exist"
        ))));
    }
    let current_height = blockchain.get_block_count().map_err(backend_down)?;
    let confirmation_height = blockchain
        .tx_block_height(&txid)
        .map_err(backend_down)?
        .ok_or_else(|| {
            FidelityCheckError::BadBond(TakerError::General(format!(
                "Fidelity bond transaction {txid} is not yet confirmed"
            )))
        })? as u32;

    verify_fidelity_checks(
        proof,
        onion_addr,
        transaction,
        current_height,
        confirmation_height,
        tweakable_point,
        tweak_chain_code,
    )
    .map_err(|e| FidelityCheckError::BadBond(TakerError::Wallet(e)))
}

/// An ephemeral Offerbook tracking good and bad makers. Currently, Offerbook is initiated
/// at the start of every swap. So good and bad maker list will not be persisted.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct OfferBook {
    pub(super) makers: Vec<MakerOfferCandidate>,
}

impl OfferBook {
    fn upsert_address(&mut self, address: MakerAddress, txid: Option<Txid>) {
        if self.makers.iter().any(|m| m.address == address) {
            return;
        }

        self.makers.push(MakerOfferCandidate {
            address,
            fidelity_outpoint: txid.map(|t| OutPoint::new(t, 0)),
            offer: None,
            state: MakerState::Unresponsive { retries: 0 },
            protocol: None,
            last_offer_update_ts: None,
            next_offer_check_ts: None,
        });
    }

    pub(crate) fn mark_success(
        &mut self,
        address: &MakerAddress,
        offer: Offer,
        protocol: MakerProtocol,
        now_ts: u64,
    ) {
        if let Some(m) = self.makers.iter_mut().find(|m| &m.address == address) {
            m.mark_success(offer, protocol, now_ts);
        }
    }

    fn mark_failure(&mut self, address: &MakerAddress, now_ts: u64) {
        if let Some(m) = self.makers.iter_mut().find(|m| &m.address == address) {
            m.mark_failure(now_ts);
        }
    }

    /// Scores a failed fidelity check only when the backend answered. Otherwise
    /// one local outage walks every honest maker to the terminal `Bad` state.
    fn record_fidelity_failure(
        &mut self,
        address: &MakerAddress,
        err: &FidelityCheckError,
        now_ts: u64,
    ) {
        match err {
            FidelityCheckError::BadBond(e) => {
                log::warn!("Fidelity verification failed for {address}: {e:?}");
                self.mark_failure(address, now_ts);
            }
            FidelityCheckError::BackendDown(e) => {
                log::warn!("Backend failed verifying {address}, leaving its score alone: {e:?}");
            }
        }
    }

    fn makers_to_poll(&self, now_ts: u64) -> Vec<MakerAddress> {
        self.makers
            .iter()
            .filter(|m| !matches!(m.state, MakerState::Bad))
            .filter(|m| match m.next_offer_check_ts {
                Some(next_ts) => now_ts >= next_ts,
                None => true,
            })
            .filter(|m| match m.last_offer_update_ts {
                Some(last_ts) => {
                    now_ts.saturating_sub(last_ts) >= OFFER_MAX_AGE_BEFORE_REFRESH.as_secs()
                }
                None => true,
            })
            .map(|m| m.address.clone())
            .collect()
    }

    fn mark_bad(&mut self, address: &MakerAddress) {
        if let Some(m) = self.makers.iter_mut().find(|m| &m.address == address) {
            #[cfg(debug_assertions)]
            if m.state != MakerState::Bad {
                log::debug!(
                    "[MAKER_STATE] Source: taker::offers::OfferBook::mark_bad | Address: {} | State: {:?} -> Bad",
                    m.address,
                    m.state
                );
            }
            m.state = MakerState::Bad;
        }
    }

    /// Gets all active (good) offers for a given protocol.
    /// Makers are included for both Legacy and Taproot requests.
    fn active_makers(&self, protocol: &MakerProtocol) -> Vec<OfferAndAddress> {
        let mut result: Vec<_> = self
            .makers
            .iter()
            .filter(|m| m.state == MakerState::Good)
            .filter(|m| {
                m.protocol
                    .as_ref()
                    .map(|p| p.supports(protocol))
                    .unwrap_or(false)
            })
            .filter_map(|m| m.as_offer_and_address())
            .collect();
        result.sort_by(|a, b| a.address.cmp(&b.address));
        result
    }

    fn good_makers(&self) -> Vec<OfferAndAddress> {
        self.makers
            .iter()
            .filter(|m| !matches!(m.state, MakerState::Bad))
            .filter_map(|m| m.as_offer_and_address())
            .collect()
    }

    /// Gets all offers.
    pub fn all_makers(&self) -> Vec<MakerOfferCandidate> {
        self.makers.to_vec()
    }

    /// Gets the list of bad makers.
    /// Makers are included for both Legacy and Taproot requests.
    fn get_bad_makers(&self, protocol: &MakerProtocol) -> Vec<OfferAndAddress> {
        let mut result: Vec<_> = self
            .makers
            .iter()
            .filter(|m| m.state == MakerState::Bad)
            .filter(|m| {
                m.protocol
                    .as_ref()
                    .map(|p| p.supports(protocol))
                    .unwrap_or(false)
            })
            .filter_map(|m| m.as_offer_and_address())
            .collect();
        result.sort_by(|a, b| a.address.cmp(&b.address));
        result
    }

    /// Load existing file, updates it, writes it back (create if path doesn't exist).
    fn write_to_disk(&self, path: &Path) -> Result<(), TakerError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Truncate to avoid leaving stale bytes if the JSON becomes shorter.
        let offerdata_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        let writer = BufWriter::new(offerdata_file);
        Ok(serde_json::to_writer_pretty(writer, &self)?)
    }

    /// Reads from a path (errors if path doesn't exist).
    fn read_from_disk(path: &Path) -> Result<Self, TakerError> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }
}

impl TryFrom<String> for MakerAddress {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err("Empty address");
        }

        #[cfg(feature = "integration-test")]
        {
            // Integration tests use "ip:port" format
            let mut parts = value.splitn(2, ':');
            let ip = parts.next().ok_or("Missing IP")?;
            let port = parts.next().ok_or("Missing port")?;
            if ip.is_empty() || port.is_empty() {
                return Err("Empty IP or port");
            }
        }

        #[cfg(not(feature = "integration-test"))]
        {
            // Production: value is just a hostname like "xyz.onion"
            if !value.ends_with(".onion") {
                return Err("Not a valid .onion hostname");
            }
        }

        Ok(MakerAddress(value))
    }
}

impl MakerAddress {
    fn download_offer_with_retries(
        self,
        socks_port: u16,
        shutdown: &AtomicBool,
    ) -> Option<OfferAndAddress> {
        for attempt in 1..=FIRST_CONNECT_ATTEMPTS {
            if shutdown.load(Ordering::Relaxed) {
                return None;
            }
            match self.clone().download_offer_auto(socks_port) {
                Ok(offer) => return Some(offer),
                Err(e) if attempt < FIRST_CONNECT_ATTEMPTS => {
                    log::debug!(
                        "Failed to fetch offer from {} (attempt {}/{}): {:?}",
                        self,
                        attempt,
                        FIRST_CONNECT_ATTEMPTS,
                        e
                    );
                    let delay = Duration::from_millis(FIRST_CONNECT_SLEEP_DELAY_SEC);
                    let mut remaining = delay;
                    while !remaining.is_zero() {
                        if shutdown.load(Ordering::Relaxed) {
                            return None;
                        }
                        let slice = remaining.min(Duration::from_millis(100));
                        sleep(slice);
                        remaining -= slice;
                    }
                }
                Err(e) => {
                    log::debug!("Exhausted retries fetching offer from {}: {:?}", self, e);
                }
            }
        }
        None
    }

    fn download_offer_auto(self, socks_port: u16) -> Result<OfferAndAddress, TakerError> {
        let (offer, protocol) = self.fetch_offer(socks_port)?;
        Ok(OfferAndAddress {
            offer,
            address: self,
            state: MakerState::Good,
            protocol,
        })
    }

    /// Download a single offer from a maker.
    fn fetch_offer(&self, socks_port: u16) -> Result<(Offer, MakerProtocol), TakerError> {
        log::debug!("Downloading offer from maker: {}", self);

        #[cfg(feature = "integration-test")]
        let mut socket = {
            let _ = socks_port;
            // Integration test: self.0 is "ip:port"
            TcpStream::connect(self.to_string())?
        };
        #[cfg(not(feature = "integration-test"))]
        let mut socket = {
            use crate::protocol::common_messages::OPENSWAP_PORT;

            // Production: self.0 is a .onion hostname, connect via the Tor proxy
            socks5_connect(
                socks_port,
                &self.0,
                OPENSWAP_PORT,
                None,
                Duration::from_secs(FIRST_CONNECT_ATTEMPT_TIMEOUT_SEC),
            )?
        };

        socket.set_read_timeout(Some(Duration::from_secs(FIRST_CONNECT_ATTEMPT_TIMEOUT_SEC)))?;
        socket.set_write_timeout(Some(Duration::from_secs(FIRST_CONNECT_ATTEMPT_TIMEOUT_SEC)))?;

        // Send TakerHello
        let taker_hello = RouterTakerToMakerMessage::TakerHello(RouterTakerHello);
        send_message(&mut socket, &taker_hello)?;

        // Read MakerHello
        let msg_bytes = read_message(&mut socket)?;
        let msg: RouterMakerToTakerMessage = serde_cbor::from_slice(&msg_bytes)?;

        match msg {
            RouterMakerToTakerMessage::MakerHello(_hello) => {
                // Maker - supports both Legacy and Taproot
            }
            msg => {
                return Err(ProtocolError::WrongMessage {
                    expected: "MakerHello".to_string(),
                    received: format!("{msg:?}"),
                }
                .into());
            }
        };

        // Send GetOffer
        let get_offer = RouterTakerToMakerMessage::GetOffer(RouterGetOffer);
        send_message(&mut socket, &get_offer)?;

        // Read Offer
        let offer_bytes = read_message(&mut socket)?;
        let offer_msg: RouterMakerToTakerMessage = serde_cbor::from_slice(&offer_bytes)?;

        let router_offer = match offer_msg {
            RouterMakerToTakerMessage::Offer(offer) => *offer,
            msg => {
                return Err(ProtocolError::WrongMessage {
                    expected: "Offer".to_string(),
                    received: format!("{msg:?}"),
                }
                .into());
            }
        };

        // Convert router offer to legacy Offer format for storage
        let offer = Offer {
            base_fee: router_offer.base_fee,
            amount_relative_fee_pct: router_offer.amount_relative_fee_pct,
            time_relative_fee_pct: router_offer.time_relative_fee_pct,
            required_confirms: router_offer.required_confirms,
            minimum_locktime: router_offer.minimum_locktime,
            max_size: router_offer.max_size,
            min_size: router_offer.min_size,
            tweakable_point: router_offer.tweakable_point,
            fidelity: FidelityProof {
                bond: router_offer.fidelity.bond,
                cert_hash: router_offer.fidelity.cert_hash,
                cert_sig: router_offer.fidelity.cert_sig,
            },
            tweak_chain_code: router_offer.tweak_chain_code,
            max_tx_splits: router_offer.max_tx_splits,
        };

        log::info!(
            "Successfully downloaded offer from maker: {} (protocol: Unified)",
            self
        );

        Ok((offer, MakerProtocol::Unified))
    }
}

/// Format state
pub fn format_state(state: &MakerState) -> String {
    match state {
        MakerState::Good => "Good".into(),
        MakerState::Unresponsive { retries } => {
            format!("Unresponsive (retries: {retries})")
        }
        MakerState::Bad => "Bad".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime,
        hashes::Hash,
        secp256k1::{Message, Secp256k1, SecretKey},
        Amount, OutPoint, Txid,
    };

    fn addr(id: &str) -> MakerAddress {
        MakerAddress(format!("testmaker{id}.onion"))
    }

    fn dummy_offer(maker_addr: &str) -> Offer {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1; 32]).expect("valid secret key");
        let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let pubkey = bitcoin::PublicKey::new(secp_pubkey);

        let bond = crate::wallet::FidelityBond {
            outpoint: OutPoint {
                txid: Txid::from_slice(&[2; 32]).expect("valid txid"),
                vout: 0,
            },
            amount: Amount::from_sat(1000),
            lock_time: LockTime::from_height(1000).expect("valid height locktime"),
            pubkey,
            conf_height: Some(1000),
            is_spent: false,
            bond_index: 0,
            tx: None,
        };

        let cert_hash = bond.generate_cert_hash(maker_addr, &pubkey);
        let msg = Message::from_digest_slice(cert_hash.as_byte_array()).expect("32-byte digest");
        let cert_sig = secp.sign_ecdsa(&msg, &secret_key);

        Offer {
            base_fee: 0,
            amount_relative_fee_pct: 0.0,
            time_relative_fee_pct: 0.0,
            required_confirms: 1,
            minimum_locktime: 1,
            max_size: 1,
            min_size: 1,
            tweakable_point: pubkey,
            fidelity: FidelityProof {
                bond,
                cert_hash,
                cert_sig,
            },
            tweak_chain_code: bitcoin::bip32::ChainCode::from([0u8; 32]),
            max_tx_splits: Some(crate::wallet::MAX_SPLITS as u32),
        }
    }

    #[test]
    fn mark_failure_state_and_backoff_growth() {
        let now_ts = 170000;
        let mut candidate = MakerOfferCandidate {
            address: addr("6104"),
            fidelity_outpoint: Some(OutPoint::new(Txid::from_slice(&[1; 32]).unwrap(), 0)),
            offer: None,
            state: MakerState::Good,
            protocol: None,
            last_offer_update_ts: None,
            next_offer_check_ts: None,
        };

        let mut prev_backoff_from_now = 0u64;
        let step = UNRESPONSIVE_MAKER_BACKOFF_STEP.as_secs();

        for i in 1..=11 {
            candidate.mark_failure(now_ts);

            // State transitions: Good -> Unresponsive{1} .. Unresponsive{10} -> Bad (on 11th)
            if i <= 10 {
                assert_eq!(candidate.state, MakerState::Unresponsive { retries: i });
            } else {
                assert_eq!(candidate.state, MakerState::Bad);
            }

            let next_ts = candidate
                .next_offer_check_ts
                .expect("next_offer_check_ts should be set after failure");
            assert!(next_ts >= now_ts);

            // Backoff interval measured from 'now' grows each time.
            let backoff_from_now = next_ts.saturating_sub(now_ts);
            assert!(backoff_from_now > prev_backoff_from_now);
            prev_backoff_from_now = backoff_from_now;

            assert_eq!(backoff_from_now, step.saturating_mul(i as u64));
        }
    }

    #[test]
    fn mark_success_rehabilitates_bad_state() {
        let now_ts = 170000;
        let mut candidate = MakerOfferCandidate {
            address: addr("6105"),
            fidelity_outpoint: Some(OutPoint::new(Txid::from_slice(&[1; 32]).unwrap(), 0)),
            offer: None,
            state: MakerState::Bad,
            protocol: None,
            last_offer_update_ts: None,
            next_offer_check_ts: Some(now_ts + 123),
        };

        candidate.mark_success(
            dummy_offer(&candidate.address.to_string()),
            MakerProtocol::Taproot,
            now_ts,
        );
        assert_eq!(candidate.state, MakerState::Good);
        assert_eq!(candidate.next_offer_check_ts, None);
        assert_eq!(candidate.last_offer_update_ts, Some(now_ts));
    }

    #[test]
    fn makers_to_poll_respects_backoff_timer() {
        let now_ts = 170000;
        let mut book = OfferBook { makers: vec![] };
        book.makers.push(MakerOfferCandidate {
            address: addr("6103"),
            fidelity_outpoint: Some(OutPoint::new(Txid::from_slice(&[1; 32]).unwrap(), 0)),
            offer: None,
            state: MakerState::Unresponsive { retries: 3 },
            protocol: None,
            last_offer_update_ts: None,
            next_offer_check_ts: Some(now_ts + 10),
        });

        let to_poll = book.makers_to_poll(now_ts);
        assert!(to_poll.is_empty());

        let to_poll_after = book.makers_to_poll(now_ts + 11);
        assert_eq!(to_poll_after, vec![addr("6103")]);
    }

    #[test]
    fn backend_down_leaves_maker_state_unchanged() {
        let now_ts = 170000;
        let address = addr("6106");
        let mut book = OfferBook { makers: vec![] };
        book.makers.push(MakerOfferCandidate {
            address: address.clone(),
            fidelity_outpoint: Some(OutPoint::new(Txid::from_slice(&[1; 32]).unwrap(), 0)),
            offer: None,
            state: MakerState::Good,
            protocol: None,
            last_offer_update_ts: None,
            next_offer_check_ts: None,
        });

        let down = FidelityCheckError::BackendDown(TakerError::General("electrum down".into()));
        book.record_fidelity_failure(&address, &down, now_ts);
        assert_eq!(book.makers[0].state, MakerState::Good);
        assert_eq!(book.makers[0].next_offer_check_ts, None);

        // A bond the backend did answer on still counts against the maker.
        let bad = FidelityCheckError::BadBond(TakerError::General("bond is spent".into()));
        book.record_fidelity_failure(&address, &bad, now_ts);
        assert_eq!(
            book.makers[0].state,
            MakerState::Unresponsive { retries: 1 }
        );
    }

    #[test]
    fn timed_sync_uses_current_book_when_ack_is_missing() {
        let (cmd_tx, cmd_rx) = mpsc::channel();

        sync_and_wait(&cmd_tx, Duration::ZERO).unwrap();
        assert!(matches!(cmd_rx.recv().unwrap(), SyncCommand::SyncNow(_)));
    }
}
