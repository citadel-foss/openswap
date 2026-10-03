//! Background service threads for the Taker.
//!
//! Owns the recovery, breach-detection, and route-heartbeat threads.
//! Each service signals and joins its thread before it is dropped.

use std::{
    collections::HashSet,
    net::TcpStream,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        mpsc, Arc, Mutex, RwLock,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use bitcoin::{OutPoint, ScriptBuf, Txid};

use crate::{
    lock_debug,
    protocol::{common_messages::TakerToMakerMessage, ProtocolVersion},
    taker::{
        api::{connect_to_maker, handshake_with_maker, ConnectionType},
        error::TakerError,
    },
    utill::HEART_BEAT_INTERVAL,
    wallet::{AnyBlockchain, Blockchain, RecoveryReport, Wallet},
    watch_tower::{service::WatchService, watcher::WatcherEvent},
};

use super::swap_tracker::{
    funding_shared, incoming_claimed, ContractOutcome, ContractResolution, RecoveryPhase,
    SwapTracker,
};

/// Interval between recovery retry attempts.
#[cfg(not(feature = "integration-test"))]
const RECOVERY_LOOP_INTERVAL: Duration = Duration::from_secs(60);
#[cfg(feature = "integration-test")]
const RECOVERY_LOOP_INTERVAL: Duration = Duration::from_secs(10);

/// Background thread that periodically retries wallet-level recovery
/// (hashlock sweep + timelock recovery) until all contract UTXOs are resolved.
///
/// Spawned at the end of `recover_active_swap()` or `init_recover_incomplete()`
/// when some contracts remain unresolved (e.g. timelocks not yet mature).
pub(crate) struct RecoveryLoop {
    shutdown: Arc<AtomicBool>,
    complete: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl RecoveryLoop {
    /// Spawn the background recovery thread.
    ///
    /// The tracker supplies the failed swaps that this loop may recover. The
    /// scope is refreshed every pass so a live swap can never be selected just
    /// because its swapcoins share the same wallet.
    pub(crate) fn start(
        wallet: Arc<RwLock<Wallet>>,
        swap_tracker: Arc<Mutex<SwapTracker>>,
        watch_service: WatchService,
        data_dir: PathBuf,
    ) -> std::io::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let complete = Arc::new(AtomicBool::new(false));

        let shutdown_clone = shutdown.clone();
        let complete_clone = complete.clone();

        let handle = thread::Builder::new()
            .name("Recovery loop".to_string())
            .spawn(move || {
                log::info!("Recovery loop started");
                let mut last_tip = None;
                while !shutdown_clone.load(Relaxed) {
                    let scope = lock_debug!(swap_tracker.lock())
                        .ok()
                        .zip(lock_debug!(wallet.read()).ok())
                        .and_then(|(mut tracker, w)| {
                            tracker
                                .recovery_scope_listing(&w)
                                .inspect_err(|e| log::warn!("Recovery loop: scope: {:?}", e))
                                .ok()
                        });
                    let Some((swap_ids, incoming_contract_txids)) = scope else {
                        thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                        continue;
                    };
                    if swap_ids.is_empty() {
                        log::info!("Recovery loop: no failed swaps remain");
                        complete_clone.store(true, Relaxed);
                        return;
                    }

                    // The chain only moves with a block, so a pass waits for one. The
                    // watcher hears each block; asking the server is the fallback.
                    let tip = watch_service.tip().or_else(|| {
                        lock_debug!(wallet.read())
                            .ok()?
                            .blockchain
                            .get_block_count()
                            .inspect_err(|e| log::warn!("Recovery loop: block height: {:?}", e))
                            .ok()
                    });
                    if tip.is_none_or(|tip| last_tip.replace(tip) == Some(tip)) {
                        thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                        continue;
                    }

                    // One connection per pass, shared by both steps below:
                    // on Tor Electrum each fresh connection costs a circuit handshake.
                    let chain = match lock_debug!(wallet.read()) {
                        Ok(w) => match w.blockchain.new_connection() {
                            Ok(chain) => chain,
                            Err(e) => {
                                log::warn!("Recovery loop: no connection: {:?}", e);
                                // A dropped circuit is passing; retry on the next interval.
                                last_tip = None;
                                thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                                continue;
                            }
                        },
                        Err(_) => {
                            thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                            continue;
                        }
                    };

                    // Sweeps and timelock refunds in one pass. It takes the lock itself
                    // and drops it across its wait, so a stuck tx cannot wedge the wallet.
                    match Wallet::recover_swapcoins(
                        &wallet,
                        &chain,
                        &shutdown_clone,
                        &incoming_contract_txids,
                        &swap_ids,
                        &|coin_swap| funding_shared(&swap_tracker, coin_swap),
                        &|swap_id| incoming_claimed(&swap_tracker, &wallet, swap_id),
                    ) {
                        Ok((swept, recovered)) if !swept.is_empty() || !recovered.is_empty() => {
                            log::info!(
                                "Recovery loop: swept {} incoming swapcoins, recovered {} timelocked swapcoins",
                                swept.resolved.len(),
                                recovered.len()
                            );
                            if let Ok(mut tracker) = lock_debug!(swap_tracker.lock()) {
                                Self::update_tracker_outcomes(
                                    &mut tracker,
                                    &swap_ids,
                                    &swept,
                                    &recovered,
                                );
                            }
                        }
                        Ok(_) => {}
                        Err(e) => log::debug!("Recovery loop: recovery pass: {:?}", e),
                    }

                    // Snapshot the outpoints, then drop the guard: the checks below
                    // are backend calls and must not hold the wallet.
                    let outpoints = match lock_debug!(wallet.read()) {
                        Ok(w) => {
                            let mut outpoints = w.outgoing_contract_outpoints(Some(&swap_ids));
                            // A coin given up for a refund has no claim left to wait on.
                            outpoints.extend(
                                w.incoming_contract_outpoints(Some(&swap_ids))
                                    .into_iter()
                                    .filter(|(op, _)| {
                                        w.find_incoming_swapcoin(&op.txid.to_string())
                                            .is_some_and(|sc| {
                                                sc.is_preimage_known() || sc.other_privkey.is_some()
                                            })
                                    }),
                            );
                            Some(outpoints)
                        }
                        Err(_) => None,
                    };

                    // Check if all contract outpoints are resolved
                    let all_resolved = match outpoints {
                        Some(outpoints) => outpoints.iter().all(|(op, spk)| {
                            // Only a confirmed spend proves a contract resolved;
                            // a missing output also means evicted or unknown, and
                            // a failed lookup keeps us watching.
                            match chain.is_confirmed_spend(op, spk) {
                                Ok(spent) => spent,
                                Err(e) => {
                                    log::warn!("Recovery loop: could not check {}: {:?}", op, e);
                                    false
                                }
                            }
                        }),
                        None => false,
                    };

                    if !all_resolved {
                        log::info!(
                            "Recovery loop: contracts still unresolved, retrying on the next block"
                        );
                    } else {
                        log::info!("Recovery loop: all contracts resolved");
                        let mut saved = false;
                        if let Ok(mut w) = lock_debug!(wallet.write()) {
                            for swap_id in &swap_ids {
                                // A sweep normally removes its incoming entry
                                // after confirmation. If the process stops
                                // after broadcast but before that removal, a
                                // restarted recovery sees the outpoint spent
                                // and arrives here with a stale incoming entry.
                                // Since `all_resolved` is based on confirmed
                                // spends, it is now safe to remove both sides.
                                let incoming_keys = w.incoming_keys_for_swap(swap_id);
                                for key in &incoming_keys {
                                    w.remove_incoming_swapcoin(key);
                                }
                                let outgoing_keys = w.outgoing_keys_for_swap(swap_id);
                                for key in &outgoing_keys {
                                    w.remove_outgoing_swapcoin(key);
                                }
                                w.remove_watchonly_swapcoins(swap_id);
                            }
                            saved = w
                                .save_to_disk()
                                .inspect_err(|e| log::warn!("Recovery loop: cleanup save: {:?}", e))
                                .is_ok();
                        }
                        // Finished only once the removal is on disk: a restart
                        // skips a CleanedUp swap and would keep its stale coins.
                        if !saved {
                            last_tip = None;
                            thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                            continue;
                        }

                        if let Ok(mut tracker) = lock_debug!(swap_tracker.lock()) {
                            // Emit recovery reports before marking as cleaned up
                            for record in tracker
                                .incomplete_swaps()
                                .into_iter()
                                .filter(|record| swap_ids.contains(&record.swap_id))
                            {
                                let network = lock_debug!(wallet.read())
                                    .map(|w| w.store.network.to_string())
                                    .unwrap_or_default();
                                let all_outcomes = record
                                    .recovery
                                    .incoming
                                    .iter()
                                    .chain(record.recovery.outgoing.iter());
                                let mut hashlock_txids: Vec<String> = Vec::new();
                                let mut timelock_txids: Vec<String> = Vec::new();
                                for o in all_outcomes {
                                    if let Some(txid) = o.spending_txid {
                                        match o.resolution {
                                            ContractResolution::Hashlock => {
                                                hashlock_txids.push(txid.to_string())
                                            }
                                            ContractResolution::Timelock => {
                                                timelock_txids.push(txid.to_string())
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                if !hashlock_txids.is_empty() {
                                    RecoveryReport::emit_taker(
                                        &data_dir,
                                        record.swap_id.clone(),
                                        network.clone(),
                                        "hashlock".to_string(),
                                        hashlock_txids,
                                    );
                                }
                                if !timelock_txids.is_empty() {
                                    RecoveryReport::emit_taker(
                                        &data_dir,
                                        record.swap_id.clone(),
                                        network,
                                        "timelock".to_string(),
                                        timelock_txids,
                                    );
                                }
                            }

                            for swap_id in &swap_ids {
                                let _ = tracker.update_and_save(swap_id, |r| {
                                    r.recovery.phase = RecoveryPhase::CleanedUp;
                                });
                            }
                        }
                        let more_failed_swaps = lock_debug!(swap_tracker.lock())
                            .map(|tracker| !tracker.recovery_scope().0.is_empty())
                            .unwrap_or(true);
                        if more_failed_swaps {
                            continue;
                        }
                        complete_clone.store(true, Relaxed);
                        return;
                    }

                    thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                }
                log::info!("Recovery loop shut down");
            })?;

        Ok(Self {
            shutdown,
            complete,
            handle: Some(handle),
        })
    }

    /// Match resolved contract txids against tracker records and update outcomes.
    pub(crate) fn update_tracker_outcomes(
        tracker: &mut SwapTracker,
        recovery_scope: &HashSet<String>,
        swept: &crate::wallet::RecoveryOutcome,
        recovered: &crate::wallet::RecoveryOutcome,
    ) {
        let swap_ids: Vec<String> = tracker
            .incomplete_swaps()
            .iter()
            .filter(|record| recovery_scope.contains(&record.swap_id))
            .map(|r| r.swap_id.clone())
            .collect();

        for swap_id in swap_ids {
            let mut changed = false;

            let _ = tracker.update_and_save(&swap_id, |record| {
                // Update incoming outcomes from sweep results
                for (contract_txid, spending_txid) in &swept.resolved {
                    if record.incoming_contract_txids.contains(contract_txid) {
                        // Find existing outcome or add new one
                        if let Some(outcome) = record
                            .recovery
                            .incoming
                            .iter_mut()
                            .find(|o| o.contract_txid == *contract_txid)
                        {
                            if outcome.resolution == ContractResolution::Unresolved {
                                outcome.resolution = ContractResolution::Hashlock;
                                outcome.spending_txid = Some(*spending_txid);
                                changed = true;
                            }
                        } else {
                            record.recovery.incoming.push(ContractOutcome {
                                contract_txid: *contract_txid,
                                resolution: ContractResolution::Hashlock,
                                spending_txid: Some(*spending_txid),
                            });
                            changed = true;
                        }
                    }
                }

                // Update outgoing outcomes from timelock recovery results
                for (contract_txid, spending_txid) in &recovered.resolved {
                    if record.outgoing_contract_txids.contains(contract_txid) {
                        if let Some(outcome) = record
                            .recovery
                            .outgoing
                            .iter_mut()
                            .find(|o| o.contract_txid == *contract_txid)
                        {
                            if outcome.resolution == ContractResolution::Unresolved {
                                outcome.resolution = ContractResolution::Timelock;
                                outcome.spending_txid = Some(*spending_txid);
                                changed = true;
                            }
                        } else {
                            record.recovery.outgoing.push(ContractOutcome {
                                contract_txid: *contract_txid,
                                resolution: ContractResolution::Timelock,
                                spending_txid: Some(*spending_txid),
                            });
                            changed = true;
                        }
                    }
                }
                for contract_txid in &recovered.discarded {
                    if record.outgoing_contract_txids.contains(contract_txid) {
                        if let Some(outcome) = record
                            .recovery
                            .outgoing
                            .iter_mut()
                            .find(|o| o.contract_txid == *contract_txid)
                        {
                            if outcome.resolution == ContractResolution::Unresolved {
                                outcome.resolution = ContractResolution::Discarded;
                                changed = true;
                            }
                        } else {
                            record.recovery.outgoing.push(ContractOutcome {
                                contract_txid: *contract_txid,
                                resolution: ContractResolution::Discarded,
                                spending_txid: None,
                            });
                            changed = true;
                        }
                    }
                }

                // Advance recovery phase based on what was resolved
                if changed {
                    let all_incoming_done = record
                        .recovery
                        .incoming
                        .iter()
                        .all(|o| o.resolution != ContractResolution::Unresolved);
                    let all_outgoing_done = record
                        .recovery
                        .outgoing
                        .iter()
                        .all(|o| o.resolution != ContractResolution::Unresolved);

                    if all_outgoing_done && record.recovery.phase < RecoveryPhase::OutgoingRecovered
                    {
                        record.recovery.phase = RecoveryPhase::OutgoingRecovered;
                    } else if all_incoming_done
                        && record.recovery.phase < RecoveryPhase::IncomingRecovered
                    {
                        record.recovery.phase = RecoveryPhase::IncomingRecovered;
                    }
                }
            });
        }
    }

    /// Check whether recovery is complete.
    pub(crate) fn is_complete(&self) -> bool {
        self.complete.load(Relaxed)
    }

    /// Block until the loop finishes on its own, reporting whether it resolved
    /// every contract.
    ///
    /// The shutdown flag is left alone so the
    /// thread runs to its natural end, which it reaches once every contract is
    /// resolved. Consumes `self` because the join handle is not reusable.
    pub(crate) fn join(mut self) -> bool {
        if let Some(handle) = self.handle.take() {
            if handle.join().is_err() {
                // Otherwise a panicked thread is indistinguishable from one that
                // finished the job.
                log::error!("Recovery loop thread panicked; contracts may be unresolved");
            }
        }
        self.is_complete()
    }
}

impl Drop for RecoveryLoop {
    fn drop(&mut self) {
        self.shutdown.store(true, Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            let thread = handle.thread().clone();
            crate::utill::log_shutdown_join_start("taker_recovery", &thread);
            let result = handle.join();
            crate::utill::log_shutdown_join_done(
                "taker_recovery",
                &thread,
                if result.is_ok() { "ok" } else { "panic" },
            );
        }
    }
}

/// Monitors Legacy funding outpoints for an adversarial contract broadcast.
/// The watcher is the primary source; a direct backend query preserves the
/// fail-closed signal if the watcher exits.
pub(crate) struct BreachDetector {
    breached: Arc<AtomicBool>,
    unknown: Arc<AtomicBool>,
    /// Mapping of funding outpoint → expected contract txid.
    /// Only a spend whose txid matches the expected contract txid is adversarial.
    /// Cooperative spends (after finalization) produce a different txid.
    sentinels: Arc<Mutex<Vec<(OutPoint, Txid, ScriptBuf)>>>,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl BreachDetector {
    /// Spawn a background thread that polls the WatchService for sentinel spends.
    pub(crate) fn start(
        watch_service: WatchService,
        backend: AnyBlockchain,
    ) -> std::io::Result<Self> {
        let breached = Arc::new(AtomicBool::new(false));
        let unknown = Arc::new(AtomicBool::new(false));
        let sentinels: Arc<Mutex<Vec<(OutPoint, Txid, ScriptBuf)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let breached_clone = breached.clone();
        let unknown_clone = unknown.clone();
        let sentinels_clone = sentinels.clone();
        let shutdown_clone = shutdown.clone();

        let handle = thread::Builder::new()
            .name("Breach detector thread".to_string())
            .spawn(move || {
                while !shutdown_clone.load(Relaxed) {
                    thread::park_timeout(HEART_BEAT_INTERVAL);
                    if shutdown_clone.load(Relaxed) {
                        break;
                    }

                    let current_sentinels = match lock_debug!(sentinels_clone.lock()) {
                        Ok(guard) => guard.clone(),
                        Err(_) => {
                            unknown_clone.store(true, Relaxed);
                            continue;
                        }
                    };

                    let mut pass_unknown = false;
                    for (outpoint, expected_contract_txid, spk) in &current_sentinels {
                        let spending_tx = if watch_service.is_alive() {
                            match watch_service.watch_request(*outpoint) {
                                Ok(WatcherEvent::UtxoSpent { spending_tx, .. }) => spending_tx,
                                Ok(_) => None,
                                Err(e) => {
                                    log::error!("watch request for {outpoint} failed: {e}");
                                    pass_unknown = true;
                                    continue;
                                }
                            }
                        } else {
                            match backend.spending_transaction(
                                outpoint,
                                spk.as_script(),
                                Some(expected_contract_txid),
                            ) {
                                Ok(tx) => tx,
                                Err(e) => {
                                    log::error!("direct breach query for {outpoint} failed: {e}");
                                    pass_unknown = true;
                                    continue;
                                }
                            }
                        };
                        if let Some(tx) = spending_tx {
                            let actual_txid = tx.compute_txid();
                            if actual_txid == *expected_contract_txid {
                                // The funding outpoint was spent by the pre-signed contract tx.
                                // This is an adversarial broadcast.
                                log::warn!(
                                    "Breach detector: contract tx {} broadcast on sentinel {}",
                                    actual_txid,
                                    outpoint
                                );
                                breached_clone.store(true, Relaxed);
                                return;
                            }
                            // Spent by a different tx — cooperative sweep after finalization.
                            log::info!(
                                "Breach detector: cooperative spend on sentinel {} (tx {})",
                                outpoint,
                                actual_txid
                            );
                        }
                    }
                    unknown_clone.store(pass_unknown, Relaxed);
                }
            })?;

        Ok(Self {
            breached,
            unknown,
            sentinels,
            shutdown,
            handle: Some(handle),
        })
    }

    /// Register funding outpoints as sentinels with the WatchService.
    ///
    /// Each sentinel is a `(funding_outpoint, expected_contract_txid,
    /// funding_script_pubkey)` triple. Only a spend matching the contract
    /// txid is considered adversarial; cooperative spends (after
    /// finalization) produce a different txid and are ignored.
    pub(crate) fn add_sentinels(
        &self,
        watch_service: &WatchService,
        sentinels: &[(OutPoint, Txid, bitcoin::ScriptBuf)],
    ) -> Result<(), TakerError> {
        lock_debug!(self.sentinels.lock())
            .map_err(|_| TakerError::General("breach sentinel lock poisoned".into()))?
            .extend_from_slice(sentinels);
        for (outpoint, _, spk) in sentinels {
            if let Err(e) = watch_service.register_watch_request(*outpoint, spk.clone()) {
                log::error!("sentinel registration for {outpoint} failed: {e}; using fallback");
            }
        }
        Ok(())
    }

    pub(crate) fn disarm(&self, watch_service: &WatchService) {
        if let Ok(mut sentinels) = lock_debug!(self.sentinels.lock()) {
            for (outpoint, _, spk) in sentinels.drain(..) {
                _ = watch_service.unwatch(outpoint, spk);
            }
        }
    }

    pub(crate) fn is_breached(&self) -> bool {
        self.breached.load(Relaxed)
    }

    pub(crate) fn requires_abort(&self) -> bool {
        self.is_breached() || self.unknown.load(Relaxed)
    }

    /// Signal the background thread to stop and wait for it to finish.
    pub(crate) fn stop(mut self) {
        self.stop_thread();
    }

    /// Wakes the detector before joining so its heartbeat wait cannot delay shutdown.
    fn stop_thread(&mut self) {
        self.shutdown.store(true, Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            let thread = handle.thread().clone();
            crate::utill::log_shutdown_join_start("taker_breach_detector", &thread);
            let result = handle.join();
            crate::utill::log_shutdown_join_done(
                "taker_breach_detector",
                &thread,
                if result.is_ok() { "ok" } else { "panic" },
            );
        }
    }
}

impl Drop for BreachDetector {
    fn drop(&mut self) {
        self.stop_thread();
    }
}

/// Ticks to wait before the first reconnect attempt after a failure.
const RECONNECT_BACKOFF_MIN_TICKS: u32 = 1;
/// Ceiling on the doubling backoff, so a maker that is really gone costs one
/// connect attempt per this many ticks instead of one per tick.
const RECONNECT_BACKOFF_MAX_TICKS: u32 = 8;

/// Deadline for a heartbeat's own connect and hello exchange. Deliberately far
/// below the maker's idle budget and unrelated to `MAKER_RESPONSE_TIMEOUT_SECS`,
/// which is sized for block-bound contract replies: reconnects run on the shared
/// heartbeat thread, so a maker that accepts TCP and then withholds `MakerHello`
/// would otherwise stall the keepalives every other maker on the route depends on.
#[cfg(not(feature = "integration-test"))]
const HEARTBEAT_DIAL_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "integration-test")]
const HEARTBEAT_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// How a heartbeat peer reaches its maker.
#[derive(Clone, Copy)]
pub(crate) struct PeerDial {
    /// Clearnet or Tor, from the taker's config.
    pub(crate) connection_type: ConnectionType,
    /// Tor SOCKS port, ignored for clearnet.
    pub(crate) socks_port: u16,
    /// Protocol the maker must support for this swap.
    pub(crate) protocol: ProtocolVersion,
}

/// One maker in the route, with its keepalive stream and reconnect state.
struct HeartbeatPeer {
    address: String,
    /// `None` while disconnected and waiting to retry.
    stream: Option<TcpStream>,
    /// Ticks still to wait before the next connect attempt.
    retry_in: u32,
    /// Ticks to wait after the next failure; doubles up to the ceiling.
    backoff: u32,
}

impl HeartbeatPeer {
    fn new(address: String) -> Self {
        Self {
            address,
            stream: None,
            retry_in: 0,
            backoff: RECONNECT_BACKOFF_MIN_TICKS,
        }
    }

    /// Reconnect if needed, then send one keepalive. Never returns an error:
    /// a heartbeat must not become a failure path of the swap.
    fn tick(&mut self, keepalive: &TakerToMakerMessage, dial: PeerDial, dial_timeout: Duration) {
        if self.stream.is_none() {
            if self.retry_in > 0 {
                self.retry_in -= 1;
                return;
            }
            match connect_to_maker(
                &self.address,
                dial.connection_type,
                dial.socks_port,
                dial_timeout,
            )
            .and_then(|mut stream| handshake_with_maker(&mut stream, dial.protocol).map(|_| stream))
            {
                Ok(stream) => {
                    log::debug!("route heartbeat: connected to {}", self.address);
                    self.stream = Some(stream);
                    self.backoff = RECONNECT_BACKOFF_MIN_TICKS;
                }
                Err(e) => {
                    log::debug!(
                        "route heartbeat: connect to {} failed, retrying in {} tick(s): {e:?}",
                        self.address,
                        self.backoff
                    );
                    self.retry_in = self.backoff;
                    self.backoff = (self.backoff * 2).min(RECONNECT_BACKOFF_MAX_TICKS);
                    return;
                }
            }
        }

        if let Some(stream) = self.stream.as_mut() {
            if let Err(e) = crate::utill::send_message(stream, keepalive) {
                // The maker may be perfectly alive with only this socket dead,
                // and the protocol reads run on a different connection, so they
                // would never notice. Drop it and reconnect on the next tick.
                log::debug!(
                    "route heartbeat: keepalive to {} failed, reconnecting: {e:?}",
                    self.address
                );
                self.stream = None;
                self.retry_in = 0;
                self.backoff = RECONNECT_BACKOFF_MIN_TICKS;
            }
        }
    }
}

/// Heartbeat that pings every maker in the route for the life of a swap.
///
/// The maker's idle timer only sees messages; while the taker negotiates one
/// hop, the other makers hear nothing and can read a live swap as dropped.
///
/// Each peer owns its own connection and repairs it: a dropped keepalive socket
/// is reconnected on the next tick, and a maker that cannot be reached is
/// retried with a doubling backoff rather than abandoned. Failures never
/// propagate — a dead maker fails the protocol's own reads soon enough, and the
/// heartbeat must not become a failure path of its own. But it must not go
/// silently deaf either: a socket that dies mid-swap used to starve that maker
/// for the rest of the swap while every write was discarded.
pub(crate) struct RouteHeartbeat {
    stop: mpsc::Sender<()>,
    handle: Option<JoinHandle<()>>,
}

impl RouteHeartbeat {
    /// Spawn the heartbeat thread. Connecting happens in the thread, so a maker
    /// that is unreachable at start is retried instead of dropped from the route.
    pub(crate) fn start(
        swap_id: &str,
        addresses: Vec<String>,
        dial: PeerDial,
    ) -> std::io::Result<Self> {
        let (stop, stop_rx) = mpsc::channel();
        let keepalive =
            crate::protocol::common_messages::TakerToMakerMessage::WaitingFundingConfirmation(
                swap_id.to_string(),
            );
        let handle = thread::Builder::new()
            .name("Route heartbeat".to_string())
            .spawn(move || {
                let mut peers: Vec<HeartbeatPeer> =
                    addresses.into_iter().map(HeartbeatPeer::new).collect();
                loop {
                    for peer in peers.iter_mut() {
                        if stop_rx.try_recv().is_ok() {
                            return;
                        }
                        peer.tick(&keepalive, dial, HEARTBEAT_DIAL_TIMEOUT);
                    }
                    match stop_rx.recv_timeout(super::api::ROUTE_HEARTBEAT_INTERVAL) {
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }
            })?;
        Ok(Self {
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for RouteHeartbeat {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(handle) = self.handle.take() {
            let thread = handle.thread().clone();
            crate::utill::log_shutdown_join_start("route_heartbeat", &thread);
            let result = handle.join();
            crate::utill::log_shutdown_join_done(
                "route_heartbeat",
                &thread,
                if result.is_ok() { "ok" } else { "panic" },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Shutdown, TcpListener};

    fn peer_on(address: &str) -> HeartbeatPeer {
        HeartbeatPeer::new(address.to_string())
    }

    fn test_dial() -> PeerDial {
        PeerDial {
            connection_type: ConnectionType::Clearnet,
            socks_port: 0,
            protocol: ProtocolVersion::Taproot,
        }
    }

    fn keepalive() -> TakerToMakerMessage {
        TakerToMakerMessage::WaitingFundingConfirmation("swap".to_string())
    }

    /// A maker that cannot be reached must be retried on a widening backoff
    /// rather than abandoned (the old code dropped it from the route entirely)
    /// or hammered once per tick.
    #[test]
    fn unreachable_peer_backs_off_instead_of_being_dropped() {
        // Binding and dropping a listener leaves a port nothing is accepting on.
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut peer = peer_on(&format!("127.0.0.1:{port}"));

        // First tick attempts immediately and fails, arming one tick of backoff.
        peer.tick(&keepalive(), test_dial(), HEARTBEAT_DIAL_TIMEOUT);
        assert!(peer.stream.is_none());
        assert_eq!(peer.retry_in, RECONNECT_BACKOFF_MIN_TICKS);

        // Backoff doubles per failed attempt and stops at the ceiling, so a
        // maker that is really gone costs one connect per ceiling ticks.
        let mut attempts = 0;
        for _ in 0..200 {
            let retrying = peer.retry_in == 0;
            peer.tick(&keepalive(), test_dial(), HEARTBEAT_DIAL_TIMEOUT);
            attempts += u32::from(retrying);
            assert!(peer.stream.is_none());
            assert!(peer.backoff <= RECONNECT_BACKOFF_MAX_TICKS);
        }
        assert!(
            attempts < 200,
            "peer retried every tick instead of backing off"
        );
        assert_eq!(peer.backoff, RECONNECT_BACKOFF_MAX_TICKS);
    }

    /// A maker that accepts TCP and then says nothing must not hold the shared
    /// heartbeat thread past the deadline we chose, because every other peer on
    /// the route is waiting its turn and its own idle budget is running.
    #[test]
    fn stalled_handshake_is_bounded_by_the_dial_timeout() {
        // Accept connections but never answer MakerHello.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let _silent = thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept() {
                held.push(stream);
            }
        });

        let dial_timeout = Duration::from_millis(300);
        let mut peer = peer_on(&address);
        let started = std::time::Instant::now();
        peer.tick(&keepalive(), test_dial(), dial_timeout);
        let elapsed = started.elapsed();

        assert!(
            elapsed < dial_timeout * 10,
            "a silent maker stalled the heartbeat for {:?}",
            elapsed
        );
        // The handshake read timed out, so no stream is kept and we back off.
        assert!(peer.stream.is_none());
        assert_eq!(peer.retry_in, RECONNECT_BACKOFF_MIN_TICKS);
    }

    /// The incident this guards: a keepalive socket dies mid-swap while the
    /// maker is alive. The protocol reads run on another connection and never
    /// notice, so the heartbeat must drop the dead stream and reconnect at once
    /// instead of discarding every write for the rest of the swap.
    #[test]
    fn dead_keepalive_socket_is_dropped_and_retried_immediately() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let stream = TcpStream::connect(&address).unwrap();
        // Shutting down our own write half makes the next send fail for sure.
        stream.shutdown(Shutdown::Write).unwrap();

        let mut peer = HeartbeatPeer {
            address,
            stream: Some(stream),
            retry_in: 0,
            backoff: RECONNECT_BACKOFF_MAX_TICKS,
        };
        peer.tick(&keepalive(), test_dial(), HEARTBEAT_DIAL_TIMEOUT);

        assert!(peer.stream.is_none(), "dead stream must not be kept");
        assert_eq!(peer.retry_in, 0, "reconnect must not wait out a backoff");
        assert_eq!(peer.backoff, RECONNECT_BACKOFF_MIN_TICKS);
    }
}
