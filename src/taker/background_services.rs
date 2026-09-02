//! Background service threads for the Taker.
//!
//! Owns the recovery, breach-detection, and route-heartbeat threads.
//! Each service signals and joins its thread before it is dropped.

use std::{
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
    taker::error::TakerError,
    utill::HEART_BEAT_INTERVAL,
    wallet::{AnyBlockchain, Blockchain, RecoveryReport, Wallet},
    watch_tower::{service::WatchService, watcher::WatcherEvent},
};

use super::swap_tracker::{ContractOutcome, ContractResolution, RecoveryPhase, SwapTracker};

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
    /// The `swap_tracker` is used to update per-contract resolution outcomes
    /// as contracts are resolved in the background.
    pub(crate) fn start(
        wallet: Arc<RwLock<Wallet>>,
        swap_tracker: Arc<Mutex<SwapTracker>>,
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
                while !shutdown_clone.load(Relaxed) {
                    // One connection per pass, shared by all three steps below:
                    // on Tor Electrum each fresh connection costs a circuit handshake.
                    let chain = match lock_debug!(wallet.read()) {
                        Ok(w) => match w.blockchain.new_connection() {
                            Ok(chain) => chain,
                            Err(e) => {
                                log::warn!("Recovery loop: no connection: {:?}", e);
                                thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                                continue;
                            }
                        },
                        Err(_) => {
                            thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                            continue;
                        }
                    };

                    // Try hashlock sweep (incoming). It takes the lock itself and drops
                    // it across its waits, so a stuck tx cannot wedge the wallet.
                    let incoming_result = match Wallet::sweep_incoming_swapcoins(
                        &wallet,
                        &chain,
                        2.0,
                        &shutdown_clone,
                        None,
                    ) {
                        Ok(ref swept) if !swept.is_empty() => {
                            log::info!(
                                "Recovery loop: swept {} incoming swapcoins",
                                swept.resolved.len()
                            );
                            Some(swept.clone())
                        }
                        Err(e) => {
                            log::debug!("Recovery loop: incoming sweep: {:?}", e);
                            None
                        }
                        _ => None,
                    };

                    // Try timelock recovery (outgoing). Same deal — it manages the
                    // lock itself and never holds it across a confirmation wait.
                    let outgoing_result = match Wallet::recover_timelocked_swapcoins(
                        &wallet,
                        &chain,
                        2.0,
                        &shutdown_clone,
                    ) {
                        Ok(ref recovered) if !recovered.is_empty() => {
                            log::info!(
                                "Recovery loop: recovered {} timelocked swapcoins",
                                recovered.len()
                            );
                            Some(recovered.clone())
                        }
                        Err(e) => {
                            log::debug!("Recovery loop: timelock recovery: {:?}", e);
                            None
                        }
                        _ => None,
                    };

                    // Update tracker outcomes from recovery results
                    if incoming_result.is_some() || outgoing_result.is_some() {
                        if let Ok(mut tracker) = lock_debug!(swap_tracker.lock()) {
                            Self::update_tracker_outcomes(
                                &mut tracker,
                                incoming_result.as_ref(),
                                outgoing_result.as_ref(),
                            );
                        }
                    }

                    // Snapshot the outpoints, then drop the guard: the checks below
                    // are backend calls and must not hold the wallet.
                    let outpoints = match lock_debug!(wallet.read()) {
                        Ok(w) => {
                            let mut outpoints = w.outgoing_contract_outpoints();
                            outpoints.extend(w.incoming_contract_outpoints());
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
                            "Recovery loop: contracts still unresolved, retrying in {}s",
                            RECOVERY_LOOP_INTERVAL.as_secs()
                        );
                    } else {
                        log::info!("Recovery loop: all contracts resolved");
                        // Clean up wallet entries and update tracker
                        let swap_ids: Vec<String> = lock_debug!(swap_tracker.lock())
                            .ok()
                            .map(|t| {
                                t.incomplete_swaps()
                                    .iter()
                                    .map(|r| r.swap_id.clone())
                                    .collect()
                            })
                            .unwrap_or_default();

                        if let Ok(mut w) = lock_debug!(wallet.write()) {
                            for swap_id in &swap_ids {
                                let keys = w.outgoing_keys_for_swap(swap_id);
                                for key in &keys {
                                    w.remove_outgoing_swapcoin(key);
                                }
                                w.remove_watchonly_swapcoins(swap_id);
                            }
                            let _ = w.save_to_disk();
                        }

                        if let Ok(mut tracker) = lock_debug!(swap_tracker.lock()) {
                            // Emit recovery reports before marking as cleaned up
                            for record in tracker.incomplete_swaps() {
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
    fn update_tracker_outcomes(
        tracker: &mut SwapTracker,
        incoming: Option<&crate::wallet::RecoveryOutcome>,
        outgoing: Option<&crate::wallet::RecoveryOutcome>,
    ) {
        let swap_ids: Vec<String> = tracker
            .incomplete_swaps()
            .iter()
            .map(|r| r.swap_id.clone())
            .collect();

        for swap_id in swap_ids {
            let mut changed = false;

            let _ = tracker.update_and_save(&swap_id, |record| {
                // Update incoming outcomes from sweep results
                if let Some(swept) = incoming {
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
                }

                // Update outgoing outcomes from timelock recovery results
                if let Some(recovered) = outgoing {
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

/// Heartbeat that pings every maker in the route for the life of a swap.
///
/// The maker's idle timer only sees messages; while the taker negotiates one
/// hop, the other makers hear nothing and can read a live swap as dropped.
/// Send failures are ignored — a dead maker fails the protocol's own reads
/// soon enough, and the heartbeat must not become a failure path of its own.
pub(crate) struct RouteHeartbeat {
    stop: mpsc::Sender<()>,
    handle: Option<JoinHandle<()>>,
}

impl RouteHeartbeat {
    /// Spawn the heartbeat thread over pre-connected, handshaked streams.
    pub(crate) fn start(swap_id: &str, streams: Vec<std::net::TcpStream>) -> std::io::Result<Self> {
        let (stop, stop_rx) = mpsc::channel();
        let keepalive =
            crate::protocol::common_messages::TakerToMakerMessage::WaitingFundingConfirmation(
                swap_id.to_string(),
            );
        let handle = thread::Builder::new()
            .name("Route heartbeat".to_string())
            .spawn(move || {
                let mut streams = streams;
                loop {
                    for stream in streams.iter_mut() {
                        if stop_rx.try_recv().is_ok() {
                            return;
                        }
                        let _ = crate::utill::send_message(stream, &keepalive);
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
