//! Background service threads for the Taker.
//!
//! Owns the recovery, breach-detection, and route-heartbeat threads.
//! Each service signals and joins its thread before it is dropped.

use std::{
    collections::HashSet,
    net::TcpStream,
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
    protocol::common_messages::TakerToMakerMessage,
    taker::{
        api::{connect_to_maker, handshake_with_maker, ConnectionType},
        error::TakerError,
    },
    utill::HEART_BEAT_INTERVAL,
    wallet::{blockchain::BackendConnector, AnyBlockchain, Blockchain, Wallet, WalletError},
    watch_tower::{service::WatchService, watcher::WatcherEvent},
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
/// when contracts remain unresolved (e.g. timelocks not yet mature).
pub(crate) struct RecoveryLoop {
    shutdown: Arc<AtomicBool>,
    complete: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl RecoveryLoop {
    /// Spawn the background recovery thread.
    ///
    /// Each pass selects stored coins outside the active swap.
    pub(crate) fn start(
        wallet: Arc<RwLock<Wallet>>,
        backend: BackendConnector,
        live_swap: Arc<Mutex<Option<String>>>,
        watch_service: WatchService,
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
                // Kept across passes: every fresh connection costs a handshake,
                // and public servers rate-limit per connection. A dropped one is
                // rebuilt inside the backend on its next call.
                let mut held: Option<AnyBlockchain> = None;
                // Set by a failed fallback height read on Electrum; see below.
                let mut deferring = false;
                while !shutdown_clone.load(Relaxed) {
                    let scope = Self::scope(&live_swap, &wallet)
                        .inspect_err(|e| log::warn!("Recovery loop: scope: {e}"))
                        .ok();
                    let Some((swap_ids, incoming_contract_txids)) = scope else {
                        thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                        continue;
                    };
                    if swap_ids.is_empty() {
                        log::info!("Recovery loop: no abandoned swaps remain");
                        complete_clone.store(true, Relaxed);
                        return;
                    }

                    // The chain only moves with a block, so a pass waits for one. The
                    // watcher hears each block; asking the server is the fallback. It
                    // uses the loop's own connection: a slow server must not hold the
                    // wallet lock. After it fails on Electrum, a live watcher is already
                    // retrying the same server and publishes a height once it answers, so
                    // the fallback waits for that instead.
                    let mut tip_refreshed = false;
                    let tip = match watch_service.tip() {
                        Some(height) => {
                            deferring = false;
                            Some(height)
                        }
                        None if deferring && watch_service.is_alive() => None,
                        None => {
                            let height = held
                                .take()
                                .map_or_else(|| backend.connect(), Ok)
                                .and_then(|chain| {
                                    let height = chain.get_block_count()?;
                                    held = Some(chain);
                                    tip_refreshed = true;
                                    Ok(height)
                                })
                                .inspect_err(|e| {
                                    log::warn!("Recovery loop: block height: {:?}", e)
                                })
                                .ok();
                            deferring = height.is_none() && backend.is_electrum();
                            height
                        }
                    };
                    let Some(tip) = tip.filter(|&tip| last_tip.replace(tip) != Some(tip)) else {
                        thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                        continue;
                    };

                    // One connection shared by both steps below and by later passes:
                    // on Tor Electrum each fresh connection costs a circuit handshake.
                    let chain: &AnyBlockchain = match held.take().map_or_else(|| backend.connect(), Ok) {
                        Ok(chain) => held.insert(chain),
                        Err(e) => {
                            log::warn!("Recovery loop: no connection: {:?}", e);
                            // A dropped circuit is passing; retry on the next interval.
                            last_tip = None;
                            thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                            continue;
                        }
                    };
                    // The watcher may have observed the new block on a
                    // different connection. Refresh this backend's tip before
                    // consulting its script and header caches, unless the
                    // fallback above just read it on this connection.
                    if let Err(e) = (!tip_refreshed)
                        .then(|| chain.get_block_count())
                        .transpose()
                    {
                        log::warn!("Recovery loop: block height: {:?}", e);
                        last_tip = None;
                        thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                        continue;
                    }

                    // Sweeps and timelock refunds in one pass. It takes the lock itself
                    // and drops it across its wait, so a stuck tx cannot wedge the wallet.
                    match Wallet::recover_swapcoins(
                        &wallet,
                        chain,
                        &shutdown_clone,
                        &incoming_contract_txids,
                        &swap_ids,
                        &|_| true,
                        &|_| false,
                    ) {
                        Ok((swept, recovered)) if !swept.is_empty() || !recovered.is_empty() => {
                            log::info!(
                                "Recovery loop: swept {} incoming swapcoins, recovered {} timelocked swapcoins",
                                swept.resolved.len(),
                                recovered.len()
                            );
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
                            "Recovery loop: contracts still unresolved at height {tip}, retrying on the next block"
                        );
                    } else {
                        log::info!("Recovery loop: all contracts resolved");
                        // Every contract has a confirmed spend, so a stale incoming
                        // entry left by a crash after its sweep goes with the rest.
                        // A failed save keeps the coins for the next pass.
                        let saved = lock_debug!(wallet.write()).is_ok_and(|mut w| {
                            swap_ids.iter().all(|swap_id| {
                                w.remove_swap_coins_and_save(swap_id, true, true)
                                    .inspect_err(|e| {
                                        log::warn!("Recovery loop: cleanup save: {:?}", e)
                                    })
                                    .is_ok()
                            })
                        });
                        if !saved {
                            last_tip = None;
                            thread::park_timeout(RECOVERY_LOOP_INTERVAL);
                            continue;
                        }

                        let more_failed_swaps = Self::scope(&live_swap, &wallet)
                            .map(|(ids, _)| !ids.is_empty())
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

    /// Snapshot the wallet while the active swap cannot change ownership.
    pub(crate) fn scope(
        live_swap: &Mutex<Option<String>>,
        wallet: &RwLock<Wallet>,
    ) -> std::io::Result<(HashSet<String>, HashSet<Txid>)> {
        let live = lock_debug!(live_swap.lock())
            .map_err(|_| std::io::Error::other("live swap lock poisoned"))?;
        let wallet = lock_debug!(wallet.read())
            .map_err(|_| std::io::Error::other("wallet lock poisoned"))?;
        let mut swap_ids = wallet.onchain_swap_ids();
        if let Some(id) = live.as_ref() {
            swap_ids.remove(id);
        }
        let incoming_txids = wallet
            .incoming_contract_outpoints(Some(&swap_ids))
            .into_iter()
            .map(|(outpoint, _)| outpoint.txid)
            .collect();
        Ok((swap_ids, incoming_txids))
    }

    /// A failed save keeps the swap excluded from recovery.
    pub(crate) fn finish_handover(
        wallet: &Wallet,
        live: &mut Option<String>,
    ) -> Result<(), WalletError> {
        wallet.save_to_disk()?;
        *live = None;
        Ok(())
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
/// heartbeat thread, so a maker that accepts TCP and then withholds its `Hello`
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
}

/// One maker in the route, with its keepalive stream and reconnect state.
struct HeartbeatPeer {
    address: String,
    /// Names the maker's Hello must list for this swap.
    needed: Vec<String>,
    /// `None` while disconnected and waiting to retry.
    stream: Option<TcpStream>,
    /// Ticks still to wait before the next connect attempt.
    retry_in: u32,
    /// Ticks to wait after the next failure; doubles up to the ceiling.
    backoff: u32,
}

impl HeartbeatPeer {
    fn new((address, needed): (String, Vec<String>)) -> Self {
        Self {
            address,
            needed,
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
            .and_then(|mut stream| handshake_with_maker(&mut stream, &self.needed).map(|_| stream))
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
        peers: Vec<(String, Vec<String>)>,
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
                    peers.into_iter().map(HeartbeatPeer::new).collect();
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
    use crate::wallet::{
        swapcoin::{IncomingSwapCoin, OutgoingSwapCoin, WatchOnlySwapCoin},
        test_wallet, LnMakerDirection, LnMakerPhase, LnMakerSwapRecord, LnPendingSwap,
    };
    use bitcoin::{
        absolute::LockTime,
        hashes::{sha256, Hash},
        secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey},
        transaction::Version,
        Amount, PublicKey, Transaction, TxOut,
    };
    use std::net::{Shutdown, TcpListener};

    fn outgoing_for(id: &str, locktime: u32) -> OutgoingSwapCoin {
        let key = SecretKey::from_slice(&[1; 32]).unwrap();
        let other = PublicKey::new(SecpPublicKey::from_secret_key(&Secp256k1::new(), &key));
        let mut coin = OutgoingSwapCoin::new_legacy(
            key,
            other,
            Transaction {
                version: Version::TWO,
                lock_time: LockTime::from_consensus(locktime),
                input: Vec::new(),
                output: vec![TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::new(),
                }],
            },
            ScriptBuf::new(),
            key,
            Amount::from_sat(10_000),
            1,
        );
        coin.swap_id = Some(id.to_owned());
        coin
    }

    fn incoming_for(id: &str, locktime: u32) -> IncomingSwapCoin {
        let outgoing = outgoing_for(id, locktime);
        let key = outgoing.my_privkey.unwrap();
        let mut coin = IncomingSwapCoin::new_legacy(
            key,
            outgoing.other_pubkey.unwrap(),
            outgoing.contract_tx,
            ScriptBuf::new(),
            key,
            outgoing.funding_amount,
            1,
        );
        coin.swap_id = Some(id.to_owned());
        coin
    }

    fn watchonly_for(id: &str, locktime: u32) -> WatchOnlySwapCoin {
        let outgoing = outgoing_for(id, locktime);
        WatchOnlySwapCoin::new_legacy(
            outgoing.my_pubkey.unwrap(),
            outgoing.other_pubkey.unwrap(),
            outgoing.contract_tx,
            ScriptBuf::new(),
            outgoing.funding_amount,
        )
    }

    #[test]
    fn compat_recovery_scope_excludes_live_coins_until_durable_handover() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = test_wallet(&dir.path().join("wallet"));
        wallet.add_outgoing_swapcoin(&outgoing_for("failed", 1));
        let failed_incoming = incoming_for("failed", 3);
        let failed_txid = failed_incoming.contract_tx.compute_txid();
        wallet.add_incoming_swapcoin(&failed_incoming);
        let wallet = RwLock::new(wallet);
        let live = Mutex::new(Some("prepared".to_owned()));
        assert_eq!(
            RecoveryLoop::scope(&live, &wallet).unwrap().0,
            HashSet::from(["failed".to_owned()])
        );
        let live_incoming = incoming_for("prepared", 4);
        let live_txid = live_incoming.contract_tx.compute_txid();
        {
            let mut wallet = wallet.write().unwrap();
            wallet.add_outgoing_swapcoin(&outgoing_for("prepared", 2));
            wallet.add_incoming_swapcoin(&live_incoming);
            wallet.add_watchonly_swapcoins("prepared", vec![watchonly_for("prepared", 5)]);
            wallet.save_to_disk().unwrap();
        }
        assert_eq!(
            RecoveryLoop::scope(&live, &wallet).unwrap().1,
            HashSet::from([failed_txid])
        );
        assert_eq!(
            RecoveryLoop::scope(&live, &wallet).unwrap().0,
            HashSet::from(["failed".to_owned()])
        );
        {
            let mut guard = live.lock().unwrap();
            let wallet = wallet.read().unwrap();
            RecoveryLoop::finish_handover(&wallet, &mut guard).unwrap();
        }
        assert_eq!(
            RecoveryLoop::scope(&live, &wallet).unwrap().0,
            HashSet::from(["failed".to_owned(), "prepared".to_owned()])
        );
        assert_eq!(
            RecoveryLoop::scope(&live, &wallet).unwrap().1,
            HashSet::from([failed_txid, live_txid])
        );
    }

    #[test]
    fn compat_handover_save_failure_keeps_the_live_slot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let wallet = test_wallet(&path);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let mut live = Some("unsaved".to_owned());
        assert!(RecoveryLoop::finish_handover(&wallet, &mut live).is_err());
        assert_eq!(live.as_deref(), Some("unsaved"));
        std::fs::remove_dir(path).unwrap();
        RecoveryLoop::finish_handover(&wallet, &mut live).unwrap();
        assert!(live.is_none());
    }

    #[test]
    fn compat_recovery_scope_includes_watchonly_and_claim_ready_coins_but_excludes_lightning() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = test_wallet(&dir.path().join("wallet"));
        let mut outgoing = outgoing_for("claimed-outgoing", 1);
        outgoing.hash_preimage = Some([7; 32]);
        outgoing.committed = true;
        outgoing.incoming_claimed = true;
        wallet.add_outgoing_swapcoin(&outgoing);
        let mut incoming = incoming_for("incoming-only", 2);
        incoming.other_privkey = incoming.my_privkey;
        let incoming_txid = incoming.contract_tx.compute_txid();
        wallet.add_incoming_swapcoin(&incoming);
        wallet.add_watchonly_swapcoins("watchonly-only", vec![watchonly_for("watchonly-only", 3)]);
        let key = SecretKey::from_slice(&[1; 32]).unwrap();
        wallet.store.ln_pending_swaps.insert(
            "pending-lightning".into(),
            LnPendingSwap {
                is_swap_in: true,
                preimage: None,
                redeemscript: ScriptBuf::new(),
                locktime: 100,
                privkey: key,
                outpoint: None,
                value: None,
            },
        );
        wallet.store.ln_maker_swaps.insert(
            "maker-lightning".into(),
            LnMakerSwapRecord {
                direction: LnMakerDirection::SwapIn,
                phase: LnMakerPhase::InAccepted,
                payment_hash: sha256::Hash::hash(&[1]),
                amount: Amount::from_sat(10_000),
                fee: Amount::ZERO,
                locktime: 100,
                min_confirmations: 1,
                redeemscript: ScriptBuf::new(),
                privkey: key,
                invoice: "pending".into(),
                preimage: None,
                refund_txid: None,
                accepted_height: None,
                payout_script: None,
                funding_outpoint: None,
                funding_value: None,
                funding_height: None,
            },
        );
        let wallet = RwLock::new(wallet);
        let live = Mutex::new(None);
        assert_eq!(
            RecoveryLoop::scope(&live, &wallet).unwrap(),
            (
                HashSet::from([
                    "claimed-outgoing".to_owned(),
                    "incoming-only".to_owned(),
                    "watchonly-only".to_owned()
                ]),
                HashSet::from([incoming_txid]),
            )
        );
        *live.lock().unwrap() = Some("watchonly-only".into());
        assert_eq!(
            RecoveryLoop::scope(&live, &wallet).unwrap().0,
            HashSet::from(["claimed-outgoing".to_owned(), "incoming-only".to_owned()])
        );
    }

    #[test]
    fn compat_unfunded_abort_preserves_scope_until_its_coin_removal_is_saved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let mut wallet = test_wallet(&path);
        wallet.add_outgoing_swapcoin(&outgoing_for("failed", 1));
        wallet.add_outgoing_swapcoin(&outgoing_for("prepared", 2));
        wallet.add_incoming_swapcoin(&incoming_for("prepared", 3));
        wallet.add_watchonly_swapcoins("prepared", vec![watchonly_for("prepared", 4)]);
        wallet.save_to_disk().unwrap();
        let original = std::fs::read(&path).unwrap();
        let snapshot = dir.path().join("snapshot");
        std::fs::rename(&path, &snapshot).unwrap();
        std::fs::create_dir(&path).unwrap();
        let wallet = RwLock::new(wallet);
        let live = Mutex::new(Some("prepared".to_owned()));
        {
            let mut guard = live.lock().unwrap();
            let mut wallet = wallet.write().unwrap();
            assert!(wallet
                .remove_swap_coins_and_save("prepared", true, true)
                .is_err());
            assert_eq!(guard.as_deref(), Some("prepared"));
            assert_eq!(wallet.get_incoming_swapcoins_count(), 1);
            assert_eq!(wallet.get_outgoing_swapcoins_count(), 2);
            assert_eq!(wallet.watchonly_contract_outpoints().len(), 1);
            assert!(RecoveryLoop::finish_handover(&wallet, &mut guard).is_err());
        }
        assert_eq!(std::fs::read(&snapshot).unwrap(), original);
        assert_eq!(
            RecoveryLoop::scope(&live, &wallet).unwrap().0,
            HashSet::from(["failed".to_owned()])
        );
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(snapshot, &path).unwrap();
        {
            let mut guard = live.lock().unwrap();
            let mut wallet = wallet.write().unwrap();
            wallet
                .remove_swap_coins_and_save("prepared", true, true)
                .unwrap();
            RecoveryLoop::finish_handover(&wallet, &mut guard).unwrap();
            assert_eq!(wallet.get_incoming_swapcoins_count(), 0);
            assert_eq!(wallet.get_outgoing_swapcoins_count(), 1);
            assert!(wallet.watchonly_contract_outpoints().is_empty());
        }
        assert!(live.lock().unwrap().is_none());
        assert_eq!(
            RecoveryLoop::scope(&live, &wallet).unwrap().0,
            HashSet::from(["failed".to_owned()])
        );
    }

    fn peer_on(address: &str) -> HeartbeatPeer {
        HeartbeatPeer::new((address.to_string(), Vec::new()))
    }

    fn test_dial() -> PeerDial {
        PeerDial {
            connection_type: ConnectionType::Clearnet,
            socks_port: 0,
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
        // Accept connections but never answer the Hello.
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
            needed: Vec::new(),
            stream: Some(stream),
            retry_in: 0,
            backoff: RECONNECT_BACKOFF_MAX_TICKS,
        };
        peer.tick(&keepalive(), test_dial(), HEARTBEAT_DIAL_TIMEOUT);

        assert!(peer.stream.is_none(), "dead stream must not be kept");
        assert_eq!(peer.retry_in, 0, "reconnect must not wait out a backoff");
        assert_eq!(peer.backoff, RECONNECT_BACKOFF_MIN_TICKS);
    }

    /// A live watcher that cannot tell whether a sentinel was spent must not
    /// read as "unspent": the swap has to abort.
    #[test]
    fn unknown_watcher_answer_requires_abort() {
        use crate::{
            wallet::{CoreRPC, CoreRpcConfig},
            watch_tower::service::answering,
        };
        use bitcoin::hashes::Hash;
        use std::time::Instant;

        let service = answering(WatcherEvent::Error("not subscribed".to_string()));
        // Only asked once the watcher is gone, which it never is here.
        let backend = AnyBlockchain::CoreRPC(
            CoreRPC::new(&CoreRpcConfig {
                url: "127.0.0.1:0".to_string(),
                ..CoreRpcConfig::default()
            })
            .unwrap(),
        );
        let detector = BreachDetector::start(service.clone(), backend).unwrap();
        let outpoint = OutPoint::new(Txid::all_zeros(), 0);
        detector
            .add_sentinels(&service, &[(outpoint, Txid::all_zeros(), ScriptBuf::new())])
            .unwrap();

        let deadline = Instant::now() + HEART_BEAT_INTERVAL * 4;
        while !detector.requires_abort() {
            assert!(
                Instant::now() < deadline,
                "an unknown answer did not abort the swap"
            );
            thread::sleep(Duration::from_millis(20));
        }
        assert!(!detector.is_breached());
        detector.stop();
        service.shutdown();
    }

    /// Unknown is no verdict, so it must not stick: once the watcher can
    /// answer again, a pass that finds no breach clears the abort.
    #[test]
    fn abort_flag_clears_once_the_watcher_answers() {
        use crate::{
            wallet::{CoreRPC, CoreRpcConfig},
            watch_tower::service::answering_with,
        };
        use bitcoin::hashes::Hash;
        use std::time::Instant;

        let outpoint = OutPoint::new(Txid::all_zeros(), 0);
        let server_down = Arc::new(AtomicBool::new(true));
        let down = server_down.clone();
        let service = answering_with(move || {
            if down.load(Relaxed) {
                WatcherEvent::Error("server down".to_string())
            } else {
                WatcherEvent::UtxoSpent {
                    outpoint,
                    spending_tx: None,
                }
            }
        });
        // Only asked once the watcher is gone, which it never is here.
        let backend = AnyBlockchain::CoreRPC(
            CoreRPC::new(&CoreRpcConfig {
                url: "127.0.0.1:0".to_string(),
                ..CoreRpcConfig::default()
            })
            .unwrap(),
        );
        let detector = BreachDetector::start(service.clone(), backend).unwrap();
        detector
            .add_sentinels(&service, &[(outpoint, Txid::all_zeros(), ScriptBuf::new())])
            .unwrap();
        let wait_for = |abort: bool| {
            let deadline = Instant::now() + HEART_BEAT_INTERVAL * 4;
            while detector.requires_abort() != abort {
                assert!(
                    Instant::now() < deadline,
                    "requires_abort never became {}",
                    abort
                );
                thread::sleep(Duration::from_millis(20));
            }
        };

        wait_for(true);
        server_down.store(false, Relaxed);
        wait_for(false);
        assert!(!detector.is_breached());
        detector.stop();
        service.shutdown();
    }
}
