//! Watchtower watcher module.
//!
//! Runs the core event loop, processes watcher commands, reacts to ZMQ backend events,
//! spawns optional RPC-based discovery and updates the on-disk registry of watches and fidelity records.

use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver as StdReceiver, RecvTimeoutError},
        Arc,
    },
    thread,
};

use bitcoin::{consensus::deserialize, Block, Network, OutPoint, ScriptBuf, Transaction};
use crossbeam_channel::Sender as CbSender;

use crate::{
    utill::HEART_BEAT_INTERVAL,
    wallet::{blockchain::WatchEvent, AnyBlockchain, Blockchain},
    watch_tower::{
        nostr,
        registry_storage::FileRegistry,
        utils::{process_block, process_transaction},
        watcher_error::WatcherError,
    },
};

/// Describes watcher behavior.
pub trait Role {
    /// Enables or disables discovery.
    const RUN_DISCOVERY: bool;
}

/// Drives the watchtower event loop, coordinating backend events and client commands.
pub struct Watcher<R: Role> {
    blockchain: AnyBlockchain,
    registry: FileRegistry,
    rx_requests: StdReceiver<WatcherCommand>,
    nostr_relays: Vec<String>,
    nostr_tor_config: Option<(u16, String)>,
    /// Watches whose script-subscribe failed; without a retry they stay
    /// undetected until restart. Retried on every event-loop pass.
    pending_subscribes: Vec<(OutPoint, ScriptBuf)>,
    /// Set by `WatchService::shutdown`; long scans check it per iteration so a
    /// deep rescan cannot stall the join.
    shutdown: Arc<AtomicBool>,
    _role: PhantomData<R>,
}

/// Events emitted by the watcher to its clients.
#[derive(Debug, Clone)]
pub enum WatcherEvent {
    /// Indicates that a watched outpoint was spent.
    UtxoSpent {
        /// Monitored outpoint.
        outpoint: OutPoint,
        /// Transaction that spent the outpoint, if known.
        spending_tx: Option<Transaction>,
    },
    /// Returned when a queried outpoint is not being watched.
    NoOutpoint,
    /// Returned when the watcher could not answer a query. Keeps the
    /// one-reply-per-request contract so blocking callers never hang.
    Error(String),
}

/// Commands accepted by the watcher from clients.
#[derive(Debug, Clone)]
pub enum WatcherCommand {
    /// Store a new watch request.
    RegisterWatchRequest {
        /// Outpoint to begin tracking.
        outpoint: OutPoint,
        /// `scriptPubKey` of the outpoint, used to arm the Electrum per-script subscription.
        script_pubkey: ScriptBuf,
    },
    /// Re-arm every watch from the wallet's live contracts after a restart.
    /// One command for the whole set, so the command drain is not flooded.
    RebuildWatches {
        /// Contract outpoints and their `scriptPubKey`s.
        watches: Vec<(OutPoint, ScriptBuf)>,
        /// Answered once the rebuild (Core rescan included) finishes, so
        /// startup blocks until the watches are armed instead of racing it.
        reply: CbSender<Result<(), String>>,
    },
    /// Query whether an outpoint has been spent.
    WatchRequest {
        /// Outpoint being queried.
        outpoint: OutPoint,
        /// Channel this query alone is answered on. A shared one lets two
        /// concurrent callers consume each other's replies.
        reply: CbSender<WatcherEvent>,
    },
    /// Remove an existing watch.
    Unwatch {
        /// Outpoint to stop tracking.
        outpoint: OutPoint,
        /// `scriptPubKey` of the outpoint, used to drop the Electrum subscription.
        script_pubkey: ScriptBuf,
    },
    /// Terminate the watcher loop.
    Shutdown,
}

impl<R: Role> Watcher<R> {
    /// Creates a watcher with its backend, registry, and communication channels.
    pub fn new(
        blockchain: AnyBlockchain,
        registry: FileRegistry,
        rx_requests: StdReceiver<WatcherCommand>,
        nostr_relays: Vec<String>,
        nostr_tor_config: Option<(u16, String)>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            blockchain,
            registry,
            rx_requests,
            nostr_relays,
            nostr_tor_config,
            pending_subscribes: Vec::new(),
            shutdown,
            _role: PhantomData,
        }
    }

    /// Runs the watcher loop: handles ZMQ events and commands, optionally spawning discovery.
    pub fn run(&mut self, initial_sync_complete: Arc<AtomicBool>) -> Result<(), WatcherError> {
        log::info!("Watcher initiated");

        // Detect network from the chain name.
        let network = match self.blockchain.chain_name()?.as_str() {
            "main" => Network::Bitcoin,
            "test" => Network::Testnet,
            "testnet4" => Network::Testnet4,
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            unknown => {
                return Err(WatcherError::General(format!(
                    "Unsupported Bitcoin network: {unknown}"
                )))
            }
        };

        // Establish the Core ZMQ Connection.
        if let AnyBlockchain::CoreRPC(core) = &self.blockchain {
            if let Err(e) = core.prime_subscription() {
                log::warn!("Failed to prime ZMQ subscription on startup: {e}");
            }
        }

        // Startup catch-up
        // Core: Process the node's mempool.
        if let Err(e) = self.process_mempool() {
            log::warn!("Failed to process mempool on startup: {e}");
        }
        // The registry is memory-only, so there is nothing persisted to
        // re-subscribe here. Watches arrive via `RebuildWatches` instead.
        #[cfg(debug_assertions)]
        log::debug!(
            "[WATCH_STATE] Source: watch_tower::watcher::run | Action: watcher_ready | Network: {} | Discovery: {}",
            network,
            R::RUN_DISCOVERY
        );

        // Discovery is part of the watcher lifetime. Sharing the owner flag
        // lets taker shutdown interrupt relay processing immediately, even if
        // the watcher event loop is still finishing its current backend call.
        let discovery_shutdown = self.shutdown.clone();
        let registry = self.registry.clone();
        let nostr_relays = self.nostr_relays.clone();
        let nostr_tor_config = self.nostr_tor_config.clone();
        std::thread::scope(move |s| -> Result<(), WatcherError> {
            let shutdown_clone = discovery_shutdown.clone();
            let mut discovery_handle = None;
            if R::RUN_DISCOVERY {
                if let Some(nostr_tor_config) = nostr_tor_config {
                    // Discovery requires it's own dedicated backend to not overlap with regular watch requests.
                    let chain = self
                        .blockchain
                        .new_connection_with_shutdown(discovery_shutdown.clone())?;
                    // The thread runs until shutdown, so its outcome is only
                    // known at the join below.
                    discovery_handle = Some(s.spawn(move || {
                        let result = nostr::run_discovery(
                            chain,
                            network,
                            registry,
                            discovery_shutdown.clone(),
                            initial_sync_complete,
                            &nostr_relays,
                            nostr_tor_config,
                        );
                        if let Err(e) = &result {
                            log::error!("Discovery thread failed: {e:?}");
                        }
                        result
                    }));
                }
            }
            'event_loop: loop {
                if self.shutdown.load(Ordering::Relaxed) {
                    break 'event_loop;
                }
                // The timeout is the idle wait, so a queued command is picked up
                // at once instead of after a full heartbeat.
                match self.rx_requests.recv_timeout(HEART_BEAT_INTERVAL) {
                    Ok(cmd) => {
                        if !self.handle_command(cmd) {
                            break 'event_loop;
                        }
                        // Drain the burst in the same pass; N queued commands
                        // cost one tick instead of N.
                        while !self.shutdown.load(Ordering::Relaxed) {
                            let Ok(cmd) = self.rx_requests.try_recv() else {
                                break;
                            };
                            if !self.handle_command(cmd) {
                                break 'event_loop;
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break 'event_loop,
                }

                // Drain pending events too: one per pass would leave the
                // notification buffer lagging a busy mempool by a heartbeat each.
                while !self.shutdown.load(Ordering::Relaxed) {
                    let Some(event) = self.blockchain.poll_event() else {
                        break;
                    };
                    self.handle_event(event);
                }
                // A failed script-subscribe retries on every pass, not just
                // idle ticks; with an empty queue this is a no-op.
                self.retry_subscribes();
            }

            // Stop and join the discovery thread on exit path.
            shutdown_clone.store(true, Ordering::SeqCst);
            if let Some(handle) = discovery_handle {
                let thread = handle.thread().clone();
                crate::utill::log_shutdown_join_start("watcher", &thread);
                // join() nests two results: the panic payload, then discovery's own error.
                // The first `?` surfaces a panic, the second discovery's WatcherError.
                let result = handle.join();
                crate::utill::log_shutdown_join_done(
                    "watcher",
                    &thread,
                    if result.is_ok() { "ok" } else { "panic" },
                );
                result.map_err(|payload| {
                    // pull out the panic message by downcast.
                    let msg = payload
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown payload".to_string());
                    WatcherError::General(format!("Discovery thread panicked: {msg}"))
                })??;
            }
            Ok(())
        })
    }

    fn handle_command(&mut self, cmd: WatcherCommand) -> bool {
        match cmd {
            WatcherCommand::RegisterWatchRequest {
                outpoint,
                script_pubkey,
            } => {
                log::info!("Intercepted register watch request: {outpoint}");
                // Merges into an existing entry so a duplicate registration
                // cannot erase a spend the watcher already recorded.
                if let Err(e) = self
                    .registry
                    .register_watch(outpoint, script_pubkey.clone())
                {
                    log::error!("registry lock poisoned, watch not stored: {e:?}");
                }
                if let Err(e) = self.blockchain.subscribe_script(&script_pubkey, outpoint) {
                    log::error!("electrum script-subscribe failed for {outpoint}: {e}");
                    self.pending_subscribes.push((outpoint, script_pubkey));
                }
            }
            WatcherCommand::RebuildWatches { watches, reply } => {
                log::info!("Rebuilding {} watches from the wallet", watches.len());
                for (outpoint, spk) in &watches {
                    if self.shutdown.load(Ordering::Relaxed) {
                        // Reply before bailing out: the caller blocks on it.
                        _ = reply.send(Ok(()));
                        return false;
                    }
                    if let Err(e) = self.registry.register_watch(*outpoint, spk.clone()) {
                        log::error!("registry lock poisoned, watch not stored: {e:?}");
                    }
                    if let Err(e) = self.blockchain.subscribe_script(spk, *outpoint) {
                        log::error!("electrum script-subscribe failed for {outpoint}: {e}");
                        self.pending_subscribes.push((*outpoint, spk.clone()));
                    }
                }
                // Electrum replays each script's whole history as `TxSeen`.
                // Core has no history feed, so a failed rescan retries until
                // it completes — the reply only fails on shutdown. A node
                // pruned past a live contract hangs startup here, loudly.
                if !self.blockchain.is_electrum() {
                    while !self.shutdown.load(Ordering::Relaxed)
                        && self.rescan_for_missed_spends(&watches).is_err()
                    {
                        thread::sleep(HEART_BEAT_INTERVAL);
                    }
                }
                _ = reply.send(Ok(()));
            }
            WatcherCommand::WatchRequest { outpoint, reply } => {
                log::info!("Intercepted watch request: {outpoint}");
                let watches = match self.registry.list_watches() {
                    Ok(watches) => watches,
                    Err(e) => {
                        log::error!("registry lock poisoned, cannot answer watch request: {e:?}");
                        // Every request must get a reply, even a failed one.
                        _ = reply.send(WatcherEvent::Error(format!(
                            "registry lock poisoned, cannot answer watch request for {outpoint}: {e:?}"
                        )));
                        return true;
                    }
                };
                let mut spent = false;
                for watch in watches {
                    if self.shutdown.load(Ordering::Relaxed) {
                        return false;
                    }
                    if watch.outpoint != outpoint {
                        continue;
                    }
                    // `in_block` is never retracted on a reorg, so confirm the
                    // recorded spend is still on chain before serving it.
                    if watch.in_block
                        && !self.confirm_recorded_spend(&outpoint, &watch.script_pubkey)
                    {
                        let mut cleared = watch.clone();
                        cleared.spent_tx = None;
                        cleared.in_block = false;
                        if let Err(e) = self.registry.upsert_watch(&cleared) {
                            log::error!("registry lock poisoned, spend not cleared: {e:?}");
                        }
                        continue;
                    }
                    spent = true;
                    _ = reply.send(WatcherEvent::UtxoSpent {
                        outpoint: watch.outpoint,
                        spending_tx: watch.spent_tx,
                    });
                }
                if !spent {
                    _ = reply.send(WatcherEvent::NoOutpoint);
                }
            }
            WatcherCommand::Unwatch {
                outpoint,
                script_pubkey,
            } => {
                log::info!("Intercepted unwatch request : {outpoint}");
                if let Err(e) = self.registry.remove_watch(outpoint) {
                    log::error!("registry lock poisoned, watch not removed: {e:?}");
                }
                self.pending_subscribes.retain(|(o, _)| *o != outpoint);
                // Release this outpoint's hold. A script another watched outpoint
                // still shares stays subscribed by design.
                if let Err(e) = self.blockchain.unsubscribe_script(&script_pubkey, outpoint) {
                    log::warn!("electrum script-unsubscribe failed for {outpoint}: {e}");
                }
            }
            WatcherCommand::Shutdown => return false,
        }
        true
    }

    /// Whether a recorded confirmed spend is still on chain. A failed query
    /// answers `true`: dropping a preimage we hold would lose the swap, and the
    /// query saying nothing is not evidence the spend is gone.
    fn confirm_recorded_spend(&self, outpoint: &OutPoint, spk: &ScriptBuf) -> bool {
        match self.blockchain.is_confirmed_spend(outpoint, spk) {
            Ok(still_there) => {
                if !still_there {
                    log::warn!("recorded spend of {outpoint} is no longer on chain, clearing it");
                }
                still_there
            }
            Err(e) => {
                log::error!("could not re-check the spend of {outpoint}: {e:?}; serving it anyway");
                true
            }
        }
    }

    /// Reads blocks back from the oldest rebuilt contract to the tip, looking for
    /// spends that confirmed while we were down. Bitcoin Core only.
    fn rescan_for_missed_spends(
        &mut self,
        watches: &[(OutPoint, ScriptBuf)],
    ) -> Result<(), String> {
        let mut oldest: Option<u64> = None;
        for (outpoint, _) in watches {
            if self.shutdown.load(Ordering::Relaxed) {
                log::info!("watch rebuild rescan aborted before funding lookup: shutdown");
                return Ok(());
            }
            match self.blockchain.tx_block_height(&outpoint.txid) {
                Ok(Some(height)) => {
                    oldest = Some(oldest.map_or(height, |old| old.min(height)));
                }
                // Nothing to scan for: an unmined contract has no confirmed
                // spend, and a spend that only ever sat in the mempool and was
                // evicted means no claim happened, so nothing needs recovering.
                Ok(None) => {}
                Err(e) => log::warn!("funding height lookup failed for {outpoint}: {e}"),
            }
        }
        let Some(from) = oldest else { return Ok(()) };
        self.scan_blocks(from).map_err(|e| {
            log::error!("block rescan from height {from} failed: {e:?}");
            format!("block rescan from height {from} failed: {e:?}")
        })
    }

    fn scan_blocks(&mut self, from: u64) -> Result<(), WatcherError> {
        let tip = self.blockchain.get_block_count()?;
        log::info!("Rescanning blocks {from}..={tip} for missed spends");
        for height in from..=tip {
            if self.shutdown.load(Ordering::Relaxed) {
                log::info!("block rescan aborted at height {height}: shutdown");
                return Ok(());
            }
            let block = self.blockchain.block_at_height(height)?;
            process_block::<R>(block, Some(height), &mut self.registry)?;
        }
        Ok(())
    }

    /// Retry script-subscribes that failed earlier. The backend records a
    /// subscription only on success, so retrying an armed script is a no-op.
    fn retry_subscribes(&mut self) {
        if self.shutdown.load(Ordering::Relaxed) {
            return;
        }
        // Destructured so the closure can call the backend while `retain`
        // holds the vec; borrowing `self` twice would not compile.
        let Self {
            blockchain,
            pending_subscribes,
            shutdown,
            ..
        } = self;
        pending_subscribes.retain(|(outpoint, spk)| {
            if shutdown.load(Ordering::Relaxed) {
                return true;
            }
            match blockchain.subscribe_script(spk, *outpoint) {
                Ok(()) => {
                    log::info!("re-subscribe succeeded for {outpoint}");
                    false
                }
                Err(e) => {
                    // The outpoint is unwatched while this fails; loud so a
                    // wedged backend shows before a swap depends on the watch.
                    log::error!("re-subscribe still failing for {outpoint}: {e}");
                    true
                }
            }
        });
    }

    /// Scan the node mempool into the registry.
    fn process_mempool(&mut self) -> Result<(), WatcherError> {
        let txids = self
            .blockchain
            .get_raw_mempool()
            .map_err(WatcherError::from)?;
        for txid in &txids {
            if self.shutdown.load(Ordering::Relaxed) {
                log::info!("mempool scan aborted: shutdown");
                return Ok(());
            }
            let tx = match self.blockchain.get_raw_transaction(txid, None) {
                Ok(tx) => tx,
                Err(e) => {
                    // There can be lot of txs in mempool.
                    // failing one fetch should not abort the scan.
                    log::error!("could not fetch mempool tx {txid}: {e:?}");
                    continue;
                }
            };
            process_transaction(&tx, &mut self.registry, false)?;
        }
        Ok(())
    }

    /// Handles a backend event, updating registry state and checkpoints.
    pub fn handle_event(&mut self, ev: WatchEvent) {
        match ev {
            WatchEvent::TxSeen { raw_tx } => {
                if let Ok(tx) = deserialize::<Transaction>(&raw_tx) {
                    if let Err(e) = process_transaction(&tx, &mut self.registry, false) {
                        log::error!("registry update failed for mempool tx: {e:?}");
                    }
                }
            }
            WatchEvent::BlockConnected(b) => {
                // ZMQ ships full block bytes; Electrum ships just the 32-byte hash.
                // No block body means no tx scan, so chain-based fidelity-bond
                // discovery does not exist on Electrum — it is nostr-only there.
                if b.hash.len() != 32 {
                    if let Ok(block) = deserialize::<Block>(&b.hash) {
                        let confirmation_height = if b.height > 0 {
                            Some(b.height)
                        } else {
                            block.txdata.first().and_then(|tx| {
                                self.blockchain
                                    .tx_block_height(&tx.compute_txid())
                                    .ok()
                                    .flatten()
                            })
                        };
                        if let Err(e) =
                            process_block::<R>(block, confirmation_height, &mut self.registry)
                        {
                            log::error!("registry update failed for connected block: {e:?}");
                        }
                    }
                }
            }
        }
    }
}
