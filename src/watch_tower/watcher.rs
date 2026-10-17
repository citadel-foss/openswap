//! Watchtower watcher module.
//!
//! Runs the core event loop, processes watcher commands, reacts to ZMQ backend events,
//! spawns optional RPC-based discovery and updates the on-disk registry of watches and fidelity records.

use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver as StdReceiver, RecvTimeoutError},
        Arc,
    },
    thread,
};

use bitcoin::{
    consensus::deserialize, Block, BlockHash, Network, OutPoint, ScriptBuf, Transaction,
};
use crossbeam_channel::Sender as CbSender;

use crate::{
    utill::HEART_BEAT_INTERVAL,
    wallet::{blockchain::WatchEvent, AnyBlockchain, Blockchain, CoreRPC},
    watch_tower::{
        nostr,
        registry_storage::{FileRegistry, WatchRequest},
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
    /// Core block hashes whose height lookup failed. Retried on every loop pass
    /// without retaining full blocks in memory.
    pending_block_discovery: Vec<BlockHash>,
    /// Watches to re-check against the backend after notifications were lost.
    /// Retried on every loop pass until each lookup completes.
    pending_reconcile: Vec<OutPoint>,
    /// Set by `WatchService::shutdown`; long scans check it per iteration so a
    /// deep rescan cannot stall the join.
    shutdown: Arc<AtomicBool>,
    /// Latest block height from the backend's block events, 0 while unknown.
    /// Shared with `WatchService`, so recovery need not ask the server each pass.
    pub(crate) tip: Arc<AtomicU64>,
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
            pending_block_discovery: Vec::new(),
            pending_reconcile: Vec::new(),
            shutdown,
            tip: Arc::new(AtomicU64::new(0)),
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
                self.drain_events();
                // Failed backend work retries on every pass, not just idle ticks;
                // with empty queues this is a no-op.
                self.retry_pending_work();
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
                match self.blockchain.subscribe_script(&script_pubkey, outpoint) {
                    Ok(()) => self.seed_tip(),
                    Err(e) => {
                        log::error!("electrum script-subscribe failed for {outpoint}: {e}");
                        self.pending_subscribes.push((outpoint, script_pubkey));
                    }
                }
            }
            WatcherCommand::RebuildWatches { watches, reply } => {
                log::info!("Rebuilding {} watches from the wallet", watches.len());
                let mut armed = false;
                for (outpoint, spk) in &watches {
                    if self.shutdown.load(Ordering::Relaxed) {
                        // Reply before bailing out: the caller blocks on it.
                        _ = reply.send(Ok(()));
                        return false;
                    }
                    if let Err(e) = self.registry.register_watch(*outpoint, spk.clone()) {
                        log::error!("registry lock poisoned, watch not stored: {e:?}");
                    }
                    match self.blockchain.subscribe_script(spk, *outpoint) {
                        Ok(()) => armed = true,
                        Err(e) => {
                            log::error!("electrum script-subscribe failed for {outpoint}: {e}");
                            self.pending_subscribes.push((*outpoint, spk.clone()));
                        }
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
                if armed {
                    self.seed_tip();
                }
                _ = reply.send(Ok(()));
            }
            WatcherCommand::WatchRequest { outpoint, reply } => {
                log::debug!("Intercepted watch request: {outpoint}");
                // Events queue while the loop waits for a command. Answer from the
                // backend's current view, or a spend it already relayed reads as unspent.
                self.drain_events();
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
                // With nothing watched the backend stops reading new blocks, so the
                // height would go stale while still looking current.
                if !self.registry.list_watches().is_ok_and(|w| !w.is_empty()) {
                    self.tip.store(0, Ordering::Release);
                }
            }
            WatcherCommand::Shutdown => return false,
        }
        true
    }

    /// Electrum's block events carry the height, so seed it once a watch is armed
    /// instead of waiting a block. Called only after the server just answered, so a
    /// down server cannot stall the command loop twice. Core publishes none.
    fn seed_tip(&self) {
        let watching = self.registry.list_watches().is_ok_and(|w| !w.is_empty());
        if watching && self.blockchain.is_electrum() && self.tip.load(Ordering::Acquire) == 0 {
            if let Ok(height) = self.blockchain.get_block_count() {
                self.tip.store(height, Ordering::Release);
            }
        }
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

    fn drain_events(&mut self) {
        while !self.shutdown.load(Ordering::Relaxed) {
            let Some(event) = self.blockchain.poll_event() else {
                break;
            };
            self.handle_event(event);
        }
    }

    /// Retry failed script subscriptions and Core block discovery. Successful
    /// subscriptions and completed or orphaned blocks leave their queues.
    fn retry_pending_work(&mut self) {
        if self.shutdown.load(Ordering::Relaxed) {
            return;
        }
        self.reconcile_watches();
        // Split the field borrows so both retry queues can retain in place.
        let Self {
            blockchain,
            registry,
            pending_subscribes,
            pending_block_discovery,
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
                    // The outpoint remains unwatched while this fails.
                    log::error!("re-subscribe still failing for {outpoint}: {e}");
                    true
                }
            }
        });

        if !R::RUN_DISCOVERY {
            return;
        }
        let AnyBlockchain::CoreRPC(core) = blockchain else {
            return;
        };
        pending_block_discovery.retain(|block_hash| {
            if shutdown.load(Ordering::Relaxed) {
                return true;
            }
            let height = match core.block_height(block_hash) {
                Ok(height) => height,
                Err(e) => {
                    log::error!("Could not retry discovery for Core block {block_hash}: {e}");
                    return true;
                }
            };
            let block = match core.block_at_height(height) {
                Ok(block) => block,
                Err(e) => {
                    log::error!("Could not reload Core block {block_hash} at height {height}: {e}");
                    return true;
                }
            };
            if block.block_hash() != *block_hash {
                log::info!("Dropping pending discovery for orphaned Core block {block_hash}");
                return false;
            }
            match process_block::<R>(block, Some(height), registry) {
                Ok(()) => false,
                Err(e) => {
                    log::error!(
                        "Fidelity discovery retry failed for Core block {block_hash}: {e:?}"
                    );
                    true
                }
            }
        });
    }

    /// Re-check queued watches against Core after lost notifications,
    /// recording any spend found. A lookup that fails, or that Core cannot
    /// answer yet, ends the pass with the rest still queued, so a node that
    /// cannot answer costs one lookup per pass instead of one per watch.
    fn reconcile_watches(&mut self) {
        if self.pending_reconcile.is_empty() {
            return;
        }
        let Self {
            blockchain,
            registry,
            pending_reconcile,
            shutdown,
            ..
        } = self;
        // Only Core reports lost notifications.
        let AnyBlockchain::CoreRPC(core) = blockchain else {
            pending_reconcile.clear();
            return;
        };
        let watches = match registry.list_watches() {
            Ok(watches) => watches,
            Err(e) => {
                log::error!("registry lock poisoned, cannot re-check watches: {e:?}");
                return;
            }
        };
        let mut stopped = false;
        pending_reconcile.retain(|outpoint| {
            if stopped || shutdown.load(Ordering::Relaxed) {
                return true;
            }
            // Unwatched since it was queued: nothing left to check.
            let Some(watch) = watches.iter().find(|watch| watch.outpoint == *outpoint) else {
                return false;
            };
            match reconcile_watch(core, registry, watch) {
                Ok(true) => false,
                Ok(false) => {
                    log::info!("Core cannot fully answer for {outpoint} yet, will re-check");
                    stopped = true;
                    true
                }
                Err(e) => {
                    log::error!("re-check of {outpoint} after lost notifications failed: {e:?}");
                    stopped = true;
                    true
                }
            }
        });
        // Every watch ahead of the one that stopped the pass has left the
        // queue, so it is first. Moving it last lets the next pass reach the
        // others, so one that never resolves cannot hold them back.
        if stopped {
            pending_reconcile.rotate_left(1);
        }
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
            // Blocks are going unheard, so the height can no longer be trusted.
            WatchEvent::Unreachable => self.tip.store(0, Ordering::Release),
            // A lost notification may have been a watched spend, or a reorg
            // that undid a recorded one, so every watch is re-checked against
            // Core on the next retry pass. There is no tip to refresh: Core's
            // block events carry no height, so on Core the tip stays unknown.
            WatchEvent::Missed => match self.registry.list_watches() {
                Ok(watches) => {
                    for watch in watches {
                        if !self.pending_reconcile.contains(&watch.outpoint) {
                            self.pending_reconcile.push(watch.outpoint);
                        }
                    }
                }
                Err(e) => log::error!("registry lock poisoned, cannot re-check watches: {e:?}"),
            },
            WatchEvent::TxSeen { raw_tx } => {
                if let Ok(tx) = deserialize::<Transaction>(&raw_tx) {
                    if let Err(e) = process_transaction(&tx, &mut self.registry, false) {
                        log::error!("registry update failed for mempool tx: {e:?}");
                    }
                }
            }
            WatchEvent::BlockConnected(b) => {
                // Core's ZMQ events carry no height, so Core never publishes one. With
                // nothing watched no later block would be read, so publish nothing.
                if b.height > 0 && self.registry.list_watches().is_ok_and(|w| !w.is_empty()) {
                    self.tip.store(b.height, Ordering::Release);
                }
                // ZMQ ships full block bytes; Electrum ships just the 32-byte hash.
                // No block body means no tx scan, so chain-based fidelity-bond
                // discovery does not exist on Electrum — it is nostr-only there.
                if b.hash.len() != 32 {
                    if let Ok(block) = deserialize::<Block>(&b.hash) {
                        let confirmation_height = if !R::RUN_DISCOVERY {
                            None
                        } else if b.height > 0 {
                            Some(b.height)
                        } else {
                            match &self.blockchain {
                                AnyBlockchain::CoreRPC(core) => {
                                    let block_hash = block.block_hash();
                                    match core.block_height(&block_hash) {
                                        Ok(height) => Some(height),
                                        Err(e) => {
                                            log::error!(
                                                "Could not resolve connected Core block {block_hash} height; will retry discovery: {e}"
                                            );
                                            for tx in &block.txdata {
                                                if let Err(e) = process_transaction(
                                                    tx,
                                                    &mut self.registry,
                                                    true,
                                                ) {
                                                    log::error!(
                                                        "registry update failed for connected block: {e:?}"
                                                    );
                                                    break;
                                                }
                                            }
                                            if !self.pending_block_discovery.contains(&block_hash) {
                                                self.pending_block_discovery.push(block_hash);
                                            }
                                            return;
                                        }
                                    }
                                }
                                AnyBlockchain::Electrum(_) => {
                                    Some(b.height).filter(|height| *height > 0)
                                }
                            }
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

/// Re-check one watch against Core, recording any spend found. `Ok(false)`
/// means Core cannot tell yet, so the watch must be checked again.
fn reconcile_watch(
    core: &CoreRPC,
    registry: &mut FileRegistry,
    watch: &WatchRequest,
) -> Result<bool, WatcherError> {
    let outpoint = watch.outpoint;
    let mut recorded = watch
        .spent_tx
        .as_ref()
        .map(|tx| (tx.compute_txid(), watch.in_block));
    if let Some((txid, true)) = recorded {
        // Still confirmed, unless a reorg replaced its block and the
        // notifications that would have undone the record were lost.
        match core.tx_confirmations(&txid)? {
            Some(confirmations) if confirmations > 0 => return Ok(true),
            // A syncing txindex cannot find a mined spend, which proves
            // nothing: keep the confirmed mark and ask again later. Unless the
            // output is back in Core's UTXO set, which needs no txindex: then
            // no mined spend exists.
            None if !core.txindex_synced()?
                && core
                    .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))?
                    .is_none() =>
            {
                return Ok(false)
            }
            _ => {}
        }
        log::warn!(
            "Core does not report recorded spend {txid} of {outpoint} as confirmed, re-checking"
        );
        // Only the confirmed mark goes, so a spend found below can replace
        // the record. The transaction stays: it may carry the only copy of a
        // preimage.
        registry.upsert_watch(&WatchRequest {
            in_block: false,
            ..watch.clone()
        })?;
        recorded = Some((txid, false));
    }
    let (tx, in_block, settled) = match lookup_spend(core, &outpoint)? {
        Spend::Found(tx, in_block) => (tx, in_block, true),
        // Recorded as confirmed, so later passes wait for the txindex instead
        // of scanning again, and Core confirms it once the index catches up.
        Spend::FoundUnindexed(tx) => (tx, true, false),
        // Kept for its preimage; the next pass sees where it went.
        Spend::LeftMempool(tx) => (tx, false, false),
        Spend::None => return Ok(true),
        Spend::Unknown => return Ok(false),
    };
    // Most re-checks only confirm a spend already on record.
    if recorded != Some((tx.compute_txid(), in_block)) {
        log::warn!(
            "recovered missed spend of {outpoint}: {} (confirmed={in_block})",
            tx.compute_txid()
        );
    }
    process_transaction(&tx, registry, in_block)?;
    Ok(settled)
}

/// What Core can say about the spend of a watched outpoint.
enum Spend {
    /// The spending transaction, and whether it is mined. Mined matters: a
    /// confirmed spend may carry the only copy of a preimage, and only a
    /// confirmed record is protected from mempool rivals.
    Found(Transaction, bool),
    /// A spending transaction the block scan found in a block the txindex
    /// has not reached: mined, but Core cannot report its confirmations yet.
    FoundUnindexed(Transaction),
    /// A mempool spender Core no longer knows by the time its confirmations
    /// are read: evicted, or mined where the txindex cannot see it yet.
    LeftMempool(Transaction),
    /// No spend exists.
    None,
    /// Core cannot tell yet.
    Unknown,
}

/// `mined_spending_transaction` also answers `None` when it cannot tell, so "no
/// spend" is trusted only when the output is unspent, or when the funding
/// transaction is not mined and the txindex is synced, so no mined spend can
/// exist. The second case covers contracts that were never broadcast.
fn lookup_spend(core: &CoreRPC, outpoint: &OutPoint) -> Result<Spend, WatcherError> {
    // Where the spender was found matters: an output spent on chain does not
    // prove that a spender Core named from its mempool is the one mined.
    if let Some(tx) = core.mempool_spending_transaction(outpoint)? {
        return Ok(match core.tx_confirmations(&tx.compute_txid())? {
            Some(confirmations) => Spend::Found(tx, confirmations > 0),
            None => Spend::LeftMempool(tx),
        });
    }
    if let Some(tx) = core.mined_spending_transaction(outpoint)? {
        // Found in a block, so a txindex that cannot report it yet has simply
        // not reached that block.
        return Ok(match core.tx_confirmations(&tx.compute_txid())? {
            Some(confirmations) => Spend::Found(tx, confirmations > 0),
            None => Spend::FoundUnindexed(tx),
        });
    }
    if core
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))?
        .is_some()
    {
        return Ok(Spend::None);
    }
    // Read first: the funding lookup below proves nothing unless the txindex
    // was already synced when it ran.
    let synced = core.txindex_synced()?;
    // Mined, its output gone, yet no spender found: Core moved on mid-lookup.
    if core
        .tx_confirmations(&outpoint.txid)?
        .is_some_and(|c| c > 0)
    {
        return Ok(Spend::Unknown);
    }
    Ok(if synced { Spend::None } else { Spend::Unknown })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        consensus::{encode::serialize_hex, serialize},
        constants::genesis_block,
        hashes::Hash,
        Sequence, TxIn, Txid, Witness,
    };
    use serde_json::{json, Value};
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        sync::Mutex,
        time::{Duration, Instant},
    };

    use crate::{
        wallet::{
            blockchain::{BlockRef, ZmqPublisher},
            CoreRPC, CoreRpcConfig,
        },
        watch_tower::service::MakerRole,
    };

    struct DiscoveryRole;

    impl Role for DiscoveryRole {
        const RUN_DISCOVERY: bool = true;
    }

    fn core_backend_for(
        announced_block: &Block,
        active_block: &Block,
    ) -> (AnyBlockchain, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock Core RPC");
        let url = listener.local_addr().unwrap().to_string();
        let announced_hash = announced_block.block_hash();
        let active_hash = active_block.block_hash();
        let active_block_hex = serialize_hex(active_block);
        let merkle_root = announced_block.header.merkle_root.to_string();
        let time = announced_block.header.time;
        let nonce = announced_block.header.nonce;
        let tx_count = announced_block.txdata.len();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept Core RPC client");
            let mut writer = stream.try_clone().expect("clone Core RPC stream");
            let mut reader = BufReader::new(stream);

            for _ in 0..3 {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                assert!(line.starts_with("POST "));

                let mut content_length = 0;
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().unwrap();
                        }
                    }
                }

                let mut body = vec![0; content_length];
                reader.read_exact(&mut body).unwrap();
                let request: Value = serde_json::from_slice(&body).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "getblockheader" => {
                        assert_eq!(request["params"], json!([announced_hash, true]));
                        json!({
                            "hash": announced_hash,
                            "confirmations": 1,
                            "height": 0,
                            "version": 1,
                            "merkleroot": merkle_root,
                            "time": time,
                            "mediantime": time,
                            "nonce": nonce,
                            "bits": "207fffff",
                            "difficulty": 1.0,
                            "chainwork": "00",
                            "nTx": tx_count,
                        })
                    }
                    "getblockhash" => {
                        assert_eq!(request["params"], json!([0]));
                        json!(active_hash)
                    }
                    "getblock" => {
                        assert_eq!(request["params"], json!([active_hash, 0]));
                        json!(active_block_hex)
                    }
                    method => panic!("unexpected Core RPC method: {}", method),
                };
                let response = json!({
                    "result": result,
                    "error": Value::Null,
                    "id": request["id"],
                })
                .to_string();
                write!(
                    writer,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    response.len(),
                    response
                )
                .unwrap();
                writer.flush().unwrap();
            }
        });

        let config = CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        };
        (
            AnyBlockchain::CoreRPC(CoreRPC::new(&config).unwrap()),
            server,
        )
    }

    #[test]
    fn core_height_failure_queues_and_retries_block_discovery() {
        let config = CoreRpcConfig {
            url: "127.0.0.1:0".to_string(),
            ..CoreRpcConfig::default()
        };
        let backend = AnyBlockchain::CoreRPC(CoreRPC::new(&config).unwrap());
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut watcher = Watcher::<DiscoveryRole>::new(
            backend,
            FileRegistry::new(),
            rx,
            Vec::new(),
            None,
            Arc::new(AtomicBool::new(false)),
        );
        let block = genesis_block(Network::Regtest);
        let block_hash = block.block_hash();
        let event = WatchEvent::BlockConnected(BlockRef {
            height: 0,
            hash: serialize(&block),
        });

        watcher.handle_event(event.clone());
        watcher.handle_event(event);
        assert_eq!(watcher.pending_block_discovery, vec![block_hash]);

        watcher.retry_pending_work();
        assert_eq!(watcher.pending_block_discovery, vec![block_hash]);
    }

    #[test]
    fn successful_core_retry_processes_and_removes_pending_block() {
        let block = genesis_block(Network::Regtest);
        let block_hash = block.block_hash();
        let (backend, server) = core_backend_for(&block, &block);
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut watcher = Watcher::<DiscoveryRole>::new(
            backend,
            FileRegistry::new(),
            rx,
            Vec::new(),
            None,
            Arc::new(AtomicBool::new(false)),
        );
        watcher.pending_block_discovery.push(block_hash);

        watcher.retry_pending_work();

        assert!(watcher.pending_block_discovery.is_empty());
        server.join().unwrap();
    }

    #[test]
    fn core_retry_removes_block_orphaned_by_reorg() {
        let announced_block = genesis_block(Network::Regtest);
        let announced_hash = announced_block.block_hash();
        let mut active_block = announced_block.clone();
        active_block.header.nonce = active_block.header.nonce.wrapping_add(1);
        assert_ne!(active_block.block_hash(), announced_hash);

        let (backend, server) = core_backend_for(&announced_block, &active_block);
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut watcher = Watcher::<DiscoveryRole>::new(
            backend,
            FileRegistry::new(),
            rx,
            Vec::new(),
            None,
            Arc::new(AtomicBool::new(false)),
        );
        watcher.pending_block_discovery.push(announced_hash);

        watcher.retry_pending_work();

        assert!(watcher.pending_block_discovery.is_empty());
        server.join().unwrap();
    }

    /// Recovery trusts this height instead of asking the server, so it must vanish
    /// once nothing is watched and the backend stops reading new blocks.
    #[test]
    fn block_heights_are_published_until_nothing_is_watched() {
        let config = CoreRpcConfig {
            url: "127.0.0.1:0".to_string(),
            ..CoreRpcConfig::default()
        };
        let backend = AnyBlockchain::CoreRPC(CoreRPC::new(&config).unwrap());
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut watcher = Watcher::<DiscoveryRole>::new(
            backend,
            FileRegistry::new(),
            rx,
            Vec::new(),
            None,
            Arc::new(AtomicBool::new(false)),
        );
        let block = |height| {
            WatchEvent::BlockConnected(BlockRef {
                height,
                hash: vec![0; 32],
            })
        };
        let (outpoint, script_pubkey) = (OutPoint::null(), ScriptBuf::new());

        watcher.handle_command(WatcherCommand::RegisterWatchRequest {
            outpoint,
            script_pubkey: script_pubkey.clone(),
        });
        watcher.handle_event(block(0));
        assert_eq!(
            watcher.tip.load(Ordering::Acquire),
            0,
            "no height, nothing published"
        );
        watcher.handle_event(block(7));
        assert_eq!(watcher.tip.load(Ordering::Acquire), 7);
        // A deaf backend misses blocks, so its last height is withdrawn.
        watcher.handle_event(WatchEvent::Unreachable);
        assert_eq!(watcher.tip.load(Ordering::Acquire), 0);
        watcher.handle_event(block(7));

        watcher.handle_command(WatcherCommand::Unwatch {
            outpoint,
            script_pubkey,
        });
        assert_eq!(watcher.tip.load(Ordering::Acquire), 0);
        // A reconnect replays the tip after the last unwatch; it must stay withdrawn.
        watcher.handle_event(block(8));
        assert_eq!(watcher.tip.load(Ordering::Acquire), 0);
    }

    /// Serves Core JSON-RPC from `answer` on every connection and records each
    /// method called; an `Err` is sent as the JSON-RPC error object. Runs
    /// until the test process exits.
    fn mock_core_rpc(
        answer: impl Fn(&str, &Value) -> Result<Value, Value> + Send + Sync + 'static,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock Core RPC");
        let url = listener.local_addr().unwrap().to_string();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let answer = Arc::new(answer);
        let server_calls = calls.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let (answer, calls) = (answer.clone(), server_calls.clone());
                thread::spawn(move || {
                    let mut writer = stream.try_clone().expect("clone Core RPC stream");
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    while reader.read_line(&mut line).unwrap_or(0) > 0 {
                        let mut content_length = 0;
                        loop {
                            line.clear();
                            reader.read_line(&mut line).unwrap();
                            if line == "\r\n" {
                                break;
                            }
                            if let Some((name, value)) = line.split_once(':') {
                                if name.eq_ignore_ascii_case("content-length") {
                                    content_length = value.trim().parse().unwrap();
                                }
                            }
                        }
                        let mut body = vec![0; content_length];
                        reader.read_exact(&mut body).unwrap();
                        let request: Value = serde_json::from_slice(&body).unwrap();
                        let method = request["method"].as_str().unwrap();
                        calls.lock().unwrap().push(method.to_string());
                        let (result, error) = match answer(method, &request["params"]) {
                            Ok(result) => (result, Value::Null),
                            Err(error) => (Value::Null, error),
                        };
                        let response =
                            json!({ "result": result, "error": error, "id": request["id"] })
                                .to_string();
                        write!(
                            writer,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                            response.len(),
                            response
                        )
                        .unwrap();
                        writer.flush().unwrap();
                        line.clear();
                    }
                });
            }
        });
        (url, calls)
    }

    fn spend(outpoint: OutPoint) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: Vec::new(),
        }
    }

    /// `getrawtransaction <txid> true` without the block fields.
    fn verbose_tx(tx: &Transaction) -> Value {
        json!({
            "hex": serialize_hex(tx),
            "txid": tx.compute_txid(),
            "hash": tx.compute_wtxid(),
            "size": serialize(tx).len(),
            "vsize": tx.vsize(),
            "version": tx.version.0,
            "locktime": tx.lock_time.to_consensus_u32(),
            "vin": tx.input.iter().map(|input| json!({
                "txid": input.previous_output.txid,
                "vout": input.previous_output.vout,
                "sequence": input.sequence.0,
            })).collect::<Vec<_>>(),
            "vout": [],
        })
    }

    /// The parts of a Core node the watcher's re-check reads.
    #[derive(Default)]
    struct Node {
        mempool: Vec<Transaction>,
        /// The active chain; a block's height is its index.
        chain: Vec<Block>,
        /// Transactions Core still indexes under a block a reorg replaced.
        reorged_out: Vec<Transaction>,
        txindex_syncing: bool,
        /// While syncing, the txindex holds only blocks below this height.
        indexed_below: usize,
    }

    impl Node {
        fn mine(&mut self, txdata: Vec<Transaction>) {
            let mut block = genesis_block(Network::Regtest);
            // A distinct header per height, so each block has its own hash.
            block.header.time += self.chain.len() as u32;
            block.txdata = txdata;
            self.chain.push(block);
        }

        fn tip(&self) -> u64 {
            self.chain.len().saturating_sub(1) as u64
        }

        fn block(&self, hash: &Value) -> (u64, &Block) {
            let hash: BlockHash = serde_json::from_value(hash.clone()).unwrap();
            self.chain
                .iter()
                .enumerate()
                .find(|(_, block)| block.block_hash() == hash)
                .map(|(height, block)| (height as u64, block))
                .expect("only active-chain blocks are looked up")
        }

        /// A transaction Core can serve, with its block hash and confirmations.
        /// While the txindex syncs, only the mempool is searchable.
        fn find(&self, txid: Txid) -> Option<(&Transaction, Option<(BlockHash, u64)>)> {
            if let Some(tx) = self.mempool.iter().find(|tx| tx.compute_txid() == txid) {
                return Some((tx, None));
            }
            // The txindex fills in height order, so while it syncs it holds
            // only the lower blocks.
            let indexed = if self.txindex_syncing {
                self.indexed_below.min(self.chain.len())
            } else {
                self.chain.len()
            };
            for (height, block) in self.chain[..indexed].iter().enumerate() {
                if let Some(tx) = block.txdata.iter().find(|tx| tx.compute_txid() == txid) {
                    let confirmations = self.tip() - height as u64 + 1;
                    return Some((tx, Some((block.block_hash(), confirmations))));
                }
            }
            if self.txindex_syncing {
                return None;
            }
            // Core reports a transaction whose block was reorged out with 0
            // confirmations, under the stale block's hash.
            self.reorged_out
                .iter()
                .find(|tx| tx.compute_txid() == txid)
                .map(|tx| (tx, Some((BlockHash::from_byte_array([0xee; 32]), 0))))
        }

        fn answer(&self, method: &str, params: &Value) -> Result<Value, Value> {
            match method {
                "gettxspendingprevout" => {
                    let prevout = &params[0][0];
                    let outpoint = OutPoint::new(
                        serde_json::from_value(prevout["txid"].clone()).unwrap(),
                        prevout["vout"].as_u64().unwrap() as u32,
                    );
                    let spender = self
                        .mempool
                        .iter()
                        .find(|tx| tx.input.iter().any(|i| i.previous_output == outpoint))
                        .map(Transaction::compute_txid);
                    Ok(json!([{
                        "txid": outpoint.txid,
                        "vout": outpoint.vout,
                        "spendingtxid": spender,
                    }]))
                }
                // Every output these tests watch is spent or was never created.
                "gettxout" => Ok(Value::Null),
                "getindexinfo" => Ok(json!({
                    "txindex": { "synced": !self.txindex_syncing, "best_block_height": self.tip() },
                })),
                "getblockcount" => Ok(json!(self.tip())),
                "getblockhash" => {
                    let height = params[0].as_u64().unwrap() as usize;
                    Ok(json!(self.chain[height].block_hash()))
                }
                "getblockheader" => {
                    let (height, block) = self.block(&params[0]);
                    let header = &block.header;
                    Ok(json!({
                        "hash": block.block_hash(),
                        "confirmations": self.tip() - height + 1,
                        "height": height,
                        "version": header.version.to_consensus(),
                        "merkleroot": header.merkle_root,
                        "time": header.time,
                        "mediantime": header.time,
                        "nonce": header.nonce,
                        "bits": "207fffff",
                        "difficulty": 1.0,
                        "chainwork": "00",
                        "nTx": block.txdata.len(),
                    }))
                }
                "getblock" => Ok(json!(serialize_hex(self.block(&params[0]).1))),
                "getrawtransaction" => {
                    let txid: Txid = serde_json::from_value(params[0].clone()).unwrap();
                    let Some((tx, block)) = self.find(txid) else {
                        return Err(json!({
                            "code": -5,
                            "message": "No such mempool or blockchain transaction",
                        }));
                    };
                    if params[1] != json!(true) {
                        return Ok(json!(serialize_hex(tx)));
                    }
                    let mut info = verbose_tx(tx);
                    if let Some((hash, confirmations)) = block {
                        info["blockhash"] = json!(hash);
                        info["confirmations"] = json!(confirmations);
                    }
                    Ok(info)
                }
                method => {
                    Err(json!({ "code": -32601, "message": format!("unexpected {}", method) }))
                }
            }
        }
    }

    fn mock_node(node: &Arc<Mutex<Node>>) -> (String, Arc<Mutex<Vec<String>>>) {
        let node = node.clone();
        mock_core_rpc(move |method, params| node.lock().unwrap().answer(method, params))
    }

    fn core_watcher(config: &CoreRpcConfig) -> Watcher<MakerRole> {
        let (_tx, rx) = std::sync::mpsc::channel();
        Watcher::new(
            AnyBlockchain::CoreRPC(CoreRPC::new(config).unwrap()),
            FileRegistry::new(),
            rx,
            Vec::new(),
            None,
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn recorded_spend<R: Role>(watcher: &Watcher<R>, outpoint: OutPoint) -> Option<Transaction> {
        watcher
            .registry
            .list_watches()
            .unwrap()
            .into_iter()
            .find(|watch| watch.outpoint == outpoint)
            .and_then(|watch| watch.spent_tx)
    }

    /// Core dropped `rawtx` seq 1, the spend of a watched outpoint. The gap in
    /// the sequence numbers is the only trace of it, so the watcher must
    /// re-check its watches against Core and record the spend found there.
    #[test]
    fn missed_zmq_spend_is_recorded_after_a_sequence_gap() {
        let missed_outpoint = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
        let seen_outpoint = OutPoint::new(Txid::from_byte_array([2; 32]), 0);
        let missed_spend = spend(missed_outpoint);
        let seen_spend = spend(seen_outpoint);
        let unrelated = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));

        // Core's mempool holds both spends.
        let (url, calls) = mock_node(&Arc::new(Mutex::new(Node {
            mempool: vec![missed_spend.clone(), seen_spend.clone()],
            ..Node::default()
        })));
        let publisher = ZmqPublisher::bind("tcp://127.0.0.1:*");
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            zmq_addr: publisher.addr.clone(),
            ..CoreRpcConfig::default()
        });
        for outpoint in [missed_outpoint, seen_outpoint] {
            watcher.handle_command(WatcherCommand::RegisterWatchRequest {
                outpoint,
                script_pubkey: ScriptBuf::new(),
            });
        }
        publisher.wait_for_subscriber(|| watcher.drain_events());

        publisher.publish("rawtx", &serialize(&unrelated), 0);
        // Seq 1, `missed_spend`, never reaches the watcher.
        publisher.publish("rawtx", &serialize(&seen_spend), 2);

        // Event-loop passes until the message after the gap is processed.
        let deadline = Instant::now() + Duration::from_secs(10);
        while recorded_spend(&watcher, seen_outpoint).is_none() {
            assert!(
                Instant::now() < deadline,
                "rawtx seq 2 never reached the watcher"
            );
            watcher.drain_events();
            watcher.retry_pending_work();
            thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(
            recorded_spend(&watcher, missed_outpoint),
            Some(missed_spend.clone()),
            "the spend Core dropped from the ZMQ feed must be recovered from Core"
        );

        // Answered from the registry, without asking Core again.
        let calls_before = calls.lock().unwrap().len();
        let (reply_tx, reply_rx) = crossbeam_channel::unbounded();
        watcher.handle_command(WatcherCommand::WatchRequest {
            outpoint: missed_outpoint,
            reply: reply_tx,
        });
        match reply_rx.try_recv() {
            Ok(WatcherEvent::UtxoSpent { spending_tx, .. }) => {
                assert_eq!(spending_tx, Some(missed_spend))
            }
            other => panic!("expected the recorded spend, got {:?}", other),
        }
        assert_eq!(calls.lock().unwrap().len(), calls_before);
    }

    /// A node that cannot answer must not hold up the event loop for a lookup
    /// per watch: the first failure ends the pass, and every queued watch is
    /// re-checked on a later pass.
    #[test]
    fn failed_reconcile_stays_queued_and_retries() {
        let outpoints = [1, 2, 3].map(|n| OutPoint::new(Txid::from_byte_array([n; 32]), 0));
        let spends = outpoints.map(spend);
        let node_up = Arc::new(AtomicBool::new(false));
        let node = Node {
            mempool: spends.to_vec(),
            ..Node::default()
        };
        let (url, calls) = mock_core_rpc({
            let node_up = node_up.clone();
            move |method, params| {
                if !node_up.load(Ordering::Relaxed) {
                    return Err(json!({ "code": -28, "message": "Loading block index" }));
                }
                node.answer(method, params)
            }
        });
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        for outpoint in outpoints {
            watcher.handle_command(WatcherCommand::RegisterWatchRequest {
                outpoint,
                script_pubkey: ScriptBuf::new(),
            });
        }

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();
        assert_eq!(calls.lock().unwrap().len(), 1, "one failed lookup per pass");
        assert_eq!(watcher.pending_reconcile.len(), outpoints.len());
        assert!(outpoints
            .iter()
            .all(|outpoint| recorded_spend(&watcher, *outpoint).is_none()));

        node_up.store(true, Ordering::Relaxed);
        watcher.retry_pending_work();
        assert!(watcher.pending_reconcile.is_empty());
        for (outpoint, spend) in outpoints.iter().zip(spends) {
            assert_eq!(recorded_spend(&watcher, *outpoint), Some(spend));
        }
    }

    fn record_confirmed_spend<R: Role>(watcher: &mut Watcher<R>, spend: &Transaction) {
        watcher
            .registry
            .upsert_watch(&WatchRequest {
                outpoint: spend.input[0].previous_output,
                script_pubkey: ScriptBuf::new(),
                in_block: true,
                spent_tx: Some(spend.clone()),
            })
            .unwrap();
    }

    fn is_recorded_confirmed<R: Role>(watcher: &Watcher<R>, outpoint: OutPoint) -> bool {
        watcher
            .registry
            .list_watches()
            .unwrap()
            .iter()
            .any(|watch| watch.outpoint == outpoint && watch.in_block)
    }

    /// A watch Core can never resolve must not hold back the watches queued
    /// behind it: here its funding transaction is mined but has no output at
    /// that index, so every lookup comes back undecided.
    #[test]
    fn undecided_watch_does_not_starve_the_queue() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let undecided = OutPoint::new(funding.compute_txid(), 5);
        let spent = OutPoint::new(Txid::from_byte_array([2; 32]), 0);
        let spender = spend(spent);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mempool.push(spender.clone());
        }
        let (url, _calls) = mock_node(&node);
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        for outpoint in [undecided, spent] {
            watcher.handle_command(WatcherCommand::RegisterWatchRequest {
                outpoint,
                script_pubkey: ScriptBuf::new(),
            });
        }
        watcher.pending_reconcile = vec![undecided, spent];

        watcher.retry_pending_work();
        watcher.retry_pending_work();

        assert_eq!(recorded_spend(&watcher, spent), Some(spender));
        assert_eq!(recorded_spend(&watcher, undecided), None);
        assert_eq!(watcher.pending_reconcile, [undecided]);
    }

    /// A lookup that keeps failing for one outpoint must not hold back the
    /// watches queued behind it, while each pass still stops at its first
    /// failure.
    #[test]
    fn failing_watch_does_not_starve_the_queue() {
        let failing = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
        let spent = OutPoint::new(Txid::from_byte_array([2; 32]), 0);
        let spender = spend(spent);
        let node = Node {
            mempool: vec![spender.clone()],
            ..Node::default()
        };
        // Calls served so far, and how many had been served when the latest
        // failure was returned.
        let served = Arc::new(AtomicU64::new(0));
        let served_at_failure = Arc::new(AtomicU64::new(0));
        let (url, _calls) = mock_core_rpc({
            let (served, served_at_failure) = (served.clone(), served_at_failure.clone());
            move |method, params| {
                let count = served.fetch_add(1, Ordering::SeqCst) + 1;
                if method == "gettxspendingprevout" && params[0][0]["txid"] == json!(failing.txid) {
                    served_at_failure.store(count, Ordering::SeqCst);
                    return Err(json!({ "code": -1, "message": "lookup failed" }));
                }
                node.answer(method, params)
            }
        });
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        for outpoint in [failing, spent] {
            watcher.handle_command(WatcherCommand::RegisterWatchRequest {
                outpoint,
                script_pubkey: ScriptBuf::new(),
            });
        }
        watcher.pending_reconcile = vec![failing, spent];

        for _ in 0..2 {
            watcher.retry_pending_work();
            // The failing lookup is the last call of every pass.
            assert_eq!(
                served.load(Ordering::SeqCst),
                served_at_failure.load(Ordering::SeqCst)
            );
        }

        assert_eq!(recorded_spend(&watcher, spent), Some(spender));
        assert_eq!(watcher.pending_reconcile, [failing]);
    }

    /// A spend recorded as confirmed costs one lookup, to prove its block is
    /// still on the chain. An unwatched outpoint has nothing to protect and
    /// costs none.
    #[test]
    fn confirmed_spend_costs_one_lookup_and_unwatched_none() {
        let confirmed = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
        let unwatched = OutPoint::new(Txid::from_byte_array([2; 32]), 0);
        let mined = spend(confirmed);
        let node = Arc::new(Mutex::new(Node::default()));
        node.lock().unwrap().mine(vec![mined.clone()]);
        let (url, calls) = mock_node(&node);
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        record_confirmed_spend(&mut watcher, &mined);
        watcher.handle_command(WatcherCommand::RegisterWatchRequest {
            outpoint: unwatched,
            script_pubkey: ScriptBuf::new(),
        });

        watcher.handle_event(WatchEvent::Missed);
        watcher.handle_command(WatcherCommand::Unwatch {
            outpoint: unwatched,
            script_pubkey: ScriptBuf::new(),
        });
        watcher.retry_pending_work();

        assert_eq!(*calls.lock().unwrap(), ["getrawtransaction"]);
        assert!(watcher.pending_reconcile.is_empty());
        assert_eq!(recorded_spend(&watcher, confirmed), Some(mined));
        assert!(is_recorded_confirmed(&watcher, confirmed));
    }

    /// A reorg replaced the block holding the recorded spend, and the
    /// notifications that would have said so were lost. The stale spend must
    /// give way to the one now on the chain.
    #[test]
    fn reorged_out_spend_gives_way_to_the_spend_on_chain() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        let orphaned = spend(outpoint);
        let mut mined = spend(outpoint);
        mined.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mine(vec![mined.clone()]);
            node.reorged_out.push(orphaned.clone());
        }
        let (url, _calls) = mock_node(&node);
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        record_confirmed_spend(&mut watcher, &orphaned);

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();

        assert_eq!(recorded_spend(&watcher, outpoint), Some(mined));
        assert!(is_recorded_confirmed(&watcher, outpoint));
        assert!(watcher.pending_reconcile.is_empty());
    }

    /// A reorged-out spend can carry the only copy of a preimage, so it stays
    /// on record until its replacement is found, even if looking for that
    /// replacement fails.
    #[test]
    fn orphaned_spend_is_kept_until_its_replacement_is_found() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        let orphaned = spend(outpoint);
        let mut mined = spend(outpoint);
        mined.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mine(vec![mined.clone()]);
            node.reorged_out.push(orphaned.clone());
        }
        let lookups_fail = Arc::new(AtomicBool::new(true));
        let (url, _calls) = mock_core_rpc({
            let (node, lookups_fail) = (node.clone(), lookups_fail.clone());
            move |method, params| {
                if method == "gettxspendingprevout" && lookups_fail.load(Ordering::Relaxed) {
                    return Err(json!({ "code": -28, "message": "Verifying blocks" }));
                }
                node.lock().unwrap().answer(method, params)
            }
        });
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        record_confirmed_spend(&mut watcher, &orphaned);

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();
        assert_eq!(recorded_spend(&watcher, outpoint), Some(orphaned));
        assert!(!is_recorded_confirmed(&watcher, outpoint));
        assert_eq!(watcher.pending_reconcile, [outpoint]);

        lookups_fail.store(false, Ordering::Relaxed);
        watcher.retry_pending_work();
        assert_eq!(recorded_spend(&watcher, outpoint), Some(mined));
        assert!(is_recorded_confirmed(&watcher, outpoint));
        assert!(watcher.pending_reconcile.is_empty());
    }

    /// While the txindex syncs, Core cannot find a confirmed spend at all.
    /// That is not evidence of a reorg, so the spend must stay on record.
    #[test]
    fn confirmed_spend_is_kept_while_the_txindex_syncs() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        let mined = spend(outpoint);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mine(vec![mined.clone()]);
            node.txindex_syncing = true;
        }
        let (url, _calls) = mock_node(&node);
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        record_confirmed_spend(&mut watcher, &mined);

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();
        assert_eq!(recorded_spend(&watcher, outpoint), Some(mined.clone()));
        assert_eq!(watcher.pending_reconcile, [outpoint]);

        node.lock().unwrap().txindex_syncing = false;
        watcher.retry_pending_work();
        assert_eq!(recorded_spend(&watcher, outpoint), Some(mined));
        assert!(is_recorded_confirmed(&watcher, outpoint));
        assert!(watcher.pending_reconcile.is_empty());
    }

    /// Not finding a confirmed spend while the txindex syncs proves nothing,
    /// so the spend keeps its confirmed mark and a mempool rival cannot
    /// overwrite it.
    #[test]
    fn mempool_rival_cannot_replace_a_confirmed_spend_while_the_txindex_syncs() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        let mined = spend(outpoint);
        let mut rival = spend(outpoint);
        rival.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mine(vec![mined.clone()]);
            node.mempool.push(rival);
            node.txindex_syncing = true;
        }
        let (url, _calls) = mock_node(&node);
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        record_confirmed_spend(&mut watcher, &mined);

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();

        assert_eq!(recorded_spend(&watcher, outpoint), Some(mined));
        assert!(is_recorded_confirmed(&watcher, outpoint));
        assert_eq!(watcher.pending_reconcile, [outpoint]);
    }

    /// The recorded mempool spend was replaced, and the notification for its
    /// replacement was lost. Core finds mempool spends without the txindex, so
    /// the replacement must be recorded while the index is still syncing.
    #[test]
    fn replaced_mempool_spend_is_recovered_while_the_txindex_syncs() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        let replaced = spend(outpoint);
        let mut replacement = spend(outpoint);
        replacement.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mempool.push(replacement.clone());
            node.txindex_syncing = true;
        }
        let (url, calls) = mock_node(&node);
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        watcher
            .registry
            .upsert_watch(&WatchRequest {
                outpoint,
                script_pubkey: ScriptBuf::new(),
                in_block: false,
                spent_tx: Some(replaced),
            })
            .unwrap();

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();

        assert_eq!(recorded_spend(&watcher, outpoint), Some(replacement));
        assert!(!is_recorded_confirmed(&watcher, outpoint));
        assert!(watcher.pending_reconcile.is_empty());
        assert!(!calls.lock().unwrap().iter().any(|call| call == "getblock"));
    }

    /// A syncing txindex can hold the funding block but not the spender's, so
    /// the block scan finds a mined spend whose confirmations Core cannot
    /// report yet. Found in a block, it is recorded as confirmed at once, and
    /// the watch stays queued, without scanning again, until Core confirms it.
    #[test]
    fn spend_found_ahead_of_the_txindex_is_confirmed_once_indexed() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        let mined = spend(outpoint);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mine(vec![mined.clone()]);
            node.txindex_syncing = true;
            node.indexed_below = 2;
        }
        let (url, calls) = mock_node(&node);
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        watcher.handle_command(WatcherCommand::RegisterWatchRequest {
            outpoint,
            script_pubkey: ScriptBuf::new(),
        });

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();
        assert_eq!(recorded_spend(&watcher, outpoint), Some(mined.clone()));
        assert!(is_recorded_confirmed(&watcher, outpoint));
        assert_eq!(watcher.pending_reconcile, [outpoint]);
        let scanned = calls.lock().unwrap().len();
        assert!(calls.lock().unwrap().iter().any(|call| call == "getblock"));

        watcher.retry_pending_work();
        assert_eq!(watcher.pending_reconcile, [outpoint]);
        node.lock().unwrap().txindex_syncing = false;
        watcher.retry_pending_work();
        assert_eq!(recorded_spend(&watcher, outpoint), Some(mined));
        assert!(is_recorded_confirmed(&watcher, outpoint));
        assert!(watcher.pending_reconcile.is_empty());
        assert!(
            !calls.lock().unwrap()[scanned..]
                .iter()
                .any(|call| call == "getblock"),
            "waiting for the txindex must not scan blocks again"
        );
    }

    /// Core names a mempool spender that is evicted before its confirmations
    /// are read. With the txindex syncing, Core cannot find it either, and
    /// cannot say whether it was mined, so it is kept as seen in the mempool
    /// and checked again; the output is still unspent, which settles it.
    #[test]
    fn spend_leaving_the_mempool_mid_lookup_is_not_recorded_as_confirmed() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        let evicted = spend(outpoint);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mempool.push(evicted.clone());
            node.txindex_syncing = true;
            node.indexed_below = 2;
        }
        let (url, _calls) = mock_core_rpc({
            let node = node.clone();
            move |method, params| {
                let mut node = node.lock().unwrap();
                if method == "getrawtransaction" && params[1] == json!(true) {
                    node.mempool.clear();
                }
                // Evicted, never mined: the output stays unspent.
                if method == "gettxout" {
                    return Ok(json!({
                        "bestblock": node.chain[node.tip() as usize].block_hash(),
                        "confirmations": 1,
                        "value": 0.0001,
                        "scriptPubKey": { "asm": "", "hex": "", "type": null },
                        "coinbase": false,
                    }));
                }
                node.answer(method, params)
            }
        });
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        watcher.handle_command(WatcherCommand::RegisterWatchRequest {
            outpoint,
            script_pubkey: ScriptBuf::new(),
        });

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();
        assert_eq!(recorded_spend(&watcher, outpoint), Some(evicted.clone()));
        assert!(!is_recorded_confirmed(&watcher, outpoint));
        assert_eq!(watcher.pending_reconcile, [outpoint]);

        watcher.retry_pending_work();
        assert_eq!(recorded_spend(&watcher, outpoint), Some(evicted));
        assert!(!is_recorded_confirmed(&watcher, outpoint));
        assert!(watcher.pending_reconcile.is_empty());
    }

    /// Core names a mempool spender, then a block holding a rival spend
    /// replaces it before its confirmations are read. The output is spent on
    /// chain, but by the rival, so the evicted spender must not be recorded as
    /// the confirmed spend.
    #[test]
    fn spender_displaced_by_a_mined_rival_mid_lookup_is_not_recorded_as_confirmed() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        let evicted = spend(outpoint);
        let mut rival = spend(outpoint);
        rival.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mempool.push(evicted.clone());
            node.txindex_syncing = true;
            node.indexed_below = 2;
        }
        let (url, _calls) = mock_core_rpc({
            let (node, evicted_txid) = (node.clone(), evicted.compute_txid());
            let rival = rival.clone();
            move |method, params| {
                let mut node = node.lock().unwrap();
                if method == "getrawtransaction"
                    && params[1] == json!(true)
                    && params[0] == json!(evicted_txid)
                    && !node.mempool.is_empty()
                {
                    node.mempool.clear();
                    node.mine(vec![rival.clone()]);
                }
                node.answer(method, params)
            }
        });
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        watcher.handle_command(WatcherCommand::RegisterWatchRequest {
            outpoint,
            script_pubkey: ScriptBuf::new(),
        });

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();
        assert!(
            !(recorded_spend(&watcher, outpoint) == Some(evicted.clone())
                && is_recorded_confirmed(&watcher, outpoint)),
            "the evicted spender is recorded as confirmed"
        );

        watcher.retry_pending_work();
        assert_eq!(recorded_spend(&watcher, outpoint), Some(rival));
        assert!(is_recorded_confirmed(&watcher, outpoint));
    }

    /// `gettxout` for an output still in Core's UTXO set.
    fn unspent_output(node: &Node) -> Value {
        json!({
            "bestblock": node.chain[node.tip() as usize].block_hash(),
            "confirmations": 1,
            "value": 0.0001,
            "scriptPubKey": { "asm": "", "hex": "", "type": null },
            "coinbase": false,
        })
    }

    /// A reorg removed the block holding the confirmed spend while the txindex
    /// syncs, and the notifications saying so were lost. The output is back in
    /// Core's UTXO set, which needs no txindex, so no mined spend exists and
    /// the spend now in the mempool must replace the record.
    #[test]
    fn spend_reorged_out_during_the_txindex_sync_gives_way_to_the_mempool_spend() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        let orphaned = spend(outpoint);
        let mut replacement = spend(outpoint);
        replacement.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mempool.push(replacement.clone());
            node.txindex_syncing = true;
            node.indexed_below = 2;
        }
        let (url, calls) = mock_core_rpc({
            let node = node.clone();
            move |method, params| {
                let node = node.lock().unwrap();
                if method == "gettxout" && params[2] == json!(false) {
                    return Ok(unspent_output(&node));
                }
                node.answer(method, params)
            }
        });
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        record_confirmed_spend(&mut watcher, &orphaned);

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();

        assert_eq!(recorded_spend(&watcher, outpoint), Some(replacement));
        assert!(!is_recorded_confirmed(&watcher, outpoint));
        assert!(watcher.pending_reconcile.is_empty());
        assert!(!calls.lock().unwrap().iter().any(|call| call == "getblock"));
    }

    /// The txindex finishes syncing between the funding lookup, which could
    /// not find the funding transaction yet, and the check of whether it is
    /// synced. "No spend" is unproven, so the watch must stay queued.
    #[test]
    fn funding_lookup_racing_the_end_of_the_txindex_sync_stays_queued() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        let mined = spend(outpoint);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mine(vec![mined.clone()]);
            node.txindex_syncing = true;
            node.indexed_below = 1;
        }
        let (url, _calls) = mock_core_rpc({
            let node = node.clone();
            let funding_lookups = AtomicU64::new(0);
            move |method, params| {
                let mut node = node.lock().unwrap();
                let answer = node.answer(method, params);
                // The second funding lookup is the last before the index
                // catches up.
                if method == "getrawtransaction"
                    && params[0] == json!(outpoint.txid)
                    && funding_lookups.fetch_add(1, Ordering::SeqCst) == 1
                {
                    node.txindex_syncing = false;
                }
                answer
            }
        });
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        watcher.handle_command(WatcherCommand::RegisterWatchRequest {
            outpoint,
            script_pubkey: ScriptBuf::new(),
        });

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();
        assert_eq!(watcher.pending_reconcile, [outpoint]);

        watcher.retry_pending_work();
        assert_eq!(recorded_spend(&watcher, outpoint), Some(mined));
        assert!(is_recorded_confirmed(&watcher, outpoint));
        assert!(watcher.pending_reconcile.is_empty());
    }

    /// The txindex finishes syncing between reading the confirmations of a
    /// spend the block scan found and the check of whether it is synced. The
    /// scan found it in a block, so it is still recorded as confirmed and
    /// kept queued until Core confirms it.
    #[test]
    fn spend_found_as_the_txindex_finishes_syncing_is_recorded_as_confirmed() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        let mined = spend(outpoint);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mine(vec![mined.clone()]);
            node.txindex_syncing = true;
            node.indexed_below = 2;
        }
        let (url, _calls) = mock_core_rpc({
            let (node, mined_txid) = (node.clone(), mined.compute_txid());
            move |method, params| {
                let mut node = node.lock().unwrap();
                let answer = node.answer(method, params);
                if method == "getrawtransaction" && params[0] == json!(mined_txid) {
                    node.txindex_syncing = false;
                }
                answer
            }
        });
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        watcher.handle_command(WatcherCommand::RegisterWatchRequest {
            outpoint,
            script_pubkey: ScriptBuf::new(),
        });

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();
        assert_eq!(recorded_spend(&watcher, outpoint), Some(mined.clone()));
        assert!(is_recorded_confirmed(&watcher, outpoint));
        assert_eq!(watcher.pending_reconcile, [outpoint]);

        watcher.retry_pending_work();
        assert_eq!(recorded_spend(&watcher, outpoint), Some(mined));
        assert!(is_recorded_confirmed(&watcher, outpoint));
        assert!(watcher.pending_reconcile.is_empty());
    }

    /// The spend is mined and gone from the mempool, but Core's txindex is
    /// still catching up and cannot find the funding transaction. "No spend"
    /// is unproven, so the watch stays queued until Core can answer.
    #[test]
    fn watch_stays_queued_while_core_cannot_find_the_funding_tx() {
        let funding = spend(OutPoint::new(Txid::from_byte_array([9; 32]), 0));
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        let mined = spend(outpoint);
        let node = Arc::new(Mutex::new(Node::default()));
        {
            let mut node = node.lock().unwrap();
            node.mine(Vec::new());
            node.mine(vec![funding]);
            node.mine(vec![mined.clone()]);
            node.txindex_syncing = true;
        }
        let (url, _calls) = mock_node(&node);
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        watcher.handle_command(WatcherCommand::RegisterWatchRequest {
            outpoint,
            script_pubkey: ScriptBuf::new(),
        });

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();
        assert_eq!(watcher.pending_reconcile, [outpoint]);
        assert_eq!(recorded_spend(&watcher, outpoint), None);

        node.lock().unwrap().txindex_syncing = false;
        watcher.retry_pending_work();
        assert!(watcher.pending_reconcile.is_empty());
        assert_eq!(recorded_spend(&watcher, outpoint), Some(mined));
        assert!(is_recorded_confirmed(&watcher, outpoint));
    }

    /// Contract outpoints are watched long before their transaction is
    /// broadcast, and usually it never is. With the txindex synced, Core not
    /// knowing the funding transaction proves there is no spend, so the watch
    /// leaves the queue instead of being re-checked on every pass.
    #[test]
    fn never_broadcast_outpoint_leaves_the_queue() {
        let outpoint = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
        let (url, _calls) = mock_node(&Arc::new(Mutex::new(Node::default())));
        let mut watcher = core_watcher(&CoreRpcConfig {
            url,
            ..CoreRpcConfig::default()
        });
        watcher.handle_command(WatcherCommand::RegisterWatchRequest {
            outpoint,
            script_pubkey: ScriptBuf::new(),
        });

        watcher.handle_event(WatchEvent::Missed);
        watcher.retry_pending_work();

        assert!(watcher.pending_reconcile.is_empty());
        assert_eq!(recorded_spend(&watcher, outpoint), None);
    }
}
