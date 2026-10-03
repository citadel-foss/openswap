//! Public watchtower service for sending commands to and receiving events from the watcher.

use bitcoin::{OutPoint, ScriptBuf};
use crossbeam_channel::{unbounded, RecvTimeoutError};
use std::{
    panic::{self, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, SendError, Sender as StdSender},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{
    lock_debug,
    wallet::{AnyBlockchain, BackendConfig},
    watch_tower::{
        registry_storage::FileRegistry,
        watcher::{Role, Watcher, WatcherCommand, WatcherEvent},
        watcher_error::WatcherError,
    },
};

/// Watcher thread handle, shared because [`WatchService`] is `Clone`.
/// The `Option` is taken by whichever clone shuts down first.
type WatcherHandle = Arc<Mutex<Option<JoinHandle<Result<(), WatcherError>>>>>;

/// Interval between shutdown checks while waiting for a watcher reply.
/// Short in tests so the blocking tests stay fast.
#[cfg(not(test))]
const WATCH_REPLY_TIMEOUT: Duration = crate::utill::HEART_BEAT_INTERVAL;
#[cfg(test)]
const WATCH_REPLY_TIMEOUT: Duration = Duration::from_millis(50);

/// Marker type for the Maker role in the watchtower.
pub struct MakerRole;

impl Role for MakerRole {
    const RUN_DISCOVERY: bool = false;
}

/// Client-facing service for sending watcher commands and receiving events.
#[derive(Clone)]
pub struct WatchService {
    tx: StdSender<WatcherCommand>,
    /// Watcher thread handle, joined on shutdown so its exit result is not lost.
    handle: WatcherHandle,
    /// Role flag checked by the watcher and every Electrum connection it owns.
    watcher_shutdown: Arc<AtomicBool>,
    /// Set while the watcher runs, then left false after any terminal exit.
    alive: Arc<AtomicBool>,
    /// The watcher's latest block height, 0 while unknown.
    tip: Arc<AtomicU64>,
}

impl WatchService {
    fn from_parts(
        tx: StdSender<WatcherCommand>,
        handle: JoinHandle<Result<(), WatcherError>>,
        watcher_shutdown: Arc<AtomicBool>,
        alive: Arc<AtomicBool>,
        tip: Arc<AtomicU64>,
    ) -> Self {
        Self {
            tx,
            handle: Arc::new(Mutex::new(Some(handle))),
            watcher_shutdown,
            alive,
            tip,
        }
    }

    /// Spawns a watcher whose lifetime is reflected by [`Self::is_alive`].
    pub(crate) fn spawn(
        tx: StdSender<WatcherCommand>,
        watcher_shutdown: Arc<AtomicBool>,
        tip: Arc<AtomicU64>,
        run: impl FnOnce() -> Result<(), WatcherError> + Send + 'static,
    ) -> std::io::Result<Self> {
        let alive = Arc::new(AtomicBool::new(true));
        let thread_alive = alive.clone();
        let handle = thread::Builder::new()
            .name("Watcher thread".to_string())
            .spawn(move || run_with_liveness(thread_alive, run))?;
        Ok(Self::from_parts(tx, handle, watcher_shutdown, alive, tip))
    }

    /// Sticky watcher availability; false only after channel-level death:
    /// thread exit, send failure, reply disconnect, or shutdown. A reply —
    /// even an error — is proof the thread answered. Does not probe backend
    /// progress or individual registrations.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Latest block height the watcher has seen, while it runs and knows one.
    pub(crate) fn tip(&self) -> Option<u64> {
        let tip = self.tip.load(Ordering::Acquire);
        (tip > 0 && self.is_alive()).then_some(tip)
    }

    fn send_command(&self, command: WatcherCommand) -> Result<(), SendError<WatcherCommand>> {
        match self.tx.send(command) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.alive.store(false, Ordering::Release);
                Err(e)
            }
        }
    }

    /// Registers an outpoint to be monitored for future spends.
    /// Errs if the watcher thread is gone.
    pub fn register_watch_request(
        &self,
        outpoint: OutPoint,
        script_pubkey: ScriptBuf,
    ) -> Result<(), SendError<WatcherCommand>> {
        self.send_command(WatcherCommand::RegisterWatchRequest {
            outpoint,
            script_pubkey,
        })
    }

    /// Re-arms the watches for every live contract in the wallet. The registry
    /// is memory-only, so a restart begins with nothing watched. Blocks until
    /// the rebuild (Core rescan included) replies, so startup never runs
    /// unwatched. The watcher retries a failed rescan until it completes, so
    /// an Err here means the watcher is gone or shutting down.
    pub fn rebuild_watches(&self, watches: Vec<(OutPoint, ScriptBuf)>) -> Result<(), WatcherError> {
        let (reply_tx, reply_rx) = unbounded();
        self.send_command(WatcherCommand::RebuildWatches {
            watches,
            reply: reply_tx,
        })
        .map_err(|_| WatcherError::SendError)?;
        // No total cap: a deep Core rescan legitimately takes minutes. The loop
        // only exists so teardown can still cut the wait short.
        loop {
            match reply_rx.recv_timeout(WATCH_REPLY_TIMEOUT) {
                Ok(result) => return result.map_err(WatcherError::General),
                Err(RecvTimeoutError::Disconnected) => {
                    self.alive.store(false, Ordering::Release);
                    return Err(WatcherError::SendError);
                }
                Err(RecvTimeoutError::Timeout) => {
                    if self.watcher_shutdown.load(Ordering::Relaxed) {
                        return Err(WatcherError::Shutdown);
                    }
                    // A rescan legitimately takes minutes, but a stuck one is
                    // invisible otherwise — keep the wait visible in logs.
                    log::warn!("still waiting for watch rebuild reply");
                }
            }
        }
    }

    /// Queries whether a previously registered outpoint has been spent and
    /// waits for this query's own reply. The private channel is what stops
    /// concurrent callers from consuming each other's answers.
    ///
    /// Send the command once and keep waiting while the watcher is alive. A
    /// backend call can legitimately take longer than a few heartbeats over
    /// Tor; re-sending on each timeout only queues duplicate work behind the
    /// slow call. Backend errors arrive as `WatcherEvent::Error`, a dead
    /// watcher disconnects the reply channel, and shutdown cuts the wait short.
    pub fn watch_request(&self, outpoint: OutPoint) -> Result<WatcherEvent, WatcherError> {
        let (reply_tx, reply_rx) = unbounded();
        self.send_command(WatcherCommand::WatchRequest {
            outpoint,
            reply: reply_tx,
        })
        .map_err(|_| WatcherError::SendError)?;

        loop {
            match reply_rx.recv_timeout(WATCH_REPLY_TIMEOUT) {
                Ok(WatcherEvent::Error(error)) => {
                    // The watcher answered with an error; callers must not read
                    // it as "not spent".
                    return Err(WatcherError::General(format!(
                        "watcher could not answer request for {outpoint}: {error}"
                    )));
                }
                Ok(event) => return Ok(event),
                Err(RecvTimeoutError::Disconnected) => {
                    self.alive.store(false, Ordering::Release);
                    return Err(WatcherError::SendError);
                }
                Err(RecvTimeoutError::Timeout) => {
                    if self.watcher_shutdown.load(Ordering::Relaxed) {
                        return Err(WatcherError::Shutdown);
                    }
                    // Warn, not debug: an alive watcher that stops answering is
                    // the wedge case liveness cannot see — it must show in logs.
                    log::warn!("still waiting for watcher reply for {outpoint}");
                }
            }
        }
    }

    /// Stops monitoring an outpoint by removing its watch entry from the
    /// registry. The `scriptPubKey` lets the watcher drop the Electrum
    /// subscription too without re-resolving it from the network.
    /// Errs if the watcher thread is gone.
    pub fn unwatch(
        &self,
        outpoint: OutPoint,
        script_pubkey: ScriptBuf,
    ) -> Result<(), SendError<WatcherCommand>> {
        self.send_command(WatcherCommand::Unwatch {
            outpoint,
            script_pubkey,
        })
    }

    /// Signals the watcher to shut down gracefully and joins its thread,
    /// aborting any Electrum retry backoff it may be stuck in.
    pub fn shutdown(&self) {
        let _ = self.send_command(WatcherCommand::Shutdown);
        self.watcher_shutdown.store(true, Ordering::Relaxed);
        self.alive.store(false, Ordering::Release);
        let handle = lock_debug!(self.handle.lock())
            .ok()
            .and_then(|mut h| h.take());
        if let Some(handle) = handle {
            let thread = handle.thread().clone();
            crate::utill::log_shutdown_join_start("watch_service", &thread);
            let result = handle.join();
            let outcome = match &result {
                Ok(Ok(())) => "ok",
                Ok(Err(_)) => "error",
                Err(_) => "panic",
            };
            crate::utill::log_shutdown_join_done("watch_service", &thread, outcome);
            // The watcher wrapper logs the detailed result when it exits.
        }
    }

    /// Makes the watcher unavailable without stopping its owner, allowing
    /// integration tests to exercise fail-closed behavior.
    #[cfg(feature = "integration-test")]
    pub fn stop_watcher_for_test(&self) {
        let _ = self.send_command(WatcherCommand::Shutdown);
        self.alive.store(false, Ordering::Release);
    }
}

/// Runs a watcher while publishing and logging its complete lifetime. Panics
/// are logged here and then resumed so the retained join handle still reports
/// the correct outcome during orderly shutdown.
fn run_with_liveness(
    alive: Arc<AtomicBool>,
    run: impl FnOnce() -> Result<(), WatcherError>,
) -> Result<(), WatcherError> {
    let result = panic::catch_unwind(AssertUnwindSafe(run));
    alive.store(false, Ordering::Release);
    match result {
        Ok(Ok(())) => {
            log::info!("watcher thread exited cleanly");
            Ok(())
        }
        Ok(Err(e)) => {
            log::error!("watcher thread exited with error: {e:?}");
            Err(e)
        }
        Err(payload) => {
            log::error!("watcher thread panicked");
            panic::resume_unwind(payload)
        }
    }
}

/// Shares the Maker's stop flag with its watcher and backend.
/// This keeps teardown from waiting through backend retries.
pub fn start_maker_watch_service(
    backend: &BackendConfig,
    shutdown: Arc<AtomicBool>,
) -> Result<WatchService, WatcherError> {
    let blockchain =
        AnyBlockchain::from_config_with_shutdown(&backend.for_watcher(), shutdown.clone())?;
    let registry = FileRegistry::new();

    // Channels
    let (tx_requests, rx_requests) = mpsc::channel();
    let mut watcher = Watcher::<MakerRole>::new(
        blockchain,
        registry,
        rx_requests,
        Vec::new(),
        None,
        shutdown.clone(),
    );
    // Makers don't run discovery, so pass an already-complete flag.
    let tip = watcher.tip.clone();
    WatchService::spawn(tx_requests, shutdown, tip, move || {
        watcher.run(Arc::new(AtomicBool::new(true)))
    })
    .map_err(WatcherError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_handle() -> JoinHandle<Result<(), WatcherError>> {
        thread::spawn(|| Ok(()))
    }

    fn test_service(
        tx: StdSender<WatcherCommand>,
        handle: JoinHandle<Result<(), WatcherError>>,
        watcher_shutdown: bool,
    ) -> WatchService {
        WatchService::from_parts(
            tx,
            handle,
            Arc::new(AtomicBool::new(watcher_shutdown)),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicU64::new(0)),
        )
    }

    #[test]
    fn liveness_tracks_the_complete_thread_lifetime() {
        let alive = Arc::new(AtomicBool::new(true));
        let thread_alive = alive.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            run_with_liveness(thread_alive, || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        });

        started_rx.recv().unwrap();
        assert!(alive.load(Ordering::Acquire));
        release_tx.send(()).unwrap();
        assert!(handle.join().unwrap().is_ok());
        assert!(!alive.load(Ordering::Acquire));
    }

    #[test]
    fn liveness_is_cleared_on_error_and_panic() {
        let errored = Arc::new(AtomicBool::new(false));
        let result = run_with_liveness(errored.clone(), || {
            Err(WatcherError::General("test error".to_string()))
        });
        assert!(result.is_err());
        assert!(!errored.load(Ordering::Acquire));

        let panicked = Arc::new(AtomicBool::new(false));
        let result = panic::catch_unwind({
            let panicked = panicked.clone();
            move || run_with_liveness(panicked, || panic!("test panic"))
        });
        assert!(result.is_err());
        assert!(!panicked.load(Ordering::Acquire));
    }

    #[test]
    fn slow_watcher_gets_one_request_and_can_reply_late() {
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            if let Ok(WatcherCommand::WatchRequest { reply, .. }) = rx.recv() {
                thread::sleep(WATCH_REPLY_TIMEOUT * 3);
                _ = reply.send(WatcherEvent::NoOutpoint);
            }
            Ok(())
        });
        let service = test_service(tx, handle, false);
        let event = service.watch_request(OutPoint::null()).unwrap();
        assert!(matches!(event, WatcherEvent::NoOutpoint));
    }

    #[test]
    fn shutdown_flag_cuts_wait_short() {
        let (tx, rx) = mpsc::channel();
        let service = test_service(tx, dummy_handle(), true);
        let err = service.watch_request(OutPoint::null()).unwrap_err();
        assert!(matches!(err, WatcherError::Shutdown));
        assert_eq!(rx.try_iter().count(), 1);
    }

    #[test]
    fn dead_watcher_errors_without_retry() {
        let (tx, rx) = mpsc::channel::<WatcherCommand>();
        drop(rx);
        let service = test_service(tx, dummy_handle(), false);
        let err = service.watch_request(OutPoint::null()).unwrap_err();
        assert!(matches!(err, WatcherError::SendError));
        assert!(!service.is_alive());
    }

    #[test]
    fn answered_request_returns_event_without_retry() {
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            if let Ok(WatcherCommand::WatchRequest { reply, .. }) = rx.recv() {
                _ = reply.send(WatcherEvent::NoOutpoint);
            }
            Ok(())
        });
        let service = test_service(tx, handle, false);
        let event = service.watch_request(OutPoint::null()).unwrap();
        assert!(matches!(event, WatcherEvent::NoOutpoint));
    }

    #[test]
    fn error_event_is_returned_as_error() {
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            if let Ok(WatcherCommand::WatchRequest { reply, .. }) = rx.recv() {
                _ = reply.send(WatcherEvent::Error("registry lock poisoned".to_string()));
            }
            Ok(())
        });
        let service = test_service(tx, handle, false);
        let err = service.watch_request(OutPoint::null()).unwrap_err();
        assert!(matches!(err, WatcherError::General(_)));
    }

    #[test]
    fn rebuild_error_reply_keeps_liveness() {
        let (tx, rx) = mpsc::channel();
        let (reply_hold_tx, reply_hold_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            if let Ok(WatcherCommand::RebuildWatches { reply, .. }) = rx.recv() {
                _ = reply_hold_tx.send(reply);
            }
            Ok(())
        });
        let service = test_service(tx, handle, false);
        let (done_tx, done_rx) = mpsc::channel();
        let svc = service.clone();
        let waiter = thread::spawn(move || _ = done_tx.send(svc.rebuild_watches(Vec::new())));
        let reply = reply_hold_rx.recv().unwrap();
        // The watcher has the command but has not replied, so the caller must
        // still be blocked.
        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        _ = reply.send(Err("rescan failed".to_string()));
        assert!(done_rx.recv().unwrap().is_err());
        // An answered reply — even an error — is not channel-level death.
        assert!(service.is_alive());
        waiter.join().unwrap();
    }

    #[test]
    fn rebuild_watches_returns_shutdown_without_reply() {
        let (tx, _rx) = mpsc::channel();
        let service = test_service(tx, dummy_handle(), true);
        let err = service.rebuild_watches(Vec::new()).unwrap_err();
        assert!(matches!(err, WatcherError::Shutdown));
    }
}
