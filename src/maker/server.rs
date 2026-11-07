//! OpenSwap Maker Server.

use std::{
    collections::HashSet,
    io::{ErrorKind, Read},
    net::{Ipv4Addr, TcpListener, TcpStream},
    sync::{
        atomic::Ordering::{self, Relaxed},
        Arc, Mutex, MutexGuard,
    },
    thread::{self, sleep},
    time::{Duration, Instant},
};

use bitcoin::OutPoint;

#[cfg(not(feature = "integration-test"))]
use crate::maker::rpc::server::MakerRpc;
use crate::{
    lock_debug,
    maker::nostr::broadcast_bond_on_nostr,
    protocol::common_messages::{
        message_name, MakerToTakerMessage, ProtocolVersion, TakerToMakerMessage, UnsupportedMessage,
    },
    utill::{
        now_secs, HEART_BEAT_INTERVAL, MAX_RPC_MESSAGE_SIZE, MIN_RELAY_FEE_RATE,
        UNBROADCAST_DISCARD_GRACE,
    },
    wallet::{AnyBlockchain, Blockchain, RecoveryOutcome, RecoveryReport, SwapRole, Wallet},
    watch_tower::{service::WatchService, watcher::WatcherEvent},
};

use super::{
    api::MakerServer,
    error::MakerError,
    handlers::{
        emit_maker_success_report, handle_message, ConnectionState, Maker, MAX_CONCURRENT_SWAPS,
    },
};

/// A live swap normally owns a route-heartbeat connection and one protocol
/// connection. The third slot allows a replacement connection to arrive before
/// the dead one has noticed the disconnect.
const MAX_INBOUND_CONNECTIONS: usize = MAX_CONCURRENT_SWAPS * 3;
/// Unidentified peers may consume only one third of the handler budget. The
/// other two thirds cover the steady heartbeat and protocol connections.
const MAX_PENDING_CONNECTIONS: usize = MAX_CONCURRENT_SWAPS;
/// A burst lets all 30 swaps reconnect together; sustained churn stays bounded.
const CONNECTIONS_PER_SECOND: f64 = 4.0;
const CONNECTION_BURST: f64 = MAX_CONCURRENT_SWAPS as f64;
// Keeping the unfunded cap full must cost a peer the whole connection rate
// budget; below that, it refuses every taker more cheaply than a flood.
#[cfg(not(feature = "integration-test"))]
const _: () = assert!(
    super::handlers::MAX_UNFUNDED_ADMISSIONS as f64
        >= IDLE_CONNECTION_TIMEOUT.as_secs() as f64 * CONNECTIONS_PER_SECOND
);
/// Tor has already established the TCP stream, so protocol identification
/// should finish well inside this deadline.
const PENDING_CONNECTION_TIMEOUT: Duration = Duration::from_secs(20);
/// Maximum time to finish a frame after its first byte arrives.
const MESSAGE_ASSEMBLY_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECTION_WRITE_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(not(feature = "integration-test"))]
const MIN_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(feature = "integration-test")]
const MIN_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(1);

struct LimiterState {
    active: usize,
    pending: usize,
    tokens: f64,
    last_refill: Instant,
}

struct ConnectionLimiter {
    state: Mutex<LimiterState>,
}

impl ConnectionLimiter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(LimiterState {
                active: 0,
                pending: 0,
                tokens: CONNECTION_BURST,
                last_refill: Instant::now(),
            }),
        })
    }

    /// A poisoned limiter lock carries no invariant worth aborting for: the
    /// counts are rebuilt from live permits either way.
    fn lock(&self) -> MutexGuard<'_, LimiterState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut state = self.lock();
        let now = Instant::now();
        state.tokens = (state.tokens
            + now.duration_since(state.last_refill).as_secs_f64() * CONNECTIONS_PER_SECOND)
            .min(CONNECTION_BURST);
        state.last_refill = now;
        if state.tokens < 1.0 {
            return None;
        }
        state.tokens -= 1.0;

        // Consume the rate token even at capacity. Under a continuous flood,
        // this prevents a full burst from accumulating while pending sockets
        // wait for their deadline.
        if state.active >= MAX_INBOUND_CONNECTIONS || state.pending >= MAX_PENDING_CONNECTIONS {
            return None;
        }
        state.active += 1;
        state.pending += 1;

        Some(ConnectionPermit {
            limiter: Arc::clone(self),
            pending: true,
        })
    }
}

/// Releases both counters on every exit path, including handler panics.
struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
    pending: bool,
}

impl ConnectionPermit {
    fn mark_established(&mut self) {
        if std::mem::replace(&mut self.pending, false) {
            self.limiter.lock().pending -= 1;
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut state = self.limiter.lock();
        if self.pending {
            state.pending -= 1;
        }
        state.active -= 1;
    }
}

enum HeartbeatAction {
    Accept,
    Reject,
    Throttle,
}

/// Admits a keepalive for `id`. A socket is bound to the first swap id it
/// keeps alive, so one persistent connection cannot rotate through many ids
/// and hold that many unfunded admissions open.
fn admit_heartbeat(
    id: &str,
    known_swap: bool,
    heartbeat_swap: &mut Option<String>,
    last_keepalive: &mut Option<Instant>,
    permit: &mut ConnectionPermit,
) -> HeartbeatAction {
    if !known_swap || heartbeat_swap.as_deref().is_some_and(|bound| bound != id) {
        HeartbeatAction::Reject
    } else if last_keepalive.is_some_and(|last| last.elapsed() < MIN_KEEPALIVE_INTERVAL) {
        HeartbeatAction::Throttle
    } else {
        heartbeat_swap.get_or_insert_with(|| id.to_owned());
        *last_keepalive = Some(Instant::now());
        permit.mark_established();
        HeartbeatAction::Accept
    }
}

/// Idle connection timeout (production).
#[cfg(not(feature = "integration-test"))]
pub const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(900);

/// Idle connection timeout (testing). Must sit above a single slow electrum
/// call (~10s over Tor) since keepalives can only land between RPCs; the slow
/// test miner keeps the refund locktime margin regardless of wall clock.
#[cfg(feature = "integration-test")]
pub const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Socket read timeout for swap connections, kept separate from
/// `IDLE_CONNECTION_TIMEOUT`. Sized for the quiet phases of a healthy swap —
/// contract confirmation waits are block-bound, not message-bound.
#[cfg(not(feature = "integration-test"))]
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(1800);
#[cfg(feature = "integration-test")]
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Fidelity bond update interval (testing): 30 seconds.
#[cfg(feature = "integration-test")]
const FIDELITY_BOND_UPDATE_INTERVAL: Duration = Duration::from_secs(30);

/// Fidelity bond update interval (production): 600 seconds (~1 block).
#[cfg(not(feature = "integration-test"))]
const FIDELITY_BOND_UPDATE_INTERVAL: Duration = Duration::from_secs(600);

/// Nostr bond re-broadcast interval (testing): 30 seconds.
#[cfg(feature = "integration-test")]
const NOSTR_BROADCAST_INTERVAL: Duration = Duration::from_secs(30);

/// Nostr bond re-broadcast interval (production): 30 minutes.
#[cfg(not(feature = "integration-test"))]
const NOSTR_BROADCAST_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Start the maker server. Returns `Ok` when the stop flag ends it, and always
/// joins the threads it started and saves the wallet on the way out.
pub fn start_server(maker: Arc<MakerServer>) -> Result<(), MakerError> {
    let served = serve(Arc::clone(&maker));
    if let Err(e) = &served {
        if !e.is_shutdown() {
            log::error!("[{}] Server failed: {:?}", maker.config.network_port, e);
        }
        // Threads started before the failure would otherwise run on.
        maker.shutdown.store(true, Relaxed);
    }
    let stopped = shutdown_server(&maker);
    match served {
        Err(e) if !e.is_shutdown() => Err(e),
        _ => stopped,
    }
}

fn serve(maker: Arc<MakerServer>) -> Result<(), MakerError> {
    log::info!("[{}] Starting maker server", maker.config.network_port);

    #[cfg(feature = "integration-test")]
    if maker.behavior == super::handlers::MakerBehavior::StopWatcherOnStartup {
        maker.watch_service.stop_watcher_for_test();
    }
    let listener = if maker.watch_service.is_alive() {
        // Tests reserve the port at allocation and hand the socket over, so a
        // parallel test cannot take it between allocation and start.
        #[cfg(feature = "integration-test")]
        let reserved = maker.reserved_network_listener.lock().unwrap().take();
        #[cfg(not(feature = "integration-test"))]
        let reserved: Option<TcpListener> = None;
        let listener = match reserved {
            Some(listener) => listener,
            None => TcpListener::bind(("127.0.0.1", maker.config.network_port)).map_err(|e| {
                log::warn!(
                    "Failed to bind network port {}: {}. Fidelity bond funds may be locked to this port.",
                    maker.config.network_port,
                    e
                );
                MakerError::IO(e)
            })?,
        };
        listener.set_nonblocking(true).map_err(MakerError::IO)?;
        Some(listener)
    } else {
        log::error!(
            "[{}] Watchtower down; recovery-only mode",
            maker.config.network_port
        );
        None
    };

    #[cfg(feature = "integration-test")]
    let maker_address = listener
        .is_some()
        .then(|| format!("127.0.0.1:{}", maker.config.network_port));
    #[cfg(not(feature = "integration-test"))]
    let maker_address = listener
        .is_some()
        .then(|| maker.get_tor_hostname())
        .transpose()?;

    maker.release_orphan_reservations()?;

    // Before the fidelity and liquidity waits, not after: both loop until the
    // wallet has funds, and a maker whose coins are locked in a Lightning
    // HTLC needs the watchdog to refund them before it can ever satisfy
    // those waits. Recovery must not depend on being ready for new swaps.
    #[cfg(feature = "lightning")]
    spawn_lightning_threads(&maker)?;

    // Check for unfinished swapcoins from a previous run and start recovery.
    {
        let (inc, out) = lock_debug!(maker.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .find_unfinished_swapcoins();
        if !inc.is_empty() || !out.is_empty() {
            log::info!(
                "[{}] Incomplete swaps detected on startup: {} incoming, {} outgoing. Starting recovery.",
                maker.config.network_port,
                inc.len(),
                out.len()
            );

            // QA: Reboot recovery could discard funded swapcoins after treating
            // the swap as "funding was never broadcast". Group unfinished coins
            // by swap id before recovery so each discard/recovery decision is
            // scoped to the swap being evaluated, preserving funded recovery
            // material across restarts.
            // Regression coverage: `tests/integration/restart/reboot.rs`.
            let mut groups = std::collections::HashMap::new();
            for incoming in inc {
                let swap_id = incoming.swap_id.clone().ok_or(MakerError::General(
                    "Persisted incoming swapcoin missing swap id",
                ))?;
                groups
                    .entry(swap_id)
                    .or_insert_with(|| (Vec::new(), Vec::new()))
                    .0
                    .push(incoming);
            }
            for outgoing in out {
                let swap_id = outgoing.swap_id.clone().ok_or(MakerError::General(
                    "Persisted outgoing swapcoin missing swap id",
                ))?;
                groups
                    .entry(swap_id)
                    .or_insert_with(|| (Vec::new(), Vec::new()))
                    .1
                    .push(outgoing);
            }

            // A completed swap leaves only the funding versions a bump left
            // behind: retired once their winner is deep, recovered as revived
            // if a reorg mined one. Any other swap is recovered as usual.
            for (swap_id, (inc, out)) in groups {
                if inc.is_empty() && !out.is_empty() && out.iter().all(|coin| coin.replaced) {
                    spawn_version_retirement(&maker, swap_id)?;
                    continue;
                }
                let maker_clone = Arc::clone(&maker);
                let handle = thread::Builder::new()
                    .name(format!("reboot-recovery-{}", maker.config.network_port))
                    .spawn(move || {
                        if let Err(e) =
                            recover_from_swap(maker_clone, swap_id.clone(), inc, out, false)
                        {
                            log::error!("Reboot recovery failed for {}: {:?}", swap_id, e);
                        }
                    })
                    .map_err(MakerError::IO)?;
                maker.thread_pool.add_thread(handle)?;
            }
        }
    }

    // Only after recovery has started: the bond wait has no deadline, and
    // contracts left from a previous run must not wait on it.
    if let Some(maker_address) = maker_address.as_ref() {
        log::info!(
            "[{}] Setting up fidelity bond...",
            maker.config.network_port
        );
        maker.setup_fidelity_bond(maker_address)?;
        spawn_nostr_broadcast_thread(&maker)?;
        log::info!("[{}] Checking swap liquidity...", maker.config.network_port);
        maker.check_swap_liquidity()?;
    }

    {
        let wallet = lock_debug!(maker.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
        log::info!(
            "[{}] Bitcoin Network: {}",
            maker.config.network_port,
            wallet.store.network
        );
        log::info!(
            "[{}] Spendable Wallet Balance: {}",
            maker.config.network_port,
            wallet.get_balances().map_err(MakerError::Wallet)?.spendable
        );
    }

    if listener.is_some() {
        maker.is_setup_complete.store(true, Relaxed);
        log::info!(
            "[{}] Server setup complete! Listening on port {}",
            maker.config.network_port,
            maker.config.network_port
        );
    }

    // Spawn RPC server thread for maker-cli operations
    let maker_rpc = Arc::clone(&maker);
    let rpc_handle = thread::Builder::new()
        .name("rpc-server".to_string())
        .spawn(move || {
            if let Err(e) = crate::maker::rpc::server::start_rpc_server(maker_rpc) {
                log::error!("RPC server error: {:?}", e);
            }
        })
        .map_err(MakerError::IO)?;
    maker.thread_pool.add_thread(rpc_handle)?;

    // Spawn idle state checker thread for recovery
    let maker_clone = Arc::clone(&maker);
    let idle_handle = thread::Builder::new()
        .name("idle-checker".to_string())
        .spawn(move || {
            if let Err(e) = check_for_idle_states(maker_clone) {
                log::error!("Idle state checker error: {:?}", e);
            }
        })
        .map_err(MakerError::IO)?;
    maker.thread_pool.add_thread(idle_handle)?;

    if let Some(maker_address) = maker_address {
        let maker_fidelity = Arc::clone(&maker);
        let fidelity_handle = thread::Builder::new()
            .name("fidelity-renewal".to_string())
            .spawn(move || {
                if let Err(e) = fidelity_renewal_loop(maker_fidelity, &maker_address) {
                    log::error!("Fidelity renewal loop error: {:?}", e);
                }
            })
            .map_err(MakerError::IO)?;
        maker.thread_pool.add_thread(fidelity_handle)?;
    }

    let connection_limiter = ConnectionLimiter::new();
    while !maker.is_shutdown() {
        let Some(listener) = listener.as_ref() else {
            sleep(Duration::from_millis(100));
            continue;
        };
        match listener.accept() {
            Ok((stream, addr)) => {
                let Some(permit) = connection_limiter.try_acquire() else {
                    // Refuse silently: logging attacker-controlled connection
                    // volume would turn the limiter into a disk-amplification path.
                    drop(stream);
                    continue;
                };

                log::debug!(
                    "[{}] New connection from {}",
                    maker.config.network_port,
                    addr
                );

                let maker_clone = Arc::clone(&maker);
                // Shared so shutdown can close the socket under a parked read. The
                // handler owns the only strong reference, so it still closes
                // normally the moment the handler returns.
                let stream = Arc::new(stream);
                let watched = Arc::clone(&stream);
                let conn_handle = thread::Builder::new()
                    .name(format!("connection-{}", addr))
                    .spawn(move || {
                        if let Err(e) = handle_connection(maker_clone, stream, permit) {
                            log::debug!("Connection closed: {:?}", e);
                        }
                    })
                    .map_err(MakerError::IO)?;
                maker.thread_pool.add_connection(conn_handle, &watched)?;
                drop(watched);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // No connection waiting, sleep briefly
                sleep(Duration::from_millis(100));
            }
            Err(e) => {
                log::error!("[{}] Accept error: {}", maker.config.network_port, e);
            }
        }
    }

    Ok(())
}

/// Stops the watcher, joins every thread that can touch the wallet, then saves it.
fn shutdown_server(maker: &MakerServer) -> Result<(), MakerError> {
    log::info!("[{}] Server shutting down...", maker.config.network_port);

    maker.watch_service.shutdown();
    maker.thread_pool.join_all_threads()?;
    maker.shutdown.reset_backend();

    log::info!(
        "shutdown_phase_start pid={} component=maker:{} phase=wallet_save",
        std::process::id(),
        maker.config.network_port
    );
    let save_result = lock_debug!(maker.wallet.write())
        .map_err(|_| MakerError::General("Failed to lock wallet"))
        .and_then(|wallet| wallet.save_to_disk().map_err(MakerError::Wallet));
    log::info!(
        "shutdown_phase_done pid={} component=maker:{} phase=wallet_save outcome={}",
        std::process::id(),
        maker.config.network_port,
        if save_result.is_ok() { "ok" } else { "error" }
    );
    save_result?;
    // Idle, these poll the flag every second; a blocked relay call is abandoned.
    maker
        .thread_pool
        .join_wallet_free_threads(Duration::from_secs(2));

    log::info!("[{}] Server shutdown complete", maker.config.network_port);

    Ok(())
}

/// Spawn a background thread for nostr bond announcements.
///
/// The thread re-reads `highest_fidelity_proof` on every broadcast cycle so
/// that bond renewals are picked up.
/// Spawns the Lightning event pump (routes node events to per-swap
/// mailboxes) and the swap watchdog (settles/refunds swaps whose final
/// message never arrived). No-ops when no Lightning backend is configured.
#[cfg(feature = "lightning")]
fn spawn_lightning_threads(maker: &Arc<MakerServer>) -> Result<(), MakerError> {
    let Some(router) = maker.ln_router.clone() else {
        return Ok(());
    };

    let pump_maker = maker.clone();
    let pump = std::thread::Builder::new()
        .name("ln-event-pump".to_string())
        .spawn(move || {
            log::info!("Lightning event pump started");
            while !pump_maker.is_shutdown() {
                if router.pump_once() == 0 {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
            log::info!("Lightning event pump stopped");
        })
        .map_err(MakerError::IO)?;
    maker.thread_pool.add_thread(pump)?;

    let watchdog_maker = maker.clone();
    let watchdog = std::thread::Builder::new()
        .name("ln-watchdog".to_string())
        .spawn(move || {
            log::info!("Lightning swap watchdog started");
            while watchdog_maker.wait_for_shutdown(Duration::from_secs(30)) {
                super::lightning_handlers::ln_watchdog_tick(&watchdog_maker);
            }
            log::info!("Lightning swap watchdog stopped");
        });
    // The pump is already running and holds a MakerServer handle. If the
    // watchdog cannot start, signal shutdown so the pump exits instead of
    // spinning for the life of the process.
    let watchdog = match watchdog {
        Ok(handle) => handle,
        Err(e) => {
            maker.shutdown.store(true, Ordering::Relaxed);
            return Err(MakerError::IO(e));
        }
    };
    maker.thread_pool.add_thread(watchdog)?;
    Ok(())
}

fn spawn_nostr_broadcast_thread(maker: &Arc<MakerServer>) -> Result<(), MakerError> {
    log::info!(
        "[{}] Spawning nostr background task",
        maker.config.network_port
    );

    let maker_clone = Arc::clone(maker);
    let relays = maker.nostr_relays.clone();
    let handle = thread::Builder::new()
        .name("nostr-thread".to_string())
        .spawn(move || {
            let tick = Duration::from_secs(2);
            // Start saturated so the first iteration broadcasts immediately.
            let mut elapsed = NOSTR_BROADCAST_INTERVAL;

            while !maker_clone.shutdown.load(Ordering::Relaxed) {
                if elapsed >= NOSTR_BROADCAST_INTERVAL {
                    elapsed = Duration::ZERO;

                    let fidelity = match lock_debug!(maker_clone.highest_fidelity_proof.read()) {
                        Ok(guard) => guard.clone(),
                        Err(e) => {
                            log::error!("Failed to read highest_fidelity_proof: {:?}", e);
                            return;
                        }
                    };

                    match fidelity {
                        Some(proof) => {
                            log::debug!("Pinging nostr relays with bond announcement");
                            if let Err(e) = broadcast_bond_on_nostr(
                                proof,
                                &relays,
                                &maker_clone.config,
                                &maker_clone.shutdown,
                            ) {
                                log::warn!("Nostr broadcast failed: {:?}", e);
                            }
                        }
                        None => {
                            log::warn!("No fidelity proof available for nostr broadcast");
                        }
                    }
                }

                if !maker_clone.wait_for_shutdown(tick) {
                    break;
                }
                elapsed += tick;
            }

            log::info!("Nostr background task stopped");
        })
        .map_err(MakerError::IO)?;

    // Reads only the fidelity proof and config, never the wallet.
    maker.thread_pool.add_wallet_free_thread(handle)?;

    Ok(())
}

/// Handle a single connection.
fn handle_connection(
    maker: Arc<MakerServer>,
    stream: Arc<TcpStream>,
    mut permit: ConnectionPermit,
) -> Result<(), MakerError> {
    stream.set_nonblocking(false).map_err(MakerError::IO)?;
    stream
        .set_read_timeout(Some(CONNECTION_READ_TIMEOUT))
        .map_err(MakerError::IO)?;
    stream
        .set_write_timeout(Some(CONNECTION_WRITE_TIMEOUT))
        .map_err(MakerError::IO)?;

    let mut state = ConnectionState::default();
    let mut pending_deadline = Instant::now() + PENDING_CONNECTION_TIMEOUT;
    let mut last_keepalive = None;
    let mut heartbeat_swap = None;

    log::debug!(
        "[{}] Starting connection handler",
        maker.config.network_port
    );

    loop {
        // Check for shutdown
        if maker.is_shutdown() {
            log::info!(
                "[{}] Shutdown requested, closing connection",
                maker.config.network_port
            );
            break;
        }

        if state.is_timed_out(IDLE_CONNECTION_TIMEOUT.as_secs()) {
            log::info!("[{}] Connection timed out", maker.config.network_port);
            break;
        }

        let frame = match read_message(&stream, permit.pending.then_some(pending_deadline)) {
            Ok(frame) => frame,
            Err(e) => {
                // A read timeout is only a wakeup: keepalives arrive on separate
                // connections and refresh the shared swap activity. Break only
                // when the swap has gone quiet everywhere, not just this socket.
                if matches!(&e, MakerError::IO(io) if matches!(io.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut))
                    && !swap_is_quiet(&maker, &state)
                {
                    continue;
                }
                log::debug!(
                    "[{}] Read error (may be normal disconnect): {:?}",
                    maker.config.network_port,
                    e
                );
                break;
            }
        };
        let message = match serde_cbor::from_slice::<TakerToMakerMessage>(&frame) {
            Ok(message) => message,
            Err(e) => {
                // Name what we can't read, so the taker can tell "unsupported"
                // from "down". A refusal is never answered, or two peers loop.
                let what = message_name(&frame).filter(|name| name != "Unsupported");
                log::info!(
                    "[{}] Cannot decode {:?}: {}",
                    maker.config.network_port,
                    what,
                    e
                );
                if let Some(what) = what {
                    let refusal = MakerToTakerMessage::Unsupported(UnsupportedMessage {
                        what,
                        reason: "cannot decode".to_string(),
                    });
                    let _ = send_message(&stream, &refusal);
                }
                break;
            }
        };

        // Every connection opens with Hello, so a reconnect or keepalive can't
        // skip the requirement check that Hello runs.
        if state.phase == super::handlers::SwapPhase::AwaitingHello
            && !matches!(message, TakerToMakerMessage::Hello(_))
        {
            log::debug!(
                "[{}] First message was not Hello; closing",
                maker.config.network_port
            );
            break;
        }

        // Heartbeat connections carry a known swap id but intentionally keep a
        // lightweight local state. Recognize them without changing the protocol.
        if let TakerToMakerMessage::WaitingFundingConfirmation(id) = &message {
            let known_swap = maker.get_connection_state(id)?.is_some();
            match admit_heartbeat(
                id,
                known_swap,
                &mut heartbeat_swap,
                &mut last_keepalive,
                &mut permit,
            ) {
                HeartbeatAction::Reject => {
                    log::warn!(
                        "[{}] Refusing keepalive for swap {}: unknown or not this connection's swap",
                        maker.config.network_port,
                        id
                    );
                    break;
                }
                HeartbeatAction::Throttle => break,
                HeartbeatAction::Accept => {}
            }
        }

        log::debug!(
            "[{}] Received message: {:?}",
            maker.config.network_port,
            message
        );

        let handover = match &message {
            TakerToMakerMessage::LegacyPrivateKeyHandover(request) => {
                Some((ProtocolVersion::Legacy, request.clone()))
            }
            TakerToMakerMessage::TaprootPrivateKeyHandover(request) => {
                Some((ProtocolVersion::Taproot, request.clone()))
            }
            _ => None,
        };
        let cached_response = match &handover {
            Some((protocol, request)) => maker.replay_completed_handover(*protocol, request)?,
            None => None,
        };
        let should_cache = cached_response.is_none();
        let handling_started = Instant::now();
        let response = if let Some(response) = cached_response {
            Some(response)
        } else {
            match handle_message(&maker, &mut state, message) {
                Ok(resp) => resp,
                Err(e) => {
                    log::error!("[{}] Handler error: {:?}", maker.config.network_port, e);
                    break;
                }
            }
        };
        if should_cache {
            if let (Some((protocol, request)), Some(response)) = (handover, response.as_ref()) {
                maker.cache_completed_handover(protocol, request, response)?;
            }
        }
        // Maker-side processing does not spend the peer's admission budget.
        if permit.pending {
            pending_deadline += handling_started.elapsed();
        }

        if state.swap_id.is_some() {
            permit.mark_established();
        }

        // Handling can block for minutes on contract confirmation waits.
        // Count the work itself as activity, or the loop-top idle check kills
        // the connection right after a long productive call.
        state.touch();

        #[cfg(feature = "integration-test")]
        let send_response = maker.behavior != super::handlers::MakerBehavior::DropHandoverResponse
            || state.phase != super::handlers::SwapPhase::Completed;
        #[cfg(not(feature = "integration-test"))]
        let send_response = true;
        if !send_response {
            log::warn!(
                "[{}] Test behavior: dropping completed handover response",
                maker.config.network_port
            );
        }
        // We close after a refusal, so the taker never has to count them.
        let refused = matches!(response, Some(MakerToTakerMessage::Unsupported(_)));
        if let Some(response) = response.filter(|_| send_response) {
            log::debug!(
                "[{}] Sending response: {:?}",
                maker.config.network_port,
                response
            );

            if let Err(e) = send_message(&stream, &response) {
                log::error!(
                    "[{}] Failed to send response: {:?}",
                    maker.config.network_port,
                    e
                );
                if state.phase != super::handlers::SwapPhase::Completed {
                    break;
                }
            }
        }
        if refused {
            break;
        }

        #[cfg(feature = "integration-test")]
        if state.phase == super::handlers::SwapPhase::Completed
            && maker.behavior() == super::handlers::MakerBehavior::CloseAfterHandoverResponse
        {
            log::warn!(
                "[{}] Test behavior: closing after handover response",
                maker.config.network_port
            );
            break;
        }

        if state.phase == super::handlers::SwapPhase::Completed {
            // Remove the completed in-memory state before slow wallet sweeping/syncing.
            // Otherwise the idle checker can race the sweep and launch recovery for
            // a swap that has already completed successfully.
            if let Some(ref swap_id) = state.swap_id {
                maker.remove_connection_state(swap_id)?;
            }

            log::info!(
                "[{}] Swap completed, sweeping incoming swapcoins",
                maker.config.network_port
            );
            let sweep_outcome = match maker.sweep_incoming_swapcoins(&state.incoming_swapcoins) {
                Ok(outcome) => Some(outcome),
                Err(e) => {
                    log::error!(
                        "[{}] Failed to sweep incoming swapcoins: {:?}",
                        maker.config.network_port,
                        e
                    );
                    None
                }
            };

            // Sync wallet after sweep to update UTXO cache.
            if let Err(e) = maker.sync_and_save_wallet() {
                log::error!(
                    "[{}] Failed to sync wallet after sweep: {:?}",
                    maker.config.network_port,
                    e
                );
            }

            let completed_settlement = if let (Some(swap_id), Some(sweep_outcome)) =
                (state.swap_id.as_ref(), sweep_outcome.as_ref())
            {
                let fully_swept = !state.incoming_swapcoins.is_empty()
                    && state.incoming_swapcoins.iter().all(|swapcoin| {
                        let contract_txid = swapcoin.contract_tx.compute_txid();
                        sweep_outcome
                            .resolved
                            .iter()
                            .any(|(resolved_txid, _)| *resolved_txid == contract_txid)
                    });
                if !fully_swept {
                    log::error!(
                        "[{}] Not writing success report for {}: only {}/{} incoming swapcoins were swept",
                        maker.config.network_port,
                        swap_id,
                        sweep_outcome.resolved.len(),
                        state.incoming_swapcoins.len()
                    );
                }
                fully_swept.then_some((swap_id.as_str(), sweep_outcome))
            } else {
                None
            };

            if let Some((swap_id, sweep_outcome)) = completed_settlement {
                #[cfg(feature = "integration-test")]
                if maker.behavior() == super::handlers::MakerBehavior::CloseBeforeSwapFinalization {
                    log::warn!(
                        "[{}] Test behavior: closing before swap finalization",
                        maker.config.network_port
                    );
                    break;
                }

                // Make the terminal state durable before reporting success. The
                // in-memory state still owns everything needed by the report.
                // Every funding version is still persisted. The losers of a
                // bump stay so until the winner is buried deep: a reorg can
                // still confirm one, and its refund needs the coin.
                let persisted_outgoing =
                    state.outgoing_swapcoins.len() + state.funding_bump.replacements.len();
                let losers: Vec<bitcoin::Txid> = state
                    .funding_bump
                    .replacements
                    .iter()
                    .map(|coin| coin.contract_tx.compute_txid())
                    .collect();
                if let Err(error) =
                    maker.finalize_successful_swap(swap_id, persisted_outgoing, &losers)
                {
                    maker.store_connection_state(swap_id, &state, false)?;
                    return Err(error);
                }
                emit_maker_success_report(&maker, &state, swap_id, sweep_outcome);

                // The swap is settled; its contract watches are no longer needed.
                let incoming = state.incoming_swapcoins.iter().map(|s| &s.contract_tx);
                let outgoing = state.outgoing_swapcoins.iter().map(|s| &s.contract_tx);
                for contract_tx in incoming.chain(outgoing) {
                    let txid = contract_tx.compute_txid();
                    for (vout, txout) in contract_tx.output.iter().enumerate() {
                        maker.unwatch_outpoint(
                            bitcoin::OutPoint {
                                txid,
                                vout: vout as u32,
                            },
                            txout.script_pubkey.clone(),
                        );
                    }
                }
                for (outpoint, spk) in state
                    .incoming_swapcoins
                    .iter()
                    .filter_map(super::legacy_handlers::funding_watch)
                {
                    maker.unwatch_outpoint(outpoint, spk);
                }
                if !losers.is_empty() {
                    spawn_version_retirement(&maker, swap_id.to_string())?;
                }
            } else if let Some(ref swap_id) = state.swap_id {
                maker.store_connection_state(swap_id, &state, false)?;
            }

            break;
        }
    }

    log::debug!(
        "[{}] Connection handler finished",
        maker.config.network_port
    );

    Ok(())
}

/// True when the error is the socket read timeout firing, not a real IO failure.
/// A swap is quiet when neither this connection nor any keepalive connection
/// has shown activity within the idle timeout.
fn swap_is_quiet(maker: &Arc<MakerServer>, state: &ConnectionState) -> bool {
    let timeout = IDLE_CONNECTION_TIMEOUT.as_secs();
    match state.swap_id {
        Some(ref id) => match maker.get_connection_state(id) {
            Ok(Some(stored)) => stored.is_timed_out(timeout),
            _ => state.is_timed_out(timeout),
        },
        None => state.is_timed_out(timeout),
    }
}

/// Background thread that checks for idle swap states and spawns recovery.
fn check_for_idle_states(maker: Arc<MakerServer>) -> Result<(), MakerError> {
    let mut latched_at = None;
    loop {
        if maker.is_shutdown() {
            break;
        }

        // Latch each block's newly mined funding before a reorg can orphan it.
        let tip = maker.watch_service.tip();
        if tip.is_none() || tip != latched_at {
            match maker.latch_confirmed_funding() {
                Ok(()) => latched_at = tip,
                Err(e) => log::warn!(
                    "[{}] Could not check outgoing funding confirmations: {:?}",
                    maker.config.network_port,
                    e
                ),
            }
        }

        let idle_swaps = maker.drain_idle_swaps(IDLE_CONNECTION_TIMEOUT)?;

        for idle in idle_swaps {
            log::error!(
                "[{}] Potential dropped connection from taker. Swap {} idle. Recovering from swap",
                maker.config.network_port,
                idle.swap_id
            );

            // A crashed process never reaches its idle recovery, so the contracts
            // stay unclaimed until a restart picks them up.
            #[cfg(feature = "integration-test")]
            if maker.behavior == super::handlers::MakerBehavior::CrashBeforeRecovery {
                log::warn!(
                    "[{}] Test behavior: crashing instead of recovering",
                    maker.config.network_port
                );
                continue;
            }

            let swap_id = idle.swap_id.clone();
            let maker_clone = Arc::clone(&maker);
            let handle = thread::Builder::new()
                .name(format!("swap-recovery-{}", swap_id))
                .spawn(move || {
                    if let Err(e) = recover_from_swap(
                        maker_clone,
                        idle.swap_id,
                        idle.incoming_swapcoins,
                        idle.outgoing_swapcoins,
                        false,
                    ) {
                        log::error!("Failed to recover from swap {}: {:?}", swap_id, e);
                    }
                })
                .map_err(MakerError::IO)?;
            maker.thread_pool.add_thread(handle)?;
        }

        if !maker.wait_for_shutdown(HEART_BEAT_INTERVAL) {
            break;
        }
    }

    Ok(())
}

/// Periodically check for expired fidelity bonds and renew them.
fn fidelity_renewal_loop(maker: Arc<MakerServer>, maker_address: &str) -> Result<(), MakerError> {
    use crate::wallet::AddressType;

    let tick = Duration::from_secs(2);
    let mut elapsed = Duration::ZERO;

    while !maker.is_shutdown() {
        if !maker.wait_for_shutdown(tick) {
            break;
        }
        elapsed += tick;

        if elapsed < FIDELITY_BOND_UPDATE_INTERVAL {
            continue;
        }
        elapsed = Duration::ZERO;

        // Runs ahead of the swap gate: a long swap must not leave us advertising
        // a height our own chain has already moved.
        if let Err(e) = refresh_fidelity_conf_heights(&maker) {
            log::warn!(
                "[{}] Could not refresh fidelity bond heights: {:?}",
                maker.config.network_port,
                e
            );
        }

        // Skip renewal check if a swap is in progress
        if maker.has_ongoing_swaps()? {
            continue;
        }

        log::debug!(
            "[{}] Checking fidelity bond status...",
            maker.config.network_port
        );

        // Redeem any expired bonds
        if let Err(e) = lock_debug!(maker.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .redeem_expired_fidelity_bonds(MIN_RELAY_FEE_RATE, AddressType::P2TR)
        {
            log::warn!(
                "[{}] Failed to redeem expired fidelity bonds: {:?}",
                maker.config.network_port,
                e
            );
            continue;
        }

        // Re-run setup to create new bond if needed
        if let Err(e) = maker.setup_fidelity_bond(maker_address) {
            log::warn!(
                "[{}] Fidelity bond renewal failed: {:?}",
                maker.config.network_port,
                e
            );
        }
    }

    Ok(())
}

/// Corrects the advertised confirmation height of every unspent bond after a
/// reorg remines it. The height is not covered by the bond certificate, so
/// nothing else would ever notice it had gone stale.
fn refresh_fidelity_conf_heights(maker: &Arc<MakerServer>) -> Result<(), MakerError> {
    let bonds: Vec<(u32, bitcoin::Txid, u32)> = lock_debug!(maker.wallet.read())
        .map_err(|_| MakerError::General("Failed to lock wallet"))?
        .store
        .fidelity_bond
        .iter()
        .filter(|bond| !bond.is_spent)
        .filter_map(|bond| {
            bond.conf_height
                .map(|height| (bond.bond_index, bond.outpoint.txid, height))
        })
        .collect();
    if bonds.is_empty() {
        return Ok(());
    }

    // A fresh connection keeps the wallet lock off the backend round trips.
    let chain = maker.backend.connect()?;

    for (index, txid, stored) in bonds {
        // No height at all means a reorg deeper than this network allows, which
        // this cannot repair; leave the bond alone and say so.
        let Some(observed) = chain.tx_block_height(&txid)? else {
            log::warn!(
                "[{}] Fidelity bond {} is not on our chain; keeping height {}",
                maker.config.network_port,
                txid,
                stored
            );
            continue;
        };
        let observed = observed as u32;
        if observed == stored {
            continue;
        }

        log::info!(
            "[{}] Fidelity bond {} moved from height {} to {}; correcting the advertisement",
            maker.config.network_port,
            txid,
            stored,
            observed
        );
        lock_debug!(maker.wallet.write())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .update_fidelity_bond_conf_details(index, observed)?;
    }

    Ok(())
}

/// Minimum witness items for a hashlock spend (signature + preimage).
const MIN_WITNESS_ITEM_FOR_HASHLOCK: usize = 2;

/// Preimage length in bytes.
const PREIMAGE_LEN: usize = 32;

/// The spend the watcher holds for `outpoint`. An answer the watcher could
/// not give is an error, never "unspent", and so is a watch it does not
/// have: every contract output is watched until its swap is finished.
fn watched_spend(
    watch_service: &WatchService,
    outpoint: OutPoint,
) -> Result<Option<bitcoin::Transaction>, MakerError> {
    match watch_service.watch_request(outpoint).map_err(|e| {
        log::warn!("watch request for {outpoint} failed: {e}");
        MakerError::General("watchtower query failed")
    })? {
        WatcherEvent::UtxoSpent { spending_tx, .. } => Ok(spending_tx),
        other => {
            log::warn!("watch request for {outpoint} has no answer: {other:?}");
            Err(MakerError::General(
                "watchtower has no watch for the contract",
            ))
        }
    }
}

/// Read spends through the watcher, or directly through the wallet backend
/// after the watcher exits, then persist any revealed hashlock preimages.
fn check_for_preimage(
    maker: &MakerServer,
    outgoing_swapcoins: &[crate::wallet::swapcoin::OutgoingSwapCoin],
    incoming_swapcoins: &[crate::wallet::swapcoin::IncomingSwapCoin],
) -> Result<(), MakerError> {
    use bitcoin::hashes::Hash;
    use std::{collections::HashSet, convert::TryFrom};

    let mut seen_outpoints = HashSet::new();
    let mut preimages: Vec<[u8; 32]> = Vec::new();
    let direct_chain = (!maker.watch_service.is_alive())
        .then(|| maker.backend.connect())
        .transpose()
        .map_err(MakerError::Wallet)?;

    // Query the watch tower for spends on each outgoing contract output.
    for outgoing in outgoing_swapcoins {
        // Only the contract output is watched; a Taproot contract can also
        // carry change, which no preimage spend touches.
        let contract_txid = outgoing.contract_tx.compute_txid();
        let vout = outgoing.get_contract_output_vout() as usize;
        let outpoint = bitcoin::OutPoint {
            txid: contract_txid,
            vout: vout as u32,
        };
        // Blocking on purpose: we need this pass's fresh answer before
        // choosing timelock over hashlock — a stale miss refunds while a
        // preimage spend already exists. A failed query aborts this pass;
        // the recovery loop retries instead of refunding blind.
        let spending_tx = match direct_chain.as_ref() {
            Some(chain) => chain
                .spending_transaction(
                    &outpoint,
                    outgoing.contract_tx.output[vout].script_pubkey.as_script(),
                    None,
                )
                .map_err(MakerError::Wallet)?,
            None => watched_spend(&maker.watch_service, outpoint)?,
        };

        if let Some(spending_tx) = spending_tx {
            // Extract preimages from the spending transaction's witnesses.
            for input in &spending_tx.input {
                let op = (input.previous_output.txid, input.previous_output.vout);
                if seen_outpoints.insert(op)
                    && input.witness.len() >= MIN_WITNESS_ITEM_FOR_HASHLOCK
                    && input.witness[1].len() == PREIMAGE_LEN
                {
                    if let Ok(preimage) = <[u8; 32]>::try_from(&input.witness[1][..]) {
                        preimages.push(preimage);
                    }
                }
            }
        }
    }

    if preimages.is_empty() {
        return Ok(());
    }

    log::info!(
        "[{}] Extracted {} preimage(s) from on-chain hashlock spends",
        maker.config.network_port,
        preimages.len()
    );

    // Apply extracted preimages to incoming swapcoins in the wallet.
    let mut wallet = lock_debug!(maker.wallet.write())
        .map_err(|_| MakerError::General("Failed to lock wallet"))?;

    for incoming in incoming_swapcoins {
        // The wallet stores incoming swapcoins keyed by contract txid, not swap_id.
        let wallet_key = incoming.contract_tx.compute_txid().to_string();

        for preimage in &preimages {
            // Verify the preimage matches the incoming swapcoin's hashlock.
            let matches = if let Some(redeemscript) = incoming.contract_redeemscript() {
                // Legacy: uses OP_HASH160 with 20-byte hash
                let hash: bitcoin::hashes::hash160::Hash = bitcoin::hashes::Hash::hash(preimage);
                crate::protocol::contract::read_hashvalue_from_contract(redeemscript)
                    .map(|h| h == hash)
                    .unwrap_or(false)
            } else {
                // Taproot: uses OP_SHA256 with 32-byte hash
                // Script format: OP_SHA256 OP_PUSHBYTES_32 <32-byte hash> OP_EQUALVERIFY ...
                let sha256_hash: [u8; 32] =
                    bitcoin::hashes::sha256::Hash::hash(preimage).to_byte_array();
                incoming
                    .hashlock_script()
                    .map(|script| {
                        let bytes = script.as_bytes();
                        bytes.len() >= 34 && bytes[2..34] == sha256_hash
                    })
                    .unwrap_or(false)
            };

            if matches {
                if let Some(swapcoin) = wallet.find_incoming_swapcoin_mut(&wallet_key) {
                    if swapcoin.hash_preimage.is_none() {
                        swapcoin.set_preimage(*preimage);
                        log::info!(
                            "[{}] Applied extracted preimage to incoming swapcoin {}",
                            maker.config.network_port,
                            wallet_key
                        );
                    }
                }
                break;
            }
        }
    }

    wallet.save_to_disk().map_err(MakerError::Wallet)?;

    Ok(())
}

/// Retire the funding versions a bump left behind once a swap completed:
/// each block, drop the ones the winner beat deep enough
/// ([`Wallet::retire_replaced_versions`]) along with their watches. If a reorg
/// mines one of them instead, the swap is recovered from it like any other.
///
/// [`Wallet::retire_replaced_versions`]: crate::wallet::Wallet::retire_replaced_versions
fn spawn_version_retirement(maker: &Arc<MakerServer>, swap_id: String) -> Result<(), MakerError> {
    let maker_clone = Arc::clone(maker);
    let handle = thread::Builder::new()
        .name(format!("version-retirement-{swap_id}"))
        .spawn(move || {
            let maker = maker_clone;
            // Kept across passes, as recovery keeps its own: a fresh Electrum
            // connection costs a handshake, over Tor a slow one. A failed pass
            // drops it and the next one reconnects.
            let mut held: Option<crate::wallet::AnyBlockchain> = None;
            loop {
                let retired = held
                    .take()
                    .map_or_else(|| maker.backend.connect(), Ok)
                    .and_then(|chain| {
                        let retired = crate::wallet::Wallet::retire_replaced_versions(
                            &maker.wallet,
                            &chain,
                            &swap_id,
                        )?;
                        held = Some(chain);
                        Ok(retired)
                    });
                match retired {
                    Ok(retirement) => {
                        for (outpoint, spk) in retirement.removed {
                            maker.unwatch_outpoint(outpoint, spk);
                        }
                        if retirement.revived {
                            log::warn!(
                                "[{}] A replaced funding version of swap {} is mined after a reorg; recovering",
                                maker.config.network_port,
                                swap_id
                            );
                            let outgoing = match lock_debug!(maker.wallet.read()) {
                                Ok(wallet) => wallet
                                    .find_unfinished_swapcoins()
                                    .1
                                    .into_iter()
                                    .filter(|coin| coin.swap_id.as_deref() == Some(&swap_id))
                                    .collect(),
                                Err(_) => Vec::new(),
                            };
                            if let Err(e) = recover_from_swap(
                                Arc::clone(&maker),
                                swap_id.clone(),
                                Vec::new(),
                                outgoing,
                                true,
                            ) {
                                log::error!("Failed to recover from swap {}: {:?}", swap_id, e);
                            }
                            return;
                        }
                        if retirement.remaining == 0 {
                            return;
                        }
                    }
                    Err(e) => log::warn!(
                        "[{}] Retiring the replaced funding of swap {}: {:?}",
                        maker.config.network_port,
                        swap_id,
                        e
                    ),
                }
                if !maker.wait_for_shutdown(HEART_BEAT_INTERVAL) {
                    return;
                }
            }
        })
        .map_err(MakerError::IO)?;
    maker.thread_pool.add_thread(handle)?;
    Ok(())
}

/// Recover maker funds after taker drops.
///
/// Two recovery paths are tried in a loop:
/// 1. **Hashlock** (incoming swapcoins): If the taker (or another party) spends
///    our outgoing contract output via hashlock, the preimage is revealed on-chain.
///    We extract it via the watch tower and sweep our incoming swapcoins.
/// 2. **Timelock** (outgoing swapcoins): After the timelock expires, we reclaim
///    our outgoing funds via the timelock spending path.
///
/// `revived` recovers a completed swap whose replaced funding version a reorg
/// mined: its incoming was claimed long ago, yet the version's coins are
/// left to the next hop only until the timelock, as any contract's are.
fn recover_from_swap(
    maker: Arc<MakerServer>,
    swap_id: String,
    mut incoming_swapcoins: Vec<crate::wallet::swapcoin::IncomingSwapCoin>,
    outgoing_swapcoins: Vec<crate::wallet::swapcoin::OutgoingSwapCoin>,
    revived: bool,
) -> Result<(), MakerError> {
    // The watcher hears each new block, so asking the server every pass is waste.
    // The fallback uses its own connection, kept while the watcher is down and dropped on error:
    // a slow server must not hold the wallet lock.
    // After a failed fallback on Electrum, a live watcher is already retrying the same server
    // and publishes a height once it answers; asking it every pass only extends a rate limit.
    let mut fallback: Option<AnyBlockchain> = None;
    let mut deferring = false;
    let mut tip = || -> Result<u32, MakerError> {
        if let Some(height) = maker.watch_service.tip() {
            fallback = None;
            deferring = false;
            return Ok(height as u32);
        }
        if deferring && maker.watch_service.is_alive() {
            return Err(MakerError::General(
                "Block height unknown; waiting for the watcher to reach the server",
            ));
        }
        let height = fallback
            .take()
            .map_or_else(|| maker.backend.connect(), Ok)
            .and_then(|chain| {
                let height = chain.get_block_count()?;
                fallback = Some(chain);
                Ok(height)
            })
            .map_err(MakerError::Wallet);
        deferring = height.is_err() && maker.backend.is_electrum();
        Ok(height? as u32)
    };

    // Timelock recovery may already have removed every outgoing coin before a
    // crash. Any claim-ready incoming coins still need an idempotent sweep, but
    // there is no outgoing timelock left to monitor.
    if outgoing_swapcoins.is_empty() {
        // Nothing respawns this thread, so a failed sweep retries on the next block.
        let mut tried_at = None;
        while !maker.is_shutdown() {
            let height = tip()
                .inspect_err(|e| {
                    log::warn!(
                        "[{}] Could not read the block height: {:?}",
                        maker.config.network_port,
                        e
                    )
                })
                .ok();
            if height.is_some() && tried_at != height {
                tried_at = height;
                match maker.sweep_incoming_swapcoins(&incoming_swapcoins) {
                    Ok(_) => {
                        let mut wallet = lock_debug!(maker.wallet.write())
                            .map_err(|_| MakerError::General("Failed to lock wallet"))?;
                        let incoming = wallet.incoming_keys_for_swap(&swap_id);
                        let refunded = wallet.swap_reports().recovery.iter().any(|report| {
                            report.swap_id == swap_id
                                && matches!(report.role, SwapRole::Maker)
                                && report.recovery_type == "timelock"
                                && !report.recovery_txids.is_empty()
                        });
                        let settled = incoming.is_empty()
                            || (refunded
                                && incoming.iter().all(|key| {
                                    wallet.find_incoming_swapcoin(key).is_none_or(|coin| {
                                        coin.other_privkey.is_none() && !coin.is_preimage_known()
                                    })
                                }));
                        // An unsettled swap keeps its coins for the next restart,
                        // as before; only a failed cleanup save retries here.
                        if !settled {
                            return Ok(());
                        }
                        let saved = wallet.remove_swap_coins_and_save(&swap_id, true, true);
                        drop(wallet);
                        match saved {
                            Ok(()) => return Ok(()),
                            Err(error) => {
                                log::warn!(
                                    "Cannot save cleanup for swap {swap_id}: {error:?}; retrying"
                                );
                                tried_at = None;
                            }
                        }
                    }
                    Err(e) => log::warn!(
                        "[{}] Incoming sweep failed: {:?}; retrying on the next block",
                        maker.config.network_port,
                        e
                    ),
                }
            }
            if !maker.wait_for_shutdown(HEART_BEAT_INTERVAL) {
                break;
            }
        }
        return Ok(());
    }

    // For Taproot, get_timelock() returns an absolute CLTV height.
    // For Legacy, it returns a relative CSV offset — but Legacy recovery
    // uses wallet-level methods that handle CSV internally, so we only
    // need the absolute value here for the monitoring loop.
    let timelock_expiry = outgoing_swapcoins
        .first()
        .and_then(|o| o.get_timelock())
        .ok_or(MakerError::General("missing timelock on outgoing swapcoin"))?;

    log::info!(
        "[{}] recover_from_swap started | timelock_expiry={} | incoming={} outgoing={}",
        maker.config.network_port,
        timelock_expiry,
        incoming_swapcoins.len(),
        outgoing_swapcoins.len()
    );

    // The next hop claimed an outgoing contract: it has a confirmed spend other
    // than our own timelock refund. That claim puts the preimage on chain.
    let claimed_downstream = |chain: &AnyBlockchain| -> Result<bool, MakerError> {
        for outgoing in &outgoing_swapcoins {
            let outpoint = bitcoin::OutPoint::new(
                outgoing.contract_tx.compute_txid(),
                outgoing.get_contract_output_vout(),
            );
            let Some(output) = outgoing.contract_tx.output.get(outpoint.vout as usize) else {
                continue;
            };
            if chain
                .confirmed_spending_transaction(&outpoint, &output.script_pubkey)
                .map_err(MakerError::Wallet)?
                .is_some_and(|tx| !outgoing.is_own_timelock_spend(&tx))
            {
                return Ok(true);
            }
        }
        Ok(false)
    };
    // A cooperative or hashlock spend of this outgoing coin's contract.
    let outgoing_settled = |chain: &AnyBlockchain,
                            outgoing: &crate::wallet::swapcoin::OutgoingSwapCoin|
     -> Result<bool, MakerError> {
        let (outpoint, output) = match outgoing.protocol {
            ProtocolVersion::Legacy => {
                let Some(input) = outgoing.contract_tx.input.first() else {
                    return Ok(false);
                };
                let Some(output) = outgoing
                    .funding_tx
                    .as_ref()
                    .filter(|tx| tx.compute_txid() == input.previous_output.txid)
                    .and_then(|tx| tx.output.get(input.previous_output.vout as usize))
                else {
                    return Ok(false);
                };
                (input.previous_output, output)
            }
            ProtocolVersion::Taproot => {
                let txid = outgoing.contract_tx.compute_txid();
                let vout = outgoing.get_contract_output_vout();
                let Some(output) = outgoing.contract_tx.output.get(vout as usize) else {
                    return Ok(false);
                };
                (bitcoin::OutPoint::new(txid, vout), output)
            }
        };
        if !chain
            .is_confirmed_spend(&outpoint, &output.script_pubkey)
            .map_err(MakerError::Wallet)?
        {
            return Ok(false);
        }
        let Some(spending_tx) = chain
            .spending_transaction(&outpoint, output.script_pubkey.as_script(), None)
            .map_err(MakerError::Wallet)?
        else {
            return Ok(false);
        };
        let settlement_spend = spending_tx.input.iter().any(|input| {
            input.previous_output == outpoint
                && match outgoing.protocol {
                    ProtocolVersion::Legacy => {
                        spending_tx.compute_txid() != outgoing.contract_tx.compute_txid()
                    }
                    ProtocolVersion::Taproot => {
                        input.witness.len() == 1
                            || input
                                .witness
                                .iter()
                                .nth(1)
                                .is_some_and(|item| item.len() == PREIMAGE_LEN)
                    }
                }
        });
        Ok(settlement_spend)
    };
    // Every split settled. A bumped split keeps all its versions, and only
    // one of them can ever be spent: one settled version settles the split,
    // but only once every other version is beaten deep enough that no reorg
    // can bring it back, since settling drops them all.
    let all_outgoing_confirmed_settled = |chain: &AnyBlockchain| -> Result<bool, MakerError> {
        if outgoing_swapcoins.is_empty() {
            return Ok(false);
        }
        fn funding_of(
            outgoing: &crate::wallet::swapcoin::OutgoingSwapCoin,
        ) -> Option<&bitcoin::Transaction> {
            match outgoing.protocol {
                ProtocolVersion::Legacy => outgoing.funding_tx.as_ref(),
                ProtocolVersion::Taproot => Some(&outgoing.contract_tx),
            }
        }
        let mut splits = std::collections::HashMap::<
            bitcoin::OutPoint,
            Vec<&crate::wallet::swapcoin::OutgoingSwapCoin>,
        >::new();
        for outgoing in &outgoing_swapcoins {
            let funding_input = funding_of(outgoing)
                .and_then(|funding| funding.input.first())
                .map(|input| input.previous_output)
                .unwrap_or(bitcoin::OutPoint::new(
                    outgoing.contract_tx.compute_txid(),
                    0,
                ));
            splits.entry(funding_input).or_default().push(outgoing);
        }
        for versions in splits.values() {
            let mut settled = None;
            for (index, outgoing) in versions.iter().enumerate() {
                if outgoing_settled(chain, outgoing)? {
                    settled = Some(index);
                    break;
                }
            }
            let Some(settled) = settled else {
                return Ok(false);
            };
            for (index, outgoing) in versions.iter().enumerate() {
                if index == settled {
                    continue;
                }
                let beaten = match funding_of(outgoing) {
                    Some(funding) => crate::wallet::Wallet::replaced_by_confirmed_spend(
                        chain,
                        funding,
                        crate::wallet::replaced_version_discard_depth(),
                    )
                    .map_err(MakerError::Wallet)?,
                    None => false,
                };
                if !beaten {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    };
    // The grace runs from the funding claim, so a restart does not reset it.
    // With no claim left there is nothing to release, only coins to watch.
    let grace_from = lock_debug!(maker.wallet.read())
        .map_err(|_| MakerError::General("Failed to lock wallet"))?
        .store
        .swap_locks
        .get(&swap_id)
        .map_or_else(now_secs, |locks| locks.reserved_at);
    let mut grace_logged = false;
    let mut watchtower_down_logged = false;
    let mut last_block = None;
    let mut last_preimages_known = None;
    // Kept across passes, so each new block does not cost a fresh handshake.
    let mut held: Option<AnyBlockchain> = None;
    while !maker.is_shutdown() {
        let current_height = match tip() {
            Ok(height) => height,
            Err(e) => {
                log::warn!(
                    "[{}] Could not read the block height: {:?}; retrying recovery",
                    maker.config.network_port,
                    e
                );
                if !maker.wait_for_shutdown(HEART_BEAT_INTERVAL) {
                    break;
                }
                continue;
            }
        };
        // The chain only moves with a block, so server work waits for one. A failed
        // pass therefore retries on the next block, not every heartbeat.
        let new_block = last_block.replace(current_height) != Some(current_height);
        // A bump of our incoming funding after a reorg moves the contract to
        // the version that was mined; claim that one.
        if new_block
            && incoming_swapcoins
                .iter()
                .any(|coin| coin.protocol == ProtocolVersion::Taproot)
        {
            if let Err(e) = maker.follow_replaced_incoming(&swap_id, &mut incoming_swapcoins) {
                log::warn!(
                    "[{}] Could not check swap {} for replaced incoming funding: {:?}",
                    maker.config.network_port,
                    swap_id,
                    e
                );
            }
        }
        let handover_persisted = !incoming_swapcoins.is_empty()
            && incoming_swapcoins
                .iter()
                .all(|incoming| incoming.other_privkey.is_some());
        let completed_candidate = incoming_swapcoins.is_empty() || handover_persisted;
        // Whether `held` has read this block's tip, so its caches answer for it.
        let mut tip_refreshed = false;
        // A confirmed cooperative or hashlock spend proves the taker claimed the
        // contract. A timelock refund is recovery, not successful settlement.
        let outgoing_spent = if completed_candidate && new_block {
            let result = held
                .take()
                .map_or_else(|| maker.backend.connect(), Ok)
                .map_err(MakerError::Wallet)
                .and_then(|chain| {
                    // The watcher reported a new block on a different
                    // connection. Refresh this backend's tip so its
                    // script and header caches cannot answer for the old one.
                    let spent = chain
                        .get_block_count()
                        .map_err(MakerError::Wallet)
                        .and_then(|_| {
                            tip_refreshed = true;
                            all_outgoing_confirmed_settled(&chain)
                        });
                    held = Some(chain);
                    spent
                });
            match result {
                Ok(spent) => spent,
                Err(error) => {
                    log::warn!(
                        "[{}] Could not classify stale outgoing swapcoins for {}: {:?}; continuing normal recovery",
                        maker.config.network_port,
                        swap_id,
                        error
                    );
                    false
                }
            }
        } else {
            false
        };
        if outgoing_spent {
            if handover_persisted {
                if let Err(e) = maker.sweep_incoming_swapcoins(&incoming_swapcoins) {
                    log::warn!(
                        "[{}] Completed swap sweep failed: {:?}; retrying on the next block",
                        maker.config.network_port,
                        e
                    );
                }
                let fully_swept = {
                    let wallet = lock_debug!(maker.wallet.read())
                        .map_err(|_| MakerError::General("Failed to lock wallet"))?;
                    incoming_swapcoins.iter().all(|incoming| {
                        let key = incoming.contract_tx.compute_txid().to_string();
                        wallet.find_incoming_swapcoin(&key).is_none()
                    })
                };
                if !fully_swept {
                    if !maker.wait_for_shutdown(HEART_BEAT_INTERVAL) {
                        break;
                    }
                    continue;
                }
            }

            let saved = {
                let mut wallet = lock_debug!(maker.wallet.write())
                    .map_err(|_| MakerError::General("Failed to lock wallet"))?;
                wallet.remove_swap_coins_and_save(&swap_id, false, true)
            };
            if let Err(error) = saved {
                log::warn!("Cannot save cleanup for swap {swap_id}: {error:?}; retrying");
                last_block = None;
                if !maker.wait_for_shutdown(HEART_BEAT_INTERVAL) {
                    break;
                }
                continue;
            }

            let incoming = incoming_swapcoins.iter().map(|s| &s.contract_tx);
            let outgoing = outgoing_swapcoins.iter().map(|s| &s.contract_tx);
            for contract_tx in incoming.chain(outgoing) {
                let txid = contract_tx.compute_txid();
                for (vout, txout) in contract_tx.output.iter().enumerate() {
                    maker.unwatch_outpoint(
                        bitcoin::OutPoint {
                            txid,
                            vout: vout as u32,
                        },
                        txout.script_pubkey.clone(),
                    );
                }
            }

            log::info!(
                "[{}] Finalized completed swap {} from persisted state and removed {} outgoing swapcoin(s)",
                maker.config.network_port,
                swap_id,
                outgoing_swapcoins.len()
            );
            return Ok(());
        }

        // Uncommitted coins: funding never sent, or its send failed. Their keys
        // stay, since that funding may still confirm; past the grace only their
        // inputs go back to the wallet. Once per block, and nothing is sent.
        let has_unsent = lock_debug!(maker.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .has_unsent_funding(&swap_id);
        if new_block && has_unsent {
            let age = now_secs().saturating_sub(grace_from);
            let grace_over = age >= UNBROADCAST_DISCARD_GRACE.as_secs();
            let pass = held
                .take()
                .map_or_else(|| maker.backend.connect(), Ok)
                .and_then(|chain| {
                    let pass = if tip_refreshed {
                        Ok(())
                    } else {
                        chain.get_block_count().map(|_| tip_refreshed = true)
                    }
                    .and_then(|()| {
                        Wallet::settle_unsent_funding(&maker.wallet, &chain, &swap_id, grace_over)
                    });
                    held = Some(chain);
                    pass
                });
            match pass {
                Ok(pass) if pass.finished => {
                    log::info!(
                        "[{}] Swap {} is settled: its unsent funding can never confirm",
                        maker.config.network_port,
                        swap_id
                    );
                    #[cfg(feature = "integration-test")]
                    maker.shutdown.store(true, Relaxed);
                    return Ok(());
                }
                Ok(pass) => {
                    log::info!(
                        "[{}] Swap {} checked its unsent funding at height {}",
                        maker.config.network_port,
                        swap_id,
                        current_height
                    );
                    if pass.waiting && !grace_logged {
                        grace_logged = true;
                        log::info!(
                            "[{}] Swap {} shows no funding broadcast after {}s; keeping it until {}s",
                            maker.config.network_port,
                            swap_id,
                            age,
                            UNBROADCAST_DISCARD_GRACE.as_secs()
                        );
                    }
                    if pass.released {
                        log::info!(
                            "[{}] Funding was never broadcast for swap {} — released its inputs, keeping swap data until they are spent elsewhere",
                            maker.config.network_port,
                            swap_id
                        );
                    }
                }
                Err(e) => log::warn!(
                    "[{}] Could not check unsent funding for swap {}: {:?}; keeping it",
                    maker.config.network_port,
                    swap_id,
                    e
                ),
            }
        }

        // --- Hashlock path: check if preimages are available ---
        // Asking the watcher is local. Without it the check is a server round trip.
        let preimage_check = (maker.watch_service.is_alive() || new_block)
            .then(|| check_for_preimage(&maker, &outgoing_swapcoins, &incoming_swapcoins));
        if let Some(Err(e)) = preimage_check {
            log::warn!(
                "[{}] Could not refresh contract spends: {:?}; retrying recovery",
                maker.config.network_port,
                e
            );
            if !maker.wait_for_shutdown(HEART_BEAT_INTERVAL) {
                break;
            }
            continue;
        }
        if maker.is_shutdown() {
            break;
        }
        if !maker.watch_service.is_alive() && !watchtower_down_logged {
            log::error!(
                "[{}] Watchtower is down; directly polling swap {} for recovery",
                maker.config.network_port,
                swap_id
            );
            watchtower_down_logged = true;
        }

        // Check if all incoming swapcoins now have preimages. One already
        // gone from the wallet was swept on an earlier pass.
        let all_preimages_known = {
            let wallet = lock_debug!(maker.wallet.read())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;
            incoming_swapcoins.iter().all(|incoming| {
                // Wallet stores incoming swapcoins keyed by contract txid.
                let key = incoming.contract_tx.compute_txid().to_string();
                wallet
                    .find_incoming_swapcoin(&key)
                    .is_none_or(|s| s.is_preimage_known())
            })
        };

        let preimages_changed =
            last_preimages_known.replace(all_preimages_known) != Some(all_preimages_known);
        if !new_block && !preimages_changed {
            if !maker.wait_for_shutdown(HEART_BEAT_INTERVAL) {
                break;
            }
            continue;
        }

        // One connection, shared by both recovery paths below and kept for later
        // passes: on Tor Electrum each fresh connection costs a circuit handshake.
        // Idle passes that only poll the watchtower open none.
        let chain: Option<&AnyBlockchain> =
            if all_preimages_known || current_height >= timelock_expiry {
                // Nothing respawns this thread, so a failed connection retries.
                // A held connection may not have seen this block yet. Read its
                // tip once so its script and header caches answer for it.
                let connected = held
                    .take()
                    .map_or_else(|| maker.backend.connect(), Ok)
                    .and_then(|chain| {
                        let refresh = if new_block && !tip_refreshed {
                            chain.get_block_count().map(|_| ())
                        } else {
                            Ok(())
                        };
                        held = Some(chain);
                        refresh
                    });
                match connected {
                    Ok(()) => held.as_ref(),
                    Err(e) => {
                        log::warn!(
                            "[{}] Could not connect for recovery: {:?}; retrying recovery",
                            maker.config.network_port,
                            e
                        );
                        if !maker.wait_for_shutdown(HEART_BEAT_INTERVAL) {
                            break;
                        }
                        continue;
                    }
                }
            } else {
                None
            };

        // A crash between the hashlock sweep and its cleanup leaves no incoming
        // coin to show the preimage, but the next hop's claim on chain still does.
        let settled_downstream = match chain.as_ref().filter(|_| incoming_swapcoins.is_empty()) {
            Some(chain) => match claimed_downstream(chain) {
                Ok(claimed) => claimed,
                Err(e) => {
                    log::warn!(
                        "[{}] Could not check outgoing contract spends: {:?}; retrying recovery",
                        maker.config.network_port,
                        e
                    );
                    if !maker.wait_for_shutdown(HEART_BEAT_INTERVAL) {
                        break;
                    }
                    continue;
                }
            },
            None => false,
        };

        if all_preimages_known && (!incoming_swapcoins.is_empty() || settled_downstream) {
            log::info!(
                "[{}] All preimages known, recovering via hashlock path",
                maker.config.network_port
            );

            let chain = chain.as_ref().expect("connection created for this branch");

            let contract_txids = incoming_swapcoins
                .iter()
                .map(|swapcoin| swapcoin.contract_tx.compute_txid())
                .collect();

            let swept = Wallet::sweep_incoming_swapcoins_for_role(
                &maker.wallet,
                chain,
                &maker.shutdown,
                Some(&contract_txids),
                SwapRole::Maker,
            )
            // Retry next pass. With the preimage known the timelock refund is never
            // an option: a hashlock claim and a refund must not both happen.
            .unwrap_or_else(|e| {
                log::warn!(
                    "[{}] Hashlock sweep failed: {:?}",
                    maker.config.network_port,
                    e
                );
                RecoveryOutcome::default()
            });

            if !swept.is_empty() {
                log::info!(
                    "[{}] Recovered {} incoming swapcoins via hashlock",
                    maker.config.network_port,
                    swept.resolved.len()
                );
            }

            // A contract still in the mempool is swept on a later pass. A contract
            // the sender took back by timelock never will be, so it is settled too,
            // and so is one an earlier hashlock sweep of ours already spent: a
            // crash between that sweep and its cleanup leaves the coin on record
            // with nothing left to sweep.
            let remaining: Vec<_> = {
                let wallet = lock_debug!(maker.wallet.read())
                    .map_err(|_| MakerError::General("Failed to lock wallet"))?;
                incoming_swapcoins
                    .iter()
                    .filter(|incoming| {
                        let key = incoming.contract_tx.compute_txid().to_string();
                        wallet.find_incoming_swapcoin(&key).is_some()
                    })
                    .collect()
            };
            // Each remaining coin's confirmed contract spend, or `None` while one
            // is unspent or cannot be read. The contract pays only our hashlock or
            // the sender's timelock, so any confirmed spend settles it.
            let settling_spends: Option<Vec<_>> = remaining
                .iter()
                .map(|incoming| {
                    let outpoint = OutPoint::new(
                        incoming.contract_tx.compute_txid(),
                        incoming.get_contract_output_vout(),
                    );
                    let output = incoming.contract_tx.output.get(outpoint.vout as usize)?;
                    chain
                        .confirmed_spending_transaction(&outpoint, &output.script_pubkey)
                        .inspect_err(|e| {
                            log::warn!(
                                "[{}] Could not check {} for a settling spend: {:?}",
                                maker.config.network_port,
                                outpoint,
                                e
                            )
                        })
                        .ok()
                        .flatten()
                })
                .collect();
            // A spend that is not the sender's refund is an earlier sweep of ours.
            // Record it in the wallet's reports with the cleanup, so a crash cannot
            // leave the coins gone without the report. Already recorded sweeps
            // must not be added twice.
            if let Some(spends) = settling_spends {
                let saved = {
                    let mut wallet = lock_debug!(maker.wallet.write())
                        .map_err(|_| MakerError::General("Failed to lock wallet"))?;
                    let mut recorded: HashSet<_> = wallet
                        .swap_reports()
                        .recovery
                        .into_iter()
                        .filter(|report| {
                            report.swap_id == swap_id
                                && report.role == SwapRole::Maker
                                && report.recovery_type == "hashlock"
                        })
                        .flat_map(|report| report.recovery_txids)
                        .collect();
                    let mut earlier_sweeps = Vec::new();
                    for (incoming, tx) in remaining.iter().zip(&spends) {
                        let txid = tx.compute_txid().to_string();
                        if !incoming.is_timelock_spend(tx) && recorded.insert(txid.clone()) {
                            earlier_sweeps.push(txid);
                        }
                    }
                    let previous_reports = wallet.store.reports.clone();
                    let saved = (|| {
                        // A sender's refund is a loss, not our hashlock recovery.
                        if !earlier_sweeps.is_empty() {
                            RecoveryReport {
                                swap_id: swap_id.clone(),
                                role: SwapRole::Maker,
                                node: maker
                                    .data_dir
                                    .file_name()
                                    .and_then(|name| name.to_str())
                                    .map(str::to_owned),
                                recovery_type: "hashlock".to_string(),
                                recovery_txids: earlier_sweeps,
                                network: wallet.store.network.to_string(),
                                timestamp: crate::utill::now_secs(),
                            }
                            .store_in_wallet(&mut wallet)?;
                        }
                        // With the preimage known the outgoing coins are the next
                        // hop's to claim, never ours to refund. Cleanup releases
                        // the swap's remaining funding locks as well.
                        wallet.remove_swap_coins_and_save(&swap_id, true, true)
                    })();
                    if saved.is_err() {
                        wallet.store.reports = previous_reports;
                    }
                    saved
                };
                if let Err(error) = saved {
                    log::warn!("Cannot save cleanup for swap {swap_id}: {error:?}; retrying");
                    last_block = None;
                    if !maker.wait_for_shutdown(HEART_BEAT_INTERVAL) {
                        break;
                    }
                    continue;
                }
                #[cfg(feature = "integration-test")]
                maker.shutdown.store(true, Relaxed);
                return Ok(());
            }
        } else if current_height >= timelock_expiry && (!incoming_swapcoins.is_empty() || revived) {
            // Refund only while incoming coins are left. They are saved before
            // outgoing ones, so a funded swap with none left had its incoming
            // claimed before a restart, and a refund would take both sides.
            // A revived version is the exception: the next hop had until the
            // timelock to claim it, and past that its coins would only be stranded.
            // --- Timelock path: reclaim outgoing after timelock expires ---
            log::info!(
                "[{}] Timelock expired at {} (expiry={}), recovering via timelock path",
                maker.config.network_port,
                current_height,
                timelock_expiry
            );

            let chain = chain.as_ref().expect("connection created for this branch");

            let swap_scope = HashSet::from([swap_id.clone()]);
            let recovered = Wallet::recover_timelocked_swapcoins(
                &maker.wallet,
                chain,
                &maker.shutdown,
                Some(&swap_scope),
                // Our funding txs leave us unsigned, so no peer can broadcast
                // them for us.
                &|_| false,
            )
            // Nothing respawns this thread: a failed wait retries on the next pass.
            .unwrap_or_else(|e| {
                log::warn!(
                    "[{}] Timelock recovery pass failed: {:?}",
                    maker.config.network_port,
                    e
                );
                RecoveryOutcome::default()
            });

            if !recovered.is_empty() {
                log::info!(
                    "[{}] Recovered {} outgoing swapcoins via timelock",
                    maker.config.network_port,
                    recovered.len()
                );
            }

            // The wallet keeps an outgoing coin the next hop claimed, so with none
            // left no hashlock spend can reveal the preimage: an incoming without
            // the handed-over key is the sender's to refund.
            let outgoing_done = lock_debug!(maker.wallet.read())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?
                .outgoing_keys_for_swap(&swap_id)
                .is_empty();
            let incoming_unclaimable = incoming_swapcoins
                .iter()
                .all(|incoming| incoming.other_privkey.is_none());
            if outgoing_done && incoming_unclaimable {
                let saved = {
                    let mut wallet = lock_debug!(maker.wallet.write())
                        .map_err(|_| MakerError::General("Failed to lock wallet"))?;
                    wallet.remove_swap_coins_and_save(&swap_id, true, true)
                };
                if let Err(error) = saved {
                    log::warn!("Cannot save cleanup for swap {swap_id}: {error:?}; retrying");
                    last_block = None;
                    if !maker.wait_for_shutdown(HEART_BEAT_INTERVAL) {
                        break;
                    }
                    continue;
                }
                #[cfg(feature = "integration-test")]
                maker.shutdown.store(true, Relaxed);
                return Ok(());
            }
        }

        sleep(HEART_BEAT_INTERVAL);
    }

    Ok(())
}

/// Read one message frame, enforcing one absolute deadline until the connection
/// proves that it belongs to an admitted swap.
fn read_message(
    stream: &TcpStream,
    pending_deadline: Option<Instant>,
) -> Result<Vec<u8>, MakerError> {
    let mut len_buf = [0u8; 4];
    read_exact_until(stream, &mut len_buf[..1], pending_deadline)?;
    let assembly_deadline = Instant::now() + MESSAGE_ASSEMBLY_TIMEOUT;
    let deadline =
        Some(pending_deadline.map_or(assembly_deadline, |pending| pending.min(assembly_deadline)));
    read_exact_until(stream, &mut len_buf[1..], deadline)?;

    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_RPC_MESSAGE_SIZE {
        return Err(MakerError::General("Message too large"));
    }

    let mut buf = vec![0u8; len];
    read_exact_until(stream, &mut buf, deadline)?;
    Ok(buf)
}

fn read_exact_until(
    stream: &TcpStream,
    mut buf: &mut [u8],
    deadline: Option<Instant>,
) -> Result<(), MakerError> {
    while !buf.is_empty() {
        let timeout = deadline
            .map(|deadline| {
                deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(MakerError::General("Message read deadline expired"))
            })
            .transpose()?
            .unwrap_or(CONNECTION_READ_TIMEOUT)
            .max(Duration::from_millis(1));
        stream
            .set_read_timeout(Some(timeout))
            .map_err(MakerError::IO)?;

        let mut stream_ref = stream;
        match stream_ref.read(buf) {
            Ok(0) => {
                return Err(MakerError::IO(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "peer closed during protocol message",
                )));
            }
            Ok(read) => buf = &mut buf[read..],
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e)
                if deadline.is_some()
                    && matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                return Err(MakerError::General("Message read deadline expired"));
            }
            Err(e) => return Err(MakerError::IO(e)),
        }
    }
    Ok(())
}

/// Send a message to a stream.
fn send_message(stream: &TcpStream, message: &MakerToTakerMessage) -> Result<(), MakerError> {
    let buf = serde_cbor::to_vec(message)
        .map_err(|_| MakerError::General("Failed to serialize message"))?;

    let len = buf.len() as u32;
    use std::io::Write;

    let mut stream_ref = stream;
    stream_ref
        .write_all(&len.to_be_bytes())
        .map_err(MakerError::IO)?;

    stream_ref.write_all(&buf).map_err(MakerError::IO)?;
    stream_ref.flush().map_err(MakerError::IO)?;

    Ok(())
}

/// Binds `port`, or the first free port above it in steps of 2.
pub fn bind_port_retry(port: u16) -> Result<(TcpListener, u16), MakerError> {
    let mut current_port = port;
    const MAX_PORT: u16 = 62000;

    while current_port < MAX_PORT {
        match TcpListener::bind((Ipv4Addr::LOCALHOST, current_port)) {
            Ok(l) => {
                let bound_port = l.local_addr().map_err(MakerError::IO)?.port();
                return Ok((l, bound_port));
            }
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                log::info!("Port {} in use, trying {}", current_port, current_port + 2);
                current_port += 2
            }
            Err(e) => {
                log::error!("Failed to bind port {}: {}", current_port, e);
                return Err(MakerError::IO(e));
            }
        }
    }
    Err(MakerError::General(
        "No available ports found in valid range",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        maker::api::tests::compat_test_maker,
        protocol::common_messages::{Hello, PrivateKeyHandover},
        watch_tower::service::answering,
    };
    use bitcoin::{hashes::Hash, Txid};
    use serde::{Deserialize, Serialize};
    use serde_cbor::{value::to_value, Value};
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        net::Shutdown,
    };

    // The handshake variants and fields from v0.2.3 stay independent of
    // the new enums so removing the deliberate refusal breaks this test.
    #[derive(Debug, Serialize, Deserialize)]
    enum CompatV023TakerMessage {
        TakerHello(()),
        Unsupported { what: String, reason: String },
    }

    #[derive(Debug, Serialize, Deserialize)]
    enum CompatV023MakerMessage {
        MakerHello {
            supported_protocols: Vec<ProtocolVersion>,
        },
        Unsupported {
            what: String,
            reason: String,
        },
    }

    fn compat_connection_replies(
        maker: &Arc<MakerServer>,
        frames: &[Vec<u8>],
        close_input: bool,
    ) -> Vec<MakerToTakerMessage> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        let maker = maker.clone();
        let permit = ConnectionLimiter::new().try_acquire().unwrap();
        let handler = thread::spawn(move || handle_connection(maker, Arc::new(server), permit));
        for frame in frames {
            client
                .write_all(&(frame.len() as u32).to_be_bytes())
                .unwrap();
            client.write_all(frame).unwrap();
        }
        if close_input {
            client.shutdown(Shutdown::Write).unwrap();
        }
        let mut replies = Vec::new();
        loop {
            let mut prefix = [0; 4];
            match client.read_exact(&mut prefix) {
                Ok(()) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
                    ) =>
                {
                    break
                }
                Err(e) => panic!("maker did not close after the frames: {}", e),
            }
            let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
            client.read_exact(&mut body).unwrap();
            replies.push(serde_cbor::from_slice(&body).unwrap());
        }
        handler.join().unwrap().unwrap();
        replies
    }

    #[test]
    fn compat_v023_taker_gets_readable_refusal_and_connection_close() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let maker = compat_test_maker(dir.path(), vec![]);
        let old_hello = serde_cbor::to_vec(&CompatV023TakerMessage::TakerHello(())).unwrap();
        let replies = compat_connection_replies(&maker, &[old_hello], false);
        let [refusal] = replies.as_slice() else {
            panic!("expected one refusal: {:?}", replies)
        };
        let old_refusal: CompatV023MakerMessage =
            serde_cbor::from_slice(&serde_cbor::to_vec(refusal).unwrap()).unwrap();
        assert!(matches!(
            old_refusal,
            CompatV023MakerMessage::Unsupported { what, reason }
                if what == "TakerHello" && reason == "cannot decode"
        ));
        let hello = Hello::default();
        for bytes in [
            serde_cbor::to_vec(&TakerToMakerMessage::Hello(hello.clone())).unwrap(),
            serde_cbor::to_vec(&MakerToTakerMessage::Hello(hello)).unwrap(),
        ] {
            assert!(serde_cbor::from_slice::<CompatV023TakerMessage>(&bytes).is_err());
            assert!(serde_cbor::from_slice::<CompatV023MakerMessage>(&bytes).is_err());
        }
        let old_refusal = CompatV023TakerMessage::Unsupported {
            what: "Hello".into(),
            reason: "unsupported".into(),
        };
        assert!(compat_connection_replies(
            &maker,
            &[serde_cbor::to_vec(&old_refusal).unwrap()],
            false,
        )
        .is_empty());
        maker.watch_service.shutdown();
    }

    #[test]
    fn compat_maker_gate_requires_hello_before_heartbeat_and_handover() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let maker = compat_test_maker(dir.path(), vec![]);
        let legacy = PrivateKeyHandover {
            id: "cached-legacy".into(),
            privkeys: vec![],
        };
        let taproot = PrivateKeyHandover {
            id: "cached-taproot".into(),
            privkeys: vec![],
        };
        for (protocol, request, response) in [
            (
                ProtocolVersion::Legacy,
                legacy.clone(),
                MakerToTakerMessage::LegacyPrivateKeyHandover(legacy.clone()),
            ),
            (
                ProtocolVersion::Taproot,
                taproot.clone(),
                MakerToTakerMessage::TaprootPrivateKeyHandover(taproot.clone()),
            ),
        ] {
            maker
                .cache_completed_handover(protocol, request.clone(), &response)
                .unwrap();
            assert!(maker
                .replay_completed_handover(protocol, &request)
                .unwrap()
                .is_some());
        }
        for message in [
            TakerToMakerMessage::GetOffer(Default::default()),
            TakerToMakerMessage::WaitingFundingConfirmation("unknown".into()),
            TakerToMakerMessage::LegacyPrivateKeyHandover(legacy.clone()),
            TakerToMakerMessage::TaprootPrivateKeyHandover(taproot.clone()),
        ] {
            assert!(compat_connection_replies(
                &maker,
                &[serde_cbor::to_vec(&message).unwrap()],
                false
            )
            .is_empty());
        }
        let hello = serde_cbor::to_vec(&TakerToMakerMessage::Hello(Hello::default())).unwrap();
        for (request, expected) in [
            (
                TakerToMakerMessage::LegacyPrivateKeyHandover(legacy.clone()),
                MakerToTakerMessage::LegacyPrivateKeyHandover(legacy),
            ),
            (
                TakerToMakerMessage::TaprootPrivateKeyHandover(taproot.clone()),
                MakerToTakerMessage::TaprootPrivateKeyHandover(taproot),
            ),
        ] {
            let replies = compat_connection_replies(
                &maker,
                &[hello.clone(), serde_cbor::to_vec(&request).unwrap()],
                true,
            );
            assert_eq!(replies.len(), 2);
            assert!(matches!(replies[0], MakerToTakerMessage::Hello(_)));
            assert_eq!(to_value(&replies[1]).unwrap(), to_value(expected).unwrap());
        }
        let replies = compat_connection_replies(&maker, &[hello.clone(), hello], false);
        assert!(matches!(
            replies.as_slice(),
            [MakerToTakerMessage::Hello(_)]
        ));
        maker.watch_service.shutdown();
    }

    #[test]
    fn compat_maker_requirements_refuse_and_close_or_accept_higher_versions() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let maker = compat_test_maker(dir.path(), vec!["x-v1".into()]);
        for (features, accepted) in [
            (vec!["x-v1", "x-v2"], true),
            (vec!["x-v2"], true),
            (vec!["x"], false),
            (vec![], false),
        ] {
            let hello = TakerToMakerMessage::Hello(Hello {
                features: features.into_iter().map(String::from).collect(),
            });
            let replies =
                compat_connection_replies(&maker, &[serde_cbor::to_vec(&hello).unwrap()], accepted);
            if accepted {
                assert!(matches!(
                    replies.as_slice(),
                    [MakerToTakerMessage::Hello(_)]
                ));
            } else {
                assert!(
                    matches!(replies.as_slice(), [MakerToTakerMessage::Unsupported(refusal)] if refusal.what == "Hello" && refusal.reason.contains("x-v1"))
                );
            }
        }
        maker.watch_service.shutdown();
    }

    #[test]
    fn compat_maker_decode_failure_names_future_variants_without_reply_loops() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let maker = compat_test_maker(dir.path(), vec![]);
        let hello = serde_cbor::to_vec(&TakerToMakerMessage::Hello(Hello::default())).unwrap();
        let tagged =
            |tag: &str, body: Value| Value::Map(BTreeMap::from([(Value::Text(tag.into()), body)]));
        for (value, expected) in [
            (Value::Text("FutureUnit".into()), Some("FutureUnit")),
            (tagged("FutureBody", Value::Integer(7)), Some("FutureBody")),
            (
                tagged("Lightning", tagged("FutureLn", Value::Null)),
                Some("Lightning::FutureLn"),
            ),
            (tagged("Unsupported", Value::Null), None),
            (Value::Text("Unsupported".into()), None),
            (Value::Integer(7), None),
        ] {
            let replies = compat_connection_replies(
                &maker,
                &[hello.clone(), serde_cbor::to_vec(&value).unwrap()],
                false,
            );
            assert!(matches!(
                replies.first(),
                Some(MakerToTakerMessage::Hello(_))
            ));
            match expected {
                Some(name) => assert!(
                    matches!(&replies[1..], [MakerToTakerMessage::Unsupported(refusal)] if refusal.what == name && refusal.reason == "cannot decode")
                ),
                None => assert_eq!(replies.len(), 1),
            }
        }
        let mut future_hello = to_value(TakerToMakerMessage::Hello(Hello::default())).unwrap();
        let Value::Map(outer) = &mut future_hello else {
            panic!()
        };
        let Value::Map(body) = outer.get_mut(&Value::Text("Hello".into())).unwrap() else {
            panic!()
        };
        body.insert(Value::Text("future".into()), Value::Bool(true));
        assert!(matches!(
            compat_connection_replies(&maker, &[serde_cbor::to_vec(&future_hello).unwrap()], true)
                .as_slice(),
            [MakerToTakerMessage::Hello(_)]
        ));
        maker.watch_service.shutdown();
    }

    /// The preimage check reads a spend's witness before it lets recovery
    /// refund. A watcher that cannot answer must stop the pass, or the
    /// timelock refund could race a preimage spend it never saw.
    #[test]
    fn preimage_check_stops_on_an_unknown_answer() {
        let outpoint = OutPoint::new(Txid::all_zeros(), 0);
        // A watch the watcher does not have is no answer either.
        for answer in [
            WatcherEvent::Error("not subscribed".to_string()),
            WatcherEvent::NoOutpoint,
        ] {
            let service = answering(answer.clone());
            assert!(watched_spend(&service, outpoint).is_err(), "{:?}", answer);
            service.shutdown();
        }

        let claim = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let service = answering(WatcherEvent::UtxoSpent {
            outpoint,
            spending_tx: Some(claim.clone()),
        });
        assert_eq!(watched_spend(&service, outpoint).unwrap(), Some(claim));
        service.shutdown();
    }

    /// A fresh maker must get the default port when it is free.
    #[test]
    fn bind_port_retry_tries_the_given_port_first() {
        // Two free ports a step apart, below the search's upper bound.
        let (held, port) = (20_000..30_000)
            .step_by(2)
            .find_map(|port| {
                let held = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).ok()?;
                TcpListener::bind((Ipv4Addr::LOCALHOST, port + 2)).ok()?;
                Some((held, port))
            })
            .expect("no free port pair");

        let (_next, bound) = bind_port_retry(port).unwrap();
        assert_eq!(bound, port + 2, "a taken port moves the search on");
        drop(_next);

        drop(held);
        let (_listener, bound) = bind_port_retry(port).unwrap();
        assert_eq!(bound, port, "a free port is used as is");
    }

    #[test]
    fn pending_connections_are_bounded() {
        let limiter = ConnectionLimiter::new();
        let permits: Vec<_> = (0..MAX_PENDING_CONNECTIONS)
            .map(|_| limiter.try_acquire().expect("pending slot below limit"))
            .collect();

        limiter.state.lock().unwrap().tokens = CONNECTION_BURST;
        assert!(limiter.try_acquire().is_none());
        assert_eq!(
            limiter.state.lock().unwrap().pending,
            MAX_PENDING_CONNECTIONS
        );
        assert_eq!(limiter.state.lock().unwrap().tokens, CONNECTION_BURST - 1.0);
        drop(permits);
        let state = limiter.state.lock().unwrap();
        assert_eq!(state.active, 0);
        assert_eq!(state.pending, 0);
    }

    #[test]
    fn established_connections_are_bounded() {
        let limiter = ConnectionLimiter::new();
        let mut permits = Vec::new();
        for _ in 0..MAX_INBOUND_CONNECTIONS {
            limiter.state.lock().unwrap().tokens = 1.0;
            let mut permit = limiter.try_acquire().expect("active slot below limit");
            permit.mark_established();
            permits.push(permit);
        }

        limiter.state.lock().unwrap().tokens = 1.0;
        assert!(limiter.try_acquire().is_none());
        {
            let state = limiter.state.lock().unwrap();
            assert_eq!(state.active, MAX_INBOUND_CONNECTIONS);
            assert_eq!(state.pending, 0);
        }
        drop(permits);
        assert_eq!(limiter.state.lock().unwrap().active, 0);
    }

    #[test]
    fn token_bucket_limits_connection_burst() {
        let limiter = ConnectionLimiter::new();
        let mut permits = Vec::new();
        for _ in 0..MAX_PENDING_CONNECTIONS {
            let mut permit = limiter.try_acquire().expect("token within burst");
            permit.mark_established();
            permits.push(permit);
        }
        let mut state = limiter.state.lock().unwrap();
        state.tokens = 0.0;
        state.last_refill = Instant::now();
        drop(state);
        assert!(limiter.try_acquire().is_none());
    }

    #[test]
    fn heartbeat_admission_rejects_throttles_and_promotes() {
        let limiter = ConnectionLimiter::new();
        let mut permit = limiter.try_acquire().unwrap();
        let mut heartbeat_swap = None;
        let mut last_keepalive = None;

        assert!(matches!(
            admit_heartbeat(
                "a",
                false,
                &mut heartbeat_swap,
                &mut last_keepalive,
                &mut permit
            ),
            HeartbeatAction::Reject
        ));
        assert!(permit.pending);
        assert!(heartbeat_swap.is_none());

        assert!(matches!(
            admit_heartbeat(
                "a",
                true,
                &mut heartbeat_swap,
                &mut last_keepalive,
                &mut permit
            ),
            HeartbeatAction::Accept
        ));
        assert!(!permit.pending);
        assert_eq!(heartbeat_swap.as_deref(), Some("a"));
        assert!(matches!(
            admit_heartbeat(
                "a",
                true,
                &mut heartbeat_swap,
                &mut last_keepalive,
                &mut permit
            ),
            HeartbeatAction::Throttle
        ));
    }

    #[test]
    fn heartbeat_socket_cannot_switch_swap_id() {
        let limiter = ConnectionLimiter::new();
        let mut permit = limiter.try_acquire().unwrap();
        let mut heartbeat_swap = None;
        let mut last_keepalive = None;

        assert!(matches!(
            admit_heartbeat(
                "a",
                true,
                &mut heartbeat_swap,
                &mut last_keepalive,
                &mut permit
            ),
            HeartbeatAction::Accept
        ));
        // Past the throttle window, a different id is still refused.
        last_keepalive = Some(Instant::now() - MIN_KEEPALIVE_INTERVAL);
        assert!(matches!(
            admit_heartbeat(
                "b",
                true,
                &mut heartbeat_swap,
                &mut last_keepalive,
                &mut permit
            ),
            HeartbeatAction::Reject
        ));
        assert_eq!(heartbeat_swap.as_deref(), Some("a"));
        assert!(matches!(
            admit_heartbeat(
                "a",
                true,
                &mut heartbeat_swap,
                &mut last_keepalive,
                &mut permit
            ),
            HeartbeatAction::Accept
        ));
    }

    #[test]
    fn pending_deadline_stops_slow_reads() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let reader = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            read_message(&stream, Some(Instant::now() + Duration::from_millis(50)))
        });

        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(&[0]).unwrap();
        thread::sleep(Duration::from_millis(150));

        assert!(reader.join().unwrap().is_err());
    }
}
