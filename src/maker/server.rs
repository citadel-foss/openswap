//! OpenSwap Maker Server.

use std::{
    io::{ErrorKind, Read},
    net::{Ipv4Addr, TcpListener, TcpStream},
    sync::{
        atomic::Ordering::{self, Relaxed},
        Arc, Mutex,
    },
    thread::{self, sleep},
    time::{Duration, Instant},
};

#[cfg(not(feature = "integration-test"))]
use crate::maker::rpc::server::MakerRpc;
use crate::{
    lock_debug,
    maker::nostr::broadcast_bond_on_nostr,
    protocol::common_messages::{MakerToTakerMessage, TakerToMakerMessage},
    utill::{HEART_BEAT_INTERVAL, MAX_RPC_MESSAGE_SIZE},
    wallet::{Blockchain, RecoveryReport, Wallet},
};

use super::{
    api::MakerServer,
    error::MakerError,
    handlers::{handle_message, ConnectionState, Maker, MAX_CONCURRENT_SWAPS},
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

impl LimiterState {
    fn new() -> Self {
        Self {
            active: 0,
            pending: 0,
            tokens: CONNECTION_BURST,
            last_refill: Instant::now(),
        }
    }
}

struct ConnectionLimiter {
    state: Mutex<LimiterState>,
}

impl ConnectionLimiter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(LimiterState::new()),
        })
    }

    fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
            let mut state = self
                .limiter
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.pending -= 1;
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut state = self
            .limiter
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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

fn admit_heartbeat(
    known_swap: bool,
    last_keepalive: &mut Option<Instant>,
    permit: &mut ConnectionPermit,
) -> HeartbeatAction {
    if !known_swap {
        HeartbeatAction::Reject
    } else if last_keepalive.is_some_and(|last| last.elapsed() < MIN_KEEPALIVE_INTERVAL) {
        HeartbeatAction::Throttle
    } else {
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

/// Start the maker server.
pub fn start_server(maker: Arc<MakerServer>) -> Result<(), MakerError> {
    log::info!("[{}] Starting maker server", maker.config.network_port);

    #[cfg(feature = "integration-test")]
    if maker.behavior == super::handlers::MakerBehavior::StopWatcherOnStartup {
        maker.watch_service.stop_watcher_for_test();
    }
    let listener = if maker.watch_service.is_alive() {
        let listener = TcpListener::bind(("127.0.0.1", maker.config.network_port)).map_err(|e| {
            log::warn!(
                "Failed to bind network port {}: {}. Fidelity bond funds may be locked to this port.",
                maker.config.network_port,
                e
            );
            MakerError::IO(e)
        })?;
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
            // Regression coverage: `tests/integration/reboot_recovery.rs`.
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

            for (swap_id, (inc, out)) in groups {
                let maker_clone = Arc::clone(&maker);
                let handle = thread::Builder::new()
                    .name(format!("reboot-recovery-{}", maker.config.network_port))
                    .spawn(move || {
                        if let Err(e) = recover_from_swap(maker_clone, swap_id.clone(), inc, out) {
                            log::error!("Reboot recovery failed for {}: {:?}", swap_id, e);
                        }
                    })
                    .map_err(MakerError::IO)?;
                maker.thread_pool.add_thread(handle)?;
            }
        }
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

    log::info!("[{}] Server shutdown complete", maker.config.network_port);

    Ok(())
}

/// Spawn a background thread for nostr bond announcements.
///
/// The thread re-reads `highest_fidelity_proof` on every broadcast cycle so
/// that bond renewals are picked up.
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

    maker.thread_pool.add_thread(handle)?;

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

        let message = match read_message(&stream, permit.pending.then_some(pending_deadline)) {
            Ok(msg) => msg,
            Err(e) => {
                // A read timeout is only a wakeup: keepalives arrive on separate
                // connections and refresh the shared swap activity. Break only
                // when the swap has gone quiet everywhere, not just this socket.
                if is_read_timeout(&e) && !swap_is_quiet(&maker, &state) {
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

        // Heartbeat connections carry a known swap id but intentionally keep a
        // lightweight local state. Recognize them without changing the protocol.
        if let TakerToMakerMessage::WaitingFundingConfirmation(id) = &message {
            let known_swap = maker.get_connection_state(id)?.is_some();
            match admit_heartbeat(known_swap, &mut last_keepalive, &mut permit) {
                HeartbeatAction::Reject | HeartbeatAction::Throttle => break,
                HeartbeatAction::Accept => {}
            }
        }

        log::debug!(
            "[{}] Received message: {:?}",
            maker.config.network_port,
            message
        );

        let handling_started = Instant::now();
        let response = match handle_message(&maker, &mut state, message) {
            Ok(resp) => resp,
            Err(e) => {
                log::error!("[{}] Handler error: {:?}", maker.config.network_port, e);
                // Some errors are recoverable, some are not
                break;
            }
        };
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

        if let Some(response) = response {
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
                break;
            }
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
            if let Err(e) = maker.sweep_incoming_swapcoins() {
                log::error!(
                    "[{}] Failed to sweep incoming swapcoins: {:?}",
                    maker.config.network_port,
                    e
                );
            }

            // Sync wallet after sweep to update UTXO cache.
            if let Err(e) = maker.sync_and_save_wallet() {
                log::error!(
                    "[{}] Failed to sync wallet after sweep: {:?}",
                    maker.config.network_port,
                    e
                );
            }

            // Unwatch all contract outputs now that the swap is complete.
            for incoming in &state.incoming_swapcoins {
                let txid = incoming.contract_tx.compute_txid();
                for (vout, txout) in incoming.contract_tx.output.iter().enumerate() {
                    maker.unwatch_outpoint(
                        bitcoin::OutPoint {
                            txid,
                            vout: vout as u32,
                        },
                        txout.script_pubkey.clone(),
                    );
                }
            }
            for outgoing in &state.outgoing_swapcoins {
                let txid = outgoing.contract_tx.compute_txid();
                for (vout, txout) in outgoing.contract_tx.output.iter().enumerate() {
                    maker.unwatch_outpoint(
                        bitcoin::OutPoint {
                            txid,
                            vout: vout as u32,
                        },
                        txout.script_pubkey.clone(),
                    );
                }
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
fn is_read_timeout(e: &MakerError) -> bool {
    matches!(e, MakerError::IO(io) if matches!(io.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut))
}

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
    use super::swap_tracker::{now_secs, MakerRecoveryState, MakerSwapPhase, MakerSwapRecord};

    loop {
        if maker.is_shutdown() {
            break;
        }

        let idle_swaps = maker.drain_idle_swaps(IDLE_CONNECTION_TIMEOUT)?;

        for idle in idle_swaps {
            log::error!(
                "[{}] Potential dropped connection from taker. Swap {} idle. Recovering from swap",
                maker.config.network_port,
                idle.swap_id
            );

            // Create a tracker record for this dropped swap.
            let now = now_secs();
            let record = MakerSwapRecord {
                swap_id: idle.swap_id.clone(),
                protocol: idle.protocol,
                phase: MakerSwapPhase::TakerDropped,
                swap_amount_sat: idle.swap_amount_sat,
                incoming_count: idle.incoming_swapcoins.len(),
                outgoing_count: idle.outgoing_swapcoins.len(),
                funding_broadcast: idle.funding_broadcast,
                recovery: MakerRecoveryState::default(),
                created_at: now,
                updated_at: now,
            };

            if let Err(e) = lock_debug!(maker.swap_tracker.lock())
                .map_err(|_| MakerError::MutexPossion)?
                .save_record(&record)
            {
                log::error!("Failed to save swap tracker record: {:?}", e);
            }

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
            .redeem_expired_fidelity_bonds(AddressType::P2TR)
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

/// Minimum witness items for a hashlock spend (signature + preimage).
const MIN_WITNESS_ITEM_FOR_HASHLOCK: usize = 2;

/// Preimage length in bytes.
const PREIMAGE_LEN: usize = 32;

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
    let wallet = lock_debug!(maker.wallet.read())
        .map_err(|_| MakerError::General("Failed to lock wallet"))?;
    let direct_chain = (!maker.watch_service.is_alive())
        .then(|| wallet.blockchain.new_connection())
        .transpose()
        .map_err(MakerError::Wallet)?;
    drop(wallet);

    // Query the watch tower for spends on each outgoing contract output.
    for outgoing in outgoing_swapcoins {
        let contract_txid = outgoing.contract_tx.compute_txid();
        for (vout, _) in outgoing.contract_tx.output.iter().enumerate() {
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
                None => match maker.watch_service.watch_request(outpoint).map_err(|e| {
                    log::warn!("watch request for {outpoint} failed: {e}");
                    MakerError::General("watchtower query failed")
                })? {
                    crate::watch_tower::watcher::WatcherEvent::UtxoSpent {
                        spending_tx, ..
                    } => spending_tx,
                    _ => None,
                },
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

/// Update the Maker swap tracker with the given closure.
///
/// Locks the tracker, applies `f` to the record matching `swap_id`, then flushes.
fn update_tracker(
    maker: &MakerServer,
    swap_id: &str,
    f: impl FnOnce(&mut super::swap_tracker::MakerSwapRecord),
) {
    let mut tracker = match lock_debug!(maker.swap_tracker.lock()) {
        Ok(tracker) => tracker,
        Err(_) => {
            log::error!("Swap tracker lock poisoned, skipping update for {swap_id}");
            return;
        }
    };
    if let Some(record) = tracker.get_record_mut(swap_id) {
        f(record);
        record.updated_at = super::swap_tracker::now_secs();
        let cloned = record.clone();
        if let Err(e) = tracker.save_record(&cloned) {
            log::error!("Failed to flush swap tracker: {:?}", e);
        }
    }
}

/// Recover maker funds after taker drops.
///
/// Two recovery paths are tried in a loop:
/// 1. **Hashlock** (incoming swapcoins): If the taker (or another party) spends
///    our outgoing contract output via hashlock, the preimage is revealed on-chain.
///    We extract it via the watch tower and sweep our incoming swapcoins.
/// 2. **Timelock** (outgoing swapcoins): After the timelock expires, we reclaim
///    our outgoing funds via the timelock spending path.
fn recover_from_swap(
    maker: Arc<MakerServer>,
    swap_id: String,
    incoming_swapcoins: Vec<crate::wallet::swapcoin::IncomingSwapCoin>,
    outgoing_swapcoins: Vec<crate::wallet::swapcoin::OutgoingSwapCoin>,
) -> Result<(), MakerError> {
    use super::swap_tracker::{MakerRecoveryPhase, MakerSwapPhase};

    // For Taproot, get_timelock() returns an absolute CLTV height.
    // For Legacy, it returns a relative CSV offset — but Legacy recovery
    // uses wallet-level methods that handle CSV internally, so we only
    // need the absolute value here for the monitoring loop.
    let timelock_expiry = outgoing_swapcoins
        .first()
        .and_then(|o| o.get_timelock())
        .ok_or(MakerError::General("missing timelock on outgoing swapcoin"))?;

    let start_height = lock_debug!(maker.wallet.read())
        .map_err(|_| MakerError::General("Failed to lock wallet"))?
        .blockchain
        .get_block_count()
        .map_err(MakerError::Wallet)? as u32;

    log::info!(
        "[{}] recover_from_swap started | height={} timelock_expiry={} | incoming={} outgoing={}",
        maker.config.network_port,
        start_height,
        timelock_expiry,
        incoming_swapcoins.len(),
        outgoing_swapcoins.len()
    );

    let all_swap_contracts_resolved = || -> Result<bool, MakerError> {
        let wallet = lock_debug!(maker.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?;

        let contract_txids = outgoing_swapcoins
            .iter()
            .map(|s| (s.contract_tx.compute_txid(), s.get_contract_output_vout()))
            .chain(
                incoming_swapcoins
                    .iter()
                    .map(|s| (s.contract_tx.compute_txid(), s.get_contract_output_vout())),
            );

        for (txid, vout) in contract_txids {
            if wallet.blockchain.get_tx_out(&txid, vout, None)?.is_some() {
                return Ok(false);
            }
        }
        Ok(true)
    };
    let mut timelock_recovery_txids = Vec::new();

    // Check if funding was ever broadcast. Only an explicit tracker record with
    // funding_broadcast=false is safe to discard; missing tracker state can
    // happen after a reboot and must not delete persisted recovery material.
    {
        let funding_broadcast = lock_debug!(maker.swap_tracker.lock())
            .map_err(|_| MakerError::MutexPossion)?
            .get_record(&swap_id)
            .map(|r| r.funding_broadcast);

        if funding_broadcast == Some(false) {
            log::info!(
                "[{}] Funding was never broadcast for swap {} — nothing to recover. Discarding swapcoins.",
                maker.config.network_port,
                swap_id
            );

            {
                let mut wallet = lock_debug!(maker.wallet.write())
                    .map_err(|_| MakerError::General("Failed to lock wallet"))?;
                for outgoing in &outgoing_swapcoins {
                    let key = outgoing.contract_tx.compute_txid().to_string();
                    wallet.remove_outgoing_swapcoin(&key);
                }
                for incoming in &incoming_swapcoins {
                    let key = incoming.contract_tx.compute_txid().to_string();
                    wallet.remove_incoming_swapcoin(&key);
                }
                wallet.save_to_disk().map_err(MakerError::Wallet)?;
            }

            update_tracker(&maker, &swap_id, |r| {
                r.phase = MakerSwapPhase::Recovered;
                r.recovery.phase = MakerRecoveryPhase::CleanedUp;
            });

            #[cfg(feature = "integration-test")]
            maker.shutdown.store(true, Relaxed);
            return Ok(());
        }
    }

    // Tracker: Recovering + Monitoring
    update_tracker(&maker, &swap_id, |r| {
        r.phase = MakerSwapPhase::Recovering;
        r.recovery.phase = MakerRecoveryPhase::Monitoring;
    });

    let mut watchtower_down_logged = false;
    while !maker.is_shutdown() {
        // --- Hashlock path: check if preimages are available ---
        if let Err(e) = check_for_preimage(&maker, &outgoing_swapcoins, &incoming_swapcoins) {
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

        // Check if all incoming swapcoins now have preimages
        let all_preimages_known = {
            let wallet = lock_debug!(maker.wallet.read())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?;
            incoming_swapcoins.iter().all(|incoming| {
                // Wallet stores incoming swapcoins keyed by contract txid.
                let key = incoming.contract_tx.compute_txid().to_string();
                wallet
                    .find_incoming_swapcoin(&key)
                    .is_some_and(|s| s.is_preimage_known())
            })
        };

        let current_height = lock_debug!(maker.wallet.read())
            .map_err(|_| MakerError::General("Failed to lock wallet"))?
            .blockchain
            .get_block_count()
            .map_err(MakerError::Wallet)? as u32;

        // One connection per pass, shared by both recovery paths below: on Tor
        // Electrum each fresh connection costs a circuit handshake. Idle passes
        // that only poll the watchtower pay for none.
        let chain = if (all_preimages_known && !incoming_swapcoins.is_empty())
            || current_height >= timelock_expiry
        {
            Some(
                lock_debug!(maker.wallet.read())
                    .map_err(|_| MakerError::General("Failed to lock wallet"))?
                    .blockchain
                    .new_connection()
                    .map_err(MakerError::Wallet)?,
            )
        } else {
            None
        };

        if all_preimages_known && !incoming_swapcoins.is_empty() {
            log::info!(
                "[{}] All preimages known, recovering via hashlock path",
                maker.config.network_port
            );

            lock_debug!(maker.wallet.write())
                .map_err(|_| MakerError::General("Failed to lock wallet"))?
                .sync_and_save(&maker.shutdown)
                .map_err(MakerError::Wallet)?;

            let chain = chain.as_ref().expect("connection created for this branch");

            let swept = Wallet::sweep_incoming_swapcoins(
                &maker.wallet,
                chain,
                crate::utill::MIN_FEE_RATE,
                &maker.shutdown,
            )
            .map_err(MakerError::Wallet)?;

            if !swept.is_empty() {
                log::info!(
                    "[{}] Recovered {} incoming swapcoins via hashlock",
                    maker.config.network_port,
                    swept.resolved.len()
                );

                // Tracker: HashlockRecovered
                let swept_txids: Vec<_> = swept.resolved.iter().map(|(_, txid)| *txid).collect();
                update_tracker(&maker, &swap_id, |r| {
                    r.recovery.incoming_swept = swept_txids;
                    r.recovery.phase = MakerRecoveryPhase::HashlockRecovered;
                });

                // Clean up outgoing swapcoins — their funding was spent by
                // someone else (hashlock), so they are no longer recoverable
                // via timelock. Remove them from the wallet store.
                {
                    let mut wallet = lock_debug!(maker.wallet.write())
                        .map_err(|_| MakerError::General("Failed to lock wallet"))?;
                    for outgoing in &outgoing_swapcoins {
                        // Wallet stores outgoing swapcoins keyed by contract txid.
                        let key = outgoing.contract_tx.compute_txid().to_string();
                        wallet.remove_outgoing_swapcoin(&key);
                    }
                    wallet.save_to_disk().map_err(MakerError::Wallet)?;
                }

                // Tracker: Recovered + CleanedUp
                update_tracker(&maker, &swap_id, |r| {
                    r.phase = MakerSwapPhase::Recovered;
                    r.recovery.phase = MakerRecoveryPhase::CleanedUp;
                });

                // Emit hashlock recovery reports
                let network = lock_debug!(maker.wallet.read())
                    .map(|w| w.store.network.to_string())
                    .unwrap_or_default();
                let recovery_txids: Vec<String> = swept
                    .resolved
                    .iter()
                    .map(|(_, spending_txid)| spending_txid.to_string())
                    .collect();
                RecoveryReport::emit_maker(
                    &maker.data_dir,
                    swap_id.clone(),
                    network.clone(),
                    "hashlock".to_string(),
                    recovery_txids,
                );

                #[cfg(feature = "integration-test")]
                maker.shutdown.store(true, Relaxed);
                return Ok(());
            }
        }

        // --- Timelock path: reclaim outgoing after timelock expires ---
        if current_height >= timelock_expiry {
            log::info!(
                "[{}] Timelock expired at {} (expiry={}), recovering via timelock path",
                maker.config.network_port,
                current_height,
                timelock_expiry
            );

            // Tracker: TimelockWaiting
            update_tracker(&maker, &swap_id, |r| {
                r.recovery.phase = MakerRecoveryPhase::TimelockWaiting;
            });

            let chain = chain.as_ref().expect("connection created for this branch");

            let recovered = Wallet::recover_timelocked_swapcoins(
                &maker.wallet,
                chain,
                crate::utill::MIN_FEE_RATE,
                &maker.shutdown,
            )
            .map_err(MakerError::Wallet)?;

            if !recovered.is_empty() {
                log::info!(
                    "[{}] Recovered {} outgoing swapcoins via timelock",
                    maker.config.network_port,
                    recovered.len()
                );

                // Tracker: TimelockRecovered → Recovered + CleanedUp
                let recovered_txids: Vec<_> =
                    recovered.resolved.iter().map(|(_, txid)| *txid).collect();
                timelock_recovery_txids.extend(recovered_txids.iter().copied());
                update_tracker(&maker, &swap_id, |r| {
                    r.recovery.outgoing_recovered = timelock_recovery_txids.clone();
                    r.recovery.phase = MakerRecoveryPhase::TimelockRecovered;
                });
                // A backend that cannot answer says nothing about the contracts;
                // ask again next pass rather than declaring the swap finished.
                let resolved = all_swap_contracts_resolved().unwrap_or_else(|e| {
                    log::warn!(
                        "[{}] Could not check contract outputs: {:?}",
                        maker.config.network_port,
                        e
                    );
                    false
                });
                if resolved {
                    update_tracker(&maker, &swap_id, |r| {
                        r.phase = MakerSwapPhase::Recovered;
                        r.recovery.phase = MakerRecoveryPhase::CleanedUp;
                    });

                    // Emit timelock recovery reports
                    let network = lock_debug!(maker.wallet.read())
                        .map(|w| w.store.network.to_string())
                        .unwrap_or_default();
                    let recovery_txids: Vec<String> = timelock_recovery_txids
                        .iter()
                        .map(|spending_txid| spending_txid.to_string())
                        .collect();
                    RecoveryReport::emit_maker(
                        &maker.data_dir,
                        swap_id.clone(),
                        network.clone(),
                        "timelock".to_string(),
                        recovery_txids,
                    );

                    #[cfg(feature = "integration-test")]
                    maker.shutdown.store(true, Relaxed);
                    return Ok(());
                }
            }
        }

        sleep(HEART_BEAT_INTERVAL);
    }

    Ok(())
}

/// Read a message, enforcing one absolute deadline until the connection proves
/// that it belongs to an admitted swap.
fn read_message(
    stream: &TcpStream,
    pending_deadline: Option<Instant>,
) -> Result<TakerToMakerMessage, MakerError> {
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

    let message: TakerToMakerMessage = serde_cbor::from_slice(&buf)
        .map_err(|_| MakerError::General("Failed to deserialize message"))?;

    Ok(message)
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

/// Retry with different ports if not availabe
pub fn bind_port_retry(port: u16) -> Result<(TcpListener, u16), MakerError> {
    let mut current_port = port + 2;
    const MAX_PORT: u16 = 62000;

    while current_port < MAX_PORT {
        match TcpListener::bind((Ipv4Addr::LOCALHOST, current_port)) {
            Ok(l) => return Ok((l, current_port)),
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
    use std::io::Write;

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
        let mut last_keepalive = None;

        assert!(matches!(
            admit_heartbeat(false, &mut last_keepalive, &mut permit),
            HeartbeatAction::Reject
        ));
        assert!(permit.pending);

        assert!(matches!(
            admit_heartbeat(true, &mut last_keepalive, &mut permit),
            HeartbeatAction::Accept
        ));
        assert!(!permit.pending);
        assert!(matches!(
            admit_heartbeat(true, &mut last_keepalive, &mut permit),
            HeartbeatAction::Throttle
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
