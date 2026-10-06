//! Nostr discovery module.
//!
//! Handles the discovery of Maker fidelity bonds via Nostr relays. It creates persistent
//! subscriptions to network-specific OpenSwap events, validates incoming fidelity
//! announcements against the Bitcoin blockchain, and stores validated candidates in the registry.

use std::{
    borrow::Cow,
    net::{Shutdown, TcpStream},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use bitcoin::Network;
use nostr::{
    event::Kind,
    filter::Filter,
    message::{ClientMessage, RelayMessage, SubscriptionId},
    types::Timestamp,
    util::JsonUtil,
};
use rustls::StreamOwned;
use tungstenite::{stream::MaybeTlsStream, Message};

use crate::{
    lock_debug,
    maker::nostr::{connect_nostr_websocket, swap_kind, EXPIRATION_SECS},
    wallet::{AnyBlockchain, Blockchain},
    watch_tower::{
        registry_storage::FileRegistry,
        utils::{parse_fidelity_event, process_fidelity, SeenTxids},
        watcher_error::WatcherError,
    },
};

/// Max seconds an event's `created_at` may sit ahead of our clock. Covers
/// clock skew only; anything further would poison the saved cursor.
const MAX_FUTURE_SKEW_SECS: u64 = 300;

/// Maximum queued Nostr discovery events before relay readers apply backpressure.
const DISCOVERY_EVENT_BUFFER_SIZE: usize = 1024;

/// Runs the main discovery routine for maker's fidelity bonds by subscribing to network-specific Nostr events.
/// Blocks until every relay session exits (normally at shutdown).
pub fn run_discovery(
    blockchain: AnyBlockchain,
    network: Network,
    registry: FileRegistry,
    shutdown: Arc<AtomicBool>,
    initial_sync_complete: Arc<AtomicBool>,
    relays: &[String],
    nostr_tor_config: (u16, String),
) -> Result<(), WatcherError> {
    let kind = Kind::Custom(swap_kind(network));
    log::info!(
        "Starting market discovery via Nostr | network={} | kind={} | relays={:?}",
        network,
        kind,
        relays
    );

    let registry = Arc::new(registry);
    let (event_tx, event_rx) = crossbeam_channel::bounded::<(Arc<str>, RelayMessage<'static>)>(
        DISCOVERY_EVENT_BUFFER_SIZE,
    );

    let worker_shutdown = shutdown.clone();
    let worker_registry = Arc::clone(&registry);
    let worker_initial_sync = initial_sync_complete.clone();
    let worker_handle = match std::thread::Builder::new()
        .name("nostr-discovery-processor".to_string())
        .spawn(move || {
            run_discovery_event_processor(
                event_rx,
                blockchain,
                worker_registry,
                kind,
                worker_shutdown,
                worker_initial_sync,
            );
        }) {
        Ok(handle) => handle,
        Err(e) => {
            shutdown.store(true, Ordering::SeqCst);
            return Err(e.into());
        }
    };

    let mut sessions = Vec::with_capacity(relays.len() + 1);
    let mut tcp_slots = Vec::with_capacity(relays.len());
    for relay in relays {
        let relay = relay.to_string();
        let session_shutdown = shutdown.clone();
        let registry = Arc::clone(&registry);
        let nostr_tor_config = nostr_tor_config.clone();
        let session_tx = event_tx.clone();
        let tcp_slot = Arc::new(Mutex::new(None));
        tcp_slots.push(Arc::clone(&tcp_slot));

        let handle = match std::thread::Builder::new()
            .name(format!("nostr-session-{}", relay))
            .spawn(move || {
                run_nostr_session_for_relay(
                    &relay,
                    kind,
                    &registry,
                    session_shutdown,
                    session_tx,
                    &tcp_slot,
                    (nostr_tor_config.0, nostr_tor_config.1.as_str()),
                );
            }) {
            Ok(handle) => handle,
            Err(e) => {
                shutdown.store(true, Ordering::SeqCst);
                drop(event_tx);
                close_relay_sockets(&tcp_slots);
                sessions.push(worker_handle);
                join_relay_sessions(sessions);
                return Err(e.into());
            }
        };
        sessions.push(handle);
    }

    // Drop original sender so the channel disconnects when all relay sessions exit
    drop(event_tx);

    // The processor stops at shutdown. Closing the relay sockets then wakes
    // sessions parked in `read()`, instead of waiting out the 30 s read timeout.
    join_relay_sessions(vec![worker_handle]);
    close_relay_sockets(&tcp_slots);

    // Joining here surfaces a panicked session to the watcher's join,
    // instead of losing it in a detached thread.
    log::info!(
        "Nostr discovery: joining {} relay session(s)",
        sessions.len()
    );
    join_relay_sessions(sessions);
    log::info!("Nostr discovery: all relay sessions joined");

    Ok(())
}

/// Wakes relay sessions parked in `read()`. Call only once shutdown is set,
/// so a session that has not stored its socket yet sees the flag instead.
fn close_relay_sockets(tcp_slots: &[Arc<Mutex<Option<TcpStream>>>]) {
    for tcp_slot in tcp_slots {
        if let Some(tcp) = lock_debug!(tcp_slot.lock())
            .ok()
            .and_then(|mut tcp| tcp.take())
        {
            let _ = tcp.shutdown(Shutdown::Both);
        }
    }
}

/// Joins every spawned relay, including sessions created before a partial-start failure.
fn join_relay_sessions(sessions: Vec<std::thread::JoinHandle<()>>) {
    for session in sessions {
        let thread = session.thread().clone();
        crate::utill::log_shutdown_join_start("nostr_discovery", &thread);
        let result = session.join();
        crate::utill::log_shutdown_join_done(
            "nostr_discovery",
            &thread,
            if result.is_ok() { "ok" } else { "panic" },
        );
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }
}

/// Single worker thread consuming Nostr events from all relays over a shared channel.
/// Uses a single shared blockchain connection to prevent duplicate node/Electrum queries.
fn run_discovery_event_processor(
    rx: crossbeam_channel::Receiver<(Arc<str>, RelayMessage<'static>)>,
    blockchain: AnyBlockchain,
    registry: Arc<FileRegistry>,
    kind: Kind,
    shutdown: Arc<AtomicBool>,
    initial_sync_complete: Arc<AtomicBool>,
) {
    let mut seen_txid = SeenTxids::new();

    while !shutdown.load(Ordering::SeqCst) {
        let (relay_url, msg) = match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(item) => item,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        };

        let registry_clone = Arc::clone(&registry);
        let process_result = catch_unwind(AssertUnwindSafe(|| {
            handle_relay_message(
                registry_clone,
                msg,
                &blockchain,
                &relay_url,
                kind,
                &mut seen_txid,
            )
        }));

        let is_eose = match process_result {
            Ok(Ok(eose)) => eose,
            Ok(Err(e)) => {
                log::warn!("Error processing relay message from {relay_url}: {e:?}");
                false
            }
            Err(panic_err) => {
                let panic_msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                    *s
                } else if let Some(s) = panic_err.downcast_ref::<String>() {
                    s.as_str()
                } else {
                    "unknown panic"
                };
                log::error!(
                    "Recovered from panic while processing Nostr relay message from {relay_url}: {panic_msg}"
                );
                false
            }
        };

        if is_eose && !initial_sync_complete.load(Ordering::SeqCst) {
            initial_sync_complete.store(true, Ordering::SeqCst);
            log::info!("Initial Nostr discovery sync complete (triggered by {relay_url})");
        }
    }
}

/// Runs a long-lived Nostr session for a single relay.
/// Reconnects automatically until shutdown is requested.
fn run_nostr_session_for_relay(
    relay_url: &str,
    kind: Kind,
    registry: &Arc<FileRegistry>,
    shutdown: Arc<AtomicBool>,
    event_tx: crossbeam_channel::Sender<(Arc<str>, RelayMessage<'static>)>,
    tcp_slot: &Mutex<Option<TcpStream>>,
    nostr_tor_config: (u16, &str),
) {
    let relay_url_arc: Arc<str> = Arc::from(relay_url);
    log::info!("Starting Nostr session | relay={relay_url}");

    while !shutdown.load(Ordering::SeqCst) {
        let result = connect_and_run_once(
            &relay_url_arc,
            kind,
            registry,
            shutdown.clone(),
            &event_tx,
            tcp_slot,
            nostr_tor_config,
        );
        // A finished connection's clone would otherwise keep its socket open.
        if let Ok(mut tcp) = lock_debug!(tcp_slot.lock()) {
            tcp.take();
        }
        match result {
            Ok(()) => {
                // Likely exited due to shutdown
                break;
            }
            Err(e) => {
                log::warn!(
                    "Nostr session error | relay={relay_url} | error={e:?} | retry_in_secs=5"
                );
                for _ in 0..5 {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        }
    }

    log::info!("Stopped Nostr session | relay={relay_url}");
}

/// Establishes websocket connection to single Nostr relay and streams events into the shared channel.
fn connect_and_run_once(
    relay_url: &Arc<str>,
    kind: Kind,
    registry: &Arc<FileRegistry>,
    shutdown: Arc<AtomicBool>,
    event_tx: &crossbeam_channel::Sender<(Arc<str>, RelayMessage<'static>)>,
    tcp_slot: &Mutex<Option<TcpStream>>,
    nostr_tor_config: (u16, &str),
) -> Result<(), WatcherError> {
    let mut socket = connect_nostr_websocket(relay_url, nostr_tor_config.0, nostr_tor_config.1)?;

    let since = registry.load_nostr_cursor(relay_url)?.map(Timestamp::from);

    let mut filter = Filter::new().kind(kind);
    if let Some(since) = since {
        filter = filter.since(since);
    }

    let req = ClientMessage::Req {
        subscription_id: Cow::Owned(SubscriptionId::new(format!(
            "market-discovery-{}",
            relay_url
        ))),
        filters: vec![Cow::Owned(filter)],
    };

    socket.write(Message::Text(req.as_json().into()))?;

    socket.flush()?;

    log::info!(
        "Subscribed to fidelity announcements | relay={} | kind={} | since={:?} | request={}",
        relay_url,
        kind,
        since,
        req.as_json()
    );

    read_event_loop(socket, shutdown, relay_url.clone(), event_tx, tcp_slot)
}

/// Stream all the events from the Nostr relay and send decoded messages into the channel until shutdown.
fn read_event_loop(
    mut socket: tungstenite::WebSocket<MaybeTlsStream<TcpStream>>,
    shutdown: Arc<AtomicBool>,
    relay_url: Arc<str>,
    event_tx: &crossbeam_channel::Sender<(Arc<str>, RelayMessage<'static>)>,
    tcp_slot: &Mutex<Option<TcpStream>>,
) -> Result<(), WatcherError> {
    // Stored before the shutdown check below, so a shutdown racing this
    // connect either closes the clone or is seen by the loop.
    if let MaybeTlsStream::Plain(tcp) | MaybeTlsStream::Rustls(StreamOwned { sock: tcp, .. }) =
        socket.get_ref()
    {
        *lock_debug!(tcp_slot.lock())? = Some(tcp.try_clone()?);
    }
    while !shutdown.load(Ordering::SeqCst) {
        let msg = match socket.read() {
            Ok(msg) => msg,
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            // Shutdown closes the socket under us, so a read error then is a clean stop.
            Err(_) if shutdown.load(Ordering::SeqCst) => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        // Relays are untrusted; a corrupt frame is skipped, not fatal.
        let Some(relay_msg) = decode_relay_frame(msg, &relay_url) else {
            continue;
        };

        let mut to_send = (relay_url.clone(), relay_msg);
        while !shutdown.load(Ordering::SeqCst) {
            match event_tx.send_timeout(to_send, std::time::Duration::from_millis(100)) {
                Ok(()) => break,
                Err(crossbeam_channel::SendTimeoutError::Timeout(item)) => {
                    to_send = item;
                }
                Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

/// Decodes one websocket frame into a relay message. `None` means the frame
/// is unusable (non-text, bad UTF-8, bad JSON) and the session skips it.
fn decode_relay_frame(msg: Message, relay_url: &str) -> Option<RelayMessage<'static>> {
    let text = match msg {
        Message::Text(t) => t,
        Message::Binary(b) => match String::from_utf8(b.to_vec()) {
            Ok(t) => t.into(),
            Err(e) => {
                log::warn!("Ignoring non-UTF8 relay frame | relay={relay_url} | error={e}");
                return None;
            }
        },
        _ => return None,
    };

    log::debug!(
        "Nostr relay message received | relay={} | bytes={} | payload={}",
        relay_url,
        text.len(),
        text
    );

    match RelayMessage::from_json(&text) {
        Ok(msg) => Some(msg),
        Err(e) => {
            log::warn!("Ignoring malformed relay frame | relay={relay_url} | error={e}");
            None
        }
    }
}

/// Cursor an event may advance the relay to, or `None` if it is dated past the
/// skew we allow. The staleness check reads a far-future date as fresh, so
/// without this a single poisoned timestamp blinds the relay forever.
fn cursor_for(created_at: u64, now: u64) -> Option<u64> {
    (created_at <= now.saturating_add(MAX_FUTURE_SKEW_SECS)).then_some(created_at.min(now))
}

/// Processes a single relay message. Returns `Ok(true)` when EOSE is received.
fn handle_relay_message(
    registry: Arc<FileRegistry>,
    msg: RelayMessage,
    blockchain: &AnyBlockchain,
    relay_url: &str,
    kind: Kind,
    seen_txid: &mut SeenTxids,
) -> Result<bool, WatcherError> {
    match msg {
        RelayMessage::Event { event, .. } => {
            if event.kind != kind {
                return Ok(false);
            }

            if event.is_expired() || event.tags.expiration().is_none() {
                log::debug!(
                    "Ignoring expired Nostr event | relay={} | event_id={} | created_at={} | has_expiration={}",
                    relay_url,
                    event.id,
                    event.created_at,
                    event.tags.expiration().is_some()
                );
                return Ok(false);
            }

            let now = Timestamp::now().as_secs();

            let Some(cursor) = cursor_for(event.created_at.as_secs(), now) else {
                log::warn!(
                    "Rejecting future-dated Nostr event | relay={} | event_id={} | created_at={}",
                    relay_url,
                    event.id,
                    event.created_at
                );
                return Ok(false);
            };

            if now.saturating_sub(event.created_at.as_secs()) > EXPIRATION_SECS {
                log::debug!(
                    "Skipping stale Nostr event | relay={} | event_id={} | created_at={} | max_age_hours={}",
                    relay_url,
                    event.id,
                    event.created_at,
                    EXPIRATION_SECS / 3600
                );
                return Ok(false);
            }

            // Decoding a raw relay message does not verify its event ID or signature.
            if let Err(e) = event.verify() {
                log::warn!(
                    "Rejecting invalid Nostr event | relay={} | event_id={} | error={e}",
                    relay_url,
                    event.id
                );
                return Ok(false);
            }

            let Some((txid, vout)) = parse_fidelity_event(&event) else {
                log::debug!(
                    "Ignoring unparsable fidelity event | relay={} | event_id={} | content={}",
                    relay_url,
                    event.id,
                    event.content
                );
                return Ok(false);
            };

            log::debug!(
                "Parsed fidelity event | relay={} | event_id={} | txid={} | vout={} | created_at={}",
                relay_url,
                event.id,
                txid,
                vout,
                event.created_at
            );

            // Claim the txid before any RPC work, so duplicate events across
            // relays don't repeat the fetch and validation.
            if !seen_txid.claim(txid) {
                log::info!("Skipping already-seen txid {txid} via {relay_url}");
                registry.save_nostr_cursor(relay_url, cursor)?;
                return Ok(false);
            }

            let tx = match blockchain.get_raw_transaction(&txid, None) {
                Ok(tx) => tx,
                Err(e) => {
                    log::warn!("Failed to fetch raw tx {txid:?} via {relay_url}: {e}");
                    // A transient fetch failure leaves the txid eligible for retry.
                    seen_txid.release(&txid);
                    return Ok(false);
                }
            };
            let confirmation_height = match blockchain.tx_block_height(&txid) {
                Ok(Some(height)) => height,
                Ok(None) => {
                    log::debug!("Ignoring unconfirmed fidelity transaction {txid} via {relay_url}");
                    seen_txid.release(&txid);
                    return Ok(false);
                }
                Err(e) => {
                    log::warn!(
                        "Failed to fetch confirmation height for {txid} via {relay_url}: {e}"
                    );
                    seen_txid.release(&txid);
                    return Ok(false);
                }
            };

            match blockchain.get_tx_out(&txid, vout, Some(true)) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    log::debug!("Ignoring spent fidelity output {txid}:{vout} via {relay_url}");
                    seen_txid.insert(txid);
                    registry.save_nostr_cursor(relay_url, cursor)?;
                    return Ok(false);
                }
                Err(e) => {
                    log::warn!(
                        "Failed to fetch fidelity output {txid}:{vout} via {relay_url}: {e}"
                    );
                    seen_txid.release(&txid);
                    return Ok(false);
                }
            }

            // Once chain state is known, remember even structurally invalid transactions so a
            // relay replay cannot force validation work repeatedly.
            seen_txid.insert(txid);
            log::info!("Added txid to Nostr discovery cache: {txid}");

            match process_fidelity(&tx, confirmation_height) {
                Some(fidelity) => {
                    let maker_address = fidelity.onion.clone();
                    let expires_at_height = fidelity.expires_at_height;
                    if registry.insert_fidelity(txid, fidelity)? {
                        log::info!(
                                "Stored validated fidelity candidate | relay={} | event_id={} | txid={} | vout={} | maker_address={} | expires_at_height={}",
                                relay_url,
                                event.id,
                                txid,
                                vout,
                                maker_address,
                                expires_at_height
                            );
                    }
                }
                None => {
                    log::warn!(
                        "Invalid fidelity transaction | relay={} | event_id={} | txid={} | vout={}",
                        relay_url,
                        event.id,
                        txid,
                        vout
                    );
                }
            }
            registry.save_nostr_cursor(relay_url, cursor)?;
        }

        RelayMessage::EndOfStoredEvents(sub_id) => {
            let expected_sub_id = format!("market-discovery-{}", relay_url);
            if sub_id.as_str() == expected_sub_id {
                log::info!("EOSE received for subscription {sub_id} via {relay_url}");
                return Ok(true);
            } else {
                log::debug!("Ignoring EOSE for unrelated subscription {sub_id} via {relay_url}");
                return Ok(false);
            }
        }

        _ => {}
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{BackendConfig, CoreRpcConfig};
    use bitcoin::{hashes::Hash, Txid};
    use nostr::{
        event::{EventBuilder, Tag, TagStandard},
        key::Keys,
    };
    use std::{net::TcpListener, str::FromStr, time::Duration};

    #[test]
    fn future_dated_event_never_moves_the_cursor() {
        let now = 1_700_000_000u64;

        // A year ahead: rejected outright, so nothing is saved.
        assert_eq!(cursor_for(now + 365 * 24 * 3600, now), None);
        assert_eq!(cursor_for(now + MAX_FUTURE_SKEW_SECS + 1, now), None);

        // Inside the skew margin the event is kept, but the cursor stays at now.
        assert_eq!(cursor_for(now + MAX_FUTURE_SKEW_SECS, now), Some(now));
        assert_eq!(cursor_for(now, now), Some(now));
        assert_eq!(cursor_for(now - 60, now), Some(now - 60));
    }

    #[test]
    fn garbage_frame_is_skipped_not_fatal() {
        let relay = "wss://relay.example";

        assert!(decode_relay_frame(Message::Text("not json".into()), relay).is_none());
        assert!(decode_relay_frame(Message::Text(r#"["NOPE"]"#.into()), relay).is_none());
        assert!(decode_relay_frame(Message::Binary(vec![0xff, 0xfe].into()), relay).is_none());

        // A well-formed frame still decodes, so the skip is not swallowing everything.
        assert!(decode_relay_frame(Message::Text(r#"["EOSE","sub1"]"#.into()), relay).is_some());
    }

    #[test]
    fn tampered_event_is_rejected_before_claiming_txid() {
        let kind = Kind::Custom(37_780);
        let txid = Txid::from_slice(&[1; 32]).unwrap();
        let keys = Keys::generate();
        let mut event = EventBuilder::new(kind, format!("{txid}:0"))
            .tag(Tag::from_standardized(TagStandard::Expiration(
                Timestamp::from_secs(Timestamp::now().as_secs() + 60),
            )))
            .build(keys.public_key)
            .sign_with_keys(&keys)
            .unwrap();
        event.content = format!("{txid}:1");
        assert!(event.verify().is_err());

        let message = RelayMessage::Event {
            subscription_id: Cow::Owned(SubscriptionId::new("test")),
            event: Cow::Owned(event),
        };
        let registry = Arc::new(FileRegistry::new());
        let blockchain =
            AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default())).unwrap();
        let mut seen_txid = SeenTxids::new();

        assert!(!handle_relay_message(
            registry.clone(),
            message,
            &blockchain,
            "wss://relay.example",
            kind,
            &mut seen_txid,
        )
        .unwrap());
        assert!(registry.list_fidelity(0).unwrap().is_empty());
        assert!(seen_txid.claim(txid));
    }

    #[test]
    fn duplicate_event_across_relays_skips_blockchain_and_advances_cursor() {
        let keys = Keys::generate();
        let kind = Kind::Custom(37778);
        let now = Timestamp::now().as_secs();
        let txid_str = "0000000000000000000000000000000000000000000000000000000000000001";
        let content = format!("{}:0", txid_str);

        let event = EventBuilder::new(kind, content)
            .tag(Tag::identifier("test-d-tag"))
            .tag(Tag::from_standardized(TagStandard::Expiration(
                Timestamp::from_secs(now + 86400),
            )))
            .build(keys.public_key)
            .sign_with_keys(&keys)
            .unwrap();

        let registry = Arc::new(FileRegistry::new());
        let mut seen_txid = SeenTxids::new();
        let txid = bitcoin::Txid::from_str(txid_str).unwrap();

        // Mark txid as already seen by a previous relay
        seen_txid.insert(txid);

        let dummy_blockchain =
            AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default())).unwrap();

        let relay_url = "wss://relay2.example";
        let relay_msg = RelayMessage::Event {
            subscription_id: Cow::Owned(SubscriptionId::new("sub")),
            event: Cow::Owned(event),
        };

        // When relay 2 processes the duplicate, it should return Ok(false) and save cursor without querying the node
        let result = handle_relay_message(
            registry.clone(),
            relay_msg,
            &dummy_blockchain,
            relay_url,
            kind,
            &mut seen_txid,
        )
        .unwrap();

        assert!(!result);
        assert!(registry.load_nostr_cursor(relay_url).unwrap().is_some());
    }

    #[test]
    fn eose_message_returns_true() {
        let registry = Arc::new(FileRegistry::new());
        let mut seen_txid = SeenTxids::new();
        let dummy_blockchain =
            AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default())).unwrap();

        let relay_url = "wss://relay.example";

        // Unrelated subscription returns false
        let unrelated_msg =
            RelayMessage::EndOfStoredEvents(Cow::Owned(SubscriptionId::new("unrelated-sub")));
        let is_eose_unrelated = handle_relay_message(
            registry.clone(),
            unrelated_msg,
            &dummy_blockchain,
            relay_url,
            Kind::Custom(37778),
            &mut seen_txid,
        )
        .unwrap();
        assert!(!is_eose_unrelated);

        // Matching discovery subscription returns true
        let matching_sub = format!("market-discovery-{}", relay_url);
        let matching_msg =
            RelayMessage::EndOfStoredEvents(Cow::Owned(SubscriptionId::new(matching_sub)));
        let is_eose_matching = handle_relay_message(
            registry,
            matching_msg,
            &dummy_blockchain,
            relay_url,
            Kind::Custom(37778),
            &mut seen_txid,
        )
        .unwrap();
        assert!(is_eose_matching);
    }

    #[test]
    fn closing_the_relay_socket_stops_a_parked_read() {
        // A silent relay, and a client with no read timeout: only the close can wake it.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let relay =
            std::thread::spawn(move || tungstenite::accept(listener.accept().unwrap().0).unwrap());
        let (socket, _) = tungstenite::connect(url).unwrap();
        let _relay = relay.join().unwrap();

        let shutdown = Arc::new(AtomicBool::new(false));
        let tcp_slot = Arc::new(Mutex::new(None));
        let (event_tx, _event_rx) = crossbeam_channel::bounded(1);
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let (session_shutdown, session_slot) = (shutdown.clone(), tcp_slot.clone());
        std::thread::spawn(move || {
            let result = read_event_loop(
                socket,
                session_shutdown,
                Arc::from("ws://relay.example"),
                &event_tx,
                &session_slot,
            );
            done_tx.send(result.is_ok()).unwrap();
        });

        let stored = (0..500).any(|_| {
            std::thread::sleep(Duration::from_millis(10));
            tcp_slot.lock().unwrap().is_some()
        });
        assert!(stored, "session never stored its socket");
        // Let the session park in `read()`.
        std::thread::sleep(Duration::from_millis(100));
        shutdown.store(true, Ordering::SeqCst);
        let tcp = tcp_slot.lock().unwrap().take().unwrap();
        tcp.shutdown(Shutdown::Both).unwrap();

        assert!(done_rx.recv_timeout(Duration::from_secs(5)).unwrap());
    }

    #[cfg(feature = "integration-test")]
    #[test]
    fn shutdown_stops_discovery_without_waiting_for_a_silent_relay() {
        // The relay takes the subscription, then stays silent until we close.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_url = format!("ws://{}", listener.local_addr().unwrap());
        let (subscribed_tx, subscribed_rx) = crossbeam_channel::bounded(1);
        std::thread::spawn(move || {
            let mut relay = tungstenite::accept(listener.accept().unwrap().0).unwrap();
            relay.read().unwrap();
            subscribed_tx.send(()).unwrap();
            let _ = relay.read();
        });

        let shutdown = Arc::new(AtomicBool::new(false));
        let discovery_shutdown = shutdown.clone();
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        std::thread::spawn(move || {
            let blockchain =
                AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default()))
                    .unwrap();
            let result = run_discovery(
                blockchain,
                Network::Regtest,
                FileRegistry::new(),
                discovery_shutdown,
                Arc::new(AtomicBool::new(false)),
                &[relay_url],
                (0, String::new()),
            );
            done_tx.send(result.is_ok()).unwrap();
        });

        subscribed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // Let the session park in `read()`.
        std::thread::sleep(Duration::from_millis(100));
        shutdown.store(true, Ordering::SeqCst);
        // Well under the 30 s read timeout a silent relay would otherwise cost.
        assert!(done_rx.recv_timeout(Duration::from_secs(5)).unwrap());
    }

    #[test]
    fn worker_handles_eose_and_exits_on_disconnect() {
        let (event_tx, event_rx) = crossbeam_channel::bounded::<(Arc<str>, RelayMessage<'static>)>(
            DISCOVERY_EVENT_BUFFER_SIZE,
        );
        let dummy_blockchain =
            AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default())).unwrap();
        let registry = Arc::new(FileRegistry::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let initial_sync_complete = Arc::new(AtomicBool::new(false));
        let kind = Kind::Custom(37778);

        let worker_shutdown = shutdown.clone();
        let worker_registry = registry.clone();
        let worker_initial_sync = initial_sync_complete.clone();

        let handle = std::thread::spawn(move || {
            run_discovery_event_processor(
                event_rx,
                dummy_blockchain,
                worker_registry,
                kind,
                worker_shutdown,
                worker_initial_sync,
            );
        });

        assert!(!initial_sync_complete.load(Ordering::SeqCst));

        // Send an unrelated EOSE message through the channel — flag should NOT flip
        let relay_url: Arc<str> = Arc::from("wss://relay.example");
        let unrelated_eose =
            RelayMessage::EndOfStoredEvents(Cow::Owned(SubscriptionId::new("sub1")));
        event_tx.send((relay_url.clone(), unrelated_eose)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!initial_sync_complete.load(Ordering::SeqCst));

        // Send matching discovery EOSE message through the channel
        let expected_sub = format!("market-discovery-{}", relay_url);
        let eose_msg =
            RelayMessage::EndOfStoredEvents(Cow::Owned(SubscriptionId::new(expected_sub)));
        event_tx.send((relay_url, eose_msg)).unwrap();

        // Wait for worker to process EOSE and flip the flag
        let mut flipped = false;
        for _ in 0..40 {
            if initial_sync_complete.load(Ordering::SeqCst) {
                flipped = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(
            flipped,
            "Worker should have marked initial_sync_complete on EOSE"
        );

        // Drop sender and ensure worker exits cleanly
        drop(event_tx);
        assert!(handle.join().is_ok());
    }
}
