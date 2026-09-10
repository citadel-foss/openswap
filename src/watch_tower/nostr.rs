//! Nostr discovery module.
//!
//! Handles the discovery of Maker fidelity bonds via Nostr relays. It creates persistent
//! subscriptions to network-specific OpenSwap events, validates incoming fidelity
//! announcements against the Bitcoin blockchain, and stores validated candidates in the registry.

use std::{
    borrow::Cow,
    net::TcpStream,
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

// ## TODO: Instead of looping over relay's have a connection Pool.
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

    let seen_txid = Arc::new(Mutex::new(SeenTxids::new()));
    let registry = Arc::new(registry);

    let connections = relays
        .iter()
        .map(|_| blockchain.new_connection_with_shutdown(shutdown.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut sessions = Vec::with_capacity(relays.len());
    for (relay, blockchain) in relays.iter().zip(connections) {
        let relay = relay.to_string();
        let session_shutdown = shutdown.clone();
        let registry = Arc::clone(&registry);
        let blockchain = Arc::new(blockchain);
        let seen_txid = Arc::clone(&seen_txid);
        let initial_sync_complete = initial_sync_complete.clone();
        let nostr_tor_config = nostr_tor_config.clone();

        let handle = match std::thread::Builder::new()
            .name(format!("nostr-session-{}", relay))
            .spawn(move || {
                run_nostr_session_for_relay(
                    &relay,
                    kind,
                    registry,
                    session_shutdown,
                    blockchain,
                    &seen_txid,
                    &initial_sync_complete,
                    (nostr_tor_config.0, nostr_tor_config.1.as_str()),
                );
            }) {
            Ok(handle) => handle,
            Err(e) => {
                shutdown.store(true, Ordering::SeqCst);
                join_relay_sessions(sessions);
                return Err(e.into());
            }
        };
        sessions.push(handle);
    }

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

/// Runs a long-lived Nostr session for a single relay.
/// Reconnects automatically until shutdown is requested.
#[allow(clippy::too_many_arguments)]
fn run_nostr_session_for_relay(
    relay_url: &str,
    kind: Kind,
    registry: Arc<FileRegistry>,
    shutdown: Arc<AtomicBool>,
    blockchain: Arc<AnyBlockchain>,
    seen_txid: &Arc<Mutex<SeenTxids>>,
    initial_sync_complete: &Arc<AtomicBool>,
    nostr_tor_config: (u16, &str),
) {
    log::info!("Starting Nostr session | relay={relay_url}");

    while !shutdown.load(Ordering::SeqCst) {
        match connect_and_run_once(
            relay_url,
            kind,
            registry.clone(),
            shutdown.clone(),
            blockchain.clone(),
            seen_txid,
            initial_sync_complete,
            nostr_tor_config,
        ) {
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

/// Establishes websocket connection to single Nostr relay and processes events until error or shutdown.
#[allow(clippy::too_many_arguments)]
fn connect_and_run_once(
    relay_url: &str,
    kind: Kind,
    registry: Arc<FileRegistry>,
    shutdown: Arc<AtomicBool>,
    blockchain: Arc<AnyBlockchain>,
    seen_txid: &Arc<Mutex<SeenTxids>>,
    initial_sync_complete: &Arc<AtomicBool>,
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

    read_event_loop(
        registry,
        socket,
        shutdown,
        blockchain,
        relay_url,
        kind,
        seen_txid,
        initial_sync_complete,
    )
}

/// Stream all the events from the Nostr relay and deserialize from json until shutdown.
#[allow(clippy::too_many_arguments)]
fn read_event_loop(
    registry: Arc<FileRegistry>,
    mut socket: tungstenite::WebSocket<MaybeTlsStream<TcpStream>>,
    shutdown: Arc<AtomicBool>,
    blockchain: Arc<AnyBlockchain>,
    relay_url: &str,
    kind: Kind,
    seen_txid: &Arc<Mutex<SeenTxids>>,
    initial_sync_complete: &Arc<AtomicBool>,
) -> Result<(), WatcherError> {
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
            Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                if shutdown.load(Ordering::SeqCst) {
                    return Ok(());
                }
                return Err(tungstenite::Error::ConnectionClosed.into());
            }
            Err(e) => return Err(e.into()),
        };

        // Relays are untrusted; a corrupt frame is skipped, not fatal.
        let Some(relay_msg) = decode_relay_frame(msg, relay_url) else {
            continue;
        };

        let is_eose = handle_relay_message(
            registry.clone(),
            relay_msg,
            blockchain.clone(),
            relay_url,
            kind,
            seen_txid,
        )?;

        if is_eose && !initial_sync_complete.load(Ordering::SeqCst) {
            initial_sync_complete.store(true, Ordering::SeqCst);
            log::info!("Initial Nostr discovery sync complete (triggered by {relay_url})");
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
    blockchain: Arc<AnyBlockchain>,
    relay_url: &str,
    kind: Kind,
    seen_txid: &Arc<Mutex<SeenTxids>>,
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

            // Claim the txid before any RPC work, so duplicate events and
            // concurrent relay sessions don't repeat the fetch and validation.
            if !lock_debug!(seen_txid.lock())?.claim(txid) {
                log::info!("Skipping already-seen txid {txid} via {relay_url}");
                registry.save_nostr_cursor(relay_url, cursor)?;
                return Ok(false);
            }

            let tx = match blockchain.get_raw_transaction(&txid, None) {
                Ok(tx) => tx,
                Err(e) => {
                    log::warn!("Failed to fetch raw tx {txid:?} via {relay_url}: {e}");
                    // A transient fetch failure leaves the txid eligible for retry.
                    lock_debug!(seen_txid.lock())?.release(&txid);
                    return Ok(false);
                }
            };
            let confirmation_height = match blockchain.tx_block_height(&txid) {
                Ok(Some(height)) => height,
                Ok(None) => {
                    log::debug!("Ignoring unconfirmed fidelity transaction {txid} via {relay_url}");
                    lock_debug!(seen_txid.lock())?.release(&txid);
                    return Ok(false);
                }
                Err(e) => {
                    log::warn!(
                        "Failed to fetch confirmation height for {txid} via {relay_url}: {e}"
                    );
                    lock_debug!(seen_txid.lock())?.release(&txid);
                    return Ok(false);
                }
            };

            match blockchain.get_tx_out(&txid, vout, Some(true)) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    log::debug!("Ignoring spent fidelity output {txid}:{vout} via {relay_url}");
                    lock_debug!(seen_txid.lock())?.insert(txid);
                    registry.save_nostr_cursor(relay_url, cursor)?;
                    return Ok(false);
                }
                Err(e) => {
                    log::warn!(
                        "Failed to fetch fidelity output {txid}:{vout} via {relay_url}: {e}"
                    );
                    lock_debug!(seen_txid.lock())?.release(&txid);
                    return Ok(false);
                }
            }

            // Once chain state is known, remember even structurally invalid transactions so a
            // relay replay cannot force validation work repeatedly.
            lock_debug!(seen_txid.lock())?.insert(txid);
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
            log::info!("EOSE received for subscription {sub_id} via {relay_url}");
            return Ok(true);
        }

        _ => {}
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
