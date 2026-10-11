//! Nostr integration for Maker announcements and coordination.
//!
//! This module provides a minimal interface for publishing Maker-related
//! events over the Nostr protocol. It is primarily used to broadcast
//! fidelity bond information and other coordination signals required
//! by the OpenSwap protocol.

#[cfg(not(feature = "integration-test"))]
use std::io;
use std::{
    net::TcpStream,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bitcoin::Network;
use nostr::{
    event::{EventBuilder, Kind, Tag, TagStandard},
    key::{Keys, SecretKey},
    message::{ClientMessage, RelayMessage},
    types::Timestamp,
    util::JsonUtil,
};
#[cfg(not(feature = "integration-test"))]
use tungstenite::http::Uri;
use tungstenite::{stream::MaybeTlsStream, Message, WebSocket};

#[cfg(not(feature = "integration-test"))]
use crate::utill::socks5_connect;
use crate::{
    maker::{MakerError, MakerServerConfig},
    protocol::common_messages::FidelityProof,
};

/// Tor circuits to a relay can take minutes to build on a slow network; a
/// shorter bound would fail real connects, not just wedged ones.
#[cfg(not(feature = "integration-test"))]
const NOSTR_SOCKS_TIMEOUT: Duration = Duration::from_secs(300);

/// nostr url for openswap
#[cfg(not(feature = "integration-test"))]
pub const NOSTR_RELAYS: &[&str] = &["wss://nos.lol", "wss://relay.damus.io"];
/// nostr url for openswap
#[cfg(feature = "integration-test")]
pub const NOSTR_RELAYS: &[&str] = &["ws://127.0.0.1:8000"];

/// Returns the OpenSwap Nostr event kind for the given Bitcoin network.
/// v0.2.3 used 37778-37782; new kinds keep it from finding makers it can't talk to.
/// Frozen: content only grows by fields after `txid:vout`.
pub fn swap_kind(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 37790,
        Network::Signet => 37791,
        Network::Regtest => 37792,
        Network::Testnet => 37793,
        Network::Testnet4 => 37794,
    }
}

/// Expiration time for noster event (24 hours)
pub(crate) const EXPIRATION_SECS: u64 = 86400;

pub(crate) fn connect_nostr_websocket(
    relay_url: &str,
    socks_port: u16,
    tor_auth_password: &str,
) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, tungstenite::Error> {
    #[cfg(feature = "integration-test")]
    {
        let _ = (socks_port, tor_auth_password);
        let (mut ws, _) = tungstenite::connect(relay_url)?;
        // Match the prod read timeout so a silent relay can't hang shutdown joins.
        if let MaybeTlsStream::Plain(tcp) = ws.get_mut() {
            tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
        }
        Ok(ws)
    }

    #[cfg(not(feature = "integration-test"))]
    {
        let invalid_relay = || io::Error::new(io::ErrorKind::InvalidInput, "invalid relay url");
        let uri: Uri = relay_url.parse().map_err(|_| invalid_relay())?;
        let scheme = uri.scheme_str().ok_or_else(invalid_relay)?;
        if scheme != "ws" && scheme != "wss" {
            return Err(invalid_relay().into());
        }
        let authority = uri.authority().ok_or_else(invalid_relay)?;
        let host = authority.host();
        let port = authority
            .port_u16()
            .unwrap_or(if scheme == "wss" { 443 } else { 80 });

        let tcp = if tor_auth_password.is_empty() {
            socks5_connect(socks_port, host, port, None, NOSTR_SOCKS_TIMEOUT)
        } else {
            socks5_connect(
                socks_port,
                host,
                port,
                Some((host, tor_auth_password)),
                NOSTR_SOCKS_TIMEOUT,
            )
        }?;

        tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(30)))?;
        match tungstenite::client_tls_with_config(relay_url, tcp, None, None) {
            Ok((ws, _)) => Ok(ws),
            Err(tungstenite::HandshakeError::Failure(e)) => Err(e),
            Err(tungstenite::HandshakeError::Interrupted(_)) => {
                Err(io::Error::other("tls handshake interrupted").into())
            }
        }
    }
}

/// Broadcasts a fidelity bond announcement over Nostr.
pub fn broadcast_bond_on_nostr(
    fidelity: FidelityProof,
    relays: &[String],
    config: &MakerServerConfig,
    shutdown: &std::sync::atomic::AtomicBool,
) -> Result<(), MakerError> {
    if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(());
    }
    let outpoint = fidelity.bond.outpoint;
    let content = format!("{}:{}", outpoint.txid, outpoint.vout);
    let kind = swap_kind(config.network);
    // OpenSwap kinds are in the NIP-33 parameterized-replaceable range (30000..39999),
    // so included a stable `d` tag to keep relay handling spec-compliant.
    let d_tag = format!("fidelity:{}", content);

    let secret_key = SecretKey::generate();
    let keys = Keys::new(secret_key);

    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| {
            log::warn!("failed to create expiration time : {}", e);
            MakerError::General("failed to create expiration time")
        })?
        .as_secs()
        + EXPIRATION_SECS;

    log::debug!(
        "Publishing fidelity bond to Nostr | outpoint={} amount_sats={} lock_time={} conf_height={:?} is_spent={} pubkey={} cert_hash={} cert_sig={:?} content={} d_tag={} expiration_unix={}",
        fidelity.bond.outpoint,
        fidelity.bond.amount.to_sat(),
        fidelity.bond.lock_time.to_consensus_u32(),
        fidelity.bond.conf_height,
        fidelity.bond.is_spent,
        fidelity.bond.pubkey,
        fidelity.cert_hash,
        fidelity.cert_sig,
        content,
        d_tag,
        expiration
    );

    let event = EventBuilder::new(Kind::Custom(kind), content)
        .tag(Tag::identifier(d_tag))
        .tag(Tag::from_standardized(TagStandard::Expiration(
            Timestamp::from_secs(expiration),
        )))
        .build(keys.public_key)
        .sign_with_keys(&keys)
        .map_err(|_| MakerError::General("failed to sign nostr event"))?;

    log::debug!(
        "Nostr event built | event_id={} pubkey={} kind={} created_at={} tags={:?}",
        event.id,
        event.pubkey,
        kind,
        event.created_at,
        event.tags
    );

    let msg = ClientMessage::Event(std::borrow::Cow::Owned(event));

    log::debug!("Nostr wire message built | payload={}", msg.as_json());

    const RELAY_DELAY: Duration = Duration::from_secs(2);
    const MAX_RETRIES: usize = 3;

    let mut success = false;

    for relay in relays {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        for attempt in 1..=MAX_RETRIES {
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(());
            }
            log::info!(
                "Publishing Nostr event | relay={} | attempt={}/{} | payload={}",
                relay,
                attempt,
                MAX_RETRIES,
                msg.as_json()
            );
            match broadcast_to_relay(relay, &msg, config.socks_port, &config.tor_auth_password) {
                Ok(()) => {
                    success = true;
                    break;
                }
                Err(e) => {
                    log::warn!(
                        "Nostr event publish failed | relay={} | attempt={}/{} | error={:?}",
                        relay,
                        attempt,
                        MAX_RETRIES,
                        e
                    );
                    if attempt < MAX_RETRIES {
                        let mut remaining = RELAY_DELAY;
                        while !remaining.is_zero() {
                            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                                return Ok(());
                            }
                            let slice = remaining.min(Duration::from_secs(1));
                            std::thread::sleep(slice);
                            remaining -= slice;
                        }
                    }
                }
            }
        }
    }

    if !success {
        log::warn!("nostr event was not accepted by any relay");
    }

    Ok(())
}

/// Sends a Nostr event to a single relay and waits for confirmation.
fn broadcast_to_relay(
    relay: &str,
    msg: &ClientMessage,
    socks_port: u16,
    tor_auth_password: &str,
) -> Result<(), MakerError> {
    let mut socket =
        connect_nostr_websocket(relay, socks_port, tor_auth_password).map_err(|e| {
            log::warn!("Nostr relay connect failed | relay={} | error={}", relay, e);
            MakerError::General("failed to connect to nostr relay")
        })?;

    socket
        .write(Message::Text(msg.as_json().into()))
        .map_err(|e| {
            log::warn!("Nostr relay write failed | relay={} | error={}", relay, e);
            MakerError::General("failed to write to nostr relay")
        })?;
    socket.flush().ok();

    match socket.read() {
        Ok(Message::Text(text)) => {
            if let Ok(relay_msg) = RelayMessage::from_json(&text) {
                match relay_msg {
                    RelayMessage::Ok {
                        event_id,
                        status: true,
                        ..
                    } => {
                        log::info!(
                            "Nostr relay accepted event | relay={} | event_id={}",
                            relay,
                            event_id
                        );
                        return Ok(());
                    }
                    RelayMessage::Ok {
                        event_id,
                        status: false,
                        message,
                    } => {
                        log::warn!(
                            "Nostr relay rejected event | relay={} | event_id={} | message={}",
                            relay,
                            event_id,
                            message
                        );
                    }
                    _ => {}
                }
            }
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("Nostr relay read failed | relay={} | error={}", relay, e);
        }
    }
    log::warn!("Nostr relay did not confirm event | relay={}", relay);
    Err(MakerError::General("nostr relay did not confirm event"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_nostr_kinds_are_frozen_and_separate_from_v023() {
        for (network, kind) in [
            (Network::Bitcoin, 37790),
            (Network::Signet, 37791),
            (Network::Regtest, 37792),
            (Network::Testnet, 37793),
            (Network::Testnet4, 37794),
        ] {
            assert_eq!(swap_kind(network), kind);
            assert!(!(37778..=37782).contains(&kind));
        }
    }
}
