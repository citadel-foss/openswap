//! BIP324 transport layer for OpenSwap's peer-to-peer communication.
//!
//! This module wraps the [`bip324`] crate's `Protocol` into a
//! `Bip324Stream` that CBOR-(de)serializes the application's messages on top
//! of the encrypted BIP324 transport.
//!
//! Both the Taker (as BIP324 *initiator*) and the Maker (as BIP324 *responder*)
//! speak through this module.

use std::{io::BufReader, net::TcpStream};

use bip324::io::{Payload, Protocol};
use bitcoin::{
    secp256k1::{ecdsa::Signature, Message, Secp256k1},
    Network, PublicKey,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::error::NetError;

/// Errors specific to the BIP324 transport and its authentication handshake.
#[derive(Debug)]
pub enum Bip324Error {
    /// The peer aborted the BIP324 protocol (e.g. unexpected packet or stream error).
    ProtocolError(bip324::io::ProtocolError),
    /// The peer's session ID did not match ours, indicating a man-in-the-middle attack.
    SessionIdMismatch,
    /// The maker's `session_id_sig` did not verify against its tweakable key.
    SessionIdSigInvalid(bitcoin::secp256k1::Error),
    /// The peer cleanly disconnected (EOF / connection closed).
    ConnectionClosed,
}

impl From<bip324::io::ProtocolError> for Bip324Error {
    fn from(value: bip324::io::ProtocolError) -> Self {
        match value {
            // `RetryV1` is the BIP324 crate's way of reporting that the remote
            // closed the stream cleanly, so map it to a dedicated variant.
            bip324::io::ProtocolError::Io(_, bip324::io::ProtocolFailureSuggestion::RetryV1) => {
                Self::ConnectionClosed
            }
            _ => Self::ProtocolError(value),
        }
    }
}

/// Role of the local peer on a `Bip324Stream`.
#[derive(Debug)]
pub(crate) enum OpenswapRole {
    /// We are the maker (BIP324 responder); no authentication is needed.
    Maker,
    /// We are the taker (BIP324 initiator).
    Taker {
        /// Whether the maker's `session_id_sig` was verified against its
        /// tweakable key (see `Bip324Stream::authenticate`).
        is_authenticated: bool,
    },
}

/// An encrypted, authenticated transport channel to a peer.
///
/// Wraps the BIP324 `Protocol` over a `TcpStream` and adds CBOR (de)serialization on top of genuine payloads.
pub(crate) struct Bip324Stream {
    /// The underlying BIP324 protocol stream.
    pub stream: Protocol<BufReader<TcpStream>, TcpStream>,
    /// Local role on this connection (maker vs taker).
    pub role: OpenswapRole,
}

impl std::fmt::Debug for Bip324Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bip324Stream").finish_non_exhaustive()
    }
}

impl Bip324Stream {
    /// Wrap a connected TCP stream in a fresh BIP324 transport.
    pub fn new(
        stream: TcpStream,
        network: Network,
        bip324_role: bip324::Role,
    ) -> Result<Self, NetError> {
        let reader = BufReader::new(stream.try_clone()?);
        let writer = stream;
        let stream = Protocol::new(
            network.magic(),
            bip324_role,
            None,
            None, // no garbage or decoys
            reader,
            writer,
        )?;

        Ok(Self {
            stream,
            role: match bip324_role {
                bip324::Role::Initiator => OpenswapRole::Taker {
                    is_authenticated: false,
                },
                bip324::Role::Responder => OpenswapRole::Maker,
            },
        })
    }

    /// Read the next genuine application message, deserializing it as `T`.
    pub(crate) fn read_message<T: DeserializeOwned>(&mut self) -> Result<T, NetError> {
        loop {
            let payload = self.stream.read()?;
            match payload.packet_type() {
                // Currently we never send decoys, but tolerate them defensively.
                bip324::PacketType::Decoy => {}
                bip324::PacketType::Genuine => {
                    return Ok(serde_cbor::from_slice(payload.contents())?);
                }
            }
        }
    }

    /// Serialize a message to CBOR and send it as a genuine BIP324 payload.
    pub(crate) fn send_message(&mut self, message: &impl Serialize) -> Result<(), NetError> {
        let msg_bytes = serde_cbor::ser::to_vec(message)?;
        let to_send = Payload::genuine(msg_bytes);

        self.stream.write(&to_send)?;

        Ok(())
    }

    /// Bind the BIP324 session to the maker's identity and mark the channel authenticated.
    pub(crate) fn authenticate(
        &mut self,
        tweakable_point: &PublicKey,
        session_id_sig: &Signature,
    ) -> Result<(), NetError> {
        let session_id = *self.stream.session_id().as_bytes();
        let secp = Secp256k1::new();
        let sighash = Message::from_digest(session_id);
        secp.verify_ecdsa(&sighash, session_id_sig, &tweakable_point.inner)
            .map_err(|e| NetError::Bip324Error(Bip324Error::SessionIdSigInvalid(e)))?;
        if let OpenswapRole::Taker { is_authenticated } = &mut self.role {
            *is_authenticated = true;
        }
        Ok(())
    }
}
