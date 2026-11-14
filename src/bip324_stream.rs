//! BIP324 transport layer for OpenSwap's peer-to-peer communication.
//!
//! `Bip324Stream` runs the BIP324 handshake over a connected `TcpStream` and
//! then carries one CBOR message per genuine BIP324 packet.
//!
//! Both the Taker (as BIP324 *initiator*) and the Maker (as BIP324 *responder*)
//! speak through this module. The stream does its own packet framing on top of
//! the crate's ciphers so that it can cap packet sizes before allocating and
//! bound how long a peer may take to deliver a packet, the same way the
//! plaintext framing did.

use std::{
    io::{self, BufReader, ErrorKind, Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use bip324::{
    io::ProtocolSessionReader, InboundCipher, OutboundCipher, PacketType, SessionId,
    NUM_HEADER_BYTES, NUM_LENGTH_BYTES,
};
use bitcoin::{
    secp256k1::{ecdsa::Signature, Message, Secp256k1},
    Network, PublicKey,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{error::NetError, utill::MAX_RPC_MESSAGE_SIZE};

/// Maximum time to finish a packet after its first byte arrives.
pub(crate) const MESSAGE_ASSEMBLY_TIMEOUT: Duration = Duration::from_secs(60);

/// Poly1305 tag appended to every BIP324 packet.
const NUM_TAG_BYTES: usize = 16;

/// Largest packet (header + contents + tag) we accept from a peer.
const MAX_PACKET_LEN: usize = MAX_RPC_MESSAGE_SIZE + NUM_HEADER_BYTES + NUM_TAG_BYTES;

/// Errors specific to the BIP324 transport and its authentication handshake.
#[derive(Debug)]
pub enum Bip324Error {
    /// The BIP324 handshake or a packet read/write failed.
    ProtocolError(bip324::io::ProtocolError),
    /// A received packet failed to decrypt or authenticate.
    Cipher(bip324::Error),
    /// The maker's Hello did not carry a `session_id_sig`.
    MissingSessionIdSig,
    /// The maker's `session_id_sig` did not verify against its tweakable key.
    SessionIdSigInvalid(bitcoin::secp256k1::Error),
    /// The peer cleanly disconnected (EOF / connection closed).
    ConnectionClosed,
    /// The peer did not deliver the handshake or a packet before its deadline.
    ReadDeadlineExpired,
}

impl From<bip324::io::ProtocolError> for Bip324Error {
    fn from(value: bip324::io::ProtocolError) -> Self {
        match value {
            bip324::io::ProtocolError::Io(ref e, _) if is_deadline_expired(e) => {
                Self::ReadDeadlineExpired
            }
            // `RetryV1` is the BIP324 crate's way of reporting that the remote
            // closed the stream, so map it to a dedicated variant.
            bip324::io::ProtocolError::Io(_, bip324::io::ProtocolFailureSuggestion::RetryV1) => {
                Self::ConnectionClosed
            }
            _ => Self::ProtocolError(value),
        }
    }
}

/// Marker carried inside the `io::Error` a [`DeadlineReader`] returns once its
/// deadline has passed, so it can't be mistaken for an idle read timeout.
#[derive(Debug)]
struct DeadlineExpired;

impl std::fmt::Display for DeadlineExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("read deadline expired")
    }
}

impl std::error::Error for DeadlineExpired {}

fn is_deadline_expired(e: &io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.is::<DeadlineExpired>())
}

/// Shared absolute deadline for the socket reads behind a [`Bip324Stream`].
type SharedDeadline = Arc<Mutex<Option<Instant>>>;

/// Reads from the socket, bounding every read by the shared deadline when one
/// is set and by the socket's own read timeout otherwise.
struct DeadlineReader {
    socket: TcpStream,
    deadline: SharedDeadline,
    idle_timeout: Option<Duration>,
    /// The read timeout last set on the socket, to skip redundant syscalls.
    applied: Option<Option<Duration>>,
}

impl Read for DeadlineReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let deadline = *self.deadline.lock().unwrap_or_else(PoisonError::into_inner);
        let timeout = match deadline {
            Some(deadline) => Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .ok_or_else(|| io::Error::other(DeadlineExpired))?
                    .max(Duration::from_millis(1)),
            ),
            None => self.idle_timeout,
        };
        if self.applied != Some(timeout) {
            // A socket the peer has already shut down can refuse the option
            // (EINVAL on macOS). The read below then reports the close itself.
            if self.socket.set_read_timeout(timeout).is_ok() {
                self.applied = Some(timeout);
            }
        }
        match self.socket.read(buf) {
            Err(e)
                if deadline.is_some()
                    && matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                Err(io::Error::other(DeadlineExpired))
            }
            other => other,
        }
    }
}

/// An encrypted transport channel to a peer.
///
/// Carries one CBOR-encoded message per genuine BIP324 packet.
pub(crate) struct Bip324Stream {
    reader: ProtocolSessionReader<BufReader<DeadlineReader>>,
    writer: TcpStream,
    inbound: InboundCipher,
    outbound: OutboundCipher,
    session_id: SessionId,
    deadline: SharedDeadline,
    /// The socket's read timeout, which is also the wait between messages.
    idle_timeout: Option<Duration>,
    /// Taker only: the maker's signature over `session_id`, from its Hello.
    maker_session_sig: Option<Signature>,
}

impl std::fmt::Debug for Bip324Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bip324Stream").finish_non_exhaustive()
    }
}

impl Bip324Stream {
    /// Run the BIP324 handshake over a connected TCP stream.
    ///
    /// With a `deadline`, the whole handshake must finish before it. Without
    /// one, each read is bounded only by the socket's read timeout, which is
    /// also the idle timeout used later between messages.
    pub fn new(
        stream: TcpStream,
        network: Network,
        role: bip324::Role,
        deadline: Option<Instant>,
    ) -> Result<Self, NetError> {
        let deadline = Arc::new(Mutex::new(deadline));
        let idle_timeout = stream.read_timeout()?;
        let reader = BufReader::new(DeadlineReader {
            idle_timeout,
            applied: None,
            socket: stream.try_clone()?,
            deadline: deadline.clone(),
        });
        let mut writer = stream;
        let (inbound, outbound, reader, session_id) = bip324::io::handshake(
            network.magic(),
            role,
            None,
            None, // no garbage or decoys
            reader,
            &mut writer,
        )
        .map_err(Bip324Error::from)?;
        *deadline.lock().unwrap_or_else(PoisonError::into_inner) = None;

        Ok(Self {
            reader,
            writer,
            inbound,
            outbound,
            session_id,
            deadline,
            idle_timeout,
            maker_session_sig: None,
        })
    }

    /// The BIP324 session id, unique to this connection.
    pub(crate) fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Read the next genuine message and decode it as `T`.
    pub(crate) fn read_message<T: DeserializeOwned>(&mut self) -> Result<T, NetError> {
        Ok(serde_cbor::from_slice(&self.read_frame(None)?)?)
    }

    /// Read the next genuine message's raw bytes.
    ///
    /// The first byte must arrive before `deadline` when one is given, or else
    /// within the socket's idle read timeout; that timeout is returned as a
    /// plain `WouldBlock`/`TimedOut` IO error and leaves the stream usable.
    /// Once a packet has started, the rest of it must arrive within
    /// [`MESSAGE_ASSEMBLY_TIMEOUT`] (and before `deadline`), or the read fails
    /// with [`Bip324Error::ReadDeadlineExpired`].
    pub(crate) fn read_frame(&mut self, deadline: Option<Instant>) -> Result<Vec<u8>, NetError> {
        let result = self.read_frame_inner(deadline);
        self.set_deadline(None);
        result
    }

    fn read_frame_inner(&mut self, deadline: Option<Instant>) -> Result<Vec<u8>, NetError> {
        let started = Instant::now();
        loop {
            let mut len_bytes = [0u8; NUM_LENGTH_BYTES];
            self.set_deadline(deadline);
            self.read_exact(&mut len_bytes[..1], true)?;

            let assembly = Instant::now() + MESSAGE_ASSEMBLY_TIMEOUT;
            self.set_deadline(Some(deadline.map_or(assembly, |d| d.min(assembly))));
            self.read_exact(&mut len_bytes[1..], false)?;

            let packet_len = self.inbound.decrypt_packet_len(len_bytes);
            if packet_len > MAX_PACKET_LEN {
                return Err(NetError::MessageTooLarge);
            }
            let mut packet = vec![0u8; packet_len];
            self.read_exact(&mut packet, false)?;

            let (packet_type, mut plaintext) = self
                .inbound
                .decrypt_to_vec(&packet, None)
                .map_err(Bip324Error::Cipher)?;
            match packet_type {
                // We never send decoys, but they are valid BIP324 traffic.
                // Decoys are not activity: once they fill an idle period,
                // report it as one so the caller rechecks inactivity.
                PacketType::Decoy => {
                    if self.idle_timeout.is_some_and(|t| started.elapsed() >= t) {
                        return Err(NetError::IO(ErrorKind::TimedOut.into()));
                    }
                }
                PacketType::Genuine => {
                    plaintext.drain(..NUM_HEADER_BYTES);
                    return Ok(plaintext);
                }
            }
        }
    }

    fn read_exact(&mut self, buf: &mut [u8], at_boundary: bool) -> Result<(), NetError> {
        self.reader.read_exact(buf).map_err(|e| {
            if is_deadline_expired(&e) {
                Bip324Error::ReadDeadlineExpired.into()
            } else if at_boundary && e.kind() == ErrorKind::UnexpectedEof {
                Bip324Error::ConnectionClosed.into()
            } else {
                NetError::IO(e)
            }
        })
    }

    fn set_deadline(&self, deadline: Option<Instant>) {
        *self.deadline.lock().unwrap_or_else(PoisonError::into_inner) = deadline;
    }

    /// Serialize a message to CBOR and send it as a genuine BIP324 packet.
    pub(crate) fn send_message(&mut self, message: &impl Serialize) -> Result<(), NetError> {
        self.send_frame(&serde_cbor::ser::to_vec(message)?)
    }

    /// Send already-encoded message bytes as one genuine BIP324 packet.
    pub(crate) fn send_frame(&mut self, frame: &[u8]) -> Result<(), NetError> {
        if frame.len() > MAX_RPC_MESSAGE_SIZE {
            return Err(NetError::MessageTooLarge);
        }
        let packet = self
            .outbound
            .encrypt_to_vec(frame, PacketType::Genuine, None);
        self.writer.write_all(&packet)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Encrypt a small genuine packet but write only its first `n` bytes, to
    /// simulate a peer that stalls mid-packet.
    #[cfg(test)]
    pub(crate) fn send_partial_for_test(&mut self, n: usize) {
        let packet = self
            .outbound
            .encrypt_to_vec(b"partial", PacketType::Genuine, None);
        self.writer.write_all(&packet[..n]).unwrap();
        self.writer.flush().unwrap();
    }

    /// Record the `session_id_sig` from the maker's Hello.
    pub(crate) fn set_maker_session_sig(&mut self, sig: Option<Signature>) {
        self.maker_session_sig = sig;
    }

    /// Check that the maker holding `tweakable_point` signed this session id,
    /// binding the channel to that maker's identity.
    pub(crate) fn authenticate(&self, tweakable_point: &PublicKey) -> Result<(), NetError> {
        let sig = self
            .maker_session_sig
            .as_ref()
            .ok_or(Bip324Error::MissingSessionIdSig)?;
        verify_session_sig(&self.session_id, sig, tweakable_point)
    }
}

/// Sign a BIP324 session id with the maker's tweakable key.
pub(crate) fn sign_session_id(
    session_id: &SessionId,
    tweakable_privkey: &bitcoin::secp256k1::SecretKey,
) -> Signature {
    Secp256k1::signing_only().sign_ecdsa_low_r(
        &Message::from_digest(*session_id.as_bytes()),
        tweakable_privkey,
    )
}

fn verify_session_sig(
    session_id: &SessionId,
    sig: &Signature,
    tweakable_point: &PublicKey,
) -> Result<(), NetError> {
    Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from_digest(*session_id.as_bytes()),
            sig,
            &tweakable_point.inner,
        )
        .map_err(|e| Bip324Error::SessionIdSigInvalid(e).into())
}

/// A real session id from a loopback handshake, for tests that drive the
/// maker's handlers without a socket. `SessionId` has no public constructor.
#[cfg(feature = "integration-test")]
pub(crate) fn loopback_session_id() -> SessionId {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("loopback address");
    let responder = std::thread::spawn(move || {
        let (socket, _) = listener.accept().expect("accept loopback");
        Bip324Stream::new(socket, Network::Regtest, bip324::Role::Responder, None)
            .map(|stream| *stream.session_id())
    });
    let socket = TcpStream::connect(addr).expect("connect loopback");
    let initiator = Bip324Stream::new(socket, Network::Regtest, bip324::Role::Initiator, None)
        .expect("loopback handshake");
    let _ = responder.join();
    *initiator.session_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::SecretKey;
    use std::{net::TcpListener, thread};

    fn pair(network: Network) -> (Bip324Stream, Bip324Stream) {
        pair_with_maker_idle(network, None)
    }

    fn pair_with_maker_idle(
        network: Network,
        maker_idle: Option<Duration>,
    ) -> (Bip324Stream, Bip324Stream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let maker = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(maker_idle).unwrap();
            Bip324Stream::new(socket, network, bip324::Role::Responder, None).unwrap()
        });
        let socket = TcpStream::connect(addr).unwrap();
        let taker = Bip324Stream::new(socket, network, bip324::Role::Initiator, None).unwrap();
        (taker, maker.join().unwrap())
    }

    #[test]
    fn roundtrip_and_session_binding() {
        let (mut taker, mut maker) = pair(Network::Regtest);
        assert_eq!(taker.session_id(), maker.session_id());

        taker.send_message(&"hello".to_string()).unwrap();
        assert_eq!(maker.read_message::<String>().unwrap(), "hello");
        maker.send_message(&42u32).unwrap();
        assert_eq!(taker.read_message::<u32>().unwrap(), 42);

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7; 32]).unwrap();
        let point = PublicKey::new(sk.public_key(&secp));
        let other = PublicKey::new(SecretKey::from_slice(&[8; 32]).unwrap().public_key(&secp));

        assert!(matches!(
            taker.authenticate(&point),
            Err(NetError::Bip324Error(Bip324Error::MissingSessionIdSig))
        ));
        taker.set_maker_session_sig(Some(sign_session_id(maker.session_id(), &sk)));
        taker.authenticate(&point).unwrap();
        assert!(matches!(
            taker.authenticate(&other),
            Err(NetError::Bip324Error(Bip324Error::SessionIdSigInvalid(_)))
        ));
    }

    #[test]
    fn clean_close_is_connection_closed() {
        let (taker, mut maker) = pair(Network::Regtest);
        drop(taker);
        assert!(matches!(
            maker.read_frame(None),
            Err(NetError::Bip324Error(Bip324Error::ConnectionClosed))
        ));
    }

    #[test]
    fn stalled_handshake_hits_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Connect but never speak.
        let _silent = TcpStream::connect(addr).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let result = Bip324Stream::new(
            socket,
            Network::Regtest,
            bip324::Role::Responder,
            Some(Instant::now() + Duration::from_millis(100)),
        );
        assert!(matches!(
            result,
            Err(NetError::Bip324Error(Bip324Error::ReadDeadlineExpired))
        ));
    }

    #[test]
    fn idle_timeout_leaves_stream_usable() {
        let (mut taker, mut maker) =
            pair_with_maker_idle(Network::Regtest, Some(Duration::from_millis(50)));
        let err = maker.read_frame(None).unwrap_err();
        assert!(
            matches!(&err, NetError::IO(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)),
            "{:?}",
            err
        );
        taker.send_message(&1u8).unwrap();
        assert_eq!(maker.read_message::<u8>().unwrap(), 1);
    }

    #[test]
    fn decoys_do_not_extend_the_idle_wait() {
        let idle = Duration::from_millis(300);
        let (mut taker, mut maker) = pair_with_maker_idle(Network::Regtest, Some(idle));
        let decoy = |t: &mut Bip324Stream| t.outbound.encrypt_to_vec(&[], PacketType::Decoy, None);
        let writer = thread::spawn(move || {
            // Decoys well inside the idle timeout, for far longer than it.
            for _ in 0..30 {
                let packet = decoy(&mut taker);
                if taker.writer.write_all(&packet).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        });
        let started = Instant::now();
        let err = maker.read_frame(None).unwrap_err();
        assert!(
            matches!(&err, NetError::IO(e) if e.kind() == ErrorKind::TimedOut),
            "{:?}",
            err
        );
        assert!(started.elapsed() < idle * 3, "{:?}", started.elapsed());
        drop(maker);
        writer.join().unwrap();
    }

    #[test]
    fn oversized_packet_is_refused_before_allocating() {
        let (mut taker, mut maker) = pair(Network::Regtest);
        // A genuine packet whose declared length exceeds the cap.
        let packet = taker.outbound.encrypt_to_vec(
            &vec![0u8; MAX_RPC_MESSAGE_SIZE + 1],
            PacketType::Genuine,
            None,
        );
        // Write from another thread: the maker stops reading after the length.
        let writer = thread::spawn(move || {
            let _ = taker.writer.write_all(&packet);
        });
        assert!(matches!(
            maker.read_frame(None),
            Err(NetError::MessageTooLarge)
        ));
        drop(maker);
        writer.join().unwrap();
    }
}
