//! A bare maker protocol client: one BIP324 connection, messages sent by hand.
//!
//! The `Taker` API drives a whole swap and never keeps a connection past its
//! turn. Tests that need an old connection held open, or a message the taker
//! would never send at that moment, use this instead.

use std::{io::ErrorKind, net::TcpStream, time::Duration};

use bitcoin::Network;
use openswap::{
    bip324_stream::{Bip324Error, Bip324Stream},
    error::NetError,
    protocol::{
        common_messages::{
            AckSwapDetails, GetOffer, Hello, MakerToTakerMessage, ProtocolVersion, SwapDetails,
            TakerToMakerMessage,
        },
        features::{choose_pins, supported},
    },
};

/// Longer than any maker reply in a test, shorter than a hung test.
const REPLY_TIMEOUT: Duration = Duration::from_secs(60);

/// One raw connection to a maker.
pub struct RawMakerConnection {
    stream: Bip324Stream,
}

impl RawMakerConnection {
    /// Opens a connection and runs the BIP324 handshake; no message is sent yet.
    pub fn connect(address: &str) -> Self {
        let socket = TcpStream::connect(address).expect("connect to maker");
        socket
            .set_read_timeout(Some(REPLY_TIMEOUT))
            .expect("set read timeout");
        let stream = Bip324Stream::new(socket, Network::Regtest, bip324::Role::Initiator, None)
            .expect("BIP324 handshake with maker");
        Self { stream }
    }

    /// Opens a connection and takes it through hello, offer and `details`,
    /// pinning `protocol` from the maker's features as the taker would.
    /// Panics unless the maker accepts the swap.
    pub fn admit(
        address: &str,
        protocol: ProtocolVersion,
        mut details: SwapDetails,
    ) -> (Self, AckSwapDetails) {
        let mut conn = Self::connect(address);
        conn.send(&TakerToMakerMessage::Hello(Hello {
            features: supported().into_iter().map(String::from).collect(),
            session_id_sig: None,
        }));
        let maker_features = match conn.recv() {
            Ok(MakerToTakerMessage::Hello(hello)) => hello.features,
            other => panic!("expected Hello, got {:?}", other),
        };
        details.features = choose_pins(protocol.feature_name(), &maker_features);
        conn.send(&TakerToMakerMessage::GetOffer(GetOffer));
        match conn.recv() {
            Ok(MakerToTakerMessage::Offer(_)) => {}
            other => panic!("expected Offer, got {:?}", other),
        }
        conn.send(&TakerToMakerMessage::SwapDetails(details));
        match conn.recv() {
            Ok(MakerToTakerMessage::AckSwapDetails(ack)) if ack.tweakable_point.is_some() => {
                (conn, ack)
            }
            other => panic!("expected the maker to admit the swap, got {:?}", other),
        }
    }

    /// Sends one message.
    pub fn send(&mut self, message: &TakerToMakerMessage) {
        self.stream.send_message(message).expect("send to maker");
    }

    /// Panics unless the maker closed the connection: a reply, a decode
    /// error or a read timeout all mean it is still open.
    pub fn expect_closed(&mut self) {
        match self.recv() {
            Err(NetError::ReachedEOF | NetError::Bip324Error(Bip324Error::ConnectionClosed)) => {}
            Err(NetError::IO(e))
                if matches!(
                    e.kind(),
                    ErrorKind::UnexpectedEof
                        | ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                ) => {}
            other => panic!(
                "expected the maker to close the connection, got {:?}",
                other
            ),
        }
    }

    /// Reads one reply. An error means the maker closed the connection or
    /// did not answer in time.
    pub fn recv(&mut self) -> Result<MakerToTakerMessage, NetError> {
        self.stream.read_message()
    }
}
