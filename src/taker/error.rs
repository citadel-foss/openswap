//! All Taker-related errors.
use crate::{
    error::NetError, protocol::error::ProtocolError, utill::TorError, wallet::WalletError,
    watch_tower::watcher_error::WatcherError,
};
use bitcoin::address::ParseError;

/// Represents errors that can occur during Taker operations.
///
/// This enum covers a range of errors related to I/O, wallet operations, network communication,
/// and other Taker-specific scenarios.
#[derive(Debug)]
pub enum TakerError {
    /// Standard input/output error.
    IO(std::io::Error),
    /// Error indicating contracts were broadcasted prematurely.
    /// Contains a list of the transaction IDs of the broadcasted contracts.
    ContractsBroadcasted(Vec<bitcoin::Txid>),
    /// Error indicating there are not enough makers available in the offer book.
    NotEnoughMakersInOfferBook,
    /// Error related to wallet operations.
    Wallet(WalletError),
    /// Error related to network operations.
    Net(NetError),
    /// Error indicating the send amount was not set for a transaction.
    SendAmountNotSet,
    /// Error deserializing data, typically related to CBOR-encoded data.
    Deserialize(String),
    /// Error indicating an MPSC channel failure.
    ///
    /// This error occurs during internal thread communication.
    MPSC(String),
    /// Tor error
    TorError(TorError),
    /// Error relating to Bitcoin Address Parsing.
    AddressParseError(ParseError),
    /// General error with a custom message
    General(String),
    /// Watcher Service Error
    Watcher(WatcherError),
}

/// The taker's only interrupt source is its breach detector, so an interrupted
/// wait means contracts hit the chain rather than a wallet failure.
pub(crate) fn breach_or_wallet_error(error: WalletError) -> TakerError {
    match error {
        WalletError::Interrupted(_) => TakerError::ContractsBroadcasted(vec![]),
        other => TakerError::Wallet(other),
    }
}

impl From<TorError> for TakerError {
    fn from(value: TorError) -> Self {
        Self::TorError(value)
    }
}

impl From<serde_cbor::Error> for TakerError {
    fn from(value: serde_cbor::Error) -> Self {
        Self::Deserialize(value.to_string())
    }
}

impl From<serde_json::Error> for TakerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Deserialize(value.to_string())
    }
}

impl From<WalletError> for TakerError {
    fn from(value: WalletError) -> Self {
        Self::Wallet(value)
    }
}

impl From<std::io::Error> for TakerError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<NetError> for TakerError {
    fn from(value: NetError) -> Self {
        Self::Net(value)
    }
}

impl From<ProtocolError> for TakerError {
    fn from(value: ProtocolError) -> Self {
        Self::Wallet(value.into())
    }
}

impl From<std::sync::mpsc::RecvError> for TakerError {
    fn from(value: std::sync::mpsc::RecvError) -> Self {
        Self::MPSC(value.to_string())
    }
}

impl From<std::sync::mpsc::RecvTimeoutError> for TakerError {
    fn from(value: std::sync::mpsc::RecvTimeoutError) -> Self {
        Self::MPSC(value.to_string())
    }
}

impl<T> From<std::sync::mpsc::SendError<T>> for TakerError {
    fn from(value: std::sync::mpsc::SendError<T>) -> Self {
        Self::MPSC(value.to_string())
    }
}

impl From<ParseError> for TakerError {
    fn from(value: ParseError) -> Self {
        Self::AddressParseError(value)
    }
}

impl From<WatcherError> for TakerError {
    fn from(value: WatcherError) -> Self {
        Self::Watcher(value)
    }
}
impl From<bip324::io::ProtocolError> for TakerError {
    fn from(value: bip324::io::ProtocolError) -> Self {
        Self::Net(value.into())
    }
}
