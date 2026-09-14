//! Defines the Contract Transaction and Protocol Messages.

pub mod common_messages;
pub mod legacy_messages;
pub mod lightning_messages;
pub mod taproot_messages;

pub(crate) mod contract;
pub mod contract2;
pub mod error;
pub mod musig2;
pub mod musig_interface;

pub use common_messages::ProtocolVersion;
pub(crate) use contract::Hash160;
