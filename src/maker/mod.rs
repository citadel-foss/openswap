//! The OpenSwap Maker.
//!
//! A Maker server that acts as a swap service provider.
//! It can be run in an unix/mac system with local access to Bitcoin Core RPC.
//!
//! Maker server responds to RPC requests via `maker-cli` app, which is used as an
//! operating tool for the server.
//!
//! Default Ports:
//! 6102: Client connection for swaps.
//! 6103: RPC Connection for operations.

mod error;
mod rpc;

pub mod legacy_handlers;
mod legacy_verification;
#[cfg(feature = "lightning")]
pub mod lightning_handlers;
pub mod taproot_handlers;
mod taproot_verification;

pub mod api;
pub mod handlers;
pub mod nostr;
pub mod server;
pub mod swap_tracker;

pub use error::MakerError;
pub use rpc::{AuthenticatedRpcRequest, RpcMsgReq, RpcMsgResp};

#[cfg(feature = "integration-test")]
pub use api::MakerBehavior;
pub use api::{MakerServer, MakerServerConfig};
pub use handlers::{
    handle_message, ConnectionState, Maker as MakerTrait, MakerConfig as HandlerConfig, SwapPhase,
};
pub use server::{bind_port_retry, start_server};
pub use swap_tracker::MakerSwapTracker;

pub use legacy_handlers::handle_legacy_message;
pub use taproot_handlers::handle_taproot_message;
