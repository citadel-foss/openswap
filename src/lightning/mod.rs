//! Lightning backend layer.
//!
//! This module defines a synchronous, backend-agnostic interface
//! ([`LightningBackend`]) to a Lightning node, together with:
//!
//! - [`LdkServerBackend`]: an implementation backed by an
//!   [LDK Server](https://github.com/lightningdevkit/ldk-server) sidecar,
//!   reached over gRPC. The async client is bridged to the crate's synchronous
//!   world through a private tokio runtime that never leaks outside the
//!   implementation.
//! - `MockLightningBackend`: a deterministic in-memory implementation for
//!   tests (available under `cfg(test)` or the `integration-test` feature).
//!
//! Higher layers share a backend as `Arc<dyn LightningBackend>` and consume
//! node events by periodically calling [`LightningBackend::poll_event`].

mod backend;
mod config;
mod error;
mod ldk_server;
#[cfg(any(test, feature = "integration-test"))]
mod mock;
mod types;

pub use backend::LightningBackend;
pub use config::{
    default_cert_path, LightningConfig, DEFAULT_LDK_SERVER_URL, DEFAULT_TIMEOUT_SECS,
};
pub use error::LightningError;
pub use ldk_server::LdkServerBackend;
#[cfg(any(test, feature = "integration-test"))]
pub use mock::MockLightningBackend;
pub use types::{
    Balances, Bolt11Invoice, ChannelId, ChannelInfo, ChannelState, InvoiceParams, LnEvent,
    NodeInfo, OpenChannelRequest, PaymentId, Preimage,
};
