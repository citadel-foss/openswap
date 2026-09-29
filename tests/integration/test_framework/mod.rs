//! A framework for functional tests of the OpenSwap protocol.
//!
//! [TestFramework] uses [bitcoind] to spawn a regtest node (plus `electrs` for the Electrum
//! backends) and a per-test nostr relay, then builds the requested takers and makers, each with
//! its own behavior, connected to that node.
//!
//! Each framework keeps its data, including the bitcoind data directory, in its own
//! `openswap-<random u64>` directory under [`std::env::temp_dir()`], logged at startup.
//! [TestFramework::stop] and `Drop for TestFramework` both delete it, so the data is only there
//! while the test runs. It survives only when teardown never runs, e.g. the process is killed.

mod actors;
mod backend;
mod chain;
#[cfg(feature = "lightning")]
mod lightning;
mod logs;
mod ports;
mod procs;
mod reports;
mod timing;
mod tracker;
mod world;

#[cfg(feature = "lightning")]
pub(crate) use self::lightning::*;
pub use self::{
    actors::*,
    backend::*,
    chain::*,
    procs::{electrs::*, tor::*},
    reports::*,
    tracker::*,
    world::*,
};
pub(crate) use self::{logs::*, procs::bitcoind::*, timing::*};
