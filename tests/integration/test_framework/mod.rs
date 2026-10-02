//! A framework for functional tests of the OpenSwap protocol.
//!
//! [TestFramework] uses [bitcoind] to spawn a regtest node (plus `electrs` for the Electrum
//! backends) and a per-test nostr relay, then builds the requested takers and makers, each with
//! its own behavior, connected to that node.
//!
//! Each framework keeps its data, including the bitcoind data directory, in its own
//! `openswap-<random u64>` directory under [`std::env::temp_dir()`], logged at startup.
//! [TestFramework::stop] deletes it, as does `Drop for TestFramework` when `stop()` was never
//! called, so the data is only there while the test runs. A failing test keeps it: teardown on
//! the panic path leaves the logs, wallets and trackers for inspection. It also survives when
//! teardown never runs, e.g. the process is killed.
//!
//! [World] wraps the same `init` call and owns what it returns: [MakerHandle]s, [TakerHandle]s
//! and a single teardown order that `Drop` also runs when a test panics. [BalanceExpect] states
//! which balance fields a test asserts, and `swap_matrix!` / `tor_gate!` (in `macros.rs`)
//! generate `#[test]` items around shared scenario bodies.

#[macro_use]
mod macros;

mod actors;
mod backend;
mod chain;
mod expect;
mod harness;
#[cfg(feature = "lightning")]
mod lightning;
mod logs;
mod node;
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
    expect::*,
    harness::*,
    macros::world_test,
    node::*,
    procs::{electrs::*, tor::*},
    reports::*,
    tracker::*,
    world::*,
};
pub(crate) use self::{logs::*, procs::bitcoind::*, timing::*};
