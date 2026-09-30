//! Electrum over a real Tor SOCKS5 proxy, under the most adverse abort paths.
//!
//! These reuse existing scenario bodies verbatim via [`TorElectrumBackend`], so
//! they assert the *same* balances as their non-Tor counterparts. A Tor-specific
//! divergence in any watchtower path therefore fails loudly instead of degrading
//! silently.
//!
//! Why these three scenarios, in terms of watchtower coverage:
//!
//! - `abort1` — the taker vanishes *after* funding is on-chain, so makers must
//!   detect it autonomously with no ZMQ and no mempool scan: `subscribe_script` /
//!   `poll_event`, the preimage/hashlock cascade, timelock fallback, and
//!   `unsubscribe_script` on cleanup. Run over both protocols.
//! - `malice2` — the only scenario driving the taker's breach detector.
//!
//! ## Requirements and gating
//!
//! An ephemeral onion service must upload its descriptor to the HSDir ring and
//! the client must fetch it back, so these **cannot work offline**. They are
//! `#[ignore]`d and additionally require `OPENSWAP_TOR_IT=1`, checked by the
//! `tor_gate!()` that opens each row; without that variable they skip, but
//! with it set and Tor unreachable they deliberately panic — a misconfigured
//! Tor must not pass silently. Run them with:
//!
//! ```text
//! OPENSWAP_TOR_IT=1 cargo test --features integration-test electrum_tor \
//!     -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! `tor` must be listening on `TOR_CONTROL_PORT` / `TOR_SOCKS_PORT` and be fully
//! bootstrapped. Set `OPENSWAP_TOR_PASSWORD` if the control port needs one.
//!
//! Ignored does not mean dead: no hermetic suite can reach the Tor network, so
//! these stay opt-in by design. They are the only coverage of the watchtower
//! over real circuit churn, and they run before every release.
//!
//! Note the onion services are created with `Flags=Detach`, so they outlive the
//! test process. That is deliberate — the CI job's tor is ephemeral and drops
//! them on restart.

use openswap::protocol::common_messages::ProtocolVersion;

use super::{
    electrum_abort1::{run_abort1, LEGACY_EXPECTED, TAPROOT_EXPECTED},
    malice2::run_malice2,
    test_framework::TorElectrumBackend,
};

use log::warn;

swap_matrix! {
    run_abort1 => {
        /// Taproot abort1 over Tor: the widest watchtower path in the suite.
        #[ignore = "requires a bootstrapped tor and OPENSWAP_TOR_IT=1"]
        tor_abort1_taproot: {
            tor_gate!();
            warn!("Running Test: abort1 (Taproot) over Tor Electrum");
        } <TorElectrumBackend>(ProtocolVersion::Taproot, &TAPROOT_EXPECTED),

        /// Legacy abort1 over Tor. Same cascade, different contract shape.
        #[ignore = "requires a bootstrapped tor and OPENSWAP_TOR_IT=1"]
        tor_abort1_legacy: {
            tor_gate!();
            warn!("Running Test: abort1 (Legacy) over Tor Electrum");
        } <TorElectrumBackend>(ProtocolVersion::Legacy, &LEGACY_EXPECTED),
    }

    run_malice2 => {
        /// Malicious contract broadcast over Tor, exercising the taker's breach detector.
        #[ignore = "requires a bootstrapped tor and OPENSWAP_TOR_IT=1"]
        tor_malice2: {
            tor_gate!();
            warn!("Running Test: malice2 (maker broadcasts contract) over Tor Electrum");
        } <TorElectrumBackend>(),
    }
}
