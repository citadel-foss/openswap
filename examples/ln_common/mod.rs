//! Helpers shared by the Lightning examples.
//!
//! Included with `#[path]` rather than published as a crate module: these
//! only exist to keep the runnable demos from repeating the same LDK Server
//! connection and polling boilerplate.

// Each example compiles this module separately and uses only the part it
// needs, so anything another example uses looks dead here.
#![allow(dead_code)]

use std::{path::Path, time::Duration};

use openswap::lightning::{LdkServerBackend, LightningConfig};

/// How often [`wait_for`] re-checks its condition.
pub const POLL: Duration = Duration::from_millis(500);

/// Connects to an LDK Server node from its on-disk data directory, reading
/// the API key and TLS certificate the node wrote there.
pub fn connect(data_dir: &Path, grpc_addr: &str) -> LdkServerBackend {
    use bitcoin::hashes::hex::DisplayHex;
    let api_key = std::fs::read(data_dir.join("regtest/api_key"))
        .expect("api_key file")
        .to_lower_hex_string();
    LdkServerBackend::new(&LightningConfig {
        base_url: grpc_addr.to_string(),
        api_key,
        tls_cert_path: Some(data_dir.join("tls.crt")),
        timeout_secs: 10,
        network: bitcoin::Network::Regtest,
    })
    .expect("backend connects")
}

/// Polls `step` until it returns true, panicking if `timeout` elapses first.
pub fn wait_for(what: &str, timeout: Duration, mut step: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + timeout;
    while !step() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for: {}",
            what
        );
        std::thread::sleep(POLL);
    }
    println!("ok: {what}");
}
