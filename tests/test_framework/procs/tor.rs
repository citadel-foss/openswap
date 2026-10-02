//! Tor daemon settings, test gating and onion warm-up for the Tor integration tests.

use openswap::{
    utill::check_tor_status,
    wallet::{Blockchain, Electrum, ElectrumConfig},
};

/// Tor control port used by the Tor integration tests.
pub const TOR_CONTROL_PORT: u16 = 9051;
/// Tor SOCKS port used by the Tor integration tests.
pub const TOR_SOCKS_PORT: u16 = 9050;

/// Control-port password for the Tor tests, from `OPENSWAP_TOR_PASSWORD`
/// (empty when unset, which matches a cookie-less `HashedControlPassword ""`).
pub fn tor_password() -> String {
    std::env::var("OPENSWAP_TOR_PASSWORD").unwrap_or_default()
}

/// True when the Tor integration tests should run.
///
/// `OPENSWAP_TOR_IT=1` means "I require Tor", so a missing daemon **panics**
/// rather than skipping. CI gates on these tests, and a silent skip would look
/// exactly like a pass. Without the variable set they skip, for local runs.
pub fn tor_it_enabled() -> bool {
    if std::env::var("OPENSWAP_TOR_IT").as_deref() != Ok("1") {
        log::warn!("skipping Tor integration test: OPENSWAP_TOR_IT=1 not set");
        return false;
    }
    if let Err(e) = check_tor_status(TOR_CONTROL_PORT, &tor_password()) {
        panic!(
            "OPENSWAP_TOR_IT=1 but tor control port {} is unreachable: {:?}",
            TOR_CONTROL_PORT, e
        );
    }
    true
}

/// Connect once before handing the config out, retrying until it works.
///
/// A fresh onion service is not reachable until its descriptor reaches the HSDir
/// ring and the client fetches it, which takes tens of seconds and is where
/// nearly all Tor flakiness lives. Tor caches the descriptor after the first
/// success, so paying for it once here makes every participant's connect fast.
pub(in crate::test_framework) fn warm_up_onion(cfg: &ElectrumConfig) {
    const ATTEMPTS: u32 = 12;
    const GAP: std::time::Duration = std::time::Duration::from_secs(10);

    for attempt in 1..=ATTEMPTS {
        match Electrum::new(cfg) {
            Ok(probe) => match probe.get_block_count() {
                Ok(tip) => {
                    log::info!("onion reachable on attempt {attempt} (tip {tip})");
                    return;
                }
                Err(e) => log::warn!("onion connected but no tip on attempt {attempt}: {e:?}"),
            },
            Err(e) => log::warn!("onion not reachable yet on attempt {attempt}: {e:?}"),
        }
        std::thread::sleep(GAP);
    }
    panic!(
        "onion service never became reachable after {} attempts",
        ATTEMPTS
    );
}
