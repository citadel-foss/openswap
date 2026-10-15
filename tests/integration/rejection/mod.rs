//! Everything either side must refuse, in one place.
//!
//! The refusal point differs per case but nothing settles in any of them.
//! The maker refuses: out-of-bounds, forged, or resent `SwapDetails`;
//! insufficient liquidity at offerbook sync or admission; under-delivered
//! amounts; wrong incoming counts; duplicated, overcounted, overstated, or
//! spent funding outpoints; a proof of funding with no contract binding;
//! mismatched taproot contract amounts; and funding plans that cost more than
//! the hop earns. The taker refuses: malformed legacy funding outputs;
//! underfunded, inflated, duplicated, or shape-breaking taproot contracts; and
//! fee skimming on either protocol. A fail-closed guard that lets one through
//! costs someone real funds.
//!
//! Each file holds one theme; see its module doc.

mod admission;
mod bans;
mod blocklist;
mod contract_response;
mod fees;
mod funding_proof;
mod keepalive;
mod partial_broadcast;
mod replay;

// Helpers shared by more than one file in this folder; each file reaches them
// through `super::`.

use std::{
    thread,
    time::{Duration, Instant},
};

/// `wait_for_log`, but matching only content past a pre-captured offset and
/// requiring at least `min_count` occurrences. `wait_for_new_log` snapshots
/// the offset at call time, which races a needle logged just before the call.
fn wait_for_log_after(
    log_path: &str,
    offset: u64,
    needle: &str,
    min_count: usize,
    timeout: Duration,
) {
    let start = Instant::now();
    loop {
        if let Ok(contents) = std::fs::read_to_string(log_path) {
            if contents
                .get(offset as usize..)
                .is_some_and(|tail| tail.matches(needle).count() >= min_count)
            {
                // Never echo the needle: callers count occurrences in the log
                // after this returns, and the echo would match itself.
                log::info!("wait_for_log_after satisfied");
                return;
            }
        }
        assert!(
            start.elapsed() <= timeout,
            "Timed out waiting for log message '{}' (x{}) in {}",
            needle,
            min_count,
            log_path
        );
        thread::sleep(Duration::from_secs(2));
    }
}
