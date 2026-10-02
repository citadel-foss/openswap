//! Helpers shared by more than one rejection theme.

use std::{
    thread,
    time::{Duration, Instant},
};

/// `wait_for_log`, but matching only content past a pre-captured offset and
/// requiring at least `min_count` occurrences. `wait_for_new_log` snapshots
/// the offset at call time, which races a needle logged just before the call.
pub(super) fn wait_for_log_after(
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
