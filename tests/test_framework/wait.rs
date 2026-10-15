//! Polling a condition until it holds, for [`wait_until!`] and [`wait_for!`].

use std::{
    thread,
    time::{Duration, Instant},
};

/// How often [`wait_until!`] and [`wait_for!`] re-check unless told otherwise.
pub const POLL: Duration = Duration::from_millis(250);

/// Calls `check` every `every` until it returns `Some`, and returns that value.
/// Fails after `timeout`, naming `what` it waited for. A sleep never runs past
/// the deadline, so the last check comes at the deadline, not up to `every`
/// after it.
#[track_caller]
pub fn wait_for<T>(
    timeout: Duration,
    every: Duration,
    what: &str,
    mut check: impl FnMut() -> Option<T>,
) -> T {
    let start = Instant::now();
    loop {
        if let Some(value) = check() {
            return value;
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < timeout,
            "timed out after {:?} waiting for: {}",
            timeout,
            what
        );
        thread::sleep(every.min(timeout - elapsed));
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        panic,
        time::{Duration, Instant},
    };

    use super::wait_for;

    #[test]
    fn returns_the_first_value_the_check_yields() {
        let calls = Cell::new(0);
        let value = wait_for(
            Duration::from_secs(5),
            Duration::ZERO,
            "the third call",
            || {
                calls.set(calls.get() + 1);
                (calls.get() == 3).then(|| calls.get() * 10)
            },
        );
        assert_eq!(value, 30);
    }

    #[test]
    #[should_panic(expected = "waiting for: something that never happens")]
    fn fails_after_the_timeout_naming_what_it_waited_for() {
        wait_for::<()>(
            Duration::from_millis(50),
            Duration::from_millis(10),
            "something that never happens",
            || None,
        );
    }

    #[test]
    fn a_long_interval_does_not_sleep_past_the_timeout() {
        let start = Instant::now();
        let result = panic::catch_unwind(|| {
            wait_for::<()>(
                Duration::from_millis(50),
                Duration::from_secs(10),
                "something that never happens",
                || None,
            )
        });
        assert!(result.is_err(), "the wait must time out");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the wait slept a whole interval past its timeout: {:?}",
            start.elapsed()
        );
    }
}
