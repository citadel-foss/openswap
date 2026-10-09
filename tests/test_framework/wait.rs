//! Polling a condition until it holds, for [`wait_until!`] and [`wait_for!`].

use std::{
    thread,
    time::{Duration, Instant},
};

/// How often [`wait_until!`] and [`wait_for!`] re-check unless told otherwise.
pub const POLL: Duration = Duration::from_millis(250);

/// Calls `check` every `every` until it returns `Some`, and returns that value.
/// Fails after `timeout`, naming `what` it waited for.
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
        assert!(
            start.elapsed() < timeout,
            "timed out after {:?} waiting for: {}",
            timeout,
            what
        );
        thread::sleep(every);
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, time::Duration};

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
}
