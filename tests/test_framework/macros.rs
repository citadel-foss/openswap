//! The suite's macros. `#[world_test]` declares a test's fixture, or a
//! `cases` table of them, around a hand-written body; it arrives with
//! `use super::test_framework::*;`. The `macro_rules!` ones reach the whole
//! suite through `#[macro_use] mod test_framework;` in `main.rs`. None
//! generates test logic: a body is a plain function.

/// `#[world_test(..)]`: one `#[test]` from a declared world, its setup steps
/// and a body, which keeps its name. Rust only defines attribute macros in a
/// `proc-macro` crate, so the code lives in `tests/macros`; see its docs for
/// the keys and the expansion.
pub use openswap_test_macros::world_test;

/// `assert_logged!(world, "needle")`: asserts the taker log (every taker and
/// maker writes there) holds `needle`, i.e.
/// `world.framework().assert_log(needle, &world.taker_log_path())`. A miss
/// panics at the macro's line.
macro_rules! assert_logged {
    ($world:expr, $needle:expr $(,)?) => {{
        let world = &$world;
        world
            .framework()
            .assert_log($needle, &world.taker_log_path());
    }};
}

/// `wait_logged!(world, "needle", timeout)`: polls the taker log until it
/// holds `needle`, i.e. `wait_for_log(&world.taker_log_path(), needle,
/// timeout)`. A timeout panics at the macro's line.
macro_rules! wait_logged {
    ($world:expr, $needle:expr, $timeout:expr $(,)?) => {{
        let world = &$world;
        $crate::test_framework::wait_for_log(&world.taker_log_path(), $needle, $timeout);
    }};
}
