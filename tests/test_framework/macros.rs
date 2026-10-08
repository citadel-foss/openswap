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

/// `assert_balances!(world, since before; { rows })`: asserts every wallet's
/// balances in one go and reports every mismatch in one failure. Without
/// `since before;` the rows cannot use `loss` or `gain`.
///
/// ```ignore
/// let before = world.balances();
/// // .. the swap ..
/// world.sync_all();
/// assert_balances!(world, since before; {
///     taker:   { regular: 14_499_538, swap: 496_447, contract: 0, fidelity: 0, loss: 4_015 },
///     makers:  { regular: [14_500_865, 14_502_398], contract: 0, fidelity: BOND, gain: [658, 621] },
///     maker 1: { swap: 497_980 },
/// });
/// ```
///
/// A row is `taker`/`maker` (wallet 0), `taker N`/`maker N`, or `takers`/
/// `makers` (every wallet of that kind). Its fields are `regular`, `swap`,
/// `contract`, `fidelity`, `spendable`, and `loss`/`gain` (the change in
/// `spendable` since the snapshot). A value is sats or an `Amount`, a list
/// with one per wallet in a `takers`/`makers` row, or an `Option` of either,
/// where `None` asserts nothing. A later row overrides the fields it sets.
macro_rules! assert_balances {
    ($world:expr, since $before:expr; { $($rows:tt)* }) => {{
        let mut table = $crate::test_framework::BalanceTable::new(&$world, Some(&$before));
        assert_balances!(@rows table; $($rows)*);
        table.assert();
    }};
    ($world:expr; { $($rows:tt)* }) => {{
        let mut table = $crate::test_framework::BalanceTable::new(&$world, None);
        assert_balances!(@rows table; $($rows)*);
        table.assert();
    }};

    (@rows $t:ident; $(,)?) => {};
    (@rows $t:ident; takers : { $($f:ident : $v:expr),* $(,)? } $(, $($rest:tt)*)?) => {
        let count = $t.taker_count();
        for i in 0..count {
            $t.taker(i, assert_balances!(@expect i, Some(count), "takers"; $($f : $v),*));
        }
        assert_balances!(@rows $t; $($($rest)*)?);
    };
    (@rows $t:ident; makers : { $($f:ident : $v:expr),* $(,)? } $(, $($rest:tt)*)?) => {
        let count = $t.maker_count();
        for i in 0..count {
            $t.maker(i, assert_balances!(@expect i, Some(count), "makers"; $($f : $v),*));
        }
        assert_balances!(@rows $t; $($($rest)*)?);
    };
    (@rows $t:ident; taker $($i:literal)? : { $($f:ident : $v:expr),* $(,)? } $(, $($rest:tt)*)?) => {
        let i = 0 $(+ $i)?;
        $t.taker(i, assert_balances!(@expect i, None, "taker"; $($f : $v),*));
        assert_balances!(@rows $t; $($($rest)*)?);
    };
    (@rows $t:ident; maker $($i:literal)? : { $($f:ident : $v:expr),* $(,)? } $(, $($rest:tt)*)?) => {
        let i = 0 $(+ $i)?;
        $t.maker(i, assert_balances!(@expect i, None, "maker"; $($f : $v),*));
        assert_balances!(@rows $t; $($($rest)*)?);
    };

    (@expect $i:expr, $wallets:expr, $row:literal; $($f:ident : $v:expr),*) => {
        $crate::test_framework::WalletExpect::default()
            $(.$f($crate::test_framework::column(
                &$v,
                $i,
                $wallets,
                concat!($row, ".", stringify!($f)),
            )))*
    };
}

/// `assert_log!(world; { checks })`: reads the log once and fails with every
/// check it does not satisfy. `world` is anything with a log: a `World` (its
/// shared taker log, where every taker and maker writes) or a log path.
/// `assert_log!(world, since mark; { .. })` checks only what was written after
/// `mark = log_mark(&world)`.
///
/// ```ignore
/// assert_log!(world; {
///     has "Successfully created fidelity bond",
///     lacks "SECURITY: Broadcasting",
///     count("No active Fidelity Bonds found. Creating one.") == 1,
///     order ["shows no funding broadcast after", "Funding was never broadcast"],
/// });
/// ```
///
/// It never writes to the log it reads, so a needle it checked cannot show up
/// in a later count or absence check.
macro_rules! assert_log {
    ($source:expr, since $mark:expr; { $($rows:tt)* }) => {
        $crate::test_framework::assert_log(&$source, Some($mark), &assert_log!(@rows []; $($rows)*))
    };
    ($source:expr; { $($rows:tt)* }) => {
        $crate::test_framework::assert_log(&$source, None, &assert_log!(@rows []; $($rows)*))
    };

    (@rows [$($acc:expr),*]; $(,)?) => {
        [$($acc),*]
    };
    (@rows [$($acc:expr),*]; has $needle:expr $(, $($rest:tt)*)?) => {
        assert_log!(@rows [$($acc,)* $crate::test_framework::LogCheck::Has($needle.to_string())];
            $($($rest)*)?)
    };
    (@rows [$($acc:expr),*]; lacks $needle:expr $(, $($rest:tt)*)?) => {
        assert_log!(@rows [$($acc,)* $crate::test_framework::LogCheck::Lacks($needle.to_string())];
            $($($rest)*)?)
    };
    (@rows [$($acc:expr),*]; count($needle:expr) == $n:expr $(, $($rest:tt)*)?) => {
        assert_log!(@rows [$($acc,)* $crate::test_framework::LogCheck::Count($needle.to_string(), $n)];
            $($($rest)*)?)
    };
    (@rows [$($acc:expr),*]; order [$($needle:expr),+ $(,)?] $(, $($rest:tt)*)?) => {
        assert_log!(@rows [$($acc,)* $crate::test_framework::LogCheck::Order(vec![$($needle.to_string()),+])];
            $($($rest)*)?)
    };
}

/// `wait_until!(timeout, "what", condition)`: re-checks `condition` every
/// 250ms (or `every interval`) until it holds; fails after `timeout`, naming
/// what it waited for. The condition may be a block with side effects.
///
/// ```ignore
/// wait_until!(Duration::from_secs(60), "the maker shut down",
///     world.makers()[0].inner().shutdown.load(Relaxed));
/// wait_until!(Duration::from_secs(180), every Duration::from_secs(2),
///     "recovery to release the inputs",
///     world.makers()[0].inner().reserved_inputs().unwrap() == 0);
/// ```
macro_rules! wait_until {
    ($timeout:expr, every $every:expr, $what:expr, $cond:expr $(,)?) => {
        $crate::test_framework::wait_for($timeout, $every, &$what, || {
            if $cond {
                Some(())
            } else {
                None
            }
        })
    };
    ($timeout:expr, $what:expr, $cond:expr $(,)?) => {
        wait_until!($timeout, every $crate::test_framework::POLL, $what, $cond)
    };
}

/// `wait_for!(timeout, "what", option)`: like [`wait_until!`], but the
/// expression yields an `Option` and the macro returns the first `Some` value.
///
/// ```ignore
/// let txids = wait_for!(Duration::from_secs(120), "the 3 funding txs in the mempool", {
///     let new = new_mempool_txids();
///     (new.len() == 3).then_some(new)
/// });
/// ```
macro_rules! wait_for {
    ($timeout:expr, every $every:expr, $what:expr, $value:expr $(,)?) => {
        $crate::test_framework::wait_for($timeout, $every, &$what, || $value)
    };
    ($timeout:expr, $what:expr, $value:expr $(,)?) => {
        wait_for!($timeout, every $crate::test_framework::POLL, $what, $value)
    };
}
