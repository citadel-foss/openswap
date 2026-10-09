//! The test logger, and polling log files for expected messages.

use std::{
    env, fs,
    path::Path,
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};

use log::LevelFilter;
use log4rs::{
    append::{console::ConsoleAppender, file::FileAppender},
    config::{Appender, Config, Logger, Root},
    encode::pattern::PatternEncoder,
    Handle,
};

use super::wait::POLL;

/// Points the process's logger at this fixture: everything goes to
/// `taker/debug.log` under `temp_dir` and to stdout, where each line names the
/// test, e.g. `2026-10-02T17:39:47Z [swap::electrum::taproot_swap_completes]
/// INFO ...`, so output from interleaved tests can be told apart in CI.
///
/// The level is debug unless `OPENSWAP_TEST_LOG` sets one (e.g. `warn`, `off`).
/// The `lock` target's WAIT/GOT traces stay at info at most, since they would
/// otherwise be most of the output; `OPENSWAP_TEST_LOG_LOCKS=debug` brings them
/// back.
///
/// The logger is installed once per process and reconfigured for each later
/// fixture, so fixtures that run one after another in a process each get
/// their own log. Fixtures running at the same time in one process share
/// whichever configured it last; nextest gives each test its own process.
pub(crate) fn setup_test_logger(temp_dir: &Path) {
    static LOGGER: OnceLock<Handle> = OnceLock::new();
    let name = thread::current().name().unwrap_or("<unnamed>").to_string();
    // Opens the block `end_test_log_group` closes; see there.
    if in_github_actions() {
        println!("::group::{name}");
    }
    let mut config = Some(test_log_config(&name, temp_dir));
    let handle = LOGGER.get_or_init(|| {
        log4rs::init_config(config.take().expect("the config is unused"))
            .expect("no other logger is installed")
    });
    // Another fixture installed the logger first: switch it to this one.
    if let Some(config) = config {
        handle.set_config(config);
    }
}

/// The logger configuration for the fixture of test `name` under `temp_dir`.
fn test_log_config(name: &str, temp_dir: &Path) -> Config {
    let level_from = |var: &str| env::var(var).ok().and_then(|level| level.parse().ok());
    let level = level_from("OPENSWAP_TEST_LOG").unwrap_or(LevelFilter::Debug);
    let lock_level =
        level_from("OPENSWAP_TEST_LOG_LOCKS").unwrap_or_else(|| level.min(LevelFilter::Info));
    let test = name.replace('{', "{{").replace('}', "}}");
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(&format!(
            "{{d}} [{test}] {{l}} {{t}} - {{m}}{{n}}"
        ))))
        .build();
    let file = FileAppender::builder()
        .build(temp_dir.join("taker").join("debug.log"))
        .expect("the test's debug.log opens");
    Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .appender(Appender::builder().build("file", Box::new(file)))
        .logger(Logger::builder().build("bitcoincore_rpc", LevelFilter::Off))
        .logger(Logger::builder().build("lock", lock_level))
        .build(
            Root::builder()
                .appender("stdout")
                .appender("file")
                .build(level),
        )
        .expect("the test logger config is valid")
}

/// Closes the GitHub Actions group `setup_test_logger` opened. nextest prints a
/// test's captured output as one block, so between the two markers the job log
/// folds that test's lines into one collapsible entry. Outside GitHub Actions
/// it prints nothing.
pub(crate) fn end_test_log_group() {
    if in_github_actions() {
        log::logger().flush();
        println!("::endgroup::");
    }
}

fn in_github_actions() -> bool {
    env::var("GITHUB_ACTIONS").is_ok_and(|value| value == "true")
}

/// Poll a log file until `expected` appears; panics after `timeout`.
#[allow(dead_code)]
#[track_caller]
pub(crate) fn wait_for_log(log_path: &str, expected: &str, timeout: Duration) {
    let start = Instant::now();
    loop {
        if let Ok(contents) = fs::read_to_string(log_path) {
            if contents.contains(expected) {
                log::info!("Found expected log message: '{expected}'");
                return;
            }
        }
        assert!(
            start.elapsed() <= timeout,
            "Timed out waiting for log message '{}' in {}",
            expected,
            log_path
        );
        thread::sleep(POLL);
    }
}

/// Like [`wait_for_log`], but only matches content appended after this call.
/// Use when the needle can already sit in the file from an earlier phase
/// (fidelity-setup sightings look identical to swap-funding sightings).
#[allow(dead_code)]
#[track_caller]
pub(crate) fn wait_for_new_log(log_path: &str, expected: &str, timeout: Duration) {
    let start = Instant::now();
    let offset = fs::metadata(log_path).map(|m| m.len()).unwrap_or(0);
    loop {
        if let Ok(contents) = fs::read_to_string(log_path) {
            if contents
                .get(offset as usize..)
                .is_some_and(|new| new.contains(expected))
            {
                log::info!("Found expected log message: '{expected}'");
                return;
            }
        }
        assert!(
            start.elapsed() <= timeout,
            "Timed out waiting for log message '{}' in {}",
            expected,
            log_path
        );
        thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::test_framework::{BitcoindBackend, Node};

    /// Two fixtures in one process, one after the other: the second still logs
    /// to its own `debug.log` after the first one's directory is gone.
    #[test]
    fn each_fixture_gets_its_own_log() {
        for run in 0..2 {
            let node = Node::builder::<BitcoindBackend>().build();
            let needle = format!("logger probe {run}");
            log::info!("{needle}");
            log::logger().flush();
            let log = fs::read_to_string(node.temp_dir().join("taker").join("debug.log"))
                .expect("this fixture's debug.log exists");
            assert!(
                log.contains(&needle),
                "run {} did not reach its own log",
                run
            );
        }
    }
}

/// One check of [`assert_log!`] against a log.
#[derive(Debug)]
pub enum LogCheck {
    /// The log holds the needle.
    Has(String),
    /// The log does not hold the needle.
    Lacks(String),
    /// The log holds the needle exactly this many times.
    Count(String, usize),
    /// Each needle appears, and each first appears after the one before it.
    Order(Vec<String>),
}

/// The failure line of every check in `checks` that `log` does not satisfy.
pub fn check_log(log: &str, checks: &[LogCheck]) -> Vec<String> {
    checks
        .iter()
        .filter_map(|check| match check {
            LogCheck::Has(needle) => {
                (!log.contains(needle.as_str())).then(|| format!("has    {:?}: not found", needle))
            }
            LogCheck::Lacks(needle) => log
                .contains(needle.as_str())
                .then(|| format!("lacks  {:?}: found", needle)),
            LogCheck::Count(needle, expected) => {
                let got = log.matches(needle.as_str()).count();
                (got != *expected)
                    .then(|| format!("count  {:?}: expected {}, got {}", needle, expected, got))
            }
            LogCheck::Order(needles) => {
                let positions: Vec<Option<usize>> =
                    needles.iter().map(|n| log.find(n.as_str())).collect();
                if let Some(i) = positions.iter().position(Option::is_none) {
                    return Some(format!("order  {:?}: not found", needles[i]));
                }
                let positions: Vec<usize> = positions.into_iter().flatten().collect();
                positions
                    .windows(2)
                    .position(|pair| pair[0] >= pair[1])
                    .map(|i| format!("order  {:?} is not before {:?}", needles[i], needles[i + 1]))
            }
        })
        .collect()
}

/// What [`assert_log!`] reads: a world's shared taker log, or a log file path.
pub trait LogSource {
    fn log_path(&self) -> String;
}

impl LogSource for super::World {
    fn log_path(&self) -> String {
        self.taker_log_path()
    }
}

impl LogSource for str {
    fn log_path(&self) -> String {
        self.to_string()
    }
}

impl LogSource for String {
    fn log_path(&self) -> String {
        self.clone()
    }
}

impl<T: LogSource + ?Sized> LogSource for &T {
    fn log_path(&self) -> String {
        (**self).log_path()
    }
}

impl<T: LogSource + ?Sized> LogSource for &mut T {
    fn log_path(&self) -> String {
        (**self).log_path()
    }
}

/// The log's current length, for `assert_log!(.., since mark; ..)` to check
/// only what is written after it.
#[allow(dead_code)]
pub fn log_mark(source: &impl LogSource) -> u64 {
    fs::metadata(source.log_path())
        .map(|m| m.len())
        .unwrap_or(0)
}

/// Reads `source`'s log once, past `since` when given, and fails with every
/// check it does not satisfy. Never writes to the log it reads.
#[track_caller]
pub fn assert_log(source: &impl LogSource, since: Option<u64>, checks: &[LogCheck]) {
    let path = source.log_path();
    let log = fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {}", path, e));
    let from = since.map_or(0, |mark| mark as usize).min(log.len());
    // A mark can fall inside a multi-byte character; start at the next boundary.
    let from = (from..=log.len())
        .find(|&i| log.is_char_boundary(i))
        .unwrap_or(log.len());
    let failures = check_log(&log[from..], checks);
    assert!(
        failures.is_empty(),
        "log checks failed ({}{}):\n  {}",
        path,
        since.map_or(String::new(), |mark| format!(", past byte {}", mark)),
        failures.join("\n  ")
    );
}

#[cfg(test)]
mod check_tests {
    use super::{check_log, LogCheck::*};

    const LOG: &str =
        "start\nShows no funding broadcast\nFunding was never broadcast\ndone\ndone\n";

    #[test]
    fn passing_checks_report_nothing() {
        let checks = [
            Has("start".into()),
            Lacks("SECURITY".into()),
            Count("done".into(), 2),
            Order(vec!["Shows no funding".into(), "never broadcast".into()]),
        ];
        assert!(check_log(LOG, &checks).is_empty());
    }

    #[test]
    fn every_failing_check_is_reported() {
        let checks = [
            Has("missing".into()),
            Lacks("start".into()),
            Count("done".into(), 1),
            Order(vec!["never broadcast".into(), "Shows no funding".into()]),
            Order(vec!["start".into(), "absent".into()]),
        ];
        let failures = check_log(LOG, &checks);
        assert_eq!(failures.len(), 5, "{:?}", failures);
        assert!(failures[2].contains("expected 1, got 2"));
        assert!(failures[3].contains("is not before"));
        assert!(failures[4].contains("\"absent\": not found"));
    }
}
