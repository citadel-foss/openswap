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
};

/// Installs the process's logger once: everything goes to `taker/debug.log`
/// under `temp_dir` and to stdout, where each line names the test, e.g.
/// `2026-10-02T17:39:47Z [swap::electrum::taproot_swap_completes] INFO ...`, so
/// output from interleaved tests can be told apart in CI.
///
/// The level is debug unless `OPENSWAP_TEST_LOG` sets one (e.g. `warn`, `off`).
/// The `lock` target's WAIT/GOT traces stay at info at most, since they would
/// otherwise be most of the output; `OPENSWAP_TEST_LOG_LOCKS=debug` brings them
/// back. nextest gives each test its own process; under `cargo test` the first
/// test of the process names every line.
pub(crate) fn setup_test_logger(temp_dir: &Path) {
    static LOGGER: OnceLock<()> = OnceLock::new();
    LOGGER.get_or_init(|| {
        let level_from = |var: &str| env::var(var).ok().and_then(|level| level.parse().ok());
        let level = level_from("OPENSWAP_TEST_LOG").unwrap_or(LevelFilter::Debug);
        let lock_level =
            level_from("OPENSWAP_TEST_LOG_LOCKS").unwrap_or_else(|| level.min(LevelFilter::Info));
        let test = thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .replace('{', "{{")
            .replace('}', "}}");
        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new(&format!(
                "{{d}} [{test}] {{l}} {{t}} - {{m}}{{n}}"
            ))))
            .build();
        let file = FileAppender::builder()
            .build(temp_dir.join("taker").join("debug.log"))
            .expect("the test's debug.log opens");
        let config = Config::builder()
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
            .expect("the test logger config is valid");
        log4rs::init_config(config).expect("no other logger is installed");
    });
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
        thread::sleep(Duration::from_secs(2));
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
        thread::sleep(Duration::from_secs(2));
    }
}
