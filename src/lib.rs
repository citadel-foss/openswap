#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
pub extern crate bitcoin;
pub extern crate bitcoind;

pub mod bip324_stream;
pub mod error;
pub mod fee_estimation;
pub mod maker;
pub mod protocol;
pub mod security;
pub mod taker;
pub mod utill;
pub mod wallet;
pub mod watch_tower;

/// Logs before and after a blocking lock acquisition.
#[macro_export]
macro_rules! lock_debug {
    ($acquire:expr) => {{
        log::debug!(
            target: "lock",
            "WAIT {:?} {}:{} {}",
            std::thread::current().id(),
            file!(),
            line!(),
            stringify!($acquire)
        );
        let guard = $acquire;
        log::debug!(
            target: "lock",
            "GOT  {:?} {}:{} {}",
            std::thread::current().id(),
            file!(),
            line!(),
            stringify!($acquire)
        );
        guard
    }};
}
