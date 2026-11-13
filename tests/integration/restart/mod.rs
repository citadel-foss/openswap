//! Processes die and come back: makers and takers restart from their wallets
//! and must keep, finish or recover what they had in flight.

mod drain_on_stop;
mod legacy_reboot;
mod reboot;
mod successful_swap;
mod taker_restart;
mod watchtower_liveness;
