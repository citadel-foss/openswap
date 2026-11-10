//! Processes die and come back: makers and takers restart from their wallets
//! and must keep, finish or recover what they had in flight. A maker can also
//! wait for its swaps in progress before it stops.

mod legacy_reboot;
mod reboot;
mod stop_after_swaps;
mod successful_swap;
mod taker_restart;
mod watchtower_liveness;
