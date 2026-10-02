//! A party drops or breaches mid-swap, and every party recovers on-chain by
//! hashlock or timelock.

mod contract_breach;
mod electrum;
mod legacy_hashlock;
mod maker_abort;
// `restart::watchtower_liveness` runs its timelock-only recovery body.
pub(crate) mod skip_funding;
mod taker_abort;
