//! Swaps that complete: the standard routes, Taproot and multi-maker routes,
//! concurrent and multi-taker swaps, payswaps, spare-maker substitution, and a
//! route with too few makers.

mod concurrent_takers;
mod electrum;
mod finalization;
mod mixed_protocol;
mod multi_confirm;
mod multi_maker;
mod multi_taker;
mod payswap;
mod spare_maker;
mod spare_pricing;
mod standard;
mod taproot;
mod too_few_makers;
