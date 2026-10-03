//! The taker's offerbook: removals that survive a restart, and repeated
//! manual syncs while makers come online in stages.

mod restart;
mod sync_race;
