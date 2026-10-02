#![cfg(feature = "integration-test")]

#[macro_use]
mod test_framework;

mod blocklist_rejection;
mod broadcast_idempotency;
mod contract_breach;
mod electrum_list_transactions;
mod electrum_recovery;
mod electrum_swap;
mod electrum_transport;
mod fidelity;
mod fidelity_renewal;
mod fidelity_timelock_violation;
mod finalization_timeout;
mod maker_abort;
mod maker_cli;
mod malice1;
mod mixed_protocol_concurrent_swaps;
mod multi_confirm_swap;
mod multi_taker;
mod payswap;
mod reboot_recovery;
mod skip_funding_recovery;
mod spare_maker;
mod spare_maker_pricing;
mod standard_swap;
mod successful_swap_restart;
mod taker_abort;
mod taproot_maker_abort1;
mod taproot_maker_malice;
mod taproot_multi_maker;
mod taproot_swap;
mod taproot_taker_abort1;
mod wallet_backup;
mod watchtower_liveness;

mod concurrent_takers;
mod legacy_contract_breach;
mod legacy_hashlock_recovery;
mod legacy_reboot_recovery;
#[cfg(feature = "lightning")]
mod lightning_e2e;
#[cfg(feature = "lightning")]
mod lightning_maker_restart;
#[cfg(feature = "lightning")]
mod lightning_offer_limits;
#[cfg(feature = "lightning")]
mod lightning_routed;
#[cfg(feature = "lightning")]
mod lightning_swap_in;
#[cfg(feature = "lightning")]
mod lightning_swap_out;
mod offerbook_restart;
mod offerbook_sync_race;
mod rejection;
mod taker_cli;
mod taker_restart_recovery;
mod utxo_behavior;
