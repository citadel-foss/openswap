#![cfg(feature = "integration-test")]

#[macro_use]
mod test_framework;

mod abort1;
mod abort2_case1;
mod abort2_case2;
mod abort2_case3;
mod abort3_case1;
mod abort3_case2;
mod abort3_case3;
mod electrum_abort1;
mod electrum_list_transactions;
mod electrum_swap;
mod electrum_tor;
mod electrum_transport;
mod fidelity;
mod fidelity_renewal;
mod fidelity_timelock_violation;
mod maker_cli;
mod malice1;
mod malice2;
mod mixed_protocol_concurrent_swaps;
mod multi_confirm_swap;
mod multi_taker;
mod payswap;
mod reboot_recovery;
mod skip_funding_recovery;
mod standard_swap;
mod taproot_hashlock_recovery;
mod taproot_maker_abort1;
mod taproot_maker_abort2;
mod taproot_maker_abort3;
mod taproot_maker_malice;
mod taproot_multi_maker;
mod taproot_multi_taker;
mod taproot_per_hop_splits;
mod taproot_swap;
mod taproot_taker_abort1;
mod taproot_taker_abort2;
mod taproot_taker_abort3;
mod taproot_timelock_recovery;
mod wallet_backup;
mod watchtower_liveness;

mod concurrent_takers;
mod legacy_hashlock_recovery;
mod legacy_reboot_recovery;
mod offerbook_restart;
mod offerbook_sync_race;
mod rejection;
mod taker_cli;
mod taker_restart_recovery;
mod utxo_behavior;
