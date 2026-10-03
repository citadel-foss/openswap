//! Fidelity bonds: creation and redemption, spending rules, auto-renewal,
//! restarts with an unconfirmed bond, and a bond with an invalid timelock.

mod creation;
mod renewal;
mod restart;
mod spending;
mod timelock_violation;

// Helpers shared by more than one file in this folder; each file reaches them
// through `super::`.

use bitcoin::Txid;
use openswap::maker::{MakerServer, MakerServerConfig};

/// Clone a stopped maker's config for a simulated restart. The first init
/// consumed the passphrase (`config.password.take()`), so re-supply it the
/// way an operator would.
fn maker_restart_config(maker: &MakerServer) -> MakerServerConfig {
    let mut config = maker.config.clone();
    config.password = Some("integration-test".to_string());
    config
}

/// The end state every restart test pins: exactly one bond, with the original
/// txid, and its confirmation recorded (valuation requires it).
fn assert_single_adopted_bond(maker: &MakerServer, bond_txid: Txid) {
    let wallet_read = maker.wallet.read().unwrap();
    let bonds = wallet_read.get_fidelity_bonds();
    assert_eq!(bonds.len(), 1, "restart must not create a second bond");
    assert_eq!(
        bonds[0].outpoint().txid,
        bond_txid,
        "restart must keep the original bond txid"
    );
    assert_eq!(
        wallet_read.get_highest_fidelity_index().unwrap(),
        Some(0),
        "adopted bond must be valuated, i.e. its confirmation was recorded"
    );
}
