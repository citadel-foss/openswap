//! Assertions over the swap reports a wallet holds.

use std::sync::RwLock;

use log::info;
use openswap::wallet::Wallet;

/// Verifies that a wallet holds the expected number of deniability proofs,
/// and that each proof passes on-chain verification.
pub fn assert_wallet_has_deniability_proofs(
    wallet: &RwLock<Wallet>,
    label: &str,
    expected_count: usize,
) {
    let wallet = wallet.read().unwrap();
    // Check what was saved, not what is in memory.
    let proofs = wallet
        .saved_deniability_proofs("integration-test")
        .unwrap_or_else(|e| panic!("{} wallet read failed: {}", label, e));
    assert_eq!(
        proofs,
        wallet.swap_reports().deniability_proofs,
        "{} saved proofs differ from the live wallet",
        label
    );
    assert_eq!(
        proofs.len(),
        expected_count,
        "{} wallet should hold {} deniability proof(s)",
        label,
        expected_count
    );
    for (i, proof) in proofs.iter().enumerate() {
        let verified = wallet
            .verify_deniability(&proof.swap_id)
            .unwrap_or_else(|e| panic!("{} proof {} verification error: {}", label, i, e));
        assert!(
            verified,
            "{} proof {} failed on-chain verification",
            label, i
        );
        info!(
            "{} proof {} verified ok (swap_id={})",
            label, i, proof.swap_id
        );
    }
    info!(
        "{} all {} deniability proof(s) verified",
        label,
        proofs.len()
    );
}
