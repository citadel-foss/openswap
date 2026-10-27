//! Assertions over the swap reports a wallet holds.

use std::{
    sync::RwLock,
    thread,
    time::{Duration, Instant},
};

use log::info;
use openswap::wallet::Wallet;

/// Verifies that a wallet holds the expected number of deniability proofs,
/// and that each proof passes on-chain verification.
///
/// The maker writes the proof after the taker's `swap` call has returned, so
/// poll until the save lands. A slow runner otherwise reads an empty file.
pub fn assert_wallet_has_deniability_proofs(
    wallet: &RwLock<Wallet>,
    label: &str,
    expected_count: usize,
) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let proofs = loop {
        let guard = wallet.read().unwrap();
        let saved = guard
            .saved_deniability_proofs("integration-test")
            .unwrap_or_else(|e| panic!("{} wallet read failed: {}", label, e));
        let live = guard.swap_reports().deniability_proofs;
        drop(guard);
        if saved.len() == expected_count && saved == live {
            break saved;
        }
        if Instant::now() >= deadline {
            assert_eq!(
                saved, live,
                "{label} saved proofs differ from the live wallet"
            );
            assert_eq!(
                saved.len(),
                expected_count,
                "{label} wallet should hold {expected_count} deniability proof(s)"
            );
            break saved;
        }
        thread::sleep(Duration::from_millis(50));
    };
    let guard = wallet.read().unwrap();
    for (i, proof) in proofs.iter().enumerate() {
        let verified = guard
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
