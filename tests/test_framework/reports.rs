//! Assertions over swap report files.

use std::fs;

use bitcoind::{bitcoincore_rpc::Auth, BitcoinD};

use log::info;
use openswap::wallet::{verify_deniability, AnyBlockchain, CoreRPC, CoreRpcConfig};

/// Verifies that a swap report file contains the expected number of deniability proofs,
/// and that each proof passes on-chain verification.
pub fn assert_report_has_deniability_proofs(
    report_path: &std::path::Path,
    label: &str,
    bitcoind: &BitcoinD,
    expected_count: usize,
) {
    let content = fs::read_to_string(report_path)
        .unwrap_or_else(|e| panic!("Failed to read {} report: {}", label, e));
    let json: serde_json::Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {} report: {}", label, e));
    let proofs = json
        .get("deniability_proofs")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("{} report is missing deniability_proofs", label));
    assert_eq!(
        proofs.len(),
        expected_count,
        "{} report should contain {} deniability proof(s) at {}",
        label,
        expected_count,
        report_path.display()
    );
    let rpc_config = CoreRpcConfig {
        url: bitcoind.rpc_url().split_at(7).1.to_string(),
        auth: Auth::CookieFile(bitcoind.params.cookie_file.clone()),
        ..Default::default()
    };
    let blockchain = AnyBlockchain::CoreRPC(
        CoreRPC::new(&rpc_config).expect("failed to connect blockchain backend for verification"),
    );
    for (i, proof_value) in proofs.iter().enumerate() {
        let swap_id = proof_value
            .get("swap_id")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{} proof {} is missing swap_id", label, i));
        let verified = verify_deniability(report_path, &blockchain, swap_id)
            .unwrap_or_else(|e| panic!("{} proof {} verification error: {}", label, i, e));
        assert!(
            verified,
            "{} proof {} failed on-chain verification",
            label, i
        );
        info!("{} proof {} verified ok (swap_id={})", label, i, swap_id);
    }
    info!(
        "{} all {} deniability proof(s) verified: {}",
        label,
        proofs.len(),
        report_path.display()
    );
}
