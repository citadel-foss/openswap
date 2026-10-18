use super::{check, write};
use crate::wallet::{
    check_container, compat_assert_empty_extra, compat_backup, compat_reports, generate_storage,
    swapcoin::{IncomingSwapCoin, OutgoingSwapCoin, WatchOnlySwapCoin},
    DeniabilityProof, FidelityBond, LnMakerSwapRecord, LnPendingSwap, MakerFeeInfo, MakerReport,
    PaymentResult, RecoveryReport, ReportUtxo, SwapReportFile, SwapReservation, TakerReport,
    UTXOSpendInfo, WalletBackup, WalletStore,
};
use bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::ListUnspentResultEntry;
use serde_cbor::value::from_value;
use std::{fs, path::Path};

pub(super) fn check_release(release: &Path) {
    for name in [
        "wallet-store",
        "bond-fidelity",
        "backup-wallet",
        "report-file",
        "coin-incoming-Legacy",
        "coin-incoming-Taproot",
        "coin-outgoing-Legacy",
        "coin-outgoing-Taproot",
        "coin-watchonly-Legacy",
        "coin-watchonly-Taproot",
        "storage-ln-maker-InAccepted",
        "storage-ln-maker-InPaid",
        "storage-ln-maker-InSwept",
        "storage-ln-maker-OutAccepted",
        "storage-ln-maker-OutFunded",
        "storage-ln-pending-true",
        "storage-ln-pending-false",
        "storage-reservation",
        "report-payment",
        "report-fee",
        "report-utxo",
        "report-proof-0",
        "report-proof-1",
    ] {
        assert!(
            release.join(format!("{name}.cbor")).is_file(),
            "missing storage fixture {} in {}",
            name,
            release.display()
        );
    }
    for prefix in [
        "storage-cache",
        "report-taker",
        "report-maker",
        "report-recovery",
    ] {
        let count = match prefix {
            "storage-cache" => 9,
            "report-recovery" => 2,
            _ => 4,
        };
        for index in 0..count {
            assert!(
                release.join(format!("{prefix}-{index}.cbor")).is_file(),
                "missing {} case {} in {}",
                prefix,
                index,
                release.display()
            );
        }
    }
    if release.file_name().unwrap() != "v0.2.3" {
        assert!(
            release.join("wallet-file.cbor").is_file(),
            "missing wallet container in {}",
            release.display()
        );
    }
    for entry in fs::read_dir(release).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "cbor") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap();
        if name == "wallet-file" {
            check_container(release);
        } else if name.starts_with("wallet-") {
            let store: WalletStore = check(release, name);
            compat_assert_empty_extra(&store);
            // Reports are raw inside the store, so check their typed fields too.
            for (kind, values) in &store.reports {
                for value in values {
                    match kind.as_str() {
                        "taker" => {
                            from_value::<TakerReport>(value.clone()).unwrap();
                        }
                        "maker" => {
                            from_value::<MakerReport>(value.clone()).unwrap();
                        }
                        "recovery" => {
                            from_value::<RecoveryReport>(value.clone()).unwrap();
                        }
                        "deniability_proofs" => {
                            from_value::<DeniabilityProof>(value.clone()).unwrap();
                        }
                        _ => panic!("uncovered fixture report kind {}", kind),
                    }
                }
            }
        } else if name.starts_with("bond-") {
            let bond: FidelityBond = check(release, name);
            assert!(bond.extra.is_empty(), "renamed bond fields in {}", name);
        } else if name.starts_with("backup-") {
            let _: WalletBackup = check(release, name);
        } else if name.starts_with("coin-incoming-") {
            let _: IncomingSwapCoin = check(release, name);
        } else if name.starts_with("coin-outgoing-") {
            let _: OutgoingSwapCoin = check(release, name);
        } else if name.starts_with("coin-watchonly-") {
            let _: WatchOnlySwapCoin = check(release, name);
        } else if name.starts_with("storage-cache-") {
            let _: (ListUnspentResultEntry, UTXOSpendInfo) = check(release, name);
        } else if name.starts_with("storage-ln-maker-") {
            let _: LnMakerSwapRecord = check(release, name);
        } else if name.starts_with("storage-ln-pending-") {
            let _: LnPendingSwap = check(release, name);
        } else if name == "storage-reservation" {
            let _: SwapReservation = check(release, name);
        } else if name == "report-file" {
            let _: SwapReportFile = check(release, name);
        } else if name.starts_with("report-taker-") {
            let _: TakerReport = check(release, name);
        } else if name.starts_with("report-maker-") {
            let _: MakerReport = check(release, name);
        } else if name.starts_with("report-recovery-") {
            let _: RecoveryReport = check(release, name);
        } else if name.starts_with("report-proof-") {
            let _: DeniabilityProof = check(release, name);
        } else if name == "report-payment" {
            let _: PaymentResult = check(release, name);
        } else if name == "report-utxo" {
            let _: ReportUtxo = check(release, name);
        } else if name == "report-fee" {
            let _: MakerFeeInfo = check(release, name);
        }
    }
}

pub(super) fn generate(release: &Path) {
    generate_storage(release);
    write(release, "backup-wallet", &compat_backup());
    let report = compat_reports();
    write(release, "report-file", &report);
    for (index, value) in report.taker.iter().enumerate() {
        write(release, &format!("report-taker-{index}"), value);
    }
    for (index, value) in report.maker.values().flatten().enumerate() {
        write(release, &format!("report-maker-{index}"), value);
    }
    for (index, value) in report.recovery.iter().enumerate() {
        write(release, &format!("report-recovery-{index}"), value);
    }
    write(
        release,
        "report-payment",
        report.taker[0].payment.as_ref().unwrap(),
    );
    write(release, "report-utxo", &report.taker[0].outgoing_utxos[0]);
    write(release, "report-fee", &report.taker[0].maker_fee_info[0]);
    // Include both protocol proof bodies stored by the populated wallet sample.
    let store: WalletStore = check(release, "wallet-store");
    let proofs = &store.reports["deniability_proofs"];
    for (index, proof) in proofs.iter().enumerate() {
        let proof: DeniabilityProof = from_value(proof.clone()).unwrap();
        write(release, &format!("report-proof-{index}"), &proof);
    }
}
