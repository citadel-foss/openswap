//! Multi-maker swap over Taproot.
//!
//! Setup: 1 taker and 4 makers, all Normal; Taproot (MuSig2), P2TR.
//! The taker routes one swap through all 4 makers.

use std::{path::Path, time::Duration};

use bitcoin::Amount;
use openswap::{protocol::common_messages::ProtocolVersion, taker::SwapParams};

use crate::test_framework::*;

use log::info;

#[world_test(
    backend = BitcoindBackend,
    makers = 4,
    takers = [Normal],
    setup = [
        // Fund the taker with 5 UTXOs of 0.05 BTC each (P2TR for Taproot)
        // Need more UTXOs for a 4-maker route
        fund_taker_default(5),
        // Fund makers with 4 UTXOs of 0.05 BTC each
        fund_makers_default(),
        // Start the makers, wait for their setup, then sync their wallets so the
        // fidelity bonds are accounted for
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
)]
fn taproot_four_maker_swap_completes(world: &mut World) {
    let before = world.balances();

    // Swap params for openswap (Taproot) with 4 makers
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 4)
        .with_tx_count(3)
        .with_required_confirms(1);

    // Mine some blocks before the swap to ensure wallet is ready
    world.mine(1);

    // Prepare the swap (negotiate with makers, get fee summary)
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Failed to prepare Taproot openswap with 4 makers");
    log::info!("Swap summary: {:?}", summary);

    // Execute the swap
    match world.taker_mut().start(&summary.swap_id) {
        Ok(report) => {
            log::info!("OpenSwap (Taproot, 4 makers) completed successfully!");
            log::info!("Swap report: {:?}", report);
        }
        Err(e) => {
            log::error!("OpenSwap (Taproot, 4 makers) failed: {:?}", e);
            panic!("OpenSwap (Taproot, 4 makers) failed: {:?}", e);
        }
    }

    log::info!("All openswaps processed successfully. Transaction complete.");

    // Sync wallets and verify results
    world.taker().sync();

    // Mine a block to confirm the sweep transactions
    world.mine(1);

    world.sync_makers();

    // Verify all 4 makers earned fees.
    assert_balances!(world, since before; {
        taker: { spendable: 24_993_271, contract: 0, fidelity: 0, loss: 6_729 },
        makers: {
            regular: [14_501_321, 14_502_814, 14_504_270, 14_505_688],
            swap: [499_169, 497_638, 496_145, 494_689],
            contract: 0,
            fidelity: BOND,
            gain: [733, 695, 658, 620],
        },
    });

    info!("All multi-maker swap tests (Taproot, 4 makers) completed successfully!");
}

/// Each maker's fee in the summary and in the report must be priced on that
/// maker's own negotiated amount. A running amount seeded from maker 0 misses
/// the funding and sweep fees each hop loses, so it overprices later makers.
#[world_test(
    backend = BitcoindBackend,
    makers = 2,
    // A 1% amount fee on the second maker turns a basis error of a few hundred
    // sats into a visible fee error.
    fee_overrides = vec![
        None,
        Some(MakerFeeOverride {
            base_fee: 500,
            amount_relative_fee_pct: 1.0,
        }),
    ],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
)]
fn taproot_fees_priced_on_each_makers_amount(world: &mut World) {
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_required_confirms(1);
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Failed to prepare Taproot swap with 2 makers");
    let report = world
        .taker_mut()
        .start(&summary.swap_id)
        .expect("Taproot swap with 2 makers failed");

    assert_eq!(summary.makers.len(), 2);
    assert_eq!(report.maker_fee_info.len(), 2);
    for (i, quoted) in summary.makers.iter().enumerate() {
        let maker = world
            .makers()
            .iter()
            .find(|maker| {
                quoted
                    .address
                    .ends_with(&format!(":{}", maker.inner().config.network_port))
            })
            .unwrap_or_else(|| panic!("no maker serves route address {}", quoted.address));

        // The maker records what it was declared and the fee it charged on it.
        let maker_report = wait_for_maker_report(&maker.report_path(), &summary.swap_id);
        let negotiated = maker_report["incoming_amount"].as_u64().unwrap();
        let fee_earned = maker_report["fee_earned"].as_u64().unwrap();
        info!("Maker {i}: negotiated {negotiated} sats, fee earned {fee_earned} sats");

        assert_eq!(
            quoted.estimated_fee_sats, fee_earned,
            "Maker {} summary fee is not priced on its negotiated amount",
            i
        );

        let priced = |pct: f64| (pct * negotiated as f64 / 100.0).ceil();
        let reported = &report.maker_fee_info[i];
        assert_eq!(
            reported.amount_relative_fee,
            priced(quoted.amount_relative_fee_pct),
            "Maker {} report amount fee is not priced on its negotiated amount",
            i
        );
        assert_eq!(
            reported.time_relative_fee,
            priced(quoted.time_relative_fee_pct * quoted.locktime as f64),
            "Maker {} report time fee is not priced on its negotiated amount",
            i
        );
    }
}

/// Waits for the maker's success report for `swap_id`; the maker writes it
/// after its own sweep, which can land after the taker returns.
fn wait_for_maker_report(path: &Path, swap_id: &str) -> serde_json::Value {
    wait_for!(
        Duration::from_secs(120),
        every Duration::from_secs(1),
        format!("maker report for {} at {}", swap_id, path.display()),
        std::fs::read_to_string(path)
            .ok()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
            .and_then(|file| {
                file["maker"]
                    .as_object()?
                    .values()
                    .filter_map(|reports| reports.as_array())
                    .flatten()
                    .find(|report| report["swap_id"] == swap_id)
                    .cloned()
            })
    )
}
