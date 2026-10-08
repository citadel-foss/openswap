//! Swaps with funding confirmation waits.
//!
//! Exercise both multiple confirmations and a first confirmation delayed beyond
//! the maker admission deadline. Route heartbeats must preserve swap activity
//! throughout these waits, and protocol sockets must not expire before use.
//!
//! Both protocols are covered: the wait sites differ (`legacy_swap.rs` vs
//! `swap/taproot.rs`) even though the keepalive message is shared.

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{protocol::common_messages::ProtocolVersion, taker::SwapParams};

use crate::test_framework::*;

use log::info;
use std::{
    thread,
    time::{Duration, Instant},
};

/// Confirmations to wait for on every funding tx.
///
/// At the normal five-blocks-per-three-seconds mining cadence, 15 confirmations
/// usually require a polling delay. The paused-mining case below separately
/// forces a wall-clock wait beyond the maker's pending-connection deadline.
const REQUIRED_CONFIRMS: u32 = 15;

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
    cases = [
        legacy_multi_confirm_swap(
            protocol = ProtocolVersion::Legacy,
            delay_first_confirmation = false,
        ),
        taproot_multi_confirm_swap(
            protocol = ProtocolVersion::Taproot,
            delay_first_confirmation = false,
        ),
        legacy_confirmation_wait_exceeds_admission_deadline(
            protocol = ProtocolVersion::Legacy,
            delay_first_confirmation = true,
        ),
        taproot_confirmation_wait_exceeds_admission_deadline(
            protocol = ProtocolVersion::Taproot,
            delay_first_confirmation = true,
        ),
    ],
)]
fn run_multi_confirm_swap(
    world: &mut World,
    protocol: ProtocolVersion,
    delay_first_confirmation: bool,
) {
    let before = world.balances();
    let required_confirms = if delay_first_confirmation {
        1
    } else {
        REQUIRED_CONFIRMS
    };
    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(required_confirms);

    world.mine(1);

    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Failed to prepare openswap");
    let log_path = world.taker_log_path();
    let swap_result = if delay_first_confirmation {
        // The miner thread holds its own handle on the framework, so the swap
        // below can borrow the taker mutably.
        let test_framework = world.framework().clone();
        let bitcoind = &test_framework.bitcoind;
        test_framework.set_block_gen_paused(true);
        // Let any in-flight mining tick finish before broadcasting funding.
        thread::sleep(Duration::from_secs(4));
        let mempool_before = bitcoind.client.get_raw_mempool().unwrap();
        thread::scope(|scope| {
            let miner = scope.spawn(|| {
                // Resume mining even if an assertion fails, so the swap thread
                // cannot remain blocked in its confirmation wait during unwind.
                struct ResumeMining<'a>(&'a TestFramework);
                impl Drop for ResumeMining<'_> {
                    fn drop(&mut self) {
                        self.0.set_block_gen_paused(false);
                    }
                }
                let _resume = ResumeMining(&test_framework);
                let deadline = Instant::now() + Duration::from_secs(120);
                let funding_txids = loop {
                    let new_txids: Vec<_> = bitcoind
                        .client
                        .get_raw_mempool()
                        .unwrap()
                        .into_iter()
                        .filter(|txid| !mempool_before.contains(txid))
                        .collect();
                    if new_txids.len() == 3 {
                        break new_txids;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "funding never reached the mempool"
                    );
                    thread::sleep(Duration::from_millis(100));
                };
                let height = bitcoind.client.get_block_count().unwrap();
                info!("Holding taker funding unconfirmed for 30 seconds at height {height}");
                // The maker's pending connection deadline is 20 seconds in
                // both production and tests. Cross it with funding unconfirmed.
                thread::sleep(Duration::from_secs(30));
                assert_eq!(bitcoind.client.get_block_count().unwrap(), height);
                let mempool = bitcoind.client.get_raw_mempool().unwrap();
                assert!(funding_txids.iter().all(|txid| mempool.contains(txid)));
            });
            let result = world.taker_mut().start(&summary.swap_id);
            miner.join().expect("delayed miner panicked");
            result
        })
    } else {
        world.taker_mut().start(&summary.swap_id)
    };
    swap_result.expect("OpenSwap should complete successfully despite the longer funding wait");

    info!("OpenSwap completed with required_confirms = {required_confirms}");

    world.shutdown_makers();

    world.taker().sync();
    world.mine(1);
    world.sync_makers();

    // Verify the requested confirmation count and that route heartbeats ran.
    world.framework().assert_log(
        &format!("Waiting for {required_confirms} confirmation(s)"),
        &log_path,
    );
    world
        .framework()
        .assert_log("Taker is waiting for funding confirmation", &log_path);

    // Waiting longer must not change what the swap costs.
    let (taker_swap, taker_loss, maker_regular, maker_swap) = match protocol {
        ProtocolVersion::Legacy => (496_447, 4_015, [14_500_865, 14_502_398], [499_550, 497_980]),
        ProtocolVersion::Taproot => (496_789, 3_673, [14_500_751, 14_502_170], [499_664, 498_208]),
    };
    assert_balances!(world, since before; {
        taker: { regular: 14_499_538, swap: taker_swap, contract: 0, fidelity: 0, loss: taker_loss },
        makers: {
            regular: maker_regular,
            swap: maker_swap,
            contract: 0,
            fidelity: BOND,
            gain: [658, 621],
        },
    });

    info!("Multi-confirmation swap test completed successfully!");
}
