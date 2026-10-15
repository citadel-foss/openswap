//! A timelock refund stuck in the mempool is fee-bumped by BIP125 replacement
//! as fees rise, on both backends.
//!
//! The second maker drops once funding is on chain, so the taker refunds its
//! outgoing coin by timelock. Mining stops just before that refund goes out.
//! Recovery passes only on a new block, so the test mines empty ones to keep
//! the refund stuck, and restarts the taker to free a pass parked in its wait.

use bitcoin::{Amount, OutPoint, Txid};
use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, Taker},
};

use crate::test_framework::*;

use log::info;
use std::{fs, thread, time::Duration};

/// Recovery reads its fee estimate from here in test builds: regtest has none.
const FEERATE_ENV: &str = "OPENSWAP_RECOVERY_FEERATE";

/// Names the feerate recovery sees, and clears it on drop so it cannot leak
/// into another test in this process.
struct FeerateOverride;

impl FeerateOverride {
    fn set(&self, sat_per_vb: u64) {
        std::env::set_var(FEERATE_ENV, sat_per_vb.to_string());
    }
}

impl Drop for FeerateOverride {
    fn drop(&mut self) {
        std::env::remove_var(FEERATE_ENV);
    }
}

/// The mempool tx spending `outpoint`, straight from bitcoind.
fn mempool_spender(bitcoind: &BitcoinD, outpoint: &OutPoint) -> Option<Txid> {
    let spends: serde_json::Value = bitcoind
        .client
        .call(
            "gettxspendingprevout",
            &[serde_json::json!([{ "txid": outpoint.txid, "vout": outpoint.vout }])],
        )
        .unwrap();
    spends[0]["spendingtxid"]
        .as_str()
        .map(|txid| txid.parse().unwrap())
}

/// Every `(old, new)` pair the taker logged as a replaced refund.
fn logged_replacements(log_path: &str) -> Vec<(Txid, Txid)> {
    fs::read_to_string(log_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let rest = line.split_once("Replaced timelock recovery tx ")?.1;
            let (old, rest) = rest.split_once(" with ")?;
            let new = rest.split_once(' ')?.0;
            Some((old.parse().ok()?, new.parse().ok()?))
        })
        .collect()
}

/// Starts a fresh taker on the same wallet: its startup pass and recovery
/// loop run while the previous loop's pass would still be waiting.
fn restart_taker<B: TestBackend>(world: &mut World) {
    world.drop_takers();
    thread::sleep(Duration::from_secs(5));
    let taker = Taker::init(world.framework().taker_init_config::<B>(0))
        .expect("restarted taker should open the same wallet");
    world.adopt_taker(taker);
}

/// Follows a stuck timelock refund through its fee bumps on a real node.
///
/// `full` adds the checks the Electrum backend is tested for: no bump while
/// fees are flat, a second bump, and silence once the refund confirms.
#[world_test(
    maker_behaviors = [Normal, closing],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120)],
    cases = [
        /// Real electrs must hide a contract output its mempool spends, or the
        /// bump never fires: the unit tests only assume it does.
        electrum_bumps_a_stuck_taproot_refund(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Taproot,
            closing = MakerBehavior::CloseAtContractSigsExchange,
            full = true,
            expected_loss = 1845,
        ),
        /// Real electrs must hide a contract output its mempool spends, or the
        /// bump never fires: the unit tests only assume it does.
        electrum_bumps_a_stuck_legacy_refund(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
            closing = MakerBehavior::CloseAtContractSigsForRecvrAndSender,
            full = true,
            expected_loss = 2019,
        ),
        /// Core finds the pending refund through `gettxspendingprevout`, not
        /// through the script history Electrum reads, so the bump is checked
        /// here too.
        core_bumps_a_stuck_taproot_refund(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Taproot,
            closing = MakerBehavior::CloseAtContractSigsExchange,
            full = false,
            expected_loss = 865,
        ),
    ],
)]
fn run_refund_fee_bump<B: TestBackend>(
    world: &mut World,
    protocol: ProtocolVersion,
    full: bool,
    expected_loss: u64,
) {
    // A handle of its own: the taker is dropped and restarted mid-test.
    let framework = world.framework().clone();
    let bitcoind = &framework.bitcoind;
    let feerate = FeerateOverride;
    let before = world.balances();

    // One outgoing coin, so the test follows exactly one refund.
    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count(1)
        .with_required_confirms(1);
    world.mine(1);
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    let swap_error = world
        .taker_mut()
        .start(&summary.swap_id)
        .expect_err("Swap should fail once the second maker closes");
    info!("Swap failed as expected: {swap_error:?}");

    let log_path = world.taker_log_path();
    let refund_targets = |world: &World| {
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .outgoing_refund_targets()
    };
    let targets = refund_targets(world);
    assert_eq!(targets.len(), 1, "expected one outgoing swapcoin");
    let (contract, timelock, _) = targets[0].clone();
    let timelock = i64::from(timelock.expect("outgoing coin has a timelock"));

    // ---- 1. The refund gets stuck ----
    // Taproot locks to a height; Legacy to confirmations of the contract tx,
    // which recovery broadcasts first.
    let blocks_left = || match protocol {
        ProtocolVersion::Taproot => {
            Some(timelock - bitcoind.client.get_block_count().unwrap() as i64)
        }
        ProtocolVersion::Legacy => bitcoind
            .client
            .get_raw_transaction_info(&contract.txid, None)
            .ok()
            .and_then(|info| info.confirmations)
            .map(|confirmations| timelock - i64::from(confirmations)),
    };
    // Stop the miner a few ticks short of the timelock, then step onto it by
    // hand: the refund goes out with nothing left to confirm it.
    wait_for!(
        Duration::from_secs(400),
        every Duration::from_millis(200),
        "the timelock to come close",
        blocks_left().filter(|left| *left <= 15)
    );
    framework.set_block_gen_paused(true);
    // A tick already under way may still land.
    thread::sleep(B::block_cadence().1 + Duration::from_secs(1));
    let left = blocks_left().unwrap();
    if left > 0 {
        generate_blocks(bitcoind, left as u64);
    }
    framework.wait_for_electrs_tip();

    let first = wait_for!(
        Duration::from_secs(120),
        every Duration::from_millis(200),
        "the refund to reach the mempool",
        mempool_spender(bitcoind, &contract)
    );
    let first_fee = bitcoind.client.get_mempool_entry(&first).unwrap().fees.base;
    assert_eq!(
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count(),
        1,
        "the outgoing swapcoin must stay while its refund is unconfirmed"
    );
    let recovery_script = refund_targets(world)[0]
        .2
        .clone()
        .expect("a broadcast refund saves its address")
        .assume_checked()
        .script_pubkey();
    let pays_saved_address = |txid: &Txid| {
        let tx = bitcoind.client.get_raw_transaction(txid, None).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output, contract);
        assert!(
            tx.input[0].sequence.is_rbf(),
            "refund {} must signal RBF",
            txid
        );
        assert_eq!(tx.output.len(), 1);
        assert_eq!(
            tx.output[0].script_pubkey, recovery_script,
            "refund {} must pay the saved recovery address",
            txid
        );
    };
    pays_saved_address(&first);

    // A bump shows as a logged replacement of `old`, now in the mempool.
    let wait_for_bump = |old: Txid| {
        let new = wait_for!(
            Duration::from_secs(120),
            every Duration::from_millis(200),
            "the refund to be replaced",
            logged_replacements(&log_path)
                .into_iter()
                .find(|(replaced, _)| *replaced == old)
                .map(|(_, new)| new)
        );
        assert_eq!(mempool_spender(bitcoind, &contract), Some(new));
        assert!(
            bitcoind.client.get_mempool_entry(&old).is_err(),
            "replaced refund {} must leave the mempool",
            old
        );
        pays_saved_address(&new);
        new
    };

    // ---- 2. No bump while fees stay flat ----
    restart_taker::<B>(world);
    if full {
        // Several recovery passes run in this window.
        thread::sleep(Duration::from_secs(35));
        assert_eq!(mempool_spender(bitcoind, &contract), Some(first));
        assert!(logged_replacements(&log_path).is_empty());
    }

    // Recovery passes only on a new block. An empty one leaves the refund
    // stuck, as when fees rise faster than it can confirm.
    let mine_empty_block = || {
        let miner = bitcoind
            .client
            .get_new_address(None, None)
            .unwrap()
            .assume_checked();
        let _: serde_json::Value = bitcoind
            .client
            .call(
                "generateblock",
                &[serde_json::json!(miner.to_string()), serde_json::json!([])],
            )
            .unwrap();
        framework.wait_for_electrs_tip();
    };

    // ---- 3. A bump once fees rise ----
    feerate.set(5);
    mine_empty_block();
    let mut latest = wait_for_bump(first);
    let entry = bitcoind.client.get_mempool_entry(&latest).unwrap();
    assert!(
        entry.fees.base >= first_fee + Amount::from_sat(entry.vsize),
        "replacement fee {} must beat {} by 1 sat/vB over {} vB",
        entry.fees.base,
        first_fee,
        entry.vsize
    );

    // ---- 4. A second bump works too ----
    if full {
        // The pass that bumped now waits on that refund; a restart frees the
        // loop. Its startup pass runs at the old rate, so it has nothing to bump.
        restart_taker::<B>(world);
        feerate.set(12);
        mine_empty_block();
        latest = wait_for_bump(latest);
    }
    let bumps = logged_replacements(&log_path).len();

    // ---- 5. It confirms and settles ----
    framework.set_block_gen_paused(false);
    wait_until!(
        Duration::from_secs(180),
        every Duration::from_millis(200),
        "recovery to complete",
        world.taker().inner().is_recovery_complete()
    );
    generate_blocks(bitcoind, 1);
    framework.wait_for_electrs_tip();
    world.taker().sync();
    let confirmations = bitcoind
        .client
        .get_raw_transaction_info(&latest, None)
        .unwrap()
        .confirmations;
    assert!(
        confirmations.is_some_and(|c| c > 0),
        "the latest replacement {} must confirm",
        latest
    );
    assert_eq!(
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count(),
        0
    );
    assert_balances!(world, since before; {
        taker: { contract: 0, loss: expected_loss },
    });

    // ---- 6. Nothing happens after that ----
    if full {
        thread::sleep(Duration::from_secs(30));
        assert_eq!(logged_replacements(&log_path).len(), bumps);
        assert_eq!(mempool_spender(bitcoind, &contract), None);
    }
}
