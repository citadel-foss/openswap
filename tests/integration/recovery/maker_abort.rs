//! Two makers; Maker2 breaks off at a given step once funding is on-chain, and
//! every party falls back to on-chain recovery.
//!
//! Route: Taker -> Maker1 (Normal) -> Maker2 (the case's behavior) -> Taker.
//! Funding is broadcast and confirmed, Maker2 drops, the taker recovers, and
//! once the timelocks mature every wallet is checked against its golden
//! balances.
//!
//! The cases of [`run_maker_abort_recovery`] differ in data alone;
//! `taproot_drop_at_private_key_handover` and `taproot_drop_at_contract_sigs_exchange` run the same
//! three [`MakerAbort`] stages with their own checks in between.

use bitcoin::{Amount, Sequence, Txid};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    maker::MakerBehavior, protocol::common_messages::ProtocolVersion, taker::SwapParams,
};

use crate::test_framework::*;

use log::info;
use std::{fs, thread, time::Duration};

/// The balances one maker-abort test asserts once recovery is done.
struct MakerAbortExpect {
    taker_regular: u64,
    taker_swap: u64,
    /// Taker funding minus its final spendable balance.
    taker_loss: u64,
    maker_regular: [u64; 2],
    maker_swap: [u64; 2],
    /// `None` where the test asserts nothing about the makers' spendable balance.
    maker_spendable: Option<[u64; 2]>,
}

/// Runs the three [`MakerAbort`] stages back to back.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, behavior],
    takers = [Normal],
    cases = [
        /// Maker drops at ProofOfFunding after funding. Recovery via timelock.
        legacy_drop_at_proof_of_funding(
            protocol = ProtocolVersion::Legacy,
            behavior = MakerBehavior::CloseAtProofOfFunding,
            failure = "Swap should fail due to Maker2 closing at ProofOfFunding",
            expected = &MakerAbortExpect {
                taker_regular: 14998662,
                taker_swap: 0,
                taker_loss: 1338,
                maker_regular: [14998419, 14999757],
                maker_swap: [0, 0],
                maker_spendable: None,
            },
        ),
        /// Maker drops at RespContractSigsForRecvrAndSender after funding. Recovery via timelock.
        legacy_drop_at_contract_sigs_for_recvr_and_sender(
            protocol = ProtocolVersion::Legacy,
            behavior = MakerBehavior::CloseAtContractSigsForRecvrAndSender,
            failure = "Swap should fail due to Maker2 closing at RespContractSigsForRecvrAndSender",
            expected = &MakerAbortExpect {
                taker_regular: 14998662,
                taker_swap: 0,
                taker_loss: 1338,
                maker_regular: [14998419, 14999757],
                maker_swap: [0, 0],
                maker_spendable: None,
            },
        ),
        /// Maker drops at ReqContractSigsForRecvr after funding. Recovery via timelock.
        legacy_drop_at_contract_sigs_for_recvr(
            protocol = ProtocolVersion::Legacy,
            behavior = MakerBehavior::CloseAtContractSigsForRecvr,
            failure = "Swap should fail due to Maker2 closing at ReqContractSigsForRecvr",
            expected = &MakerAbortExpect {
                taker_regular: 14499538,
                taker_swap: 495997,
                taker_loss: 4465,
                maker_regular: [14500865, 14502398],
                maker_swap: [499100, 497530],
                maker_spendable: Some([14999965, 14999928]),
            },
        ),
        /// Maker drops at hash preimage handover. Recovery via timelock.
        legacy_drop_at_hash_preimage(
            protocol = ProtocolVersion::Legacy,
            behavior = MakerBehavior::CloseAtHashPreimage,
            failure = "Swap should fail due to Maker2 closing at hash preimage handover",
            expected = &MakerAbortExpect {
                taker_regular: 14499538,
                taker_swap: 495997,
                taker_loss: 4465,
                maker_regular: [14500865, 14502398],
                maker_swap: [499550, 497530],
                maker_spendable: Some([15000415, 14999928]),
            },
        ),
        /// Maker drops after sweep (Taproot). Recovery via hashlock/timelock.
        taproot_drop_after_sweep(
            protocol = ProtocolVersion::Taproot,
            behavior = MakerBehavior::CloseAfterSweep,
            failure = "Swap should fail due to Maker2 closing after sweep",
            expected = &MakerAbortExpect {
                taker_regular: 14499538,
                taker_swap: 496660,
                taker_loss: 3802,
                maker_regular: [14500751, 14502170],
                maker_swap: [499664, 498208],
                maker_spendable: Some([15000415, 15000378]),
            },
        ),
    ],
)]
fn run_maker_abort_recovery(
    world: &mut World,
    protocol: ProtocolVersion,
    failure: &str,
    expected: &MakerAbortExpect,
) {
    let abort = MakerAbort::fail_swap(world, protocol, failure);
    abort.recover();
    abort.assert_recovered(expected);
}

/// A world whose swap Maker2 has just broken off.
struct MakerAbort<'w> {
    world: &'w mut World,
    taker_original_balance: Amount,
    tracker_logger: TrackerLoggerHandle,
}

impl<'w> MakerAbort<'w> {
    /// Runs a Taker -> Maker1 -> Maker2 swap over `protocol` on a world whose
    /// Maker2 breaks off, and asserts it fails, with `failure` as the message.
    fn fail_swap(world: &'w mut World, protocol: ProtocolVersion, failure: &str) -> Self {
        // Fund the taker with 3 UTXOs of 0.05 BTC each
        let taker_original_balance = world.fund_taker_default(3);

        // Fund the makers with 4 UTXOs of 0.05 BTC each
        world.fund_makers_default();

        log::info!("Starting Maker servers...");
        world.start_makers(120);

        // Use post-fidelity, pre-swap balances as the correct baseline
        world.verify_maker_pre_swap_balances();

        // Start periodic swap tracker logging (every 10s)
        let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

        let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
            .with_tx_count(3)
            .with_required_confirms(1);

        world.mine(1);

        // Prepare should succeed; execution should fail because Maker2 drops
        let summary = world
            .taker_mut()
            .prepare(swap_params)
            .expect("Prepare should succeed");
        let swap_result = world.taker_mut().start(&summary.swap_id);
        assert!(swap_result.is_err(), "{}", failure);
        info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

        MakerAbort {
            world,
            taker_original_balance,
            tracker_logger,
        }
    }

    fn world(&self) -> &World {
        self.world
    }

    /// Waits out the timelocks, asserts both makers recovered their
    /// contracts, then waits for the taker's recovery loop.
    fn recover(&self) {
        let world = &*self.world;
        world.taker().log_tracker_state();

        // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
        // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
        // 5 blocks/3s; remaining ~105s is scheduling margin.
        info!("Waiting for makers to timeout and blocks to mature timelocks...");
        thread::sleep(Duration::from_secs(300));

        world.assert_makers_contract_zero();

        // The background recovery loop (spawned by recover_active_swap) periodically
        // retries hashlock sweeps and timelock recovery. Wait for it to finish.
        info!("Waiting for background recovery loop to complete...");
        world.taker().await_recovery(Duration::from_secs(120));
        info!("Background recovery loop completed.");
    }

    /// Mines the recovery txs, asserts the taker's and then each maker's
    /// balances, and shuts the makers down.
    fn assert_recovered(self, expected: &MakerAbortExpect) {
        let MakerAbort {
            world,
            taker_original_balance,
            tracker_logger,
        } = self;

        // Mine a block to confirm recovery txs, then sync wallet
        world.mine(1);
        world.taker().sync();

        let taker_balances = world.taker().balances();
        info!(
            "Taker balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            taker_balances.regular,
            taker_balances.swap,
            taker_balances.contract,
            taker_balances.spendable,
        );
        BalanceExpect {
            regular: Some(Is::Sats(expected.taker_regular)),
            swap: Some(Is::Sats(expected.taker_swap)),
            contract: Some(Is::Sats(0)),
            fidelity: Some(Is::Amount(Amount::ZERO)),
            spendable: None,
            delta: Some(Delta::Loss {
                baseline: taker_original_balance,
                style: DiffStyle::UnwrapOrZero,
                sats: expected.taker_loss,
            }),
        }
        .assert("Taker", &taker_balances);

        for (i, maker) in world.makers().iter().enumerate() {
            maker.sync();
            let balances = maker.balances();
            info!(
                "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
                i,
                balances.regular,
                balances.swap,
                balances.contract,
                balances.fidelity,
                balances.spendable,
            );
            BalanceExpect {
                regular: Some(Is::Sats(expected.maker_regular[i])),
                swap: Some(Is::Sats(expected.maker_swap[i])),
                contract: Some(Is::Sats(0)),
                fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
                spendable: expected
                    .maker_spendable
                    .map(|spendable| Is::Sats(spendable[i])),
                delta: None,
            }
            .assert(&format!("Maker {i}"), &balances);
        }

        world.taker().log_tracker_state();

        world.shutdown_makers();
        tracker_logger.stop();
    }
}

/// Test: Maker drops at private key handover phase (Taproot). Recovery via timelock.
/// Test: Maker drops at private key handover phase (Taproot). Recovery via timelock.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAtPrivateKeyHandover],
    takers = [Normal],
)]
fn taproot_drop_at_private_key_handover(world: &mut World) {
    let abort = MakerAbort::fail_swap(
        world,
        ProtocolVersion::Taproot,
        "Swap should fail due to Maker2 closing at private key handover",
    );

    // Retrying finalization must resume at the failing maker. Replaying the
    // completed prefix sends a duplicate handover to Maker1 after it has
    // removed its live state, which then produces the misleading
    // Legacy-vs-Taproot error seen in the original failure.
    let log = std::fs::read_to_string(abort.world().taker_log_path()).unwrap();
    assert_eq!(
        log.matches("Sending privkey to maker 0 and awaiting response")
            .count(),
        1,
        "a completed maker must not receive finalization again"
    );
    assert_eq!(
        log.matches("Sending privkey to maker 1 and awaiting response")
            .count(),
        2,
        "only the failing maker should consume both integration-test attempts"
    );
    assert!(
        !log.contains(
            "UnexpectedMessage { expected: \"Legacy protocol message\", got: \"Taproot protocol message\" }"
        ),
        "retry replayed a Taproot handover into a completed maker's default Legacy state"
    );

    abort.recover();
    abort.assert_recovered(&MakerAbortExpect {
        taker_regular: 14499538,
        taker_swap: 496660,
        taker_loss: 3802,
        maker_regular: [14500751, 14502170],
        maker_swap: [499664, 498079],
        maker_spendable: Some([15000415, 15000249]),
    });
}

/// Test: Maker drops at taproot contract sigs exchange. Recovery via timelock.
/// Test: Maker drops at taproot contract sigs exchange. Recovery via timelock.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAtContractSigsExchange],
    takers = [Normal],
)]
fn taproot_drop_at_contract_sigs_exchange(world: &mut World) {
    let abort = MakerAbort::fail_swap(
        world,
        ProtocolVersion::Taproot,
        "Swap should fail due to Maker2 closing at contract sigs exchange",
    );
    let outgoing_coins = abort
        .world()
        .taker()
        .inner()
        .get_wallet()
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count();
    assert!(outgoing_coins > 1, "the batch check needs several refunds");
    abort.recover();

    // An underpriced recovery must stay replaceable, so it has to signal RBF.
    let world = abort.world();
    let taker_log = fs::read_to_string(world.taker_log_path()).unwrap();
    let recovery_txids: Vec<Txid> = taker_log
        .lines()
        .filter_map(|line| {
            let rest = line.split_once("Timelock recovery tx ")?.1;
            rest.split_once(' ')?.0.parse().ok()
        })
        .collect();
    assert!(
        !recovery_txids.is_empty(),
        "no timelock recovery in the taker log"
    );
    for txid in recovery_txids {
        let tx = world
            .bitcoind()
            .client
            .get_raw_transaction(&txid, None)
            .unwrap();
        assert!(tx
            .input
            .iter()
            .all(|i| i.sequence == Sequence::ENABLE_RBF_NO_LOCKTIME));
    }

    // Every refund goes out before one shared wait, so a single pass records
    // them all. Waiting per coin would record one refund per pass.
    let taker_wallet = format!(
        "Wallet: {} |",
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_name()
    );
    let refunded = format!("| Refunded: {outgoing_coins} |");
    assert!(
        taker_log
            .lines()
            .any(|line| line.contains(&taker_wallet) && line.contains(&refunded)),
        "the taker's {} refunds were not recorded in one pass",
        outgoing_coins
    );

    abort.assert_recovered(&MakerAbortExpect {
        taker_regular: 14999118,
        taker_swap: 0,
        taker_loss: 882,
        maker_regular: [14998875, 14999757],
        maker_swap: [0, 0],
        maker_spendable: None,
    });
}
