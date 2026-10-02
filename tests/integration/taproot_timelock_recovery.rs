use bitcoin::{Sequence, Txid};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::protocol::common_messages::ProtocolVersion;

use super::scenarios::maker_abort::{MakerAbort, MakerAbortExpect};

use super::test_framework::*;

use std::fs;

/// Test: Maker drops at taproot contract sigs exchange. Recovery via timelock.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAtContractSigsExchange],
    takers = [Normal],
)]
fn test_taproot_timelock_recovery(world: &mut World) {
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
