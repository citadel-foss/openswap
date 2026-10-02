//! What a real backend answers when the same transaction is broadcast twice.
//!
//! The maker's "already broadcast" predicate decides whether a rebroadcast
//! rejection means carry on or abort the swap. These tests pin what Core and
//! Electrum actually reply, unmined and mined, instead of guessing.

use bitcoin::Amount;
use bitcoind::{
    bitcoincore_rpc::{jsonrpc::error::Error as JsonRpcError, Error as CoreRpcError, RpcApi},
    BitcoinD,
};
use log::info;
use openswap::{taker::Taker, utill::MIN_RELAY_FEE_RATE, wallet::WalletError};

use crate::test_framework::*;

const SEND_AMOUNT: Amount = Amount::from_sat(1_000_000);

fn spend_once(taker: &Taker, bitcoind: &BitcoinD) -> (bitcoin::Txid, bitcoin::Transaction) {
    let external = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let txid = taker
        .get_wallet()
        .write()
        .unwrap()
        .send_to_address(
            SEND_AMOUNT.to_sat(),
            external.to_string(),
            Some(MIN_RELAY_FEE_RATE),
            None,
        )
        .unwrap();
    let tx = bitcoind.client.get_raw_transaction(&txid, None).unwrap();
    (txid, tx)
}

#[world_test(
    makers = 0,
    takers = [Normal],
    setup = [fund_taker_default(3)],
    cases = [
        rebroadcast_unmined_bitcoind(backend = BitcoindBackend),
        rebroadcast_unmined_electrum(backend = ElectrumBackend),
    ],
)]
fn run_rebroadcast_unmined(world: &mut World) {
    let (txid, tx) = spend_once(world.taker().inner(), world.bitcoind());

    // A duplicate of an unconfirmed tx is not an error on either backend:
    // both accept it and hand the txid back.
    let reply = world
        .taker()
        .inner()
        .get_wallet()
        .read()
        .unwrap()
        .send_tx(&tx);
    info!("unmined rebroadcast reply: {reply:?}");
    assert_eq!(
        reply.unwrap(),
        txid,
        "an unconfirmed rebroadcast must succeed and return the txid"
    );
}

#[world_test(
    makers = 0,
    takers = [Normal],
    setup = [fund_taker_default(3)],
    cases = [
        rebroadcast_mined_bitcoind(backend = BitcoindBackend, core_backend = true),
        rebroadcast_mined_electrum(backend = ElectrumBackend, core_backend = false),
    ],
)]
fn run_rebroadcast_mined(world: &mut World, core_backend: bool) {
    let (_, tx) = spend_once(world.taker().inner(), world.bitcoind());
    world.mine(1);
    world.framework().wait_for_electrs_tip();

    let reply = world
        .taker()
        .inner()
        .get_wallet()
        .read()
        .unwrap()
        .send_tx(&tx);
    info!("mined rebroadcast reply: {reply:?}");
    let err = reply.expect_err("a confirmed duplicate must be rejected");
    if core_backend {
        match err {
            WalletError::Rpc(CoreRpcError::JsonRpc(JsonRpcError::Rpc(e))) => {
                assert_eq!(e.code, -27, "{:?}", e);
                assert!(e.message.contains("already in utxo set"), "{:?}", e);
            }
            other => panic!("expected RPC -27 from Core, got {:?}", other),
        }
    } else {
        // Electrum carries the same "already in utxo set" wording but as its
        // own error type, not WalletError::Rpc — the maker's Rpc-only
        // predicate cannot see it, so the is_transaction_known fallback is
        // load-bearing on this path.
        match err {
            WalletError::Electrum(e) => {
                assert!(format!("{e:?}").contains("already in utxo set"), "{:?}", e);
            }
            other => panic!("expected an Electrum protocol error, got {:?}", other),
        }
    }
}
