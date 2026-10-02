//! Mock-node channels and chain helpers for the Lightning tests.

use std::{thread, time::Duration};

use bitcoin::{secp256k1::PublicKey, Amount, Txid};
use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};
use openswap::lightning::{LightningBackend, MockLightningBackend, OpenChannelRequest};

use super::procs::bitcoind::{generate_blocks, send_to_address};

/// Fetches a transaction by txid, retrying briefly: the asynchronous txindex
/// can lag behind a freshly mined block under parallel test load.
pub(crate) fn raw_tx_with_retry(bitcoind: &BitcoinD, txid: &Txid) -> bitcoin::Transaction {
    for _ in 0..50 {
        if let Ok(tx) = bitcoind.client.get_raw_transaction(txid, None) {
            return tx;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("transaction {} not found after retries", txid);
}

/// Funds `spk` with `amount`, mines a block and returns the confirmed
/// funding txid, outpoint and output.
pub(crate) fn fund_script(
    bitcoind: &BitcoinD,
    spk: &bitcoin::ScriptBuf,
    amount: Amount,
) -> (Txid, bitcoin::OutPoint, bitcoin::TxOut) {
    let address = bitcoin::Address::from_script(spk, bitcoin::Network::Regtest).unwrap();
    let txid = send_to_address(bitcoind, &address, amount);
    generate_blocks(bitcoind, 1);
    let funding_tx = raw_tx_with_retry(bitcoind, &txid);
    let vout = funding_tx
        .output
        .iter()
        .position(|o| &o.script_pubkey == spk)
        .expect("funding output present");
    let outpoint = bitcoin::OutPoint {
        txid,
        vout: vout as u32,
    };
    (txid, outpoint, funding_tx.output[vout].clone())
}

/// Confirmation count for `txid`, retrying while the txindex catches up.
pub(crate) fn confirmations(bitcoind: &BitcoinD, txid: &Txid) -> u32 {
    for _ in 0..50 {
        if let Ok(info) = bitcoind.client.get_raw_transaction_info(txid, None) {
            return info.confirmations.unwrap_or(0);
        }
        thread::sleep(Duration::from_millis(100));
    }
    0
}

/// A fresh address from the node's own wallet, as a spend destination.
pub(crate) fn miner_spk(bitcoind: &BitcoinD) -> bitcoin::ScriptBuf {
    bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked()
        .script_pubkey()
}

/// Gives `node` 0.02 BTC on-chain and one ready 1M-sat channel to `peer`, with
/// the channel's open event drained so later polls only see swap events.
/// `push_msat` goes to the peer and is `node`'s inbound capacity: swap-outs
/// are bounded by inbound, so with `None` the node can only pay.
pub(crate) fn open_ready_channel(
    node: &MockLightningBackend,
    peer: PublicKey,
    push_msat: Option<u64>,
) {
    node.set_onchain_balance(Amount::from_btc(0.02).unwrap());
    let channel = node
        .open_channel(OpenChannelRequest {
            node_pubkey: peer,
            address: "127.0.0.1:9735".to_string(),
            channel_amount: Amount::from_sat(1_000_000),
            push_to_counterparty_msat: push_msat,
            announce_channel: false,
        })
        .unwrap();
    node.simulate_channel_ready(&channel);
    let _ = node.poll_event().unwrap();
}
