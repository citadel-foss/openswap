//! Electrum-only: wallet transaction history (`Wallet::get_transactions`).
//!
//! Bitcoin Core just forwards `listtransactions` to its server-side wallet, so
//! there is nothing of ours to test there. Electrum has no wallet, so the
//! backend rebuilds the same view from the history of the scripts it watches —
//! these are the invariants the GUI history view relies on.

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::{
    json::GetTransactionResultDetailCategory as Category, RpcApi as _,
};
use log::info;
use openswap::{taker::TakerBehavior, utill::MIN_RELAY_FEE_RATE, wallet::AddressType};

use super::test_framework::*;

const UTXO_VALUE: Amount = Amount::from_sat(5_000_000);
const UTXO_COUNT: u32 = 3;
const SEND_AMOUNT: Amount = Amount::from_sat(1_000_000);

#[test]
fn test_electrum_list_transactions() {
    info!("Running Test: Electrum wallet transaction history");
    let (test_framework, mut takers, _makers, block_generation_handle) =
        TestFramework::init::<ElectrumBackend>(vec![], vec![TakerBehavior::Normal], vec![]);
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(taker, bitcoind, UTXO_COUNT, UTXO_VALUE, AddressType::P2WPKH);

    let txs = taker
        .get_wallet()
        .read()
        .unwrap()
        .get_transactions(None, None)
        .unwrap();
    assert_eq!(
        txs.len(),
        UTXO_COUNT as usize,
        "expected one entry per funding output, got {txs:#?}"
    );
    for tx in &txs {
        assert_eq!(tx.detail.category, Category::Receive, "{tx:#?}");
        assert_eq!(tx.detail.amount, UTXO_VALUE.to_signed().unwrap(), "{tx:#?}");
        assert!(tx.info.confirmations >= 1, "{:#?}", tx);
        assert!(tx.info.blockhash.is_some(), "{:#?}", tx);
        assert!(tx.info.blocktime.is_some(), "{:#?}", tx);
    }

    // Spend to an address outside the wallet: the payment must show up as a
    // send, and the change coming back must not be counted as a receive.
    let external = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let spend_txid = taker
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
    generate_blocks(bitcoind, 1);
    test_framework.wait_for_electrs_tip();
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    let txs = taker
        .get_wallet()
        .read()
        .unwrap()
        .get_transactions(None, None)
        .unwrap();
    let sends: Vec<_> = txs
        .iter()
        .filter(|t| t.detail.category == Category::Send)
        .collect();
    assert_eq!(
        sends.len(),
        1,
        "expected exactly one send entry, got {txs:#?}"
    );
    let send = sends[0];
    assert_eq!(send.info.txid, spend_txid, "{send:#?}");
    assert_eq!(
        send.detail.amount,
        -SEND_AMOUNT.to_signed().unwrap(),
        "{send:#?}"
    );
    assert_eq!(
        send.detail
            .address
            .as_ref()
            .map(|a| a.clone().assume_checked()),
        Some(external),
        "{send:#?}"
    );
    assert!(
        send.detail.fee.is_some_and(|f| f.to_sat() < 0),
        "send entry should carry a negative fee, got {:#?}",
        send
    );
    let receives = txs
        .iter()
        .filter(|t| t.detail.category == Category::Receive)
        .count();
    assert_eq!(
        receives, UTXO_COUNT as usize,
        "change must not be listed as a receive, got {txs:#?}"
    );

    // Paging: `skip` walks back from the newest entry.
    let newest = taker
        .get_wallet()
        .read()
        .unwrap()
        .get_transactions(Some(1), None)
        .unwrap();
    assert_eq!(newest.len(), 1, "{newest:#?}");
    assert_eq!(newest[0].info.txid, spend_txid, "{newest:#?}");
    let skipped = taker
        .get_wallet()
        .read()
        .unwrap()
        .get_transactions(Some(1), Some(1))
        .unwrap();
    assert_eq!(skipped.len(), 1, "{skipped:#?}");
    assert_ne!(skipped[0].info.txid, spend_txid, "{skipped:#?}");

    info!("Electrum transaction history test completed successfully!");
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
