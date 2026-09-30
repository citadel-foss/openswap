# Working with `bitcoind` for the OpenSwap signet

In this tutorial, we will guide you through setting up `bitcoind` for the OpenSwap signet. A signet is a public test network. One fixed key signs all its blocks. The Citadel FOSS developers run this custom signet to host the openswap marketplace.

OpenSwap doesn't need any experimental consensus. The install steps below use the [Mutinynet](https://github.com/benthecarman/bitcoin/tree/mutinynet-inq-29) build of Bitcoin Core as one way to run the node. That build runs on the [inquisition hardfork](https://github.com/bitcoin-inquisition/bitcoin) of Bitcoin Core.

This tutorial will cover basic operations like setting up, creating wallets, getting funds, checking balances, and sending sats between two wallets using `bitcoin-cli`.

### 1. Installing `bitcoind`

#### Steps:

1. Download and install:

   - Download the [latest binaries](https://github.com/benthecarman/bitcoin/releases/latest) from the Mutinynet project repository.
   - Extract the `.tar.gz` archive. The required binaries are in the `bin/` folder.
   - Copy the `bitcoind` and `bitcoin-cli` binaries to a directory in your PATH (for Unix: `/usr/local/bin/`).

2. Verify installation:
  
   After installation, you can run the following command to confirm that `bitcoind` is properly installed:
   ```bash
   $ which bitcoind
   /usr/local/bin/bitcoind
   ```
---

### 2. Setting up the `bitcoin.conf` file

First, create the Bitcoin data directory if it doesn't already exist:

```bash
mkdir -p ~/.bitcoin
```

Copy this [`bitcoin.conf`](./bitcoin.conf) file from the docs folder into the data directory:

```bash
cp ./docs/bitcoin.conf ~/.bitcoin/bitcoin.conf
```

This reference configuration contains the settings required to run `bitcoind` for OpenSwap on either the OpenSwap signet or Regtest.

---

### 3. Basic Operations

Once the `bitcoin.conf` file is configured, you can start `bitcoind` and perform basic operations using `bitcoin-cli`.

#### 3.1 Start the `bitcoind` daemon

Run the OpenSwap signet:

```bash
$ bitcoind -signet
```
Or, run local Regtest
```bash
$ bitcoind -regtest 
```

> **Note**: The OpenSwap marketplace is live on the OpenSwap signet. To access the market and perform swaps with other makers, start `bitcoind -signet`.

Useful link for signet operations:
 - [OpenSwap Signet Faucet](https://faucet.openswap.live/)

> **Note**: The rest of the tutorial runs on Regtest. Every `bitcoin-cli` command below uses `-regtest`. On the OpenSwap signet, use `-signet` instead. The mining command, `bitcoin-cli generatetoaddress`, does not work on the signet. Use the faucet to fund your wallet there.

To check the status of the node and confirm that it's running, use:

```bash
$ bitcoin-cli -regtest getblockchaininfo
```

This will output the current state of the blockchain, including the number of blocks and synchronization status, for example:

```bash
{
  "chain": "regtest",
  "blocks": 0,
  "headers": 0,
  "bestblockhash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
  "difficulty": 4.656542373906925e-10,
  "time": 1296688602,
  "mediantime": 1296688602,
  "verificationprogress": 1,
  "initialblockdownload": true,
  "chainwork": "0000000000000000000000000000000000000000000000000000000000000002",
  "size_on_disk": 293,
  "pruned": false,
  "warnings": ""
}
```

#### 3.2 Create a wallet for Alice

Create a wallet named `alice` to perform wallet-related operations in the regtest environment:

```bash
$ bitcoin-cli -regtest createwallet "alice"
```

The response will confirm that the wallet `alice` has been created:

```json
{
  "name": "alice"
}
```

#### 3.3 Create a wallet for Bob

Similarly, create another wallet named `bob`:

```bash
$ bitcoin-cli -regtest createwallet "bob"
```

The response will confirm that the wallet `bob` has been created:

```json
{
  "name": "bob"
}
```

#### 3.4 Get a new Bitcoin address for Alice

Generate a new Bitcoin address for `alice` to receive funds:

```bash
$ bitcoin-cli -regtest -rpcwallet=alice getnewaddress
```

This returns a new address for `alice`:

```bash
bcrt1qfvgecwpwtn77f7vv6wfc78zdcxseq4pjpyn9jv
```

#### 3.5 Generate some blocks for Alice

Since we’re using `regtest`, you can generate new blocks to Alice's address and receive Bitcoin as block rewards:

```bash
$ bitcoin-cli -regtest -rpcwallet=alice generatetoaddress 101 <alice_address>
```

This will return a list of block hashes in hex format, corresponding to the 101 newly generated blocks, for example:

```bash
[
  "00b968e6627d8f160369a06a3169719487cf246a5d43afa113c42a236305b7d3",
  "3ac6820a58627c9e69dcd349d9d152909b018a2afe923bed73dae0c7b7134104",
  "0d4b1870a18216450e5da68c7349e7cb26beb144c671524c23798728ca222cd8",
  "41c1c331c93e75f2048a285c925e15eca423b0a93f1f7354261adef8f29186c3",

  ... till 101 block hashes
]
```

#### 3.6 Check Alice's wallet balance

Now check the balance in `alice`'s wallet:

```bash
$ bitcoin-cli -regtest -rpcwallet=alice getbalances
```

This will show a balance corresponding to the block rewards for the generated blocks:

```bash
{
  "mine": {
    "trusted": 50.00000000,
    "untrusted_pending": 0.00000000,
    "immature": 0.00000000
  }
}
```

---

### 4. Sending Bitcoin from Alice to Bob

Now, let’s send 1 BTC from `alice` to `bob` using the `sendtoaddress` RPC command.

#### 4.1 Get Bob's Bitcoin address

Generate a new Bitcoin address for `bob`:

```bash
$ bitcoin-cli -regtest -rpcwallet=bob getnewaddress
```

This returns a new address for `bob`:

```bash
bcrt1q2nys4aedf448ngt5gpw5gmun6gdjqgy04qj6cq
```

#### 4.2 Send 1 BTC from Alice to Bob

Next, send 1 BTC from `alice` to `bob` using the `sendtoaddress` command:

```bash
$ bitcoin-cli -regtest -rpcwallet=alice sendtoaddress <bob_address> 1
```

This will create and broadcast a signed transaction, returning the transaction hash:

```bash
0b0c6a25e16f987e5a68fe59c301e06615376837b11a3ed678b0f0bd8a69a18a
```

#### 4.3 Generate a block to confirm the transaction

Generate a block to confirm the transaction:

```bash
$ bitcoin-cli -regtest -rpcwallet=bob generatetoaddress 1 <bob_address>
```

This will return the block hash in hex format:

```bash
"43e5d06abcf026e3faec392626545fb4880592682fd61645dc99d51e277bd761"
```

#### 4.4 Check the final balance of each wallet

Finally, check the balance of both wallets to confirm that the transaction was successful.

##### For Bob's wallet:

```bash
$ bitcoin-cli -regtest -rpcwallet=bob getbalances
```

The response should show that `bob` has received the 1 BTC:

```json
{
  "mine": {
    "trusted": 1.00000000,
    "untrusted_pending": 0.00000000,
    "immature": 0.00000000
  }
}
```

##### For Alice's wallet:

```bash
$ bitcoin-cli -regtest -rpcwallet=alice getbalances
```

Alice's balance will be reduced by slightly more than 1 BTC: 1 BTC was sent to Bob and the remainder was paid as transaction fees. For example:

```json
{
  "mine": {
    "trusted": 48.99998590,
    "untrusted_pending": 0.00000000,
    "immature": 0.00000000
  }
}
```

---

We’ve set up `bitcoind`, created two wallets (`alice` and `bob`), generated blocks, and sent Bitcoin between the wallets. You are now ready to explore Bitcoin transactions and experiment with openswap CLI apps.

