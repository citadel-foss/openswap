# Taker Tutorial

The **Taker** is the party that initiates the openswap. It discovers makers, requests offers from them and selects suitable makers for the swap.

In this tutorial, we will guide you through the process of setting up and running the taker, and conducting a openswap.

## Setup

## Taker CLI

The taker CLI is an application that allows you to perform openswaps as a taker.

> **Warning:**  
> Taker wallet files contain private keys required to spend your funds. Ensure these wallet files are backed up securely, and take appropriate measures to protect your private keys.

### Start Bitcoin Core (Pre-requisite)

`Taker` requires a **Bitcoin Core** RPC connection running on a **custom signet** for its operation(check [demo doc](./demo.md)).
> **Important:**  
> All apps are designed to run on our **custom signet** for testing purposes. The marketplace is only live in custom signet. Running the taker in other networks will not work as there's no marketplace in that network.

To start `bitcoind`:

```bash
$ bitcoind
```

**Note:** If you don't have `bitcoind` installed or need help setting it up, refer to the [bitcoind demo documentation](./bitcoind.md).

**Electrum backend:** the taker can run against an Electrum server instead of Bitcoin Core via `--electrum <URL>`. Electrum servers do not serve full blocks, so chain-based fidelity-bond discovery is unavailable on this path — maker discovery relies on nostr relays only. An Esplora backend that restores block scanning is future work.

### Usage

Run the `taker` command to see the list of available commands and options:

```bash
$ ./taker --help
```

This will display a detailed guide about the app and its capabilities.

#### **Output:**

```bash
A simple command line app to operate as openswap client.

The app works as a regular Bitcoin wallet with the added capability to perform openswaps. It can talk to either a Bitcoin Core node (over RPC + ZMQ — the default) or an Electrum-protocol server (via `--electrum`). Both paths support the full swap flow and the `restore` subcommand. It currently only runs on the custom signet. Suggested faucet for getting signet coins (tor browser required): <http://s2ncekhezyo2tkwtftti3aiukfpqmxidatjrdqmwie6xnf2dfggyscad.onion/>

For more detailed usage information, please refer: <https://github.com/citadel-foss/openswap/blob/master/docs/taker.md>

This is early beta, and there are known and unknown bugs. Please report issues at: <https://github.com/citadel-foss/openswap/issues>

Usage: taker [OPTIONS] <COMMAND>

Commands:
  list-utxo           Lists all utxos we know about along with their spend info. This is useful for debugging
  list-utxo-regular   Lists all single signature wallet Utxos. These are all non-swap regular wallet utxos
  list-utxo-swap      Lists all utxos received in incoming swaps
  list-utxo-contract  Lists all utxos that we need to claim via timelock. If you see entries in this list, do a `taker recover` to claim them
  get-balances        Get total wallet balances of different categories. regular: All single signature regular wallet coins (seed balance). swap: All 2of2 multisig coins received in swaps. contract: All live contract transaction balance locked in timelocks. If you see value in this field, you have unfinished or malfinished swaps. You can claim them back with the recover command. spendable: Spendable amount in wallet (regular + swap balance)
  get-new-address     Returns a new address
  send-to-address     Send to an external wallet address
  fetch-offers        Update the offerbook with current market offers and display them
  list-offers         List makers from the locally cached offerbook without triggering a network sync
  poll-maker          Fetch an offer from a single maker address, verify the fidelity proof, and store the result in the offerbook. Adds the maker if absent
  remove-maker        Remove a maker from the local offerbook by address
  open-swap           Initiate the openswap process
  recover             Recover from all failed swaps
  backup              Backup the selected wallet.
  restore             Restore a wallet from a backup file
  verify-deniability  Verify the deniability proof for a specific swap
  help                Print this message or the help of the given subcommand(s)

Options:
  -d, --data-directory <DATA_DIRECTORY>
          Optional data directory. Default value: "~/.openswap/taker"

  -r, --ADDRESS:PORT <ADDRESS:PORT>
          Bitcoin Core RPC address:port value. Conflicts with `--electrum`
          
          [default: 127.0.0.1:38332]

  -z, --ZMQ <ZMQ>
          Bitcoin Core ZMQ address:port value. Defaults to the RPC host on port 28332

  -a, --USER:PASSWORD <USER:PASSWORD>
          Bitcoin Core RPC authentication string. Ex: username:password. Conflicts with `--electrum`
          
          [default: user:password]

  -t, --tor-auth <TOR_AUTH>
          

      --electrum <ELECTRUM_URL>
          Electrum server URL (e.g. `tcp://localhost:50001`). When set, the wallet is initialised against an Electrum backend instead of Bitcoin Core. Mutually exclusive with the Bitcoin Core flags (--rpc/--zmq/--auth). Electrum servers do not serve full blocks, so chain-based fidelity-bond discovery is unavailable — maker discovery relies on nostr relays only

      --electrum-tor
          Route the Electrum backend through the Tor SOCKS proxy on `socks_port`. Works with an onion or a clearnet server; an onion URL needs it. Peer-to-peer Tor is unaffected either way

  -w, --WALLET <WALLET>
          Sets the taker wallet's name. If the wallet file already exists, it will load that wallet. Default: taker-wallet

  -p, --PASSWORD <PASSWORD>
          Password for the encryption of the wallet. Required when creating a new wallet (wallet files are always encrypted) and to open an encrypted one

  -v, --verbosity <VERBOSITY>
          Sets the verbosity level of debug.log file
          
          [default: info]
          [possible values: off, error, warn, info, debug, trace]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

### Key Points About Command Arguments

- The `-p` or `--PASSWORD` option sets the wallet encryption passphrase. It is **required** when creating a new wallet and to open an encrypted one — wallet files are always encrypted (see [wallet security](./wallet-security.md)). The passphrase must be supplied on every (re)start; it is never persisted.

- The `-r` or `--ADDRESS:PORT` option specifies the Bitcoin Core RPC address and port. By default, this is set to `127.0.0.1:38332`.

- The `-z` or `--ZMQ` option specifies the Bitcoin Core ZMQ address. If omitted, it defaults to the RPC host on port `28332`.

- The `-a` or `--USER:PASSWORD` option specifies the Bitcoin Core RPC authentication. By default, this is set to **`user:password`**.

- The `--electrum <ELECTRUM_URL>` option switches the wallet to an Electrum backend instead of Bitcoin Core (e.g. `tcp://localhost:50001`). It is mutually exclusive with `--rpc`, `--zmq`, and `--auth`. Add `--electrum-tor` to route the Electrum connection through the Tor SOCKS proxy (required for onion servers). Peer-to-peer Tor is unaffected either way.

- The `-v` or `--verbosity` option sets the log level of the `debug.log` file (default: `info`).

- #### If you're using the **default configuration**:

  - You don't need to include these arguments.

- #### If you're using a **custom configuration**:
  - Pass your custom values using the `-r` and `-a` options, like this:

```bash
  $ ./taker -r 127.0.0.1:38332 -a myuser:mypass -p my-wallet-passphrase <SUBCOMMAND>
```

> **Note:** Every `taker` command opens the encrypted wallet, so `-p` is required on each invocation. The tutorial's bare `taker <SUBCOMMAND>` examples assume it is supplied.

## For this tutorial, we'll assume a custom configuration with port 38332. Output examples will reflect this setup.

---

## Setting Up Your Wallet

### Generate a New Address

Before you can perform openswaps, you need to fund your wallet. First, generate a new receiving address:

```bash
$ taker get-new-address
```

**Output:**

```bash
bcrt1qyywgd4we5y7u05lnrgs8runc3j7sspwqhekrdd
```

This returns a new Bitcoin receiving address from the taker's wallet.

Now we can use the signet faucet to send some coins to this address. Use [this faucet](http://s2ncekhezyo2tkwtftti3aiukfpqmxidatjrdqmwie6xnf2dfggyscad.onion/)(open in Tor browser) to get some signet coins.

### Check Wallet Balances

Once you have some coins in your wallet, you can check your balance by running the following command:

```bash
$ taker get-balances
```

**Output:**

```json
{
  "contract": 0,
  "regular": 232560,
  "spendable": 251239,
  "swap": 18679
}
```

The balance categories are explained as follows:
- **contract**: All live contract transaction balance locked in timelocks (if you see value here, you have unfinished or failed swaps)
- **regular**: All single signature regular wallet coins (seed balance)
- **spendable**: Total spendable amount in wallet (regular + swap balance)
- **swap**: All 2of2 multisig coins received in swaps

### List All UTXOs

To view all UTXOs in your wallet, use this command:

```bash
$ taker list-utxo
```

**Output:**

```bash
{
  "addr": "tb1qhfgd9u7y8usez37dl9uglv3s6wnugppmy2xeps",
  "amount": 18679,
  "confirmations": 2,
  "utxo_type": "swept-incoming-swap"
}
{
  "addr": "tb1qrsg2ls8exyzthjt2rsvkjhuag0a269867m3e0f",
  "amount": 232560,
  "confirmations": 3,
  "utxo_type": "regular"
}
```

This lists all UTXOs the wallet knows about, along with their spend info — useful for debugging.

### List Regular UTXOs

To view only single signature wallet UTXOs, run:

```bash
$ taker list-utxo-regular
```

**Output:**

```bash
{
  "addr": "tb1qrsg2ls8exyzthjt2rsvkjhuag0a269867m3e0f",
  "amount": 232560,
  "confirmations": 3,
  "utxo_type": "regular"
}
```

This lists all single signature wallet UTXOs. These are all non-swap regular wallet UTXOs.

### List Swap UTXOs

To view UTXOs received from incoming swaps, run:

```bash
$ taker list-utxo-swap
```

**Output:**

```bash
{
  "addr": "tb1qhfgd9u7y8usez37dl9uglv3s6wnugppmy2xeps",
  "amount": 18679,
  "confirmations": 2,
  "utxo_type": "swept-incoming-swap"
}
```

This lists all UTXOs received in incoming swaps. In this example the wallet holds one swept swap coin; on a fresh wallet that has never swapped, this list is empty.

### List Contract UTXOs

To check for any locked funds from failed swaps, run:

```bash
$ taker list-utxo-contract
```

**Output:**

```bash
```

This lists all UTXOs that we need to claim via timelock. If you see entries in this list, you should run the `recover` command to claim them.

### Fetch Available Offers

Now we are ready to initiate a openswap. We are first going to sync the offer book to get a list of available makers:

```bash
$ taker fetch-offers
```

This blocks until the offerbook sync cycle completes (including Nostr-based maker discovery), then prints each discovered maker with its state, offer terms, and fidelity bond details, followed by a summary line:

```bash
Waiting for offerbook synchronization to complete…
Offerbook synchronized in 12.34s

Discovered 2 makers


    Maker
    ─────
    Address        : rywnaguli5qwad2ayqyu3673acyyl5dw7bsjifhge4zohftfi76ybbid.onion:6102
    Protocol       : Legacy
    State          : Good

    Offer
    ─────
    Base Fee       : 500
    Amount Fee %   : 0.0025
    Time Fee %     : 0.0001

    Limits
    ──────
    Min Size       : 10000
    Max Size       : 49949540
    Required Conf. : 1
    Min Locktime   : 20

    Fidelity Bond
    ─────────────
    Outpoint       : 21e3902cc0a2b94602fa94a7d3664f1a4d861df84af5049a334d5ddf402ed7f5:0
    Value          : 904
    Expiry         : 28864

...

Offerbook summary → good: 2, bad: 0, unresponsive: 0 (total: 2)
```

### List Cached Offers

To list the makers already stored in the local offerbook without triggering a network sync:

```bash
$ taker list-offers
```

This prints the same per-maker display as `fetch-offers`, but reads only the locally cached offerbook.

### Poll or Remove a Single Maker

You can fetch and verify the offer of one specific maker (adding it to the offerbook if absent):

```bash
$ taker poll-maker --address <maker-onion-address:port>
```

And remove a maker from the local offerbook by address:

```bash
$ taker remove-maker --address <maker-onion-address:port>
```

### Initiate a OpenSwap

Now we can initiate a openswap with the makers:

```bash
$ taker open-swap
```

This initiates a openswap with the default parameters (2 makers, 20,000 sats, legacy protocol). To see all available options, run:

```bash
$ taker open-swap --help
```

**Output:**

```bash
Initiate the openswap process

Usage: taker open-swap [OPTIONS]

Options:
  -m, --makers <MAKERS>
          Sets the Maker count to swap with. Swapping with less than 2 makers is not allowed to maintain client privacy. Adding more makers in the swap will incur more swap fees [default: 2]
  -a, --amount <AMOUNT>
          Sets the swap amount in sats [default: 20000]
      --tx-count <TX_COUNT>
          [default: 1]
      --protocol <PROTOCOL>
          Protocol version to use: "legacy" or "taproot" [default: legacy]
      --maker-address <MAKER_ADDRESSES>
          Manually specify maker addresses (host:port). Can be repeated. When set, these makers are used directly instead of auto-discovery
      --auto-select
          Automatically select UTXOs instead of interactive picker
      --payment-address <PAYMENT_ADDRESS>
          PaySwap: settle the swap to this third-party address. The swap amount then means the exact amount the receiver gets
  -y, --yes
          Skip the confirmation prompt and proceed immediately
  -h, --help
          Print help
```

By default, the command opens an interactive UTXO picker so you can choose which coins fund the swap; pass `--auto-select` to let the wallet pick them automatically.

The swap runs in two phases. First it prepares the swap — discovering makers, negotiating with each hop, and computing the fees — then prints a summary and asks for confirmation:

```bash
========== Swap Summary ==========
Swap ID:   c874d9f7ac7e6230
Protocol:  Legacy
Sending:   20000 sats

  Hop 0: ewaexd2es2uzr34wp26cj5zgph7bug7znmmxolvwzmoeedbiyfgz3wqd.onion:8202 (Legacy)
         Fees: base=500 sats, amt=0.0025%, time=0.000100%
         Locktime: 48 blocks, Estimated fee: 550 sats
  Hop 1: rywnaguli5qwad2ayqyu3673acyyl5dw7bsjifhge4zohftfi76ybbid.onion:6102 (Legacy)
         Fees: base=500 sats, amt=0.0025%, time=0.000100%
         Locktime: 24 blocks, Estimated fee: 530 sats

Total estimated fee: 1080 sats
Estimated receive:   18920 sats
==================================

Proceed with this swap? [y/N]
```

Confirm with `y` (or pass `-y`/`--yes` upfront) to execute the swap. With `--payment-address <addr>` (PaySwap), the summary instead shows the receiver, the exact amount the receiver gets, and the total openswap cost.

The process typically takes several minutes to complete. You can monitor the swap progress by watching the debug log in a new terminal:

```bash
tail -f ~/.openswap/taker/debug.log
```

```bash
INFO openswap::wallet::api - Wallet file at "/home/user/.openswap/taker/wallets/taker-wallet" successfully loaded.
INFO openswap::taker::config - Successfully loaded config file from : /home/user/.openswap/taker/config.toml
INFO openswap::utill - Tor is fully started and operational!
INFO openswap::taker::api - Syncing Offerbook
INFO openswap::taker::api - Found 5 suitable makers for this swap round
INFO openswap::taker::api - Initiating openswap with id : c874d9f7ac7e6230
INFO openswap::taker::api - Initializing First Hop.
INFO openswap::taker::api - Choosing next maker: ewaexd2es2uzr34wp26cj5zgph7bug7znmmxolvwzmoeedbiyfgz3wqd.onion:8202
INFO openswap::wallet::spend - Created Funding tx, txid: 5eacac48... | Size: 220 vB | Fee: 440 sats | Feerate: 2.00 sat/vB
INFO openswap::taker::api - ===> ReqContractSigsForSender | ewaexd2es2uzr34wp26cj5zgph7bug7znmmxolvwzmoeedbiyfgz3wqd.onion:8202
INFO openswap::taker::api - <=== RespContractSigsForSender | ewaexd2es2uzr34wp26cj5zgph7bug7znmmxolvwzmoeedbiyfgz3wqd.onion:8202
INFO openswap::taker::api - Broadcasted Funding tx. txid: 5eacac48...
INFO openswap::taker::api - Waiting for funding transaction confirmation. Txids : [5eacac48...]

.
.
.

INFO openswap::wallet::api - Successfully swept incoming swap coin, txid: aed232df...
INFO openswap::taker::api - Successfully swept 1 incoming swap coins: [aed232df...]
INFO openswap::taker::api - Successfully Completed OpenSwap.
INFO openswap::taker::api - Shutting down taker.
INFO openswap::taker::api - offerbook data saved to disk.
INFO openswap::taker::api - Wallet data saved to disk.
```

### Recovering Failed Swaps

If a swap fails for any reason, the funds might be locked in a timelock contract. To check if you have any such locked funds, run:

```bash
$ taker list-utxo-contract
```

**Output:**

```bash
```

If you see any UTXOs in the output, you can recover them using the `recover` command:

```bash
$ taker recover
```

**Output:**

```bash
2025-08-13T14:36:38.734842084+05:30 INFO openswap::wallet::api - Unfinished incoming txids: []
2025-08-13T14:36:38.734849418+05:30 INFO openswap::wallet::api - Unfinished outgoing txids: []
2025-08-13T14:36:38.752510411+05:30 INFO openswap::taker::api - Recovery completed.
```

This will attempt to recover all funds from failed swaps. In this case, since there are no unfinished transactions (both incoming and outgoing txids arrays are empty), the recovery process completes immediately with no funds to recover.

### Backing Up the Wallet

To back up the selected wallet (use `-w` to pick a non-default wallet), run:

```bash
$ taker backup
```

The backup is created in the current working directory as `<wallet_name>-backup.json`. Backups contain the master key and are always encrypted — you will be prompted interactively for a passphrase.

### Restoring a Wallet

To restore a wallet from a backup file:

```bash
$ taker restore --backup-file <backup-file>
```

If no `-w` wallet name is provided, the wallet is restored with its original name stored in the backup; otherwise it is restored under the given name.

### Verifying a Deniability Proof

After a completed swap, you can verify the deniability proof for a specific swap ID:

```bash
$ taker verify-deniability --swap-id <swap_id>

Proof valid: swap participated in a completed openswap
```

If the proof is missing or doesn't check out, the command prints `Proof invalid or not found for this swap ID`.

## Data, Config and Wallets

The taker stores all its data in a data directory. By default, the data directory is located at `$HOME/.openswap/taker`. You can change the data directory by passing the `--data-directory` option to the `taker` command.

The data directory contains the following files:

1. `config.toml` - The configuration file for the taker.
2. `debug.log` - The log file for the taker.
3. `wallets` directory - Contains the wallet files for the taker.
4. `offerbook.json` - The locally cached offerbook of known makers, updated by `fetch-offers` and `poll-maker`.

**Default Taker Configuration (`~/.openswap/taker/config.toml`):**

```toml
control_port = 9051
socks_port = 9050
tor_auth_password = ""
```
 
- `control_port`: The Tor Control Port. Check the [tor doc](tor.md) for more details.
- `socks_port`: The Tor Socks Port. Check the [tor doc](tor.md) for more details.
- `tor_auth_password`: Optional password for Tor control authentication; empty by default.

### Wallets

The taker uses wallet files to store the wallet data. The wallet files are stored in the `wallets` directory. These wallet files should be safely backed up as they contain the private keys to the wallet.
