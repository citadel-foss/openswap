## Maker Overview

The **Maker** is the party that provides liquidity for a coin swap initiated by a **Taker**. In return, the Maker earns a fee for facilitating the swap.

The Maker component is based on the `makerd/maker-cli` architecture, which is similar to `bitcoind/bitcoin-cli`. The `makerd` is a background daemon that handles the heavy tasks in the **OpenSwap** protocol, such as maintaining fidelity bonds, and processing Taker requests.

The `makerd` server should run 24/7 to ensure it can process Taker requests and facilitate coin swaps at any time.

> **Warning:**  
> Maker private keys should be kept in a hot wallet used by `makerd` to facilitate coin swap requests. Users are responsible for securing the server-side infrastructure.

The `maker-cli` is a command-line application that allows you to operate and manage `makerd` through RPC commands.

## Data, Configuration, and Wallets

Maker stores all its data in a directory located by default at `$HOME/.openswap/maker`. This directory contains the following important files:

### **1. Default Maker Configuration (`~/.openswap/maker/config.toml`):**

```toml
# Maker Configuration File

# Network port for client connections
network_port = 6102
# RPC port for maker-cli operations
rpc_port = 6103
# Socks port for Tor proxy
socks_port = 9050
# Control port for Tor interface
control_port = 9051
# Authentication password for Tor interface
tor_auth_password = ""
# Minimum amount in satoshis that can be swapped
min_swap_amount = 10000
# Fidelity Bond amount in satoshis
fidelity_amount = 10000
# Fidelity Bond timelock in blocks (must be between 12960 and 25920)
fidelity_timelock = 15000
# Fee rate in sats/vB for the fidelity bond transaction (must be at least 1.0)
fidelity_feerate = 2.0
# A fixed base fee charged by the Maker for providing its services (in satoshis)
base_fee = 500
# A percentage fee based on the swap amount
amount_relative_fee_pct = 0.0025
# A percentage fee based on the swap duration
time_relative_fee_pct = 0.0001
# Required confirmations for funding transactions
required_confirms = 1
```
- `network_port`: TCP port where the Maker listens for incoming OpenSwap protocol messages.
- `rpc_port`: The port through which `makerd` listens for RPC commands from `maker-cli`.
- `socks_port`: The Tor Socks Port.  Check the [tor doc](tor.md) for more details.
- `control_port`: The Tor Control Port. Check the [tor doc](tor.md) for more details.
- `tor_auth_password`: Optional password for Tor control authentication; empty by default.
- `min_swap_amount`: Minimum swap amount (in satoshis). Values below the protocol minimum of 10,000 sats are rejected at startup.
- `fidelity_amount`: Amount (in satoshis) locked as a fidelity bond to deter Sybil attacks. Defaults to 10,000 sats.
- `fidelity_timelock`: Lock duration in block heights for the fidelity bond. Defaults to 15,000 blocks; must be within the accepted range of 12,960–25,920 blocks.
- `fidelity_feerate`: Fee rate (in sats/vB) for the fidelity bond transaction. Defaults to 2.0; lower values are allowed, but anything below the relay minimum of 1.0 sats/vB is clamped to 1.0.
- `base_fee`: A fixed fee charged by the Maker for providing its services (in satoshis).
- `amount_relative_fee_pct`: A percentage fee based on the swap amount.
- `time_relative_fee_pct`: A percentage fee based on the swap duration.
- `required_confirms`: Number of confirmations required for funding transactions (default: 1).

> **Note:**  
> On the first run, if the default `network_port` or `rpc_port` is already in use, `makerd` automatically discovers a free port and persists it to `config.toml`.

> **Important:**  
> At the moment, OpenSwap operates only on the **TOR** network for peer-to-peer connections. There is no clearnet option; the app will only work over Tor until multi-network support is added.

### 2. **wallets Directory**

This folder contains the wallet files used by the Maker to store wallet data, including private keys. Ensure these wallet files are backed up securely.

The default wallet directory is `$HOME/.openswap/maker/wallets`.

### 3. **debug.log**

The log file for `makerd`, where debug information is stored for troubleshooting and monitoring.

### 4. **rpc_cookie**

A randomly generated authentication token written by `makerd` on startup and removed on shutdown. `maker-cli` reads this file from the maker data directory to authenticate its RPC requests, so it must be run on the same machine (and with read access to the data directory) as `makerd`.

---

## Maker Tutorial

In this tutorial, we will guide you through the process of operating the Maker component, including how to set up `Makerd` and how to use `maker-cli` for managing `Makerd` and performing wallet-related operations.

This tutorial is split into two parts:

- **Makerd Tutorial**
- **maker-cli Tutorial**

This section focuses on `Makerd`, walking you through the process of starting and fully setting up the server. For instructions on `maker-cli`, refer to the [maker-cli demo](./maker-cli.md).

---

## How to Set Up Makerd

### 1. Start the Blockchain Backend (Pre-requisite)

`Makerd` talks to a **Bitcoin Core** node (RPC + ZMQ) by default, and can use an **Electrum** server instead via `--electrum` — either way running on the **custom signet** (check [demo doc](./demo.md)). The examples below use Bitcoin Core. To get started, start `bitcoind`:

> **Important:**  
> All apps are designed to run on our **custom signet** for testing purposes. The marketplace is only live in custom signet. Running the maker in other networks will not work as there's no marketplace in that network.

To start `bitcoind`:

```bash
$ bitcoind
```

**Note:** If you don't have `bitcoind` installed or need help setting it up, refer to the [bitcoind demo documentation](./bitcoind.md).

### 2. Run the Help Command to See All Makerd Arguments

To see all the available arguments for `Makerd`, run the following command:

```bash
$ ./makerd --help
```

This will display information about the `makerd` binary and its options.

**Output:**

```bash
OpenSwap Maker Server

The server requires a Bitcoin Core RPC connection or an Electrum server (via --electrum), running on the custom signet. It requires some starting balance — around 50,000 sats for Fidelity + Swap Liquidity. A 0.001 BTC top-up covers this with margin. Suggested faucet: <https://faucet.citadelfoss.xyz/>

All server processes will start after the fidelity bond transaction is confirmed. This may take some time. Approx: 10 mins. Once the bond is confirmed, the server starts listening for incoming swap requests. As it performs swaps for clients, it keeps earning fees.

The server is operated with the maker-cli app, for all basic wallet related operations.

For more detailed usage information, please refer the [Maker Doc]<https://github.com/citadel-foss/openswap/blob/master/docs/makerd.md>

This is early beta, and there are known and unknown bugs. Please report issues in the [Project Issue Board]<https://github.com/citadel-foss/openswap/issues>

Usage: makerd [OPTIONS]

Options:
  -d, --data-directory <DATA_DIRECTORY>
          Optional DNS data directory. Default value: "~/.openswap/maker"

  -r, --ADDRESS:PORT <ADDRESS:PORT>
          Bitcoin Core RPC network address. Conflicts with `--electrum`
          
          [default: 127.0.0.1:38332]

  -z, --ZMQ <ZMQ>
          Bitcoin Core ZMQ address:port value. Defaults to the RPC host on port 28332

  -a, --USER:PASSWORD <USER:PASSWORD>
          Bitcoin Core RPC authentication string (username, password). Conflicts with `--electrum`
          
          [default: user:password]

      --electrum <ELECTRUM_URL>
          Electrum server URL (e.g. `tcp://localhost:50001`). When set, the wallet is initialised against an Electrum backend instead of Bitcoin Core. Mutually exclusive with the Bitcoin Core flags (--rpc/--zmq/--auth)

      --electrum-tor
          Route the Electrum backend through the Tor SOCKS proxy on `socks_port`. Works with an onion or a clearnet server; an onion URL needs it. Peer-to-peer Tor is unaffected either way

  -t, --tor-auth <TOR_AUTH>
          

  -w, --WALLET <WALLET>
          Optional wallet name. If the wallet exists, load the wallet, else create a new wallet with the given name. Default: maker

  -p, --PASSWORD <PASSWORD>
          Password for the encryption of the wallet. Required when creating a new wallet (wallet files are always encrypted) and to open an encrypted one

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

This will give you detailed information about the options and arguments available for `Makerd`.

### Key Points About Command Arguments

- The `-r` or `--ADDRESS:PORT` option specifies the Bitcoin Core RPC address and port. By default, this is set to **`127.0.0.1:38332`**.

- The `-z` or `--ZMQ` option specifies the Bitcoin Core ZMQ address. If omitted, it defaults to the RPC host on port **`28332`**.

- The `-a` or `--USER:PASSWORD` option specifies the Bitcoin Core RPC authentication. By default, this is set to **`user:password`**.

- The `--electrum <ELECTRUM_URL>` option switches the wallet to an Electrum backend instead of Bitcoin Core (e.g. `tcp://localhost:50001`). It is mutually exclusive with `--rpc`, `--zmq`, and `--auth`. Add `--electrum-tor` to route the Electrum connection through the Tor SOCKS proxy (required for onion servers). Peer-to-peer Tor is unaffected either way.

- The `-w` or `--WALLET` option selects the wallet file. The default wallet name is **`maker`**.

- The `-p` or `--PASSWORD` option sets the wallet encryption passphrase. It is **required** when creating a new wallet and to open an encrypted one — wallet files are always encrypted (see [wallet security](./wallet-security.md)). The passphrase must be supplied on every (re)start; it is never persisted.

- #### If you're using the **default configuration**:

  - You don't need to include these arguments.

- #### If you're using a **custom configuration**:
  - Pass your custom values using the `-r` and `-a` options, like this:

```bash
  $ ./makerd -r 127.0.0.1:38332 -a myuser:mypass -p my-wallet-passphrase
```

## For this tutorial, we'll assume a custom configuration with port 38332. Output examples will reflect this setup.

> **Note:** The sample outputs were captured on **regtest**, so they show `tb1`/`bcrt1` addresses and `Bitcoin Network: regtest` log lines. On the custom signet the addresses and network name differ — the commands are the same.

### Start `makerd`:

To start `makerd`, run the following command:

```bash
$ ./makerd -a user:password -r 127.0.0.1:38332 -p my-wallet-passphrase
```

This will launch `makerd` and connect it to the Bitcoin RPC core running on its RPC port, using the default data directory for `maker` located at `$HOME/.openswap/maker`. The `-p` passphrase is required every time: it opens (or creates) the encrypted wallet file.

**What happens next:**

- **Wallet Loading**: If an existing wallet file is found at `$HOME/.openswap/maker/wallets`, `makerd` will load it:

  ```bash
  INFO openswap::wallet::api - Wallet file at "/path/to/maker" successfully loaded.
  ```

- **New Wallet Creation**: If no wallet file is found, `makerd` will create a new wallet named `maker`. Wallet files are always encrypted, so a wallet passphrase must be supplied via `-p`/`--PASSWORD` when creating (and later opening) the wallet — restarts always require an operator to provide it:

  ```bash
  $ ./makerd -a user:password -r 127.0.0.1:38332 -p my-wallet-passphrase
  ```

  On creation, the wallet's mnemonic seed phrase is displayed once on the terminal — back it up securely before continuing:

  ```bash
  ========== New Wallet Seed Phrase ==========
  harvest trust catalog degree oxygen business crawl enemy hamster music this idle

  Write these words down and store them offline. They will not be shown again.

  INFO openswap::maker::api - New Wallet created at : "$HOME/.openswap/maker/wallets/maker".
  ```

- **Configuration File**: If no `config` file exists, `makerd` will create a default `config.toml` file at `$HOME/.openswap/maker/config.toml`:

   ```bash
   WARN openswap::maker::api - Maker config file not found, creating default at: $HOME/.openswap/maker/config.toml
   INFO openswap::maker::api - Loaded config file from: $HOME/.openswap/maker/config.toml
   ```

- **Wallet Sync**: The wallet will sync to catch up with the latest updates:

  ```bash
  INFO openswap::wallet::rpc - Initializing wallet sync and save
  INFO openswap::wallet::rpc - Completed wallet sync and save
  ```

- **TOR Initialization**: `makerd` will start the TOR process and listen for connections on a TOR address.

- **Fidelity Bond Check**: `makerd` checks for existing fidelity bonds. 

  **If an existing fidelity bond is found**:
  ```bash
  INFO openswap::maker::api - Highest bond at outpoint fc11a129...c:0 | index 0 | Amount 10000 sats | Remaining Timelock: 536 Blocks | Bond Value: 1523 sats
  ```

  **If no fidelity bonds are found**, it will create one using the fidelity amount and timelock from the configuration file. By default, the fidelity amount is `10,000 sats` and the timelock is `15,000 blocks`:

  ```bash
  INFO openswap::maker::api - No active Fidelity Bonds found. Creating one.
  INFO openswap::maker::api - Fidelity value chosen = 10000 sats
  INFO openswap::maker::api - Fidelity timelock 15000 blocks
  ```

  > **Note**: The fidelity bond transaction fee is calculated from the `fidelity_feerate` config value (default 2.0 sats/vB, clamped to the 1.0 sats/vB relay minimum), not a fixed amount.

- **Funding Requirements**: If creating a new fidelity bond and the maker wallet is empty, you'll need to fund it — `makerd` will tell you exactly how much is missing and where to send it:

  ```bash
  WARN openswap::maker::api - Insufficient funds to create fidelity bond.
  INFO openswap::maker::api - Send at least 0.00010500 BTC to "tb1p..."
  INFO openswap::maker::api - Next sync in 10 secs
  ```

  To fund the wallet, you can use [this faucet](https://faucet.citadelfoss.xyz/).
  We suggest taking `0.01 BTC` testcoins as the extra amount will be used in doing wallet related operations in [maker-cli demo](./maker-cli.md)

- **Regular Wallet Sync**: The server will regularly sync the wallet every 10 seconds, increasing the interval in the pattern 10,20,30..., to detect any incoming funds.

- **Fidelity Transaction Creation**: Once the server detects sufficient funding (for new setups), it will automatically create and broadcast a fidelity transaction using the funding UTXOs:

  ```bash
  INFO openswap::maker::api - [6102] Fidelity bond broadcast, waiting for confirmation: 4593a892809621b64418d6bf9590c6536a1fa27f7a136d176ad302fb8ec3ce23
  ```
  
- **Fidelity Transaction Confirmation**: Once the transaction is confirmed:
  
  ```bash
  INFO openswap::maker::api - [6102] Successfully created fidelity bond
  ```


- **Thread Spawning**: Several threads will be spawned to handle specific tasks — a Nostr background task (to announce the fidelity bond), the RPC server, an idle-state checker, and a fidelity renewal loop:

  ```bash
  INFO openswap::maker::server - [6102] Spawning nostr background task
  INFO openswap::maker::rpc::server - [6102] RPC socket binding successful at 127.0.0.1:6103
  ```

- **Server Ready**: Finally, the `makerd` server is fully set up and ready to connect with other takers for coin swaps:

```bash
INFO openswap::maker::server - [6102] Server setup complete! Listening on port 6102
```

The server will display information about swap liquidity and continue listening for requests:

```bash
INFO openswap::maker::api - Swap Liquidity: 5001672 sats | Min: 10000 sats | Listening for requests.
INFO openswap::maker::server - [6102] Bitcoin Network: regtest
INFO openswap::maker::server - [6102] Spendable Wallet Balance: 0.05001672 BTC
```

---

For detailed instructions on how to use the maker-cli, please refer to the [maker-cli demo](./maker-cli.md). This guide will provide a comprehensive overview of the available commands and features for operating your maker server effectively.

---
