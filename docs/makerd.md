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
tor_auth_password =
# Fidelity Bond amount in satoshis (must be at least 10000)
fidelity_amount = 10000
# Fidelity Bond timelock in blocks (must be between 12960 and 25920)
fidelity_timelock = 15000
# Fee rate in sats/vB for the fidelity bond transaction (must be at least 1)
fidelity_feerate = 1
# A fixed base fee charged by the Maker for providing its services (in satoshis)
base_fee = 500
# A percentage fee based on the swap amount
amount_relative_fee_pct = 0.0025
# A percentage fee based on the swap duration
time_relative_fee_pct = 0.0001
# Required confirmations for funding transactions
required_confirms = 1
# Check funding inputs against the address blocklist
check_blocklist = false
# Public name shown to takers (required, at most 32 characters, no control characters)
name = "default-maker"
# Highest feerate (sat/vB) we replace our own swap funding at when a taker asks; 0 refuses
max_funding_bump_feerate = 0
# Most extra fee (sats) one hop's funding may take across its bumps; lost if the swap fails
max_funding_bump_sats = 0
```
- `network_port`: TCP port where the Maker listens for incoming OpenSwap protocol messages.
- `rpc_port`: The port through which `makerd` listens for RPC commands from `maker-cli`.
- `socks_port`: The Tor Socks Port.  Check the [tor doc](tor.md) for more details.
- `control_port`: The Tor Control Port. Check the [tor doc](tor.md) for more details.
- `tor_auth_password`: Optional password for Tor control authentication; empty by default.
- `fidelity_amount`: Amount (in satoshis) locked as a fidelity bond to deter Sybil attacks. Defaults to 10,000 sats, which is also the minimum; lower values are refused at startup, because takers drop announcements for bonds below that floor and the maker would never be discovered.
- `fidelity_timelock`: Lock duration in block heights for the fidelity bond. Defaults to 15,000 blocks; must be within the accepted range of 12,960–25,920 blocks.
- `fidelity_feerate`: Fee rate (in sats/vB) for the fidelity bond transaction. Defaults to 1.0, the relay minimum; lower values are clamped to it.
- `base_fee`: A fixed fee charged by the Maker for providing its services (in satoshis).
- `amount_relative_fee_pct`: A percentage fee based on the swap amount.
- `time_relative_fee_pct`: A percentage fee based on the swap duration.
- `required_confirms`: Number of confirmations required for funding transactions (default: 1). Must be at least 1: the maker refuses to start with 0.
- `check_blocklist`: When `true`, your node refuses a swap if the coins paid into it come straight from an address on your blocklist. Defaults to `false`. See [the blocklist doc](./blocklist.md).
- `max_funding_bump_feerate`, `max_funding_bump_sats`: Limits on funding bumps. A taker may ask you to replace your funding of its swap at a higher feerate when fees jump. The extra fee comes out of the contract you fund, and the taker pays it when the swap succeeds. If the swap fails, you refund the smaller contract, so a bump costs you that fee. The first setting caps the feerate you replace at; the second caps how much all bumps of one hop may take. Both are 0 by default, which refuses every bump. Both go out in your offer. See [Funding bumps](./fee-policy.md#funding-bumps).
- `name`: The public name takers see for your maker. Defaults to `default-maker`. It must be 1 to 32 characters long. It must not contain control characters, the invisible characters such as tabs and line breaks. Otherwise the maker refuses to start.
- `ldk_server_url`, `ldk_api_key_path`, `ldk_tls_cert_path`: Optional settings that connect your maker to a Lightning node. They are absent by default. See [the Lightning doc](./lightning.md).
- The per-hop parameters the taker negotiates (`tx_count`, `max_input_budget`, `feerate`) — and what the maker is reimbursed on top of its service fees — are covered in [the fee policy](./fee-policy.md).

There is no minimum swap setting. Your node works out the smallest swap it accepts for each request. The swap must pay your fee and the mining fees. Every coin you receive or send must also stay above dust after you pay to spend it. Dust is an amount too small for the network to forward. At 1 sat/vB, one taproot coin needs at least 485 sats: 330 sats of dust plus 155 sats to spend it.

Your node advertises a minimum swap size that is sure to pass. It works this out each time a taker asks for its price list. It assumes one coin in, one coin out, 1 sat/vB, and the lock a one-maker swap uses. It prices the costlier of the two swap types, legacy, so the number holds for both. It then rounds up to the next 500 sats. With the default fees, that is 1,500 sats:

1. Sweeping the incoming coin costs 150 sats.
2. The outgoing coin must hold at least 630 sats.
3. Funding the outgoing coin costs 165 sats.
4. Your base fee adds 500 sats, for 1,445.
5. Your percentage fees round that up to 1,446.
6. Rounding up to the next 500 gives 1,500.

A swap with more coins, more makers, or a higher fee rate needs more.

Each percentage fee must be at least 0 and below 100. Your node refuses to start otherwise. Your node also checks that some swap can pay your fees. A one-maker swap locks coins for 20 blocks. Your node adds your amount fee to 20 times your time fee. If the sum is 100 or more, no swap can pay your fees. Your node then stops with an error before it takes any swaps. With the default fees, the sum is 0.0025 + 20 × 0.0001 = 0.0045, far below 100.

> **Note:**  
> If `network_port` is still the default 6102, `makerd` binds 6102, or else the first free port in steps of two (6104, 6106, …), and saves that to `config.toml`. `makerd` does the same for `rpc_port` on every start, beginning at the configured port.

> **Important:**  
> At the moment, OpenSwap operates only on the **TOR** network for peer-to-peer connections. There is no clearnet option; the app will only work over Tor until multi-network support is added.

### 2. **wallets Directory**

This folder contains the wallet files used by the Maker to store wallet data, including private keys. Ensure these wallet files are backed up securely. See "Backing up and restoring the wallet" below.

The default wallet directory is `$HOME/.openswap/maker/wallets`.

### 3. **debug.log**

The log file for `makerd`, where debug information is stored for troubleshooting and monitoring.

### 4. **rpc_cookie**

A randomly generated authentication token written by `makerd` on startup and removed on shutdown. `maker-cli` reads this file from the maker data directory to authenticate its RPC requests, so it must be run on the same machine (and with read access to the data directory) as `makerd`.

---

## Backing Up and Restoring the Wallet

Both commands run on their own and then exit. They do not start the maker. Both need the chain backend (Bitcoin Core or Electrum) running and reachable, and stop with an error if it is not. Stop `makerd` before you use them. Pass the same `-d`, `-w` and blockchain flags you use to run the maker.

### Backup

```bash
$ makerd --password-file <path> backup -o maker-backup.json
```

`--password-file` (or `-p`) is the wallet's own passphrase. It only unlocks the wallet file at startup; it does not authorize the seed export. The command then asks for two more passphrases at hidden prompts. First it asks for the current wallet passphrase again, which opens the seed phrase to put it into the backup. Then it asks for a backup password, which is separate: it encrypts only the backup file. It writes an encrypted file. Without `-o`, the file is `<wallet>-backup.json` in the current directory. The file always ends in `.json`: `-o maker.bak` writes `maker.json`. The log shows the path written. The command needs an existing wallet. It never creates one.

The backup holds your keys, your fidelity bond records and your swept-coin tags. It does not hold swaps in progress or the swap report file. Finish open swaps first. Copy `<wallet>_swap_report.json` by hand. There is no backup command in `maker-cli`.

### Restore

Stop every process that uses the old wallet. Keep the old wallet files. Then restore from a backup file:

```bash
$ makerd restore --backup-file maker-backup.json
```

Or from your seed phrase:

```bash
$ makerd restore --mnemonic
```

The phrase goes in at a hidden prompt. A restore never overwrites an existing wallet. The new wallet uses the maker wallet name (`maker` by default, or what you pass with `-w`).

A restore cannot bring back swaps in progress or pending refunds. It does find coins and your announced fidelity bond. After the restore, start `makerd` as usual. It adopts the restored bond and does not make a second one.

Options:

- `--birthday <HEIGHT>`: the first block to scan from. Pick one before the wallet's first transaction.
- `--address-gap <N>`: unused addresses in a row that end the search. Default 100, lowest 20, highest 100000. The gap plus the highest used address number must stay within 100000, or the restore stops with an error.
- `--bond-hint <INDEX:LOCKTIME>`: a bond made without an announcement. `makerd` always announces its bonds, so you rarely need this. You can repeat it.

After the restore, the command lists the bond indexes it found. It also names each hint that found no bond.

See [wallet security](wallet-security.md) for what a restore does and does not bring back.

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

`Makerd` talks to a **Bitcoin Core** node (RPC + ZMQ) by default, and can use an **Electrum** server instead via `--electrum` — either way running on the **custom signet**, with mainnet use experimental (check the [bitcoind doc](./bitcoind.md)). The examples below use Bitcoin Core. To get started, start `bitcoind`:

> **Important:**  
> The marketplace runs on our **custom signet**, where we test. Mainnet use is experimental. Makers announce themselves separately on each network, so you only find makers on the network your node runs.

To start `bitcoind`:

```bash
$ bitcoind -signet
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

The server requires a Bitcoin Core RPC connection or an Electrum server (via --electrum), running on the custom signet (mainnet use is experimental). It requires some starting balance — around 50,000 sats for Fidelity + Swap Liquidity. A 0.001 BTC top-up covers this with margin. Suggested faucet: <https://faucet.openswap.live/>

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
          Electrum server URL (e.g. `tcp://localhost:50001`). When set, the wallet is initialised against an Electrum backend instead of Bitcoin Core. Mutually exclusive with the Bitcoin Core flags (-r/--ADDRESS:PORT, -z/--ZMQ, -a/--USER:PASSWORD)

      --electrum-tor
          Route the Electrum backend through the Tor SOCKS proxy on `socks_port`. Works with an onion or a clearnet server; an onion URL needs it. Peer-to-peer Tor is unaffected either way

  -t, --tor-auth <TOR_AUTH>
          

  -w, --WALLET <WALLET>
          Optional wallet name. If the wallet exists, load the wallet, else create a new wallet with the given name. Default: maker

  -p, --PASSWORD <PASSWORD>
          Password for the encryption of the wallet. Required when creating a new wallet (wallet files are always encrypted) and to open an encrypted one. Visible to other users in /proc while the process runs; prefer `--password-file`

      --password-file <PASSWORD_FILE>
          Read the wallet password from this file (one trailing newline is dropped). Keeps the password off the command line

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

- The `--electrum <ELECTRUM_URL>` option switches the wallet to an Electrum backend instead of Bitcoin Core (e.g. `tcp://localhost:50001`). It is mutually exclusive with `-r`, `-z`, and `-a`. Add `--electrum-tor` to route the Electrum connection through the Tor SOCKS proxy (required for onion servers). Peer-to-peer Tor is unaffected either way.

- The `-w` or `--WALLET` option selects the wallet file. The default wallet name is **`maker`**.

- The wallet passphrase creates and opens the wallet file, which is always encrypted (see [wallet security](./wallet-security.md)). Give it with `--password-file <FILE>` (one trailing newline is dropped) or with `-p`/`--PASSWORD`, never both. Prefer the file: other users on the machine can see `-p` in the process list. One of the two is **required** on every start; the passphrase is never saved. `restore` instead asks for the new wallet's passphrase at a prompt. `show-seed` and `attach-seed` refuse both options and ask only at a hidden prompt.

- #### If you're using the **default configuration**:

  - You don't need to include these arguments.

- #### If you're using a **custom configuration**:
  - Pass your custom values using the `-r` and `-a` options, like this:

```bash
  $ ./makerd -r 127.0.0.1:38332 -a myuser:mypass --password-file ./wallet.pass
```

## For this tutorial, we'll assume a custom configuration with port 38332. Output examples will reflect this setup.

> **Note:** The sample outputs were captured on **regtest**, so they show `tb1`/`bcrt1` addresses and `Bitcoin Network: regtest` log lines. On the custom signet the addresses and network name differ — the commands are the same.

### Start `makerd`:

To start `makerd`, run the following command:

```bash
$ ./makerd -a user:password -r 127.0.0.1:38332 --password-file ./wallet.pass
```

This will launch `makerd` and connect it to the Bitcoin RPC core running on its RPC port, using the default data directory for `maker` located at `$HOME/.openswap/maker`. The passphrase is required every time, from `--password-file` as here or from `-p`: it opens (or creates) the encrypted wallet file.

**What happens next:**

- **Wallet Loading**: If an existing wallet file is found at `$HOME/.openswap/maker/wallets`, `makerd` will load it:

  ```bash
  INFO openswap::wallet::api - Wallet file at "/path/to/maker" successfully loaded.
  ```

- **New Wallet Creation**: If no wallet file is found, `makerd` will create a new wallet named `maker`. Wallet files are always encrypted, so a wallet passphrase must be supplied via `--password-file` or `-p`/`--PASSWORD` when creating (and later opening) the wallet — restarts always require an operator to provide it:

  ```bash
  $ ./makerd -a user:password -r 127.0.0.1:38332 --password-file ./wallet.pass
  ```

  On creation, the wallet's seed phrase is sealed in the wallet file and not printed. `makerd` warns on every start until you back it up. Run `makerd -w <wallet> show-seed` in a terminal, write the words down, and re-type the words it asks for:

  ```bash
  $ makerd -w maker show-seed
  ```

  The command works offline, asks for the passphrase at a hidden prompt, and refuses unless stdout is a terminal. It shows the words and never writes while the maker runs. To record the confirmation, stop the maker first: it holds the wallet and would overwrite the change. In Docker, run `./docker-setup show-seed`: it stops the maker, shows the words, records the confirmation and starts the maker again. `docker exec -it openswap-makerd makerd -w <wallet> show-seed`, with your `BITCOIN_WALLET_NAME` as `<wallet>` (default `openswap-maker`), only shows the words while the maker runs. See [Docker](./docker.md).

- **Configuration File**: If no `config` file exists, `makerd` will create a default `config.toml` file at `$HOME/.openswap/maker/config.toml`:

   ```bash
   WARN openswap::maker::api - Maker config file not found, creating default at: $HOME/.openswap/maker/config.toml
   INFO openswap::maker::api - Loaded config file from: $HOME/.openswap/maker/config.toml
   ```

- **Wallet Sync**: The wallet will sync to catch up with the latest updates:

  ```bash
  INFO openswap::wallet::api - Sync Started for "maker"
  INFO openswap::wallet::api - Synced & Saved "maker"
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

  > **Note**: The fidelity bond transaction fee is calculated from the `fidelity_feerate` config value (default 1.0 sats/vB, the relay minimum; lower values are clamped to it), not a fixed amount.

- **Funding Requirements**: If creating a new fidelity bond and the maker wallet is empty, you'll need to fund it — `makerd` will tell you exactly how much is missing and where to send it:

  ```bash
  WARN openswap::maker::api - Insufficient funds to create fidelity bond.
  INFO openswap::maker::api - Send at least 0.00011894 BTC to tb1p... (fidelity bond + fees + minimum swap liquidity) to be visible in the market
  INFO openswap::maker::api - Next sync in 10 secs
  ```

  To fund the wallet, you can use [this faucet](https://faucet.openswap.live/).
  We suggest taking `0.01 BTC` testcoins as the extra amount will be used in doing wallet related operations in [maker-cli demo](./maker-cli.md)

- **Regular Wallet Sync**: The server syncs the wallet every 10 seconds to detect incoming funds.

- **Fidelity Transaction Creation**: Once the server detects sufficient funding (for new setups), it will automatically create and broadcast a fidelity transaction using the funding UTXOs:

  ```bash
  INFO openswap::maker::api - [6102] Fidelity bond broadcast, waiting for confirmation: 4593a892809621b64418d6bf9590c6536a1fa27f7a136d176ad302fb8ec3ce23
  ```
  
- **Fidelity Transaction Confirmation**: Once the transaction is confirmed:
  
  ```bash
  INFO openswap::maker::api - [6102] Successfully created fidelity bond
  ```


- **Nostr Task**: `makerd` starts a background task that announces the fidelity bond over Nostr:

  ```bash
  INFO openswap::maker::server - [6102] Spawning nostr background task
  ```

- **Liquidity Check**: `makerd` checks that the wallet holds enough coins for the smallest swap:

  ```bash
  INFO openswap::maker::api - Swap Liquidity: 5001672 sats | Min: 1500 sats | Listening for requests.
  ```

- **Server Ready**: Finally, the `makerd` server is fully set up and ready to connect with other takers for coin swaps. It shows the network and the spendable balance. It then starts the RPC server for `maker-cli`:

```bash
INFO openswap::maker::server - [6102] Bitcoin Network: regtest
INFO openswap::maker::server - [6102] Spendable Wallet Balance: 0.05001672 BTC
INFO openswap::maker::server - [6102] Server setup complete! Listening on port 6102
INFO openswap::maker::rpc::server - [6103] RPC socket binding successful at 127.0.0.1:6103
```

`makerd` also starts an idle-state checker and a fidelity renewal loop in the background. It then keeps listening for requests.

---

For detailed instructions on how to use the maker-cli, please refer to the [maker-cli demo](./maker-cli.md). This guide will provide a comprehensive overview of the available commands and features for operating your maker server effectively.

---

## Upgrading and downgrading

This release is a one-time break. After it, later releases stay compatible with each other.

### Before you upgrade

1. **Stop every v0.2.3 process** that uses this data directory. This includes `makerd` and any `taker` on the same wallet.
2. Do not skip step 1. An old process that keeps running can overwrite the new swap keys. That can lose funds.
3. Finish every open swap on v0.2.3. Start v0.2.3 once if a swap is half done. The new version refuses to upgrade a wallet with open work. It changes nothing and tells you why.

### What the upgrade does

1. The first start loads your old wallet and checks that nothing is open.
2. It saves private copies of your old wallet and old swap report. They end in `.v023`. Only you can read them.
3. It writes the new wallet file. Your swap reports move into it.
4. It deletes the old report file.

The new wallet file also keeps the swap state that older versions kept in tracker files.

### After you upgrade

1. Upgrade every wallet in this data directory.
2. Then delete `maker_swap_tracker.cbor` and `swap_tracker.cbor` by hand. The software never deletes them. They hold swap secrets in clear text.
3. Keep the `.v023` copies for as long as you may go back.

### Going back

v0.2.3 cannot open the new wallet. The `.v023` copies are only a snapshot from the moment of the upgrade. Any swap you started after that is missing from them. Restoring them over the new files **erases the keys for those swaps and can lose funds**.

Go back only like this:

1. Keep your daemons running until every swap you started after the upgrade has finished and is gone from the wallet. Pending refunds need them.
2. Stop every daemon that uses this data directory.
3. Make a fresh copy of the whole new wallet file and keep it.
4. Restore the `.v023` copies.

### Later releases

- A newer wallet may need a feature your build does not have. Your build then refuses to open it and names the missing feature. Upgrade and try again.
- The `require_features` setting lists features you insist on. Each one counts only in the swaps it belongs to. For example, `taproot` counts in Taproot swaps only. It does not turn Legacy swaps off, and no setting does. A name your node does not know counts in every swap. The list must sit on one line. That line takes no comment.
- Changing the default of `require_features` in a later release counts as a break.

### A coin that stays locked

Before your node sends funding, it saves the coin as committed. Your node then keeps that coin until a timelock refund, or until a confirmed transaction spends its inputs elsewhere. A crash between the save and the send can leave a coin held this way. A failed send does the same, for example when your node loses its connection to the backend.

- **If the funding reached the chain**, leave your node running. The refund frees the coin when its timelock matures.
- **If the funding never left your node**, recovery sends the saved funding and then refunds it. This holds for Legacy and Taproot swaps alike. Leave your node running until the refund confirms. You pay the network fees of those transactions. Do not edit the wallet file.
