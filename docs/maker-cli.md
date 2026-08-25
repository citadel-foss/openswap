# Maker-cli Tutorial

`maker-cli` is a straightforward command-line tool designed as an RPC client for `makerd`. It allows you to connect to the server, retrieve vital information, and manage various server operations efficiently.

In this guide, we'll walk you through how to use `maker-cli` to get the most out of your `makerd` setup. Let's get started!

> ### **Important Note**
>
> `makerd` listens to RPC requests from `maker-cli` **only** when it is fully set up. This setup includes creating a new fidelity bond (if one doesn't already exist) and completing other necessary configurations.
>
> If `makerd` is not fully set up, `maker-cli` commands will not function.
>
> 👉 **Before starting this tutorial**, ensure your `makerd` setup is complete.  
> If you're unsure how to set it up, check out our [Makerd Setup Guide](./makerd.md) first, and then return to this tutorial.

---

## Getting Started with `maker-cli`

### View All Available Commands

To see the full list of arguments and options available in `maker-cli`, run the following command:

```bash
$ ./maker-cli --help
```

This will display a detailed guide about the app and its capabilities.

#### **Output:**

```bash
A simple command line app to operate the makerd server.

The app works as an RPC client for makerd, useful to access the server, retrieve information, and manage server operations.

For more detailed usage information, please refer: <https://github.com/citadel-foss/openswap/blob/master/docs/maker-cli.md>

This is early beta, and there are known and unknown bugs. Please report issues at: <https://github.com/citadel-foss/openswap/issues>

Usage: maker-cli [OPTIONS] <COMMAND>

Commands:
  send-ping           Sends a ping to makerd. Will return a pong
  list-utxo           Lists all utxos in the wallet. Including fidelity bonds
  list-utxo-swap      Lists utxos received from incoming swaps
  list-utxo-contract  Lists HTLC contract utxos
  list-utxo-fidelity  Lists fidelity bond utxos
  get-balances        Get total wallet balances of different categories. regular: All single signature regular wallet coins (seed balance). swap: All 2of2 multisig coins received in swaps. contract: All live contract transaction balance locked in timelocks. If you see value in this field, you have unfinished or malfinished swaps. You can claim them back with the recover command. fidelity: All coins locked in fidelity bonds. spendable: Spendable amount in wallet (regular + swap balance)
  get-new-address     Gets a new bitcoin receiving address
  send-to-address     Send Bitcoin to an external address and return the txid
  show-tor-address    Show the server tor address
  show-data-dir       Show the data directory path
  stop                Shutdown the makerd server
  show-fidelity       Show all the fidelity bonds, current and previous, with an (index, {bond_proof, is_spent}) tuple
  sync-wallet         Sync the Maker wallet with the current blockchain state
  verify-deniability  Verify the deniability proof for a specific swap
  help                Print this message or the help of the given subcommand(s)

Options:
  -p, --rpc-port <RPC_PORT>
          Sets the rpc-port of Makerd
          
          [default: 127.0.0.1:6103]

  -d, --data-directory <DATA_DIRECTORY>
          Maker data directory used to read the RPC authentication cookie

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

### Key Points About the Arguments

- The `rpc-port` option specifies the RPC port that `makerd` listens on. By default, this is set to **`127.0.0.1:6103`**.

- The `-d` or `--data-directory` option points `maker-cli` at the maker's data directory. It defaults to `~/.openswap/maker` and is used to read the **`rpc_cookie`** file that `makerd` writes on startup — every RPC request is authenticated with this token. If you started `makerd` with a custom `--data-directory`, pass the same directory to `maker-cli`.

- #### If you're using the **default configuration**:

  - You don't need to include the `rpc-port` argument.

- #### If you're using a **custom configuration**:
  - Pass your custom port number using the `-p` or `--rpc-port` option, like this:

```bash
  $ ./maker-cli -p 6104 <SUBCOMMAND>
```

## For this tutorial, we'll assume the default configuration is being used. Output examples will reflect this setup.

---

## Exploring Maker CLI Commands

### SendPing

To check if `makerd` is listening to RPC requests from `maker-cli`, use the `send-ping` command.

Run:

```bash
$ ./maker-cli send-ping
```

**Output:**

```bash
success
```

This sends a ping to `makerd` and will return a pong, confirming that the maker server is listening and responding to requests.

---

### ShowDataDir

To get the maker server's data directory, use this command:

```bash
$ ./maker-cli show-data-dir
```

**Output:**

```bash
<home_directory>/openswap/maker
```

This is where all the maker's data is stored.

---

### ShowTorAddress

If your maker server is running on `Tor`, find its Tor address using this command:

```bash
$ ./maker-cli show-tor-address
```

**Output:**

```bash
<maker's tor_address>
```

This shows the server's Tor address, which is our maker server's identity on the Tor network.

---

### ShowFidelity

When setting up `makerd`, we fund the maker's wallet and create a fidelity bond. To see details about our existing fidelity bond, use:

```bash
$ ./maker-cli show-fidelity
```

**Output:**

```json
[
  {
    "index": 0,
    "outpoint": "6c06a925066b0cf8adb400e53001b20587729407bce7dcb95dcacd038950b0e4:0",
    "amount": 10000,
    "status": "Live",
    "bond_value": 904
  }
]
```

This shows our maker's fidelity bond in a clean JSON format:

- **index**: The bond index (0 for the first/current bond)
- **outpoint**: The transaction output point (txid:vout) where the bond is locked
- **amount**: The amount locked in the fidelity bond (10,000 sats by default)
- **status**: Current status of the bond ("Live" means active and unspent, "Redeemed" means it has been spent after expiry)
- **bond_value**: The calculated bond value (only shown for live bonds)

> **Note:** Currently, a maker can have only one active (unexpired) fidelity bond at a time. `makerd` automatically creates a new bond once the previous one expires and is redeemed.

---

### ListFidelityUTXOs

To view fidelity UTXOs in the maker's wallet, run:

```bash
$ ./maker-cli list-utxo-fidelity
```

**Output:**

```bash
[
  {
    "addr": "tb1qttutr6nuum6e5neyddukxrzvnx87eksteu9vzx6xfmrfc30cppqspa6ut2",
    "amount": 10000,
    "confirmations": 1,
    "utxo_type": "fidelity-bond"
  }
]
```

This lists fidelity bond UTXOs. Since only one live fidelity bond is allowed at a time, this shows a single UTXO of `10,000 sats`. Note that the `txid` and `vout` match the `outpoint` from the `show-fidelity` command, confirming this is the same fidelity bond UTXO.

---

### CheckFidelityBalance

To check the balance of our fidelity UTXOs, use:

```bash
$ ./maker-cli get-balances
```

**Output:**

```json
{
  "contract": 0,
  "fidelity": 10000,
  "regular": 989000,
  "spendable": 989000,
  "swap": 0
}
```

This command shows the total wallet balances of different categories:

- **contract**: All live contract transaction balance locked in timelocks. If you see value in this field, you have unfinished or malfinished swaps. You can claim them back with the recover command
- **fidelity**: All coins locked in fidelity bonds
- **regular**: All single signature regular wallet coins (seed balance)
- **spendable**: Spendable amount in wallet (regular + swap balance)
- **swap**: All 2of2 multisig coins received in swaps

This confirms the balance of our fidelity UTXOs matches the amount we set when creating the bond.

---

For more details about fidelity bonds, refer to the [Fidelity Bond Documentation](https://github.com/citadel-foss/OpenSwap-Protocol-Specification/blob/main/v1/4_fidelity.md).

---

Next, we’ll explore other UTXOs and balances in OpenSwap.

### Other UTXOs and Their Balances

#### Swap UTXOs

```bash
$ ./maker-cli list-utxo-swap
[]
```

This lists UTXOs received from incoming swaps. Since we have not done any openswap yet, we have no swap UTXOs and thus no swap balances.

#### Contract UTXOs

```bash
$ ./maker-cli list-utxo-contract
[]
```

This lists HTLC contract UTXOs. As mentioned above: We haven't participated in any openswap transactions yet, so we don't have any unsuccessful openswaps. Therefore, we have no `contract UTXOs` and no balance in this category.

Both categories show zero balances as confirmed by our `get-balances` output:

```bash
$ ./maker-cli get-balances
{
  "contract": 0,
  "fidelity": 10000,
  "regular": 989000,
  "spendable": 989000,
  "swap": 0
}
```

> **IMPORTANT:**  
> We need to manually check UTXOs and their balances using the `list-utxo` and `get-balances` commands, respectively.
> The `list-utxo` command returns all UTXOs present in the maker wallet, including the fidelity UTXOs.
> The `get-balances` command returns the total wallet balances of different categories, including normal UTXOs, swap UTXOs, contract UTXOs, fidelity UTXOs, and spendable UTXOs (normal + swap UTXOs).

Let's find them out:

```bash
$ ./maker-cli list-utxo
[
  {
    "addr": "tb1qttutr6nuum6e5neyddukxrzvnx87eksteu9vzx6xfmrfc30cppqspa6ut2",
    "amount": 10000,
    "confirmations": 1,
    "utxo_type": "fidelity-bond"
  },
  {
    "addr": "tb1qu332pjytwdu0z73f5xzftkk06hpgdyvjvef9kn",
    "amount": 989000,
    "confirmations": 1,
    "utxo_type": "regular"
  }
]
```

This lists all UTXOs in the wallet, including fidelity bonds. We created a funding transaction to fund the maker wallet and establish the fidelity bonds. As a result, the command displays two UTXOs:

1. The **fidelity UTXO** (which we've already seen).
2. The **normal funding UTXO**.

### Breakdown:

- Initially, we funded the wallet with `0.01 BTC` (1,000,000 sats).
- `10,000 sats` were locked in the fidelity bond.
- `1,000 sats` were paid as the mining fee for the fidelity transaction (at the default `fidelity_feerate` of 2 sats/vB).

The remaining balance after these transactions is:

**989,000 sats** = **1,000,000 sats** (total funding) - **10,000 sats** (for the fidelity bond) - **1,000 sats** (mining fees).

We can verify this balance by running the `get-balances` command, which shows the total wallet balances of different categories:

```bash
$ ./maker-cli get-balances
{
  "contract": 0,
  "fidelity": 10000,
  "regular": 989000,
  "spendable": 989000,
  "swap": 0
}
```

---

### Deriving an Address from the Maker's Wallet:

To derive a new external address from the maker's wallet, use the `get-new-address` command with `maker-cli`.

```bash
$ ./maker-cli get-new-address

<maker's external address>
```

This gets a new bitcoin receiving address from the maker's wallet.

### Spending `10,000 sats` from the Maker's Wallet:

Next, let's send `10,000 sats` from the maker's wallet to an external address.

#### **Step 1**: Derive an External Address Using `bitcoin-cli`'s `getnewaddress` Command

```bash
$ bitcoin-cli getnewaddress
```

#### **Step 2**: Use `maker-cli`'s `send-to-address` Command to Send the Amount to the Derived Address

The `send-to-address` command allows us to send Bitcoin to an external address. To view the available options for this command, run the `--help` option:

```bash
$ ./maker-cli send-to-address --help

Send Bitcoin to an external address and return the txid

Usage: maker-cli send-to-address [OPTIONS] --address <ADDRESS> --amount <AMOUNT>

Options:
  -t, --address <ADDRESS>  Recipient's address
  -a, --amount <AMOUNT>    Amount to send in sats
  -f, --feerate <FEERATE>  Feerate in sats/vByte. Defaults to 2 sats/vByte
  -h, --help               Print help
```

> **Note:**  
> The transaction fee is specified as a fee rate in sats/vByte via the `--feerate` option. If omitted, it defaults to 2 sats/vByte.

Let's now send `10,000 sats` to the derived address, with a fee rate of 2 sats/vByte:

```bash
$ ./maker-cli send-to-address --amount 10000 --address <derived address> --feerate 2

<txid>
```

This command will create a transaction, send `10,000 sats` from the maker's wallet to the derived address, broadcast the transaction to the network, and return the transaction ID in hex format.

### Transaction Confirmation and Wallet Synchronization:

Once the transaction is broadcasted to the network, it will need to be confirmed. After confirmation, we have to sync our wallet to catch the latest updates:

```bash
$ ./maker-cli sync-wallet
success
```

This syncs the maker wallet with the current blockchain state. On `makerd`, we will see:

```bash
INFO openswap::maker::rpc::server - Initializing wallet sync
INFO openswap::maker::rpc::server - Completed wallet sync
```

### Checking Wallet Balances and UTXOs:

Finally, we can check the wallet's updated balances and the list of UTXOs as done previously.

---

### **Fidelity UTXOs**:

```bash
$ ./maker-cli list-utxo-fidelity

[
  {
    "addr": "tb1qttutr6nuum6e5neyddukxrzvnx87eksteu9vzx6xfmrfc30cppqspa6ut2",
    "amount": 10000,
    "confirmations": 1,
    "utxo_type": "fidelity-bond"
  }
]

$ ./maker-cli get-balances

{
    "regular": 978500,
    "swap": 0,
    "contract": 0,
    "fidelity": 10000,
    "spendable": 978500
}
```

> **NOTE**: Fidelity UTXOs are not used for spending purposes. These UTXOs can only be spent after the fidelity bond expires, which `makerd` handles automatically during bond renewal. This is why the UTXO list and balance remain unchanged.

---

### **Swap UTXOs**:

```bash
$ ./maker-cli list-utxo-swap
[]

$ ./maker-cli get-balances
{
    "regular": 978500,
    "swap": 0,
    "contract": 0,
    "fidelity": 10000,
    "spendable": 978500
}
```

---

### **Contract UTXOs**:

```bash
$ ./maker-cli list-utxo-contract
[]

$ ./maker-cli get-balances
{
    "regular": 978500,
    "swap": 0,
    "contract": 0,
    "fidelity": 10000,
    "spendable": 978500
}
```

---

### **Total UTXOs**:

```bash
$ ./maker-cli list-utxo

[
  {
    "addr": "tb1qttutr6nuum6e5neyddukxrzvnx87eksteu9vzx6xfmrfc30cppqspa6ut2",
    "amount": 10000,
    "confirmations": 1,
    "utxo_type": "fidelity-bond"
  },
  {
    "addr": "tb1qu332pjytwdu0z73f5xzftkk06hpgdyvjvef9kn",
    "amount": 978500,
    "confirmations": 1,
    "utxo_type": "regular"
  }
]

$ ./maker-cli get-balances
{
    "regular": 978500,
    "swap": 0,
    "contract": 0,
    "fidelity": 10000,
    "spendable": 978500
}
```

After sending `10,000 sats` with a ~`500 sats` mining fee, the spendable balance dropped from `989,000` to `978,500` sats, and the change was consolidated back into the regular wallet UTXO.

---

### VerifyDeniability

After a completed swap, you can verify the deniability proof for a specific swap ID:

```bash
$ ./maker-cli verify-deniability --swap-id <swap_id>

Proof valid: swap participated in a completed openswap
```

If the proof is missing or doesn't check out, the command prints `Proof invalid or not found for this swap ID`.

---

### **Shutting Down Maker Server**:

After performing all functionalities, we can stop the maker server using the `stop` command.

```bash
$ ./maker-cli stop

Shutdown Initiated
```

This shuts down the makerd server. Once you run this command, the maker server initiates a shutdown, and we'll see the following logs indicating the shutdown process:

```bash
 INFO openswap::maker::server - [6102] Server shutting down...
 INFO openswap::maker::server - shutdown_phase_start pid=... component=maker:6102 phase=wallet_save
 INFO openswap::maker::server - shutdown_phase_done pid=... component=maker:6102 phase=wallet_save outcome=ok
 INFO openswap::maker::server - [6102] Server shutdown complete
```

On shutdown, `makerd` also removes the `rpc_cookie` file from the data directory.

---

And that's it! Now you are ready to be a maker in the OpenSwap network. Start your maker servers, perform openswaps, and enjoy earning fees from takers who participate in openswaps with you.
