<div align="center">

# OpenSwap All System Demo

### Prerequisites & Setup Guide

Get your system ready for the **OpenSwap Live Demo**. You run Portal, fund a wallet, and perform a real trustless swap on the OpenSwap custom signet.

</div>

---

## 📦 What You'll Be Running

| App | Role | Repository |
| --- | --- | --- |
| 🌀 **Portal** | Wallet and swap app. Also runs a router (a maker) | [`citadel-foss/portal`](https://github.com/citadel-foss/portal) |

Portal is one app with two roles. You pick one each time it starts:

- **Wallet** starts swaps and pays the fees. You have nothing to run and nothing to lock up. The protocol docs call this role the *taker*.
- **Router** provides liquidity and earns a fee on every swap through it. It needs uptime, coins in a hot wallet, and a fidelity bond. A fidelity bond is coins locked for a time, which makes faking many routers expensive. The protocol docs call this role the *maker*.

Portal runs three ways:

- **Desktop app**: a normal window on Linux, macOS, or Windows.
- **Web app**: a server you host yourself and open in a browser.
- **Container**: the same web app in Docker. This is what the Umbrel package runs.

> 📥 **Download a pre-compiled build if one exists for your system.** Check Portal's [releases page](https://github.com/citadel-foss/portal/releases). A release build needs nothing else installed.
>
> 🛠️ **Otherwise, build from source.** You need Rust, Node.js, and a few system packages. See [Build-from-source prerequisites](#2-build-from-source-prerequisites--only-if-you-self-compile).

---

## ⚙️ System Prerequisites

### 1. A chain backend — *nothing to install by default*

Portal needs a way to read the blockchain. It asks you on every launch.

- **Electrum (default).** Portal fills in `ssl://electrum.openswap.live:50002`, a public server for the OpenSwap custom signet. You do not need to install anything.
- **Your own Bitcoin Core (optional).** Use this if you want to check the chain yourself. Download Bitcoin Core from <https://bitcoin.org/en/download>. Then start `bitcoind` with this `bitcoin.conf`:

```ini
signet=1
[signet]
# Custom Signet dedicated for the OpenSwap Network.
# This signet is maintained by Citadel FOSS Developers.
signetchallenge=0014a3ec9c731da66d9725d54947aede5c830623f33d
addnode=170.75.166.88:38333
dnsseed=0

# RPC configuration for OpenSwap operations
server=1
rpcuser=user
rpcpassword=password
rpcport=38332
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# ZMQ configuration for real-time transaction and block notifications (needed by the watchers)
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28332

# Required indexes for faster wallet sync
txindex=1
blockfilterindex=1
```

Start `bitcoind` in its own terminal and let it sync. Portal's Bitcoin Core option points at `127.0.0.1:38332` by default, which matches this file.

> 🚰 Get signet coins from the **[Faucet](https://faucet.openswap.live/)**. Trace transactions on the **[Block Explorer](https://mempool.openswap.live/)**.

> 🧅 **Tor** comes bundled with Portal. Portal starts it fresh on every launch. You do not need to install Tor.

---

### 2. Build-from-Source Prerequisites — *only if you self-compile*

> ⏭️ **Skip this subsection if you use a pre-compiled build.**

#### Rust & Cargo

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Check the install:

```bash
rustc --version
cargo --version
```

#### Node.js & npm

Portal builds its screens with **Node.js v18 or newer**, which ships with `npm`. Install it from <https://nodejs.org> or with [`nvm`](https://github.com/nvm-sh/nvm). Then check:

```bash
node --version   # v18.x or newer
npm --version
```

#### System packages

- **Linux (Debian / Ubuntu):**

  ```bash
  sudo apt-get update
  sudo apt-get install -y build-essential curl wget file libssl-dev libayatana-appindicator3-dev \
    librsvg2-dev libwebkit2gtk-4.1-dev libxdo-dev pkg-config
  ```

- **macOS:**

  ```sh
  xcode-select --install
  ```

For other platforms, see Tauri's [prerequisites guide](https://tauri.app/start/prerequisites/). Tauri is the toolkit Portal uses for its desktop window.

---

## 🌀 Portal

### 📥 Download a Pre-compiled Build (Recommended)

1. Visit the **[releases page](https://github.com/citadel-foss/portal/releases)**.
2. Download the installer for your system: `.dmg` on macOS, `.deb`, `.AppImage` or `.rpm` on Linux, `.msi` on Windows.
3. Install it and launch **Portal**.

### 🛠️ Build from Source

Clone the repository once:

```bash
git clone https://github.com/citadel-foss/portal.git
cd portal
npm install
```

Then pick how you want to run it.

- **Desktop app:**

  ```bash
  npm run tauri dev
  ```

  The first run compiles the Rust backend and the OpenSwap library. That takes several minutes. Later runs are faster.

  To make installers instead, run `npm run tauri build`. They land in `target/release/bundle/`. Tauri only builds for the system you are on.

- **Web app:**

  ```bash
  npm run web:dev
  ```

  Then open <http://localhost:1430> in your browser.

- **Container** (needs [Docker](https://docs.docker.com/engine/install/)):

  ```bash
  docker compose -f umbrel/compose.local.yaml up --build
  ```

  Then open <http://localhost:3000>. If port 3000 is taken, set `PORTAL_LOCAL_PORT=3100`. Keep it bound to `127.0.0.1`. Its session cookie is not marked `Secure`.

See the Portal [README](https://github.com/citadel-foss/portal#readme) and [developer guide](https://github.com/citadel-foss/portal/blob/main/docs/DEVELOPMENT.md) for more.

---

## 🔌 First Launch

Every launch starts at the **connection screen**. Portal will not let you skip it. A swap started without a working backend fails in ways that cost money to undo.

1. Pick a chain backend. Keep the pre-filled Electrum server, or choose Bitcoin Core and enter your node's RPC details.
2. Wait for Tor to start and the chain to answer.
3. Pick **Wallet** or **Router**.
4. Open or create a wallet.
5. Let the wallet sync.

Portal never saves the connection settings to disk. You enter them fresh each launch. That way your node's RPC password is never stored.

---

## 🚀 Perform a Swap

1. Launch Portal and pick **Wallet**.
2. Copy a receiving address and fund it from the signet **[Faucet](https://faucet.openswap.live/)**.
3. Wait for the funding transaction to confirm. Track it on the **[Block Explorer](https://mempool.openswap.live/)**.
4. Open the swap screen. Pick an amount and how many hops. A hop is one router's leg of the swap.
5. Press swap. 🎉

Swaps take a while. Most of the time goes to waiting for confirmations, one per hop plus the final sweep.

**Closing the window does not stop a swap.** Portal hides in the system tray and keeps working. To quit, use the tray menu, the app menu, or `Cmd`/`Ctrl`+`Q`. Portal warns you first if a swap is still running.

---

## 🛰️ Run a Router (Optional)

1. Launch Portal and pick **Router**.
2. Open or create the router's wallet.
3. Fund it from the **[Faucet](https://faucet.openswap.live/)**. The coins cover the fidelity bond and the liquidity you route with.
4. Portal creates the fidelity bond and announces your router to the market.
5. Keep Portal running. You earn a fee on every swap routed through you.

Portal warns you before quitting while the router is still running.

---

## 🗂️ Where Portal Keeps Its Data

Portal uses the same data folders as the OpenSwap command-line tools, so their wallets work in both. The wallet role lives in `~/.openswap/taker/`:

```
~/.openswap/taker/
├── wallets/            wallet files, plus one swap report per wallet
├── debug.log           application log
├── offerbook.json      cached marketplace state
├── swap_tracker.cbor   crash-resilient swap state, for recovery
└── config.toml
```

> 🆘 Something didn't work as expected? Please report an [Issue](https://github.com/citadel-foss/portal/issues) or ping the devs in the [community forum](https://matrix.to/#/#citadel-foss:matrix.org).
