# Lightning Swaps

Openswap can move value between the Bitcoin blockchain and the Lightning
Network using **submarine swaps**. This document covers what the feature does,
how to turn it on, and how to use it as a taker or a maker.

> **Note:**
> Lightning support is compiled out by default. Stock binaries do **not**
> include it, and a maker built without it will politely decline Lightning
> requests rather than dropping the connection.

## What you can do

| Command | You send | You receive | Needs your own Lightning node? |
|---|---|---|---|
| `ln-swap-in` | on-chain BTC | Lightning balance | **Yes** |
| `ln-swap-out` | Lightning balance | on-chain BTC | **Yes** |
| `ln-swap-routed` | on-chain BTC | on-chain BTC | **No** |

`ln-swap-routed` is worth calling out: it sends your coins through two makers
with Lightning as the middle hop, so you get a swap with a Lightning-shaped
privacy profile without running a Lightning node at all. The first maker takes
your on-chain funds and forwards over Lightning to the second maker, which pays
you back on-chain.

## Building with Lightning enabled

Lightning lives behind the `lightning` cargo feature:

```bash
$ cargo build --release --features lightning
```

This applies to both `taker` and `makerd`. Without the feature the three
`ln-swap-*` subcommands do not exist.

## The Lightning backend (`ldk-server`)

Openswap does not embed a Lightning node. It talks over gRPC to an
[`ldk-server`](https://github.com/lightningdevkit/ldk-server) sidecar that you
run and fund yourself. You need this for `ln-swap-in` and `ln-swap-out`, and as
a maker offering Lightning; you do **not** need it for `ln-swap-routed`.

`ldk-server` generates two credentials on first start, both inside its data
directory:

| Credential | Location |
|---|---|
| TLS certificate | `<data_dir>/tls.crt` |
| API key | `<data_dir>/<network>/api_key` |

The default data directory is `~/.ldk-server` on Linux and
`~/Library/Application Support/ldk-server` on macOS. The default gRPC address is
`127.0.0.1:3536`.

The API key file holds raw bytes, not text. Point openswap at the file and it
handles the encoding itself — do not try to paste the contents into the config.

## Taker setup

Add these keys to the taker config at `~/.openswap/taker/config.toml`:

```toml
# LDK Server gRPC address (host:port, no scheme)
ldk_server_url = 127.0.0.1:3536
# Path to the LDK Server API key file
ldk_api_key_path = /home/you/.ldk-server/regtest/api_key
# Path to the LDK Server TLS certificate (optional)
ldk_tls_cert_path = /home/you/.ldk-server/tls.crt
```

Set `ldk_server_url` and `ldk_api_key_path` together. `ldk_tls_cert_path` is
optional. Without it, your node reads `tls.crt` from ldk-server's default data
directory. Your node turns Lightning off and logs the reason in two cases:
`ldk_server_url` has no `ldk_api_key_path` beside it, or your node cannot read
a credential file. The taker still starts. On-chain swaps work as usual.

Openswap verifies the backend at startup with a real call. If the sidecar is
unreachable you will see this in the log, and the `ln-swap-*` commands will
fail with:

```
no lightning backend configured (set ldk_server_url)
```

### Swap in: on-chain to Lightning

```bash
$ ./taker ln-swap-in --amount 100000
```

```
swap-in complete: 100000 sats to Lightning via <maker> (fee 750 sats, HTLC <outpoint>)
```

You fund an on-chain HTLC; the maker pays you the same amount over Lightning.

### Swap out: Lightning to on-chain

```bash
$ ./taker ln-swap-out --amount 100000
```

```
swap-out complete: 100000 sats to on-chain via <maker> (fee 750 sats, claim <txid>)
```

You pay the maker's hold invoice; the maker funds an on-chain HTLC that you
claim.

### Routed swap: on-chain to on-chain, no Lightning node

```bash
$ ./taker ln-swap-routed --amount 100000
```

```
routed swap complete: sent 105000 sats via <maker1>, received 100000 sats via <maker2> (fees 750 + 750 sats, claim <txid>)
```

`--amount` is what you want to **receive**. Both makers' fees are funded on top
of it, so the amount leaving your wallet is larger.

### Common options

| Flag | Meaning |
|---|---|
| `-a, --amount <SATS>` | Swap amount. Required. |
| `--maker-address <ADDR>` | Pick a specific maker. Omit to choose from the offerbook. |
| `--locktime <BLOCKS>` | Refund timelock on the on-chain HTLC. |
| `--min-confirmations <N>` | Confirmations required on the HTLC funding output. Default `1`. |

`ln-swap-routed` uses `--first-maker` and `--second-maker` instead of
`--maker-address`, and its `--locktime` sets the second hop's refund window —
the first hop automatically gets more, so the leg you funded stays locked until
after the leg you are claiming.

For `ln-swap-out` and `ln-swap-routed`, `--locktime` defaults to **144 blocks**
(about a day). For `ln-swap-in` it is derived from the invoice's CLTV when you
omit it.

Makers are only offered a Lightning swap if their offer advertises suitable
terms, so you can run these commands against a mixed offerbook safely. If
nothing matches you get:

```
no maker in the offerbook advertises suitable Lightning terms
```

## Maker setup

A maker opts in with the same keys, in `~/.openswap/maker/config.toml`.
`ldk_server_url` and `ldk_api_key_path` are required. `ldk_tls_cert_path` is
optional, as on the taker side:

```toml
ldk_server_url = 127.0.0.1:3536
ldk_api_key_path = /home/you/.ldk-server/regtest/api_key
# Optional
ldk_tls_cert_path = /home/you/.ldk-server/tls.crt
```

As on the taker side, a misconfigured or unreachable sidecar disables Lightning
and logs the reason instead of failing startup. Your on-chain swap business
keeps running either way — that is deliberate, so a Lightning outage never takes
your maker offline.

### What gets advertised

When Lightning is working, your offer gains a Lightning section that takers can
filter on. Openswap computes it from live state each time a taker asks for your
offer, so it tracks reality rather than a number you configured:

- **`swap_in` / `swap_out`** — whether you serve each direction at all.
- **`max_swap_in`** — bounded by your **outbound** channel capacity, since you
  pay over Lightning.
- **`max_swap_out`** — bounded by your **inbound** channel capacity *and* your
  on-chain wallet, since you receive over Lightning and pay out on-chain.
- **`min_size`** — your usual minimum swap amount.
- **`base_fee` / `amount_relative_fee_pct`** — reused from your existing fee
  settings (see [the fee policy](./fee-policy.md)); there is no separate
  Lightning fee schedule.

The two directions draw on genuinely different resources, so they are sized
separately. It is normal for one to be larger than the other, or for only one
to be served. If you have no usable capacity in either direction, the Lightning
section is simply omitted from your offer.

Your maker also runs two background threads while Lightning is enabled: an
event pump that routes node events to the right swap, and a watchdog that
settles or refunds swaps whose final message never arrived.

## When something goes wrong

Every Lightning swap is backed by an on-chain HTLC with a refund branch, and the
state needed to claim or refund it is written to your (encrypted) wallet file
*before* any value is committed. A crash or a maker that disappears mid-swap
does not cost you the funds.

To finish anything left over:

```bash
$ ./taker recover
```

`recover` handles both coinswaps and Lightning swaps. If there are no
coinswaps outstanding it says so and continues to the Lightning side rather
than stopping:

```
No unfinished coinswaps to recover
```

Because recovery depends on the refund branch becoming spendable, leave the
node running — or re-run `recover` later — until it reports the swap as
resolved. A maker restarting mid-swap recovers the same way: its records are
restored into the live swap map on startup so it can still sweep or refund.

## Current limitations

- `ln-swap-out` needs a maker whose `ldk-server` is patched to allow a larger
  invoice `min_final_cltv_expiry_delta`. Stock `ldk-node` holds a payment for
  only a few blocks, which is narrower than the on-chain refund window, so a
  maker running it rejects swap-outs rather than risk losing the funds. Swap-in
  and routed swaps are unaffected.
- Requires an external `ldk-server` sidecar; there is no embedded node.
- The `ldk-server` dependency is pinned to a specific upstream commit, so build
  it from the matching revision.
- Lightning is off by default and must be compiled in.
