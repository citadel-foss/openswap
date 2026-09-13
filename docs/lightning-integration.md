# Lightning Integration Design

**Status:** Draft / exploration
**Lightning stack:** [LDK Server](https://github.com/lightningdevkit/ldk-server) run as a sidecar daemon, driven over its gRPC/protobuf API (see stack decision below)

This document covers three integration tracks, each building on the previous:

1. **Channel lifecycle privacy** — coinswap around channel open/close
2. **Submarine swaps** — atomic on-chain ↔ LN exchanges, makers as providers
3. **LN-routed coinswap** — Lightning as the middle hops of a coinswap route

```
Track 1 (channel open/close)      standalone, feasible today
Track 2 (submarine swaps)         hold invoices via Bolt11ReceiveForHash
Track 3 (LN-routed coinswap)      composes Track 2 primitives
```

---

## 1. Common foundation

### Stack decision: LDK Server as a sidecar daemon

Candidates considered: LDK Server (standalone node daemon, gRPC/protobuf API)
and raw `rust-lightning` (protocol library, maximum flexibility).

| Capability | LDK Server | raw `rust-lightning` |
|---|---|---|
| Hold-HTLC-by-hash (Tracks 2–3) | **yes** — `Bolt11ReceiveForHash` / `Bolt11ClaimForHash` / `Bolt11FailForHash` | yes |
| External/PSBT channel funding (Track 1) | no | yes |
| Custom shutdown script (Track 1) | no | yes |
| Node plumbing provided (chain sync, persistence, gossip, sweeping) | yes | **no — build it all** |

**Decision: run LDK Server.**

- The feasibility-critical capability — accepting an inbound HTLC for an
  externally supplied hash, holding it unsettled, and claiming later with an
  externally learned preimage — is exposed in LDK Server's API:
  `Bolt11ReceiveForHash` + `Bolt11ClaimForHash` / `Bolt11FailForHash`. This
  unblocks Track 2 swap-out and all of Track 3 without upstream work.
- Process isolation: the LN node survives makerd/taker restarts and upgrades
  independently of coinswap releases. Deployment mirrors the existing
  `bitcoind` sidecar pattern (Tor-only, local gRPC endpoint).
- `SubscribeEvents` provides the event stream the orchestrator needs for
  payment/close detection.
- Raw `rust-lightning` would also fix the Track 1 gaps, but at the cost of
  owning a node's worth of security-sensitive plumbing and LDK's release churn.
  Those gaps only cost one extra transaction each way (see Track 1 cost note),
  which doesn't justify it. Raw LDK remains the fallback if an upstream need
  stalls.

### Remaining LDK Server constraints (drive Track 1's design)

- Channels are funded from the node's **internal on-chain wallet**; PSBT /
  external channel funding is not exposed (raw rust-lightning supports it via
  `FundingGenerationReady`).
- Custom shutdown scripts (close address) are not exposed; cooperative close
  outputs land in the internal wallet.

### Orchestrator component

An orchestrator (new binary, or extension of `taker`) that connects to the LDK
Server sidecar as a gRPC client and:

- drives the node via the protobuf API (`OnchainReceive` / `OnchainSend`,
  `OpenChannel` / `CloseChannel`, `Bolt11Send` / `Bolt11Receive` /
  `Bolt11ReceiveForHash` / `Bolt11ClaimForHash`, `SubscribeEvents`)
- drives `Taker::prepare_coinswap` / `start_coinswap`
- enforces wallet-hygiene invariants (Track 1) and manages swap state machines
  (Tracks 2–3)

### Upstream wishlist (removes costs below; nothing here is a blocker)

1. External/PSBT channel funding in LDK Server → eliminates Track 1's extra
   deposit transaction and the swap-only-wallet quarantine.
2. Custom shutdown script exposure in LDK Server → eliminates Track 1's
   close-side hop transaction.
3. (Long-term) LN PTLCs → restores cross-hop decorrelation in Track 3.

---

## 2. Track 1: Channel lifecycle privacy

### Goal

- **Open:** the funding UTXO has no on-chain link to the user's prior coins, so
  the node identity (pubkey, IP/Tor) cannot be tied to wallet history. For
  *public* channels the funding outpoint is gossiped with the node pubkey — the
  swap protects history, not the channel itself.
- **Close:** the close output is publicly linked to the node; coinswapping it
  afterward unlinks post-channel funds from the node identity.

### Design response to the no-external-funding constraint: swap-only LDK wallet

Treat the LDK Server node's on-chain wallet as quarantined: it *only ever
receives coinswapped outputs*. Channel funding is then unlinked by construction with
implicit coin control (there are no tainted coins to select).

### Flow: channel open

```
coinswap → swapped UTXOs in taker wallet → send to LDK wallet address → OpenChannel
```

1. Taker completes a normal coinswap; unlinked swap UTXOs land in the taker wallet.
2. Get a deposit address from the LDK Server node (`OnchainReceive`).
3. Transfer swapped coins with `Wallet::spend_from_wallet` (`src/wallet/spend.rs`),
   passing only swap-tagged UTXOs (`list_utxo_swap`) as `coins_to_spend`.
   `Destination::Multi` for exact amounts, `Destination::Sweep` to move everything.
4. Once confirmed, `OpenChannel`; the node funds from its (swap-only) internal wallet.

Deposit sizing: channel capacity + funding-tx fee + the node's anchor reserve.

### Flow: channel close

```
CloseChannel → close output lands in LDK wallet → OnchainSend to taker wallet → coinswap
```

The extra hop (LDK wallet → taker wallet) is observable and does not itself break
the link — the subsequent swap does the unlinking.

**Known gap:** the taker swap-funding path needs UTXO selection so a swap can be
pinned to specific source coins (the deposited close output). Verify whether
`SwapParams` / `src/wallet/funding.rs` supports this; if not, that is the first
concrete PR.

### Cost note

Versus an LND-style PSBT funding shim, this design costs **one extra transaction
each way** (deposit tx on open, hop tx on close, ~110–150 vB each). Structurally
unavoidable with LDK Server today: swap outputs must be held by taker-controlled
keys (they can't land in the node's internal wallet), and channel funding/close
outputs are confined to the internal wallet. Upstream wishlist items 1 and 2
remove these costs.

### Privacy caveats

1. **Last-hop maker knows the taker's received UTXOs** and can watch them become
   a channel funding output, linking them to gossip data. Mitigate with
   multi-maker routes (`maker_count >= 2`) and a delay before deposit.
2. **Timing correlation:** randomized delays at each phase boundary.
3. **Amount correlation:** use `tx_count` splits; avoid channel capacities equal
   to any single swap output.
4. **Wallet hygiene is the security model:** one unswapped deposit permanently
   taints the LDK wallet (the node does its own coin selection; no per-open
   coin control).

### Rejected alternative: atomic funding (swap output = funding output)

Not expressible through LDK Server (no external funding API); even with raw LDK,
funding-reservation timeouts vs multi-confirmation swap duration, plus
settlement-to-external-script protocol changes and abort teardown, make it
impractical. Two-phase gets nearly all the benefit; the only extra leak is the
hop between swap output and funding tx.

---

## 3. Track 2: Submarine swaps

Atomic exchanges between on-chain BTC and Lightning balance, secured by the same
hash preimage on both layers. **Makers act as providers; takers are clients.**

Terminology: *submarine swap* (Loop In) = swap-in, on-chain → LN.
*Reverse submarine swap* (Loop Out) = swap-out, LN → on-chain.

### Why this fits coinswap naturally

1. **The contract primitive already exists.** Coinswap contracts are
   hashlock + timelock scripts (`src/protocol/contract.rs`; taproot leaf scripts
   in the MuSig2 flow) — the same construction submarine swaps need, and both
   hash160-on-chain and sha256-on-LN commit to the same 32-byte preimage.
2. **Maker infrastructure carries over:** offer discovery (Nostr), Tor, fidelity
   bonds (provider sybil resistance), watch-tower, fee model.
3. **The Track 1 orchestrator provides the LN client.**

### Swap-in (taker: on-chain → LN)

```
1. Taker → Maker: SwapInRequest { invoice, amount }        (invoice carries hash H)
2. Maker → Taker: SwapInQuote { fee, htlc_pubkey, min_conf, expiry }
3. Taker broadcasts on-chain HTLC(H, maker_key, refund_to_taker after T)
4. Maker waits min_conf, then pays the invoice over LN
5. LN settlement reveals preimage to maker → maker claims the HTLC on-chain
6. Refund: if maker never pays, taker reclaims via timelock T
```

`P` is generated by the **invoice recipient** — the taker's own LDK Server node
in the top-up case (`Bolt11Receive`), or a third party if the taker is having an
external invoice paid. The maker never knows `P` upfront: receiving it as LN
proof-of-payment is what arms its on-chain claim.

Maker risk ≈ zero (pays LN only after the HTLC confirms). Taker risk: capital
locked until `T` on maker failure. Self-invoice subtlety: the taker could hold
the maker's LN payment and settle near `T` — the maker must cap its LN CLTV
exposure well below `T`.

### Swap-out / reverse submarine (taker: LN → on-chain)

```
1. Taker generates preimage P, H = sha256(P)
2. Taker → Maker: SwapOutRequest { H, amount }
3. Maker → Taker: SwapOutQuote { fee, prepay_invoice, hold_invoice(H), htlc_params }
   (hold invoice created via Bolt11ReceiveForHash(H) — maker doesn't know P)
4. Taker pays prepay (miner-fee griefing protection) and the hold invoice
   (HELD, not settled — maker cannot claim without P; Bolt11ClaimForHash(P) later)
5. Maker broadcasts on-chain HTLC(H, taker_key, refund_to_maker after T)
6. Taker claims on-chain with P → maker learns P → settles the held LN payment
7. Refund: hold invoice expires unsettled; maker reclaims HTLC via timelock
```

Maker risk: chain fees on griefing (mitigated by prepay, as in Lightning Loop).

### Timelock safety (critical)

On-chain refund timelock `T` must comfortably exceed the LN payment's maximum
CLTV exposure: `T > max_ln_cltv + safety_margin`. For swap-out, hold-invoice
expiry must end well before `T` so the maker can always refund. These margins
are protocol constants needing the same review as the existing contract cascade.

---

## 4. Track 3: LN-routed coinswap

**Opt-in route type beside the pure on-chain taproot flow, not a replacement.**

### Construction

```
Standard:    taker ──on-chain──> M1 ──on-chain──> M2 ──on-chain──> taker

LN-routed:   taker ──on-chain(H)──> M1 ──LN HTLC(H)──> M2 ──on-chain(H)──> taker
```

Structurally a swap-in and a reverse submarine swap sharing one payment hash,
with LN carrying the middle of the route.

**Why:** exactly 2 on-chain funding hops regardless of route length (vs N+1,
each with `tx_count` splits); intermediate hops cost millisat routing fees and
settle at LN speed; no on-chain path at all between taker input and output.

### Setup

1. Taker generates `P`, `H = sha256(P)` (fallback leaves must use sha256 for LN
   compatibility).
2. `taker→M1`: on-chain P2TR contract — key path MuSig2(taker, M1); leaves =
   hashlock(H) + timelock `T1` refund.
3. `M1→M2`: LN payment on `H`, CLTV expiry `E_LN`; M2 **holds** it (registered
   via `Bolt11ReceiveForHash(H)`, cannot settle without `P`).
4. `M2→taker`: on-chain P2TR contract — key path MuSig2(M2, taker); leaves =
   hashlock(H) paying taker + timelock `T2` refund.

Timelock cascade, decreasing toward the taker with margins:

```
T1  >  E_LN  >  T2
```

### Settlement — cooperative path

The hashlock leaves are **enforcement insurance, never used in the happy path**,
exactly like the current taproot protocol:

1. Taker verifies all three locks are in place and its incoming contract is
   unilaterally enforceable via the hashlock leaf.
2. Taker reveals `P` **off-chain via a protocol message**. Safe once locks exist:
   `P` gives M2 nothing (its contract's hashlock leaf pays the taker), and M1
   learning `P` is the intended payment.
3. M2 settles the held LN HTLC with `P`; M1 is paid on LN.
4. Cooperative MuSig2 key handover / key-path settlement on both contracts;
   outputs swept later as normal-looking P2TR spends.

**On-chain, the happy path is indistinguishable from the current cooperative
flow:** no script reveal, no hashlock, no `H` visible.

### Non-cooperative paths

- **Taker aborts, never reveals `P`:** M2's held HTLC expires back to M1; both
  contracts refund via timelock. No fund loss.
- **M2 stonewalls after learning `P`:** taker claims via hashlock leaf on-chain
  (revealing `H`); M2 settles LN with the observed `P`; M1 claims the taker
  contract.
- **LN payment unroutable at setup:** abort before `P` reveal; timelock refunds.

### Privacy analysis

Preserved: happy-path on-chain footprint identical to today; no on-chain graph
link between endpoints.

Regressed (must be explicit in user-facing docs):

1. **Cross-hop decorrelation lost for the LN segment.** LN HTLCs are
   sha256-settled; M1, M2, and routing nodes all see the same `H` — per-hop
   adaptor-point blinding cannot extend across LN until PTLCs. Maker-collusion
   resistance drops to legacy level for this route type.
2. **Dispute-path correlation:** an on-chain hashlock claim reveals `H` matching
   the LN HTLC — a routing node watching the chain can link them.
3. **Mitigation:** prefer direct M1↔M2 channels, containing `H` visibility to the
   makers (who already see swap details under the legacy trust model).

### Additional requirements

- Maker LN liquidity: swap amount within M1→M2 capacity; MPP + pre-quote probing.
- Offerbook: LN capability, node id, liquidity bounds; route selection considers
  LN connectivity, not just fees/fidelity.
- Watch-tower: LN-side monitoring (force-closes with in-flight swap HTLCs).
- Griefing: taker locking the route without revealing `P` ties up M1→M2
  liquidity until `E_LN` — short expiries and/or prepay.

### Protocol changes (sketch)

- Route/hop type in swap negotiation: `OnChain` | `Lightning` per hop.
- LN-hop setup messages: M2 hold-registration for `H`, M1 payment intent,
  probe/quote exchange.
- Off-chain `P`-reveal settlement message (extends the existing settlement phase).
- sha256 hashlock leaves when the route contains an LN hop.
- Timelock parameter negotiation covering `T1 > E_LN > T2` with margins.

---

## 5. Roadmap

### Phase 0 — spikes (do first, cheap, de-risk everything)
- [ ] Validate `Bolt11ReceiveForHash` / `Bolt11ClaimForHash` semantics against
      our settlement timing: maximum hold duration, expiry behavior, interaction
      with force-closes while an HTLC is held
- [ ] Verify hash compatibility of `contract.rs` script builders with 32-byte LN
      preimages
- [ ] UTXO pinning in `SwapParams` / `src/wallet/funding.rs` (Track 1 close-side)

### Phase 1 — Track 1 (feasible today)
- [ ] Orchestrator: gRPC client for the LDK Server sidecar + taker driving
- [ ] Open flow (swap-only wallet, deposit, `OpenChannel`), close flow
- [ ] Randomized delays; wallet-hygiene enforcement
- [ ] Regtest integration tests (bitcoind + LDK Server)

### Phase 2 — Track 2 swap-in
- [ ] `SwapInRequest`/`SwapInQuote` message family; HTLC construction reusing
      `contract.rs`
- [ ] Maker handler (`Bolt11Send`, claim on preimage); taker
      `swap-in --invoice`; timelock refund
- [ ] Watch-tower monitoring (ZMQ/Core and Electrum backends)
- [ ] Offer advertisement: submarine capability, rates, min/max, LN node id
- [ ] Tests: happy path, maker no-pay refund, claim race near timeout

### Phase 3 — Track 2 swap-out
- [ ] Hold-invoice integration (`Bolt11ReceiveForHash` / `Bolt11ClaimForHash`,
      validated in Phase 0), prepay mechanics
- [ ] Maker HTLC funding + refund sweep; taker `swap-out --amount`, preimage
      management, on-chain claim
- [ ] Tests: happy path, taker never claims, fee-spike behavior

### Phase 4 — Track 3
- [ ] Hop-type negotiation + offerbook LN fields
- [ ] 2-maker LN-routed swap: setup, cooperative settlement, all three
      non-cooperative paths; timelock margin constants + review
- [ ] MPP + probing; N-maker routes; griefing protections
- [ ] Tests incl. LN force-close during in-flight swap

### Phase 5 — composition & polish
- [ ] Privacy chaining: coinswap → swap-in; swap-out → coinswap
- [ ] Fee estimation / quote expiry under mempool volatility
- [ ] GUI surfaces (taker-app; maker-dashboard pricing) with explicit
      privacy-trade-off disclosure for LN-routed swaps
- [ ] PTLC migration path when available (restores Track 3 decorrelation)
- [ ] User + provider docs

## 6. Open questions

1. Offer format: extend existing Nostr offer events or a parallel event kind?
2. Fee models: coinswap-style flat + proportional vs per-swap quotes (Loop
   style); intermediate makers in Track 3 pay no chain fees — how do
   `base_fee` / `amount_relative_fee_pct` reprice for LN hops?
3. Taproot HTLCs for submarine swaps from day one (key-path cooperative claim +
   script fallback) — cheaper, more private, consistent with protocol direction?
4. Batch claims for maker swap-in HTLCs (fee efficiency vs on-chain linking).
5. RBF-aware fee bumping for near-timeout claims in the watch-tower.
6. Track 3: restrict to direct-channel maker pairs initially? Does MPP help or
   just spread `H` wider? Can taker↔maker hops also go over LN (generalizing to
   pure LN-in / on-chain-out routes)?
7. `SubscribeEvents` stream vs polling for close/payment detection in the
   orchestrator; reconnection/replay semantics across sidecar restarts.

## 7. Prior art

- **Vortex** (Ben Carman): taproot channel opens inside coinjoins — Track 1's
  goal, different mixing primitive.
- **Boltz**: open-source submarine swap provider; scripts and timelock margins
  worth studying.
- **Lightning Loop**: Loop In/Out; prepayment design for griefing protection.
- **PeerSwap**: LN-node-to-LN-node submarine swaps; closest in spirit to
  maker↔taker swaps.
- **PTLC literature**: the eventual fix for `H` correlation across LN hops.
