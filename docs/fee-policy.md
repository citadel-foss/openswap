# Fee policy and funding splits

This document explains what a coinswap costs and why. It covers the settings
that shape the price, who pays which part, and how both sides check the
numbers. It describes the policy in plain terms. It does not describe the
code.

## The players and the settings

A swap moves your coins through one or more makers. A maker is a stranger's
server that trades coins with you. You are the taker. At the end you hold
different coins, and nothing links the new coins back to the old ones.
Call one maker's leg of the journey a hop.

Four numbers shape every swap:

- **Feerate** — the price paid to miners, in sats per virtual byte (sat/vB).
  A sat is the smallest unit of bitcoin. A virtual byte is the unit Bitcoin
  uses to measure transaction size. The default is 1. One rate applies to
  every transaction in the swap.
- **Funding transaction count** (`tx_count`) — the most funding transactions
  a maker may use for one hop. A funding transaction is the on-chain
  transaction that locks coins into a hop. The default is 2, the maximum is
  10. This is a ceiling, not a promise. A maker may deliver fewer.
- **Incoming count** — how many contracts a hop actually receives. A
  contract is a coin locked so that only the swap can unlock it. You do not
  set this number. It comes out of the funding plan, and both sides check
  it for exact equality.
- **Input budget** (`max_input_budget`) — how many inputs per funding
  transaction you pay for. The default is 2, the maximum is 10. This is a
  billing cap, not a permission. A maker may use more inputs. The extra
  ones are the maker's own cost.

Two rules protect these numbers. No count may pass 10. That way a stranger
cannot make your node do unbounded work. The feerate may not go below
1 sat/vB, because Bitcoin nodes do not forward cheaper transactions. Every
place you can set these numbers rejects bad values. Nothing silently
corrects them.

## Who pays what

For each hop, you pay exactly three things:

1. **The service fee** — the maker's price for doing the swap. Each maker
   sets its own price in its public offer. An offer is the maker's
   advertised price list.
2. **The funding fee** — the maker spends miner fees to build its funding
   transactions. You cover this, up to the input budget, at the swap
   feerate.
3. **The sweep fee** — at the end, the maker claims each contract it
   received. You cover one claim per contract, at the swap feerate.

The maker pays for everything else. That means inputs beyond the budget,
and any claim that costs more than the fixed sizes below. If the maker
combines several claims into one cheaper transaction, it keeps the savings.
The fixed sizes still set your price.

You also pay the ordinary miner fee for your own first funding transaction,
just like any wallet send.

## How the service fee is set

Each maker's offer carries three numbers:

- a **flat part** (default 500 sats),
- an **amount part** (default 0.0025% of the swapped amount),
- a **time part** (default 0.0001% of the amount per block of lock time).

The lock time is how long the coins stay locked if the swap fails. Longer
locks cost the maker more. They cost you more too. Different makers charge
different prices. You see the full price before you confirm anything.

## How the miner fees are set

Both sides must agree on miner fees before any money moves. Neither side
can measure the transactions in advance. The policy prices them with fixed
sizes instead:

- **Funding transaction:** 97 virtual bytes, plus 68 per input.
- **Claim transaction:** 166 virtual bytes for taproot, 204 for legacy.

Taproot and legacy are the two transaction types the swap supports. Taproot
is the newer one.

These sizes slightly overestimate real transactions. That is deliberate.
Both sides use the same sizes and the same feerate. Your quoted price and
the built transaction can never drift apart. If the agreed numbers cannot
produce an exact price, the swap stops. Neither side estimates.

Both sides agree the feerate once, at the start. A reconnect cannot change
it. The maker stores the whole agreement and demands an exact match if you
return.

## A worked example

Say you swap 500,000 sats through one maker, with the default settings.
Taproot, feerate 1 sat/vB, 20 blocks of lock time. The maker delivers 2
funding transactions with 1 input each.

**Service fee:**

- Flat part: 500 sats.
- Amount part: 0.0025% of 500,000 = 12.5 sats.
- Time part: 0.0001% of 500,000 times 20 blocks = 10 sats.
- Total: 522.5, rounded up to **523 sats**.

**Funding fee:** one transaction costs 97 + 68 = 165 virtual bytes. That is
165 sats at 1 sat/vB. Two transactions: **330 sats**.

**Sweep fee:** one taproot claim costs 166 virtual bytes. That is 166 sats.
Two contracts: **332 sats**.

**What you receive:** 500,000 − 523 − 330 − 332 = **498,815 sats**.

The hop costs 1,185 sats in total, about 0.24%. You also pay the miner fee
for your own funding transaction on top. At 5 sat/vB the two miner fees
grow fivefold (1,650 + 1,660). The service fee stays the same.

## Funding splits

Makers rarely hold one coin of exactly the right size. They hold many coins
of different sizes. A maker may fund one hop with several smaller
transactions instead of one big one. These are the splits.

The planner works like this:

- It tries to reach your `tx_count` first. If the maker's coins cannot
  cover that many splits, it tries one fewer, then one fewer, down to 1.
  A maker whose wallet holds many small coins delivers fewer splits. The
  swap still runs. The swap never fails just because the split count comes
  out lower.
- Each split uses the fewest coins that cover it. Ties go to the smallest
  total value. That way an early split never eats coins a later split
  needs.
- No split may be smaller than 5,000 sats. Below that, the miner fees
  cost more than the split is worth.
- Once the maker accepts a swap, it freezes the plan. It reserves the
  chosen coins for that swap, and nothing else can spend them. Funding
  time follows the frozen plan exactly. It never re-plans.

## What the maker checks

You set the feerate and the input budget. The maker protects itself from a
bad deal. Before it locks anything, it adds up what it would spend on
inputs beyond your budget. If that cost is larger than the service fee the
hop earns, the maker refuses the swap. A swap that costs the maker more
than it earns never starts.

## What the taker checks

You do not trust the maker's numbers. Your node checks them against the
chain:

- **Exact totals and counts.** The funded amount must equal the agreed
  amount to the sat. The contract count must equal the accepted plan.
- **Real outputs.** Every claimed amount must match a real on-chain
  output. One funded output cannot back two contracts in the same hop.
- **The real miner fee.** Your node fetches the maker's funding inputs and
  recomputes the fee actually paid. Your node catches a maker that charges
  one rate and builds cheaper.
- **No replays.** The maker also refuses a funding output that is already
  spent, or one that belongs to another swap. Replayed data can never
  fund a second hop.

Your node records a proven cheat in the offerbook, its local record of
known makers. One proof already sidelines the maker. Enough proofs mark it
bad for good. A timeout or a node failure never counts as proof. Only
arithmetic does.

## Before you confirm

The command line shows you the ceiling, not the best case. It adds up the
service fees, the largest possible funding fee (every split at the full
input budget), the sweep fees, and your own funding fee. The label says
"Maximum total cost (ceiling)". The final report after the swap uses the
real transactions. It can be lower than the ceiling, never higher.

## PaySwap

A normal swap returns your own coins to you. A PaySwap uses the same route
to pay someone else. The receiver gets an ordinary-looking payment of
exactly the amount you chose. Nothing links that payment back to your
wallet. That unlinkability is the whole point, and it shapes every rule
below.

Here is the flow, step by step:

1. You give the receiver's address and an exact amount, say 50,000 sats.
2. Your node plans the route at the ceiling. It assumes every maker
   charges the most possible: full splits, full input budget. It sizes
   the last hop to leave the receiver exactly 50,000 in that worst case.
3. The swap runs like any other, until the last hop. There, your node
   claims the maker's coins straight to the receiver's address instead of
   its own. Each incoming coin becomes one output of the payment.
4. Each output keeps a small reserve for its own claim's miner fee. Every
   output must stay above the dust limit. That limit is about 546 sats.
   Bitcoin nodes refuse to forward smaller outputs.
5. Makers often come in cheaper than the worst case. That leaves a
   leftover. The leftover cannot go back to you as change. A change
   output would link the payment to your wallet. Your node shaves the
   leftover off the largest outputs instead, never below dust. The shaved
   amount becomes extra miner fee on the payment transaction. This burn
   is deliberate. It is the price of the payment staying unlinked.
6. After shaving, the outputs add up to the requested amount to the sat.
   The receiver sees exactly 50,000 sats arrive.

Two rules follow from this design. Your amount must be at least 546 times
`tx_count`. That way every output can stay above dust even at the maximum
split count. A PaySwap also never substitutes a maker mid-route. If a maker
fails, the payment aborts and your coins come back through recovery. The
payment never finishes through a different maker at a different price.
