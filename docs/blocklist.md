# Funding-Source Blocklist

The blocklist allows a participant to refuse a swap when coins funding it originate from a listed address.
It applies to the Legacy (v1) and Taproot (v2) protocols and to Lightning submarine swaps, and is disabled by default.

## Turning screening on

Set `check_blocklist = true` in the maker's or the taker's `config.toml`. It defaults to `false`.

Your node keeps the list in `blocklist.json`, in the parent of its data directory. By default, that is `~/.openswap/blocklist.json`. A missing file counts as an empty list.

With screening on, your node reads the file at startup. If your node cannot read or parse the file, it refuses to start.

## Matching

Screening examines a funding transaction: one that pays into a swap contract.
In Legacy that is a funding transaction; in Taproot, which has no separate funding transaction, it is the contract transaction that pays the taproot output.
In a Lightning swap it is the transaction that funds the on-chain HTLC, fetched from the chain by its txid once it confirms, so the check applies to the coins that actually confirmed.

For each input of that transaction, the previous output it spends is looked up on-chain and its `scriptPubKey` is compared against the scripts derived from the listed addresses.
A match refuses the swap.

Only the previous outputs need to be on-chain, never the transaction being screened.
In Legacy this lets the taker screen the maker's funding transaction while it is still unbroadcast, since the transaction reaches the taker in a protocol message.
In Taproot the maker waits for the contract transaction to confirm before screening it, while the taker screens it on arrival — after the maker has broadcast it, but usually before it confirms.

Two properties follow from this definition:

- **Single hop.** Only the immediate inputs are examined. An address that received coins from a listed address is not itself matched. This is a direct-spend check, not a taint analysis.
- **The output paid into the swap is not matched.** Each swap pays to an address derived from values exchanged during that swap — a 2-of-2 in Legacy, a taproot output in Taproot. It has not appeared on-chain before and will not appear again, so no list compiled in advance can contain it.

## Screening points

Each participant screens every funding transaction it is shown, not only the one that pays it.

```text
Taker → Maker 1 → Maker 2 → Taker

Maker 1 screens the Taker's funding
Maker 2 screens Maker 1's funding
Taker   screens Maker 1's and Maker 2's funding
```

The taker verifies each maker's contracts before passing them to the next hop, and that maker's funding arrives with them, so the taker screens every hop, intermediate ones included.
A maker is only ever shown its own incoming funding.

| Swap | Role | Screens | Screened at | Counterparty funded | Cost to refuse |
|------|------|---------|-------------|---------------------|----------------|
| Legacy | Maker | its incoming funding | `ProofOfFunding`, before constructing its own funding | yes | reserved UTXOs released |
| Legacy | Taker | each maker's funding | `ReqContractSigsAsRecvrAndSender` from that maker | not yet broadcast | timelock recovery |
| Taproot | Maker | its incoming contract | contract data, after confirmation, before constructing its own funding | yes | reserved UTXOs released |
| Taproot | Taker | each maker's contract | contract data returned by that maker | yes | timelock recovery |
| Lightning swap-in | Maker | the taker's HTLC funding | `SwapInFunded`, after confirmation, before paying the invoice | yes | nothing; the taker refunds its HTLC |
| Lightning swap-out | Taker | the maker's HTLC funding | `SwapOutFunded`, after confirmation, before claiming | yes | Lightning payment stays held until it expires or the maker cancels it |
| Lightning routed | Taker | the second maker's HTLC funding | `SwapOutFunded`, after confirmation, before claiming | yes | first-hop timelock refund |

A maker screens before broadcasting its own funding transaction, so refusal releases its reserved UTXOs and costs nothing further.
In Legacy, Taproot and routed swaps the taker has already funded on-chain when a maker's funding transaction becomes visible, so refusal means abandoning the swap and reclaiming its coins through timelock recovery.
In a direct Lightning swap-out the taker has only paid a hold invoice and has no on-chain output to refund, so refusal leaves that payment held until it expires or the maker cancels it.
The taker always commits first, so this asymmetry follows from the protocol rather than from the blocklist.

Refusing an intermediate hop aborts the whole route.
Every hop funded before that point waits out its timelock, the same cost as refusing the final maker.
In Legacy the taker screens a maker's funding before that maker broadcasts it; in Taproot, just after.

In a Lightning swap-in the maker answers with a rejection and never pays the invoice.
The rejection does not name the list or the entry.
In a swap-out or routed swap the taker screens before it records the HTLC for recovery, so recovery never claims refused coins either.
Not claiming keeps the preimage private, so the maker can never settle the Lightning payment.

## Constraints

| Condition | Behaviour |
|-----------|-----------|
| More than 25 inputs, list not empty | Refused without screening |
| Previous output cannot be resolved | Refused |
| List empty | Returns without querying the node |
| Entry's address encodes a different network | Skipped, with address and reason recorded |
| All entries skipped | List behaves as empty |

The input bound exists because each input costs one query against the participant's own node, and the transaction originates with the counterparty.
Inputs spending the same parent share one query.
Because the taker screens every hop, a route costs it up to 25 queries per maker funding transaction rather than only the final maker's.
None of these queries happen while screening is off or the list is empty.

Addresses encode their network, so a list compiled for one network loads as empty on another.
The scripts are network-independent — the same key hash yields the same `scriptPubKey` across networks, and only the address encoding differs — so this is a property of the stored representation, not of the underlying data.

## Storage

A single JSON document, shared by both roles, held in the parent of each role's data directory so that a maker and a taker on one host consult the same file.

```json
{
  "entries": [
    { "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "label": "Some Group" },
    { "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "label": null }
  ]
}
```

`label` is optional and is recorded in the refusal.

Rules:

- Entries are stored as address strings, but indexed and compared by the `scriptPubKey` each one derives to. Bech32 encoding is case-insensitive, so indexing by the string would admit two entries for one address.
- A batch addition applies whole or not at all. If any address fails validation, none are written. An address encoding a different network fails validation like any malformed one, so it cannot be added. The skipping described under Constraints applies only on load, to entries already in the file.
- Adding an address already present updates its label rather than appending.

## Relationship to the protocol

The blocklist is local policy and does not appear in any message.
A peer cannot determine whether a counterparty applies one, and a refusal is indistinguishable from any other abandoned swap.
This prevents peers from probing which addresses a participant considers unacceptable.

A match aborts the swap but is never recorded against the peer and never bans it: the peer cannot know what the list contains, so funding from a listed address is not misbehaviour.

Two participants may hold different lists, or none, without affecting the protocol.

## Populating the list

To add or remove one address, use these commands:

```bash
$ ./maker-cli blocklist-add <address> --label "<why it is blocked>"
$ ./maker-cli blocklist-remove <address>
$ ./taker blocklist-add <address> --label "<why it is blocked>"
$ ./taker blocklist-remove <address>
```

`maker-cli` sends the change to a running `makerd`. `taker` edits the file itself. Both print the result, such as `Added: 1, updated: 0` or `Removed: 1`. See the [maker-cli doc](./maker-cli.md#blocklist) for details.

Addresses may be added individually or imported in bulk from a published dataset such as [OpenSanctions](https://www.opensanctions.org/), which publishes sanctioned crypto wallets.

OpenSanctions data is [CC-BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/): personal and non-commercial use only.
Their terms count compliance screening as commercial use even where it generates no revenue, so operating as a business requires a licence from them.
The underlying sanctions lists can be consumed directly from their publishers instead. OpenSanctions aggregates hundreds of sources whose terms differ — some are public domain, others carry their own reuse conditions — so check each publisher's licence before relying on it.

Selecting Bitcoin addresses requires either a Bitcoin chain tag or a `bc1` prefix:

- Roughly 45% of wallet records carrying an address have no chain tag, so the tag alone is insufficient.
- Other chains in the same data use Bitcoin's base58 form, so a record beginning `1` or `3` is not necessarily a Bitcoin address.

An importer should therefore accept a record when its chain tag names Bitcoin, or when its address begins `bc1`, a prefix no other chain uses.
The prefix test is case-insensitive: Bech32 addresses are also valid in all-uppercase form, so `BC1` must match as well.
