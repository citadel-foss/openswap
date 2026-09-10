# Funding-Source Blocklist

The blocklist allows a participant to refuse a swap when the counterparty's coins originate from a listed address.
It applies to both the Legacy (v1) and Taproot (v2) protocols, and is disabled by default.

## Matching

Screening examines the transaction by which the counterparty pays into the swap.
In Legacy that is its funding transaction; in Taproot, which has no separate funding transaction, it is the contract transaction that pays the taproot output.

For each input of that transaction, the previous output it spends is looked up on-chain and its `scriptPubKey` is compared against the scripts derived from the listed addresses.
A match refuses the swap.

Only the previous outputs need to be on-chain, never the transaction being screened.
In Legacy this lets the taker screen the maker's funding transaction while it is still unbroadcast, since the transaction reaches the taker in a protocol message.
In Taproot the maker waits for the contract transaction to confirm before screening it, while the taker screens it on arrival — after the maker has broadcast it, but usually before it confirms.

Two properties follow from this definition:

- **Single hop.** Only the immediate inputs are examined. An address that received coins from a listed address is not itself matched. This is a direct-spend check, not a taint analysis.
- **The output paid into the swap is not matched.** Each swap pays to an address derived from values exchanged during that swap — a 2-of-2 in Legacy, a taproot output in Taproot. It has not appeared on-chain before and will not appear again, so no list compiled in advance can contain it.

## Screening points

Each participant screens only the funding it directly receives.
Intermediate maker-to-maker hops are not screened by the taker.

```text
Taker → Maker 1 → Maker 2 → Taker

Maker 1 screens the Taker's funding
Maker 2 screens Maker 1's funding
Taker   screens Maker 2's funding
```

| Protocol | Role  | Screened at | Counterparty funded | Cost to refuse |
|----------|-------|-------------|---------------------|----------------|
| Legacy   | Maker | `ProofOfFunding`, before constructing its own funding | yes | reserved UTXOs released |
| Legacy   | Taker | `ReqContractSigsAsRecvrAndSender` | not yet broadcast | timelock recovery |
| Taproot  | Maker | contract data, after confirmation, before constructing its own funding | yes | reserved UTXOs released |
| Taproot  | Taker | contract data returned by the final maker | yes | timelock recovery |

A maker screens before broadcasting its own funding transaction, so refusal releases its reserved UTXOs and costs nothing further.
A taker has already funded the swap when the counterparty's funding transaction becomes visible, so refusal means abandoning it and reclaiming its coins through timelock recovery.
The taker always funds first, so this asymmetry follows from the protocol rather than from the blocklist.

## Constraints

| Condition | Behaviour |
|-----------|-----------|
| Input count above the configured maximum | Refused without screening |
| Previous output cannot be resolved | Refused |
| List empty | Returns without querying the node |
| Entry's address encodes a different network | Skipped, with address and reason recorded |
| All entries skipped | List behaves as empty |

The input bound exists because each input costs one query against the participant's own node, and the transaction originates with the counterparty.

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

Two participants may hold different lists, or none, without affecting the protocol.

## Populating the list

Addresses may be added individually or imported in bulk from a published dataset such as [OpenSanctions](https://www.opensanctions.org/), which publishes sanctioned crypto wallets.

OpenSanctions data is [CC-BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/): personal and non-commercial use only.
Their terms count compliance screening as commercial use even where it generates no revenue, so operating as a business requires a licence from them.
The underlying sanctions lists can be consumed directly from their publishers instead. OpenSanctions aggregates hundreds of sources whose terms differ — some are public domain, others carry their own reuse conditions — so check each publisher's licence before relying on it.

Selecting Bitcoin addresses requires either a Bitcoin chain tag or a `bc1` prefix:

- Roughly 45% of wallet records carrying an address have no chain tag, so the tag alone is insufficient.
- Other chains in the same data use Bitcoin's base58 form, so a record beginning `1` or `3` is not necessarily a Bitcoin address.

An importer should therefore accept a record when its chain tag names Bitcoin, or when its address begins `bc1`, a prefix no other chain uses.
The prefix test is case-insensitive: Bech32 addresses are also valid in all-uppercase form, so `BC1` must match as well.
