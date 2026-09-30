# Taproot OpenSwap Protocol Documentation

## Overview

This document describes the complete taproot-based openswap protocol implementation using MuSig2 signatures for enhanced privacy and efficiency. The protocol enables trustless atomic swaps between a taker and multiple makers in a cyclic flow.

## Protocol Architecture

### Core Concepts

- **Cyclic Flow**: Funds flow in a circle (Taker → Maker0 → Maker1 → ... → Taker) to break transaction links
- **Taproot Contracts**: P2TR outputs with script trees for cooperative (key path) and non-cooperative (script path) spending
- **MuSig2 Signatures**: Schnorr signature aggregation for the cooperative spending path
- **Dual Spending Modes**: 
  - **Happy Path**: MuSig2 key spend (cooperative, private, efficient)
  - **Recovery Path**: Script spend using hashlock/timelock (non-cooperative, for failures)

### Transaction Structure

Each contract transaction uses P2TR with this structure:
```
P2TR Output:
├── Internal Key: MuSig2_KeyAgg(party1_pubkey, party2_pubkey)
├── Script Tree:
│   ├── Hashlock Script: "OP_SHA256 <hash> OP_EQUALVERIFY <receiver_pubkey> OP_CHECKSIG"
│   └── Timelock Script: "<locktime> OP_CLTV OP_DROP <sender_pubkey> OP_CHECKSIG"
└── Tap Tweak: Derived from script tree merkle root
```

## Complete Message Flow (1 Taker + 2 Makers)

Every connection starts with the same handshake. The taker sends `TakerHello`. The maker answers `MakerHello` with the protocol versions it supports. During a Taproot swap, the taker stops if Taproot is not in that list.

The taker opens a new connection to each maker for each phase. Each message travels as a variant of `TakerToMakerMessage` or `MakerToTakerMessage`.

### Phase 1: Discovery and Negotiation

The taker talks to the makers one at a time, in route order. Maker0 goes first, because Maker1's amount depends on Maker0's reply.

```
1. Taker → Maker0: TakerHello
2. Maker0 → Taker: MakerHello { supported_protocols }

3. Taker → Maker0: GetOffer
4. Maker0 → Taker: Offer {
    base_fee, amount_relative_fee_pct, time_relative_fee_pct,
    required_confirms, minimum_locktime, max_size, min_size,
    tweakable_point, fidelity, tweak_chain_code, name, lightning,
}

5. Taker → Maker0: SwapDetails {
    id, protocol_version: Taproot, amount, tx_count, incoming_count,
    max_input_budget, feerate, timelock, refund_locktime_offset,
}
6. Maker0 → Taker: AckSwapDetails {
    tweakable_point: Some(maker0_tweakable_point),
    funding_splits: [inputs per planned contract tx],
}

7.  Taker → Maker1: TakerHello
8.  Maker1 → Taker: MakerHello { supported_protocols }
9.  Taker → Maker1: GetOffer
10. Maker1 → Taker: Offer { ... }
11. Taker → Maker1: SwapDetails { ... }
12. Maker1 → Taker: AckSwapDetails { tweakable_point: Some(maker1_tweakable_point), funding_splits }
```

For Taproot, `timelock` is an absolute block height: the negotiation height plus `refund_locktime_offset`. A maker rejects with `AckSwapDetails { tweakable_point: None, funding_splits: [] }`.

The taker also fetches offers earlier, when it syncs its offer book. That sync uses the same `TakerHello` and `GetOffer` exchange on its own connections.

### Phase 2: Contract Creation (Cyclic Flow)

Both directions use one message type, `TaprootContractData`. The taker sends it to a maker. The maker answers with its own `TaprootContractData` for the next hop.

Before funding, the taker draws one random hashlock nonce per maker. The hashlock key for hop `i` is `tweakable_point_i + nonce_i·G`. The taker sends `nonce_i` to maker `i` so that maker can rebuild the private key. The last hop's hashlock key is the taker's own key, with no nonce.

#### Step 1: Taker → Maker0 Contract
```
13. Taker creates, broadcasts, and waits for its contract transactions to confirm:
    - One contract tx per funding split
    - Output: P2TR(MuSig2(taker_contract_pubkey, maker0_tweakable_point), script_tree)
    - Hashlock key: maker0_tweakable_point + nonce_0·G
    - Timelock key: taker_contract_pubkey

14. Taker → Maker0: TakerHello          (new connection)
15. Maker0 → Taker: MakerHello

16. Taker → Maker0: TaprootContractData {
    id,
    pubkeys: [taker_contract_pubkey, ...],
    next_hop_point: maker1_tweakable_point,
    internal_keys, tap_tweaks,
    hashlock_script,                      // shared by every contract of the hop
    timelock_scripts,
    contract_txs: [taker_to_maker0_tx, ...],
    amounts,
    hashlock_nonce: Some(nonce_0),        // Maker0 rebuilds its hashlock key
    next_hashlock_nonce: Some(nonce_1),   // Maker0 builds Maker1's hashlock key
}

17. Maker0 checks the data and waits for the taker's contracts to confirm.
    Then it creates and broadcasts its own contract transactions:
    - Output: P2TR(MuSig2(maker0_outgoing_pubkey, maker1_tweakable_point), script_tree)
    - Hashlock key: maker1_tweakable_point + nonce_1·G

18. Maker0 → Taker: TaprootContractData {
    id,
    pubkeys: [maker0_outgoing_pubkey, ...],
    next_hop_point: maker0_tweakable_point,
    internal_keys, tap_tweaks, hashlock_script, timelock_scripts,
    contract_txs: [maker0_to_maker1_tx, ...],
    amounts,
    hashlock_nonce: None,
    next_hashlock_nonce: None,
}

19. Taker checks Maker0's hashlock key and waits for Maker0's contracts to confirm.
```

#### Step 2: Maker0 → Maker1 Contract (Forwarded via Taker)
```
20. Taker → Maker1: TakerHello          (new connection)
21. Maker1 → Taker: MakerHello

22. Taker → Maker1: TaprootContractData {
    id,
    pubkeys: [maker0_outgoing_pubkey, ...],     // Forwarded from Maker0
    next_hop_point: taker_incoming_pubkey,      // Cycle back to taker
    internal_keys, tap_tweaks, hashlock_script,
    timelock_scripts, contract_txs, amounts,    // Forwarded from Maker0
    hashlock_nonce: Some(nonce_1),
    next_hashlock_nonce: None,                  // Next hop is the taker
}

23. Maker1 checks the data and waits for Maker0's contracts to confirm.
    Then it creates and broadcasts its own contract transactions:
    - Output: P2TR(MuSig2(maker1_outgoing_pubkey, taker_incoming_pubkey), script_tree)
    - Hashlock key: taker_incoming_pubkey

24. Maker1 → Taker: TaprootContractData {
    pubkeys: [maker1_outgoing_pubkey, ...],
    contract_txs: [maker1_to_taker_tx, ...],    // Final contracts back to taker
    ...
    hashlock_nonce: None,
    next_hashlock_nonce: None,
}

25. Taker checks that the hashlock key is its own key and waits for Maker1's contracts to confirm.
```

### Phase 3: Private Key Handover and Sweeping

**Design Principle**: After contract creation, parties exchange their outgoing contract private keys in a forward flow. Each party independently sweeps their incoming contract using MuSig2 with both keys (their incoming key + sender's outgoing key).

#### Flow Description (1 Taker + 2 Makers)

```
26. Taker → Maker0: TakerHello          (new connection)
27. Maker0 → Taker: MakerHello

28. Taker → Maker0: TaprootPrivateKeyHandover {
    id,
    privkeys: [taker_contract_privkey, ...]   // Taker's keys for Taker→Maker0 contracts
}

29. Maker0 checks each key against its incoming contracts and stores it.

30. Maker0 → Taker: TaprootPrivateKeyHandover {
    id,
    privkeys: [maker0_outgoing_privkey, ...]  // Maker0's keys for Maker0→Maker1 contracts
}

31. After sending its reply, Maker0 sweeps the Taker→Maker0 contracts:
    - Creates the spending transaction
    - Generates fresh nonce pairs for both keys it now holds
    - Creates both partial signatures with MuSig2 and aggregates them
    - Broadcasts the sweep transaction

32. Taker → Maker1: TakerHello          (new connection)
33. Maker1 → Taker: MakerHello

34. Taker → Maker1: TaprootPrivateKeyHandover {
    id,
    privkeys: [maker0_outgoing_privkey, ...]  // Relayed from Maker0
}

35. Maker1 checks each key against its incoming contracts and stores it.

36. Maker1 → Taker: TaprootPrivateKeyHandover {
    id,
    privkeys: [maker1_outgoing_privkey, ...]  // Maker1's keys for Maker1→Taker contracts
}

37. After sending its reply, Maker1 sweeps the Maker0→Maker1 contracts the same way.

38. Taker checks that each of Maker1's keys matches the expected pubkey of its incoming contracts.
    Then it sweeps the Maker1→Taker contracts the same way.
```

#### Message Type for Private Key Handover

```rust
TakerToMakerMessage::TaprootPrivateKeyHandover(PrivateKeyHandover)
MakerToTakerMessage::TaprootPrivateKeyHandover(PrivateKeyHandover)

PrivateKeyHandover {
    id: String,                  // Swap ID
    privkeys: Vec<SwapPrivkey>,  // One outgoing contract key per contract
}
```

#### Key Characteristics

1. **Forward Flow**: Each party sends their OUTGOING contract private keys
2. **Independent Sweeping**: Each party generates their own nonces and performs MuSig2 aggregation locally
3. **No Coordination Required**: No need to exchange nonces or partial signatures between parties
4. **Two Messages per Maker**: One key handover in, one key handover back, after the handshake
5. **Security Note**: Contract keys are fresh for each swap. The taker draws a random key for each outgoing contract, and a fresh one for its incoming side. A maker's outgoing key is its tweakable key plus a fresh random tweak. The m/175' path gives only the maker's tweakable key. The maker uses it as its side of each incoming contract and never hands it over. A handed-over key belongs to that one contract only

## Spending Transaction Details

### All Three Spending Transactions

#### Maker0's Spending Transaction (from Taker's Contract)
```rust
Maker0_Spending_Transaction:
├── Input[0]:
│   ├── previous_output: taker_to_maker0_txid:0
│   ├── script_sig: empty
│   └── witness: [maker0_taker_aggregated_signature]
└── Output[0]:
    ├── value: swap_amount - fees
    └── script_pubkey: maker0_receiving_address
```

#### Maker1's Spending Transaction (from Maker0's Contract)
```rust
Maker1_Spending_Transaction:
├── Input[0]:
│   ├── previous_output: maker0_to_maker1_txid:0
│   ├── script_sig: empty
│   └── witness: [maker1_maker0_aggregated_signature]
└── Output[0]:
    ├── value: swap_amount - fees
    └── script_pubkey: maker1_receiving_address
```

#### Taker's Spending Transaction (from Maker1's Contract)
```rust
Taker_Spending_Transaction:
├── Input[0]:
│   ├── previous_output: maker1_to_taker_txid:0
│   ├── script_sig: empty
│   └── witness: [taker_maker1_aggregated_signature]
└── Output[0]:
    ├── value: swap_amount - fees
    └── script_pubkey: taker_receiving_address
```

### Sighash Calculation
After the handover, the receiver holds both keys. It calculates the sighash once and makes both partial signatures from it:

```rust
// Example: Taker calculating the sighash for its spending tx
let sighash = SighashCache::new(&taker_spending_tx)
    .taproot_key_spend_signature_hash(
        0,                           // input_index
        &prevouts,                   // Previous outputs (maker1's contract output)
        TapSighashType::Default      // sighash_type
    )?;
let message = Message::from(sighash);

// The taker signs this message with its own key and with maker1's handed-over key
```

## Complete Protocol Summary

### Total Message Flow
With 2 makers, the complete taproot openswap involves **28 messages** across 3 phases. Each maker adds 14:

1. **Discovery (12 messages, 6 per maker)**: Handshake, offer fetching, and swap negotiation
2. **Contract Creation (8 messages, 4 per maker)**: Handshake and cyclic contract setup
3. **Private Key Handover (8 messages, 4 per maker)**: Handshake and forward-flow exchange of outgoing contract keys

These counts leave out the offer book sync, retries, and keepalives. During phases 2 and 3, the taker sends `WaitingFundingConfirmation(swap_id)` keepalives to each maker on separate connections. The maker does not reply to them.

### Execution Order
The protocol phases execute sequentially with taker coordination:

```
Phase 1: Discovery & Negotiation (messages 1-12)
    ↓
Phase 2: Contract Creation (steps 13-25)
    ↓
Phase 3: Private Key Handover & Sweeping (steps 26-38)
    ├─ Taker → Maker0: Taker's outgoing keys
    ├─ Maker0 returns Maker0's outgoing keys, then sweeps
    ├─ Taker → Maker1: Maker0's outgoing keys (relayed)
    ├─ Maker1 returns Maker1's outgoing keys, then sweeps
    └─ Taker sweeps using Maker1's outgoing keys
```

### Non-Cooperative Cases (Recovery Paths)

#### Hashlock Path (Receiver Claiming)
```rust
// Receiver can claim using preimage without sender cooperation
witness: [
    receiver_signature,
    preimage,
    hashlock_script,
    control_block,  // Proves script is in taproot tree
]
```

#### Timelock Path (Sender Recovery)
```rust
// Sender can recover funds after timeout without receiver cooperation
witness: [
    sender_signature,
    timelock_script,
    control_block,
]
```

## Message Types

Messages travel as variants of `TakerToMakerMessage` and `MakerToTakerMessage`.

### Handshake and Discovery Messages
```rust
TakerHello
MakerHello {
    supported_protocols: Vec<ProtocolVersion>,  // Legacy, Taproot
}

GetOffer
Offer {
    base_fee: u64,
    amount_relative_fee_pct: f64,
    time_relative_fee_pct: f64,
    required_confirms: u32,
    minimum_locktime: u16,
    max_size: u64,
    min_size: u64,
    tweakable_point: PublicKey,
    fidelity: FidelityProof,
    tweak_chain_code: ChainCode,
    name: String,
    lightning: Option<LightningOffer>,
}

SwapDetails {
    id: String,
    protocol_version: ProtocolVersion,
    amount: Amount,
    tx_count: u32,                // Most contract txs this hop may send
    incoming_count: u32,          // Exact contract txs the taker sends this hop
    max_input_budget: u32,
    feerate: u64,                 // sats/vB
    timelock: u32,                // Taproot: absolute block height
    refund_locktime_offset: u16,
}
AckSwapDetails {
    tweakable_point: Option<PublicKey>,  // None means rejected
    funding_splits: Vec<u32>,            // Inputs per planned contract tx
}
```

### Contract Messages
```rust
TaprootContractData {
    id: String,
    pubkeys: Vec<PublicKey>,
    next_hop_point: PublicKey,
    internal_keys: Vec<XOnlyPublicKey>,
    tap_tweaks: Vec<SerializableScalar>,
    hashlock_script: ScriptBuf,
    timelock_scripts: Vec<ScriptBuf>,
    contract_txs: Vec<Transaction>,
    amounts: Vec<Amount>,
    hashlock_nonce: Option<SecretKey>,       // None in maker replies
    next_hashlock_nonce: Option<SecretKey>,  // None for the last maker and in maker replies
}
```

### Private Key Handover Message
```rust
PrivateKeyHandover {
    id: String,
    privkeys: Vec<SwapPrivkey>,
}

SwapPrivkey {
    identifier: ScriptBuf,
    key: SecretKey,
}
```

**Usage**: After contract creation, each party sends their OUTGOING contract private keys to enable the receiver to sweep independently without coordination. The taproot flow sends it as `TaprootPrivateKeyHandover`.

## Implementation Architecture

### Key Components

1. **MuSig2 Engine** (`src/protocol/musig2.rs`)
   - Nonce generation and aggregation
   - Partial signature creation and aggregation
   - Key aggregation for internal keys

2. **Taproot Contracts** (`src/protocol/contract2.rs`)
   - Script tree construction
   - P2TR output creation
   - Control block generation

3. **Protocol Messages** (`src/protocol/taproot_messages.rs` and `src/protocol/common_messages.rs`)
   - Taproot contract data in `taproot_messages.rs`
   - Handshake, offer, negotiation, handover, and the top-level message enums in `common_messages.rs`

4. **State Management**
   - Taker: `OngoingSwapState` for tracking multi-maker flow
   - Maker: `ConnectionState` persisted across TCP connections