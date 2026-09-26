//! Domain types shared by all Lightning backends.
//!
//! These types are deliberately independent of any specific backend client
//! (e.g. the LDK Server protobufs) so that backend API churn stays contained
//! inside the backend implementation.

use bitcoin::{
    hashes::{hex::DisplayHex, sha256, Hash},
    secp256k1::PublicKey,
    Amount, BlockHash,
};

/// Static information about the Lightning node backing a [`LightningBackend`].
///
/// [`LightningBackend`]: crate::lightning::LightningBackend
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    /// The node's public key (node id).
    pub node_id: PublicKey,
    /// Height of the best block the node's wallets are synced to.
    pub block_height: u32,
    /// Hash of the best block the node's wallets are synced to.
    pub block_hash: BlockHash,
}

/// Snapshot of the node's on-chain and Lightning balances.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Balances {
    /// Total balance of the node's on-chain wallet.
    pub total_onchain: Amount,
    /// Currently spendable on-chain balance (confirmed, minus anchor reserves).
    pub spendable_onchain: Amount,
    /// On-chain amount retained as anchor-channel emergency reserve.
    pub anchor_reserve: Amount,
    /// Total claimable balance across all Lightning channels.
    pub total_lightning: Amount,
}

/// Stable, backend-assigned identifier of a channel.
///
/// This wraps the LDK `user_channel_id` (hex string), which stays constant for
/// the lifetime of a channel and is the handle used to close it. The protocol
/// level channel id (which can change once at funding) is exposed separately
/// via [`ChannelInfo::channel_id`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChannelId(pub String);

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A 32-byte Lightning payment preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Preimage(pub [u8; 32]);

impl Preimage {
    /// Returns the payment hash committed to by this preimage, i.e.
    /// `SHA256(preimage)`.
    pub fn payment_hash(&self) -> sha256::Hash {
        sha256::Hash::hash(&self.0)
    }

    /// Returns the preimage as a lower-case hex string.
    pub fn to_hex(&self) -> String {
        self.0.to_lower_hex_string()
    }
}

/// Backend-assigned identifier of an outbound payment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaymentId(pub String);

impl std::fmt::Display for PaymentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Coarse lifecycle state of a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Funding negotiated but the channel is not yet ready for payments.
    Pending,
    /// The channel is ready to send and receive payments.
    Ready,
    /// The channel open attempt failed.
    OpenFailed,
    /// The channel has been closed.
    Closed,
    /// The backend reported a state we do not recognize.
    Unknown,
}

/// Information about a single channel, as reported by the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelInfo {
    /// Protocol-level channel id (hex). May change once at funding time; use
    /// [`ChannelInfo::user_channel_id`] as the stable handle.
    pub channel_id: String,
    /// Stable backend-assigned channel identifier.
    pub user_channel_id: ChannelId,
    /// Node id of the channel counterparty.
    pub counterparty: PublicKey,
    /// Total channel value as it appears in the funding output.
    pub value: Amount,
    /// Available outbound capacity in millisatoshis.
    pub outbound_capacity_msat: u64,
    /// Available inbound capacity in millisatoshis.
    pub inbound_capacity_msat: u64,
    /// `true` if the channel was initiated (and funded) by us.
    pub is_outbound: bool,
    /// Current number of confirmations on the funding transaction, if known.
    pub confirmations: Option<u32>,
    /// Coarse channel state derived from the backend's readiness flags.
    pub state: ChannelState,
    /// `true` if the channel is ready and the peer is currently connected.
    pub is_usable: bool,
}

/// A BOLT11 invoice returned by the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bolt11Invoice {
    /// The bech32-encoded invoice string.
    pub invoice: String,
    /// The payment hash committed to by the invoice.
    pub payment_hash: sha256::Hash,
}

/// Parameters for opening a new outbound channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenChannelRequest {
    /// Node id of the peer to open the channel with.
    pub node_pubkey: PublicKey,
    /// Network address of the peer (`host:port`, IPv4/IPv6/OnionV3/hostname).
    pub address: String,
    /// Amount we commit to the channel.
    pub channel_amount: Amount,
    /// Amount in millisatoshis to push to the counterparty in the initial
    /// commitment.
    pub push_to_counterparty_msat: Option<u64>,
    /// Whether the channel should be publicly announced.
    pub announce_channel: bool,
}

/// Parameters for creating a BOLT11 invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceParams {
    /// Invoice amount in millisatoshis. `None` creates a variable-amount
    /// ("zero-amount") invoice.
    pub amount_msat: Option<u64>,
    /// Description embedded in the invoice.
    pub description: String,
    /// Invoice expiry in seconds.
    pub expiry_secs: u32,
}

impl Default for InvoiceParams {
    fn default() -> Self {
        Self {
            amount_msat: None,
            description: String::new(),
            expiry_secs: 3600,
        }
    }
}

/// A normalized event emitted by a Lightning backend.
///
/// Events are delivered at-most-once via [`LightningBackend::poll_event`];
/// consumers must be able to reconstruct state from the query methods (e.g.
/// [`LightningBackend::list_channels`]) after a restart or missed event.
///
/// [`LightningBackend::poll_event`]: crate::lightning::LightningBackend::poll_event
/// [`LightningBackend::list_channels`]: crate::lightning::LightningBackend::list_channels
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LnEvent {
    /// An inbound payment has been received and claimed.
    PaymentReceived {
        /// Backend payment identifier.
        payment_id: PaymentId,
        /// Payment hash, if reported.
        payment_hash: Option<sha256::Hash>,
        /// Received amount in millisatoshis, if reported.
        amount_msat: Option<u64>,
    },
    /// A payment for a hold invoice (created via
    /// [`LightningBackend::create_hold_invoice`]) has arrived and is waiting
    /// to be claimed or failed.
    ///
    /// [`LightningBackend::create_hold_invoice`]: crate::lightning::LightningBackend::create_hold_invoice
    PaymentClaimable {
        /// Backend payment identifier.
        payment_id: PaymentId,
        /// Payment hash, if reported.
        payment_hash: Option<sha256::Hash>,
        /// Claimable amount in millisatoshis, if reported.
        amount_msat: Option<u64>,
        /// Block height by which the payment must be claimed, if reported.
        claim_deadline: Option<u32>,
    },
    /// An outbound payment succeeded.
    PaymentSuccessful {
        /// Backend payment identifier.
        payment_id: PaymentId,
        /// Payment hash, if reported.
        payment_hash: Option<sha256::Hash>,
        /// The preimage released by the payee, if reported.
        preimage: Option<Preimage>,
        /// Routing fees paid in millisatoshis, if reported.
        fee_paid_msat: Option<u64>,
    },
    /// An outbound payment failed.
    PaymentFailed {
        /// Backend payment identifier.
        payment_id: PaymentId,
        /// Payment hash, if reported.
        payment_hash: Option<sha256::Hash>,
    },
    /// A payment was forwarded through our node.
    PaymentForwarded {
        /// Fee earned in millisatoshis, if known.
        fee_earned_msat: Option<u64>,
    },
    /// A channel changed state.
    ChannelStateChanged {
        /// Stable identifier of the channel.
        channel_id: ChannelId,
        /// Counterparty node id, if reported.
        counterparty: Option<PublicKey>,
        /// The new channel state.
        state: ChannelState,
    },
    /// An event kind we do not recognize (forward compatibility).
    Unknown(String),
}
