//! The [`LightningBackend`] trait: a synchronous, backend-agnostic interface
//! to a Lightning node.

use bitcoin::{hashes::sha256, secp256k1::PublicKey, Address, Amount, Txid};

use super::{
    error::LightningError,
    types::{
        Balances, Bolt11Invoice, ChannelId, ChannelInfo, InvoiceParams, LnEvent, NodeInfo,
        OpenChannelRequest, PaymentId, Preimage,
    },
};

/// A synchronous interface to a Lightning node.
///
/// Implementations must be safe to share across threads (typically as
/// `Arc<dyn LightningBackend>`). All methods block the calling thread until
/// the backend responds or an internal timeout elapses.
pub trait LightningBackend: Send + Sync {
    /// Returns static information about the backing node.
    fn node_info(&self) -> Result<NodeInfo, LightningError>;

    /// Returns a snapshot of the node's on-chain and Lightning balances.
    fn balances(&self) -> Result<Balances, LightningError>;

    /// Returns a fresh on-chain receive address from the node's wallet.
    fn new_onchain_address(&self) -> Result<Address, LightningError>;

    /// Sends an on-chain payment to `address`.
    ///
    /// If `amount` is `None`, all spendable funds are sent (respecting anchor
    /// reserves). If `fee_rate_sat_vb` is `None`, the node estimates a
    /// reasonable fee rate.
    fn send_onchain(
        &self,
        address: &Address,
        amount: Option<Amount>,
        fee_rate_sat_vb: Option<u64>,
    ) -> Result<Txid, LightningError>;

    /// Opens a new outbound channel and returns its stable identifier.
    fn open_channel(&self, req: OpenChannelRequest) -> Result<ChannelId, LightningError>;

    /// Closes the channel identified by `channel_id` with `counterparty`.
    ///
    /// Attempts a cooperative close unless `force` is set.
    fn close_channel(
        &self,
        channel_id: &ChannelId,
        counterparty: &PublicKey,
        force: bool,
    ) -> Result<(), LightningError>;

    /// Lists all channels known to the node.
    fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError>;

    /// Creates a regular BOLT11 invoice (backend generates the preimage and
    /// auto-claims on arrival).
    fn create_invoice(&self, params: InvoiceParams) -> Result<Bolt11Invoice, LightningError>;

    /// Pays a BOLT11 `invoice`.
    ///
    /// `amount_msat` must be set when paying a variable-amount invoice and
    /// left `None` otherwise.
    fn pay_invoice(
        &self,
        invoice: &str,
        amount_msat: Option<u64>,
    ) -> Result<PaymentId, LightningError>;

    /// Creates a hold invoice for an externally supplied `payment_hash`.
    ///
    /// The arriving payment is *not* auto-claimed: it is surfaced as
    /// [`LnEvent::PaymentClaimable`] and must be settled with
    /// [`claim_held_payment`](Self::claim_held_payment) or cancelled with
    /// [`fail_held_payment`](Self::fail_held_payment).
    fn create_hold_invoice(
        &self,
        payment_hash: sha256::Hash,
        params: InvoiceParams,
    ) -> Result<Bolt11Invoice, LightningError>;

    /// Claims a held payment by revealing its `preimage`.
    fn claim_held_payment(&self, preimage: &Preimage) -> Result<(), LightningError>;

    /// Fails a held payment back to the payer.
    fn fail_held_payment(&self, payment_hash: sha256::Hash) -> Result<(), LightningError>;

    /// Returns the next pending backend event, or `Ok(None)` if no event is
    /// currently queued. Never blocks.
    ///
    /// Delivery is at-most-once: events observed while disconnected (or before
    /// a restart) are dropped, so consumers must be able to resynchronize via
    /// the query methods.
    fn poll_event(&self) -> Result<Option<LnEvent>, LightningError>;
}
