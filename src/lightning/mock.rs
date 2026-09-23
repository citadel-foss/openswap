//! A deterministic in-memory [`LightningBackend`] for tests.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use bitcoin::{
    hashes::{sha256, Hash},
    key::CompressedPublicKey,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    Address, Amount, BlockHash, Network, Txid,
};

use super::{
    backend::LightningBackend,
    error::LightningError,
    types::{
        Balances, Bolt11Invoice, ChannelId, ChannelInfo, ChannelState, InvoiceParams, LnEvent,
        NodeInfo, OpenChannelRequest, PaymentId, Preimage,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvoiceStatus {
    /// Created, nothing has arrived yet.
    Open,
    /// A hold-invoice HTLC has arrived and is waiting for claim/fail.
    Held { amount_msat: u64 },
    /// Settled (claimed or paid).
    Settled,
    /// Cancelled via `fail_held_payment`.
    Cancelled,
}

#[derive(Debug)]
struct MockInvoice {
    invoice: String,
    amount_msat: Option<u64>,
    /// Preimage known to the mock. `Some` for regular invoices (backend
    /// generated), `None` for hold invoices (held by the caller).
    preimage: Option<Preimage>,
    is_hold: bool,
    status: InvoiceStatus,
    /// Node that created the invoice (receives `PaymentClaimable` /
    /// `PaymentReceived`).
    owner: usize,
    /// Node that paid it, once paid (receives `PaymentSuccessful` /
    /// `PaymentFailed`).
    payer: Option<usize>,
}

/// Invoice ledger and event routing shared by all nodes of a mock network.
#[derive(Debug, Default)]
struct SharedLedger {
    invoices: HashMap<sha256::Hash, MockInvoice>,
    /// One event queue per node.
    queues: Vec<VecDeque<LnEvent>>,
    next_id: u64,
}

impl SharedLedger {
    fn push(&mut self, node: usize, event: LnEvent) {
        self.queues[node].push_back(event);
    }
}

/// Per-node state (balances and channels are node-local).
#[derive(Debug, Default)]
struct LocalState {
    onchain_balance: Amount,
    channels: Vec<ChannelInfo>,
}

/// A deterministic, in-memory Lightning backend for unit and integration
/// tests.
///
/// State transitions that would normally be driven by the network (HTLC
/// arrival, channel confirmation) are triggered explicitly through the
/// `simulate_*` helpers. Events are queued FIFO per node and drained via
/// [`LightningBackend::poll_event`].
///
/// [`MockLightningBackend::new`] creates a standalone node that plays both
/// ends of its payments (its queue sees both payer- and payee-side events).
/// [`MockLightningBackend::new_pair`] creates two nodes over one shared
/// invoice ledger: a payment made on one node parks/settles on the other,
/// and each node's queue only sees its own side's events — mirroring two
/// real nodes.
pub struct MockLightningBackend {
    local: Mutex<LocalState>,
    ledger: Arc<Mutex<SharedLedger>>,
    node_index: usize,
    node_id: PublicKey,
    node_sk: SecretKey,
    /// CLTV bound passed to the most recent [`LightningBackend::pay_invoice`]
    /// call. The mock does no routing, but swaps must bound their routes, so
    /// tests assert on it.
    last_pay_cltv_bound: Mutex<Option<u32>>,
}

impl Default for MockLightningBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockLightningBackend {
    fn with_ledger(ledger: Arc<Mutex<SharedLedger>>, node_index: usize, key_byte: u8) -> Self {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[key_byte; 32]).expect("constant key is valid");
        Self {
            local: Mutex::new(LocalState::default()),
            ledger,
            node_index,
            node_id: PublicKey::from_secret_key(&secp, &sk),
            node_sk: sk,
            last_pay_cltv_bound: Mutex::new(None),
        }
    }

    /// The `max_total_cltv_expiry_delta` of the last `pay_invoice` call on
    /// this node, or `None` if it never paid (or paid unbounded).
    pub fn last_pay_cltv_bound(&self) -> Option<u32> {
        *self.last_pay_cltv_bound.lock().unwrap()
    }

    /// Builds a real, signed BOLT11 invoice string so code under test can
    /// run genuine invoice verification against mock invoices.
    fn build_bolt11(
        &self,
        payment_hash: sha256::Hash,
        amount_msat: Option<u64>,
        description: String,
    ) -> String {
        use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[..32].copy_from_slice(payment_hash.as_byte_array());
        let builder = InvoiceBuilder::new(Currency::Regtest)
            .description(description)
            .payment_hash(payment_hash)
            .payment_secret(PaymentSecret(secret))
            .duration_since_epoch(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock after unix epoch"),
            )
            .min_final_cltv_expiry_delta(42);
        let builder = match amount_msat {
            Some(msat) => builder.amount_milli_satoshis(msat),
            None => builder,
        };
        builder
            .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &self.node_sk))
            .expect("mock invoice construction is infallible")
            .to_string()
    }

    /// Creates a standalone mock node with a fixed node id and zero balances.
    pub fn new() -> Self {
        let ledger = Arc::new(Mutex::new(SharedLedger {
            queues: vec![VecDeque::new()],
            ..Default::default()
        }));
        Self::with_ledger(ledger, 0, 0x42)
    }

    /// Creates two mock nodes sharing one invoice ledger, so payments flow
    /// between them like between two real nodes.
    pub fn new_pair() -> (Arc<Self>, Arc<Self>) {
        let ledger = Arc::new(Mutex::new(SharedLedger {
            queues: vec![VecDeque::new(), VecDeque::new()],
            ..Default::default()
        }));
        (
            Arc::new(Self::with_ledger(Arc::clone(&ledger), 0, 0x42)),
            Arc::new(Self::with_ledger(ledger, 1, 0x43)),
        )
    }

    /// Sets the mock's on-chain balance.
    pub fn set_onchain_balance(&self, amount: Amount) {
        self.local.lock().unwrap().onchain_balance = amount;
    }

    /// Simulates the arrival of an HTLC paying the hold invoice registered
    /// for `payment_hash`, queuing a [`LnEvent::PaymentClaimable`] on the
    /// invoice owner's node.
    ///
    /// # Panics
    ///
    /// Panics if no hold invoice is registered for `payment_hash` or the
    /// invoice is not open (test misuse).
    pub fn simulate_htlc_arrival(&self, payment_hash: sha256::Hash, amount_msat: u64) {
        let mut ledger = self.ledger.lock().unwrap();
        let invoice = ledger
            .invoices
            .get_mut(&payment_hash)
            .expect("simulate_htlc_arrival: unknown payment hash");
        assert!(invoice.is_hold, "simulate_htlc_arrival: not a hold invoice");
        assert_eq!(
            invoice.status,
            InvoiceStatus::Open,
            "simulate_htlc_arrival: invoice not open"
        );
        invoice.status = InvoiceStatus::Held { amount_msat };
        let owner = invoice.owner;
        ledger.push(
            owner,
            LnEvent::PaymentClaimable {
                payment_id: PaymentId(payment_hash.to_string()),
                payment_hash: Some(payment_hash),
                amount_msat: Some(amount_msat),
                claim_deadline: None,
            },
        );
    }

    /// Marks the channel `channel_id` as ready, queuing a
    /// [`LnEvent::ChannelStateChanged`].
    ///
    /// # Panics
    ///
    /// Panics if the channel does not exist (test misuse).
    pub fn simulate_channel_ready(&self, channel_id: &ChannelId) {
        let mut local = self.local.lock().unwrap();
        let channel = local
            .channels
            .iter_mut()
            .find(|c| &c.user_channel_id == channel_id)
            .expect("simulate_channel_ready: unknown channel");
        channel.state = ChannelState::Ready;
        channel.is_usable = true;
        let event = LnEvent::ChannelStateChanged {
            channel_id: channel.user_channel_id.clone(),
            counterparty: Some(channel.counterparty),
            state: ChannelState::Ready,
        };
        self.ledger.lock().unwrap().push(self.node_index, event);
    }

    fn next_id(&self) -> u64 {
        let mut ledger = self.ledger.lock().unwrap();
        ledger.next_id += 1;
        ledger.next_id
    }
}

impl LightningBackend for MockLightningBackend {
    fn node_info(&self) -> Result<NodeInfo, LightningError> {
        Ok(NodeInfo {
            node_id: self.node_id,
            block_height: 0,
            block_hash: BlockHash::all_zeros(),
        })
    }

    fn balances(&self) -> Result<Balances, LightningError> {
        let local = self.local.lock()?;
        let total_lightning_msat: u64 = local
            .channels
            .iter()
            .filter(|c| c.state == ChannelState::Ready || c.state == ChannelState::Pending)
            .map(|c| c.outbound_capacity_msat)
            .sum();
        Ok(Balances {
            total_onchain: local.onchain_balance,
            spendable_onchain: local.onchain_balance,
            anchor_reserve: Amount::ZERO,
            total_lightning: Amount::from_sat(total_lightning_msat / 1000),
        })
    }

    fn new_onchain_address(&self) -> Result<Address, LightningError> {
        let id = self.next_id();
        let secp = Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[..8].copy_from_slice(&id.to_be_bytes());
        sk_bytes[31] = 1;
        let sk =
            SecretKey::from_slice(&sk_bytes).map_err(|e| LightningError::General(e.to_string()))?;
        let pk = CompressedPublicKey(PublicKey::from_secret_key(&secp, &sk));
        Ok(Address::p2wpkh(&pk, Network::Regtest))
    }

    fn send_onchain(
        &self,
        _address: &Address,
        amount: Option<Amount>,
        _fee_rate_sat_vb: Option<u64>,
    ) -> Result<Txid, LightningError> {
        let mut local = self.local.lock()?;
        match amount {
            Some(amount) => {
                if amount > local.onchain_balance {
                    return Err(LightningError::InsufficientFunds);
                }
                local.onchain_balance -= amount;
            }
            None => local.onchain_balance = Amount::ZERO,
        }
        drop(local);
        let id = self.next_id();
        let mut txid_bytes = [0u8; 32];
        txid_bytes[..8].copy_from_slice(&id.to_be_bytes());
        Ok(Txid::from_byte_array(txid_bytes))
    }

    fn open_channel(&self, req: OpenChannelRequest) -> Result<ChannelId, LightningError> {
        {
            let local = self.local.lock()?;
            if req.channel_amount > local.onchain_balance {
                return Err(LightningError::InsufficientFunds);
            }
        }
        let id = self.next_id();
        let mut local = self.local.lock()?;
        local.onchain_balance -= req.channel_amount;
        let channel_id = ChannelId(format!("mock-chan-{id}"));
        let push_msat = req.push_to_counterparty_msat.unwrap_or(0);
        local.channels.push(ChannelInfo {
            channel_id: format!("{id:064x}"),
            user_channel_id: channel_id.clone(),
            counterparty: req.node_pubkey,
            value: req.channel_amount,
            outbound_capacity_msat: req.channel_amount.to_sat() * 1000 - push_msat,
            inbound_capacity_msat: push_msat,
            is_outbound: true,
            confirmations: Some(0),
            state: ChannelState::Pending,
            is_usable: false,
        });
        Ok(channel_id)
    }

    fn close_channel(
        &self,
        channel_id: &ChannelId,
        counterparty: &PublicKey,
        _force: bool,
    ) -> Result<(), LightningError> {
        let mut local = self.local.lock()?;
        let channel = local
            .channels
            .iter_mut()
            .find(|c| &c.user_channel_id == channel_id && &c.counterparty == counterparty)
            .ok_or_else(|| LightningError::General(format!("unknown channel: {channel_id}")))?;
        if channel.state == ChannelState::Closed {
            return Err(LightningError::General(format!(
                "channel already closed: {channel_id}"
            )));
        }
        channel.state = ChannelState::Closed;
        channel.is_usable = false;
        let refund = Amount::from_sat(channel.outbound_capacity_msat / 1000);
        let event = LnEvent::ChannelStateChanged {
            channel_id: channel.user_channel_id.clone(),
            counterparty: Some(channel.counterparty),
            state: ChannelState::Closed,
        };
        local.onchain_balance += refund;
        drop(local);
        self.ledger.lock()?.push(self.node_index, event);
        Ok(())
    }

    fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        Ok(self.local.lock()?.channels.clone())
    }

    fn create_invoice(&self, params: InvoiceParams) -> Result<Bolt11Invoice, LightningError> {
        let id = self.next_id();
        let mut preimage_bytes = [0u8; 32];
        preimage_bytes[..8].copy_from_slice(&id.to_be_bytes());
        let preimage = Preimage(preimage_bytes);
        let payment_hash = preimage.payment_hash();
        let invoice = self.build_bolt11(payment_hash, params.amount_msat, params.description);
        self.ledger.lock()?.invoices.insert(
            payment_hash,
            MockInvoice {
                invoice: invoice.clone(),
                amount_msat: params.amount_msat,
                preimage: Some(preimage),
                is_hold: false,
                status: InvoiceStatus::Open,
                owner: self.node_index,
                payer: None,
            },
        );
        Ok(Bolt11Invoice {
            invoice,
            payment_hash,
        })
    }

    fn pay_invoice(
        &self,
        invoice: &str,
        amount_msat: Option<u64>,
        max_total_cltv_expiry_delta: Option<u32>,
    ) -> Result<PaymentId, LightningError> {
        // No routing to constrain in-memory; recorded so tests can assert
        // that swap code bounds its routes.
        *self.last_pay_cltv_bound.lock()? = max_total_cltv_expiry_delta;
        let mut ledger = self.ledger.lock()?;
        let (payment_hash, entry) = ledger
            .invoices
            .iter_mut()
            .find(|(_, inv)| inv.invoice == invoice)
            .map(|(hash, inv)| (*hash, inv))
            .ok_or_else(|| LightningError::InvalidInvoice(invoice.to_string()))?;
        if entry.status != InvoiceStatus::Open {
            return Err(LightningError::InvalidInvoice(format!(
                "invoice not payable: {invoice}"
            )));
        }
        let amount_msat = match (entry.amount_msat, amount_msat) {
            (Some(fixed), _) => fixed,
            (None, Some(amount)) => amount,
            (None, None) => {
                return Err(LightningError::InvalidInvoice(
                    "amount required for variable-amount invoice".to_string(),
                ))
            }
        };
        entry.payer = Some(self.node_index);
        let owner = entry.owner;
        if entry.is_hold {
            // The payment parks at the invoice owner's node until it is
            // claimed or failed by that side.
            entry.status = InvoiceStatus::Held { amount_msat };
            ledger.push(
                owner,
                LnEvent::PaymentClaimable {
                    payment_id: PaymentId(payment_hash.to_string()),
                    payment_hash: Some(payment_hash),
                    amount_msat: Some(amount_msat),
                    claim_deadline: None,
                },
            );
        } else {
            entry.status = InvoiceStatus::Settled;
            let preimage = entry.preimage;
            ledger.push(
                self.node_index,
                LnEvent::PaymentSuccessful {
                    payment_id: PaymentId(payment_hash.to_string()),
                    payment_hash: Some(payment_hash),
                    preimage,
                    fee_paid_msat: Some(0),
                },
            );
            ledger.push(
                owner,
                LnEvent::PaymentReceived {
                    payment_id: PaymentId(payment_hash.to_string()),
                    payment_hash: Some(payment_hash),
                    amount_msat: Some(amount_msat),
                },
            );
        }
        Ok(PaymentId(payment_hash.to_string()))
    }

    fn create_hold_invoice(
        &self,
        payment_hash: sha256::Hash,
        params: InvoiceParams,
    ) -> Result<Bolt11Invoice, LightningError> {
        let invoice = self.build_bolt11(payment_hash, params.amount_msat, params.description);
        let mut ledger = self.ledger.lock()?;
        if ledger.invoices.contains_key(&payment_hash) {
            return Err(LightningError::General(format!(
                "invoice already exists for hash: {payment_hash}"
            )));
        }
        ledger.invoices.insert(
            payment_hash,
            MockInvoice {
                invoice: invoice.clone(),
                amount_msat: params.amount_msat,
                preimage: None,
                is_hold: true,
                status: InvoiceStatus::Open,
                owner: self.node_index,
                payer: None,
            },
        );
        Ok(Bolt11Invoice {
            invoice,
            payment_hash,
        })
    }

    fn claim_held_payment(&self, preimage: &Preimage) -> Result<(), LightningError> {
        let mut ledger = self.ledger.lock()?;
        let payment_hash = preimage.payment_hash();
        let (amount_msat, owner, payer) = match ledger.invoices.get_mut(&payment_hash) {
            Some(invoice) if invoice.is_hold => match invoice.status {
                InvoiceStatus::Held { amount_msat } => {
                    invoice.status = InvoiceStatus::Settled;
                    invoice.preimage = Some(*preimage);
                    (amount_msat, invoice.owner, invoice.payer)
                }
                _ => return Err(LightningError::PaymentNotFound),
            },
            _ => return Err(LightningError::PaymentNotFound),
        };
        // The claim releases the preimage to the payer via
        // `PaymentSuccessful` and settles the owner via `PaymentReceived`.
        // A standalone node (or a simulated arrival with no payer) plays
        // both ends and sees both events on its own queue.
        ledger.push(
            payer.unwrap_or(owner),
            LnEvent::PaymentSuccessful {
                payment_id: PaymentId(payment_hash.to_string()),
                payment_hash: Some(payment_hash),
                preimage: Some(*preimage),
                fee_paid_msat: Some(0),
            },
        );
        ledger.push(
            owner,
            LnEvent::PaymentReceived {
                payment_id: PaymentId(payment_hash.to_string()),
                payment_hash: Some(payment_hash),
                amount_msat: Some(amount_msat),
            },
        );
        Ok(())
    }

    fn fail_held_payment(&self, payment_hash: sha256::Hash) -> Result<(), LightningError> {
        let mut ledger = self.ledger.lock()?;
        let payer = match ledger.invoices.get_mut(&payment_hash) {
            Some(invoice) if invoice.is_hold => match invoice.status {
                InvoiceStatus::Open | InvoiceStatus::Held { .. } => {
                    invoice.status = InvoiceStatus::Cancelled;
                    invoice.payer
                }
                _ => return Err(LightningError::PaymentNotFound),
            },
            _ => return Err(LightningError::PaymentNotFound),
        };
        if let Some(payer) = payer {
            ledger.push(
                payer,
                LnEvent::PaymentFailed {
                    payment_id: PaymentId(payment_hash.to_string()),
                    payment_hash: Some(payment_hash),
                },
            );
        }
        Ok(())
    }

    fn poll_event(&self) -> Result<Option<LnEvent>, LightningError> {
        Ok(self.ledger.lock()?.queues[self.node_index].pop_front())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn peer_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x17; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn open_request(amount_sat: u64) -> OpenChannelRequest {
        OpenChannelRequest {
            node_pubkey: peer_pubkey(),
            address: "127.0.0.1:9735".to_string(),
            channel_amount: Amount::from_sat(amount_sat),
            push_to_counterparty_msat: None,
            announce_channel: false,
        }
    }

    #[test]
    fn hold_invoice_happy_path() {
        let mock = MockLightningBackend::new();
        let preimage = Preimage([7u8; 32]);
        let payment_hash = preimage.payment_hash();

        let invoice = mock
            .create_hold_invoice(payment_hash, InvoiceParams::default())
            .unwrap();
        assert_eq!(invoice.payment_hash, payment_hash);

        mock.simulate_htlc_arrival(payment_hash, 50_000);
        match mock.poll_event().unwrap() {
            Some(LnEvent::PaymentClaimable {
                payment_hash: hash,
                amount_msat,
                ..
            }) => {
                assert_eq!(hash, Some(payment_hash));
                assert_eq!(amount_msat, Some(50_000));
            }
            other => panic!("expected PaymentClaimable, got {:?}", other),
        }

        mock.claim_held_payment(&preimage).unwrap();
        // The claim settles both ends: payer-side PaymentSuccessful (carrying
        // the revealed preimage) first, then payee-side PaymentReceived.
        match mock.poll_event().unwrap() {
            Some(LnEvent::PaymentSuccessful {
                payment_hash: hash,
                preimage: released,
                ..
            }) => {
                assert_eq!(hash, Some(payment_hash));
                assert_eq!(released, Some(preimage));
            }
            other => panic!("expected PaymentSuccessful, got {:?}", other),
        }
        match mock.poll_event().unwrap() {
            Some(LnEvent::PaymentReceived {
                payment_hash: hash,
                amount_msat,
                ..
            }) => {
                assert_eq!(hash, Some(payment_hash));
                assert_eq!(amount_msat, Some(50_000));
            }
            other => panic!("expected PaymentReceived, got {:?}", other),
        }

        // Claiming twice fails: the payment is already settled.
        assert!(matches!(
            mock.claim_held_payment(&preimage),
            Err(LightningError::PaymentNotFound)
        ));
    }

    /// The paired mode routes each side's events to its own node: the payer
    /// sees `PaymentSuccessful`/`PaymentFailed`, the invoice owner sees
    /// `PaymentClaimable`/`PaymentReceived`, and neither steals the other's.
    #[test]
    fn paired_nodes_route_events_to_their_own_queues() {
        let (owner, payer) = MockLightningBackend::new_pair();
        let preimage = Preimage([7u8; 32]);
        let payment_hash = preimage.payment_hash();

        let invoice = owner
            .create_hold_invoice(payment_hash, InvoiceParams::default())
            .unwrap();
        payer
            .pay_invoice(&invoice.invoice, Some(50_000), Some(200))
            .unwrap();

        // The held payment parks at the owner; the payer sees nothing yet.
        assert!(payer.poll_event().unwrap().is_none());
        assert!(matches!(
            owner.poll_event().unwrap(),
            Some(LnEvent::PaymentClaimable { .. })
        ));

        owner.claim_held_payment(&preimage).unwrap();
        // Settlement: preimage goes to the payer, receipt to the owner.
        match payer.poll_event().unwrap() {
            Some(LnEvent::PaymentSuccessful {
                preimage: released, ..
            }) => assert_eq!(released, Some(preimage)),
            other => panic!("expected PaymentSuccessful, got {:?}", other),
        }
        assert!(matches!(
            owner.poll_event().unwrap(),
            Some(LnEvent::PaymentReceived { .. })
        ));
        assert!(payer.poll_event().unwrap().is_none());
        assert!(owner.poll_event().unwrap().is_none());
    }

    /// Failing a held payment notifies the payer.
    #[test]
    fn paired_fail_held_payment_notifies_payer() {
        let (owner, payer) = MockLightningBackend::new_pair();
        let preimage = Preimage([9u8; 32]);
        let payment_hash = preimage.payment_hash();
        let invoice = owner
            .create_hold_invoice(payment_hash, InvoiceParams::default())
            .unwrap();
        payer
            .pay_invoice(&invoice.invoice, Some(1_000), Some(200))
            .unwrap();
        let _ = owner.poll_event().unwrap();

        owner.fail_held_payment(payment_hash).unwrap();
        assert!(matches!(
            payer.poll_event().unwrap(),
            Some(LnEvent::PaymentFailed { .. })
        ));
    }

    #[test]
    fn claim_with_wrong_or_unregistered_preimage_fails() {
        let mock = MockLightningBackend::new();
        let preimage = Preimage([7u8; 32]);
        let payment_hash = preimage.payment_hash();
        mock.create_hold_invoice(payment_hash, InvoiceParams::default())
            .unwrap();
        mock.simulate_htlc_arrival(payment_hash, 1_000);

        // Wrong preimage hashes to an unregistered payment hash.
        let wrong = Preimage([8u8; 32]);
        assert!(matches!(
            mock.claim_held_payment(&wrong),
            Err(LightningError::PaymentNotFound)
        ));

        // Fully unregistered hash cannot be failed either.
        assert!(matches!(
            mock.fail_held_payment(Preimage([9u8; 32]).payment_hash()),
            Err(LightningError::PaymentNotFound)
        ));
    }

    #[test]
    fn fail_held_payment_cancels_and_blocks_claim() {
        let mock = MockLightningBackend::new();
        let preimage = Preimage([7u8; 32]);
        let payment_hash = preimage.payment_hash();
        mock.create_hold_invoice(payment_hash, InvoiceParams::default())
            .unwrap();
        mock.simulate_htlc_arrival(payment_hash, 1_000);
        let _ = mock.poll_event().unwrap();

        mock.fail_held_payment(payment_hash).unwrap();
        assert!(matches!(
            mock.claim_held_payment(&preimage),
            Err(LightningError::PaymentNotFound)
        ));
    }

    #[test]
    fn regular_invoice_round_trip() {
        let mock = MockLightningBackend::new();
        let invoice = mock
            .create_invoice(InvoiceParams {
                amount_msat: Some(25_000),
                ..Default::default()
            })
            .unwrap();

        let payment_id = mock.pay_invoice(&invoice.invoice, None, Some(200)).unwrap();
        assert_eq!(payment_id.0, invoice.payment_hash.to_string());

        match mock.poll_event().unwrap() {
            Some(LnEvent::PaymentSuccessful {
                payment_hash,
                preimage,
                ..
            }) => {
                assert_eq!(payment_hash, Some(invoice.payment_hash));
                assert_eq!(
                    preimage.unwrap().payment_hash(),
                    invoice.payment_hash,
                    "released preimage must commit to the invoice hash"
                );
            }
            other => panic!("expected PaymentSuccessful, got {:?}", other),
        }
        assert!(matches!(
            mock.poll_event().unwrap(),
            Some(LnEvent::PaymentReceived { .. })
        ));

        // Unknown invoice strings are rejected.
        assert!(matches!(
            mock.pay_invoice("lnbcrt-unknown", None, None),
            Err(LightningError::InvalidInvoice(_))
        ));
    }

    #[test]
    fn channel_lifecycle() {
        let mock = MockLightningBackend::new();
        mock.set_onchain_balance(Amount::from_sat(1_000_000));

        let channel_id = mock.open_channel(open_request(400_000)).unwrap();
        let channels = mock.list_channels().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].state, ChannelState::Pending);
        assert_eq!(
            mock.balances().unwrap().total_onchain,
            Amount::from_sat(600_000)
        );

        mock.simulate_channel_ready(&channel_id);
        assert_eq!(mock.list_channels().unwrap()[0].state, ChannelState::Ready);
        assert!(matches!(
            mock.poll_event().unwrap(),
            Some(LnEvent::ChannelStateChanged {
                state: ChannelState::Ready,
                ..
            })
        ));

        mock.close_channel(&channel_id, &peer_pubkey(), false)
            .unwrap();
        assert_eq!(mock.list_channels().unwrap()[0].state, ChannelState::Closed);
        assert!(matches!(
            mock.poll_event().unwrap(),
            Some(LnEvent::ChannelStateChanged {
                state: ChannelState::Closed,
                ..
            })
        ));
        // Channel balance returns on-chain after close.
        assert_eq!(
            mock.balances().unwrap().total_onchain,
            Amount::from_sat(1_000_000)
        );

        // Closing again fails.
        assert!(mock
            .close_channel(&channel_id, &peer_pubkey(), false)
            .is_err());
    }

    #[test]
    fn insufficient_funds() {
        let mock = MockLightningBackend::new();
        mock.set_onchain_balance(Amount::from_sat(1_000));

        assert!(matches!(
            mock.open_channel(open_request(2_000)),
            Err(LightningError::InsufficientFunds)
        ));

        let address = mock.new_onchain_address().unwrap();
        assert!(matches!(
            mock.send_onchain(&address, Some(Amount::from_sat(2_000)), None),
            Err(LightningError::InsufficientFunds)
        ));

        // Send-all always succeeds and drains the balance.
        mock.send_onchain(&address, None, None).unwrap();
        assert_eq!(mock.balances().unwrap().total_onchain, Amount::ZERO);
    }

    #[test]
    fn poll_event_is_fifo_and_drains() {
        let mock = MockLightningBackend::new();
        mock.set_onchain_balance(Amount::from_sat(1_000_000));
        let a = mock.open_channel(open_request(100_000)).unwrap();
        let b = mock.open_channel(open_request(100_000)).unwrap();
        mock.simulate_channel_ready(&a);
        mock.simulate_channel_ready(&b);

        match mock.poll_event().unwrap() {
            Some(LnEvent::ChannelStateChanged { channel_id, .. }) => assert_eq!(channel_id, a),
            other => panic!("expected ChannelStateChanged, got {:?}", other),
        }
        match mock.poll_event().unwrap() {
            Some(LnEvent::ChannelStateChanged { channel_id, .. }) => assert_eq!(channel_id, b),
            other => panic!("expected ChannelStateChanged, got {:?}", other),
        }
        assert!(mock.poll_event().unwrap().is_none());
    }

    #[test]
    fn shared_across_threads_as_trait_object() {
        let backend: Arc<dyn LightningBackend> = Arc::new(MockLightningBackend::new());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let backend = Arc::clone(&backend);
                std::thread::spawn(move || {
                    backend.node_info().unwrap();
                    backend.create_invoice(InvoiceParams::default()).unwrap()
                })
            })
            .collect();
        let mut hashes: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().unwrap().payment_hash)
            .collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 4, "invoices must be unique across threads");
    }

    #[test]
    fn preimage_payment_hash_is_sha256() {
        let preimage = Preimage([3u8; 32]);
        assert_eq!(
            preimage.payment_hash(),
            sha256::Hash::hash(&[3u8; 32]),
            "payment hash must be single SHA256 of the preimage"
        );
        assert_eq!(preimage.to_hex(), "03".repeat(32));
    }
}
