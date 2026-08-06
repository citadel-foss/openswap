//! A deterministic in-memory [`LightningBackend`] for tests.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
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
}

#[derive(Debug, Default)]
struct MockState {
    onchain_balance: Amount,
    channels: Vec<ChannelInfo>,
    invoices: HashMap<sha256::Hash, MockInvoice>,
    events: VecDeque<LnEvent>,
    next_id: u64,
}

/// A deterministic, in-memory Lightning backend for unit and integration
/// tests.
///
/// State transitions that would normally be driven by the network (HTLC
/// arrival, channel confirmation) are triggered explicitly through the
/// `simulate_*` helpers. Events are queued FIFO and drained via
/// [`LightningBackend::poll_event`].
pub struct MockLightningBackend {
    state: Mutex<MockState>,
    node_id: PublicKey,
}

impl Default for MockLightningBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockLightningBackend {
    /// Creates a mock backend with a fixed node id and zero balances.
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).expect("constant key is valid");
        Self {
            state: Mutex::new(MockState::default()),
            node_id: PublicKey::from_secret_key(&secp, &sk),
        }
    }

    /// Sets the mock's on-chain balance.
    pub fn set_onchain_balance(&self, amount: Amount) {
        self.state.lock().unwrap().onchain_balance = amount;
    }

    /// Simulates the arrival of an HTLC paying the hold invoice registered
    /// for `payment_hash`, queuing a [`LnEvent::PaymentClaimable`].
    ///
    /// # Panics
    ///
    /// Panics if no hold invoice is registered for `payment_hash` or the
    /// invoice is not open (test misuse).
    pub fn simulate_htlc_arrival(&self, payment_hash: sha256::Hash, amount_msat: u64) {
        let mut state = self.state.lock().unwrap();
        let invoice = state
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
        state.events.push_back(LnEvent::PaymentClaimable {
            payment_id: PaymentId(payment_hash.to_string()),
            payment_hash: Some(payment_hash),
            amount_msat: Some(amount_msat),
            claim_deadline: None,
        });
    }

    /// Marks the channel `channel_id` as ready, queuing a
    /// [`LnEvent::ChannelStateChanged`].
    ///
    /// # Panics
    ///
    /// Panics if the channel does not exist (test misuse).
    pub fn simulate_channel_ready(&self, channel_id: &ChannelId) {
        let mut state = self.state.lock().unwrap();
        let channel = state
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
        state.events.push_back(event);
    }

    fn next_id(state: &mut MockState) -> u64 {
        state.next_id += 1;
        state.next_id
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
        let state = self.state.lock()?;
        let total_lightning_msat: u64 = state
            .channels
            .iter()
            .filter(|c| c.state == ChannelState::Ready || c.state == ChannelState::Pending)
            .map(|c| c.outbound_capacity_msat)
            .sum();
        Ok(Balances {
            total_onchain: state.onchain_balance,
            spendable_onchain: state.onchain_balance,
            anchor_reserve: Amount::ZERO,
            total_lightning: Amount::from_sat(total_lightning_msat / 1000),
        })
    }

    fn new_onchain_address(&self) -> Result<Address, LightningError> {
        let mut state = self.state.lock()?;
        let id = Self::next_id(&mut state);
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
        let mut state = self.state.lock()?;
        match amount {
            Some(amount) => {
                if amount > state.onchain_balance {
                    return Err(LightningError::InsufficientFunds);
                }
                state.onchain_balance -= amount;
            }
            None => state.onchain_balance = Amount::ZERO,
        }
        let id = Self::next_id(&mut state);
        let mut txid_bytes = [0u8; 32];
        txid_bytes[..8].copy_from_slice(&id.to_be_bytes());
        Ok(Txid::from_byte_array(txid_bytes))
    }

    fn open_channel(&self, req: OpenChannelRequest) -> Result<ChannelId, LightningError> {
        let mut state = self.state.lock()?;
        if req.channel_amount > state.onchain_balance {
            return Err(LightningError::InsufficientFunds);
        }
        state.onchain_balance -= req.channel_amount;
        let id = Self::next_id(&mut state);
        let channel_id = ChannelId(format!("mock-chan-{id}"));
        let push_msat = req.push_to_counterparty_msat.unwrap_or(0);
        state.channels.push(ChannelInfo {
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
        let mut state = self.state.lock()?;
        let channel = state
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
        state.onchain_balance += refund;
        state.events.push_back(event);
        Ok(())
    }

    fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        Ok(self.state.lock()?.channels.clone())
    }

    fn create_invoice(&self, params: InvoiceParams) -> Result<Bolt11Invoice, LightningError> {
        let mut state = self.state.lock()?;
        let id = Self::next_id(&mut state);
        let mut preimage_bytes = [0u8; 32];
        preimage_bytes[..8].copy_from_slice(&id.to_be_bytes());
        let preimage = Preimage(preimage_bytes);
        let payment_hash = preimage.payment_hash();
        let invoice = format!("lnbcrt-mock-{payment_hash}");
        state.invoices.insert(
            payment_hash,
            MockInvoice {
                invoice: invoice.clone(),
                amount_msat: params.amount_msat,
                preimage: Some(preimage),
                is_hold: false,
                status: InvoiceStatus::Open,
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
    ) -> Result<PaymentId, LightningError> {
        let mut state = self.state.lock()?;
        let (payment_hash, entry) = state
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
        if entry.is_hold {
            // Paying a hold invoice held by this same mock: the payment stays
            // pending until claimed/failed by the receiver side.
            entry.status = InvoiceStatus::Held { amount_msat };
            state.events.push_back(LnEvent::PaymentClaimable {
                payment_id: PaymentId(payment_hash.to_string()),
                payment_hash: Some(payment_hash),
                amount_msat: Some(amount_msat),
                claim_deadline: None,
            });
        } else {
            entry.status = InvoiceStatus::Settled;
            let preimage = entry.preimage;
            state.events.push_back(LnEvent::PaymentSuccessful {
                payment_id: PaymentId(payment_hash.to_string()),
                payment_hash: Some(payment_hash),
                preimage,
                fee_paid_msat: Some(0),
            });
            state.events.push_back(LnEvent::PaymentReceived {
                payment_id: PaymentId(payment_hash.to_string()),
                payment_hash: Some(payment_hash),
                amount_msat: Some(amount_msat),
            });
        }
        Ok(PaymentId(payment_hash.to_string()))
    }

    fn create_hold_invoice(
        &self,
        payment_hash: sha256::Hash,
        params: InvoiceParams,
    ) -> Result<Bolt11Invoice, LightningError> {
        let mut state = self.state.lock()?;
        if state.invoices.contains_key(&payment_hash) {
            return Err(LightningError::General(format!(
                "invoice already exists for hash: {payment_hash}"
            )));
        }
        let invoice = format!("lnbcrt-mock-hold-{payment_hash}");
        state.invoices.insert(
            payment_hash,
            MockInvoice {
                invoice: invoice.clone(),
                amount_msat: params.amount_msat,
                preimage: None,
                is_hold: true,
                status: InvoiceStatus::Open,
            },
        );
        Ok(Bolt11Invoice {
            invoice,
            payment_hash,
        })
    }

    fn claim_held_payment(&self, preimage: &Preimage) -> Result<(), LightningError> {
        let mut state = self.state.lock()?;
        let payment_hash = preimage.payment_hash();
        let amount_msat = match state.invoices.get_mut(&payment_hash) {
            Some(invoice) if invoice.is_hold => match invoice.status {
                InvoiceStatus::Held { amount_msat } => {
                    invoice.status = InvoiceStatus::Settled;
                    invoice.preimage = Some(*preimage);
                    amount_msat
                }
                _ => return Err(LightningError::PaymentNotFound),
            },
            _ => return Err(LightningError::PaymentNotFound),
        };
        state.events.push_back(LnEvent::PaymentReceived {
            payment_id: PaymentId(payment_hash.to_string()),
            payment_hash: Some(payment_hash),
            amount_msat: Some(amount_msat),
        });
        Ok(())
    }

    fn fail_held_payment(&self, payment_hash: sha256::Hash) -> Result<(), LightningError> {
        let mut state = self.state.lock()?;
        match state.invoices.get_mut(&payment_hash) {
            Some(invoice) if invoice.is_hold => match invoice.status {
                InvoiceStatus::Open | InvoiceStatus::Held { .. } => {
                    invoice.status = InvoiceStatus::Cancelled;
                    Ok(())
                }
                _ => Err(LightningError::PaymentNotFound),
            },
            _ => Err(LightningError::PaymentNotFound),
        }
    }

    fn poll_event(&self) -> Result<Option<LnEvent>, LightningError> {
        Ok(self.state.lock()?.events.pop_front())
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

        let payment_id = mock.pay_invoice(&invoice.invoice, None).unwrap();
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
            mock.pay_invoice("lnbcrt-unknown", None),
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
