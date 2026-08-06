//! [`LightningBackend`] implementation backed by an LDK Server sidecar.
//!
//! This is the only file that touches the async `ldk-server-client` crate and
//! its protobuf types. A private tokio runtime bridges the async client into
//! the crate's synchronous world:
//!
//! - Unary calls are executed with `Runtime::block_on` under a per-call
//!   timeout.
//! - A background task on the same runtime consumes the server's
//!   `SubscribeEvents` gRPC stream, converts each message into an [`LnEvent`]
//!   and pushes it into a crossbeam channel drained by
//!   [`LightningBackend::poll_event`]. The task reconnects with a fixed
//!   backoff if the stream drops; events emitted by the server while
//!   disconnected are lost (at-most-once delivery).

use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use bitcoin::{
    hashes::{hex::FromHex, sha256},
    secp256k1::PublicKey,
    Address, Amount, BlockHash, Txid,
};
use crossbeam_channel::{Receiver, Sender, TryRecvError};
use ldk_server_client::{
    client::LdkServerClient,
    error::LdkServerError,
    ldk_server_grpc::{api as proto_api, events as proto_events, types as proto_types},
};
use tokio::runtime::Runtime;

use super::{
    backend::LightningBackend,
    config::{default_cert_path, LightningConfig},
    error::LightningError,
    types::{
        Balances, Bolt11Invoice, ChannelId, ChannelInfo, ChannelState, InvoiceParams, LnEvent,
        NodeInfo, OpenChannelRequest, PaymentId, Preimage,
    },
};

/// Delay between reconnection attempts of the event subscription stream.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// A [`LightningBackend`] talking to an LDK Server instance over gRPC.
///
/// The TLS certificate of the server is pinned (self-signed certificates are
/// what ldk-server generates), and every request is authenticated with an
/// HMAC over the configured API key.
pub struct LdkServerBackend {
    runtime: Runtime,
    client: LdkServerClient,
    timeout: Duration,
    event_rx: Receiver<LnEvent>,
    shutdown: Arc<AtomicBool>,
}

impl LdkServerBackend {
    /// Connects to the LDK Server described by `config` and starts the
    /// background event subscription task.
    ///
    /// Fails if the TLS certificate cannot be read or the HTTP client cannot
    /// be constructed; it does *not* fail if the server is currently
    /// unreachable (calls will error individually instead).
    pub fn new(config: &LightningConfig) -> Result<Self, LightningError> {
        let cert_path = config
            .tls_cert_path
            .clone()
            .or_else(default_cert_path)
            .ok_or_else(|| {
                LightningError::General(
                    "no TLS certificate path configured and no default path available".to_string(),
                )
            })?;
        let cert_pem = std::fs::read(&cert_path).map_err(|e| {
            LightningError::Connection(format!(
                "failed to read TLS certificate {}: {e}",
                cert_path.display()
            ))
        })?;

        let client =
            LdkServerClient::new(config.base_url.clone(), config.api_key.clone(), &cert_pem)
                .map_err(LightningError::Connection)?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|e| LightningError::Runtime(e.to_string()))?;

        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let shutdown = Arc::new(AtomicBool::new(false));
        runtime.spawn(event_loop(client.clone(), event_tx, Arc::clone(&shutdown)));

        Ok(Self {
            runtime,
            client,
            timeout: Duration::from_secs(config.timeout_secs),
            event_rx,
            shutdown,
        })
    }

    /// Runs an async unary call on the private runtime under the configured
    /// timeout.
    fn call<F, T>(&self, fut: F) -> Result<T, LightningError>
    where
        F: Future<Output = Result<T, LdkServerError>>,
    {
        match self
            .runtime
            .block_on(tokio::time::timeout(self.timeout, fut))
        {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(convert_error(e)),
            Err(_elapsed) => Err(LightningError::Timeout),
        }
    }
}

impl Drop for LdkServerBackend {
    fn drop(&mut self) {
        // Signal the event task; dropping the runtime afterwards cancels it
        // at its next await point.
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// Background task: subscribe to server events, forward them into `tx`, and
/// reconnect with a fixed backoff when the stream drops.
async fn event_loop(client: LdkServerClient, tx: Sender<LnEvent>, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        match client.subscribe_events().await {
            Ok(mut stream) => {
                log::info!("lightning: event stream connected");
                loop {
                    if shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    match stream.next_message().await {
                        Some(Ok(envelope)) => {
                            if tx.send(convert_event(envelope)).is_err() {
                                // Receiver dropped: backend is gone.
                                return;
                            }
                        }
                        Some(Err(e)) => {
                            log::warn!("lightning: event stream error: {e}");
                            break;
                        }
                        None => {
                            log::warn!("lightning: event stream ended by server");
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("lightning: event subscription failed: {e}");
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

impl LightningBackend for LdkServerBackend {
    fn node_info(&self) -> Result<NodeInfo, LightningError> {
        let response = self.call(self.client.get_node_info(proto_api::GetNodeInfoRequest {}))?;
        let node_id = parse_pubkey(&response.node_id)?;
        let best_block = response.current_best_block.ok_or_else(|| {
            LightningError::InvalidResponse("missing current_best_block".to_string())
        })?;
        let block_hash = best_block.block_hash.parse::<BlockHash>().map_err(|e| {
            LightningError::InvalidResponse(format!("invalid best block hash: {e}"))
        })?;
        Ok(NodeInfo {
            node_id,
            block_height: best_block.height,
            block_hash,
        })
    }

    fn balances(&self) -> Result<Balances, LightningError> {
        let response = self.call(self.client.get_balances(proto_api::GetBalancesRequest {}))?;
        Ok(Balances {
            total_onchain: Amount::from_sat(response.total_onchain_balance_sats),
            spendable_onchain: Amount::from_sat(response.spendable_onchain_balance_sats),
            anchor_reserve: Amount::from_sat(response.total_anchor_channels_reserve_sats),
            total_lightning: Amount::from_sat(response.total_lightning_balance_sats),
        })
    }

    fn new_onchain_address(&self) -> Result<Address, LightningError> {
        let response = self.call(
            self.client
                .onchain_receive(proto_api::OnchainReceiveRequest {}),
        )?;
        // The sidecar is our own trusted node; network consistency between
        // the node and the coinswap wallet is enforced by the caller.
        Ok(response
            .address
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()?
            .assume_checked())
    }

    fn send_onchain(
        &self,
        address: &Address,
        amount: Option<Amount>,
        fee_rate_sat_vb: Option<u64>,
    ) -> Result<Txid, LightningError> {
        let request = proto_api::OnchainSendRequest {
            address: address.to_string(),
            amount_sats: amount.map(|a| a.to_sat()),
            send_all: if amount.is_none() { Some(true) } else { None },
            fee_rate_sat_per_vb: fee_rate_sat_vb,
        };
        let response = self.call(self.client.onchain_send(request))?;
        response
            .txid
            .parse::<Txid>()
            .map_err(|e| LightningError::InvalidResponse(format!("invalid txid: {e}")))
    }

    fn open_channel(&self, req: OpenChannelRequest) -> Result<ChannelId, LightningError> {
        let request = proto_api::OpenChannelRequest {
            node_pubkey: req.node_pubkey.to_string(),
            address: req.address,
            channel_amount_sats: req.channel_amount.to_sat(),
            push_to_counterparty_msat: req.push_to_counterparty_msat,
            channel_config: None,
            announce_channel: req.announce_channel,
            disable_counterparty_reserve: false,
        };
        let response = self.call(self.client.open_channel(request))?;
        Ok(ChannelId(response.user_channel_id))
    }

    fn close_channel(
        &self,
        channel_id: &ChannelId,
        counterparty: &PublicKey,
        force: bool,
    ) -> Result<(), LightningError> {
        if force {
            let request = proto_api::ForceCloseChannelRequest {
                user_channel_id: channel_id.0.clone(),
                counterparty_node_id: counterparty.to_string(),
                force_close_reason: None,
            };
            self.call(self.client.force_close_channel(request))?;
        } else {
            let request = proto_api::CloseChannelRequest {
                user_channel_id: channel_id.0.clone(),
                counterparty_node_id: counterparty.to_string(),
            };
            self.call(self.client.close_channel(request))?;
        }
        Ok(())
    }

    fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        let response = self.call(self.client.list_channels(proto_api::ListChannelsRequest {}))?;
        response.channels.iter().map(convert_channel).collect()
    }

    fn create_invoice(&self, params: InvoiceParams) -> Result<Bolt11Invoice, LightningError> {
        let request = proto_api::Bolt11ReceiveRequest {
            amount_msat: params.amount_msat,
            description: Some(invoice_description(params.description)),
            expiry_secs: params.expiry_secs,
        };
        let response = self.call(self.client.bolt11_receive(request))?;
        let payment_hash = parse_payment_hash(&response.payment_hash)?;
        Ok(Bolt11Invoice {
            invoice: response.invoice,
            payment_hash,
        })
    }

    fn pay_invoice(
        &self,
        invoice: &str,
        amount_msat: Option<u64>,
    ) -> Result<PaymentId, LightningError> {
        let request = proto_api::Bolt11SendRequest {
            invoice: invoice.to_string(),
            amount_msat,
            route_parameters: None,
        };
        let response = self.call(self.client.bolt11_send(request))?;
        Ok(PaymentId(response.payment_id))
    }

    fn create_hold_invoice(
        &self,
        payment_hash: sha256::Hash,
        params: InvoiceParams,
    ) -> Result<Bolt11Invoice, LightningError> {
        let request = proto_api::Bolt11ReceiveForHashRequest {
            amount_msat: params.amount_msat,
            description: Some(invoice_description(params.description)),
            expiry_secs: params.expiry_secs,
            payment_hash: payment_hash.to_string(),
        };
        let response = self.call(self.client.bolt11_receive_for_hash(request))?;
        Ok(Bolt11Invoice {
            invoice: response.invoice,
            payment_hash,
        })
    }

    fn claim_held_payment(&self, preimage: &Preimage) -> Result<(), LightningError> {
        let request = proto_api::Bolt11ClaimForHashRequest {
            payment_hash: Some(preimage.payment_hash().to_string()),
            claimable_amount_msat: None,
            preimage: preimage.to_hex(),
        };
        self.call(self.client.bolt11_claim_for_hash(request))?;
        Ok(())
    }

    fn fail_held_payment(&self, payment_hash: sha256::Hash) -> Result<(), LightningError> {
        let request = proto_api::Bolt11FailForHashRequest {
            payment_hash: payment_hash.to_string(),
        };
        self.call(self.client.bolt11_fail_for_hash(request))?;
        Ok(())
    }

    fn poll_event(&self) -> Result<Option<LnEvent>, LightningError> {
        match self.event_rx.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(LightningError::EventStream(
                "event task terminated".to_string(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Proto conversions. These private functions are the only seam that touches
// ldk-server protobuf types, keeping upstream API churn contained here.
// ---------------------------------------------------------------------------

fn convert_error(error: LdkServerError) -> LightningError {
    LightningError::Api {
        code: error.error_code.to_string(),
        message: error.message,
    }
}

fn parse_pubkey(hex: &str) -> Result<PublicKey, LightningError> {
    hex.parse::<PublicKey>()
        .map_err(|e| LightningError::InvalidResponse(format!("invalid public key '{hex}': {e}")))
}

fn parse_payment_hash(hex: &str) -> Result<sha256::Hash, LightningError> {
    hex.parse::<sha256::Hash>()
        .map_err(|e| LightningError::InvalidResponse(format!("invalid payment hash '{hex}': {e}")))
}

fn parse_preimage(hex: &str) -> Result<Preimage, LightningError> {
    <[u8; 32]>::from_hex(hex)
        .map(Preimage)
        .map_err(|e| LightningError::InvalidResponse(format!("invalid preimage '{hex}': {e}")))
}

fn invoice_description(description: String) -> proto_types::Bolt11InvoiceDescription {
    proto_types::Bolt11InvoiceDescription {
        kind: Some(proto_types::bolt11_invoice_description::Kind::Direct(
            description,
        )),
    }
}

/// Fields of interest extracted from a proto `Payment`.
struct PaymentFields {
    payment_id: PaymentId,
    payment_hash: Option<sha256::Hash>,
    preimage: Option<Preimage>,
    amount_msat: Option<u64>,
    fee_paid_msat: Option<u64>,
}

fn extract_payment_fields(payment: Option<&proto_types::Payment>) -> PaymentFields {
    let Some(payment) = payment else {
        return PaymentFields {
            payment_id: PaymentId(String::new()),
            payment_hash: None,
            preimage: None,
            amount_msat: None,
            fee_paid_msat: None,
        };
    };
    let (hash_hex, preimage_hex) = match payment.kind.as_ref().and_then(|k| k.kind.as_ref()) {
        Some(proto_types::payment_kind::Kind::Bolt11(bolt11)) => {
            (Some(bolt11.hash.as_str()), bolt11.preimage.as_deref())
        }
        Some(proto_types::payment_kind::Kind::Spontaneous(spontaneous)) => (
            Some(spontaneous.hash.as_str()),
            spontaneous.preimage.as_deref(),
        ),
        _ => (None, None),
    };
    PaymentFields {
        payment_id: PaymentId(payment.id.clone()),
        payment_hash: hash_hex.and_then(|h| parse_payment_hash(h).ok()),
        preimage: preimage_hex.and_then(|p| parse_preimage(p).ok()),
        amount_msat: payment.amount_msat,
        fee_paid_msat: payment.fee_paid_msat,
    }
}

fn convert_channel_state(state: i32) -> ChannelState {
    match proto_events::ChannelState::from_i32(state) {
        Some(proto_events::ChannelState::Pending) => ChannelState::Pending,
        Some(proto_events::ChannelState::Ready) => ChannelState::Ready,
        Some(proto_events::ChannelState::OpenFailed) => ChannelState::OpenFailed,
        Some(proto_events::ChannelState::Closed) => ChannelState::Closed,
        Some(proto_events::ChannelState::Unspecified) | None => ChannelState::Unknown,
    }
}

fn convert_channel(channel: &proto_types::Channel) -> Result<ChannelInfo, LightningError> {
    Ok(ChannelInfo {
        channel_id: channel.channel_id.clone(),
        user_channel_id: ChannelId(channel.user_channel_id.clone()),
        counterparty: parse_pubkey(&channel.counterparty_node_id)?,
        value: Amount::from_sat(channel.channel_value_sats),
        outbound_capacity_msat: channel.outbound_capacity_msat,
        inbound_capacity_msat: channel.inbound_capacity_msat,
        is_outbound: channel.is_outbound,
        confirmations: channel.confirmations,
        state: if channel.is_channel_ready {
            ChannelState::Ready
        } else {
            ChannelState::Pending
        },
        is_usable: channel.is_usable,
    })
}

fn convert_event(envelope: proto_events::EventEnvelope) -> LnEvent {
    use proto_events::event_envelope::Event;
    match envelope.event {
        Some(Event::PaymentReceived(event)) => {
            let fields = extract_payment_fields(event.payment.as_ref());
            LnEvent::PaymentReceived {
                payment_id: fields.payment_id,
                payment_hash: fields.payment_hash,
                amount_msat: fields.amount_msat,
            }
        }
        Some(Event::PaymentClaimable(event)) => {
            let fields = extract_payment_fields(event.payment.as_ref());
            LnEvent::PaymentClaimable {
                payment_id: fields.payment_id,
                payment_hash: fields.payment_hash,
                amount_msat: fields.amount_msat,
                claim_deadline: event.claim_deadline,
            }
        }
        Some(Event::PaymentSuccessful(event)) => {
            let fields = extract_payment_fields(event.payment.as_ref());
            LnEvent::PaymentSuccessful {
                payment_id: fields.payment_id,
                payment_hash: fields.payment_hash,
                preimage: fields.preimage,
                fee_paid_msat: fields.fee_paid_msat,
            }
        }
        Some(Event::PaymentFailed(event)) => {
            let fields = extract_payment_fields(event.payment.as_ref());
            LnEvent::PaymentFailed {
                payment_id: fields.payment_id,
                payment_hash: fields.payment_hash,
            }
        }
        Some(Event::PaymentForwarded(event)) => LnEvent::PaymentForwarded {
            fee_earned_msat: event
                .forwarded_payment
                .and_then(|f| f.total_fee_earned_msat),
        },
        Some(Event::ChannelStateChanged(event)) => LnEvent::ChannelStateChanged {
            channel_id: ChannelId(event.user_channel_id),
            counterparty: event
                .counterparty_node_id
                .as_deref()
                .and_then(|pk| parse_pubkey(pk).ok()),
            state: convert_channel_state(event.state),
        },
        None => LnEvent::Unknown("empty event envelope".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;

    use super::*;

    const PUBKEY_HEX: &str = "0217890e3aad8d35bc054f43acc00084b25229ecff0ab68debd82883ad65ee8266";

    fn bolt11_payment(preimage: Option<&Preimage>) -> proto_types::Payment {
        let preimage = preimage.copied().unwrap_or(Preimage([5u8; 32]));
        proto_types::Payment {
            id: "payment-1".to_string(),
            kind: Some(proto_types::PaymentKind {
                kind: Some(proto_types::payment_kind::Kind::Bolt11(
                    proto_types::Bolt11 {
                        hash: preimage.payment_hash().to_string(),
                        preimage: Some(preimage.to_hex()),
                        secret: None,
                        counterparty_skimmed_fee_msat: None,
                    },
                )),
            }),
            amount_msat: Some(42_000),
            fee_paid_msat: Some(12),
            direction: 0,
            status: 1,
            latest_update_timestamp: 0,
        }
    }

    #[test]
    fn converts_payment_claimable_event() {
        let preimage = Preimage([5u8; 32]);
        let envelope = proto_events::EventEnvelope {
            event: Some(proto_events::event_envelope::Event::PaymentClaimable(
                proto_events::PaymentClaimable {
                    payment: Some(bolt11_payment(Some(&preimage))),
                    custom_records: vec![],
                    claim_deadline: Some(800_000),
                },
            )),
        };
        match convert_event(envelope) {
            LnEvent::PaymentClaimable {
                payment_id,
                payment_hash,
                amount_msat,
                claim_deadline,
            } => {
                assert_eq!(payment_id.0, "payment-1");
                assert_eq!(payment_hash, Some(preimage.payment_hash()));
                assert_eq!(amount_msat, Some(42_000));
                assert_eq!(claim_deadline, Some(800_000));
            }
            other => panic!("expected PaymentClaimable, got {:?}", other),
        }
    }

    #[test]
    fn converts_payment_successful_event_with_preimage() {
        let preimage = Preimage([5u8; 32]);
        let envelope = proto_events::EventEnvelope {
            event: Some(proto_events::event_envelope::Event::PaymentSuccessful(
                proto_events::PaymentSuccessful {
                    payment: Some(bolt11_payment(Some(&preimage))),
                },
            )),
        };
        match convert_event(envelope) {
            LnEvent::PaymentSuccessful {
                preimage: extracted,
                fee_paid_msat,
                ..
            } => {
                assert_eq!(extracted, Some(preimage));
                assert_eq!(fee_paid_msat, Some(12));
            }
            other => panic!("expected PaymentSuccessful, got {:?}", other),
        }
    }

    #[test]
    fn converts_channel_state_changed_event() {
        let envelope = proto_events::EventEnvelope {
            event: Some(proto_events::event_envelope::Event::ChannelStateChanged(
                proto_events::ChannelStateChanged {
                    channel_id: "aa".repeat(32),
                    user_channel_id: "user-chan-1".to_string(),
                    counterparty_node_id: Some(PUBKEY_HEX.to_string()),
                    state: proto_events::ChannelState::Ready as i32,
                    funding_txo: None,
                    reason: None,
                    closure_initiator: 0,
                },
            )),
        };
        match convert_event(envelope) {
            LnEvent::ChannelStateChanged {
                channel_id,
                counterparty,
                state,
            } => {
                assert_eq!(channel_id, ChannelId("user-chan-1".to_string()));
                assert_eq!(counterparty, Some(PUBKEY_HEX.parse().unwrap()));
                assert_eq!(state, ChannelState::Ready);
            }
            other => panic!("expected ChannelStateChanged, got {:?}", other),
        }
    }

    #[test]
    fn converts_empty_envelope_and_unknown_state() {
        assert_eq!(
            convert_event(proto_events::EventEnvelope { event: None }),
            LnEvent::Unknown("empty event envelope".to_string())
        );
        assert_eq!(convert_channel_state(999), ChannelState::Unknown);
        assert_eq!(convert_channel_state(0), ChannelState::Unknown);
    }

    #[test]
    fn converts_channel() {
        let proto = proto_types::Channel {
            channel_id: "cc".repeat(32),
            counterparty_node_id: PUBKEY_HEX.to_string(),
            user_channel_id: "user-chan-2".to_string(),
            channel_value_sats: 250_000,
            outbound_capacity_msat: 200_000_000,
            inbound_capacity_msat: 50_000_000,
            is_outbound: true,
            is_channel_ready: true,
            is_usable: true,
            confirmations: Some(6),
            ..Default::default()
        };
        let info = convert_channel(&proto).unwrap();
        assert_eq!(info.user_channel_id, ChannelId("user-chan-2".to_string()));
        assert_eq!(info.value, Amount::from_sat(250_000));
        assert_eq!(info.state, ChannelState::Ready);
        assert!(info.is_usable);

        let pending = proto_types::Channel {
            is_channel_ready: false,
            ..proto
        };
        assert_eq!(
            convert_channel(&pending).unwrap().state,
            ChannelState::Pending
        );

        let bad = proto_types::Channel {
            counterparty_node_id: "nonsense".to_string(),
            ..pending
        };
        assert!(matches!(
            convert_channel(&bad),
            Err(LightningError::InvalidResponse(_))
        ));
    }

    #[test]
    fn payment_fields_from_malformed_payment_degrade_gracefully() {
        let payment = proto_types::Payment {
            id: "payment-2".to_string(),
            kind: Some(proto_types::PaymentKind {
                kind: Some(proto_types::payment_kind::Kind::Bolt11(
                    proto_types::Bolt11 {
                        hash: "not-hex".to_string(),
                        preimage: Some("also-not-hex".to_string()),
                        secret: None,
                        counterparty_skimmed_fee_msat: None,
                    },
                )),
            }),
            ..Default::default()
        };
        let fields = extract_payment_fields(Some(&payment));
        assert_eq!(fields.payment_id.0, "payment-2");
        assert!(fields.payment_hash.is_none());
        assert!(fields.preimage.is_none());

        let empty = extract_payment_fields(None);
        assert!(empty.payment_id.0.is_empty());
        assert!(empty.payment_hash.is_none());
    }

    #[test]
    fn converts_ldk_error_to_api_error() {
        let error = LdkServerError::new(
            ldk_server_client::error::LdkServerErrorCode::InvalidRequestError,
            "bad request",
        );
        match convert_error(error) {
            LightningError::Api { code, message } => {
                assert_eq!(code, "InvalidRequestError");
                assert_eq!(message, "bad request");
            }
            other => panic!("expected Api error, got {:?}", other),
        }
    }

    #[test]
    fn parses_hashes_and_preimages() {
        let hash = sha256::Hash::hash(b"test");
        assert_eq!(parse_payment_hash(&hash.to_string()).unwrap(), hash);
        assert!(parse_payment_hash("xyz").is_err());

        let preimage = Preimage([1u8; 32]);
        assert_eq!(parse_preimage(&preimage.to_hex()).unwrap(), preimage);
        assert!(parse_preimage("deadbeef").is_err());
    }
}
