// Insert inside src/taker/offers.rs::tests in the v0.2.3 tag source.
    fn v023_sample_offerbook() -> OfferBook {
        let mut book = OfferBook::default();
        let mut states = vec![MakerState::Good];
        states.extend(
            [
                UnavailableReason::AwaitingOffer,
                UnavailableReason::NoOfferResponse,
                UnavailableReason::BondUnconfirmed,
                UnavailableReason::BondExpired,
                UnavailableReason::BondReorged,
                UnavailableReason::BondUnverified,
                UnavailableReason::UnpriceableOffer,
                UnavailableReason::LegacyStatus,
            ]
            .iter()
            .cloned()
            .map(|reason| {
                MakerState::Unavailable(UnavailableState {
                    reason,
                    since_ts: Some(10),
                    last_attempt_ts: Some(20),
                    attempts: 3,
                })
            }),
        );
        states.extend(
            [
                BanReason::ProvenViolation,
                BanReason::InvalidFidelityProof,
                BanReason::FundingWithheld,
                BanReason::LegacyProvenViolation,
            ]
            .iter()
            .cloned()
            .map(|reason| {
                MakerState::Banned(BanRecord {
                    reason,
                    recorded_at_ts: 30,
                })
            }),
        );
        for (i, state) in states.into_iter().enumerate() {
            let address = addr(&(6102 + i).to_string());
            let mut maker = candidate(address.clone());
            maker.fidelity_outpoint = Some(OutPoint {
                txid: Txid::from_slice(&[i as u8; 32]).unwrap(),
                vout: 0,
            });
            maker.fidelity_expiry_height = Some(800_100);
            maker.first_seen_ts = Some(1);
            maker.mark_success(
                dummy_offer(&address.to_string()),
                MakerProtocol::Unified,
                40,
            );
            maker.state = state.clone();
            book.suppressed_makers.insert(
                address,
                SuppressedMaker {
                    fidelity_outpoint: maker.fidelity_outpoint,
                    fidelity_expiry_height: maker.fidelity_expiry_height,
                    state: Some(state),
                    legacy_proven_violation: false,
                    retry_after_ts: 50,
                },
            );
            book.makers.push(maker);
        }
        book
    }

    #[test]
    fn generate_v023_offerbook_fixture() {
        let output = std::path::PathBuf::from(std::env::var_os("OPENSWAP_COMPAT_FIXTURES").unwrap());
        let book = v023_sample_offerbook();
        std::fs::write(output.join("offerbook-all-states.cbor"), serde_cbor::to_vec(&book).unwrap()).unwrap();
    }
