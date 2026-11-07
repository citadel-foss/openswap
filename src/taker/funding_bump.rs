//! Funding bumps on the taker side.
//!
//! While a hop's funding waits to confirm, the taker may replace it at a
//! higher feerate: its own hop-0 funding directly, a maker's by asking that
//! maker with a signed [`BumpFunding`]. The replacement takes the extra fee out
//! of the contract output, so every later hop forwards that much less and the
//! taker, receiving last, pays for it. Off unless the swap sets a
//! [`FundingBumpPolicy`].
//!
//! Every version of a bumped split spends the same coins, so exactly one
//! confirms. Until one does, all are kept, in memory and in the wallet, so a
//! crash still recovers whichever version lands. Once the hop confirms,
//! [`Taker::settle_hop_funding`] keeps the winners and drops the rest.

use std::time::{Duration, Instant};

use bitcoin::{
    ecdsa::Signature as EcdsaSignature,
    hashes::{hash160::Hash as Hash160, Hash},
    secp256k1::{self, Secp256k1, SecretKey},
    Amount, OutPoint, PublicKey, Transaction, Txid,
};

use crate::{
    protocol::{
        common_messages::{MakerToTakerMessage, ProtocolVersion, TakerToMakerMessage},
        contract::{
            create_multisig_redeemscript, create_senders_contract_tx,
            read_pubkeys_from_multisig_redeemscript, sign_contract_tx, verify_contract_tx_sig,
        },
        funding_bump::{
            bump_delta_sats, is_bumped_replacement, sign_bump, unsigned_replacement,
            within_bump_shortfall, BumpFunding, BumpFundingCommit, BumpedFunding,
            FUNDING_BUMP_FEATURE, MAX_FUNDING_BUMPS,
        },
        legacy_messages::{
            ContractTxInfoForSender, ReqContractSigsForSender, SenderContractTxInfo,
        },
    },
    utill::{read_message, send_message},
    wallet::{
        min_contract_value_sats,
        swapcoin::{IncomingSwapCoin, OutgoingSwapCoin, WatchOnlySwapCoin},
        wait_for_slots_confirmation, AnyBlockchain, Blockchain, FeePriority, SlotTrack, SlotWait,
        SlotWaitOutcome, UTXOSpendInfo, WalletError,
    },
};

use super::{
    api::{Taker, CONFIRMATION_HEIGHT_TOLERANCE},
    error::{breach_or_wallet_error, TakerError},
    legacy_verification::fetch_tx_with_retry,
};

/// When the taker bumps a hop whose funding sits unconfirmed. A swap without
/// one never bumps, and makers advertise their own limits on top of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundingBumpPolicy {
    /// Blocks a hop's funding may stay unconfirmed before a bump, and between
    /// bumps. Legacy needs this well inside the few blocks two consecutive
    /// hops may confirm apart, or the bump comes too late to help.
    pub after_blocks: u32,
    /// Highest feerate in sat/vB a bump may reach.
    pub max_feerate: u64,
    /// Most bumps per hop.
    pub max_bumps: u32,
}

impl FundingBumpPolicy {
    /// Bump after 2 blocks, at most twice per hop, up to `max_feerate`.
    pub fn new(max_feerate: u64) -> Self {
        FundingBumpPolicy {
            after_blocks: 2,
            max_feerate,
            max_bumps: 2,
        }
    }

    /// Set the blocks a hop waits before each bump.
    pub fn with_after_blocks(mut self, after_blocks: u32) -> Self {
        self.after_blocks = after_blocks;
        self
    }

    /// Set the most bumps per hop.
    pub fn with_max_bumps(mut self, max_bumps: u32) -> Self {
        self.max_bumps = max_bumps;
        self
    }

    /// Checks the policy before any swap state exists.
    pub(crate) fn validate(
        &self,
        protocol: ProtocolVersion,
        swap_feerate: u64,
    ) -> Result<(), TakerError> {
        if self.after_blocks == 0 {
            return Err(TakerError::General(
                "A funding bump must wait at least one block".to_string(),
            ));
        }
        if !(1..=MAX_FUNDING_BUMPS).contains(&self.max_bumps) {
            return Err(TakerError::General(format!(
                "Funding bumps per hop must be in 1..={MAX_FUNDING_BUMPS}, got {}",
                self.max_bumps
            )));
        }
        if self.max_feerate <= swap_feerate {
            return Err(TakerError::General(format!(
                "Funding bump cap {} sat/vB must exceed the swap feerate {swap_feerate} sat/vB",
                self.max_feerate
            )));
        }
        // A Legacy hop confirming further than this after the previous one
        // fails the swap, so a bump that waits that long can no longer help.
        if protocol == ProtocolVersion::Legacy && self.after_blocks >= CONFIRMATION_HEIGHT_TOLERANCE
        {
            return Err(TakerError::General(format!(
                "Legacy funding bumps must fire within {CONFIRMATION_HEIGHT_TOLERANCE} blocks, got {}",
                self.after_blocks
            )));
        }
        Ok(())
    }
}

/// Funding bump state of one swap.
#[derive(Debug, Clone, Default)]
pub(crate) struct SwapBumps {
    /// Highest sequence number signed for any maker of this swap.
    pub(crate) seq: u32,
    /// How to sign each of our hop-0 funding txs' inputs, kept from the build:
    /// once a tx is out, the coin cache no longer lists what it spends.
    pub(crate) hop0_input_infos: Vec<Vec<UTXOSpendInfo>>,
    /// Our outgoing swapcoins of unsettled replacement versions.
    pub(crate) outgoing_versions: Vec<OutgoingSwapCoin>,
    /// Our incoming swapcoins of unsettled replacement versions.
    pub(crate) incoming_versions: Vec<IncomingSwapCoin>,
    /// Watch-only swapcoins of unsettled replacement versions.
    pub(crate) watchonly_versions: Vec<WatchOnlySwapCoin>,
    /// A Legacy last hop's losing versions, by split: its funding tx,
    /// contract tx and funding amount. Our incoming coins are built only from the winners,
    /// so these become flagged copies of them, which recovery needs should a
    /// reorg mine one.
    pub(crate) legacy_last_hop_losers: Vec<(usize, Transaction, Transaction, Amount)>,
    /// Those copies, by split, kept as incoming swapcoins until the winner
    /// is buried deep. They take the handed-over key with the winners.
    pub(crate) replaced_incoming: Vec<(usize, IncomingSwapCoin)>,
}

/// One version of a funding split.
#[derive(Debug, Clone)]
pub(crate) struct FundingVersion {
    /// The funding tx. A Legacy maker's original comes without signatures.
    pub(crate) funding_tx: Transaction,
    /// Legacy: the sender contract spending this version's contract output.
    pub(crate) contract_tx: Option<Transaction>,
    /// Feerate the version was built at.
    pub(crate) feerate: u64,
}

/// Why looking for unreported replacements failed: the maker proved it broke
/// the swap, or the backend could not answer and the look can be retried.
enum Discovery {
    Violation(TakerError),
    Backend(TakerError),
}

impl From<TakerError> for Discovery {
    fn from(error: TakerError) -> Self {
        Discovery::Backend(error)
    }
}

impl From<WalletError> for Discovery {
    fn from(error: WalletError) -> Self {
        Discovery::Backend(error.into())
    }
}

impl From<Discovery> for TakerError {
    fn from(discovery: Discovery) -> Self {
        match discovery {
            Discovery::Violation(e) | Discovery::Backend(e) => e,
        }
    }
}

/// A hop's funding while it waits to confirm.
#[derive(Debug, Clone)]
pub(crate) struct HopFunding {
    /// 0 is our own; `k` is maker `k - 1`'s, paying maker `k` (or us, last).
    pub(crate) hop: usize,
    /// Index of the contract output in each split's funding tx.
    pub(crate) contract_vouts: Vec<usize>,
    /// Every version of each split, oldest first.
    pub(crate) versions: Vec<Vec<FundingVersion>>,
    /// Feerate the latest versions pay.
    pub(crate) feerate: u64,
    /// Bumps tried so far, successful or not.
    pub(crate) attempts: u32,
    /// Legacy maker hop: what the next hop signs the sender contracts against.
    pub(crate) senders_info: Vec<SenderContractTxInfo>,
    /// Legacy last hop: our multisig keys, since we sign as the next hop.
    pub(crate) receiver_privkeys: Option<Vec<SecretKey>>,
    /// Each split's original funding tx, signed, once read: every version is
    /// priced on its size.
    pub(crate) signed_originals: Vec<Option<Transaction>>,
    /// Tip when the wait began: no version of the hop can be mined below it.
    started_height: u64,
}

impl HopFunding {
    /// A hop with only its original funding, at the swap feerate.
    pub(crate) fn new(
        hop: usize,
        originals: Vec<FundingVersion>,
        contract_vouts: Vec<usize>,
        feerate: u64,
    ) -> Self {
        HopFunding {
            hop,
            contract_vouts,
            signed_originals: vec![None; originals.len()],
            started_height: 0,
            versions: originals.into_iter().map(|version| vec![version]).collect(),
            feerate,
            attempts: 0,
            senders_info: Vec::new(),
            receiver_privkeys: None,
        }
    }

    /// The first coin this hop's funding spends, the same in every version:
    /// what a bump request of it is signed for.
    fn hop_outpoint(&self) -> Result<OutPoint, TakerError> {
        self.versions
            .first()
            .and_then(|split| split.first())
            .and_then(|version| version.funding_tx.input.first())
            .map(|input| input.previous_output)
            .ok_or_else(|| TakerError::General("Hop has no funding to bump".into()))
    }

    fn slots(&self) -> Vec<Vec<Txid>> {
        self.versions
            .iter()
            .map(|split| {
                split
                    .iter()
                    .map(|version| version.funding_tx.compute_txid())
                    .collect()
            })
            .collect()
    }

    /// The contract value version `index` of split `split` funds.
    fn contract_value(&self, split: usize, index: usize) -> Amount {
        self.versions[split][index].funding_tx.output[self.contract_vouts[split]].value
    }

    /// What the settled versions gave up against the originals.
    pub(crate) fn shortfall(&self, winners: &[usize]) -> Amount {
        winners
            .iter()
            .enumerate()
            .map(|(split, &index)| {
                self.contract_value(split, 0)
                    .checked_sub(self.contract_value(split, index))
                    .unwrap_or(Amount::ZERO)
            })
            .sum()
    }
}

/// The tx spending `outpoint`, from the mempool or mined at `since` or
/// later. Core's own lookup scans from the block that created the output,
/// which for an old coin is the whole chain since; a hop's versions can only
/// be mined after its wait began.
fn spender_since(
    chain: &AnyBlockchain,
    outpoint: &OutPoint,
    script: &bitcoin::Script,
    since: u64,
) -> Result<Option<Transaction>, TakerError> {
    let AnyBlockchain::CoreRPC(core) = chain else {
        return Ok(chain.spending_transaction(outpoint, script, None)?);
    };
    if let Some(tx) = core.mempool_spending_transaction(outpoint)? {
        return Ok(Some(tx));
    }
    for height in since..=chain.get_block_count()? {
        if let Some(tx) = chain
            .block_at_height(height)?
            .txdata
            .into_iter()
            .find(|tx| {
                tx.input
                    .iter()
                    .any(|input| input.previous_output == *outpoint)
            })
        {
            return Ok(Some(tx));
        }
    }
    Ok(None)
}

/// What interrupts a hop's wait besides a confirmation.
#[derive(Debug, Clone, Copy)]
pub(crate) enum BreachCheck {
    /// Taproot: never set mid-swap, kept for the shared wait's signature.
    Breached,
    /// Legacy: an adversarial contract broadcast must stop the swap.
    RequiresAbort,
}

impl Taker {
    /// The swap's bump policy, when every maker on the route pinned funding
    /// bumps: each one funds a hop that may be bumped, or takes one that
    /// arrives short of a bump. A maker that predates the feature knows
    /// neither, so the swap is not bumped at all.
    pub(crate) fn funding_bump_policy(&self) -> Result<Option<FundingBumpPolicy>, TakerError> {
        let swap = self.swap_state()?;
        let Some(policy) = swap.params.funding_bump else {
            return Ok(None);
        };
        let all_pinned = swap.makers.iter().all(|maker| {
            maker
                .needed()
                .iter()
                .any(|feature| feature == FUNDING_BUMP_FEATURE)
        });
        if !all_pinned {
            log::warn!("Not bumping funding: a maker on the route does not support funding bumps");
            return Ok(None);
        }
        Ok(Some(policy))
    }

    /// Wait for a hop's funding to confirm, bumping it under the swap's policy
    /// while it sits unconfirmed. Returns the height the last split confirmed
    /// at and, per split, the index of the version that did.
    pub(crate) fn wait_for_hop_funding(
        &mut self,
        funding: &mut HopFunding,
        required_confirms: u32,
        arrival_timeout: Duration,
        breach: BreachCheck,
    ) -> Result<(u32, Vec<usize>), TakerError> {
        let chain = self.backend.connect()?;
        let policy = self.funding_bump_policy()?;
        let started = Instant::now();
        // One track for the whole hop: a bump interval resumes the wait, and
        // must not restart its arrival deadline or forget an eviction.
        let mut track = SlotTrack::new(funding.versions.len());
        funding.started_height = chain.get_block_count()?;
        let mut next_bump_at = match policy {
            Some(policy) => Some(chain.get_block_count()? + u64::from(policy.after_blocks)),
            None => None,
        };
        loop {
            let slots = funding.slots();
            let outcome = {
                let abort = || match breach {
                    BreachCheck::Breached => self
                        .breach_detector
                        .as_ref()
                        .is_some_and(|detector| detector.is_breached()),
                    BreachCheck::RequiresAbort => self
                        .breach_detector
                        .as_ref()
                        .is_some_and(|detector| detector.requires_abort()),
                };
                wait_for_slots_confirmation(
                    &chain,
                    &slots,
                    &SlotWait {
                        required_confirms,
                        arrival_timeout,
                        started,
                        interrupt_at_height: next_bump_at,
                    },
                    &mut track,
                    None,
                    Some(&abort),
                )
            };
            let outcome = match outcome {
                Ok(outcome) => outcome,
                // Every version we know of may have left the mempool because
                // the funder replaced it and its answer never reached us.
                // Look for that version on chain before giving up on the hop.
                Err(WalletError::TxConfirmationTimeout(reason)) => {
                    if self
                        .discover_replacements(&chain, funding)
                        .map_err(TakerError::from)?
                        > 0
                    {
                        continue;
                    }
                    return Err(TakerError::Wallet(WalletError::TxConfirmationTimeout(
                        reason,
                    )));
                }
                Err(e) => return Err(breach_or_wallet_error(e)),
            };
            match outcome {
                SlotWaitOutcome::Confirmed { height, winners } => {
                    let indexes = slots
                        .iter()
                        .zip(&winners)
                        .map(|(slot, winner)| slot.iter().position(|txid| txid == winner))
                        .collect::<Option<Vec<_>>>()
                        .ok_or_else(|| {
                            TakerError::General("Confirmed funding is no known version".into())
                        })?;
                    return Ok((height, indexes));
                }
                SlotWaitOutcome::HeightReached(tip) => {
                    let Some(policy) = policy else {
                        next_bump_at = None;
                        continue;
                    };
                    // Checked on every interval, bumps left or not: a version
                    // we never heard of may be what is about to confirm.
                    next_bump_at = Some(tip + u64::from(policy.after_blocks));
                    // Only a proven violation ends the wait here: a backend
                    // hiccup is retried on the next interval, and the wait
                    // itself still sees whatever confirms meanwhile.
                    match self.discover_replacements(&chain, funding) {
                        Ok(_) => {}
                        Err(Discovery::Violation(e)) => return Err(e),
                        Err(Discovery::Backend(e)) => log::warn!(
                            "Looking for replacements of hop {} funding failed; still waiting: {:?}",
                            funding.hop,
                            e
                        ),
                    }
                    if funding.attempts >= policy.max_bumps {
                        continue;
                    }
                    match self.next_bump_feerate(&chain, funding, &policy) {
                        // Only a bump tried spends the budget: an interval
                        // where none is due leaves it for a later fee rise.
                        Some(feerate) => {
                            funding.attempts += 1;
                            if let Err(e) = self.bump_hop_funding(&chain, funding, feerate) {
                                log::warn!(
                                    "Funding bump of hop {} to {} sat/vB failed; still waiting: {:?}",
                                    funding.hop,
                                    feerate,
                                    e
                                );
                            }
                        }
                        None => log::info!(
                            "Hop {} funding is unconfirmed, but no bump is due or allowed",
                            funding.hop
                        ),
                    }
                }
            }
        }
    }

    /// The feerate to bump `funding` to, if a bump would help and is allowed:
    /// the market's next-blocks rate, or twice the current rate where the
    /// backend has no estimate, at least one relay step above the current
    /// rate, and within our cap and, for a maker's hop, the maker's.
    fn next_bump_feerate(
        &self,
        chain: &AnyBlockchain,
        funding: &HopFunding,
        policy: &FundingBumpPolicy,
    ) -> Option<u64> {
        let step = (chain.replacement_increment_rate().ceil() as u64).max(1);
        let floor = funding.feerate.saturating_add(step);
        let market = chain
            .estimate_feerate(FeePriority::Urgent)
            .ok()
            .filter(|rate| rate.is_finite())
            .map(|rate| rate.ceil() as u64);
        // Regtest estimates follow whatever the test happened to mine, so a
        // test names the rate the market has reached.
        #[cfg(feature = "integration-test")]
        let market = std::env::var("OPENSWAP_FUNDING_BUMP_FEERATE")
            .ok()
            .and_then(|rate| rate.parse::<u64>().ok())
            .or(market);
        // The market does not pay more than the funding already does.
        if market.is_some_and(|rate| rate < floor) {
            return None;
        }
        let target = market
            .unwrap_or_else(|| funding.feerate.saturating_mul(2))
            .max(floor);
        let mut cap = policy.max_feerate;
        if funding.hop > 0 {
            let maker_cap = self
                .swap_state()
                .ok()?
                .makers
                .get(funding.hop - 1)?
                .offer
                .as_ref()
                .map_or(0, |offer| offer.max_funding_bump_feerate);
            cap = cap.min(maker_cap);
        }
        let target = target.min(cap);
        (target >= floor).then_some(target)
    }

    /// Find versions of a maker's hop that its funder broadcast without our
    /// hearing of them: a bump whose answer went missing. A spend of an
    /// original's coins must be exactly that original bumped to some feerate
    /// within the caps; anything else is the maker spending its funding
    /// coins outside the swap, a proven violation. Returns how many versions
    /// were added.
    fn discover_replacements(
        &mut self,
        chain: &AnyBlockchain,
        funding: &mut HopFunding,
    ) -> Result<usize, Discovery> {
        if funding.hop == 0 {
            return Ok(0);
        }
        let maker_idx = funding.hop - 1;
        let swap = self.swap_state()?;
        let swap_feerate = swap.params.swap_feerate();
        // A maker never bumps past its own cap, nor past ours: we never ask.
        let cap = swap.makers[maker_idx]
            .offer
            .as_ref()
            .map_or(0, |offer| offer.max_funding_bump_feerate)
            .min(
                swap.params
                    .funding_bump
                    .map_or(0, |policy| policy.max_feerate),
            );
        let mut added = 0;
        for split in 0..funding.versions.len() {
            let known = funding.slots().swap_remove(split);
            let mut confirmed = false;
            for txid in &known {
                if chain.tx_block_height(txid)?.is_some() {
                    confirmed = true;
                    break;
                }
            }
            if confirmed {
                continue;
            }
            // Never read while it sat in the mempool: nothing to price on.
            let Ok(original) = self.signed_original(chain, funding, split) else {
                continue;
            };
            let Some(outpoint) = original.input.first().map(|input| input.previous_output) else {
                continue;
            };
            let parent = fetch_tx_with_retry(chain, &outpoint.txid)?;
            let Some(prevout) = parent.output.get(outpoint.vout as usize) else {
                continue;
            };
            let Some(spender) = spender_since(
                chain,
                &outpoint,
                &prevout.script_pubkey,
                funding.started_height,
            )?
            else {
                continue;
            };
            if known.contains(&spender.compute_txid()) {
                continue;
            }

            let vout = funding.contract_vouts[split];
            let base = funding.versions[split][0].feerate;
            let step_size = original.vsize() as u64 + 1;
            let delta = spender
                .output
                .get(vout)
                .and_then(|output| original.output[vout].value.checked_sub(output.value))
                .map(|delta| delta.to_sat())
                .unwrap_or(0);
            let feerate = base + delta / step_size;
            let exact_bump = delta > 0
                && delta % step_size == 0
                && feerate <= cap
                && bump_delta_sats(&original, base, feerate) == Some(delta)
                && is_bumped_replacement(&original, &spender, vout, delta);
            if !exact_bump {
                self.note_proven_violation(maker_idx);
                return Err(Discovery::Violation(TakerError::General(format!(
                    "Maker {maker_idx} spent the coins of its funding split {split} outside the swap"
                ))));
            }
            let contract_tx = match funding.senders_info.get(split) {
                Some(info) => Some(
                    create_senders_contract_tx(
                        OutPoint::new(spender.compute_txid(), vout as u32),
                        spender.output[vout].value,
                        &info.contract_redeemscript,
                        swap_feerate,
                    )
                    .map_err(TakerError::from)?,
                ),
                None => None,
            };
            log::warn!(
                "Found replacement funding {} for hop {} split {} at {} sat/vB that its maker never reported",
                spender.compute_txid(),
                funding.hop,
                split,
                feerate
            );
            self.keep_maker_version(funding, split, &spender, contract_tx.as_ref())?;
            funding.versions[split].push(FundingVersion {
                funding_tx: spender,
                contract_tx,
                feerate,
            });
            funding.feerate = funding.feerate.max(feerate);
            added += 1;
        }
        Ok(added)
    }

    /// Split `split`'s original funding tx, signed, which every version is
    /// priced on: ours and a Taproot maker's arrive signed, a Legacy maker's
    /// is read off the backend the first time, while it sits in the mempool.
    fn signed_original(
        &self,
        chain: &AnyBlockchain,
        funding: &mut HopFunding,
        split: usize,
    ) -> Result<Transaction, TakerError> {
        if let Some(signed) = funding.signed_originals[split].clone() {
            return Ok(signed);
        }
        let original = &funding.versions[split][0].funding_tx;
        let signed = if original.input.iter().all(|i| !i.witness.is_empty()) {
            original.clone()
        } else {
            let txid = original.compute_txid();
            let signed = fetch_tx_with_retry(chain, &txid)?;
            if signed.compute_txid() != txid {
                return Err(TakerError::General(format!(
                    "Backend returned another tx for funding {txid}"
                )));
            }
            signed
        };
        funding.signed_originals[split] = Some(signed.clone());
        Ok(signed)
    }

    /// Replace every unconfirmed split of `funding` with its version at
    /// `feerate`: ours directly, a maker's through its funder.
    fn bump_hop_funding(
        &mut self,
        chain: &AnyBlockchain,
        funding: &mut HopFunding,
        feerate: u64,
    ) -> Result<(), TakerError> {
        let mut pending = Vec::new();
        // What the contracts give up at this rate: each bumped split's new
        // version, and whatever a split that already confirmed gave up.
        let mut reduction = Amount::ZERO;
        for split in 0..funding.versions.len() {
            let mut confirmed = false;
            for version in &funding.versions[split] {
                if chain
                    .tx_block_height(&version.funding_tx.compute_txid())?
                    .is_some()
                {
                    confirmed = true;
                    break;
                }
            }
            if confirmed {
                let lowest = (0..funding.versions[split].len())
                    .map(|index| funding.contract_value(split, index))
                    .min()
                    .unwrap_or(Amount::ZERO);
                reduction += funding
                    .contract_value(split, 0)
                    .checked_sub(lowest)
                    .unwrap_or(Amount::ZERO);
                continue;
            }
            let original = self.signed_original(chain, funding, split)?;
            let base = funding.versions[split][0].feerate;
            let delta = bump_delta_sats(&original, base, feerate)
                .ok_or_else(|| TakerError::General("Bump does not raise the feerate".into()))?;
            reduction = reduction
                .checked_add(Amount::from_sat(delta))
                .ok_or_else(|| TakerError::General("Funding bump total overflows".into()))?;
            pending.push((split, original, delta));
        }
        if pending.is_empty() {
            return Ok(());
        }
        self.check_bump_bounds(funding, reduction)?;

        log::info!(
            "Bumping hop {} funding ({} tx) from {} to {} sat/vB, {} out of the contracts",
            funding.hop,
            pending.len(),
            funding.feerate,
            feerate,
            reduction
        );
        let protocol = self.swap_state()?.params.protocol;
        let added = match (funding.hop, protocol) {
            (0, ProtocolVersion::Taproot) => self.bump_own_taproot(funding, &pending, feerate)?,
            (0, ProtocolVersion::Legacy) => self.bump_own_legacy(funding, &pending, feerate)?,
            (_, ProtocolVersion::Taproot) => self.bump_maker_taproot(funding, &pending, feerate)?,
            (_, ProtocolVersion::Legacy) => self.bump_maker_legacy(funding, &pending, feerate)?,
        };
        if added == 0 {
            // Our own versions are tracked even so, and one may be out: a
            // later bump must price above it.
            if funding.hop == 0 {
                funding.feerate = feerate;
            }
            return Err(TakerError::General(
                "No replacement funding reached the backend".into(),
            ));
        }
        funding.feerate = feerate;
        log::info!(
            "Funding bump broadcast for hop {}: {} replacement(s) at {} sat/vB",
            funding.hop,
            added,
            feerate
        );
        Ok(())
    }

    /// A bump taking `reduction` out of the hop's contracts must fit the
    /// funding maker's cap and leave every later hop within the shortfall it
    /// accepts.
    fn check_bump_bounds(&self, funding: &HopFunding, reduction: Amount) -> Result<(), TakerError> {
        let swap = self.swap_state()?;
        if funding.hop > 0 {
            let cap = swap.makers[funding.hop - 1]
                .offer
                .as_ref()
                .map_or(0, |offer| offer.max_funding_bump_sats);
            if reduction.to_sat() > cap {
                return Err(TakerError::General(format!(
                    "Maker {} caps its funding bumps at {cap} sats",
                    funding.hop - 1
                )));
            }
        }
        // Every hop from the bumped one on forwards the whole bump less.
        let upstream = funding
            .hop
            .checked_sub(1)
            .and_then(|maker| swap.makers.get(maker))
            .map_or(Amount::ZERO, |maker| maker.incoming_shortfall);
        let shortfall = upstream + reduction;
        for maker in swap.makers.iter().skip(funding.hop) {
            let arrives = maker.amount.checked_sub(shortfall).unwrap_or(Amount::ZERO);
            if !within_bump_shortfall(arrives, maker.amount) {
                return Err(TakerError::General(format!(
                    "A bump to {reduction} would leave maker {} short past what it accepts",
                    maker.address
                )));
            }
        }
        Ok(())
    }

    /// Our Taproot hop 0: re-sign each split's original funding with the
    /// contract output lowered, keep it as an outgoing swapcoin, broadcast it.
    fn bump_own_taproot(
        &mut self,
        funding: &mut HopFunding,
        pending: &[(usize, Transaction, u64)],
        feerate: u64,
    ) -> Result<usize, TakerError> {
        let floor = min_contract_value_sats(ProtocolVersion::Taproot, feerate as f64)
            .ok_or_else(|| TakerError::General("Contract floor cannot be priced".into()))?;
        let mut added = 0;
        for (split, signed, delta) in pending {
            let vout = funding.contract_vouts[*split];
            let mut tx = unsigned_replacement(signed, vout, *delta, floor)?;
            let infos = self
                .swap_state()?
                .funding_bump
                .hop0_input_infos
                .get(*split)
                .cloned()
                .ok_or_else(|| TakerError::General("No signing data for our funding".into()))?;
            self.read_wallet()?
                .sign_transaction(&mut tx, infos.into_iter())?;
            let mut version = self.swap_state()?.outgoing_swapcoins[*split].clone();
            version.funding_amount = tx.output[vout].value;
            version.contract_tx = tx.clone();
            self.keep_outgoing_version(&version)?;
            let script_pubkey = tx.output[vout].script_pubkey.clone();
            self.watch_service
                .register_watch_request(
                    OutPoint::new(tx.compute_txid(), vout as u32),
                    script_pubkey,
                )
                .map_err(|e| TakerError::General(format!("watch registration failed: {e}")))?;
            // Tracked whatever the broadcast reports: an error can hide an
            // accepted tx whose reply was lost, and confirmation decides.
            added += usize::from(self.broadcast_replacement(&tx));
            funding.versions[*split].push(FundingVersion {
                funding_tx: tx,
                contract_tx: None,
                feerate,
            });
        }
        Ok(added)
    }

    /// Our Legacy hop 0: re-sign the funding, rebuild the sender contract on
    /// the new outpoint, and have maker 0 sign that contract before anything
    /// is broadcast: a funding whose contract it never signed we could not
    /// refund.
    fn bump_own_legacy(
        &mut self,
        funding: &mut HopFunding,
        pending: &[(usize, Transaction, u64)],
        feerate: u64,
    ) -> Result<usize, TakerError> {
        let floor = min_contract_value_sats(ProtocolVersion::Legacy, feerate as f64)
            .ok_or_else(|| TakerError::General("Contract floor cannot be priced".into()))?;
        let swap_feerate = self.swap_state()?.params.swap_feerate();
        let secp = Secp256k1::new();
        let mut versions = Vec::with_capacity(pending.len());
        let mut txs_info = Vec::with_capacity(pending.len());
        for (split, signed, delta) in pending {
            let vout = funding.contract_vouts[*split];
            let mut tx = unsigned_replacement(signed, vout, *delta, floor)?;
            let infos = self
                .swap_state()?
                .funding_bump
                .hop0_input_infos
                .get(*split)
                .cloned()
                .ok_or_else(|| TakerError::General("No signing data for our funding".into()))?;
            self.read_wallet()?
                .sign_transaction(&mut tx, infos.into_iter())?;
            let mut version = self.swap_state()?.outgoing_swapcoins[*split].clone();
            let redeemscript = version.contract_redeemscript.clone().ok_or_else(|| {
                TakerError::General("Outgoing swapcoin has no contract script".into())
            })?;
            version.funding_amount = tx.output[vout].value;
            version.contract_tx = create_senders_contract_tx(
                OutPoint::new(tx.compute_txid(), vout as u32),
                version.funding_amount,
                &redeemscript,
                swap_feerate,
            )?;
            version.funding_tx = Some(tx);
            version.others_contract_sig = None;
            let (Some(my_pubkey), Some(other_pubkey)) = (version.my_pubkey, version.other_pubkey)
            else {
                return Err(TakerError::General(
                    "Outgoing swapcoin is missing its keys".into(),
                ));
            };
            let swap = self.swap_state()?;
            txs_info.push(ContractTxInfoForSender {
                multisig_nonce: *swap.multisig_nonces.get(*split).ok_or_else(|| {
                    TakerError::General("No multisig nonce for this split".into())
                })?,
                hashlock_nonce: *swap.hashlock_nonces.get(*split).ok_or_else(|| {
                    TakerError::General("No hashlock nonce for this split".into())
                })?,
                timelock_pubkey: PublicKey {
                    compressed: true,
                    inner: secp256k1::PublicKey::from_secret_key(&secp, &version.timelock_privkey),
                },
                senders_contract_tx: version.contract_tx.clone(),
                multisig_redeemscript: create_multisig_redeemscript(&my_pubkey, &other_pubkey),
                funding_input_value: version.funding_amount,
            });
            versions.push((*split, version));
        }

        let maker_address = self.swap_state()?.makers[0].address.to_string();
        let locktime = self.swap_state()?.makers[0].negotiated_timelock as u16;
        let sigs = self.request_sender_sigs(&maker_address, txs_info, locktime)?;
        for ((_, version), sig) in versions.iter_mut().zip(sigs) {
            let (Some(my_pubkey), Some(other_pubkey)) = (version.my_pubkey, version.other_pubkey)
            else {
                return Err(TakerError::General(
                    "Outgoing swapcoin is missing its keys".into(),
                ));
            };
            verify_contract_tx_sig(
                &version.contract_tx,
                &create_multisig_redeemscript(&my_pubkey, &other_pubkey),
                version.funding_amount,
                &other_pubkey,
                &sig.signature,
            )
            .map_err(|e| {
                self.note_proven_violation(0);
                TakerError::General(format!("Maker 0 signed a bumped contract wrongly: {e:?}"))
            })?;
            crate::protocol::contract::check_contract_sig_sighash(&sig)?;
            version.others_contract_sig = Some(sig);
        }

        let mut added = 0;
        for (split, version) in versions {
            // Kept with the maker's signature before the broadcast: a crash
            // after it must still be able to refund this version.
            self.keep_outgoing_version(&version)?;
            let tx = version
                .funding_tx
                .clone()
                .ok_or_else(|| TakerError::General("Version has no funding tx".into()))?;
            // Tracked whatever the broadcast reports, as in `bump_own_taproot`.
            added += usize::from(self.broadcast_replacement(&tx));
            funding.versions[split].push(FundingVersion {
                funding_tx: tx,
                contract_tx: Some(version.contract_tx.clone()),
                feerate,
            });
        }
        Ok(added)
    }

    /// A Taproot maker's hop: ask the maker, then check each replacement is
    /// exactly its latest version less the bump.
    fn bump_maker_taproot(
        &mut self,
        funding: &mut HopFunding,
        pending: &[(usize, Transaction, u64)],
        feerate: u64,
    ) -> Result<usize, TakerError> {
        let maker_idx = funding.hop - 1;
        let replacements =
            match self.send_bump_request(maker_idx, funding.hop_outpoint()?, feerate)? {
                MakerToTakerMessage::FundingBumped(bumped) => bumped.replacements,
                other => {
                    return Err(TakerError::General(format!(
                        "Maker {maker_idx} answered a funding bump with {other:?}"
                    )))
                }
            };
        let mut added = 0;
        for replacement in replacements {
            let (split, signed, delta) = self.matching_bump(pending, &replacement, maker_idx)?;
            let vout = funding.contract_vouts[split];
            if !is_bumped_replacement(signed, &replacement.funding_tx, vout, *delta) {
                self.note_proven_violation(maker_idx);
                return Err(TakerError::General(format!(
                    "Maker {maker_idx} replaced split {split} with something other than its bump"
                )));
            }
            self.keep_maker_version(funding, split, &replacement.funding_tx, None)?;
            funding.versions[split].push(FundingVersion {
                funding_tx: replacement.funding_tx,
                contract_tx: None,
                feerate,
            });
            added += 1;
        }
        Ok(added)
    }

    /// A Legacy maker's hop: the maker proposes unsigned replacements, the
    /// next hop signs their sender contracts, and the maker broadcasts only
    /// once it holds those signatures.
    fn bump_maker_legacy(
        &mut self,
        funding: &mut HopFunding,
        pending: &[(usize, Transaction, u64)],
        feerate: u64,
    ) -> Result<usize, TakerError> {
        let maker_idx = funding.hop - 1;
        let swap_feerate = self.swap_state()?.params.swap_feerate();
        let (proposal, already_out) =
            match self.send_bump_request(maker_idx, funding.hop_outpoint()?, feerate)? {
                MakerToTakerMessage::BumpFundingProposal(proposal) => {
                    (proposal.replacements, false)
                }
                // Our earlier commit at this rate went through but its answer
                // was lost: the maker hands back what it broadcast then.
                MakerToTakerMessage::FundingBumped(bumped) => (bumped.replacements, true),
                other => {
                    return Err(TakerError::General(format!(
                        "Maker {maker_idx} answered a funding bump with {other:?}"
                    )))
                }
            };

        let mut txs_info = Vec::with_capacity(proposal.len());
        let mut checked = Vec::with_capacity(proposal.len());
        for replacement in &proposal {
            let (split, signed, delta) = self.matching_bump(pending, replacement, maker_idx)?;
            let vout = funding.contract_vouts[split];
            let info = funding.senders_info.get(split).ok_or_else(|| {
                TakerError::General("No sender contract info for this split".into())
            })?;
            let new_amount = replacement
                .funding_tx
                .output
                .get(vout)
                .map(|output| output.value)
                .ok_or_else(|| TakerError::General("Replacement has no contract output".into()))?;
            let expected_contract = create_senders_contract_tx(
                OutPoint::new(replacement.funding_tx.compute_txid(), vout as u32),
                new_amount,
                &info.contract_redeemscript,
                swap_feerate,
            )?;
            if !is_bumped_replacement(signed, &replacement.funding_tx, vout, *delta)
                || replacement.contract_tx.as_ref() != Some(&expected_contract)
            {
                self.note_proven_violation(maker_idx);
                return Err(TakerError::General(format!(
                    "Maker {maker_idx} proposed something other than its bump for split {split}"
                )));
            }
            txs_info.push(ContractTxInfoForSender {
                multisig_nonce: info.multisig_nonce,
                hashlock_nonce: info.hashlock_nonce,
                timelock_pubkey: info.timelock_pubkey,
                senders_contract_tx: expected_contract.clone(),
                multisig_redeemscript: info.multisig_redeemscript.clone(),
                funding_input_value: new_amount,
            });
            checked.push((
                split,
                replacement.funding_tx.compute_txid(),
                expected_contract,
            ));
        }
        if already_out {
            let mut added = 0;
            for (replacement, (split, _, contract_tx)) in proposal.iter().zip(&checked) {
                self.keep_maker_version(
                    funding,
                    *split,
                    &replacement.funding_tx,
                    Some(contract_tx),
                )?;
                funding.versions[*split].push(FundingVersion {
                    funding_tx: replacement.funding_tx.clone(),
                    contract_tx: Some(contract_tx.clone()),
                    feerate,
                });
                added += 1;
            }
            return Ok(added);
        }

        // The next hop signs: a maker, or we ourselves on the last hop.
        let sigs = match &funding.receiver_privkeys {
            Some(privkeys) => txs_info
                .iter()
                .zip(&checked)
                .map(|(info, (split, _, _))| {
                    let privkey = privkeys.get(*split).ok_or_else(|| {
                        TakerError::General("No multisig key for this split".into())
                    })?;
                    Ok(sign_contract_tx(
                        &info.senders_contract_tx,
                        &info.multisig_redeemscript,
                        info.funding_input_value,
                        privkey,
                    )?)
                })
                .collect::<Result<Vec<_>, TakerError>>()?,
            None => {
                let receiver = self.swap_state()?.makers[funding.hop].address.to_string();
                let locktime = self.swap_state()?.makers[funding.hop].negotiated_timelock as u16;
                let sigs = self.request_sender_sigs(&receiver, txs_info.clone(), locktime)?;
                for (info, sig) in txs_info.iter().zip(&sigs) {
                    let (pubkey1, pubkey2) =
                        read_pubkeys_from_multisig_redeemscript(&info.multisig_redeemscript)?;
                    let valid = [pubkey1, pubkey2].iter().any(|pubkey| {
                        verify_contract_tx_sig(
                            &info.senders_contract_tx,
                            &info.multisig_redeemscript,
                            info.funding_input_value,
                            pubkey,
                            &sig.signature,
                        )
                        .is_ok()
                    });
                    if !valid {
                        self.note_proven_violation_at(&receiver);
                        return Err(TakerError::General(
                            "Next hop signed a bumped contract wrongly".into(),
                        ));
                    }
                }
                sigs
            }
        };

        let seq = self.swap_state()?.funding_bump.seq;
        let swap_id = self.swap_state()?.id.clone();
        let hop = funding.hop_outpoint()?;
        let commit = BumpFundingCommit {
            id: swap_id.clone(),
            feerate,
            seq,
            senders_sigs: sigs,
            signature: sign_bump(&self.bump_key()?, &swap_id, &hop, feerate, seq, true),
        };
        let maker_address = self.swap_state()?.makers[maker_idx].address.to_string();
        let broadcast = match self.exchange_bump_message(
            &maker_address,
            TakerToMakerMessage::BumpFundingCommit(commit),
        )? {
            MakerToTakerMessage::FundingBumped(bumped) => bumped.replacements,
            other => {
                return Err(TakerError::General(format!(
                    "Maker {maker_idx} answered a bump commit with {other:?}"
                )))
            }
        };

        let mut added = 0;
        for replacement in broadcast {
            let txid = replacement.funding_tx.compute_txid();
            let Some((split, _, contract_tx)) = checked
                .iter()
                .find(|(split, proposed, _)| {
                    *proposed == txid && *split == replacement.split as usize
                })
                .cloned()
            else {
                self.note_proven_violation(maker_idx);
                return Err(TakerError::General(format!(
                    "Maker {maker_idx} broadcast a funding it never proposed"
                )));
            };
            self.keep_maker_version(funding, split, &replacement.funding_tx, Some(&contract_tx))?;
            funding.versions[split].push(FundingVersion {
                funding_tx: replacement.funding_tx,
                contract_tx: Some(contract_tx),
                feerate,
            });
            added += 1;
        }
        Ok(added)
    }

    /// The pending bump a maker's replacement answers, by its split and coins.
    fn matching_bump<'a>(
        &self,
        pending: &'a [(usize, Transaction, u64)],
        replacement: &BumpedFunding,
        maker_idx: usize,
    ) -> Result<(usize, &'a Transaction, &'a u64), TakerError> {
        pending
            .iter()
            .find(|(split, _, _)| *split == replacement.split as usize)
            .map(|(split, signed, delta)| (*split, signed, delta))
            .ok_or_else(|| {
                self.note_proven_violation(maker_idx);
                TakerError::General(format!(
                    "Maker {maker_idx} replaced split {} we did not ask to bump",
                    replacement.split
                ))
            })
    }

    /// Sign and send a [`BumpFunding`] for the hop whose funding first spends
    /// `hop` to a maker, returning its answer.
    fn send_bump_request(
        &mut self,
        maker_idx: usize,
        hop: OutPoint,
        feerate: u64,
    ) -> Result<MakerToTakerMessage, TakerError> {
        let key = self.bump_key()?;
        let swap = self.swap_state_mut()?;
        swap.funding_bump.seq += 1;
        let seq = swap.funding_bump.seq;
        let swap_id = swap.id.clone();
        let request = BumpFunding {
            id: swap_id.clone(),
            feerate,
            seq,
            signature: sign_bump(&key, &swap_id, &hop, feerate, seq, false),
        };
        let maker_address = swap.makers[maker_idx].address.to_string();
        self.exchange_bump_message(&maker_address, TakerToMakerMessage::BumpFunding(request))
    }

    /// The key our bump requests are signed with.
    fn bump_key(&self) -> Result<SecretKey, TakerError> {
        #[cfg(feature = "integration-test")]
        if self.behavior == super::api::TakerBehavior::ForgeFundingBumpKey {
            log::warn!("Test behavior: signing the funding bump with a key nobody agreed to");
            return Ok(SecretKey::from_slice(&[7u8; 32]).expect("valid test key"));
        }
        Ok(self.swap_state()?.taker_auth_key)
    }

    fn exchange_bump_message(
        &self,
        maker_address: &str,
        message: TakerToMakerMessage,
    ) -> Result<MakerToTakerMessage, TakerError> {
        let mut stream = self.net_connect(maker_address)?;
        send_message(&mut stream, &message)?;
        let reply: MakerToTakerMessage = serde_cbor::from_slice(&read_message(&mut stream)?)?;
        #[cfg(feature = "integration-test")]
        if self.behavior == super::api::TakerBehavior::DropBumpReply
            && matches!(reply, MakerToTakerMessage::FundingBumped(_))
        {
            log::warn!("Test behavior: losing the maker's answer that its replacement is out");
            return Err(TakerError::General(
                "Test: lost the maker's bump answer".to_string(),
            ));
        }
        Ok(reply)
    }

    /// Test hook: once every hop funded, orphan the block that mined the
    /// first maker's funding, ask that maker to bump it, and wait until one
    /// of its versions is mined again.
    #[cfg(feature = "integration-test")]
    pub(crate) fn reorg_and_bump_first_maker_hop(&mut self) -> Result<(), TakerError> {
        // Long enough for the maker's per-block latch to have run.
        std::thread::sleep(crate::utill::HEART_BEAT_INTERVAL * 3);
        let first_hop = self
            .swap_state()?
            .watchonly_swapcoins
            .first()
            .cloned()
            .ok_or_else(|| TakerError::General("Test: no maker-to-maker hop".into()))?;
        let original = match first_hop.protocol {
            ProtocolVersion::Taproot => first_hop.contract_tx.compute_txid(),
            ProtocolVersion::Legacy => first_hop.contract_tx.input[0].previous_output.txid,
        };
        let chain = self.backend.connect()?;
        // Every later hop's funding, signed, read while it is still mined:
        // this deep reorg undoes the height it was built at, so the node drops
        // it as not yet final and nobody else will relay it again.
        let swap = self.swap_state()?;
        let funding_txid = |protocol, contract_tx: &Transaction| match protocol {
            ProtocolVersion::Taproot => contract_tx.compute_txid(),
            ProtocolVersion::Legacy => contract_tx.input[0].previous_output.txid,
        };
        let later_txids: Vec<Txid> = swap
            .incoming_swapcoins
            .iter()
            .map(|coin| funding_txid(coin.protocol, &coin.contract_tx))
            .chain(
                swap.watchonly_swapcoins
                    .iter()
                    // The first hop's own splits are the ones being bumped.
                    .skip(swap.makers[0].funding_splits.len())
                    .map(|coin| funding_txid(coin.protocol, &coin.contract_tx)),
            )
            .collect();
        let later_funding = later_txids
            .iter()
            .map(|txid| chain.get_raw_transaction(txid, None))
            .collect::<Result<Vec<_>, _>>()?;
        let original_signed = chain.get_raw_transaction(&original, None)?;
        // Out of the miner's view first, or the next block mines it again
        // before the bump arrives.
        chain.prioritise_for_test(&original, -100_000_000)?;
        chain.orphan_block_of_for_test(&original)?;
        log::warn!("Test behavior: orphaned the block that mined maker 0's funding {original}");

        let feerate = self.swap_state()?.params.feerate * 3;
        let hop = original_signed
            .input
            .first()
            .map(|input| input.previous_output)
            .ok_or_else(|| TakerError::General("Test: funding with no input".into()))?;
        let answer = self.send_bump_request(0, hop, feerate);
        let replacement = match &answer {
            Ok(MakerToTakerMessage::FundingBumped(bumped)) => bumped
                .replacements
                .first()
                .map(|replacement| replacement.funding_tx.compute_txid()),
            _ => None,
        };
        log::warn!(
            "Test behavior: post-reorg bump of maker 0 answered: {}",
            match &answer {
                Ok(MakerToTakerMessage::FundingBumped(_)) => "replaced".to_string(),
                Ok(other) => format!("{other:?}"),
                Err(e) => format!("refused: {e:?}"),
            }
        );
        if replacement.is_none() {
            // Refused: the original is the hop, so let it be mined again.
            chain.prioritise_for_test(&original, 100_000_000)?;
        }
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let mined = [Some(original), replacement]
                .iter()
                .flatten()
                .map(|txid| chain.tx_block_height(txid))
                .collect::<Result<Vec<_>, _>>()?;
            // The orphaned blocks also held the later hops' funding, which
            // our own incoming coins need mined again before they are swept.
            let later_mined = later_txids
                .iter()
                .map(|txid| chain.tx_block_height(txid).map(|height| height.is_some()))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .all(|mined| mined);
            if mined.iter().any(Option::is_some) && later_mined {
                return Ok(());
            }
            // Refused: the original is the hop. Its block left the chain while
            // it was out of the miner's view, so the node dropped it too.
            let original_again = replacement.is_none().then_some(&original_signed);
            for tx in later_funding.iter().chain(original_again) {
                if let Err(e) = chain.send_raw_transaction(tx) {
                    log::debug!("Test behavior: relaying {} again: {e:?}", tx.compute_txid());
                }
            }
            if Instant::now() > deadline {
                return Err(TakerError::General(
                    "Test: no version of maker 0's funding was mined again".into(),
                ));
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// Have `maker_address` sign sender contracts of a bumped funding.
    fn request_sender_sigs(
        &self,
        maker_address: &str,
        txs_info: Vec<ContractTxInfoForSender>,
        locktime: u16,
    ) -> Result<Vec<EcdsaSignature>, TakerError> {
        let count = txs_info.len();
        let request = ReqContractSigsForSender {
            id: self.swap_state()?.id.clone(),
            txs_info,
            hashvalue: Hash160::hash(&self.swap_state()?.preimage),
            locktime,
        };
        match self.exchange_bump_message(
            maker_address,
            TakerToMakerMessage::ReqContractSigsForSender(request),
        )? {
            MakerToTakerMessage::RespContractSigsForSender(resp) if resp.sigs.len() == count => {
                Ok(resp.sigs)
            }
            other => {
                self.note_proven_violation_at(maker_address);
                Err(TakerError::General(format!(
                    "Expected {count} bumped contract signatures, got {other:?}"
                )))
            }
        }
    }

    /// Broadcast a replacement of our own funding. A refusal is not an error:
    /// the original may have confirmed meanwhile, and the wait settles it.
    fn broadcast_replacement(&self, tx: &Transaction) -> bool {
        let txid = tx.compute_txid();
        let sent = self.read_wallet().map(|wallet| wallet.send_tx(tx));
        #[cfg(feature = "integration-test")]
        let sent = match sent {
            Ok(Ok(_))
                if self.behavior
                    == super::api::TakerBehavior::StallFundingAndLoseBroadcastReply =>
            {
                log::warn!("Test behavior: losing the node's answer to broadcast {txid}");
                Ok(Err(crate::wallet::WalletError::General(
                    "Test: lost the broadcast answer".to_string(),
                )))
            }
            other => other,
        };
        match sent {
            Ok(Ok(_)) => {
                log::info!("Broadcast replacement funding {txid}");
                true
            }
            Ok(Err(e)) => {
                log::warn!("Replacement funding {txid} was not accepted: {e:?}");
                false
            }
            Err(e) => {
                log::warn!("Replacement funding {txid} was not sent: {e:?}");
                false
            }
        }
    }

    /// Persist an outgoing version of our own funding before it is sent.
    fn keep_outgoing_version(&mut self, version: &OutgoingSwapCoin) -> Result<(), TakerError> {
        {
            let mut wallet = self.write_wallet()?;
            wallet.add_outgoing_swapcoin(version);
            wallet.save_to_disk()?;
        }
        self.swap_state_mut()?
            .funding_bump
            .outgoing_versions
            .push(version.clone());
        Ok(())
    }

    /// Keep what we track of a maker's hop in its new version too: the
    /// watch-only coin of a hop between makers, or our incoming coin of the
    /// last Taproot hop. A Legacy last hop's incoming is built only once the
    /// hop confirms.
    fn keep_maker_version(
        &mut self,
        funding: &HopFunding,
        split: usize,
        funding_tx: &Transaction,
        legacy_contract: Option<&Transaction>,
    ) -> Result<(), TakerError> {
        let vout = funding.contract_vouts[split];
        let amount = funding_tx.output[vout].value;
        let original_contract = funding.versions[split][0]
            .contract_tx
            .clone()
            .unwrap_or_else(|| funding.versions[split][0].funding_tx.clone());
        let original_txid = original_contract.compute_txid();
        let swap_id = self.swap_state()?.id.clone();
        let is_last_hop = funding.hop == self.swap_state()?.makers.len();

        if !is_last_hop {
            let Some(original) = self
                .swap_state()?
                .watchonly_swapcoins
                .iter()
                .find(|coin| coin.contract_txid() == original_txid)
                .cloned()
            else {
                return Ok(());
            };
            let mut version = original;
            version.contract_tx = legacy_contract
                .cloned()
                .unwrap_or_else(|| funding_tx.clone());
            version.funding_amount = amount;
            {
                let mut wallet = self.write_wallet()?;
                wallet.add_watchonly_swapcoins(&swap_id, vec![version.clone()]);
                wallet.save_to_disk()?;
            }
            self.swap_state_mut()?
                .funding_bump
                .watchonly_versions
                .push(version);
        } else if legacy_contract.is_none() {
            let Some(original) = self
                .swap_state()?
                .incoming_swapcoins
                .iter()
                .find(|coin| coin.contract_tx.compute_txid() == original_txid)
                .cloned()
            else {
                return Ok(());
            };
            let mut version = original;
            version.contract_tx = funding_tx.clone();
            version.funding_amount = amount;
            {
                let mut wallet = self.write_wallet()?;
                wallet.add_incoming_swapcoin(&version);
                wallet.save_to_disk()?;
            }
            self.swap_state_mut()?
                .funding_bump
                .incoming_versions
                .push(version);
        }
        Ok(())
    }

    /// Settle a confirmed hop on its winning versions: they replace the
    /// originals in what the swap goes on with, and the shortfall is carried
    /// to the hops that forward it. The other versions keep their swapcoins
    /// and watches, past the swap's end too, until the winner is buried deep
    /// enough: a reorg can still confirm one of them, and recovery then
    /// needs it.
    pub(crate) fn settle_hop_funding(
        &mut self,
        funding: &HopFunding,
        winners: &[usize],
    ) -> Result<(), TakerError> {
        let shortfall = funding.shortfall(winners);
        let makers = self.swap_state()?.makers.len();
        if funding.hop < makers {
            let upstream = funding.hop.checked_sub(1).map_or(Amount::ZERO, |maker| {
                self.swap_state()
                    .map(|swap| swap.makers[maker].incoming_shortfall)
                    .unwrap_or(Amount::ZERO)
            });
            self.swap_state_mut()?.makers[funding.hop].incoming_shortfall = upstream + shortfall;
        }
        if funding.versions.iter().all(|split| split.len() == 1) {
            return Ok(());
        }
        if shortfall > Amount::ZERO {
            log::info!(
                "Hop {} confirmed {} sats short of its original funding after bumps",
                funding.hop,
                shortfall.to_sat()
            );
        }

        // Contract txids of every version, and of the ones that confirmed.
        let contract_txid = |version: &FundingVersion| {
            version
                .contract_tx
                .as_ref()
                .unwrap_or(&version.funding_tx)
                .compute_txid()
        };
        let mut losing = Vec::new();
        let mut winning = Vec::new();
        // A Legacy last hop pays us, and our incoming coins are built only
        // later, from the winners: keep what a losing version needs.
        let legacy_last_hop =
            funding.hop == makers && self.swap_state()?.params.protocol == ProtocolVersion::Legacy;
        let mut last_hop_losers = Vec::new();
        for (split, &winner) in winners.iter().enumerate() {
            for (index, version) in funding.versions[split].iter().enumerate() {
                if index == winner {
                    winning.push((split, contract_txid(version)));
                } else {
                    losing.push(contract_txid(version));
                    if let (true, Some(contract_tx)) = (legacy_last_hop, &version.contract_tx) {
                        let vout = funding.contract_vouts[split];
                        last_hop_losers.push((
                            split,
                            version.funding_tx.clone(),
                            contract_tx.clone(),
                            version.funding_tx.output[vout].value,
                        ));
                    }
                }
            }
        }

        let swap = self.swap_state_mut()?;
        let bumps = std::mem::take(&mut swap.funding_bump);
        swap.funding_bump.seq = bumps.seq;
        swap.funding_bump.hop0_input_infos = bumps.hop0_input_infos;
        swap.funding_bump.legacy_last_hop_losers = last_hop_losers;
        if funding.hop == 0 {
            let every_version: Vec<OutgoingSwapCoin> = swap
                .outgoing_swapcoins
                .iter()
                .chain(&bumps.outgoing_versions)
                .cloned()
                .collect();
            for (split, txid) in &winning {
                if let Some(version) = every_version
                    .iter()
                    .find(|coin| coin.contract_tx.compute_txid() == *txid)
                {
                    swap.outgoing_swapcoins[*split] = version.clone();
                }
            }
        } else {
            // A Taproot last hop's losing versions are flagged copies of our
            // incoming coins: they take the handed-over key with the winners.
            if funding.hop == makers && !legacy_last_hop {
                let every_version: Vec<IncomingSwapCoin> = swap
                    .incoming_swapcoins
                    .iter()
                    .chain(&bumps.incoming_versions)
                    .cloned()
                    .collect();
                for (split, &winner) in winners.iter().enumerate() {
                    for (index, version) in funding.versions[split].iter().enumerate() {
                        let txid = contract_txid(version);
                        if index == winner {
                            continue;
                        }
                        if let Some(coin) = every_version
                            .iter()
                            .find(|coin| coin.contract_tx.compute_txid() == txid)
                        {
                            let mut copy = coin.clone();
                            copy.replaced = true;
                            swap.funding_bump.replaced_incoming.push((split, copy));
                        }
                    }
                }
            }
            for (_, txid) in &winning {
                if let Some(version) = bumps
                    .watchonly_versions
                    .iter()
                    .find(|coin| coin.contract_txid() == *txid)
                {
                    if let Some(slot) = swap
                        .watchonly_swapcoins
                        .iter_mut()
                        .find(|coin| coin.is_version_of(version))
                    {
                        *slot = version.clone();
                    }
                }
                if let Some(version) = bumps
                    .incoming_versions
                    .iter()
                    .find(|coin| coin.contract_tx.compute_txid() == *txid)
                {
                    if let Some(slot) = swap.incoming_swapcoins.iter_mut().find(|coin| {
                        coin.timelock_script == version.timelock_script
                            && coin.hashlock_script == version.hashlock_script
                    }) {
                        *slot = version.clone();
                    }
                }
            }
        }

        self.write_wallet()?.mark_replaced_versions(&losing)?;
        log::info!(
            "Hop {} settled; keeping {} other funding version(s) until the winner is buried deep",
            funding.hop,
            losing.len()
        );
        Ok(())
    }
}
