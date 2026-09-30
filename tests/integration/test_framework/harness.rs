//! [`World`]: one test's framework, takers and makers, torn down in one order.
//!
//! A [`World`] wraps what [`TestFramework::init`] returns and adds nothing to
//! setup: [`WorldBuilder::build`] passes the maker count and the behavior lists
//! to `init` exactly as given. What it adds is ownership. Each maker's server
//! and its thread live in one [`MakerHandle`], and [`World::finish`] (or `Drop`,
//! when a test panics first) tears everything down in one order:
//!
//! 1. drop the takers,
//! 2. shut the makers down (signal all, then join all),
//! 3. stop the framework,
//! 4. join the block-generation thread.
//!
//! The step methods ([`World::fund_taker_default`], [`World::start_makers`],
//! [`World::mine`], ...) each call the framework helper of the same name with
//! the same arguments, so a converted test runs the calls it ran before.

use std::{
    marker::PhantomData,
    mem,
    path::{Path, PathBuf},
    sync::{atomic::Ordering::Relaxed, Arc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use bitcoin::Amount;
use bitcoind::BitcoinD;
use openswap::{
    maker::{MakerBehavior, MakerServer},
    taker::{error::TakerError, SwapParams, SwapSummary, Taker, TakerBehavior},
    utill::NO_SHUTDOWN,
    wallet::{AddressType, Balances, TakerReport},
};

use super::{
    actors::{
        fund_makers, fund_makers_default, fund_taker, fund_taker_default, shutdown_makers,
        spawn_makers, spawn_ready_makers_and_mine, sync_maker_wallets,
        verify_maker_pre_swap_balances, wait_for_makers_setup,
    },
    backend::TestBackend,
    procs::bitcoind::generate_blocks,
    tracker::{spawn_tracker_logger, TrackerLoggerHandle},
    world::{MakerFeeOverride, TestFramework},
};

/// Collects what [`TestFramework::init`] takes. Nothing is defaulted on the
/// test's behalf: no takers and no makers unless named.
pub struct WorldBuilder<B> {
    maker_count: usize,
    maker_behaviors: Vec<MakerBehavior>,
    taker_behaviors: Vec<TakerBehavior>,
    fee_overrides: Option<Vec<Option<MakerFeeOverride>>>,
    check_blocklist: bool,
    backend: PhantomData<fn() -> B>,
}

impl<B: TestBackend> WorldBuilder<B> {
    /// How many makers to create; `init`'s `maker_count`.
    pub fn makers(mut self, count: usize) -> Self {
        self.maker_count = count;
        self
    }

    /// Per-maker behaviors, in maker order; `init`'s `maker_behaviors`. Left
    /// unset, `init` gets an empty list and every maker runs `Normal`.
    pub fn maker_behaviors(mut self, behaviors: impl IntoIterator<Item = MakerBehavior>) -> Self {
        self.maker_behaviors = behaviors.into_iter().collect();
        self
    }

    /// One taker per behavior, in order; `init`'s `taker_behavior`. An empty
    /// list stays empty: the world then has no taker.
    pub fn takers(mut self, behaviors: impl IntoIterator<Item = TakerBehavior>) -> Self {
        self.taker_behaviors = behaviors.into_iter().collect();
        self
    }

    /// Per-maker fee schedules, in maker order, one slot per maker; `None`
    /// keeps the default schedule. Builds through
    /// [`TestFramework::init_with_fee_overrides`] instead of `init`.
    pub fn fee_overrides(
        mut self,
        overrides: impl IntoIterator<Item = Option<MakerFeeOverride>>,
    ) -> Self {
        self.fee_overrides = Some(overrides.into_iter().collect());
        self
    }

    /// Enables runtime blocklist screening on every taker and maker. Builds
    /// through [`TestFramework::init_with_blocklist`] instead of `init`.
    pub fn check_blocklist(mut self) -> Self {
        self.check_blocklist = true;
        self
    }

    /// Runs [`TestFramework::init`] with the collected arguments, or
    /// [`TestFramework::init_with_fee_overrides`] when fee overrides are set,
    /// or [`TestFramework::init_with_blocklist`] when screening is enabled.
    #[must_use = "dropping the World tears the framework down at once"]
    pub fn build(self) -> World {
        // `init` ignores behaviors past the maker count; refuse instead of
        // silently running a scenario without its faulty maker.
        assert!(
            self.maker_behaviors.len() <= self.maker_count,
            "{} maker behaviors for {} makers",
            self.maker_behaviors.len(),
            self.maker_count
        );
        let (framework, takers, makers, block_generation) =
            match (self.fee_overrides, self.check_blocklist) {
                (None, false) => TestFramework::init::<B>(
                    self.maker_count,
                    self.taker_behaviors,
                    self.maker_behaviors,
                ),
                // `init_with_fee_overrides` reads only the length of the config map.
                (Some(fee_overrides), false) => TestFramework::init_with_fee_overrides::<B>(
                    vec![(0, None); self.maker_count],
                    fee_overrides,
                    self.taker_behaviors,
                    self.maker_behaviors,
                ),
                (None, true) => TestFramework::init_with_blocklist::<B>(
                    self.maker_count,
                    self.taker_behaviors,
                    self.maker_behaviors,
                ),
                (Some(_), true) => {
                    panic!("no TestFramework init takes both fee overrides and the blocklist")
                }
            };
        World {
            takers: takers
                .into_iter()
                .map(|taker| TakerHandle { taker })
                .collect(),
            makers: makers
                .into_iter()
                .map(|server| MakerHandle {
                    server,
                    thread: None,
                })
                .collect(),
            block_generation: Some(block_generation),
            torn_down: false,
            framework,
        }
    }
}

/// A running test framework with its takers and makers.
///
/// Field order is drop order: the takers and makers go before the framework,
/// whose own `Drop` then sweeps whatever they flushed into the temp dir.
pub struct World {
    takers: Vec<TakerHandle>,
    makers: Vec<MakerHandle>,
    block_generation: Option<JoinHandle<()>>,
    torn_down: bool,
    framework: Arc<TestFramework>,
}

impl World {
    /// Starts describing a world over backend `B`.
    pub fn builder<B: TestBackend>() -> WorldBuilder<B> {
        WorldBuilder {
            maker_count: 0,
            maker_behaviors: Vec::new(),
            taker_behaviors: Vec::new(),
            fee_overrides: None,
            check_blocklist: false,
            backend: PhantomData,
        }
    }

    /// The framework itself, for what the world does not wrap.
    pub fn framework(&self) -> &Arc<TestFramework> {
        &self.framework
    }

    /// The regtest node.
    pub fn bitcoind(&self) -> &BitcoinD {
        &self.framework.bitcoind
    }

    /// This test's temp dir; taker `i` keeps its data in `taker{i + 1}` under it.
    pub fn temp_dir(&self) -> &Path {
        &self.framework.temp_dir
    }

    /// The debug.log every taker and maker of this test writes to.
    pub fn taker_log_path(&self) -> String {
        self.framework.taker_log_path()
    }

    /// The first taker (`takers[0]`).
    #[track_caller]
    pub fn taker(&self) -> &TakerHandle {
        self.takers.first().expect("this world has no taker")
    }

    /// The first taker (`takers[0]`), mutably.
    #[track_caller]
    pub fn taker_mut(&mut self) -> &mut TakerHandle {
        self.takers.first_mut().expect("this world has no taker")
    }

    /// Moves the first taker out, e.g. into a swap thread. The world no longer
    /// drops it; the test does.
    #[track_caller]
    pub fn take_taker(&mut self) -> TakerHandle {
        assert!(!self.takers.is_empty(), "this world has no taker");
        self.takers.remove(0)
    }

    /// The takers, in taker order.
    pub fn takers(&self) -> &[TakerHandle] {
        &self.takers
    }

    /// The takers, in taker order, mutably.
    pub fn takers_mut(&mut self) -> &mut [TakerHandle] {
        &mut self.takers
    }

    /// The makers, in maker order.
    pub fn makers(&self) -> &[MakerHandle] {
        &self.makers
    }

    /// [`fund_taker_default`] on the first taker; returns its spendable balance.
    pub fn fund_taker_default(&self, utxo_count: u32) -> Amount {
        fund_taker_default(&self.taker().taker, self.bitcoind(), utxo_count)
    }

    /// [`fund_taker`] on the first taker; returns its spendable balance.
    pub fn fund_taker(
        &self,
        utxo_count: u32,
        utxo_value: Amount,
        address_type: AddressType,
    ) -> Amount {
        fund_taker(
            &self.taker().taker,
            self.bitcoind(),
            utxo_count,
            utxo_value,
            address_type,
        )
    }

    /// [`fund_taker_default`] on `takers[index]`; returns its spendable balance.
    #[track_caller]
    pub fn fund_nth_taker_default(&self, index: usize, utxo_count: u32) -> Amount {
        fund_taker_default(&self.takers[index].taker, self.bitcoind(), utxo_count)
    }

    /// [`fund_makers_default`] on every maker.
    pub fn fund_makers_default(&self) -> Vec<Amount> {
        fund_makers_default(&self.servers(), self.bitcoind())
    }

    /// [`fund_makers`] on every maker.
    pub fn fund_makers(
        &self,
        utxo_count: u32,
        utxo_value: Amount,
        address_type: AddressType,
    ) -> Vec<Amount> {
        fund_makers(
            &self.servers(),
            self.bitcoind(),
            utxo_count,
            utxo_value,
            address_type,
        )
    }

    /// Starts every maker server, waits up to `setup_timeout_secs` for their
    /// setup, then syncs their wallets: [`spawn_makers`],
    /// [`wait_for_makers_setup`] and [`sync_maker_wallets`], in that order.
    pub fn start_makers(&mut self, setup_timeout_secs: u64) {
        let servers = self.servers();
        let threads = spawn_makers(&servers);
        self.attach_threads(threads);
        wait_for_makers_setup(&servers, setup_timeout_secs);
        sync_maker_wallets(&servers);
    }

    /// [`spawn_makers`] on every maker, without waiting for their setup.
    pub fn spawn_makers(&mut self) {
        let threads = spawn_makers(&self.servers());
        self.attach_threads(threads);
    }

    /// Starts maker `index`'s server alone, e.g. to bring makers up in stages.
    pub fn spawn_maker(&mut self, index: usize) {
        let maker = &mut self.makers[index];
        assert!(maker.thread.is_none(), "maker server started twice");
        maker.thread = spawn_makers(std::slice::from_ref(&maker.server)).pop();
    }

    /// [`wait_for_makers_setup`] on the first `count` makers.
    pub fn wait_for_first_makers_setup(&self, count: usize, setup_timeout_secs: u64) {
        wait_for_makers_setup(&self.servers()[..count], setup_timeout_secs);
    }

    /// [`wait_for_makers_setup`] on every maker.
    pub fn wait_for_makers_setup(&self, setup_timeout_secs: u64) {
        wait_for_makers_setup(&self.servers(), setup_timeout_secs);
    }

    /// [`spawn_makers`] then [`wait_for_makers_setup`]: [`World::start_makers`]
    /// without its wallet sync.
    pub fn start_makers_without_sync(&mut self, setup_timeout_secs: u64) {
        let servers = self.servers();
        let threads = spawn_makers(&servers);
        self.attach_threads(threads);
        wait_for_makers_setup(&servers, setup_timeout_secs);
    }

    /// [`spawn_ready_makers_and_mine`]: start every maker server, wait for
    /// their setup, mine one block. No wallet sync.
    pub fn spawn_ready_makers_and_mine(&mut self) {
        let servers = self.servers();
        let threads = spawn_ready_makers_and_mine(&servers, self.bitcoind());
        self.attach_threads(threads);
    }

    /// [`verify_maker_pre_swap_balances`]: asserts each maker's post-bond
    /// balances and returns their spendable balances, in maker order.
    pub fn verify_maker_pre_swap_balances(&self) -> Vec<Amount> {
        verify_maker_pre_swap_balances(&self.servers())
    }

    /// [`sync_maker_wallets`] on every maker.
    pub fn sync_makers(&self) {
        sync_maker_wallets(&self.servers());
    }

    /// Syncs each maker in turn and asserts its contract balance is zero: it
    /// recovered every contract it held.
    #[track_caller]
    pub fn assert_makers_contract_zero(&self) {
        for (i, maker) in self.makers.iter().enumerate() {
            maker.sync();
            let balances = maker.balances();
            log::info!(
                "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
                i,
                balances.regular,
                balances.swap,
                balances.contract,
                balances.spendable,
            );
            assert_eq!(
                balances.contract,
                Amount::ZERO,
                "Maker {} should have no contract balance after recovery",
                i
            );
        }
    }

    /// Mines `n` blocks.
    pub fn mine(&self, n: u64) {
        generate_blocks(self.bitcoind(), n);
    }

    /// [`spawn_tracker_logger`] over the first taker's data dir, `taker1`.
    pub fn spawn_tracker_logger(&self, interval: Duration) -> TrackerLoggerHandle {
        spawn_tracker_logger(self.temp_dir().join("taker1"), interval)
    }

    /// [`shutdown_makers`] on every started maker: signal all, then join all,
    /// propagating a maker thread's panic. For tests that stop the makers
    /// before the end; [`World::finish`] then skips them.
    pub fn shutdown_makers(&mut self) {
        let (servers, threads): (Vec<_>, Vec<_>) = self
            .makers
            .iter_mut()
            .filter_map(|maker| Some((maker.server.clone(), maker.thread.take()?)))
            .unzip();
        shutdown_makers(&servers, threads);
    }

    /// Joins every started maker's thread without signalling shutdown, for a
    /// maker expected to exit on its own; propagates a maker thread's panic.
    pub fn join_makers(&mut self) {
        for maker in &mut self.makers {
            if let Some(thread) = maker.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    /// Drops every taker now, e.g. before restarting the makers or the taker
    /// itself from its config.
    pub fn drop_takers(&mut self) {
        drop(mem::take(&mut self.takers));
    }

    /// Hands a taker the test built (e.g. restarted from its config) to the
    /// world, which then drops it at teardown like any other taker.
    pub fn adopt_taker(&mut self, taker: Taker) {
        self.takers.push(TakerHandle { taker });
    }

    /// Hands maker servers the test built (e.g. restarted from their configs)
    /// to the world, unstarted; the world then shuts them down at teardown
    /// like any other maker.
    pub fn adopt_makers(&mut self, servers: impl IntoIterator<Item = Arc<MakerServer>>) {
        self.makers
            .extend(servers.into_iter().map(|server| MakerHandle {
                server,
                thread: None,
            }));
    }

    /// Drops every maker, releasing its server, for a test that restarts a
    /// maker from its config. The makers must be shut down first.
    #[track_caller]
    pub fn drop_makers(&mut self) {
        assert!(
            self.makers.iter().all(|maker| maker.thread.is_none()),
            "drop_makers on a running maker"
        );
        self.makers.clear();
    }

    /// Tears the world down in the canonical order (see the module doc),
    /// propagating a maker or block-generation thread's panic.
    pub fn finish(mut self) {
        self.teardown(true);
    }

    fn servers(&self) -> Vec<Arc<MakerServer>> {
        self.makers
            .iter()
            .map(|maker| maker.server.clone())
            .collect()
    }

    fn attach_threads(&mut self, threads: Vec<JoinHandle<()>>) {
        for (maker, thread) in self.makers.iter_mut().zip(threads) {
            assert!(maker.thread.is_none(), "maker server started twice");
            maker.thread = Some(thread);
        }
    }

    /// With `propagate` false (unwinding from a failed test) no thread's panic
    /// is re-raised, since a second panic would abort the test binary.
    fn teardown(&mut self, propagate: bool) {
        if mem::replace(&mut self.torn_down, true) {
            return;
        }
        drop(mem::take(&mut self.takers));
        if propagate {
            self.shutdown_makers();
        } else {
            // `shutdown_makers` without its `join().unwrap()`.
            let started: Vec<_> = self
                .makers
                .iter_mut()
                .filter_map(|maker| Some((maker.server.clone(), maker.thread.take()?)))
                .collect();
            started
                .iter()
                .for_each(|(server, _)| server.shutdown.store(true, Relaxed));
            started.into_iter().for_each(|(_, thread)| {
                let _ = thread.join();
            });
        }
        self.framework.stop();
        if let Some(block_generation) = self.block_generation.take() {
            if propagate {
                block_generation.join().unwrap();
            } else {
                let _ = block_generation.join();
            }
        }
    }
}

impl Drop for World {
    /// Runs the [`World::finish`] teardown when the test did not, which is
    /// the panic path.
    fn drop(&mut self) {
        self.teardown(!thread::panicking());
    }
}

/// One maker: its server and, once started, the thread running it.
pub struct MakerHandle {
    server: Arc<MakerServer>,
    thread: Option<JoinHandle<()>>,
}

impl MakerHandle {
    /// The maker server itself, for what the handle does not wrap.
    pub fn inner(&self) -> &Arc<MakerServer> {
        &self.server
    }

    /// Syncs the maker's wallet against the backend and saves it.
    #[track_caller]
    pub fn sync(&self) {
        self.server
            .wallet
            .write()
            .expect("maker wallet lock poisoned")
            .sync_and_save(&NO_SHUTDOWN)
            .expect("maker wallet sync failed");
    }

    /// The maker wallet's balances as of its last sync.
    #[track_caller]
    pub fn balances(&self) -> Balances {
        self.server
            .wallet
            .read()
            .expect("maker wallet lock poisoned")
            .get_balances()
            .expect("maker balances unreadable")
    }

    /// `<data_dir>/wallets/<wallet_name>_swap_report.json`.
    pub fn report_path(&self) -> PathBuf {
        self.server.data_dir.join("wallets").join(format!(
            "{}_swap_report.json",
            self.server.config.wallet_name
        ))
    }
}

/// One taker.
pub struct TakerHandle {
    taker: Taker,
}

impl TakerHandle {
    /// The taker itself, for what the handle does not wrap.
    pub fn inner(&self) -> &Taker {
        &self.taker
    }

    /// Sets the taker's test behavior for its next swap.
    pub fn set_behavior(&mut self, behavior: TakerBehavior) {
        self.taker.behavior = behavior;
    }

    /// [`Taker::log_tracker_state`].
    pub fn log_tracker_state(&self) {
        self.taker.log_tracker_state();
    }

    /// Polls [`Taker::is_recovery_complete`] every 5s, panicking once
    /// `timeout` has passed without it.
    #[track_caller]
    pub fn await_recovery(&self, timeout: Duration) {
        let start = Instant::now();
        while !self.taker.is_recovery_complete() {
            if start.elapsed() > timeout {
                panic!("Background recovery did not complete within timeout");
            }
            thread::sleep(Duration::from_secs(5));
        }
    }

    /// Syncs the taker's wallet against the backend and saves it.
    #[track_caller]
    pub fn sync(&self) {
        self.taker
            .get_wallet()
            .write()
            .expect("taker wallet lock poisoned")
            .sync_and_save(&NO_SHUTDOWN)
            .expect("taker wallet sync failed");
    }

    /// The taker wallet's balances as of its last sync.
    #[track_caller]
    pub fn balances(&self) -> Balances {
        self.taker
            .get_wallet()
            .read()
            .expect("taker wallet lock poisoned")
            .get_balances()
            .expect("taker balances unreadable")
    }

    /// [`Taker::prepare_swap`].
    pub fn prepare(&mut self, params: SwapParams) -> Result<SwapSummary, TakerError> {
        self.taker.prepare_swap(params)
    }

    /// [`Taker::start_swap`].
    pub fn start(&mut self, swap_id: &str) -> Result<TakerReport, TakerError> {
        self.taker.start_swap(swap_id)
    }
}
