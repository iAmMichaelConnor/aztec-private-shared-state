//! GigaDoram: a three-party distributed oblivious RAM.
//!
//! [`GigaDoram`] is generic over the stored value type `V: DoramValue`, so the
//! same protocol serves `u32`/`u64`/`u128` and field `BigInt` values. Aliases
//! are exported for the common choices: [`GigaDoramU32`], [`GigaDoramU64`],
//! [`GigaDoramU128`], [`GigaDoramField`], and [`GigaDoramBn254`].
//!
//! A DORAM is built from a small writable [`SpeedCache`] in front of a stack of
//! oblivious hash table levels ([`OhTable`]); [`GigaDoram::read`] and
//! [`GigaDoram::write`] are the entry points, rebuilding levels as needed.

use std::time::{Duration, Instant};

pub mod state;

use circuits::{
    lowmc::{
        self, ROUND_KEYS,
        packed_u8_lanes::{
            CombinedRoundKeys, combine_round_keys,
            encrypt_many_inputs_with_combined_keys as encrypt_many,
        },
        packed_u8_lanes_with_speed_cache::encrypt_many_inputs_with_combined_keys as encrypt_many_with_cache,
    },
    oblivious_sort::ObliviousSort,
    replace_if_dummy::replace_if_dummy_circuit,
};
use data_structures::{OHTableParams, OhTable, OhTableQueryTiming, OhTableTiming, SpeedCache};
use eyre::{Result, ensure};
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID},
    rep3_ring::{arithmetic, binary, ring::bit::Bit},
};
use mpc_net::Network;
use primitives::{
    AlibiShare, ArrayShuffler, Block, Chunked, CommunicationTimer, DoramValue, Record,
    TimingBreakdown, X, XShare, alibi_from_blocks, alibi_to_blocks, dummy_x, network_phase,
    open_many, promote_public, upcast_x_to_block,
};

/// `GigaDoram` storing `u32` values.
pub type GigaDoramU32 = GigaDoram<u32>;
/// `GigaDoram` storing `u64` values.
pub type GigaDoramU64 = GigaDoram<u64>;
/// `GigaDoram` storing `u128` values.
pub type GigaDoramU128 = GigaDoram<u128>;
/// `GigaDoram` storing a prime field's `BigInt` values.
pub type GigaDoramField<F> = GigaDoram<primitives::FieldValue<F>>;
/// `GigaDoram` storing `ark_bn254::Fr` field values (the historical default).
pub type GigaDoramBn254 = GigaDoramField<primitives::YField>;

pub const EMPIRICAL_CHT_STASH_SIZE: usize = 8;
pub const PROVEN_CHT_STASH_SIZE: usize = 50;

/// Which cuckoo-hash-table analysis the stash size and column lengths are
/// based on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChtBounds {
    /// Empirically chosen stash size with column load factor 1.2.
    Empirical,
    /// Proven stash bound with column load factor 2.0.
    Proven,
}

impl ChtBounds {
    fn stash_size(self) -> usize {
        match self {
            Self::Empirical => EMPIRICAL_CHT_STASH_SIZE,
            Self::Proven => PROVEN_CHT_STASH_SIZE,
        }
    }

    fn column_load_factor(self) -> f64 {
        match self {
            Self::Empirical => 1.2,
            Self::Proven => 2.0,
        }
    }
}

/// The shape of a DORAM: its address space (a label space of
/// `log_address_space_size` bits, below which every real address lies and
/// above which the dummy labels do), the capacity of its bottom level
/// (`2^log_capacity` records: every address of a dense DORAM, whose bottom
/// level is built from them all, or as many distinct addresses as a sparse
/// one may ever hold, its bottom level built lazily from the addresses
/// written), and the hierarchy above it (the speed cache of
/// `2^log_speed_cache_size` entries, `num_levels` levels growing by
/// `2^log_amp_factor` each, the bottom one the capacity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GigaDoramConfig {
    pub log_address_space_size: usize,
    pub log_capacity: usize,
    pub num_levels: usize,
    pub log_speed_cache_size: usize,
    pub log_amp_factor: usize,
    pub stash_size: usize,
    pub cht_bounds: ChtBounds,
}

impl GigaDoramConfig {
    /// A dense DORAM: the capacity is the whole address space.
    pub fn new(log_address_space_size: usize, num_levels: usize, log_amp_factor: usize) -> Self {
        Self::with_cht_bounds(
            log_address_space_size,
            num_levels,
            log_amp_factor,
            ChtBounds::Empirical,
        )
    }

    /// A sparse DORAM: `2^log_address_space_size` addresses (up to 126
    /// bits), of which at most `2^log_capacity` are ever written; an address
    /// never written reads as the zero value. Built with [`GigaDoram::new`]
    /// (no initial bottom level).
    pub fn sparse(
        log_address_space_size: usize,
        log_capacity: usize,
        num_levels: usize,
        log_amp_factor: usize,
    ) -> Self {
        Self::with_capacity(
            log_address_space_size,
            log_capacity,
            num_levels,
            log_amp_factor,
            ChtBounds::Empirical.stash_size(),
            ChtBounds::Empirical,
        )
    }

    pub fn with_proven_cht_bounds(
        log_address_space_size: usize,
        num_levels: usize,
        log_amp_factor: usize,
    ) -> Self {
        Self::with_cht_bounds(
            log_address_space_size,
            num_levels,
            log_amp_factor,
            ChtBounds::Proven,
        )
    }

    pub fn with_cht_bounds(
        log_address_space_size: usize,
        num_levels: usize,
        log_amp_factor: usize,
        cht_bounds: ChtBounds,
    ) -> Self {
        Self::with_stash_size(
            log_address_space_size,
            num_levels,
            log_amp_factor,
            cht_bounds.stash_size(),
            cht_bounds,
        )
    }

    pub fn with_stash_size(
        log_address_space_size: usize,
        num_levels: usize,
        log_amp_factor: usize,
        stash_size: usize,
        cht_bounds: ChtBounds,
    ) -> Self {
        Self::with_capacity(
            log_address_space_size,
            log_address_space_size,
            num_levels,
            log_amp_factor,
            stash_size,
            cht_bounds,
        )
    }

    /// The general constructor: the address space, the bottom level's
    /// capacity (equal to the address space for a dense DORAM) and the
    /// hierarchy above it. Panics on a shape [`Self::try_with_capacity`]
    /// refuses.
    pub fn with_capacity(
        log_address_space_size: usize,
        log_capacity: usize,
        num_levels: usize,
        log_amp_factor: usize,
        stash_size: usize,
        cht_bounds: ChtBounds,
    ) -> Self {
        Self::try_with_capacity(
            log_address_space_size,
            log_capacity,
            num_levels,
            log_amp_factor,
            stash_size,
            cht_bounds,
        )
        .unwrap_or_else(|e| panic!("{e}"))
    }

    /// [`Self::with_capacity`], or why the shape is not one a DORAM can
    /// have ([`Self::check`]).
    pub fn try_with_capacity(
        log_address_space_size: usize,
        log_capacity: usize,
        num_levels: usize,
        log_amp_factor: usize,
        stash_size: usize,
        cht_bounds: ChtBounds,
    ) -> Result<Self> {
        ensure!(num_levels > 0, "DORAM must have at least one OHTable level");
        let log_speed_cache_size = (num_levels - 1)
            .checked_mul(log_amp_factor)
            .and_then(|x| log_capacity.checked_sub(x))
            .ok_or_else(|| {
                eyre::eyre!("capacity log is too small for num_levels and amplification")
            })?;

        let config = Self {
            log_address_space_size,
            log_capacity,
            num_levels,
            log_speed_cache_size,
            log_amp_factor,
            stash_size,
            cht_bounds,
        };
        config.check()?;
        Ok(config)
    }

    /// Whether the bottom level holds every address (built at creation)
    /// rather than the addresses written.
    pub fn is_dense(&self) -> bool {
        self.log_capacity == self.log_address_space_size
    }

    pub fn speed_cache_size(&self) -> usize {
        1usize << self.log_speed_cache_size
    }

    pub fn fill_time(&self) -> usize {
        self.speed_cache_size() - self.stash_size
    }

    pub fn amp_factor(&self) -> usize {
        1usize << self.log_amp_factor
    }

    /// Panics on a configuration [`Self::check`] refuses.
    pub fn validate(&self) {
        if let Err(e) = self.check() {
            panic!("{e}");
        }
    }

    /// Whether the configuration is one a DORAM can have: every bound the
    /// protocol relies on, the hierarchy invariant among them.
    pub fn check(&self) -> Result<()> {
        ensure!(
            self.num_levels > 0,
            "DORAM must have at least one OHTable level"
        );
        ensure!(
            self.log_address_space_size < X::BITS as usize - 1,
            "must reserve 2^N..2^(N+1)-1 as dummy labels inside x, below 2^127 (the sort's row)"
        );
        ensure!(
            self.log_capacity <= self.log_address_space_size,
            "the capacity cannot exceed the address space"
        );
        ensure!(
            self.log_capacity < 48,
            "a bottom level of 2^48 records or more does not fit memory"
        );
        ensure!(
            self.log_speed_cache_size < usize::BITS as usize,
            "speed-cache size shift is too large"
        );
        ensure!(
            self.log_amp_factor < usize::BITS as usize,
            "amplification factor shift is too large"
        );
        ensure!(
            self.stash_size < self.speed_cache_size(),
            "stash must fit inside the speed cache"
        );
        ensure!(
            self.num_levels <= u8::BITS as usize,
            "alibi bits must fit in YRecord's alibi byte"
        );
        ensure!(
            (self.num_levels - 1)
                .checked_mul(self.log_amp_factor)
                .and_then(|x| x.checked_add(self.log_speed_cache_size))
                == Some(self.log_capacity),
            "the capacity must match the bottom-level size the hierarchy gives"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct GigaDoram<V: DoramValue> {
    pub config: GigaDoramConfig,
    pub speed_cache: SpeedCache<V>,
    pub levels: Vec<Option<OhTable<V>>>,
    pub base_b_state_vec: Vec<usize>,
    packed_query_key: Option<CombinedRoundKeys>,
    packed_batch_query_keys: Option<(usize, Vec<CombinedRoundKeys>)>,
    had_initial_bottom_level: bool,
    /// A sparse DORAM's number of distinct addresses at its last bottom-level
    /// rebuild (opened there); none before the first rebuild or for a dense
    /// DORAM.
    fill_count: Option<usize>,
    /// Per level, the build that made its table (meaningful while the level
    /// is live): public and equal at the three parties, so a persisted
    /// level is rewritten only when a rebuild replaced it.
    stamps: Vec<u64>,
    /// The next build's stamp.
    next_stamp: u64,
}

#[derive(Clone, Debug, Default)]
pub struct GigaDoramTiming {
    pub time_total_builds: Vec<Duration>,
    pub time_total_build_prf: TimingBreakdown,
    pub time_total_batcher: Duration,
    pub time_total_queries: TimingBreakdown,
    pub time_total_query_prf: TimingBreakdown,
    pub time_total_query_speed_cache: TimingBreakdown,
    pub time_total_query_ohtable: Duration,
    pub time_total_query_ohtable_details: OhTableQueryTiming,
    pub time_total_query_writeback: Duration,
    pub communication_timer: CommunicationTimer,
}

impl GigaDoramTiming {
    pub fn with_communication_timer(communication_timer: CommunicationTimer) -> Self {
        Self {
            communication_timer,
            ..Self::default()
        }
    }

    fn record_build(&mut self, level: usize, elapsed: Duration) {
        if self.time_total_builds.len() <= level {
            self.time_total_builds.resize(level + 1, Duration::ZERO);
        }
        self.time_total_builds[level] += elapsed;
    }
}

impl<V: DoramValue> GigaDoram<V> {
    /// A DORAM from its persisted parts (`state`): the query-key caches are
    /// rebuilt lazily.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        config: GigaDoramConfig,
        speed_cache: SpeedCache<V>,
        levels: Vec<Option<OhTable<V>>>,
        base_b_state_vec: Vec<usize>,
        had_initial_bottom_level: bool,
        fill_count: Option<usize>,
        stamps: Vec<u64>,
        next_stamp: u64,
    ) -> Self {
        config.validate();
        assert_eq!(levels.len(), config.num_levels);
        assert_eq!(base_b_state_vec.len(), config.num_levels);
        assert_eq!(stamps.len(), config.num_levels);
        Self {
            config,
            speed_cache,
            levels,
            base_b_state_vec,
            packed_query_key: None,
            packed_batch_query_keys: None,
            had_initial_bottom_level,
            fill_count,
            stamps,
            next_stamp,
        }
    }

    /// The stamp of `level`'s table, if the level is live: equal at the
    /// three parties, and new at every build of the level.
    pub fn level_stamp(&self, level: usize) -> Option<u64> {
        self.levels[level].as_ref().map(|_| self.stamps[level])
    }

    /// The next build's stamp.
    pub fn next_stamp(&self) -> u64 {
        self.next_stamp
    }

    /// Whether the bottom level was built from every address at creation.
    pub fn had_initial_bottom_level(&self) -> bool {
        self.had_initial_bottom_level
    }

    /// A sparse DORAM's number of distinct addresses written, as opened at its
    /// last bottom-level rebuild (none before the first; the addresses written
    /// since are not counted). Public at every party.
    pub fn fill_count(&self) -> Option<usize> {
        self.fill_count
    }

    /// The bottom level's capacity in records.
    pub fn capacity(&self) -> usize {
        self.bottom_num_elements()
    }

    pub fn new(config: GigaDoramConfig, id: PartyID) -> Self {
        config.validate();

        let mut speed_cache =
            SpeedCache::new(config.speed_cache_size(), config.log_address_space_size, id);
        speed_cache.skip(config.stash_size);

        Self {
            config,
            speed_cache,
            levels: vec![None; config.num_levels],
            base_b_state_vec: vec![0; config.num_levels],
            packed_query_key: None,
            packed_batch_query_keys: None,
            had_initial_bottom_level: false,
            fill_count: None,
            stamps: vec![0; config.num_levels],
            next_stamp: 0,
        }
    }

    pub fn new_with_initial_bottom_level<N: Network>(
        config: GigaDoramConfig,
        ys: Vec<V::Share>,
        net: &N,
        state: &mut Rep3State,
        timing: Option<&mut GigaDoramTiming>,
    ) -> Result<Self> {
        // every message in frames below the transport's frame limit
        let net = &Chunked::new(net);
        config.validate();
        ensure!(
            config.is_dense(),
            "an initial bottom level needs a dense configuration (the capacity is the address space)"
        );

        let bottom_num_elements = 1usize << config.log_address_space_size;
        ensure!(
            ys.len() == bottom_num_elements,
            "initial bottom level must contain exactly every address in [0, 2^N)"
        );

        let mut doram = Self {
            config,
            speed_cache: SpeedCache::new(
                config.speed_cache_size(),
                config.log_address_space_size,
                state.id,
            ),
            levels: vec![None; config.num_levels],
            base_b_state_vec: vec![0; config.num_levels],
            packed_query_key: None,
            packed_batch_query_keys: None,
            had_initial_bottom_level: true,
            fill_count: None,
            stamps: vec![0; config.num_levels],
            next_stamp: 0,
        };

        let bottom_level = doram.config.num_levels - 1;
        let xs = (0..bottom_num_elements)
            .map(|x| promote_public(state.id, x as X))
            .collect::<Vec<_>>();
        let ys = ys
            .into_iter()
            .map(Record::<V>::from_value)
            .collect::<Vec<_>>();

        doram.new_ohtable_of_level(bottom_level, xs, ys, net, state, timing);
        doram.insert_stash(bottom_level, state.id);

        Ok(doram)
    }

    /// WARN: This leaks that the access is a read
    pub fn read<N: Network>(
        &mut self,
        query_x: XShare,
        net: &N,
        state: &mut Rep3State,
        timing: Option<&mut GigaDoramTiming>,
    ) -> Result<V::Share> {
        self.read_and_maybe_write(query_x, None, net, state, timing)
    }

    /// WARN: This leaks that the access is a write
    pub fn write<N: Network>(
        &mut self,
        query_x: XShare,
        query_y: V::Share,
        net: &N,
        state: &mut Rep3State,
        timing: Option<&mut GigaDoramTiming>,
    ) -> Result<V::Share> {
        self.read_and_maybe_write(query_x, Some(query_y), net, state, timing)
    }

    pub fn batch_read<N: Network>(
        &mut self,
        xs: &[XShare],
        net: &N,
        state: &mut Rep3State,
        timing: Option<&mut GigaDoramTiming>,
    ) -> Result<Vec<V::Share>> {
        let ops = xs.iter().map(|&x| (x, None)).collect::<Vec<_>>();
        self.batch_access(&ops, net, state, timing)
    }

    pub fn batch_write<N: Network>(
        &mut self,
        writes: &[(XShare, V::Share)],
        net: &N,
        state: &mut Rep3State,
        timing: Option<&mut GigaDoramTiming>,
    ) -> Result<Vec<V::Share>> {
        let ops = writes
            .iter()
            .map(|&(x, y)| (x, Some(y)))
            .collect::<Vec<_>>();
        self.batch_access(&ops, net, state, timing)
    }

    pub fn batch_access<N: Network>(
        &mut self,
        ops: &[(XShare, Option<V::Share>)],
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<Vec<V::Share>> {
        // every message in frames below the transport's frame limit
        let net = &Chunked::new(net);
        ensure!(
            !ops.is_empty(),
            "batch access requires at least one operation"
        );
        // Split the batch at speed cache capacity so a rebuild only ever runs
        // on an exactly full cache
        let mut outputs = Vec::with_capacity(ops.len());
        let mut remaining = ops;
        while !remaining.is_empty() {
            let free = self.speed_cache.length - self.speed_cache.num_stored;
            if free == 0 {
                self.rebuild(net, state, timing.as_deref_mut())?;
                continue;
            }
            let (chunk, rest) = remaining.split_at(remaining.len().min(free));
            outputs.extend(self.batch_access_chunk(chunk, net, state, timing.as_deref_mut())?);
            remaining = rest;
        }
        Ok(outputs)
    }

    fn batch_access_chunk<N: Network>(
        &mut self,
        ops: &[(XShare, Option<V::Share>)],
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<Vec<V::Share>> {
        let count = ops.len();
        let query_start = Instant::now();
        let query_communication = Self::timer(&timing).elapsed();
        let queries = ops.iter().map(|op| op.0).collect::<Vec<_>>();
        let live_levels = self
            .levels
            .iter()
            .enumerate()
            .filter_map(|(level, table)| table.as_ref().map(|_| level))
            .collect::<Vec<_>>();
        let keys_cached = matches!(&self.packed_batch_query_keys, Some((k, _)) if *k == count);
        if !keys_cached {
            let keys = (0..count)
                .flat_map(|_| live_levels.iter().copied())
                .map(|level| &self.levels[level].as_ref().unwrap().packed_key)
                .collect::<Vec<_>>();
            self.packed_batch_query_keys =
                Some((count, keys.chunks(8).map(combine_round_keys).collect()));
        }
        let keys = &self.packed_batch_query_keys.as_ref().unwrap().1;
        let inputs = queries
            .iter()
            .copied()
            .map(upcast_x_to_block)
            .collect::<Vec<_>>();
        let (qs, precomputed) = network_phase!(timing, time_total_query_prf, {
            let mut data = queries
                .iter()
                .map(|&query| self.speed_cache.precompute_query(query))
                .collect::<Option<Vec<_>>>();
            let qs = match data.as_deref_mut() {
                Some(data) => encrypt_many_with_cache(
                    keys,
                    live_levels.len(),
                    &inputs,
                    Some(data),
                    net,
                    state,
                )?,
                None => encrypt_many(keys, live_levels.len(), &inputs, net, state)?,
            };
            let results = data.and_then(|mut data| {
                data.iter_mut()
                    .map(|query| query.take_result())
                    .collect::<Option<Vec<_>>>()
            });
            (qs, results)
        });
        let results = network_phase!(timing, time_total_query_speed_cache, {
            self.speed_cache
                .query_many(&queries, precomputed, net, state)?
        });
        let mut y_accum = results.iter().map(|result| result.0).collect::<Vec<_>>();
        let mut found = results.iter().map(|result| result.1).collect::<Vec<_>>();
        let mut alibi = y_accum
            .iter()
            .map(|value| value.get_alibi_bits(self.config.num_levels))
            .collect::<Vec<_>>();

        for (position, &level) in live_levels.iter().enumerate() {
            let start = Instant::now();
            let use_dummies = (0..count)
                .map(|query| binary::xor(&alibi[query][level], &found[query]))
                .collect::<Vec<_>>();
            let table = self.levels[level].as_mut().unwrap();
            let mut table_timing =
                OhTableQueryTiming::with_communication_timer(Self::timer(&timing));
            let collect_timing = timing.is_some().then_some(&mut table_timing);
            let level_qs = qs.iter().map(|tags| tags[position]).collect::<Vec<_>>();
            let results = table.query_many(&level_qs, &use_dummies, net, state, collect_timing)?;
            for (query, (value, is_found)) in results.into_iter().enumerate() {
                y_accum[query] ^= value;
                found[query] ^= is_found;
                alibi[query] = y_accum[query].get_alibi_bits(self.config.num_levels);
            }
            if let Some(timing) = &mut timing {
                timing.time_total_query_ohtable += start.elapsed();
                timing
                    .time_total_query_ohtable_details
                    .add_assign(&table_timing);
            }
        }

        let writeback = Instant::now();
        let outputs = y_accum
            .iter()
            .map(|record| record.value)
            .collect::<Vec<_>>();
        let values = ops
            .iter()
            .zip(&outputs)
            .map(|(op, &output)| Record::<V>::from_value(op.1.unwrap_or(output)))
            .collect::<Vec<_>>();
        self.speed_cache.write(queries, values);
        if let Some(timing) = &mut timing {
            timing.time_total_query_writeback += writeback.elapsed();
            timing.time_total_queries.total += query_start.elapsed();
            timing.time_total_queries.communication += timing
                .communication_timer
                .elapsed()
                .saturating_sub(query_communication);
        }
        Ok(outputs)
    }

    pub fn num_levels(&self) -> usize {
        self.config.num_levels
    }

    pub fn speed_cache_len(&self) -> usize {
        self.speed_cache.num_stored
    }

    /// Whether [`Self::grow_naturally`] can currently be called.
    pub fn ready_to_grow_naturally(&self) -> bool {
        !self.speed_cache.is_writeable() && self.rebuild_target().0 == self.config.num_levels - 1
    }

    /// Migrate all live data into `new_config`, whose address space must be
    /// exactly one bit larger than the current one, and adopt it.
    ///
    /// Existing entries keep their addresses and values,
    /// the freshly exposed addresses `[2^old_n, 2^new_n)` start at the default value.
    pub fn grow_naturally<Net: Network>(
        &mut self,
        new_config: GigaDoramConfig,
        net: &Net,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<()> {
        // every message in frames below the transport's frame limit
        let net = &Chunked::new(net);
        let old_log_n = self.config.log_address_space_size;
        self.check_grow(&new_config)?;
        ensure!(
            self.ready_to_grow_naturally(),
            "grow is only valid at a full-collapse boundary (see `ready_to_grow_naturally`)"
        );

        let (rebuild_to, need_to_extract_from_rebuild_to) = self.rebuild_target();
        debug_assert_eq!(rebuild_to, self.config.num_levels - 1);

        let (mut xs, mut ys) = self.speed_cache.extract();
        let last_level_to_extract = rebuild_to + usize::from(need_to_extract_from_rebuild_to);
        for level in 0..last_level_to_extract {
            let Some(table) = self.levels[level].as_ref() else {
                continue;
            };
            let mut level_xs = Vec::new();
            let mut level_ys = Vec::new();
            table.extract(&mut level_xs, &mut level_ys);
            let offset = xs.len();
            let end = offset + self.num_elements_at(level, self.base_b_state_vec[level]);
            xs.resize(end, dummy_x(state.id, old_log_n));
            ys.resize(end, Record::<V>::default());
            xs[offset..offset + level_xs.len()].clone_from_slice(&level_xs);
            ys[offset..offset + level_ys.len()].clone_from_slice(&level_ys);
        }

        ensure!(!xs.is_empty(), "grow needs at least one extracted item");
        for y in &mut ys {
            *y = y.clear_alibi();
        }

        let (xs, ys) = self.finalize_bottom_level(xs, ys, net, state, timing.as_deref_mut())?;
        self.finish_grow(new_config, xs, ys, net, state, timing)
    }

    /// Grow immediately, without waiting for a full-collapse boundary.
    ///
    /// Collapses the speed cache and every level's untouched slots into the
    /// bottom level, regardless of how full the hierarchy is. Levels
    /// whose dummy budget is not spent carry their unconsumed
    /// dummies (they are indistinguishable from real entries
    /// until the oblivious bottom cleanse processes them).
    pub fn grow_on_demand<Net: Network>(
        &mut self,
        new_config: GigaDoramConfig,
        net: &Net,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<()> {
        // every message in frames below the transport's frame limit
        let net = &Chunked::new(net);
        self.check_grow(&new_config)?;

        let (mut xs, mut ys) = self.speed_cache.extract_stored();
        for level in 0..self.config.num_levels {
            let Some(table) = self.levels[level].as_ref() else {
                continue;
            };
            let mut level_xs = Vec::new();
            let mut level_ys = Vec::new();
            table.extract_untouched(&mut level_xs, &mut level_ys);
            xs.extend_from_slice(&level_xs);
            ys.extend_from_slice(&level_ys);
        }

        ensure!(!xs.is_empty(), "grow needs at least one extracted item");
        for y in &mut ys {
            *y = y.clear_alibi();
        }

        let (xs, ys) = self.finalize_bottom_level(xs, ys, net, state, timing.as_deref_mut())?;
        self.finish_grow(new_config, xs, ys, net, state, timing)
    }

    /// The new configuration of a grow: one more bit of capacity, and for a
    /// dense DORAM one more bit of address space with it (a sparse one keeps
    /// its address space).
    fn check_grow(&self, new_config: &GigaDoramConfig) -> Result<()> {
        new_config.validate();
        ensure!(
            new_config.log_capacity == self.config.log_capacity + 1,
            "grow must increase the capacity by exactly one bit"
        );
        if self.had_initial_bottom_level {
            ensure!(
                new_config.is_dense()
                    && new_config.log_address_space_size == self.config.log_address_space_size + 1,
                "a dense DORAM grows its address space with its capacity"
            );
        } else {
            ensure!(
                new_config.log_address_space_size >= self.config.log_address_space_size,
                "grow cannot shrink the address space"
            );
        }
        Ok(())
    }

    /// Pad the cleansed data to the new capacity and set the new config.
    fn finish_grow<Net: Network>(
        &mut self,
        new_config: GigaDoramConfig,
        mut xs: Vec<XShare>,
        mut ys: Vec<Record<V>>,
        net: &Net,
        state: &mut Rep3State,
        timing: Option<&mut GigaDoramTiming>,
    ) -> Result<()> {
        let old_log_n = self.config.log_address_space_size;
        let new_log_n = new_config.log_address_space_size;
        let new_bottom_elems = 1usize << new_config.log_capacity;
        ensure!(
            xs.len() <= new_bottom_elems,
            "widened bottom level cannot hold the collapsed data"
        );

        if self.had_initial_bottom_level {
            xs.reserve(new_bottom_elems - xs.len());
            ys.resize(new_bottom_elems, Record::<V>::default());
            for addr in ((1 as X) << old_log_n)..((1 as X) << new_log_n) {
                xs.push(promote_public(state.id, addr));
            }
        } else {
            xs.resize(new_bottom_elems, dummy_x(state.id, old_log_n));
            ys.resize(new_bottom_elems, Record::<V>::default());
            let replacements = (0..new_bottom_elems)
                .map(|i| promote_public(state.id, ((1 as X) << new_log_n) + i as X))
                .collect::<Vec<_>>();
            xs = replace_if_dummy_circuit(&xs, &replacements, old_log_n, net, state)?;
        }

        self.config = new_config;
        self.levels = vec![None; new_config.num_levels];
        self.base_b_state_vec = vec![0; new_config.num_levels];
        self.stamps = vec![0; new_config.num_levels];
        self.speed_cache = SpeedCache::new(new_config.speed_cache_size(), new_log_n, state.id);
        self.packed_query_key = None;
        self.packed_batch_query_keys = None;

        let bottom = self.config.num_levels - 1;
        self.new_ohtable_of_level(bottom, xs, ys, net, state, timing);
        self.insert_stash(bottom, state.id);

        Ok(())
    }

    fn read_and_maybe_write<N: Network>(
        &mut self,
        query_x: XShare,
        write_y: Option<V::Share>,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<V::Share> {
        // every message in frames below the transport's frame limit
        let net = &Chunked::new(net);
        // If we need to rebuild before we can query
        if !self.speed_cache.is_writeable() {
            self.rebuild(net, state, timing.as_deref_mut())?;
        }

        let query_start = Instant::now();
        let query_communication = timing
            .as_ref()
            .map(|timing| timing.communication_timer.elapsed())
            .unwrap_or_default();

        // Compute PRFs for each live level
        let live_levels = self
            .levels
            .iter()
            .enumerate()
            .filter_map(|(level, table)| table.as_ref().map(|_| level))
            .collect::<Vec<_>>();
        if self.packed_query_key.is_none() {
            let keys = live_levels
                .iter()
                .map(|&level| &self.levels[level].as_ref().unwrap().packed_key)
                .collect::<Vec<_>>();
            self.packed_query_key = Some(combine_round_keys(&keys));
        }
        let mut speed_cache_precompute_data = self.speed_cache.precompute_query(query_x);
        let qs = network_phase!(timing, time_total_query_prf, {
            lowmc::packed_u8_lanes_with_speed_cache::encrypt_with_combined_round_keys(
                self.packed_query_key.as_ref().unwrap(),
                live_levels.len(),
                upcast_x_to_block(query_x),
                speed_cache_precompute_data.as_mut(),
                net,
                state,
            )?
        });

        // Query the SpeedCache and extract alibi bits
        let (mut y_accum, mut found) = network_phase!(timing, time_total_query_speed_cache, {
            self.speed_cache
                .query(query_x, speed_cache_precompute_data, net, state)?
        });
        let mut alibi_mask = y_accum.get_alibi_bits(self.config.num_levels);

        // Traverse each live level and query the corresponding table
        for (&level, &q) in live_levels.iter().zip(&qs) {
            let start = Instant::now();
            let use_dummy = binary::xor(&alibi_mask[level], &found);
            let table = self.levels[level]
                .as_mut()
                .expect("live level should still exist during query");
            let mut ohtable_timing =
                OhTableQueryTiming::with_communication_timer(Self::timer(&timing));
            let table_timing = timing.is_some().then_some(&mut ohtable_timing);
            let (y_returned, found_returned) =
                table.query(q, use_dummy, net, state, table_timing)?;

            y_accum ^= y_returned;
            found ^= found_returned;
            alibi_mask = y_accum.get_alibi_bits(self.config.num_levels);
            if let Some(timing) = &mut timing {
                timing.time_total_query_ohtable += start.elapsed();
                timing
                    .time_total_query_ohtable_details
                    .add_assign(&ohtable_timing);
            }
        }

        // Write the new value on writes, or refresh the old value on reads.
        // Either way the speed-cache entry starts with a fresh (zero) alibi byte.
        let start = Instant::now();
        let value_to_write = Record::<V>::from_value(write_y.unwrap_or(y_accum.value));
        self.speed_cache.write(vec![query_x], vec![value_to_write]);
        if let Some(timing) = &mut timing {
            timing.time_total_query_writeback += start.elapsed();
            timing.time_total_queries.total += query_start.elapsed();
            timing.time_total_queries.communication += timing
                .communication_timer
                .elapsed()
                .saturating_sub(query_communication);
        }

        // Return the full-field value (alibi bits live separately now).
        Ok(y_accum.value)
    }

    fn rebuild<N: Network>(
        &mut self,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<()> {
        // Check up to which level we need to rebuild and whether the range is inclusive
        let (rebuild_to, need_to_extract_from_rebuild_to) = self.rebuild_target();

        // Extract from the SpeedCache and reset it
        let (mut extracted_xs, mut extracted_ys) = self.speed_cache.extract();
        self.speed_cache = SpeedCache::new(
            self.config.speed_cache_size(),
            self.config.log_address_space_size,
            state.id,
        );

        let last_level_to_extract = rebuild_to + usize::from(need_to_extract_from_rebuild_to);
        for level in 0..last_level_to_extract {
            let Some(table) = self.levels[level].as_ref() else {
                continue;
            };

            let mut xs = Vec::new();
            let mut ys = Vec::new();
            table.extract(&mut xs, &mut ys);
            let offset = extracted_xs.len();
            let end = offset + self.num_elements_at(level, self.base_b_state_vec[level]);
            // Pad missing entries with the dummy sentinel
            extracted_xs.resize(end, dummy_x(state.id, self.config.log_address_space_size));
            extracted_ys.resize(end, Record::<V>::default());
            extracted_xs[offset..offset + xs.len()].clone_from_slice(&xs);
            extracted_ys[offset..offset + ys.len()].clone_from_slice(&ys);
        }

        ensure!(
            !extracted_xs.is_empty(),
            "rebuild needs at least one extracted item"
        );
        ensure!(
            extracted_xs.len() == extracted_ys.len(),
            "rebuild extracted mismatched x/y lengths"
        );

        for y in &mut extracted_ys {
            *y = y.clear_alibi();
        }

        if rebuild_to == self.config.num_levels - 1 {
            (extracted_xs, extracted_ys) = self.finalize_bottom_level(
                extracted_xs,
                extracted_ys,
                net,
                state,
                timing.as_deref_mut(),
            )?;
        } else {
            let target_num_elements =
                self.num_elements_at(rebuild_to, self.base_b_state_vec[rebuild_to] + 1);
            assert_eq!(extracted_xs.len(), target_num_elements);
            self.relabel_dummies(&mut extracted_xs, net, state)?;
        }

        for level in 0..rebuild_to {
            self.delete_level(level);
        }
        if need_to_extract_from_rebuild_to {
            self.delete_level(rebuild_to);
        }

        self.new_ohtable_of_level(rebuild_to, extracted_xs, extracted_ys, net, state, timing);
        self.insert_stash(rebuild_to, state.id);

        Ok(())
    }

    fn rebuild_target(&self) -> (usize, bool) {
        let amp_factor = self.config.amp_factor();
        let mut rebuild_to = 0;
        let mut need_to_extract_from_rebuild_to = false;

        while rebuild_to < self.config.num_levels - 1 {
            if self.base_b_state_vec[rebuild_to] < amp_factor - 1 {
                need_to_extract_from_rebuild_to = self.levels[rebuild_to].is_some();
                break;
            }

            rebuild_to += 1;
        }

        if rebuild_to == self.config.num_levels - 1 {
            need_to_extract_from_rebuild_to = self.base_b_state_vec[rebuild_to] != 0;
        }

        (rebuild_to, need_to_extract_from_rebuild_to)
    }

    fn new_ohtable_of_level<N: Network>(
        &mut self,
        level: usize,
        xs: Vec<XShare>,
        ys: Vec<Record<V>>,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) {
        assert!(level < self.config.num_levels);
        assert_eq!(xs.len(), ys.len());
        assert!(xs.len() >= self.config.stash_size);

        if level == self.config.num_levels - 1 {
            self.base_b_state_vec[level] = 1;
        } else {
            self.base_b_state_vec[level] += 1;
            assert!(self.base_b_state_vec[level] < self.config.amp_factor());
        }

        let base_b_num = if level == self.config.num_levels - 1 {
            1
        } else {
            self.base_b_state_vec[level]
        };
        let d = self.config.cht_bounds.column_load_factor();
        let log_single_col_len = level * self.config.log_amp_factor
            + self.config.log_speed_cache_size
            + ((d * base_b_num as f64) as usize).ilog2() as usize
            + 1;

        let params = OHTableParams::new(
            xs.len(),
            self.num_dummies(level),
            self.config.stash_size,
            log_single_col_len as u32,
            self.config.log_address_space_size,
        );
        let key = (0..ROUND_KEYS)
            .map(|_| arithmetic::rand::<Block>(state))
            .collect();
        let start = Instant::now();
        let mut ohtable_timing = OhTableTiming::with_communication_timer(Self::timer(&timing));
        let table_timing = timing.is_some().then_some(&mut ohtable_timing);
        let table = OhTable::new(params, xs, ys, key, net, state, table_timing);
        if let Some(timing) = &mut timing {
            timing.time_total_build_prf.total += ohtable_timing.build_prf.total;
            timing.time_total_build_prf.communication += ohtable_timing.build_prf.communication;
            timing.record_build(level, start.elapsed());
        }
        self.levels[level] = Some(table);
        self.stamps[level] = self.next_stamp;
        self.next_stamp += 1;
        self.packed_query_key = None;
        self.packed_batch_query_keys = None;
    }

    fn delete_level(&mut self, level: usize) {
        self.levels[level] = None;
        self.packed_query_key = None;
        self.packed_batch_query_keys = None;
        if level < self.config.num_levels - 1
            && self.base_b_state_vec[level] == self.config.amp_factor() - 1
        {
            self.base_b_state_vec[level] = 0;
        }
    }

    fn insert_stash(&mut self, level: usize, party_id: PartyID) {
        let (stash_xs, stash_ys) = {
            let table = self.levels[level]
                .as_ref()
                .expect("newly rebuilt level should exist");
            let stash_ys = table
                .stash_ys
                .iter()
                .map(|y| y.set_alibi_bit(level, party_id))
                .collect::<Vec<_>>();
            (table.stash_xs.clone(), stash_ys)
        };

        self.speed_cache.write(stash_xs, stash_ys);
    }

    fn num_dummies(&self, level: usize) -> usize {
        self.config
            .amp_factor()
            .pow(level as u32)
            .checked_mul(self.config.fill_time())
            .expect("number of dummies should fit usize")
    }

    fn num_elements_at(&self, level: usize, state: usize) -> usize {
        if level == self.config.num_levels - 1 {
            self.bottom_num_elements()
        } else {
            state << (level * self.config.log_amp_factor + self.config.log_speed_cache_size)
        }
    }

    fn bottom_num_elements(&self) -> usize {
        1usize << self.config.log_capacity
    }

    fn dummy_label(&self, offset: usize) -> X {
        ((1 as X) << self.config.log_address_space_size) + offset as X
    }

    fn relabel_dummies<N: Network>(
        &self,
        xs: &mut [XShare],
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        let replacements = xs
            .iter()
            .enumerate()
            .map(|(i, _)| promote_public(state.id, self.dummy_label(i)))
            .collect::<Vec<_>>();
        let relabeled = replace_if_dummy_circuit(
            xs,
            &replacements,
            self.config.log_address_space_size,
            net,
            state,
        )?;
        xs.clone_from_slice(&relabeled);

        Ok(())
    }

    fn finalize_bottom_level<N: Network>(
        &mut self,
        mut xs: Vec<XShare>,
        mut ys: Vec<Record<V>>,
        net: &N,
        state: &mut Rep3State,
        timing: Option<&mut GigaDoramTiming>,
    ) -> Result<(Vec<XShare>, Vec<Record<V>>)> {
        if self.had_initial_bottom_level {
            let shuffler = ArrayShuffler::new(xs.len(), state);
            let values = Record::<V>::get_y_values(&ys);
            let alibis = Record::<V>::get_alibis(&ys);
            let mut value_blocks = V::to_blocks(&values);
            let mut y_alibi = alibi_to_blocks(&alibis);
            shuffler.forward(&mut xs, net, state)?;
            for col in &mut value_blocks {
                shuffler.forward(col, net, state)?;
            }
            shuffler.forward(&mut y_alibi, net, state)?;
            ys =
                Record::<V>::from_columns(V::from_blocks(value_blocks), alibi_from_blocks(y_alibi));
        }
        self.cleanse_bottom_level(xs, ys, net, state, timing)
    }

    fn cleanse_bottom_level<N: Network>(
        &mut self,
        mut xs: Vec<XShare>,
        mut ys: Vec<Record<V>>,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<(Vec<XShare>, Vec<Record<V>>)> {
        ensure!(
            xs.len() == ys.len(),
            "bottom cleanse received mismatched x/y lengths"
        );
        let bottom_num_elements = self.bottom_num_elements();

        let mut dummy_flags = xs
            .iter()
            .map(|x| x.get_bit(self.config.log_address_space_size))
            .collect::<Vec<_>>();

        if self.had_initial_bottom_level {
            ensure!(
                xs.len() >= bottom_num_elements,
                "initial bottom cleanse needs enough extracted entries for the bottom level"
            );

            let dummy_flags = open_many(&dummy_flags, net);
            let mut cleansed_xs = Vec::with_capacity(bottom_num_elements);
            let mut cleansed_ys = Vec::with_capacity(bottom_num_elements);

            for ((x, y), is_dummy) in xs.into_iter().zip(ys).zip(dummy_flags) {
                if !is_dummy.convert() {
                    cleansed_xs.push(x);
                    cleansed_ys.push(y);
                }
            }

            ensure!(
                cleansed_xs.len() == bottom_num_elements,
                "initial bottom cleanse found wrong number of real entries"
            );

            return Ok((cleansed_xs, cleansed_ys));
        }

        let sort_len = xs.len().next_power_of_two();
        let mut values = Record::<V>::get_y_values(&ys);
        let mut alibis = Record::<V>::get_alibis(&ys);
        xs.resize(
            sort_len,
            dummy_x(state.id, self.config.log_address_space_size),
        );
        values.resize(sort_len, V::zero_share());
        alibis.resize(sort_len, AlibiShare::default());
        dummy_flags.resize(sort_len, promote_public(state.id, Bit::new(true)));
        let start = Instant::now();
        ObliviousSort::sort::<V, _>(
            &mut dummy_flags,
            &mut xs,
            &mut values,
            &mut alibis,
            net,
            state,
        )?;
        if let Some(timing) = &mut timing {
            timing.time_total_batcher += start.elapsed();
        }

        // The sort leaves the real records first. A sparse DORAM's capacity is
        // below its address space, so the records past it must all be dummies:
        // the sorted flags are opened (what they tell is the number of real
        // records, the DORAM's fill, which the owner reads from `fill_count`)
        // and a real record past the capacity is refused rather than truncated
        // away.
        if !self.config.is_dense() {
            let flags = open_many(&dummy_flags, net);
            let fill = flags.iter().filter(|dummy| !dummy.convert()).count();
            ensure!(
                fill <= bottom_num_elements,
                "the DORAM holds {fill} distinct addresses, over its capacity of 2^{}",
                self.config.log_capacity
            );
            self.fill_count = Some(fill);
        }

        xs.truncate(bottom_num_elements);
        values.truncate(bottom_num_elements);
        alibis.truncate(bottom_num_elements);
        ys = Record::<V>::from_columns(values, alibis);
        self.relabel_dummies(&mut xs, net, state)?;

        Ok((xs, ys))
    }

    fn timer(timing: &Option<&mut GigaDoramTiming>) -> CommunicationTimer {
        timing
            .as_ref()
            .map(|timing| timing.communication_timer.clone())
            .unwrap_or_default()
    }
}
