//! Persisting a `GigaDoram<FieldValue<F>>` level by level (added to the
//! vendored crate for the machine's oblivious tree brick; see
//! `PROVENANCE.md`).
//!
//! One party's state is a head and one part per live level. The head holds
//! the configuration, the level counters, each live level's stamp and query
//! bookkeeping (the query count, the touched slots, the last query's trace)
//! and the speed cache: it changes at every access. A level's part holds what
//! its build made (the parameters, the PRF key, the stash, the dummy
//! indices, the table in receiver order, the CHT, the receivers' shuffle):
//! it changes only when a rebuild replaces the level, which the level's
//! stamp names.
//!
//! Every part is [`Parts`]: public bytes, equal at the three parties; the
//! party's share components as two byte streams `a` and `b` of equal length
//! (party `j` holds components `x_j` and `x_{j-1}` of every Rep3 XOR share,
//! element after element in the same order and widths at the three
//! parties, so stream `a` of party `j` is stream `b` of party `j + 1`); and
//! the copies `copy_a` and `copy_b`, values two parties hold alike and the
//! third does not, placed by the same rule (a level's receiver shuffle,
//! known to the builder's two neighbours `B + 1` and `B + 2`, is
//! component `B + 1`: `B + 1`'s `copy_a` and `B + 2`'s `copy_b`; the
//! builder's copies are empty). Every share here is an XOR (binary)
//! sharing, so XORing the three parties' streams opens the values. The
//! encodings are plain little-endian: lengths as `u64` in the public bytes,
//! ring elements at their width, field integers as their `u64` limbs.
//!
//! Not persisted: the builder-order arrays a build works in (unread once the
//! table is built), the bit-sliced round keys (recomputed from the key, a
//! local linear map), the receiver shuffle's inverse (recomputed on first
//! use) and the CHT's two-party resharing (recomputed from its Rep3 shares,
//! locally).

use ark_ff::PrimeField;
use circuits::lowmc::{ROUND_KEYS, packed_u8_lanes};
use data_structures::{OHTableParams, OhTable, SpeedCache, ohtable::OhTableQueryTrace};
use eyre::{Result, bail, ensure};
use mpc_core::protocols::{
    rep3::id::PartyID,
    rep3_ring::{
        Rep3RingShare,
        ring::{int_ring::IntRing2k, ring_impl::RingElement},
    },
};
use primitives::{AlibiShare, Block, BlockShare, FieldValue, LocalPermutation, Record, X, XShare};

use crate::{ChtBounds, GigaDoram, GigaDoramConfig};

/// The format's version byte, first in every part's public bytes.
const VERSION: u8 = 2;

/// One persisted part of a party's state: public bytes, the share
/// components and the copies (module documentation).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Parts {
    pub public: Vec<u8>,
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub copy_a: Vec<u8>,
    pub copy_b: Vec<u8>,
}

impl Parts {
    /// The part's size in bytes.
    pub fn len(&self) -> usize {
        self.public.len() + self.a.len() + self.b.len() + self.copy_a.len() + self.copy_b.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn bool(&mut self, v: bool) {
        self.u8(u8::from(v));
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn usize(&mut self, v: usize) {
        self.u64(v as u64);
    }
    fn usizes(&mut self, v: &[usize]) {
        self.usize(v.len());
        for x in v {
            self.usize(*x);
        }
    }
}

/// The share components of a part: component `a` of every share to one
/// stream, `b` to the other.
#[derive(Default)]
struct Shares {
    a: Vec<u8>,
    b: Vec<u8>,
}

fn put_ring<T: IntRing2k + Into<u128>>(out: &mut Vec<u8>, v: T) {
    let bytes = std::mem::size_of::<T>();
    out.extend_from_slice(&v.into().to_le_bytes()[..bytes]);
}

impl Shares {
    fn ring<T: IntRing2k + Into<u128>>(&mut self, share: &Rep3RingShare<T>) {
        put_ring(&mut self.a, share.a.0);
        put_ring(&mut self.b, share.b.0);
    }
    fn rings<T: IntRing2k + Into<u128>>(&mut self, shares: &[Rep3RingShare<T>]) {
        for s in shares {
            self.ring(s);
        }
    }
    fn bigint<F: PrimeField>(out: &mut Vec<u8>, v: &F::BigInt) {
        let limbs: &[u64] = v.as_ref();
        for l in limbs {
            out.extend_from_slice(&l.to_le_bytes());
        }
    }
    fn record<F: PrimeField>(&mut self, r: &Record<FieldValue<F>>) {
        Self::bigint::<F>(&mut self.a, &r.value.a);
        Self::bigint::<F>(&mut self.b, &r.value.b);
        self.ring(&r.alibi);
    }
    fn records<F: PrimeField>(&mut self, rs: &[Record<FieldValue<F>>]) {
        for r in rs {
            self.record::<F>(r);
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        ensure!(self.0.len() >= n, "DORAM state: truncated");
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            b => bail!("DORAM state: {b} is not a boolean"),
        }
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn usize(&mut self) -> Result<usize> {
        usize::try_from(self.u64()?).map_err(|_| eyre::eyre!("DORAM state: a length overflows"))
    }
    /// A length of items that take at least `unit` bytes of a stream of
    /// `left` bytes.
    fn len(&mut self, left: usize, unit: usize) -> Result<usize> {
        let n = self.usize()?;
        ensure!(
            n.checked_mul(unit.max(1)).is_some_and(|b| b <= left),
            "DORAM state: a length of {n} exceeds the stream"
        );
        Ok(n)
    }
    fn usizes(&mut self) -> Result<Vec<usize>> {
        let n = self.len(self.0.len(), 8)?;
        (0..n).map(|_| self.usize()).collect()
    }
    fn done(&self, what: &str) -> Result<()> {
        ensure!(
            self.0.is_empty(),
            "DORAM state: {} trailing bytes in the {what}",
            self.0.len()
        );
        Ok(())
    }
}

/// The share components of a part, read in step.
struct SharesReader<'a> {
    a: Reader<'a>,
    b: Reader<'a>,
}

fn take_ring<T: IntRing2k + TryFrom<u128>>(r: &mut Reader<'_>) -> Result<T> {
    let bytes = std::mem::size_of::<T>();
    let mut buf = [0u8; 16];
    buf[..bytes].copy_from_slice(r.take(bytes)?);
    T::try_from(u128::from_le_bytes(buf))
        .map_err(|_| eyre::eyre!("DORAM state: a ring element is too wide"))
}

impl<'a> SharesReader<'a> {
    fn new(parts: &'a Parts) -> Result<Self> {
        ensure!(
            parts.a.len() == parts.b.len(),
            "DORAM state: share streams of {} and {} bytes",
            parts.a.len(),
            parts.b.len()
        );
        Ok(SharesReader {
            a: Reader(&parts.a),
            b: Reader(&parts.b),
        })
    }
    fn left(&self) -> usize {
        self.a.0.len()
    }
    fn ring<T: IntRing2k + TryFrom<u128>>(&mut self) -> Result<Rep3RingShare<T>> {
        let a = take_ring::<T>(&mut self.a)?;
        let b = take_ring::<T>(&mut self.b)?;
        Ok(Rep3RingShare::new_ring(RingElement(a), RingElement(b)))
    }
    fn rings<T: IntRing2k + TryFrom<u128>>(&mut self, n: usize) -> Result<Vec<Rep3RingShare<T>>> {
        ensure!(
            n.checked_mul(std::mem::size_of::<T>())
                .is_some_and(|b| b <= self.left()),
            "DORAM state: {n} shares exceed the stream"
        );
        (0..n).map(|_| self.ring()).collect()
    }
    fn bigint<F: PrimeField>(r: &mut Reader<'_>) -> Result<F::BigInt> {
        let mut out = F::BigInt::default();
        let limbs: &mut [u64] = out.as_mut();
        for l in limbs.iter_mut() {
            *l = r.u64()?;
        }
        Ok(out)
    }
    fn record<F: PrimeField>(&mut self) -> Result<Record<FieldValue<F>>> {
        let a = Self::bigint::<F>(&mut self.a)?;
        let b = Self::bigint::<F>(&mut self.b)?;
        let alibi: AlibiShare = self.ring()?;
        Ok(Record {
            value: primitives::bigintshare::Rep3BigIntShare::new(a, b),
            alibi,
        })
    }
    fn records<F: PrimeField>(&mut self, n: usize) -> Result<Vec<Record<FieldValue<F>>>> {
        ensure!(
            n.checked_mul(8).is_some_and(|b| b <= self.left()),
            "DORAM state: {n} records exceed the stream"
        );
        (0..n).map(|_| self.record::<F>()).collect()
    }
    fn done(&self, what: &str) -> Result<()> {
        self.a.done(what)?;
        self.b.done(what)
    }
}

fn write_config(w: &mut Writer, c: &GigaDoramConfig) {
    w.usize(c.log_address_space_size);
    w.usize(c.log_capacity);
    w.usize(c.num_levels);
    w.usize(c.log_speed_cache_size);
    w.usize(c.log_amp_factor);
    w.usize(c.stash_size);
    w.u8(match c.cht_bounds {
        ChtBounds::Empirical => 0,
        ChtBounds::Proven => 1,
    });
}

fn read_config(r: &mut Reader<'_>) -> Result<GigaDoramConfig> {
    let log_address_space_size = r.usize()?;
    let log_capacity = r.usize()?;
    let num_levels = r.usize()?;
    let log_speed_cache_size = r.usize()?;
    let log_amp_factor = r.usize()?;
    let stash_size = r.usize()?;
    let cht_bounds = match r.u8()? {
        0 => ChtBounds::Empirical,
        1 => ChtBounds::Proven,
        b => bail!("DORAM state: {b} is not a CHT bound"),
    };
    let config = GigaDoramConfig {
        log_address_space_size,
        log_capacity,
        num_levels,
        log_speed_cache_size,
        log_amp_factor,
        stash_size,
        cht_bounds,
    };
    config
        .check()
        .map_err(|e| eyre::eyre!("DORAM state: the configuration is inconsistent: {e}"))?;
    Ok(config)
}

fn write_params(w: &mut Writer, p: &OHTableParams) {
    w.usize(p.num_elements);
    w.usize(p.num_dummies);
    w.usize(p.stash_size);
    w.u8(p.builder as u8);
    w.u32(p.log_single_col_len);
    w.usize(p.log_address_space_size);
}

fn read_params(r: &mut Reader<'_>) -> Result<OHTableParams> {
    let num_elements = r.usize()?;
    let num_dummies = r.usize()?;
    let stash_size = r.usize()?;
    let builder =
        PartyID::try_from(r.u8()?).map_err(|_| eyre::eyre!("DORAM state: a bad party id"))?;
    let log_single_col_len = r.u32()?;
    let log_address_space_size = r.usize()?;
    ensure!(
        log_single_col_len < 48
            && log_address_space_size < X_BITS
            && stash_size <= num_elements
            && num_elements
                .checked_add(num_dummies)
                .is_some_and(|n| n < 1 << 40),
        "DORAM state: a level's parameters are out of range"
    );
    Ok(OHTableParams {
        num_elements,
        num_dummies,
        stash_size,
        builder,
        log_single_col_len,
        log_address_space_size,
    })
}

/// A level's query bookkeeping, in the head: the query count, the touched
/// slots (as a list: at most the dummies of the level are touched beside
/// the stash) and the last query's trace.
fn write_bookkeeping<F: PrimeField>(w: &mut Writer, t: &OhTable<FieldValue<F>>) {
    w.usize(t.query_count);
    w.usize(t.touched.len());
    let touched: Vec<usize> = t
        .touched
        .iter()
        .enumerate()
        .filter_map(|(i, b)| b.then_some(i))
        .collect();
    w.usizes(&touched);
    match &t.last_query_trace {
        None => w.bool(false),
        Some(trace) => {
            w.bool(true);
            w.usize(trace.old_query_count);
            w.usize(trace.selected_receiver_index);
            w.bool(trace.was_touched_before);
        }
    }
}

struct Bookkeeping {
    query_count: usize,
    touched: Vec<bool>,
    last_query_trace: Option<OhTableQueryTrace>,
}

/// `max_total` bounds a level's slots: no level of the configuration has
/// more (see [`max_level_slots`]).
fn read_bookkeeping(r: &mut Reader<'_>, max_total: usize) -> Result<Bookkeeping> {
    let query_count = r.usize()?;
    let total = r.usize()?;
    ensure!(
        total <= max_total,
        "DORAM state: a level of {total} slots, over the configuration's {max_total}"
    );
    let mut touched = vec![false; total];
    for i in r.usizes()? {
        ensure!(i < total, "DORAM state: a touched slot {i} of {total}");
        touched[i] = true;
    }
    let last_query_trace = if r.bool()? {
        Some(OhTableQueryTrace {
            old_query_count: r.usize()?,
            selected_receiver_index: r.usize()?,
            was_touched_before: r.bool()?,
        })
    } else {
        None
    };
    Ok(Bookkeeping {
        query_count,
        touched,
        last_query_trace,
    })
}

fn write_level<F: PrimeField>(
    t: &OhTable<FieldValue<F>>,
    stamp: u64,
    id: PartyID,
) -> Result<Parts> {
    let mut w = Writer(Vec::new());
    let mut s = Shares::default();
    w.u8(VERSION);
    w.u64(stamp);
    write_params(&mut w, &t.params);
    w.usizes(&t.builder_stash_indices);
    w.usize(t.key.len());
    s.rings(&t.key);
    w.usize(t.stash_xs.len());
    s.rings(&t.stash_xs);
    w.usize(t.stash_ys.len());
    s.records::<F>(&t.stash_ys);
    w.usize(t.dummy_indices.len());
    s.rings(&t.dummy_indices);
    w.usize(t.xs_receiver_order.len());
    s.rings(&t.xs_receiver_order);
    w.usize(t.ys_receiver_order.len());
    s.records::<F>(&t.ys_receiver_order);
    let Some(cht) = &t.cht_rep3 else {
        bail!("DORAM state: a level built without its CHT's Rep3 shares");
    };
    w.usize(cht.len());
    s.rings(cht);
    let builder = t.params.builder;
    let mut copy = Writer(Vec::new());
    match (&t.receiver_shuffle, id == builder) {
        (None, true) => {}
        (Some(p), false) => {
            copy.usize(p.n);
            copy.usizes(&p.fy);
        }
        _ => bail!("DORAM state: a level's receiver shuffle does not match its builder"),
    }
    let (copy_a, copy_b) = if id == builder.next() {
        (copy.0, vec![])
    } else {
        (vec![], copy.0)
    };
    Ok(Parts {
        public: w.0,
        a: s.a,
        b: s.b,
        copy_a,
        copy_b,
    })
}

fn read_level<F: PrimeField>(
    parts: &Parts,
    stamp: u64,
    bookkeeping: Bookkeeping,
    id: PartyID,
) -> Result<OhTable<FieldValue<F>>> {
    let mut r = Reader(&parts.public);
    let mut s = SharesReader::new(parts)?;
    let version = r.u8()?;
    ensure!(
        version == VERSION,
        "DORAM state: format version {version}, this build reads {VERSION}"
    );
    let stored = r.u64()?;
    ensure!(
        stored == stamp,
        "DORAM state: a level part of build {stored} for the head's build {stamp}"
    );
    let params = read_params(&mut r)?;
    let builder_stash_indices = r.usizes()?;
    let n = r.usize()?;
    ensure!(n == ROUND_KEYS, "DORAM state: a key of {n} round keys");
    let key: Vec<BlockShare> = s.rings(n)?;
    let n = r.usize()?;
    let stash_xs: Vec<XShare> = s.rings(n)?;
    let n = r.usize()?;
    let stash_ys = s.records::<F>(n)?;
    let n = r.usize()?;
    let dummy_indices: Vec<XShare> = s.rings(n)?;
    let n = r.usize()?;
    let xs_receiver_order: Vec<XShare> = s.rings(n)?;
    let n = r.usize()?;
    let ys_receiver_order = s.records::<F>(n)?;
    let n = r.usize()?;
    let cht_rep3: Vec<BlockShare> = s.rings(n)?;
    r.done("level")?;
    s.done("level")?;
    let total = params.total_size();
    ensure!(
        stash_xs.len() == params.stash_size
            && stash_ys.len() == params.stash_size
            && builder_stash_indices.len() == params.stash_size
            && dummy_indices.len() == params.num_dummies
            && xs_receiver_order.len() == total
            && ys_receiver_order.len() == total
            && bookkeeping.touched.len() == total
            && bookkeeping.query_count <= params.num_dummies,
        "DORAM state: a level's arrays do not have its parameters' sizes"
    );
    let builder = params.builder;
    let copy = if id == builder.next() {
        ensure!(parts.copy_b.is_empty(), "DORAM state: misplaced copies");
        &parts.copy_a
    } else {
        ensure!(parts.copy_a.is_empty(), "DORAM state: misplaced copies");
        &parts.copy_b
    };
    let receiver_shuffle = if id == builder {
        ensure!(copy.is_empty(), "DORAM state: a builder with a shuffle");
        None
    } else {
        let mut c = Reader(copy);
        let n = c.usize()?;
        let fy = c.usizes()?;
        c.done("receiver shuffle")?;
        ensure!(
            n == total && fy.len() == n && fy.iter().enumerate().all(|(i, j)| *j <= i),
            "DORAM state: a receiver shuffle of the wrong shape"
        );
        Some(LocalPermutation::from_fisher_yates(fy))
    };
    // the receivers' two-party resharing of the CHT (primitives'
    // reshare_3_to_2 to builder.next and builder.prev), locally
    let cht_2shares: Vec<Block> = cht_rep3
        .iter()
        .map(|share| {
            if id == builder.next() {
                (share.a ^ share.b).0
            } else if id == builder.prev() {
                share.a.0
            } else {
                0
            }
        })
        .collect();
    let packed_key = packed_u8_lanes::precompute_round_keys(&key);
    Ok(OhTable {
        params,
        key,
        packed_key,
        stash_xs,
        stash_ys,
        builder_stash_indices,
        qs_builder_order: vec![],
        xs_builder_order: vec![],
        ys_builder_order: vec![],
        dummy_indices,
        xs_receiver_order,
        ys_receiver_order,
        cht_2shares: Some(cht_2shares),
        cht_rep3: Some(cht_rep3),
        receiver_shuffle,
        query_count: bookkeeping.query_count,
        touched: bookkeeping.touched,
        last_query_trace: bookkeeping.last_query_trace,
    })
}

impl<F: PrimeField> GigaDoram<FieldValue<F>> {
    /// This party's head: everything but the live levels' parts.
    pub fn head_parts(&self) -> Parts {
        let mut w = Writer(Vec::new());
        let mut s = Shares::default();
        w.u8(VERSION);
        write_config(&mut w, &self.config);
        w.bool(self.had_initial_bottom_level());
        w.bool(self.fill_count().is_some());
        w.usize(self.fill_count().unwrap_or(0));
        w.usizes(&self.base_b_state_vec);
        w.u64(self.next_stamp());
        let c = &self.speed_cache;
        w.usize(c.length);
        w.usize(c.log_address_space_size);
        w.usize(c.num_stored);
        s.rings(&c.addrs);
        s.records::<F>(&c.data);
        w.usize(self.levels.len());
        for (level, table) in self.levels.iter().enumerate() {
            match table {
                None => w.bool(false),
                Some(t) => {
                    w.bool(true);
                    w.u64(self.level_stamp(level).expect("a live level"));
                    write_bookkeeping::<F>(&mut w, t);
                }
            }
        }
        Parts {
            public: w.0,
            a: s.a,
            b: s.b,
            ..Parts::default()
        }
    }

    /// This party's part of `level` (party `id`), if the level is live; 500
    /// for a table that lacks what a part holds.
    pub fn level_parts(&self, level: usize, id: PartyID) -> Result<Option<Parts>> {
        match (&self.levels[level], self.level_stamp(level)) {
            (Some(t), Some(stamp)) => write_level::<F>(t, stamp, id).map(Some),
            _ => Ok(None),
        }
    }

    /// The stamps of the head's live levels, without decoding the rest:
    /// which level parts a head needs.
    pub fn head_stamps(head: &Parts) -> Result<Vec<Option<u64>>> {
        Ok(read_head(head)?.levels.iter().map(|l| l.stamp).collect())
    }

    /// Party `id`'s state from its head and the parts of the levels the
    /// head names live (`levels[l]`, `None` for a level the head names
    /// absent), checked for shape and for each part's stamp.
    pub fn from_parts_of(id: PartyID, head: &Parts, levels: Vec<Option<Parts>>) -> Result<Self> {
        let h = read_head(head)?;
        ensure!(
            levels.len() == h.levels.len(),
            "DORAM state: {} level parts for {} levels",
            levels.len(),
            h.levels.len()
        );
        let mut tables = Vec::with_capacity(levels.len());
        let mut stamps = Vec::with_capacity(levels.len());
        for (level, (part, head_level)) in levels.iter().zip(h.levels).enumerate() {
            match (part, head_level.stamp, head_level.bookkeeping) {
                (None, None, _) => {
                    tables.push(None);
                    stamps.push(0);
                }
                (Some(part), Some(stamp), Some(bk)) => {
                    tables.push(Some(read_level::<F>(part, stamp, bk, id)?));
                    stamps.push(stamp);
                }
                (None, Some(_), _) => {
                    bail!("DORAM state: the part of live level {level} is missing")
                }
                _ => bail!("DORAM state: a part of level {level}, which the head names absent"),
            }
        }
        let mut sr = SharesReader::new(head)?;
        let c = h.cache;
        let addrs: Vec<XShare> = sr.rings(c.length)?;
        let data = sr.records::<F>(c.length)?;
        sr.done("head")?;
        ensure!(
            c.num_stored <= c.length,
            "DORAM state: the speed cache is inconsistent"
        );
        let speed_cache = SpeedCache {
            length: c.length,
            log_address_space_size: c.log_address_space_size,
            num_stored: c.num_stored,
            addrs,
            data,
        };
        Ok(GigaDoram::from_parts(
            h.config,
            speed_cache,
            tables,
            h.base_b_state_vec,
            h.had_initial_bottom_level,
            h.fill_count,
            stamps,
            h.next_stamp,
        ))
    }
}

/// The most slots (records and dummies) a level of `config` has: the bottom
/// level's capacity and its dummies, each at most `2^log_capacity`; an upper
/// level holds fewer records and dummies than the level below it.
fn max_level_slots(config: &GigaDoramConfig) -> usize {
    2usize << config.log_capacity
}

impl<F: PrimeField> GigaDoram<FieldValue<F>> {
    /// The configuration a head names, read before anything it sizes, so a
    /// caller can check it against the shape it expects first.
    pub fn head_config(head: &Parts) -> Result<GigaDoramConfig> {
        let mut r = Reader(&head.public);
        let version = r.u8()?;
        ensure!(
            version == VERSION,
            "DORAM state: format version {version}, this build reads {VERSION}"
        );
        read_config(&mut r)
    }
}

struct HeadLevel {
    stamp: Option<u64>,
    bookkeeping: Option<Bookkeeping>,
}

struct Cache {
    length: usize,
    log_address_space_size: usize,
    num_stored: usize,
}

struct Head {
    config: GigaDoramConfig,
    had_initial_bottom_level: bool,
    fill_count: Option<usize>,
    base_b_state_vec: Vec<usize>,
    next_stamp: u64,
    cache: Cache,
    levels: Vec<HeadLevel>,
}

fn read_head(head: &Parts) -> Result<Head> {
    let mut r = Reader(&head.public);
    let version = r.u8()?;
    ensure!(
        version == VERSION,
        "DORAM state: format version {version}, this build reads {VERSION}"
    );
    let config = read_config(&mut r)?;
    let had_initial_bottom_level = r.bool()?;
    let has_fill = r.bool()?;
    let fill = r.usize()?;
    let base_b_state_vec = r.usizes()?;
    let next_stamp = r.u64()?;
    let length = r.usize()?;
    let log_address_space_size = r.usize()?;
    let num_stored = r.usize()?;
    ensure!(
        length == config.speed_cache_size(),
        "DORAM state: a speed cache of {length} for a configuration of {}",
        config.speed_cache_size()
    );
    let n = r.len(config.num_levels, 1)?;
    ensure!(
        n == config.num_levels && base_b_state_vec.len() == n,
        "DORAM state: {n} levels for a {}-level DORAM",
        config.num_levels
    );
    let mut levels = Vec::with_capacity(n);
    for _ in 0..n {
        levels.push(if r.bool()? {
            let stamp = r.u64()?;
            ensure!(
                stamp < next_stamp,
                "DORAM state: a level stamp from the future"
            );
            HeadLevel {
                stamp: Some(stamp),
                bookkeeping: Some(read_bookkeeping(&mut r, max_level_slots(&config))?),
            }
        } else {
            HeadLevel {
                stamp: None,
                bookkeeping: None,
            }
        });
    }
    r.done("head")?;
    ensure!(
        head.copy_a.is_empty() && head.copy_b.is_empty(),
        "DORAM state: a head with copies"
    );
    Ok(Head {
        config,
        had_initial_bottom_level,
        fill_count: has_fill.then_some(fill),
        base_b_state_vec,
        next_stamp,
        cache: Cache {
            length,
            log_address_space_size,
            num_stored,
        },
        levels,
    })
}

/// The address type's width in bits, for callers sizing address spaces.
pub const X_BITS: usize = X::BITS as usize;
