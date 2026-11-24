//! A key's DORAM (docs/ARCHITECTURE.md section 6, "The DORAM and its
//! layout", "The round" and "Versions, rollback and pipelining"; for the
//! keyed map "The storage: one DORAM addressed by (height, prefix)"): a `GigaDoram` of field
//! values at the addresses of a [`Layout`], built from the empty tree, read
//! and written one slot at a time at shared addresses, with the stored
//! encoding the layout prescribes (a hash of height `l` as `v XOR Z_l` in a
//! keyed map, so an untouched address reads as the empty node; the values
//! as they are in a dense tree), the conversions between the machine's
//! arithmetic Rep3 shares and the DORAM's XOR shares, the journal of a
//! round's old values and this party's persisted state: a head blob and one
//! blob per live level (docs/ARCHITECTURE.md section 6, "Persistence, resync,
//! share refresh, audit"), each in sidecar-core's blob format, a level written
//! only when a rebuild replaced it.

use ark_ff::PrimeField;
use doram::GigaDoramBn254;
use doram::state::Parts;
use eyre::Result;
use mpc_core::protocols::rep3::conversion::{a2b_many, b2a_many};
use mpc_core::protocols::rep3::id::PartyID;
use mpc_core::protocols::rep3::{Rep3State, Rep3UintShare};
use mpc_core::uint::{U256, UintBackend};
use mpc_net::Network;
use mpc_net::bytes::Bytes;
use primitives::bigintshare::Rep3BigIntShare;
use primitives::{X, XShare, Y, YShare, promote_public_y};
use sidecar_core::bind::{Elem, Share};
use sidecar_core::codec::{Decoded, Reader};
use sidecar_core::error::Refusal;
use sidecar_core::field::Fr;
use sidecar_core::store::StoreRead;
use sidecar_core::store::blob::{Blob, Pair};

use crate::fill::Schedule;
use crate::layout::Layout;

/// A `&dyn Network` as the `Network` the DORAM's generic protocols take.
pub struct DynNet<'a>(pub &'a dyn Network);

impl Network for DynNet<'_> {
    fn id(&self) -> usize {
        self.0.id()
    }
    fn send(&self, to: usize, data: Bytes) -> Result<()> {
        self.0.send(to, data)
    }
    fn recv(&self, from: usize) -> Result<Bytes> {
        self.0.recv(from)
    }
    fn flush(&self) -> Result<()> {
        self.0.flush()
    }
    fn get_connection_stats(&self) -> mpc_net::ConnectionStats {
        self.0.get_connection_stats()
    }
}

pub(crate) fn mpc(e: eyre::Report) -> Refusal {
    Refusal::mpc_failure(format!("oblivious tree: {e}"))
}

/// A field element's integer as the binary shares' uint.
fn to_uint(v: &Y) -> U256 {
    let limbs: &[u64] = v.as_ref();
    let mut out = U256::from(0u64);
    for (i, l) in limbs.iter().enumerate() {
        out |= U256::from(*l) << (64 * i);
    }
    out
}

/// The binary shares' uint as a field element's integer (below 2^254).
fn to_bigint(u: &U256) -> Y {
    let mut out = Y::default();
    let limbs: &mut [u64] = out.as_mut();
    for (o, l) in limbs.iter_mut().zip(u.as_limbs()) {
        *o = *l;
    }
    out
}

/// Arithmetic shares of indices or keys to XOR-shared paths: one `a2b`
/// batch, then the low `D` bits of each (the two low limbs, masked locally).
pub fn indices_to_xor<L: Layout>(
    layout: &L,
    shares: &[Share],
    net: &dyn Network,
    state: &mut Rep3State,
) -> Result<Vec<XShare>, Refusal> {
    if shares.is_empty() {
        return Ok(vec![]);
    }
    let bits = a2b_many::<Fr, _>(shares, &DynNet(net), state).map_err(mpc)?;
    Ok(bits
        .iter()
        .map(|b| {
            let low = |u: &U256| {
                let l = u.as_limbs();
                (l[0] as X) | ((l[1] as X) << 64)
            };
            layout.mask_path(&XShare::new(low(&b.a), low(&b.b)))
        })
        .collect())
}

/// XOR-shared DORAM values to arithmetic shares: one `b2a` batch (every
/// stored value is a field element, so `b2a` applies).
pub fn values_to_field(
    values: &[YShare],
    net: &dyn Network,
    state: &mut Rep3State,
) -> Result<Vec<Share>, Refusal> {
    if values.is_empty() {
        return Ok(vec![]);
    }
    let bin: Vec<Rep3UintShare<Fr>> = values
        .iter()
        .map(|y| Rep3UintShare::new(to_uint(&y.a), to_uint(&y.b)))
        .collect();
    b2a_many::<Fr, _>(&bin, &DynNet(net), state).map_err(mpc)
}

/// Arithmetic shares to XOR-shared DORAM values: one `a2b` batch.
pub fn field_to_values(
    shares: &[Share],
    net: &dyn Network,
    state: &mut Rep3State,
) -> Result<Vec<YShare>, Refusal> {
    if shares.is_empty() {
        return Ok(vec![]);
    }
    let bin = a2b_many::<Fr, _>(shares, &DynNet(net), state).map_err(mpc)?;
    Ok(bin
        .iter()
        .map(|b| Rep3BigIntShare::new(to_bigint(&b.a), to_bigint(&b.b)))
        .collect())
}

/// The arithmetic share of an element (a public one as its trivial sharing).
pub fn share_of(id: PartyID, e: &Elem) -> Share {
    match e {
        Elem::Shared(s) => *s,
        Elem::Public(v) => mpc_core::protocols::rep3::arithmetic::promote_to_trivial_share(id, *v),
    }
}

/// `v XOR k` for a public `k`, on an XOR sharing: the trivial sharing of `k`
/// XORed in. Its own inverse: the stored encoding and its decoding.
pub fn xor_public(id: PartyID, v: &YShare, k: &Y) -> YShare {
    *v ^ promote_public_y(id, *k)
}

fn xor_offsets(id: PartyID, values: &[YShare], offsets: &[Y]) -> Vec<YShare> {
    debug_assert_eq!(values.len(), offsets.len());
    values
        .iter()
        .zip(offsets)
        .map(|(v, k)| xor_public(id, v, k))
        .collect()
}

/// One slot's journal: the addresses it read and the raw values they held
/// (in read order), the addresses it writes (the stored vector's order) and,
/// once the version's writes are applied to the DORAM, the raw values the
/// write addresses held before (`old_writes`, empty until then). Writing
/// `old_writes` back at `writes` undoes the slot's writes exactly; writing
/// the version's vector at `writes` applies them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotJournal {
    pub reads: Vec<XShare>,
    pub old: Vec<YShare>,
    pub writes: Vec<XShare>,
    pub old_writes: Vec<YShare>,
}

/// The share components of a journal: component `a` of every share to one
/// stream, `b` to the other.
#[derive(Default)]
struct Streams {
    a: Vec<u8>,
    b: Vec<u8>,
}

impl Streams {
    fn xs(&mut self, xs: &[XShare]) {
        for x in xs {
            self.a.extend_from_slice(&x.a.0.to_le_bytes());
            self.b.extend_from_slice(&x.b.0.to_le_bytes());
        }
    }
    fn ys(&mut self, ys: &[YShare]) {
        for y in ys {
            for (out, v) in [(&mut self.a, &y.a), (&mut self.b, &y.b)] {
                let limbs: &[u64] = v.as_ref();
                for l in limbs {
                    out.extend_from_slice(&l.to_le_bytes());
                }
            }
        }
    }
}

fn malformed() -> Refusal {
    Refusal::mpc_failure("oblivious tree: a journal entry is malformed")
}

/// One `Y` as [`Streams::ys`] wrote its component: its limbs, little-endian.
fn read_y(r: &mut Reader<'_>) -> Decoded<Y> {
    let mut out = Y::default();
    let limbs: &mut [u64] = out.as_mut();
    for l in limbs.iter_mut() {
        *l = r.u64()?;
    }
    Ok(out)
}

/// A round's journal entry: one [`SlotJournal`] per slot, in slot order.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Journal {
    pub slots: Vec<SlotJournal>,
}

impl Journal {
    /// Whether every slot's old write values are recorded (the entry was
    /// applied to the DORAM), so the entry can be undone.
    pub fn applied(&self) -> bool {
        self.slots
            .iter()
            .all(|s| s.old_writes.len() == s.writes.len())
    }

    /// The entry as a blob: the slots' lengths public, every address and
    /// value as this party's two XOR components.
    pub fn to_blob(&self) -> Blob {
        let mut public = Vec::new();
        let mut s = Streams::default();
        public.extend_from_slice(&(self.slots.len() as u64).to_le_bytes());
        for slot in &self.slots {
            for n in [
                slot.reads.len(),
                slot.writes.len(),
                slot.old.len(),
                slot.old_writes.len(),
            ] {
                public.extend_from_slice(&(n as u64).to_le_bytes());
            }
            s.xs(&slot.reads);
            s.xs(&slot.writes);
            s.ys(&slot.old);
            s.ys(&slot.old_writes);
        }
        Blob {
            public,
            shares: Pair { a: s.a, b: s.b },
            copies: Pair::default(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_blob().to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Refusal> {
        let blob = Blob::from_bytes(bytes)?;
        Self::parse(&blob).map_err(|_| malformed())
    }

    fn parse(blob: &Blob) -> Decoded<Self> {
        let short = || "short".to_string();
        let mut p = Reader::new(&blob.public);
        let (mut a, mut b) = (Reader::new(&blob.shares.a), Reader::new(&blob.shares.b));
        let n = p.u64()? as usize;
        if n.checked_mul(32).is_none_or(|len| len > p.remaining()) {
            return Err(short());
        }
        let mut slots = Vec::with_capacity(n);
        for _ in 0..n {
            let mut lens = [0usize; 4];
            for l in lens.iter_mut() {
                *l = p.u64()? as usize;
            }
            let [reads, writes, old, old_writes] = lens;
            let need = (reads + writes)
                .checked_mul(16)
                .zip((old + old_writes).checked_mul(32))
                .and_then(|(x, y)| x.checked_add(y));
            if need.is_none_or(|need| need > a.remaining()) {
                return Err(short());
            }
            let mut xs = |n: usize| -> Decoded<Vec<XShare>> {
                (0..n)
                    .map(|_| Ok(XShare::new(a.u128()?, b.u128()?)))
                    .collect()
            };
            let reads = xs(reads)?;
            let writes = xs(writes)?;
            let mut ys = |n: usize| -> Decoded<Vec<YShare>> {
                (0..n)
                    .map(|_| Ok(Rep3BigIntShare::new(read_y(&mut a)?, read_y(&mut b)?)))
                    .collect()
            };
            let old = ys(old)?;
            let old_writes = ys(old_writes)?;
            slots.push(SlotJournal {
                reads,
                old,
                writes,
                old_writes,
            });
        }
        p.finish()?;
        a.finish()?;
        if !blob.copies.a.is_empty() || !blob.copies.b.is_empty() {
            return Err("copies".into());
        }
        Ok(Journal { slots })
    }
}

/// What one slot's read returns: its addresses, the raw values as stored
/// (the journal's) and the decoded values (the loaded vector's).
pub struct SlotRead {
    pub reads: Vec<XShare>,
    pub raw: Vec<YShare>,
    pub values: Vec<YShare>,
}

/// One `tip_blobs` write of a commit: the blob's name and its bytes, or
/// `None` to delete it.
pub type BlobWrite = (String, Option<Vec<u8>>);

/// The blob of a key's DORAM head (the configuration, the level counters,
/// each live level's stamp and query bookkeeping, the speed cache).
pub const HEAD: &str = "oram";

/// The blob of level `level` of a key's DORAM (what its build made).
pub fn level_blob(level: usize) -> String {
    format!("oram.level.{level}")
}

fn blob_of(parts: Parts) -> Blob {
    Blob {
        public: parts.public,
        shares: Pair {
            a: parts.a,
            b: parts.b,
        },
        copies: Pair {
            a: parts.copy_a,
            b: parts.copy_b,
        },
    }
}

fn parts_of(blob: Blob) -> Parts {
    Parts {
        public: blob.public,
        a: blob.shares.a,
        b: blob.shares.b,
        copy_a: blob.copies.a,
        copy_b: blob.copies.b,
    }
}

/// This party's DORAM of one oblivious key.
pub struct Doram<L: Layout> {
    pub layout: L,
    pub id: PartyID,
    doram: GigaDoramBn254,
    read_offsets: Vec<Y>,
    write_offsets: Vec<Y>,
    /// The stamp of each level as the store holds it (none for a level the
    /// store holds no part of): what [`Self::writes`] compares against.
    persisted: Vec<Option<u64>>,
}

fn bigints(values: &[Fr]) -> Vec<Y> {
    values.iter().map(|v| v.into_bigint()).collect()
}

impl<L: Layout> Doram<L> {
    fn wrap(layout: L, id: PartyID, doram: GigaDoramBn254, persisted: Vec<Option<u64>>) -> Self {
        Doram {
            layout,
            id,
            doram,
            read_offsets: bigints(&layout.read_offsets()),
            write_offsets: bigints(&layout.write_offsets()),
            persisted,
        }
    }

    /// The DORAM of the empty tree, as the layout builds it.
    pub fn build_empty(
        layout: L,
        net: &dyn Network,
        state: &mut Rep3State,
    ) -> Result<Self, Refusal> {
        let doram = layout.build_empty(net, state)?;
        let persisted = vec![None; doram.num_levels()];
        Ok(Self::wrap(layout, state.id, doram, persisted))
    }

    /// Read the raw values at `addrs` (distinct), one batch.
    pub fn read_raw(
        &mut self,
        addrs: &[XShare],
        net: &dyn Network,
        state: &mut Rep3State,
    ) -> Result<Vec<YShare>, Refusal> {
        if addrs.is_empty() {
            return Ok(vec![]);
        }
        self.doram
            .batch_read(addrs, &DynNet(net), state, None)
            .map_err(mpc)
    }

    /// Read one slot's path: its `D + 1 + W` addresses in one batch, decoded.
    pub fn read_slot(
        &mut self,
        path: &XShare,
        net: &dyn Network,
        state: &mut Rep3State,
    ) -> Result<SlotRead, Refusal> {
        let reads = self.layout.slot_reads(self.id, path);
        let raw = self.read_raw(&reads, net, state)?;
        let values = xor_offsets(self.id, &raw, &self.read_offsets);
        Ok(SlotRead { reads, raw, values })
    }

    /// Write raw values at `addrs` (distinct), one batch; returns the raw
    /// values the addresses held before.
    pub fn write_raw(
        &mut self,
        addrs: &[XShare],
        values: &[YShare],
        net: &dyn Network,
        state: &mut Rep3State,
    ) -> Result<Vec<YShare>, Refusal> {
        if addrs.len() != values.len() {
            return Err(Refusal::mpc_failure(format!(
                "oblivious tree: {} addresses for {} values",
                addrs.len(),
                values.len()
            )));
        }
        if addrs.is_empty() {
            return Ok(vec![]);
        }
        let writes: Vec<(XShare, YShare)> =
            addrs.iter().copied().zip(values.iter().copied()).collect();
        self.doram
            .batch_write(&writes, &DynNet(net), state, None)
            .map_err(mpc)
    }

    /// Write one slot's stored vector (its elements, leaf hash and path
    /// nodes, plain) at its write addresses, encoded; returns the raw values
    /// the addresses held before, the journal's `old_writes`.
    pub fn write_slot(
        &mut self,
        writes: &[XShare],
        values: &[YShare],
        net: &dyn Network,
        state: &mut Rep3State,
    ) -> Result<Vec<YShare>, Refusal> {
        if values.len() != self.write_offsets.len() {
            return Err(Refusal::mpc_failure(format!(
                "oblivious tree: a slot stores {} elements, the layout gives {}",
                values.len(),
                self.write_offsets.len()
            )));
        }
        let encoded = xor_offsets(self.id, values, &self.write_offsets);
        self.write_raw(writes, &encoded, net, state)
    }

    /// Undo a journal entry: every slot's old raw values written back at its
    /// write addresses, last slot first. The entry must have been applied.
    pub fn undo(
        &mut self,
        journal: &Journal,
        net: &dyn Network,
        state: &mut Rep3State,
    ) -> Result<(), Refusal> {
        if !journal.applied() {
            return Err(Refusal::mpc_failure(
                "oblivious tree: undoing an attempt whose writes were never applied",
            ));
        }
        for slot in journal.slots.iter().rev() {
            self.write_raw(&slot.writes, &slot.old_writes, net, state)?;
        }
        Ok(())
    }

    /// The blob writes that persist this party's state over what the store
    /// holds: the head always (it changes at every access), the part of
    /// each level a rebuild made since the store's (its stamp differs), and
    /// a deletion for each level the store holds that is gone. So a commit
    /// without a rebuild writes the head alone; a version's state is the
    /// head plus the levels it names, which the store holds at their stamps.
    pub fn writes(&self) -> Result<Vec<BlobWrite>, Refusal> {
        let mut out = vec![(
            HEAD.to_string(),
            Some(blob_of(self.doram.head_parts()).to_bytes()),
        )];
        for (level, stored) in self.persisted.iter().enumerate() {
            let now = self.doram.level_stamp(level);
            if now == *stored {
                continue;
            }
            let part = self.doram.level_parts(level, self.id).map_err(mpc)?;
            out.push((level_blob(level), part.map(|p| blob_of(p).to_bytes())));
        }
        Ok(out)
    }

    /// Take the store as holding what [`Self::writes`] gave (after its
    /// commit).
    pub fn persisted(&mut self) {
        self.persisted = (0..self.doram.num_levels())
            .map(|l| self.doram.level_stamp(l))
            .collect();
    }

    /// The DORAM key `key` of namespace `ns` holds in `store`, for party
    /// `id`: its head and the levels the head names; `None` when the store
    /// holds no head (the key's DORAM was never persisted). 500 for a
    /// missing level part, parts of another build than the head names, or a
    /// stored DORAM of another shape than `layout`'s.
    pub fn load(
        layout: L,
        id: PartyID,
        store: &dyn StoreRead,
        ns: Fr,
        key: &str,
    ) -> Result<Option<Self>, Refusal> {
        let Some(head) = store.blob(ns, key, HEAD)? else {
            return Ok(None);
        };
        let head = parts_of(Blob::from_bytes(&head)?);
        // the stored configuration is the layout's before the head sizes anything
        let stored = GigaDoramBn254::head_config(&head).map_err(mpc)?;
        let expected = layout.config();
        if stored != expected {
            return Err(Refusal::mpc_failure(format!(
                "oblivious tree: a stored DORAM of 2^{} addresses and 2^{} records ({} levels) \
                 for a layout of 2^{} and 2^{} ({} levels)",
                stored.log_address_space_size,
                stored.log_capacity,
                stored.num_levels,
                expected.log_address_space_size,
                expected.log_capacity,
                expected.num_levels
            )));
        }
        let stamps = GigaDoramBn254::head_stamps(&head).map_err(mpc)?;
        let mut levels = Vec::with_capacity(stamps.len());
        for (level, stamp) in stamps.iter().enumerate() {
            levels.push(match stamp {
                None => None,
                Some(_) => {
                    let bytes = store.blob(ns, key, &level_blob(level))?.ok_or_else(|| {
                        Refusal::mpc_failure(format!(
                            "key `{key}`: the DORAM's level {level} is missing (resync this node)"
                        ))
                    })?;
                    Some(parts_of(Blob::from_bytes(&bytes)?))
                }
            });
        }
        let doram = GigaDoramBn254::from_parts_of(id, &head, levels).map_err(mpc)?;
        Ok(Some(Self::wrap(layout, id, doram, stamps)))
    }

    /// The public bytes of this party's head (the configuration, the level
    /// counters, each live level's stamp and query bookkeeping, the speed
    /// cache's fill): equal at the three parties of one DORAM, since every
    /// one of them is opened to all three or computed from what is.
    pub fn head_public(&self) -> Vec<u8> {
        self.doram.head_parts().public
    }

    /// The stamp of the bottom level's build (none before the first): it
    /// changes at every bottom rebuild.
    pub fn bottom_stamp(&self) -> Option<u64> {
        self.doram.level_stamp(self.doram.num_levels() - 1)
    }

    /// When the next bottom rebuild runs, from the public counters: the
    /// speed cache's free entries, then `fill_time` accesses for each rebuild
    /// of an upper level before it. The upper levels' counters read as a
    /// base-`amp` number count the speed cache's flushes since the last
    /// bottom rebuild; the flush that finds every one at `amp - 1` rebuilds
    /// the bottom.
    pub fn schedule(&self) -> Schedule {
        let config = &self.doram.config;
        let cache = &self.doram.speed_cache;
        let fill_time = config.fill_time() as u64;
        let amp = config.amp_factor() as u64;
        let upper = config.num_levels - 1;
        let flushes = amp.saturating_pow(upper as u32);
        let done = self.doram.base_b_state_vec[..upper]
            .iter()
            .rev()
            .fold(0u64, |n, digit| {
                n.saturating_mul(amp).saturating_add(*digit as u64)
            });
        let free = (cache.length - cache.num_stored) as u64;
        Schedule {
            before_bottom: free.saturating_add(
                flushes
                    .saturating_sub(1)
                    .saturating_sub(done)
                    .saturating_mul(fill_time),
            ),
            cycle: flushes.saturating_mul(fill_time),
            capacity: self.doram.capacity() as u64,
        }
    }

    /// A sparse DORAM's distinct addresses at its last bottom-level rebuild.
    pub fn fill_count(&self) -> Option<usize> {
        self.doram.fill_count()
    }

    /// The bottom level's capacity in records.
    pub fn capacity(&self) -> usize {
        self.doram.capacity()
    }
}

/// The loaded vector's order for a window read (`Layout::window_reads`
/// returns leaves as hash then elements per leaf, then the root siblings):
/// the leaves' elements, the leaves' hashes, the root siblings.
pub fn window_vector<L: Layout>(layout: &L, width: usize, values: &[Share]) -> Vec<Elem> {
    let w = layout.leaf_len();
    let mut leaves = Vec::with_capacity(width * w);
    let mut hashes = Vec::with_capacity(width);
    for i in 0..width {
        let at = i * (1 + w);
        hashes.push(values[at]);
        leaves.extend_from_slice(&values[at + 1..at + 1 + w]);
    }
    let rest = &values[width * (1 + w)..];
    leaves
        .into_iter()
        .chain(hashes)
        .chain(rest.iter().copied())
        .map(Elem::Shared)
        .collect()
}

/// The field's integer as a trivially shared DORAM value.
pub fn public_y(id: PartyID, v: Fr) -> YShare {
    promote_public_y(id, v.into_bigint())
}
