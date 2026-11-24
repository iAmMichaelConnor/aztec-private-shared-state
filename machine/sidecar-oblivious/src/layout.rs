//! The DORAM address layouts of the two oblivious bricks: the dense tree
//! (docs/ARCHITECTURE.md section 6, "The DORAM and its layout") and the
//! sparse keyed map (docs/ARCHITECTURE.md section 6, "The storage: one
//! DORAM addressed by (height, prefix)"). One trait, [`Layout`],
//! is what differs between them on the store side; the DORAM wrapper and
//! the state holder are written once over it.
//!
//! ```text
//! dense (Addressing)
//!   hash region   the heap index of a node: the root is 1, the children of h are 2h and
//!                 2h + 1, leaf i's hash sits at 2^D + i; the node at height l on leaf i's
//!                 path is 2^(D-l) + (i >> l), its sibling that ^ 1        (1 <= h < 2^(D+1))
//!   leaf region   2^(D+1) + i * 2^LW + e for element e of leaf i, LW = ceil(log2 W)
//!   every address holds its value as it is; the bottom level is built from the empty tree
//!
//! keyed map (MapAddressing), path p the key's low D bits
//!   hash node at height l (the root l = D)   l * 2^(D + LW) + (p >> l); its sibling ^ 1
//!   leaf element e                            (D + 1) * 2^(D + LW) + (p << LW) + e
//!   a hash of height l is stored as v XOR Z_l, so an address never written (0) reads as
//!   the empty node; the bottom level is lazy and bounded by a capacity
//! ```
//!
//! Every address a slot needs is a shift, an XOR with a public constant or an
//! OR of disjoint bits of the path, so on an XOR sharing of the path the
//! nodes derive the addresses locally, with no communication.

use ark_ff::PrimeField;
use doram::{ChtBounds, EMPIRICAL_CHT_STASH_SIZE, GigaDoramBn254, GigaDoramConfig};
use mpc_core::protocols::rep3::Rep3State;
use mpc_core::protocols::rep3::id::PartyID;
use mpc_net::Network;
use primitives::{X, XShare, promote_public, promote_public_y};
use sidecar_core::error::Refusal;
use sidecar_core::field::Fr;
use sidecar_core::manifest::TreeLayout;
use sidecar_core::tree::zeros;

use crate::fill::{Bound, Fill, Unbounded};
use crate::oram::{DynNet, mpc};

// The shapes the two bricks serve. REGISTER refuses any other
// ([`check_shape`], through the holder's `check_manifest`); the bounds are
// what one node allocates and computes for a key, and what the vendored
// DORAM's own invariants allow.

/// The shallowest and the deepest keyed map (docs/ARCHITECTURE.md section 6,
/// "The key, the path and the depth"): a path of 32 to 120 bits of the key.
pub const MIN_MAP_DEPTH: u32 = 32;
pub const MAX_MAP_DEPTH: u32 = 120;

/// The smallest and the largest keyed map capacity, log2 of the distinct
/// DORAM addresses the map may hold: a bottom level of 2^8 to 2^36 records.
/// The hierarchy of a larger capacity has more than the eight levels the
/// DORAM's alibi byte can name ([`hierarchy`] gives nine at 2^37).
pub const MIN_MAP_CAPACITY: usize = 8;
pub const MAX_MAP_CAPACITY: usize = 36;

/// The widest dense DORAM, log2 of its addresses: a dense tree's DORAM holds
/// every one of its `2^(D + 1 + max(1, LW))` addresses from its first
/// session, built under the node-wide mesh lock (about 1.7 GB per 2^20 at
/// each node, so about 7 GB at 2^22: lending's depth 16 with leaves of 8 is
/// 2^20).
pub const MAX_DENSE_LOG_ADDRESSES: usize = 22;

/// The longest leaf of an oblivious tree or map: a slot reads and writes
/// `D + 1 + W` addresses, and a dense DORAM's leaf region is `2^(D + LW)`.
pub const MAX_LEAF_LEN: usize = 64;

/// The most slots an oblivious round touches: each is a batch of `D + 1 + W`
/// DORAM reads in the session and as many writes at the next one.
pub const MAX_PROBE: usize = 16;

/// The widest DORAM address space: below the sort's 127-bit row.
pub const MAX_LOG_ADDRESSES: usize = 126;

/// Whether an oblivious tree entry has a shape its brick can serve: the
/// dense tree's [`Addressing::checked`] or the keyed map's
/// [`MapAddressing::checked`], and a probe in 1 ..= [`MAX_PROBE`]. The text
/// names the field of the entry (`` `depth`: ... ``).
pub fn check_shape(tree: &TreeLayout) -> Result<(), String> {
    if !(1..=MAX_PROBE).contains(&tree.probe) {
        return Err(format!(
            "`probe`: an oblivious round touches 1 to {MAX_PROBE} slots, not {}",
            tree.probe
        ));
    }
    if tree.keyed {
        MapAddressing::checked(
            tree.depth,
            tree.leaf_len,
            tree.capacity.unwrap_or(crate::DEFAULT_MAP_CAPACITY_LOG2),
        )
        .map(|_| ())
    } else {
        Addressing::checked(tree.depth, tree.leaf_len).map(|_| ())
    }
}

/// The leaf length check both bricks share.
fn check_leaf_len(leaf_len: usize, least: usize, what: &str) -> Result<(), String> {
    if (least..=MAX_LEAF_LEN).contains(&leaf_len) {
        Ok(())
    } else {
        Err(format!(
            "`leaf_len`: {what} has {least} to {MAX_LEAF_LEN} elements, not {leaf_len}"
        ))
    }
}

/// How a tree's nodes and leaves are addressed in the key's DORAM, what each
/// address holds when empty, and how the DORAM of the empty tree is made.
pub trait Layout: Copy + Send + Sync + 'static {
    /// The public bound on the DORAM's fill this layout keeps: none for a
    /// dense layout (every address exists), a keyed map's [`Fill`].
    type Bound: Bound;

    /// The tree's depth `D`: a path has `D` bits.
    fn depth(&self) -> u32;
    /// The elements of one leaf, `W`.
    fn leaf_len(&self) -> usize;
    /// log2 of the DORAM's address space (its label space).
    fn log_addresses(&self) -> usize;
    /// log2 of the DORAM's bottom level in records: the whole address space
    /// for a dense layout, the capacity for a sparse one.
    fn log_capacity(&self) -> usize;
    /// The addresses one slot reads from its path, in the loaded vector's
    /// order: the `D` siblings bottom up, the leaf hash, the `W` elements.
    fn slot_reads(&self, id: PartyID, path: &XShare) -> Vec<XShare>;
    /// The addresses one slot writes, in the stored vector's order: the `W`
    /// elements, the leaf hash, the `D` path nodes of heights 1 to `D`.
    fn slot_writes(&self, id: PartyID, path: &XShare) -> Vec<XShare>;
    /// The low `D` bits of an XOR-shared integer: a path.
    fn mask_path(&self, x: &XShare) -> XShare;
    /// What the stored encoding hides at each read position (XORed into the
    /// value as stored): `Z_l` under a hash of height `l` for a layout whose
    /// untouched addresses read as 0, zeros for one whose DORAM holds the
    /// values as they are.
    fn read_offsets(&self) -> Vec<Fr>;
    /// The same for each write position.
    fn write_offsets(&self) -> Vec<Fr>;
    /// The value the empty tree holds at a read position, in the clear.
    fn empty_reads(&self) -> Vec<Fr>;
    /// The value the empty tree holds at a write position, in the clear.
    fn empty_writes(&self) -> Vec<Fr>;
    /// The DORAM of the empty tree.
    fn build_empty(
        &self,
        net: &dyn Network,
        state: &mut Rep3State,
    ) -> Result<GigaDoramBn254, Refusal>;
    /// The addresses a window of `width` leaves from `start` reads, for a
    /// layout that has windows (the dense tree); empty otherwise.
    fn window_reads(&self, id: PartyID, start: u64, width: usize) -> Vec<XShare>;

    /// `D + 1 + W`: the reads of one slot, and its writes.
    fn reads_per_slot(&self) -> usize {
        self.depth() as usize + 1 + self.leaf_len()
    }

    /// The configuration of the key's DORAM (the hierarchy over the bottom
    /// level, [`hierarchy`]), or why the vendored DORAM cannot take it.
    fn try_config(&self) -> Result<GigaDoramConfig, String> {
        let (levels, amp) = hierarchy(self.log_capacity());
        GigaDoramConfig::try_with_capacity(
            self.log_addresses(),
            self.log_capacity(),
            levels,
            amp,
            EMPIRICAL_CHT_STASH_SIZE,
            ChtBounds::Empirical,
        )
        .map_err(|e| e.to_string())
    }

    /// The configuration of the key's DORAM, for a layout REGISTER checked.
    fn config(&self) -> GigaDoramConfig {
        self.try_config()
            .expect("REGISTER checked the layout's DORAM (check_shape)")
    }

    /// [`Self::slot_reads`] for a public path, in the clear.
    fn clear_slot_reads(&self, path: u64) -> Vec<X> {
        let id = PartyID::ID0;
        self.slot_reads(id, &promote_public(id, path as X))
            .iter()
            .map(open_trivial)
            .collect()
    }

    /// [`Self::slot_writes`] for a public path, in the clear.
    fn clear_slot_writes(&self, path: u64) -> Vec<X> {
        let id = PartyID::ID0;
        self.slot_writes(id, &promote_public(id, path as X))
            .iter()
            .map(open_trivial)
            .collect()
    }
}

/// The value of a trivial sharing made by party 0 (`a` holds it, `b` is 0).
fn open_trivial(x: &XShare) -> X {
    x.a.0 ^ x.b.0
}

/// `ceil(log2 w)`: the bits an element index takes within a leaf.
fn log_width(w: usize) -> u32 {
    w.next_power_of_two().trailing_zeros()
}

/// The hierarchy for a bottom level of `log_capacity` records: amplification
/// 4 at most and the fewest levels that bring the speed cache down to
/// 2^8 entries or fewer, each level's amplification the least that does,
/// so the cache holds 32 to 256 entries from 2^9 up
/// (docs/ARCHITECTURE.md section 6, "The DORAM and its measurements": "4
/// / 3" at 2^17, "4 / 4" at 2^20; one level below 2^9).
pub fn hierarchy(log_capacity: usize) -> (usize, usize) {
    let levels = 1 + log_capacity.saturating_sub(8).div_ceil(4);
    let amp = if levels == 1 {
        1
    } else {
        (log_capacity - 8).div_ceil(levels - 1)
    };
    (levels, amp)
}

/// The address layout of a dense tree of depth `depth` with leaves of
/// `leaf_len` elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addressing {
    pub depth: u32,
    pub leaf_len: usize,
}

impl Addressing {
    /// The layout, or why the depth and leaf length do not fit (the text
    /// names the field): a depth of at least 1, a leaf of 1 to
    /// [`MAX_LEAF_LEN`] elements, an address space of at most
    /// [`MAX_DENSE_LOG_ADDRESSES`] bits whose hierarchy the DORAM can take
    /// (from 2^4 addresses: the speed cache holds more than the stash).
    pub fn checked(depth: u32, leaf_len: usize) -> Result<Self, String> {
        check_leaf_len(leaf_len, 1, "a leaf")?;
        if depth == 0 || depth as usize > MAX_DENSE_LOG_ADDRESSES - 2 {
            return Err(format!(
                "`depth`: a dense oblivious tree is 1 to {} deep, not {depth}",
                MAX_DENSE_LOG_ADDRESSES - 2
            ));
        }
        let out = Addressing { depth, leaf_len };
        if out.log_addresses() > MAX_DENSE_LOG_ADDRESSES {
            return Err(format!(
                "`depth`: a dense oblivious tree of depth {depth} with leaves of {leaf_len} \
                 elements holds 2^{} DORAM addresses at each node; at most \
                 2^{MAX_DENSE_LOG_ADDRESSES}",
                out.log_addresses()
            ));
        }
        out.try_config().map_err(|e| {
            format!(
                "`depth`: a dense oblivious tree of depth {depth} with leaves of {leaf_len} \
                 elements has a DORAM of 2^{} addresses, which the DORAM cannot take: {e}",
                out.log_addresses()
            )
        })?;
        Ok(out)
    }

    /// The layout of a dense tree whose depth and leaf length REGISTER
    /// checked ([`Self::checked`]).
    pub fn new(depth: u32, leaf_len: usize) -> Self {
        Addressing { depth, leaf_len }
    }

    /// `LW`: the bits an element index takes within a leaf.
    pub fn log_leaf_width(&self) -> u32 {
        log_width(self.leaf_len)
    }

    /// The address of the node at `height` (0 the leaves, `D` the root) and
    /// `position` (the index shifted by the height).
    pub fn node(&self, height: u32, position: X) -> X {
        ((1 as X) << (self.depth - height)) | position
    }

    /// The address of leaf `index`'s hash (its node at height 0).
    #[cfg(test)]
    pub fn leaf_hash(&self, index: X) -> X {
        self.node(0, index)
    }

    /// The address of element `e` of leaf `index`.
    #[cfg(test)]
    pub fn leaf_element(&self, index: X, e: X) -> X {
        ((1 as X) << (self.depth + 1)) | (index << self.log_leaf_width()) | e
    }

    /// What every address holds in the empty tree: `Z_l` at a node of height
    /// `l` (`zeros[l]`, `Z_0 = 0`), 0 elsewhere (address 0, the leaf region).
    pub fn empty_value(&self, address: X, zeros: &[Fr]) -> Fr {
        if address == 0 || address >= ((1 as X) << (self.depth + 1)) {
            return Fr::from(0u64);
        }
        // the height of heap index h: D - floor(log2 h)
        let height = self.depth - (X::BITS - 1 - address.leading_zeros());
        zeros[height as usize]
    }

    /// The addresses of leaf `index`'s elements.
    fn leaf_elements(&self, id: PartyID, index: &XShare) -> Vec<XShare> {
        let base = (1 as X) << (self.depth + 1);
        let shifted = shl(index, self.log_leaf_width());
        (0..self.leaf_len as X)
            .map(|e| or_const(&shifted, id, base | e))
            .collect()
    }
}

impl Layout for Addressing {
    type Bound = Unbounded;

    fn depth(&self) -> u32 {
        self.depth
    }

    fn leaf_len(&self) -> usize {
        self.leaf_len
    }

    /// The hash region takes `D + 1` bits, the leaf region `D + LW`, so both
    /// fit `D + 1 + max(1, LW)`.
    fn log_addresses(&self) -> usize {
        self.depth as usize + 1 + self.log_leaf_width().max(1) as usize
    }

    fn log_capacity(&self) -> usize {
        self.log_addresses()
    }

    fn slot_reads(&self, id: PartyID, index: &XShare) -> Vec<XShare> {
        let mut out = Vec::with_capacity(self.reads_per_slot());
        for height in 0..self.depth {
            let position = shr(index, height);
            let node = or_const(&position, id, (1 as X) << (self.depth - height));
            out.push(xor_const(&node, id, 1));
        }
        out.push(or_const(index, id, (1 as X) << self.depth));
        out.extend(self.leaf_elements(id, index));
        out
    }

    fn slot_writes(&self, id: PartyID, index: &XShare) -> Vec<XShare> {
        let mut out = self.leaf_elements(id, index);
        out.push(or_const(index, id, (1 as X) << self.depth));
        for height in 1..=self.depth {
            let position = shr(index, height);
            out.push(or_const(&position, id, (1 as X) << (self.depth - height)));
        }
        out
    }

    fn mask_path(&self, index: &XShare) -> XShare {
        let mask = ((1 as X) << self.depth) - 1;
        XShare::new(index.a.0 & mask, index.b.0 & mask)
    }

    /// The dense DORAM holds every value as it is.
    fn read_offsets(&self) -> Vec<Fr> {
        vec![Fr::from(0u64); self.reads_per_slot()]
    }

    fn write_offsets(&self) -> Vec<Fr> {
        vec![Fr::from(0u64); self.reads_per_slot()]
    }

    fn empty_reads(&self) -> Vec<Fr> {
        let z = zeros(self.depth);
        self.clear_slot_reads(0)
            .iter()
            .map(|a| self.empty_value(*a, &z))
            .collect()
    }

    fn empty_writes(&self) -> Vec<Fr> {
        let z = zeros(self.depth);
        self.clear_slot_writes(0)
            .iter()
            .map(|a| self.empty_value(*a, &z))
            .collect()
    }

    /// Every hash-region address holds the zero subtree of its height, every
    /// other address 0; the bottom level built at once (the measured "setup"
    /// cost).
    fn build_empty(
        &self,
        net: &dyn Network,
        state: &mut Rep3State,
    ) -> Result<GigaDoramBn254, Refusal> {
        let z = zeros(self.depth);
        let n = 1usize << self.log_addresses();
        let ys: Vec<_> = (0..n)
            .map(|a| promote_public_y(state.id, self.empty_value(a as X, &z).into_bigint()))
            .collect();
        GigaDoramBn254::new_with_initial_bottom_level(self.config(), ys, &DynNet(net), state, None)
            .map_err(mpc)
    }

    /// Each leaf's hash and elements in leaf order, then the window root's
    /// siblings from height `log2 width` up (the loaded vector's order is
    /// leaves, hashes, siblings; [`crate::oram::window_vector`] reorders).
    fn window_reads(&self, id: PartyID, start: u64, width: usize) -> Vec<XShare> {
        let height = width.trailing_zeros();
        let mut out = Vec::new();
        for i in start..start + width as u64 {
            let index = promote_public(id, i as X);
            out.push(or_const(&index, id, (1 as X) << self.depth));
            out.extend(self.leaf_elements(id, &index));
        }
        for h in height..self.depth {
            let node = self.node(h, (start as X) >> h) ^ 1;
            out.push(promote_public(id, node));
        }
        out
    }
}

/// The address layout of a keyed map: a sparse tree of depth `depth` (32 to
/// [`MAX_MAP_DEPTH`]) whose leaves have `leaf_len` elements, in a DORAM
/// bounded by `2^log_capacity` distinct addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapAddressing {
    pub depth: u32,
    pub leaf_len: usize,
    pub log_capacity: usize,
}

impl MapAddressing {
    /// The layout, or why the depth, leaf length and capacity do not fit
    /// (the text names the field).
    pub fn checked(depth: u32, leaf_len: usize, log_capacity: usize) -> Result<Self, String> {
        if !(MIN_MAP_DEPTH..=MAX_MAP_DEPTH).contains(&depth) {
            return Err(format!(
                "`depth`: a keyed map is {MIN_MAP_DEPTH} to {MAX_MAP_DEPTH} deep (its path is the \
                 key's low bits), not {depth}"
            ));
        }
        check_leaf_len(
            leaf_len,
            3,
            "a keyed map's leaf holds the key, at least one value and the blinding: it",
        )?;
        let out = MapAddressing {
            depth,
            leaf_len,
            log_capacity,
        };
        if out.log_addresses() > MAX_LOG_ADDRESSES {
            return Err(format!(
                "`depth`: a depth of {depth} with leaves of {leaf_len} elements needs a {}-bit \
                 address space; the DORAM's is at most {MAX_LOG_ADDRESSES} bits",
                out.log_addresses()
            ));
        }
        if !(MIN_MAP_CAPACITY..=MAX_MAP_CAPACITY).contains(&log_capacity) {
            return Err(format!(
                "`capacity`: log2 of the distinct addresses the map may hold is \
                 {MIN_MAP_CAPACITY} to {MAX_MAP_CAPACITY}, not {log_capacity}"
            ));
        }
        out.try_config().map_err(|e| {
            format!("`capacity`: a capacity of 2^{log_capacity} the DORAM cannot take: {e}")
        })?;
        Ok(out)
    }

    /// The layout of a keyed map whose depth, leaf length and capacity
    /// REGISTER checked ([`Self::checked`]).
    pub fn new(depth: u32, leaf_len: usize, log_capacity: usize) -> Self {
        MapAddressing {
            depth,
            leaf_len,
            log_capacity,
        }
    }

    /// `LW`: the bits an element index takes within a leaf.
    pub fn log_leaf_width(&self) -> u32 {
        log_width(self.leaf_len)
    }

    /// The bits of a region's low part: a path, or a path and an element.
    fn region_shift(&self) -> u32 {
        self.depth + self.log_leaf_width()
    }

    /// The address of the hash node at `height` with `prefix` (the path
    /// shifted by the height; the root is height `D`, prefix 0).
    #[cfg(test)]
    pub fn node(&self, height: u32, prefix: X) -> X {
        ((height as X) << self.region_shift()) | prefix
    }

    /// The address of element `e` of the leaf at `path`.
    #[cfg(test)]
    pub fn leaf_element(&self, path: X, e: X) -> X {
        (((self.depth + 1) as X) << self.region_shift()) | (path << self.log_leaf_width()) | e
    }

    fn leaf_elements(&self, id: PartyID, path: &XShare) -> Vec<XShare> {
        let base = ((self.depth + 1) as X) << self.region_shift();
        let shifted = shl(path, self.log_leaf_width());
        (0..self.leaf_len as X)
            .map(|e| or_const(&shifted, id, base | e))
            .collect()
    }
}

impl Layout for MapAddressing {
    type Bound = Fill;

    fn depth(&self) -> u32 {
        self.depth
    }

    fn leaf_len(&self) -> usize {
        self.leaf_len
    }

    /// `ceil(log2 (D + 2))` region bits over `D + LW`.
    fn log_addresses(&self) -> usize {
        let regions = (self.depth + 2).next_power_of_two().trailing_zeros();
        (regions + self.region_shift()) as usize
    }

    fn log_capacity(&self) -> usize {
        self.log_capacity
    }

    fn slot_reads(&self, id: PartyID, path: &XShare) -> Vec<XShare> {
        let mut out = Vec::with_capacity(self.reads_per_slot());
        for height in 0..self.depth {
            let prefix = shr(path, height);
            let node = or_const(&prefix, id, (height as X) << self.region_shift());
            out.push(xor_const(&node, id, 1));
        }
        out.push(*path);
        out.extend(self.leaf_elements(id, path));
        out
    }

    fn slot_writes(&self, id: PartyID, path: &XShare) -> Vec<XShare> {
        let mut out = self.leaf_elements(id, path);
        out.push(*path);
        for height in 1..=self.depth {
            let prefix = shr(path, height);
            out.push(or_const(&prefix, id, (height as X) << self.region_shift()));
        }
        out
    }

    /// The depth is at most [`MAX_MAP_DEPTH`], below the address's width.
    fn mask_path(&self, x: &XShare) -> XShare {
        let mask = ((1 as X) << self.depth) - 1;
        XShare::new(x.a.0 & mask, x.b.0 & mask)
    }

    /// `Z_l` under the sibling of height `l`; 0 under the leaf hash (`Z_0`)
    /// and the elements.
    fn read_offsets(&self) -> Vec<Fr> {
        let z = zeros(self.depth);
        let mut out: Vec<Fr> = z[..self.depth as usize].to_vec();
        out.extend(vec![Fr::from(0u64); 1 + self.leaf_len]);
        out
    }

    /// 0 under the elements and the leaf hash; `Z_l` under the path node of
    /// height `l`, 1 to `D`.
    fn write_offsets(&self) -> Vec<Fr> {
        let z = zeros(self.depth);
        let mut out = vec![Fr::from(0u64); self.leaf_len + 1];
        out.extend_from_slice(&z[1..=self.depth as usize]);
        out
    }

    /// What an untouched address decodes to is the empty tree's value.
    fn empty_reads(&self) -> Vec<Fr> {
        self.read_offsets()
    }

    fn empty_writes(&self) -> Vec<Fr> {
        self.write_offsets()
    }

    /// Lazy: no bottom level; an address never written reads as 0, which the
    /// encoding turns into the empty node of its height.
    fn build_empty(
        &self,
        _net: &dyn Network,
        state: &mut Rep3State,
    ) -> Result<GigaDoramBn254, Refusal> {
        Ok(GigaDoramBn254::new(self.config(), state.id))
    }

    fn window_reads(&self, _id: PartyID, _start: u64, _width: usize) -> Vec<XShare> {
        vec![]
    }
}

/// `x >> l` on an XOR sharing: each component shifted (bitwise linear).
fn shr(x: &XShare, l: u32) -> XShare {
    XShare::new(x.a.0 >> l, x.b.0 >> l)
}

/// `x << l` on an XOR sharing.
fn shl(x: &XShare, l: u32) -> XShare {
    XShare::new(x.a.0 << l, x.b.0 << l)
}

/// `x ^ c` for a public `c`: XOR with `c`'s trivial sharing.
fn xor_const(x: &XShare, id: PartyID, c: X) -> XShare {
    let t = promote_public(id, c);
    XShare::new(x.a.0 ^ t.a.0, x.b.0 ^ t.b.0)
}

/// `x | c` for a public `c` whose bits are clear in `x`: the same XOR.
fn or_const(x: &XShare, id: PartyID, c: X) -> XShare {
    xor_const(x, id, c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_net::Network;
    use primitives::open_many;
    use primitives::run_parties;

    #[test]
    fn the_regions_do_not_overlap_and_fit_the_address_space() {
        for (depth, w) in [(1u32, 1usize), (4, 2), (4, 3), (16, 8), (16, 1)] {
            let a = Addressing::new(depth, w);
            let n = (1 as X) << a.log_addresses();
            let hash_end = (1 as X) << (depth + 1);
            assert_eq!(a.leaf_element(0, 0), hash_end);
            let last = a.leaf_element((1 << depth) - 1, w as X - 1);
            assert!(last < n, "depth {depth} w {w}: {last} < {n}");
            assert_eq!(a.node(depth, 0), 1, "the root");
            assert_eq!(a.leaf_hash(0), (1 as X) << depth);
            assert_eq!(a.leaf_hash((1 << depth) - 1), hash_end - 1);
        }
        assert_eq!(Addressing::new(16, 8).log_addresses(), 20);
        assert_eq!(Addressing::new(16, 1).log_addresses(), 18);
    }

    #[test]
    fn empty_values_are_the_zero_subtrees_by_height() {
        let a = Addressing::new(3, 2);
        let z = zeros(3);
        assert_eq!(a.empty_value(1, &z), z[3], "the root of an empty tree");
        assert_eq!(a.empty_value(2, &z), z[2]);
        assert_eq!(a.empty_value(7, &z), z[1]);
        assert_eq!(a.empty_value(8, &z), Fr::from(0u64), "a leaf hash");
        assert_eq!(a.empty_value(15, &z), Fr::from(0u64));
        assert_eq!(a.empty_value(0, &z), Fr::from(0u64));
        assert_eq!(a.empty_value(16, &z), Fr::from(0u64), "a leaf element");
        // the dense layout's empty reads and writes of leaf 0 by position
        assert_eq!(
            a.empty_reads(),
            vec![
                Fr::from(0u64),
                z[1],
                z[2],
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64)
            ]
        );
        assert_eq!(
            a.empty_writes(),
            vec![
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                z[1],
                z[2],
                z[3]
            ]
        );
    }

    /// The shared address arithmetic opens to the clear layout: leaf 5 of a
    /// depth-3 tree reads the siblings of nodes 13, 6, 3 (heap 12, 7, 2), its
    /// hash at 13 and its elements at 16 + 10, 16 + 11; it writes its
    /// elements, its hash and the nodes 6, 3, 1.
    #[test]
    fn shared_addresses_open_to_the_clear_layout() {
        let a = Addressing::new(3, 2);
        let [r0, r1, r2] = run_parties(|net| {
            let id = PartyID::try_from(net.id()).unwrap();
            let index = a.mask_path(&promote_public(id, 5 | ((1 as X) << 7)));
            let reads = open_many(&a.slot_reads(id, &index), &net);
            let writes = open_many(&a.slot_writes(id, &index), &net);
            let window = open_many(&a.window_reads(id, 4, 2), &net);
            (reads, writes, window)
        })
        .unwrap();
        assert_eq!(r0, r1);
        assert_eq!(r0, r2);
        let (reads, writes, window) = r0;
        assert_eq!(reads, vec![12, 7, 2, 13, 26, 27]);
        assert_eq!(writes, vec![26, 27, 13, 6, 3, 1]);
        assert_eq!(a.clear_slot_reads(5), reads);
        assert_eq!(a.clear_slot_writes(5), writes);
        // leaves 4 and 5 (hashes 12, 13; elements 24, 25, 26, 27), then the
        // siblings of node 6 (height 1) and node 3 (height 2): 7 and 2
        assert_eq!(window, vec![12, 24, 25, 13, 26, 27, 7, 2]);
    }

    /// The keyed map's regions: height `l` at `l << (D + LW)`, the leaves at
    /// `(D + 1) << (D + LW)`; the whole space `ceil(log2 (D + 2)) + D + LW`
    /// bits, within the DORAM's 126.
    #[test]
    fn map_regions_are_disjoint_and_bounded() {
        let m = MapAddressing::new(64, 3, 18);
        assert_eq!(m.log_leaf_width(), 2);
        assert_eq!(m.log_addresses(), 7 + 64 + 2);
        let shift = 66;
        assert_eq!(m.node(0, 5), 5);
        assert_eq!(m.node(1, 2), (1 << shift) | 2);
        assert_eq!(m.node(64, 0), 64 << shift, "the root");
        assert_eq!(m.leaf_element(5, 2), (65 << shift) | (5 << 2) | 2);
        assert!(m.leaf_element(u64::MAX as X, 2) < (1 as X) << m.log_addresses());
        assert_eq!(MapAddressing::new(116, 8, 18).log_addresses(), 7 + 116 + 3);
    }

    #[test]
    fn map_layout_checks_name_the_field() {
        assert!(
            MapAddressing::checked(31, 3, 18)
                .unwrap_err()
                .contains("`depth`")
        );
        assert!(
            MapAddressing::checked(121, 3, 18)
                .unwrap_err()
                .contains("`depth`")
        );
        assert!(
            MapAddressing::checked(64, 2, 18)
                .unwrap_err()
                .contains("`leaf_len`")
        );
        assert!(
            MapAddressing::checked(64, 3, 7)
                .unwrap_err()
                .contains("`capacity`")
        );
        assert!(
            MapAddressing::checked(120, 8, 18)
                .unwrap_err()
                .contains("address space")
        );
        assert!(MapAddressing::checked(116, 8, 18).is_ok());
        assert!(MapAddressing::checked(117, 4, 18).is_ok());
        assert!(
            MapAddressing::checked(118, 4, 18)
                .unwrap_err()
                .contains("address space")
        );
        assert!(MapAddressing::checked(64, 64, 36).is_ok());
        assert!(
            MapAddressing::checked(64, 65, 18)
                .unwrap_err()
                .contains("`leaf_len`")
        );
        for capacity in 37..=40 {
            assert!(
                MapAddressing::checked(64, 3, capacity)
                    .unwrap_err()
                    .contains("`capacity`")
            );
            // past the bound, the hierarchy has nine levels: the DORAM's own
            // check refuses it too
            let m = MapAddressing::new(64, 3, capacity);
            assert!(m.try_config().unwrap_err().contains("alibi"), "{capacity}");
        }
    }

    /// The dense tree's shapes: a DORAM of 2^4 to 2^22 addresses, a leaf of
    /// 1 to 64 elements; depth 1 with leaves of 1 or 2 is a DORAM of 2^3,
    /// whose speed cache cannot hold the stash. Every shape the check passes
    /// has a configuration.
    #[test]
    fn dense_layout_checks_name_the_field() {
        for (depth, w) in [(1u32, 3usize), (2, 1), (16, 8), (18, 8), (20, 2), (4, 64)] {
            let a = Addressing::checked(depth, w).unwrap();
            a.config();
        }
        for (depth, w, field) in [
            (0u32, 1usize, "`depth`"),
            (21, 1, "`depth`"),
            (19, 8, "2^23"),
            (28, 8, "`depth`"),
            (1, 1, "stash must fit inside the speed cache"),
            (1, 2, "stash must fit inside the speed cache"),
            (4, 0, "`leaf_len`"),
            (4, 65, "`leaf_len`"),
        ] {
            let err = Addressing::checked(depth, w).unwrap_err();
            assert!(err.contains(field), "{depth} {w}: {err}");
        }
    }

    #[test]
    fn the_shape_check_bounds_the_probe() {
        let tree = |probe: usize| -> TreeLayout {
            serde_json::from_value(serde_json::json!({
                "depth": 16, "leaf_len": 8, "probe": probe, "access": "oblivious"
            }))
            .unwrap()
        };
        assert!(check_shape(&tree(16)).is_ok());
        for probe in [0, 17] {
            assert!(check_shape(&tree(probe)).unwrap_err().contains("`probe`"));
        }
    }

    /// A keyed slot's shared addresses open to the clear layout, in the dense
    /// brick's read and write order: the path 0b1011 (11) of a depth-4 map
    /// reads the siblings (0, 10), (1, 4), (2, 3), (3, 0), its leaf hash
    /// (0, 11) and its elements; it writes the elements, the hash and the
    /// nodes (1, 5), (2, 2), (3, 1), (4, 0).
    #[test]
    fn map_addresses_open_to_the_clear_layout() {
        let m = MapAddressing {
            depth: 4,
            leaf_len: 3,
            log_capacity: 8,
        };
        let s = m.region_shift(); // 4 + 2
        let [r0, r1, r2] = run_parties(|net| {
            let id = PartyID::try_from(net.id()).unwrap();
            // the key's low 4 bits: 0xfb masks to 11
            let path = m.mask_path(&promote_public(id, 0xfb));
            let reads = open_many(&m.slot_reads(id, &path), &net);
            let writes = open_many(&m.slot_writes(id, &path), &net);
            (reads, writes)
        })
        .unwrap();
        assert_eq!(r0, r1);
        assert_eq!(r0, r2);
        let (reads, writes) = r0;
        let n = |h: X, p: X| (h << s) | p;
        let e = |i: X| (5 << s) | (11 << 2) | i;
        assert_eq!(
            reads,
            vec![
                n(0, 10),
                n(1, 4),
                n(2, 3),
                n(3, 0),
                n(0, 11),
                e(0),
                e(1),
                e(2)
            ]
        );
        assert_eq!(
            writes,
            vec![
                e(0),
                e(1),
                e(2),
                n(0, 11),
                n(1, 5),
                n(2, 2),
                n(3, 1),
                n(4, 0)
            ]
        );
        assert_eq!(m.clear_slot_reads(11), reads);
        assert_eq!(m.clear_slot_writes(11), writes);
    }

    /// The encoding offsets: `Z_l` under a sibling of height `l` and under a
    /// written node of height `l`, 0 under the leaf hash and the elements, so
    /// an untouched address (0) decodes to the empty tree's value.
    #[test]
    fn map_offsets_are_the_empty_tree() {
        let m = MapAddressing {
            depth: 4,
            leaf_len: 3,
            log_capacity: 8,
        };
        let z = zeros(4);
        let zero = Fr::from(0u64);
        assert_eq!(
            m.read_offsets(),
            vec![z[0], z[1], z[2], z[3], zero, zero, zero, zero]
        );
        assert_eq!(
            m.write_offsets(),
            vec![zero, zero, zero, zero, z[1], z[2], z[3], z[4]]
        );
        assert_eq!(m.empty_reads(), m.read_offsets());
        assert_eq!(z[0], zero);
    }

    #[test]
    fn the_hierarchy_follows_the_capacity() {
        assert_eq!(hierarchy(8), (1, 1));
        assert_eq!(hierarchy(12), (2, 4));
        assert_eq!(hierarchy(17), (4, 3));
        assert_eq!(hierarchy(18), (4, 4));
        assert_eq!(hierarchy(20), (4, 4));
        let c = MapAddressing::new(64, 3, 18).config();
        assert_eq!(
            (c.log_address_space_size, c.log_capacity, c.num_levels),
            (73, 18, 4)
        );
        assert!(!c.is_dense());
        assert!(Addressing::new(16, 8).config().is_dense());
    }

    // ---- testvectors/manifest_limits.json ----

    const LIMITS: &str = "testvectors/manifest_limits.json";

    /// The manifest bounds a client mirrors so it refuses what REGISTER
    /// refuses: the clear tree's depth and window (sidecar-core's manifest),
    /// a keyed map's depth (this brick) and a registered name's length
    /// (sidecar-core's schnorr).
    fn limits() -> serde_json::Value {
        use sidecar_core::manifest::{MAX_TREE_DEPTH, MAX_TREE_WINDOW};
        serde_json::json!({
            "description": "The manifest bounds REGISTER enforces and pss-client mirrors: a clear tree's depth (1 ..= max_tree_depth) and window (at most max_tree_window), a keyed map's depth (min_map_depth ..= max_map_depth) and a registered name's length in bytes (at most max_name_bytes). Written by sidecar-oblivious's layout tests (write_manifest_limits_vector).",
            "max_tree_depth": MAX_TREE_DEPTH,
            "max_tree_window": MAX_TREE_WINDOW,
            "min_map_depth": MIN_MAP_DEPTH,
            "max_map_depth": MAX_MAP_DEPTH,
            "max_name_bytes": sidecar_core::schnorr::MAX_NAME_BYTES,
        })
    }

    /// The committed vector is what this code states.
    #[test]
    fn the_manifest_limits_vector_matches() {
        let path = sidecar_core::testing::artifacts::repo().join(LIMITS);
        let committed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(committed, limits(), "rerun write_manifest_limits_vector");
    }

    /// `cargo test -p sidecar-oblivious write_manifest_limits_vector -- --ignored`.
    #[test]
    #[ignore = "writes testvectors/; run on purpose"]
    fn write_manifest_limits_vector() {
        let path = sidecar_core::testing::artifacts::repo().join(LIMITS);
        std::fs::write(
            path,
            serde_json::to_string_pretty(&limits()).unwrap() + "\n",
        )
        .unwrap();
    }
}
