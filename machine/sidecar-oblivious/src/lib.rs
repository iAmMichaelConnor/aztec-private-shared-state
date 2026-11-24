//! The oblivious bricks: a tree-valued node-held key with `access:
//! oblivious`, whose leaves and hashes live in a three-party distributed
//! oblivious RAM (GigaDORAM, `vendor/`) and whose position index, or key, is
//! a secret-shared input. [`ObliviousTree`] is the dense tree's state holder
//! (docs/ARCHITECTURE.md section 6, "The oblivious tree"), [`ObliviousMap`] the
//! keyed map's (docs/ARCHITECTURE.md section 6, "The oblivious sparse map");
//! both are [`holder::Holder`] over a [`Layout`], behind sidecar-core's state
//! seam, and sidecar-tip pairs each with its `TipState`.

pub mod fill;
pub mod holder;
pub mod layout;
pub mod oram;

pub use holder::{DEFAULT_MAP_CAPACITY_LOG2, Holder, ObliviousMap, ObliviousTree};
pub use layout::{
    Addressing, Layout, MAX_MAP_CAPACITY, MAX_MAP_DEPTH, MIN_MAP_CAPACITY, MIN_MAP_DEPTH,
    MapAddressing, check_shape,
};
pub use oram::{Doram, Journal, SlotJournal};
