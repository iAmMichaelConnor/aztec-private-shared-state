//! Where an upgradable tip contract keeps its circuit pins, and which
//! contract manifest version they name at a block (ARCHITECTURE.md section
//! 7, "Upgrades").
//!
//! pss_public_contract's `CircuitUpgrades` stores the scheduled pins
//! (`UpgradedPins`: the class id, then the circuit pins, whose first field is
//! the contract manifest's hash, `2P + 2` fields for a package capacity `P`)
//! in aztec-nr's `DelayedPublicMutable`, from the slot the contract manifest
//! names (`storage.circuit_pins`): `+0` a metadata field whose low 32 bits
//! are the time of change, `+1 ..= +N` the value before the change, `+N + 1
//! ..= +2N` the value after it, then their hash. The value in force at a
//! block whose timestamp is `t` is the one after the change when
//! `t >= time of change`, else the one before; all zero is the
//! never-written value, under which the constructor's pins are in force
//! (`TipPins.circuits.manifest_hash`, after the stale period and the three
//! `sig` keys in the Config's packing).
//!
//! The nodes and the scheduler read these slots on their own Aztec node, at
//! the block they are reading, and run a round only under the version the
//! pins in force name. Nothing read here is trusted for soundness: the
//! contract verifies every result under the pins it holds, so a wrong read
//! can only delay (invariant 13).

use crate::field::Fr;
use crate::request::NODES;

/// The index of the class id in `UpgradedPins`' packing.
pub const CLASS_ID: u64 = 0;
/// The index of the contract manifest's hash in `UpgradedPins`' packing.
pub const MANIFEST_HASH: u64 = 1;

/// The packed length of `UpgradedPins` for a package capacity `capacity`:
/// the class id, the manifest hash, the package list and the vk hashes.
pub fn pins_len(capacity: usize) -> u64 {
    2 * capacity as u64 + 2
}

/// The slot of the constructor's manifest hash (`TipPins.circuits`'s first
/// field): after `stale_blocks` (two fields) and the three `sig` keys (two
/// fields each), `stale_blocks_slot` being the namespace's
/// `TipConfig.stale_blocks` slot ([`crate::key_epoch::epoch0_sig_slots`]
/// reads the keys before it).
pub fn constructor_manifest_hash_slot(stale_blocks_slot: Fr) -> Fr {
    stale_blocks_slot + Fr::from(2 + 2 * NODES as u64)
}

/// The slots of the pins' stored value that say which version is in
/// force, from the pins' slot `slot` for a package capacity `capacity`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinsSlots {
    /// The metadata field (the time of change in its low 32 bits).
    pub metadata: Fr,
    /// The class id and the manifest hash before the change.
    pub before: [Fr; 2],
    /// The class id and the manifest hash after the change.
    pub after: [Fr; 2],
}

impl PinsSlots {
    pub fn new(slot: Fr, capacity: usize) -> Self {
        let n = pins_len(capacity);
        let at = |k: u64| slot + Fr::from(k);
        PinsSlots {
            metadata: slot,
            before: [at(1 + CLASS_ID), at(1 + MANIFEST_HASH)],
            after: [at(1 + n + CLASS_ID), at(1 + n + MANIFEST_HASH)],
        }
    }
}

/// One half of the stored value: the class id and the manifest hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pinned {
    pub class_id: Fr,
    pub manifest_hash: Fr,
}

/// The stored pins as read: the time of change and both halves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredPins {
    pub time_of_change: u64,
    pub before: Pinned,
    pub after: Pinned,
}

impl StoredPins {
    /// From the metadata field and the two halves' fields.
    pub fn new(metadata: Fr, before: [Fr; 2], after: [Fr; 2]) -> Self {
        let half = |[class_id, manifest_hash]: [Fr; 2]| Pinned {
            class_id,
            manifest_hash,
        };
        StoredPins {
            time_of_change: low_u32(metadata),
            before: half(before),
            after: half(after),
        }
    }

    /// The half in force at a block of timestamp `timestamp`; `None` when
    /// it is the never-written value (the constructor's pins are in force).
    pub fn in_force(&self, timestamp: u64) -> Option<Pinned> {
        let pinned = if timestamp >= self.time_of_change {
            self.after
        } else {
            self.before
        };
        (pinned.manifest_hash != Fr::from(0u64)).then_some(pinned)
    }

    /// The change scheduled after `timestamp`, if any: its time and the pins
    /// it brings.
    pub fn scheduled(&self, timestamp: u64) -> Option<(u64, Pinned)> {
        (timestamp < self.time_of_change && self.after != self.before)
            .then_some((self.time_of_change, self.after))
    }
}

/// The low 32 bits of a field.
fn low_u32(value: Fr) -> u64 {
    let bytes = crate::field::fr_to_be_bytes(value);
    u64::from(u32::from_be_bytes([
        bytes[28], bytes[29], bytes[30], bytes[31],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // aztec-nr's metadata field: the value's time of change in the low 32
    // bits, the delay's time of change and options above (packed as
    // `DelayedPublicMutableValues::pack` does).
    fn metadata(time_of_change: u64, delay_change: u64) -> Fr {
        Fr::from(time_of_change) + Fr::from(delay_change) * Fr::from(1u64 << 32)
    }

    #[test]
    fn the_slots_follow_the_delayed_value_s_packing() {
        let s = PinsSlots::new(Fr::from(100u64), 2);
        assert_eq!(pins_len(2), 6);
        assert_eq!(s.metadata, Fr::from(100u64));
        assert_eq!(s.before, [Fr::from(101u64), Fr::from(102u64)]);
        assert_eq!(s.after, [Fr::from(107u64), Fr::from(108u64)]);
        assert_eq!(
            constructor_manifest_hash_slot(Fr::from(1u64)),
            Fr::from(9u64)
        );
    }

    #[test]
    fn the_value_in_force_switches_at_the_time_of_change() {
        let before = [Fr::from(0xc1u64), Fr::from(0xa1u64)];
        let after = [Fr::from(0xc1u64), Fr::from(0xa2u64)];
        let pins = StoredPins::new(metadata(1000, 77), before, after);
        assert_eq!(pins.time_of_change, 1000);
        assert_eq!(pins.in_force(999).unwrap().manifest_hash, Fr::from(0xa1u64));
        assert_eq!(
            pins.in_force(1000).unwrap().manifest_hash,
            Fr::from(0xa2u64)
        );
        assert_eq!(pins.scheduled(999).unwrap().0, 1000);
        assert_eq!(pins.scheduled(1000), None);
        // a first upgrade: before it, the never-written half
        let first = StoredPins::new(metadata(1000, 0), [Fr::from(0u64); 2], after);
        assert_eq!(first.in_force(999), None);
        assert_eq!(
            first.in_force(1001).unwrap().manifest_hash,
            Fr::from(0xa2u64)
        );
        // never written at all
        let unset = StoredPins::new(Fr::from(0u64), [Fr::from(0u64); 2], [Fr::from(0u64); 2]);
        assert_eq!(unset.in_force(5), None);
        assert_eq!(unset.scheduled(5), None);
    }
}
