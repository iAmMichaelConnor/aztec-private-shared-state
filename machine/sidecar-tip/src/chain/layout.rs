//! Where the tip contract keeps what the chain reader reads: the queue's
//! storage slots, the slot of a `Map` entry as aztec-nr derives it, the
//! log-tag rule, and the tag of the on-chain request log (the sealed-thirds
//! log's domain and tag are [`crate::state::chain`]'s). Everything here must
//! equal what aztec-nr v6.0.0 and `noir/pss_public_contract`
//! compute; the tests pin each rule to values aztec.js 6.0.0 computed for
//! the same inputs, and write `testvectors/queue.json` (the queue's slots at
//! several base slots and the `done` codes), which pss-client and the Noir
//! intake vector program check against queue.ts and queue.nr.

use sidecar_core::Fr;
use sidecar_core::hash::poseidon2_hash_with_separator;

/// `DOM_SEP__PUBLIC_STORAGE_MAP_SLOT` of protocol_types v6.0.0
/// (`DomainSeparator.PUBLIC_STORAGE_MAP_SLOT` in aztec.js).
pub const PUBLIC_STORAGE_MAP_SLOT: u32 = 4015149901;

/// The storage slot of `map.at(key)` for a `Map` at `map_slot`: aztec-nr's
/// `derive_storage_slot_in_map`, `poseidon2_hash_with_separator([map_slot,
/// key.to_field()], DOM_SEP__PUBLIC_STORAGE_MAP_SLOT)`. A `u64` or `bool` key
/// is its integer value as a field; a `Field` key is itself.
pub fn map_slot(map_slot: Fr, key: Fr) -> Fr {
    poseidon2_hash_with_separator(&[map_slot, key], PUBLIC_STORAGE_MAP_SLOT)
}

/// The queue's storage, from the slot the app's `#[storage]` struct gives its
/// `Queue` (`queue.nr`: one `StateVariable<6>`): +0 `requests`
/// (`Map<u64, PublicMutable<Field>>`), +1 `tail` (`u64`), +2 and +3 `head`
/// (`Head {index: u64, since: u32}`, packed one field per member), +4 `seen`
/// (`Map<Field, PublicMutable<bool>>`), +5 `done` (`Map<u64,
/// PublicMutable<u8>>`).
///
/// The base slot is the app's: aztec-nr numbers `#[storage]` fields from 1 in
/// declaration order, each taking its state variable's slot count, and writes
/// the result into the contract artifact's `STORAGE_LAYOUT_<Contract>` global
/// (`PssPublicTest`: `config` 1, `vk_hash` 11, `queue` 15, `pool` 21). Take it
/// from there. What an intake keeps in the contract beside the queue has
/// its own layout (`crate::intake::IntakeLayout`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueLayout {
    pub base: Fr,
}

impl QueueLayout {
    pub fn new(base: Fr) -> Self {
        QueueLayout { base }
    }

    fn at(&self, offset: u64) -> Fr {
        self.base + Fr::from(offset)
    }

    /// `requests[index]`: the chain request id at `index`.
    pub fn request(&self, index: u64) -> Fr {
        map_slot(self.at(0), Fr::from(index))
    }

    /// `tail`: the next free index.
    pub fn tail(&self) -> Fr {
        self.at(1)
    }

    /// `head.index`: the index of the request to process next.
    pub fn head_index(&self) -> Fr {
        self.at(2)
    }

    /// `head.since` (`head_since`): the block at which the head last moved.
    pub fn head_since(&self) -> Fr {
        self.at(3)
    }

    /// `seen[request_id]`.
    pub fn seen(&self, request_id: Fr) -> Fr {
        map_slot(self.at(4), request_id)
    }

    /// `done[index]`: [`DONE_PENDING`], [`DONE_APPLIED`] or [`DONE_SKIPPED`].
    pub fn done(&self, index: u64) -> Fr {
        map_slot(self.at(5), Fr::from(index))
    }
}

/// `done[index]` of an entry not yet finished (the storage default): queue.nr's
/// `DONE_PENDING`.
pub const DONE_PENDING: u8 = 0;
/// `done[index]` of an entry `apply` finished, `ok` true or false: queue.nr's
/// `DONE_APPLIED`.
pub const DONE_APPLIED: u8 = 1;
/// `done[index]` of an entry `skip()` finished: queue.nr's `DONE_SKIPPED`.
pub const DONE_SKIPPED: u8 = 2;

// The log-tag domains. `REQUEST_DOMAIN` (the on-chain
// intake request log that intake emits) is 0x70737271, ASCII "psrq", the
// value `pss_public_contract/src/domains.nr` defines; the sealed-thirds log's
// domain is `state::chain::PSS_STATE` under the same rule. They are the
// `dom_sep: u32` of protocol_types' `compute_log_tag(raw_tag, dom_sep)`, so
// they must be u32. The reader must look the logs up under the tags the
// contract emits; neither equals a `DOM_SEP__*` value of protocol_types
// v6.0.0, so a PSS tag never equals an Aztec message or event tag for the
// same raw value. The Noir intake and apply functions must use the same
// values (testvectors/log_tags.json pins them, with tags aztec.js computed);
// changing one strands every log already on chain under the old tag.
/// The domain of the on-chain request log's tag.
pub const REQUEST_DOMAIN: u32 = 0x7073_7271;

/// protocol_types' `compute_log_tag(raw_tag, dom_sep)`:
/// `poseidon2_hash_with_separator([raw_tag], dom_sep)`, the value a public log
/// carries in its field 0 and `getPublicLogsByTags` matches.
pub fn compute_log_tag(raw_tag: Fr, domain: u32) -> Fr {
    poseidon2_hash_with_separator(&[raw_tag], domain)
}

/// The tag of chain request `request_id`'s on-chain request log (and,
/// before the kernel silos it, of its secret-shared on-chain request log).
pub fn request_log_tag(request_id: Fr) -> Fr {
    compute_log_tag(request_id, REQUEST_DOMAIN)
}

/// `DOM_SEP__PRIVATE_LOG_FIRST_FIELD` of protocol_types v6.0.0.
pub const PRIVATE_LOG_FIRST_FIELD: u32 = 2769976252;

/// A private log's first field as the chain shows it: the tag `contract`
/// emitted it under, siloed by the kernel with the contract's address
/// (protocol_types' `compute_siloed_private_log_first_field`), the tag
/// `getPrivateLogsByTags` matches.
pub fn siloed_private_log_tag(contract: Fr, tag: Fr) -> Fr {
    poseidon2_hash_with_separator(&[contract, tag], PRIVATE_LOG_FIRST_FIELD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidecar_core::field::{fr_from_hex, fr_to_hex};
    use sidecar_test_fixtures::dirs::repo;

    fn f(hex: &str) -> Fr {
        fr_from_hex(hex).unwrap()
    }

    // Known answers from aztec.js 6.0.0 (`deriveStorageSlotInMap` of
    // @aztec-labs/stdlib/hash), for a queue at base slot 12; the last row is
    // protocol_types' own map-slot test vector.
    #[test]
    fn map_slots_match_aztec_js() {
        let q = QueueLayout::new(Fr::from(12u64));
        let cases = [
            (
                q.request(0),
                "0x0b8231a42f1b14f6d5723e64e4e4d3c4061c684f446e5eaaea1b1848ce4fed97",
            ),
            (
                q.request(1),
                "0x1734bbf673a816bc80a7223360b826f1f446bc59afd737ff2119a4e6cb129e2d",
            ),
            (
                q.request(2),
                "0x124aa1a0ff4e1a94901da7f3ade46128d57894d0044e9466670567340b9a009d",
            ),
            (
                q.seen(Fr::from(0xa1u64)),
                "0x2508af14acd99fac2f9e3c66b2042e61a52510ba7070c8d11ef477add048b2c2",
            ),
            (
                q.done(0),
                "0x2acc00a91751b6025e9506841accdb3c82ffc1dbfb4b1222a766f5463862ecec",
            ),
            (
                map_slot(
                    f("0x132258fb6962c4387ba659d9556521102d227549a386d39f0b22d1890d59c2b5"),
                    f("0x302dbc2f9b50a73283d5fb2f35bc01eae8935615817a0b4219a057b2ba8a5a3f"),
                ),
                "0x2d225f361108379adc2da91378b9702675c5546b57e78bafc1e74ec7fec55967",
            ),
        ];
        for (slot, expected) in cases {
            assert_eq!(fr_to_hex(slot), expected);
        }
    }

    #[test]
    fn the_plain_slots_follow_the_base() {
        let q = QueueLayout::new(Fr::from(12u64));
        assert_eq!(q.tail(), Fr::from(13u64));
        assert_eq!(q.head_index(), Fr::from(14u64));
        assert_eq!(q.head_since(), Fr::from(15u64));
    }

    // Known answers from aztec.js 6.0.0 (`computeLogTag` of
    // @aztec-labs/stdlib/hash). Tags under the same rule also find the logs
    // that Noir contracts emitted with aztec-nr's `compute_log_tag` on a local
    // network (tests/fixtures/logs.json, tests/chain.rs).
    #[test]
    fn log_tags_match_aztec_js() {
        assert_eq!(
            fr_to_hex(request_log_tag(Fr::from(0xa1u64))),
            "0x07384a321e3008a4537889580343a86a74a8e8cd74f5ac9d9ee887389c9101d8"
        );
        assert_eq!(REQUEST_DOMAIN.to_be_bytes(), *b"psrq");
        // aztec.js 6.0.0 computeSiloedPrivateLogFirstField(0xc0ffee, 0xa1)
        assert_eq!(
            fr_to_hex(siloed_private_log_tag(
                Fr::from(0xc0ffeeu64),
                Fr::from(0xa1u64)
            )),
            "0x2302a706031637b58538dbfaee093eb9d528def2fe2e491ad8c36fa794930ee2"
        );
    }

    const QUEUE_VECTORS: &str = "testvectors/queue.json";

    /// testvectors/queue.json: the queue's slots at three base slots (12,
    /// whose map slots aztec.js computed above; `PssPublicTest`'s 15; and
    /// one near the field's end), the map entries at the first indices, a
    /// large one and the largest u64, and the `done` codes.
    fn queue_vectors() -> serde_json::Value {
        use serde_json::json;
        let h = |v: Fr| json!(fr_to_hex(v));
        let near_end = Fr::from(0u64) - Fr::from(16u64);
        let cases: Vec<serde_json::Value> = [
            ("base 12", Fr::from(12u64)),
            ("base 15 (PssPublicTest's queue)", Fr::from(15u64)),
            ("base p - 16, the field's last base with room for six slots", near_end),
        ]
        .iter()
        .map(|(name, base)| {
            let q = QueueLayout::new(*base);
            let indices = [0u64, 1, 2, 1 << 40, u64::MAX];
            let ids = [Fr::from(0xa1u64), Fr::from(0u64) - Fr::from(1u64)];
            json!({
                "name": name,
                "base": h(*base),
                "requests": indices.iter().map(|&i| json!({"index": format!("{i:#x}"), "slot": h(q.request(i))})).collect::<Vec<_>>(),
                "tail": h(q.tail()),
                "head_index": h(q.head_index()),
                "head_since": h(q.head_since()),
                "seen": ids.iter().map(|&id| json!({"request_id": h(id), "slot": h(q.seen(id))})).collect::<Vec<_>>(),
                "done": indices.iter().map(|&i| json!({"index": format!("{i:#x}"), "slot": h(q.done(i))})).collect::<Vec<_>>(),
            })
        })
        .collect();
        json!({
            "description": "The tip queue's storage slots and done codes (pss_public_contract queue.nr's Queue). Written by sidecar-tip src/chain/layout.rs; read by sidecar-core tests/vectors.rs, pss-client test/result.test.ts (queue.ts QueueSlots and the DONE_ codes) and testvectors/noir/tip_intake_vectors (queue.nr's Queue and DONE_ globals).",
            "rule": "from the slot base the app's #[storage] gives its Queue: requests = base + 0 (Map<u64, Field>), tail = base + 1, head.index = base + 2, head.since = base + 3 (Head packed one field per member), seen = base + 4 (Map<Field, bool>), done = base + 5 (Map<u64, u8>); the slot of map.at(key) is poseidon2_hash_with_separator([map_slot, key], DOM_SEP__PUBLIC_STORAGE_MAP_SLOT), a u64 key as its integer value (aztec-nr derive_storage_slot_in_map, aztec.js deriveStorageSlotInMap); an index is a u64 in hex",
            "map_slot_domain": PUBLIC_STORAGE_MAP_SLOT,
            "done": {"pending": DONE_PENDING, "applied": DONE_APPLIED, "skipped": DONE_SKIPPED},
            "vectors": cases,
        })
    }

    /// The committed testvectors/queue.json is what QueueLayout computes.
    #[test]
    fn the_queue_vectors_match() {
        let text = std::fs::read_to_string(repo().join(QUEUE_VECTORS)).unwrap();
        let committed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(committed, queue_vectors(), "rerun write_queue_vectors");
        assert_eq!(
            committed["vectors"][0]["done"][0]["slot"],
            "0x2acc00a91751b6025e9506841accdb3c82ffc1dbfb4b1222a766f5463862ecec"
        );
    }

    /// `cargo test -p sidecar-tip write_queue_vectors -- --ignored`.
    #[test]
    #[ignore = "writes testvectors/; run on purpose"]
    fn write_queue_vectors() {
        let text = serde_json::to_string_pretty(&queue_vectors()).unwrap() + "\n";
        std::fs::write(repo().join(QUEUE_VECTORS), text).unwrap();
    }

    // testvectors/log_tags.json, which the Noir side and pss-client check
    // too, holds these constants and tags aztec.js computed with them.
    #[test]
    fn the_constants_are_the_vector_files() {
        let file: serde_json::Value =
            serde_json::from_str(include_str!("../../../../testvectors/log_tags.json")).unwrap();
        assert_eq!(file["request_domain"], u64::from(REQUEST_DOMAIN));
        for v in file["vectors"].as_array().unwrap() {
            let id = f(v["chain_request_id"].as_str().unwrap());
            assert_eq!(fr_to_hex(request_log_tag(id)), v["request_tag"]);
        }
    }
}
