//! The audit circuit: the machine-defined circuit that recomputes, from the
//! nodes' pairs, the public hashes of node-held tip state (docs/
//! ARCHITECTURE.md section 6, "Node-held state", the audit). Each of its
//! ITEMS items is the preimage of one hash, laid out by the node:
//!
//!   a flat key's version   [pss.tip.state, namespace, slot, vector...]   -> its commitment
//!   a tree leaf            [pss.tip.leaf, namespace, key, index, leaf...] -> its leaf hash
//!
//! the labels, the namespace, the key and the index public, the stored
//! elements as the node holds them (pairs, or public values). Item k's
//! digest is the Poseidon2 hash of its first len[k] fields; an item of
//! length 0 is padding and gives 0. The digests are opened as public
//! outputs, which the nodes compare with the commitment the chain holds and
//! the leaf hashes of their clear trees: both are public already, so the
//! audit opens nothing new.
//!
//! Public inputs (1 + 2 * ITEMS), in ACIR order: [namespace, len[0..ITEMS],
//! digest[0..ITEMS]].

use total::hash::p2_hash_var_or;

/// The items of one audit round: a flat key is one item, a tree key one
/// item per stored leaf.
pub global ITEMS: u32 = 16;
/// The fields of one item's preimage: 3 or 4 public fields, then the
/// stored elements.
pub global FIELDS: u32 = 16;

/// Item `k` of the flat preimage.
fn item(preimage: [Field; ITEMS * FIELDS], k: u32) -> [Field; FIELDS] {
    let mut out = [0; FIELDS];
    for j in 0..FIELDS {
        out[j] = preimage[k * FIELDS + j];
    }
    out
}

/// The digest of every item; 0 for an item of length 0 or longer than
/// FIELDS (the node never sends one). Every non-empty item hashes under
/// `namespace` (its second field).
pub fn digests(
    namespace: Field,
    len: [Field; ITEMS],
    preimage: [Field; ITEMS * FIELDS],
) -> [Field; ITEMS] {
    let mut out = [0; ITEMS];
    for k in 0..ITEMS {
        let fields = item(preimage, k);
        let used = len[k] != 0;
        assert(!used | (fields[1] == namespace), "an audited item hashes under another namespace");
        let (digest, ok) = p2_hash_var_or(fields, len[k]);
        out[k] = if used & ok { digest } else { 0 };
    }
    out
}

fn main(
    namespace: pub Field,
    len: pub [Field; ITEMS],
    preimage: [Field; ITEMS * FIELDS],
) -> pub [Field; ITEMS] {
    digests(namespace, len, preimage)
}

mod tests {
    use super::{digests, FIELDS, ITEMS};
    use total::hash::{p2_hash, p2_hash_sep};

    global NS: Field = 0xc0ffee;
    // ASCII "pss.tip.state" and "pss.tip.leaf" read big-endian (pss_core
    // tip::slot and tip::tree).
    global STATE: Field = 0x7073732e7469702e7374617465;
    global LEAF: Field = 0x7073732e7469702e6c656166;

    fn place<let N: u32>(
        mut preimage: [Field; ITEMS * FIELDS],
        k: u32,
        fields: [Field; N],
    ) -> [Field; ITEMS * FIELDS] {
        for j in 0..N {
            preimage[k * FIELDS + j] = fields[j];
        }
        preimage
    }

    #[test]
    fn a_flat_commitment_and_two_leaves() {
        let mut preimage = [0; ITEMS * FIELDS];
        let mut len = [0; ITEMS];
        preimage = place(preimage, 0, [STATE, NS, 0xa002, 100, 200, 7]);
        len[0] = 6;
        preimage = place(preimage, 1, [LEAF, NS, 0xa003, 0, 5, 9]);
        len[1] = 6;
        preimage = place(preimage, 2, [LEAF, NS, 0xa003, 1, 10, 8]);
        len[2] = 6;
        let out = digests(NS, len, preimage);
        assert_eq(out[0], p2_hash_sep([NS, 0xa002, 100, 200, 7], STATE));
        assert_eq(out[1], p2_hash_sep([NS, 0xa003, 0, 5, 9], LEAF));
        assert_eq(out[2], p2_hash([LEAF, NS, 0xa003, 1, 10, 8]));
        for k in 3..ITEMS {
            assert_eq(out[k], 0);
        }
    }

    #[test]
    fn every_length_up_to_the_capacity() {
        let mut fields = [0; FIELDS];
        fields[0] = STATE;
        fields[1] = NS;
        for j in 2..FIELDS {
            fields[j] = j as Field;
        }
        let mut preimage = [0; ITEMS * FIELDS];
        let mut len = [0; ITEMS];
        for k in 0..ITEMS {
            preimage = place(preimage, k, fields);
            len[k] = (k + 1) as Field;
        }
        let out = digests(NS, len, preimage);
        assert_eq(out[0], p2_hash([STATE]));
        assert_eq(out[2], p2_hash([STATE, NS, 2]));
        assert_eq(out[5], p2_hash([STATE, NS, 2, 3, 4, 5]));
        assert_eq(out[ITEMS - 1], p2_hash(fields));
    }

    #[test(should_fail_with = "another namespace")]
    fn an_item_of_another_namespace_fails() {
        let mut len = [0; ITEMS];
        len[0] = 4;
        let preimage = place([0; ITEMS * FIELDS], 0, [STATE, 0xbeef, 0xa002, 1]);
        let _ = digests(NS, len, preimage);
    }
}
