// Registered under examples/lending-tip/manifests/lending_init.json.
//
// This round keeps one assert, that liquidity is a u128,
// justified by its total-lint marker, so circuits.env lints it with the
// queued rounds. Totality matters only for a queued request, and this
// round is never queued: the operator's deployment runs it once, with the
// liquidity it funds the contract with, and the contract applies its
// result once, through the library's init path, while the market slot
// is empty. A failure here stops a deployment, never a queue. It still
// runs in co-noir, so its range flag is total's fits_bits, whose hint co-noir runs.

use lending_tip::rounds::empty_book;
use pss_core::tip::outputs::{Init, Written};
use total::range::fits_bits;

/// Start the book at the tip: the empty tree of depth D with the header at
/// leaf 0 (lending_tip `empty_book`: the seeded liquidity and as many
/// shares, its append index 1, the first position; its tests pin the
/// header); hand the header to the machine and output the tree's
/// commitment, the first value of the market slot.
///
/// Public inputs (8), in ACIR order (pub params, then the return struct):
///   [namespace, vk_hash, out_slots[0], request_id, old_c (= 0), new_c,
///    npk_app_hash, new_hashes[0]] (pss_core `tip::outputs::Init`)
fn main(
    namespace: pub Field,
    vk_hash: pub Field,
    out_slots: pub [Field; 1],
    // the seeded liquidity, a u128 the contract's Config pins
    liquidity: Field,
    r_new: Field,
    nsk_app: Field,
) -> pub Init<1> {
    // total-lint: allow the init is never queued; a liquidity that is not a u128 stops the deployment, never a queue
    assert(fits_bits::<128>(liquidity), "liquidity is not a u128");
    empty_book(namespace, out_slots[0], liquidity, r_new).init(namespace, vk_hash, [liquidity], nsk_app)
}

