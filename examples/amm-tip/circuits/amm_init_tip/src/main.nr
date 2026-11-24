// Registered under examples/amm-tip/manifests/amm_init_tip.json ("intake":
// "onchain" because a tip round takes a queued intake, though the contract
// never enqueues this round).
//
// This round is not declared total, and circuits.env leaves it out of
// TOTAL_CIRCUITS: it keeps examples/amm's Pool::from_seed as it is,
// native u64 arithmetic (a cast, a modulo, an addition) that cannot fail
// for any seed, since each reserve is 1e6 plus a residue below 1e6; its
// u64 modulo hints sit in examples/amm's code, where no marker of this
// example counts. Totality matters only for
// a queued request, and this round is never queued: the operator's
// deployment runs it once, with inputs the network samples (rand_seed,
// r_new) and the request's public prefix, and the contract applies its
// result once, through the library's init path, while the pool slot is
// empty. A failure here would stop a deployment, never a queue.

use amm::pool::Pool;
use pss_core::tip::outputs::{Init, Written};
use pss_core::tip::slot;

/// Start the pool at the tip: derive the starting reserves from a seed
/// the network samples, hand [reserve_x, reserve_y, r_new] to the machine
/// and output its commitment, the first value of the pool slot.
///
/// Public inputs (7), in ACIR order (pub params, then the return struct):
///   [namespace, vk_hash, out_slots[0], request_id, old_c = 0, new_c,
///    npk_app_hash] (pss_core `tip::outputs::Init`, no leaf hashes)
fn main(
    // ---- public prefix ----
    // PUBLIC $namespace, as amm_swap_tip
    namespace: pub Field,
    // vk_hash, a public input, as amm_swap_tip: hashed into the init
    // request id, and checked by init_pool against the init vk the Config
    // pins
    vk_hash: pub Field,
    // key binding: out_slots[0] from $state_keys.writes[0] is bound into new_c,
    // and the contract passes its pool slot, so the first commitment names
    // the key every swap then reads
    out_slots: pub [Field; 1],
    // the seed, SAMPLE 1 in this round. examples/amm seeds
    // in a separate round and consumes the seed note so the pool starts
    // once; at the tip the contract applies init once (the pool slot must
    // be empty), so the seed can be sampled here and no seed round or
    // seed key exists. No party knows the seed; nothing proves it random.
    rand_seed: Field,
    // the pool's first blinding, SAMPLE 1
    r_new: Field,
    // nsk_app by the fixed LOAD nsk_app, only to output npk_app_hash, so
    // the contract can pin the network identity from the first round
    nsk_app: Field,
) -> pub Init<0> {
    let reserves = Pool::from_seed(rand_seed).as_field_array();
    // BRICK shape = flat (pss_core::tip::slot::create). Alternatives: tree, tree_oblivious,
    // map_oblivious (pss_core tip::tree and tip::map). docs/design-guide/BRICKS.md#shape
    // the init round takes no app inputs and no nonce
    slot::create(namespace, out_slots[0], reserves, r_new).init(namespace, vk_hash, [], nsk_app)
}
