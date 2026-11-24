//! view: look `key` up (credits_tip ledger.nr `view`), the prove-absent
//! round: writes no new value (its slot is written under a fresh blinding,
//! as on every round, so the chain cannot tell a view from a claim, nor a
//! present key from an absent one), and the completed note `[code,
//! ROUND_VIEW, present, balance, request_id]` tells the requester privately whether the key is in
//! the map, proven on a path the circuit verified to the committed root,
//! and what it holds. Under secret-shared receipt intake over the keyed
//! oblivious map as ../pay.
//!
//! Public inputs (16), the manifest (manifests/view.json: the app input is
//! `key` alone) and the constraints as ../pay's, with `view` for `pay`.

use credits_tip::ledger::{DEPTH, LEAF_LEN};
use credits_tip::shared::{self, Prefix, Shared, SharedIntake, Slots};

fn main(
    namespace: pub Field,
    vk_hash: pub Field,
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    inputs_hash: Field,
    key: Field,
    partial_note: Field,
    outcome_key: Field,
    outcome_tag: Field,
    blinding: Field,
    leaves: [[Field; LEAF_LEN]; 1],
    old_hashes: [Field; 1],
    siblings: [[Field; DEPTH]; 1],
    r_new: [Field; 1],
    nsk_app: Field,
) -> pub Shared {
    shared::view(
        Prefix { namespace, vk_hash, in_slots, out_slots },
        SharedIntake { inputs_hash, partial: partial_note, outcome_key, outcome_tag, blinding },
        [key],
        Slots { leaves, old_hashes, siblings },
        r_new,
        nsk_app,
    )
        .stored()
}
