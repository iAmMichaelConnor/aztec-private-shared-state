//! move: move `amount` from the key `from` to the key `to` (credits_tip
//! ledger.nr `move_credit`): two keys in one round, both shared, the
//! source held with the balance, the destination inserted when absent.
//! Under secret-shared receipt intake over the keyed oblivious map as
//! ../pay; the completed note is `[code, ROUND_MOVE, amount, source
//! balance left, request_id]`.
//!
//! Public inputs (16) as ../pay's. The manifest (manifests/move.json): the
//! app inputs `from`, `to` and `amount` INPUT_SHARED; the map's two slots
//! as three LOAD slices of 136 elements ([0, 6], [6, 8], [8, 136]); `r_new`
//! SAMPLE 2; out0 stored under $state_keys.writes[0] (136 elements). Constraints
//! as ../pay's with `move_credit` for `pay`.

use credits_tip::ledger::{DEPTH, LEAF_LEN};
use credits_tip::shared::{self, Prefix, Shared, SharedIntake, Slots};

fn main(
    namespace: pub Field,
    vk_hash: pub Field,
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    inputs_hash: Field,
    from: Field,
    to: Field,
    amount: Field,
    partial_note: Field,
    outcome_key: Field,
    outcome_tag: Field,
    blinding: Field,
    leaves: [[Field; LEAF_LEN]; 2],
    old_hashes: [Field; 2],
    siblings: [[Field; DEPTH]; 2],
    r_new: [Field; 2],
    nsk_app: Field,
) -> pub Shared {
    shared::move_credit(
        Prefix { namespace, vk_hash, in_slots, out_slots },
        SharedIntake { inputs_hash, partial: partial_note, outcome_key, outcome_tag, blinding },
        [from, to, amount],
        Slots { leaves, old_hashes, siblings },
        r_new,
        nsk_app,
    )
        .stored()
}
