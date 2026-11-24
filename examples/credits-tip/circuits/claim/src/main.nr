//! claim: take `amount` from `key` (credits_tip ledger.nr `claim`), which
//! must hold the balance (a zero balance is absent); under secret-shared receipt intake
//! with a private outcome, over the keyed oblivious map as ../pay. The
//! completed note is `[code, ROUND_CLAIM, amount, balance left,
//! request_id]`; an absent
//! key is code 4, the non-membership outcome, delivered privately.
//!
//! Public inputs (16), the manifest (manifests/claim.json) and the
//! constraints as ../pay's, with `claim` for `pay`.

use credits_tip::ledger::{DEPTH, LEAF_LEN};
use credits_tip::shared::{self, Prefix, Shared, SharedIntake, Slots};

fn main(
    namespace: pub Field,
    vk_hash: pub Field,
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    inputs_hash: Field,
    key: Field,
    amount: Field,
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
    shared::claim(
        Prefix { namespace, vk_hash, in_slots, out_slots },
        SharedIntake { inputs_hash, partial: partial_note, outcome_key, outcome_tag, blinding },
        [key, amount],
        Slots { leaves, old_hashes, siblings },
        r_new,
        nsk_app,
    )
        .stored()
}
