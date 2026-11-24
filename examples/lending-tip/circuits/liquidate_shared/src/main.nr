//! liquidate under the secret-shared intakes over the clear book
//! (manifests/liquidate_shared.json): lending_tip's `entry::liquidate` with the
//! `Clear` entry. The round is rounds.nr `liquidate`; the intake's checks, the
//! writes and the outputs are entry.nr's. Public inputs (38): the prefix
//! [namespace, vk_hash, in_slots[0], out_slots[0], price, price_epoch, clock],
//! then `Shared<PROBES>`.

use lending_tip::entry::{self, Clear, Pinned, Prefix, Shared, SharedIntake, Slots};
use lending_tip::market::{DEPTH, Leaf, PROBES};

fn main(
    // ---- the public prefix (entry::Prefix) and the pinned reads (entry::Pinned) ----
    namespace: pub Field,
    vk_hash: pub Field,
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    // the pinned epoch read: the oracle's price and its epoch
    price: pub Field,
    price_epoch: pub Field,
    // the pinned clock read: the market's clock(), within CLOCK_BAND blocks
    clock: pub Field,
    // ---- the secret-shared intake: C, then the values it commits to, in C's order ----
    // C, PUBLIC $inputs_hash
    inputs_hash: Field,
    // the probed position's index
    p1: Field,
    // the probes used, 1 .. PROBES - 1
    count: Field,
    // the most the liquidator repays
    budget: Field,
    // the user's partial note, completed with the outcome
    partial_note: Field,
    outcome_key: Field,
    outcome_tag: Field,
    blinding: Field,
    // ---- the book's slots, from the nodes ----
    leaves: [Leaf; PROBES],
    old_hashes: [Field; PROBES],
    siblings: [[Field; DEPTH]; PROBES],
    // the indices the nodes placed
    indices: [Field; PROBES],
    // ---- the new blindings, SAMPLE 2 ----
    r_new: [Field; PROBES],
    // the fixed LOAD, for npk_app_hash
    nsk_app: Field,
) -> pub Shared<PROBES> {
    entry::liquidate(
        Clear { indices, shared: SharedIntake { inputs_hash, partial: partial_note, outcome_key, outcome_tag, blinding }, handle: Option::none() },
        Prefix { namespace, vk_hash, in_slots, out_slots },
        Pinned { price, price_epoch, clock },
        [p1, count, budget],
        Slots { leaves, old_hashes, siblings },
        r_new,
        nsk_app,
    )
}
