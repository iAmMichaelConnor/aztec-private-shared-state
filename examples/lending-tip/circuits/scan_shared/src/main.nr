//! scan under the secret-shared intakes over the clear book
//! (manifests/scan_shared.json): lending_tip's `entry::scan` with the `Clear`
//! entry. The round is rounds.nr `scan`; the intake's checks, the writes and
//! the outputs are entry.nr's. Public inputs (36): the prefix [namespace,
//! vk_hash, in_slots[0], out_slots[0], price, price_epoch, clock], then
//! `Shared<SCAN_SLOTS>`.

use lending_tip::entry::{self, Clear, Pinned, Prefix, Shared, SharedIntake, Slots, WindowSlots};
use lending_tip::market::{DEPTH, Leaf, SCAN_SLOTS, WINDOW, WINDOW_SIBLINGS};

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
    // the window's first index, a multiple of WINDOW
    start: Field,
    // the user's partial note, completed with the outcome
    partial_note: Field,
    outcome_key: Field,
    outcome_tag: Field,
    blinding: Field,
    // ---- the book's slots, from the nodes ----
    leaves: [Leaf; SCAN_SLOTS],
    old_hashes: [Field; SCAN_SLOTS],
    siblings: [[Field; DEPTH]; SCAN_SLOTS],
    // the indices the nodes placed
    indices: [Field; SCAN_SLOTS],
    // the window at start: its leaves, their old hashes and the window root's siblings
    window_leaves: [Leaf; WINDOW],
    window_hashes: [Field; WINDOW],
    window_siblings: [Field; WINDOW_SIBLINGS],
    // ---- the new blindings, SAMPLE 1 ----
    r_new: [Field; SCAN_SLOTS],
    // the fixed LOAD, for npk_app_hash
    nsk_app: Field,
) -> pub Shared<SCAN_SLOTS> {
    entry::scan(
        Clear { indices, shared: SharedIntake { inputs_hash, partial: partial_note, outcome_key, outcome_tag, blinding }, handle: Option::none() },
        Prefix { namespace, vk_hash, in_slots, out_slots },
        Pinned { price, price_epoch, clock },
        [start],
        Slots { leaves, old_hashes, siblings },
        WindowSlots { leaves: window_leaves, hashes: window_hashes, siblings: window_siblings },
        r_new,
        nsk_app,
    )
}
