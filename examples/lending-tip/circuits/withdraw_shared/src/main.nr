//! withdraw under the secret-shared intakes over the clear book
//! (manifests/withdraw_shared.json): lending_tip's `entry::withdraw` with the
//! `Clear` entry. The round is rounds.nr `withdraw`; the intake's checks, the
//! writes and the outputs are entry.nr's. Public inputs (38): the prefix
//! [namespace, vk_hash, in_slots[0], out_slots[0], price, price_epoch, clock],
//! then `Shared<OWNER_SLOTS>`.

use lending_tip::entry::{self, Clear, Handle, Pinned, Prefix, Shared, SharedIntake, Slots};
use lending_tip::market::{DEPTH, Leaf, OWNER_SLOTS};

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
    // the position's index
    position: Field,
    // the collateral withdrawn
    amount: Field,
    // the owner's delivery handle for the position: its partial commitment (0 for none),
    // then its key
    handle_partial: Field,
    handle_key: Field,
    // the user's partial note, completed with the outcome
    partial_note: Field,
    outcome_key: Field,
    outcome_tag: Field,
    blinding: Field,
    // ---- the book's slots, from the nodes ----
    leaves: [Leaf; OWNER_SLOTS],
    old_hashes: [Field; OWNER_SLOTS],
    siblings: [[Field; DEPTH]; OWNER_SLOTS],
    // the indices the nodes placed
    indices: [Field; OWNER_SLOTS],
    // ---- the new blindings, SAMPLE 2 ----
    r_new: [Field; OWNER_SLOTS],
    // the fixed LOAD, for npk_app_hash
    nsk_app: Field,
) -> pub Shared<OWNER_SLOTS> {
    entry::withdraw(
        Clear { indices, shared: SharedIntake { inputs_hash, partial: partial_note, outcome_key, outcome_tag, blinding }, handle: Option::some(Handle { partial: handle_partial, key: handle_key }) },
        Prefix { namespace, vk_hash, in_slots, out_slots },
        Pinned { price, price_epoch, clock },
        [position, amount],
        Slots { leaves, old_hashes, siblings },
        r_new,
        nsk_app,
    )
}
