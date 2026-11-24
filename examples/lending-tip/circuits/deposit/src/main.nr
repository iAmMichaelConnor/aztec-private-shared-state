//! deposit under the non-secret-shared intakes (on-chain intake,
//! manifests/deposit.json, and receipt intake, deposit_receipt.json), one
//! compiled circuit for both: lending_tip's `entry::deposit` with the `Plain`
//! entry. The round is rounds.nr `deposit`; the intake's checks, the writes and
//! the outputs are entry.nr's. Public inputs (19): the prefix [namespace,
//! vk_hash, in_slots[0], out_slots[0], price, price_epoch, clock], then
//! `PlainOwner`.

use lending_tip::entry::{self, Pinned, Plain, PlainOwner, Prefix, Slots};
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
    // ---- the app inputs, then the request's partial note and salt ----
    // the position's index; 0 opens a new position
    position: Field,
    // the collateral added
    amount: Field,
    // the request's partial note, PUBLIC $partial_note, echoed for apply's public
    // completion
    partial_note: Field,
    // the request's salt, PUBLIC $user_nonce
    user_nonce: Field,
    // ---- the book's slots, from the nodes ----
    leaves: [Leaf; OWNER_SLOTS],
    old_hashes: [Field; OWNER_SLOTS],
    siblings: [[Field; DEPTH]; OWNER_SLOTS],
    // the indices the nodes placed
    indices: [Field; OWNER_SLOTS],
    // the append index the scheduler assigns ($new_leaf), 0 when the book is full
    new_leaf: Field,
    // ---- the new blindings, SAMPLE 2 ----
    r_new: [Field; OWNER_SLOTS],
    // the fixed LOAD, for npk_app_hash
    nsk_app: Field,
) -> pub PlainOwner {
    entry::deposit(
        Plain { indices, partial_note, user_nonce },
        Prefix { namespace, vk_hash, in_slots, out_slots },
        Pinned { price, price_epoch, clock },
        [position, amount],
        Slots { leaves, old_hashes, siblings },
        new_leaf,
        r_new,
        nsk_app,
    )
}
