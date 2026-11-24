//! The lending rounds under a secret-shared intake (docs/ARCHITECTURE.md section
//! 6, "Secret-shared intake" and "Private outcomes"): what a secret-shared main adds to
//! its round's `Step`, the round itself being the non-secret-shared rounds' source
//! (rounds.nr).
//!
//! - The inputs commitment. The round takes the app inputs (the position
//!   indices clear to the nodes, the amount shared), the reserved
//!   `$partial_note`, `$outcome_key` and `$outcome_tag`, the `$blinding`
//!   and C (`$inputs_hash`), pss_core's
//!   `tip::intake::SharedIntake`, and checks first that C opens to them
//!   (the `SharedIntake` family's check, code 14, a flag: shares that do
//!   not open make an ok = 0 round, never an unsatisfiable one). The
//!   request id is the secret-shared one over C (`SharedIntake::request_id`).
//! - The writes: pss_core's `Tree::update_private` under the round's write
//!   policy (`Step::reblind`), which the family's write passes whether C
//!   opens: every outcome re-blinds the header and an owner round's
//!   position, except that shares which do not open C (code 14) land
//!   nothing and re-blind the header alone (the position is an unbound
//!   witness then);
//!   a liquidation writes a probe only when it
//!   liquidates it, so a probe it leaves keeps its leaf
//!   (examples/lending-tip/README.md, "The escape hatch", "The liquidation's
//!   write rule"). The write is pss_core's tagged write
//!   (`Tree::update_private_tagged`, the escape hatch's exit tags): every
//!   written position leaf takes the exit tag of the note the round issues for
//!   it, the requester's for an owner round and the notice's for a liquidated
//!   probe, and the round outputs the tag it replaces.
//! - The outcome: `[code, position, mask, x, y, payout, aux]`
//!   (`Step::outcome_fields`, position the index the tagged write wrote for
//!   an owner round, `Step::named`), the request's partial note completed
//!   with it and the chain request id, and the outcome encrypted under
//!   `$outcome_key` with the nonce of that note hash (pss_core's
//!   `outcome::finish`): the user's position
//!   note, which its next request opens to prove ownership and its `redeem`
//!   spends once. One shape for every round type, so the ciphertext tells
//!   nothing of the round. The round never sees an owner: `$partial_note`
//!   hides it behind the user's randomness.
//!
//! - The inputs-opened bit: `opened`, 1 when the shares opened C, as the
//!   round's last app value (pss_core's `Valued`), which the contract's
//!   `apply` reads: a round
//!   whose shares did not open C (code 14) cannot settle its escrow in a
//!   note (the note's owner is not the one the user committed), so `apply`
//!   refunds the escrow in full when the bit is 0
//!   (examples/lending-tip/README.md, "Tokens", "The inputs-opened bit").
//!   It says only that the request's shares failed, which the escrow record
//!   does not change.
//! - The exit tags: EXIT_TAGS values first among the app values, per
//!   position slot the exit tag the round replaced or a filler
//!   (pss_core `Tagged::nullifiers`), which the contract's landing emits as
//!   nullifiers with the commitment move (examples/lending-tip/README.md,
//!   "The escape hatch", "The exit tag at place 6"); then the book's append index on the
//!   oblivious deployment (0 on a clear one) when the round has a position
//!   slot, and the bit last (`app_values`).
//!
//! - The deliveries (pss_core `tip::handle`, the standing delivery handle):
//!   an owner round on a borrower position carries the owner's next handle
//!   (`handle_partial`, `handle_key`, in C after the app inputs), which the
//!   round writes into the position's leaf (`with_handle`) whether it
//!   applies or re-blinds the leaf; a liquidation completes the handle of
//!   each probe it writes with the position after it (`deliveries`,
//!   `notice_fields`) and keeps it, so every later liquidation notifies the
//!   owner too, each under its own log tag. Every round outputs DELIVERIES
//!   of them, fillers where nobody is notified, so the round type stays
//!   hidden.
//!
//! The public outputs are pss_core's `handle::Delivered`: the tree's new leaf
//! hashes, the app values (the exit tags, the append index and the bit),
//! then the deliveries, the layout pss_public_contract's `handle::Delivered`
//! verifies: `[request_id, machine_request_id, old_c, new_c, npk_app_hash,
//! new_hashes[K], outcome_tag, note_hash, ciphertext[8], exit_tags[1],
//! next_index (K > 1), opened, tag, delivery_note_hash,
//! delivery_ciphertext[9]]` after the
//! public parameters `[namespace, vk_hash, in_slots[0], out_slots[0],
//! price, price_epoch, clock]`: the round's two pinned reads, the price
//! epoch read and the clock read (the market's `clock()`, the L2 block
//! number, under a tolerance of CLOCK_BAND blocks).
use crate::market::{
    CODE_BAD_STATE, CODE_INPUTS_MISMATCH, DEPTH, H_NEXT_INDEX, KIND_BORROWER, Leaf, LEAF_LEN, P_HANDLE,
    P_INDEX_AT_TOUCH, PROBES,
};
use crate::entry::{Pinned, Prefix};
use crate::rounds::{OUTCOME_FIELDS, Step};
/// The secret-shared intake's values (C, `$partial_note`, `$outcome_key`,
/// `$outcome_tag`, `$blinding`), pss_core's, re-exported for the secret-shared mains,
/// which depend on this library alone.
pub use pss_core::tip::intake::SharedIntake;
/// The delivery handle an owner round's request carries (`handle_partial`,
/// `handle_key`), pss_core's, re-exported for the mains.
pub use pss_core::tip::handle::Handle;
use pss_core::tip::exit::{TaggedWrite, Tagging};
use pss_core::tip::family::{Checked, Family};
use pss_core::tip::handle::{deliver, Delivered, Delivery, filler, filler_seed};
use pss_core::tip::outcome::Private;
use pss_core::tip::outputs::{Finished, Written};
use pss_core::tip::tree::{Access, Oblivious, Tree, Updated};
use total::cmp::eq;
use total::core::select_field;
use total::hash::p2_hash;

/// The outcome ciphertext's length: the seven outcome fields and the AEAD
/// tag.
pub global CIPHERTEXT_LEN: u32 = OUTCOME_FIELDS + 1;

/// The deliveries every secret-shared round outputs (pss_core
/// `handle::Delivered`): one per probe a liquidation may write, PROBES - 1,
/// so a liquidation that notifies its probe's owner and every other round,
/// which notifies nobody, have the same outputs (the hidden round type).
pub global DELIVERIES: u32 = PROBES - 1;

/// A delivery's ciphertext length: the notice note's packed fields (the
/// seven outcome fields and the chain request id) and the AEAD tag.
pub global DELIVERY_LEN: u32 = OUTCOME_FIELDS + 2;

/// The storage slot of the lending contract's outcome notes
/// (examples/lending-tip/contract `outcome_notes`, the contract's
/// `OUTCOME_SLOT`, which its TXE suite pins against `get_state().outcome_slot`),
/// where every secret-shared round's outcome note lives. A constant of the
/// circuit, so no node can put the note where the user's claim does not
/// look, and so the completed note is the contract's note at that slot.
/// The set is the contract's first storage field, so its slot does
/// not move when another field's size changes.
pub global OUTCOME_SLOT: Field = 1;

/// The exit-tag values every secret-shared round outputs first among its
/// app values (pss_core `Tagged::nullifiers`): one per position slot a round
/// may write, PROBES - 1, so the header-only rounds output as many (all
/// fillers) and every landing emits the same number of nullifiers.
pub global EXIT_TAGS: u32 = PROBES - 1;

/// A secret-shared round's public outputs over a tree of K slots: the
/// EXIT_TAGS exit tags, then K values (`app_values`), then the DELIVERIES
/// deliveries.
pub type Shared<let K: u32> = Delivered<1, 1, K, 1, CIPHERTEXT_LEN, EXIT_TAGS + K, DELIVERIES, DELIVERY_LEN>;

/// The app values of a round over K slots: its exit tags, then, when the
/// round has a position slot (K > 1), the book's append index
/// (`next_index`: the oblivious deployment's public `next_index` of an
/// opening round's manifest, from which the nodes keep theirs; 0 on a clear
/// deployment, whose nodes see the indices: one result layout for both),
/// zeros, and `opened` last. No constraint.
pub fn app_values<let K: u32>(tags: [Field; EXIT_TAGS], next_index: Field, opened: bool) -> [Field; EXIT_TAGS + K] {
    let mut values = [0; K];
    if K > 1 {
        values[0] = next_index;
    }
    values[K - 1] = opened as Field;
    tags.concat(values)
}

/// The book's append index a round outputs (`app_values`), one
/// implementation per tree access (the book key's `access` in the manifest),
/// over the form pss_core's tagged write leaves the book in (`tree::Access`):
///
/// - `access: clear` (the default): pss_core's `Updated`; 0, since the
///   clear deployment's nodes see the indices.
/// - `access: oblivious`: pss_core's `tree::Oblivious` (docs/ARCHITECTURE.md
///   section 6, "The oblivious tree", "The circuit"), whose K public leaf
///   hashes are all zero, so the result's layout is the clear deployment's and
///   the contract's `process_*_shared` land both; the header's append index as
///   stored.
pub trait AppendIndex {
    /// The append index the round outputs.
    fn next_index(self) -> Field;
}

// BRICK shape = tree (pss_core::tip::tree::Updated): the clear book's form. Alternatives:
// tree_oblivious (the Oblivious implementation below), map_oblivious. docs/design-guide/BRICKS.md#shape
impl<let K: u32> AppendIndex for Updated<K, LEAF_LEN> {
    /// None: the clear deployment's nodes see the indices.
    fn next_index(self) -> Field {
        0
    }
}

// BRICK shape = tree_oblivious (pss_core::tip::tree::Oblivious): the oblivious book's form, with
// each slot's new path. Alternatives: tree (the Updated implementation above), map_oblivious. docs/design-guide/BRICKS.md#shape
impl<let K: u32> AppendIndex for Oblivious<K, LEAF_LEN, DEPTH, K> {
    /// The header's append index as stored: the new header's when the
    /// round applied, the old one when it failed (re-blinded) or wrote
    /// nothing, so the nodes advance theirs exactly when an opening applied.
    fn next_index(self) -> Field {
        self.updated.stored[0][H_NEXT_INDEX]
    }
}

/// What a round's write leaves (pss_core's `exit::TaggedWrite`): the book in
/// its access's form, and under the secret-shared intakes the tagged write's
/// EXIT_TAGS nullifiers and each slot's entry. Under the non-secret-shared
/// intakes, whose leaves hold no exit tag, both are zeros.
pub type Booked<B, let K: u32> = TaggedWrite<B, K, EXIT_TAGS>;

/// A secret-shared round over the clear book, finished: the tree it leaves
/// and its public outputs; a secret-shared main ends in `stored`, which
/// hands the leaves to the machine (TACEO_store "out0").
pub type SharedRound<let K: u32> = Finished<Updated<K, LEAF_LEN>, Shared<K>>;

/// A round over the oblivious book, finished: the book as pss_core's
/// `tree::Oblivious` leaves it, with K public leaf hashes, all zero.
pub type ObliviousRound<let K: u32> = Finished<Oblivious<K, LEAF_LEN, DEPTH, K>, Shared<K>>;

/// A borrower leaf with `handle` in its handle's places (market.nr
/// `P_HANDLE`); any other leaf as it is (a lender's holds no handle, an
/// empty one has no kind). No constraint but an equality and selects.
pub fn with_handle(leaf: Leaf, handle: Handle) -> Leaf {
    let borrower = eq(leaf[0], KIND_BORROWER);
    let mut out = leaf;
    out[P_HANDLE] = select_field(borrower, handle.partial, leaf[P_HANDLE]);
    out[P_HANDLE + 1] = select_field(borrower, handle.key, leaf[P_HANDLE + 1]);
    out
}

/// The handle a loaded leaf holds (zeros for none).
pub fn handle_of(leaf: Leaf) -> Handle {
    Handle::of([leaf[P_HANDLE], leaf[P_HANDLE + 1]])
}

/// A notice's outcome fields: an owner round's report of slot `k`'s
/// position as the round wrote it, `[0, index, index_at_touch, collateral,
/// debt, 0, 0]` (`Step::outcome_fields`' layout), an owner note of the
/// position that pays nothing. No constraint.
pub fn notice_fields<let K: u32>(t: Tree<K, DEPTH, LEAF_LEN>, u: Updated<K, LEAF_LEN>, k: u32) -> [Field; OUTCOME_FIELDS] {
    let leaf = u.stored[k];
    [0, t.indices[k], leaf[P_INDEX_AT_TOUCH], leaf[1], leaf[2], 0, 0]
}

/// The seeds of a round's DELIVERIES deliveries: `seed` itself for the
/// first and `poseidon2([seed, d])` after it, so no two deliveries of a
/// round that deliver nothing are equal (equal ones would show how many
/// delivered nothing). Constraints: one p2_hash per delivery after the
/// first (none at DELIVERIES = 1).
pub fn delivery_seeds(seed: Field) -> [Field; DELIVERIES] {
    let mut seeds = [seed; DELIVERIES];
    for d in 1..DELIVERIES {
        seeds[d] = p2_hash([seed, d as Field]);
    }
    seeds
}

/// The partial commitment of the note a round issues for each slot it
/// writes (pss_core `Tagging::partials`): for a probe whose owner the step
/// notifies, the partial its delivery completes (`deliveries`: the loaded
/// leaf's handle when it holds one, else the delivery's seed, which no
/// note opens); for every other slot the requester's, `requester`. The
/// header's is not read. No constraint but selects.
pub fn issued_partials<let K: u32>(
    t: Tree<K, DEPTH, LEAF_LEN>,
    notices: [bool; K],
    requester: Field,
    seeds: [Field; DELIVERIES],
) -> [Field; K] {
    let mut partials = [requester; K];
    for k in 1..K {
        if (k - 1 < DELIVERIES) & notices[k] {
            let handle = handle_of(t.leaves[k]);
            partials[k] = select_field(handle.present(), handle.partial, seeds[k - 1]);
        }
    }
    partials
}

/// The round's DELIVERIES deliveries (pss_core `tip::handle`): for each
/// probe slot whose owner the step notifies (`Step::notices`), its loaded
/// leaf's handle completed with `notice_fields` when the round wrote the
/// slot and the leaf holds a handle, else the seeded stand-in (`deliver`);
/// a filler for each delivery the round has no slot for (every round but a
/// liquidation). Delivery d is made from `seeds[d]` (`delivery_seeds`), all
/// at the outcome note's slot and under log tags of the round's request id.
/// Constraints: per notified slot one `deliver`, per other delivery one
/// `filler` (permutations and selects).
pub fn deliveries<let K: u32>(
    t: Tree<K, DEPTH, LEAF_LEN>,
    u: Updated<K, LEAF_LEN>,
    notices: [bool; K],
    request_id: Field,
    seeds: [Field; DELIVERIES],
) -> [Delivery<DELIVERY_LEN>; DELIVERIES] {
    // BRICK delivery-handle (pss_core::tip::handle::deliver), with filler where nobody is notified.
    // No alternative; an app whose rounds notify nobody but the requester leaves it out.
    // docs/design-guide/BRICKS.md#other-bricks
    let mut out = seeds.map(|s| filler::<OUTCOME_FIELDS>(s, request_id));
    for k in 1..K {
        if (k - 1 < DELIVERIES) & notices[k] {
            let handle = handle_of(t.leaves[k]);
            out[k - 1] = deliver(
                handle,
                u.write[k] & handle.present(),
                notice_fields(t, u, k),
                OUTCOME_SLOT,
                request_id,
                seeds[k - 1],
            );
        }
    }
    out
}

/// Finish a round under a secret-shared intake: check that C opens to `inputs`
/// (the app inputs before `$partial_note`, in ABI order), then the request's
/// delivery handle when it carries one (`handle`), then `$partial_note`,
/// `$outcome_key` and `$outcome_tag`, under `$blinding` (pss_core's
/// `SharedIntake` family check, code 14, ahead of the round's codes); write
/// the step in the family's form (`Checked::write` of the step's
/// change, pss_core's `Tree::change_tagged`) under the step's write policy (so
/// a failed opening deposit leaves its slot empty, which the nodes see:
/// re-blinding an empty leaf would create a position, and one past the
/// append index would move it; a probe a liquidation does not liquidate
/// keeps its leaf; and shares that do not open C land nothing and re-blind
/// the header alone), the request's handle in the position's leaf
/// (`with_handle`, slot 1) whether the round writes it or re-blinds it, and
/// each written position's exit tag that of the note the round issues for
/// it (`issued_partials`, under the chain request id); name the position the
/// write wrote in the outcome (`Step::named`); complete the request's
/// partial note with the outcome `Step::outcome_fields` at `OUTCOME_SLOT`
/// and encrypt it under the nonce of that note hash, the pinned values
/// `pin`'s (`Checked::finish`); output the exit tags, the book's append index and the
/// inputs-opened bit (`app_values`); and last the round's deliveries
/// (`deliveries`), seeded from `$blinding`.
///
/// `consistent` is an oblivious opening round's check that its public
/// opening flag agrees with the committed position (`opens == (position
/// == 0)`; true for every other round): a flag the nodes could flip is
/// otherwise what redirects a deposit into a fresh position, so a mismatch
/// is a flagged no-op (code 4) that writes nothing.
///
/// Constraints: C (one p2_hash and one equality), the round's tagged tree
/// update and `outcome::finish`'s (the machine request id, the outcome's AEAD
/// and completed note hash, npk_app_hash: the std scalar decomposition of
/// nsk_app, hint-satisfiable for every Field, and one fixed-base
/// multi_scalar_mul, which cannot fail), the handle's selects, `deliveries`'
/// and the seed's permutation, and one AND for `consistent` when it is not
/// the constant true; the store is an unconstrained side-effect-only oracle
/// (`stored`). No assert.
pub fn finish<B, let K: u32, let I: u32>(
    p: Prefix,
    pin: Pinned,
    t: Tree<K, DEPTH, LEAF_LEN>,
    step: Step<K>,
    consistent: bool,
    inputs: [Field; I],
    handle: Option<Handle>,
    shared: SharedIntake,
    nsk_app: Field,
) -> Finished<B, Shared<K>>
where
    B: Access<K, DEPTH, LEAF_LEN> + AppendIndex + Written<K>,
{
    // BRICK intake = shared_receipt, shared_onchain (pss_core::tip::intake::SharedIntake), one
    // circuit for both. Alternatives: onchain, receipt (entry.nr's Plain entry). docs/design-guide/BRICKS.md#intake
    let checked: Checked<SharedIntake> = if handle.is_some() {
        shared.check(inputs.concat(handle.unwrap_unchecked().fields()), CODE_INPUTS_MISMATCH)
    } else {
        shared.check(inputs, CODE_INPUTS_MISMATCH)
    };
    let s = step.with_intake(checked.first.require(consistent, CODE_BAD_STATE));
    let request_id = shared.request_id(p.namespace, p.vk_hash);
    let seeds = delivery_seeds(filler_seed(shared.blinding));
    let mut change = s.change(t);
    change.change.placed = s.placed & consistent;
    change.tagging = Tagging { request_id, requester: shared.partial, partials: issued_partials(t, s.notices, shared.partial, seeds) };
    if handle.is_some() & (K > 1) {
        let h = handle.unwrap_unchecked();
        change.change.new_leaves[1] = with_handle(change.change.new_leaves[1], h);
        change.change.kept[1] = with_handle(change.change.kept[1], h);
    }
    let booked: Booked<B, K> = checked.write(change);
    // the first position slot; a header-only round's slot 0 holds no entry (0)
    let fields: [Field; OUTCOME_FIELDS] = s.named(booked.entry((K > 1) as u32)).outcome_fields();
    let values = app_values::<K>(booked.nullifiers, booked.written.next_index(), checked.opened());
    // no non-secret-shared app outputs here (`()`): entry.nr's Plain entry has its own
    let sealed: Finished<B, Private<1, 1, K, 1, CIPHERTEXT_LEN>> =
        checked.finish(booked.written, p.namespace, p.vk_hash, inputs, pin.values(), (), fields, OUTCOME_SLOT, nsk_app);
    let round = sealed.valued(values);
    let sent = deliveries(t, round.written.updated(), s.notices, request_id, seeds);
    round.delivered(sent)
}
