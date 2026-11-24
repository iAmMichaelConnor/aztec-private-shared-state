//! The exit tag (docs/ARCHITECTURE.md section 6, "The escape hatch"): how a
//! round on a tree-valued key lets the owner of an entry leave a frozen app
//! privately, with no node, by pushing one nullifier.
//!
//! ```text
//! exit_tag(P, request_id, entry) = poseidon2([PSS_EXIT_TAG    + 2^128 * entry, P, request_id])
//! exit_filler(P, request_id, j)  = poseidon2([PSS_EXIT_FILLER + 2^128 * j,     P, request_id])
//! ```
//!
//! Every non-empty entry leaf holds one tag, in its second-to-last element
//! (the last is its blinding). A round that writes an entry slot stores
//! `exit_tag(P_k, request_id, index_k)` in the new leaf, `P_k` the partial
//! commitment of the note the round issues for that entry (the requester's
//! own, or a delivery handle's for an entry the round changes on its
//! owner's behalf), and outputs the old leaf's tag, which the landing
//! emits as a nullifier with the commitment move. So the tags of one entry
//! form a chain: each write stores a new one and spends the one before, and
//! the one unspent tag is the newest note's. The app's exit recomputes it
//! from the owner's note and pushes it once (pss_public_contract `hatch`).
//!
//! The rules the brick keeps (`Tree::update_private_tagged`, which a round
//! reaches through `Tree::change_tagged`, its write in either family's
//! form):
//!
//! 1. A round outputs the same number of values whatever it does
//!    (`Tagged::nullifiers`): per entry slot the old tag where it wrote a
//!    leaf that held one, else a filler; then fillers. Fillers are hashes
//!    under `PSS_EXIT_FILLER` of the requester's partial commitment and the
//!    request id, so nobody but the requester tells them from tags, and no
//!    filler equals a tag.
//! 2. A note names an entry only if its round wrote that entry:
//!    `Tagged::entry` is the slot's index where written and 0 otherwise, the
//!    value the app's note takes its entry from.
//! 3. A round whose shares do not open C writes no entry slot (the tree's
//!    `private_writes`: only the header's index is bound then), so nodes
//!    that change their shares cannot spend an owner's tag by naming its
//!    entry. A keyed map's private write does not keep this rule (it
//!    re-blinds the slots at the keys the prover chose), so there is no
//!    tagged map: one needs its own rule first.
//!
//! The request id makes a tag unique per landed round (a reused partial
//! commitment or handle still gives a new tag), and is the chain request id,
//! never the attempt's: every attempt of one request stores and outputs the
//! same values. `entry` separates two slots of one round that carry one
//! partial commitment and ties the tag to the position the note names. No
//! sampled value enters a tag, so nodes cannot aim one at another.
//!
//! One permutation per entry slot: the hash's inputs are selected on
//! whether the slot is written, `[TAG(index), P_k]` or `[FILLER(j),
//! requester]`, and the first output element is the stored tag or the
//! filler. A written slot that held no leaf (an opening) has no old tag to
//! spend: it outputs the permutation's second element, which nobody outside
//! the round recomputes and which reveals nothing of the first.
//!
//! Every function here is permutation black boxes, additions and selects:
//! total, with no failure source, and runs in co-noir.
use super::family::Change;
use super::tree::{Access, Tree, TreeChange, Updated};
use std::hash::poseidon2_permutation;
use total::core::{is_zero, select_field, TWO_POW_128, TWO_POW_64};

/// ASCII "pss.exit_tag" as a big-endian integer (96 bits): the domain of an
/// exit tag (pss-client's PSS_EXIT_TAG holds the same value).
pub global PSS_EXIT_TAG: Field = 0x7073732e657869745f746167;

/// ASCII "pss.exit_filler" as a big-endian integer (120 bits): the domain of
/// a filler, the output of a slot that spends no tag.
pub global PSS_EXIT_FILLER: Field = 0x7073732e657869745f66696c6c6572;

/// The sponge's initial capacity element of a three-element Poseidon2 hash
/// (Aztec's `poseidon2_hash`, total's `p2_hash`): the length times 2^64.
global IV3: Field = 3 * TWO_POW_64;

/// The first element of a tag's or a filler's hash: the domain in the low
/// 128 bits and `at` (an entry index, or a filler's place) above them, below
/// 2^248, so no domain and no index alias.
fn domain(sep: Field, at: Field) -> Field {
    sep + TWO_POW_128 * at
}

/// The permutation of a three-element hash of `[first, secret, request_id]`:
/// its first element is the hash. Total: one permutation.
fn permuted(first: Field, secret: Field, request_id: Field) -> [Field; 4] {
    poseidon2_permutation([first, secret, request_id, IV3])
}

/// The exit tag of the note that completes the partial commitment `partial`
/// in the round of chain request `request_id`, naming entry `entry` (a leaf
/// index below 2^120): the nullifier that note's exit pushes. Total: one
/// permutation.
pub fn exit_tag(partial: Field, request_id: Field, entry: Field) -> Field {
    permuted(domain(PSS_EXIT_TAG, entry), partial, request_id)[0]
}

/// The `j`-th filler of a round of chain request `request_id` whose
/// requester's partial commitment is `partial`. Total: one permutation.
pub fn exit_filler(partial: Field, request_id: Field, j: u32) -> Field {
    permuted(domain(PSS_EXIT_FILLER, j as Field), partial, request_id)[0]
}

/// What a tagged write needs beside the tree update's own arguments.
pub struct Tagging<let K: u32> {
    /// the chain request id (`SharedIntake::request_id`), public
    pub request_id: Field,
    /// the requester's partial commitment (`SharedIntake::partial`): the
    /// fillers' secret
    pub requester: Field,
    /// per slot, the partial commitment of the note this round issues for
    /// the slot's entry when it writes it; the header slot's is not read
    pub partials: [Field; K],
}

/// A tagged write (`Tree::update_private_tagged`): the tree as written,
/// each slot's new path nodes (`Tree::update_paths`), and the exit outputs.
pub struct Tagged<let K: u32, let W: u32, let D: u32> {
    pub updated: Updated<K, W>,
    pub paths: [[Field; D]; K],
    /// per entry slot: the old tag where the slot spends one, else the
    /// slot's filler (0 at the header)
    outputs: [Field; K],
    /// per slot: its index where written and an entry slot, else 0
    entries: [Field; K],
    /// the slots that hold no entry before the first that does: 1 for a
    /// `headed` tree, else 0
    first: u32,
    request_id: Field,
    requester: Field,
}

impl<let K: u32, let W: u32, let D: u32> Tagged<K, W, D> {
    /// The N values every landing of the app pushes as nullifiers: each
    /// entry slot's output in slot order, then fillers up to N (filler `j`
    /// for place `j`), so every round type outputs N. N must be at least the
    /// entry slots: an assertion on constants of the round, which the
    /// compiler folds. Total: one permutation per padding filler.
    pub fn nullifiers<let N: u32>(self) -> [Field; N] {
        // total-lint: allow N, K and whether the tree is headed are constants of the round: the assertion folds at compile time and no request reaches it
        assert(N + self.first >= K, "exit: fewer nullifiers than entry slots");
        let mut out = [0; N];
        for j in 0..N {
            if j + self.first < K {
                out[j] = self.outputs[(j + self.first) % K];
            } else {
                out[j] = exit_filler(self.requester, self.request_id, j);
            }
        }
        out
    }

    /// Slot k's leaf index when the round wrote the slot and it holds an
    /// entry, else 0: the value an app's note must take the entry it names
    /// from (rule 2). No constraint. Two rules for the app:
    ///
    /// - 0 means "no entry", and the app's exit refuses it, so a tagged
    ///   tree must hold no entry at index 0: a `headed` tree keeps its
    ///   header there; a tree without one must leave index 0 unused, or that
    ///   entry can never exit.
    /// - `entry(k)` goes only into the note that completes `partials[k]`,
    ///   the one whose tag the leaf stores. Another note of the same round
    ///   that named the entry (a liquidator's own, say) would carry a tag
    ///   the leaf never held: nothing would ever spend it, and it would exit.
    pub fn entry(self, k: u32) -> Field {
        self.entries[k]
    }
}

impl<let K: u32, let D: u32, let W: u32> Tree<K, D, W> {
    /// `update_private` with the exit tags (module doc): each
    /// written entry slot's new leaf holds `exit_tag(tagging.partials[k],
    /// request_id, index_k)` in its second-to-last element (the app's value
    /// there in `new_leaves` and `kept` is replaced), and the outputs and
    /// entries of `Tagged`. The write flag the tags select on is the one the
    /// update writes by (`Tree::write_flags`), so the tags and the write
    /// cannot disagree. A slot that is not written keeps its leaf and its
    /// hash, its tag unspent.
    ///
    /// Constraints: `update_private`'s, and per entry slot one
    /// permutation over shared values, an equality gadget on the old hash and
    /// the selects.
    pub fn update_private_tagged(
        self,
        placed: bool,
        opened: bool,
        ok: bool,
        writes: [bool; K],
        reblind: [bool; K],
        new_leaves: [[Field; W]; K],
        kept: [[Field; W]; K],
        r_new: [Field; K],
        tagging: Tagging<K>,
    ) -> Tagged<K, W, D> {
        std::static_assert(W >= 3, "a tagged leaf holds a value, its exit tag and its blinding");
        std::static_assert(D <= 120, "an entry index enters a tag above 2^128, below 2^248");
        let (lands, written) = self.private_writes(opened, ok, writes, reblind);
        let (_, write) = self.write_flags(placed, written);
        let mut fresh = new_leaves;
        let mut held = kept;
        let mut outputs = [0; K];
        let mut entries = [0; K];
        let first = (!self.entry_slot(0)) as u32;
        for k in 0..K {
            if self.entry_slot(k) {
                let w = write[k];
                let s = permuted(
                    select_field(
                        w,
                        domain(PSS_EXIT_TAG, self.indices[k]),
                        domain(PSS_EXIT_FILLER, k as Field - first as Field),
                    ),
                    select_field(w, tagging.partials[k], tagging.requester),
                    tagging.request_id,
                );
                // stored only where written, where it is the slot's tag
                fresh[k][W - 2] = s[0];
                held[k][W - 2] = s[0];
                let spends = w & !is_zero(self.old_hashes[k]);
                outputs[k] = select_field(spends, self.leaves[k][W - 2], select_field(w, s[1], s[0]));
                entries[k] = select_field(w, self.indices[k], 0);
            }
        }
        let (updated, paths) = self.write_private(placed, lands, written, fresh, held, r_new);
        Tagged {
            updated,
            paths,
            outputs,
            entries,
            first,
            request_id: tagging.request_id,
            requester: tagging.requester,
        }
    }
}

/// A tagged write in either family's form (`super::family::Change`):
/// `Tree::update` under a public outcome, whose leaves hold no exit tag and
/// whose landing pushes no nullifier, and `Tree::update_private_tagged` under
/// a private one. The app's round function makes it with
/// `Tree::change_tagged`; it leaves a `TaggedWrite`.
pub struct TaggedChange<let K: u32, let D: u32, let W: u32> {
    pub change: TreeChange<K, D, W>,
    pub tagging: Tagging<K>,
}

/// What a tagged write leaves: the key in the access's form (`written`,
/// `tree::Access`), the N values its landing pushes as nullifiers
/// (`Tagged::nullifiers`) and each slot's entry (`Tagged::entry`). Under a
/// public outcome both are zeros.
pub struct TaggedWrite<S, let K: u32, let N: u32> {
    pub written: S,
    pub nullifiers: [Field; N],
    entries: [Field; K],
}

impl<S, let K: u32, let N: u32> TaggedWrite<S, K, N> {
    /// Slot k's leaf index when the round wrote the slot and it holds an
    /// entry, else 0 (`Tagged::entry`, whose two rules apply). No constraint.
    pub fn entry(self, k: u32) -> Field {
        self.entries[k]
    }
}

impl<let K: u32, let D: u32, let W: u32> Tree<K, D, W> {
    /// `Tree::change` with the exit tags (`TaggedChange`): `tagging` is read
    /// by the private form only. No constraint.
    pub fn change_tagged(
        self,
        placed: bool,
        ok: bool,
        writes: [bool; K],
        reblind: [bool; K],
        new_leaves: [[Field; W]; K],
        kept: [[Field; W]; K],
        r_new: [Field; K],
        tagging: Tagging<K>,
    ) -> TaggedChange<K, D, W> {
        TaggedChange { change: self.change(placed, ok, writes, reblind, new_leaves, kept, r_new), tagging }
    }
}

impl<S, let K: u32, let D: u32, let W: u32, let N: u32> Change<TaggedWrite<S, K, N>> for TaggedChange<K, D, W>
where
    S: Access<K, D, W>,
{
    fn plain(self) -> TaggedWrite<S, K, N> {
        let written: S = self.change.plain();
        TaggedWrite { written, nullifiers: [0; N], entries: [0; K] }
    }

    fn private(self, opened: bool) -> TaggedWrite<S, K, N> {
        let c = self.change;
        let tagged = c.tree.update_private_tagged(
            c.placed,
            opened,
            c.ok,
            c.writes,
            c.reblind,
            c.new_leaves,
            c.kept,
            c.r_new,
            self.tagging,
        );
        TaggedWrite { written: S::of(tagged.updated, tagged.paths), nullifiers: tagged.nullifiers(), entries: tagged.entries }
    }
}

mod tests {
    use super::{exit_filler, exit_tag, PSS_EXIT_FILLER, PSS_EXIT_TAG, Tagged, TaggedWrite, Tagging};
    use crate::test_support::{ascii, full};
    use crate::tip::family::Change;
    use crate::tip::tree::{load, Oblivious, Tree, Updated};
    use protocol_types::hash::poseidon2_hash;
    use total::core::TWO_POW_128;

    global NS: Field = 0x7196;
    global KEY: Field = 0xa003;
    global D: u32 = 3;
    global W: u32 = 3;
    global REQUEST: Field = 0x1d;
    global REQUESTER: Field = 0x9a;
    global P1: Field = 0xa1;
    global P2: Field = 0xa2;

    /// A depth-3 tree of `[value, tag, blinding]` leaves, `filled` (index,
    /// leaf) of the eight, loaded at the slots `at` with the first `n_used`
    /// used, slot 0 the header leaf 0.
    fn book<let F: u32, let K: u32>(filled: [(Field, [Field; W]); F], at: [Field; K], n_used: Field) -> Tree<K, D, W> {
        unheaded(filled, at, n_used).headed()
    }

    /// `book` without a header: every slot holds an entry.
    fn unheaded<let F: u32, let K: u32>(filled: [(Field, [Field; W]); F], at: [Field; K], n_used: Field) -> Tree<K, D, W> {
        let (_, hashes, siblings, leaves) = full(NS, KEY, filled, at);
        load(NS, KEY, leaves, hashes, siblings, at, n_used)
    }

    /// The header at 0, position 1 with tag 0x7a1, position 2 with tag 0x7a2.
    fn filled() -> [(Field, [Field; W]); 3] {
        [(0, [100, 0, 7]), (1, [10, 0x7a1, 8]), (2, [20, 0x7a2, 9])]
    }

    fn tagging<let K: u32>(partials: [Field; K]) -> Tagging<K> {
        Tagging { request_id: REQUEST, requester: REQUESTER, partials }
    }

    /// A write of every used slot, the header re-blinded, the positions
    /// written where `writes`; leaves `[v + 1, 0, r]`.
    fn write<let K: u32>(t: Tree<K, D, W>, opened: bool, writes: [bool; K], partials: [Field; K], r: Field) -> Tagged<K, W, D> {
        let mut new_leaves = [[0; W]; K];
        let mut reblind = [false; K];
        for k in 0..K {
            new_leaves[k] = [t.leaves[k][0] + 1, 0, 0];
            reblind[k] = k == 0;
        }
        let mut r_new = [0; K];
        for k in 0..K {
            r_new[k] = r + k as Field;
        }
        t.update_private_tagged(true, opened, true, writes, reblind, new_leaves, t.leaves, r_new, tagging(partials))
    }

    #[test]
    fn the_domains_are_the_labels() {
        assert_eq(ascii("pss.exit_tag"), PSS_EXIT_TAG);
        assert_eq(ascii("pss.exit_filler"), PSS_EXIT_FILLER);
    }

    // Each is Aztec's three-element poseidon2_hash of its labelled preimage.
    #[test]
    fn the_hashes_are_poseidon2_of_their_preimages() {
        assert_eq(exit_tag(P1, REQUEST, 5), poseidon2_hash([PSS_EXIT_TAG + TWO_POW_128 * 5, P1, REQUEST]));
        assert_eq(exit_filler(P1, REQUEST, 3), poseidon2_hash([PSS_EXIT_FILLER + TWO_POW_128 * 3, P1, REQUEST]));
    }

    // Every input changes a tag, and an index never aliases a filler's place.
    #[test]
    fn every_input_changes_a_tag() {
        let t = exit_tag(P1, REQUEST, 1);
        assert(t != exit_tag(P2, REQUEST, 1));
        assert(t != exit_tag(P1, REQUEST + 1, 1));
        assert(t != exit_tag(P1, REQUEST, 2));
        assert(t != exit_filler(P1, REQUEST, 1));
        assert(exit_filler(P1, REQUEST, 0) != exit_filler(P1, REQUEST, 1));
    }

    // A written slot that held a leaf outputs the old leaf's tag and stores
    // the tag of the note the round issues for it; the note names it.
    #[test]
    fn a_written_slot_spends_its_old_tag() {
        let t = book(filled(), [0, 1], 2);
        let tagged = write(t, true, [true, true], [0, P1], 0x50);
        assert_eq(tagged.updated.write, [true, true]);
        assert_eq(tagged.nullifiers::<1>(), [0x7a1]);
        assert_eq(tagged.updated.stored[1][1], exit_tag(P1, REQUEST, 1));
        assert_eq(tagged.updated.stored[1][0], 11);
        assert_eq(tagged.entry(1), 1);
        // the header holds no tag
        assert_eq(tagged.updated.stored[0][1], 0);
        assert_eq(tagged.entry(0), 0);
    }

    // `Tree::change_tagged` in the private form is the tagged write, in
    // either access's form; in the public form it writes the new leaves as
    // `Tree::update` does, and outputs no tag and names no entry.
    #[test]
    fn a_tagged_change_takes_the_familys_form() {
        let t = book(filled(), [0, 1], 2);
        let new_leaves = [[101, 0, 0], [11, 0, 0]];
        let r_new = [0x50, 0x51];
        let change = t.change_tagged(true, true, [true, true], [true, false], new_leaves, t.leaves, r_new, tagging([0, P1]));
        let tagged = write(t, true, [true, true], [0, P1], 0x50);
        let private: TaggedWrite<Oblivious<2, W, D, 2>, 2, 1> = change.private(true);
        assert_eq(private.written.updated.new_c, tagged.updated.new_c);
        assert_eq(private.written.paths, tagged.paths);
        assert_eq(private.nullifiers, tagged.nullifiers::<1>());
        assert_eq(private.entry(1), 1);
        let public: TaggedWrite<Updated<2, W>, 2, 1> = change.plain();
        assert_eq(public.written.new_c, t.update(true, [true, true], new_leaves).new_c);
        assert_eq(public.nullifiers, [0]);
        assert_eq(public.entry(1), 0);
    }

    // A slot the round does not write keeps its leaf, its hash and its tag;
    // its output is the requester's filler and the note names nothing.
    #[test]
    fn an_unwritten_slot_outputs_a_filler() {
        let t = book(filled(), [0, 2], 2);
        let tagged = write(t, true, [true, false], [0, P1], 0x50);
        assert_eq(tagged.updated.write, [true, false]);
        assert_eq(tagged.updated.stored[1], [20, 0x7a2, 9]);
        assert_eq(tagged.updated.new_hashes[1], t.old_hashes[1]);
        assert_eq(tagged.nullifiers::<1>(), [exit_filler(REQUESTER, REQUEST, 0)]);
        assert_eq(tagged.entry(1), 0);
    }

    // An opening (a written slot that held no leaf) stores a tag and spends
    // none: its output is neither its tag nor a filler anyone recomputes.
    #[test]
    fn an_opening_stores_a_tag_and_outputs_a_filler() {
        let t = book(filled(), [0, 3], 2);
        let tagged = write(t, true, [true, true], [0, P1], 0x50);
        assert_eq(tagged.updated.write, [true, true]);
        let tag = exit_tag(P1, REQUEST, 3);
        assert_eq(tagged.updated.stored[1][1], tag);
        let out = tagged.nullifiers::<1>()[0];
        assert(out != tag);
        assert(out != exit_filler(REQUESTER, REQUEST, 0));
        assert(out != 0);
        assert_eq(tagged.entry(1), 3);
    }

    // Shares that do not open C write no entry slot, whatever the prover
    // named, and output fillers whatever partial commitment it supplied.
    #[test]
    fn a_round_whose_shares_do_not_open_writes_no_entry() {
        let t = book(filled(), [0, 1], 2);
        let tagged = write(t, false, [true, true], [0, P1], 0x50);
        assert_eq(tagged.updated.write, [true, false]);
        assert_eq(tagged.updated.stored[1], [10, 0x7a1, 8]);
        assert_eq(tagged.nullifiers::<1>(), [exit_filler(REQUESTER, REQUEST, 0)]);
        assert_eq(tagged.entry(1), 0);
        // the slot keeps its leaf whatever the policy: re-blinding it would spend its tag
        let mut reblinds = t.leaves;
        reblinds[1] = [10, 0, 0];
        let again = t.update_private_tagged(true, false, true, [true, true], [true, true], reblinds, t.leaves, [1, 2], tagging([0, P1]));
        assert_eq(again.updated.write, [true, false]);
        assert_eq(again.nullifiers::<1>(), [exit_filler(REQUESTER, REQUEST, 0)]);
    }

    // A slot whose policy does not write an empty leaf never writes it, so
    // it outputs no tag of its own.
    #[test]
    fn an_empty_slot_is_written_only_by_the_round() {
        let t = book(filled(), [0, 3], 2);
        let tagged = write(t, true, [true, false], [0, P1], 0x50);
        assert_eq(tagged.updated.write, [true, false]);
        assert_eq(tagged.updated.new_hashes[1], 0);
        assert_eq(tagged.nullifiers::<1>(), [exit_filler(REQUESTER, REQUEST, 0)]);
    }

    // A header-only round outputs N distinct fillers, each the requester's.
    #[test]
    fn a_header_only_round_outputs_fillers() {
        let t: Tree<1, D, W> = book(filled(), [0], 1);
        let tagged = write(t, true, [true], [0], 0x50);
        let n = tagged.nullifiers::<3>();
        assert_eq(n, [exit_filler(REQUESTER, REQUEST, 0), exit_filler(REQUESTER, REQUEST, 1), exit_filler(REQUESTER, REQUEST, 2)]);
        assert(n[0] != n[1]);
    }

    // Two written slots that carry one partial commitment store two tags.
    #[test]
    fn two_slots_with_one_partial_get_two_tags() {
        let t = book(filled(), [0, 1, 2], 3);
        let tagged = write(t, true, [true, true, true], [0, P1, P1], 0x50);
        assert(tagged.updated.stored[1][1] != tagged.updated.stored[2][1]);
        assert_eq(tagged.nullifiers::<2>(), [0x7a1, 0x7a2]);
        assert_eq([tagged.entry(1), tagged.entry(2)], [1, 2]);
    }

    // Two attempts of one request (other blindings) store the same tag and
    // output the same values: a tag depends on the chain request id alone.
    #[test]
    fn attempts_of_one_request_agree() {
        let t = book(filled(), [0, 1], 2);
        let a = write(t, true, [true, true], [0, P1], 0x50);
        let b = write(t, true, [true, true], [0, P1], 0x60);
        assert(a.updated.new_hashes[1] != b.updated.new_hashes[1]);
        assert_eq(a.updated.stored[1][1], b.updated.stored[1][1]);
        assert_eq(a.nullifiers::<1>(), b.nullifiers::<1>());
        let u = book(filled(), [0, 2], 2);
        assert_eq(write(u, true, [true, false], [0, P1], 0x50).nullifiers::<1>(), write(u, true, [true, false], [0, P1], 0x60).nullifiers::<1>());
    }

    // A round whose placement fails writes nothing and names nothing.
    #[test]
    fn an_unplaced_round_writes_nothing() {
        let t = book(filled(), [0, 1], 2);
        let tagged = t.update_private_tagged(false, true, true, [true, true], [true, true], t.leaves, t.leaves, [1, 2], tagging([0, P1]));
        assert_eq(tagged.updated.write, [false, false]);
        assert_eq(tagged.nullifiers::<1>(), [exit_filler(REQUESTER, REQUEST, 0)]);
        assert_eq(tagged.entry(1), 0);
    }

    // A tree without a header: every slot is an entry slot and the
    // nullifiers start at slot 0. An entry at index 0 is written but its
    // `entry` reads 0, "no entry" (`Tagged::entry`'s first rule), so it
    // could never exit.
    #[test]
    fn an_unheaded_tree_tags_every_slot() {
        let tagged = write(unheaded(filled(), [1, 2], 2), true, [true, true], [P1, P2], 0x50);
        assert_eq(tagged.updated.write, [true, true]);
        assert_eq(tagged.nullifiers::<2>(), [0x7a1, 0x7a2]);
        assert_eq([tagged.entry(0), tagged.entry(1)], [1, 2]);
        assert_eq(tagged.updated.stored[0][1], exit_tag(P1, REQUEST, 1));
        let at_zero = write(unheaded(filled(), [0, 1], 2), true, [true, true], [P1, P2], 0x50);
        assert_eq(at_zero.updated.write, [true, true]);
        assert_eq([at_zero.entry(0), at_zero.entry(1)], [0, 1]);
    }
}
