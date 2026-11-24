//! A chain-held key at the tip: what its contract slot holds, and how a
//! round reads and writes it.
//!
//! The slot holds `commitment(namespace, slot, fields, blinding)`. A round
//! loads the vector `[fields..., blinding]` (LOAD of the key it reads), is
//! handed a fresh blinding (SAMPLE 1), and outputs the commitment of the
//! loaded vector (`old_c`, the manifest's commitment_slot old) and the
//! commitment of the vector it hands to TACEO_store (`new_c`, the key's
//! outputs[].note_hash). Apply requires the slot to equal `old_c` and
//! writes `new_c`.

use crate::mpc_store;
use super::family::Change;
use total::cmp::eq;
use total::core::select_field;
use total::ctl::Outcome;
use total::hash::p2_hash_sep;

/// Domain separator of the slot commitment, ASCII "pss.tip.state" as a
/// big-endian integer.
pub global TIP_STATE_SEP: Field = 0x7073732e7469702e7374617465;

/// The slot commitment of one chain-held key:
/// p2_hash_sep([namespace, slot, fields..., blinding], TIP_STATE_SEP),
/// which is poseidon2([TIP_STATE_SEP, namespace, slot, fields...,
/// blinding]).
///
/// What the commitment binds: the namespace and the key's slot as well as
/// the vector and its blinding (a hash of the state fields and a
/// randomness, plus the two public prefix values, as pss_core's note hash
/// binds its slot). The machine never recomputes it:
/// a record's note hash is the value the round output, and apply only
/// compares old_c with the slot and writes new_c. Binding the slot ties
/// the vector the nodes LOAD and STORE (from $state_keys.reads[0] and
/// $state_keys.writes[0]) to the slot the contract compares, so a request naming
/// another key gives an old_c the contract's slot cannot match; binding
/// the namespace keeps one namespace's commitment from standing for
/// another's. Hashing costs ceil((N + 4) / 3) permutations; dropping the
/// namespace and the slot saves at most one and loses those bindings.
///
/// Total: p2_hash_sep emits only permutation black boxes and additions.
pub fn commitment<let N: u32>(
    namespace: Field,
    slot: Field,
    fields: [Field; N],
    blinding: Field,
) -> Field {
    p2_hash_sep(
        [namespace, slot].concat(fields).concat([blinding]),
        TIP_STATE_SEP,
    )
}

/// A chain-held key as a round loads it: the key alone, whatever the
/// intake (`load`; an intake adds only its binding, `super::intake`).
pub struct Loaded<let N: u32> {
    /// the namespace, PUBLIC $namespace (the app contract's address)
    pub namespace: Field,
    /// the slot the round reads, PUBLIC $state_keys.reads[0]
    pub in_slot: Field,
    /// the slot the round writes, PUBLIC $state_keys.writes[0]
    pub out_slot: Field,
    /// the loaded vector before its blinding (LOAD slice [0, N])
    pub fields: [Field; N],
    /// the loaded blinding (the same LOAD, slice [N, N + 1])
    pub r_old: Field,
    /// the new blinding, SAMPLE 1; stored only when the round succeeds
    pub r_new: Field,
}

/// The key a round loads: the namespace, the slot it reads and the slot it
/// writes (the round's `in_slots[0]` and `out_slots[0]`), the LOADed vector
/// and blinding, and the SAMPLEd new blinding. No constraint.
pub fn load<let N: u32>(
    namespace: Field,
    in_slot: Field,
    out_slot: Field,
    fields: [Field; N],
    r_old: Field,
    r_new: Field,
) -> Loaded<N> {
    Loaded { namespace, in_slot, out_slot, fields, r_old, r_new }
}

/// What a round leaves at a chain-held key.
///
/// The fail rule, enforced here: on outcome.ok = false the stored vector is
/// the loaded one under r_old, and new_c is the value the written slot
/// holds, so apply's no-op leaves the slot and the result agreeing. When
/// the round reads and writes the same slot that is old_c; when it writes
/// a slot it does not read (a create), it is 0, the empty slot's value
/// (pss_public_contract's `assert_failed_round_keeps_its_state`).
pub struct Round<let N: u32> {
    pub outcome: Outcome,
    /// the commitment of the loaded vector at in_slot
    pub old_c: Field,
    /// the commitment of the stored vector at out_slot when ok; the
    /// written slot's current value when not (above)
    pub new_c: Field,
    /// the vector to store, before the blinding
    pub fields: [Field; N],
    /// the blinding to store: r_new on ok, r_old otherwise
    pub blinding: Field,
}

impl<let N: u32> Loaded<N> {
    /// The blinding the round stores: r_new when the round succeeds, r_old
    /// when not.
    ///
    /// The blinding on failure is r_old, so on ok = false the stored vector
    /// is the loaded one and new_c = old_c.
    /// Apply leaves a chain-held slot alone on ok = false, and the next
    /// round's record must match the slot's commitment, so a fresh blinding
    /// on failure would leave a sealed state no slot names. (A note-held
    /// round re-randomises on failure because a consumed note hash may not
    /// be stored again; chain-held keys are never consumed.)
    ///
    /// Total: one select.
    pub fn blinding(self, outcome: Outcome) -> Field {
        outcome.guard(self.r_new, self.r_old)
    }

    /// The round over this key: `fields` is the vector the app's round
    /// function computed, stored when outcome.ok and replaced by the loaded
    /// one when not (the fail rule is this brick's, not the app's). Commits
    /// to the loaded vector at in_slot and to the stored one, under
    /// `blinding(outcome)`, at out_slot; on failure new_c is the written
    /// slot's current value (`Round`). On ok, and on a failed round over one
    /// slot, new_c is computed from exactly the vector `store` hands to
    /// TACEO_store, so the record the nodes seal matches the commitment the
    /// result carries.
    ///
    /// Total: the guard's selects, one equality, one select and two
    /// `commitment`s.
    pub fn finish(self, outcome: Outcome, fields: [Field; N]) -> Round<N> {
        let fields = outcome.guard(fields, self.fields);
        let blinding = self.blinding(outcome);
        let old_c = commitment(self.namespace, self.in_slot, self.fields, self.r_old);
        let stored_c = commitment(self.namespace, self.out_slot, fields, blinding);
        // a failed create leaves the empty slot's 0
        let kept = select_field(eq(self.in_slot, self.out_slot), stored_c, 0);
        Round { outcome, old_c, new_c: outcome.guard(stored_c, kept), fields, blinding }
    }

    /// The round over this key under private outcomes (the secret-shared intakes):
    /// as `finish`, the new vector when `opened` and outcome.ok and the
    /// loaded one when not, but always under the sampled r_new, so new_c
    /// differs from old_c on every outcome and the slot write the contract
    /// makes on every round (pss_public_contract `apply_round` over an
    /// `OutcomeApply`) tells nothing of `ok` (docs/ARCHITECTURE.md section 6,
    /// "Private outcomes": a fresh blinding on every outcome). `opened` is
    /// the intake's binding, whether C opens to the request's inputs
    /// (`intake::SharedIntake::opens`): no round lands the effect of inputs
    /// nobody committed, whatever its outcome says. Commits to the loaded
    /// vector at in_slot and to the stored one at out_slot, from exactly the
    /// vector `store` hands to TACEO_store.
    ///
    /// Total: one AND, the selects and two `commitment`s.
    pub fn finish_private(self, opened: bool, outcome: Outcome, fields: [Field; N]) -> Round<N> {
        let fields = Outcome { ok: opened & outcome.ok, code: outcome.code }.guard(fields, self.fields);
        let old_c = commitment(self.namespace, self.in_slot, self.fields, self.r_old);
        let new_c = commitment(self.namespace, self.out_slot, fields, self.r_new);
        Round { outcome, old_c, new_c, fields, blinding: self.r_new }
    }
}

/// A write to a chain-held key in either family's form (`super::family::
/// Change`): `Loaded::finish` under a public outcome, `Loaded::finish_private`
/// under a private one. The app's round function makes it with
/// `Loaded::change` and hands it to `family::Checked::write`.
pub struct SlotChange<let N: u32> {
    pub key: Loaded<N>,
    pub outcome: Outcome,
    pub fields: [Field; N],
}

impl<let N: u32> Loaded<N> {
    /// The write of `fields` under `outcome` (`SlotChange`), in the form the
    /// round's intake family picks. No constraint.
    pub fn change(self, outcome: Outcome, fields: [Field; N]) -> SlotChange<N> {
        SlotChange { key: self, outcome, fields }
    }
}

impl<let N: u32> Change<Round<N>> for SlotChange<N> {
    fn plain(self) -> Round<N> {
        self.key.finish(self.outcome, self.fields)
    }

    fn private(self, opened: bool) -> Round<N> {
        self.key.finish_private(opened, self.outcome, self.fields)
    }
}

impl<let N: u32> Round<N> {
    /// Hand the stored vector to the machine as TACEO_store("out<j>",
    /// [fields..., blinding]), j the key's position in the round's
    /// out_slots (a constant; mpc_store's key convention).
    pub fn store(self, j: u32) {
        // Safety: side-effect-only oracle (mpc_store); the nodes keep the
        // stored vector's shares, which new_c commits to
        unsafe { mpc_store::store_out_note(j, self.fields, self.blinding) };
    }
}

/// The round that creates a chain-held key at `out_slot` (an init round,
/// never queued): it reads no key, so old_c is 0, the empty slot's value, and
/// it stores `fields` under `blinding` with their commitment as new_c. No
/// constraint but the commitment's permutations.
pub fn create<let N: u32>(
    namespace: Field,
    out_slot: Field,
    fields: [Field; N],
    blinding: Field,
) -> Round<N> {
    Round {
        outcome: Outcome::good(),
        old_c: 0,
        new_c: commitment(namespace, out_slot, fields, blinding),
        fields,
        blinding,
    }
}

mod tests {
    use super::{commitment, create, load, Loaded, TIP_STATE_SEP};
    use total::ctl::Outcome;
    use total::hash::p2_hash;
    use crate::test_support::ascii;

    global NS: Field = 0xc0ffee;
    global SLOT: Field = 0xa002;

    fn key() -> Loaded<2> {
        load(NS, SLOT, SLOT, [3, 4], 5, 6)
    }

    #[test]
    fn commitment_binds_namespace_slot_vector_and_blinding() {
        let c = commitment(NS, SLOT, [3, 4], 5);
        assert(c != commitment(NS + 1, SLOT, [3, 4], 5));
        assert(c != commitment(NS, SLOT + 1, [3, 4], 5));
        assert(c != commitment(NS, SLOT, [3, 9], 5));
        assert(c != commitment(NS, SLOT, [3, 4], 9));
        // the layout: the separator first, then the five elements
        assert_eq(c, p2_hash([TIP_STATE_SEP, NS, SLOT, 3, 4, 5]));
    }

    #[test]
    fn the_separator_is_ascii_pss_tip_state() {
        assert_eq(ascii("pss.tip.state"), TIP_STATE_SEP);
    }

    #[test]
    fn a_good_round_stores_the_new_vector_under_r_new() {
        let r = key().finish(Outcome::good(), [7, 8]);
        assert_eq(r.blinding, 6);
        assert_eq(r.fields, [7, 8]);
        assert_eq(r.old_c, commitment(NS, SLOT, [3, 4], 5));
        assert_eq(r.new_c, commitment(NS, SLOT, [7, 8], 6));
    }

    #[test]
    fn a_failed_round_keeps_r_old_and_the_commitment() {
        // the app's vector is discarded: the brick stores the loaded one
        let r = key().finish(Outcome::good().require(false, 3), [7, 8]);
        assert(!r.outcome.ok);
        assert_eq(r.outcome.code, 3);
        assert_eq(r.fields, [3, 4]);
        assert_eq(r.blinding, 5);
        assert_eq(r.new_c, r.old_c);
    }

    #[test]
    fn the_slots_enter_their_own_commitments() {
        let r = load(NS, 1, 2, [3, 4], 5, 6).finish(Outcome::good(), [7, 8]);
        assert_eq(r.old_c, commitment(NS, 1, [3, 4], 5));
        assert_eq(r.new_c, commitment(NS, 2, [7, 8], 6));
    }

    #[test]
    fn a_private_round_re_blinds_on_every_outcome() {
        let good = key().finish_private(true, Outcome::good(), [7, 8]);
        assert_eq(good.fields, [7, 8]);
        assert_eq(good.blinding, 6);
        assert_eq(good.new_c, commitment(NS, SLOT, [7, 8], 6));
        // a failed round keeps the loaded vector, under the new blinding
        let failed = key().finish_private(true, Outcome::good().require(false, 3), [7, 8]);
        assert(!failed.outcome.ok);
        assert_eq(failed.fields, [3, 4]);
        assert_eq(failed.blinding, 6);
        assert_eq(failed.old_c, commitment(NS, SLOT, [3, 4], 5));
        assert_eq(failed.new_c, commitment(NS, SLOT, [3, 4], 6));
        assert(failed.new_c != failed.old_c);
        // shares that do not open C land nothing, whatever the outcome says,
        // and still re-blind
        let unbound = key().finish_private(false, Outcome::good(), [7, 8]);
        assert_eq(unbound.fields, [3, 4]);
        assert_eq(unbound.new_c, commitment(NS, SLOT, [3, 4], 6));
        assert(unbound.new_c != unbound.old_c);
    }

    #[test]
    fn create_commits_the_first_vector_over_the_empty_slot() {
        let r = create(NS, SLOT, [7, 8], 6);
        assert(r.outcome.ok);
        assert_eq(r.old_c, 0);
        assert_eq(r.new_c, commitment(NS, SLOT, [7, 8], 6));
        assert_eq(r.fields, [7, 8]);
        assert_eq(r.blinding, 6);
    }

    #[test]
    fn a_failed_create_leaves_the_empty_slot() {
        // the round writes slot 2 without reading it: on failure its new_c is
        // 0, the value the slot holds, never a commitment it would not hold
        let r = load(NS, 1, 2, [3, 4], 5, 6).finish(Outcome::good().require(false, 1), [7, 8]);
        assert_eq(r.old_c, commitment(NS, 1, [3, 4], 5));
        assert_eq(r.new_c, 0);
        assert_eq(r.fields, [3, 4]);
        assert_eq(r.blinding, 5);
    }
}
