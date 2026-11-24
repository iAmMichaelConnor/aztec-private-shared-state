//! The intake family as a round circuit sees it (docs/ARCHITECTURE.md
//! section 6): one interface, `Family`, with one implementation per family,
//! so that an app writes its round once, generic over the family, and each
//! main names the family it compiles and declares its inputs.
//!
//! - `Plain`: the non-secret-shared intakes (on-chain intake and receipt
//!   intake), one compiled circuit for both. The request's values are the
//!   round's private inputs, so nothing is checked first; the write is the
//!   public outcome's (`Change::plain`: a failed round leaves the state as
//!   it was); the outputs are the binding `intake::plain` over the app
//!   inputs and the request's partial note, with the partial note echoed
//!   after `ok` (`Written::bound_partial`), which the app's `apply`
//!   completes in public (`value: partial`). A non-secret-shared round that
//!   completes no note (`value: none`, an init or a machine test round)
//!   outputs `Written::bound` without a family.
//! - `SharedIntake`: the secret-shared intakes, one compiled circuit for
//!   both. The round checks first that C opens to the request's values
//!   (`SharedIntake::opens`, under the app's mismatch code); the write is
//!   the private outcome's (`Change::private`: a fresh blinding on every
//!   outcome, the effect landed only when C opens); the outputs are the
//!   private outcome (`outcome::finish`: the encrypted outcome and the
//!   request's partial note completed with it; when C does not open, the
//!   mismatch code alone, under the mismatch domain's nonce).
//!
//! A round under either family is three calls, in this order:
//!
//! ```noir
//! let checked = family.check(inputs, CODE_INPUTS_MISMATCH);
//! let step = app::step(key, inputs, checked.first);
//! let written = checked.write(key.change(step.outcome, step.new_fields));
//! checked.finish(written, namespace, vk_hash, inputs, [], step.outputs(), step.fields(), OUTCOME_SLOT, nsk_app)
//! ```
//!
//! and the main ends in `Finished::stored`. Whether C opens is produced in
//! one place, `<SharedIntake as Family>::check`, and consumed by the write
//! (`Checked::write`) and the outputs (`Checked::finish`). Both take the
//! `Checked` itself, whose fields only this module can set, and
//! `outcome::finish` is crate-visible: no app can pass it to a brick. The step starts from `Checked::first`, so the intake's code
//! comes before the app's.
//!
//! Two traits, not one: `Finish` is generic over what the round leaves and
//! outputs (its output type depends on them), while the check and the write
//! are not, so they sit in `Family`, which a call can name without those.

use super::intake::{self, SharedIntake};
use super::outcome::{self, Private};
use super::outputs::{BoundPartial, Finished, Written};
use total::ctl::Outcome;

/// A round main's public prefix: the namespace (PUBLIC `$namespace`, the
/// app contract's address), the circuit's vk hash (hashed into the request
/// id; process_result checks it against the Config's pin) and the key the
/// round reads and the key it writes (`$state_keys.reads[0]` and
/// `$state_keys.writes[0]`), bound into both commitments. A round with
/// pinned reads declares them after it.
pub struct Prefix {
    pub namespace: Field,
    pub vk_hash: Field,
    pub in_slots: [Field; 1],
    pub out_slots: [Field; 1],
}

/// The non-secret-shared intakes: the request's partial note (PUBLIC
/// `$partial_note`, an app input after the others, echoed right after
/// `ok` for apply's public completion) and its salt (`user_nonce`, not
/// checked here: apply compares the request id with the queue's).
pub struct Plain {
    pub partial_note: Field,
    pub user_nonce: Field,
}

/// A family after the intake's check of one request: `first`, the outcome
/// the app's step starts from, and whether the request's values are the
/// ones it committed, which only this module reads (`write`).
pub struct Checked<F> {
    family: F,
    opened: bool,
    /// `Outcome::good()` under `Plain`; under `SharedIntake`, failed with
    /// the app's mismatch code when C does not open
    pub first: Outcome,
}

/// A write to the key a round writes, one implementation per state shape
/// (`slot::SlotChange`, `tree::TreeChange`, `exit::TaggedChange` for a tree
/// with exit tags, `map::MapChange`, or an app's own), in both
/// families' forms, `S` what it leaves at the key (a `Written`); the family
/// picks the form (`Family::write`).
pub trait Change<S> {
    /// The write under a public outcome (`Plain`): the new state when the
    /// round is ok, the loaded one under its old blinding when not.
    fn plain(self) -> S;
    /// The write under a private outcome (`SharedIntake`): a fresh blinding
    /// on every outcome, the new state only when `opened` (C opens) and
    /// the round is ok.
    fn private(self, opened: bool) -> S;
}

/// The intake family: the check a round makes first and the form of its
/// write. Implemented by `Plain` and `SharedIntake`.
pub trait Family {
    /// Check the request: `inputs` are the values C commits to before
    /// `$partial_note`, in ABI order (the app inputs, then any value the
    /// app adds to C, such as a delivery handle), and `mismatch` the app's
    /// code for shares that do not open C. A flag folded into `first`,
    /// never an assertion, so shares that do not open make a no-op round
    /// and the queue moves.
    fn check<let I: u32>(self, inputs: [Field; I], mismatch: Field) -> Checked<Self>;

    /// Write `change` in the family's form (`Checked::write`).
    fn write<C, S>(checked: Checked<Self>, change: C) -> S
    where
        C: Change<S>;
}

/// The round's public outputs under the family, from what it leaves at its
/// key (`S`, a `Written<T>`) and its outcome in both forms: `app`, the app
/// outputs after `ok` under `Plain` (its code first), and `fields`, the
/// outcome plaintext under `SharedIntake` (its code first, at most seven
/// fields). Each family reads the form it outputs.
pub trait Finish<S, O, let T: u32, let N: u32> {
    /// `Finished<S, BoundPartial<O>>` under `Plain`, `Finished<S,
    /// Private<1, 1, T, 1, N + 1>>` under `SharedIntake`
    type Out;

    /// The outputs (`Checked::finish`). `checked` is the family after the
    /// intake's check: whether the request's values are the ones it
    /// committed and the code the round failed first with when they are
    /// not (`Checked::first`); `inputs` are the app inputs in ABI order,
    /// before `$partial_note`; `pinned` the round's pinned values in the
    /// manifest's `public_reads` order (`[]` without pinned reads);
    /// `outcome_slot` the storage slot of the app contract's outcome notes.
    fn finish<let I: u32, let Q: u32>(
        checked: Checked<Self>,
        written: S,
        namespace: Field,
        vk_hash: Field,
        inputs: [Field; I],
        pinned: [Field; Q],
        app: O,
        fields: [Field; N],
        outcome_slot: Field,
        nsk_app: Field,
    ) -> Self::Out;
}

impl<F> Checked<F> {
    /// Write `change` in the family's form: `Change::plain` under `Plain`,
    /// `Change::private` with whether C opens under `SharedIntake`.
    pub fn write<C, S>(self, change: C) -> S
    where
        F: Family,
        C: Change<S>,
    {
        F::write(self, change)
    }

    /// The round's public outputs (`Finish::finish`); the main ends in
    /// `Finished::stored`.
    pub fn finish<S, O, let T: u32, let N: u32, let I: u32, let Q: u32>(
        self,
        written: S,
        namespace: Field,
        vk_hash: Field,
        inputs: [Field; I],
        pinned: [Field; Q],
        app: O,
        fields: [Field; N],
        outcome_slot: Field,
        nsk_app: Field,
    ) -> <F as Finish<S, O, T, N>>::Out
    where
        F: Finish<S, O, T, N>,
    {
        F::finish(
            self,
            written,
            namespace,
            vk_hash,
            inputs,
            pinned,
            app,
            fields,
            outcome_slot,
            nsk_app,
        )
    }

    /// Whether the request's values are the ones it committed (always under
    /// `Plain`): for an app that outputs it as a public value of the
    /// attempt, e.g. the inputs-opened bit an escrowing app's `apply`
    /// refunds on. A write takes it from `write`, never from here.
    pub fn opened(self) -> bool {
        self.opened
    }

    /// The family the round was checked under.
    pub fn family(self) -> F {
        self.family
    }
}

impl Family for Plain {
    /// No check: the request's values are the round's own inputs.
    fn check<let I: u32>(self, _inputs: [Field; I], _mismatch: Field) -> Checked<Self> {
        Checked { family: self, opened: true, first: Outcome::good() }
    }

    fn write<C, S>(_checked: Checked<Self>, change: C) -> S
    where
        C: Change<S>,
    {
        change.plain()
    }
}

impl Family for SharedIntake {
    /// The MPC receipt check (`SharedIntake::opens`): the one place a round
    /// decides whether C opens. Total: one p2_hash, one equality and
    /// `Outcome::require`.
    fn check<let I: u32>(self, inputs: [Field; I], mismatch: Field) -> Checked<Self> {
        let opened = self.opens(inputs);
        Checked { family: self, opened, first: Outcome::good().require(opened, mismatch) }
    }

    fn write<C, S>(checked: Checked<Self>, change: C) -> S
    where
        C: Change<S>,
    {
        change.private(checked.opened)
    }
}

impl<S, O, let T: u32, let N: u32> Finish<S, O, T, N> for Plain
where
    S: Written<T>,
{
    type Out = Finished<S, BoundPartial<O>>;

    /// The request id over the app inputs and the partial note
    /// (`intake::plain`) and the outputs with the partial note after `ok`
    /// (`Written::bound_partial`). Constraints: two p2_hash and
    /// npk_app_hash (`bound_partial`'s).
    fn finish<let I: u32, let Q: u32>(
        checked: Checked<Self>,
        written: S,
        namespace: Field,
        vk_hash: Field,
        inputs: [Field; I],
        _pinned: [Field; Q],
        app: O,
        _fields: [Field; N],
        _outcome_slot: Field,
        nsk_app: Field,
    ) -> Finished<S, BoundPartial<O>> {
        let plain = checked.family;
        let request_id = intake::plain(namespace, vk_hash, inputs.concat([plain.partial_note]), plain.user_nonce);
        written.bound_partial(request_id, nsk_app, plain.partial_note, app)
    }
}

impl<S, O, let T: u32, let N: u32> Finish<S, O, T, N> for SharedIntake
where
    S: Written<T>,
{
    type Out = Finished<S, Private<1, 1, T, 1, N + 1>>;

    /// The private outcome (`outcome::finish`): the request's partial note
    /// completed at `outcome_slot` with `fields`, or with the mismatch code
    /// alone when C does not open (`checked.first`'s code), and that
    /// plaintext encrypted under its note hash's nonce. Constraints:
    /// `outcome::finish`'s.
    fn finish<let I: u32, let Q: u32>(
        checked: Checked<Self>,
        written: S,
        namespace: Field,
        vk_hash: Field,
        _inputs: [Field; I],
        pinned: [Field; Q],
        _app: O,
        fields: [Field; N],
        outcome_slot: Field,
        nsk_app: Field,
    ) -> Finished<S, Private<1, 1, T, 1, N + 1>> {
        outcome::finish(
            written,
            namespace,
            vk_hash,
            checked.family,
            checked.opened,
            checked.first.code,
            pinned,
            fields,
            outcome_slot,
            nsk_app,
        )
    }
}

mod tests {
    use super::{Family, Plain};
    use crate::effects;
    use crate::tip::intake::{self, commit, SharedIntake};
    use crate::tip::outcome::{self, completed_note_hash};
    use crate::tip::slot::{commitment, load, Loaded};
    use total::ctl::Outcome;

    global NS: Field = 0xc0ffee;
    global VK: Field = 0x5a;
    global SLOT: Field = 0xa002;
    global R_OLD: Field = 333;
    global R_NEW: Field = 444;
    global NSK: Field = 777;
    global MISMATCH: Field = 9;
    global INPUTS: [Field; 2] = [25000, 1];

    fn key() -> Loaded<2> {
        load(NS, SLOT, SLOT, [7, 8], R_OLD, R_NEW)
    }

    /// A secret-shared request committing INPUTS, or other values.
    fn shared(opens: bool) -> SharedIntake {
        let c = commit(INPUTS.concat([0x9a, 0x6b, 0x7a]), 0xb1);
        SharedIntake { inputs_hash: if opens { c } else { c + 1 }, partial: 0x9a, outcome_key: 0x6b, outcome_tag: 0x7a, blinding: 0xb1 }
    }

    // Plain checks nothing, writes in the public form (a failed round keeps
    // the loaded vector under r_old) and outputs the binding over the app
    // inputs and the partial note, with the partial note after ok.
    #[test]
    fn plain_writes_the_public_form_and_binds_the_inputs() {
        let plain = Plain { partial_note: 0x9a, user_nonce: 3 };
        let checked = plain.check(INPUTS, MISMATCH);
        assert(checked.first.ok);
        assert(checked.opened());
        let failed = checked.write(key().change(Outcome::good().require(false, 4), [9, 9]));
        assert_eq(failed.fields, [7, 8]);
        assert_eq(failed.new_c, failed.old_c);
        let landed = checked.write(key().change(Outcome::good(), [9, 9]));
        assert_eq(landed.new_c, commitment(NS, SLOT, [9, 9], R_NEW));
        let f = checked.finish(landed, NS, VK, INPUTS, [], [0, 5], [0, 5], 0x1, NSK);
        assert_eq(f.outputs.request_id, intake::plain(NS, VK, INPUTS.concat([0x9a]), 3));
        assert_eq(f.outputs.partial_note, 0x9a);
        assert_eq(f.outputs.ok, 1);
        assert_eq(f.outputs.app, [0, 5]);
        assert_eq(f.outputs.npk_app_hash, effects::npk_app_hash(NSK));
    }

    // SharedIntake checks that C opens: shares that open start the step
    // from a good outcome and land their write under the fresh blinding.
    #[test]
    fn shares_that_open_land_under_the_private_form() {
        let checked = shared(true).check(INPUTS, MISMATCH);
        assert(checked.first.ok);
        assert(checked.opened());
        let round = checked.write(key().change(checked.first, [9, 9]));
        assert_eq(round.fields, [9, 9]);
        assert_eq(round.new_c, commitment(NS, SLOT, [9, 9], R_NEW));
        let f = checked.finish(round, NS, VK, INPUTS, [0x7d0], (), [0, 5], 0x1, NSK);
        let expected = outcome::finish(round, NS, VK, shared(true), true, MISMATCH, [0x7d0], [0, 5], 0x1, NSK);
        assert_eq(f.outputs.request_id, intake::shared(NS, VK, shared(true).inputs_hash));
        assert_eq(f.outputs.machine_request_id, expected.outputs.machine_request_id);
        assert_eq(f.outputs.note_hashes, [completed_note_hash(0x1, 0x9a, [0, 5], f.outputs.request_id)]);
        assert_eq(f.outputs.ciphertext, expected.outputs.ciphertext);
    }

    // Shares that do not open C fail first with the app's mismatch code, and
    // the write lands nothing even when the step says ok: the loaded vector
    // is kept, under the fresh blinding, so the commitment still changes.
    #[test]
    fn shares_that_do_not_open_fail_first_and_land_nothing() {
        let checked = shared(false).check(INPUTS, MISMATCH);
        assert(!checked.first.ok);
        assert_eq(checked.first.code, MISMATCH);
        assert(!checked.opened());
        assert_eq(checked.first.require(false, 4).code, MISMATCH);
        let round = checked.write(key().change(Outcome::good(), [9, 9]));
        assert_eq(round.fields, [7, 8]);
        assert_eq(round.new_c, commitment(NS, SLOT, [7, 8], R_NEW));
        assert(round.new_c != round.old_c);
    }

    // Shares that do not open C finish as `outcome::finish` does with the
    // mismatch code: `Checked` passes whether they open and its first code
    // through.
    #[test]
    fn shares_that_do_not_open_seal_the_mismatch_code_alone() {
        let checked = shared(false).check(INPUTS, MISMATCH);
        let round = checked.write(key().change(Outcome::good(), [9, 9]));
        let f = checked.finish(round, NS, VK, INPUTS, [0x7d0], (), [4, 5], 0x1, NSK);
        let expected = outcome::finish(round, NS, VK, shared(false), false, MISMATCH, [0x7d0], [4, 5], 0x1, NSK);
        assert_eq(f.outputs.note_hashes, expected.outputs.note_hashes);
        assert_eq(f.outputs.ciphertext, expected.outputs.ciphertext);
    }
}
