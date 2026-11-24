//! The outputs of a tip round, after its public parameters, in the order
//! pss_public_contract rebuilds them, flattened in field order: one pipeline
//! whatever the key's shape and the intake.
//!
//! - `Written`: what a round leaves at the key it writes, one implementation
//!   per state shape: a flat key's `super::slot::Round`, a tree-valued key's
//!   `super::tree::Updated`, and under `access: oblivious`
//!   `super::tree::Oblivious`. Each gives the commitment it read and the one it
//!   leaves, whether its writes landed, the new leaf hashes (none for a flat
//!   key) and the store of what the nodes keep.
//! - `Written::bound`: the non-secret-shared intakes' outputs (`Bound`, the result path's
//!   `proved_public_inputs`): the binding first, then the commitments,
//!   `npk_app_hash`, `ok` and `app`, the app's own outputs struct (its code
//!   first, then whatever apply needs).
//! - `Written::bound_partial`: the same under partial-note delivery
//!   (`BoundPartial`, the result path's `PartialResult`): the request's
//!   partial note right after `ok`, which the app's `apply` completes in
//!   public with the app outputs and the request id; returned with the key
//!   as `Finished` (the non-secret-shared family's outputs,
//!   `super::family::Plain`).
//! - `Written::init`: the init round's (`Init`, the init path's).
//! - Private outcomes (the secret-shared intakes): `super::outcome::finish` seals the
//!   outcome into `super::outcome::Private` and returns it with the written
//!   key as `Finished`, which the main ends in (`Finished::stored`).
//!
//! Each finisher hands the stored vector or leaves to the machine
//! (TACEO_store "out0"), `bound_partial` and `outcome::finish` through
//! `Finished::stored`. A round main with no family ends in:
//!
//! ```noir
//! let key = slot::load(namespace, in_slots[0], out_slots[0], fields, r_old, r_new);
//! let r = app::step(key, inputs);
//! r.round.bound(intake::plain(namespace, vk_hash, inputs, user_nonce), nsk_app, r.outputs())
//! ```
use crate::effects;
use super::intake;

/// ASCII "sidecar.result" as a big-endian integer: the first element of
/// every result message the nodes sign over a round's outputs
/// (pss_public_contract re-exports it with the message; sidecar-core's
/// pipeline/result.rs holds the same value).
pub global RESULT_DOMAIN: Field = 0x736964656361722e726573756c74;
use super::slot::Round;
use super::tree::{Oblivious, Updated};

/// The outputs of a round whose proof outputs its binding (both non-secret-shared
/// intakes): `[request_id, old_c, new_c, npk_app_hash, ok, app...]`. apply
/// requires request_id to equal requests[head].
pub struct Bound<O> {
    /// the chain request id the round computed from its inputs
    /// (`super::intake::plain`)
    pub request_id: Field,
    /// the commitment of the state the round loaded (the manifest's
    /// commitment_slot old); apply requires it to equal the slot
    pub old_c: Field,
    /// the commitment of the state handed to TACEO_store (the manifest's
    /// outputs[0].note_hash); the slot's value when ok = 0
    pub new_c: Field,
    /// the namespace's network identity; process_result pins it
    pub npk_app_hash: Field,
    /// 1 when the round applied, 0 when not: a Field, so every output is
    /// one Field the manifest can name
    pub ok: Field,
    /// the app's outputs
    pub app: O,
}

/// `Bound` under partial-note delivery (`outcome: partial`, a
/// non-secret-shared intake): `[request_id, old_c, new_c, npk_app_hash, ok,
/// partial_note, app...]`. The round echoes its PUBLIC `$partial_note` input
/// (an app input covered by the binding), so the proof binds the note the
/// app's `apply` completes; sidecar-core's REGISTER requires the output named
/// `partial_note` right after `ok`.
pub struct BoundPartial<O> {
    pub request_id: Field,
    pub old_c: Field,
    pub new_c: Field,
    pub npk_app_hash: Field,
    pub ok: Field,
    /// the request's partial note, `$partial_note`
    pub partial_note: Field,
    /// the app's outputs, its code first; with the request id they are the
    /// completed note's fields (at most seven)
    pub app: O,
}

/// The outputs of an init round, which creates its key and is never queued:
/// `[request_id, old_c, new_c, npk_app_hash, new_hashes[H]]`, H the leaves a
/// tree-valued key's init writes (0 for a flat key).
pub struct Init<let H: u32> {
    /// the init request id, the non-secret-shared intakes' binding over the init's app
    /// inputs and nonce 0 (`super::intake::plain`); the contract recomputes it
    pub request_id: Field,
    /// 0: the empty slot's value.
    ///
    /// old_c = 0 is the value of a never-written PublicMutable. It gives init the same leading outputs as the
    /// queued rounds (request_id, old_c, new_c, npk_app_hash), so the
    /// contract can apply it with the rounds' "slot equals old_c, then write
    /// new_c" check, which also refuses a second init. The contract's init
    /// path feeds 0 to the verifier for it and writes new_c only while the
    /// slot is 0.
    pub old_c: Field,
    /// the key's first commitment (the manifest's outputs[0].note_hash)
    pub new_c: Field,
    /// the namespace's network identity; the contract pins it
    pub npk_app_hash: Field,
    /// the written leaves' hashes, from which the nodes build the clear tree
    pub new_hashes: [Field; H],
}

/// A round finished under private outcomes: the key it leaves and its public
/// outputs (`super::outcome::finish`).
pub struct Finished<S, O> {
    pub written: S,
    pub outputs: O,
}

impl<S, O> Finished<S, O> {
    /// Hand what the round leaves to the machine (TACEO_store "out0") and
    /// return the public outputs: what a secret-shared main ends in.
    pub fn stored<let T: u32>(self) -> O
    where
        S: Written<T>,
    {
        self.written.keep(0);
        self.outputs
    }
}

/// What a round leaves at the key it writes, `T` the new leaf hashes it
/// outputs (0 for a flat key): the one interface of the outputs axis, which
/// `bound`, `init` and `super::outcome::finish` assemble the same way for
/// every state shape.
pub trait Written<let T: u32> {
    /// `(old_c, new_c)`: the commitment of the state the round loaded and of
    /// the state it leaves
    fn commitments(self) -> (Field, Field);
    /// whether the round's writes landed (a non-secret-shared round's `ok`)
    fn landed(self) -> bool;
    /// the written leaves' new hashes, in slot order
    fn leaf_hashes(self) -> [Field; T];
    /// Hand what the round leaves to the machine as TACEO_store("out<j>"),
    /// j the key's position in the round's out_slots (`Round::store`,
    /// `Updated::store`).
    fn keep(self, j: u32);

    /// Store at out0 and return the outputs under the binding `request_id`.
    ///
    /// Constraints: pss_core's npk_app_hash (the std scalar decomposition of
    /// nsk_app, hint-satisfiable for every Field, and one fixed-base
    /// multi_scalar_mul on the generator, which cannot fail); the store is
    /// an unconstrained side-effect-only oracle.
    fn bound<O>(self, request_id: Field, nsk_app: Field, app: O) -> Bound<O> {
        self.keep(0);
        bound_of::<Self, O, T>(self, request_id, nsk_app, app)
    }

    /// `bound` under partial-note delivery: the same outputs with
    /// `partial_note`, the request's `$partial_note` input, right after `ok`,
    /// returned with the key as `Finished`, which the main ends in
    /// (`Finished::stored`), as under private outcomes. Constraints: those
    /// of `bound`.
    fn bound_partial<O>(
        self,
        request_id: Field,
        nsk_app: Field,
        partial_note: Field,
        app: O,
    ) -> Finished<Self, BoundPartial<O>> {
        let b = bound_of::<Self, O, T>(self, request_id, nsk_app, app);
        let outputs = BoundPartial {
            request_id: b.request_id,
            old_c: b.old_c,
            new_c: b.new_c,
            npk_app_hash: b.npk_app_hash,
            ok: b.ok,
            partial_note,
            app: b.app,
        };
        Finished { written: self, outputs }
    }

    /// Store at out0 and return the init round's outputs, its request id
    /// `plain(namespace, vk_hash, inputs, 0)` over its app inputs. The round
    /// creates the key (`super::slot::create`, `super::tree::empty`).
    ///
    /// Constraints: two p2_hash and npk_app_hash, as `bound`.
    fn init<let I: u32>(
        self,
        namespace: Field,
        vk_hash: Field,
        inputs: [Field; I],
        nsk_app: Field,
    ) -> Init<T> {
        self.keep(0);
        let (_, new_c) = self.commitments();
        Init {
            request_id: intake::plain(namespace, vk_hash, inputs, 0),
            old_c: 0,
            new_c,
            npk_app_hash: effects::npk_app_hash(nsk_app),
            new_hashes: self.leaf_hashes(),
        }
    }
}

/// `Bound` over what `written` leaves, without the store. Constraints:
/// npk_app_hash.
fn bound_of<S, O, let T: u32>(written: S, request_id: Field, nsk_app: Field, app: O) -> Bound<O>
where
    S: Written<T>,
{
    let (old_c, new_c) = written.commitments();
    Bound {
        request_id,
        old_c,
        new_c,
        npk_app_hash: effects::npk_app_hash(nsk_app),
        ok: written.landed() as Field,
        app,
    }
}

impl<let N: u32> Written<0> for Round<N> {
    fn commitments(self) -> (Field, Field) {
        (self.old_c, self.new_c)
    }

    fn landed(self) -> bool {
        self.outcome.ok
    }

    fn leaf_hashes(self) -> [Field; 0] {
        []
    }

    fn keep(self, j: u32) {
        self.store(j)
    }
}

impl<let K: u32, let W: u32> Written<K> for Updated<K, W> {
    fn commitments(self) -> (Field, Field) {
        (self.old_c, self.new_c)
    }

    fn landed(self) -> bool {
        self.ok
    }

    fn leaf_hashes(self) -> [Field; K] {
        self.new_hashes
    }

    fn keep(self, j: u32) {
        self.store(j)
    }
}

impl<let K: u32, let W: u32, let D: u32, let T: u32> Written<T> for Oblivious<K, W, D, T> {
    fn commitments(self) -> (Field, Field) {
        (self.updated.old_c, self.updated.new_c)
    }

    fn landed(self) -> bool {
        self.updated.ok
    }

    fn leaf_hashes(self) -> [Field; T] {
        [0; T]
    }

    fn keep(self, j: u32) {
        self.updated.store_oblivious(self.paths, j)
    }
}

mod tests {
    use super::{RESULT_DOMAIN, Written};
    use crate::effects;
    use crate::test_support::ascii;
    use crate::tip::slot;

    #[test]
    fn the_result_domain_is_its_label() {
        assert_eq(RESULT_DOMAIN, ascii("sidecar.result"));
    }

    // Under partial-note delivery the partial note sits right after ok, the
    // rest as `bound` gives it.
    #[test]
    fn bound_partial_puts_the_partial_note_after_ok() {
        let round = slot::create(0xc0ffee, 0xa002, [7, 8], 6);
        let b = round.bound_partial(0x1d, 777, 0x9a, [0, 24000]).outputs;
        assert_eq(b.request_id, 0x1d);
        assert_eq(b.old_c, 0);
        assert_eq(b.new_c, round.new_c);
        assert_eq(b.npk_app_hash, effects::npk_app_hash(777));
        assert_eq(b.ok, 1);
        assert_eq(b.partial_note, 0x9a);
        assert_eq(b.app, [0, 24000]);
    }
}
