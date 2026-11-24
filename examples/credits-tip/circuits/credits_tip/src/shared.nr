//! The rounds' secret-shared entry (docs/ARCHITECTURE.md section 6, "Secret-shared
//! intake" and "Private outcomes"), the only entry a keyed map has (REGISTER
//! accepts `access: oblivious` under the secret-shared intakes alone): C
//! opens to the app inputs (the keys and the amount), the request's partial
//! note, the outcome key and tag under the blinding (code
//! `CODE_INPUTS_MISMATCH`, ahead of the round's codes); no slot's leaf may
//! hold another key (`CODE_TAKEN`); the map is written with pss_core's
//! `Map::update_private`, every slot on every outcome under a fresh blinding
//! (`finish`: the commitment changes on every round, so the chain cannot
//! tell an effect from a no-op, nor a present key from an absent one), no key
//! entering the map unless C opens, and
//! the slots' leaves, new hashes and `DEPTH` path nodes go to the machine
//! (`Updated::store_oblivious`), which writes them into the nodes' oblivious
//! RAM at the next session's start; the outcome `[code, round, a, b]`
//! completes the request's partial note at `OUTCOME_SLOT` and is encrypted
//! under that note hash's nonce. No leaf hash is output: the public outputs are pss_core's
//! `Private<1, 1, 0, 1, 5>`, the AMM's shape with a longer ciphertext, so the chain sees the two
//! commitments, the note hash and the ciphertext, and never which key a
//! round touched or whether it inserted.

use crate::ledger::{self, CODE_INPUTS_MISMATCH, CODE_TAKEN, DEPTH, LEAF_LEN, OUTCOME_FIELDS, Step};
/// A main's public prefix (pss_core's): the namespace (PUBLIC `$namespace`),
/// the circuit's vk hash and the map key read and written.
pub use pss_core::tip::family::Prefix;
use pss_core::tip::family::{Checked, Family};
pub use pss_core::tip::intake::SharedIntake;
use pss_core::tip::map::{self, Map};
use pss_core::tip::outcome::Private;
use pss_core::tip::outputs::Finished;
use pss_core::tip::tree::{self, Oblivious};
use total::core::select_field;
use total::ctl::Outcome;

/// The outcome ciphertext's length: the four outcome fields and the AEAD
/// tag.
pub global CIPHERTEXT_LEN: u32 = OUTCOME_FIELDS + 1;

/// The storage slot of the credits contract's outcome notes (the contract's
/// first storage variable, which its TXE suite pins), where every round's
/// completed note lives. A constant of the circuit, so no node can put the
/// note where the user's client does not look.
pub global OUTCOME_SLOT: Field = 0x1;

/// A round's public outputs: one key read and written (the map), no leaf
/// hash, one completed note hash and the five-field ciphertext.
pub type Shared = Private<1, 1, 0, 1, CIPHERTEXT_LEN>;

/// A round finished: the map it leaves and its public outputs; a main ends
/// in `stored`, which hands the slots to the machine (TACEO_store "out0"),
/// and a test reads both.
pub type KeyedRound<let K: u32> = Finished<Oblivious<K, LEAF_LEN, DEPTH, 0>, Shared>;

/// Finish a round checked under the secret-shared intake (`checked`): write
/// the step under private outcomes (`Checked::write` of the map's
/// `Map::change`), every used slot
/// on every outcome under its fresh blinding `r_new[k]` (the keyed rule:
/// docs/ARCHITECTURE.md section 6, "The keyed map's circuit"), so the commitment changes
/// on every round and neither the nodes nor the chain learn whether the
/// round applied, inserted, or found its key absent. When C opens, a slot
/// the step writes takes its new value when the round is
/// ok; any other slot keeps its own value: a present leaf its key and
/// balance, an absent key entered with a zero balance (which every round
/// reads as absent, ledger.nr `held`), a taken slot the other key's leaf
/// (re-blinded, never rewritten under this key: `Map::update_private`).
/// When C does not open, the keys are not the ones the request committed:
/// the map brick inserts none of them and changes no value, re-blinding a
/// present leaf as it is and turning an absent slot into a vacant leaf, so
/// no request can enter another user's key. The brick folds in the map's
/// placement (`Tree::placed`: the count, the paths, two keys on one path):
/// when it fails nothing is written and new_c is old_c, so a path that does
/// not meet slot 0's root never commits a root no node can rebuild. Then
/// complete the request's partial note with `[code, round, a, b]` (`a` and
/// `b` zero when the round failed; the code alone when the shares do not
/// open C) and encrypt it under that note hash's nonce (`Checked::finish`,
/// pss_core's `outcome::finish`, no pinned reads).
///
/// Constraints: one select per slot and value element, the map's update
/// (`Map::update_private` at depth `DEPTH`) and `outcome::finish`'s (the machine request id, the outcome's
/// AEAD and completed note hash, npk_app_hash: the std scalar decomposition
/// of nsk_app, hint-satisfiable for every Field, and one fixed-base
/// multi_scalar_mul, which cannot fail); the store is an unconstrained
/// side-effect-only oracle (`stored`). No assert.
pub fn finish<let K: u32>(
    namespace: Field,
    vk_hash: Field,
    m: Map<K, DEPTH, LEAF_LEN>,
    step: Step<K>,
    checked: Checked<SharedIntake>,
    r_new: [Field; K],
    nsk_app: Field,
) -> KeyedRound<K> {
    let mut values = [[0; LEAF_LEN - 2]; K];
    for k in 0..K {
        let lands = step.outcome.ok & step.writes[k];
        let own = m.value(k);
        for e in 0..LEAF_LEN - 2 {
            values[k][e] = select_field(lands, step.values[k][e], own[e]);
        }
    }
    let written = checked.write(m.change(true, [true; K], [true; K], values, r_new));
    let fields = [
        step.outcome.code,
        step.fields[1],
        step.outcome.mask_field(step.fields[2]),
        step.outcome.mask_field(step.fields[3]),
    ];
    // no app outputs (`()`): a keyed map takes a secret-shared intake alone, so
    // the round's outcome is the private `fields`
    checked.finish(written, namespace, vk_hash, [], [], (), fields, OUTCOME_SLOT, nsk_app)
}

/// The map's slots as the nodes' oblivious RAM reads them (three LOAD
/// slices): the leaves, their old hashes and their DEPTH siblings
/// (pss_core's `tree::Slots`).
pub type Slots<let K: u32> = tree::Slots<K, DEPTH, LEAF_LEN>;

/// The map at `keys` (pss_core `map::load`, every slot used), the checks
/// every round makes first, the round, and `finish`: what each round's
/// entry below runs. The checks: C opens to the app inputs, then
/// `$partial_note`, `$outcome_key` and `$outcome_tag`, under `$blinding`
/// (the family's check, `CODE_INPUTS_MISMATCH`), and no used slot's leaf
/// holds another key (`CODE_TAKEN`); the round's step starts from them.
fn run<let K: u32, let I: u32, Env>(
    p: Prefix,
    shared: SharedIntake,
    keys: [Field; K],
    inputs: [Field; I],
    slots: Slots<K>,
    r_new: [Field; K],
    nsk_app: Field,
    round: fn[Env](Map<K, DEPTH, LEAF_LEN>, Outcome) -> Step<K>,
) -> KeyedRound<K> {
    // BRICK shape = map_oblivious (pss_core::tip::map::load). Alternatives: flat (tip::slot), tree,
    // tree_oblivious (tip::tree: state addressed by position). docs/design-guide/BRICKS.md#shape
    let m = map::load::<K, DEPTH, LEAF_LEN>(
        p.namespace,
        p.in_slots[0],
        keys,
        slots.leaves,
        slots.old_hashes,
        slots.siblings,
        K as Field,
    )
        .writes_to(p.out_slots[0]);
    // BRICK intake = shared_receipt (pss_core::tip::intake::SharedIntake). Alternatives:
    // shared_onchain (the same circuit, a request function of its own; a keyed map takes no
    // non-secret-shared intake). docs/design-guide/BRICKS.md#intake
    let checked = shared.check(inputs, CODE_INPUTS_MISMATCH);
    let step = round(m, checked.first.require(m.keys_ok, CODE_TAKEN));
    finish(p.namespace, p.vk_hash, m, step, checked, r_new, nsk_app)
}

/// pay(key, amount): ledger.nr `pay`, finished; the pay main stores it and
/// outputs its public outputs (`stored`).
pub fn pay(p: Prefix, shared: SharedIntake, inputs: [Field; 2], slots: Slots<1>, r_new: [Field; 1], nsk_app: Field) -> KeyedRound<1> {
    run(p, shared, [inputs[0]], inputs, slots, r_new, nsk_app, |m, first| ledger::pay(m, inputs[1], first))
}

/// claim(key, amount): ledger.nr `claim`.
pub fn claim(p: Prefix, shared: SharedIntake, inputs: [Field; 2], slots: Slots<1>, r_new: [Field; 1], nsk_app: Field) -> KeyedRound<1> {
    run(p, shared, [inputs[0]], inputs, slots, r_new, nsk_app, |m, first| ledger::claim(m, inputs[1], first))
}

/// view(key): ledger.nr `view`.
pub fn view(p: Prefix, shared: SharedIntake, inputs: [Field; 1], slots: Slots<1>, r_new: [Field; 1], nsk_app: Field) -> KeyedRound<1> {
    run(p, shared, inputs, inputs, slots, r_new, nsk_app, |m, first| ledger::view(m, first))
}

/// move(from, to, amount): ledger.nr `move_credit`.
pub fn move_credit(
    p: Prefix,
    shared: SharedIntake,
    inputs: [Field; 3],
    slots: Slots<2>,
    r_new: [Field; 2],
    nsk_app: Field,
) -> KeyedRound<2> {
    run(p, shared, [inputs[0], inputs[1]], inputs, slots, r_new, nsk_app, |m, first| ledger::move_credit(m, inputs[2], first))
}
