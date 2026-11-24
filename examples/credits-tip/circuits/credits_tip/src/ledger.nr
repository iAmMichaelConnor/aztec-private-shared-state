//! The credits ledger: a keyed oblivious map (pss_core `tip::map`,
//! docs/ARCHITECTURE.md section 6, "The oblivious sparse map") from a key, a
//! hash the contract's request function computes from the handle a payee hands
//! out, to its credit balance. Anyone pays a key (`pay`: an insert where the
//! key is absent, an addition where it is present, and nobody but the circuit
//! learns which); the key's owner claims from it (`claim`), looks it up
//! (`view`: the prove-absent round, whose private outcome says whether the key
//! is in the map and what it holds) or moves credit to another key
//! (`move_credit`, two keys in one round). The map is `DEPTH` deep over the
//! key's low bits; a leaf is `[key, balance, blinding]`.
//!
//! Every round is a step over the loaded map: the checks as a total
//! `Outcome` (the first failing code wins), the slots to write, their new
//! values and the four outcome fields `[code, round, a, b]` the round's
//! private outcome carries, `round` naming the round (`ROUND_*`). The writes happen in `shared::finish` under private
//! outcomes (every slot written on every outcome under a fresh blinding, an
//! absent key entered with a zero balance when C opens, none when it does
//! not; a key whose balance is zero is absent to every round, `held`). No round can
//! land on a slot whose leaf holds another key (`Map::taken`, code
//! `CODE_TAKEN`, required by `finish` ahead of the step).
//!
//! Ownership of a key is proven in the user's private function, never here:
//! the circuit checks presence and balance, the contract checks the
//! request's authority as every example does.

use pss_core::tip::map::Map;
use total::core::{is_zero, select_field};
use total::ctl::Outcome;
use total::range::fits_bits;

/// The map's depth: a key's path is its low 64 bits (a targeted collision
/// with a known key's path costs a 2^64 search because every key is a hash
/// output, computed by the contract's request functions, `map_key`; random
/// collisions start at four billion keys). DEV DECISION: 64, the brick's default; 32 halves the
/// circuit's shared permutations and the DORAM's accesses for a map whose
/// keys are unpredictable and few; up to 120 for a registry of names whose
/// hash the app controls (docs/ARCHITECTURE.md section 6, "The key, the path and
/// the depth").
pub global DEPTH: u32 = 64;
/// A leaf: `[key, balance, blinding]`.
pub global LEAF_LEN: u32 = 3;
/// The width of an amount and of a balance: a u64.
pub global AMOUNT_BITS: u32 = 64;
/// The outcome fields a round's private outcome carries: `[code, round, a,
/// b]`, `round` the round's `ROUND_*` (so a note of a claim, which pays its
/// owner, is never read as a payer's note of a pay) and `a`, `b` its values
/// (`pay`: the amount paid; `claim`: the amount and the balance left;
/// `view`: whether the key is present and its balance; `move_credit`: the
/// amount and the source's balance left).
pub global OUTCOME_FIELDS: u32 = 4;

/// The queued rounds, each one's place in the deployment's package list (the
/// contract's round table, after the init at 0): the `round` an outcome names.
pub global ROUND_PAY: u32 = 1;
pub global ROUND_CLAIM: u32 = 2;
pub global ROUND_VIEW: u32 = 3;
pub global ROUND_MOVE: u32 = 4;

/// The shares do not open to the request's C (the MPC receipt check).
pub global CODE_INPUTS_MISMATCH: Field = 1;
/// The amount is zero or not a u64.
pub global CODE_AMOUNT: Field = 2;
/// A slot's leaf holds another key: a collision in the key's low `DEPTH`
/// bits; the round touches nothing of it.
pub global CODE_TAKEN: Field = 3;
/// The key is not in the map (a claim, a move from it): the non-membership
/// outcome.
pub global CODE_ABSENT: Field = 4;
/// The balance is below the amount.
pub global CODE_BALANCE: Field = 5;
/// The balance after the payment would not be a u64.
pub global CODE_OVERFLOW: Field = 6;
/// A move names one key twice.
pub global CODE_DISTINCT: Field = 7;
/// The nodes' reads do not form paths to one root, or the count is not in
/// range: node-supplied data, never a request's.
pub global CODE_PATHS: Field = 8;

/// A round's result over `K` slots: the checks, the slots it writes, their
/// new balances and the outcome fields.
pub struct Step<let K: u32> {
    pub outcome: Outcome,
    pub writes: [bool; K],
    pub values: [[Field; LEAF_LEN - 2]; K],
    pub fields: [Field; OUTCOME_FIELDS],
}

/// The map's own flags as the round's codes: `CODE_PATHS` when the loaded
/// paths do not meet at one root or the count is wrong. Total: two ANDs.
fn consistent<let K: u32>(m: Map<K, DEPTH, LEAF_LEN>) -> bool {
    m.tree.count_ok & m.tree.paths_ok
}

/// `amount` is a nonzero u64. Total: one range flag and one is_zero.
fn amount_ok(amount: Field) -> bool {
    fits_bits::<AMOUNT_BITS>(amount) & !is_zero(amount)
}

/// Slot k's balance (0 when absent). No constraint.
fn balance<let K: u32>(m: Map<K, DEPTH, LEAF_LEN>, k: u32) -> Field {
    m.value(k)[0]
}

/// Whether slot k's key holds credit: its leaf is in the map with a nonzero
/// balance. A zero balance is absence: every round writes its slots, so a
/// round on an absent key enters it with a zero balance (`shared::finish`),
/// and a claim of the whole balance leaves one. Total: one is_zero.
fn held<let K: u32>(m: Map<K, DEPTH, LEAF_LEN>, k: u32) -> bool {
    m.present[k] & !is_zero(balance(m, k))
}

/// Pay `amount` to the key in slot 0: an insert where the key is absent (its
/// leaf becomes `[key, amount, r]`), an addition where it is present. Codes,
/// after `first`'s: `CODE_AMOUNT`, `CODE_PATHS`, `CODE_OVERFLOW` (the new
/// balance is not a u64). The outcome fields are `[code, ROUND_PAY, amount,
/// 0]`: the
/// payer learns nothing of the payee's balance, not even whether the entry
/// existed. Total: the flags, one addition and selects.
pub fn pay(m: Map<1, DEPTH, LEAF_LEN>, amount: Field, first: Outcome) -> Step<1> {
    let new_balance = balance(m, 0) + amount;
    let outcome = first
        .require(amount_ok(amount), CODE_AMOUNT)
        .require(consistent(m), CODE_PATHS)
        .require(fits_bits::<AMOUNT_BITS>(new_balance), CODE_OVERFLOW);
    Step { outcome, writes: [true], values: [[new_balance]], fields: [outcome.code, ROUND_PAY as Field, amount, 0] }
}

/// Claim `amount` from the key in slot 0: requires the key held (`held`;
/// `CODE_ABSENT`, the non-membership outcome, delivered privately) and
/// `amount <= balance` (`CODE_BALANCE`); writes `[key, balance - amount,
/// r]`. The outcome fields are `[code, ROUND_CLAIM, amount, balance left]`.
/// Total: the flags, one bounded comparison, one subtraction.
pub fn claim(m: Map<1, DEPTH, LEAF_LEN>, amount: Field, first: Outcome) -> Step<1> {
    let bal = balance(m, 0);
    // bal and amount are u64s (a stored balance by construction, the amount by
    // its check), so their difference is a u64 exactly when bal >= amount
    let enough = fits_bits::<AMOUNT_BITS>(bal - amount);
    let outcome = first
        .require(amount_ok(amount), CODE_AMOUNT)
        .require(consistent(m), CODE_PATHS)
        .require(held(m, 0), CODE_ABSENT)
        .require(enough, CODE_BALANCE);
    let left = bal - amount;
    Step { outcome, writes: [true], values: [[left]], fields: [outcome.code, ROUND_CLAIM as Field, amount, left] }
}

/// Look the key in slot 0 up: writes no new value (the slot is written
/// under a fresh blinding, as on every round), the outcome fields `[code,
/// ROUND_VIEW, present, balance]`: the prove-absent round, `present` 0 with a zero
/// balance proving the key holds nothing (`held`) on a path the circuit
/// verified to the committed root. Codes: `first`'s and `CODE_PATHS`.
/// Total: the flags.
pub fn view(m: Map<1, DEPTH, LEAF_LEN>, first: Outcome) -> Step<1> {
    let outcome = first.require(consistent(m), CODE_PATHS);
    Step {
        outcome,
        writes: [false],
        values: [[balance(m, 0)]],
        fields: [outcome.code, ROUND_VIEW as Field, held(m, 0) as Field, balance(m, 0)],
    }
}

/// Move `amount` from the key in slot 0 to the key in slot 1: the two keys
/// distinct (`CODE_DISTINCT`), the source held with the balance
/// (`CODE_ABSENT`, `CODE_BALANCE`), the destination's new balance a u64
/// (`CODE_OVERFLOW`; an absent destination is inserted). The outcome fields
/// are `[code, ROUND_MOVE, amount, source balance left]`. Total: the flags, one
/// difference range flag, one subtraction and one addition.
pub fn move_credit(m: Map<2, DEPTH, LEAF_LEN>, amount: Field, first: Outcome) -> Step<2> {
    let from = balance(m, 0);
    let to = balance(m, 1);
    let enough = fits_bits::<AMOUNT_BITS>(from - amount);
    let outcome = first
        .require(amount_ok(amount), CODE_AMOUNT)
        .require(consistent(m), CODE_PATHS)
        .require(m.tree.distinct, CODE_DISTINCT)
        .require(held(m, 0), CODE_ABSENT)
        .require(enough, CODE_BALANCE)
        .require(fits_bits::<AMOUNT_BITS>(to + amount), CODE_OVERFLOW);
    let left = from - amount;
    Step {
        outcome,
        writes: [true, true],
        values: [[left], [to + amount]],
        fields: [outcome.code, ROUND_MOVE as Field, amount, select_field(outcome.ok, left, 0)],
    }
}

mod tests {
    use super::{
        CODE_ABSENT, CODE_AMOUNT, CODE_BALANCE, CODE_DISTINCT, CODE_OVERFLOW, CODE_PATHS, DEPTH, LEAF_LEN,
        claim, move_credit, pay, ROUND_CLAIM, ROUND_MOVE, ROUND_PAY, ROUND_VIEW, view,
    };
    use crate::shared::{self, finish, Prefix, Slots};
    use super::CODE_INPUTS_MISMATCH;
    use pss_core::tip::family::{Checked, Family};
    use pss_core::tip::intake::commit;
    use pss_core::test_support::keyed_map::ClearMap;
    use pss_core::tip::intake::SharedIntake;
    use pss_core::tip::map::{self, Map};
    use pss_core::tip::tree::zeros;
    use total::ctl::Outcome;

    global NS: Field = 0xc0ffee;
    global KEY: Field = 0xa004;
    /// Two keys whose paths (low 64 bits) are 5 and 9.
    global KA: Field = 0x1111_0000_0000_0000_0005;
    global KB: Field = 0x2222_0000_0000_0000_0009;
    global R: Field = 1;

    /// The map holding `a` at KA and `b` at KB, each `(present, balance)`.
    fn ledger(a: (bool, Field), b: (bool, Field)) -> ClearMap<2, DEPTH, LEAF_LEN> {
        let mut m = ClearMap::empty(NS, KEY);
        if a.0 {
            m = m.with([KA, a.1, R]);
        }
        if b.0 {
            m = m.with([KB, b.1, R]);
        }
        m
    }

    fn loaded<let K: u32>(a: (bool, Field), b: (bool, Field), keys: [Field; K]) -> Map<K, DEPTH, LEAF_LEN> {
        ledger(a, b).load(keys, K as Field)
    }

    global NONE: (bool, Field) = (false, 0);

    #[test]
    fn the_slots_verify_against_the_root() {
        let m = loaded((true, 500), (true, 10), [KA, KB]);
        assert(m.tree.paths_ok & m.tree.distinct & m.keys_ok);
        assert_eq(m.present, [true, true]);
        assert_eq(m.tree.old_root, ledger((true, 500), (true, 10)).root());
        let one = loaded((true, 500), NONE, [KA, KB]);
        assert(one.tree.paths_ok);
        assert_eq(one.present, [true, false]);
        let empty = loaded(NONE, NONE, [KA]);
        assert_eq(empty.tree.old_root, zeros::<DEPTH>()[DEPTH]);
    }

    #[test]
    fn paying_an_absent_key_inserts_and_a_present_one_adds() {
        let m = loaded(NONE, NONE, [KA]);
        assert(!m.present[0]);
        let s = pay(m, 500, Outcome::good());
        assert(s.outcome.ok);
        assert_eq(s.values, [[500]]);
        assert_eq(s.fields, [0, ROUND_PAY as Field, 500, 0]);
        let n = loaded((true, 500), NONE, [KA]);
        assert(n.present[0]);
        let t = pay(n, 250, Outcome::good());
        assert(t.outcome.ok);
        assert_eq(t.values, [[750]]);
        assert_eq(pay(n, 0, Outcome::good()).outcome.code, CODE_AMOUNT);
        assert_eq(pay(n, 0x1_0000_0000_0000_0000, Outcome::good()).outcome.code, CODE_AMOUNT);
        assert_eq(pay(n, 0xffff_ffff_ffff_ffff, Outcome::good()).outcome.code, CODE_OVERFLOW);
    }

    #[test]
    fn claiming_needs_presence_and_balance() {
        let m = loaded((true, 500), NONE, [KA]);
        let s = claim(m, 200, Outcome::good());
        assert(s.outcome.ok);
        assert_eq(s.values, [[300]]);
        assert_eq(s.fields, [0, ROUND_CLAIM as Field, 200, 300]);
        assert_eq(claim(m, 501, Outcome::good()).outcome.code, CODE_BALANCE);
        assert(claim(m, 500, Outcome::good()).outcome.ok);
        let absent = loaded((true, 500), NONE, [KB]);
        assert_eq(claim(absent, 1, Outcome::good()).outcome.code, CODE_ABSENT);
    }

    #[test]
    fn a_view_proves_presence_or_absence() {
        let present = view(loaded((true, 500), NONE, [KA]), Outcome::good());
        assert(present.outcome.ok);
        assert_eq(present.fields, [0, ROUND_VIEW as Field, 1, 500]);
        assert_eq(present.writes, [false]);
        let absent = view(loaded((true, 500), NONE, [KB]), Outcome::good());
        assert(absent.outcome.ok);
        assert_eq(absent.fields, [0, ROUND_VIEW as Field, 0, 0]);
    }

    // Every keyed round writes its slot under a fresh blinding, so the chain
    // sees a new commitment whatever the outcome: a view or a failed claim of
    // an absent key enters it with a zero balance, which reads as absent.
    #[test]
    fn every_round_changes_the_commitment_and_a_zero_balance_is_absent() {
        let shared = opened([KB]);
        let absent = loaded((true, 500), NONE, [KB]);
        let seen = view(absent, Outcome::good());
        let r = finish(NS, 0x5a, absent, seen, shared, [0x71], 777);
        assert_eq(r.written.updated.write, [true]);
        assert_eq(r.written.updated.stored, [[KB, 0, 0x71]]);
        assert(r.written.updated.new_c != r.written.updated.old_c);
        let refused = claim(absent, 1, Outcome::good());
        assert_eq(refused.outcome.code, CODE_ABSENT);
        let r = finish(NS, 0x5a, absent, refused, shared, [0x72], 777);
        assert_eq(r.written.updated.stored, [[KB, 0, 0x72]]);
        assert(r.written.updated.new_c != r.written.updated.old_c);
        // a present leaf a round does not change keeps its key and balance
        let present = loaded((true, 500), NONE, [KA]);
        let r = finish(NS, 0x5a, present, view(present, Outcome::good()), shared, [0x73], 777);
        assert_eq(r.written.updated.stored, [[KA, 500, 0x73]]);
        assert(r.written.updated.new_c != r.written.updated.old_c);
        // the entry a no-op left, and one claimed to zero, hold nothing
        let zero = loaded((true, 0), NONE, [KA]);
        assert(zero.present[0]);
        assert_eq(view(zero, Outcome::good()).fields, [0, ROUND_VIEW as Field, 0, 0]);
        assert_eq(claim(zero, 1, Outcome::good()).outcome.code, CODE_ABSENT);
        assert_eq(move_credit(loaded((true, 0), NONE, [KA, KB]), 1, Outcome::good()).outcome.code, CODE_ABSENT);
        // a taken slot keeps the other key's leaf
        let taken = loaded((true, 500), NONE, [KA + 0x1_0000_0000_0000_0000]);
        assert(!taken.keys_ok);
        let r = finish(NS, 0x5a, taken, view(taken, Outcome::good()), shared, [0x74], 777);
        assert_eq(r.written.updated.stored, [[KA, 500, 0x74]]);
    }

    #[test]
    fn a_move_needs_two_distinct_keys_and_the_source_balance() {
        let m = loaded((true, 500), NONE, [KA, KB]);
        let s = move_credit(m, 200, Outcome::good());
        assert(s.outcome.ok);
        assert_eq(s.values, [[300], [200]]);
        assert_eq(s.fields, [0, ROUND_MOVE as Field, 200, 300]);
        let both = loaded((true, 500), (true, 10), [KA, KB]);
        assert_eq(move_credit(both, 200, Outcome::good()).values, [[300], [210]]);
        assert_eq(move_credit(both, 600, Outcome::good()).outcome.code, CODE_BALANCE);
        let same = loaded((true, 500), NONE, [KA, KA]);
        assert_eq(move_credit(same, 1, Outcome::good()).outcome.code, CODE_DISTINCT);
        let empty_source = loaded((true, 500), NONE, [KB, KA]);
        assert_eq(move_credit(empty_source, 1, Outcome::good()).outcome.code, CODE_ABSENT);
    }

    // A read whose paths do not meet at one root is node-supplied data: the
    // round fails with CODE_PATHS and writes nothing, so the commitment stays
    // (a root built from those siblings is one no node could rebuild).
    #[test]
    fn a_path_failure_writes_nothing() {
        let keys = [KA, KB];
        let read = ledger((true, 500), NONE).slots(keys);
        let mut tampered = read.siblings;
        tampered[1][0] += 1;
        let m = map::load(NS, KEY, keys, read.leaves, read.old_hashes, tampered, 2);
        assert(!m.tree.paths_ok);
        let shared = opened(keys);
        let step = move_credit(m, 200, Outcome::good());
        assert_eq(step.outcome.code, CODE_PATHS);
        let r = finish(NS, 0x5a, m, step, shared, [0x71, 0x72], 777);
        assert_eq(r.written.updated.write, [false, false]);
        assert_eq(r.written.updated.new_c, r.written.updated.old_c);
    }

    global TWO_POW_64: Field = 0x1_0000_0000_0000_0000;

    /// The round's prefix over the ledger key.
    fn prefix() -> Prefix {
        Prefix { namespace: NS, vk_hash: 0x5a, in_slots: [KEY], out_slots: [KEY] }
    }

    /// The secret-shared intake of a request committing `values` (the app
    /// inputs) under the partial note, outcome key and tag below, or one whose
    /// C commits other values (`opens` false).
    fn intake<let I: u32>(values: [Field; I], opens: bool) -> SharedIntake {
        let (partial, key, tag, blinding) = (0x9a, 0x6b, 0x3a, 0xb1);
        let c = commit(values.concat([partial, key, tag]), blinding);
        SharedIntake { inputs_hash: if opens { c } else { c + 1 }, partial, outcome_key: key, outcome_tag: tag, blinding }
    }

    /// A request committing `values`, checked under the secret-shared
    /// intake: C opens.
    fn opened<let I: u32>(values: [Field; I]) -> Checked<SharedIntake> {
        intake(values, true).check(values, CODE_INPUTS_MISMATCH)
    }

    fn slots_of<let E: u32, let K: u32>(ledger: ClearMap<E, DEPTH, LEAF_LEN>, keys: [Field; K]) -> Slots<K> {
        let read = ledger.slots(keys);
        Slots { leaves: read.leaves, old_hashes: read.old_hashes, siblings: read.siblings }
    }

    // The squat by shares: the attacker's pay is queued under a valid C, but
    // the shares it sends carry KA + 2^64, a field on KA's path that no
    // request function computes. C does not open, so the round inserts no
    // key: KA's path takes a vacant leaf (the commitment still changes, as on
    // every outcome), and KA's own first pay then inserts it (code 0), where
    // an entry under the squatted key would answer CODE_TAKEN for ever.
    #[test]
    fn shares_that_do_not_open_c_insert_no_key_and_leave_the_victims_key_free() {
        let squat = KA + TWO_POW_64;
        let empty: ClearMap<3, DEPTH, LEAF_LEN> = ClearMap::empty(NS, KEY);
        let inputs = [squat, 1];
        let r = shared::pay(prefix(), intake([KA, 1], false), inputs, slots_of(empty, [squat]), [0x71], 777);
        assert_eq(r.written.updated.write, [true]);
        assert_eq(r.written.updated.stored, [[0, 0, 0x71]]);
        assert(r.written.updated.new_c != r.written.updated.old_c);
        let after = empty.after([squat], r.written.updated);
        assert_eq(after.commitment(), r.written.updated.new_c);
        // the victim pays itself: inserted, not taken
        let v = shared::pay(prefix(), intake([KA, 500], true), [KA, 500], slots_of(after, [KA]), [0x72], 777);
        assert_eq(v.written.updated.stored, [[KA, 500, 0x72]]);
        let m = after.load([KA], 1);
        assert(m.keys_ok);
        assert_eq(pay(m, 500, Outcome::good()).outcome.code, 0);
        // the same shares over a present key re-blind its leaf, value kept
        let present = ledger((true, 500), NONE);
        let p = shared::pay(prefix(), intake([KB, 1], false), [KA, 9], slots_of(present, [KA]), [0x73], 777);
        assert_eq(p.written.updated.stored, [[KA, 500, 0x73]]);
        // a squat that opens C (the shares are the committed ones) is the
        // contract's to refuse: map_key hashes every key it computes
        let honest_squat = shared::pay(prefix(), intake(inputs, true), inputs, slots_of(empty, [squat]), [0x74], 777);
        assert_eq(honest_squat.written.updated.stored, [[squat, 1, 0x74]]);
        assert_eq(empty.after([squat], honest_squat.written.updated).load([KA], 1).taken, [true]);
    }

    // A move naming two keys on one path, KA twice or KA and KA + 2^64:
    // the map is not placed (two slots on one path), so nothing is written
    // and the machine is never handed two leaves for one address, whether
    // or not C opens.
    #[test]
    fn a_move_naming_one_path_twice_writes_nothing() {
        let book = ledger((true, 500), NONE);
        for to in [KA, KA + TWO_POW_64] {
            for opens in [true, false] {
                let inputs = [KA, to, 1];
                let r = shared::move_credit(prefix(), intake(inputs, opens), inputs, slots_of(book, [KA, to]), [0x71, 0x72], 777);
                assert_eq(r.written.updated.write, [false, false]);
                assert_eq(r.written.updated.new_c, r.written.updated.old_c);
            }
        }
        assert_eq(move_credit(book.load([KA, KA], 2), 1, Outcome::good()).outcome.code, CODE_DISTINCT);
    }
}
