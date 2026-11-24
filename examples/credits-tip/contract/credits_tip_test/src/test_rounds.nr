//! The init and the four rounds as the contract lands them, each computed by
//! the circuits' own functions over the suite's model of the map: the init
//! creating the empty map; a pay inserting the key and completing the payer's
//! note; the owner's claim and move, a view of a present key and one of an
//! absent key (the prove-absent round); a claim naming another sender's
//! key, which reads that sender's own, absent, key; a pay to a field
//! whose low 64 bits are a known key's, which does not block that key; and
//! a pay whose shares carry such a field, which inserts nothing.
use crate::{
    claim, claim_round, deliver, deploy, empty_ledger, empty_map, init, Ledger, move_round, move_to, notes_of,
    outcome_slot, pay, pay_round, pay_round_on, Setup, setup, submit, view, view_round,
};
use aztec::protocol::traits::ToField;
use credits_circuit::ledger::{CODE_ABSENT, CODE_INPUTS_MISMATCH, DEPTH, LEAF_LEN};
use credits_tip::app::{
    CreditOutcomeNote, map_key, own_map_key, payee_handle, ROUND_CLAIM, ROUND_MOVE, ROUND_PAY, ROUND_VIEW,
};
use pss_core::tip::map;
use pss_public_contract::{DONE_APPLIED, Head, TWO_POW_64};

// the payee's and a second owner's secrets
global SECRET_A: Field = 0xa5ec;
global SECRET_B: Field = 0xb5ec;
// the rounds' fresh blindings
global R1: Field = 0x111;
global R2: Field = 0x222;
global R3: Field = 0x333;
global R4: Field = 0x444;
global R5: Field = 0x555;

/// bob pays 500 to alice's handle, landed and delivered to bob; returns the
/// map it leaves.
unconstrained fn paid(s: Setup) -> Ledger {
    let r = pay(s, s.bob, payee_handle(s.alice, SECRET_A), 500, 0x9a01);
    let round = pay_round(s, empty_map(s), r, R1);
    submit(s, r, round.outputs);
    let _ = deliver(s, r);
    empty_map(s).after([r.inputs[0]], round.written.updated)
}

// The init lands the commitment of the empty keyed map at the ledger key,
// which is what credits_init computes (its map created empty, the unused slot
// never written), and leaves the queue empty; the outcome notes sit at the
// slot the rounds complete them at.
#[test]
unconstrained fn the_init_of_the_empty_map() {
    let s = deploy();
    assert_eq(s.ledger(), 0);
    init(s);
    let created = map::empty::<1, DEPTH, LEAF_LEN>(s.app.to_field(), s.ledger_key(), [0], 1);
    let (updated, _) = created.update(true, [false], [[0]], [R1]);
    assert_eq(s.ledger(), updated.new_c);
    assert_eq(s.ledger(), empty_ledger(s));
    assert_eq(s.ledger(), empty_map(s).commitment());
    assert_eq(s.queue().tail(), 0);
    let _ = outcome_slot(s);
}

// bob pays 500 to alice's handle, whose key the map does not hold: the
// request queues the id over C, its key map_key(handle), the key alice's own
// functions name; the round inserts [key, 500, r] and lands with its
// new commitment, the commitment of the map holding that one leaf; bob opens
// [0, ROUND_PAY, 500, 0] (nothing of the payee's balance) and his PXE holds
// the completed note [0, ROUND_PAY, 500, 0, request_id].
#[test]
unconstrained fn a_pay_inserts_the_key_and_completes_the_payers_note() {
    let s = setup();
    let key = own_map_key(s.alice, SECRET_A);
    let r = pay(s, s.bob, payee_handle(s.alice, SECRET_A), 500, 0x9a01);
    assert_eq(r.inputs[0], key);
    assert_eq(s.queue().request_at(0), r.id(s));

    let round = pay_round(s, empty_map(s), r, R1);
    let o = round.outputs;
    assert_eq(o.old_commitments[0], s.ledger());
    submit(s, r, o);
    assert_eq(s.ledger(), o.new_commitments[0]);
    assert_eq(s.queue().head(), Head { index: 1, since: s.env.last_block_number() });
    assert_eq(s.queue().done_at(0), DONE_APPLIED);

    let after = empty_map(s).after([r.inputs[0]], round.written.updated);
    assert_eq(after.count, 1);
    assert_eq(after.leaves[0], [key, 500, R1]);
    assert_eq(after.commitment(), s.ledger());

    assert_eq(deliver(s, r), [0, ROUND_PAY as Field, 500, 0]);
    let notes = notes_of(s, s.bob);
    assert_eq(notes.count, 1);
    assert_eq(
        notes.first,
        CreditOutcomeNote { code: 0, round: ROUND_PAY as Field, a: 500, b: 0, request_id: r.id(s) },
    );
    assert_eq(notes_of(s, s.alice).count, 0);
}

// alice claims 200 of her 500 ([0, ROUND_CLAIM, 200, 300]) and moves 100 to
// bob's handle, whose key the map does not hold ([0, ROUND_MOVE, 100, 200]: the move
// inserts it); bob's view of his key finds it present with 100 ([0,
// ROUND_VIEW, 1, 100]); the relayer's view of a key nobody was paid proves it
// absent ([0, ROUND_VIEW, 0, 0]). Each round lands on
// the commitment the one before left, and each is the model map's.
#[test]
unconstrained fn the_owner_claims_and_moves_and_views_find_a_key_present_and_one_absent() {
    let s = setup();
    let mut ledger = paid(s);

    let c = claim(s, s.alice, SECRET_A, 200, 0x9a02);
    let round = claim_round(s, ledger, c, R2);
    assert_eq(round.outputs.old_commitments[0], s.ledger());
    submit(s, c, round.outputs);
    ledger = ledger.after([c.inputs[0]], round.written.updated);
    assert_eq(s.ledger(), ledger.commitment());
    assert_eq(deliver(s, c), [0, ROUND_CLAIM as Field, 200, 300]);

    let m = move_to(s, s.alice, SECRET_A, payee_handle(s.bob, SECRET_B), 100, 0x9a03);
    assert_eq(m.inputs[1], own_map_key(s.bob, SECRET_B));
    let round = move_round(s, ledger, m, [R3, R4]);
    submit(s, m, round.outputs);
    ledger = ledger.after([m.inputs[0], m.inputs[1]], round.written.updated);
    assert_eq(ledger.count, 2);
    assert_eq(s.ledger(), ledger.commitment());
    assert_eq(deliver(s, m), [0, ROUND_MOVE as Field, 100, 200]);

    let v = view(s, s.bob, SECRET_B, 0x9a04);
    let round = view_round(s, ledger, v, R5);
    submit(s, v, round.outputs);
    ledger = ledger.after([v.inputs[0]], round.written.updated);
    assert_eq(s.ledger(), ledger.commitment());
    assert_eq(deliver(s, v), [0, ROUND_VIEW as Field, 1, 100]);

    let absent = view(s, s.relayer, SECRET_A, 0x9a05);
    let round = view_round(s, ledger, absent, R1);
    submit(s, absent, round.outputs);
    ledger = ledger.after([absent.inputs[0]], round.written.updated);
    assert_eq(s.ledger(), ledger.commitment());
    assert_eq(deliver(s, absent), [0, ROUND_VIEW as Field, 0, 0]);

    assert_eq(notes_of(s, s.alice).count, 2);
    assert_eq(notes_of(s, s.bob).count, 2);
    assert_eq(notes_of(s, s.relayer).count, 1);
    assert_eq(s.queue().head().index, 5);
}

// The key is the sender's own: bob's claim under alice's secret names
// own_map_key(bob, secret), a key the map does not hold, so the round answers
// code 4 (absent) with nothing claimed, and alice's balance is untouched.
#[test]
unconstrained fn a_claim_names_only_the_senders_own_key() {
    let s = setup();
    let mut ledger = paid(s);
    let c = claim(s, s.bob, SECRET_A, 100, 0x9a02);
    assert(c.inputs[0] != own_map_key(s.alice, SECRET_A));
    let round = claim_round(s, ledger, c, R2);
    submit(s, c, round.outputs);
    ledger = ledger.after([c.inputs[0]], round.written.updated);
    assert_eq(deliver(s, c), [CODE_ABSENT, ROUND_CLAIM as Field, 0, 0]);

    let v = view(s, s.alice, SECRET_A, 0x9a03);
    let round = view_round(s, ledger, v, R3);
    submit(s, v, round.outputs);
    assert_eq(deliver(s, v), [0, ROUND_VIEW as Field, 1, 500]);
}

// The squat: bob pays 1 to K + 2^64, K alice's map key, whose low 64 bits
// are K's. The request function hashes it (map_key), so the key the round
// inserts lands on an unrelated path and alice's key stays free: bob's pay of
// 500 to her handle then inserts her entry (code 0), and her view finds it.
#[test]
unconstrained fn a_pay_to_a_field_on_a_known_keys_path_does_not_block_that_key() {
    let s = setup();
    let key = own_map_key(s.alice, SECRET_A);
    let squat = pay(s, s.bob, key + TWO_POW_64, 1, 0x9a01);
    assert_eq(squat.inputs[0], map_key(key + TWO_POW_64));
    assert(map::path_of::<DEPTH>(squat.inputs[0]) != map::path_of::<DEPTH>(key));
    let round = pay_round(s, empty_map(s), squat, R1);
    submit(s, squat, round.outputs);
    let mut ledger = empty_map(s).after([squat.inputs[0]], round.written.updated);
    assert_eq(deliver(s, squat), [0, ROUND_PAY as Field, 1, 0]);

    let r = pay(s, s.bob, payee_handle(s.alice, SECRET_A), 500, 0x9a02);
    let round = pay_round(s, ledger, r, R2);
    submit(s, r, round.outputs);
    ledger = ledger.after([r.inputs[0]], round.written.updated);
    assert_eq(ledger.count, 2);
    assert_eq(s.ledger(), ledger.commitment());
    assert_eq(deliver(s, r), [0, ROUND_PAY as Field, 500, 0]);

    let v = view(s, s.alice, SECRET_A, 0x9a03);
    let round = view_round(s, ledger, v, R3);
    submit(s, v, round.outputs);
    assert_eq(deliver(s, v), [0, ROUND_VIEW as Field, 1, 500]);
}

// The squat by shares: bob queues an honest pay (C over map_key of his own
// handle) but sends the nodes shares of K + 2^64, K alice's map key, a field
// on K's path that no request function computes. C does not open, so the
// round lands as code 1 and inserts no key: K's path takes a vacant leaf,
// the commitment still moving, and bob's note carries the code alone. Bob's pay of 500 to alice's handle then
// inserts her entry (code 0, not CODE_TAKEN), and her view finds it.
#[test]
unconstrained fn shares_that_do_not_open_c_cannot_block_a_key() {
    let s = setup();
    let key = own_map_key(s.alice, SECRET_A);
    let r = pay(s, s.bob, payee_handle(s.bob, SECRET_B), 1, 0x9a01);
    let forged = [key + TWO_POW_64, 1];
    assert_eq(map::path_of::<DEPTH>(forged[0]), map::path_of::<DEPTH>(key));
    let round = pay_round_on(s, empty_map(s), r, forged, R1);
    submit(s, r, round.outputs);
    assert(s.ledger() != empty_map(s).commitment());
    assert_eq(round.written.updated.stored, [[0, 0, R1]]);
    let mut ledger = empty_map(s).after([forged[0]], round.written.updated);
    assert_eq(s.ledger(), ledger.commitment());
    assert_eq(deliver(s, r), [CODE_INPUTS_MISMATCH, 0, 0, 0]);

    let p = pay(s, s.bob, payee_handle(s.alice, SECRET_A), 500, 0x9a02);
    let round = pay_round(s, ledger, p, R2);
    submit(s, p, round.outputs);
    ledger = ledger.after([p.inputs[0]], round.written.updated);
    assert_eq(s.ledger(), ledger.commitment());
    assert_eq(deliver(s, p), [0, ROUND_PAY as Field, 500, 0]);

    let v = view(s, s.alice, SECRET_A, 0x9a03);
    let round = view_round(s, ledger, v, R3);
    submit(s, v, round.outputs);
    assert_eq(deliver(s, v), [0, ROUND_VIEW as Field, 1, 500]);
}
