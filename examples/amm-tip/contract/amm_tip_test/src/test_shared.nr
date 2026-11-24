//! The swap under secret-shared receipt intake, on the secret-shared deployment (the init
//! and `amm_swap_tip_shared`): the request (`swap_shared`: the trader's
//! partial note committed from its own address and `rho` with its use
//! nullifier, three receipts over C, a public call holding only the request
//! id and the expiry block, no input or account in the transaction), the
//! result under private outcomes with partial-note delivery
//! (`process_result_shared`: one completed note hash and one outcome log, no
//! call into another contract; `apply_shared`: the pool's new commitment,
//! whatever the outcome), and the trader's own delivery and `redeem` of the
//! completed note.
//!
//! Every round is computed by the circuits' own `swap_round` (amm_tip
//! tip.nr, under `SharedIntake`, through lib.nr's secret-shared-intake helpers) over the deployed
//! namespace and pool key, so the commitments, the completed note hash and
//! the ciphertext the contract lands are the round circuit's. The proofs are
//! the suite's dummy capsule (TXE skips recursive verification); that a
//! failed swap's amount is 0 is the round's (its `Prover-*.toml` cases and
//! amm_tip's tests), shown here on the note the trader opens.
use crate::{
    deliver, deploy_shared, init, is_seen, last_tx, notes_of, opened_outcome, outcome_log,
    partial_of, pool, pool_key, POOL, redeem, request_shared, request_shared_as, OUTCOME_KEY,
    OUTCOME_TAG, RHO, Setup, setup, shared_round, shared_round_of, shared_values, submit_shared,
};
use amm_tip::AmmTip;
use amm_tip::app::SwapOutcomeNote;
use amm_tip_circuit::shared::{CODE_INPUTS_MISMATCH, OUTCOME_SLOT};
use amm_tip_circuit::tip::CODE_MIN_OUT;
use aztec::note::note_interface::NoteHash;
use aztec::protocol::abis::function_selector::FunctionSelector;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::{compute_siloed_nullifier, compute_siloed_private_log_first_field};
use aztec::protocol::traits::{Packable, ToField};
use aztec::test::helpers::txe_oracles;
use pss_core::tip::outcome::completed_note_hash;
use pss_core::tip::slot::commitment;
use pss_public_contract::{DONE_APPLIED, Head, inputs_commitment};
use pss_public_contract::outcome::OutcomeApply;
use pss_public_contract::partial_note::use_nullifier;
use pss_probe::PssProbe;

// the blindings the rounds sample after the init's R0
global R0: Field = 333;
global R1: Field = 444;
global R2: Field = 555;
// the trader's request blinding, and the rho of its second request
global BLINDING: Field = 0xb1b1;
global RHO_2: Field = 0x5eee;
// sell 25000 x with min_out 33000 (pays 33450); the same with a limit it
// misses (code 8); a second sale on the pool the first leaves
global TRADE: [Field; 3] = [25000, 0, 33000];
global MISSES_MIN_OUT: [Field; 3] = [25000, 0, 33451];
global SECOND: [Field; 3] = [1000, 1, 0];

/// The secret-shared deployment with the pool initialised to POOL under R0.
unconstrained fn setup_shared() -> Setup {
    let s = deploy_shared();
    init(s, pool_c(s, POOL, R0));
    s
}

unconstrained fn pool_c(s: Setup, reserves: [Field; 2], blinding: Field) -> Field {
    commitment(s.app.to_field(), pool_key(s), reserves, blinding)
}

/// A transaction's side effects by kind, as the probe's `tx_summary` counts
/// them.
struct Effects {
    note_hashes: u32,
    nullifiers: u32,
    private_logs: u32,
    public_logs: u32,
    l2_to_l1_msgs: u32,
}

unconstrained fn last_summary(s: Setup) -> Effects {
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let e = s.env.execute_utility(PssProbe::at(s.probe).tx_summary(tx_hash));
    Effects {
        note_hashes: e.note_hashes,
        nullifiers: e.nullifiers,
        private_logs: e.private_logs,
        public_logs: e.public_logs,
        l2_to_l1_msgs: e.l2_to_l1_msgs,
    }
}

/// Whether none of `values` appears anywhere in the last transaction's
/// effect (the probe's requester audit, over any four fields).
unconstrained fn assert_last_tx_holds_none(s: Setup, values: [Field; 4]) {
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let as_addresses = values.map(|v| AztecAddress { inner: v });
    assert(s.env.execute_utility(PssProbe::at(s.probe).tx_names_no_requester(tx_hash, as_addresses)));
}

/// Whether the last transaction pushed `nullifier`, siloed with the app.
unconstrained fn last_tx_nullifies(s: Setup, nullifier: Field) -> bool {
    let effects = txe_oracles::get_last_tx_effects();
    let mut found = false;
    for i in 0..effects.nullifiers.len() {
        found |= effects.nullifiers.get(i) == compute_siloed_nullifier(s.app, nullifier);
    }
    found
}

/// The user's trade: requested, landed and delivered to the user's PXE;
/// returns the chain request id.
unconstrained fn traded(s: Setup) -> Field {
    let (id, _) = request_shared(s, TRADE, RHO, BLINDING);
    let _ = submit_shared(s, shared_round(s, TRADE, RHO, BLINDING, BLINDING, POOL, R0, R1));
    deliver(s, s.user, RHO, id);
    id
}

// ---- intake ----------------------------------------------------------------

// Three receipts over C queue the secret-shared request id. The public call
// the request enqueues is receipt intake's `append_receipt`, with the
// request id and the expiry block only (the contract's interface at its own
// address: TestEnvironment's private context cannot enqueue, so the call is
// checked as the interface builds it); the transaction emits no log and no
// note. The request commits the sender's partial note from `rho` and pushes
// its use nullifier; C covers that partial note, so the queued id is the one
// over the sender's P. No input, no account, neither C, the partial note,
// the blinding, the outcome key nor the outcome tag appears anywhere in the
// request transaction's effects (the use nullifier is a hash of the partial
// note). The same rho from another sender is another partial note (the
// owner is the sender), so both requests are queued.
#[test]
unconstrained fn a_shared_request_carries_only_the_id_and_expiry_uses_its_partial_note_and_names_no_requester() {
    let s = setup_shared();
    let (id, expiry) = request_shared(s, TRADE, RHO, BLINDING);
    assert_eq(s.env.view_public(AmmTip::at(s.app).request_at(0)), id);
    assert(is_seen(s, id));
    let effects = last_summary(s);
    assert_eq(effects.public_logs, 0);
    assert_eq(effects.private_logs, 0);
    assert_eq(effects.note_hashes, 0);
    assert_eq(effects.l2_to_l1_msgs, 0);
    let call = AmmTip::at(s.app).append_receipt(id, expiry);
    assert_eq(call.target_contract, s.app);
    assert_eq(call.selector, comptime { FunctionSelector::from_signature("append_receipt(Field,u32)") });
    assert_eq(call.args, [id, expiry as Field]);

    assert(last_tx_nullifies(s, use_nullifier(partial_of(s.user, RHO))));

    let c = inputs_commitment(shared_values(s, TRADE, RHO), BLINDING);
    assert_last_tx_holds_none(s, [s.user.to_field(), s.relayer.to_field(), TRADE[0], TRADE[2]]);
    assert_last_tx_holds_none(s, [c, BLINDING, OUTCOME_KEY, OUTCOME_TAG]);
    assert_last_tx_holds_none(s, [partial_of(s.user, RHO), RHO, TRADE[0], TRADE[2]]);

    let (b, _) = request_shared_as(s, s.trader_b, TRADE, RHO, BLINDING);
    assert(id != b);
    assert(partial_of(s.user, RHO) != partial_of(s.trader_b, RHO));
    assert_eq(s.queue().request_at(1), b);
}

// A refused request (a zero amount, `valid_swap`): the request function
// reverts before anything is queued, so no partial note is used and no
// round will complete a note for it.
#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_shared_request_of_a_zero_amount_is_refused() {
    let s = setup_shared();
    let _ = request_shared(s, [0, 0, 0], RHO, BLINDING);
}

// The non-secret-shared intakes' functions refuse on the secret-shared deployment, whose list
// has no non-secret-shared swap (one intake family per key).
#[test(should_fail_with = "package not in this deployment")]
unconstrained fn the_plain_swap_is_not_in_the_shared_deployment() {
    let s = setup_shared();
    s.env.call_private(s.user, AmmTip::at(s.app).swap(25000, 0, 33000, RHO, 0xa1));
}

// ---- the result: the private completion ------------------------------------

// The round circuit completes every note at the contract's outcome-note
// slot, and the contract's note type hashes a note created whole as the
// round's completion of its partial note does. The trade lands with one
// note hash (the completed note) and one outcome log, and nothing else: no
// public log, no call into another contract; the pool takes the round's new
// commitment; the head moves. The trader opens [0, 33450] from the log; a
// note rebuilt under another rho, or for another owner, is not the
// completed one (the PXE stores nothing), and the trader's delivery of
// [0, 33450, request_id] under its rho is: its PXE then holds that note. A
// second swap lands on the commitment the first left and completes a
// second note of the trader's. The trader redeems its first note once: the
// note is nullified and the amount returned; the PXE no longer holds it.
#[test]
unconstrained fn shared_trades_complete_notes_only_their_trader_delivers_and_redeems() {
    let s = setup_shared();
    let slot = s.queue().state().outcome_slot;
    assert_eq(slot, OUTCOME_SLOT);
    let note = SwapOutcomeNote { code: 0, amount_out: 33450, request_id: 0x1d };
    assert_eq(
        note.compute_note_hash(s.user, slot, RHO),
        completed_note_hash(slot, partial_of(s.user, RHO), [0, 33450], 0x1d),
    );
    assert_eq(note.pack(), [0, 33450, 0x1d]);

    let (id, _) = request_shared(s, TRADE, RHO, BLINDING);
    let r = shared_round(s, TRADE, RHO, BLINDING, BLINDING, POOL, R0, R1);
    assert_eq(r.outputs.old_commitments, [pool(s)]);
    let block = submit_shared(s, r);
    assert_eq(pool(s), r.outputs.new_commitments[0]);
    assert_eq(pool(s), pool_c(s, [1384373, 1818881], R1));
    assert_eq(s.queue().head(), Head { index: 1, since: block });
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    let effects = last_summary(s);
    assert_eq(effects.note_hashes, 1);
    assert_eq(effects.private_logs, 1);
    assert_eq(effects.public_logs, 0);
    assert_eq(effects.l2_to_l1_msgs, 0);
    let log = outcome_log();
    assert_eq(log.get(0), compute_siloed_private_log_first_field(s.app, OUTCOME_TAG));
    assert_eq(log.get(1), r.outputs.note_hashes[0]);
    assert_eq(opened_outcome(), [0, 33450]);
    assert_eq(r.outputs.note_hashes, [completed_note_hash(OUTCOME_SLOT, partial_of(s.user, RHO), [0, 33450], id)]);
    assert(id == r.outputs.request_id);
    assert_eq(notes_of(s, s.user).count, 0);

    let tx = last_tx();
    let packed = opened_outcome().concat([id]);
    s.env.execute_utility(AmmTip::at(s.app).deliver_outcome(s.user, RHO + 1, packed, tx));
    assert_eq(notes_of(s, s.user).count, 0);
    s.env.execute_utility(AmmTip::at(s.app).deliver_outcome(s.trader_b, RHO, packed, tx));
    assert_eq(notes_of(s, s.trader_b).count, 0);

    deliver(s, s.user, RHO, id);
    let notes = notes_of(s, s.user);
    assert_eq(notes.count, 1);
    assert_eq(notes.first, SwapOutcomeNote { code: 0, amount_out: 33450, request_id: id });

    let (second_id, _) = request_shared(s, SECOND, RHO_2, BLINDING + 1);
    let second = shared_round(s, SECOND, RHO_2, BLINDING + 1, BLINDING + 1, [1384373, 1818881], R1, R2);
    assert(second.written.outcome.ok);
    let _ = submit_shared(s, second);
    assert_eq(pool(s), second.outputs.new_commitments[0]);
    let out = opened_outcome();
    assert_eq(out[0], 0);
    assert(out[1] != 0);
    deliver(s, s.user, RHO_2, second_id);
    assert_eq(notes_of(s, s.user).count, 2);
    assert(id != second_id);

    assert_eq(redeem(s, s.user, id), 33450);
    assert_eq(notes_of(s, s.user).count, 1);
}

// Shares that do not open to the queued C: the round's request id is still
// the queued one, so the result lands; the pool takes a new commitment (the
// pool kept, under the fresh blinding) and the trader's note says code 9
// with nothing out. Then a swap that fails on the pool (trader B's, below
// min_out): the pool again takes the kept reserves under the fresh
// blinding, and B's note says code 8 with nothing out. That a failed
// swap's transaction has a trade's effects is test_round_shape.nr's.
#[test]
unconstrained fn a_mismatch_and_a_missed_min_out_reblind_the_pool_and_complete_zero_notes() {
    let s = setup_shared();
    let (id, _) = request_shared(s, TRADE, RHO, BLINDING);
    let old = pool(s);
    let r = shared_round(s, TRADE, RHO, BLINDING, BLINDING + 1, POOL, R0, R1);
    assert_eq(r.outputs.request_id, id);
    let _ = submit_shared(s, r);
    assert(pool(s) != old);
    assert_eq(pool(s), pool_c(s, POOL, R1));
    assert_eq(opened_outcome(), [CODE_INPUTS_MISMATCH, 0]);
    deliver(s, s.user, RHO, id);
    assert_eq(notes_of(s, s.user).first, SwapOutcomeNote { code: CODE_INPUTS_MISMATCH, amount_out: 0, request_id: id });

    let b = s.trader_b;
    let (id_b, _) = request_shared_as(s, b, MISSES_MIN_OUT, RHO, BLINDING + 1);
    let missed = shared_round_of(s, MISSES_MIN_OUT, partial_of(b, RHO), BLINDING + 1, BLINDING + 1, POOL, R1, R2);
    assert_eq(missed.outputs.request_id, id_b);
    let _ = submit_shared(s, missed);
    assert_eq(opened_outcome(), [CODE_MIN_OUT, 0]);
    assert_eq(pool(s), pool_c(s, POOL, R2));
    deliver(s, b, RHO, id_b);
    assert_eq(notes_of(s, b).first, SwapOutcomeNote { code: CODE_MIN_OUT, amount_out: 0, request_id: id_b });
}

// ---- the spend --------------------------------------------------------------

// A second redeem of the same note finds none.
#[test(should_fail_with = "no swap note of this request to redeem")]
unconstrained fn a_note_is_redeemed_once() {
    let s = setup_shared();
    let id = traded(s);
    let _ = redeem(s, s.user, id);
    let _ = redeem(s, s.user, id);
}

// Another account holds no note of the request: it cannot redeem the
// trader's.
#[test(should_fail_with = "no swap note of this request to redeem")]
unconstrained fn another_account_cannot_redeem_the_traders_note() {
    let s = setup_shared();
    let id = traded(s);
    let _ = redeem(s, s.trader_b, id);
}

// A failed swap's note has nothing to redeem.
#[test(should_fail_with = "the swap note has nothing to redeem")]
unconstrained fn a_failed_swaps_note_has_nothing_to_redeem() {
    let s = setup_shared();
    let (id, _) = request_shared(s, MISSES_MIN_OUT, RHO, BLINDING);
    let _ = submit_shared(s, shared_round(s, MISSES_MIN_OUT, RHO, BLINDING, BLINDING, POOL, R0, R1));
    deliver(s, s.user, RHO, id);
    let _ = redeem(s, s.user, id);
}

// ---- refusals ---------------------------------------------------------------

// The shared result function refuses on the non-secret-shared deployment, whose list has
// no secret-shared swap.
#[test(should_fail_with = "package not in this deployment")]
unconstrained fn the_shared_result_is_not_in_the_plain_deployment() {
    let s = setup();
    let r = shared_round(s, TRADE, RHO, BLINDING, BLINDING, POOL, R0, R1);
    let _ = submit_shared(s, r);
}

// A result whose apply does not land (it read another commitment than the
// slot holds) reverts as a whole: no note, no log.
#[test(should_fail_with = "state moved")]
unconstrained fn a_result_over_another_pool_reverts_with_its_note() {
    let s = setup_shared();
    let _ = request_shared(s, TRADE, RHO, BLINDING);
    let _ = submit_shared(s, shared_round(s, TRADE, RHO, BLINDING, BLINDING, POOL, R2, R1));
}

#[test(should_fail_with = "Function apply_shared can only be called by the same contract")]
unconstrained fn apply_shared_from_outside_the_contract_is_refused() {
    let s = setup_shared();
    let (id, _) = request_shared(s, TRADE, RHO, BLINDING);
    let c = pool(s);
    s.env.call_public(s.user, AmmTip::at(s.app).apply_shared(OutcomeApply::new(id, [c], [c + 1], [])));
}
