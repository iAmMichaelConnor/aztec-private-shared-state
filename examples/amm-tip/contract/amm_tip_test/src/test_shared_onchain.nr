//! The swap under secret-shared on-chain intake, on the secret-shared deployment (the init
//! and the secret-shared swap): the nodes key
//! the contract with signed `rotate_enc_key` transactions, the trader's
//! `swap_shared_onchain` queues the chain request id with the data hash of
//! one private log of encoded shares, every node derives its pair of every
//! shared value from that log, and the round lands through the secret-shared
//! swap's `process_result_shared`, the same circuit and public inputs as
//! under secret-shared receipt intake; the trader delivers the completed
//! note to its PXE.
//!
//! C commits to `[amount_in, direction, min_out, partial_note, outcome_key,
//! outcome_tag]` under the blinding, every value chosen (one correction
//! each): the swap inputs, the trader's partial note (computed by the
//! request function from the sender and `rho`), and the outcome key and
//! tag, which the trader's client derives per request and passes; the
//! blinding is the encoding's
//! (`AMM_SWAP_TIP_SHARED_ONCHAIN_LAYOUT`). The nodes' `enc` scalars are test-local. The expected log is recomputed here with pss_core's
//! `tip::derived`, and each node's pairs are re-derived from the landed log
//! under the round's kinds (the generated layout's, testvectors/onchain_layouts.json),
//! as the machine derives them; the values they reconstruct feed the circuits' own
//! `swap_round`, so the round that lands is the one the nodes would prove.
use crate::{
    deploy_shared, init, notes_of, NSK_APP, outcome_log, OUTCOME_KEY, OUTCOME_TAG, partial_of, pool,
    pool_key, POOL, REQUEST_GAS, RHO, Setup, submit_shared,
};
use amm_tip::AmmTip;
use amm_tip::app::{
    PACKAGES, rounds, SHARED_VALUES, SwapNotes, SwapOutcomeNote, valid_swap,
};
use amm_tip::layouts::AMM_SWAP_TIP_SHARED_ONCHAIN_LAYOUT;
use amm_tip_circuit::shared::{CODE_INPUTS_MISMATCH, SharedRound};
use amm_tip_circuit::tip::swap_round;
use aztec::context::{PrivateContext, PublicContext};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::compute_siloed_private_log_first_field;
use aztec::protocol::traits::ToField;
use aztec::state_vars::{PublicImmutable, PublicMutable, StateVariable};
use aztec::test::helpers::test_environment::PrivateContextOptions;
use aztec::test::helpers::txe_oracles;
use pss_core::tip::derived::{
    data_hash, node_pair, pack_epochs, REQUEST_LOG_LEN,
};
use pss_core::tip::intake::SharedIntake;
use pss_core::tip::slot::{commitment, load};
use pss_public_contract::{
    CommitmentSlot, Configured, DONE_APPLIED, EncKey, Queue,
    shared_onchain_request, SharedOnchain, SharedOnchainRequest,
};
use pss_public_contract::outcome::OutcomeTx;
use pss_public_contract::partial_note::use_nullifier;
use pss_public_contract::shared_onchain::{anchor_keys, request_log_tag};
use pss_probe::PssProbe;
use pss_tip_test::{key_set, rotation_signatures};
use pss_tip_test::nodes::NODE_SIG;
use pss_tip_test::shared_onchain;
use pss_tip_test::shared_onchain::{
    body, ENC, ENC_NEXT, enc_key, EPH, Expected, node_rotation, opened, the_request_log,
};
use pss_tip_test::shape::kind_options;
use pss_tip_test::outcome::open_outcome_log;
use pss_utils::dh::{ecdh_x, public_key};

// the replacing node's sig scalar
global NEWCOMER_SIG: Field = 0x5e9a;

// the blindings the rounds sample after the init's R0
global R0: Field = 333;
global R1: Field = 444;
// sell 25000 x with min_out 33000 (pays 33450 on POOL)
global TRADE: [Field; 3] = [25000, 0, 33000];
// the pool TRADE leaves
global TRADED: [Field; 2] = [1384373, 1818881];

/// The secret-shared deployment with the pool initialised to POOL under R0, every
/// node keyed at epoch 1.
unconstrained fn keyed() -> Setup {
    let s = deploy_shared();
    init(s, pool_c(s, POOL, R0));
    for i in 0..3 {
        rotate(s, i, ENC[i], 1);
    }
    s
}

unconstrained fn pool_c(s: Setup, reserves: [Field; 2], blinding: Field) -> Field {
    commitment(s.app.to_field(), pool_key(s), reserves, blinding)
}

/// Node i's rotation to `sk` at `epoch`, signed under its pinned `sig` key
/// and sent by the relayer.
unconstrained fn rotate(s: Setup, i: u32, sk: Field, epoch: u32) {
    let (key, signature) = node_rotation(s.app, i, sk, epoch);
    s.env.call_private(s.relayer, AmmTip::at(s.app).rotate_enc_key(i, key, signature));
}

unconstrained fn stored_key(s: Setup, i: u32) -> EncKey {
    s.env.view_public(AmmTip::at(s.app).get_enc_key(i))
}

/// C's values for the user's swap of TRADE under RHO, as the request
/// function builds them: the swap inputs, the user's partial note, and the
/// outcome key and tag its client derived for the request.
unconstrained fn values(s: Setup) -> [Field; SHARED_VALUES] {
    TRADE.concat([partial_of(s.user, RHO), OUTCOME_KEY, OUTCOME_TAG])
}

/// The user's secret-shared on-chain swap of TRADE under RHO, the outcome
/// key and tag, and `eph`, under the request gas setting.
unconstrained fn request(s: Setup, eph: Field) {
    s.env.call_private_opts(
        s.user,
        kind_options(REQUEST_GAS),
        AmmTip::at(s.app).swap_shared_onchain(TRADE[0], TRADE[1], TRADE[2], RHO, OUTCOME_KEY, OUTCOME_TAG, eph),
    );
}

/// What the request function computes from `values` under `eph` and the
/// node scalars `scalars` at `epochs` (every value chosen: C's values are
/// `values` itself).
unconstrained fn expected(
    s: Setup,
    values: [Field; SHARED_VALUES],
    eph: Field,
    scalars: [Field; 3],
    epochs: [u32; 3],
) -> Expected<SHARED_VALUES, 6> {
    let want = shared_onchain::expected(
        AMM_SWAP_TIP_SHARED_ONCHAIN_LAYOUT,
        s.app.to_field(),
        s.vks.shared_vk_hash,
        values,
        eph,
        scalars,
        epochs,
    );
    assert_eq(want.values, values);
    want
}

/// Every node, using `scalars[i]` under the machine's kinds vector, opens
/// C's values and the blinding the request committed to.
unconstrained fn assert_served(log: BoundedVec<Field, 16>, eph: Field, scalars: [Field; 3], want: Expected<SHARED_VALUES, 6>) {
    let (vals, blinding) = opened(log, eph, scalars, AMM_SWAP_TIP_SHARED_ONCHAIN_LAYOUT.kinds);
    assert_eq(vals, want.values);
    assert_eq(blinding, want.blinding);
}

/// The round the circuit computes for the queued C from the values and the
/// blinding the nodes opened, on `reserves` under `r_old`, sampling
/// `r_new`.
unconstrained fn onchain_round(
    s: Setup,
    c: Field,
    vals: [Field; SHARED_VALUES],
    blinding: Field,
    reserves: [Field; 2],
    r_old: Field,
    r_new: Field,
) -> SharedRound {
    let key = pool_key(s);
    let intake = SharedIntake {
        inputs_hash: c,
        partial: vals[3],
        outcome_key: vals[4],
        outcome_tag: vals[5],
        blinding,
    };
    swap_round(
        s.vks.shared_vk_hash,
        load(s.app.to_field(), key, key, reserves, r_old, r_new),
        [vals[0], vals[1], vals[2]],
        intake,
        NSK_APP,
    )
}

/// Open the last transaction's outcome log under the outcome key and tag
/// `key` and `tag` (the trader's own, which its request chose):
/// `[code, amount_out]`.
unconstrained fn opened_outcome(s: Setup, key: Field, tag: Field) -> [Field; 2] {
    let log = outcome_log();
    assert_eq(log.get(0), compute_siloed_private_log_first_field(s.app, tag));
    open_outcome_log(log, key)
}

/// Deliver the last transaction's completed note, `[code, amount_out,
/// request_id]` from the outcome opened under `key` and `tag`, to the
/// user's PXE under RHO, and return the notes it then holds.
unconstrained fn deliver_note(s: Setup, key: Field, tag: Field, request_id: Field) -> SwapNotes {
    let packed = opened_outcome(s, key, tag).concat([request_id]);
    let effects = txe_oracles::get_last_tx_effects();
    let tx = OutcomeTx {
        tx_hash: effects.tx_hash,
        unique_note_hashes: effects.note_hashes,
        first_nullifier: effects.nullifiers.get(0),
    };
    s.env.execute_utility(AmmTip::at(s.app).deliver_outcome(s.user, RHO, packed, tx));
    notes_of(s, s.user)
}

/// The nodes open the request at queue index `index` from its landed log
/// (each with `scalars[i]`), and its round, computed by the circuit from
/// what they opened, lands on POOL: the pool takes TRADED under R1, the
/// entry is applied, and the trader opens `[0, 33450]` and holds the
/// completed note.
unconstrained fn assert_lands(
    s: Setup,
    index: u64,
    log: BoundedVec<Field, 16>,
    eph: Field,
    scalars: [Field; 3],
    want: Expected<SHARED_VALUES, 6>,
) {
    let (vals, blinding) = opened(log, eph, scalars, AMM_SWAP_TIP_SHARED_ONCHAIN_LAYOUT.kinds);
    let r = onchain_round(s, want.c, vals, blinding, POOL, R0, R1);
    assert_eq(r.outputs.request_id, want.id);
    assert_eq(r.outputs.old_commitments, [pool(s)]);
    let _ = submit_shared(s, r);
    assert_eq(pool(s), pool_c(s, TRADED, R1));
    assert_eq(s.queue().done_at(index), DONE_APPLIED);
    assert_eq(opened_outcome(s, want.values[4], want.values[5]), [0, 33450]);
    let notes = deliver_note(s, want.values[4], want.values[5], want.id);
    assert_eq(notes.count, 1);
    assert_eq(notes.first, SwapOutcomeNote { code: 0, amount_out: 33450, request_id: want.id });
}

// ---- the layout --------------------------------------------------------------

// What the layout guards: nodes that open the log under another layout than
// the request function's reconstruct values that do not open to the queued
// C. With every value chosen, such a layout differs in its order: here a
// manifest that commits to `$outcome_tag` before `$outcome_key`, so the
// nodes take each for the other. The round, still for the queued request
// id, lands as a failure that re-blinds the pool and whose outcome opens to code 9 with
// nothing out; it is encrypted to the key and tag the nodes reconstructed,
// so no log lands under the trader's tag. Under the manifest's layout the
// same log opens to C.
#[test]
unconstrained fn a_layout_other_than_the_manifests_makes_the_round_flag_code_9() {
    let s = keyed();
    let v = values(s);
    request(s, EPH);
    let want = expected(s, v, EPH, ENC, [1, 1, 1]);
    let log = the_request_log();
    let (right, right_blinding) = opened(log, EPH, ENC, AMM_SWAP_TIP_SHARED_ONCHAIN_LAYOUT.kinds);
    let intake = SharedIntake {
        inputs_hash: want.c,
        partial: right[3],
        outcome_key: right[4],
        outcome_tag: right[5],
        blinding: right_blinding,
    };
    assert(intake.opens(TRADE));
    assert_eq(right, v);
    let wrong = [right[0], right[1], right[2], right[3], right[5], right[4]];
    let blinding = right_blinding;
    assert_eq(wrong[3], partial_of(s.user, RHO));
    assert(wrong[4] != OUTCOME_KEY);
    assert(wrong[5] != OUTCOME_TAG);
    let r = onchain_round(s, want.c, wrong, blinding, POOL, R0, R1);
    assert_eq(r.outputs.request_id, want.id);
    assert(!r.written.outcome.ok);
    let _ = submit_shared(s, r);
    assert_eq(pool(s), pool_c(s, POOL, R1));
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    assert(outcome_log().get(0) != compute_siloed_private_log_first_field(s.app, OUTCOME_TAG));
    assert_eq(opened_outcome(s, wrong[4], wrong[5]), [CODE_INPUTS_MISMATCH, 0]);
}

// ---- request, round, outcome -------------------------------------------------

// Every node keys the contract at epoch 1; the trader's request queues the
// chain request id with the data hash of its one private log, `[siloed
// tag, C, epochs, E.x, w_0..w_2, six corrections, padding…]`, 16 fields,
// and the partial note's use nullifier, and nothing else (no public log,
// no note hash). The request names no requester and shows no input: no
// account (the user, whose partial note it commits, and the relayer), no
// swap input, neither the partial note, the outcome key, the outcome tag,
// the blinding nor a key-exchange secret appears in its effects. Every node
// derives its pair of every shared value from the log; the round the
// circuit computes from what the nodes opened lands through
// `process_result_shared`, and the trader opens its outcome with the key
// and tag its request chose and holds the completed note.
#[test]
unconstrained fn a_shared_onchain_swap_is_queued_names_no_requester_is_served_and_lands_its_outcome() {
    let s = keyed();
    for i in 0..3 {
        assert_eq(stored_key(s, i), enc_key(ENC[i], 1));
    }
    let v = values(s);
    request(s, EPH);
    let want = expected(s, v, EPH, ENC, [1, 1, 1]);
    assert_eq(s.queue().request_at(0), want.id);
    assert_eq(s.queue().tail(), 1);
    let log = the_request_log();
    assert_eq(log.len(), 16);
    assert_eq(log.get(0), compute_siloed_private_log_first_field(s.app, request_log_tag(want.id)));
    assert_eq(body(log), want.log);
    assert_eq(s.env.view_public(AmmTip::at(s.app).get_data_hash(want.id)), data_hash(want.log));
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let effects = s.env.execute_utility(PssProbe::at(s.probe).tx_summary(tx_hash));
    assert_eq(effects.public_logs, 0);
    assert_eq(effects.note_hashes, 0);
    assert_eq(effects.private_logs, 1);
    let mut used = false;
    let nullifiers = txe_oracles::get_last_tx_effects().nullifiers;
    for i in 0..nullifiers.len() {
        used |= nullifiers.get(i)
            == aztec::protocol::hash::compute_siloed_nullifier(s.app, use_nullifier(partial_of(s.user, RHO)));
    }
    assert(used);

    let holds_none = |vals: [Field; 4]| {
        let as_addresses = vals.map(|v| AztecAddress { inner: v });
        assert(s.env.execute_utility(PssProbe::at(s.probe).tx_names_no_requester(tx_hash, as_addresses)));
    };
    holds_none([s.user.to_field(), s.relayer.to_field(), TRADE[0], TRADE[2]]);
    holds_none([want.values[4], want.values[5], want.blinding, want.secrets[0]]);
    holds_none([want.values[3], RHO, want.secrets[1], want.secrets[2]]);

    assert_served(log, EPH, ENC, want);
    assert_lands(s, 0, log, EPH, ENC, want);
}

// ---- rotation ----------------------------------------------------------------

// A rotation then a request under the new key: node 1 rotates to epoch 2,
// the log names [1, 2, 1], node 1 derives its pairs with its new scalar
// and not with its old one, and the round lands.
#[test]
unconstrained fn a_swap_after_a_rotation_is_under_the_new_key_and_lands() {
    let s = keyed();
    rotate(s, 1, ENC_NEXT[1], 2);
    assert_eq(stored_key(s, 1), enc_key(ENC_NEXT[1], 2));
    let v = values(s);
    request(s, EPH);
    let scalars = [ENC[0], ENC_NEXT[1], ENC[2]];
    let want = expected(s, v, EPH, scalars, [1, 2, 1]);
    let log = the_request_log();
    assert_eq(log.get(2), pack_epochs([1, 2, 1]));
    assert_eq(body(log), want.log);
    assert_eq(s.queue().request_at(0), want.id);
    assert_served(log, EPH, scalars, want);
    let e = public_key(EPH);
    let wrap = log.get(1 + 3);
    assert(
        node_pair(1, ecdh_x(ENC[1], e), wrap, 0, 0)[0]
            != node_pair(1, ecdh_x(ENC_NEXT[1], e), wrap, 0, 0)[0],
    );
    assert_lands(s, 0, log, EPH, scalars, want);
}

// A key-set rotation that replaces node 2 (its sig and enc keys, signed by
// nodes 0 and 1) voids node 2's enc key in the contract with the install,
// so a swap that would share to the replaced key is refused at once, not
// queued for a node that cannot open it.
#[test(should_fail_with = "a node's enc key is void until it rotates")]
unconstrained fn a_swap_to_a_replaced_nodes_enc_key_is_refused() {
    let s = keyed();
    let keys = key_set([NODE_SIG[0], NODE_SIG[1], NEWCOMER_SIG], [ENC[0], ENC[1], ENC_NEXT[2]]);
    let signatures = rotation_signatures(s.app, 1, keys, [NODE_SIG[0], NODE_SIG[1], 0]);
    s.env.call_private(s.relayer, AmmTip::at(s.app).rotate_keys(1, keys, signatures));
    assert_eq(stored_key(s, 2), EncKey { x: 0, y: 0, epoch: 3 });
    request(s, EPH);
}

// A request under the retired key is still served: queued at epochs
// [1, 1, 1], then node 1 rotates to epoch 2; the queued id and data hash
// stand, node 1 derives its pairs of the request with its epoch-1 scalar,
// and the round lands.
#[test]
unconstrained fn a_swap_under_the_retired_key_is_still_served_and_lands() {
    let s = keyed();
    let v = values(s);
    request(s, EPH);
    let want = expected(s, v, EPH, ENC, [1, 1, 1]);
    let log = the_request_log();
    rotate(s, 1, ENC_NEXT[1], 2);
    assert_eq(stored_key(s, 1), enc_key(ENC_NEXT[1], 2));
    assert_eq(s.queue().request_at(0), want.id);
    assert_eq(s.env.view_public(AmmTip::at(s.app).get_data_hash(want.id)), data_hash(want.log));
    assert_eq(log.get(2), pack_epochs([1, 1, 1]));
    assert_lands(s, 0, log, EPH, ENC, want);
}

// A request proven at an anchor older than a rotation: node 1 rotates to
// epoch 2, then the request function's library half (`shared_onchain_request`,
// with the contract's round, slot, layout and validity check) runs in the
// app's private context anchored at the block before that rotation. It reads
// the epoch-1 keys there (at the latest block node 1's is epoch 2) and builds
// the log naming [1, 1, 1], read from the context as the request function
// emitted it; the append wrapper's body
// (`SharedOnchain::append` on the app's storage, in the app's public
// context) accepts the epoch one before the stored one and queues the id
// with the data hash; the nodes serve it with the epoch-1 scalars and the
// round lands. (TestEnvironment's private context cannot enqueue, so the
// wrapper's public body runs in a public context of its own.)
#[test]
unconstrained fn a_swap_proven_at_an_anchor_before_a_rotation_is_queued_and_lands() {
    let s = keyed();
    let anchor = s.env.last_block_number();
    rotate(s, 1, ENC_NEXT[1], 2);
    let app = s.app;
    let layout = AmmTip::storage_layout();
    let slot = layout.shared_onchain.slot;
    let latest = s.env.private_context_at(app, |context| anchor_keys(context, slot));
    assert_eq(latest[1], enc_key(ENC_NEXT[1], 2));
    let v = values(s);
    let opts = PrivateContextOptions::new().at_anchor_block_number(anchor).at_contract_address(app);
    let (keys, r, emitted) = s.env.private_context_opts(opts, |context| {
        let keys = anchor_keys(context, slot);
        let configured: PublicImmutable<Configured<PACKAGES>, &mut PrivateContext> =
            PublicImmutable::new(context, layout.configured.slot);
        let pool: CommitmentSlot<&mut PrivateContext> = PublicMutable::new(context, layout.pool.slot);
        let round = rounds(configured.read(), pool).swap_shared;
        let r: SharedOnchainRequest =
            shared_onchain_request(context, round, slot, AMM_SWAP_TIP_SHARED_ONCHAIN_LAYOUT, v, EPH, valid_swap);
        let logs = context.finish().private_logs;
        assert_eq(logs.length, 1);
        (keys, r, logs.array[0].inner.log)
    });
    for i in 0..3 {
        assert_eq(keys[i], enc_key(ENC[i], 1));
    }
    let want = expected(s, v, EPH, ENC, [1, 1, 1]);
    assert_eq(r.request_id, want.id);
    assert_eq(r.epochs, [1, 1, 1]);
    assert_eq(r.data_hash, data_hash(want.log));
    // the log the request function emitted, its tag before the kernel
    // silos it with the app's address
    assert_eq(emitted.length, 16);
    assert_eq(emitted.fields[0], request_log_tag(want.id));
    let mut log: BoundedVec<Field, 16> = BoundedVec::new();
    log.push(compute_siloed_private_log_first_field(app, emitted.fields[0]));
    for i in 0..REQUEST_LOG_LEN {
        log.push(emitted.fields[1 + i]);
    }
    assert_eq(body(log), want.log);
    let (id, hash, epochs) = (r.request_id, r.data_hash, r.epochs);
    let index = s.env.public_context_at(app, |context| {
        let onchain: SharedOnchain<PublicContext> = SharedOnchain::new(context, slot);
        let queue: Queue<PublicContext> = Queue::new(context, layout.queue.slot);
        onchain.append(queue, id, hash, epochs)
    });
    assert_eq(index, 0);
    assert_eq(s.queue().request_at(0), want.id);
    assert_eq(s.env.view_public(AmmTip::at(app).get_data_hash(want.id)), data_hash(want.log));
    assert_served(log, EPH, ENC, want);
    assert_lands(s, 0, log, EPH, ENC, want);
}
