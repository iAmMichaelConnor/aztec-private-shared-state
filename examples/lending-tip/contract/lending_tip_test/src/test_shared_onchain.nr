//! The deposit under secret-shared on-chain intake, on the secret-shared deployment
//! (`shared_setup`): the nodes key the contract with signed
//! `rotate_enc_key` transactions, the depositor's `deposit_shared_onchain`
//! queues the chain request id with the data hash of one private log of
//! encoded shares, every node derives its pair of every shared value from
//! that log, and the round lands through `process_shared(ROUND_DEPOSIT, ...)`, the same
//! circuit and public inputs as under secret-shared receipt intake.
//!
//! C commits to `[position, amount, handle_partial, handle_key, partial_note,
//! outcome_key, outcome_tag]` (the request's delivery handle after the app
//! inputs) under the blinding: `position` clear in the log, the rest chosen (one
//! correction each; the partial note always, and the outcome key and tag are
//! the client's derivations, as under secret-shared receipt intake), the
//! partial note the request function's own from the sender and rho, the blinding the
//! encoding's (`DEPOSIT_SHARED_ONCHAIN_LAYOUT`). The nodes' `enc` scalars are
//! test-local. The expected log is recomputed here with pss_core's
//! `tip::derived`, and each node's pairs are re-derived from the landed log
//! under the round's kinds (the generated layout's, testvectors/onchain_layouts.json),
//! as the machine derives them. As in the rest of the shared suite the outcomes are
//! stand-ins encrypted with the round's own `encrypt_outcome` (lib.nr's
//! `submit_shared`); the round's first check, that C opens to what the
//! nodes reconstructed (`SharedIntake::opens`, code 14 when not), is run
//! here on the reconstructed values.
use crate::{
    MISMATCH, OPENED,
    deploy_probe,
    C1, C_INIT, DEPOSIT, EPOCH, market, open_and_deliver, outcome_notes,
    handle_secrets, partial_of, POSITION, PRICE, REQUEST_GAS, Request, request_keys, rho_of, Setup,
    shared_setup, submit_shared,
};
use aztec::context::{PrivateContext, PublicContext};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::compute_siloed_private_log_first_field;
use aztec::protocol::traits::ToField;
use aztec::state_vars::{PublicImmutable, PublicMutable, StateVariable};
use aztec::test::helpers::test_environment::PrivateContextOptions;
use aztec::test::helpers::txe_oracles;
use lending_market::app::{PACKAGES, ROUND_DEPOSIT, valid_deposit};
use lending_market::layouts::DEPOSIT_SHARED_ONCHAIN_LAYOUT;
use lending_tip::{LendingTip, ROUNDS};
use pss_core::tip::derived::{
    data_hash, node_pair, pack_epochs,
    REQUEST_LOG_HEADER, REQUEST_LOG_LEN,
};
use pss_core::tip::intake::SharedIntake;
use pss_core::tip::outcome::log_padding;
use pss_public_contract::{
    CommitmentSlot, Configured, DONE_APPLIED, EncKey, Queue,
    shared_onchain_request, SharedOnchain, SharedOnchainRequest,
};
use pss_public_contract::shared_onchain::{anchor_keys, request_log_tag};
use pss_probe::PssProbe;
use pss_tip_test::shared_onchain;
use pss_tip_test::shared_onchain::{body, ENC, ENC_NEXT, enc_key, EPH, Expected, node_rotation};
use pss_tip_test::shape::kind_options;
use pss_utils::dh::{ecdh_x, public_key};

/// The secret-shared deployment, every node keyed at epoch 1.
unconstrained fn keyed() -> Setup {
    let s = shared_setup();
    for i in 0..3 {
        rotate(s, i, ENC[i], 1);
    }
    s
}

/// Node i's rotation to `sk` at `epoch`, signed under its pinned `sig` key
/// and sent by the relayer.
unconstrained fn rotate(s: Setup, i: u32, sk: Field, epoch: u32) {
    let (key, signature) = node_rotation(s.app, i, sk, epoch);
    s.env.call_private(s.relayer, LendingTip::at(s.app).rotate_enc_key(i, key, signature));
}

unconstrained fn stored_key(s: Setup, i: u32) -> EncKey {
    s.env.view_public(LendingTip::at(s.app).get_enc_key(i))
}

/// C's values for the user's opening deposit of DEPOSIT, the delivery
/// handle, the partial note, outcome key and tag of request number 1.
unconstrained fn values(s: Setup) -> [Field; 7] {
    let (key, tag, _) = request_keys(1);
    let (handle_rho, handle_key) = handle_secrets(1);
    [0, DEPOSIT, partial_of(s.user, handle_rho), handle_key, partial_of(s.user, rho_of(1)), key, tag]
}

/// The user's secret-shared on-chain deposit of `v` under EPH, under the request
/// gas setting: the request function commits the partial note from the
/// sender and rho itself.
unconstrained fn request(s: Setup, v: [Field; 7]) {
    let (handle_rho, _) = handle_secrets(1);
    s.env.call_private_opts(
        s.user,
        kind_options(REQUEST_GAS),
        LendingTip::at(s.app).deposit_shared_onchain(v[0], v[1], handle_rho, v[3], rho_of(1), v[5], v[6], EPH),
    );
}

/// What the request function computes from `v` under EPH and the node
/// scalars `scalars` at `epochs`.
unconstrained fn expected(s: Setup, v: [Field; 7], scalars: [Field; 3], epochs: [u32; 3]) -> Expected<7, 6> {
    shared_onchain::expected(
        DEPOSIT_SHARED_ONCHAIN_LAYOUT,
        s.app.to_field(),
        crate::shared_vk_hash(ROUND_DEPOSIT),
        v,
        EPH,
        scalars,
        epochs,
    )
}

/// The queued request as lib.nr's result helpers take it: the outcome key
/// and tag the round encrypts to, and the user's partial note (its owner and
/// rho, which the nodes never see: they hold the partial note `opened[4]`),
/// and the delivery handle it leaves (`opened[2]` and `opened[3]`).
unconstrained fn queued(s: Setup, id: Field, opened: [Field; 7]) -> Request {
    let (handle_rho, handle_key) = handle_secrets(1);
    assert_eq(opened[2], partial_of(s.user, handle_rho));
    assert_eq(opened[4], partial_of(s.user, rho_of(1)));
    Request {
        kind: ROUND_DEPOSIT,
        id,
        expiry: 0,
        key: opened[5],
        tag: opened[6],
        owner: s.user,
        rho: rho_of(1),
        handle_rho,
        handle_key,
    }
}

/// The last transaction's one private log: `[siloed tag, fields…]`.
/// The request log: the transaction's first private log (the request
/// function emits it before its token calls, whose own logs follow).
unconstrained fn the_request_log() -> BoundedVec<Field, 16> {
    let effects = txe_oracles::get_last_tx_effects();
    assert(effects.private_logs.len() > 1);
    effects.private_logs.get(0)
}

/// What the nodes open from the landed log under the kinds vector `kinds`
/// (`shared_onchain::opened` under EPH).
unconstrained fn opened(log: BoundedVec<Field, 16>, scalars: [Field; 3], kinds: [u8; 7]) -> ([Field; 7], Field) {
    shared_onchain::opened(log, EPH, scalars, kinds)
}

/// Whether C opens to the reconstructed values under the reconstructed
/// blinding: the round's first check.
fn opens(c: Field, vals: [Field; 7], blinding: Field) -> bool {
    let intake = SharedIntake {
        inputs_hash: c,
        partial: vals[4],
        outcome_key: vals[5],
        outcome_tag: vals[6],
        blinding,
    };
    intake.opens([vals[0], vals[1], vals[2], vals[3]])
}

/// Every node, using `scalars[i]` under the machine's kinds vector, opens
/// C's values and the blinding the request committed to; C opens to them.
unconstrained fn assert_served(log: BoundedVec<Field, 16>, scalars: [Field; 3], want: Expected<7, 6>) {
    let (vals, blinding) = opened(log, scalars, DEPOSIT_SHARED_ONCHAIN_LAYOUT.kinds);
    assert_eq(vals, want.values);
    assert_eq(blinding, want.blinding);
    assert(opens(want.c, vals, blinding));
}

/// The nodes open the request at queue index 0 from its landed log (each
/// with `scalars[i]`) and its round lands on C_INIT: the market takes C1,
/// the entry is applied, and the depositor opens the outcome with its own
/// outcome key under its own tag, position 1 assigned, and its PXE holds the
/// completed note.
unconstrained fn assert_lands(s: Setup, log: BoundedVec<Field, 16>, scalars: [Field; 3], want: Expected<7, 6>) {
    let (vals, blinding) = opened(log, scalars, DEPOSIT_SHARED_ONCHAIN_LAYOUT.kinds);
    assert(opens(want.c, vals, blinding));
    let req = queued(s, want.id, vals);
    let tx = submit_shared(s, req, C_INIT, C1, PRICE, EPOCH, OPENED);
    assert_eq(market(s), C1);
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    let outcome = open_and_deliver(s, req, tx);
    assert_eq(outcome, OPENED);
    assert_eq(outcome[1], POSITION);
    assert_eq(outcome_notes(s, s.user).count, 1);
}

// ---- the layout --------------------------------------------------------------

// What the layout guards: nodes that open the log under another layout than
// the request function's reconstruct values that do not open to the queued
// C, so the round flags code 14. With the clear position first and every
// other value chosen, such a layout differs in its order: here a manifest
// that commits to `$outcome_tag` before `$outcome_key`, so the nodes take
// each for the other. Its result, for the queued request
// id, still lands and re-blinds the market, but its outcome is encrypted to
// the key and tag the nodes reconstructed: no log under the depositor's tag,
// and the completed note says code 14. Under the manifest's layout the same
// log opens to C.
#[test]
unconstrained fn a_layout_other_than_the_manifests_makes_the_round_flag_code_14() {
    let s = keyed();
    let v = values(s);
    request(s, v);
    let want = expected(s, v, ENC, [1, 1, 1]);
    let log = the_request_log();
    assert_served(log, ENC, want);
    let (right, blinding) = opened(log, ENC, DEPOSIT_SHARED_ONCHAIN_LAYOUT.kinds);
    let wrong = [right[0], right[1], right[2], right[3], right[4], right[6], right[5]];
    assert_eq(wrong[4], v[4]);
    assert(wrong[5] != v[5]);
    assert(!opens(want.c, wrong, blinding));
    let req = queued(s, want.id, wrong);
    let tx = submit_shared(s, req, C_INIT, C1, PRICE, EPOCH, MISMATCH);
    assert_eq(market(s), C1);
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    let landed = txe_oracles::get_last_tx_effects().private_logs.get(0);
    assert(landed.get(0) != compute_siloed_private_log_first_field(s.app, v[6]));
    assert_eq(open_and_deliver(s, req, tx), MISMATCH);
}

// ---- request, round, outcome -------------------------------------------------

// The opening deposit's request log: every node keys the contract at epoch
// 1, and the request queues the chain request id with the data hash of its
// one private log, 16 fields, `[siloed tag, C, epochs, E.x, w_0..w_2,
// position (clear, 0), six corrections, padding…]`, the padding keyed by
// the blinding; every node derives its pair of every shared value from it.
// The request transaction has no public log, and names no requester and
// shows no input but the escrowed amount (public by design, the escrow's
// transfer into the market's public balance): no account (the user, also
// the partial note's owner, and the relayer), neither rho, the outcome key,
// the outcome tag, the delivery handle, the blinding nor a key-exchange secret appears in its
// effects. Its round then lands through `process_shared(ROUND_DEPOSIT, ...)` on what the
// nodes opened from the log: the market takes the new commitment and the
// depositor opens its outcome, position 1 assigned, and holds the outcome
// note.
#[test]
unconstrained fn an_opening_deposit_logs_its_clear_position_and_six_corrections_and_lands() {
    let s = keyed();
    for i in 0..3 {
        assert_eq(stored_key(s, i), enc_key(ENC[i], 1));
    }
    let v = values(s);
    request(s, v);
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let want = expected(s, v, ENC, [1, 1, 1]);
    assert_eq(s.queue().request_at(0), want.id);
    assert_eq(s.queue().tail(), 1);
    let log = the_request_log();
    assert_eq(log.len(), 16);
    assert_eq(log.get(0), compute_siloed_private_log_first_field(s.app, request_log_tag(want.id)));
    let b = body(log);
    assert_eq(b, want.log);
    assert_eq(b[REQUEST_LOG_HEADER], 0);
    for i in 0..6 {
        assert_eq(b[REQUEST_LOG_HEADER + 1 + i], want.corrections[i]);
    }
    for i in REQUEST_LOG_HEADER + 7..REQUEST_LOG_LEN {
        assert_eq(b[i], log_padding(want.blinding, i));
    }
    assert_eq(s.env.view_public(LendingTip::at(s.app).get_data_hash(want.id)), data_hash(want.log));
    assert_served(log, ENC, want);
    let probe = deploy_probe(s);
    let effects = s.env.execute_utility(PssProbe::at(probe).tx_summary(tx_hash));
    // no public log; its note hashes and the private logs after the request
    // log are the token transfers' (change notes, refund-note messages)
    assert_eq(effects.public_logs, 0);
    let holds_none = |vals: [Field; 4]| {
        let as_addresses = vals.map(|v| AztecAddress { inner: v });
        assert(s.env.execute_utility(PssProbe::at(probe).tx_names_no_requester(tx_hash, as_addresses)));
    };
    // the amount is public by design: the escrow moves it into the market's
    // public balance
    holds_none([s.user.to_field(), s.relayer.to_field(), rho_of(1), rho_of(1)]);
    holds_none([v[5], v[6], want.blinding, want.secrets[0]]);
    holds_none([v[2], v[3], handle_secrets(1).0, want.blinding]);
    assert_lands(s, log, ENC, want);
}

// ---- rotation ----------------------------------------------------------------

// A rotation then a request under the new key: node 1 rotates to epoch 2,
// the log names [1, 2, 1], node 1 derives its pairs with its new scalar
// and not with its old one, and the round lands.
#[test]
unconstrained fn a_deposit_after_a_rotation_is_under_the_new_key_and_lands() {
    let s = keyed();
    rotate(s, 1, ENC_NEXT[1], 2);
    assert_eq(stored_key(s, 1), enc_key(ENC_NEXT[1], 2));
    let v = values(s);
    request(s, v);
    let scalars = [ENC[0], ENC_NEXT[1], ENC[2]];
    let want = expected(s, v, scalars, [1, 2, 1]);
    let log = the_request_log();
    assert_eq(log.get(2), pack_epochs([1, 2, 1]));
    assert_eq(body(log), want.log);
    assert_eq(s.queue().request_at(0), want.id);
    assert_served(log, scalars, want);
    let e = public_key(EPH);
    let wrap = log.get(1 + 3);
    assert(
        node_pair(1, ecdh_x(ENC[1], e), wrap, 0, 0)[0]
            != node_pair(1, ecdh_x(ENC_NEXT[1], e), wrap, 0, 0)[0],
    );
    assert_lands(s, log, scalars, want);
}

// A request under the retired key is still served: queued at epochs
// [1, 1, 1], then node 1 rotates to epoch 2; the queued id and data hash
// stand, node 1 derives its pairs of the request with its epoch-1 scalar,
// and the round lands.
#[test]
unconstrained fn a_deposit_under_the_retired_key_is_still_served_and_lands() {
    let s = keyed();
    let v = values(s);
    request(s, v);
    let want = expected(s, v, ENC, [1, 1, 1]);
    let log = the_request_log();
    rotate(s, 1, ENC_NEXT[1], 2);
    assert_eq(stored_key(s, 1), enc_key(ENC_NEXT[1], 2));
    assert_eq(s.queue().request_at(0), want.id);
    assert_eq(s.env.view_public(LendingTip::at(s.app).get_data_hash(want.id)), data_hash(want.log));
    assert_eq(log.get(2), pack_epochs([1, 1, 1]));
    assert_served(log, ENC, want);
    assert_lands(s, log, ENC, want);
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
unconstrained fn a_deposit_proven_at_an_anchor_before_a_rotation_is_queued_and_lands() {
    let s = keyed();
    let anchor = s.env.last_block_number();
    rotate(s, 1, ENC_NEXT[1], 2);
    let app = s.app;
    let layout = LendingTip::storage_layout();
    let slot = layout.shared_onchain.slot;
    let latest = s.env.private_context_at(app, |context| anchor_keys(context, slot));
    assert_eq(latest[1], enc_key(ENC_NEXT[1], 2));
    let v = values(s);
    let opts = PrivateContextOptions::new().at_anchor_block_number(anchor).at_contract_address(app);
    let (keys, r, emitted) = s.env.private_context_opts(opts, |context| {
        let keys = anchor_keys(context, slot);
        let configured: PublicImmutable<Configured<PACKAGES>, &mut PrivateContext> =
            PublicImmutable::new(context, layout.configured.slot);
        let market: CommitmentSlot<&mut PrivateContext> = PublicMutable::new(context, layout.market.slot);
        let round = ROUNDS.round(configured.read(), market, ROUND_DEPOSIT);
        let r: SharedOnchainRequest =
            shared_onchain_request(context, round, slot, DEPOSIT_SHARED_ONCHAIN_LAYOUT, v, EPH, valid_deposit::<4>);
        let logs = context.finish().private_logs;
        assert_eq(logs.length, 1);
        (keys, r, logs.array[0].inner.log)
    });
    for i in 0..3 {
        assert_eq(keys[i], enc_key(ENC[i], 1));
    }
    let want = expected(s, v, ENC, [1, 1, 1]);
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
    assert_eq(s.env.view_public(LendingTip::at(app).get_data_hash(want.id)), data_hash(want.log));
    assert_served(log, ENC, want);
    assert_lands(s, log, ENC, want);
}
