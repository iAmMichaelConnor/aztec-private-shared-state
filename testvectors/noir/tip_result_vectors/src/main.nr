//! Checks testvectors/tip_results.json, two chain-held result rounds the
//! machine signed, with the functions the tip contract library runs on chain
//! (noir/pss_public_contract): the chain request id from its
//! preimage (intake.nr), the machine request id the nodes sign under (over
//! the old commitments and then the round's pinned reads, the entry point's
//! `round{k}_reads` where it has some),
//! `record_hash` of every sealed third, `sealed_hashes` (H(sealed_i)),
//! `result_message` per node and its signature under keys.json's `sig` key
//! with `result_signature_verifies`, and all three together with
//! `assert_result_signatures`, the check process_result makes (result.nr).
//! The sealed-thirds log body is rebuilt as `chain_state::emit_state_log`
//! serialises it, `(new_commitments, sealed)`, under `compute_log_tag(chain_request_id,
//! PSS_STATE)`. It also checks testvectors/results.json, the result
//! signatures the machine signs (written by sidecar-core's write_vectors):
//! every message and all nine signatures with the same library functions,
//! H(sealed_i) for two thirds, one and none (the node-held case, 0), and the
//! mutations pss-client's test applies (a tampered, missing or moved
//! signature; another namespace, commitment or third) refused. The library has no log parser and does not re-check the size
//! bound (REGISTER does), so the layout arithmetic is checked here: L = 3·len
//! + 5 per third, W + 3·T·L fields of body (W = T = 1), REGISTER's 9·len + 15
//! = 3·L of thirds and its log count 1 + W + 9·len + 15 = 1 + body (the tag,
//! then the body), with its verdict under protocol_types'
//! MAX_PUBLIC_LOG_SIZE_IN_FIELDS (FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH minus
//! PUBLIC_LOG_HEADER_LENGTH, the file's public_log numbers). Each round's
//! public-input array is result.nr's `proved_public_inputs` of its parts,
//! and each init round's is init.nr's `init_public_inputs` of its parts,
//! with `init_request_id` and the machine request id over empty slots
//! (`process_init`'s). Prover.toml is
//! written from the vector file by sidecar-tip (tests/write_vectors, write_tip_vectors);
//! `nargo execute` fails on any disagreement.

use aztec::protocol::address::AztecAddress;
use aztec::protocol::constants::{
    FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH, MAX_PUBLIC_LOG_SIZE_IN_FIELDS, PUBLIC_LOG_HEADER_LENGTH,
};
use aztec::protocol::hash::compute_log_tag;
use aztec::protocol::traits::{FromField, Serialize};
use pss_public_contract::{chain_request_id, inputs_hash, PSS_ATTEMPT, RESULT_DOMAIN};
use pss_public_contract::init::{init_public_inputs, init_request_id};
use pss_public_contract::chain_state::{
    PSS_STATE, record_hash, sealed_hash_of_record_hashes, sealed_hashes,
};
use pss_public_contract::result::{
    assert_result_signatures, machine_request_id, NodeHeld, proved_public_inputs, result_message,
    result_messages, result_signature_verifies, Sealing,
};
use std::embedded_curve_ops::EmbeddedCurvePoint;

/// One round of tip_results.json: P app inputs, R old commitments, one
/// chain-held output (W = T = 1) of N elements, thirds of L fields, a log
/// body of B fields, A app outputs and M public inputs.
struct Round<let P: u32, let R: u32, let N: u32, let L: u32, let B: u32, let A: u32, let M: u32> {
    namespace: Field,
    vk_hash: Field,
    inputs: [Field; P],
    inputs_hash: Field,
    user_nonce: Field,
    chain_request_id: Field,
    old_commitments: [Field; R],
    machine_request_id: Field,
    new_commitments: [Field; 1],
    len: u32,
    /// `sealed[i][t]`: node i's third of chain-held output t, [key id, ct..., tag]
    sealed: [[[Field; L]; 1]; 3],
    key_ids: [Field; 3],
    record_hashes: [Field; 3],
    sealed_hashes: [Field; 3],
    messages: [Field; 3],
    /// [s.lo, s.hi, e.lo, e.hi]
    signatures: [[Field; 4]; 3],
    log_tag: Field,
    third_len: u32,
    log_body: [Field; B],
    register_fields: u32,
    register_log_fields: u32,
    register_accepted: bool,
    in_slots: [Field; R],
    out_slots: [Field; 1],
    npk_app_hash: Field,
    ok: bool,
    app_outputs: [Field; A],
    public_inputs: [Field; M],
}

/// One init round of tip_results.json: W keys created, M public inputs; its
/// inputs and new leaf hashes are the entry point's `init{k}_inputs` and
/// `init{k}_new_hashes` where it has some.
struct InitRound<let W: u32, let M: u32> {
    namespace: Field,
    vk_hash: Field,
    chain_request_id: Field,
    machine_request_id: Field,
    npk_app_hash: Field,
    out_slots: [Field; W],
    new_commitments: [Field; W],
    public_inputs: [Field; M],
}

/// The init's ids as process_init derives them, and its public-input array
/// as init_public_inputs rebuilds it.
fn check_init<let W: u32, let M: u32, let P: u32, let H: u32>(
    r: InitRound<W, M>,
    inputs: [Field; P],
    new_hashes: [Field; H],
) {
    let id = init_request_id(AztecAddress::from_field(r.namespace), r.vk_hash, inputs);
    assert_eq(id, r.chain_request_id, "init chain request id");
    assert_eq(id, chain_request_id(AztecAddress::from_field(r.namespace), r.vk_hash, inputs_hash(inputs), 0));
    assert_eq(machine_request_id(id, [0; W], []), r.machine_request_id, "init machine request id");
    let pi = init_public_inputs(
        r.namespace,
        r.vk_hash,
        r.out_slots,
        id,
        r.new_commitments,
        r.npk_app_hash,
        new_hashes,
    );
    assert_eq(pi.len(), M, "init public-input count");
    for k in 0..M {
        assert_eq(pi[k], r.public_inputs[k], "init public input");
    }
}

/// A REGISTER verdict: `chain_outputs` outputs of `len` elements each, every
/// one a written key.
struct Bound {
    len: u32,
    chain_outputs: u32,
    writes: u32,
    sealed_thirds_fields: u32,
    log_fields: u32,
    accepted: bool,
}

/// The v6 public-log numbers the file states.
struct PublicLog {
    payload_fields: u32,
    header_fields: u32,
    max_log_fields: u32,
}

struct Key {
    x: Field,
    y: Field,
}

fn check_round<let P: u32, let R: u32, let Q: u32, let N: u32, let L: u32, let B: u32, let A: u32, let M: u32>(
    r: Round<P, R, N, L, B, A, M>,
    reads: [Field; Q],
    keys: [EmbeddedCurvePoint; 3],
) {
    // the ids
    let ih = inputs_hash(r.inputs);
    assert_eq(ih, r.inputs_hash, "inputs_hash");
    let chain = chain_request_id(
        AztecAddress::from_field(r.namespace),
        r.vk_hash,
        ih,
        r.user_nonce,
    );
    assert_eq(chain, r.chain_request_id, "chain_request_id");
    let machine = machine_request_id(chain, r.old_commitments, reads);
    assert_eq(machine, r.machine_request_id, "machine_request_id");

    // the public inputs process_result verifies the proof over
    let pi = proved_public_inputs(
        r.namespace,
        r.vk_hash,
        r.in_slots,
        r.out_slots,
        reads,
        chain,
        r.old_commitments,
        r.new_commitments,
        r.npk_app_hash,
        r.ok,
        r.app_outputs,
    );
    assert_eq(pi.len(), M, "public-input count");
    for k in 0..M {
        assert_eq(pi[k], r.public_inputs[k], "public input");
    }

    // the thirds and H(sealed_i)
    let hashes = sealed_hashes(r.sealed);
    for i in 0..3 {
        assert_eq(r.sealed[i][0][0], r.key_ids[i], "a third's key id");
        assert_eq(record_hash(r.sealed[i][0]), r.record_hashes[i], "record_hash");
        assert_eq(sealed_hash_of_record_hashes([r.record_hashes[i]]), r.sealed_hashes[i]);
        assert_eq(hashes[i], r.sealed_hashes[i], "H(sealed_i)");
    }

    // the messages and the signatures, as process_result checks them
    for i in 0..3 {
        let message = result_message(r.namespace, machine, r.new_commitments, i, hashes[i]);
        assert_eq(message, r.messages[i], "result message");
        assert(result_signature_verifies(keys[i], r.signatures[i], message), "node's result signature");
        // node i's only, over the machine request id, over its own third
        assert(!result_signature_verifies(keys[(i + 1) % 3], r.signatures[i], message));
        let over_chain = result_message(r.namespace, chain, r.new_commitments, i, hashes[i]);
        assert(!result_signature_verifies(keys[i], r.signatures[i], over_chain));
        let other_third = result_message(r.namespace, machine, r.new_commitments, i, hashes[(i + 1) % 3]);
        assert(!result_signature_verifies(keys[i], r.signatures[i], other_third));
        // a round with pinned reads is signed over the id that covers them
        if Q != 0 {
            let unpinned = machine_request_id(chain, r.old_commitments, []);
            let over_unpinned = result_message(r.namespace, unpinned, r.new_commitments, i, hashes[i]);
            assert(!result_signature_verifies(keys[i], r.signatures[i], over_unpinned));
        }
    }
    assert_result_signatures(
        keys,
        result_messages(r.namespace, machine, r.new_commitments, hashes),
        r.signatures,
    );

    // the sealed-thirds log: emit_state_log's tag and body
    assert_eq(compute_log_tag(chain, PSS_STATE), r.log_tag, "sealed log tag");
    let body = (r.new_commitments, r.sealed).serialize();
    assert_eq(body.len(), B, "log body length");
    for k in 0..B {
        assert_eq(body[k], r.log_body[k], "log body field");
    }

    // the layout arithmetic and REGISTER's count
    assert_eq(N, r.len);
    assert_eq(L, r.third_len);
    assert_eq(L, 3 * N + 5, "a third is 3·len + 5 fields");
    assert_eq(B, 1 + 3 * 1 * L, "the body is W + 3·T·L fields");
    assert_eq(r.register_fields, 9 * N + 15, "REGISTER counts 9·len + 15");
    assert_eq(r.register_fields, 3 * L);
    assert_eq(r.register_log_fields, 1 + 1 + r.register_fields, "REGISTER counts 1 + W + 9·len + 15");
    assert_eq(r.register_log_fields, 1 + B, "the tag, then the body");
    assert_eq(r.register_accepted, r.register_log_fields <= MAX_PUBLIC_LOG_SIZE_IN_FIELDS);
    assert(1 + B <= MAX_PUBLIC_LOG_SIZE_IN_FIELDS, "the log fits one public log");
}

/// One case of results.json: W commitments, three nodes' H(sealed_i),
/// messages and signatures; its record hashes come beside it (none for the
/// node-held case).
struct ResultCase<let W: u32> {
    request_id: Field,
    commitments: [Field; W],
    sealed_hashes: [Field; 3],
    messages: [Field; 3],
    /// [s.lo, s.hi, e.lo, e.hi]
    signatures: [[Field; 4]; 3],
}

/// Every message of one results.json case equals the file's, each signature
/// verifies under its node's key and under no other node's message, and the
/// three pass `assert_result_signatures`; each mutation pss-client's test
/// applies is refused at the node it names.
fn check_result_case<let W: u32, let T: u32>(
    namespace: Field,
    c: ResultCase<W>,
    record_hashes: [[Field; T]; 3],
    other_record_hash: Field,
    keys: [EmbeddedCurvePoint; 3],
) {
    let sealed = record_hashes.map(|r| sealed_hash_of_record_hashes(r));
    assert_eq(sealed, c.sealed_hashes, "H(sealed_i)");
    for i in 0..3 {
        let message = result_message(namespace, c.request_id, c.commitments, i, sealed[i]);
        assert_eq(message, c.messages[i], "result message");
        let sig = c.signatures[i];
        assert(result_signature_verifies(keys[i], sig, message), "node's result signature");
        let j = (i + 1) % 3;
        let other = result_message(namespace, c.request_id, c.commitments, j, sealed[i]);
        assert(!result_signature_verifies(keys[i], sig, other));
        // a tampered signature: s.lo with its low bit flipped
        let mut bad = sig;
        bad[0] = ((bad[0] as u128) ^ 1) as Field;
        assert(!result_signature_verifies(keys[i], bad, message));
        // a missing signature (all zero)
        assert(!result_signature_verifies(keys[i], [0; 4], message));
        // node i's valid signature in node j's place
        let message_j = result_message(namespace, c.request_id, c.commitments, j, sealed[j]);
        assert(!result_signature_verifies(keys[j], sig, message_j));
    }
    assert_result_signatures(
        keys,
        result_messages(namespace, c.request_id, c.commitments, sealed),
        c.signatures,
    );

    // another namespace, a changed commitment, a changed third: node 0's
    // message changes, so its signature is refused
    let m0 = |ns: Field, cs: [Field; W], s0: Field| result_message(ns, c.request_id, cs, 0, s0);
    assert(!result_signature_verifies(keys[0], c.signatures[0], m0(namespace + 1, c.commitments, sealed[0])));
    let mut changed = c.commitments;
    changed[0] = 7;
    assert(!result_signature_verifies(keys[0], c.signatures[0], m0(namespace, changed, sealed[0])));
    if T > 0 {
        let mut thirds = record_hashes[0];
        thirds[0] = other_record_hash;
        let s0 = sealed_hash_of_record_hashes(thirds);
        assert(!result_signature_verifies(keys[0], c.signatures[0], m0(namespace, c.commitments, s0)));
    }
}

fn main(
    result_domain: Field,
    pss_attempt: Field,
    pss_state: u32,
    round1_reads: [Field; 1],
    init1_inputs: [Field; 1],
    init1_new_hashes: [Field; 1],
    results_namespace: Field,
    results0_record_hashes: [[Field; 2]; 3],
    results1_record_hashes: [[Field; 1]; 3],
    public_log: PublicLog,
    sig_keys: [Key; 3],
    round0: Round<2, 1, 2, 11, 34, 2, 11>,
    round1: Round<3, 2, 3, 14, 43, 3, 15>,
    init0: InitRound<1, 7>,
    init1: InitRound<1, 8>,
    results0: ResultCase<2>,
    results1: ResultCase<2>,
    results2: ResultCase<2>,
    register_bound: [Bound; 4],
) {
    assert_eq(result_domain, RESULT_DOMAIN);
    assert_eq(pss_attempt, PSS_ATTEMPT);
    assert_eq(pss_state, PSS_STATE);
    let keys = sig_keys.map(|k: Key| EmbeddedCurvePoint { x: k.x, y: k.y });
    assert_eq(public_log.payload_fields, FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH);
    assert_eq(public_log.header_fields, PUBLIC_LOG_HEADER_LENGTH);
    assert_eq(public_log.max_log_fields, MAX_PUBLIC_LOG_SIZE_IN_FIELDS);
    assert_eq(MAX_PUBLIC_LOG_SIZE_IN_FIELDS, FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH - PUBLIC_LOG_HEADER_LENGTH);
    check_round(round0, [], keys);
    check_round(round1, round1_reads, keys);
    check_init(init0, [], []);
    check_init(init1, init1_inputs, init1_new_hashes);
    // results.json: node 1's first third stands in for node 0's changed one
    let other = results0_record_hashes[1][0];
    check_result_case(results_namespace, results0, results0_record_hashes, other, keys);
    check_result_case(results_namespace, results1, results1_record_hashes, other, keys);
    let none: [[Field; 0]; 3] = [[], [], []];
    check_result_case(results_namespace, results2, none, 0, keys);
    // the node-held case makes no thirds: every H(sealed_i) is 0
    assert_eq(results2.sealed_hashes, NodeHeld {}.sealed_hashes());
    for b in register_bound {
        assert_eq(b.writes, b.chain_outputs);
        assert_eq(b.sealed_thirds_fields, b.chain_outputs * (9 * b.len + 15), "REGISTER counts 9·len + 15 per output");
        assert_eq(b.log_fields, 1 + b.writes + b.sealed_thirds_fields, "the tag, the new commitments, the thirds");
        assert_eq(b.accepted, b.log_fields <= MAX_PUBLIC_LOG_SIZE_IN_FIELDS, "REGISTER's verdict");
    }
    // three outputs of 150: thirds under 4,096, the log over 4,094
    assert_eq(register_bound[3].sealed_thirds_fields, 4095);
    assert(!register_bound[3].accepted);
}
