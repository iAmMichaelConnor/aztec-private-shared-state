//! The tip's shared test vectors that sidecar-tip writes for the other two
//! languages: `testvectors/tip_results.json` (two chain-held rounds, from the
//! machine request id to the three result signatures, the sealed-thirds log
//! body and the REGISTER size bound, each with its public-input array in the
//! non-secret-shared layout, and two init rounds' public-input arrays, which
//! [`public_input_layouts_read_back`] reads back with the machine's own
//! readers) and the `Prover.toml` of the two Noir
//! vector programs that read the tip's files with pss_public_contract's own
//! functions: `testvectors/noir/tip_intake_vectors` (chain_request_id.json,
//! receipts.json, log_tags.json, queue.json, shared_intake.json) and `testvectors/noir/tip_result_vectors`
//! (tip_results.json, and results.json's signed results); and `testvectors/slot_commitment.json` (a chain-held
//! key's slot commitment) with the `Prover.toml` of
//! `testvectors/noir/tip_round_vectors`, which checks it,
//! chain_request_id.json and shared_intake.json's C and chain request id with
//! the round circuits' own helpers (pss_core's `tip` module). sidecar-core's `tests/vectors.rs` and pss-client's
//! `test/vectors.test.ts` read the same files.
//!
//! ```sh
//! cargo test -p sidecar-tip --test write_vectors -- --ignored  # rewrites the files below
//! cargo test --release -p sidecar-tip --test write_vectors     # they are what this code computes
//! scripts/check-vectors.sh tip_intake_vectors tip_result_vectors tip_round_vectors
//! ```
//!
//! The intake files themselves are written by the `ids`, `receipt` and
//! `layout` modules' ignored writers (log_tags.json by aztec.js); rerun
//! `write_tip_vectors` after any of them, so the Noir program's inputs follow.

mod shared_onchain;

use std::fmt::Write as _;

use serde_json::{Value, json};
use sidecar_core::bind::{Elem, Share};
use sidecar_core::derived::Kind;
use sidecar_core::field::{FieldHex, Fr, HexBytes, RequestId};
use sidecar_core::grumpkin::point_to_wire;
use sidecar_core::hash::poseidon2_hash;
use sidecar_core::keys::{NodeKeys, label_field};
use sidecar_core::pipeline::{RESULT_DOMAIN, result_message, sealed_hash};
use sidecar_core::record::{
    self, associated_data, encode_elements, key_hash, record_hash, third_fields, third_fields_len,
};
use sidecar_core::register::Signature;
use sidecar_core::request::NODES;
use sidecar_core::schnorr::verify;
use sidecar_core::store::PackageRow;

use sidecar_test_fixtures::dirs::repo;
use sidecar_test_fixtures::vectors::{hex, node_keys, read};
use sidecar_tip::state::chain::{
    FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH, MAX_PUBLIC_LOG_SIZE_IN_FIELDS, PSS_STATE,
    PUBLIC_LOG_HEADER_LENGTH, SealedLog, apply_log_fields, sealed_log_tag, sealed_thirds_fields,
};
use sidecar_tip::testing::{
    AMM_SWAP_TIP, AMM_SWAP_TIP_ABI, SUMMAND_SALT_SEED, shared_circuit_abi, shared_package,
    shared_values, sharing, summand_salts,
};
use sidecar_tip::{PSS_ATTEMPT, chain_request_id, inputs_hash, machine_request_id};

const TIP_RESULTS: &str = "testvectors/tip_results.json";
const INTAKE_NOIR: &str = "testvectors/noir/tip_intake_vectors";
const RESULT_NOIR: &str = "testvectors/noir/tip_result_vectors";
const SLOT_COMMITMENT: &str = "testvectors/slot_commitment.json";
const ROUND_NOIR: &str = "testvectors/noir/tip_round_vectors";
const SHARED_INTAKE: &str = "testvectors/shared_intake.json";

fn fh(v: Fr) -> FieldHex {
    FieldHex(v)
}

fn fhs(v: &[Fr]) -> Vec<FieldHex> {
    v.iter().copied().map(FieldHex).collect()
}

// The node's result signature as sidecar-core's pipeline makes it at step 14.
fn result_signature(keys: &NodeKeys, message: Fr) -> Signature {
    sidecar_core::schnorr::sign_derived(
        keys.sig_scalar(),
        sidecar_core::pipeline::RESULT_NONCE_LABEL,
        message,
    )
}

/// One chain-held round: a queued request (its chain request id from the
/// intake preimage), the commitments it read, the pinned values it used, and
/// one chain-held output of shared elements, sealed by each node for itself.
struct Round {
    name: &'static str,
    namespace: Fr,
    vk_hash: Fr,
    inputs: Vec<Fr>,
    user_nonce: Fr,
    old_commitments: Vec<Fr>,
    /// The pinned public read values, in `public_reads` order.
    reads: Vec<Fr>,
    key: &'static str,
    new_commitment: Fr,
    /// The stored vector in the clear, with the seed of each sharing.
    value: Vec<(Fr, u64)>,
    /// The slots of the keys the round reads, one per old commitment; it
    /// writes one, `key`.
    in_slots: Vec<Fr>,
    npk_app_hash: Fr,
    ok: bool,
    app_outputs: Vec<Fr>,
}

fn rounds() -> Vec<Round> {
    let namespace = hex("0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809");
    let vk_hash = hex("0x2a8f1c0e9b7d6a5f4e3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6");
    vec![
        // chain_request_id.json's first case (the amm_swap_tip request) with a
        // pool of two reserves
        Round {
            name: "n = 2: one chain-held output of two shared elements, one old commitment",
            namespace,
            vk_hash,
            inputs: vec![Fr::from(5000u64), Fr::from(0u64)],
            user_nonce: Fr::from(1u64),
            old_commitments: vec![hex(
                "0x2f00c0ffee000000000000000000000000000000000000000000000000000001",
            )],
            reads: vec![],
            key: "0xa002",
            new_commitment: hex(
                "0x2f00c0ffee000000000000000000000000000000000000000000000000000002",
            ),
            value: vec![(Fr::from(1_000_000u64), 40), (Fr::from(2_000_000u64), 41)],
            // amm_swap_tip's shape: the pool read and written, two app
            // outputs (code, amount_out)
            in_slots: vec![Fr::from(0xa002u64)],
            npk_app_hash: hex("0x2e8507de00eae98d7d6eba0603074b7b18a966500f3af64da28810924a21adf2"),
            ok: true,
            app_outputs: vec![Fr::from(0u64), Fr::from(33450u64)],
        },
        // chain_request_id.json's second case (its pinned read, a price),
        // with the field's end values
        Round {
            name: "n = 3: one chain-held output of three shared elements (7, p - 1, 0), two old commitments, one pinned read",
            namespace,
            vk_hash,
            inputs: vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
            user_nonce: Fr::from(0xfeedu64),
            old_commitments: vec![Fr::from(0xaaaau64), Fr::from(0xbbbbu64)],
            reads: vec![Fr::from(2000u64)],
            key: "0xa003",
            new_commitment: Fr::from(0xccccu64),
            value: vec![
                (Fr::from(7u64), 42),
                (-Fr::from(1u64), 43),
                (Fr::from(0u64), 44),
            ],
            in_slots: vec![Fr::from(0xa003u64), Fr::from(0xa004u64)],
            npk_app_hash: Fr::from(0x9bu64),
            ok: true,
            app_outputs: vec![Fr::from(0u64), Fr::from(7u64), -Fr::from(1u64)],
        },
    ]
}

/// A public-input array with the index of each named part, built part by
/// part in a layout's order.
#[derive(Default)]
struct Layout {
    fields: Vec<Fr>,
    at: serde_json::Map<String, Value>,
}

impl Layout {
    fn one(mut self, name: &str, v: Fr) -> Self {
        self.at.insert(name.into(), json!(self.fields.len()));
        self.fields.push(v);
        self
    }

    fn many(mut self, name: &str, vs: &[Fr]) -> Self {
        let from = self.fields.len();
        self.at.insert(
            name.into(),
            json!((from..from + vs.len()).collect::<Vec<_>>()),
        );
        self.fields.extend_from_slice(vs);
        self
    }

    /// `{"public_inputs": [...], "layout": {part: index or indices}}`.
    fn json(self) -> (Value, Value) {
        (json!(fhs(&self.fields)), Value::Object(self.at))
    }
}

/// The non-secret-shared public-input layout, pss_public_contract's
/// `proved_public_inputs`: the public parameters `[namespace, vk_hash,
/// in_slots[R], out_slots[W], reads[Q]]`, then the return value
/// `[request_id, old_commitments[R], new_commitments[W], npk_app_hash, ok,
/// app_outputs[A]]`.
#[allow(clippy::too_many_arguments)]
fn plain_layout(
    namespace: Fr,
    vk_hash: Fr,
    in_slots: &[Fr],
    out_slots: &[Fr],
    reads: &[Fr],
    request_id: Fr,
    old_commitments: &[Fr],
    new_commitments: &[Fr],
    npk_app_hash: Fr,
    ok: bool,
    app_outputs: &[Fr],
) -> Layout {
    Layout::default()
        .one("namespace", namespace)
        .one("vk_hash", vk_hash)
        .many("in_slots", in_slots)
        .many("out_slots", out_slots)
        .many("reads", reads)
        .one("request_id", request_id)
        .many("old_commitments", old_commitments)
        .many("new_commitments", new_commitments)
        .one("npk_app_hash", npk_app_hash)
        .one("ok", Fr::from(ok as u64))
        .many("app_outputs", app_outputs)
}

/// One init round: the round that creates a namespace's keys, with no
/// queue entry, no key read and no pinned read (pss_public_contract
/// init.nr).
struct InitRound {
    name: &'static str,
    namespace: Fr,
    vk_hash: Fr,
    /// The init constants, the init circuit's app inputs.
    inputs: Vec<Fr>,
    out_slots: Vec<Fr>,
    new_commitments: Vec<Fr>,
    npk_app_hash: Fr,
    /// A tree-valued key's new leaf hashes, none for slot keys.
    new_hashes: Vec<Fr>,
}

fn init_rounds() -> Vec<InitRound> {
    let namespace = hex("0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809");
    vec![
        InitRound {
            name: "amm_init_tip's shape: one slot key created, no init inputs, no new leaf hashes",
            namespace,
            vk_hash: Fr::from(0x1417u64),
            inputs: vec![],
            out_slots: vec![Fr::from(0xa002u64)],
            new_commitments: vec![hex(
                "0x216c4005a3578abf5f829fbf121dc857749f82d555c519c24b4984c7c7b7a399",
            )],
            npk_app_hash: Fr::from(0x9bu64),
            new_hashes: vec![],
        },
        InitRound {
            name: "lending_init's shape: one tree-valued key created, one init input, its header's new leaf hash",
            namespace,
            vk_hash: Fr::from(0x1418u64),
            inputs: vec![Fr::from(1_000_000u64)],
            out_slots: vec![Fr::from(0x30u64)],
            new_commitments: vec![Fr::from(0xc1u64)],
            npk_app_hash: Fr::from(0x9bu64),
            new_hashes: vec![Fr::from(0x1eafu64)],
        },
    ]
}

/// The init public-input layout, pss_public_contract's `init_public_inputs`:
/// `[namespace, vk_hash, out_slots[W], request_id, 0 (W times),
/// new_commitments[W], npk_app_hash, new_hashes[H]]`, the request id the
/// init chain request id (user_nonce 0).
fn init_round_json(r: &InitRound) -> Value {
    let chain = chain_request_id(r.namespace, r.vk_hash, &r.inputs, Fr::from(0u64));
    let empty = vec![Fr::from(0u64); r.out_slots.len()];
    let (public_inputs, layout) = Layout::default()
        .one("namespace", r.namespace)
        .one("vk_hash", r.vk_hash)
        .many("out_slots", &r.out_slots)
        .one("request_id", chain)
        .many("old_commitments", &empty)
        .many("new_commitments", &r.new_commitments)
        .one("npk_app_hash", r.npk_app_hash)
        .many("new_hashes", &r.new_hashes)
        .json();
    json!({
        "name": r.name,
        "namespace": fh(r.namespace),
        "vk_hash": fh(r.vk_hash),
        "inputs": fhs(&r.inputs),
        "chain_request_id": fh(chain),
        "machine_request_id": fh(machine_request_id(chain, &empty, &[])),
        "out_slots": fhs(&r.out_slots),
        "new_commitments": fhs(&r.new_commitments),
        "npk_app_hash": fh(r.npk_app_hash),
        "new_hashes": fhs(&r.new_hashes),
        "public_inputs": public_inputs,
        "layout": layout,
    })
}

fn round_json(keys: &[NodeKeys], r: &Round) -> Value {
    let ih = inputs_hash(&r.inputs);
    let chain = chain_request_id(r.namespace, r.vk_hash, &r.inputs, r.user_nonce);
    let machine = machine_request_id(chain, &r.old_commitments, &r.reads);
    let new_commitments = vec![r.new_commitment];
    let n = r.value.len();

    let mut thirds_c: Vec<Vec<u8>> = Vec::new();
    let thirds: Vec<Value> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let elems: Vec<Elem> = r
                .value
                .iter()
                .map(|(x, seed)| {
                    let s = sharing(*x, *seed);
                    Elem::Shared(Share::new(s[i], s[(i + 2) % 3]))
                })
                .collect();
            let owner = k.enc_pk();
            let mut plaintext = vec![r.namespace, key_hash(r.key), r.new_commitment];
            plaintext.extend(encode_elements(&elems));
            let nonce = associated_data(r.namespace, r.key, r.new_commitment, owner);
            let (ct, tag) = sidecar_core::ae::encrypt(k.seal_key(), nonce, &plaintext);
            let c = record::seal(k, r.namespace, r.key, r.new_commitment, owner, &elems);
            assert_eq!(
                record::open_own(k, r.namespace, r.key, r.new_commitment, &c).unwrap(),
                elems
            );
            let fields = third_fields(&c).unwrap();
            assert_eq!(fields.len(), third_fields_len(n));
            assert_eq!(fields[1..fields.len() - 1], ct[..]);
            thirds_c.push(c.clone());
            json!({
                "node": i,
                "owner": point_to_wire(owner),
                "elements": elems.iter().map(|e| match e {
                    Elem::Shared(s) => json!([fh(s.a), fh(s.b)]),
                    _ => unreachable!("every element here is shared"),
                }).collect::<Vec<_>>(),
                "plaintext": fhs(&plaintext),
                "nonce": fh(nonce),
                "ciphertext": fhs(&ct),
                "tag": fh(tag),
                "c": HexBytes(c.clone()).to_string(),
                "fields": fhs(&fields),
                "record_hash": fh(record_hash(&c).unwrap()),
            })
        })
        .collect();

    let nodes: Vec<Value> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let hashes = vec![record_hash(&thirds_c[i]).unwrap()];
            let sealed = sealed_hash(&hashes);
            let message =
                result_message(r.namespace, RequestId(machine), &new_commitments, i, sealed);
            let mut preimage = vec![Fr::from(RESULT_DOMAIN), r.namespace, machine];
            preimage.extend(&new_commitments);
            preimage.extend([Fr::from(i as u64), sealed]);
            assert_eq!(message, poseidon2_hash(&preimage));
            let signature = result_signature(k, message);
            assert!(verify(k.sig_pk(), signature, message));
            json!({
                "node": i,
                "sig_pk": point_to_wire(k.sig_pk()),
                "record_hashes": fhs(&hashes),
                "sealed_hash": fh(sealed),
                "message_preimage": fhs(&preimage),
                "message": fh(message),
                "signature": signature,
            })
        })
        .collect();

    let thirds_arr: [Vec<u8>; 3] = thirds_c.clone().try_into().unwrap();
    let log = SealedLog {
        new_commitments: new_commitments.clone(),
        thirds: vec![thirds_arr],
    };
    let body = log.to_fields().unwrap();
    assert_eq!(SealedLog::from_fields(&body, 1, 1).unwrap(), log);
    let size = sealed_thirds_fields(n);
    assert_eq!(body.len(), new_commitments.len() + size);
    let log_fields = apply_log_fields(new_commitments.len(), [n]);
    assert_eq!(log_fields, 1 + body.len(), "the tag, then the body");
    let out_slots = vec![hex(r.key)];
    let (public_inputs, layout) = plain_layout(
        r.namespace,
        r.vk_hash,
        &r.in_slots,
        &out_slots,
        &r.reads,
        chain,
        &r.old_commitments,
        &new_commitments,
        r.npk_app_hash,
        r.ok,
        &r.app_outputs,
    )
    .json();

    json!({
        "name": r.name,
        "namespace": fh(r.namespace),
        "vk_hash": fh(r.vk_hash),
        "inputs": fhs(&r.inputs),
        "inputs_hash": fh(ih),
        "user_nonce": fh(r.user_nonce),
        "chain_request_id": fh(chain),
        "old_commitments": fhs(&r.old_commitments),
        "reads": fhs(&r.reads),
        "machine_request_id": fh(machine),
        "key": r.key,
        "key_hash": fh(key_hash(r.key)),
        "len": n,
        "value": r.value.iter().map(|(x, _)| json!({"shared": fh(*x)})).collect::<Vec<_>>(),
        "new_commitments": fhs(&new_commitments),
        "in_slots": fhs(&r.in_slots),
        "out_slots": fhs(&out_slots),
        "npk_app_hash": fh(r.npk_app_hash),
        "ok": r.ok,
        "app_outputs": fhs(&r.app_outputs),
        "public_inputs": public_inputs,
        "layout": layout,
        "thirds": thirds,
        "nodes": nodes,
        "sealed_log": {
            "tag": fh(sealed_log_tag(chain)),
            "writes": new_commitments.len(),
            "chain_outputs": 1,
            "third_len": third_fields_len(n),
            "body": fhs(&body),
        },
        "register": {
            "len": n,
            "chain_outputs": 1,
            "writes": new_commitments.len(),
            "sealed_thirds_fields": size,
            "log_fields": log_fields,
            "accepted": log_fields <= MAX_PUBLIC_LOG_SIZE_IN_FIELDS,
        },
    })
}

/// testvectors/tip_results.json.
fn tip_results() -> Value {
    let keys = node_keys();
    // (len, chain-held outputs of that len, each a written key): one output
    // at the bound and one element over; three outputs of 449 elements in all
    // and of 450, whose thirds alone (4,095) would pass under 4,096
    let bound_cases: Vec<Value> = [(453usize, 1usize), (454, 1), (149, 3), (150, 3)]
        .iter()
        .map(|&(len, t)| {
            let size = t * sealed_thirds_fields(len);
            let log_fields = apply_log_fields(t, vec![len; t]);
            json!({
                "len": len,
                "chain_outputs": t,
                "writes": t,
                "sealed_thirds_fields": size,
                "log_fields": log_fields,
                "accepted": log_fields <= MAX_PUBLIC_LOG_SIZE_IN_FIELDS,
            })
        })
        .collect();
    json!({
        "description": "Two chain-held result rounds of the tip, as a node signs them (sidecar-core pipeline steps 13 and 14 with state mode chain), process_result rebuilds and verifies them (noir/pss_public_contract result.nr) and apply logs them, each with its public-input array; and two init rounds' public-input arrays. Written by sidecar-tip tests/write_vectors; read by sidecar-tip's own tests (the machine's readers of both layouts), sidecar-core tests/vectors.rs, pss-client test/vectors.test.ts and testvectors/noir/tip_result_vectors.",
        "rules": {
            "ids": "inputs_hash = poseidon2(inputs); chain_request_id = poseidon2([namespace, vk_hash, inputs_hash, user_nonce]); machine_request_id = poseidon2([PSS_ATTEMPT, chain_request_id, old_commitments..., reads...]), reads the pinned public read values in public_reads order (chain_request_id.json)",
            "thirds": "node i's third of the round's one chain-held output, sealed for node i itself: owner = node i's enc_pk, key the request key string, note_hash the output's new commitment; plaintext, nonce, ciphertext, tag and c as in records.json, under K_i of keys.json; fields = [key id as an integer, ciphertext..., tag], the form process_result's sealed argument and the log carry; record_hash = poseidon2(fields)",
            "sealed_hash": "H(sealed_i) = poseidon2([record_hash of node i's third]), a one-element list: one chain-held output",
            "message": "poseidon2([RESULT_DOMAIN, namespace, machine_request_id, new_commitments..., i, H(sealed_i)]); the signed request id is the machine request id, not the chain request id",
            "signature": "Schnorr over Grumpkin (noir-lang/schnorr v0.4.0) by node i's sig key of keys.json, {s: [lo, hi], e: [lo, hi]}; nonce derived as in results.json (label \"sidecar.result_nonce\")",
            "sealed_log": "the log apply emits: tag = compute_log_tag(chain_request_id, PSS_STATE); body = new_commitments[0..W] then sealed[0][0..T], sealed[1][0..T], sealed[2][0..T] (node by node, output by output), each third its L = 3·len + 5 fields; here W = T = 1, so 1 + 3L fields after the tag (sidecar-tip chain_state::SealedLog)",
            "register": "REGISTER's chain-held size bound (sidecar-tip chain_state::apply_log_fields): the sealed-thirds log of one apply, log_fields = 1 (tag) + writes (new commitments) + sealed_thirds_fields, where an output of len elements takes 9·len + 15 = 3 · (3·len + 5) fields of thirds (chain_state::sealed_thirds_fields), summed over the chain_outputs; accepted when log_fields is at most public_log.max_log_fields",
            "public_inputs": "a round's public-input array in the non-secret-shared layout, pss_public_contract result.nr proved_public_inputs: [namespace, vk_hash, in_slots[R], out_slots[W], reads[Q], request_id, old_commitments[R], new_commitments[W], npk_app_hash, ok, app_outputs[A]], request_id the chain request id; layout gives each part's index (or indices); rounds[0] has amm_swap_tip's shape (R = W = 1, Q = 0, A = 2)",
            "init_public_inputs": "an init round's public-input array, pss_public_contract init.nr init_public_inputs: [namespace, vk_hash, out_slots[W], request_id, 0 (W times), new_commitments[W], npk_app_hash, new_hashes[H]], request_id the init chain request id chain_request_id(namespace, vk_hash, inputs, 0) and the machine request id over W old commitments of 0; init_rounds[0] has amm_init_tip's shape, init_rounds[1] lending_init's",
            "public_log": "Aztec v6 protocol types constants.nr: every public log of a transaction, behind its header of header_fields (length, contract address), shares one payload of payload_fields (FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH, PUBLIC_LOG_HEADER_LENGTH), so one log carries at most max_log_fields = payload_fields - header_fields (MAX_PUBLIC_LOG_SIZE_IN_FIELDS)",
        },
        "result_domain": fh(Fr::from(RESULT_DOMAIN)),
        "pss_attempt": fh(Fr::from(PSS_ATTEMPT)),
        "pss_state": PSS_STATE,
        "public_log": {
            "payload_fields": FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH,
            "header_fields": PUBLIC_LOG_HEADER_LENGTH,
            "max_log_fields": MAX_PUBLIC_LOG_SIZE_IN_FIELDS,
        },
        "register_bound": bound_cases,
        "rounds": rounds().iter().map(|r| round_json(&keys, r)).collect::<Vec<_>>(),
        "init_rounds": init_rounds().iter().map(init_round_json).collect::<Vec<_>>(),
    })
}

// ---- the slot commitment ----

/// The slot commitment of one chain-held key, pss_core's
/// `tip::slot::commitment`: `poseidon2([TIP_STATE_SEP, namespace, slot,
/// fields..., blinding])`, TIP_STATE_SEP = ASCII "pss.tip.state".
fn slot_commitment(namespace: Fr, slot: Fr, fields: &[Fr], blinding: Fr) -> Fr {
    let mut preimage = vec![label_field(b"pss.tip.state"), namespace, slot];
    preimage.extend_from_slice(fields);
    preimage.push(blinding);
    poseidon2_hash(&preimage)
}

/// testvectors/slot_commitment.json: preimages of 5 to 9 elements (the
/// separator included), so the sponge's last block is full, one short and
/// two short.
fn slot_commitments() -> Value {
    let p_minus_1 = Fr::from(0u64) - Fr::from(1u64);
    let n = |v: u64| Fr::from(v);
    let cases: [(&str, Fr, Fr, Vec<Fr>, Fr); 4] = [
        (
            "amm-tip fixture: the pool Pool::from_seed(111) under blinding 333 (amm_init_tip's Prover.toml new_c)",
            n(0xc0ffee),
            n(0xa002),
            vec![n(1359373), n(1852331)],
            n(333),
        ),
        ("one field", n(0xc0ffee), n(0xa003), vec![n(7)], n(9)),
        (
            "three fields",
            hex("0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"),
            n(0x1234),
            vec![n(1), n(2), n(3)],
            n(0xfeed),
        ),
        (
            "five fields, field-sized values (p - 1) in every position",
            p_minus_1,
            p_minus_1,
            vec![p_minus_1; 5],
            p_minus_1,
        ),
    ];
    let vectors: Vec<Value> = cases
        .iter()
        .map(|(name, ns, slot, fields, blinding)| {
            json!({
                "name": name,
                "namespace": fh(*ns),
                "slot": fh(*slot),
                "fields": fhs(fields),
                "blinding": fh(*blinding),
                "commitment": fh(slot_commitment(*ns, *slot, fields, *blinding)),
            })
        })
        .collect();
    json!({
        "description": "The slot commitment of a chain-held tip key: what its contract slot holds, the old_c and new_c a round outputs. Written by sidecar-tip tests/write_vectors; read by sidecar-core tests/vectors.rs, pss-client test/vectors.test.ts and testvectors/noir/tip_round_vectors (pss_core tip::slot::commitment).",
        "rule": "commitment = poseidon2([TIP_STATE_SEP, namespace, slot, fields..., blinding]) (total-noir p2_hash_sep([namespace, slot, fields..., blinding], TIP_STATE_SEP)); namespace the app contract's address, slot the key's storage slot, fields the stored vector before its blinding",
        "hash": "poseidon2 is the width-4 sponge of docs/ARCHITECTURE.md section 1 (IV len << 64 in the capacity element; Noir std Poseidon2::hash, protocol_types poseidon2_hash, total-noir p2_hash, aztec.js poseidon2Hash)",
        "tip_state_sep": fh(label_field(b"pss.tip.state")),
        "vectors": vectors,
    })
}

// ---- the Noir programs' Prover.toml ----

fn s(v: &Value) -> String {
    format!(
        "\"{}\"",
        v.as_str().unwrap_or_else(|| panic!("{v} is not a string"))
    )
}

fn list(v: &Value) -> String {
    let items: Vec<String> = v.as_array().unwrap().iter().map(s).collect();
    format!("[{}]", items.join(", "))
}

// `name = [..]`, or nothing for an empty list: a Noir entry point takes no
// zero-length array, so the program passes `[]` itself for such a case.
fn list_entry(out: &mut String, name: &str, v: &Value) {
    if !v.as_array().unwrap().is_empty() {
        writeln!(out, "{name} = {}", list(v)).unwrap();
    }
}

// A wire signature {s: [lo, hi], e: [lo, hi]} as the four limbs
// [s.lo, s.hi, e.lo, e.hi] (pss_public_contract's ResultSignature).
fn limbs(sig: &Value) -> String {
    format!(
        "[{}, {}, {}, {}]",
        s(&sig["s"][0]),
        s(&sig["s"][1]),
        s(&sig["e"][0]),
        s(&sig["e"][1])
    )
}

fn sig_keys(out: &mut String) {
    for n in read("testvectors/keys.json")["nodes"].as_array().unwrap() {
        writeln!(out, "\n[[sig_keys]]").unwrap();
        writeln!(
            out,
            "x = {}\ny = {}",
            s(&n["sig_pk"]["x"]),
            s(&n["sig_pk"]["y"])
        )
        .unwrap();
    }
}

/// Prover.toml of testvectors/noir/tip_intake_vectors.
fn intake_prover_toml() -> String {
    let ids = read("testvectors/chain_request_id.json");
    let receipts = read("testvectors/receipts.json");
    let tags = read("testvectors/log_tags.json");
    let mut out = String::from(
        "# Written by sidecar-tip tests/write_vectors (write_tip_vectors) from testvectors/chain_request_id.json, receipts.json, log_tags.json, queue.json, shared_intake.json and keys.json.\n",
    );
    writeln!(out, "pss_attempt = {}", s(&ids["pss_attempt"])).unwrap();
    writeln!(out, "receipt_domain = {}", s(&receipts["receipt_domain"])).unwrap();
    writeln!(out, "request_domain = {}", tags["request_domain"]).unwrap();
    writeln!(out, "pss_state = {}", tags["pss_state"]).unwrap();
    let done = &read("testvectors/queue.json")["done"];
    writeln!(
        out,
        "done_codes = [{}, {}, {}]",
        done["pending"], done["applied"], done["skipped"]
    )
    .unwrap();
    // a case's pinned reads sit at the top level as `ids{k}_pinned_reads`
    // (only where there are some), beside the case's table
    for (k, v) in ids["vectors"].as_array().unwrap().iter().enumerate() {
        list_entry(
            &mut out,
            &format!("ids{k}_pinned_reads"),
            &v["pinned_reads"],
        );
    }
    sig_keys(&mut out);
    for (k, v) in ids["vectors"].as_array().unwrap().iter().enumerate() {
        writeln!(out, "\n# {}\n[ids{k}]", v["name"].as_str().unwrap()).unwrap();
        for f in ["namespace", "vk_hash"] {
            writeln!(out, "{f} = {}", s(&v[f])).unwrap();
        }
        list_entry(&mut out, "inputs", &v["inputs"]);
        for f in ["inputs_hash", "user_nonce", "chain_request_id"] {
            writeln!(out, "{f} = {}", s(&v[f])).unwrap();
        }
        list_entry(&mut out, "old_commitments", &v["old_commitments"]);
        writeln!(out, "machine_request_id = {}", s(&v["machine_request_id"])).unwrap();
        writeln!(out, "request_log = {}", list(&v["request_log"])).unwrap();
    }
    for (k, v) in receipts["vectors"].as_array().unwrap().iter().enumerate() {
        writeln!(out, "\n# {}\n[receipt{k}]", v["name"].as_str().unwrap()).unwrap();
        for f in ["namespace", "vk_hash"] {
            writeln!(out, "{f} = {}", s(&v[f])).unwrap();
        }
        writeln!(out, "inputs = {}", list(&v["inputs"])).unwrap();
        for f in ["inputs_hash", "user_nonce", "request_id"] {
            writeln!(out, "{f} = {}", s(&v[f])).unwrap();
        }
        writeln!(out, "expiry_block = {}", v["expiry_block"]).unwrap();
        writeln!(out, "message_preimage = {}", list(&v["message_preimage"])).unwrap();
        writeln!(out, "message = {}", s(&v["message"])).unwrap();
        let sigs: Vec<String> = v["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(limbs)
            .collect();
        writeln!(out, "signatures = [{}]", sigs.join(", ")).unwrap();
    }
    for v in tags["vectors"].as_array().unwrap() {
        writeln!(out, "\n[[tags]]").unwrap();
        for f in ["chain_request_id", "request_tag", "sealed_tag"] {
            writeln!(out, "{f} = {}", s(&v[f])).unwrap();
        }
    }
    let queue = read("testvectors/queue.json");
    for v in queue["vectors"].as_array().unwrap() {
        writeln!(out, "\n# {}\n[[queue]]", v["name"].as_str().unwrap()).unwrap();
        for f in ["base", "tail", "head_index", "head_since"] {
            writeln!(out, "{f} = {}", s(&v[f])).unwrap();
        }
        let column = |list: &str, f: &str| -> String {
            let items: Vec<String> = v[list]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| s(&e[f]))
                .collect();
            format!("[{}]", items.join(", "))
        };
        writeln!(out, "request_indices = {}", column("requests", "index")).unwrap();
        writeln!(out, "request_slots = {}", column("requests", "slot")).unwrap();
        writeln!(out, "seen_ids = {}", column("seen", "request_id")).unwrap();
        writeln!(out, "seen_slots = {}", column("seen", "slot")).unwrap();
        writeln!(out, "done_indices = {}", column("done", "index")).unwrap();
        writeln!(out, "done_slots = {}", column("done", "slot")).unwrap();
    }
    let shared = read(SHARED_INTAKE);
    shared_entries(&mut out, "shared", &shared);
    let receipt = &shared["receipt"];
    writeln!(out, "expiry_block = {}", receipt["expiry_block"]).unwrap();
    writeln!(
        out,
        "message_preimage = {}",
        list(&receipt["message_preimage"])
    )
    .unwrap();
    writeln!(out, "message = {}", s(&receipt["message"])).unwrap();
    let sigs: Vec<String> = receipt["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(limbs)
        .collect();
    writeln!(out, "signatures = [{}]", sigs.join(", ")).unwrap();
    let summands: Vec<String> = shared["summands"]
        .as_array()
        .unwrap()
        .iter()
        .map(list)
        .collect();
    writeln!(out, "summands = [{}]", summands.join(", ")).unwrap();
    writeln!(out, "salts = {}", list(&shared["salts"])).unwrap();
    writeln!(out, "value_kinds = {}", list(&shared["value_kinds"])).unwrap();
    writeln!(out, "sharing_digest = {}", s(&shared["sharing_digest"])).unwrap();
    out
}

// The `[name]` table of shared_intake.json's commitment: the namespace, the
// vk hash, C's values and blinding, C and the chain request id.
fn shared_entries(out: &mut String, name: &str, shared: &Value) {
    writeln!(
        out,
        "\n# secret-shared receipt intake: C and the chain request id\n[{name}]"
    )
    .unwrap();
    for f in ["namespace", "vk_hash"] {
        writeln!(out, "{f} = {}", s(&shared[f])).unwrap();
    }
    writeln!(
        out,
        "commitment_values = {}",
        list(&shared["commitment_values"])
    )
    .unwrap();
    for f in ["blinding", "inputs_commitment", "chain_request_id"] {
        writeln!(out, "{f} = {}", s(&shared[f])).unwrap();
    }
}

/// Prover.toml of testvectors/noir/tip_round_vectors.
fn round_prover_toml(slots: &Value) -> String {
    let ids = read("testvectors/chain_request_id.json");
    let mut out = String::from(
        "# Written by sidecar-tip tests/write_vectors (write_tip_vectors) from testvectors/slot_commitment.json, chain_request_id.json and shared_intake.json.\n",
    );
    writeln!(out, "tip_state_sep = {}", s(&slots["tip_state_sep"])).unwrap();
    for (k, v) in slots["vectors"].as_array().unwrap().iter().enumerate() {
        writeln!(out, "\n# {}\n[slot{k}]", v["name"].as_str().unwrap()).unwrap();
        for f in ["namespace", "slot"] {
            writeln!(out, "{f} = {}", s(&v[f])).unwrap();
        }
        writeln!(out, "fields = {}", list(&v["fields"])).unwrap();
        for f in ["blinding", "commitment"] {
            writeln!(out, "{f} = {}", s(&v[f])).unwrap();
        }
    }
    for (k, v) in ids["vectors"].as_array().unwrap().iter().enumerate() {
        writeln!(out, "\n# {}\n[ids{k}]", v["name"].as_str().unwrap()).unwrap();
        for f in ["namespace", "vk_hash"] {
            writeln!(out, "{f} = {}", s(&v[f])).unwrap();
        }
        list_entry(&mut out, "inputs", &v["inputs"]);
        for f in ["inputs_hash", "user_nonce", "chain_request_id"] {
            writeln!(out, "{f} = {}", s(&v[f])).unwrap();
        }
    }
    shared_entries(&mut out, "shared_intake", &read(SHARED_INTAKE));
    out
}

/// Prover.toml of testvectors/noir/tip_result_vectors.
fn result_prover_toml(file: &Value) -> String {
    let results = read("testvectors/results.json");
    let mut out = String::from(
        "# Written by sidecar-tip tests/write_vectors (write_tip_vectors) from testvectors/tip_results.json, results.json and keys.json.\n",
    );
    writeln!(out, "result_domain = {}", s(&file["result_domain"])).unwrap();
    writeln!(out, "pss_attempt = {}", s(&file["pss_attempt"])).unwrap();
    writeln!(out, "pss_state = {}", file["pss_state"]).unwrap();
    // a round's pinned reads sit at the top level as `round{k}_reads` (only
    // where there are some), beside the round's table
    for (k, r) in file["rounds"].as_array().unwrap().iter().enumerate() {
        list_entry(&mut out, &format!("round{k}_reads"), &r["reads"]);
    }
    // likewise an init round's inputs and new leaf hashes, `init{k}_inputs`
    // and `init{k}_new_hashes`
    for (k, r) in file["init_rounds"].as_array().unwrap().iter().enumerate() {
        list_entry(&mut out, &format!("init{k}_inputs"), &r["inputs"]);
        list_entry(&mut out, &format!("init{k}_new_hashes"), &r["new_hashes"]);
    }
    // results.json: the namespace, and each case's record hashes per node
    // at the top level as `results{k}_record_hashes` (only where there are
    // some: the node-held case has none)
    writeln!(out, "results_namespace = {}", s(&results["namespace"])).unwrap();
    let cases = results["cases"].as_array().unwrap();
    for (k, c) in cases.iter().enumerate() {
        let nodes = c["nodes"].as_array().unwrap();
        if !nodes[0]["record_hashes"].as_array().unwrap().is_empty() {
            let per_node: Vec<String> = nodes.iter().map(|n| list(&n["record_hashes"])).collect();
            writeln!(out, "results{k}_record_hashes = [{}]", per_node.join(", ")).unwrap();
        }
    }
    sig_keys(&mut out);
    let public_log = &file["public_log"];
    writeln!(out, "\n[public_log]").unwrap();
    for f in ["payload_fields", "header_fields", "max_log_fields"] {
        writeln!(out, "{f} = {}", public_log[f]).unwrap();
    }
    for (k, r) in file["rounds"].as_array().unwrap().iter().enumerate() {
        writeln!(out, "\n# {}\n[round{k}]", r["name"].as_str().unwrap()).unwrap();
        for f in ["namespace", "vk_hash"] {
            writeln!(out, "{f} = {}", s(&r[f])).unwrap();
        }
        writeln!(out, "inputs = {}", list(&r["inputs"])).unwrap();
        for f in ["inputs_hash", "user_nonce", "chain_request_id"] {
            writeln!(out, "{f} = {}", s(&r[f])).unwrap();
        }
        writeln!(out, "old_commitments = {}", list(&r["old_commitments"])).unwrap();
        writeln!(out, "machine_request_id = {}", s(&r["machine_request_id"])).unwrap();
        writeln!(out, "new_commitments = {}", list(&r["new_commitments"])).unwrap();
        writeln!(out, "len = {}", r["len"]).unwrap();
        let thirds = r["thirds"].as_array().unwrap();
        let sealed: Vec<String> = thirds
            .iter()
            .map(|t| format!("[{}]", list(&t["fields"])))
            .collect();
        writeln!(out, "sealed = [{}]", sealed.join(", ")).unwrap();
        let ids: Vec<String> = thirds.iter().map(|t| s(&t["fields"][0])).collect();
        writeln!(out, "key_ids = [{}]", ids.join(", ")).unwrap();
        let nodes = r["nodes"].as_array().unwrap();
        let pick = |f: &str| -> String {
            let v: Vec<String> = nodes.iter().map(|n| s(&n[f])).collect();
            format!("[{}]", v.join(", "))
        };
        let record_hashes: Vec<String> = nodes.iter().map(|n| s(&n["record_hashes"][0])).collect();
        writeln!(out, "record_hashes = [{}]", record_hashes.join(", ")).unwrap();
        writeln!(out, "sealed_hashes = {}", pick("sealed_hash")).unwrap();
        writeln!(out, "messages = {}", pick("message")).unwrap();
        let sigs: Vec<String> = nodes.iter().map(|n| limbs(&n["signature"])).collect();
        writeln!(out, "signatures = [{}]", sigs.join(", ")).unwrap();
        let log = &r["sealed_log"];
        writeln!(out, "log_tag = {}", s(&log["tag"])).unwrap();
        writeln!(out, "third_len = {}", log["third_len"]).unwrap();
        writeln!(out, "log_body = {}", list(&log["body"])).unwrap();
        writeln!(
            out,
            "register_fields = {}",
            r["register"]["sealed_thirds_fields"]
        )
        .unwrap();
        writeln!(out, "register_log_fields = {}", r["register"]["log_fields"]).unwrap();
        writeln!(out, "register_accepted = {}", r["register"]["accepted"]).unwrap();
        for f in ["in_slots", "out_slots"] {
            writeln!(out, "{f} = {}", list(&r[f])).unwrap();
        }
        writeln!(out, "npk_app_hash = {}", s(&r["npk_app_hash"])).unwrap();
        writeln!(out, "ok = {}", r["ok"]).unwrap();
        for f in ["app_outputs", "public_inputs"] {
            writeln!(out, "{f} = {}", list(&r[f])).unwrap();
        }
    }
    for (k, r) in file["init_rounds"].as_array().unwrap().iter().enumerate() {
        writeln!(out, "\n# {}\n[init{k}]", r["name"].as_str().unwrap()).unwrap();
        for f in [
            "namespace",
            "vk_hash",
            "chain_request_id",
            "machine_request_id",
            "npk_app_hash",
        ] {
            writeln!(out, "{f} = {}", s(&r[f])).unwrap();
        }
        for f in ["out_slots", "new_commitments", "public_inputs"] {
            writeln!(out, "{f} = {}", list(&r[f])).unwrap();
        }
    }
    for (k, c) in cases.iter().enumerate() {
        writeln!(out, "\n# {}\n[results{k}]", c["name"].as_str().unwrap()).unwrap();
        writeln!(out, "request_id = {}", s(&c["request_id"])).unwrap();
        writeln!(out, "commitments = {}", list(&c["commitments"])).unwrap();
        let nodes = c["nodes"].as_array().unwrap();
        let pick = |f: &str| -> String {
            let v: Vec<String> = nodes.iter().map(|n| s(&n[f])).collect();
            format!("[{}]", v.join(", "))
        };
        writeln!(out, "sealed_hashes = {}", pick("sealed_hash")).unwrap();
        writeln!(out, "messages = {}", pick("message")).unwrap();
        let sigs: Vec<String> = nodes.iter().map(|n| limbs(&n["signature"])).collect();
        writeln!(out, "signatures = [{}]", sigs.join(", ")).unwrap();
    }
    for b in file["register_bound"].as_array().unwrap() {
        writeln!(out, "\n[[register_bound]]").unwrap();
        for f in [
            "len",
            "chain_outputs",
            "writes",
            "sealed_thirds_fields",
            "log_fields",
            "accepted",
        ] {
            writeln!(out, "{f} = {}", b[f]).unwrap();
        }
    }
    out
}

fn read_text(path: &str) -> String {
    std::fs::read_to_string(repo().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The committed tip_results.json and both Prover.toml files are what this
/// code computes, and the file's rounds run chain_request_id.json's first two
/// requests, each signed over its machine request id with the round's pinned
/// values (tests/vectors.rs checks the rest of the file against the crates).
#[test]
fn tip_vector_files_match() {
    let committed = read(TIP_RESULTS);
    assert_eq!(committed, tip_results(), "rerun write_tip_vectors");
    assert_eq!(
        read_text(&format!("{RESULT_NOIR}/Prover.toml")),
        result_prover_toml(&committed),
        "rerun write_tip_vectors"
    );
    assert_eq!(
        read_text(&format!("{INTAKE_NOIR}/Prover.toml")),
        intake_prover_toml(),
        "rerun write_tip_vectors (after the ids or receipt writer)"
    );

    let keys = node_keys();
    let rounds = committed["rounds"].as_array().unwrap();
    assert_eq!(
        rounds
            .iter()
            .map(|r| r["len"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [2, 3]
    );
    let ids = read("testvectors/chain_request_id.json");
    for (k, r) in rounds.iter().enumerate() {
        // the rounds run chain_request_id.json's first two requests, at
        // their pinned values (none for the first, a price for the second)
        assert_eq!(r["chain_request_id"], ids["vectors"][k]["chain_request_id"]);
        assert_eq!(r["reads"], ids["vectors"][k]["pinned_reads"]);
        assert_eq!(
            r["machine_request_id"],
            ids["vectors"][k]["machine_request_id"]
        );
        let ns = hex(r["namespace"].as_str().unwrap());
        let list = |k: &str| -> Vec<Fr> {
            r[k].as_array()
                .unwrap()
                .iter()
                .map(|v| hex(v.as_str().unwrap()))
                .collect()
        };
        let reads = list("reads");
        if reads.is_empty() {
            continue;
        }
        // signed over the id with the round's pinned values, not without them
        let chain = hex(r["chain_request_id"].as_str().unwrap());
        let unpinned = machine_request_id(chain, &list("old_commitments"), &[]);
        let new_commitments = list("new_commitments");
        for (i, key) in keys.iter().enumerate() {
            let sig: Signature =
                serde_json::from_value(r["nodes"][i]["signature"].clone()).unwrap();
            let sealed = hex(r["nodes"][i]["sealed_hash"].as_str().unwrap());
            let over_unpinned =
                result_message(ns, RequestId(unpinned), &new_commitments, i, sealed);
            assert!(!verify(key.sig_pk(), sig, over_unpinned));
        }
    }
}

// The init ABI of examples/amm-tip/circuits/amm_init_tip, which
// examples/amm-tip/manifests/amm_init_tip.json fits: init.nr's layout with
// W = 1, no app inputs and no new leaf hashes.
const AMM_INIT_TIP_ABI: &str = r#"{
  "parameters": [
    {"name": "namespace", "type": {"kind": "field"}, "visibility": "public"},
    {"name": "vk_hash", "type": {"kind": "field"}, "visibility": "public"},
    {"name": "out_slots", "type": {"kind": "array", "length": 1, "type": {"kind": "field"}}, "visibility": "public"},
    {"name": "rand_seed", "type": {"kind": "field"}, "visibility": "private"},
    {"name": "r_new", "type": {"kind": "field"}, "visibility": "private"},
    {"name": "nsk_app", "type": {"kind": "field"}, "visibility": "private"}
  ],
  "return_type": {"abi_type": {"kind": "struct", "path": "InitTipOutputs", "fields": [
    {"name": "request_id", "type": {"kind": "field"}},
    {"name": "old_c", "type": {"kind": "field"}},
    {"name": "new_c", "type": {"kind": "field"}},
    {"name": "npk_app_hash", "type": {"kind": "field"}}
  ]}, "visibility": "public"},
  "error_types": {}
}"#;

fn layout_package(name: &str, abi: &str, manifest: Value, vk_hash: Fr) -> sidecar_tip::TipPackage {
    let row = PackageRow {
        name: name.into(),
        manifest_hash: Fr::from(0u64),
        circuit_json: serde_json::to_vec(
            &json!({"abi": serde_json::from_str::<Value>(abi).unwrap()}),
        )
        .unwrap(),
        manifest,
        vk: vec![],
        vk_hash,
        disabled: false,
        seq: 1,
    };
    sidecar_tip::TipPackage::from_row(&row, Some(50))
        .unwrap()
        .unwrap()
}

/// The machine's readers of the non-secret-shared and init public-input layouts take
/// each part back from tip_results.json's arrays at the index the circuit's
/// ABI gives it: rounds[0] under amm_swap_tip's package (the scheduler's and
/// the orchestrator's `old_commitments_of` and `reads_of`, from which the
/// machine request id is rederived), init_rounds[0] under amm_init_tip's
/// (`init_commitments` and the init chain request id the chain verifier
/// rebuilds).
#[test]
fn public_input_layouts_read_back() {
    let file = read(TIP_RESULTS);
    let fields = |v: &Value| -> Vec<Fr> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|x| hex(x.as_str().unwrap()))
            .collect()
    };
    let at = |v: &Value| v.as_u64().unwrap() as usize;
    let ats = |v: &Value| -> Vec<usize> { v.as_array().unwrap().iter().map(at).collect() };

    let r = &file["rounds"][0];
    let (layout, pi) = (&r["layout"], fields(&r["public_inputs"]));
    // the vector's round is the swap without a partial note (`outcome:
    // none`, pss_core's `Bound`): the circuit's app outputs are its
    // SwapOutputs struct, code then amount_out
    let abi = AMM_SWAP_TIP_ABI
        .replace(
            r#"{"name": "partial_note", "type": {"kind": "field"}, "visibility": "private"},"#,
            "",
        )
        .replace(
            r#"{"name": "partial_note", "type": {"kind": "field"}},"#,
            "",
        )
        .replace(
            r#"{"name": "code", "type": {"kind": "field"}},"#,
            r#"{"name": "app", "type": {"kind": "struct", "path": "amm_tip::tip::SwapOutputs",
            "fields": [{"name": "code", "type": {"kind": "field"}},"#,
        )
        .replace(
            r#"{"name": "amount_out", "type": {"kind": "field"}}"#,
            r#"{"name": "amount_out", "type": {"kind": "field"}}]}}"#,
        );
    let mut manifest: Value = serde_json::from_str(AMM_SWAP_TIP).unwrap();
    manifest["outcome"] = json!("none");
    manifest["witness"]
        .as_array_mut()
        .unwrap()
        .retain(|w| w["param"] != "partial_note");
    let pkg = layout_package(
        "amm_swap_tip",
        &abi,
        manifest,
        hex(r["vk_hash"].as_str().unwrap()),
    );
    let chain = hex(r["chain_request_id"].as_str().unwrap());
    let old = pkg.old_commitments_of(&pi).unwrap();
    let reads = pkg.reads_of(&pi).unwrap();
    assert_eq!(old, fields(&r["old_commitments"]));
    assert_eq!(reads, fields(&r["reads"]));
    assert_eq!(
        machine_request_id(chain, &old, &reads),
        hex(r["machine_request_id"].as_str().unwrap())
    );
    let shape = &pkg.shape;
    assert_eq!(shape.public_input_count, pi.len());
    assert_eq!(shape.namespace_index, at(&layout["namespace"]));
    assert_eq!(
        shape.return_index("request_id"),
        Some(at(&layout["request_id"]))
    );
    assert_eq!(pi[at(&layout["request_id"])], chain);
    let new: Vec<usize> = shape.outputs.iter().map(|o| o.note_hash_index).collect();
    assert_eq!(new, ats(&layout["new_commitments"]));
    assert_eq!(
        shape.return_index("npk_app_hash"),
        Some(at(&layout["npk_app_hash"]))
    );
    assert_eq!(shape.return_index("ok"), Some(at(&layout["ok"])));
    let app: Vec<usize> = (at(&layout["ok"]) + 1..shape.public_input_count).collect();
    assert_eq!(app, ats(&layout["app_outputs"]));

    let r = &file["init_rounds"][0];
    let (layout, pi) = (&r["layout"], fields(&r["public_inputs"]));
    let ns = hex(r["namespace"].as_str().unwrap());
    let vk = hex(r["vk_hash"].as_str().unwrap());
    let pkg = layout_package(
        "amm_init_tip",
        AMM_INIT_TIP_ABI,
        read("examples/amm-tip/manifests/amm_init_tip.json"),
        vk,
    );
    let read = sidecar_tip::init::InitRead {
        block: 0,
        head: 0,
        configured: Fr::from(1u64),
        inputs: fields(&r["inputs"]),
        slots: vec![],
    };
    let chain = read.chain_request_id(ns, vk);
    assert_eq!(chain, hex(r["chain_request_id"].as_str().unwrap()));
    let empty = pkg.init_commitments().unwrap();
    assert!(pkg.old_commitments_of(&pi).unwrap().is_empty());
    assert!(pkg.reads_of(&pi).unwrap().is_empty());
    assert_eq!(
        machine_request_id(chain, &empty, &[]),
        hex(r["machine_request_id"].as_str().unwrap())
    );
    let shape = &pkg.shape;
    assert_eq!(shape.public_input_count, pi.len());
    assert_eq!(shape.namespace_index, at(&layout["namespace"]));
    assert_eq!(
        shape.return_index("request_id"),
        Some(at(&layout["request_id"]))
    );
    assert_eq!(pi[at(&layout["request_id"])], chain);
    let olds: Vec<Fr> = ats(&layout["old_commitments"])
        .iter()
        .map(|&i| pi[i])
        .collect();
    assert_eq!(olds, empty);
    assert_eq!(
        shape.return_index("old_c"),
        Some(ats(&layout["old_commitments"])[0])
    );
    let new: Vec<usize> = shape.outputs.iter().map(|o| o.note_hash_index).collect();
    assert_eq!(new, ats(&layout["new_commitments"]));
    assert_eq!(
        shape.return_index("npk_app_hash"),
        Some(at(&layout["npk_app_hash"]))
    );
    assert!(ats(&layout["new_hashes"]).is_empty());
}

/// The committed slot_commitment.json and tip_round_vectors' Prover.toml are
/// what this code computes, and the amm-tip fixture's commitment is the
/// new_c amm_init_tip outputs on its Prover.toml.
#[test]
fn slot_commitment_files_match() {
    let committed = read(SLOT_COMMITMENT);
    assert_eq!(committed, slot_commitments(), "rerun write_tip_vectors");
    assert_eq!(
        read_text(&format!("{ROUND_NOIR}/Prover.toml")),
        round_prover_toml(&committed),
        "rerun write_tip_vectors (after the ids writer)"
    );
    assert_eq!(
        committed["vectors"][0]["commitment"],
        "0x216c4005a3578abf5f829fbf121dc857749f82d555c519c24b4984c7c7b7a399"
    );
    // tip_round_vectors' main takes one parameter per case (slot0..slot3,
    // ids0..ids4): a case added to either file needs one there too, or the
    // program never checks it
    let ids = read("testvectors/chain_request_id.json");
    assert_eq!(
        committed["vectors"].as_array().unwrap().len(),
        4,
        "slot cases: add a `slotK` parameter to {ROUND_NOIR}/src/main.nr"
    );
    assert_eq!(
        ids["vectors"].as_array().unwrap().len(),
        5,
        "chain request id cases: add an `idsK` parameter to {ROUND_NOIR}/src/main.nr"
    );
}

/// `cargo test -p sidecar-tip write_tip_vectors -- --ignored`: rewrites
/// testvectors/tip_results.json, testvectors/slot_commitment.json,
/// testvectors/shared_intake.json and the three Noir programs' Prover.toml.
#[test]
#[ignore = "writes testvectors/; run on purpose"]
fn write_tip_vectors() {
    let file = tip_results();
    let slots = slot_commitments();
    let shared = shared_intake();
    for (path, value) in [
        (TIP_RESULTS, &file),
        (SLOT_COMMITMENT, &slots),
        (SHARED_INTAKE, &shared),
    ] {
        std::fs::write(
            repo().join(path),
            serde_json::to_string_pretty(value).unwrap() + "\n",
        )
        .unwrap();
    }
    for (dir, toml) in [
        (RESULT_NOIR, result_prover_toml(&file)),
        (INTAKE_NOIR, intake_prover_toml()),
        (ROUND_NOIR, round_prover_toml(&slots)),
    ] {
        std::fs::create_dir_all(repo().join(dir)).unwrap();
        std::fs::write(repo().join(dir).join("Prover.toml"), toml).unwrap();
    }
}

// ---- secret-shared receipt intake: testvectors/shared_intake.json ----

fn shared_intake() -> Value {
    use sidecar_core::envelope::{
        EnvelopeAd, SIDECAR_INTAKE_AD_LABEL, seal_envelope_with, sidecar_intake_ad,
    };
    use sidecar_core::request::{NodeSharedInput, ShareCiphertext, SharedInput};

    let pkg = shared_package();
    let package = sidecar_tip::TipPackage::from_row(&pkg, Some(50))
        .unwrap()
        .unwrap();
    let namespace = hex("0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809");
    let values = shared_values();
    let value = |name: &str| values.iter().find(|(n, ..)| *n == name).unwrap().1;
    let names = sidecar_tip::commitment_names(&package.shape, &package.tip);
    let committed: Vec<Fr> = names.iter().map(|n| value(n)).collect();
    let blinding = value("$blinding");
    let c = sidecar_tip::inputs_commitment(&committed, blinding);
    let id = sidecar_tip::shared_chain_request_id(namespace, pkg.vk_hash, c);

    // every circuit INPUT_SHARED value, then the salts' envelope: one
    // sharing each, node i sealed [x_i, x_{i-1}]
    let salts = summand_salts();
    let mut sealed: Vec<(String, Fr, u64)> =
        sidecar_tip::shared_names(&package.shape, &package.tip)
            .into_iter()
            .map(|name| {
                let (_, x, seed) = *values.iter().find(|(n, ..)| *n == name).unwrap();
                (name, x, seed.unwrap())
            })
            .collect();
    sealed.push((
        sidecar_tip::SUMMAND_SALT.to_string(),
        salts.iter().copied().sum(),
        SUMMAND_SALT_SEED,
    ));
    let keys = node_keys();
    let mut shared = Vec::new();
    let mut detail = Vec::new();
    for (name, x, seed) in sealed {
        let ad = EnvelopeAd::for_intake(namespace, id, &pkg.name, &name);
        let sh = sharing(x, seed);
        let mut shares = Vec::new();
        let mut nodes = Vec::new();
        for (i, k) in keys.iter().enumerate() {
            let pair = [sh[i], sh[(i + NODES - 1) % NODES]];
            let eph = poseidon2_hash(&[Fr::from(seed), Fr::from(10 + i as u64)]);
            let envelope: ShareCiphertext = seal_envelope_with(k.enc_pk(), i, &ad, pair, eph);
            nodes.push(json!({
                "node": i,
                "pair": fhs(&pair),
                "eph_secret": fh(eph),
                "nonce": fh(ad.nonce(i)),
            }));
            shares.push(envelope);
        }
        let shares: [ShareCiphertext; NODES] = shares.try_into().unwrap();
        let share_hashes = shares.map(|s| fh(s.hash()));
        detail.push(json!({"name": name, "value": fh(x), "sharing": fhs(&sh), "nodes": nodes}));
        shared.push(SharedInput {
            name,
            shares,
            share_hashes,
        });
    }

    // the summand vectors over the summand names, their commitments and D
    let layout = sidecar_tip::commitment_layout(&package.shape, &package.tip);
    let order = layout.summand_names();
    let seed_of = |name: &str| values.iter().find(|(n, ..)| *n == name).unwrap().2.unwrap();
    let summands: Vec<Vec<Fr>> = (0..NODES)
        .map(|j| {
            order
                .iter()
                .map(|n| sharing(value(n), seed_of(n))[j])
                .collect()
        })
        .collect();
    let commitments: [Fr; NODES] =
        std::array::from_fn(|j| sidecar_tip::summand_commitment(&summands[j], salts[j]));
    let kinds = layout.value_kinds();
    let clear = [value("position")];
    let d = sidecar_tip::sharing_digest(&commitments, &kinds, &clear);

    // node 0's receipt request, as the orchestrator forwards it
    let (current, expiry) = (1000u32, 1300u32);
    let body = json!({
        "namespace": fh(namespace),
        "circuit": pkg.name,
        "inputs": {"position": fh(value("position"))},
        "inputs_hash": fh(c),
        "shared_inputs": shared.iter().map(|s| NodeSharedInput {
            name: s.name.clone(),
            share: s.shares[0],
            share_hashes: s.share_hashes,
        }).collect::<Vec<_>>(),
        "summand_commitments": fhs(&commitments),
        "sharing_digest": fh(d),
        "current_block": current,
        "expiry_block": expiry,
    });
    let req = sidecar_tip::ReceiptRequest::from_json(&body.to_string()).unwrap();
    let checked = sidecar_tip::check_receipt_request(&pkg, Some(50), &req).unwrap();
    assert_eq!((checked.request_id, checked.inputs_hash), (id, c));
    let message = sidecar_tip::shared_receipt_message(id, c, expiry, d);
    assert_eq!(checked.message(expiry), message);
    let signatures: Vec<Signature> = keys
        .iter()
        .map(|k| sidecar_tip::sign_receipt_message(k.sig_scalar(), message))
        .collect();

    json!({
        "rule": "secret-shared receipt intake (docs/ARCHITECTURE.md section 6, \"Secret-shared intake\"): C = poseidon2([v_1, ..., v_m, blinding]) over commitment_names, the values of every app input (clear or INPUT_SHARED) and of $partial_note, $outcome_key and $outcome_tag in the order the ABI walk first meets each, $blinding last; chain_request_id = poseidon2([namespace, vk_hash, C]); node i's envelope of each INPUT_SHARED value, and of $summand_salt after them, seals its pair [x_i, x_{i-1}] of that value's sharing as envelope.json does, under the intake associated data nonce = poseidon2([namespace, chain_request_id, poseidon2_hash_bytes(circuit), poseidon2_hash_bytes(name), i, SIDECAR_INTAKE_AD]); the summand vectors s_j hold the j-th summand of each of summand_names (C's shared values in C's order, then $blinding), the salts are $summand_salt's sharing, S_j = poseidon2([SUMMANDS_DOMAIN, s_j..., salt_j]) and D = poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds..., clear values...]) with kinds the kind of each of commitment_names (value_kinds: 0 clear, 1 an INPUT_SHARED or reserved value) and the clear values in commitment_names order (clear_values), SUMMANDS_DOMAIN and SHARING_DOMAIN the bytes sidecar.summands and sidecar.sharing read big-endian; node i signs only when its pairs and salts hash to S_i and S_{i-1}; the receipt message is poseidon2([RECEIPT_DOMAIN, chain_request_id, C, expiry_block, D]), signatures[i] by node i's sig key of keys.json",
        "manifest": "testvectors/manifests/shared_receipt_round.json",
        "abi": shared_circuit_abi(),
        "circuit": pkg.name,
        "vk_hash": fh(pkg.vk_hash),
        "namespace": fh(namespace),
        "intake_ad": fh(sidecar_intake_ad()),
        "intake_ad_ascii": std::str::from_utf8(SIDECAR_INTAKE_AD_LABEL).unwrap(),
        "values": values.iter().map(|(n, v, _)| (n.to_string(), json!(fh(*v)))).collect::<serde_json::Map<_, _>>(),
        "commitment_names": names,
        "commitment_values": fhs(&committed),
        "blinding": fh(blinding),
        "inputs_commitment": fh(c),
        "chain_request_id": fh(id),
        "shared_inputs": shared,
        "envelopes": detail,
        "summands_domain": fh(label_field(b"sidecar.summands")),
        "sharing_domain": fh(label_field(b"sidecar.sharing")),
        "summand_names": order,
        "summand_salt_name": sidecar_tip::SUMMAND_SALT,
        "summands": summands.iter().map(|v| fhs(v)).collect::<Vec<_>>(),
        "salts": fhs(&salts),
        "summand_commitments": fhs(&commitments),
        "value_kinds": kinds.iter().map(|k| fh(k.field())).collect::<Vec<_>>(),
        "clear_values": fhs(&clear),
        "sharing_digest": fh(d),
        "receipt_body_node0": body,
        "receipt": {
            "expiry_block": expiry,
            "message_preimage": [fh(label_field(b"sidecar.receipt")), fh(id), fh(c), fh(Fr::from(u64::from(expiry))), fh(d)],
            "message": fh(message),
            "signatures": signatures,
        },
    })
}

/// The committed shared_intake.json is what this code computes: the
/// commitment walk puts `$blinding` last and leaves it out of the values,
/// each node opens its own envelope under the intake associated data (and
/// no other node's), the summand vectors add up to the shared values and
/// the blinding, each node's pairs and salts are the summand vectors and
/// salts it holds and pass its own check, and each receipt verifies over C
/// and D.
#[test]
fn shared_intake_file_matches() {
    use sidecar_core::envelope::{EnvelopeAd, open_envelope};
    use sidecar_core::request::SharedInput;
    let committed = read(SHARED_INTAKE);
    assert_eq!(committed, shared_intake(), "rerun write_tip_vectors");
    assert_eq!(
        committed["commitment_names"],
        json!([
            "amount",
            "position",
            "$partial_note",
            "$outcome_key",
            "$outcome_tag"
        ])
    );
    assert_eq!(
        committed["summand_names"],
        json!([
            "amount",
            "$partial_note",
            "$outcome_key",
            "$outcome_tag",
            "$blinding"
        ])
    );
    let (ns, id) = (
        hex(committed["namespace"].as_str().unwrap()),
        hex(committed["chain_request_id"].as_str().unwrap()),
    );
    let keys = node_keys();
    let shared: Vec<SharedInput> =
        serde_json::from_value(committed["shared_inputs"].clone()).unwrap();
    assert_eq!(
        shared.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        [
            "amount",
            "$partial_note",
            "$outcome_key",
            "$blinding",
            "$outcome_tag",
            "$summand_salt"
        ]
    );
    let field_rows = |v: &Value| -> Vec<Vec<Fr>> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|r| {
                r.as_array()
                    .unwrap()
                    .iter()
                    .map(|f| hex(f.as_str().unwrap()))
                    .collect()
            })
            .collect()
    };
    let summands = field_rows(&committed["summands"]);
    let salts: Vec<Fr> = committed["salts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| hex(f.as_str().unwrap()))
        .collect();
    let order: Vec<String> = serde_json::from_value(committed["summand_names"].clone()).unwrap();
    for (s, d) in shared
        .iter()
        .zip(committed["envelopes"].as_array().unwrap())
    {
        let ad = EnvelopeAd::for_intake(ns, id, "shared_receipt_round", &s.name);
        for i in 0..NODES {
            let pair = open_envelope(&keys[i], i, &ad, &s.shares[i]).unwrap();
            assert_eq!(json!(fhs(&pair)), d["nodes"][i]["pair"]);
            assert!(open_envelope(&keys[(i + 1) % NODES], i, &ad, &s.shares[i]).is_err());
            // the intake associated data is not the body's
            let body = EnvelopeAd {
                binds: Fr::from(0u64),
                ..ad.clone()
            };
            assert!(open_envelope(&keys[i], i, &body, &s.shares[i]).is_err());
            // node i's pair is the i-th and (i-1)-th summand vectors' (or salts')
            let prev = (i + NODES - 1) % NODES;
            match order.iter().position(|n| n == &s.name) {
                Some(k) => assert_eq!(pair, [summands[i][k], summands[prev][k]]),
                None => {
                    assert_eq!(s.name, "$summand_salt");
                    assert_eq!(pair, [salts[i], salts[prev]]);
                }
            }
        }
    }
    // the summands add up to the shared values, the blinding last
    let values = &committed["values"];
    for (k, name) in order.iter().enumerate() {
        let sum: Fr = (0..NODES).map(|j| summands[j][k]).sum();
        assert_eq!(sum, hex(values[name].as_str().unwrap()), "{name}");
    }
    let commitments: [Fr; NODES] =
        std::array::from_fn(|j| sidecar_tip::summand_commitment(&summands[j], salts[j]));
    assert_eq!(json!(fhs(&commitments)), committed["summand_commitments"]);
    // D over them, the kinds of commitment_names (position clear, the rest
    // shared) and the clear position; another clear value is another D
    let kinds = [
        Kind::Chosen,
        Kind::Clear,
        Kind::Chosen,
        Kind::Chosen,
        Kind::Chosen,
    ];
    assert_eq!(
        committed["value_kinds"],
        json!(kinds.map(|k| fh(k.field())))
    );
    let clear = [hex(values["position"].as_str().unwrap())];
    assert_eq!(committed["clear_values"], json!([fh(clear[0])]));
    let d = sidecar_tip::sharing_digest(&commitments, &kinds, &clear);
    assert_eq!(json!(fh(d)), committed["sharing_digest"]);
    assert_ne!(
        d,
        sidecar_tip::sharing_digest(&commitments, &kinds, &[clear[0] + Fr::from(1u64)])
    );
    let receipt = &committed["receipt"];
    let c = hex(committed["inputs_commitment"].as_str().unwrap());
    let message = sidecar_tip::shared_receipt_message(id, c, 1300, d);
    for (i, s) in receipt["signatures"].as_array().unwrap().iter().enumerate() {
        let s: Signature = serde_json::from_value(s.clone()).unwrap();
        assert!(verify(keys[i].sig_pk(), s, message));
        // a receipt over C alone is not this one
        assert!(!sidecar_tip::verify_receipt(
            keys[i].sig_pk(),
            s,
            id,
            c,
            1300
        ));
    }
}
