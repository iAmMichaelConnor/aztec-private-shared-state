//! Checks the tip's intake vectors with the functions of the tip contract
//! library that computes them on chain (noir/pss_public_contract):
//! every case of testvectors/chain_request_id.json against intake.nr's
//! `inputs_hash` and `chain_request_id` and result.nr's `machine_request_id`
//! (over the old commitments and then the case's pinned reads), and its
//! on-chain intake request log against what `append_onchain` emits
//! (`request_log_tag`, then `PlainRequest::serialize()`);
//! every case of testvectors/receipts.json against `receipt_message` and the
//! three node signatures against `result_signature_verifies` under keys.json's `sig`
//! keys; every tag of testvectors/log_tags.json against `request_log_tag` and
//! `compute_log_tag(_, PSS_STATE)` (the tag `apply` gives the sealed-thirds
//! log); testvectors/shared_intake.json's C, chain request id, layout,
//! sharing digest and receipts over C against shared_intake.nr's
//! `inputs_commitment`, `shared_chain_request_id`, `opened_sharing` and the
//! receipt check; every case of
//! testvectors/queue.json against the slots of queue.nr's `Queue` at its base
//! slot, and its `done` codes against queue.nr's; and the files' domain
//! constants against domains.nr. Prover.toml is
//! written from the vector files by sidecar-tip (tests/write_vectors, write_tip_vectors);
//! `nargo execute` fails on any disagreement.

use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::{compute_log_tag, poseidon2_hash};
use aztec::protocol::traits::{FromField, Packable, Serialize};
use aztec::state_vars::StateVariable;
use pss_public_contract::{
    chain_request_id, DONE_APPLIED, DONE_PENDING, DONE_SKIPPED, Head, inputs_commitment,
    CHOSEN, CLEAR, inputs_hash, Layout, opened_sharing, PlainRequest, PSS_ATTEMPT, Queue, Receipt,
    RECEIPT_DOMAIN, receipt_message, REQUEST_DOMAIN, request_log_tag, shared_chain_request_id,
    shared_receipt_message, Sharing,
};
use pss_public_contract::chain_state::PSS_STATE;
use pss_public_contract::result::{machine_request_id, result_signature_verifies};
use pss_core::test_support::ascii;
use std::embedded_curve_ops::EmbeddedCurvePoint;

/// One case of chain_request_id.json: N app inputs, R old commitments, a
/// request log of L = N + 2 fields. A case's pinned reads are the entry
/// point's `ids{k}_pinned_reads` where it has some (an entry point takes no
/// zero-length array).
struct IdVector<let N: u32, let R: u32, let L: u32> {
    namespace: Field,
    vk_hash: Field,
    inputs: [Field; N],
    inputs_hash: Field,
    user_nonce: Field,
    chain_request_id: Field,
    old_commitments: [Field; R],
    machine_request_id: Field,
    request_log: [Field; L],
}

/// One case of receipts.json, its signatures as [s.lo, s.hi, e.lo, e.hi].
struct ReceiptVector<let N: u32> {
    namespace: Field,
    vk_hash: Field,
    inputs: [Field; N],
    inputs_hash: Field,
    user_nonce: Field,
    request_id: Field,
    expiry_block: u32,
    message_preimage: [Field; 4],
    message: Field,
    signatures: [[Field; 4]; 3],
}

/// A case of chain_request_id.json with no inputs and no old commitments:
/// an entry point takes no zero-length array, so the program passes `[]`.
struct EmptyIdVector {
    namespace: Field,
    vk_hash: Field,
    inputs_hash: Field,
    user_nonce: Field,
    chain_request_id: Field,
    machine_request_id: Field,
    request_log: [Field; 2],
}

/// shared_intake.json: C over its five commitment values (three app inputs,
/// the outcome key and the outcome tag), the shared chain request id, and
/// the three receipts over C.
struct SharedVector {
    namespace: Field,
    vk_hash: Field,
    commitment_values: [Field; 5],
    blinding: Field,
    inputs_commitment: Field,
    chain_request_id: Field,
    expiry_block: u32,
    message_preimage: [Field; 5],
    message: Field,
    signatures: [[Field; 4]; 3],
    /// the summand vectors over C's shared values (amount, the partial note,
    /// the outcome key and tag), then the blinding
    summands: [[Field; 5]; 3],
    salts: [Field; 3],
    /// the kind of each of C's values as the machine derives it (0 clear,
    /// 1 shared), which `SHARED_LAYOUT` must equal
    value_kinds: [Field; 5],
    sharing_digest: Field,
}

/// The kinds of the shared vector's values in C's order: `amount` shared,
/// `position` clear, the reserved three shared.
global SHARED_LAYOUT: Layout<5, 1, 4> = Layout { kinds: [CHOSEN, CLEAR, CHOSEN, CHOSEN, CHOSEN] };

/// One case of queue.json: the slots of a queue at `base`, five indices of
/// `requests` and `done` and two keys of `seen`.
struct QueueVector {
    base: Field,
    tail: Field,
    head_index: Field,
    head_since: Field,
    request_indices: [u64; 5],
    request_slots: [Field; 5],
    seen_ids: [Field; 2],
    seen_slots: [Field; 2],
    done_indices: [u64; 5],
    done_slots: [Field; 5],
}

/// The slots of queue.nr's `Queue` at the case's base, as the library's
/// own state variables derive them (no context is needed to name a slot).
fn check_queue(v: QueueVector) {
    let q: Queue<()> = StateVariable::new((), v.base);
    assert_eq(q.get_storage_slot(), v.base, "the queue's slot");
    assert_eq(q.tail.get_storage_slot(), v.tail, "tail");
    // head is {index, since}, packed one field per member from its slot
    assert_eq(q.head.get_storage_slot(), v.head_index, "head.index");
    assert_eq(<Head as Packable>::N, 2);
    assert_eq(v.head_since, v.head_index + 1, "head.since");
    for k in 0..5 {
        let r = q.requests.at(v.request_indices[k]);
        assert_eq(r.get_storage_slot(), v.request_slots[k], "requests[index]");
        assert_eq(q.done.at(v.done_indices[k]).get_storage_slot(), v.done_slots[k], "done[index]");
    }
    for k in 0..2 {
        assert_eq(q.seen.at(v.seen_ids[k]).get_storage_slot(), v.seen_slots[k], "seen[request_id]");
    }
}

struct TagVector {
    chain_request_id: Field,
    request_tag: Field,
    sealed_tag: Field,
}

struct Key {
    x: Field,
    y: Field,
}

fn check_ids<let N: u32, let R: u32, let L: u32, let Q: u32>(
    v: IdVector<N, R, L>,
    pinned_reads: [Field; Q],
) -> Field {
    let ih = inputs_hash(v.inputs);
    assert_eq(ih, v.inputs_hash, "inputs_hash");
    let id = chain_request_id(
        AztecAddress::from_field(v.namespace),
        v.vk_hash,
        ih,
        v.user_nonce,
    );
    assert_eq(id, v.chain_request_id, "chain_request_id");
    assert_eq(
        machine_request_id(id, v.old_commitments, pinned_reads),
        v.machine_request_id,
        "machine_request_id",
    );
    // the request log append_onchain emits: its tag, then the log body
    let log = [request_log_tag(id)].concat(
        PlainRequest { inputs: v.inputs, user_nonce: v.user_nonce }.serialize(),
    );
    assert_eq(L, N + 2, "a request log is the tag, the inputs and user_nonce");
    for k in 0..L {
        assert_eq(log[k], v.request_log[k], "request log field");
    }
    id
}

fn check_empty_ids(v: EmptyIdVector) {
    let _ = check_ids(
        IdVector {
        namespace: v.namespace,
        vk_hash: v.vk_hash,
        inputs: [],
        inputs_hash: v.inputs_hash,
        user_nonce: v.user_nonce,
        chain_request_id: v.chain_request_id,
        old_commitments: [],
        machine_request_id: v.machine_request_id,
        request_log: v.request_log,
    },
        [],
    );
}

fn receipt(sig: [Field; 4]) -> Receipt {
    Receipt { s: [sig[0], sig[1]], e: [sig[2], sig[3]] }
}

fn check_receipt<let N: u32>(v: ReceiptVector<N>, keys: [EmbeddedCurvePoint; 3]) -> Field {
    let ih = inputs_hash(v.inputs);
    assert_eq(ih, v.inputs_hash, "inputs_hash");
    let id = chain_request_id(
        AztecAddress::from_field(v.namespace),
        v.vk_hash,
        ih,
        v.user_nonce,
    );
    assert_eq(id, v.request_id, "request_id");
    assert_eq(v.message_preimage, [RECEIPT_DOMAIN, id, ih, v.expiry_block as Field]);
    let message = receipt_message(id, ih, v.expiry_block);
    assert_eq(message, v.message, "receipt message");
    for i in 0..3 {
        assert(result_signature_verifies(keys[i], receipt(v.signatures[i]).limbs(), message), "a node's receipt");
        // a receipt is its own node's only, and only over its own message
        assert(!result_signature_verifies(keys[(i + 1) % 3], receipt(v.signatures[i]).limbs(), message));
        assert(!result_signature_verifies(keys[i], receipt(v.signatures[i]).limbs(), message + 1));
    }
    id
}

fn check_shared(v: SharedVector, keys: [EmbeddedCurvePoint; 3]) {
    // the request function's check: the sharing opens C's values, its last
    // summands add up to the blinding, and it gives the digest
    assert_eq(SHARED_LAYOUT.kinds.map(|k: u8| k as Field), v.value_kinds, "the layout is the machine's");
    let sharing = Sharing { summands: v.summands, salts: v.salts };
    let (blinding, d) = opened_sharing(SHARED_LAYOUT, v.commitment_values, sharing);
    assert_eq(blinding, v.blinding, "the sharing's blinding");
    assert_eq(d, v.sharing_digest, "sharing digest");
    let c = inputs_commitment(v.commitment_values, v.blinding);
    assert_eq(c, v.inputs_commitment, "inputs commitment");
    let id = shared_chain_request_id(AztecAddress::from_field(v.namespace), v.vk_hash, c);
    assert_eq(id, v.chain_request_id, "shared chain request id");
    assert_eq(v.message_preimage, [RECEIPT_DOMAIN, id, c, v.expiry_block as Field, d]);
    let message = shared_receipt_message(id, c, v.expiry_block, d);
    assert_eq(message, v.message, "receipt message over C and D");
    for i in 0..3 {
        assert(result_signature_verifies(keys[i], receipt(v.signatures[i]).limbs(), message), "a node's receipt over C");
        assert(!result_signature_verifies(keys[(i + 1) % 3], receipt(v.signatures[i]).limbs(), message));
    }
}

fn main(
    pss_attempt: Field,
    receipt_domain: Field,
    request_domain: u32,
    pss_state: u32,
    done_codes: [u8; 3],
    ids1_pinned_reads: [Field; 1],
    ids4_pinned_reads: [Field; 2],
    sig_keys: [Key; 3],
    ids0: IdVector<2, 1, 4>,
    ids1: IdVector<3, 2, 5>,
    ids2: EmptyIdVector,
    ids3: IdVector<4, 1, 6>,
    ids4: IdVector<2, 1, 4>,
    receipt0: ReceiptVector<2>,
    receipt1: ReceiptVector<3>,
    tags: [TagVector; 3],
    queue: [QueueVector; 3],
    shared: SharedVector,
) {
    // The files' domains are the libraries', and each of domains.nr's is its
    // ASCII name (pss_core's own test pins PSS_ATTEMPT's).
    assert_eq(pss_attempt, PSS_ATTEMPT);
    assert_eq(receipt_domain, RECEIPT_DOMAIN);
    assert_eq(RECEIPT_DOMAIN, ascii("sidecar.receipt"));
    assert_eq(request_domain, REQUEST_DOMAIN);
    assert_eq(REQUEST_DOMAIN as Field, ascii("psrq"));
    assert_eq(pss_state, PSS_STATE);
    assert_eq(PSS_STATE as Field, ascii("PSS") * 256 + 2);

    let first = check_ids(ids0, []);
    let _ = check_ids(ids1, ids1_pinned_reads);
    check_empty_ids(ids2);
    let _ = check_ids(ids3, []);
    let _ = check_ids(ids4, ids4_pinned_reads);
    // the pinned reads follow the old commitments in the one sponge, and a
    // moved value is another attempt
    assert_eq(
        ids1.machine_request_id,
        poseidon2_hash([PSS_ATTEMPT, ids1.chain_request_id].concat(ids1.old_commitments).concat(
            ids1_pinned_reads,
        )),
    );
    assert(
        machine_request_id(ids1.chain_request_id, ids1.old_commitments, [ids1_pinned_reads[0] + 1])
            != ids1.machine_request_id,
    );

    let keys = sig_keys.map(|k: Key| EmbeddedCurvePoint { x: k.x, y: k.y });
    // the first receipt is chain_request_id.json's first request under receipt intake
    assert_eq(check_receipt(receipt0, keys), first);
    let _ = check_receipt(receipt1, keys);
    check_shared(shared, keys);

    // done[index]: pending, applied, skipped
    assert_eq(done_codes, [DONE_PENDING, DONE_APPLIED, DONE_SKIPPED]);
    for v in queue {
        check_queue(v);
    }
    for t in tags {
        assert_eq(request_log_tag(t.chain_request_id), t.request_tag, "request log tag");
        assert_eq(compute_log_tag(t.chain_request_id, PSS_STATE), t.sealed_tag, "sealed log tag");
    }
}
