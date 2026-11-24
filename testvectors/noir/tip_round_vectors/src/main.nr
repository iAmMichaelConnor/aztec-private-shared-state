//! Checks the tip's round-side hashes with the functions the round circuits
//! call (noir/pss_core's `tip` module): every case of
//! testvectors/slot_commitment.json against tip::slot::commitment, and every
//! case of testvectors/chain_request_id.json against tip::intake's
//! inputs_hash and chain_request_id and the non-secret-shared intakes' binding (the
//! circuit side of the id the contract and the nodes compute), and
//! testvectors/shared_intake.json's C and chain request id against the shared
//! intakes' tip::intake::commit and shared. Prover.toml is
//! written from the vector files by sidecar-tip (tests/write_vectors, write_tip_vectors);
//! `nargo execute` fails on any disagreement.

use pss_core::tip::intake::{chain_request_id, commit, inputs_hash, plain, shared};
use pss_core::tip::slot::{commitment, TIP_STATE_SEP};

/// One case of slot_commitment.json: N stored fields.
struct SlotVector<let N: u32> {
    namespace: Field,
    slot: Field,
    fields: [Field; N],
    blinding: Field,
    commitment: Field,
}

/// One case of chain_request_id.json, the part a round computes: I app
/// inputs.
struct IdVector<let I: u32> {
    namespace: Field,
    vk_hash: Field,
    inputs: [Field; I],
    inputs_hash: Field,
    user_nonce: Field,
    chain_request_id: Field,
}

/// A case of chain_request_id.json with no inputs: an entry point takes no
/// zero-length array, so the program passes `[]` itself.
struct EmptyIdVector {
    namespace: Field,
    vk_hash: Field,
    inputs_hash: Field,
    user_nonce: Field,
    chain_request_id: Field,
}

/// shared_intake.json, the part a round computes: C over its five commitment
/// values and the blinding, and the shared chain request id.
struct SharedVector {
    namespace: Field,
    vk_hash: Field,
    commitment_values: [Field; 5],
    blinding: Field,
    inputs_commitment: Field,
    chain_request_id: Field,
}

fn check_slot<let N: u32>(v: SlotVector<N>) {
    assert_eq(
        commitment(v.namespace, v.slot, v.fields, v.blinding),
        v.commitment,
        "slot commitment",
    );
}

fn check_id<let I: u32>(v: IdVector<I>) {
    let ih = inputs_hash(v.inputs);
    assert_eq(ih, v.inputs_hash, "inputs_hash");
    let id = chain_request_id(v.namespace, v.vk_hash, ih, v.user_nonce);
    assert_eq(id, v.chain_request_id, "chain_request_id");
    // the non-secret-shared intakes' binding is the same id over the same inputs
    let request_id = plain(v.namespace, v.vk_hash, v.inputs, v.user_nonce);
    assert_eq(request_id, v.chain_request_id, "plain binding request id");
}

fn main(
    tip_state_sep: Field,
    slot0: SlotVector<2>,
    slot1: SlotVector<1>,
    slot2: SlotVector<3>,
    slot3: SlotVector<5>,
    ids0: IdVector<2>,
    ids1: IdVector<3>,
    ids2: EmptyIdVector,
    ids3: IdVector<4>,
    ids4: IdVector<2>,
    shared_intake: SharedVector,
) {
    // the file's separator is pss_core's (whose own test pins its ASCII name)
    assert_eq(tip_state_sep, TIP_STATE_SEP);

    check_slot(slot0);
    check_slot(slot1);
    check_slot(slot2);
    check_slot(slot3);

    check_id(ids0);
    check_id(ids1);
    check_id(
        IdVector {
            namespace: ids2.namespace,
            vk_hash: ids2.vk_hash,
            inputs: [],
            inputs_hash: ids2.inputs_hash,
            user_nonce: ids2.user_nonce,
            chain_request_id: ids2.chain_request_id,
        },
    );
    check_id(ids3);
    check_id(ids4);

    let c = commit(shared_intake.commitment_values, shared_intake.blinding);
    assert_eq(c, shared_intake.inputs_commitment, "inputs commitment");
    assert_eq(
        shared(shared_intake.namespace, shared_intake.vk_hash, c),
        shared_intake.chain_request_id,
        "shared chain request id",
    );
}
