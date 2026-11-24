//! Contract side of private shared state (PSS): the generic body of a
//! private function that verifies a network co-SNARK and forwards its
//! effects, plus the anchoring helpers every PSS app needs.
//!
//! The split of work in one call:
//! - the co-SNARK proves note PREIMAGES and NULLIFIER correctness under
//!   the namespace's nsk_app (its public inputs carry the hashes and nullifiers);
//! - the protocol KERNEL proves note-hash EXISTENCE in the tree, via
//!   hash-only read requests;
//! - `apply` BINDS the two: the values it read-requests and pushes are
//!   the values it feeds into `verify_proof_with_type`'s public inputs.
//!
//! Everything here is a plain function: call it from an `#[aztec]`
//! contract's private function with `self.context`.
pub mod anchor;
pub mod effects;
pub mod proof_data;

pub use anchor::{anchor_leaf, assert_anchored, once_nullifier, push_once};
pub use effects::{PssConfig, PssEffects};
pub use proof_data::{CAPSULE_SLOT_PROOF, PROOF_TYPE_HONK_ZK, ProofData};

use aztec::context::{NoteExistenceRequest, PrivateContext};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash;
use aztec::protocol::traits::ToField;

/// The circuit's public-input array, rebuilt from what the contract holds:
///
/// ```text
/// [namespace, owner,
///  in_slots[0..R], out_slots[0..W],
///  app_inputs[0..P],
///  read_leaves[0..R], nullifiers[0..R], new_note_hashes[0..W],
///  npk_app_hash,
///  app_outputs[0..A]]
/// ```
///
/// ACIR orders public inputs as pub parameters in declaration order, then
/// the return value flattened in field order; every PSS circuit declares
/// its pub parameters in this order and returns `PssEffects`.
pub fn canonical_public_inputs<let R: u32, let W: u32, let P: u32, let A: u32>(
    this: AztecAddress,
    config: PssConfig,
    in_slots: [Field; R],
    out_slots: [Field; W],
    app_inputs: [Field; P],
    effects: PssEffects<R, W, A>,
) -> [Field; 2 + R + W + P + R + R + W + 1 + A] {
    [this.to_field(), config.owner]
        .concat(in_slots)
        .concat(out_slots)
        .concat(app_inputs)
        .concat(effects.read_leaves)
        .concat(effects.nullifiers)
        .concat(effects.new_note_hashes)
        .concat([effects.npk_app_hash])
        .concat(effects.app_outputs)
}

/// Pop the (vk, proof) pair the sender staged as a capsule at
/// `CAPSULE_SLOT_PROOF`, under `scope`. Public so that a contract library
/// verifying another kind of PSS result (the tip's `process_result`) loads
/// its proof the same way; the caller pins the vk hash and verifies the proof
/// over the hint.
pub unconstrained fn load_proof_capsule(
    contract_address: AztecAddress,
    scope: AztecAddress,
) -> ProofData {
    aztec::oracle::capsules::load(contract_address, CAPSULE_SLOT_PROOF, scope).expect(
        f"proof capsule missing",
    )
}

/// Load the (vk, proof) capsule staged under `scope`, require that the vk
/// hashes to `expected_vk_hash` and verify the proof over `public_inputs`:
/// the one "load, pin, verify" of every PSS call (`apply` here, the tip's
/// result and init in pss_public_contract).
///
/// `scope` selects the capsule: the account that staged it, normally the
/// msg_sender.
///
/// The vk-hash pin: `expected_vk_hash` names the one
/// circuit this call accepts; pass a hash fixed at deployment (a Config
/// field or a global), never a caller argument, or any circuit's proof
/// is accepted.
pub fn verify_pinned<let N: u32>(
    context: &mut PrivateContext,
    scope: AztecAddress,
    expected_vk_hash: Field,
    public_inputs: [Field; N],
) {
    // Safety: the capsule contents are unconstrained hints; their
    // correctness is enforced by the vk-hash pin below plus the in-circuit
    // proof verification over them. The address and scope only select an
    // untrusted hint; accepting any proof for the pinned key and these
    // public inputs is intentional, regardless of its source.
    let data = unsafe { load_proof_capsule(context.this_address(), scope) };
    let vk_hash = poseidon2_hash(data.vk);
    assert_eq(vk_hash, expected_vk_hash, "unexpected verification key");
    std::verify_proof_with_type(data.vk, data.proof, public_inputs, vk_hash, PROOF_TYPE_HONK_ZK);
}

/// The generic body of a PSS private function. Verifies the network's
/// proof for the circuit pinned by `expected_vk_hash` and forwards its
/// effects: a read request and a nullifier for every consumed note, a note
/// hash for every created one.
///
/// `scope` selects the capsule: the account that staged it, normally the
/// msg_sender. App checks on `app_inputs` belong before the call; anything
/// done with `effects.app_outputs` belongs after it.
///
/// The vk-hash pin is `verify_pinned`'s.
///
/// Note-hash order and nonce mining: note hashes are pushed
/// in `out_slots` order, after anything the caller pushed before this
/// call and before anything it pushes after. A note's protocol nonce is
/// `compute_note_hash_nonce(first nullifier of the tx, index)`, where the
/// index is its position among all note hashes of the tx; clients mine
/// nonces by that index, so document it per function and keep it stable.
pub fn apply<let R: u32, let W: u32, let P: u32, let A: u32>(
    context: &mut PrivateContext,
    scope: AztecAddress,
    expected_vk_hash: Field,
    config: PssConfig,
    in_slots: [Field; R],
    out_slots: [Field; W],
    app_inputs: [Field; P],
    effects: PssEffects<R, W, A>,
) {
    let this = context.this_address();
    verify_pinned(
        context,
        scope,
        expected_vk_hash,
        canonical_public_inputs(this, config, in_slots, out_slots, app_inputs, effects),
    );

    // The network pin: a round that consumes notes must be
    // by the network whose npk_app_hash the contract pinned. A round with
    // R = 0 nullifies nothing and outputs 0 here, so there is nothing to
    // pin; its proof still binds that 0 through the public inputs.
    if R > 0 {
        assert_eq(effects.npk_app_hash, config.npk_app_hash, "unexpected network identity");
    }

    // Every consumed note must be a leaf in the tree, and is spent by its
    // canonical nullifier: replaying a spent note re-derives the same
    // nullifier, which the protocol rejects as a duplicate.
    for i in 0..R {
        context.assert_note_exists(NoteExistenceRequest::for_settled(effects.read_leaves[i]));
        // `(nullifier, 0)` is the note-nullifier push for SETTLED notes
        context.push_nullifier_for_note_hash(effects.nullifiers[i], 0);
    }

    // the kernel silos and uniquifies each; the preimages stay with the
    // network as shares, so there is nothing to deliver to a PXE
    for j in 0..W {
        context.push_note_hash(effects.new_note_hashes[j]);
    }
}

/// The seed round of a note-client app (`pss_seed`: R = 0, W = 1, P = 0,
/// A = 0): verify its proof under `seed_vk_hash` and push the seed note's
/// hash at `seed_slot`. It nullifies nothing, so its `npk_app_hash` output
/// is 0 and `apply` does not check the pin. The seed note is one field of
/// randomness nobody knows, which the app's init round spends.
pub fn apply_seed(
    context: &mut PrivateContext,
    scope: AztecAddress,
    seed_vk_hash: Field,
    config: PssConfig,
    seed_slot: Field,
    seed_note_hash: Field,
) {
    apply(
        context,
        scope,
        seed_vk_hash,
        config,
        [],
        [seed_slot],
        [],
        PssEffects {
            read_leaves: [],
            nullifiers: [],
            new_note_hashes: [seed_note_hash],
            npk_app_hash: 0,
            app_outputs: [],
        },
    );
}

mod tests {
    use super::{canonical_public_inputs, PssConfig, PssEffects};
    use aztec::protocol::address::AztecAddress;
    use aztec::protocol::traits::FromField;

    #[test]
    fn canonical_public_inputs_order() {
        let this = AztecAddress::from_field(0xc0);
        let config = PssConfig { owner: 0x0e, npk_app_hash: 0x9b };
        let effects = PssEffects {
            read_leaves: [0x1a, 0x1b],
            nullifiers: [0x2a, 0x2b],
            new_note_hashes: [0x3a],
            npk_app_hash: 0x9b,
            app_outputs: [0x4a, 0x4b, 0x4c],
        };
        let inputs = canonical_public_inputs(this, config, [0xa1, 0xa2], [0xb1], [0xd1], effects);
        assert_eq(
            inputs,
            [
                0xc0, 0x0e, 0xa1, 0xa2, 0xb1, 0xd1, 0x1a, 0x1b, 0x2a, 0x2b, 0x3a, 0x9b, 0x4a, 0x4b,
                0x4c,
            ],
        );

        // the seed shape, R = P = A = 0: the npk_app_hash field is kept, as 0
        let seed = PssEffects {
            read_leaves: [],
            nullifiers: [],
            new_note_hashes: [0x3a],
            npk_app_hash: 0,
            app_outputs: [],
        };
        assert_eq(
            canonical_public_inputs(this, config, [], [0xb1], [], seed),
            [0xc0, 0x0e, 0xb1, 0x3a, 0],
        );
    }
}
