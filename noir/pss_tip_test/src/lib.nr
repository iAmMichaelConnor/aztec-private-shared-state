//! What every tip contract suite shares (the library's
//! `pss_public_contract_test` and each tip example's test package): the test
//! network that signs receipts, results and REGISTER answers as the nodes
//! would (`nodes`), the pins of its keys, the proof capsule, stand-in sealed
//! thirds, the signatures over a result, a key set rotation and the
//! `configure` answer, the transaction shape and metered gas the
//! hidden-round-type cases compare (`shape`), and a tip app's queue and
//! slots as its suite reads them, with the post-condition of a refused call
//! (`queue`), secret-shared receipt intake's sharing and receipts
//! (`sharing`), the secret-shared on-chain intake's fixtures
//! (`shared_onchain`), a private outcome's landed result and opened log
//! (`outcome`), and the last transaction's effects as a suite checks
//! them (`tx_effects`, which the sidecar examples' suites use too). Test-only: no app contract depends on it (the test
//! contracts `pss_public_contract_test` and `pss_probe` do).
//!
//! The proofs: recursive proof verification is a no-op during TXE witness
//! execution, so a suite stages a dummy vk whose hash its contract pins and a
//! zero proof (`stage_proof`); the vk pin in front of the verification runs
//! for real, and so does everything after it. The signatures are real.
pub mod audit;
pub mod nodes;
pub mod outcome;
pub mod queue;
pub mod shape;
pub mod shared_onchain;
pub mod sharing;
pub mod tx_effects;

use aztec::oracle::capsules;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::ToField;
use aztec::test::helpers::test_environment::TestEnvironment;
use aztec::test::helpers::txe_oracles;
use nodes::{NODE_SIG, NODE_SIG_PK, public_key, sign_result};
use pss_contract::{CAPSULE_SLOT_PROOF, ProofData};
use pss_public_contract::{CircuitPins, KeySet, NODES, RegistryAnswer, StaleBlocks, TipConfig, TipPins};
use pss_public_contract::key_epoch::rotation_message;
use pss_public_contract::configure::manifest_message;
use pss_public_contract::chain_state::SealedThirds;
use pss_public_contract::outcome::OutcomeTx;
use pss_public_contract::result::{machine_request_id, result_message, ResultSignature};

/// The gas a probe gives the call it attempts (a test-only
/// knob, the probe contract's `try_skip` and the library suite's probes):
/// 2,000,000 L2 and 300,000 DA, several times what the library suite's
/// `apply`, `append` and an app's `skip()` use (the transaction has 6,540,000
/// L2 and 786,432 DA in the TXE), and bounded rather than everything left:
/// an attempted call that halts exceptionally deep inside (the re-entrant
/// `skip()` meeting the static-call rule) consumes its whole allotment, and
/// with everything allotted the probe could not return its answer. Too small
/// and a call the library accepts would fail for gas and read as a refusal;
/// the suite's positive probes (a `try_skip` and a `try_apply` that land)
/// show the bound suffices.
pub global PROBE_L2_GAS: u32 = 2000000;
pub global PROBE_DA_GAS: u32 = 300000;

/// The `TipConfig` that pins the test network's `sig` keys.
pub fn tip_config(stale_blocks: StaleBlocks, npk_app_hash: Field) -> TipConfig {
    TipConfig { stale_blocks, node_sig_keys: NODE_SIG_PK, npk_app_hash }
}

/// The contract manifest hash the test deployments pin: a stand-in, since
/// no contract reads the manifest itself; `configure` checks the nodes'
/// signatures over it.
pub global MANIFEST_HASH: Field = 0x6d616e6966657374;

/// The constructor's `TipPins` over the test network's `sig` keys: the
/// stand-in manifest hash, the package list and each listed package's vk
/// hash.
pub fn tip_pins<let P: u32>(
    stale_blocks: StaleBlocks,
    packages: [Field; P],
    vk_hashes: [Field; P],
) -> TipPins<P> {
    TipPins {
        stale_blocks,
        node_sig_keys: NODE_SIG_PK,
        circuits: CircuitPins { manifest_hash: MANIFEST_HASH, packages, vk_hashes },
    }
}

/// The REGISTER answer node by node, as the test network signs it for a
/// contract manifest of `namespace` whose hash and package list are
/// `circuits`', at `seq`: node i's signature over the manifest result
/// message. The answer carries neither hash: `configure` checks the
/// signatures over the constructor's.
pub unconstrained fn manifest_answer<let P: u32>(
    namespace: AztecAddress,
    circuits: CircuitPins<P>,
    npk_app_hash: Field,
    seq: Field,
) -> RegistryAnswer {
    let packages_hash = circuits.packages_hash();
    let mut signatures = [[0; 4]; NODES];
    for i in 0..NODES {
        let message = manifest_message(
            namespace.to_field(),
            circuits.manifest_hash,
            packages_hash,
            npk_app_hash,
            seq,
            i,
        );
        signatures[i] = sign_result(NODE_SIG[i], message);
    }
    RegistryAnswer { seq, signatures }
}

/// The `configure` answer of a deployment whose contract manifest was
/// registered with the constructor's hash and list: its first REGISTER's
/// answer, at seq 0.
pub unconstrained fn configure_answer<let P: u32>(
    namespace: AztecAddress,
    pins: TipPins<P>,
    npk_app_hash: Field,
) -> RegistryAnswer {
    manifest_answer(namespace, pins.circuits, npk_app_hash, 0)
}

/// A dummy verification key, every field `k`: one per circuit a suite pins,
/// so each pin is tested against the others' proofs.
pub unconstrained fn dummy_vk(k: Field) -> [Field; 115] {
    [k; 115]
}

/// Stage the (vk, proof) capsule the result and init functions of `app`
/// load, with `scope` (the submitter) as its scope and a zero proof.
pub unconstrained fn stage_proof(
    env: TestEnvironment,
    app: AztecAddress,
    scope: AztecAddress,
    vk: [Field; 115],
) {
    let data = ProofData { vk, proof: [0; 458] };
    env.private_context_at(app, |context| {
        capsules::store(context.this_address(), CAPSULE_SLOT_PROOF, data, scope);
    });
}

/// The three nodes' signatures over a result for chain request
/// `request_id` of namespace `namespace`, read at `old` with the pinned
/// values `reads` and leaving `new`: node i signs poseidon2(RESULT_DOMAIN,
/// namespace, machine request id, new…, i, sealed_hashes[i]), the machine
/// request id over the old commitments and the pinned values
/// (`result::NodeHeld` for the hashes under node-held state,
/// `chain_state::sealed_hashes` of the thirds under chain-held state).
pub unconstrained fn result_signatures<let R: u32, let W: u32, let Q: u32>(
    namespace: Field,
    request_id: Field,
    old: [Field; R],
    reads: [Field; Q],
    new: [Field; W],
    sealed_hashes: [Field; NODES],
) -> [ResultSignature; NODES] {
    result_signatures_by(NODE_SIG, namespace, request_id, old, reads, new, sealed_hashes)
}

/// `result_signatures` with node i's signature made by the scalar
/// `signers[i]` (a key set after a rotation, or a key no node holds).
pub unconstrained fn result_signatures_by<let R: u32, let W: u32, let Q: u32>(
    signers: [Field; NODES],
    namespace: Field,
    request_id: Field,
    old: [Field; R],
    reads: [Field; Q],
    new: [Field; W],
    sealed_hashes: [Field; NODES],
) -> [ResultSignature; NODES] {
    let machine_id = machine_request_id(request_id, old, reads);
    let mut sigs = [[0; 4]; NODES];
    for i in 0..NODES {
        let message = result_message(namespace, machine_id, new, i, sealed_hashes[i]);
        sigs[i] = sign_result(signers[i], message);
    }
    sigs
}

/// The key set of the `sig` scalars `sig` and the `enc` scalars `enc`,
/// node 0 first.
pub unconstrained fn key_set(sig: [Field; NODES], enc: [Field; NODES]) -> KeySet {
    KeySet { sig: sig.map(|k| public_key(k)), enc: enc.map(|k| public_key(k)) }
}

/// The signatures of a key set rotation of `namespace` to `epoch` under
/// `keys` (`key_epoch::rotation_message`), place i signed by the scalar
/// `signers[i]`; a signer of 0 leaves place i missing (all zeros, which
/// never verifies).
pub unconstrained fn rotation_signatures(
    namespace: AztecAddress,
    epoch: u32,
    keys: KeySet,
    signers: [Field; NODES],
) -> [ResultSignature; NODES] {
    let message = rotation_message(namespace.to_field(), epoch, keys);
    let mut sigs = [[0; 4]; NODES];
    for i in 0..NODES {
        if signers[i] != 0 {
            sigs[i] = sign_result(signers[i], message);
        }
    }
    sigs
}

/// Node i's stand-in sealed third of one chain-held output: [key id 0x4b0 +
/// i, then fields counting up from a base], L fields, distinct per node and
/// per `round` (for L below 0x1000).
pub unconstrained fn thirds<let L: u32>(round: Field) -> SealedThirds<1, L> {
    let mut sealed = [[[0; L]; 1]; NODES];
    for i in 0..NODES {
        let base = round * 0x10000 + (i as Field) * 0x1000;
        for k in 0..L {
            sealed[i][0][k] = base + k as Field;
        }
        sealed[i][0][0] = 0x4b0 + i as Field;
    }
    sealed
}

/// `[new_c]` and the three thirds of one chain-held output, flattened as
/// `chain_state::emit_state_log` logs them: 1 + 3 × L fields.
pub unconstrained fn state_log_payload<let L: u32>(
    new_c: Field,
    sealed: SealedThirds<1, L>,
) -> [Field; 1 + 3 * L] {
    let mut out = [new_c; 1 + 3 * L];
    for i in 0..NODES {
        for k in 0..L {
            out[1 + L * i + k] = sealed[i][0][k];
        }
    }
    out
}

/// The last transaction as the user's client reads it for its outcome
/// notes (`OutcomeTx`): its hash, its unique note hashes and its first
/// nullifier.
pub unconstrained fn last_tx() -> OutcomeTx {
    let effects = txe_oracles::get_last_tx_effects();
    OutcomeTx {
        tx_hash: effects.tx_hash,
        unique_note_hashes: effects.note_hashes,
        first_nullifier: effects.nullifiers.get(0),
    }
}

/// Mine empty blocks until the next block is `block`; fails when it has
/// passed.
pub unconstrained fn mine_until_next_block_is(env: TestEnvironment, block: u32) {
    assert(env.next_block_number() <= block, "block already passed");
    while env.next_block_number() < block {
        env.mine_block();
    }
}
