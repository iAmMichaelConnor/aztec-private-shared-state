//! The intakes of a tip round, as the circuit sees them: each returns only
//! its binding, the value that ties the proof to the request the queue
//! holds. The key is the round's whatever the intake (`super::slot::load`),
//! and the app's round function takes the app inputs as one array in ABI
//! order, the array the binding hashes.
//!
//! - The non-secret-shared intakes, on-chain intake (`onchain`) and receipt intake
//!   (`receipt`): the contract's intake function logged the app inputs and
//!   the request's nonce, or the nodes signed receipts over them and keep
//!   them; either way the round takes the app inputs and the nonce as
//!   private witnesses and outputs `plain(...)`, the chain request id over
//!   them, which apply requires to equal requests[head]. One compiled
//!   circuit serves both: the intakes differ in how the inputs reach the
//!   nodes, never in the round's layout.
//! - The secret-shared intakes: the round takes C (PUBLIC `$inputs_hash`), the app
//!   inputs, the reserved `$partial_note` (the request's partial note),
//!   `$outcome_key` and `$outcome_tag`, and the `$blinding` as private
//!   witnesses (`SharedIntake`),
//!   flags first whether C opens to them (`SharedIntake::opens`, the app's
//!   mismatch code) and outputs `shared(namespace, vk_hash, C)`
//!   (`SharedIntake::request_id`); both secret-shared intakes compute
//!   the same C, so one compiled circuit serves both. The user's request
//!   function already proved that what the nodes hold opens C
//!   (secret-shared receipt intake: `summand_commitment` and
//!   `sharing_digest`, over the shares, the layout and the clear values,
//!   which the receipts sign; secret-shared on-chain intake: the encoding),
//!   so only nodes that change their shares make a round that does not
//!   open.
//! - The init round, never queued: `plain(namespace, vk_hash, inputs, 0)`,
//!   the fixed init request id over its app inputs.
//!
//! The non-secret-shared intakes' chain request id is the one every party computes
//! (docs/ARCHITECTURE.md section 6; testvectors/chain_request_id.json):
//! poseidon2([namespace, vk_hash, inputs_hash, user_nonce]) with
//! inputs_hash = poseidon2(inputs) and user_nonce a salt the user draws at
//! random per request. No requester enters it (docs/ARCHITECTURE.md
//! section 6, "The hidden requester"). Every hash here is total's fixed-length
//! p2_hash, which equals Aztec's poseidon2_hash and has no failure source
//! (Aztec's variable-length form is input-falsifiable). The contract
//! library (pss_public_contract) calls these same functions.

use super::derived::Layout;
use total::cmp::eq;
use total::hash::p2_hash;

/// inputs_hash = poseidon2(inputs), the app inputs in ABI order. Total.
pub fn inputs_hash<let I: u32>(inputs: [Field; I]) -> Field {
    p2_hash(inputs)
}

/// The non-secret-shared intakes' chain request id, poseidon2([namespace, vk_hash,
/// inputs_hash, user_nonce]). Total.
pub fn chain_request_id(namespace: Field, vk_hash: Field, inputs_hash: Field, user_nonce: Field) -> Field {
    p2_hash([namespace, vk_hash, inputs_hash, user_nonce])
}

/// The non-secret-shared intakes' binding: the chain request id over the private app
/// inputs (in ABI order) and user_nonce under vk_hash, the round's public
/// vk_hash input (a circuit cannot know its own verification key's hash;
/// process_result checks it against the Config pin). user_nonce is not
/// checked: any value gives some request id, and apply compares it with
/// the queue.
///
/// Total: two p2_hash (permutations and additions).
pub fn plain<let I: u32>(
    namespace: Field,
    vk_hash: Field,
    inputs: [Field; I],
    user_nonce: Field,
) -> Field {
    chain_request_id(namespace, vk_hash, inputs_hash(inputs), user_nonce)
}

/// The inputs commitment of the secret-shared intakes, C = poseidon2([inputs...,
/// blinding]): the app inputs in ABI order, then the reserved
/// `$partial_note`, `$outcome_key` and `$outcome_tag`, then the `$blinding`
/// the user draws per request. Total.
pub fn commit<let I: u32>(inputs: [Field; I], blinding: Field) -> Field {
    p2_hash(inputs.concat([blinding]))
}

/// The secret-shared intakes' chain request id, poseidon2([namespace, vk_hash, C]),
/// with no nonce (the blinding makes it unique). Total.
pub fn shared(namespace: Field, vk_hash: Field, c: Field) -> Field {
    p2_hash([namespace, vk_hash, c])
}

/// ASCII "sidecar.summands" as a big-endian integer: the first element of a
/// summand commitment (`summand_commitment`).
pub global SUMMANDS_DOMAIN: Field = 0x736964656361722e73756d6d616e6473;

/// ASCII "sidecar.sharing" as a big-endian integer: the first element of a
/// sharing digest (`sharing_digest`).
pub global SHARING_DOMAIN: Field = 0x736964656361722e73686172696e67;

/// The commitment to one summand vector of a secret-shared receipt
/// request, `S_j = poseidon2([SUMMANDS_DOMAIN, s_j..., salt_j])`. The
/// client splits the request's shared values and its `$blinding` into
/// three Rep3 summand vectors `s_0 + s_1 + s_2` (one element per shared
/// value in C's order, then the blinding's) and draws a salt per vector;
/// node i holds `s_i` and `s_{i-1}` with their salts, so each `S_j` is
/// checked by both nodes that hold `s_j`. The node that lacks `s_j` cannot
/// test guesses of a shared value against `S_j`: the vector's last element
/// is a summand of the uniform blinding, which that node cannot know, so
/// `S_j` hides the values as C does. The salt is a second layer. The
/// machine (sidecar-tip `ids::summand_commitment`) and pss-client compute
/// the same value (testvectors/shared_intake.json). Total.
pub fn summand_commitment<let L: u32>(summands: [Field; L], salt: Field) -> Field {
    p2_hash([SUMMANDS_DOMAIN].concat(summands).concat([salt]))
}

/// The sharing digest of a secret-shared receipt request,
/// `D = poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kind_1, …, kind_M,
/// clear_1, …, clear_Q])`: the three summand commitments, the kind of each
/// of C's M values (`CLEAR` 0, `CHOSEN` 1) and the Q clear values in C's
/// order. Every node's receipt signs it, each node computing it from the
/// layout it derives from the round's manifest and the clear inputs it
/// stores, and the user's request function recomputes it from its layout
/// global and C's values, so three receipts and an accepted request mean
/// the nodes hold a sharing of C's shared values under C's layout and C's
/// clear values. The machine (sidecar-tip `ids::sharing_digest`) and
/// pss-client compute the same value (testvectors/shared_intake.json).
/// Total.
pub fn sharing_digest<let M: u32, let Q: u32, let X: u32>(
    commitments: [Field; 3],
    layout: Layout<M, Q, X>,
    clear: [Field; Q],
) -> Field {
    p2_hash([SHARING_DOMAIN].concat(commitments).concat(layout.kinds.map(|k: u8| k as Field)).concat(clear))
}

/// What a secret-shared intake hands a round besides its app inputs
/// (docs/ARCHITECTURE.md section 6, "The MPC receipt check"): C and the
/// values C commits to after the app inputs, each a private witness. The
/// round's main declares its parameters in C's order: the app inputs, then
/// `partial_note`, `outcome_key` and `outcome_tag`, then `blinding` (the ABI
/// walk gives the client, the nodes and the contract that order).
pub struct SharedIntake {
    /// C, PUBLIC `$inputs_hash`: the commitment the queued request carries
    pub inputs_hash: Field,
    /// INPUT_SHARED `$partial_note`: the partial note the round completes,
    /// `poseidon2_hash_with_separator([owner, rho],
    /// DOM_SEP__PARTIAL_NOTE_COMMITMENT)` (`super::outcome::
    /// partial_commitment`), computed by the user's request function.
    pub partial: Field,
    /// INPUT_SHARED `$outcome_key`: the outcome's encryption key
    pub outcome_key: Field,
    /// INPUT_SHARED `$outcome_tag`: the outcome log's tag
    pub outcome_tag: Field,
    /// INPUT_SHARED `$blinding`: C's last element
    pub blinding: Field,
}

impl SharedIntake {
    /// Whether C opens to `inputs` (the app inputs before `$partial_note`, in
    /// ABI order), then `$partial_note`, `$outcome_key` and `$outcome_tag`, under
    /// `$blinding`: the round's first check, a flag folded into `ok` with the
    /// app's mismatch code, never an assertion, so the round stays total:
    /// shares that do not open make a no-op round and the queue moves. The
    /// request function proved the user's sharing opens C, so a round that
    /// does not open comes from nodes that changed their shares. Total: one
    /// p2_hash and one equality.
    pub fn opens<let I: u32>(self, inputs: [Field; I]) -> bool {
        let values = inputs.concat([self.partial, self.outcome_key, self.outcome_tag]);
        eq(commit(values, self.blinding), self.inputs_hash)
    }

    /// The secret-shared chain request id the round outputs, `shared(namespace,
    /// vk_hash, C)`: from values every node checked against requests[head]
    /// before the round, so a mismatch never fails apply's head check. Total.
    pub fn request_id(self, namespace: Field, vk_hash: Field) -> Field {
        shared(namespace, vk_hash, self.inputs_hash)
    }
}

mod tests {
    use super::{
        chain_request_id, commit, inputs_hash, plain, shared, sharing_digest, SHARING_DOMAIN, SharedIntake,
        summand_commitment, SUMMANDS_DOMAIN,
    };
    use crate::test_support::ascii;
    use crate::tip::derived::{CHOSEN, CLEAR, Layout};
    use total::hash::p2_hash;

    global NS: Field = 0xc0ffee;

    #[test]
    fn the_request_id_is_poseidon2_of_the_preimage() {
        // p2_hash is Aztec's poseidon2_hash (total's KATs, and
        // testvectors/noir/tip_round_vectors on chain_request_id.json), so
        // the contract and the nodes compute the same ids.
        let ih = inputs_hash([25000, 0, 33000]);
        assert_eq(ih, p2_hash([25000, 0, 33000]));
        let id = chain_request_id(NS, 0x5a, ih, 3);
        assert_eq(id, p2_hash([NS, 0x5a, ih, 3]));
        // every component changes it
        assert(id != chain_request_id(NS + 1, 0x5a, ih, 3));
        assert(id != chain_request_id(NS, 0x5b, ih, 3));
        assert(id != chain_request_id(NS, 0x5a, inputs_hash([25000, 0, 33001]), 3));
        assert(id != chain_request_id(NS, 0x5a, ih, 4));
    }

    #[test]
    fn the_plain_binding_is_the_chain_request_id() {
        let inputs = [25000, 0, 33000];
        assert_eq(plain(NS, 0x5a, inputs, 3), chain_request_id(NS, 0x5a, inputs_hash(inputs), 3));
    }

    #[test]
    fn the_shared_binding_is_the_id_over_c() {
        let c = commit([25000, 0, 33000], 0xb1);
        assert_eq(c, p2_hash([25000, 0, 33000, 0xb1]));
        assert(c != commit([25000, 0, 33000], 0xb2));
        assert_eq(shared(NS, 0x5a, c), p2_hash([NS, 0x5a, c]));
    }

    #[test]
    fn a_shared_intake_opens_only_to_its_values() {
        let values = [25000, 0, 33000, 0xa11ce, 0x6b, 0x7a];
        let c = commit(values, 0xb1);
        let i = |partial: Field, blinding: Field| SharedIntake {
            inputs_hash: c,
            partial,
            outcome_key: 0x6b,
            outcome_tag: 0x7a,
            blinding,
        };
        assert(i(0xa11ce, 0xb1).opens([25000, 0, 33000]));
        assert(!i(0xa11ce, 0xb1).opens([25001, 0, 33000]));
        assert(!i(0xb0b, 0xb1).opens([25000, 0, 33000]));
        assert(!i(0xa11ce, 0xb2).opens([25000, 0, 33000]));
        assert_eq(i(0xa11ce, 0xb1).request_id(NS, 0x5a), shared(NS, 0x5a, c));
    }

    #[test]
    fn the_sharing_domains_are_their_labels() {
        assert_eq(SUMMANDS_DOMAIN, ascii("sidecar.summands"));
        assert_eq(SHARING_DOMAIN, ascii("sidecar.sharing"));
    }

    // S_j = poseidon2([SUMMANDS_DOMAIN, s_j..., salt_j]): every summand, its
    // place and the salt change it.
    #[test]
    fn a_summand_commitment_is_the_stated_hash() {
        let s = summand_commitment([5, 6, 7], 0x5a17);
        assert_eq(s, p2_hash([SUMMANDS_DOMAIN, 5, 6, 7, 0x5a17]));
        assert(s != summand_commitment([5, 6, 8], 0x5a17));
        assert(s != summand_commitment([6, 5, 7], 0x5a17));
        assert(s != summand_commitment([5, 6, 7], 0x5a18));
    }

    // D = poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds..., clear...]):
    // each S_j's place, every kind and every clear value change it.
    #[test]
    fn the_sharing_digest_binds_the_commitments_the_layout_and_the_clear_values() {
        let layout: Layout<3, 1, 2> = Layout { kinds: [CLEAR, CHOSEN, CHOSEN] };
        let d = sharing_digest([1, 2, 3], layout, [7]);
        assert_eq(d, p2_hash([SHARING_DOMAIN, 1, 2, 3, 0, 1, 1, 7]));
        assert(d != sharing_digest([2, 1, 3], layout, [7]));
        assert(d != sharing_digest([1, 2, 4], layout, [7]));
        // a changed clear value
        assert(d != sharing_digest([1, 2, 3], layout, [8]));
        // the same counts in other places
        let moved: Layout<3, 1, 2> = Layout { kinds: [CHOSEN, CLEAR, CHOSEN] };
        assert(d != sharing_digest([1, 2, 3], moved, [7]));
    }
}
