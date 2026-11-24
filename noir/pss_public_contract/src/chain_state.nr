//! Chain-held state: the option where the chain itself holds a tip app's
//! state, as the nodes' sealed thirds in a public log of every apply. It
//! suits a small fixed-size state. Recovery needs the nodes' keys, the package
//! that decodes the log, and a matching log from the last 64 queue entries
//! before the head or from the init round. Only an app that opts into
//! chain-held state uses this module. The shared result path
//! (`crate::result`, `crate::init`) is generic over sealing.
//!
//! It is one implementation of the result path's state-mode seam
//! (`result::Sealing`) for `SealedThirds<T, L>`: the thirds' hashes,
//! `H(sealed_i)`, which each node's result signature covers
//! (`sealed_hashes`), and the sealed-thirds log `apply` and `apply_init`
//! emit after their writes (`emit_state_log`, `PSS_STATE`).
//!
//! An app picks the state mode by the value it hands the library's entry
//! points (`result::check_round`, `result::apply_round`,
//! `init::process_init`, `init::apply_init`): `result::NodeHeld {}` for
//! node-held state, or its sealed thirds for chain-held state, which its
//! wrappers take as their own argument:
//!
//! ```noir
//! #[external("private")]
//! fn process_result(result: PoolResult, sealed: PoolThirds, signatures: [ResultSignature; 3]) {
//!     let checked = check_round(rounds(self.storage.configured.read(), self.storage.pool).swap,
//!         self.context, self.msg_sender(), result, sealed, signatures);
//!     self.enqueue_self.apply(checked, sealed);
//! }
//! ```
use crate::config::NODES;
use crate::result::Sealing;
use aztec::context::PublicContext;
use aztec::protocol::hash::{compute_log_tag, poseidon2_hash};

/// The separator of the sealed-thirds log's tag:
/// `compute_log_tag(request_id, PSS_STATE)` (docs/ARCHITECTURE.md section 6;
/// sidecar-tip's `chain_state::PSS_STATE`), a u32 for the same reason as
/// `domains::REQUEST_DOMAIN`: ASCII "PSS" and the index 2.
///
/// `PSS_STATE = 0x50535302`: like `REQUEST_DOMAIN` it only has
/// to differ from every other tag separator the namespace contract emits
/// under, so the chain reader never takes another log for the state. The
/// chain reader fetches the log by this tag, so it is part of the interface
/// with sidecar-tip.
pub global PSS_STATE: u32 = 0x50535302;

/// `sealed[i][t]`: node i's third of chain-held output t, the fields
/// `[key id, ct…, tag]` of `NodeResult.records[t].c_i`, L per third.
pub type SealedThirds<let T: u32, let L: u32> = [[[Field; L]; T]; NODES];

/// `record_hashes[i]` of one sealed third: Poseidon2 over its fields
/// `[key id, ct…, tag]` (sidecar-core `record::record_hash`).
pub fn record_hash<let L: u32>(third: [Field; L]) -> Field {
    poseidon2_hash(third)
}

/// `H(sealed_i)` from node i's record hashes in manifest order: Poseidon2
/// over the list (a one-element list for one third), 0 when there are none.
pub fn sealed_hash_of_record_hashes<let T: u32>(record_hashes: [Field; T]) -> Field {
    if T == 0 {
        0
    } else {
        poseidon2_hash(record_hashes)
    }
}

/// `H(sealed_i)` for each node from its thirds, the hashes
/// `result::assert_result_signatures` takes.
pub fn sealed_hashes<let T: u32, let L: u32>(sealed: SealedThirds<T, L>) -> [Field; NODES] {
    let mut hashes = [0; NODES];
    for i in 0..NODES {
        hashes[i] = sealed_hash_of_record_hashes(sealed[i].map(|third| record_hash(third)));
    }
    hashes
}

impl<let T: u32, let L: u32> Sealing for SealedThirds<T, L> {
    fn sealed_hashes(self) -> [Field; NODES] {
        sealed_hashes(self)
    }

    /// The sealed-thirds log (`emit_state_log`), on `ok` and on not `ok`.
    fn log<let W: u32>(
        self,
        context: PublicContext,
        request_id: Field,
        new_commitments: [Field; W],
    ) {
        emit_state_log(context, request_id, new_commitments, self);
    }
}

/// The sealed-thirds log `(new_commitments, sealed)` under
/// `compute_log_tag(request_id, PSS_STATE)`.
///
/// The sealed-thirds log is the state's storage path under chain-held
/// state (not a result event). Tag `compute_log_tag(request_id,
/// PSS_STATE)` with the chain request id, so the chain reader fetches it by
/// the id the queue holds and keeps it only when the AVM-set emitting
/// address is this contract. Body: the new commitments, then `sealed[i][t]`
/// node by node, output by output, so the log names the note hash each
/// record is sealed under (its AD) and the reader needs no other read to
/// rebuild the records. Emitted on `ok` and on not `ok`: a failed round
/// keeps every key it writes at the value its slot holds (`process_result`
/// asserts it), so its log re-seals the unchanged state under the unchanged
/// commitment, the slot and the log agree, and the latest log is the one to
/// reload from. Size: 1 + W + 3·T·L fields with the tag, bounded at REGISTER
/// by MAX_PUBLIC_LOG_SIZE_IN_FIELDS (4,094: the transaction's 4,096-field
/// public-log payload less this log's 2-field header), so not re-checked
/// here; the app hook's own logs share what is left.
///
/// Chain-held state and `enc` rotation. The nodes seal each third to their
/// current `enc` key and open thirds under the previous key only for the
/// rotation's grace window, and at the tip only an `apply` re-seals the
/// state. A namespace with no `apply` for a whole grace window keeps its
/// slot commitment, but no node can open its last logged thirds: the state
/// is lost and the app is frozen. So every chain-held namespace needs one
/// `apply` per grace window; the operator's keep-alive for an idle namespace
/// is a statically valid request that fails against the state (an AMM swap
/// with an unreachable `min_out`), which lands as an `ok = false` no-op and
/// re-seals the state under the new key (DESIGN.md, "Rotating a node's
/// `enc` key").
pub fn emit_state_log<let W: u32, let T: u32, let L: u32>(
    context: PublicContext,
    request_id: Field,
    new_commitments: [Field; W],
    sealed: SealedThirds<T, L>,
) {
    context.emit_public_log_unsafe(compute_log_tag(request_id, PSS_STATE), (new_commitments, sealed));
}

mod test {
    use super::{sealed_hash_of_record_hashes, sealed_hashes};
    use aztec::protocol::hash::poseidon2_hash;

    #[test]
    fn sealed_hash_shapes() {
        assert_eq(sealed_hash_of_record_hashes([]), 0);
        assert_eq(sealed_hash_of_record_hashes([5]), poseidon2_hash([5]));
        let thirds = [[[1, 2, 3]], [[4, 5, 6]], [[7, 8, 9]]];
        let h = sealed_hashes(thirds);
        assert_eq(h[1], poseidon2_hash([poseidon2_hash([4, 5, 6])]));
        assert_eq(sealed_hashes::<0, 3>([[], [], []]), [0, 0, 0]);
    }
}
