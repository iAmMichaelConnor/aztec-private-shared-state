//! The dead records: the client-held records a rolled-back round created
//! (ARCHITECTURE.md section 3, step 7 and the rollback path).
//!
//! A rollback abandons the round's branch: the owner re-presents the record the
//! round consumed, and no node signs a round on a record the round created.
//! The operator rollback ([`crate::store::rules::restore`]) writes one entry per
//! record the rolled-back request created, `(namespace, note_hash) ->
//! request_id`, in the commit that marks the request rolled back; step 7
//! refuses (400) a supplied record whose note hash has an entry, before step 8
//! opens it. A later round that creates a record with the same note hash (a
//! circuit that computes the same state again from the re-presented record)
//! deletes the entry in its commit, since that record is then the round's own
//! output. Nothing else removes an entry: the `requests` prune keeps them.

use crate::error::Refusal;
use crate::field::{Fr, RequestId, fr_to_hex};
use crate::store::StoreRead;

/// One dead record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeadRecord {
    /// The note hash of a record the rolled-back request created.
    pub note_hash: Fr,
    /// The rolled-back request.
    pub request_id: RequestId,
}

/// Step 7: refuse (400) the record supplied for `key` when its note hash is
/// dead. The refusal does not name the rolled-back request that created it
/// (a request id scopes FETCH); the node logs it.
pub fn check_dead<R: StoreRead + ?Sized>(
    read: &R,
    namespace: Fr,
    key: &str,
    note_hash: Fr,
) -> Result<(), Refusal> {
    let Some(dead) = read.dead_record(namespace, note_hash)? else {
        return Ok(());
    };
    tracing::info!(
        created_by = %dead.request_id,
        note_hash = %fr_to_hex(note_hash),
        "refused: record of a rolled-back round"
    );
    Err(Refusal::bad_request(format!(
        "key `{key}`: record {} was created by a round that was rolled back",
        fr_to_hex(note_hash),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;
    use crate::store::testing::{client_round, id, node_keys, ns};
    use crate::store::{MemoryStore, rules};

    #[test]
    fn a_record_of_a_rolled_back_round_is_refused_without_its_request() {
        let store = MemoryStore::new();
        let (old, new) = (Fr::from(0x70u64), Fr::from(0x71u64));
        client_round(&store, 1, &[], &[("0xff02", old)]).unwrap();
        client_round(&store, 2, &[old], &[("0xff02", new)]).unwrap();
        check_dead(&store, ns(), "0xff02", new).unwrap();
        rules::restore(&store, &node_keys(), ns(), id(2)).unwrap();

        let err = check_dead(&store, ns(), "0xff02", new).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(
            err.message.contains("key `0xff02`")
                && !err.message.contains(&id(2).to_string())
                && err.message.contains("rolled back"),
            "{}",
            err.message
        );
        // The record the round consumed is live again.
        check_dead(&store, ns(), "0xff02", old).unwrap();
    }
}
