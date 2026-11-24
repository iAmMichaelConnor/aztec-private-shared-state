//! The consumed set and the CONSUME policies (ARCHITECTURE.md section 3, steps
//! 7 and 15; section 5, invariant 4).
//!
//! Before any source is bound, the state of every key the manifest consumes
//! under `once` is checked against the namespace's consumed set: a consumed
//! state is refused (409) whatever the circuit or inputs. The round's commit
//! adds one entry per such key, `(namespace, note_hash) -> (circuit vk_hash,
//! request_id)`. There is no repeat path through the consumed set: a retry of a
//! committed round is answered by its request id and body hash (FETCH).

use crate::field::{Fr, RequestId};
use crate::manifest::{KeyRef, Manifest, Policy};
use crate::store::ConsumedRow;

// The consumed set is never pruned. Pruning a row would re-admit
// a still-unspent state for a second evaluation, which is the replay the set
// exists to stop; it grows by under 100 bytes per consuming round. The one
// removal is the operator rollback (`store::rules::restore`), which deletes
// every entry the rolled-back request wrote.
pub use crate::store::rules::check_consumed;

// CONSUME policies are `once` (the default for every consumed key, in both
// state modes) and `never`; the app chooses per key in the manifest's
// `consume` (manifest.rs). `once`: the loaded state may be transitioned
// once, ever; any second request on it is 409 whatever its circuit or inputs.
// `never` (client-held keys only): untracked, neither checked nor recorded. The
// rule for choosing is the one-evaluation leakage rule: a holder of a state gets
// one evaluation of the round's public outputs, with inputs of their choice, so
// ask what one evaluation reveals; `never` is safe only when the outputs reveal
// nothing that depends on the state, since it allows unlimited evaluations.
/// The keys whose state the round must check and consume: those the manifest
/// lists under `once`, in manifest order. `never` keys are skipped.
pub fn once_keys(manifest: &Manifest) -> Vec<KeyRef> {
    manifest
        .consume_policies()
        .into_iter()
        .filter(|(_, policy)| *policy == Policy::Once)
        .map(|(key, _)| key)
        .collect()
}

/// The consumed entries a round adds: one per [`once_keys`] key, from
/// `loaded`, the note hash of each loaded key's value (the `values` row's for a
/// node-held key, the record's for a client-held one). A key the round did not
/// load is skipped (the manifest check makes every consumed key a loaded one).
pub fn consumed_rows(
    manifest: &Manifest,
    loaded: &[(KeyRef, Fr)],
    circuit: Fr,
    request_id: RequestId,
) -> Vec<ConsumedRow> {
    once_keys(manifest)
        .into_iter()
        .filter_map(|key| loaded.iter().find(|(k, _)| *k == key))
        .map(|(_, note_hash)| ConsumedRow {
            note_hash: *note_hash,
            circuit,
            request_id,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;
    use crate::error::Refusal;
    use crate::field::fr_to_hex;
    use crate::manifest::Manifest;
    use crate::store::StoreRead;
    use crate::store::tests::{id, ns, round, shared};
    use crate::store::{MemoryStore, Store};
    use serde_json::json;

    const FINISH: u64 = 0xf1;
    const OPEN_DOOR: u64 = 0xd0;

    // A client-held round in the shape of Monty Hall's finish: it loads the game
    // state and stores nothing.
    fn finish_manifest(policy: &str) -> Manifest {
        let mut consume = json!({ "key": "$state_keys.reads[0]" });
        if !policy.is_empty() {
            consume["policy"] = json!(policy);
        }
        let v = json!({
            "manifest": 1,
            "circuit": "monty_hall_finish",
            "namespace_param": "namespace",
            "state_keys": { "reads": 1, "writes": 0 },
            "witness": [
                { "param": "namespace", "from": { "PUBLIC": "$namespace" } },
                { "param": "switch_door", "from": { "PUBLIC": "switch_door" } },
                { "param": "state", "from": { "LOAD": "$state_keys.reads[0]", "slice": [0, 2], "len": 2 } }
            ],
            "outputs": [],
            "state": { "$state_keys.reads[0]": "client" },
            "consume": [consume]
        });
        Manifest::parse(&v).unwrap()
    }

    // One node's view of a finish round on the record with note hash `state`:
    // the consumed check before LOAD, then the commit with the policy's rows.
    fn run_finish(
        store: &MemoryStore,
        manifest: &Manifest,
        circuit: u64,
        n: u8,
        state: Fr,
    ) -> Result<(), Refusal> {
        for key in once_keys(manifest) {
            assert_eq!(key, KeyRef::Read(0));
            check_consumed(store, ns(), state, Fr::from(circuit))?;
        }
        let rows = consumed_rows(
            manifest,
            &[(KeyRef::Read(0), state)],
            Fr::from(circuit),
            id(n),
        );
        let mut txn = store.begin(ns());
        for row in rows {
            txn.consume(row);
        }
        txn.put_request(crate::store::tests::new_request(n, 0));
        store.commit(txn)
    }

    #[test]
    fn the_default_policy_is_once() {
        let m = finish_manifest("");
        assert_eq!(m.consume_policies(), [(KeyRef::Read(0), Policy::Once)]);
    }

    #[test]
    fn monty_finish_replay_is_refused() {
        let store = MemoryStore::new();
        let m = finish_manifest("once");
        let state = Fr::from(0x77u64);
        run_finish(&store, &m, FINISH, 1, state).unwrap();
        // The same record again (switch flipped, a fresh request id): 409.
        let err = run_finish(&store, &m, FINISH, 2, state).unwrap_err();
        assert_eq!(err.class, ErrorClass::Conflict);
        assert!(err.message.contains("already consumed"), "{}", err.message);
        assert!(!err.message.contains("another circuit"), "{}", err.message);
        assert!(!err.message.contains(&id(1).to_string()), "{}", err.message);
        let row = store.consumed(ns(), state).unwrap().unwrap();
        assert_eq!((row.circuit, row.request_id), (Fr::from(FINISH), id(1)));
    }

    #[test]
    fn another_circuit_on_a_consumed_state_is_refused_naming_it() {
        let store = MemoryStore::new();
        let state = Fr::from(0x77u64);
        run_finish(&store, &finish_manifest("once"), FINISH, 1, state).unwrap();
        let err = run_finish(&store, &finish_manifest("once"), OPEN_DOOR, 2, state).unwrap_err();
        assert_eq!(err.class, ErrorClass::Conflict);
        assert!(
            err.message.contains("another circuit")
                && err.message.contains(&fr_to_hex(Fr::from(FINISH)))
                && !err.message.contains(&id(1).to_string()),
            "{}",
            err.message
        );
    }

    #[test]
    fn never_is_untracked() {
        let store = MemoryStore::new();
        let m = finish_manifest("never");
        let state = Fr::from(0x78u64);
        run_finish(&store, &m, FINISH, 1, state).unwrap();
        run_finish(&store, &m, FINISH, 2, state).unwrap();
        assert!(store.consumed(ns(), state).unwrap().is_none());
        assert!(once_keys(&m).is_empty());
        // A `never` key is not checked either: a state another round consumed
        // under `once` still runs under `never`.
        run_finish(&store, &finish_manifest("once"), OPEN_DOOR, 3, state).unwrap();
        run_finish(&store, &m, FINISH, 4, state).unwrap();
        assert_eq!(
            store.consumed(ns(), state).unwrap().unwrap().request_id,
            id(3)
        );
    }

    #[test]
    fn a_store_over_a_consumed_node_held_key_is_accepted() {
        let store = MemoryStore::new();
        let seed = Fr::from(0x5eedu64);
        // pss_seed writes the seed; amm_init consumes it (once) and writes the pool.
        round(&store, 1, &[], &[], &[("seed", vec![shared(1)], seed)]).unwrap();
        round(
            &store,
            2,
            &["seed"],
            &[seed],
            &[("pool", vec![shared(2)], Fr::from(2u64))],
        )
        .unwrap();
        assert_eq!(
            check_consumed(&store, ns(), seed, Fr::from(0xc1u64))
                .unwrap_err()
                .class,
            ErrorClass::Conflict
        );
        // A new pss_seed round writes the seed key without loading it.
        round(
            &store,
            3,
            &[],
            &[],
            &[("seed", vec![shared(3)], Fr::from(3u64))],
        )
        .unwrap();
        assert_eq!(
            store.value(ns(), "seed").unwrap().unwrap().request_id,
            id(3)
        );
    }
}
