//! The state mode `client`: [`ClientRecord`], a sealed record the requester carries.

use super::*;
use crate::bind::Elem;
use crate::error::Refusal;
use crate::field::Fr;
use crate::manifest::KeyRef;
use crate::record;
use crate::store::Txn;

/// The state mode `client`: a record the requester carries, sealed by each
/// node to the requester's key, and only for intake direct (the manifest's
/// path rule). Every request that supplies or stores one is signed by its
/// requester.
pub struct ClientRecord;

impl StateHolder for ClientRecord {
    fn noun(&self) -> &'static str {
        "client-held"
    }

    fn needs_requester(&self) -> bool {
        true
    }

    fn note_hash(&self, at: &StateCtx<'_>, key: &str) -> Result<Option<Fr>, Refusal> {
        Ok(at.supplied(key).map(|r| r.note_hash.fr()))
    }

    fn check_dead(&self, at: &StateCtx<'_>, key: &str) -> Result<(), Refusal> {
        at.check_supplied_dead(key)
    }

    fn load(
        &self,
        at: &StateCtx<'_>,
        keyref: KeyRef,
        key: &str,
        round: &mut RoundEntries,
    ) -> Result<Held, Refusal> {
        let record = round.open_record(at, keyref, key)?;
        let note_hash = record.note_hash.fr();
        let owner = at
            .requester
            .expect("step 4 requires a requester for a client-held record");
        let vec = record::open(
            at.keys,
            at.namespace,
            key,
            note_hash,
            owner,
            record.c_i.as_slice(),
        )?;
        Ok(Held { vec, note_hash })
    }

    fn check_supplied(&self, at: &StateCtx<'_>, round: &RoundEntries) -> Result<(), Refusal> {
        round.refuse_unopened(at, self.noun())
    }

    fn summand(&self, key: &str) -> Option<String> {
        Some(format!("record `{key}`"))
    }

    fn stage(
        &self,
        at: &StateCtx<'_>,
        _txn: &mut Txn,
        key: &str,
        vec: Vec<Elem>,
        note_hash: Fr,
        round: &mut RoundEntries,
    ) -> Result<(), Refusal> {
        // 13. seal, for the requester
        let owner = at
            .requester
            .expect("step 4 requires a requester for a client-held output");
        let c_i = record::seal(at.keys, at.namespace, key, note_hash, owner, &vec);
        round.sealed(key, note_hash, c_i);
        Ok(())
    }
}
