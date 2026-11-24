//! The state mode `node` on the sidecar path: [`NodeRow`], one `values` row per key.

use super::*;
use crate::bind::Elem;
use crate::error::Refusal;
use crate::field::Fr;
use crate::manifest::KeyRef;
use crate::store::Txn;
use crate::store::rules;

/// The state mode `node` (the default): one `values` row per key at each
/// node, written under the write rule, its replaced vector sealed into the
/// request row for the rollback.
pub struct NodeRow;

impl StateHolder for NodeRow {
    fn noun(&self) -> &'static str {
        "node-held"
    }

    /// Refuses (400) a node-held key when the store holds no `values` table
    /// (the local store; `Store::holds_values`), naming the key: at
    /// REGISTER (section 4 step 3), instead of every round on the key
    /// failing at the commit (500, after a full MPC round and a proof at all
    /// three nodes). In a deployment where one node runs such a store and
    /// the other two a store with `values`, that late failure would commit
    /// the round at two nodes and not the third, and every later round on
    /// the key would be refused at the handshake. A seq 0 body refused here
    /// still joins the registration handshake with its refusal, so the other
    /// two nodes refuse 400 too; the commit's own refusal stays as a second
    /// line.
    fn check_store(&self, keys: &[KeyRef], holds_values: bool) -> Result<(), Refusal> {
        refuse_without_values(keys, holds_values)
    }

    fn note_hash(&self, at: &StateCtx<'_>, key: &str) -> Result<Option<Fr>, Refusal> {
        Ok(at.store.value(at.namespace, key)?.map(|row| row.note_hash))
    }

    fn load(
        &self,
        at: &StateCtx<'_>,
        keyref: KeyRef,
        key: &str,
        _round: &mut RoundEntries,
    ) -> Result<Held, Refusal> {
        let row = at.store.value(at.namespace, key)?.ok_or_else(|| {
            Refusal::conflict(format!("{keyref} = `{key}`: no value at this key"))
        })?;
        Ok(Held {
            vec: row.vec,
            note_hash: row.note_hash,
        })
    }

    fn summand(&self, key: &str) -> Option<String> {
        Some(format!("value `{key}`"))
    }

    fn mark_loaded(&self, txn: &mut Txn, key: &str) {
        txn.loaded(key);
    }

    fn stage(
        &self,
        at: &StateCtx<'_>,
        txn: &mut Txn,
        key: &str,
        vec: Vec<Elem>,
        note_hash: Fr,
        round: &mut RoundEntries,
    ) -> Result<(), Refusal> {
        let created = at.store.value(at.namespace, key)?.is_none();
        // the write rule, and step 13's sealed replaced vector
        rules::stage_store(at.store, at.keys, txn, key, vec, note_hash)?;
        round.stored(key, created);
        Ok(())
    }
}

/// The store check of both node-held holders: 400 naming the first key when
/// the store holds no `values` table (nor `tip_versions`).
pub(super) fn refuse_without_values(keys: &[KeyRef], holds_values: bool) -> Result<(), Refusal> {
    match keys.first() {
        Some(key) if !holds_values => Err(Refusal::bad_request(format!(
            "field `state`: {key} has the state mode `node`, and this node's store \
             backend holds no `values` table (the local store serves client-held keys only); \
             a namespace with node-held keys runs on nodes with the Postgres store"
        ))),
        _ => Ok(()),
    }
}
