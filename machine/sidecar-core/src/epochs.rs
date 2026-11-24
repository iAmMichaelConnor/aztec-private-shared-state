//! A node's `enc` scalars by contract and epoch, for secret-shared on-chain intake
//! (docs/ARCHITECTURE.md section 6, "Secret-shared on-chain intake"). Each app
//! contract keeps its own `enc_keys[i] = (pk, epoch)` in public storage, and
//! a node rotates its key there with one signed transaction per contract,
//! so a rotation can land in some contracts before others: the node keeps,
//! per contract, the scalar of every epoch a queued request may still name,
//! and the binder derives its pairs with the scalar of the epoch the request
//! log names ([`EpochKeys::scalar`]).
//!
//! ```text
//! signed    the node signed a rotation to its current key at epoch e
//!           (EpochKeys::sign): the scalar is pending; signing e again
//!           replaces it, so a rotation that never lands leaves nothing to clear
//! landed    the node's chain view shows the contract's stored epoch at e under
//!           this scalar's public key, or past e (EpochKeys::land): recorded;
//!           e is then never signed under another scalar
//! retired   the stored epoch is e + 2 and the head has reached the tail read
//!           then (EpochKeys::observe): deleted
//! ```
//!
//! A contract accepts a request naming its stored epoch or the one before
//! it, so once its stored epoch is two ahead of epoch `e`, no new request
//! names `e`, and every queued request that does sits below the tail the
//! node then reads. The node retires `e`'s scalar for that contract once its
//! head reaches that tail. A request naming `e` can enter the queue only
//! once `e` has landed, so the binder takes `e`'s scalar whether the node has
//! observed the landing yet or not.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::field::{FieldHex, Fr};
use crate::grumpkin::{Fq, coordinates, fixed_base_mul};
use crate::keys::{scalar_from_hex, scalar_to_hex};

/// One epoch of one contract: the scalar, whether its rotation is still
/// pending (signed, not yet seen landed), and once the contract's stored
/// epoch is two ahead, the tail the node read then. `Debug` leaves the
/// scalar out; it is overwritten when dropped.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Epoch {
    scalar: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retire_at_head: Option<u64>,
}

impl std::fmt::Debug for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Epoch")
            .field("pending", &self.pending)
            .field("retire_at_head", &self.retire_at_head)
            .finish_non_exhaustive()
    }
}

impl Drop for Epoch {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.scalar.zeroize();
    }
}

impl Epoch {
    fn new(scalar: Fq, pending: bool) -> Self {
        Epoch {
            scalar: scalar_to_hex(scalar),
            pending,
            retire_at_head: None,
        }
    }
}

/// One read of a contract's `enc_keys[i]` and its queue, all at one block:
/// the stored epoch and public key of node `i`, and the queue's head and
/// tail. Read the four from one snapshot: a request appended between a read
/// of the epoch and a later read of the tail would sit at or past that tail
/// with its epoch's scalar retired once the head reaches it, and be refused
/// until `skip()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncKeyObservation {
    /// `enc_keys[i].epoch`: 0 before the node's first key.
    pub epoch: u32,
    /// `(enc_keys[i].x, enc_keys[i].y)`.
    pub pk: (Fr, Fr),
    /// `head.index`.
    pub head: u64,
    /// `tail`.
    pub tail: u64,
}

/// What one observation changed for one contract.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observed {
    /// The epochs recorded: their rotation landed.
    pub recorded: Vec<u32>,
    /// The epochs whose scalar was deleted.
    pub retired: Vec<u32>,
}

/// Every contract's epochs this node holds a scalar for. Serialised as
/// `{"<contract>": {"<epoch>": {"scalar", "pending", "retire_at_head"}}}`
/// (`KeyFiles::epochs_path`), written as the other key files are.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EpochKeys(BTreeMap<FieldHex, BTreeMap<u32, Epoch>>);

impl EpochKeys {
    /// Keep `scalar` pending as this node's key at `epoch` in `contract`:
    /// the node signed the rotation to its public key
    /// (`enc_rotation_message`), which has not been seen landing. Replaces a
    /// pending scalar at that epoch. Signing a recorded epoch again under its
    /// scalar changes nothing; refuses another scalar at a recorded epoch,
    /// and an epoch below the highest recorded one: neither can land.
    pub fn sign(&mut self, contract: Fr, epoch: u32, scalar: Fq) -> Result<(), String> {
        let epochs = self.0.entry(FieldHex(contract)).or_default();
        let hex = scalar_to_hex(scalar);
        if let Some(held) = epochs.get(&epoch)
            && !held.pending
        {
            return if held.scalar == hex {
                Ok(())
            } else {
                Err(format!(
                    "epoch {epoch} of contract {} landed under another key; sign the next epoch",
                    FieldHex(contract)
                ))
            };
        }
        if let Some((&landed, _)) = epochs.iter().rev().find(|(_, held)| !held.pending)
            && epoch < landed
        {
            return Err(format!(
                "epoch {epoch} of contract {} is below its landed epoch {landed}; sign the next \
                 epoch",
                FieldHex(contract)
            ));
        }
        epochs.insert(epoch, Epoch::new(scalar, true));
        Ok(())
    }

    /// Record `scalar` as this node's key at `epoch` in `contract`: its
    /// rotation landed. Replaces a pending scalar at that epoch; refuses
    /// another scalar at an epoch already recorded.
    pub fn record(&mut self, contract: Fr, epoch: u32, scalar: Fq) -> Result<(), String> {
        let epochs = self.0.entry(FieldHex(contract)).or_default();
        let hex = scalar_to_hex(scalar);
        match epochs.get_mut(&epoch) {
            Some(held) if !held.pending && held.scalar != hex => Err(format!(
                "epoch {epoch} of contract {} holds another scalar",
                FieldHex(contract)
            )),
            Some(held) if !held.pending => Ok(()),
            _ => {
                epochs.insert(epoch, Epoch::new(scalar, false));
                Ok(())
            }
        }
    }

    /// The scalar of `epoch` in `contract`, while the node holds it, pending
    /// or recorded: a request names an epoch only once its rotation landed.
    pub fn scalar(&self, contract: Fr, epoch: u32) -> Option<Fq> {
        let held = self.0.get(&FieldHex(contract))?.get(&epoch)?;
        scalar_from_hex(&held.scalar).ok()
    }

    /// The epochs held for `contract`, pending or recorded, in order.
    pub fn epochs(&self, contract: Fr) -> Vec<u32> {
        self.0
            .get(&FieldHex(contract))
            .map(|e| e.keys().copied().collect())
            .unwrap_or_default()
    }

    /// The epochs of `contract` whose rotation is pending, in order.
    pub fn pending(&self, contract: Fr) -> Vec<u32> {
        self.0
            .get(&FieldHex(contract))
            .map(|e| {
                e.iter()
                    .filter(|(_, h)| h.pending)
                    .map(|(&k, _)| k)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The contracts this node holds an epoch of, in order.
    pub fn contracts(&self) -> Vec<Fr> {
        self.0.keys().map(|c| c.fr()).collect()
    }

    // When a node records a contract epoch's scalar: once its rotation
    // lands, never at signing. Signing keeps the scalar pending
    // ([`Self::sign`]); the node records it when its chain view shows the
    // rotation landed. At the stored epoch `S` that is the scalar whose
    // public key the contract stores: the pending one, or else one of the
    // node's `candidates` (its current and previous `enc` scalars), which
    // covers a rotation signed under a scalar a later signature at the same
    // epoch replaced. Below `S` the stored key has moved on, but `S` only
    // climbs one epoch per landed rotation, so every epoch below it landed:
    // its pending scalar, the last the node signed there, is recorded. An
    // epoch above `S` stays pending, and a pending scalar at `S` under
    // another key stays pending too (a later signature at that epoch
    // replaces it). A request naming an epoch already finds its scalar
    // while pending ([`Self::scalar`]), so recording late costs nothing.
    /// Record what landed in `contract`, whose stored epoch for this node is
    /// `stored_epoch` under the public key `stored_pk`; returns the epochs
    /// recorded.
    pub fn land(
        &mut self,
        contract: Fr,
        stored_epoch: u32,
        stored_pk: (Fr, Fr),
        candidates: &[Fq],
    ) -> Vec<u32> {
        if stored_epoch == 0 {
            return Vec::new();
        }
        let epochs = self.0.entry(FieldHex(contract)).or_default();
        let mut recorded = Vec::new();
        for (&e, held) in epochs.iter_mut() {
            if e < stored_epoch && held.pending {
                held.pending = false;
                recorded.push(e);
            }
        }
        let at_stored = epochs.get(&stored_epoch);
        if at_stored.is_none_or(|held| held.pending) {
            let pending = at_stored.and_then(|held| scalar_from_hex(&held.scalar).ok());
            let landed = pending
                .into_iter()
                .chain(candidates.iter().copied())
                .find(|s| coordinates(fixed_base_mul(*s)) == stored_pk);
            if let Some(scalar) = landed {
                epochs.insert(stored_epoch, Epoch::new(scalar, false));
                recorded.push(stored_epoch);
            }
        }
        if epochs.is_empty() {
            self.0.remove(&FieldHex(contract));
        }
        recorded
    }

    // When a node retires a contract's scalar (DECISIONS.md section 9, the
    // secret-shared on-chain intake's epoch bound). The scalar of epoch `e` in a
    // contract is deleted once the contract's stored epoch is at least
    // `e + 2` and its queue head has reached the tail the node read when it
    // first saw that; until then the node keeps it, per contract, whatever
    // its other contracts hold. `append_onchain_shared` accepts only the
    // stored epoch or the one before it, so from the block the stored epoch
    // reached `e + 2` no request names `e`, and every request that does sits
    // below that block's tail, which is at most the tail the node read later;
    // the epochs and the queue are public, so the node needs no request log
    // to decide. A scalar outlives its key's grace window until the queue
    // drains past it (a stalled queue keeps it, `skip()` moves it); a node
    // that observes late keeps it longer, never shorter. An app that wants a
    // hard bound sets its stale period, which bounds how long the head waits.
    // The stored epoch, head and tail must come from one snapshot
    // ([`EncKeyObservation`]). A pending epoch is never retired here: run
    // [`Self::land`] first, which records every epoch below the stored one.
    /// Apply the retirement rule to `contract` at one observation of its
    /// stored epoch, queue head and tail, all read at one block; returns the
    /// epochs deleted.
    pub fn observe(&mut self, contract: Fr, stored_epoch: u32, head: u64, tail: u64) -> Vec<u32> {
        let Some(epochs) = self.0.get_mut(&FieldHex(contract)) else {
            return Vec::new();
        };
        let mut retired = Vec::new();
        for (&e, held) in epochs.iter_mut() {
            if held.pending || e.saturating_add(2) > stored_epoch {
                continue;
            }
            let at = *held.retire_at_head.get_or_insert(tail);
            if head >= at {
                retired.push(e);
            }
        }
        for e in &retired {
            epochs.remove(e);
        }
        if epochs.is_empty() {
            self.0.remove(&FieldHex(contract));
        }
        retired
    }

    /// [`Self::land`], then [`Self::observe`], at one observation of
    /// `contract`: what the pruning job runs per contract.
    pub fn apply(&mut self, contract: Fr, at: &EncKeyObservation, candidates: &[Fq]) -> Observed {
        let recorded = self.land(contract, at.epoch, at.pk, candidates);
        let retired = self.observe(contract, at.epoch, at.head, at.tail);
        Observed { recorded, retired }
    }

    /// The file form: JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("epoch keys serialise")
    }

    /// From the file form; refuses a scalar that is not one.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let keys: EpochKeys = serde_json::from_str(text).map_err(|e| e.to_string())?;
        for epochs in keys.0.values() {
            for held in epochs.values() {
                scalar_from_hex(&held.scalar)?;
            }
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u64 = 0xa;
    const B: u64 = 0xb;

    fn s(k: u64) -> Fq {
        Fq::from(k)
    }

    #[test]
    fn debug_hides_the_scalars() {
        let mut keys = EpochKeys::default();
        let scalar = -Fq::from(0x5ec7e7u64);
        keys.record(Fr::from(A), 1, scalar).unwrap();
        let text = format!("{keys:?}");
        assert!(text.contains("pending"), "{text}");
        assert!(!text.contains(&scalar_to_hex(scalar)[2..18]), "{text}");
    }

    // One node rotation lands in contract A (epochs 1 → 2 → 3) but only
    // once in B (1 → 2): each contract keeps its own epochs, and the same
    // epoch number names another scalar in each.
    #[test]
    fn a_rotation_landed_in_one_contract_leaves_each_contract_s_epochs_its_own() {
        let mut keys = EpochKeys::default();
        let (a, b) = (Fr::from(A), Fr::from(B));
        keys.record(a, 1, s(10)).unwrap();
        keys.record(b, 1, s(10)).unwrap();
        keys.record(a, 2, s(20)).unwrap();
        keys.record(b, 2, s(20)).unwrap();
        keys.record(a, 3, s(30)).unwrap();
        assert_eq!(keys.epochs(a), [1, 2, 3]);
        assert_eq!(keys.epochs(b), [1, 2]);
        assert_eq!(keys.scalar(a, 3), Some(s(30)));
        assert_eq!(keys.scalar(b, 3), None);
        // A's stored epoch is 3: epoch 1 retires there once the head passes,
        // and stays in B, whose stored epoch is 2
        assert_eq!(keys.observe(a, 3, 5, 5), [1]);
        assert_eq!(keys.observe(b, 2, 9, 9), Vec::<u32>::new());
        assert_eq!(keys.epochs(a), [2, 3]);
        assert_eq!(keys.scalar(b, 1), Some(s(10)));
        // the same epoch twice with another scalar is refused
        assert!(keys.record(a, 3, s(31)).is_err());
        keys.record(a, 3, s(30)).unwrap();
    }

    // A scalar is deleted only once the stored epoch is two ahead and the
    // head has reached the tail read then.
    #[test]
    fn a_retired_scalar_goes_only_when_the_rule_allows() {
        let mut keys = EpochKeys::default();
        let a = Fr::from(A);
        keys.record(a, 1, s(10)).unwrap();
        keys.record(a, 2, s(20)).unwrap();
        // the stored epoch is one ahead: epoch 1 may still be named
        assert!(keys.observe(a, 2, 100, 100).is_empty());
        // two ahead, with requests 4..7 queued: kept until the head is at 7
        assert!(keys.observe(a, 3, 4, 7).is_empty());
        assert!(keys.observe(a, 3, 6, 9).is_empty());
        assert_eq!(keys.scalar(a, 1), Some(s(10)));
        assert_eq!(keys.observe(a, 3, 7, 9), [1]);
        assert_eq!(keys.scalar(a, 1), None);
        assert_eq!(keys.scalar(a, 2), Some(s(20)));
        // the file form keeps the mark
        let mut held = EpochKeys::default();
        held.record(a, 5, s(50)).unwrap();
        assert!(held.observe(a, 7, 1, 3).is_empty());
        let back = EpochKeys::from_json(&held.to_json()).unwrap();
        assert_eq!(back, held);
        let mut back = back;
        assert_eq!(back.observe(a, 7, 3, 10), [5]);
    }

    fn pk(k: u64) -> (Fr, Fr) {
        coordinates(fixed_base_mul(s(k)))
    }

    // A signed scalar is pending: the binder finds it, the retirement rule
    // leaves it, and it is recorded once the contract stores its key at
    // that epoch; the landed epoch is then never signed under another key.
    #[test]
    fn a_signed_scalar_is_pending_until_its_rotation_lands() {
        let mut keys = EpochKeys::default();
        let a = Fr::from(A);
        keys.sign(a, 1, s(10)).unwrap();
        assert_eq!(keys.pending(a), [1]);
        assert_eq!(keys.scalar(a, 1), Some(s(10)));
        // no key stored yet (epoch 0): nothing lands
        assert!(
            keys.land(a, 0, (Fr::from(0u64), Fr::from(0u64)), &[])
                .is_empty()
        );
        assert_eq!(keys.pending(a), [1]);
        // the stored key is the signed one: recorded
        assert_eq!(keys.land(a, 1, pk(10), &[]), [1]);
        assert!(keys.pending(a).is_empty());
        assert_eq!(keys.scalar(a, 1), Some(s(10)));
        assert!(keys.land(a, 1, pk(10), &[]).is_empty());
        // a landed epoch: the same scalar answers again, another is refused,
        // and so is an epoch below it
        keys.sign(a, 1, s(10)).unwrap();
        let err = keys.sign(a, 1, s(11)).unwrap_err();
        assert!(err.contains("landed under another key"), "{err}");
        keys.record(a, 3, s(30)).unwrap();
        let err = keys.sign(a, 2, s(20)).unwrap_err();
        assert!(err.contains("below its landed epoch 3"), "{err}");
    }

    // Signing a pending epoch again replaces its scalar, and the contract's
    // stored key decides which scalar is recorded: the pending one, or a
    // candidate (the node's current or previous scalar) whose rotation at
    // that epoch landed instead.
    #[test]
    fn signing_a_pending_epoch_again_replaces_it() {
        let a = Fr::from(A);
        let mut keys = EpochKeys::default();
        keys.sign(a, 2, s(20)).unwrap();
        keys.sign(a, 2, s(21)).unwrap();
        assert_eq!(keys.scalar(a, 2), Some(s(21)));
        assert_eq!(keys.land(a, 2, pk(21), &[s(20)]), [2]);
        assert_eq!(keys.scalar(a, 2), Some(s(21)));

        // the replaced signature was the one submitted: its scalar, still
        // the node's previous one, is recorded
        let mut keys = EpochKeys::default();
        keys.sign(a, 2, s(20)).unwrap();
        keys.sign(a, 2, s(21)).unwrap();
        assert_eq!(keys.land(a, 2, pk(20), &[s(21), s(20)]), [2]);
        assert_eq!(keys.scalar(a, 2), Some(s(20)));
        assert!(keys.pending(a).is_empty());

        // a key the node holds no scalar of: the epoch stays pending
        let mut keys = EpochKeys::default();
        keys.sign(a, 2, s(20)).unwrap();
        assert!(keys.land(a, 2, pk(99), &[s(21)]).is_empty());
        assert_eq!(keys.pending(a), [2]);
    }

    // A rotation that never lands leaves a pending epoch that blocks
    // nothing: the retirement rule passes it by, a later signature at that
    // epoch replaces it, and a stored epoch that moved past it (the node's
    // own rotations landing in order) records it.
    #[test]
    fn an_abandoned_rotation_leaves_nothing_to_clear() {
        let a = Fr::from(A);
        let mut keys = EpochKeys::default();
        keys.record(a, 1, s(10)).unwrap();
        keys.sign(a, 2, s(20)).unwrap();
        // the contract still stores epoch 1: epoch 2 stays pending
        assert!(keys.land(a, 1, pk(10), &[s(20)]).is_empty());
        assert!(keys.observe(a, 1, 50, 50).is_empty());
        assert_eq!(keys.pending(a), [2]);
        // abandoned: the operator signs epoch 2 again under a new scalar
        keys.sign(a, 2, s(22)).unwrap();
        assert_eq!(keys.pending(a), [2]);
        assert_eq!(keys.scalar(a, 2), Some(s(22)));
        // a pending epoch two below the stored one is never retired unlanded
        let mut lone = EpochKeys::default();
        lone.sign(a, 5, s(50)).unwrap();
        assert!(lone.observe(a, 9, 100, 100).is_empty());
        assert_eq!(lone.scalar(a, 5), Some(s(50)));

        // epochs 2 and 3 landed before the node looked: epoch 2 is recorded
        // from below the stored epoch, epoch 3 by its stored key
        keys.sign(a, 3, s(30)).unwrap();
        let at = EncKeyObservation {
            epoch: 3,
            pk: pk(30),
            head: 4,
            tail: 7,
        };
        let seen = keys.apply(a, &at, &[s(30)]);
        assert_eq!(seen.recorded, [2, 3]);
        assert!(seen.retired.is_empty());
        assert!(keys.pending(a).is_empty());
        // epoch 1 retires once the head reaches the tail read at epoch 3
        let at = EncKeyObservation { head: 7, ..at };
        assert_eq!(keys.apply(a, &at, &[]).retired, [1]);
        assert_eq!(keys.epochs(a), [2, 3]);
    }

    // The file form keeps the pending flag; a file without it reads as
    // recorded epochs.
    #[test]
    fn the_file_form_keeps_what_is_pending() {
        let a = Fr::from(A);
        let mut keys = EpochKeys::default();
        keys.record(a, 1, s(10)).unwrap();
        keys.sign(a, 2, s(20)).unwrap();
        let text = keys.to_json();
        assert_eq!(text.matches("pending").count(), 1, "{text}");
        assert_eq!(EpochKeys::from_json(&text).unwrap(), keys);
        let recorded = text.replace("\"pending\": true", "\"retire_at_head\": null");
        let back = EpochKeys::from_json(&recorded).unwrap();
        assert!(back.pending(a).is_empty());
        assert_eq!(back.epochs(a), [1, 2]);
    }
}
