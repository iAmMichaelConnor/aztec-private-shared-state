//! Secret-shared on-chain intake (`intake: shared_onchain`, docs/ARCHITECTURE.md
//! section 6, "Secret-shared on-chain intake"): the [`IntakeSource`] whose inputs
//! come from the user's private request log, and the node's side of a key
//! rotation in a contract.
//!
//! The user's private function encodes the request's values under the
//! nodes' `enc` keys that the contract stores (`pss_public_contract`
//! `shared_onchain`), emits one private log under
//! `compute_log_tag(chain_request_id, REQUEST_DOMAIN)` and stores
//! `data_hash = poseidon2(log)` beside the queue entry
//! (sidecar-core `derived`). The scheduler and every chain verifier read the
//! logs under the request's siloed tag and the stored hash at their snapshot
//! ([`shared_request`], through [`ChainLogs`]: the private logs by siloed tag
//! and the slot [`SharedOnchainLayout`] gives), take the log whose hash is
//! the stored one (a log that hashes otherwise is refused), and fill the
//! synthesised request with its clear inputs, `C` and the log itself as
//! `shared_log`, with the round's encoding layout ([`onchain_layout`]); each
//! node's binder derives its pairs from it with its scalar for the epoch the
//! log names (sidecar-core `derived::node_share`). There is no receipt and
//! nothing is stored at intake. A node's receipt chain view reads its own
//! stored key through the same layout ([`enc_key`]).

use ark_std::rand::{CryptoRng, RngCore};
use sidecar_core::abi::CircuitShape;
use sidecar_core::derived::{
    DerivedInput, MAX_LOGGED_VALUES, REQUEST_LOG_HEADER, REQUEST_LOG_LEN, SharedLog, data_hash,
};
use sidecar_core::epochs::EncKeyObservation;
use sidecar_core::error::Refusal;
use sidecar_core::field::{FieldHex, Fr, fr_to_hex};
use sidecar_core::grumpkin::coordinates;
use sidecar_core::hash::poseidon2_hash;
use sidecar_core::keys::{NodeKeys, label_field};
use sidecar_core::manifest::QueuedIntake;
use sidecar_core::register::Signature;
use sidecar_core::request::{Full, Request};
use sidecar_core::schnorr::sign;

use crate::TipManifest;
use crate::chain::layout::{map_slot, request_log_tag, siloed_private_log_tag};
use crate::chain::rpc::Transport;
use crate::chain::{ChainReader, LogRef, QueueTarget, ReadError, Snapshot};
use crate::config::RegisterNode;
use crate::intake::route::{CommitmentLayout, commitment_layout};
use crate::intake::{
    CarriedShares, ChainHeld, ChainLogs, Found, IntakeLayout, IntakeLookup, IntakeSource,
    NodeInputs, SharedOnchainFound, found,
};
use crate::state::TipFuture;
use crate::synth::TipPackage;
use crate::verifier::refused;

/// Where the app's `SharedOnchain` (`shared_onchain.nr`: one
/// `StateVariable<2>`) keeps its storage, from its slot (the namespace's
/// `shared_onchain_slot`, from the contract artifact's storage layout as
/// `queue_slot` is): +0 `enc_keys` (`Map<u32, PublicMutable<EncKey>>`, each
/// entry `x`, `y`, `epoch` in three slots), +1 `data_hashes`
/// (`Map<Field, PublicMutable<Field>>` by chain request id).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedOnchainLayout {
    pub slot: Fr,
}

impl SharedOnchainLayout {
    pub fn new(slot: Fr) -> Self {
        SharedOnchainLayout { slot }
    }

    /// `data_hashes[request_id]`.
    pub fn data_hash(&self, request_id: Fr) -> Fr {
        map_slot(self.slot + Fr::from(1u64), request_id)
    }

    /// The first of the three slots of `enc_keys[i]` (`x`; `y` and
    /// `epoch` follow).
    pub fn enc_key(&self, i: usize) -> Fr {
        map_slot(self.slot, Fr::from(i as u64))
    }
}

/// What the chain holds of one secret-shared on-chain request at a snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedRead {
    /// Every private log under the request's siloed tag, its fields after
    /// the tag, in chain order.
    pub logs: Vec<(Vec<Fr>, LogRef)>,
    /// `data_hashes[chain_request_id]`: zero before intake.
    pub data_hash: Fr,
}

/// What the chain holds of secret-shared on-chain request `chain_request_id`
/// at `at`'s snapshot: `data_hashes[chain_request_id]` (zero before intake),
/// read at the snapshot's block, and every private log under the request's
/// siloed tag (the namespace contract's own: the kernel silos the tag with
/// the emitting address), anchored at the snapshot's block, in chain order.
/// `None` for a namespace without `SharedOnchain` storage.
pub async fn shared_request(
    at: &dyn ChainLogs,
    chain_request_id: Fr,
) -> Result<Option<SharedRead>, ReadError> {
    let Some(layout) = at.layout().shared_onchain else {
        return Ok(None);
    };
    let data_hash = at.storage(layout.data_hash(chain_request_id)).await?;
    let tag = siloed_private_log_tag(at.namespace(), request_log_tag(chain_request_id));
    let logs = at.private_logs(tag).await?;
    Ok(Some(SharedRead { logs, data_hash }))
}

/// Node `i`'s stored key in `target`'s contract and the queue's head and
/// tail, all at `snap` (`enc_keys[i]` is `x`, `y` and `epoch` in three
/// consecutive slots); `None` for a contract without `SharedOnchain`
/// storage (`layout`, the namespace's).
pub async fn enc_key<T: Transport>(
    reader: &ChainReader<T>,
    snap: Snapshot,
    target: &QueueTarget,
    layout: &IntakeLayout,
    i: usize,
) -> Result<Option<EncKeyObservation>, ReadError> {
    let c = target.contract;
    let Some(shared_onchain) = layout.shared_onchain else {
        return Ok(None);
    };
    let slot = shared_onchain.enc_key(i);
    let x = reader.storage(snap, c, slot).await?;
    let y = reader.storage(snap, c, slot + Fr::from(1u64)).await?;
    let epoch = reader
        .storage_u64(snap, c, slot + Fr::from(2u64), "epoch")
        .await?;
    let epoch = u32::try_from(epoch).map_err(|_| ReadError::Malformed {
        method: "node_getPublicStorageAt",
        detail: format!("enc_keys[{i}].epoch {epoch} is not a u32"),
    })?;
    let (head, tail) = reader.head_and_tail(snap, target).await?;
    Ok(Some(EncKeyObservation {
        epoch,
        pk: (x, y),
        head,
        tail,
    }))
}

/// Secret-shared on-chain intake's shares derive from the request log,
/// carried as the synthesised request's `shared_log`.
impl CarriedShares for SharedLog {
    fn carry(&self, request: &mut Request<Full>) {
        request.shared_log = Some(self.clone());
    }
}

/// A round's encoding layout, from its manifest and shape: C's values and
/// their kinds ([`CommitmentLayout`]), and every value of the sharing in
/// its order ([`CommitmentLayout::summand_names`]: the chosen values, then
/// `$blinding`) with the log position of its correction: after the header
/// and the clear values, in that order; `$blinding` has none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnchainLayout {
    pub commitment: CommitmentLayout,
    pub shared: Vec<DerivedInput>,
}

impl OnchainLayout {
    /// How many corrections the log carries.
    pub fn corrections(&self) -> usize {
        self.shared
            .iter()
            .filter(|s| s.correction.is_some())
            .count()
    }
}

/// The encoding layout of a round of `shape` under the queued manifest `tip`.
pub fn onchain_layout(shape: &CircuitShape, tip: &TipManifest) -> OnchainLayout {
    let commitment = commitment_layout(shape, tip);
    let names = commitment.summand_names();
    let chosen = names.len() - 1;
    let first = REQUEST_LOG_HEADER + commitment.clear();
    let shared = names
        .into_iter()
        .enumerate()
        .map(|(k, name)| DerivedInput {
            name,
            correction: (k < chosen).then_some(first + k),
        })
        .collect();
    OnchainLayout { commitment, shared }
}

/// Why a read gives no request: the log is missing or hashes otherwise
/// ([`Refused::Log`], refused), or it is another package's entry
/// ([`Refused::Other`], whose `C` gives another chain request id here).
enum Refused {
    Log(String),
    Other(String),
}

/// The inputs of chain request `chain` under `package` from `read`: the log
/// whose hash is the stored `data_hash`, its `C` and clear inputs, and the
/// log itself with the package's encoding layout.
fn logged(
    read: &SharedRead,
    namespace: Fr,
    package: &TipPackage,
    chain: Fr,
) -> Result<SharedOnchainFound, Refused> {
    let id = fr_to_hex(chain);
    if read.logs.is_empty() {
        return Err(Refused::Log(format!(
            "no private request log of chain request {id} is on chain"
        )));
    }
    let Some((fields, _)) = read
        .logs
        .iter()
        .find(|(f, _)| f.len() == REQUEST_LOG_LEN && data_hash(f) == read.data_hash)
    else {
        return Err(Refused::Log(format!(
            "none of the {} private log(s) under chain request {id}'s tag hashes to the \
             data_hash the contract stores ({})",
            read.logs.len(),
            fr_to_hex(read.data_hash)
        )));
    };
    let layout = onchain_layout(&package.shape, &package.tip);
    let q = layout.commitment.clear();
    let Some(clear) = fields.get(REQUEST_LOG_HEADER..REQUEST_LOG_HEADER + q) else {
        return Err(Refused::Log(format!(
            "circuit `{}` takes {q} clear inputs, more than a request log holds",
            package.name
        )));
    };
    let log = SharedLog {
        fields: fields.iter().copied().map(FieldHex).collect(),
        shared: layout.shared,
    };
    let inputs = SharedOnchainFound::new(clear.to_vec(), fields[0], log);
    let derived = package.chain_request_id(namespace, &inputs);
    if derived != chain {
        return Err(Refused::Other(format!(
            "the log's inputs commitment gives chain request {} under circuit `{}`",
            fr_to_hex(derived),
            package.name
        )));
    }
    Ok(inputs)
}

/// Secret-shared on-chain intake: the private request log and the stored data
/// hash give the inputs; nothing is held at the nodes.
#[derive(Clone, Copy, Debug)]
pub struct SharedOnchain;

impl IntakeSource for SharedOnchain {
    fn intake(&self) -> QueuedIntake {
        QueuedIntake::SharedOnchain
    }

    fn reads_nodes(&self) -> bool {
        false
    }

    /// The log under the request's tag whose hash is the stored one. A
    /// request whose logs all hash otherwise is logged and gives no request
    /// (the head waits for `skip()`); a log of another package's request
    /// gives none here.
    fn find<'a>(
        &'a self,
        at: &'a dyn IntakeLookup,
        package: &'a TipPackage,
        chain: Fr,
    ) -> TipFuture<'a, Result<Option<Found>, ReadError>> {
        Box::pin(async move {
            let Some(read) = shared_request(at, chain).await? else {
                return Ok(None);
            };
            if read.logs.is_empty() {
                return Ok(None);
            }
            match logged(&read, at.namespace(), package, chain) {
                Ok(inputs) => Ok(Some(found(inputs))),
                Err(Refused::Other(_)) => Ok(None),
                Err(Refused::Log(why)) => {
                    tracing::warn!(
                        circuit = %package.name,
                        chain_request_id = %fr_to_hex(chain),
                        "scheduler: no secret-shared on-chain request: {why}"
                    );
                    Ok(None)
                }
            }
        })
    }

    fn read_chain<'a>(
        &'a self,
        at: &'a dyn ChainLogs,
        chain: Fr,
    ) -> TipFuture<'a, Result<ChainHeld, ReadError>> {
        Box::pin(async move {
            Ok(shared_request(at, chain)
                .await?
                .map_or_else(ChainHeld::none, ChainHeld::new))
        })
    }

    fn node_view(&self, at: &NodeInputs<'_>) -> Result<Found, Refusal> {
        let read = at.held.get::<SharedRead>().ok_or_else(|| {
            refused(format!(
                "no secret-shared on-chain intake storage is configured for namespace {} \
                 (shared_onchain_slot), so chain request {} cannot be read at block {}",
                fr_to_hex(at.namespace),
                fr_to_hex(at.chain_request_id),
                at.block
            ))
        })?;
        let inputs =
            logged(read, at.namespace, at.package, at.chain_request_id).map_err(|e| match e {
                Refused::Log(why) | Refused::Other(why) => {
                    refused(format!("at block {}: {why}", at.block))
                }
            })?;
        Ok(found(inputs))
    }

    /// The request log bound: at most [`MAX_LOGGED_VALUES`] clear inputs and
    /// chosen shared values together. (The contract manifest states
    /// `storage.shared_onchain` exactly when a package takes this intake,
    /// which the contract manifest's own checks enforce.) The log is sealed
    /// to the keys of the epochs it names, which the epoch rule keeps
    /// (sidecar-core `epochs`), not the grace window, so the stale period is
    /// not bounded by it.
    fn check_register(
        &self,
        shape: &CircuitShape,
        tip: &TipManifest,
        _node: &RegisterNode,
    ) -> Result<(), Refusal> {
        let layout = onchain_layout(shape, tip);
        let (q, m) = (layout.commitment.clear(), layout.corrections());
        if q + m > MAX_LOGGED_VALUES {
            return Err(Refusal::bad_request(format!(
                "field `manifest.witness`: {q} clear input(s) and {m} chosen shared value(s); \
                 secret-shared on-chain intake's request log holds at most {MAX_LOGGED_VALUES} together \
                 (one private log: the tag, C, the epochs, E.x and three wraps before them)"
            )));
        }
        Ok(())
    }
}

/// The label of the rotation message's first element.
pub const PSS_ENC_ROTATE_LABEL: &[u8] = b"pss.enc_rotate";

/// The message node `i` signs to set its key in `namespace` to `pk` at
/// `epoch`: `poseidon2([PSS_ENC_ROTATE, namespace, i, pk.x, pk.y, epoch])`
/// (`pss_public_contract` `enc_rotation_message`).
pub fn enc_rotation_message(namespace: Fr, i: usize, pk: (Fr, Fr), epoch: u32) -> Fr {
    poseidon2_hash(&[
        label_field(PSS_ENC_ROTATE_LABEL),
        namespace,
        Fr::from(i as u64),
        pk.0,
        pk.1,
        Fr::from(u64::from(epoch)),
    ])
}

/// Node `i`'s rotation of its current `enc` key into `namespace` at
/// `epoch`, the contract's stored epoch + 1: keeps the current scalar
/// pending as that epoch's ([`sidecar_core::epochs::EpochKeys::sign`]) and
/// returns the signature the contract's rotation function checks; the
/// operator then submits the transaction, and the node records the scalar
/// once its chain view shows the rotation landed
/// ([`sidecar_core::epochs::EpochKeys::land`]). Persist `keys` before
/// submitting, so a request under the new epoch always finds its scalar.
pub fn rotate_into<R: RngCore + CryptoRng>(
    keys: &mut NodeKeys,
    i: usize,
    namespace: Fr,
    epoch: u32,
    rng: &mut R,
) -> Result<Signature, String> {
    let scalar = keys.enc_scalar();
    keys.epochs_mut().sign(namespace, epoch, scalar)?;
    let message = enc_rotation_message(namespace, i, coordinates(keys.enc_pk()), epoch);
    Ok(sign(keys.sig_scalar(), message, rng))
}

#[cfg(test)]
mod tests;
