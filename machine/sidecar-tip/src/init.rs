//! The init round at the tip (docs/ARCHITECTURE.md section 6, "Deployment,
//! configure and the init round"): the one round of a tip app that never
//! enters the queue and has no requester. The scheduler sends it and each
//! node's chain verifier checks it, both from the same chain reads:
//!
//! ```text
//! configured   Configured.configured, the flag `configure` sets once
//! inputs       the constructor's init constants (lending's liquidity), in the
//!              init circuit's input order
//! slots        the commitment slot of every key the init creates
//! head         the queue's head, the entry index the round's versions carry
//! ```
//!
//! The round is due once the contract is configured and every slot it
//! creates is empty. Its request id is fixed: the chain request id of the
//! inputs with `user_nonce` 0 under the init package's vk hash
//! (pss_public_contract's `init_request_id`; the registered package's, which
//! is the contract's pin, since `configure` landed only over the registered
//! package list), and the machine request id covers one old commitment
//! of 0 per created key ([`crate::synth::synthesise_init`]). The same
//! request is rebuilt byte for byte from the same reads, so a resend is a
//! replay the nodes answer from their rows, and a slot once written stops
//! the round at the scheduler and at every chain verifier.

use sidecar_core::error::Refusal;
use sidecar_core::field::{Fr, fr_from_hex};
use sidecar_core::request::StateKeys;

use crate::chain::rpc::Transport;
use crate::chain::{ChainReader, PinnedValues, QueueEntry, QueueTarget, ReadError, Snapshot};
use crate::chain_request_id;
use crate::intake::PlainFound;
use crate::state::tree::PublicMap;
use crate::synth::{SynthesisView, Synthesised, TipPackage, synthesise_init};

/// Where a namespace contract keeps what the init round is built from, as
/// storage slots, and the init package's name: the contract manifest's
/// `init` and `storage.configured` ([`crate::TipLayout`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitLayout {
    /// The init package, one of the namespace's queued packages.
    pub circuit: String,
    /// `Configured.configured`: the slot of the app's `configured` immutable
    /// (its first packed field).
    pub configured_slot: Fr,
    /// Each init input's slot in the app's Config, in the init circuit's
    /// input order.
    pub input_slots: Vec<Fr>,
}

/// What the chain holds for the init round at one block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitRead {
    pub block: u64,
    /// The queue's head.
    pub head: u64,
    /// The stored `Configured.configured`: 1 once `configure` has landed, 0
    /// before.
    pub configured: Fr,
    /// The init inputs, in the init circuit's input order.
    pub inputs: Vec<Fr>,
    /// Each key the init creates (its request key, `state_keys.writes` order) with
    /// the commitment its slot holds.
    pub slots: Vec<(String, Fr)>,
}

impl InitRead {
    /// Whether `configure` has landed.
    pub fn is_configured(&self) -> bool {
        self.configured == Fr::from(1u64)
    }

    /// The first key the init creates whose slot is written, with its
    /// commitment.
    pub fn written(&self) -> Option<&(String, Fr)> {
        self.slots.iter().find(|(_, c)| *c != Fr::from(0u64))
    }

    /// Whether the init round is due: configured, and every slot it creates
    /// still empty.
    pub fn due(&self) -> bool {
        self.is_configured() && self.written().is_none()
    }

    /// The init round's fixed chain request id under the init package's
    /// `vk_hash`: `chain_request_id(namespace, vk_hash, inputs, 0)`.
    pub fn chain_request_id(&self, namespace: Fr, vk_hash: Fr) -> Fr {
        chain_request_id(namespace, vk_hash, &self.inputs, Fr::from(0u64))
    }

    /// The init's inputs as a non-secret-shared intake gives them, with `user_nonce` 0.
    pub fn intake_inputs(&self) -> PlainFound {
        PlainFound::new(self.inputs.clone(), Fr::from(0u64))
    }

    /// The entry the init round runs as: the init id at the queue's head
    /// (the index its node-held versions carry; the queue holds no init).
    pub fn entry(&self, namespace: Fr, vk_hash: Fr) -> QueueEntry {
        QueueEntry {
            index: self.head,
            chain_request_id: self.chain_request_id(namespace, vk_hash),
        }
    }
}

impl<T: Transport> ChainReader<T> {
    /// Everything the init round is built from, at `snap`: the configured
    /// flag, the init inputs, each slot of `state_keys.writes`
    /// (the init circuit's request keys, each a storage slot) and the head.
    pub async fn init(
        &self,
        snap: Snapshot,
        target: &QueueTarget,
        layout: &InitLayout,
        state_keys: &StateKeys,
    ) -> Result<InitRead, ReadError> {
        let contract = target.contract;
        let configured = self.storage(snap, contract, layout.configured_slot).await?;
        let mut inputs = Vec::with_capacity(layout.input_slots.len());
        for &slot in &layout.input_slots {
            inputs.push(self.storage(snap, contract, slot).await?);
        }
        let mut slots = Vec::with_capacity(state_keys.writes.len());
        for key in &state_keys.writes {
            let slot = fr_from_hex(key).map_err(|detail| ReadError::BadKey {
                key: key.clone(),
                detail,
            })?;
            slots.push((key.clone(), self.storage(snap, contract, slot).await?));
        }
        let head = self.queue(snap, target).await?.head;
        Ok(InitRead {
            block: snap.block,
            head,
            configured,
            inputs,
            slots,
        })
    }
}

/// The init request of `pkg` (the init package, under `state_keys`) at
/// `read`, which the scheduler sends and each chain verifier rebuilds.
pub fn init_request(
    namespace: Fr,
    read: &InitRead,
    pkg: &TipPackage,
    state_keys: &StateKeys,
) -> Result<Synthesised, Refusal> {
    let pinned = PinnedValues::default();
    let node_values = PublicMap::new();
    let view = SynthesisView {
        namespace,
        entry: read.entry(namespace, pkg.vk_hash),
        state_keys,
        pinned: &pinned,
        state: &[],
        node_values: &node_values,
    };
    synthesise_init(&view, pkg, &read.intake_inputs())
}
