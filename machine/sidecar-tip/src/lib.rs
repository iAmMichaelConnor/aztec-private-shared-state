//! The tip-of-chain additions of the co-SNARK sidecar (docs/ARCHITECTURE.md
//! sections 1 and 6), shared by sidecar-node and sidecar-orchestrator: the
//! queued-manifest view that the chain reader, the scheduler and the chain
//! verifier read; the content-derived chain request id and the machine
//! request id derived from it; the chain reader over an Aztec node's RPC; the
//! request synthesiser that turns the queue's head into an ordinary
//! `Request<Full>`; the init round, which the scheduler sends once the
//! contract is configured ([`init`]); the receipt message and its signer; where a stored receipt's request
//! stands in its queue (for the node's receipt pruning); and the
//! result-signature message helpers; the `[[tip.namespaces]]` allowlist both
//! binaries' config files share ([`config`]); and a namespace's facts from
//! its registered contract manifest ([`namespace`]).
//!
//! It is built on sidecar-core and never adds a store or a second pipeline:
//! the scheduler, the synthesiser and the chain verifier see a key's state
//! through one interface, [`TipState`] ([`state`]), and a queued
//! request's inputs through another, [`IntakeSource`] ([`intake`]: on-chain
//! intake, receipt intake and the secret-shared intakes, picked once per package). Each tip state mode
//! is one entry of the tip-mode table ([`TIP_MODES`]), pairing its
//! implementation of [`TipState`] with sidecar-core's state holder, which
//! [`holders`] installs: node-held state (sidecar-core's `NodeVersions`, the
//! default) and chain-held state ([`state::chain`]: the record sealed to the
//! machine itself, its REGISTER size bound, the sealed-thirds log and its
//! decoder into request records, [`SealedRecord`]). A synthesised request
//! runs through the same library call as every other request. It also holds the queued-manifest
//! view, [`TipManifest`], the ids, the receipt, the chain reader and the
//! synthesiser ([`synthesise`]).

#[cfg(any(test, feature = "test-util"))]
pub mod audit;
mod blocking;
pub mod chain;
pub mod config;
mod ids;
pub mod init;
pub mod intake;
pub mod namespace;
mod receipt;
pub mod standing;
pub mod state;
pub mod synth;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
pub mod verifier;

pub use chain::layout::{QueueLayout, REQUEST_DOMAIN, compute_log_tag};
pub use chain::{
    ChainReader, PinnedValue, PinnedValues, QueueEntry, QueueTarget, QueueView, ReadError,
    ReaderConfig, SlotView, Snapshot, StoredStaleBlocks,
};
pub use config::{
    AztecNode, DEFAULT_BLOCK_TIME_SECS, DEFAULT_RECEIPT_TTL_BLOCKS, ReceiptLife, RegisterNode,
    TipNamespace, check_enc_grace, check_register_intake, check_tip,
};
pub use ids::{
    PSS_ATTEMPT, check_request_ids, inputs_commitment, machine_request_id, shared_chain_request_id,
    shared_receipt_message, sharing_digest, summand_commitment,
};
pub use init::{InitLayout, InitRead, init_request};
pub use intake::onchain::{PlainInputs, RequestInputs};
pub use intake::shared_onchain::{
    OnchainLayout, SharedOnchain, SharedOnchainLayout, SharedRead, enc_rotation_message,
    onchain_layout, rotate_into,
};
pub use intake::{
    ChainAt, ChainHeld, ChainLogs, Found, FoundInputs, IntakeLayout, IntakeLookup, IntakeSource,
    NodeInputs, OnchainPlain, PlainFound, ReceiptPlain, SharedOnchainFound, SharedReceipt,
    SharedReceiptFound, find_entry, holds_previous_enc, intake_source, receipt_resync,
};
pub use state::chain::{ChainSealed, ChainTip, PSS_STATE, SealedRecord, SealedState};
// The tip follower's prune event, which a read refuses as `ReadError::Pruned`.
pub use chain::Prune;
pub use chain::rpc::{HttpTransport, RpcError, Transport, url_origin};
pub use intake::route::{
    CheckedReceipt, CommitmentLayout, ReceiptAnswer, ReceiptRequest, ReceiptResponse,
    ReceiptSigning, SUMMAND_SALT, StoredReceipt, check_expiry, check_receipt_request,
    commitment_layout, commitment_names, intake_inputs, public_inputs, shared_names,
};
pub use namespace::TipLayout;
pub use receipt::{
    RECEIPT_DOMAIN, chain_request_id, inputs_hash, receipt_message, sign_receipt,
    sign_receipt_message, verify_receipt,
};
pub use standing::{ReceiptChainView, ReceiptTarget, Standing};
pub use state::tree::{PublicMap, TreeSource};
pub use state::{
    KeyState, ReloadError, SettledHashes, TIP_MODES, TipCheck, TipFuture, TipHistory, TipMode,
    TipState, holders, key_tip_state, version_views,
};
pub use synth::{SynthesisView, Synthesised, TipPackage, stale_blocks_of, synthesise};
pub use verifier::ChainVerifier;

use sidecar_core::abi::CircuitShape;
use sidecar_core::manifest::{KeyRef, Manifest, PublicRead, QueuedIntake, StateMode};

/// A queued manifest as the tip reads it: typed accessors over a manifest
/// sidecar-core parsed and checked ([`Manifest::parse`], and at REGISTER
/// [`sidecar_core::abi::check_manifest_value`]), with the defaults applied
/// (`binding` turn, state mode `node`), and its namespace's stale period
/// from the contract manifest.
/// The indices into the public inputs come from the package's [`CircuitShape`].
#[derive(Clone, Debug, PartialEq)]
pub struct TipManifest {
    manifest: Manifest,
    intake: QueuedIntake,
    stale_blocks: Option<u64>,
}

/// A key's old commitment: the public output carrying the commitment of the
/// state the circuit read (`commitment_slot.<key>.old`). The slot it is checked
/// against follows from the request key the reference names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OldCommitment<'a> {
    pub key: KeyRef,
    pub output: &'a str,
}

impl TipManifest {
    /// The view of a parsed manifest in a namespace whose contract manifest
    /// states the stale period `stale_blocks`, or `None` under intake
    /// direct.
    pub fn new(manifest: Manifest, stale_blocks: Option<u64>) -> Option<Self> {
        let intake = manifest.queued_intake()?;
        Some(Self {
            manifest,
            intake,
            stale_blocks,
        })
    }

    /// The view of a manifest whose queued intake is `intake` (a queued
    /// round's, as the step 4 hook receives it).
    pub(crate) fn queued(
        manifest: Manifest,
        intake: QueuedIntake,
        stale_blocks: Option<u64>,
    ) -> Self {
        debug_assert_eq!(manifest.queued_intake(), Some(intake));
        Self {
            manifest,
            intake,
            stale_blocks,
        }
    }

    /// As [`Self::new`], from a borrowed manifest.
    pub fn from_manifest(manifest: &Manifest, stale_blocks: Option<u64>) -> Option<Self> {
        Self::new(manifest.clone(), stale_blocks)
    }

    /// The parsed manifest itself.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The registered circuit name.
    pub fn circuit(&self) -> &str {
        &self.manifest.circuit
    }

    /// The queued intake: [`intake::intake_source`] picks its
    /// implementation once per package ([`TipPackage::intake`]).
    pub fn intake(&self) -> QueuedIntake {
        self.intake
    }

    /// The stale period in L2 blocks, or `None` when skipping is disabled: the
    /// scheduler stops working on a head older than this, the relayer may
    /// `skip()` it, and a receipt whose request never entered the queue, or
    /// is done, is pruned this long after its expiry. The contract
    /// manifest's `queue.stale_blocks`, one per namespace.
    pub fn stale_blocks(&self) -> Option<u64> {
        self.stale_blocks
    }

    /// The state mode of a key the manifest loads or stores (`node` unless
    /// `state` says otherwise); `None` for a key it does not use.
    pub fn state_mode(&self, key: KeyRef) -> Option<StateMode> {
        self.manifest.state_mode(key)
    }

    /// The old commitment of every key with a commitment slot, in key order:
    /// what the chain reader compares with each slot, the scheduler expects,
    /// and the chain verifier checks a state record's note hash against.
    pub fn old_commitments(&self) -> impl Iterator<Item = OldCommitment<'_>> {
        self.manifest
            .commitment_slots()
            .map(|(key, slot)| OldCommitment {
                key: *key,
                output: &slot.old,
            })
    }

    /// The pinned public reads: the scheduler fills each `param` from a
    /// simulated call, the chain verifier repeats it, `apply` rechecks it.
    pub fn public_reads(&self) -> &[PublicRead] {
        &self.manifest.public_reads
    }

    /// The public-input index of a public output named by this manifest (an
    /// old or new commitment), in `shape`, the package's shape.
    pub fn output_index(&self, shape: &CircuitShape, output: &str) -> Option<usize> {
        shape.return_index(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{AMM_SWAP_TIP, AMM_SWAP_TIP_ABI, amm_swap_tip_abi};
    use sidecar_core::abi::check_manifest_value;
    use sidecar_core::error::parse_json;
    use sidecar_core::manifest::{Binding, DEFAULT_STALE_BLOCKS};

    fn view() -> TipManifest {
        TipManifest::from_manifest(
            &Manifest::parse(&parse_json(AMM_SWAP_TIP).unwrap()).unwrap(),
            Some(50),
        )
        .unwrap()
    }

    #[test]
    fn the_amm_tip_view_reads_the_tip_fields() {
        let tip = view();
        assert_eq!(tip.circuit(), "amm_swap_tip");
        assert_eq!(tip.intake(), QueuedIntake::Onchain);
        assert_eq!(tip.manifest().binding(), Binding::Turn);
        assert_eq!(tip.stale_blocks(), Some(50));
        assert_eq!(tip.state_mode(KeyRef::Read(0)), Some(StateMode::Chain));
        assert_eq!(tip.state_mode(KeyRef::Write(0)), Some(StateMode::Chain));
        assert_eq!(tip.state_mode(KeyRef::Read(1)), None);
        assert_eq!(
            tip.old_commitments().collect::<Vec<_>>(),
            [OldCommitment {
                key: KeyRef::Read(0),
                output: "old_c"
            }]
        );
        assert!(tip.public_reads().is_empty());
    }

    #[test]
    fn a_direct_manifest_has_no_view() {
        let direct = r#"{"manifest": 1, "circuit": "c", "namespace_param": "ns",
          "state_keys": {"reads": 0, "writes": 0},
          "witness": [{"param": "ns", "from": {"PUBLIC": "$namespace"}}],
          "outputs": [], "state": {}}"#;
        assert!(
            TipManifest::from_manifest(
                &Manifest::parse(&parse_json(direct).unwrap()).unwrap(),
                Some(50)
            )
            .is_none()
        );
    }

    #[test]
    fn defaults_apply_when_the_fields_are_left_out() {
        let mut text = AMM_SWAP_TIP.replace("\"binding\": \"turn\",", "");
        text = text.replace(
            "\"state\": { \"$state_keys.reads[0]\": \"chain\", \"$state_keys.writes[0]\": \"chain\" },",
            "",
        );
        assert!(!text.contains("binding") && !text.contains("\"state\""));
        let manifest = Manifest::parse(&parse_json(&text).unwrap()).unwrap();
        let tip = TipManifest::from_manifest(&manifest, Some(DEFAULT_STALE_BLOCKS)).unwrap();
        assert_eq!(tip.manifest().binding(), Binding::Turn);
        // a key left out of `state` is node-held, not chain-held
        assert_eq!(tip.state_mode(KeyRef::Read(0)), Some(StateMode::Node));
        // the stale period is the namespace's (its contract manifest's), and
        // null disables skipping
        assert_eq!(tip.stale_blocks(), Some(DEFAULT_STALE_BLOCKS));
        let tip = TipManifest::from_manifest(&manifest, None).unwrap();
        assert_eq!(tip.stale_blocks(), None);
    }

    #[test]
    fn the_public_input_indices_come_from_the_shape() {
        let value = parse_json(AMM_SWAP_TIP).unwrap();
        let abi = parse_json(AMM_SWAP_TIP_ABI).unwrap();
        let (manifest, shape) = check_manifest_value(&value, &abi).unwrap();
        let tip = TipManifest::from_manifest(&manifest, Some(50)).unwrap();
        // public inputs: namespace, vk_hash, in_slots, out_slots, then the
        // return value (request_id first)
        let old = tip.old_commitments().next().unwrap();
        assert_eq!(tip.output_index(&shape, old.output), Some(5));
        assert_eq!(tip.output_index(&shape, "new_c"), Some(6));
        assert_eq!(shape.outputs[0].note_hash_index, 6);

        // a lending-style read of a price into a public parameter, after the
        // key slots
        let text = AMM_SWAP_TIP.replace(
            "\"public_reads\": []",
            r#""public_reads": [{"contract": "0x1234", "function": "get_price", "args": ["0x01"], "param": "direction"}]"#,
        );
        let value = parse_json(&text).unwrap();
        let priced = serde_json::from_value(amm_swap_tip_abi(&["direction"])).unwrap();
        let (manifest, shape) = check_manifest_value(&value, &priced).unwrap();
        let tip = TipManifest::from_manifest(&manifest, Some(50)).unwrap();
        let read = &tip.public_reads()[0];
        assert_eq!(read.function, "get_price");
        assert_eq!(
            shape.param(&read.param).and_then(|p| p.public_index),
            Some(4)
        );
    }
}
