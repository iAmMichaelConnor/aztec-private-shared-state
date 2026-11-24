//! The intake seam of the tip (docs/ARCHITECTURE.md section 6, "Secret-shared
//! intake" and the intake rows): where a queued request's inputs come from,
//! as the scheduler, the synthesiser, the chain verifier and the receipt
//! route see them. One trait, [`IntakeSource`], with one implementation per
//! built queued intake, picked once per package from the manifest's
//! `intake` ([`intake_source`], from the one table of implementations):
//!
//! ```text
//! OnchainPlain   on-chain intake: the request log carries the inputs in the clear
//!                and `user_nonce`
//! ReceiptPlain   receipt intake: each node stored the inputs when it signed
//!                the receipt (`POST /v1/receipt`)
//! SharedReceipt  secret-shared receipt intake: each node stored the clear inputs,
//!                the inputs commitment C and its own envelope of every
//!                shared value when it signed the receipt
//! SharedOnchain  secret-shared on-chain intake: the user's private request log
//!                carries C, the clear inputs and the encoded shares, and
//!                the contract stores its hash (`intake_shared_onchain`)
//! ```
//!
//! Each implementation finds a queue entry's inputs (the scheduler, through
//! an [`IntakeLookup`] and [`find_entry`]; the chain verifier, through
//! [`ChainLogs`] at its snapshot, into an opaque [`ChainHeld`], and then
//! this node's own rows) as an opaque [`Found`] value of its own type, which
//! alone gives the parts of the inputs commitment the chain request id is
//! built from (`inputs_hash, user_nonce` for the non-secret-shared intakes,
//! `C` for the secret-shared ones), the clear app inputs, the reserved
//! operands it fills and what else a synthesised request carries of it (the
//! shared inputs, the request log). Each also checks a receipt request at
//! the receipt route, says whether it reads the nodes, and says which of
//! its stored receipt rows a node's resync copies and how the lost node
//! keeps them ([`receipt_resync`]: receipt intake's rows only). Every queued intake is built;
//! relayed intake is deferred.
//!
//! An intake reads the chain only through [`ChainLogs`]: the namespace
//! contract's public logs by tag, private logs by siloed tag and storage
//! slots, at one snapshot, with the namespace's [`IntakeLayout`]. Each
//! intake computes its own tags and slots ([`onchain::request_log`],
//! [`shared_onchain::shared_request`]); the scheduler's lookup and the
//! chain verifier answer only the generic reads ([`ChainAt`]).
//!
//! Under secret-shared receipt intake the scheduler reads all three nodes' rows,
//! which must agree on everything but each node's own envelopes and
//! signature, and puts the three envelopes in the synthesised request; the
//! chain verifier reads only its own row, so its rebuilt request holds only
//! its own envelope, the one its projection keeps. At the receipt route each
//! intake that takes receipts checks the request
//! ([`IntakeSource::check_receipt`]) and supplies the message the receipt
//! signs and the node's check of its own envelopes before it signs
//! ([`route::ReceiptSigning`]: none under receipt intake), so the node and
//! the orchestrator sign and check a receipt without naming its intake. Both
//! secret-shared intakes read C's values and their kinds from one layout
//! ([`route::commitment_layout`]).
//! Secret-shared on-chain intake reads the private request logs by siloed tag
//! and the stored data hash, and fills the synthesised request's `shared_log`.

mod found;
pub mod onchain;
mod receipt;
pub(crate) mod route;
pub mod shared_onchain;
mod shared_receipt;

pub use found::{CarriedShares, PlainFound, SharedFound, SharedOnchainFound, SharedReceiptFound};
pub use onchain::OnchainPlain;
pub use receipt::ReceiptPlain;
pub use shared_receipt::SharedReceipt;

use std::any::Any;
use std::sync::Arc;

use sidecar_core::abi::CircuitShape;
use sidecar_core::error::Refusal;
use sidecar_core::field::{Fr, fr_to_hex};
use sidecar_core::grumpkin::Point;
use sidecar_core::hash::poseidon2_hash;
use sidecar_core::keys::NodeKeys;
use sidecar_core::manifest::{QueuedIntake, ReservedOperand};
use sidecar_core::pipeline::VerifierRows;
use sidecar_core::request::{Full, NODES, Request};
use sidecar_core::resync::{ReceiptBody, ReceiptResync, ReceiptResyncHook};
use sidecar_core::store::ReceiptRow;

use crate::TipManifest;
use crate::chain::rpc::Transport;
use crate::chain::{ChainReader, ReadError, Snapshot, TaggedLogs};
use crate::config::RegisterNode;
use crate::intake::route::{CheckedReceipt, ReceiptRequest, StoredReceipt};
use crate::intake::shared_onchain::{SharedOnchain, SharedOnchainLayout};
use crate::state::TipFuture;
use crate::synth::TipPackage;
use crate::verifier::refused;

/// One queued request's inputs as its intake found them, in a type of the
/// intake's own: what the chain request id commits to and what synthesis
/// places in the request. Only the intake that found them knows their
/// parts; everything above the seam reads them through these methods.
pub trait FoundInputs: Any + std::fmt::Debug + Send + Sync {
    /// The parts of the inputs commitment: the chain request id is
    /// `poseidon2([namespace, vk_hash, parts...])`
    /// ([`TipPackage::chain_request_id`]).
    fn commitment_parts(&self) -> Vec<Fr>;

    /// The clear app inputs in ABI order (`intake_inputs`), which synthesis
    /// places in `public` by name ([`TipPackage::app_public`]).
    fn clear_inputs(&self) -> &[Fr];

    /// The value of reserved operand `operand` when the intake fills it
    /// (on-chain intake and receipt intake: `$user_nonce`; the
    /// secret-shared intakes: `$inputs_hash`, the inputs commitment `C`);
    /// `None` for one it does not.
    fn reserved(&self, operand: ReservedOperand) -> Option<Fr>;

    /// Whatever a synthesised request carries of the inputs besides
    /// `public`: the shared inputs, or the request log the shares derive
    /// from; nothing under the non-secret-shared intakes.
    fn fill(&self, _request: &mut Request<Full>) {}
}

/// A found value, as the scheduler holds it and synthesis reads it.
pub type Found = Arc<dyn FoundInputs>;

/// `inputs` as a [`Found`].
fn found(inputs: impl FoundInputs) -> Found {
    Arc::new(inputs)
}

impl dyn FoundInputs {
    /// The value as `T`, when it is one (tests compare an intake's value
    /// through it).
    pub fn downcast<T: FoundInputs>(&self) -> Option<&T> {
        (self as &dyn Any).downcast_ref()
    }
}

/// What an intake keeps on chain for one request, as
/// [`IntakeSource::read_chain`] read it at one snapshot. Opaque: the chain
/// verifier holds it in its reads and hands it back to the same intake's
/// [`IntakeSource::node_view`], which alone knows its type (the request log
/// under on-chain intake). Empty for an intake that keeps nothing on chain
/// but the request id, or before the request reached the chain.
#[derive(Clone, Default)]
pub struct ChainHeld(Option<Arc<dyn Any + Send + Sync>>);

impl ChainHeld {
    /// Nothing held.
    pub fn none() -> Self {
        ChainHeld(None)
    }

    /// `value`, as the intake that read it will read it back.
    pub fn new<T: Any + Send + Sync>(value: T) -> Self {
        ChainHeld(Some(Arc::new(value)))
    }

    /// The value, if one of type `T` is held.
    pub fn get<T: Any>(&self) -> Option<&T> {
        self.0.as_deref().and_then(|v| v.downcast_ref())
    }
}

impl std::fmt::Debug for ChainHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "ChainHeld(..)"
        } else {
            "ChainHeld(none)"
        })
    }
}

/// Where a namespace contract keeps what its intakes read, each intake's
/// part its own: from the namespace's contract manifest
/// ([`crate::TipLayout`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IntakeLayout {
    /// The app's `SharedOnchain` (`storage.shared_onchain`); `None` for a
    /// namespace without secret-shared on-chain intake.
    pub shared_onchain: Option<SharedOnchainLayout>,
}

/// The chain at one snapshot of one namespace contract, as an intake reads
/// what it keeps there: generic reads only, the tags and slots being each
/// intake's own. The scheduler's lookup and the chain verifier answer them
/// at their own snapshot.
pub trait ChainLogs: Sync {
    /// The namespace contract: the address that emits the logs and holds
    /// the slots.
    fn namespace(&self) -> Fr;

    /// Where the namespace contract keeps what its intakes read.
    fn layout(&self) -> &IntakeLayout;

    /// The public logs the namespace contract emitted under `tag` up to the
    /// snapshot's block, in chain order (`ChainReader::logs`).
    fn public_logs(&self, tag: Fr) -> TipFuture<'_, Result<TaggedLogs, ReadError>>;

    /// The private logs under `siloed_tag` (the kernel silos a tag with the
    /// emitting address, so only the contract whose address it was siloed
    /// with matches), anchored at the snapshot's block, in chain order
    /// (`ChainReader::private_logs`).
    fn private_logs(&self, siloed_tag: Fr) -> TipFuture<'_, Result<TaggedLogs, ReadError>>;

    /// One storage slot of the namespace contract at the snapshot's block.
    fn storage(&self, slot: Fr) -> TipFuture<'_, Result<Fr, ReadError>>;
}

/// [`ChainLogs`] through a chain reader at one snapshot: the chain
/// verifier's reads, and what the scheduler's lookup caches.
pub struct ChainAt<'a, T> {
    pub reader: &'a ChainReader<T>,
    pub snap: Snapshot,
    /// The namespace contract.
    pub namespace: Fr,
    pub layout: IntakeLayout,
}

impl<T: Transport> ChainLogs for ChainAt<'_, T> {
    fn namespace(&self) -> Fr {
        self.namespace
    }

    fn layout(&self) -> &IntakeLayout {
        &self.layout
    }

    fn public_logs(&self, tag: Fr) -> TipFuture<'_, Result<TaggedLogs, ReadError>> {
        Box::pin(self.reader.logs(self.snap, self.namespace, tag))
    }

    fn private_logs(&self, siloed_tag: Fr) -> TipFuture<'_, Result<TaggedLogs, ReadError>> {
        Box::pin(self.reader.private_logs(self.snap, siloed_tag))
    }

    fn storage(&self, slot: Fr) -> TipFuture<'_, Result<Fr, ReadError>> {
        Box::pin(self.reader.storage(self.snap, self.namespace, slot))
    }
}

/// What the scheduler finds a queued request's inputs in: the chain at its
/// snapshot and the receipts the nodes stored.
pub trait IntakeLookup: ChainLogs {
    /// Each node's stored receipt for chain request `chain`
    /// (`GET /v1/receipt/{namespace}/{chain_request_id}`), node 0 first;
    /// `None` for a node that holds none or does not answer.
    fn stored_receipts(&self, chain: Fr) -> TipFuture<'_, [Option<StoredReceipt>; NODES]>;
}

/// What the chain verifier reads a received request's inputs from: what the
/// intake read on chain at the verifier's snapshot
/// ([`IntakeSource::read_chain`]) and this node's own rows.
pub struct NodeInputs<'a> {
    /// This node's index: the received request is its projection.
    pub node: usize,
    pub namespace: Fr,
    pub chain_request_id: Fr,
    /// The package the request names.
    pub package: &'a TipPackage,
    /// The block the verifier read the chain at.
    pub block: u64,
    /// What [`IntakeSource::read_chain`] found.
    pub held: &'a ChainHeld,
    /// This node's own rows, read-only.
    pub rows: &'a dyn VerifierRows,
}

/// One queued intake: where a queued request's inputs come from, what its
/// chain request id commits to, and what of them a synthesised request
/// carries ([`FoundInputs`]). No method changes anything.
pub trait IntakeSource: Send + Sync {
    /// The intake this implementation serves.
    fn intake(&self) -> QueuedIntake;

    /// Whether [`Self::find`] asks the nodes for their stored receipts (one
    /// `GET /v1/receipt` to each of the three) rather than reading the chain
    /// at the snapshot. [`find_entry`] asks the intakes that read the chain
    /// first, so an on-chain entry costs no fan-out to the nodes; the
    /// lookup reads each source once per entry whatever the order.
    fn reads_nodes(&self) -> bool;

    /// Scheduler: the inputs of chain request `chain` under the lookup's
    /// namespace as `at` holds them, when they are `package`'s (they give
    /// `chain` under it); `None` when nothing `at` holds does.
    fn find<'a>(
        &'a self,
        at: &'a dyn IntakeLookup,
        package: &'a TipPackage,
        chain: Fr,
    ) -> TipFuture<'a, Result<Option<Found>, ReadError>>;

    /// Chain verifier, at its snapshot: what this intake keeps on chain for
    /// chain request `chain`; nothing by default.
    fn read_chain<'a>(
        &'a self,
        _at: &'a dyn ChainLogs,
        _chain: Fr,
    ) -> TipFuture<'a, Result<ChainHeld, ReadError>> {
        Box::pin(async { Ok(ChainHeld::none()) })
    }

    /// Chain verifier: the inputs of the received request in this node's
    /// view, refused (400) when this node holds none. Whether they give the
    /// request's ids is [`crate::check_request_ids`]'s to say.
    fn node_view(&self, at: &NodeInputs<'_>) -> Result<Found, Refusal>;

    /// The receipt route: `req` checked against `package`, with the
    /// intake's own message and envelope check
    /// ([`route::ReceiptSigning`]); 400 when the inputs fail their static
    /// validity, and by default (an intake that takes no receipts) always.
    fn check_receipt(
        &self,
        package: &TipPackage,
        _req: &ReceiptRequest,
    ) -> Result<CheckedReceipt, Refusal> {
        Err(not_for_receipts(&package.name, self.intake().as_str()))
    }

    /// `enc` retirement: whether node `node`'s stored receipt row `row` of
    /// `namespace` holds an envelope to it that opens under its previous
    /// `enc` scalar and not its current one, so the previous scalar is kept
    /// while the row's request may still reach the head
    /// ([`holds_previous_enc`]); false by default (an intake that stores no
    /// envelope sealed to the node-wide `enc` key).
    fn holds_previous_enc(
        &self,
        _keys: &NodeKeys,
        _node: usize,
        _namespace: Fr,
        _row: &ReceiptRow,
    ) -> bool {
        false
    }

    /// Resync: the bundle body a neighbour sends of its stored receipt row
    /// `row` when the row is this intake's and the lost node can rebuild it
    /// ([`ReceiptResync::send`]); `None` by default (an intake that stores
    /// no receipt rows, or rows only this node can open).
    fn resync_send(&self, _row: &ReceiptRow) -> Option<ReceiptBody> {
        None
    }

    /// Resync: the row the lost node keeps from its two neighbours' bodies
    /// of one request, alike but for their signatures, when they are this
    /// intake's and check, signed again with `keys`
    /// ([`ReceiptResync::keep`]); `None` by default.
    fn resync_keep(
        &self,
        _namespace: Fr,
        _from_prev: &ReceiptBody,
        _from_next: &ReceiptBody,
        _pins: [Point; 2],
        _keys: &NodeKeys,
    ) -> Option<ReceiptRow> {
        None
    }

    /// REGISTER on a node: the intake's own rules on a manifest of it, its
    /// circuit's shape and the node's facts `node`; 400 naming the field;
    /// none by default.
    fn check_register(
        &self,
        _shape: &CircuitShape,
        _tip: &TipManifest,
        _node: &RegisterNode,
    ) -> Result<(), Refusal> {
        Ok(())
    }
}

/// The implementation of every built queued intake
/// ([`QueuedIntake::built`]), one each.
const INTAKE_SOURCES: [&dyn IntakeSource; 4] =
    [&OnchainPlain, &ReceiptPlain, &SharedReceipt, &SharedOnchain];

/// Whether any intake's rule keeps node `node`'s previous `enc` scalar for
/// its stored receipt row `row` of `namespace`
/// ([`IntakeSource::holds_previous_enc`]). A row is one intake's, which
/// alone answers for it.
pub fn holds_previous_enc(keys: &NodeKeys, node: usize, namespace: Fr, row: &ReceiptRow) -> bool {
    INTAKE_SOURCES
        .into_iter()
        .any(|source| source.holds_previous_enc(keys, node, namespace, row))
}

/// How a resync carries a node's receipt rows, from the intakes
/// ([`IntakeSource::resync_send`], [`IntakeSource::resync_keep`]). A row is
/// one intake's, which alone answers for it.
struct IntakeResync;

impl ReceiptResync for IntakeResync {
    fn send(&self, row: &ReceiptRow) -> Option<ReceiptBody> {
        INTAKE_SOURCES
            .into_iter()
            .find_map(|source| source.resync_send(row))
    }

    fn keep(
        &self,
        namespace: Fr,
        from_prev: &ReceiptBody,
        from_next: &ReceiptBody,
        pins: [Point; 2],
        keys: &NodeKeys,
    ) -> Option<ReceiptRow> {
        INTAKE_SOURCES
            .into_iter()
            .find_map(|source| source.resync_keep(namespace, from_prev, from_next, pins, keys))
    }
}

/// The receipt resync hook every tip node takes
/// ([`sidecar_core::pipeline::Node::with_receipt_resync`]): the intakes'
/// rules for which receipt rows a resync sends and how it keeps them.
pub fn receipt_resync() -> ReceiptResyncHook {
    Arc::new(IntakeResync)
}

/// The implementation of a queued intake; 400 for an intake with none. All
/// four are built (the library, the machine and the client; example cases:
/// see the examples' READMEs).
pub fn intake_source(intake: QueuedIntake) -> Result<&'static dyn IntakeSource, Refusal> {
    INTAKE_SOURCES
        .into_iter()
        .find(|source| source.intake() == intake)
        .ok_or_else(|| {
            Refusal::bad_request(format!(
                "{} (`{}`) is not built",
                intake.name(),
                intake.as_str()
            ))
        })
}

/// The package and inputs of chain request `chain` under the lookup's
/// namespace, among `packages`; `None` when nothing `at` holds names it yet.
/// The queue holds only the chain request id, which commits to the
/// circuit's vk_hash, so each package's intake is asked for the entry's
/// inputs under that package until the recomputed chain request id is the
/// entry's. The intakes that read the chain are asked first, then those
/// that ask the nodes ([`IntakeSource::reads_nodes`]), in the given order
/// within each, so an on-chain entry costs no fan-out to the nodes. Two
/// packages of one namespace with the same circuit (same vk_hash) and the
/// same intake give one chain request id for the same inputs, so the first
/// in that order is taken.
pub async fn find_entry<'p>(
    at: &dyn IntakeLookup,
    packages: &'p [TipPackage],
    chain: Fr,
) -> Result<Option<(&'p TipPackage, Found)>, ReadError> {
    let mut ordered: Vec<&TipPackage> = packages.iter().collect();
    ordered.sort_by_key(|p| p.intake.reads_nodes());
    for pkg in ordered {
        if let Some(found) = pkg.intake.find(at, pkg, chain).await? {
            return Ok(Some((pkg, found)));
        }
    }
    Ok(None)
}

impl TipPackage {
    /// The chain request id `inputs` give under this package and `namespace`:
    /// `poseidon2([namespace, vk_hash, the inputs' commitment parts...])`;
    /// equal to a queue entry's exactly when the inputs are that entry's and
    /// the package is the circuit it was queued for.
    pub fn chain_request_id(&self, namespace: Fr, inputs: &dyn FoundInputs) -> Fr {
        let mut fields = vec![namespace, self.vk_hash];
        fields.extend(inputs.commitment_parts());
        poseidon2_hash(&fields)
    }
}

/// The refusal of a receipt request for a circuit whose intake takes none.
pub(crate) fn not_for_receipts(circuit: &str, intake: &str) -> Refusal {
    Refusal::bad_request(format!(
        "field `circuit`: `{circuit}` takes `intake: {intake}`; receipts are for `intake: \
         receipt` and `intake: shared_receipt`"
    ))
}

/// 400 for a receipt request field the intake does not take.
pub(super) fn not_taken(field: &str, intake: QueuedIntake, why: &str) -> Refusal {
    Refusal::bad_request(format!(
        "field `{field}`: {} takes none; {why}",
        intake.name()
    ))
}

/// 400 for a stored receipt that names another circuit, vk_hash, namespace
/// or chain request than `package`'s `chain` under `namespace`.
pub(super) fn check_origin(
    receipt: &StoredReceipt,
    namespace: Fr,
    package: &TipPackage,
    chain: Fr,
) -> Result<(), Refusal> {
    if receipt.circuit != package.name || receipt.vk_hash.fr() != package.vk_hash {
        return Err(Refusal::bad_request(format!(
            "the stored receipt of chain request {} names circuit `{}` (vk_hash {}), not `{}`",
            fr_to_hex(chain),
            receipt.circuit,
            receipt.vk_hash,
            package.name
        )));
    }
    if receipt.namespace.fr() != namespace || receipt.request_id.fr() != chain {
        return Err(Refusal::bad_request(format!(
            "the stored receipt answers request {} under namespace {}, not chain request {} \
             under {}",
            receipt.request_id,
            receipt.namespace,
            fr_to_hex(chain),
            fr_to_hex(namespace)
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::receipt::inputs_hash;
    use crate::testing::Rows;
    use sidecar_core::field::{FieldHex, fr_from_hex};
    use sidecar_core::register::Signature;
    use sidecar_core::request::{NodeSharedInput, ShareCiphertext, SharedInput};
    use sidecar_core::store::ReceiptRow;
    use sidecar_test_fixtures::block_on;

    const NS: u64 = 0x5e;

    /// A lookup of namespace `ns` holding each node's stored receipt, and
    /// an empty chain.
    struct Held {
        ns: Fr,
        receipts: [Option<StoredReceipt>; NODES],
        layout: IntakeLayout,
    }

    impl ChainLogs for Held {
        fn namespace(&self) -> Fr {
            self.ns
        }

        fn layout(&self) -> &IntakeLayout {
            &self.layout
        }

        fn public_logs(&self, _: Fr) -> TipFuture<'_, Result<TaggedLogs, ReadError>> {
            Box::pin(async { Ok(vec![]) })
        }

        fn private_logs(&self, _: Fr) -> TipFuture<'_, Result<TaggedLogs, ReadError>> {
            Box::pin(async { Ok(vec![]) })
        }

        fn storage(&self, _: Fr) -> TipFuture<'_, Result<Fr, ReadError>> {
            Box::pin(async { Ok(Fr::from(0u64)) })
        }
    }

    impl IntakeLookup for Held {
        fn stored_receipts(&self, _: Fr) -> TipFuture<'_, [Option<StoredReceipt>; NODES]> {
            let receipts = self.receipts.clone();
            Box::pin(async move { receipts })
        }
    }

    /// What `pkg`'s intake finds for `chain` when only node 1 answers, with
    /// `receipt`.
    fn find(pkg: &TipPackage, receipt: Option<StoredReceipt>, chain: Fr) -> Option<Found> {
        find_in(pkg, [None, receipt, None], Fr::from(NS), chain)
    }

    fn find_in(
        pkg: &TipPackage,
        receipts: [Option<StoredReceipt>; NODES],
        ns: Fr,
        chain: Fr,
    ) -> Option<Found> {
        let held = Held {
            ns,
            receipts,
            layout: IntakeLayout::default(),
        };
        block_on(pkg.intake.find(&held, pkg, chain)).unwrap()
    }

    /// `found` as an intake's own type.
    pub(crate) fn as_<T: FoundInputs>(found: &Found) -> &T {
        found.downcast::<T>().expect("the intake's own type")
    }

    /// A request with nothing in it but what `found` carries.
    pub(crate) fn carried(found: &dyn FoundInputs) -> Request<Full> {
        let mut req = Request {
            namespace: FieldHex(Fr::from(0u64)),
            circuit: String::new(),
            request_id: sidecar_core::field::RequestId(Fr::from(0u64)),
            public: Default::default(),
            state_keys: Default::default(),
            shared_inputs: vec![],
            records: vec![],
            requester: None,
            signature: None,
            chain_request_id: None,
            shared_log: None,
            manifest_hash: None,
        };
        found.fill(&mut req);
        req
    }

    /// Secret-shared receipt intake on testvectors/shared_intake.json: the package
    /// of testvectors/manifests/shared_receipt_round.json, the request (a
    /// clear `position` of 7, C, the chain request id) and every shared
    /// input with its three envelopes, as the client sent them and the
    /// nodes store them: without the salts' envelope (`$summand_salt`).
    pub(crate) struct SharedFixture {
        pub pkg: TipPackage,
        pub ns: Fr,
        pub chain: Fr,
        pub c: Fr,
        pub shared: Vec<SharedInput>,
    }

    impl SharedFixture {
        pub(crate) fn new() -> Self {
            let file = sidecar_test_fixtures::vectors::read("testvectors/shared_intake.json");
            let hex = |k: &str| fr_from_hex(file[k].as_str().unwrap()).unwrap();
            let pkg = TipPackage::from_row(&crate::testing::shared_package(), Some(50))
                .unwrap()
                .unwrap();
            let mut shared: Vec<SharedInput> =
                serde_json::from_value(file["shared_inputs"].clone()).unwrap();
            shared.retain(|s| s.name != crate::SUMMAND_SALT);
            SharedFixture {
                pkg,
                ns: hex("namespace"),
                chain: hex("chain_request_id"),
                c: hex("inputs_commitment"),
                shared,
            }
        }

        /// Node `i`'s `receipts` row: its own envelope of each shared input.
        pub(crate) fn row(&self, i: usize) -> ReceiptRow {
            ReceiptRow {
                request_id: self.chain,
                circuit: self.pkg.name.clone(),
                vk_hash: self.pkg.vk_hash,
                inputs: vec![Fr::from(7u64)],
                inputs_hash: self.c,
                user_nonce: None,
                shares: self
                    .shared
                    .iter()
                    .map(|s| NodeSharedInput {
                        name: s.name.clone(),
                        share: s.shares[i],
                        share_hashes: s.share_hashes,
                    })
                    .collect(),
                expiry_block: 1300,
                stale_blocks: Some(50),
                signature: Signature::default(),
            }
        }

        /// Node `i`'s stored receipt, as `GET /v1/receipt` answers it.
        pub(crate) fn stored(&self, i: usize) -> StoredReceipt {
            StoredReceipt::new(self.ns, &self.row(i))
        }

        /// The three nodes' stored receipts.
        fn all(&self) -> [Option<StoredReceipt>; NODES] {
            [0, 1, 2].map(|i| Some(self.stored(i)))
        }

        fn find(&self, receipts: [Option<StoredReceipt>; NODES]) -> Option<Found> {
            find_in(&self.pkg, receipts, self.ns, self.chain)
        }

        fn agreed(&self, receipts: [Option<StoredReceipt>; NODES]) -> String {
            SharedReceipt::agreed(&receipts, self.ns, &self.pkg, self.chain).unwrap_err()
        }
    }

    // The futures here never wait on anything.
    #[test]
    fn each_built_queued_intake_has_its_implementation() {
        for intake in QueuedIntake::ALL {
            match intake_source(intake) {
                Ok(source) => {
                    assert!(intake.built(), "{intake:?}");
                    assert_eq!(source.intake(), intake);
                }
                Err(err) => {
                    assert!(!intake.built(), "{intake:?}");
                    assert!(err.message.contains("is not built"), "{err}");
                }
            }
        }
    }

    /// The non-secret-shared intakes' chain request id is ids.rs's, whatever the intake.
    #[test]
    fn the_plain_commitment_parts_give_the_vector_id() {
        let pkg = TipPackage::from_row(&crate::intake::route::tests::receipt_package(), Some(50))
            .unwrap()
            .unwrap();
        let user_nonce = Fr::from(9u64);
        let inputs = PlainFound::new(
            vec![
                Fr::from(5000u64),
                Fr::from(1u64),
                Fr::from(4000u64),
                Fr::from(0x9au64),
            ],
            user_nonce,
        );
        let want = crate::chain_request_id(Fr::from(NS), pkg.vk_hash, &inputs.inputs, user_nonce);
        assert_eq!(pkg.chain_request_id(Fr::from(NS), &inputs), want);
        assert_eq!(
            inputs.commitment_parts(),
            [inputs_hash(&inputs.inputs), user_nonce]
        );
        assert_eq!(pkg.app_public(&inputs).unwrap().len(), 4);
        // nothing else in the request
        let req = carried(&inputs);
        assert!(req.shared_inputs.is_empty() && req.shared_log.is_none());
        // the non-secret-shared intakes fill `$user_nonce` only, never `$vk_hash`
        for operand in ReservedOperand::ALL {
            let want = (operand == ReservedOperand::UserNonce).then_some(user_nonce);
            assert_eq!(inputs.reserved(operand), want, "{operand:?}");
        }
    }

    /// The scheduler takes a stored receipt only for the package and the
    /// request it names.
    #[test]
    fn receipt_intake_finds_only_the_package_s_own_receipt() {
        let pkg = TipPackage::from_row(&crate::intake::route::tests::receipt_package(), Some(50))
            .unwrap()
            .unwrap();
        let inputs = [
            Fr::from(5000u64),
            Fr::from(1u64),
            Fr::from(4000u64),
            Fr::from(0x9au64),
        ];
        let chain = crate::chain_request_id(Fr::from(NS), pkg.vk_hash, &inputs, Fr::from(9u64));
        let receipt = StoredReceipt {
            namespace: FieldHex(Fr::from(NS)),
            request_id: FieldHex(chain),
            circuit: pkg.name.clone(),
            vk_hash: FieldHex(pkg.vk_hash),
            inputs: inputs.iter().copied().map(FieldHex).collect(),
            inputs_hash: FieldHex(inputs_hash(&inputs)),
            user_nonce: Some(FieldHex(Fr::from(9u64))),
            shared_inputs: vec![],
            expiry_block: 400,
            stale_blocks: Some(50),
            signature: Signature::default(),
        };
        let found = find(&pkg, Some(receipt.clone()), chain).unwrap();
        assert_eq!(
            as_::<PlainFound>(&found),
            &ReceiptPlain::stored_inputs(&receipt).unwrap()
        );
        assert!(find(&pkg, None, chain).is_none());
        // another circuit, another request, other inputs
        let mut other = receipt.clone();
        other.circuit = "amm_swap".into();
        assert!(find(&pkg, Some(other.clone()), chain).is_none());
        let err = check_origin(&other, Fr::from(NS), &pkg, chain).unwrap_err();
        assert!(err.message.contains("names circuit `amm_swap`"), "{err}");
        let mut other = receipt.clone();
        other.request_id = FieldHex(Fr::from(1u64));
        assert!(find(&pkg, Some(other.clone()), chain).is_none());
        let err = check_origin(&other, Fr::from(NS), &pkg, chain).unwrap_err();
        assert!(err.message.contains("not chain request"), "{err}");
        let mut other = receipt;
        other.inputs[0] = FieldHex(Fr::from(5001u64));
        assert!(find(&pkg, Some(other), chain).is_none());
    }

    /// The scheduler asks the intakes that read the chain before those that
    /// ask the nodes.
    #[test]
    fn only_on_chain_intake_finds_without_the_nodes() {
        assert!(!OnchainPlain.reads_nodes());
        assert!(ReceiptPlain.reads_nodes() && SharedReceipt.reads_nodes());
    }

    /// A receipt that gives no request (another request, other inputs) is
    /// passed over for the next node's; another circuit's is another
    /// package's entry.
    #[test]
    fn receipt_intake_tries_the_next_node_s_receipt() {
        let pkg = TipPackage::from_row(&crate::intake::route::tests::receipt_package(), Some(50))
            .unwrap()
            .unwrap();
        let inputs = [
            Fr::from(5000u64),
            Fr::from(1u64),
            Fr::from(4000u64),
            Fr::from(0x9au64),
        ];
        let chain = crate::chain_request_id(Fr::from(NS), pkg.vk_hash, &inputs, Fr::from(9u64));
        let good = StoredReceipt {
            namespace: FieldHex(Fr::from(NS)),
            request_id: FieldHex(chain),
            circuit: pkg.name.clone(),
            vk_hash: FieldHex(pkg.vk_hash),
            inputs: inputs.iter().copied().map(FieldHex).collect(),
            inputs_hash: FieldHex(inputs_hash(&inputs)),
            user_nonce: Some(FieldHex(Fr::from(9u64))),
            shared_inputs: vec![],
            expiry_block: 400,
            stale_blocks: Some(50),
            signature: Signature::default(),
        };
        let mut wrong_request = good.clone();
        wrong_request.request_id = FieldHex(Fr::from(1u64));
        let mut wrong_inputs = good.clone();
        wrong_inputs.inputs[0] = FieldHex(Fr::from(5001u64));
        let mut other_circuit = good.clone();
        other_circuit.circuit = "amm_swap".into();
        let want = ReceiptPlain::stored_inputs(&good).unwrap();
        for bad in [wrong_request, wrong_inputs, other_circuit] {
            let found = find_in(
                &pkg,
                [Some(bad.clone()), None, Some(good.clone())],
                Fr::from(NS),
                chain,
            );
            assert_eq!(
                found.as_ref().map(as_::<PlainFound>),
                Some(&want),
                "{bad:?}"
            );
            assert!(find_in(&pkg, [Some(bad), None, None], Fr::from(NS), chain).is_none());
        }
    }

    /// Secret-shared receipt intake: the three rows give the clear inputs, C and
    /// the three envelopes of every shared input, in ABI order, with the
    /// share hashes the rows agree on.
    #[test]
    fn shared_receipt_intake_puts_the_three_nodes_envelopes_in_the_request() {
        let f = SharedFixture::new();
        let found = f.find(f.all()).unwrap();
        assert_eq!(
            as_::<SharedReceiptFound>(&found),
            &SharedReceiptFound::new(vec![Fr::from(7u64)], f.c, f.shared.clone())
        );
        for operand in ReservedOperand::ALL {
            let want = (operand == ReservedOperand::InputsHash).then_some(f.c);
            assert_eq!(found.reserved(operand), want, "{operand:?}");
        }
        assert_eq!(found.commitment_parts(), [f.c]);
        assert_eq!(f.pkg.chain_request_id(f.ns, &*found), f.chain);
        let public = f.pkg.app_public(&*found).unwrap();
        assert_eq!(public.keys().collect::<Vec<_>>(), ["position"]);
        let req = carried(&*found);
        assert_eq!(
            (req.shared_inputs, req.shared_log),
            (f.shared.clone(), None)
        );
        // the order is the circuit's, whatever order a row keeps them in
        let mut reordered = f.all();
        for r in reordered.iter_mut().flatten() {
            r.shared_inputs.reverse();
        }
        let reordered = f.find(reordered).unwrap();
        assert_eq!(as_::<SharedReceiptFound>(&reordered).shares, f.shared);
    }

    /// No secret-shared request comes from rows that are missing or disagree, or
    /// that do not give the entry: the scheduler then holds the entry.
    #[test]
    fn missing_or_disagreeing_rows_give_no_shared_request() {
        let f = SharedFixture::new();
        // a node without its row
        let mut held = f.all();
        held[2] = None;
        assert!(f.find(held.clone()).is_none());
        assert!(f.agreed(held).contains("node 2 holds no stored receipt"));
        // another circuit's rows: another package's entry
        let mut held = f.all();
        for r in held.iter_mut().flatten() {
            r.circuit = "other".into();
        }
        assert!(f.find(held).is_none());

        type Edit = fn(&mut StoredReceipt);
        let cases: Vec<(Edit, &str)> = vec![
            // one node's C, share hash, clear input or expiry differs
            (
                |r| r.inputs_hash = FieldHex(Fr::from(1u64)),
                "node 1's stored receipt differs from node 0's",
            ),
            (
                |r| r.shared_inputs[0].share_hashes[0] = FieldHex(Fr::from(1u64)),
                "node 1's stored receipt differs from node 0's",
            ),
            (
                |r| r.inputs[0] = FieldHex(Fr::from(8u64)),
                "node 1's stored receipt differs from node 0's",
            ),
            (
                |r| r.expiry_block += 1,
                "node 1's stored receipt differs from node 0's",
            ),
            // node 1's envelope of `amount` swapped for its `$partial_note` one
            (
                |r| r.shared_inputs[0].share = r.shared_inputs[1].share,
                "node 1's stored receipt: field `shared_inputs[0]` (`amount`): the envelope to node 1 \
                 does not hash to share_hashes[1]",
            ),
            // a row without one of the circuit's shared inputs
            (
                |r| {
                    r.shared_inputs.remove(4);
                },
                "node 1's stored receipt differs from node 0's",
            ),
        ];
        for (edit, needle) in cases {
            let mut held = f.all();
            edit(held[1].as_mut().unwrap());
            assert!(f.find(held.clone()).is_none(), "{needle}");
            let why = f.agreed(held);
            assert!(why.contains(needle), "`{needle}` not in: {why}");
        }

        // every row alike, and still no request
        let cases: Vec<(Edit, &str)> = vec![
            (
                |r| r.inputs_hash = FieldHex(Fr::from(1u64)),
                "gives chain request",
            ),
            (
                |r| r.user_nonce = Some(FieldHex(Fr::from(1u64))),
                "holds a user_nonce",
            ),
            (
                |r| r.vk_hash = FieldHex(Fr::from(1u64)),
                "names circuit `shared_receipt_round`",
            ),
            (
                |r| {
                    r.shared_inputs.remove(4);
                },
                "holds 0 envelope(s) of `$outcome_tag`",
            ),
            (
                |r| r.shared_inputs[0].name = "position".into(),
                "an envelope of `position`, not a shared input",
            ),
        ];
        for (edit, needle) in cases {
            let mut held = f.all();
            for r in held.iter_mut().flatten() {
                edit(r);
            }
            assert!(f.find(held.clone()).is_none(), "{needle}");
            let why = f.agreed(held);
            assert!(why.contains(needle), "`{needle}` not in: {why}");
        }
    }

    /// The chain verifier's view of a secret-shared request is its own row: its
    /// own envelope of each shared input, the stored share hashes, C.
    #[test]
    fn the_chain_verifier_s_shared_view_is_its_own_row() {
        let f = SharedFixture::new();
        for node in 0..NODES {
            let rows = Rows::with_receipts([(f.chain, f.row(node))]);
            let at = NodeInputs {
                node,
                namespace: f.ns,
                chain_request_id: f.chain,
                package: &f.pkg,
                block: 60,
                held: &ChainHeld::none(),
                rows: &rows,
            };
            let view = f.pkg.intake.node_view(&at).unwrap();
            let view = as_::<SharedReceiptFound>(&view);
            assert_eq!(view.inputs, [Fr::from(7u64)]);
            assert_eq!(view.c, f.c);
            for (got, want) in view.shares.iter().zip(&f.shared) {
                assert_eq!(got.name, want.name);
                assert_eq!(got.share_hashes, want.share_hashes);
                for i in 0..NODES {
                    let own = if i == node {
                        want.shares[i]
                    } else {
                        ShareCiphertext::default()
                    };
                    assert_eq!(got.shares[i], own, "node {node}, share {i}");
                }
            }
            // another node's row is not this node's
            let other = Rows::with_receipts([(f.chain, f.row((node + 1) % NODES))]);
            let err = f
                .pkg
                .intake
                .node_view(&NodeInputs { rows: &other, ..at })
                .unwrap_err();
            assert!(
                err.message
                    .contains(&format!("does not hash to share_hashes[{node}]")),
                "{err}"
            );
        }
        let none = Rows::default();
        let err = f
            .pkg
            .intake
            .node_view(&NodeInputs {
                node: 0,
                namespace: f.ns,
                chain_request_id: f.chain,
                package: &f.pkg,
                block: 60,
                held: &ChainHeld::none(),
                rows: &none,
            })
            .unwrap_err();
        assert!(err.message.contains("holds no receipt"), "{err}");
    }
}
