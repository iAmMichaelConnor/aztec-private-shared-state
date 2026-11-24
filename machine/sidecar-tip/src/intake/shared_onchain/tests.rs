//! Secret-shared on-chain intake's fixture tests, on the request of its
//! vectors (`crate::testing::shared_onchain`; tests/write_vectors.rs writes
//! and checks the vector files): a rotation then a request under the new key, a request
//! under a retired key still served, a log whose hash differs from the
//! stored one refused, a synthesised request whose `shared_log` differs from
//! the log read refused by the chain verifier, a request log beside an
//! envelope or under secret-shared receipt intake refused by the binder, the
//! request log bound at REGISTER.

use sidecar_test_fixtures::block_on;
use sidecar_test_fixtures::vectors::{hex, node_keys, read};

use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use serde_json::json;
use sidecar_core::abi::CircuitShape;
use sidecar_core::bind::Share;
use sidecar_core::derived::{self, node_share};
use sidecar_core::field::{FieldHex, Fr};
use sidecar_core::grumpkin::coordinates;
use sidecar_core::keys::NodeKeys;
use sidecar_core::request::NODES;
use sidecar_core::schnorr::verify;

use super::*;
use crate::chain::TaggedLogs;
use crate::intake::tests::{as_, carried};
use crate::testing::Rows;
use crate::testing::shared_onchain::{
    EPOCHS, NAMESPACE, Request, log_ref, node_with, package, request_under, rotation_scalar,
    the_request,
};
use sidecar_core::manifest::ReservedOperand;

/// Every node's pairs reconstruct every shared value, each node holding
/// `keys[i]`.
fn assert_served(r: &Request, keys: &[NodeKeys]) {
    let log = r.shared_log();
    for (j, (input, want)) in log.shared.iter().zip(r.shared_values()).enumerate() {
        let pairs: Vec<Share> = (0..NODES)
            .map(|i| node_share(&keys[i], i, r.ns, &log, &input.name).unwrap())
            .collect();
        for i in 0..NODES {
            assert_eq!(pairs[i].b, pairs[(i + 2) % NODES].a, "{}", input.name);
        }
        assert_eq!(pairs.iter().map(|p| p.a).sum::<Fr>(), want, "value {j}");
    }
}

/// A lookup of namespace `ns` whose chain holds one shared read (every
/// private log, the stored data hash) when the namespace keeps
/// `SharedOnchain` storage, and no public log or receipt.
struct Held {
    ns: Fr,
    read: Option<SharedRead>,
    layout: IntakeLayout,
}

impl Held {
    fn new(ns: Fr, read: Option<SharedRead>) -> Self {
        let layout = IntakeLayout {
            shared_onchain: read
                .is_some()
                .then(|| SharedOnchainLayout::new(Fr::from(0x40u64))),
        };
        Held { ns, read, layout }
    }
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
        let logs = self
            .read
            .as_ref()
            .map(|r| r.logs.clone())
            .unwrap_or_default();
        Box::pin(async move { Ok(logs) })
    }

    fn storage(&self, _: Fr) -> TipFuture<'_, Result<Fr, ReadError>> {
        let hash = self.read.as_ref().map_or(Fr::from(0u64), |r| r.data_hash);
        Box::pin(async move { Ok(hash) })
    }
}

impl IntakeLookup for Held {
    fn stored_receipts(
        &self,
        _: Fr,
    ) -> TipFuture<'_, [Option<crate::intake::route::StoredReceipt>; NODES]> {
        Box::pin(async { [None, None, None] })
    }
}

fn find(r: &Request, read: Option<SharedRead>) -> Option<Found> {
    block_on(r.pkg.intake.find(&Held::new(r.ns, read), &r.pkg, r.id)).unwrap()
}

fn node_view(r: &Request, read: Option<SharedRead>) -> Result<Found, Refusal> {
    let held = read.map_or_else(ChainHeld::none, ChainHeld::new);
    r.pkg.intake.node_view(&NodeInputs {
        node: 1,
        namespace: r.ns,
        chain_request_id: r.id,
        package: &r.pkg,
        block: 60,
        held: &held,
        rows: &Rows::default(),
    })
}

/// The scheduler and the chain verifier take the log whose hash is the
/// stored one: its clear input, C, and the log itself with the layout, in
/// the synthesised request's `shared_log`; nothing in `shared_inputs`.
#[test]
fn the_request_log_gives_the_inputs_c_and_the_shared_log() {
    let r = the_request(&node_keys());
    assert_eq!(r.pkg.intake.intake(), QueuedIntake::SharedOnchain);
    let found = find(&r, Some(r.read())).unwrap();
    let want = SharedOnchainFound::new(vec![Fr::from(7u64)], r.c, r.shared_log());
    assert_eq!(as_::<SharedOnchainFound>(&found), &want);
    assert_eq!(found.commitment_parts(), [r.c]);
    assert_eq!(found.reserved(ReservedOperand::InputsHash), Some(r.c));
    assert_eq!(r.pkg.chain_request_id(r.ns, &*found), r.id);
    let public = r.pkg.app_public(&*found).unwrap();
    assert_eq!(public.keys().collect::<Vec<_>>(), ["position"]);
    let req = carried(&*found);
    assert!(req.shared_inputs.is_empty());
    assert_eq!(req.shared_log, Some(r.shared_log()));
    let view = node_view(&r, Some(r.read())).unwrap();
    assert_eq!(as_::<SharedOnchainFound>(&view), &want);
    // another log under the same tag (one that never queued) is passed over
    let mut two = r.read();
    let mut other = r.log.clone();
    other[14] += Fr::from(1u64);
    two.logs.insert(0, (other, log_ref(0)));
    let found = find(&r, Some(two)).unwrap();
    assert_eq!(as_::<SharedOnchainFound>(&found), &want);
    // no log yet, or no secret-shared on-chain storage: no request
    assert!(find(&r, None).is_none());
    assert!(
        find(
            &r,
            Some(SharedRead {
                logs: vec![],
                data_hash: Fr::from(0u64)
            })
        )
        .is_none()
    );
    assert!(!r.pkg.intake.reads_nodes());
}

/// A log whose hash differs from the stored data hash is refused: the
/// scheduler finds no request and the chain verifier refuses the round.
#[test]
fn a_log_whose_hash_differs_from_the_data_hash_is_refused() {
    let r = the_request(&node_keys());
    let mut read = r.read();
    read.logs[0].0[6] += Fr::from(1u64);
    assert!(find(&r, Some(read.clone())).is_none());
    let err = node_view(&r, Some(read)).unwrap_err();
    assert!(
        err.message
            .contains("hashes to the data_hash the contract stores"),
        "{err}"
    );
    let mut read = r.read();
    read.data_hash += Fr::from(1u64);
    assert!(
        node_view(&r, Some(read))
            .unwrap_err()
            .message
            .contains("data_hash")
    );
    let err = node_view(&r, None).unwrap_err();
    assert!(err.message.contains("shared_onchain_slot"), "{err}");
    // another package's log under this id: no request for this package
    let mut other = package();
    other.vk_hash += Fr::from(1u64);
    assert!(
        block_on(
            other
                .intake
                .find(&Held::new(r.ns, Some(r.read())), &other, r.id)
        )
        .unwrap()
        .is_none()
    );
}

/// The scheduler and the chain verifier read a request through
/// [`shared_request`] over a chain reader (the reader's private logs by the
/// siloed tag, and `data_hashes[id]` from storage): the namespace's log is
/// the request; the same tag emitted by another contract silos to another
/// tag and is never read; a stored hash the log does not hash to finds no
/// request.
#[tokio::test]
async fn the_reader_fetches_the_log_through_the_tag_queries_and_its_stored_hash() {
    use crate::intake::ChainAt;
    use crate::testing::MemoryChain;

    let r = the_request(&node_keys());
    let shared_onchain = SharedOnchainLayout::new(Fr::from(9u64));
    let layout = IntakeLayout {
        shared_onchain: Some(shared_onchain),
    };
    let chain = std::sync::Arc::new(MemoryChain::new(30));
    let other = r.ns + Fr::from(1u64);
    let mut forged = r.log.clone();
    forged[3] += Fr::from(1u64);
    chain
        .node()
        .push_private(20, siloed_private_log_tag(other, r.tag), &forged);
    chain
        .node()
        .push_private(21, siloed_private_log_tag(r.ns, r.tag), &r.log);
    let slot = shared_onchain.data_hash(r.id);
    chain.set_storage(r.ns, slot, derived::data_hash(&r.log));
    let reader = ChainReader::new(chain.clone());
    let at = |snap, layout| ChainAt {
        reader: &reader,
        snap,
        namespace: r.ns,
        layout,
    };
    let snap = reader.snapshot().await.unwrap();
    let read = shared_request(&at(snap, layout), r.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.logs.len(), 1);
    assert_eq!(read.logs[0].0, r.log);
    assert_eq!(read.logs[0].1.block, 21);
    assert_eq!(read.data_hash, derived::data_hash(&r.log));
    let found = r
        .pkg
        .intake
        .find(&Held::new(r.ns, Some(read)), &r.pkg, r.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(as_::<SharedOnchainFound>(&found).shares, r.shared_log());
    // a stored hash the log does not hash to: no request
    chain.set_storage(r.ns, slot, derived::data_hash(&forged));
    let snap = reader.snapshot().await.unwrap();
    let read = shared_request(&at(snap, layout), r.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        r.pkg
            .intake
            .find(&Held::new(r.ns, Some(read)), &r.pkg, r.id)
            .await
            .unwrap()
            .is_none()
    );
    // a namespace without secret-shared on-chain storage reads nothing
    assert!(
        shared_request(&at(snap, IntakeLayout::default()), r.id)
            .await
            .unwrap()
            .is_none()
    );
}

/// Every node derives its pair of every shared value from the vectors' log
/// with its scalar of the named epoch, and the pairs reconstruct each value.
#[test]
fn each_node_derives_its_pairs_from_the_log() {
    let r = the_request(&node_keys());
    let keys: Vec<NodeKeys> = (0..NODES)
        .map(|i| {
            node_with(
                &node_keys()[i],
                r.ns,
                &[(EPOCHS[i], node_keys()[i].enc_scalar())],
            )
        })
        .collect();
    assert_served(&r, &keys);
    // a node without the named epoch's scalar refuses
    let err = node_share(&node_keys()[0], 0, r.ns, &r.shared_log(), "amount").unwrap_err();
    assert!(
        err.message.contains("holds no enc scalar of that epoch"),
        "{err}"
    );
}

/// A rotation then a request under the new key: node 1 signs its rotation
/// into the contract at epoch 3 (its new scalar pending at that epoch), a request
/// names [2, 3, 1], and node 1 derives its pairs with the new scalar.
#[test]
fn a_rotation_then_a_request_under_the_new_key() {
    let keys = node_keys();
    let ns = hex(NAMESPACE);
    let mut node1 = node_with(&node_keys()[1], ns, &[(2, keys[1].enc_scalar())]);
    node1 = node1.rotate_enc(rotation_scalar(), 1_000).unwrap();
    let sig = rotate_into(&mut node1, 1, ns, 3, &mut StdRng::seed_from_u64(3)).unwrap();
    let pk = coordinates(node1.enc_pk());
    assert!(verify(
        keys[1].sig_pk(),
        sig,
        enc_rotation_message(ns, 1, pk, 3)
    ));
    assert_eq!(node1.epochs().epochs(ns), [2, 3]);
    let pks = [keys[0].enc_pk(), node1.enc_pk(), keys[2].enc_pk()];
    let r = request_under(pks, [2, 3, 1]);
    let nodes = [
        node_with(&node_keys()[0], ns, &[(2, keys[0].enc_scalar())]),
        node1.clone(),
        node_with(&node_keys()[2], ns, &[(1, keys[2].enc_scalar())]),
    ];
    assert_served(&r, &nodes);
    // under its old epoch's scalar node 1 would derive another pair
    let log = r.shared_log();
    let mut stale = log.clone();
    stale.fields[1] = FieldHex(derived::pack_epochs([2, 2, 1]));
    assert_ne!(
        node_share(&node1, 1, ns, &stale, "amount").unwrap(),
        node_share(&node1, 1, ns, &log, "amount").unwrap()
    );
}

/// A request under the retired key is still served: node 0 rotated to
/// epoch 3 and its grace window ended (the previous scalar retired), but a
/// request queued under epoch 2 still opens with the scalar the epoch rule
/// keeps, until the rule deletes it.
#[test]
fn a_request_under_the_retired_key_is_still_served() {
    let keys = node_keys();
    let ns = hex(NAMESPACE);
    let mut node0 = node_with(&node_keys()[0], ns, &[(2, keys[0].enc_scalar())]);
    node0 = node0.rotate_enc(rotation_scalar(), 1_000).unwrap();
    rotate_into(&mut node0, 0, ns, 3, &mut StdRng::seed_from_u64(5)).unwrap();
    node0 = node0.retire_previous_enc();
    assert!(node0.previous_enc_scalar().is_none());
    let r = the_request(&node_keys());
    let nodes = [
        node0.clone(),
        node_with(&node_keys()[1], ns, &[(2, keys[1].enc_scalar())]),
        node_with(&node_keys()[2], ns, &[(1, keys[2].enc_scalar())]),
    ];
    assert_served(&r, &nodes);
    // the stored epoch is 3 (one ahead): kept whatever the queue
    assert!(node0.epochs_mut().observe(ns, 3, 10, 10).is_empty());
    assert_served(&r, &nodes);
    // two ahead with the request still queued: kept
    assert!(node0.epochs_mut().observe(ns, 4, 5, 6).is_empty());
    let mut nodes = nodes;
    nodes[0] = node0.clone();
    assert_served(&r, &nodes);
    // the head passed it: deleted, and the node refuses
    assert_eq!(node0.epochs_mut().observe(ns, 4, 6, 9), [2]);
    let err = node_share(&node0, 0, ns, &r.shared_log(), "amount").unwrap_err();
    assert!(err.message.contains("never recorded, or retired"), "{err}");
}

/// A rotation that landed in one contract but not another: the node holds
/// each contract's epochs apart, and a request in each derives under its
/// own contract's epoch.
#[test]
fn a_rotation_in_one_contract_leaves_another_s_epochs() {
    let keys = node_keys();
    let (a, b) = (hex(NAMESPACE), hex(NAMESPACE) + Fr::from(1u64));
    let mut node1 = keys[1].clone();
    node1
        .epochs_mut()
        .record(a, 2, keys[1].enc_scalar())
        .unwrap();
    node1
        .epochs_mut()
        .record(b, 2, keys[1].enc_scalar())
        .unwrap();
    node1 = node1.rotate_enc(rotation_scalar(), 1_000).unwrap();
    rotate_into(&mut node1, 1, a, 3, &mut StdRng::seed_from_u64(9)).unwrap();
    assert_eq!(node1.epochs().epochs(a), [2, 3]);
    assert_eq!(node1.epochs().epochs(b), [2]);
    // contract b's request names epoch 2: node 1 derives with its old scalar
    let r = the_request(&node_keys());
    let in_b = r.shared_log();
    let want = node_share(
        &node_with(&node_keys()[1], b, &[(2, keys[1].enc_scalar())]),
        1,
        b,
        &in_b,
        "amount",
    );
    assert_eq!(
        node_share(&node1, 1, b, &in_b, "amount").unwrap(),
        want.unwrap()
    );
    // and in contract b, epoch 3 holds no scalar
    let mut three = in_b.clone();
    three.fields[1] = FieldHex(derived::pack_epochs([2, 3, 1]));
    assert!(node_share(&node1, 1, b, &three, "amount").is_err());
    assert!(node_share(&node1, 1, a, &three, "amount").is_ok());
}

/// The request the scheduler fills for `r` (the request log as
/// `shared_log`, no envelope), with the public values the binder checks.
fn filled(r: &Request) -> sidecar_core::request::Request {
    use sidecar_core::request::{PublicValue, StateKeys};

    let found = find(r, Some(r.read())).unwrap();
    let extra = carried(&*found);
    let mut public = r.pkg.app_public(&*found).unwrap();
    for (name, v) in [("vk_hash", r.pkg.vk_hash), ("inputs_hash", r.c)] {
        public.insert(name.to_string(), PublicValue::One(FieldHex(v)));
    }
    sidecar_core::request::Request {
        namespace: FieldHex(r.ns),
        circuit: r.pkg.name.clone(),
        request_id: sidecar_core::field::RequestId(Fr::from(0x5e0u64)),
        public,
        state_keys: StateKeys {
            reads: vec!["0x0a".into()],
            writes: vec!["0x0b".into()],
        },
        shared_inputs: extra.shared_inputs,
        records: vec![],
        requester: None,
        signature: None,
        chain_request_id: Some(FieldHex(r.id)),
        shared_log: extra.shared_log,
        manifest_hash: None,
    }
}

/// The binder's INPUT_SHARED hook on node `i`, as a round binds: zeros for
/// each LOAD and SAMPLE, and the pair the share source gives for each
/// shared input.
struct NodeSources<'a> {
    keys: &'a NodeKeys,
    i: usize,
    req: &'a sidecar_core::request::NodeRequest,
}

impl sidecar_core::bind::Sources for NodeSources<'_> {
    fn load(
        &mut self,
        _: sidecar_core::manifest::KeyRef,
        key: &str,
    ) -> Result<Vec<sidecar_core::bind::Elem>, Refusal> {
        let len = if key == "nsk_app" { 1 } else { 3 };
        Ok(vec![
            sidecar_core::bind::Elem::Shared(Share::default());
            len
        ])
    }

    fn sample(&mut self) -> Share {
        Share::default()
    }

    fn shared_input(&mut self, name: &str) -> Result<Share, Refusal> {
        sidecar_core::manifest::Intake::SharedOnchain
            .share_source()
            .share(self.keys, self.i, self.req, name)
    }
}

/// The binder takes each node's derived pairs as its shares: the request
/// the scheduler fills (the request log as `shared_log`, no envelope) binds,
/// on every node, each INPUT_SHARED parameter to the pair that node derives
/// with its scalar of the named epoch, and the three bound pairs open to the
/// encoded values; a request without the log is refused before any share is
/// taken.
#[test]
fn the_binder_takes_the_derived_pairs_as_each_node_s_shares() {
    use sidecar_core::bind::{Elem, bind, check_request};

    let r = the_request(&node_keys());
    let req = filled(&r);
    let manifest = r.pkg.tip.manifest();
    let keys: Vec<NodeKeys> = (0..NODES)
        .map(|i| {
            node_with(
                &node_keys()[i],
                r.ns,
                &[(EPOCHS[i], node_keys()[i].enc_scalar())],
            )
        })
        .collect();
    let log = r.shared_log();
    let bound: Vec<_> = (0..NODES)
        .map(|i| {
            let view = req.project(i);
            let mut sources = NodeSources {
                keys: &keys[i],
                i,
                req: &view,
            };
            bind(&r.pkg.shape, manifest, &view, &mut sources).unwrap()
        })
        .collect();
    let params = [
        ("amount", "amount"),
        ("partial_note", "$partial_note"),
        ("outcome_key", "$outcome_key"),
        ("outcome_tag", "$outcome_tag"),
        ("blinding", "$blinding"),
    ];
    for (param, name) in params {
        let pairs: Vec<Share> = (0..NODES)
            .map(|i| {
                let want = node_share(&keys[i], i, r.ns, &log, name).unwrap();
                assert_eq!(
                    bound[i].input[param],
                    Elem::Shared(want),
                    "{param} on node {i}"
                );
                want
            })
            .collect();
        let value = r.shared_values()[log.shared.iter().position(|s| s.name == name).unwrap()];
        assert_eq!(pairs.iter().map(|p| p.a).sum::<Fr>(), value, "{param}");
    }
    let mut no_log = req.clone();
    no_log.shared_log = None;
    let err = check_request(&r.pkg.shape, manifest, &no_log.project(0)).unwrap_err();
    assert!(err.message.contains("field `shared_log`: missing"), "{err}");
}

/// The binder's request check takes the shares from where the intake's row
/// says, and only from there: a request log beside an envelope under secret-shared
/// on-chain intake is refused (it takes no envelope), and so is a request
/// log under secret-shared receipt intake (whose shares come in envelopes); each
/// before any share is taken.
#[test]
fn check_request_refuses_a_log_beside_envelopes_and_a_log_under_receipt_intake() {
    use sidecar_core::bind::check_request;
    use sidecar_core::envelope::{EnvelopeAd, seal_envelope};
    use sidecar_core::request::SharedInput;

    let r = the_request(&node_keys());
    let req = filled(&r);
    let manifest = r.pkg.tip.manifest();
    check_request(&r.pkg.shape, manifest, &req.project(0)).unwrap();
    // a well-formed envelope of `amount` beside the log
    let keys = node_keys();
    let ad = EnvelopeAd::for_intake(r.ns, r.id, &r.pkg.name, "amount");
    let mut rng = StdRng::seed_from_u64(7);
    let shares: [_; NODES] = std::array::from_fn(|i| {
        seal_envelope(
            keys[i].enc_pk(),
            i,
            &ad,
            [Fr::from(1u64), Fr::from(2u64)],
            &mut rng,
        )
    });
    let mut beside = req.clone();
    beside.shared_inputs = vec![SharedInput {
        name: "amount".into(),
        shares,
        share_hashes: shares.map(|s| FieldHex(s.hash())),
    }];
    let err = check_request(&r.pkg.shape, manifest, &beside.project(0)).unwrap_err();
    assert_eq!(err.class, sidecar_core::ErrorClass::BadRequest, "{err}");
    assert!(err.message.contains("field `shared_inputs`"), "{err}");
    assert!(err.message.contains("it takes no envelope"), "{err}");
    // the same round under secret-shared receipt intake (its user supplies each
    // shared value in an envelope): the log is refused
    let mut text = read("testvectors/manifests/shared_onchain_round.json");
    text["intake"] = json!("shared_receipt");
    let receipt = sidecar_core::Manifest::parse(&text).unwrap();
    let err = check_request(&r.pkg.shape, &receipt, &req.project(0)).unwrap_err();
    assert_eq!(err.class, sidecar_core::ErrorClass::BadRequest, "{err}");
    assert!(err.message.contains("field `shared_log`"), "{err}");
    assert!(
        err.message.contains("whose shares come in envelopes"),
        "{err}"
    );
}

/// The chain verifier rebuilds the scheduler's request from the request log
/// it reads at its snapshot (the log whose hash the contract stores) and
/// accepts it; a request whose `shared_log` differs from that log in one
/// field (a correction, so C, the public map and the machine request id are
/// unchanged) is refused, naming `shared_log`.
#[test]
fn the_chain_verifier_refuses_a_shared_log_other_than_the_one_it_read() {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use sidecar_core::pipeline::ChainRound;
    use sidecar_core::request::StateKeys;

    use crate::chain::layout::QueueLayout;
    use crate::chain::{PinnedValues, QueueEntry};
    use crate::state::KeyState;
    use crate::state::tree::PublicMap;
    use crate::testing::MemoryChain;
    use crate::{ChainVerifier, SynthesisView, TipLayout, synthesise};

    const NODE: usize = 1;
    const STALE: u64 = 1;
    let r = the_request(&node_keys());
    let queue = QueueLayout::new(Fr::from(12u64));
    let shared_onchain = SharedOnchainLayout::new(Fr::from(0x40u64));
    let mem = Arc::new(MemoryChain::new(60));
    mem.write_queue(r.ns, queue, &[r.id], 0, 41);
    mem.set_storage(r.ns, Fr::from(STALE), Fr::from(1u64));
    mem.set_storage(r.ns, Fr::from(STALE + 1), Fr::from(50u64));
    mem.node()
        .push_private(40, siloed_private_log_tag(r.ns, r.tag), &r.log);
    mem.set_storage(
        r.ns,
        shared_onchain.data_hash(r.id),
        derived::data_hash(&r.log),
    );
    let state_keys = StateKeys {
        reads: vec!["0x12".into()],
        writes: vec!["0x12".into()],
    };
    let verifier = ChainVerifier::new(NODE, mem, [r.ns]).unwrap();
    let layout = TipLayout {
        contract: r.ns,
        manifest_hash: Fr::from(0x6du64),
        class_id: Fr::from(crate::testing::MEMORY_CLASS_ID),
        node_keys: sidecar_core::manifest::contract::NodeKeysAxis::Rotating,
        upgrades: sidecar_core::manifest::contract::Upgrades::Fixed,
        circuit_pins: None,
        queue,
        intake: IntakeLayout {
            shared_onchain: Some(shared_onchain),
        },
        stale_blocks_slot: Fr::from(STALE),
        circuits: BTreeMap::from([(r.pkg.name.clone(), state_keys.clone())]),
        slots: BTreeMap::from([(Fr::from(0x12u64), "0x12".to_string())]),
        plain_reads: BTreeMap::new(),
        init: None,
    };
    // the scheduler's request, on the node-held pool's empty slot
    let state = [KeyState {
        key: "0x12".into(),
        commitment: Fr::from(0u64),
        record: None,
    }];
    let view = SynthesisView {
        namespace: r.ns,
        entry: QueueEntry {
            index: 0,
            chain_request_id: r.id,
        },
        state_keys: &state_keys,
        pinned: &PinnedValues::default(),
        state: &state,
        node_values: &PublicMap::new(),
    };
    let found = find(&r, Some(r.read())).unwrap();
    let req = synthesise(&view, &r.pkg, &*found).unwrap().request;
    assert_eq!(req.shared_log, Some(r.shared_log()));
    let verify = |req: &sidecar_core::request::Request| {
        let round = ChainRound {
            manifest: r.pkg.tip.manifest(),
            intake: r.pkg.tip.intake(),
            shape: &r.pkg.shape,
            vk_hash: r.pkg.vk_hash,
            manifest_hash: Fr::from(0u64),
            stale_blocks: r.pkg.tip.stale_blocks(),
            rows: &Rows::default(),
        };
        verifier
            .verify_in(&layout, &req.project(NODE), &round)
            .map(|_| ())
    };
    verify(&req).unwrap();
    // the correction of `amount` (log position 7) moved by one
    let mut tampered = req.clone();
    let log = tampered.shared_log.as_mut().unwrap();
    log.fields[7] = FieldHex(log.fields[7].fr() + Fr::from(1u64));
    assert_eq!(tampered.request_id, req.request_id);
    let err = verify(&tampered).unwrap_err();
    assert_eq!(err.class, sidecar_core::ErrorClass::BadRequest, "{err}");
    assert!(err.message.contains("field `shared_log`: differs"), "{err}");
    // a log with its correction positions moved is refused the same way
    let mut moved = req.clone();
    moved.shared_log.as_mut().unwrap().shared.swap(0, 1);
    let err = verify(&moved).unwrap_err();
    assert!(err.message.contains("field `shared_log`: differs"), "{err}");
}

/// REGISTER refuses a secret-shared on-chain manifest whose clear inputs and
/// chosen shared values do not fit one request log; the vectors' round (one
/// clear, four chosen) fits.
#[test]
fn register_bounds_the_request_log() {
    let pkg = package();
    // the node's window does not bound this intake's stale period
    let node = crate::RegisterNode {
        enc_grace_secs: 0,
        life: crate::ReceiptLife {
            ttl_blocks: 0,
            allowance_blocks: 0,
            stale_blocks: 0,
            block_time_secs: 0,
        },
    };
    SharedOnchain
        .check_register(&pkg.shape, &pkg.tip, &node)
        .unwrap();
    let mut layout = onchain_layout(&pkg.shape, &pkg.tip);
    assert_eq!((layout.commitment.clear(), layout.corrections()), (1, 4));
    // a shape with ten clear app input elements: `position` as a [u32; 10]
    let mut shape: CircuitShape = pkg.shape.clone();
    let p = shape
        .params
        .iter_mut()
        .find(|p| p.name == "position")
        .unwrap();
    p.width = 10;
    p.leaves = vec![p.leaves[0]; 10];
    layout = onchain_layout(&shape, &pkg.tip);
    assert_eq!(layout.commitment.clear(), 10);
    let err = SharedOnchain
        .check_register(&shape, &pkg.tip, &node)
        .unwrap_err();
    assert!(
        err.message.contains("10 clear input(s) and 4 chosen"),
        "{err}"
    );
    assert!(err.message.contains("at most 9 together"), "{err}");
}

// ---- the example rounds' layouts (testvectors/onchain_layouts.json) ----
