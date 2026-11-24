//! Node recovery on three in-process nodes (sidecar-core's `testing`
//! harness: mpc_net's local network, one thread per node), with real MPC
//! proofs of the registration and audit circuits: a namespace registered at
//! seq 0 (its nsk_app pairs from the registration circuit), node-held tip
//! state written straight into the three stores as a dealer's sharing of
//! known values (a flat key with a canonical, a live and an orphaned
//! version, and a tree-valued key of three leaves), a sidecar-path round
//! (a node-held `values` row and a consumed state), and a receipt row at
//! every node. The nodes take the core's receipt resync hook, which carries
//! no receipt row; receipt intake's rows, which sidecar-tip's hook carries,
//! are tested in sidecar-tip's `tests/receipt_resync.rs`.
//!
//! - The audit passes every canonical version; a version whose pairs agree
//!   at all three nodes but open to a vector its commitment does not name
//!   fails at the circuit, naming the key.
//! - A node's store deleted with its key directory kept is resynced from
//!   its two neighbours: the namespace row with its nsk_app pair, the
//!   package, every canonical and live version (not the orphan), every
//!   tree node, the `values` row with its pairs and writer, the consumed
//!   row, the dead record of a rolled-back round (step 7 at the rebuilt
//!   node then refuses that record) come back as they were; the
//!   npk_app_hash check, the `values` check and the audit pass at all three
//!   nodes. The receipt row the hook does not send is not carried: its
//!   queued request cannot run at the lost node and is skipped after
//!   `stale_blocks` (the chain verifier refuses a round without the row;
//!   sidecar-tip's verifier tests).
//! - The audit and the resync first mark each node's versions against its
//!   own chain view, so both pass when one neighbour has not run its prune
//!   pass since the chain moved (a version landed; a replaced block put the
//!   earlier one back).
//! - A neighbour that sends a wrong component of a version is caught by the
//!   audit (the handshake names the element); one that sends a wrong nsk_app
//!   component is caught by the npk_app_hash check; one that sends a wrong
//!   component of a `values` row is caught by the `values` check.
//! - One key of a live store, its canonical version deleted (a slot at a
//!   commitment the node does not hold) or a leaf of its clear tree damaged
//!   (a diverged tree), is resynced from the neighbours alone: its versions
//!   and tree come back as they were, the audit of the key passes, and the
//!   namespace's other rows are untouched. A key the neighbours hold no
//!   version of is refused.
//! - A bundle under another sig key, a changed body, one sealed to another
//!   node, bodies that differ (a namespace row, the dead records), wrong pins and a store that is not empty are
//!   refused.
//! - A store backed up (sidecar-core's export), then lost after a version,
//!   and a value were written since, is restored by a delta resync: the
//!   pairs of what the backup holds come from it, the rest from the
//!   neighbours, and every row comes back, with the backup's `requests`
//!   rows and the receipt row no neighbour sends; the dead
//!   records are the neighbours' current set (a round rolled back since the
//!   backup is dead, a backup's dead record created again since is not); the
//!   npk_app_hash check, the `values` check and the audit pass.
//!   Another node's backup is refused.
//! - A tree of more stored leaves than one audit round takes is audited in
//!   chunks, one round per 16 leaves; a wrong leaf in the second chunk fails
//!   the key there, naming the leaf.
//! - Holder blobs (an oblivious key's state: public bytes, XOR share
//!   components, copies) come back with a resync and a restored backup (the
//!   unchanged ones from the backup), are compared by the blob handshake
//!   (a component held differently is named), and are refreshed by a node
//!   replacement (the same values, fresh components, the departed pair
//!   retired); a version with no clear tree is audited with no hash.
//!
//! Needs `scripts/prepare-data.sh` (examples/amm's `pss_seed` and the CRS
//! under machine/data, or DATA_DIR); every test fails naming the missing
//! file if it is absent, so a passing run proves it ran. Run with
//! `--release`.

use std::collections::BTreeMap;
use std::time::Instant;

use ark_ff::UniformRand;
use mpc_net::local::LocalNetwork;
use sidecar_core::audit::{self, AUDIT_ITEMS, KeyAudit};
use sidecar_core::backup::{self, StoreExport};
use sidecar_core::bind::{Elem, Share};
use sidecar_core::crs::Circuit;
use sidecar_core::dead;
use sidecar_core::error::{ErrorClass, Refusal};
use sidecar_core::field::FieldHex;
use sidecar_core::field::{Fr, RequestId, fr_from_hex};
use sidecar_core::handshake::{self, Handshake};
use sidecar_core::pipeline::{NamespacesGuard, Node};
use sidecar_core::replace;
use sidecar_core::request::NODES;
use sidecar_core::response::NodesResponse;
use sidecar_core::resync::{self, Contents, ResyncReport, Scope};
use sidecar_core::state::NodeVersions;
use sidecar_core::store::blob::{Blob, Pair};
use sidecar_core::store::rules::{self, TreeNodes, VersionView};
use sidecar_core::store::testing::{new_request, shared_receipt_row};
use sidecar_core::store::{
    ConsumedRow, NewRequest, Store, StoreRead, TipVersion, TreeRoot, ValueRow, VersionStatus,
    VersionTree, VersionWrite,
};
use sidecar_core::testing::{Fixture, Network, TestStore, rng, serial};
use sidecar_core::tree::{self, StoredNode, TreeNode};

const NS: u64 = 0xc0ffee;
const FLAT: &str = "0xa002";
const TREE: &str = "0xa003";
const BAD: &str = "0xa004";
/// The sidecar path's node-held key.
const POOL: &str = "pool";
const DEPTH: u32 = 4;
/// The consumed state of the sidecar round.
const SPENT: u64 = 0x5bea7;

fn ns() -> Fr {
    Fr::from(NS)
}

fn fixture() -> &'static Fixture {
    sidecar_core::testing::fixture(&["pss_seed"]).expect(
        "the recovery tests need scripts/prepare-data.sh's pss_seed and CRS (see the SKIPPED \
         line above)",
    )
}

/// A dealer's sharing of `values`: node i's vector of pairs.
fn deal(values: &[Fr], seed: u64) -> [Vec<Elem>; NODES] {
    let mut r = rng(seed);
    let mut out: [Vec<Elem>; NODES] = Default::default();
    for v in values {
        let x0 = Fr::rand(&mut r);
        let x1 = Fr::rand(&mut r);
        let x = [x0, x1, *v - x0 - x1];
        for (i, vec) in out.iter_mut().enumerate() {
            vec.push(Elem::Shared(Share::new(x[i], x[(i + 2) % 3])));
        }
    }
    out
}

fn f(x: u64) -> Fr {
    Fr::from(x)
}

/// One version as all three nodes hold it.
struct Held {
    commitment: Fr,
    parent: Fr,
    index: u64,
    status: VersionStatus,
    vecs: [Vec<Elem>; NODES],
    tree: Option<VersionTree>,
}

/// The tree key: leaves at 0, 1 and 5 of depth DEPTH, each [value, blinding].
struct Book {
    root: Fr,
    commitment: Fr,
    leaves: Vec<(u64, Fr, [Vec<Elem>; NODES])>,
    inner: Vec<(Fr, TreeNode)>,
}

fn book() -> Book {
    let key = fr_from_hex(TREE).unwrap();
    let z = tree::zeros(DEPTH);
    let mut leaves = Vec::new();
    for (k, index) in [0u64, 1, 5].into_iter().enumerate() {
        let values = [f(100 + index), f(7000 + index)];
        let hash = tree::leaf_hash(ns(), key, index, &values);
        leaves.push((index, hash, deal(&values, 40 + k as u64)));
    }
    let empty = |_: Fr| -> Result<Option<TreeNode>, Refusal> { Ok(None) };
    let changes: Vec<(u64, Fr)> = leaves.iter().map(|(i, h, _)| (*i, *h)).collect();
    let rebuilt = tree::rebuild(&empty, &z, z[DEPTH as usize], &changes).unwrap();
    Book {
        root: rebuilt.root,
        commitment: tree::commitment(ns(), key, rebuilt.root),
        leaves,
        inner: rebuilt.added.into_iter().map(|(h, _, n)| (h, n)).collect(),
    }
}

/// Write `versions` of `key` (and, for a tree, `book`'s nodes) into node
/// `i`'s store, as one round would.
fn write(store: &TestStore, i: usize, n: u8, key: &str, versions: &[Held], book: Option<&Book>) {
    let mut txn = store.begin(ns());
    if let Some(book) = book {
        let mut added: Vec<(Fr, TreeNode)> = book
            .leaves
            .iter()
            .map(|(index, hash, vecs)| {
                (
                    *hash,
                    TreeNode::Leaf {
                        index: *index,
                        vec: vecs[i].clone(),
                    },
                )
            })
            .collect();
        added.extend(book.inner.iter().cloned());
        TreeNodes { read: store, key }
            .add_version(&mut txn, book.root, added)
            .unwrap();
    }
    for v in versions {
        txn.version(VersionWrite::Put(TipVersion {
            key: key.to_string(),
            commitment: v.commitment,
            parent: v.parent,
            index: v.index,
            request_id: RequestId(f(0x1000 + v.index)),
            vec: v.vecs[i].clone(),
            tree: v.tree,
            status: v.status,
            block: 100 + i as u64,
            block_hash: Fr::from(0u64),
        }));
    }
    txn.put_request(NewRequest {
        request_id: RequestId(f(0x5000 + n as u64)),
        ..new_request(n, 1000 + n as u64)
    });
    store.commit(txn).unwrap();
}

/// The flat key's three versions: canonical, a live child, an orphan.
fn flat() -> Vec<Held> {
    let slot = fr_from_hex(FLAT).unwrap();
    let version = |values: [u64; 3], parent: Fr, index: u64, status, seed| {
        let values = values.map(f);
        Held {
            commitment: audit::flat_commitment(ns(), slot, &values),
            parent,
            index,
            status,
            vecs: deal(&values, seed),
            tree: None,
        }
    };
    let canonical = version([1000, 2000, 31], f(0), 0, VersionStatus::Canonical, 1);
    let live = version(
        [1100, 1900, 32],
        canonical.commitment,
        1,
        VersionStatus::Live,
        2,
    );
    let orphan = version(
        [1200, 1800, 33],
        canonical.commitment,
        1,
        VersionStatus::Orphan,
        3,
    );
    vec![canonical, live, orphan]
}

/// The sidecar round at node `i`: it consumes SPENT and stores POOL.
fn sidecar_round(node: &Node<TestStore>, i: usize) {
    let id = RequestId(f(0x6000));
    let mut txn = node.store.begin(ns());
    txn.consume(ConsumedRow {
        note_hash: f(SPENT),
        circuit: f(0xc1),
        request_id: id,
    });
    let vec = deal(&[f(500), f(600), f(61)], 50)[i].clone();
    rules::stage_store(&node.store, &node.keys(), &mut txn, POOL, vec, f(0x9001)).unwrap();
    txn.put_request(NewRequest {
        request_id: id,
        body_hash: f(0x60),
        stored_keys: vec![POOL.into()],
        created_keys: vec![POOL.into()],
        ..new_request(0x60, 2000)
    });
    node.store.commit(txn).unwrap();
}

/// The receipt row every node holds: a secret-shared receipt intake row,
/// which the core's hook does not send.
fn receipts(net: &Network) {
    for node in &net.nodes {
        node.store
            .put_receipt(ns(), shared_receipt_row(9, 500, Some(50)))
            .unwrap();
    }
}

/// Three nodes with the namespace registered, the flat and tree keys
/// written, the sidecar round committed and the receipt row stored.
fn network(fx: &Fixture, seed: u64) -> Network {
    let mut net = Network::new(fx, seed);
    net.register(fx, NS, "amm", &["pss_seed"]);
    let flat = flat();
    let book = book();
    let tree_version = Held {
        commitment: book.commitment,
        parent: f(0),
        index: 0,
        status: VersionStatus::Canonical,
        vecs: Default::default(),
        tree: Some(VersionTree::Clear(TreeRoot {
            root: book.root,
            next: 6,
        })),
    };
    for (i, node) in net.nodes.iter().enumerate() {
        write(&node.store, i, 1, FLAT, &flat, None);
        let tree = std::slice::from_ref(&tree_version);
        write(&node.store, i, 2, TREE, tree, Some(&book));
        sidecar_round(node, i);
    }
    receipts(&net);
    net
}

/// Where the first component of `key`'s canonical version sits in
/// `contents` (after the master's and the namespace's nsk_app's).
fn canonical_component(contents: &Contents, key: &str) -> usize {
    let mut at = 2;
    for v in &contents.body.namespaces[0].versions {
        if v.key == key && v.canonical {
            return at;
        }
        at += v.vec.iter().filter(|e| e.is_none()).count();
    }
    panic!("no canonical version of {key}")
}

/// The chain view of a node that reads none: every version stays as marked.
fn unread(_: Fr, _: &[String]) -> Result<Option<Vec<VersionView>>, Refusal> {
    Ok(None)
}

/// Run `f` on the three nodes at once, one thread each, over one local mesh.
fn session<T: Send>(
    nodes: &[Node<TestStore>],
    f: impl Fn(&Node<TestStore>, &LocalNetwork) -> T + Sync,
) -> Vec<T> {
    std::thread::scope(|s| {
        let handles: Vec<_> = nodes
            .iter()
            .zip(LocalNetwork::new_3_parties())
            .map(|(node, net)| {
                let f = &f;
                s.spawn(move || f(node, &net))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

/// The audit of the namespace, each node's findings.
fn audit_each(net: &Network, circuit: &Circuit) -> Vec<Vec<KeyAudit>> {
    let started = Instant::now();
    let found = session(&net.nodes, |node, mesh| {
        let targets = audit::targets(&node.store, ns()).unwrap();
        audit::audit(circuit, &node.crs, ns(), targets, mesh).unwrap()
    });
    eprintln!(
        "AUDIT: {:.3}s on three nodes",
        started.elapsed().as_secs_f64()
    );
    found
}

/// The audit of the namespace at all three nodes, which must agree.
fn audit_all(net: &Network, circuit: &Circuit) -> Vec<KeyAudit> {
    let found = audit_each(net, circuit);
    assert!(found.iter().all(|f| *f == found[0]), "{found:?}");
    found[0].clone()
}

/// The resync of `scope` of `lost` as the node's admin socket runs it,
/// with `tamper` applied to node `from`'s contents before it seals them.
fn resync_all(
    net: &Network,
    circuit: &Circuit,
    lost: usize,
    scope: &Scope,
    tamper: impl Fn(usize, &mut Contents) + Sync,
) -> Vec<Result<ResyncReport, Refusal>> {
    net.resync(circuit, lost, scope, None, &unread, tamper)
}

/// The restore of `lost` from `backup` as the admin socket runs it: a
/// delta resync.
fn restore_all(
    net: &Network,
    circuit: &Circuit,
    lost: usize,
    backup: &StoreExport,
) -> Vec<Result<ResyncReport, Refusal>> {
    net.resync(
        circuit,
        lost,
        &Scope::Delta,
        Some(backup),
        &unread,
        |_, _| {},
    )
}

/// Node `i`'s rows of the namespace, without the parts each node marks
/// against its own chain view.
#[derive(Debug, PartialEq)]
struct Rows {
    namespace: Option<sidecar_core::store::NamespaceRow>,
    package: Option<sidecar_core::store::PackageRow>,
    versions: Vec<TipVersion>,
    nodes: BTreeMap<Fr, (TreeNode, u64)>,
    value: Option<ValueRow>,
    consumed: Vec<ConsumedRow>,
}

fn rows(store: &TestStore) -> Rows {
    let mut versions = Vec::new();
    for key in [FLAT, TREE] {
        for v in store.tip_versions(ns(), key).unwrap() {
            if v.status != VersionStatus::Orphan {
                versions.push(TipVersion { block: 0, ..v });
            }
        }
    }
    let book = book();
    let mut nodes = BTreeMap::new();
    for h in book
        .leaves
        .iter()
        .map(|l| l.1)
        .chain(book.inner.iter().map(|n| n.0))
    {
        if let Some(n) = store.tip_node(ns(), TREE, h).unwrap() {
            nodes.insert(h, (n.node, n.refs));
        }
    }
    Rows {
        namespace: store.namespace(ns()).unwrap(),
        package: store.package(ns(), "pss_seed").unwrap(),
        versions,
        nodes,
        value: store.value(ns(), POOL).unwrap(),
        consumed: store.consumed_rows(ns()).unwrap(),
    }
}

#[test]
fn the_audit_passes_canonical_versions_and_catches_a_wrong_vector() {
    let _serial = serial();
    let fx = fixture();
    let net = network(fx, 11);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let found = audit_all(&net, &circuit);
    let keys: Vec<(&str, usize, bool)> = found
        .iter()
        .map(|k| (k.key.as_str(), k.hashes, k.passed()))
        .collect();
    assert_eq!(keys, [(FLAT, 1, true), (TREE, 3, true)], "{found:?}");

    // a version whose pairs agree at all three nodes but open to a vector
    // its commitment does not name
    let slot = fr_from_hex(BAD).unwrap();
    let wrong = Held {
        commitment: audit::flat_commitment(ns(), slot, &[f(5), f(6)]),
        parent: f(0),
        index: 0,
        status: VersionStatus::Canonical,
        vecs: deal(&[f(5), f(7)], 9),
        tree: None,
    };
    for (i, node) in net.nodes.iter().enumerate() {
        write(&node.store, i, 3, BAD, std::slice::from_ref(&wrong), None);
    }
    let found = audit_all(&net, &circuit);
    let bad = found.iter().find(|k| k.key == BAD).unwrap();
    assert!(!bad.passed(), "{bad:?}");
    let why = bad.failure().unwrap();
    assert!(why.contains("not the version's commitment"), "{why}");
    assert!(found.iter().filter(|k| k.key != BAD).all(|k| k.passed()));
}

#[test]
fn a_lost_store_is_resynced_from_the_two_neighbours() {
    let _serial = serial();
    let fx = fixture();
    let mut net = network(fx, 12);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let lost = 1;
    let dead_note = f(0xdead);
    let rolled_back = rolled_back_record(&net, 1, dead_note);
    let dead_before = net.nodes[lost].store.dead_records(ns()).unwrap();
    assert_eq!(dead_before.len(), 1);
    let before = rows(&net.nodes[lost].store);
    assert_eq!(before.versions.len(), 3, "two flat, one tree");
    assert!(before.value.is_some() && before.consumed.len() == 1);
    assert_eq!(net.nodes[lost].store.receipts(ns()).unwrap().len(), 1);
    net.lose_store(fx, lost);
    assert!(net.nodes[lost].store.namespaces().unwrap().is_empty());

    let reports: Vec<ResyncReport> = resync_all(&net, &circuit, lost, &Scope::Store, |_, _| {})
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    // every check passed: the lost node serves again
    net.nodes[lost].check_serving().unwrap();
    for r in &reports {
        assert!(r.passed(), "{r:?}");
        assert_eq!(r.scope, Scope::Store);
        assert_eq!(r.npk_checked.len(), 1);
        assert_eq!(r.audit.len(), 2);
    }
    let imported = &reports[lost].imported;
    assert_eq!(
        (imported.namespaces, imported.packages, imported.versions),
        (1, 1, 3),
        "{imported:?}"
    );
    assert_eq!(
        (imported.values, imported.consumed, imported.dead_records),
        (1, 1, 1),
        "{imported:?}"
    );
    // the hook sends no receipt row, so none is kept or left out
    assert_eq!(
        (imported.receipts, imported.receipts_left_out),
        (0, 0),
        "{imported:?}"
    );
    assert_eq!(
        reports[0].imported.receipts, 0,
        "node 0 sent no receipt row"
    );
    // the rebuilt rows are the lost ones: the nsk_app pair, the vectors'
    // pairs, the tree nodes and their counts, the values row with its
    // writer, the consumed row
    let after = rows(&net.nodes[lost].store);
    assert_eq!(after, before);
    // the dead record: step 7 at the rebuilt node refuses the record the
    // rolled-back round created, as the neighbours do
    assert_eq!(
        net.nodes[lost].store.dead_records(ns()).unwrap(),
        dead_before
    );
    for node in &net.nodes {
        refused_as_dead(&node.store, dead_note, rolled_back);
    }
    assert!(net.nodes[lost].store.receipts(ns()).unwrap().is_empty());
    let orphans = net.nodes[lost]
        .store
        .tip_versions(ns(), FLAT)
        .unwrap()
        .into_iter()
        .filter(|v| v.status == VersionStatus::Orphan)
        .count();
    assert_eq!(orphans, 0, "an orphan is not resynced");
    let shared = shared_receipt_row(9, 500, Some(50)).request_id;
    assert!(
        net.nodes[lost]
            .store
            .receipt(ns(), shared)
            .unwrap()
            .is_none()
    );
    assert!(net.nodes[0].store.receipt(ns(), shared).unwrap().is_some());
    // a second resync into the store it filled is refused at every node
    let again = resync_all(&net, &circuit, lost, &Scope::Store, |_, _| {});
    for r in again {
        let err = r.unwrap_err();
        assert!(err.message.contains("empty store"), "{err}");
    }
}

/// The audit and the resync mark every node's versions against its own
/// chain view before they read them, so a neighbour that has not run its
/// prune pass since the chain moved acts on the same versions as one that
/// has. The flat key's live version lands (the slot holds it, the head is
/// past its entry) and only node 2 prunes: the three nodes audit the landed
/// version. Then a replaced block puts the earlier commitment back and only
/// node 2 prunes again: the two neighbours send the same versions, and the
/// resync of node 1 and its audit pass.
#[test]
fn a_resync_and_an_audit_succeed_when_one_neighbour_has_not_pruned() {
    let _serial = serial();
    let fx = fixture();
    let mut net = network(fx, 17);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let held = flat();
    let (earlier, landed) = (held[0].commitment, held[1].commitment);
    let tree_c = book().commitment;
    let view = |slot: Fr, head: u64, block: u64| {
        move |_: Fr, keys: &[String]| -> Result<Option<Vec<VersionView>>, Refusal> {
            Ok(Some(
                keys.iter()
                    .map(|k| VersionView {
                        slot: if k == FLAT { slot } else { tree_c },
                        head,
                        block,
                        // the settled block lags 64 blocks behind each
                        // view, so the marks orphan versions and delete none
                        settled: block - 64,
                        ..Default::default()
                    })
                    .collect(),
            ))
        }
    };
    let status = |net: &Network, i: usize, c: Fr| {
        let v = net.nodes[i].store.tip_version(ns(), FLAT, c).unwrap();
        v.unwrap().status
    };
    use VersionStatus::{Canonical, Live, Orphan};

    // the live version lands; node 2 prunes, nodes 0 and 1 do not
    let lands = view(landed, 2, 150);
    NodeVersions::mark(&net.nodes[2].store, ns(), &lands).unwrap();
    assert_eq!(
        [0, 2].map(|i| (status(&net, i, earlier), status(&net, i, landed))),
        [(Canonical, Live), (Orphan, Canonical)]
    );
    let found = session(&net.nodes, |node, mesh| {
        let targets = audit::marked_targets(node, ns(), &lands).unwrap();
        audit::audit(&circuit, &node.crs, ns(), targets, mesh).unwrap()
    });
    for keys in &found {
        assert!(keys.iter().all(|k| k.passed()), "{keys:?}");
        let flat = keys.iter().find(|k| k.key == FLAT).unwrap();
        assert_eq!(flat.commitment, FieldHex(landed));
    }

    // a replaced block puts the earlier commitment back; node 2 prunes,
    // node 0 does not
    let replaced = view(earlier, 1, 160);
    NodeVersions::mark(&net.nodes[2].store, ns(), &replaced).unwrap();
    assert_eq!(
        [0, 2].map(|i| (status(&net, i, earlier), status(&net, i, landed))),
        [(Orphan, Canonical), (Canonical, Live)]
    );
    let lost = 1;
    // the versions each node holds, and how it marked them
    let marks = |net: &Network, i: usize| -> Vec<(String, Fr, VersionStatus)> {
        rows(&net.nodes[i].store)
            .versions
            .into_iter()
            .map(|v| (v.key, v.commitment, v.status))
            .collect()
    };
    let expected = marks(&net, 2);
    assert_eq!(expected.len(), 4, "the flat key's three, the tree's one");
    net.lose_store(fx, lost);
    let reports = net.resync(&circuit, lost, &Scope::Store, None, &replaced, |_, _| {});
    for r in reports {
        let r = r.unwrap();
        assert!(r.passed(), "{r:?}");
        let flat = r.audit.iter().find(|k| k.key == FLAT).unwrap();
        assert_eq!(flat.commitment, FieldHex(earlier));
    }
    assert_eq!(marks(&net, lost), expected);
    assert_eq!(marks(&net, 0), expected);
}

#[test]
fn a_wrong_component_is_caught_by_the_audit_or_the_npk_check() {
    let _serial = serial();
    let fx = fixture();
    let mut net = network(fx, 13);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let lost = 2;

    // node 0 (lost + 1) sends a wrong component of the flat key's canonical
    // version: components are [master, nsk_app, versions..., leaves...]
    net.lose_store(fx, lost);
    let reports = resync_all(&net, &circuit, lost, &Scope::Store, |from, c| {
        if from == 0 {
            let at = canonical_component(c, FLAT);
            c.components[at] += Fr::from(1u64);
        }
    });
    for r in &reports {
        let r = r.as_ref().unwrap();
        assert_eq!(r.npk_checked.len(), 1);
        let flat = r.audit.iter().find(|k| k.key == FLAT).unwrap();
        assert!(!flat.passed(), "{flat:?}");
        let why = flat.failure().unwrap();
        assert!(why.contains("not shared consistently"), "{why}");
        assert!(r.audit.iter().find(|k| k.key == TREE).unwrap().passed());
    }
    // the lost node imported and a key failed: it serves no round until a
    // resync passes; its neighbours serve on
    let err = net.nodes[lost].check_serving().unwrap_err();
    assert!(err.message.contains("store resync's import"), "{err}");
    net.nodes[0].check_serving().unwrap();

    // node 0 sends a wrong nsk_app component: the npk_app_hash check
    // refuses at every node
    net.lose_store(fx, lost);
    let reports = resync_all(&net, &circuit, lost, &Scope::Store, |from, c| {
        if from == 0 {
            c.components[1] += Fr::from(1u64);
        }
    });
    for r in reports {
        let err = r.unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
        assert!(err.message.contains("nsk_app"), "{err}");
    }

    // node 0 sends a wrong component of the values row (the last shared
    // element sent): the values check refuses at every node, naming it
    net.lose_store(fx, lost);
    let reports = resync_all(&net, &circuit, lost, &Scope::Store, |from, c| {
        if from == 0 {
            *c.components.last_mut().unwrap() += Fr::from(1u64);
        }
    });
    for r in reports {
        let err = r.unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
        assert!(err.message.contains("value `pool`"), "{err}");
    }
    assert!(net.nodes[lost].check_serving().is_err());
}

/// Commit `txn`'s writes at `store` as a round would (with a request row).
fn damage(store: &TestStore, n: u8, f: impl FnOnce(&mut sidecar_core::store::Txn)) {
    let mut txn = store.begin(ns());
    f(&mut txn);
    txn.put_request(NewRequest {
        request_id: RequestId(Fr::from(0x7000 + n as u64)),
        ..new_request(n, 3000 + n as u64)
    });
    store.commit(txn).unwrap();
}

#[test]
fn one_key_is_resynced_into_a_live_store() {
    let _serial = serial();
    let fx = fixture();
    let net = network(fx, 15);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let lost = 1;
    let store = &net.nodes[lost].store;
    let before = rows(store);
    let receipts_before = store.receipts(ns()).unwrap();

    // node 1 loses the flat key's canonical version (its slot names a
    // commitment the node does not hold) and holds one leaf of the tree
    // with a wrong component (a diverged tree)
    let canonical = store
        .tip_versions(ns(), FLAT)
        .unwrap()
        .into_iter()
        .find(|v| v.status == VersionStatus::Canonical)
        .unwrap();
    let (hash, leaf) = book()
        .leaves
        .iter()
        .map(|l| (l.1, store.tip_node(ns(), TREE, l.1).unwrap().unwrap()))
        .next()
        .unwrap();
    let TreeNode::Leaf { index, mut vec } = leaf.node.clone() else {
        panic!("a leaf")
    };
    if let Elem::Shared(s) = &mut vec[0] {
        s.a += Fr::from(1u64);
    }
    damage(store, 1, |txn| {
        txn.version(VersionWrite::Delete {
            key: FLAT.into(),
            commitment: canonical.commitment,
        });
        txn.node(
            TREE,
            hash,
            Some(StoredNode {
                node: TreeNode::Leaf { index, vec },
                refs: leaf.refs,
            }),
        );
    });
    // node 0 audits both keys and fails both (node 1 holds no canonical
    // version of the flat key, and its leaf is not shared consistently)
    let found = &audit_each(&net, &circuit)[0];
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found.iter().all(|k| !k.passed()), "{found:?}");

    for (key, versions) in [(FLAT, 2), (TREE, 1)] {
        let scope = Scope::Key {
            namespace: FieldHex(ns()),
            key: key.into(),
        };
        for r in resync_all(&net, &circuit, lost, &scope, |_, _| {}) {
            let r = r.unwrap();
            assert_eq!(r.scope, scope);
            assert!(r.npk_checked.is_empty());
            assert_eq!(r.audit.len(), 1, "{r:?}");
            assert_eq!(r.audit[0].key, key);
            assert!(r.passed(), "{r:?}");
            assert_eq!(r.imported.versions, versions, "{:?}", r.imported);
            assert_eq!((r.imported.packages, r.imported.values), (0, 0));
        }
    }
    // the key's rows are the neighbours' again; the rest is untouched
    assert_eq!(rows(store), before);
    assert_eq!(store.receipts(ns()).unwrap(), receipts_before);
    assert!(audit_all(&net, &circuit).iter().all(|k| k.passed()));

    // a key the neighbours hold no version of
    let absent = Scope::Key {
        namespace: FieldHex(ns()),
        key: "0xa0ff".into(),
    };
    for r in resync_all(&net, &circuit, lost, &absent, |_, _| {}) {
        let err = r.unwrap_err();
        assert!(
            err.message.contains("no canonical or live version"),
            "{err}"
        );
    }
    assert_eq!(rows(store), before);
}

#[test]
fn bundles_that_are_not_the_neighbours_are_refused() {
    let _serial = serial();
    let fx = fixture();
    let net = network(fx, 14);
    let pins = net.pins();
    let lost = 1;
    let keys = |i: usize| net.nodes[i].keys();
    let enc = |i: usize| keys(i).enc_pk();
    let from_next = resync::collect(
        &net.nodes[2],
        &locked(&net.nodes[2], &Scope::Store),
        lost,
        &Scope::Store,
        &unread,
    )
    .unwrap();
    let from_prev = resync::collect(
        &net.nodes[0],
        &locked(&net.nodes[0], &Scope::Store),
        lost,
        &Scope::Store,
        &unread,
    )
    .unwrap();
    let rebuild = |p: Contents, n: Contents, master: Share| {
        resync::rebuild(
            lost,
            p,
            n,
            &keys(lost),
            Some(master),
            &pins,
            None,
            &resync::NoReceiptResync,
        )
    };
    let mut r = rng(5);
    let bundle = resync::seal(&from_next, &keys(2), enc(lost), &mut r);
    let refused = |result: Result<Contents, Refusal>, needle: &str| {
        let err = result.unwrap_err();
        assert!(err.message.contains(needle), "{err}");
    };

    // the honest bundle opens to what was sealed
    let opened = resync::open(&bundle, &keys(lost), lost, 2, &pins.nodes[2].sig).unwrap();
    assert_eq!(opened, from_next);
    // checked against another node's sig key, or with its body changed
    refused(
        resync::open(&bundle, &keys(lost), lost, 2, &pins.nodes[0].sig),
        "not signed by its pinned sig key",
    );
    let mut changed = bundle.clone();
    changed.body = changed.body.replace("\"seq\":0", "\"seq\":1");
    assert_ne!(changed.body, bundle.body);
    refused(
        resync::open(&changed, &keys(lost), lost, 2, &pins.nodes[2].sig),
        "not signed",
    );
    // sealed to another node
    let elsewhere = resync::seal(&from_next, &keys(2), enc(0), &mut r);
    refused(
        resync::open(&elsewhere, &keys(lost), lost, 2, &pins.nodes[2].sig),
        "does not open",
    );

    // bodies that differ, and a master that is not the key directory's
    let mut other = from_prev.clone();
    other.body.namespaces[0].seq = 7;
    let err = rebuild(other, from_next.clone(), net.nodes[lost].master())
        .err()
        .unwrap();
    assert!(err.message.contains("namespace 0x"), "{err}");
    assert!(err.message.contains("row"), "{err}");
    let mut other = from_prev.clone();
    other.body.namespaces[0].dead.push(resync::DeadBody {
        note_hash: FieldHex(f(0xdead)),
        request_id: RequestId(f(0x8001)),
    });
    let err = rebuild(other, from_next.clone(), net.nodes[lost].master())
        .err()
        .unwrap();
    assert!(err.message.contains("dead records"), "{err}");
    let not_master = Share::new(Fr::from(1u64), Fr::from(2u64));
    let err = rebuild(from_prev.clone(), from_next.clone(), not_master)
        .err()
        .unwrap();
    assert!(err.message.contains("master"), "{err}");
    // bundles of another scope
    let key = Scope::Key {
        namespace: FieldHex(ns()),
        key: FLAT.into(),
    };
    let keyed = resync::collect(
        &net.nodes[0],
        &locked(&net.nodes[0], &key),
        lost,
        &key,
        &unread,
    )
    .unwrap();
    let err = rebuild(keyed, from_next.clone(), net.nodes[lost].master())
        .err()
        .unwrap();
    assert!(err.message.contains("scope"), "{err}");
    // into a store that holds the namespace
    let rebuilt = rebuild(from_prev, from_next, net.nodes[lost].master()).unwrap();
    let err = resync::import(&net.nodes[lost].store, rebuilt).unwrap_err();
    assert_eq!(err.class, ErrorClass::Conflict, "{err}");

    // pins whose own entry is not the node's
    let mut wrong = pins;
    wrong.nodes.swap(0, 1);
    let err = resync::check_own_pins(&keys(0), 0, &wrong).unwrap_err();
    assert!(err.message.contains("not this node's"), "{err}");
}

/// The client-held key of the records the rounds below create.
const RECORD: &str = "0xff02";

/// A client-held round `n` at every node that creates one record under
/// `note_hash` (a round that creates a dead record's note hash clears its
/// mark).
fn record_round(net: &Network, n: u8, note_hash: Fr) -> RequestId {
    let id = RequestId(f(0x8000 + n as u64));
    for node in &net.nodes {
        let mut txn = node.store.begin(ns());
        txn.add_record(RECORD, note_hash, vec![n, 1, 2]);
        txn.put_request(NewRequest {
            request_id: id,
            ..new_request(n, 4000 + n as u64)
        });
        node.store.commit(txn).unwrap();
    }
    id
}

/// [`record_round`], rolled back at every node: its record is dead.
fn rolled_back_record(net: &Network, n: u8, note_hash: Fr) -> RequestId {
    let id = record_round(net, n, note_hash);
    for node in &net.nodes {
        rules::restore(&node.store, &node.keys(), ns(), id).unwrap();
    }
    id
}

/// Step 7 at `store`: the record under `note_hash` is dead, created by the
/// rolled-back request `id`, and refused without naming that request.
fn refused_as_dead(store: &TestStore, note_hash: Fr, id: RequestId) {
    let dead = store.dead_record(ns(), note_hash).unwrap().unwrap();
    assert_eq!(dead.request_id, id);
    let err = dead::check_dead(store, ns(), RECORD, note_hash).unwrap_err();
    assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
    assert!(
        !err.message.contains(&id.to_string()) && err.message.contains("rolled back"),
        "{err}"
    );
}

#[test]
fn a_restored_backup_is_delta_resynced_from_the_neighbours() {
    let _serial = serial();
    let fx = fixture();
    let mut net = network(fx, 16);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let lost = 1;
    let dead_note = f(0xdead);
    let rolled_back = rolled_back_record(&net, 1, dead_note);
    let backup = backup::export(&net.nodes[lost], &unread).unwrap();
    let counts = backup.counts();
    assert_eq!(
        (counts.namespaces, counts.versions, counts.tree_nodes),
        (1, 3, book().leaves.len() + book().inner.len()),
        "{counts:?}"
    );
    assert_eq!(
        (counts.values, counts.consumed, counts.receipts),
        (1, 1, 1),
        "{counts:?}"
    );
    let requests = net.nodes[lost].store.requests(ns()).unwrap();
    assert_eq!(counts.requests, requests.len());
    // the backup is taken with a dead record in the store, which it does
    // not carry
    let dead_at_backup = net.nodes[lost].store.dead_record(ns(), dead_note).unwrap();
    assert_eq!(dead_at_backup.map(|d| d.request_id), Some(rolled_back));

    // after the backup: a live version of the flat key on the live one, a
    // second rolled-back round, and a round that
    // creates the first dead record's note hash again (clearing its mark),
    // at every node
    let slot = fr_from_hex(FLAT).unwrap();
    let live = flat()[1].commitment;
    let values = [f(1150), f(1850), f(34)];
    let newer = Held {
        commitment: audit::flat_commitment(ns(), slot, &values),
        parent: live,
        index: 2,
        status: VersionStatus::Live,
        vecs: deal(&values, 60),
        tree: None,
    };
    for (i, node) in net.nodes.iter().enumerate() {
        write(&node.store, i, 5, FLAT, std::slice::from_ref(&newer), None);
    }
    let later_note = f(0xdead2);
    let later = rolled_back_record(&net, 2, later_note);
    record_round(&net, 3, dead_note);
    let dead_before = net.nodes[lost].store.dead_records(ns()).unwrap();
    assert_eq!(dead_before.len(), 1, "{dead_before:?}");
    let before = rows(&net.nodes[lost].store);
    assert_eq!(before.versions.len(), 4, "three flat, one tree");
    let receipts_before = net.nodes[lost].store.receipts(ns()).unwrap();
    net.lose_store(fx, lost);

    let reports: Vec<ResyncReport> = restore_all(&net, &circuit, lost, &backup)
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    for r in &reports {
        assert!(r.passed(), "{r:?}");
        assert_eq!(r.scope, Scope::Delta);
        assert_eq!(r.npk_checked.len(), 1);
        assert_eq!(r.audit.len(), 2);
    }
    let imported = &reports[lost].imported;
    assert_eq!(imported.versions, 4, "{imported:?}");
    // the pairs of the two flat versions, the tree version, its three
    // leaves and the values row from the backup; the newer version's from
    // the neighbours
    assert_eq!(imported.from_backup, 2 + 1 + 3 + 1, "{imported:?}");
    // the `requests` rows from the backup; the dead records from the
    // neighbours, whose set is the current one: the later rollback's record
    // is dead, the backup's dead record (created again since) is not
    assert_eq!(
        (imported.requests, imported.dead_records),
        (requests.len(), 1),
        "{imported:?}"
    );
    let store = &net.nodes[lost].store;
    assert_eq!(rows(store), before);
    assert_eq!(store.requests(ns()).unwrap(), requests);
    assert_eq!(store.dead_records(ns()).unwrap(), dead_before);
    refused_as_dead(store, later_note, later);
    assert_eq!(store.dead_record(ns(), dead_note).unwrap(), None);
    dead::check_dead(store, ns(), RECORD, dead_note).unwrap();
    // the receipt row no neighbour sends is back from the backup
    assert_eq!(store.receipts(ns()).unwrap(), receipts_before);
    assert_eq!(receipts_before.len(), 1);

    // the neighbours sent the components of the newer version only (and the
    // master's and the nsk_app's)
    let held = backup::Own::new(&backup).held();
    let sent = resync::collect(
        &net.nodes[0],
        &locked(&net.nodes[0], &Scope::Delta),
        lost,
        &Scope::Delta,
        &unread,
    )
    .unwrap();
    assert_eq!(resync::omit(sent, &held).unwrap().components.len(), 2 + 3);

    // another node's backup is refused at every node
    net.lose_store(fx, lost);
    let other = StoreExport {
        party: 0,
        ..backup.clone()
    };
    for r in restore_all(&net, &circuit, lost, &other) {
        let err = r.unwrap_err();
        assert!(err.message.contains("node 0's"), "{err}");
    }
    assert!(net.nodes[lost].store.namespaces().unwrap().is_empty());
}

/// A tree of `leaves` stored leaves under `key` at every node of `net`
/// (canonical, depth 5), each [value, blinding]; the leaf at `wrong` is
/// shared as another value than its hash names.
fn big_tree(net: &Network, key: &str, leaves: u64, wrong: u64) {
    let slot = fr_from_hex(key).unwrap();
    let depth = 5;
    let z = tree::zeros(depth);
    let mut dealt = Vec::new();
    for index in 0..leaves {
        let values = [f(300 + index), f(9000 + index)];
        let hash = tree::leaf_hash(ns(), slot, index, &values);
        let shared = if index == wrong {
            [f(301 + index), values[1]]
        } else {
            values
        };
        dealt.push((index, hash, deal(&shared, 70 + index)));
    }
    let empty = |_: Fr| -> Result<Option<TreeNode>, Refusal> { Ok(None) };
    let changes: Vec<(u64, Fr)> = dealt.iter().map(|(i, h, _)| (*i, *h)).collect();
    let rebuilt = tree::rebuild(&empty, &z, z[depth as usize], &changes).unwrap();
    let book = Book {
        root: rebuilt.root,
        commitment: tree::commitment(ns(), slot, rebuilt.root),
        leaves: dealt,
        inner: rebuilt.added.into_iter().map(|(h, _, n)| (h, n)).collect(),
    };
    let version = Held {
        commitment: book.commitment,
        parent: f(0),
        index: 0,
        status: VersionStatus::Canonical,
        vecs: Default::default(),
        tree: Some(VersionTree::Clear(TreeRoot {
            root: book.root,
            next: leaves,
        })),
    };
    for (i, node) in net.nodes.iter().enumerate() {
        let one = std::slice::from_ref(&version);
        write(&node.store, i, 6, key, one, Some(&book));
    }
}

#[test]
fn a_tree_larger_than_one_audit_round_is_audited_in_chunks() {
    let _serial = serial();
    let fx = fixture();
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let leaves = AUDIT_ITEMS as u64 + 4;

    let mut net = Network::new(fx, 17);
    net.register(fx, NS, "amm", &["pss_seed"]);
    big_tree(&net, TREE, leaves, u64::MAX);
    let found = audit_all(&net, &circuit);
    assert_eq!(found.len(), 1, "{found:?}");
    let key = &found[0];
    assert!(key.passed(), "{key:?}");
    assert_eq!((key.hashes, key.rounds), (leaves as usize, 2), "{key:?}");

    // the same tree with leaf 17, in the second chunk, shared wrongly at
    // every node: the second round fails the key, naming the leaf
    let mut net = Network::new(fx, 18);
    net.register(fx, NS, "amm", &["pss_seed"]);
    big_tree(&net, TREE, leaves, 17);
    let found = audit_all(&net, &circuit);
    let key = &found[0];
    assert!(!key.passed(), "{key:?}");
    assert_eq!(key.rounds, 2, "{key:?}");
    let why = key.failure().unwrap();
    assert!(
        why.contains("leaf 17") && why.contains("leaf hash"),
        "{why}"
    );
}

// ---------------------------------------------------------------------------
// Node replacement (sidecar_core::replace)
// ---------------------------------------------------------------------------

/// A node's replacement persistence, in memory: its refresh journal and the
/// last master share it wrote.
#[derive(Default)]
struct MemPersist {
    journal: std::sync::Mutex<Option<replace::Journal>>,
    master: std::sync::Mutex<Option<Share>>,
}

impl replace::Persist for MemPersist {
    fn journal(&self) -> Result<Option<replace::Journal>, Refusal> {
        Ok(self.journal.lock().unwrap().clone())
    }
    fn save_journal(&self, journal: &replace::Journal) -> Result<(), Refusal> {
        *self.journal.lock().unwrap() = Some(journal.clone());
        Ok(())
    }
    fn clear_journal(&self) -> Result<(), Refusal> {
        *self.journal.lock().unwrap() = None;
        Ok(())
    }
    fn save_master(&self, master: Share) -> Result<(), Refusal> {
        *self.master.lock().unwrap() = Some(master);
        Ok(())
    }
}

/// A newcomer in place `departed`: fresh keys, the zero master pair, an
/// empty store.
fn newcomer(fx: &Fixture, departed: usize, seed: u64) -> Node<TestStore> {
    let keys = sidecar_core::keys::NodeKeys::generate(&mut rng(seed));
    let zero = Share::new(Fr::from(0u64), Fr::from(0u64));
    Node::new(departed, keys, zero, TestStore::default(), fx.crs.clone()).unwrap()
}

/// The replacement of `departed` at all three nodes of `net` (the newcomer
/// already in its place), each with its persistence, declaring the
/// namespace at key epoch 1.
fn replace_all(
    net: &Network,
    circuit: &Circuit,
    departed: usize,
    persist: &[MemPersist; NODES],
) -> Vec<Result<replace::ReplaceReport, Refusal>> {
    let pins = net.pins();
    let started = Instant::now();
    let out = session(&net.nodes, |node, mesh| {
        let hs = Handshake::build(
            replace::session_id(),
            replace::session_body(departed, &pins),
            &[],
            &[],
        );
        handshake::exchange(mesh, &hs)?;
        replace::replace(
            node,
            &locked(node, &Scope::Replace),
            circuit,
            mesh,
            departed,
            &pins,
            &persist[node.index],
            &unread,
            &[(ns(), 1)],
            &mut rng(40 + node.index as u64),
        )
    });
    eprintln!(
        "REPLACE: {:.3}s on three nodes",
        started.elapsed().as_secs_f64()
    );
    out
}

/// Every namespace lock a session of `scope` at `node` holds.
fn locked<'a>(node: &'a Node<TestStore>, scope: &Scope) -> NamespacesGuard<'a> {
    node.lock_namespaces(scope.namespaces(&node.store).unwrap())
}

/// The opened sum of the three pairs' first components.
fn opened(shares: [Share; NODES]) -> Fr {
    shares[0].a + shares[1].a + shares[2].a
}

/// Node replacement: node 2 departs and a newcomer with fresh keys and an
/// empty store takes its place. The two remaining nodes refresh every pair
/// they hold (the master, the nsk_app, every version in any status, every
/// leaf, the `values` row) and delete their `requests` rows; the newcomer
/// imports its pairs from them and installs the master; the npk_app_hash
/// check, the `values` check and the audit pass at all three; every value
/// opens as before, and the departed node's old pair, with either remaining
/// node's new pair, no longer does. The two remaining nodes' rotate_keys
/// signatures of the new key set reach all three nodes and verify under the
/// current set.
#[test]
fn a_departed_node_is_replaced_after_a_share_refresh() {
    let _serial = serial();
    let fx = fixture();
    let mut net = network(fx, 21);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let departed = 2;
    let old_pins = net.pins();
    let nsk =
        |net: &Network, i: usize| net.nodes[i].store.namespace(ns()).unwrap().unwrap().nsk_app;
    let old_nsk = [0, 1, 2].map(|i| nsk(&net, i));
    let old_master = [0, 1, 2].map(|i| net.nodes[i].master());
    let orphan_before = |net: &Network, i: usize| {
        net.nodes[i]
            .store
            .tip_versions(ns(), FLAT)
            .unwrap()
            .into_iter()
            .find(|v| v.status == VersionStatus::Orphan)
            .unwrap()
    };
    let old_orphan = orphan_before(&net, 0);
    assert!(!net.nodes[0].store.requests(ns()).unwrap().is_empty());
    net.nodes[departed] = newcomer(fx, departed, 77);

    let persist: [MemPersist; NODES] = Default::default();
    let reports: Vec<replace::ReplaceReport> = replace_all(&net, &circuit, departed, &persist)
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    for r in &reports {
        assert!(r.passed(), "{r:?}");
        assert_eq!(r.resync.scope, Scope::Replace);
        assert_eq!(r.resync.npk_checked.len(), 1);
        assert_eq!(r.resync.audit.len(), 2);
        assert_eq!(r.rotations, reports[0].rotations);
    }
    let refreshed = reports[0].refreshed.as_ref().unwrap();
    assert_eq!(
        (refreshed.namespaces, refreshed.versions, refreshed.values),
        (1, 4, 1),
        "three flat versions (the orphan too) and the tree's: {refreshed:?}"
    );
    assert!(
        refreshed.master && refreshed.requests_deleted >= 1,
        "{refreshed:?}"
    );
    assert!(reports[departed].refreshed.is_none());
    assert!(net.nodes[0].store.requests(ns()).unwrap().is_empty());
    // the rotation: the new key set, signed by nodes 0 and 1 under the
    // current set
    let rotation = &reports[0].rotations[0];
    assert_eq!((rotation.namespace, rotation.epoch), (FieldHex(ns()), 1));
    assert!(rotation.signatures[departed].is_none());
    assert!(rotation.verifies(&old_pins));
    assert_eq!(NodesResponse::from(rotation.keys), net.pins());
    // the master: persisted at every node, the same value, new pairs
    let new_master = [0, 1, 2].map(|i| net.nodes[i].master());
    for i in 0..NODES {
        assert_eq!(*persist[i].master.lock().unwrap(), Some(new_master[i]));
        assert_ne!(new_master[i], old_master[i]);
    }
    assert_eq!(opened(new_master), opened(old_master));
    // the nsk_app: the same value, and the departed pair combines with
    // neither remaining node's new pair
    let new_nsk = [0, 1, 2].map(|i| nsk(&net, i));
    assert_eq!(opened(new_nsk), opened(old_nsk));
    let gone = old_nsk[departed];
    assert_ne!(gone.a + gone.b + new_nsk[0].a, opened(old_nsk));
    assert_ne!(gone.a + gone.b + new_nsk[1].b, opened(old_nsk));
    // an orphaned version is refreshed too, and is not sent to the newcomer
    let new_orphan = orphan_before(&net, 0);
    assert_eq!(new_orphan.commitment, old_orphan.commitment);
    assert_ne!(new_orphan.vec, old_orphan.vec);
    assert!(
        net.nodes[departed]
            .store
            .tip_versions(ns(), FLAT)
            .unwrap()
            .iter()
            .all(|v| v.status != VersionStatus::Orphan)
    );
    // the journals are cleared, and the network audits as a whole
    assert!(persist.iter().all(|p| p.journal.lock().unwrap().is_none()));
    let found = audit_all(&net, &circuit);
    assert!(found.iter().all(|k| k.passed()), "{found:?}");
}

/// A crash between the two remaining nodes' commits: node 0 (the node after
/// the departed node 2) committed its refresh of the namespace and node 1
/// did not. Run again under the journal's seed, the shared component shows
/// node 0 a refresh ahead, so only node 1 refreshes the namespace, and the
/// replacement and the audit pass. A remaining node with no journal whose
/// copy is more than one refresh away is refused at both.
#[test]
fn a_refresh_one_node_committed_is_finished_by_the_other() {
    let _serial = serial();
    let fx = fixture();
    let mut net = network(fx, 22);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let departed = 2;
    let seed = Fr::from(0x5eedu64);
    let persist: [MemPersist; NODES] = Default::default();
    for i in [0, 1] {
        *persist[i].journal.lock().unwrap() = Some(replace::Journal {
            departed,
            seed: FieldHex(seed),
            generation: 0,
        });
    }
    let r = replace::Refresher::new(seed, 0, departed, 0).unwrap();
    let mut done = replace::Refreshed::default();
    replace::refresh_namespace(
        &net.nodes[0],
        &locked(&net.nodes[0], &Scope::Replace),
        ns(),
        &r,
        &mut done,
    )
    .unwrap();
    assert_eq!(done.namespaces, 1);
    net.nodes[departed] = newcomer(fx, departed, 78);
    let reports: Vec<replace::ReplaceReport> = replace_all(&net, &circuit, departed, &persist)
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    for r in &reports {
        assert!(r.passed(), "{r:?}");
    }
    assert_eq!(reports[0].refreshed.as_ref().unwrap().namespaces, 0);
    assert_eq!(reports[1].refreshed.as_ref().unwrap().namespaces, 1);
    let found = audit_all(&net, &circuit);
    assert!(found.iter().all(|k| k.passed()), "{found:?}");

    // node 0 refreshes twice under a seed node 1 does not know
    let mut net = network(fx, 23);
    let other = replace::Refresher::new(Fr::from(9u64), 0, departed, 0).unwrap();
    for _ in 0..2 {
        replace::refresh_namespace(
            &net.nodes[0],
            &locked(&net.nodes[0], &Scope::Replace),
            ns(),
            &other,
            &mut done,
        )
        .unwrap();
    }
    net.nodes[departed] = newcomer(fx, departed, 79);
    let persist: [MemPersist; NODES] = Default::default();
    for r in replace_all(&net, &circuit, departed, &persist) {
        let err = r.unwrap_err();
        assert!(err.message.contains("refresh"), "{err}");
    }
}

/// The key whose state lives in holder blobs, as an oblivious tree's does:
/// a canonical version whose tree root is 0 (no clear tree) and two blobs.
const OBL: &str = "0xa005";

/// A dealer's XOR sharing of `values` as node j's blob (`a` = `x_j`, `b` =
/// `x_{j-1}`), with `copy` held by nodes 1 and 2 (component 1).
fn deal_blob(values: &[u8], copy: &[u8], seed: u64) -> [Blob; NODES] {
    use ark_std::rand::RngCore;
    let mut r = rng(seed);
    let mut x0 = vec![0u8; values.len()];
    let mut x1 = vec![0u8; values.len()];
    r.fill_bytes(&mut x0);
    r.fill_bytes(&mut x1);
    let x2: Vec<u8> = values
        .iter()
        .zip(&x0)
        .zip(&x1)
        .map(|((v, a), b)| v ^ a ^ b)
        .collect();
    let x = [x0, x1, x2];
    [0, 1, 2].map(|j| Blob {
        public: b"shape".to_vec(),
        shares: Pair {
            a: x[j].clone(),
            b: x[(j + 2) % 3].clone(),
        },
        copies: Pair {
            a: if j == 1 { copy.to_vec() } else { vec![] },
            b: if j == 2 { copy.to_vec() } else { vec![] },
        },
    })
}

/// Node `i`'s blob `name` of the key OBL.
fn blob_of(net: &Network, i: usize, name: &str) -> Blob {
    let bytes = net.nodes[i].store.blob(ns(), OBL, name).unwrap();
    Blob::from_bytes(&bytes.unwrap_or_else(|| panic!("node {i} holds no blob {name}"))).unwrap()
}

/// The three nodes' blobs `name` are one sharing (node j's `a` is node
/// j+1's `b`, the public bytes alike); returns the values they open to and
/// the copy.
fn opened_blob(net: &Network, name: &str) -> (Vec<u8>, Vec<u8>) {
    let b = [0, 1, 2].map(|i| blob_of(net, i, name));
    for j in 0..NODES {
        let n = (j + 1) % 3;
        assert_eq!(b[j].shares.a, b[n].shares.b, "blob {name}: node {j}'s a");
        assert_eq!(
            b[j].copies.a, b[n].copies.b,
            "blob {name}: node {j}'s copies"
        );
        assert_eq!(b[j].public, b[n].public, "blob {name}");
    }
    let open: Vec<u8> = (0..b[0].shares.a.len())
        .map(|k| b[0].shares.a[k] ^ b[1].shares.a[k] ^ b[2].shares.a[k])
        .collect();
    (open, b[1].copies.a.clone())
}

/// The key OBL at every node: its version and its blobs `head` (values
/// `head`) and `level` (values `level`, with a copy).
fn write_blobs(net: &Network, head: &[u8], level: &[u8], seed: u64) {
    let heads = deal_blob(head, &[], seed);
    let levels = deal_blob(level, b"shuffle", seed + 1);
    let version = Held {
        commitment: f(0x0b1),
        parent: f(0),
        index: 0,
        status: VersionStatus::Canonical,
        vecs: deal(&[f(9), f(10)], seed + 2),
        tree: Some(VersionTree::Blobs { next: 1 }),
    };
    for (i, node) in net.nodes.iter().enumerate() {
        write(&node.store, i, 9, OBL, std::slice::from_ref(&version), None);
        let mut txn = node.store.begin(ns());
        txn.blob(OBL, "head", Some(heads[i].to_bytes()));
        txn.blob(OBL, "level", Some(levels[i].to_bytes()));
        node.store.commit(txn).unwrap();
    }
}

/// Holder blobs (an oblivious key's DORAM and journals: public bytes, XOR
/// share components, copies) are carried by every recovery path:
///
/// - a lost store is resynced with them, rebuilt from the components its
///   neighbours share with it, and the blob handshake compares them; the
///   key's version has no clear tree, so the audit recomputes no hash of
///   it and passes;
/// - a backup carries them; after the head blob changed, the restore takes
///   the unchanged level blob's two parts from the backup and the head from
///   the neighbours;
/// - a component one node holds differently from its neighbour is caught by
///   the blob handshake, naming the blob, at the two nodes that share it;
/// - a node replacement XORs a fresh zero-sharing into every blob's share
///   components at the two remaining nodes: every blob opens as before,
///   its copies and public bytes unchanged, the newcomer holds its part of
///   the same sharing, and the departed node's old pair combined with a
///   remaining node's new component no longer opens.
#[test]
fn holder_blobs_are_carried_by_every_recovery_path() {
    let _serial = serial();
    let fx = fixture();
    let mut net = network(fx, 23);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let head: Vec<u8> = (0..100u8).collect();
    let level: Vec<u8> = (0..77u8).map(|b| b.wrapping_mul(3)).collect();
    write_blobs(&net, &head, &level, 70);
    assert_eq!(
        opened_blob(&net, "level"),
        (level.clone(), b"shuffle".to_vec())
    );

    // ---- a lost store, resynced with its blobs ---------------------------
    let lost = 1;
    let before = [blob_of(&net, lost, "head"), blob_of(&net, lost, "level")];
    net.lose_store(fx, lost);
    for r in resync_all(&net, &circuit, lost, &Scope::Store, |_, _| {}) {
        let r = r.unwrap();
        assert!(r.passed(), "{r:?}");
        assert_eq!(r.blobs_checked, 2, "{r:?}");
        let obl = r.audit.iter().find(|k| k.key == OBL).unwrap();
        assert_eq!((obl.hashes, obl.rounds), (0, 0), "{obl:?}");
    }
    assert_eq!(blob_of(&net, lost, "head"), before[0]);
    assert_eq!(blob_of(&net, lost, "level"), before[1]);
    let v = net.nodes[lost].store.tip_versions(ns(), OBL).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].tree, Some(VersionTree::Blobs { next: 1 }));

    // ---- a backup, restored after the head changed -----------------------
    let backup = backup::export(&net.nodes[lost], &unread).unwrap();
    assert_eq!(backup.counts().blobs, 2);
    let head2: Vec<u8> = (0..100u8).rev().collect();
    let heads = deal_blob(&head2, &[], 80);
    for (i, node) in net.nodes.iter().enumerate() {
        let mut txn = node.store.begin(ns());
        txn.blob(OBL, "head", Some(heads[i].to_bytes()));
        node.store.commit(txn).unwrap();
    }
    let current = blob_of(&net, lost, "head");
    net.lose_store(fx, lost);
    let reports: Vec<ResyncReport> = restore_all(&net, &circuit, lost, &backup)
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    for r in &reports {
        assert!(r.passed(), "{r:?}");
        assert_eq!(r.blobs_checked, 2);
    }
    assert_eq!(reports[lost].imported.blobs, 2);
    assert_eq!(
        reports[lost].imported.blob_parts_from_backup, 2,
        "the level's two parts"
    );
    assert_eq!(blob_of(&net, lost, "head"), current);
    assert_eq!(blob_of(&net, lost, "level"), before[1]);
    assert_eq!(opened_blob(&net, "head").0, head2);

    // ---- a component held differently is caught by the blob handshake ----
    let damaged = |net: &Network, flip: u8| {
        let mut b = blob_of(net, 0, "level");
        b.shares.a[5] ^= flip;
        let mut txn = net.nodes[0].store.begin(ns());
        txn.blob(OBL, "level", Some(b.to_bytes()));
        net.nodes[0].store.commit(txn).unwrap();
    };
    damaged(&net, 1);
    let checked = session(&net.nodes, |node, mesh| {
        resync::check_blobs(node, ns(), None, mesh)
    });
    for i in [0, 1] {
        let err = checked[i].as_ref().unwrap_err();
        assert!(err.message.contains("blob `level`"), "node {i}: {err}");
    }
    assert_eq!(checked[2].as_ref().unwrap(), &2);
    damaged(&net, 1);

    // ---- a node replacement refreshes them ---------------------------------
    let departed = 2;
    let old = blob_of(&net, departed, "level");
    let old0 = blob_of(&net, 0, "level");
    net.nodes[departed] = newcomer(fx, departed, 81);
    let persist: [MemPersist; NODES] = Default::default();
    let reports: Vec<replace::ReplaceReport> = replace_all(&net, &circuit, departed, &persist)
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    for r in &reports {
        assert!(r.passed(), "{r:?}");
        assert_eq!(r.resync.blobs_checked, 2);
    }
    for i in [0, 1] {
        assert_eq!(reports[i].refreshed.as_ref().unwrap().blobs, 2);
    }
    assert_eq!(
        opened_blob(&net, "level"),
        (level.clone(), b"shuffle".to_vec())
    );
    assert_eq!(opened_blob(&net, "head").0, head2);
    let now = [0, 1].map(|i| blob_of(&net, i, "level"));
    assert_ne!(now[0].shares, old0.shares, "fresh components");
    assert_eq!(now[0].copies, old0.copies, "copies are not shares");
    // the departed pair (x_2, x_1) with node 0's new x_0 opens to something
    // else
    let stale: Vec<u8> = (0..level.len())
        .map(|k| old.shares.a[k] ^ old.shares.b[k] ^ now[0].shares.a[k])
        .collect();
    assert_ne!(stale, level);
}

/// `resync::run` and `replace::replace` refuse a node index that is not 0, 1
/// or 2 before they exchange anything.
#[test]
fn recovery_refuses_a_node_index_out_of_range() {
    let _serial = serial();
    let fx = fixture();
    let net = network(fx, 24);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let pins = net.pins();
    let [mesh, _, _] = LocalNetwork::new_3_parties();
    let err = resync::run(
        &net.nodes[0],
        &circuit,
        &mesh,
        NODES,
        &Scope::Store,
        &pins,
        None,
        None,
        &mut rng(0),
    )
    .unwrap_err();
    assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
    assert!(err.message.contains("3 is not a node index"), "{err}");
    let err = replace::replace(
        &net.nodes[0],
        &locked(&net.nodes[0], &Scope::Replace),
        &circuit,
        &mesh,
        NODES,
        &pins,
        &MemPersist::default(),
        &unread,
        &[],
        &mut rng(0),
    )
    .unwrap_err();
    assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
    assert!(err.message.contains("3 is not a node index"), "{err}");
}
