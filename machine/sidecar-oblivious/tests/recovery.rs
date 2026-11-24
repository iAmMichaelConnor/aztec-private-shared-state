//! An oblivious key's state carried by node recovery, on three in-process
//! nodes (sidecar-core's `testing` harness, mpc_net's local network) with
//! the namespace registered by the real registration circuit: the dense
//! DORAM of a depth-7 tree (a speed cache and two levels) built at the
//! three nodes, leaves written (enough
//! accesses for level rebuilds), the journal of the last write and the
//! key's version committed to each store as the holder commits them (the
//! head, one blob per live level, the journal).
//!
//! - A node's store deleted (its key directory kept) is resynced from its
//!   two neighbours; a backup of a node, taken before further writes, is
//!   restored by a delta resync; a departed node is replaced by a newcomer
//!   after the two remaining nodes refresh every blob's share components.
//! - After each, a session reads the key from the three stores: each node
//!   loads its DORAM, the three read every written leaf's path at an
//!   address converted from a secret-shared index, and the opened values are
//!   the clear tree's; the journal carried with it undoes the last write,
//!   after which the leaf reads as before that write.
//!
//! Needs `scripts/prepare-data.sh` (pss_seed and the CRS under machine/data,
//! or DATA_DIR): skipped without them, a failure under `PSS_REQUIRE_DATA=1`.
//! Run with `--release`.

use std::collections::BTreeMap;

use ark_ff::PrimeField;
use mpc_core::protocols::rep3::arithmetic::promote_to_trivial_share;
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{Rep3State, id::PartyID};
use mpc_net::local::LocalNetwork;
use primitives::{X, open_many_y, promote_public};
use sidecar_core::audit;
use sidecar_core::backup::{self, StoreExport};
use sidecar_core::bind::{Elem, Share};
use sidecar_core::crs::Circuit;
use sidecar_core::error::Refusal;
use sidecar_core::field::{Fr, RequestId};
use sidecar_core::handshake::{self, Handshake};
use sidecar_core::pipeline::Node;
use sidecar_core::replace;
use sidecar_core::request::NODES;
use sidecar_core::response::NodesResponse;
use sidecar_core::resync::{self, ResyncReport, Scope};
use sidecar_core::state::VersionViews;
use sidecar_core::store::rules::VersionView;
use sidecar_core::store::testing::new_request;
use sidecar_core::store::{Store, StoreRead, TipVersion, VersionStatus, VersionTree, VersionWrite};
use sidecar_core::testing::{Fixture, Network, TestStore, rng, serial};
use sidecar_core::tree::{leaf_hash, node};
use sidecar_oblivious::holder::journal_blob;
use sidecar_oblivious::oram::{field_to_values, indices_to_xor};
use sidecar_oblivious::{Addressing, Doram, Journal, Layout, SlotJournal};

const NS: u64 = 0xc0ffee;
const KEY: &str = "0xa003";
const DEPTH: u32 = 7;
const W: usize = 2;

fn ns() -> Fr {
    Fr::from(NS)
}

type Leaves = BTreeMap<u64, [u64; W]>;

/// The clear tree with `leaves`, level by level.
fn clear_tree(leaves: &Leaves) -> Vec<Vec<Fr>> {
    let mut level = vec![Fr::from(0u64); 1 << DEPTH];
    for (i, leaf) in leaves {
        let leaf: Vec<Fr> = leaf.iter().map(|x| Fr::from(*x)).collect();
        level[*i as usize] = leaf_hash(ns(), Fr::from(0xa003u64), *i, &leaf);
    }
    let mut out = vec![level.clone()];
    for _ in 0..DEPTH {
        level = (0..level.len() / 2)
            .map(|p| node(level[2 * p], level[2 * p + 1]))
            .collect();
        out.push(level.clone());
    }
    out
}

/// What a slot read of leaf `i` returns: siblings bottom up, the leaf hash,
/// the elements.
fn expected_read(leaves: &Leaves, i: u64) -> Vec<<Fr as PrimeField>::BigInt> {
    let t = clear_tree(leaves);
    let mut out: Vec<Fr> = (0..DEPTH as usize)
        .map(|h| t[h][((i >> h) ^ 1) as usize])
        .collect();
    out.push(t[0][i as usize]);
    let leaf = leaves.get(&i).copied().unwrap_or([0; W]);
    out.extend(leaf.iter().map(|x| Fr::from(*x)));
    out.iter().map(|v| v.into_bigint()).collect()
}

/// What a slot write of leaf `i` stores: the elements, the hash, the path
/// nodes of heights 1 to D.
fn write_values(leaves: &Leaves, i: u64) -> Vec<Fr> {
    let t = clear_tree(leaves);
    let leaf = leaves.get(&i).copied().unwrap_or([0; W]);
    let mut out: Vec<Fr> = leaf.iter().map(|x| Fr::from(*x)).collect();
    out.push(t[0][i as usize]);
    out.extend((1..=DEPTH as usize).map(|h| t[h][(i >> h) as usize]));
    out
}

fn layout() -> Addressing {
    Addressing::new(DEPTH, W)
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

/// Write `writes` (leaf, value) in order into `d` at public paths, each
/// slot's stored vector the clear tree's after it; returns the journal of
/// the last write (applied: its old write values recorded).
fn write_leaves(
    d: &mut Doram<Addressing>,
    leaves: &mut Leaves,
    writes: &[(u64, [u64; W])],
    net: &LocalNetwork,
    state: &mut Rep3State,
) -> Journal {
    let a = layout();
    let id = state.id;
    let mut journal = Journal::default();
    for (i, leaf) in writes {
        leaves.insert(*i, *leaf);
        let path = a.mask_path(&promote_public(id, *i as X));
        let read = d.read_slot(&path, net, state).unwrap();
        let shares: Vec<_> = write_values(leaves, *i)
            .iter()
            .map(|v| promote_to_trivial_share(id, *v))
            .collect();
        let values = field_to_values(&shares, net, state).unwrap();
        let writes = a.slot_writes(id, &path);
        let old_writes = d.write_slot(&writes, &values, net, state).unwrap();
        journal = Journal {
            slots: vec![SlotJournal {
                reads: read.reads,
                old: read.raw,
                writes,
                old_writes,
            }],
        };
    }
    journal
}

/// Commit node `node`'s DORAM blob writes, the journal of `commitment` and
/// its canonical version (no clear tree: the append index alone), as the
/// holder's commit does.
fn commit(node: &Node<TestStore>, d: &mut Doram<Addressing>, commitment: u64, journal: &Journal) {
    let mut txn = node.store.begin(ns());
    for (name, bytes) in d.writes().unwrap() {
        txn.blob(KEY, &name, bytes);
    }
    let c = Fr::from(commitment);
    txn.blob(KEY, &journal_blob(c), Some(journal.to_bytes()));
    let parents = node.store.tip_versions(ns(), KEY).unwrap();
    for v in &parents {
        txn.version(VersionWrite::Mark {
            key: KEY.into(),
            commitment: v.commitment,
            status: VersionStatus::Orphan,
            block: 1,
            block_hash: Fr::from(0u64),
        });
    }
    txn.version(VersionWrite::Put(TipVersion {
        key: KEY.into(),
        commitment: c,
        parent: parents.last().map_or(Fr::from(0u64), |v| v.commitment),
        index: commitment,
        request_id: RequestId(Fr::from(0x1000 + commitment)),
        vec: vec![Elem::Public(Fr::from(0u64)); W + 1 + DEPTH as usize],
        tree: Some(VersionTree::Blobs { next: 1 }),
        status: VersionStatus::Canonical,
        block: 1,
        block_hash: Fr::from(0u64),
    }));
    txn.put_request(new_request(commitment as u8, 1000 + commitment));
    node.store.commit(txn).unwrap();
    d.persisted();
}

/// Read the key from the three stores: every leaf of `leaves` (and an empty
/// one) at an address converted from a secret-shared index opens to the
/// clear tree's path; then the journal of `last` undoes its write, after
/// which leaf `undone.0` reads as `undone.1` says.
fn read_back(net: &Network, leaves: &Leaves, last: u64, undone: (u64, Option<[u64; W]>)) {
    let a = layout();
    let mut probe: Vec<u64> = leaves.keys().copied().collect();
    probe.push(100);
    let opened = session(&net.nodes, |node, mesh| {
        let mut state = Rep3State::new(mesh, A2BType::Direct).unwrap();
        let id = PartyID::try_from(node.index).unwrap();
        let mut d = Doram::load(a, id, &node.store, ns(), KEY)
            .unwrap()
            .expect("the store holds the key's DORAM");
        // the indices as Rep3 shares of a dealer: (i - 33, 11, 22)
        let shares: Vec<Share> = probe
            .iter()
            .map(|i| {
                let x = [
                    Fr::from(*i) - Fr::from(33u64),
                    Fr::from(11u64),
                    Fr::from(22u64),
                ];
                Share::new(x[node.index], x[(node.index + 2) % 3])
            })
            .collect();
        let paths = indices_to_xor(&a, &shares, mesh, &mut state).unwrap();
        let mut out = Vec::new();
        for path in &paths {
            let read = d.read_slot(path, mesh, &mut state).unwrap();
            out.push(open_many_y(&read.values, mesh));
        }
        let bytes = node
            .store
            .blob(ns(), KEY, &journal_blob(Fr::from(last)))
            .unwrap()
            .expect("the journal is carried");
        d.undo(&Journal::from_bytes(&bytes).unwrap(), mesh, &mut state)
            .unwrap();
        let path = a.mask_path(&promote_public(id, undone.0 as X));
        let read = d.read_slot(&path, mesh, &mut state).unwrap();
        out.push(open_many_y(&read.values, mesh));
        out
    });
    let mut before = leaves.clone();
    match undone.1 {
        Some(leaf) => before.insert(undone.0, leaf),
        None => before.remove(&undone.0),
    };
    for got in &opened {
        for (k, i) in probe.iter().enumerate() {
            assert_eq!(got[k], expected_read(leaves, *i), "leaf {i}");
        }
        assert_eq!(
            got[probe.len()],
            expected_read(&before, undone.0),
            "leaf {} after the undo",
            undone.0
        );
    }
}

fn pins(net: &Network) -> NodesResponse {
    NodesResponse {
        nodes: [0, 1, 2].map(|i| net.nodes[i].keys().public_keys()),
    }
}

fn unread(_: Fr, _: &[String]) -> Result<Option<Vec<VersionView>>, Refusal> {
    Ok(None)
}

fn resync_session(
    net: &Network,
    circuit: &Circuit,
    lost: usize,
    scope: &Scope,
    backup: Option<&StoreExport>,
) -> Vec<ResyncReport> {
    let pins = pins(net);
    let views: &VersionViews<'_> = &unread;
    session(&net.nodes, |node, mesh| {
        let sent = (node.index != lost).then(|| {
            resync::collect(
                node,
                &node.lock_namespaces(scope.namespaces(&node.store).unwrap()),
                lost,
                scope,
                views,
            )
            .unwrap()
        });
        let hs = Handshake::build(
            resync::session_id(),
            resync::session_body(lost, scope, &pins),
            &[],
            &[],
        );
        handshake::exchange(mesh, &hs)?;
        resync::run(
            node,
            circuit,
            mesh,
            lost,
            scope,
            &pins,
            sent,
            backup.filter(|_| node.index == lost),
            &mut rng(node.index as u64),
        )
    })
    .into_iter()
    .map(|r| r.unwrap())
    .collect()
}

/// Node `i` with its keys and master share kept and an empty store.
fn lose_store(net: &mut Network, fx: &Fixture, i: usize) {
    let old = &net.nodes[i];
    net.nodes[i] = Node::new(
        i,
        old.keys().as_ref().clone(),
        old.master(),
        TestStore::default(),
        fx.crs.clone(),
    )
    .unwrap();
}

#[derive(Default)]
struct MemPersist {
    journal: std::sync::Mutex<Option<replace::Journal>>,
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
    fn save_master(&self, _: Share) -> Result<(), Refusal> {
        Ok(())
    }
}

/// The oblivious key's DORAM and journal survive a resync of a lost store,
/// a backup restored by a delta resync after further writes, and a node
/// replacement with its refresh; after each, the three stores read the
/// key's leaves at shared addresses as the clear tree has them, and the
/// carried journal undoes the last write.
#[test]
fn an_oblivious_key_is_carried_by_resync_backup_and_replacement() {
    let _serial = serial();
    // skipped, or failed under PSS_REQUIRE_DATA=1, without pss_seed and the CRS
    let Some(fx) = sidecar_core::testing::fixture(&["pss_seed"]) else {
        return;
    };
    let mut net = Network::new(fx, 31);
    net.register(fx, NS, "amm", &["pss_seed"]);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let a = layout();

    // ---- the key written at the three nodes ------------------------------
    // enough slot accesses to fill the speed cache (256 at this size) and
    // rebuild the level above the bottom one
    let mut first: Vec<(u64, [u64; W])> = (1..=16u64).map(|i| (20 + 6 * i, [i, 2 * i])).collect();
    first.insert(0, (3, [30, 7]));
    first.push((5, [50, 8]));
    let mut leaves = Leaves::new();
    let written = session(&net.nodes, |node, mesh| {
        let mut state = Rep3State::new(mesh, A2BType::Direct).unwrap();
        let mut d = Doram::build_empty(a, mesh, &mut state).unwrap();
        let mut l = Leaves::new();
        let journal = write_leaves(&mut d, &mut l, &first, mesh, &mut state);
        commit(node, &mut d, 1, &journal);
        l
    });
    leaves.extend(written[0].clone());
    let levels = net.nodes[0].store.blob_names(ns(), KEY).unwrap();
    assert!(
        levels
            .iter()
            .filter(|n| n.starts_with("oram.level."))
            .count()
            >= 2,
        "a rebuild made more than the bottom level: {levels:?}"
    );
    read_back(&net, &leaves, 1, (5, None));

    // ---- a lost store, resynced from the two neighbours --------------------
    let lost = 1;
    let held: Vec<(String, Vec<u8>)> = net.nodes[lost]
        .store
        .blob_names(ns(), KEY)
        .unwrap()
        .into_iter()
        .map(|n| {
            let b = net.nodes[lost].store.blob(ns(), KEY, &n).unwrap().unwrap();
            (n, b)
        })
        .collect();
    lose_store(&mut net, fx, lost);
    for r in resync_session(&net, &circuit, lost, &Scope::Store, None) {
        assert!(r.passed(), "{r:?}");
        assert_eq!(r.blobs_checked, held.len(), "{r:?}");
    }
    for (name, bytes) in &held {
        let got = net.nodes[lost].store.blob(ns(), KEY, name).unwrap();
        assert_eq!(got.as_ref(), Some(bytes), "blob {name}");
    }
    read_back(&net, &leaves, 1, (5, None));

    // ---- a backup, further writes, the store lost and restored -------------
    let backup = backup::export(&net.nodes[lost], &unread).unwrap();
    assert_eq!(backup.counts().blobs, held.len());
    let second: Vec<(u64, [u64; W])> = vec![(6, [60, 3]), (3, [31, 4])];
    let written = session(&net.nodes, |node, mesh| {
        let mut state = Rep3State::new(mesh, A2BType::Direct).unwrap();
        let id = PartyID::try_from(node.index).unwrap();
        let mut d = Doram::load(a, id, &node.store, ns(), KEY).unwrap().unwrap();
        let mut l = written[0].clone();
        let journal = write_leaves(&mut d, &mut l, &second, mesh, &mut state);
        commit(node, &mut d, 2, &journal);
        l
    });
    leaves = written[0].clone();
    lose_store(&mut net, fx, lost);
    let reports = resync_session(&net, &circuit, lost, &Scope::Delta, Some(&backup));
    for r in &reports {
        assert!(r.passed(), "{r:?}");
    }
    let imported = &reports[lost].imported;
    assert!(imported.blobs > 0, "{imported:?}");
    read_back(&net, &leaves, 2, (3, Some([30, 7])));

    // ---- a departed node replaced after the refresh ------------------------
    let departed = 2;
    let keys = sidecar_core::keys::NodeKeys::generate(&mut rng(90));
    let zero = Share::new(Fr::from(0u64), Fr::from(0u64));
    net.nodes[departed] =
        Node::new(departed, keys, zero, TestStore::default(), fx.crs.clone()).unwrap();
    let persist: [MemPersist; NODES] = Default::default();
    let pins = pins(&net);
    let reports = session(&net.nodes, |node, mesh| {
        let hs = Handshake::build(
            replace::session_id(),
            replace::session_body(departed, &pins),
            &[],
            &[],
        );
        handshake::exchange(mesh, &hs)?;
        replace::replace(
            node,
            &node.lock_namespaces(node.store.namespaces().unwrap()),
            &circuit,
            mesh,
            departed,
            &pins,
            &persist[node.index],
            &unread,
            &[(ns(), 1)],
            &mut rng(40 + node.index as u64),
        )
    });
    for r in reports {
        let r = r.unwrap();
        assert!(r.passed(), "{r:?}");
        assert!(r.resync.blobs_checked > 0, "{r:?}");
        if let Some(refreshed) = &r.refreshed {
            assert!(refreshed.blobs > 0, "{refreshed:?}");
        }
    }
    read_back(&net, &leaves, 2, (3, Some([30, 7])));
}
