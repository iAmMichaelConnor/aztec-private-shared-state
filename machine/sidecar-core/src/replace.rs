//! Node replacement (docs/ARCHITECTURE.md section 6, "Node replacement and
//! key epochs"; DECISIONS.md section 15): a newcomer takes the place of a
//! departed node, over one MPC session of the two remaining nodes and the
//! newcomer, run while the orchestrator has paused scheduling:
//!
//! ```text
//! refresh   the two remaining nodes only (the newcomer waits): a fresh zero-sharing
//!           added to every stored pair of every node-held value they hold (the master
//!           share, every namespace's nsk_app, every version of every tip key in any
//!           status, every leaf of its clear tree, every `values` row), and a fresh XOR
//!           zero-sharing XORed into the share components of every holder blob (the
//!           oblivious tree's DORAM levels and journals, crate::store::blob), never
//!           reconstructing anything; their `requests` rows are deleted
//! import    the newcomer's pairs from the two remaining nodes' bundles: the lost-store
//!           resync (crate::resync, Scope::Replace) with the master pair installed from
//!           the bundles instead of compared with a key directory's
//! check     per namespace the registration circuit on the installed master
//!           (npk_app_hash), the nsk_app pairs against the circuit's fresh sharing and
//!           a handshake over every `values` row; the audit round over every
//!           canonical version (crate::audit); every handshake is the neighbour
//!           summand-hash comparison, the newcomer's first rounds
//! declare   each remaining node signs the contract's rotate_keys for every tip
//!           namespace at its next key epoch (crate::key_epoch); the two
//!           signatures go to all three nodes, which print the arguments
//! ```
//!
//! The namespaces declared are those whose contract manifest says
//! `node_keys: rotating`; nothing on chain tells a contract with a fixed key
//! set from one that has not rotated (both read as key epoch 0), so the
//! manifest is what decides. A tip namespace whose manifest says `fixed` has
//! no `rotate_keys`: it is not declared, the report names it (`redeploy`),
//! and its app is redeployed instead (docs/ARCHITECTURE.md section 6, "Node
//! replacement and key epochs").
//!
//! Why the refresh comes first. Rep3 gives every component of a value to two
//! nodes, so any two nodes reconstruct, and the newcomer rebuilt from the
//! neighbours holds exactly the pairs the departed node held: a hand-over
//! alone would leave the departed node's copy (or a thief's) one of three
//! valid shares for ever. After the refresh, each value's three components
//! `x_d`, `x_{d+1}`, `x_{d-1}` (d the departed index) have moved by `r_d`,
//! `r_s` and `-(r_d + r_s)`, fresh per element: the departed pair
//! `(x_d, x_{d-1})` combines with no current pair (each holds a moved
//! component it lacks the mask of), and the newcomer's pair plus the
//! departed one still miss `x_{d+1}`. Collusion before the departure is not
//! undone: a value the departed node opened with another node stays open.
//!
//! What is not refreshed, and why. A client-held record's third and a
//! chain-held third are sealed by a node under its own key and held by the
//! client or the chain: the nodes cannot reach them, and the departed node's
//! third is lost with its key, so those records cannot run again (a planned
//! departure re-seals live records first; a chain-held tip namespace does
//! not survive a replacement). A secret-shared receipt intake row holds an
//! envelope sealed to its node alone: the newcomer cannot open the departed
//! node's, so its request cannot run and is skipped; the row is pruned with
//! its receipt. A node's backup taken before the refresh holds pairs of the
//! old sharing: it must be destroyed and a new backup taken. The `requests`
//! rows (whose sealed replaced vectors are pairs of the old sharing, and
//! which no rollback or FETCH across a replacement can use, the newcomer
//! holding none) are deleted.
//!
//! The masks come from a seed the remaining node before the departed one
//! (`d - 1`) draws and sends the other over the mesh, through Poseidon2 as a
//! PRF keyed by the seed over each element's identity (its table, namespace,
//! key, commitment or note hash, and position), so both derive the same
//! mask of the same element without agreeing on an order. A holder blob's
//! share components are XOR shares of bytes (crate::store::blob): its masks
//! are two byte streams, ChaCha20 keyed by the Poseidon2 PRF of the seed over
//! the blob's identity (namespace, key, name), and the rule is the same with
//! XOR for addition: `x_d ^= r_d`, `x_{d+1} ^= r_s`, `x_{d-1} ^= r_d ^ r_s`
//! (docs/ARCHITECTURE.md section 6, "Persistence, resync, share refresh,
//! audit"). The blob's copies (values two nodes hold alike, not shares) and
//! public bytes are left: the departed node keeps its copy of the receivers'
//! shuffles, which ages out at each DORAM level's next rebuild. That is
//! accepted for the prototype; rotating the copies would mean a reshuffle of
//! every level within the replacement.
//!
//! Each remaining node keeps the seed in its key directory until the
//! replacement ends ([`Journal`]), with the run's generation: every run of
//! the replacement under one seed is the next generation, and the generation
//! is bound into every mask. A namespace (or the master) whose refresh one
//! node committed and the other did not (a crash between the two commits) is
//! found by comparing the hash of the one component the two remaining nodes
//! share, now and one refresh back under each earlier generation, and only
//! the node behind refreshes, under the generation the other committed. Two
//! nodes level refresh again under the run's generation. Never the same
//! masks twice: a blob's XOR mask applied twice undoes itself, which would
//! give the departed node's blob components back their meaning.

use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_std::rand::{CryptoRng, RngCore, SeedableRng};
use mpc_net::Network;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::bind::{Elem, Share};
use crate::crs::Circuit;
use crate::error::Refusal;
use crate::field::{FieldHex, Fr, RequestId, fr_to_hex};
use crate::handshake::{Verdict, recv_json, send_json, summand_hash};
use crate::hash::poseidon2_hash;
use crate::key_epoch::{KeySetWire, Rotation, sign_rotation};
use crate::keys::label_field;
use crate::pipeline::{NamespacesGuard, Node};
use crate::record::key_hash;
use crate::register::Signature;
use crate::request::{NODES, next, prev};
use crate::response::NodesResponse;
use crate::resync::{self, ResyncReport, Scope};
use crate::state::VersionViews;
use crate::store::blob::Blob;
use crate::store::{NamespaceRow, RestoredValue, Store, TipVersion, VersionWrite, tip_rows};
use crate::tree::{StoredNode, TreeNode};

/// The replacement's label, `sidecar.replace`: the session's request id.
pub const REPLACE_LABEL: &[u8] = b"sidecar.replace";

/// The refresh masks' domain, `sidecar.refresh`.
pub const REFRESH_LABEL: &[u8] = b"sidecar.refresh";

/// The session's request id.
pub fn session_id() -> RequestId {
    RequestId(label_field(REPLACE_LABEL))
}

/// The session's body hash, which all three nodes must agree on: the
/// departed index and the new key set (the newcomer's keys in its place).
pub fn session_body(departed: usize, pins: &NodesResponse) -> Fr {
    resync::session_body(departed, &Scope::Replace, pins)
}

/// What a remaining node keeps in its key directory while a replacement
/// runs: the departed index, the refresh seed and the generation of the
/// latest run under it, written before the first refreshed row is committed
/// and removed when the replacement ends, so a replacement run again after
/// a failure refreshes under the same seed at the next generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub departed: usize,
    pub seed: FieldHex,
    /// The latest run's generation: 0 for the first run under the seed.
    #[serde(default)]
    pub generation: u32,
}

/// The seed and generation node `d - 1` sends node `d + 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunSeed {
    seed: FieldHex,
    generation: u32,
}

/// What the replacement persists at a node, outside the store: the
/// journal (a remaining node) and the master share (a remaining node's
/// refreshed share, the newcomer's installed one). sidecar-node keeps both
/// in the key directory.
pub trait Persist {
    fn journal(&self) -> Result<Option<Journal>, Refusal>;
    fn save_journal(&self, journal: &Journal) -> Result<(), Refusal>;
    fn clear_journal(&self) -> Result<(), Refusal>;
    fn save_master(&self, master: Share) -> Result<(), Refusal>;
}

/// A remaining node's refresh masks: node `me`'s change of each pair for
/// the departed node `departed`, under `seed` at run `generation`.
#[derive(Clone, Copy, Debug)]
pub struct Refresher {
    seed: Fr,
    generation: u32,
    departed: usize,
    me: usize,
}

impl Refresher {
    /// 400 unless `me` is one of the two nodes beside `departed`.
    pub fn new(seed: Fr, generation: u32, departed: usize, me: usize) -> Result<Self, Refusal> {
        if departed >= NODES || me >= NODES || me == departed {
            return Err(Refusal::bad_request(format!(
                "replace: node {me} does not refresh for departed node {departed}"
            )));
        }
        Ok(Refresher {
            seed,
            generation,
            departed,
            me,
        })
    }

    /// The same masks at another generation.
    fn at(&self, generation: u32) -> Self {
        Refresher {
            generation,
            ..*self
        }
    }

    /// The masks of the element named `label`: `r_d`, added to the
    /// departed node's own component `x_d`, and `r_s`, added to the
    /// component the two remaining nodes share, `x_{d+1}`; `x_{d-1}` takes
    /// `-(r_d + r_s)`, so the value is unchanged.
    fn masks(&self, label: &[Fr]) -> (Fr, Fr) {
        let mut fields = vec![
            label_field(REFRESH_LABEL),
            self.seed,
            Fr::from(self.generation),
        ];
        fields.extend_from_slice(label);
        fields.push(Fr::from(0u64));
        let r_d = poseidon2_hash(&fields);
        *fields.last_mut().expect("non-empty") = Fr::from(1u64);
        (r_d, poseidon2_hash(&fields))
    }

    /// The pair after the refresh. At node `d + 1`, `(a, b) = (x_{d+1},
    /// x_d)`; at node `d - 1`, `(x_{d-1}, x_{d+1})`.
    pub fn share(&self, label: &[Fr], share: Share) -> Share {
        let (r_d, r_s) = self.masks(label);
        if self.me == next(self.departed) {
            Share::new(share.a + r_s, share.b + r_d)
        } else {
            Share::new(share.a - r_d - r_s, share.b + r_s)
        }
    }

    /// The pair one refresh back (the inverse of [`Self::share`]).
    fn back(&self, label: &[Fr], share: Share) -> Share {
        let (r_d, r_s) = self.masks(label);
        if self.me == next(self.departed) {
            Share::new(share.a - r_s, share.b - r_d)
        } else {
            Share::new(share.a + r_d + r_s, share.b - r_s)
        }
    }

    /// The two mask streams of `len` bytes of the blob named `label`:
    /// `r_d` and `r_s`, ChaCha20 under the Poseidon2 PRF of the seed.
    fn blob_masks(&self, label: &[Fr], len: usize) -> (Vec<u8>, Vec<u8>) {
        let (k_d, k_s) = self.masks(label);
        let stream = |k: Fr| {
            let key: [u8; 32] = k
                .into_bigint()
                .to_bytes_le()
                .try_into()
                .expect("a field element is 32 bytes");
            let mut out = vec![0u8; len];
            ChaCha20Rng::from_seed(key).fill_bytes(&mut out);
            out
        };
        (stream(k_d), stream(k_s))
    }

    /// The blob after the refresh: its share components XORed with the
    /// masks (at node `d + 1`, `(a, b) = (x_{d+1}, x_d)` take `(r_s, r_d)`;
    /// at node `d - 1`, `(x_{d-1}, x_{d+1})` take `(r_d ^ r_s, r_s)`), its
    /// copies and public bytes as they were. XOR is its own inverse, so the
    /// same call takes a refreshed blob one refresh back.
    pub fn blob(&self, label: &[Fr], mut blob: Blob) -> Blob {
        let (r_d, r_s) = self.blob_masks(label, blob.shares.a.len());
        let xor = |v: &mut [u8], m: &[u8]| v.iter_mut().zip(m).for_each(|(x, r)| *x ^= r);
        if self.me == next(self.departed) {
            xor(&mut blob.shares.a, &r_s);
            xor(&mut blob.shares.b, &r_d);
        } else {
            xor(&mut blob.shares.a, &r_d);
            xor(&mut blob.shares.a, &r_s);
            xor(&mut blob.shares.b, &r_s);
        }
        blob
    }

    /// The component this node shares with the other remaining node.
    fn shared(&self, share: Share) -> Fr {
        if self.me == next(self.departed) {
            share.a
        } else {
            share.b
        }
    }

    /// Every shared element of `vec` refreshed, element `k` under
    /// `label ++ [k]`.
    fn vec(&self, label: &[Fr], vec: &[Elem]) -> Vec<Elem> {
        vec.iter()
            .enumerate()
            .map(|(k, e)| match e {
                Elem::Public(v) => Elem::Public(*v),
                Elem::Shared(s) => {
                    let mut l = label.to_vec();
                    l.push(Fr::from(k as u64));
                    Elem::Shared(self.share(&l, *s))
                }
            })
            .collect()
    }
}

fn tag(name: &[u8]) -> Fr {
    label_field(name)
}

/// The label of the master share.
fn master_label() -> Vec<Fr> {
    vec![tag(b"master")]
}

/// The label of `namespace`'s nsk_app pair.
fn nsk_label(namespace: Fr) -> Vec<Fr> {
    vec![tag(b"nsk_app"), namespace]
}

/// How many rows a remaining node's refresh rewrote.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refreshed {
    /// Namespaces refreshed here (a namespace the other node was behind on
    /// is refreshed there only).
    pub namespaces: usize,
    pub versions: usize,
    pub tree_nodes: usize,
    pub values: usize,
    /// The holder blobs (every `tip_blobs` row).
    #[serde(default)]
    pub blobs: usize,
    /// Whether this node refreshed its master share in this run.
    pub master: bool,
    /// The `requests` rows deleted.
    pub requests_deleted: usize,
}

/// The label of the blob `name` of `key` under `namespace`.
pub fn blob_label(namespace: Fr, key: &str, name: &str) -> Vec<Fr> {
    vec![
        tag(b"blob"),
        namespace,
        key_hash(key),
        crate::schnorr::poseidon2_hash_bytes(name.as_bytes()),
    ]
}

/// Refresh every pair of `namespace` at a remaining node, in one store
/// transaction under the namespace lock, which `held` must hold: the
/// nsk_app pair, every version of every tip key (any status), every leaf of
/// the clear trees they reach (the inner nodes rewritten unchanged), every
/// `values` row, the share components of every holder blob.
pub fn refresh_namespace<S: Store>(
    node: &Node<S>,
    held: &NamespacesGuard<'_>,
    namespace: Fr,
    refresher: &Refresher,
    done: &mut Refreshed,
) -> Result<(), Refusal> {
    held.require(namespace)?;
    let store = &node.store;
    let row = store.namespace(namespace)?.ok_or_else(|| {
        Refusal::mpc_failure(format!(
            "replace: no namespace {} to refresh",
            fr_to_hex(namespace)
        ))
    })?;
    let mut txn = store.begin(namespace);
    txn.import_refresh(NamespaceRow {
        nsk_app: refresher.share(&nsk_label(namespace), row.nsk_app),
        ..row
    });
    let rows = tip_rows(store, namespace, &store.tip_keys(namespace)?, |_| true)?;
    for v in rows.versions {
        let kh = key_hash(&v.key);
        let vec = refresher.vec(&[tag(b"version"), namespace, kh, v.commitment], &v.vec);
        done.versions += 1;
        txn.version(VersionWrite::Put(TipVersion { vec, ..v }));
    }
    for ((key, hash), node) in rows.nodes {
        let Some(stored) = store.tip_node(namespace, &key, hash)? else {
            continue;
        };
        let node = match node {
            TreeNode::Leaf { index, vec } => TreeNode::Leaf {
                index,
                vec: refresher.vec(&[tag(b"leaf"), namespace, key_hash(&key), hash], &vec),
            },
            inner => inner,
        };
        done.tree_nodes += 1;
        txn.node(
            &key,
            hash,
            Some(StoredNode {
                node,
                refs: stored.refs,
            }),
        );
    }
    for key in store.blob_keys(namespace)? {
        for name in store.blob_names(namespace, &key)? {
            let Some(bytes) = store.blob(namespace, &key, &name)? else {
                continue;
            };
            let blob = Blob::from_bytes(&bytes)?;
            let refreshed = refresher.blob(&blob_label(namespace, &key, &name), blob);
            done.blobs += 1;
            txn.blob(&key, &name, Some(refreshed.to_bytes()));
        }
    }
    for key in store.value_keys(namespace)? {
        let Some(v) = store.value(namespace, &key)? else {
            continue;
        };
        let vec = refresher.vec(
            &[tag(b"value"), namespace, key_hash(&key), v.note_hash],
            &v.vec,
        );
        done.values += 1;
        txn.import_value(RestoredValue {
            key,
            vec,
            note_hash: v.note_hash,
            prior_request_id: v.request_id,
        });
    }
    store.commit(txn)?;
    done.namespaces += 1;
    Ok(())
}

/// Which of the two remaining nodes refreshes one item (a namespace or the
/// master), and under which generation: from the hashes of the shared
/// component now and one refresh back under each earlier generation, each
/// node's and the other's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Level {
    now: FieldHex,
    /// One refresh back under generation 0, 1, .. up to the run's, exclusive.
    back: Vec<FieldHex>,
}

/// The level of one item at this node: `id` names it, `label` is its mask
/// label, `share` its pair now; `refresher` is at the run's generation.
fn level(refresher: &Refresher, id: &RequestId, label: &[Fr], share: Share) -> Level {
    Level {
        now: FieldHex(summand_hash(id, refresher.shared(share))),
        back: (0..refresher.generation)
            .map(|g| {
                let back = refresher.at(g).back(label, share);
                FieldHex(summand_hash(id, refresher.shared(back)))
            })
            .collect(),
    }
}

/// Whether this node refreshes an item, given its level and the other's,
/// and under which generation: both at `generation` (the run's) when level;
/// only the one behind, under the generation the other committed, when one
/// is a refresh ahead; 400 when the two share no level (they diverged some
/// other way).
fn refreshes(
    mine: &Level,
    theirs: &Level,
    generation: u32,
    what: &str,
) -> Result<Option<u32>, Refusal> {
    let at = |backs: &[FieldHex], now: FieldHex| backs.iter().position(|b| *b == now);
    if mine.now == theirs.now {
        Ok(Some(generation))
    } else if at(&mine.back, theirs.now).is_some() {
        Ok(None)
    } else if let Some(g) = at(&theirs.back, mine.now) {
        Ok(Some(g as u32))
    } else {
        Err(Refusal::bad_request(format!(
            "replace: the two remaining nodes' copies of the component they share differ for \
             {what}, by more than one refresh under this seed; their stores diverged (compare \
             them with the audit before replacing)"
        )))
    }
}

/// The refresh at a remaining node, over `net` with the other remaining node
/// `other`: the seed and the run's generation (node `d - 1`'s: a fresh seed
/// at generation 0, or its journal's seed at the journal's generation + 1),
/// the namespace lists compared, then every namespace and the master
/// refreshed where this node is level with or behind the other, and the
/// `requests` rows deleted. `held` holds every namespace's lock.
fn refresh<S: Store, N: Network, R: RngCore + CryptoRng>(
    node: &Node<S>,
    held: &NamespacesGuard<'_>,
    net: &N,
    departed: usize,
    persist: &dyn Persist,
    rng: &mut R,
) -> Result<Refreshed, Refusal> {
    let me = node.index;
    let (p, n) = (prev(departed), next(departed));
    let other = if me == p { n } else { p };
    let run = if me == p {
        let run = match persist.journal()?.filter(|j| j.departed == departed) {
            Some(j) => RunSeed {
                seed: j.seed,
                generation: j.generation.checked_add(1).ok_or_else(|| {
                    Refusal::mpc_failure("replace: the journal's generation is exhausted")
                })?,
            },
            None => RunSeed {
                seed: FieldHex(Fr::rand(rng)),
                generation: 0,
            },
        };
        // journalled before it is sent: no generation is ever used twice
        persist.save_journal(&Journal {
            departed,
            seed: run.seed,
            generation: run.generation,
        })?;
        send_json(net, n, "refresh seed", &run)?;
        run
    } else {
        let run: RunSeed = recv_json(net, p, "refresh seed")?;
        persist.save_journal(&Journal {
            departed,
            seed: run.seed,
            generation: run.generation,
        })?;
        run
    };
    let refresher = Refresher::new(run.seed.fr(), run.generation, departed, me)?;
    let namespaces = node.store.namespaces()?;
    let listed: Vec<FieldHex> = namespaces.iter().copied().map(FieldHex).collect();
    send_json(net, other, "refresh namespaces", &listed)?;
    let theirs: Vec<FieldHex> = recv_json(net, other, "refresh namespaces")?;
    if theirs != listed {
        return Err(Refusal::bad_request(format!(
            "replace: node {me} holds {} namespace(s) and node {other} {}, not the same list; \
             their registries diverged (sync-registry --check)",
            listed.len(),
            theirs.len()
        )));
    }
    let id = |item: Fr| RequestId(poseidon2_hash(&[label_field(REFRESH_LABEL), item]));
    let mut done = Refreshed::default();
    for ns in namespaces {
        let row = node.store.namespace(ns)?.ok_or_else(|| {
            Refusal::mpc_failure(format!("replace: no namespace {}", fr_to_hex(ns)))
        })?;
        let mine = level(&refresher, &id(ns), &nsk_label(ns), row.nsk_app);
        send_json(net, other, "refresh level", &mine)?;
        let theirs: Level = recv_json(net, other, "refresh level")?;
        let what = format!("namespace {}", fr_to_hex(ns));
        if let Some(g) = refreshes(&mine, &theirs, run.generation, &what)? {
            refresh_namespace(node, held, ns, &refresher.at(g), &mut done)?;
        }
    }
    let master = node.master();
    let item = label_field(b"master");
    let mine = level(&refresher, &id(item), &master_label(), master);
    send_json(net, other, "refresh level", &mine)?;
    let theirs: Level = recv_json(net, other, "refresh level")?;
    if let Some(g) = refreshes(&mine, &theirs, run.generation, "the master share")? {
        let refreshed = refresher.at(g).share(&master_label(), master);
        persist.save_master(refreshed)?;
        node.set_master(refreshed);
        done.master = true;
    }
    // every row, whatever its age: their sealed replaced vectors are pairs
    // of the old sharing
    done.requests_deleted = node.store.prune_requests(i64::MAX as u64)?;
    Ok(done)
}

/// What a replacement did, at each of the three nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceReport {
    pub departed: usize,
    /// A remaining node's refresh; none at the newcomer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshed: Option<Refreshed>,
    /// The newcomer's import and the checks, as a resync reports them.
    pub resync: ResyncReport,
    /// The contracts' `rotate_keys` arguments, one per tip namespace whose
    /// contract manifest says `node_keys: rotating`, with the two remaining
    /// nodes' signatures (none when the audit failed).
    pub rotations: Vec<Rotation>,
    /// The registered tip namespaces whose contract manifest says
    /// `node_keys: fixed`: no rotation can land in them, so their apps are
    /// redeployed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redeploy: Vec<FieldHex>,
}

impl ReplaceReport {
    /// Whether no key failed the audit (a key not audited did not).
    pub fn passed(&self) -> bool {
        self.resync.passed()
    }
}

/// One remaining node's declarations: the namespaces and epochs it signs,
/// and its signature of each.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    rotations: Vec<(FieldHex, u32, Signature)>,
}

/// The replacement of node `departed` by a newcomer over the open session
/// `net`, after its opening handshake ([`session_id`], [`session_body`]),
/// at all three nodes: this node is the newcomer (index `departed`, an empty
/// store, no master share) or one of the two remaining nodes. `pins` is the
/// new key set (the newcomer's keys at `departed`); `views` is this node's
/// own chain view, which a remaining node marks its versions against before
/// it collects the newcomer's bundle; `held` holds the lock of every
/// namespace of this node's store, taken before the session's mesh lock
/// (`Node::maintain`); `declare` is the tip namespaces and
/// the key epoch each moves to (a remaining node's, read from its own chain
/// view; the two must agree; ignored at the newcomer). The order:
/// [`refresh`] at the remaining nodes, the import and the checks
/// ([`resync::run`] under [`Scope::Replace`]), the newcomer's master share
/// persisted, then, when every audited key passed, the declarations. Any
/// node's refusal is every node's.
#[allow(clippy::too_many_arguments)]
pub fn replace<S: Store, N: Network, R: RngCore + CryptoRng>(
    node: &Node<S>,
    held: &NamespacesGuard<'_>,
    audit_circuit: &Circuit,
    net: &N,
    departed: usize,
    pins: &NodesResponse,
    persist: &dyn Persist,
    views: &VersionViews<'_>,
    declare: &[(Fr, u32)],
    rng: &mut R,
) -> Result<ReplaceReport, Refusal> {
    if departed >= NODES {
        return Err(Refusal::bad_request(format!(
            "replace: {departed} is not a node index (0, 1 or 2)"
        )));
    }
    let me = node.index;
    let (p, n) = (prev(departed), next(departed));
    let refreshed = if me == departed {
        for from in [p, n] {
            let verdict: Verdict = recv_json(net, from, "refresh verdict")?;
            if !verdict.accepted {
                return Err(Refusal::bad_request(format!(
                    "node {from} refused the refresh: {}",
                    verdict.refusal.unwrap_or_default()
                )));
            }
        }
        None
    } else {
        let other = if me == p { n } else { p };
        let result = refresh(node, held, net, departed, persist, rng);
        let verdict = Verdict {
            accepted: result.is_ok(),
            refusal: result.as_ref().err().map(|r| r.message.clone()),
        };
        for peer in [other, departed] {
            send_json(net, peer, "refresh verdict", &verdict)?;
        }
        let theirs: Verdict = recv_json(net, other, "refresh verdict")?;
        let done = result?;
        if !theirs.accepted {
            return Err(Refusal::bad_request(format!(
                "node {other} refused the refresh: {}",
                theirs.refusal.unwrap_or_default()
            )));
        }
        Some(done)
    };
    let sent = if me == departed {
        None
    } else {
        Some(resync::collect(
            node,
            held,
            departed,
            &Scope::Replace,
            views,
        )?)
    };
    let report = resync::run(
        node,
        audit_circuit,
        net,
        departed,
        &Scope::Replace,
        pins,
        sent,
        None,
        rng,
    )?;
    if me == departed {
        persist.save_master(node.master())?;
    }
    let mut rotations = Vec::new();
    if report.passed() {
        rotations = declarations(node, net, departed, pins, declare, rng)?;
    }
    if me != departed {
        persist.clear_journal()?;
    }
    Ok(ReplaceReport {
        departed,
        refreshed,
        resync: report,
        rotations,
        redeploy: Vec::new(),
    })
}

/// The declarations: each remaining node signs `rotate_keys` of every
/// namespace in `declare` at its epoch under the new key set `pins`, sends
/// its list to the other remaining node and the newcomer; the two lists must
/// name the same namespaces and epochs. Every node returns the arguments
/// with both signatures.
fn declarations<S: Store, N: Network, R: RngCore + CryptoRng>(
    node: &Node<S>,
    net: &N,
    departed: usize,
    pins: &NodesResponse,
    declare: &[(Fr, u32)],
    rng: &mut R,
) -> Result<Vec<Rotation>, Refusal> {
    let me = node.index;
    let (p, n) = (prev(departed), next(departed));
    let lists: [Signed; 2] = if me == departed {
        [
            recv_json(net, p, "rotation signatures")?,
            recv_json(net, n, "rotation signatures")?,
        ]
    } else {
        let sig = node.keys().sig_scalar();
        let mine = Signed {
            rotations: declare
                .iter()
                .map(|&(ns, epoch)| {
                    (
                        FieldHex(ns),
                        epoch,
                        sign_rotation(sig, ns, epoch, pins, rng),
                    )
                })
                .collect(),
        };
        let other = if me == p { n } else { p };
        for peer in [other, departed] {
            send_json(net, peer, "rotation signatures", &mine)?;
        }
        let theirs: Signed = recv_json(net, other, "rotation signatures")?;
        if me == p {
            [mine, theirs]
        } else {
            [theirs, mine]
        }
    };
    let [from_p, from_n] = lists;
    let named = |s: &Signed| -> Vec<(FieldHex, u32)> {
        s.rotations.iter().map(|(ns, e, _)| (*ns, *e)).collect()
    };
    if named(&from_p) != named(&from_n) {
        return Err(Refusal::bad_request(format!(
            "replace: nodes {p} and {n} declare different namespaces or epochs ({:?} and {:?}); \
             their chain views or [tip] sections differ",
            named(&from_p),
            named(&from_n)
        )));
    }
    let keys = KeySetWire::from(pins);
    Ok(from_p
        .rotations
        .into_iter()
        .zip(from_n.rotations)
        .map(|((ns, epoch, sp), (_, _, sn))| {
            let mut signatures = [None; NODES];
            signatures[p] = Some(sp);
            signatures[n] = Some(sn);
            Rotation {
                namespace: ns,
                epoch,
                keys,
                signatures,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refreshed_value(departed: usize, seed: Fr, shares: [Share; 3]) -> [Share; 3] {
        let mut out = shares;
        for me in [prev(departed), next(departed)] {
            let r = Refresher::new(seed, 0, departed, me).unwrap();
            out[me] = r.share(&[Fr::from(5u64)], shares[me]);
        }
        out
    }

    /// Rep3 pairs of `x = x0 + x1 + x2`: party j holds `(x_j, x_{j-1})`.
    fn pairs(x: [Fr; 3]) -> [Share; 3] {
        [0, 1, 2].map(|j| Share::new(x[j], x[prev(j)]))
    }

    #[test]
    fn a_refresh_keeps_the_value_and_retires_the_departed_pair() {
        let x = [Fr::from(11u64), Fr::from(22u64), Fr::from(33u64)];
        let value = x[0] + x[1] + x[2];
        for departed in 0..NODES {
            let old = pairs(x);
            let new = refreshed_value(departed, Fr::from(77u64), old);
            let (p, n) = (prev(departed), next(departed));
            // the two remaining nodes still agree on the component they share
            assert_eq!(new[n].a, new[p].b);
            // the newcomer's pair from the neighbours: x_d' from node d+1's b,
            // x_{d-1}' from node d-1's a
            let newcomer = Share::new(new[n].b, new[p].a);
            assert_eq!(newcomer.a + new[n].a + newcomer.b, value);
            // the departed pair plus either remaining node's new pair opens
            // nothing: x_{d+1} moved
            assert_ne!(old[departed].a + old[departed].b + new[n].a, value);
            assert_ne!(old[departed].a + old[departed].b + new[p].b, value);
            // one refresh back is the old pair
            let r = Refresher::new(Fr::from(77u64), 0, departed, n).unwrap();
            assert_eq!(r.back(&[Fr::from(5u64)], new[n]), old[n]);
        }
    }

    #[test]
    fn the_node_behind_refreshes() {
        let h = |v: u64| FieldHex(Fr::from(v));
        let l = |now: u64, back: &[u64]| Level {
            now: h(now),
            back: back.iter().map(|b| h(*b)).collect(),
        };
        assert_eq!(refreshes(&l(1, &[]), &l(1, &[]), 0, "x").unwrap(), Some(0));
        assert_eq!(
            refreshes(&l(1, &[0]), &l(1, &[0]), 1, "x").unwrap(),
            Some(1)
        );
        // this node is one ahead under generation 1: the other refreshes
        assert_eq!(
            refreshes(&l(2, &[7, 1]), &l(1, &[6, 5]), 2, "x").unwrap(),
            None
        );
        // the other is one ahead under generation 1: this node refreshes under it
        assert_eq!(
            refreshes(&l(1, &[6, 5]), &l(2, &[7, 1]), 2, "x").unwrap(),
            Some(1)
        );
        assert!(refreshes(&l(5, &[4]), &l(1, &[0]), 1, "x").is_err());
    }

    /// Rep3 XOR pairs of a blob's share section: party j holds
    /// `(x_j, x_{j-1})`, the three `a` streams XOR to the value.
    fn blob_pairs(x: [&[u8]; 3]) -> [Blob; 3] {
        [0, 1, 2].map(|j| Blob {
            public: b"public".to_vec(),
            shares: crate::store::blob::Pair {
                a: x[j].to_vec(),
                b: x[prev(j)].to_vec(),
            },
            copies: crate::store::blob::Pair {
                a: vec![j as u8; 4],
                b: vec![prev(j) as u8; 4],
            },
        })
    }

    fn open_blob(blobs: &[Blob; 3]) -> Vec<u8> {
        let mut out = blobs[0].shares.a.clone();
        for b in &blobs[1..] {
            out.iter_mut().zip(&b.shares.a).for_each(|(o, x)| *o ^= x);
        }
        out
    }

    /// One run of the refresh at the two remaining nodes, as `refresh` runs
    /// it per item: each node's level of the item, the generation each
    /// refreshes under, then the refresh at the nodes in `commit` only (a
    /// crash before the other commits). Field pairs and blobs move together,
    /// as one namespace's do.
    fn run(
        departed: usize,
        seed: Fr,
        generation: u32,
        commit: &[usize],
        shares: &mut [Share; 3],
        blobs: &mut [Blob; 3],
    ) {
        let label = [Fr::from(5u64)];
        let blob_label = blob_label(Fr::from(1u64), "0x01", "level.0");
        let id = RequestId(Fr::from(99u64));
        let (p, n) = (prev(departed), next(departed));
        let r = |me| Refresher::new(seed, generation, departed, me).unwrap();
        let levels = [p, n].map(|me| level(&r(me), &id, &label, shares[me]));
        for (k, me) in [p, n].into_iter().enumerate() {
            let g = refreshes(&levels[k], &levels[1 - k], generation, "x").unwrap();
            if let Some(g) = g
                && commit.contains(&me)
            {
                shares[me] = r(me).at(g).share(&label, shares[me]);
                blobs[me] = r(me).at(g).blob(&blob_label, blobs[me].clone());
            }
        }
    }

    /// A replacement run again after both remaining nodes committed the
    /// refresh (a failure before the journal was cleared) refreshes again at
    /// the next generation: the blob share components differ from the
    /// original ones and from the first run's, the departed node's old
    /// components open nothing with the current ones, the copies and public
    /// bytes are untouched, and every value opens as before. A crash between
    /// the two commits of a run is finished by the node behind, under the
    /// generation the other committed.
    #[test]
    fn a_rerun_refresh_never_restores_the_old_blob_sharing() {
        let seed = Fr::from(0x5eedu64);
        let x: [&[u8]; 3] = [
            b"\x01\x02\x03\x04",
            b"\x10\x20\x30\x40",
            b"\xaa\xbb\xcc\xdd",
        ];
        let fx = [Fr::from(11u64), Fr::from(22u64), Fr::from(33u64)];
        for departed in 0..NODES {
            let (p, n) = (prev(departed), next(departed));
            let original = blob_pairs(x);
            let value = open_blob(&original);
            let mut blobs = original.clone();
            let mut shares = pairs(fx);
            let opened = |s: &[Share; 3]| s[0].a + s[1].a + s[2].a;
            let field = opened(&shares);

            run(departed, seed, 0, &[p, n], &mut shares, &mut blobs);
            let first = blobs.clone();
            // the rerun, at the journal's generation + 1
            run(departed, seed, 1, &[p, n], &mut shares, &mut blobs);
            for me in [p, n] {
                assert_ne!(blobs[me].shares, original[me].shares, "departed {departed}");
                assert_ne!(blobs[me].shares, first[me].shares, "departed {departed}");
                assert_eq!(blobs[me].copies, original[me].copies);
                assert_eq!(blobs[me].public, original[me].public);
            }
            // the newcomer's components from the neighbours
            blobs[departed] =
                Blob::rebuild(blobs[n].part(n, departed), blobs[p].part(p, departed)).unwrap();
            assert_eq!(open_blob(&blobs), value);
            let mut stale = blobs.clone();
            stale[departed] = original[departed].clone();
            assert_ne!(open_blob(&stale), value, "departed {departed}");
            assert_eq!(shares[p].b, shares[n].a);

            // generation 2 commits at node n only; generation 3 finishes it
            // at node p under generation 2, and node n refreshes nothing
            let before = blobs.clone();
            run(departed, seed, 2, &[n], &mut shares, &mut blobs);
            assert_ne!(shares[p].b, shares[n].a);
            let ahead = blobs[n].clone();
            run(departed, seed, 3, &[p, n], &mut shares, &mut blobs);
            assert_eq!(blobs[n], ahead);
            assert_ne!(blobs[p].shares, before[p].shares);
            assert_eq!(shares[p].b, shares[n].a);
            blobs[departed] =
                Blob::rebuild(blobs[n].part(n, departed), blobs[p].part(p, departed)).unwrap();
            assert_eq!(open_blob(&blobs), value);
            let newcomer = Share::new(shares[n].b, shares[p].a);
            assert_eq!(newcomer.a + shares[n].a + newcomer.b, field);
        }
    }
}
