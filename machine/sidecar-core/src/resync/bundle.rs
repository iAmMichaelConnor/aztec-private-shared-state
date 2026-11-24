//! The bundle a neighbour sends: its body rows, collecting them from a store,
//! and sealing and opening the components.

use super::*;
use ark_ff::{BigInteger, PrimeField};

// ---------------------------------------------------------------------------
// The bundle
// ---------------------------------------------------------------------------

/// One contract manifest version with its packages, as a whole-store
/// bundle carries it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestBody {
    pub manifest: ManifestRows,
    pub packages: Vec<PackageBody>,
}

/// One package row, as a bundle carries it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageBody {
    pub name: String,
    pub circuit: HexBytes,
    pub manifest: serde_json::Value,
    pub vk: HexBytes,
    pub vk_hash: FieldHex,
    pub disabled: bool,
    pub seq: u64,
}

/// One stored vector: each element's public value, or `None` for a shared
/// one, whose component travels sealed.
pub type VecBody = Vec<Option<FieldHex>>;

/// A tree-valued version's clear tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeBody {
    pub root: FieldHex,
    pub next: u64,
}

/// One canonical or live version, as a bundle carries it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionBody {
    pub key: String,
    pub commitment: FieldHex,
    pub parent: FieldHex,
    pub index: u64,
    pub request_id: RequestId,
    pub canonical: bool,
    pub block: u64,
    /// The hash of `block` as the sender's chain view read it
    /// ([`crate::store::TipVersion::block_hash`]).
    pub block_hash: FieldHex,
    pub vec: VecBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree: Option<TreeBody>,
}

/// One node of a clear tree the versions reach.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeBody {
    Inner {
        key: String,
        hash: FieldHex,
        left: FieldHex,
        right: FieldHex,
    },
    Leaf {
        key: String,
        hash: FieldHex,
        index: u64,
        vec: VecBody,
    },
}

/// One `values` row of the sidecar path, as a bundle carries it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueBody {
    pub key: String,
    pub note_hash: FieldHex,
    /// The request that wrote it.
    pub request_id: RequestId,
    pub vec: VecBody,
}

/// One `consumed` row, as a bundle carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumedBody {
    pub note_hash: FieldHex,
    pub circuit: FieldHex,
    pub request_id: RequestId,
}

/// One dead record ([`crate::dead`]), as a bundle carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadBody {
    pub note_hash: FieldHex,
    /// The rolled-back request that created the record.
    pub request_id: RequestId,
}

/// One receipt row, as a bundle carries it: the row with the sender's own
/// receipt signature. The node's receipt hook makes it from a stored row and
/// rebuilds the row from it ([`ReceiptResync`]); sidecar-tip sends receipt
/// intake's rows only.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBody {
    pub request_id: FieldHex,
    pub circuit: String,
    pub vk_hash: FieldHex,
    pub inputs: Vec<FieldHex>,
    pub inputs_hash: FieldHex,
    pub user_nonce: FieldHex,
    pub expiry_block: u64,
    pub stale_blocks: Option<u64>,
    pub signature: Signature,
}

/// One holder blob (crate::store::blob), as a bundle carries it: its name
/// and public bytes; its components travel sealed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobBody {
    pub key: String,
    pub name: String,
    pub public: HexBytes,
}

/// One namespace, as a bundle carries it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceBody {
    pub namespace: FieldHex,
    pub owner_pubkey: GrumpkinPoint,
    pub npk_app_hash: FieldHex,
    pub seq: u64,
    /// Every contract manifest version the sender holds, oldest first,
    /// each with its packages (a whole-store resync; none otherwise).
    pub manifests: Vec<ManifestBody>,
    pub versions: Vec<VersionBody>,
    pub nodes: Vec<NodeBody>,
    pub values: Vec<ValueBody>,
    pub consumed: Vec<ConsumedBody>,
    /// The dead records, in ascending note hash order.
    pub dead: Vec<DeadBody>,
    pub receipts: Vec<ReceiptBody>,
    /// The holder blobs, by key then name.
    #[serde(default)]
    pub blobs: Vec<BlobBody>,
}

/// The clear part of a bundle: what node `from` sends node `to`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    pub from: usize,
    pub to: usize,
    pub scope: Scope,
    pub namespaces: Vec<NamespaceBody>,
}

/// A bundle before sealing (or after opening): the body and the components,
/// in body order: the master share's, then per namespace its nsk_app's, its
/// versions' shared elements, its leaves' shared elements, its values'
/// shared elements and per blob its part ([`pack_part`]).
#[derive(Clone, Debug, PartialEq)]
pub struct Contents {
    pub body: Body,
    pub components: Vec<Fr>,
}

/// A bundle on the wire: the body as JSON text, the components sealed to
/// the receiver's enc key, and the sender's signature over both.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub body: String,
    pub eph: GrumpkinPoint,
    pub ct: Vec<FieldHex>,
    pub tag: FieldHex,
    pub signature: Signature,
}

/// The component of `share` that node `from` shares with node `to`.
fn component(from: usize, to: usize, share: Share) -> Fr {
    if from == next(to) { share.b } else { share.a }
}

/// The bytes one field element carries in a bundle: 31, so every chunk is
/// below the field's modulus.
const CHUNK: usize = 31;

/// `bytes` as field elements: its length, then its chunks of [`CHUNK`]
/// bytes, little-endian.
fn pack(bytes: &[u8], out: &mut Vec<Fr>) {
    out.push(Fr::from(bytes.len() as u64));
    out.extend(bytes.chunks(CHUNK).map(Fr::from_le_bytes_mod_order));
}

/// The bytes [`pack`] wrote; 400 for a bundle that ends early or carries
/// another value.
fn unpack(it: &mut impl Iterator<Item = Fr>) -> Result<Vec<u8>, Refusal> {
    let short = || Refusal::bad_request("resync: a bundle's blob part is malformed");
    let len = it.next().and_then(crate::tree::fr_u64).ok_or_else(short)? as usize;
    let mut out = Vec::with_capacity(len.min(1 << 30));
    while out.len() < len {
        let bytes = it.next().ok_or_else(short)?.into_bigint().to_bytes_le();
        let n = (len - out.len()).min(CHUNK);
        if bytes[n..].iter().any(|b| *b != 0) {
            return Err(short());
        }
        out.extend_from_slice(&bytes[..n]);
    }
    Ok(out)
}

/// A blob part in the components: 1, then its share component and copies
/// packed; or 0 for a part a delta resync's neighbour leaves to the
/// restored node's backup.
fn pack_part(part: Option<&Part>, out: &mut Vec<Fr>) {
    match part {
        None => out.push(Fr::from(0u64)),
        Some(p) => {
            out.push(Fr::from(1u64));
            pack(&p.shares, out);
            pack(&p.copies, out);
        }
    }
}

/// The blob part [`pack_part`] wrote, under the body's `public` bytes (none
/// when it was left to the backup).
pub(super) fn unpack_part(
    it: &mut impl Iterator<Item = Fr>,
    public: &[u8],
) -> Result<Option<Part>, Refusal> {
    match it.next() {
        Some(m) if m == Fr::from(0u64) => Ok(None),
        Some(m) if m == Fr::from(1u64) => Ok(Some(Part {
            public: public.to_vec(),
            shares: unpack(it)?,
            copies: unpack(it)?,
        })),
        _ => Err(Refusal::bad_request(
            "resync: a bundle carries fewer components than its body names",
        )),
    }
}

fn vec_body(from: usize, to: usize, vec: &[Elem], components: &mut Vec<Fr>) -> VecBody {
    vec.iter()
        .map(|e| match e {
            Elem::Public(v) => Some(FieldHex(*v)),
            Elem::Shared(s) => {
                components.push(component(from, to, *s));
                None
            }
        })
        .collect()
}

/// What node `node` sends node `to` for `scope`: every namespace of its
/// store (or the scope's one, its row and the key's versions and tree
/// only), each read under the namespace's lock, which `held` must hold
/// (taken before the session's mesh lock, [`Node::maintain`]), right after
/// the prune pass marks its versions against the node's own chain view
/// `views` ([`NodeVersions::mark`]), so two neighbours send the same
/// versions whenever they last pruned; a delta resync's bundle is a store
/// resync's, [`omit`]ted once the restored node has said what it holds. 400
/// for a key scope whose namespace this node does not hold.
pub fn collect<S: Store>(
    node: &Node<S>,
    held: &NamespacesGuard<'_>,
    to: usize,
    scope: &Scope,
    views: &VersionViews<'_>,
) -> Result<Contents, Refusal> {
    let from = node.index;
    if from == to {
        return Err(Refusal::bad_request(
            "a node does not send a resync bundle to itself",
        ));
    }
    let store = &node.store;
    let whole = scope.key().is_none();
    let mut components = vec![component(from, to, node.master())];
    let mut namespaces = Vec::new();
    for ns in scope.namespaces(store)? {
        held.require(ns)?;
        NodeVersions::mark(store, ns, views)?;
        let row = store.namespace(ns)?.ok_or_else(|| match scope.key() {
            None => Refusal::mpc_failure("store: a listed namespace has no row"),
            Some(_) => Refusal::bad_request(format!(
                "resync: node {from} holds no namespace {}",
                fr_to_hex(ns)
            )),
        })?;
        components.push(component(from, to, row.nsk_app));
        let mut manifests = Vec::new();
        if whole {
            for (m, packages) in held_versions(store, ns)? {
                let packages = packages
                    .into_iter()
                    .map(|p| PackageBody {
                        name: p.name,
                        circuit: HexBytes(p.circuit_json),
                        manifest: p.manifest,
                        vk: HexBytes(p.vk),
                        vk_hash: FieldHex(p.vk_hash),
                        disabled: p.disabled,
                        seq: p.seq,
                    })
                    .collect();
                manifests.push(ManifestBody {
                    manifest: ManifestRows::from(&m),
                    packages,
                });
            }
        }
        let keys = scope.keys(|| store.tip_keys(ns))?;
        let rows = tip_rows(store, ns, &keys, |v| v.status != VersionStatus::Orphan)?;
        let versions = rows
            .versions
            .into_iter()
            .map(|v| VersionBody {
                vec: vec_body(from, to, &v.vec, &mut components),
                tree: v.tree.map(|t| {
                    let (root, next) = t.stored();
                    TreeBody {
                        root: FieldHex(root),
                        next,
                    }
                }),
                key: v.key,
                commitment: FieldHex(v.commitment),
                parent: FieldHex(v.parent),
                index: v.index,
                request_id: v.request_id,
                canonical: v.status == VersionStatus::Canonical,
                block: v.block,
                block_hash: FieldHex(v.block_hash),
            })
            .collect();
        // the nodes in (key, hash) order, then the leaves' components in
        // that order
        let mut nodes = Vec::with_capacity(rows.nodes.len());
        let mut leaves = Vec::new();
        for ((key, hash), node) in rows.nodes {
            nodes.push(match node {
                TreeNode::Inner { left, right } => NodeBody::Inner {
                    key,
                    hash: FieldHex(hash),
                    left: FieldHex(left),
                    right: FieldHex(right),
                },
                TreeNode::Leaf { index, vec } => {
                    let body = NodeBody::Leaf {
                        key,
                        hash: FieldHex(hash),
                        index,
                        vec: vec
                            .iter()
                            .map(|e| match e {
                                Elem::Public(v) => Some(FieldHex(*v)),
                                Elem::Shared(_) => None,
                            })
                            .collect(),
                    };
                    leaves.push(vec);
                    body
                }
            });
        }
        for vec in &leaves {
            vec_body(from, to, vec, &mut components);
        }
        let (mut values, mut consumed, mut dead, mut receipts) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        if whole {
            for key in store.value_keys(ns)? {
                let Some(v) = store.value(ns, &key)? else {
                    continue;
                };
                values.push(ValueBody {
                    vec: vec_body(from, to, &v.vec, &mut components),
                    key,
                    note_hash: FieldHex(v.note_hash),
                    request_id: v.request_id,
                });
            }
            consumed = store
                .consumed_rows(ns)?
                .into_iter()
                .map(|c| ConsumedBody {
                    note_hash: FieldHex(c.note_hash),
                    circuit: FieldHex(c.circuit),
                    request_id: c.request_id,
                })
                .collect();
            dead = store
                .dead_records(ns)?
                .into_iter()
                .map(|d| DeadBody {
                    note_hash: FieldHex(d.note_hash),
                    request_id: d.request_id,
                })
                .collect();
            let hook = node.receipt_resync();
            receipts = store
                .receipts(ns)?
                .iter()
                .filter_map(|r| hook.send(r))
                .collect();
        }
        let blob_keys = scope.keys(|| store.blob_keys(ns))?;
        let mut blobs = Vec::new();
        for key in blob_keys {
            for name in store.blob_names(ns, &key)? {
                let Some(bytes) = store.blob(ns, &key, &name)? else {
                    continue;
                };
                let part = Blob::from_bytes(&bytes)?.part(from, to);
                pack_part(Some(&part), &mut components);
                blobs.push(BlobBody {
                    key: key.clone(),
                    name,
                    public: HexBytes(part.public),
                });
            }
        }
        namespaces.push(NamespaceBody {
            blobs,
            namespace: FieldHex(ns),
            owner_pubkey: point_to_wire(row.owner_pubkey),
            npk_app_hash: FieldHex(row.npk_app_hash),
            seq: row.seq,
            manifests,
            versions,
            nodes,
            values,
            consumed,
            dead,
            receipts,
        });
    }
    Ok(Contents {
        body: Body {
            from,
            to,
            scope: scope.clone(),
            namespaces,
        },
        components,
    })
}

fn shared(vec: &VecBody) -> usize {
    vec.iter().filter(|e| e.is_none()).count()
}

/// A delta resync's bundle contents: `contents` without the components of
/// the versions, leaves and `values` rows the restored node's backup holds
/// (`held`), and without the part of each blob whose digest is the one the
/// backup's blob gives for this neighbour (a 0 in its place). The body is
/// unchanged, so both neighbours' bodies still agree; the master's and
/// every nsk_app's components are always sent. 400 for contents whose blob
/// parts do not parse.
pub fn omit(contents: Contents, held: &Held) -> Result<Contents, Refusal> {
    let Contents { body, components } = contents;
    let mut it = components.into_iter();
    let mut kept = Vec::new();
    let take = |it: &mut std::vec::IntoIter<Fr>, kept: &mut Vec<Fr>, n: usize, keep: bool| {
        for c in it.by_ref().take(n) {
            if keep {
                kept.push(c);
            }
        }
    };
    take(&mut it, &mut kept, 1, true);
    let from_next = body.from == next(body.to);
    for ns in &body.namespaces {
        let n = ns.namespace.fr();
        take(&mut it, &mut kept, 1, true);
        for v in &ns.versions {
            let keep = !held.version(n, &v.key, v.commitment.fr());
            take(&mut it, &mut kept, shared(&v.vec), keep);
        }
        for node in &ns.nodes {
            if let NodeBody::Leaf { key, hash, vec, .. } = node {
                let keep = !held.leaf(n, key, hash.fr());
                take(&mut it, &mut kept, shared(vec), keep);
            }
        }
        for v in &ns.values {
            let keep = !held.value(n, &v.key, v.note_hash.fr(), v.request_id);
            take(&mut it, &mut kept, shared(&v.vec), keep);
        }
        for b in &ns.blobs {
            let part = unpack_part(&mut it, &b.public.0)?;
            let backed = held
                .blob(n, &b.key, &b.name)
                .map(
                    |(next_digest, prev_digest)| {
                        if from_next { next_digest } else { prev_digest }
                    },
                );
            let same = match (&part, backed) {
                (Some(p), Some(digest)) => part_digest(p) == digest,
                _ => false,
            };
            pack_part(part.as_ref().filter(|_| !same), &mut kept);
        }
    }
    take(&mut it, &mut kept, usize::MAX, true);
    Ok(Contents {
        body,
        components: kept,
    })
}

fn body_nonce(from: usize, to: usize, body_hash: Fr) -> Fr {
    poseidon2_hash(&[
        label_field(RESYNC_LABEL),
        Fr::from(from as u64),
        Fr::from(to as u64),
        body_hash,
    ])
}

/// The message a bundle's signature covers: the label, the sender, the
/// receiver, the body's bytes and the sealed components.
fn bundle_message(from: usize, to: usize, body_hash: Fr, eph: Point, ct: &[Fr], tag: Fr) -> Fr {
    let (x, y) = coordinates(eph);
    let mut sealed: Vec<Fr> = ct.to_vec();
    sealed.extend([tag, x, y]);
    poseidon2_hash(&[
        label_field(RESYNC_LABEL),
        Fr::from(from as u64),
        Fr::from(to as u64),
        body_hash,
        poseidon2_hash(&sealed),
    ])
}

// How a resync bundle is protected. The clear body (rows,
// packages, versions' metadata, public elements, tree structure: nothing a
// node does not already serve or publish) travels as JSON text; the
// components travel sealed to the receiver's pinned `enc` key (ECDH with a
// fresh ephemeral key, then the Poseidon2 AEAD under a nonce bound to the
// sender, the receiver and the body); the sender signs both with its `sig`
// key, and the receiver checks the signature against the operator's pinned
// keys, not keys a peer reports. The mesh's pinned TLS already authenticates
// the peers; the seal and the signature make the bundle stand on its own,
// so it is the sender's statement whatever carried it. Changing either
// breaks the resync between nodes of different versions.
/// Seal `contents` to node `to`'s `enc_pk` and sign it with `keys`.
pub fn seal<R: RngCore + CryptoRng>(
    contents: &Contents,
    keys: &NodeKeys,
    enc_pk: Point,
    rng: &mut R,
) -> Bundle {
    let (from, to) = (contents.body.from, contents.body.to);
    let body = serde_json::to_string(&contents.body).expect("a resync body serialises");
    let body_hash = poseidon2_hash_bytes(body.as_bytes());
    let eph = loop {
        let e = Fr::rand(rng);
        if !e.is_zero() {
            break scalar_from_field(e);
        }
    };
    let e = fixed_base_mul(eph);
    let secret = coordinates(mul(enc_pk, eph)).0;
    let (ct, tag) = ae::encrypt(
        secret,
        body_nonce(from, to, body_hash),
        &contents.components,
    );
    let message = bundle_message(from, to, body_hash, e, &ct, tag);
    Bundle {
        body,
        eph: point_to_wire(e),
        ct: ct.into_iter().map(FieldHex).collect(),
        tag: FieldHex(tag),
        signature: schnorr::sign(keys.sig_scalar(), message, rng),
    }
}

/// Node `me` opens the bundle node `from` sent: 400 unless its signature
/// verifies under `from_sig` (the pinned key), its body parses and names
/// `from` and `me`, and its components open under this node's enc key (the
/// current one, or the previous one during a grace window).
pub fn open(
    bundle: &Bundle,
    keys: &NodeKeys,
    me: usize,
    from: usize,
    from_sig: &GrumpkinPoint,
) -> Result<Contents, Refusal> {
    let refuse = |why: String| Refusal::bad_request(format!("resync: node {from}'s bundle {why}"));
    let body_hash = poseidon2_hash_bytes(bundle.body.as_bytes());
    let eph = point_from_wire(&bundle.eph).map_err(|e| refuse(format!("has no key: {e}")))?;
    let ct: Vec<Fr> = bundle.ct.iter().map(|f| f.fr()).collect();
    let message = bundle_message(from, me, body_hash, eph, &ct, bundle.tag.fr());
    if !schnorr::verify_wire(from_sig, bundle.signature, message) {
        return Err(refuse("is not signed by its pinned sig key".to_string()));
    }
    let body: Body =
        serde_json::from_str(&bundle.body).map_err(|e| refuse(format!("does not parse: {e}")))?;
    if body.from != from || body.to != me {
        return Err(refuse(format!(
            "is from node {} to node {}, not from {from} to {me}",
            body.from, body.to
        )));
    }
    let nonce = body_nonce(from, me, body_hash);
    let components = keys
        .shared_secrets(eph)
        .into_iter()
        .find_map(|secret| ae::decrypt(secret, nonce, &ct, bundle.tag.fr()).ok())
        .ok_or_else(|| refuse("does not open under this node's enc key".to_string()))?;
    Ok(Contents { body, components })
}
