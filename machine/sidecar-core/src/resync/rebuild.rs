//! The rebuild of the lost node's pairs and rows from its two neighbours' bundles.

use super::receipts::receipt_rows;
use super::*;

// ---------------------------------------------------------------------------
// The rebuild
// ---------------------------------------------------------------------------

/// The body as the two neighbours must agree on it: without the sender,
/// with each version's status, block and block hash cleared (each node
/// marks those against its own chain view), and without the receipt rows (each node
/// prunes its own, at its own time, and signs them with its own key; a row
/// is kept only when both send it alike, [`receipt_rows`]).
fn agreed(body: &Body) -> Body {
    let mut b = body.clone();
    b.from = 0;
    for ns in &mut b.namespaces {
        for v in &mut ns.versions {
            v.canonical = false;
            v.block = 0;
            v.block_hash = FieldHex(Fr::from(0u64));
        }
        ns.receipts.clear();
    }
    b
}

/// The mark a rebuilt version takes from its two neighbours' copies: the
/// later block with the hash its sender read; at one block, that block with
/// the hash both read, or with none when they read different hashes (a mark
/// with no hash, [`crate::store::TipVersion::block_hash`]).
fn later_mark(v: &VersionBody, w: &VersionBody) -> (u64, Fr) {
    match v.block.cmp(&w.block) {
        std::cmp::Ordering::Greater => (v.block, v.block_hash.fr()),
        std::cmp::Ordering::Less => (w.block, w.block_hash.fr()),
        std::cmp::Ordering::Equal if v.block_hash == w.block_hash => (v.block, v.block_hash.fr()),
        std::cmp::Ordering::Equal => (v.block, Fr::from(0u64)),
    }
}

/// The first place two bodies differ, for the refusal.
fn first_difference(a: &Body, b: &Body) -> String {
    if a.scope != b.scope {
        return format!("scope {:?} against {:?}", a.scope, b.scope);
    }
    if a.namespaces.len() != b.namespaces.len() {
        return format!(
            "{} namespaces against {}",
            a.namespaces.len(),
            b.namespaces.len()
        );
    }
    for (x, y) in a.namespaces.iter().zip(&b.namespaces) {
        let ns = fr_to_hex(x.namespace.fr());
        if x.namespace != y.namespace {
            return format!("namespace {ns} against {}", fr_to_hex(y.namespace.fr()));
        }
        if (&x.owner_pubkey, x.npk_app_hash, x.seq) != (&y.owner_pubkey, y.npk_app_hash, y.seq) {
            return format!("namespace {ns}'s row");
        }
        if x.manifests != y.manifests {
            return format!("namespace {ns}'s contract manifests or packages");
        }
        if x.versions != y.versions {
            let key = x
                .versions
                .iter()
                .zip(&y.versions)
                .find(|(p, q)| p != q)
                .map_or("?", |(p, _)| p.key.as_str());
            return format!("namespace {ns}'s versions (key `{key}`)");
        }
        if x.nodes != y.nodes {
            return format!("namespace {ns}'s tree nodes");
        }
        if x.values != y.values {
            let key = x
                .values
                .iter()
                .zip(&y.values)
                .find(|(p, q)| p != q)
                .map_or("?", |(p, _)| p.key.as_str());
            return format!("namespace {ns}'s values (key `{key}`)");
        }
        if x.consumed != y.consumed {
            return format!("namespace {ns}'s consumed rows");
        }
        if x.dead != y.dead {
            return format!("namespace {ns}'s dead records");
        }
        if x.blobs != y.blobs {
            let named = x
                .blobs
                .iter()
                .zip(&y.blobs)
                .find(|(p, q)| p != q)
                .map_or("?".to_string(), |(p, _)| {
                    format!("`{}` of key `{}`", p.name, p.key)
                });
            return format!("namespace {ns}'s holder blobs ({named})");
        }
    }
    "the bodies".to_string()
}

/// What a resync rebuilt at the lost node, ready to import: per namespace
/// its row, its packages, its versions, its tree nodes, its `values` and
/// `consumed` rows, its dead records and the receipt rows it keeps.
pub struct Rebuilt {
    pub scope: Scope,
    /// The master pair the two neighbours' components rebuild (equal to the
    /// key directory's, or the newcomer's to install).
    pub master: Share,
    pub namespaces: Vec<RebuiltNamespace>,
    /// The receipt rows not kept: sent by one neighbour only, sent
    /// differently, or refused by the node's hook (their signatures or ids).
    pub receipts_left_out: usize,
    /// The versions, leaves and `values` rows whose pairs came from the
    /// node's backup (a delta resync).
    pub from_backup: usize,
    /// The blob parts taken from the node's backup (a delta resync).
    pub blob_parts_from_backup: usize,
}

pub struct RebuiltNamespace {
    pub namespace: Fr,
    pub row: NamespaceRow,
    /// Every contract manifest version, oldest first (a whole-store
    /// resync).
    pub manifests: Vec<ManifestRow>,
    /// The packages of every version.
    pub packages: Vec<PackageRow>,
    pub versions: Vec<TipVersion>,
    pub nodes: BTreeMap<(String, Fr), TreeNode>,
    pub values: Vec<RestoredValue>,
    pub consumed: Vec<ConsumedRow>,
    /// Signed with this node's own key: the rows both neighbours sent alike
    /// that the node's hook kept, then (a delta resync) the backup's rows of
    /// other requests.
    pub receipts: Vec<ReceiptRow>,
    /// The backup's `requests` rows (a delta resync; none otherwise).
    pub requests: Vec<RequestRow>,
    /// The neighbours' dead records (none under a key scope).
    pub dead: Vec<DeadRecord>,
    /// The holder blobs, as (key, name, bytes).
    pub blobs: Vec<(String, String, Vec<u8>)>,
}

/// The components of both neighbours, paired in body order.
struct Pairs {
    from_next: std::vec::IntoIter<Fr>,
    from_prev: std::vec::IntoIter<Fr>,
}

impl Pairs {
    fn take(&mut self) -> Result<Share, Refusal> {
        match (self.from_next.next(), self.from_prev.next()) {
            (Some(a), Some(b)) => Ok(Share::new(a, b)),
            _ => Err(Refusal::bad_request(
                "resync: a bundle carries fewer components than its body names",
            )),
        }
    }

    fn vec(&mut self, body: &VecBody) -> Result<Vec<Elem>, Refusal> {
        body.iter()
            .map(|e| match e {
                Some(v) => Ok(Elem::Public(v.fr())),
                None => self.take().map(Elem::Shared),
            })
            .collect()
    }

    /// The pairs of `body`: from the backup when it holds them (`own`,
    /// which must have the body's shape and public elements), from the
    /// neighbours otherwise. Counts what came from the backup.
    fn vec_or_own(
        &mut self,
        body: &VecBody,
        own: Option<&[Elem]>,
        from_backup: &mut usize,
        what: impl FnOnce() -> String,
    ) -> Result<Vec<Elem>, Refusal> {
        let Some(own) = own else {
            return self.vec(body);
        };
        let same = own.len() == body.len()
            && own.iter().zip(body).all(|(e, b)| match (e, b) {
                (Elem::Public(v), Some(w)) => *v == w.fr(),
                (Elem::Shared(_), None) => true,
                _ => false,
            });
        if !same {
            return Err(Refusal::bad_request(format!(
                "resync: {}: the backup's vector is not the one the neighbours' bodies name",
                what()
            )));
        }
        *from_backup += 1;
        Ok(own.to_vec())
    }

    /// One blob's parts from the two neighbours, a part a delta resync's
    /// neighbour left out taken from the backup's blob (`own`: the parts
    /// node i+1 and node i-1 would send), counting those.
    fn blob(
        &mut self,
        public: &[u8],
        own: Option<(Part, Part)>,
        from_backup: &mut usize,
        what: impl Fn() -> String,
    ) -> Result<Blob, Refusal> {
        let (own_next, own_prev) = own.unzip();
        let mut side =
            |it: &mut std::vec::IntoIter<Fr>, own: Option<Part>| match bundle::unpack_part(
                it, public,
            )? {
                Some(part) => Ok::<Part, Refusal>(part),
                None => {
                    let part = own.filter(|p| p.public == public).ok_or_else(|| {
                        Refusal::bad_request(format!(
                            "resync: {}: a neighbour left the blob to the backup, which does \
                             not hold it",
                            what()
                        ))
                    })?;
                    *from_backup += 1;
                    Ok(part)
                }
            };
        let from_next = side(&mut self.from_next, own_next)?;
        let from_prev = side(&mut self.from_prev, own_prev)?;
        Blob::rebuild(from_next, from_prev)
            .map_err(|e| Refusal::bad_request(format!("resync: {}: {}", what(), e.message)))
    }
}

/// Node `me` rebuilds its pairs from the two neighbours' opened bundles
/// (`from_prev` from node me-1, `from_next` from node me+1). 400 when the
/// bodies differ (naming the first difference), a component is missing or
/// left over, the master pair is not `master` (the key directory's; a
/// newcomer has none to compare, `None`, and installs the rebuilt one), a
/// tree node does not hash to its address, or a key resync's neighbours
/// hold no canonical or live version of the key. The receipt rows both
/// neighbours sent alike are checked and signed again with `keys` by
/// `receipt_resync`, the node's hook ([`ReceiptResync::keep`], the senders'
/// sig keys from `pins`). Under a delta scope `own` is the node's
/// backup: the pairs of what it holds come from it (400 when one's shape or
/// public elements are not the body's), and its `requests` rows and
/// receipt rows of requests the neighbours did not bring back join the
/// rebuilt namespace.
#[allow(clippy::too_many_arguments)]
pub fn rebuild(
    me: usize,
    from_prev: Contents,
    from_next: Contents,
    keys: &NodeKeys,
    master: Option<Share>,
    pins: &NodesResponse,
    own: Option<&Own>,
    receipt_resync: &dyn ReceiptResync,
) -> Result<Rebuilt, Refusal> {
    let refuse = |why: String| Refusal::bad_request(format!("resync: {why}"));
    if from_prev.body.from != prev(me) || from_next.body.from != next(me) {
        return Err(refuse(
            "the bundles are not from this node's neighbours".into(),
        ));
    }
    let (a, b) = (agreed(&from_next.body), agreed(&from_prev.body));
    if a != b {
        return Err(refuse(format!(
            "the two neighbours' bundles differ: {}",
            first_difference(&a, &b)
        )));
    }
    let mut pairs = Pairs {
        from_next: from_next.components.into_iter(),
        from_prev: from_prev.components.into_iter(),
    };
    let rebuilt_master = pairs.take()?;
    if master.is_some_and(|m| m != rebuilt_master) {
        return Err(refuse(
            "the neighbours' master components do not rebuild this node's master share (its key \
             directory's)"
                .into(),
        ));
    }
    if let Some((_, key)) = from_next.body.scope.key()
        && from_next
            .body
            .namespaces
            .iter()
            .all(|ns| ns.versions.is_empty())
    {
        return Err(refuse(format!(
            "the neighbours hold no canonical or live version of key `{key}`"
        )));
    }
    let scope = from_next.body.scope.clone();
    let mut namespaces = Vec::new();
    let mut receipts_left_out = 0;
    let mut from_backup = 0;
    let mut blob_parts_from_backup = 0;
    for (ns_next, ns_prev) in from_next
        .body
        .namespaces
        .into_iter()
        .zip(from_prev.body.namespaces)
    {
        let namespace = ns_next.namespace.fr();
        let (receipts, left_out) = receipt_rows(
            me,
            namespace,
            &ns_prev.receipts,
            &ns_next.receipts,
            keys,
            pins,
            receipt_resync,
        )?;
        receipts_left_out += left_out;
        let backup = own.and_then(|o| o.namespace(namespace));
        let ns_hex = fr_to_hex(namespace);
        let owner_pubkey = point_from_wire(&ns_next.owner_pubkey)
            .map_err(|e| refuse(format!("namespace {}: {e}", fr_to_hex(namespace))))?;
        let row = NamespaceRow {
            owner_pubkey,
            nsk_app: pairs.take()?,
            npk_app_hash: ns_next.npk_app_hash.fr(),
            seq: ns_next.seq,
        };
        let mut manifests = Vec::new();
        let mut packages = Vec::new();
        for ManifestBody {
            manifest: m,
            packages: sent,
        } in ns_next.manifests
        {
            let hash = manifest_hash(&m.document).map_err(|r| refuse(r.message))?;
            if hash != m.manifest_hash.fr() {
                return Err(refuse(format!(
                    "namespace {ns_hex}: the contract manifest hashes to {}, not the {} sent \
                     with it",
                    fr_to_hex(hash),
                    m.manifest_hash
                )));
            }
            packages.extend(sent.into_iter().map(|p| PackageRow {
                name: p.name,
                manifest_hash: hash,
                circuit_json: p.circuit.0,
                manifest: p.manifest,
                vk: p.vk.0,
                vk_hash: p.vk_hash.fr(),
                disabled: p.disabled,
                seq: p.seq,
            }));
            manifests.push(ManifestRow::from(&m));
        }
        let mut versions = Vec::new();
        for (v, w) in ns_next.versions.into_iter().zip(ns_prev.versions) {
            let canonical = v.canonical || w.canonical;
            let (block, block_hash) = later_mark(&v, &w);
            let held = own.and_then(|o| o.version(namespace, &v.key, v.commitment.fr()));
            let vec = pairs.vec_or_own(&v.vec, held, &mut from_backup, || {
                format!(
                    "namespace {ns_hex} key `{}` version {}",
                    v.key,
                    fr_to_hex(v.commitment.fr())
                )
            })?;
            versions.push(TipVersion {
                vec,
                key: v.key,
                commitment: v.commitment.fr(),
                parent: v.parent.fr(),
                index: v.index,
                request_id: v.request_id,
                tree: v
                    .tree
                    .map(|t| VersionTree::from_stored(t.root.fr(), t.next)),
                status: if canonical {
                    VersionStatus::Canonical
                } else {
                    VersionStatus::Live
                },
                block,
                block_hash,
            });
        }
        let mut nodes = BTreeMap::new();
        for n in ns_next.nodes {
            let (key, hash, node) = match n {
                NodeBody::Inner {
                    key,
                    hash,
                    left,
                    right,
                } => {
                    if tree::node(left.fr(), right.fr()) != hash.fr() {
                        return Err(refuse(format!(
                            "key `{key}`: the tree node {} does not hash to its address",
                            fr_to_hex(hash.fr())
                        )));
                    }
                    let node = TreeNode::Inner {
                        left: left.fr(),
                        right: right.fr(),
                    };
                    (key, hash, node)
                }
                NodeBody::Leaf {
                    key,
                    hash,
                    index,
                    vec,
                } => {
                    let held = own.and_then(|o| o.leaf(namespace, &key, hash.fr()));
                    let vec = pairs.vec_or_own(&vec, held, &mut from_backup, || {
                        format!(
                            "namespace {ns_hex} key `{key}` leaf {}",
                            fr_to_hex(hash.fr())
                        )
                    })?;
                    (key, hash, TreeNode::Leaf { index, vec })
                }
            };
            nodes.insert((key, hash.fr()), node);
        }
        let mut values = Vec::new();
        for v in ns_next.values {
            let held = own.and_then(|o| o.value(namespace, &v.key, v.note_hash.fr(), v.request_id));
            let vec = pairs.vec_or_own(&v.vec, held, &mut from_backup, || {
                format!("namespace {ns_hex} value `{}`", v.key)
            })?;
            values.push(RestoredValue {
                vec,
                key: v.key,
                note_hash: v.note_hash.fr(),
                prior_request_id: v.request_id,
            });
        }
        let mut blobs = Vec::new();
        for b in ns_next.blobs {
            let own = own
                .and_then(|o| o.blob(namespace, &b.key, &b.name))
                .map(own_parts);
            let blob = pairs.blob(&b.public.0, own, &mut blob_parts_from_backup, || {
                format!("namespace {ns_hex} key `{}` blob `{}`", b.key, b.name)
            })?;
            blobs.push((b.key, b.name, blob.to_bytes()));
        }
        let consumed = ns_next
            .consumed
            .into_iter()
            .map(|c| ConsumedRow {
                note_hash: c.note_hash.fr(),
                circuit: c.circuit.fr(),
                request_id: c.request_id,
            })
            .collect();
        let dead = ns_next
            .dead
            .into_iter()
            .map(|d| DeadRecord {
                note_hash: d.note_hash.fr(),
                request_id: d.request_id,
            })
            .collect();
        let mut receipts = receipts;
        let mut requests = Vec::new();
        if let Some(b) = backup {
            let kept: std::collections::BTreeSet<Fr> =
                receipts.iter().map(|r| r.request_id).collect();
            receipts.extend(
                b.receipts
                    .iter()
                    .filter(|r| !kept.contains(&r.request_id))
                    .cloned(),
            );
            requests = b.requests.clone();
        }
        namespaces.push(RebuiltNamespace {
            namespace,
            row,
            manifests,
            packages,
            versions,
            nodes,
            values,
            consumed,
            receipts,
            requests,
            dead,
            blobs,
        });
    }
    if pairs.from_next.next().is_some() || pairs.from_prev.next().is_some() {
        return Err(refuse(
            "a bundle carries more components than its body names".into(),
        ));
    }
    Ok(Rebuilt {
        scope,
        master: rebuilt_master,
        namespaces,
        receipts_left_out,
        from_backup,
        blob_parts_from_backup,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marked(block: u64, hash: u64) -> VersionBody {
        VersionBody {
            key: "k".into(),
            commitment: FieldHex::from(1),
            parent: FieldHex::from(0),
            index: 0,
            request_id: RequestId(Fr::from(2u64)),
            canonical: true,
            block,
            block_hash: FieldHex::from(hash),
            vec: vec![],
            tree: None,
        }
    }

    #[test]
    fn a_rebuilt_version_takes_the_later_mark_with_its_hash() {
        let b = Fr::from(0xbu64);
        assert_eq!(later_mark(&marked(5, 0xa), &marked(7, 0xb)), (7, b));
        assert_eq!(later_mark(&marked(7, 0xb), &marked(5, 0xa)), (7, b));
        assert_eq!(later_mark(&marked(7, 0xb), &marked(7, 0xb)), (7, b));
        // one block read under two hashes: a mark with no hash
        assert_eq!(
            later_mark(&marked(7, 0xb), &marked(7, 0xc)),
            (7, Fr::from(0u64))
        );
    }
}
