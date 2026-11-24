//! The npk_app_hash, `values` pairs and holder blob checks after a resync.

use super::*;
use crate::registry;

// ---------------------------------------------------------------------------
// The npk_app_hash check
// ---------------------------------------------------------------------------

// How a resync checks a namespace's rebuilt `nsk_app`. The
// registration circuit runs again on the three master shares: its proven
// `npk_app_hash` must equal the registered one (which every contract of the
// namespace pins), so the master is right. Its fresh sharing of `nsk_app` is
// then compared with the rebuilt one: the difference of the two pairs is
// opened and must be 0, which reveals nothing when they agree and only the
// error when they do not. Before either, the session handshake compares the
// rebuilt pair with the neighbours' (a component sent wrongly differs from
// the one the neighbour holds). The check stores nothing: the rebuilt pairs
// stay, so the other two nodes' rows are untouched.
/// Check `namespace`'s `nsk_app` pairs and `npk_app_hash` over the open
/// session `net` (all three nodes run it): 400 naming what failed, 500 when
/// the mesh or the circuit fails.
pub fn check_npk_app<S: Store, N: Network>(
    node: &Node<S>,
    namespace: Fr,
    net: &N,
) -> Result<(), Refusal> {
    let row = node.store.namespace(namespace)?.ok_or_else(|| {
        Refusal::mpc_failure(format!(
            "resync: no namespace {} to check",
            fr_to_hex(namespace)
        ))
    })?;
    let ns = fr_to_hex(namespace);
    let body = poseidon2_hash(&[label_field(NPK_CHECK_LABEL), row.npk_app_hash]);
    let hs = Handshake::build(RequestId(namespace), body, &[("nsk_app", row.nsk_app)], &[]);
    handshake::exchange(net, &hs)?;
    let derived = registry::derive(&node.registration, &node.crs, node.master(), namespace, net)?;
    if derived.npk_app_hash != row.npk_app_hash {
        return Err(Refusal::bad_request(format!(
            "resync: namespace {ns}: the master gives npk_app_hash {}, not the registered {}",
            fr_to_hex(derived.npk_app_hash),
            fr_to_hex(row.npk_app_hash)
        )));
    }
    let diff = arithmetic::sub(derived.nsk_app, row.nsk_app);
    let opened = arithmetic::open(diff, net).map_err(|e| {
        Refusal::mpc_failure(format!(
            "MPC session failed opening the nsk_app check: {e:#}"
        ))
    })?;
    if !opened.is_zero() {
        return Err(Refusal::bad_request(format!(
            "resync: namespace {ns}: the nsk_app pairs do not rebuild the master's nsk_app"
        )));
    }
    Ok(())
}

/// Check `namespace`'s `values` rows (the sidecar path's node-held state)
/// over the open session `net` (all three nodes run it): one handshake over
/// every row's pairs, in key order, whose body names the keys and note
/// hashes. A component one neighbour sent differently from the one the
/// other holds refuses (400), naming the key and the element; 500 when the
/// mesh fails. The rows' note hashes are the app circuits' own, so no
/// machine circuit recomputes them.
pub fn check_values<S: Store, N: Network>(
    node: &Node<S>,
    namespace: Fr,
    net: &N,
) -> Result<(), Refusal> {
    let mut rows = Vec::new();
    for key in node.store.value_keys(namespace)? {
        if let Some(row) = node.store.value(namespace, &key)? {
            rows.push((key, row));
        }
    }
    let id = poseidon2_hash(&[label_field(VALUES_CHECK_LABEL), namespace]);
    let mut body = vec![id];
    for (key, row) in &rows {
        body.extend([key_hash(key), row.note_hash]);
    }
    let values: Vec<(String, &[Elem])> = rows
        .iter()
        .map(|(key, row)| (format!("value `{key}`"), row.vec.as_slice()))
        .collect();
    let hs = Handshake::of_values(RequestId(id), poseidon2_hash(&body), &values);
    handshake::exchange(net, &hs)
}

/// The label of the blob check, `sidecar.blob_check`.
const BLOB_CHECK_LABEL: &[u8] = b"sidecar.blob_check";

/// One node's digests of its blobs for the blob check: per (key, name),
/// the digest of the part it shares with each neighbour.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobDigests {
    blobs: Vec<(String, String, FieldHex)>,
}

/// Check `namespace`'s holder blobs (every key's, or `only`'s) over the
/// open session `net` (all three nodes run it): each node sends node i+1
/// the digests of the parts that node holds alike (its `a` components,
/// with the public bytes and its `a` copies) and node i-1 those of its `b`,
/// and compares what each neighbour sent with its own. A blob one node
/// holds and another does not, or a component one neighbour sent
/// differently from the one the other holds, refuses (400), naming the key
/// and the blob; 500 when the mesh fails. Returns the blobs checked.
pub fn check_blobs<S: Store, N: Network>(
    node: &Node<S>,
    namespace: Fr,
    only: Option<&str>,
    net: &N,
) -> Result<usize, Refusal> {
    let me = node.index;
    let store = &node.store;
    let keys = match only {
        Some(key) => vec![key.to_string()],
        None => store.blob_keys(namespace)?,
    };
    let (mut to_next, mut to_prev) = (Vec::new(), Vec::new());
    for key in keys {
        for name in store.blob_names(namespace, &key)? {
            let Some(bytes) = store.blob(namespace, &key, &name)? else {
                continue;
            };
            let blob = Blob::from_bytes(&bytes)?;
            let digest = |part: Part| {
                FieldHex(poseidon2_hash(&[
                    label_field(BLOB_CHECK_LABEL),
                    namespace,
                    part_digest(&part),
                ]))
            };
            to_next.push((key.clone(), name.clone(), digest(blob.part(me, next(me)))));
            to_prev.push((key.clone(), name, digest(blob.part(me, prev(me)))));
        }
    }
    let checked = to_next.len();
    send_json(
        net,
        next(me),
        "blob check",
        &BlobDigests {
            blobs: to_next.clone(),
        },
    )?;
    send_json(
        net,
        prev(me),
        "blob check",
        &BlobDigests {
            blobs: to_prev.clone(),
        },
    )?;
    let from_prev: BlobDigests = recv_json(net, prev(me), "blob check")?;
    let from_next: BlobDigests = recv_json(net, next(me), "blob check")?;
    // node i-1's part for node i is the one node i shares with node i-1
    for (theirs, mine, peer) in [
        (from_prev, &to_prev, prev(me)),
        (from_next, &to_next, next(me)),
    ] {
        if theirs.blobs.len() != mine.len()
            || theirs
                .blobs
                .iter()
                .zip(mine)
                .any(|(t, m)| (&t.0, &t.1) != (&m.0, &m.1))
        {
            return Err(Refusal::bad_request(format!(
                "resync: namespace {}: node {peer} holds other holder blobs than node {me}",
                fr_to_hex(namespace)
            )));
        }
        if let Some((key, name, _)) = theirs
            .blobs
            .iter()
            .zip(mine)
            .find(|(t, m)| t.2 != m.2)
            .map(|(t, _)| t)
        {
            return Err(Refusal::bad_request(format!(
                "resync: namespace {}: key `{key}` blob `{name}`: node {peer}'s component \
                 differs from node {me}'s",
                fr_to_hex(namespace)
            )));
        }
    }
    Ok(checked)
}
