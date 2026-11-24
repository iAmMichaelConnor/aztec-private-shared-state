//! Comparing registry rows between their holders: the three nodes, which
//! compare theirs over one mesh session ([`check`], `sidecar-node
//! sync-registry --check`), and the orchestrator's copy, which its start-up
//! check compares with the nodes' answers over their mutual-TLS legs
//! (sidecar-orchestrator `sync::check_agreement`). Read-only: nothing here
//! writes a row; the registry resync ([`crate::resync::resync_registry`])
//! compares the same rows before it repairs one node's.
//!
//! A holder's rows of one namespace are its `namespaces` row (owner, `seq`,
//! `npk_app_hash`; the `nsk_app` share differs at every node and is not
//! compared), its contract manifest (compared by its hash and the `seq` that
//! wrote it) and each of its `packages` rows by name (vk_hash, manifest,
//! disabled flag and the `seq` that last wrote it; the vk itself is each
//! holder's own build of the circuit, which the vk_hash names). Every row is
//! public: the GETs serve them.

use std::collections::BTreeSet;

use mpc_net::Network;
use serde::{Deserialize, Serialize};

use crate::error::Refusal;
use crate::field::{FieldHex, Fr, RequestId, fr_to_hex};
use crate::handshake::{self, Handshake, recv_json, send_json};
use crate::hash::poseidon2_hash;
use crate::keys::label_field;
use crate::pipeline::Node;
use crate::register::{ContractManifestResponse, NamespaceResponse, PackageResponse};
use crate::request::{GrumpkinPoint, NODES, next, prev};
use crate::store::{ManifestRow, PackageRow, Store};

const CHECK_LABEL: &[u8] = b"pss.registry-check";

/// One `packages` row as the holders compare it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRows {
    pub name: String,
    pub vk_hash: FieldHex,
    pub manifest: serde_json::Value,
    pub disabled: bool,
    pub seq: u64,
}

/// A namespace's `manifests` row as the holders compare it: by its hash
/// and `seq`; the document travels with them for a holder that rebuilds its
/// rows from another's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRows {
    pub manifest_hash: FieldHex,
    pub seq: u64,
    pub document: serde_json::Value,
}

impl From<&ManifestRow> for ManifestRows {
    fn from(row: &ManifestRow) -> Self {
        ManifestRows {
            manifest_hash: FieldHex(row.manifest_hash),
            seq: row.seq,
            document: row.document.clone(),
        }
    }
}

impl From<&ManifestRows> for ManifestRow {
    fn from(rows: &ManifestRows) -> Self {
        ManifestRow {
            manifest_hash: rows.manifest_hash.fr(),
            document: rows.document.clone(),
            seq: rows.seq,
        }
    }
}

/// One holder's registry rows of one namespace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceRows {
    pub namespace: FieldHex,
    pub owner_pubkey: GrumpkinPoint,
    pub seq: u64,
    pub npk_app_hash: FieldHex,
    /// The contract manifest; `None` for a namespace row without one, which
    /// a REGISTER never leaves.
    pub manifest: Option<ManifestRows>,
    /// By name, in byte order.
    pub packages: Vec<PackageRows>,
}

impl From<&PackageRow> for PackageRows {
    fn from(row: &PackageRow) -> Self {
        PackageRows {
            name: row.name.clone(),
            vk_hash: FieldHex(row.vk_hash),
            manifest: row.manifest.clone(),
            disabled: row.disabled,
            seq: row.seq,
        }
    }
}

impl From<&PackageResponse> for PackageRows {
    fn from(pkg: &PackageResponse) -> Self {
        PackageRows {
            name: pkg.name.clone(),
            vk_hash: pkg.vk_hash,
            manifest: pkg.manifest.clone(),
            disabled: pkg.disabled,
            seq: pkg.seq,
        }
    }
}

impl NamespaceRows {
    /// The rows of `namespace` in `store`; `None` when it holds no
    /// `namespaces` row for it.
    pub fn read<S: Store + ?Sized>(store: &S, namespace: Fr) -> Result<Option<Self>, Refusal> {
        let Some(row) = store.namespace(namespace)? else {
            return Ok(None);
        };
        let mut packages = Vec::new();
        for name in store.package_names(namespace)? {
            if let Some(pkg) = store.package(namespace, &name)? {
                packages.push(PackageRows::from(&pkg));
            }
        }
        packages.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Some(NamespaceRows {
            namespace: FieldHex(namespace),
            owner_pubkey: crate::grumpkin::point_to_wire(row.owner_pubkey),
            seq: row.seq,
            npk_app_hash: FieldHex(row.npk_app_hash),
            manifest: store
                .contract_manifest(namespace)?
                .as_ref()
                .map(ManifestRows::from),
            packages,
        }))
    }

    /// The rows a node's `GET /v1/namespaces/{namespace}`, `GET
    /// /v1/namespaces/{namespace}/manifest` and `GET
    /// /v1/packages/{namespace}/{name}` answers describe, each package
    /// answer reduced to its row ([`PackageRows::from`]).
    pub fn from_answers(
        info: &NamespaceResponse,
        manifest: &ContractManifestResponse,
        mut packages: Vec<PackageRows>,
    ) -> Self {
        packages.sort_by(|a, b| a.name.cmp(&b.name));
        NamespaceRows {
            namespace: info.namespace,
            owner_pubkey: info.owner_pubkey,
            seq: info.seq,
            npk_app_hash: info.npk_app_hash,
            manifest: Some(ManifestRows {
                manifest_hash: manifest.manifest_hash,
                seq: manifest.seq,
                document: manifest.manifest.clone(),
            }),
            packages,
        }
    }

    fn package(&self, name: &str) -> Option<&PackageRows> {
        self.packages.iter().find(|p| p.name == name)
    }
}

/// What one group of holders holds for a row the holders do not agree on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Held {
    /// The holders, by the names the comparison was given ("node 0", "the
    /// copy").
    pub holders: Vec<String>,
    /// What they hold: "no row", or the row's fields ("seq 3, disabled,
    /// vk_hash 0x…").
    pub row: String,
}

/// One row the holders do not agree on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Divergence {
    pub namespace: FieldHex,
    /// "the namespace row", or "package `name`".
    pub row: String,
    /// One entry per distinct value, in the order of their first holder.
    pub held: Vec<Held>,
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "namespace {}: {}: ", self.namespace, self.row)?;
        for (k, held) in self.held.iter().enumerate() {
            if k > 0 {
                f.write_str("; ")?;
            }
            let verb = if held.holders.len() == 1 {
                "holds"
            } else {
                "hold"
            };
            write!(f, "{} {verb} {}", and_list(&held.holders), held.row)?;
        }
        Ok(())
    }
}

fn and_list(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// Compare the rows of each holder (`holders[k]` holds `rows[k]`, one entry
/// per namespace it holds) and return every row they do not all hold alike:
/// a namespace or package one holder lacks, or holds with other fields. A
/// manifest or owner that differs is named by its order of appearance
/// ("manifest A", "manifest B"), the other fields by value.
pub fn compare(holders: &[String], rows: &[Vec<NamespaceRows>]) -> Vec<Divergence> {
    assert_eq!(holders.len(), rows.len(), "one row list per holder");
    let namespaces: BTreeSet<Fr> = rows
        .iter()
        .flat_map(|held| held.iter().map(|ns| ns.namespace.fr()))
        .collect();
    let mut out = Vec::new();
    for namespace in namespaces {
        let each: Vec<Option<&NamespaceRows>> = rows
            .iter()
            .map(|held| held.iter().find(|ns| ns.namespace.fr() == namespace))
            .collect();
        type Row<'r> = (&'r GrumpkinPoint, u64, FieldHex, Option<(FieldHex, u64)>);
        let ns_rows: Vec<Option<Row>> = each
            .iter()
            .map(|ns| {
                ns.map(|ns| {
                    let manifest = ns.manifest.as_ref().map(|m| (m.manifest_hash, m.seq));
                    (&ns.owner_pubkey, ns.seq, ns.npk_app_hash, manifest)
                })
            })
            .collect();
        let owners = distinct(ns_rows.iter().flatten().map(|(owner, _, _, _)| *owner));
        let manifests = distinct(ns_rows.iter().flatten().map(|(_, _, _, m)| m));
        if let Some(held) = groups(holders, &ns_rows, |(owner, seq, npk, manifest)| {
            let mut row = format!("seq {seq}, npk_app_hash {npk}");
            if manifests.len() > 1 {
                match manifest {
                    Some((hash, at)) => {
                        row.push_str(&format!(", contract manifest {hash} of seq {at}"));
                    }
                    None => row.push_str(", no contract manifest"),
                }
            }
            if owners.len() > 1 {
                row.push_str(&format!(", owner {}", letter(&owners, owner)));
            }
            row
        }) {
            out.push(Divergence {
                namespace: FieldHex(namespace),
                row: "the namespace row".into(),
                held,
            });
        }
        let names: BTreeSet<&str> = each
            .iter()
            .flatten()
            .flat_map(|ns| ns.packages.iter().map(|p| p.name.as_str()))
            .collect();
        for name in names {
            let pkgs: Vec<Option<&PackageRows>> = each
                .iter()
                .map(|ns| ns.and_then(|ns| ns.package(name)))
                .collect();
            let manifests = distinct(pkgs.iter().flatten().map(|p| &p.manifest));
            if let Some(held) = groups(holders, &pkgs, |p| {
                let state = if p.disabled { "disabled" } else { "enabled" };
                let mut row = format!("seq {}, {state}, vk_hash {}", p.seq, p.vk_hash);
                if manifests.len() > 1 {
                    row.push_str(&format!(", manifest {}", letter(&manifests, &p.manifest)));
                }
                row
            }) {
                out.push(Divergence {
                    namespace: FieldHex(namespace),
                    row: format!("package `{name}`"),
                    held,
                });
            }
        }
    }
    out
}

/// The distinct values of `items`, in order of first appearance.
fn distinct<'a, T: PartialEq + ?Sized>(items: impl Iterator<Item = &'a T>) -> Vec<&'a T> {
    let mut seen: Vec<&T> = Vec::new();
    for item in items {
        if !seen.contains(&item) {
            seen.push(item);
        }
    }
    seen
}

/// "A", "B", ... for `item`'s place among `seen`.
fn letter<T: PartialEq + ?Sized>(seen: &[&T], item: &T) -> char {
    let k = seen.iter().position(|s| *s == item).unwrap_or(0);
    char::from(b'A' + (k % 26) as u8)
}

/// The holders grouped by equal value, when they are not all equal.
fn groups<T: PartialEq + Copy>(
    holders: &[String],
    values: &[Option<T>],
    describe: impl Fn(T) -> String,
) -> Option<Vec<Held>> {
    if values.windows(2).all(|w| w[0] == w[1]) {
        return None;
    }
    let mut held: Vec<(Option<T>, Vec<String>)> = Vec::new();
    for (holder, value) in holders.iter().zip(values) {
        match held.iter_mut().find(|(v, _)| v == value) {
            Some((_, names)) => names.push(holder.clone()),
            None => held.push((*value, vec![holder.clone()])),
        }
    }
    Some(
        held.into_iter()
            .map(|(value, holders)| Held {
                holders,
                row: value.map_or_else(|| "no row".to_string(), &describe),
            })
            .collect(),
    )
}

/// What [`check`] found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCheck {
    /// The namespaces any node holds (of the one checked, or all).
    pub namespaces: usize,
    /// The package names any node holds under them.
    pub packages: usize,
    /// Every row the three nodes do not hold alike; empty when they agree.
    pub divergences: Vec<Divergence>,
}

impl RegistryCheck {
    /// The report on `rows` held by `holders` (as [`compare`] takes them).
    pub fn of(holders: &[String], rows: &[Vec<NamespaceRows>]) -> Self {
        let namespaces: BTreeSet<Fr> = rows
            .iter()
            .flat_map(|held| held.iter().map(|r| r.namespace.fr()))
            .collect();
        let packages: BTreeSet<(Fr, &str)> = rows
            .iter()
            .flat_map(|held| {
                held.iter().flat_map(|r| {
                    r.packages
                        .iter()
                        .map(move |p| (r.namespace.fr(), p.name.as_str()))
                })
            })
            .collect();
        RegistryCheck {
            namespaces: namespaces.len(),
            packages: packages.len(),
            divergences: compare(holders, rows),
        }
    }
}

/// The session's request id, which all three nodes use.
pub fn session_id() -> RequestId {
    RequestId(label_field(CHECK_LABEL))
}

/// The session's body hash, which all three nodes must agree on: which
/// namespace is checked (or every one).
pub fn session_body(namespace: Option<Fr>) -> Fr {
    match namespace {
        Some(ns) => poseidon2_hash(&[label_field(CHECK_LABEL), Fr::from(1u64), ns]),
        None => poseidon2_hash(&[label_field(CHECK_LABEL), Fr::from(0u64)]),
    }
}

/// The holder names of the three nodes.
pub fn node_names() -> Vec<String> {
    (0..NODES).map(|i| format!("node {i}")).collect()
}

// How the three nodes compare their registries: the operator
// runs `sidecar-node sync-registry --check` on all three nodes at once (as
// `audit` and `resync`), and each node's admin socket runs this: it reads
// its own rows of the namespace checked (or of every namespace it holds),
// each under that namespace's lock, then takes the mesh lock, opens one
// session, runs the handshake on the scope, and sends both neighbours its
// rows as one JSON frame. Each node compares the three lists itself, so all
// three print the same report. The rows are public (the nodes serve them on
// their GETs), so they travel whole, and the nsk_app share is never sent. A
// node that cannot read its rows joins the handshake with its refusal, so
// the other two refuse at once. The check writes nothing: the repair is
// resending the signed body that diverged, or, for a node several bodies
// behind, the registry resync from a neighbour (`sidecar-node sync-registry
// --lost <i> --from <j>`, crate::resync::resync_registry; DESIGN.md, "A
// registry body only some nodes committed"). The orchestrator's own copy is
// compared at its start instead, from the nodes' GETs.
/// Compare this node's registry rows with its two neighbours' over one mesh
/// session that `connect` opens: of `namespace`, or of every namespace any of
/// the three holds. Run on all three nodes at once.
pub fn check<S, N>(
    node: &Node<S>,
    namespace: Option<Fr>,
    connect: impl FnOnce(&crate::mesh_lock::MeshHeld) -> Result<N, Refusal>,
) -> Result<RegistryCheck, Refusal>
where
    S: Store,
    N: Network,
{
    let pre = (|| -> Result<Vec<NamespaceRows>, Refusal> {
        let namespaces = match namespace {
            Some(ns) => vec![ns],
            None => node.store.namespaces()?,
        };
        let mut rows = Vec::new();
        for ns in namespaces {
            let _lock = node.lock_namespace(ns);
            rows.extend(NamespaceRows::read(&node.store, ns)?);
        }
        Ok(rows)
    })();
    let hs = Handshake::build(session_id(), session_body(namespace), &[], &[]);
    let mesh = node.lock_mesh();
    let net = connect(&mesh)?;
    if net.id() != node.index {
        return Err(Refusal::mpc_failure(format!(
            "the mesh gives this node party id {}, not its index {}",
            net.id(),
            node.index
        )));
    }
    let mine = match pre {
        Err(refusal) => return Err(handshake::exchange_refusing(&net, &hs, refusal)),
        Ok(rows) => {
            handshake::exchange(&net, &hs)?;
            rows
        }
    };
    let all = exchange_rows(&net, node.index, mine)?;
    if let Some(ns) = namespace
        && let Some((i, _)) = all
            .iter()
            .enumerate()
            .find(|(_, rows)| rows.iter().any(|r| r.namespace.fr() != ns))
    {
        return Err(Refusal::mpc_failure(format!(
            "MPC session: node {i} sent rows of another namespace than {}",
            fr_to_hex(ns)
        )));
    }
    let report = RegistryCheck::of(&node_names(), &all);
    tracing::info!(
        namespaces = report.namespaces,
        packages = report.packages,
        diverged = report.divergences.len(),
        "registry check done"
    );
    Ok(report)
}

/// Node `me` sends its rows `mine` to both neighbours over the open session
/// `net` as one JSON frame and receives theirs: the three nodes' rows, by
/// node index. 500 when the mesh fails.
pub fn exchange_rows<N: Network>(
    net: &N,
    me: usize,
    mine: Vec<NamespaceRows>,
) -> Result<[Vec<NamespaceRows>; NODES], Refusal> {
    let (next, prev) = (next(me), prev(me));
    send_json(net, next, "registry rows", &mine)?;
    send_json(net, prev, "registry rows", &mine)?;
    let from_prev: Vec<NamespaceRows> = recv_json(net, prev, "registry rows")?;
    let from_next: Vec<NamespaceRows> = recv_json(net, next, "registry rows")?;
    let mut all: [Vec<NamespaceRows>; NODES] = Default::default();
    all[me] = mine;
    all[prev] = from_prev;
    all[next] = from_next;
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn point(k: u64) -> GrumpkinPoint {
        GrumpkinPoint {
            x: FieldHex::from(k),
            y: FieldHex::from(k + 1),
        }
    }

    fn pkg(name: &str, seq: u64, disabled: bool) -> PackageRows {
        PackageRows {
            name: name.into(),
            vk_hash: FieldHex::from(0x77),
            manifest: json!({"version": 1}),
            disabled,
            seq,
        }
    }

    fn rows(seq: u64, packages: Vec<PackageRows>) -> NamespaceRows {
        NamespaceRows {
            namespace: FieldHex::from(0x40),
            owner_pubkey: point(5),
            seq,
            npk_app_hash: FieldHex::from(0x9e),
            manifest: Some(ManifestRows {
                manifest_hash: FieldHex::from(0xaa),
                seq: 0,
                document: json!({"contract_manifest": 1}),
            }),
            packages,
        }
    }

    #[test]
    fn agreeing_holders_have_no_divergence() {
        let same = vec![rows(1, vec![pkg("a", 0, false), pkg("b", 1, false)])];
        let found = compare(&node_names(), &[same.clone(), same.clone(), same]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_disable_one_node_lacks_names_the_package_and_the_namespace_row() {
        let committed = vec![rows(2, vec![pkg("a", 0, false), pkg("b", 2, true)])];
        let behind = vec![rows(1, vec![pkg("a", 0, false), pkg("b", 1, false)])];
        let found = compare(&node_names(), &[committed.clone(), committed, behind]);
        let text: Vec<String> = found.iter().map(ToString::to_string).collect();
        assert_eq!(
            text,
            [
                format!(
                    "namespace {}: the namespace row: node 0 and node 1 hold seq 2, \
                     npk_app_hash {}; node 2 holds seq 1, npk_app_hash {}",
                    FieldHex::from(0x40),
                    FieldHex::from(0x9e),
                    FieldHex::from(0x9e)
                ),
                format!(
                    "namespace {}: package `b`: node 0 and node 1 hold seq 2, disabled, \
                     vk_hash {}; node 2 holds seq 1, enabled, vk_hash {}",
                    FieldHex::from(0x40),
                    FieldHex::from(0x77),
                    FieldHex::from(0x77)
                ),
            ]
        );
    }

    #[test]
    fn a_missing_namespace_package_manifest_or_owner_is_named() {
        let full = rows(1, vec![pkg("a", 0, false), pkg("b", 1, false)]);
        let mut other = full.clone();
        other.packages[0].manifest = json!({"version": 2});
        other.owner_pubkey = point(9);
        other.packages.pop();
        let holders = vec!["node 0".to_string(), "node 1".into(), "the copy".into()];
        let found = compare(&holders, &[vec![full.clone()], vec![other], vec![]]);
        let text: Vec<String> = found.iter().map(ToString::to_string).collect();
        assert_eq!(text.len(), 3, "{text:#?}");
        assert!(
            text[0].ends_with(&format!(
                "the namespace row: node 0 holds seq 1, npk_app_hash {npk}, owner A; node 1 \
                 holds seq 1, npk_app_hash {npk}, owner B; the copy holds no row",
                npk = FieldHex::from(0x9e)
            )),
            "{}",
            text[0]
        );
        assert!(
            text[1].contains("package `a`: node 0 holds seq 0, enabled, vk_hash ")
                && text[1].contains(", manifest A; node 1 holds ")
                && text[1].ends_with(", manifest B; the copy holds no row"),
            "{}",
            text[1]
        );
        assert!(
            text[2].contains("package `b`: node 0 holds seq 1")
                && text[2].ends_with("; node 1 and the copy hold no row"),
            "{}",
            text[2]
        );
    }
}
