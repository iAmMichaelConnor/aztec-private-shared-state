//! One resync session at each of the three nodes: the report and the run.

use super::*;

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

/// What a resync did, at each of the three nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResyncReport {
    /// The node resynced.
    pub lost: usize,
    pub scope: Scope,
    /// What the lost node imported (at a neighbour: what it sent).
    pub imported: Imported,
    /// The namespaces whose npk_app_hash, nsk_app pairs and `values` pairs
    /// were checked (none under a key scope).
    pub npk_checked: Vec<FieldHex>,
    /// The audit of every canonical version (under a key scope, the key's).
    pub audit: Vec<KeyAudit>,
    /// The holder blobs whose components the blob handshake compared
    /// (crate::resync::check_blobs).
    #[serde(default)]
    pub blobs_checked: usize,
}

impl ResyncReport {
    /// Whether no key failed the audit (a key not audited did not).
    pub fn passed(&self) -> bool {
        !self.audit.iter().any(KeyAudit::failed_audit)
    }
}

fn counts(body: &Body) -> Imported {
    let sum = |f: fn(&NamespaceBody) -> usize| body.namespaces.iter().map(f).sum();
    Imported {
        namespaces: body.namespaces.len(),
        packages: sum(|n| n.manifests.iter().map(|m| m.packages.len()).sum()),
        versions: sum(|n| n.versions.len()),
        tree_nodes: sum(|n| n.nodes.len()),
        values: sum(|n| n.values.len()),
        blobs: sum(|n| n.blobs.len()),
        consumed: sum(|n| n.consumed.len()),
        receipts: sum(|n| n.receipts.len()),
        dead_records: sum(|n| n.dead.len()),
        ..Imported::default()
    }
}

/// The resync of node `lost` for `scope` over the open session `net`,
/// after its opening handshake ([`session_id`], [`session_body`]): a
/// neighbour sends `sent` (its [`collect`]ed contents, sealed here), the
/// lost node rebuilds and imports; then, under a store scope, all three
/// check every namespace's npk_app_hash and `values` pairs and audit it;
/// under a key scope, they audit the key. Under a delta scope the lost node
/// first sends both neighbours what `backup` (its decrypted backup) holds,
/// they [`omit`] those components, and it takes them from the backup;
/// then everything runs as under a store scope. `audit_circuit` is the
/// audit circuit under the node's CRS. The lost node's refusal (a bundle
/// that does not open, bodies that differ or name another scope, a store
/// that is not empty under a store or delta scope, a delta without this
/// node's backup) is every node's: it sends it to both neighbours as its
/// verdict.
#[allow(clippy::too_many_arguments)]
pub fn run<S: Store, N: Network, R: RngCore + CryptoRng>(
    node: &Node<S>,
    audit_circuit: &Circuit,
    net: &N,
    lost: usize,
    scope: &Scope,
    pins: &NodesResponse,
    sent: Option<Contents>,
    backup: Option<&crate::backup::StoreExport>,
    rng: &mut R,
) -> Result<ResyncReport, Refusal> {
    if lost >= NODES {
        return Err(Refusal::bad_request(format!(
            "resync: {lost} is not a node index (0, 1 or 2)"
        )));
    }
    let me = node.index;
    let imported = if me == lost {
        let own = backup.map(Own::new);
        if scope.restores_backup() {
            let held = own.as_ref().map(Own::held).unwrap_or_default();
            for peer in [prev(me), next(me)] {
                send_json(net, peer, "resync held", &held)?;
            }
        }
        let mut bundles = Vec::new();
        for from in [prev(me), next(me)] {
            let bundle: Result<Bundle, Refusal> = recv_json(net, from, "resync bundle");
            bundles.push(bundle);
        }
        let result = (|| {
            let [p, n] = <[_; 2]>::try_from(bundles).expect("two neighbours");
            let keys = node.keys();
            let p = open(&p?, &keys, me, prev(me), &pins.nodes[prev(me)].sig)?;
            let n = open(&n?, &keys, me, next(me), &pins.nodes[next(me)].sig)?;
            if p.body.scope != *scope || n.body.scope != *scope {
                return Err(Refusal::bad_request(
                    "resync: a neighbour's bundle names another scope than the session's",
                ));
            }
            if !scope.restores_backup() && own.is_some() {
                return Err(Refusal::bad_request(
                    "resync: a backup is restored by a delta resync only",
                ));
            }
            if scope.restores_backup() {
                match &own {
                    None => {
                        return Err(Refusal::bad_request(
                            "resync: a delta resync restores this node's backup, and none was \
                             given",
                        ));
                    }
                    Some(o) if o.party() != me => {
                        return Err(Refusal::bad_request(format!(
                            "resync: the backup is node {}'s, not this node's ({me})",
                            o.party()
                        )));
                    }
                    Some(_) => {}
                }
            }
            if scope.key().is_none() && !node.store.namespaces()?.is_empty() {
                return Err(Refusal::conflict(
                    "resync: this node's store holds namespaces; a resync imports into an \
                     empty store",
                ));
            }
            let master = (!scope.installs_master()).then(|| node.master());
            let hook = node.receipt_resync();
            let rebuilt = rebuild(me, p, n, &keys, master, pins, own.as_ref(), hook.as_ref())?;
            let installed = rebuilt.master;
            // marked before the import, cleared when every check passed
            node.mark_unverified(Some(&scope.import_name()))?;
            let imported = import(&node.store, rebuilt)?;
            if scope.installs_master() {
                node.set_master(installed);
            }
            Ok(imported)
        })();
        let verdict = Verdict {
            accepted: result.is_ok(),
            refusal: result.as_ref().err().map(|r| r.message.clone()),
        };
        for peer in [prev(me), next(me)] {
            send_json(net, peer, "resync verdict", &verdict)?;
        }
        result?
    } else {
        let mut contents =
            sent.ok_or_else(|| Refusal::mpc_failure("resync: a neighbour has no bundle to send"))?;
        if scope.restores_backup() {
            let held: Held = recv_json(net, lost, "resync held")?;
            contents = omit(contents, &held)?;
        }
        let NodePublicKeys { enc, .. } = pins.nodes[lost];
        let enc = point_from_wire(&enc)
            .map_err(|e| Refusal::bad_request(format!("resync: node {lost}'s pinned enc: {e}")))?;
        let imported = counts(&contents.body);
        send_json(
            net,
            lost,
            "resync bundle",
            &seal(&contents, &node.keys(), enc, rng),
        )?;
        let verdict: Verdict = recv_json(net, lost, "resync verdict")?;
        if !verdict.accepted {
            return Err(Refusal::bad_request(format!(
                "node {lost} refused the resync: {}",
                verdict.refusal.unwrap_or_default()
            )));
        }
        imported
    };
    let mut npk_checked = Vec::new();
    let mut audit = Vec::new();
    let mut blobs_checked = 0;
    match scope.key() {
        None => {
            for ns in node.store.namespaces()? {
                check_npk_app(node, ns, net)?;
                check_values(node, ns, net)?;
                blobs_checked += check_blobs(node, ns, None, net)?;
                npk_checked.push(FieldHex(ns));
                let targets = audit::targets(&node.store, ns)?;
                audit.extend(audit::audit(audit_circuit, &node.crs, ns, targets, net)?);
            }
        }
        Some((ns, key)) => {
            blobs_checked += check_blobs(node, ns, Some(key), net)?;
            let mut targets = audit::targets(&node.store, ns)?;
            targets.retain(|(k, _, _)| k == key);
            audit.extend(audit::audit(audit_circuit, &node.crs, ns, targets, net)?);
        }
    }
    let report = ResyncReport {
        lost,
        scope: scope.clone(),
        imported,
        npk_checked,
        audit,
        blobs_checked,
    };
    if me == lost && report.passed() {
        node.mark_unverified(None)?;
    }
    Ok(report)
}
