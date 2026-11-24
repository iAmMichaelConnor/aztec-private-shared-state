//! The registry scope: its plan, session and write.

use super::*;

// ---------------------------------------------------------------------------
// The registry scope
// ---------------------------------------------------------------------------

/// The label of the registry scope's session body, `sidecar.resync.registry`.
pub const REGISTRY_LABEL: &[u8] = b"sidecar.resync.registry";

/// The registry scope's session body, which all three nodes must agree on:
/// the node resynced and the neighbour it takes its rows from.
pub fn registry_session_body(lost: usize, from: usize) -> Fr {
    poseidon2_hash(&[
        label_field(RESYNC_LABEL),
        Fr::from(lost as u64),
        label_field(REGISTRY_LABEL),
        Fr::from(from as u64),
    ])
}

/// What the registry scope writes in one namespace of the node resynced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryPlan {
    pub namespace: Fr,
    /// The node's `seq`, and the other two's, which it advances to.
    pub seq: (u64, u64),
    /// The other two's contract manifest, when the node holds another one;
    /// then every package of it is in `packages`.
    pub manifest: Option<ManifestRows>,
    /// The other two's rows of each package the node holds otherwise or not
    /// at all, by name.
    pub packages: Vec<PackageRows>,
}

/// The registry scope's plan for a node holding `own`, from the rows
/// `agreed` the other two both hold: per namespace whose rows differ, the
/// `seq` to advance to and the packages to write. 409 naming every row the
/// scope cannot bring level, each with its repair: a namespace the node
/// holds no row of (its nsk_app share comes only from the registration
/// circuit), or that the other two do not hold; another owner or
/// npk_app_hash (another identity: the store needs a resync); a `seq` ahead
/// of theirs or a package they do not hold (a body only this node committed:
/// resend it, so the other two commit it).
pub fn registry_plan(
    own: &[NamespaceRows],
    agreed: &[NamespaceRows],
) -> Result<Vec<RegistryPlan>, Refusal> {
    let find = |rows: &[NamespaceRows], ns: Fr| -> Option<NamespaceRows> {
        rows.iter().find(|r| r.namespace.fr() == ns).cloned()
    };
    let mut namespaces: Vec<Fr> = own.iter().chain(agreed).map(|r| r.namespace.fr()).collect();
    namespaces.sort();
    namespaces.dedup();
    let mut plan = Vec::new();
    let mut cannot = Vec::new();
    for ns in namespaces {
        let hex = fr_to_hex(ns);
        let (mine, theirs) = match (find(own, ns), find(agreed, ns)) {
            (Some(mine), Some(theirs)) => (mine, theirs),
            (None, Some(_)) => {
                cannot.push(format!(
                    "namespace {hex}: this node holds no row of it, and its nsk_app share comes \
                     only from the registration circuit (resend the seq 0 REGISTER while the \
                     namespace's seq is 0, or resync this node's store)"
                ));
                continue;
            }
            (Some(_), None) => {
                cannot.push(format!(
                    "namespace {hex}: the other two nodes hold no row of it (a seq 0 REGISTER \
                     only this node committed: resend it)"
                ));
                continue;
            }
            (None, None) => continue,
        };
        if (&mine.owner_pubkey, mine.npk_app_hash) != (&theirs.owner_pubkey, theirs.npk_app_hash) {
            cannot.push(format!(
                "namespace {hex}: this node holds another owner or npk_app_hash than the other \
                 two (resync this node's store)"
            ));
            continue;
        }
        if mine.seq > theirs.seq {
            cannot.push(format!(
                "namespace {hex}: this node holds seq {}, ahead of the other two's {} (a body \
                 only this node committed: resend it, so the other two commit it)",
                mine.seq, theirs.seq
            ));
            continue;
        }
        let manifest = (mine.manifest != theirs.manifest)
            .then(|| theirs.manifest.clone())
            .flatten();
        let extra: Vec<&str> = mine
            .packages
            .iter()
            .filter(|p| !theirs.packages.iter().any(|q| q.name == p.name))
            .map(|p| p.name.as_str())
            .collect();
        if manifest.is_none() && !extra.is_empty() {
            cannot.push(format!(
                "namespace {hex}: this node holds package(s) `{}` the other two do not (a \
                 REGISTER only this node committed: resend it, so the other two commit it)",
                extra.join("`, `")
            ));
            continue;
        }
        // a contract manifest replaces the node's packages whole
        let packages: Vec<PackageRows> = theirs
            .packages
            .iter()
            .filter(|p| manifest.is_some() || !mine.packages.contains(p))
            .cloned()
            .collect();
        if mine.seq < theirs.seq || !packages.is_empty() || manifest.is_some() {
            plan.push(RegistryPlan {
                namespace: ns,
                seq: (mine.seq, theirs.seq),
                manifest,
                packages,
            });
        }
    }
    if !cannot.is_empty() {
        return Err(Refusal::conflict(format!(
            "registry resync: {} row(s) a registry resync cannot bring level: {}",
            cannot.len(),
            cannot.join("; ")
        )));
    }
    Ok(plan)
}

/// One package's circuit, as the neighbour a registry resync takes the rows
/// from sends it: the circuit JSON as that neighbour stores it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCircuit {
    pub namespace: FieldHex,
    pub name: String,
    pub circuit: HexBytes,
}

/// What a registry resync did, at each of the three nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryResync {
    /// The node resynced.
    pub lost: usize,
    /// The neighbour it took its rows from.
    pub from: usize,
    /// Every row the three nodes held otherwise before the resync (none:
    /// the node held the other two's rows already, and nothing was written).
    pub repaired: Vec<Divergence>,
    /// The namespaces whose rows the node rewrote.
    pub namespaces: usize,
    /// The `packages` rows it wrote.
    pub packages: usize,
    /// The vks it built from the circuits sent (a package whose circuit it
    /// held already keeps its own vk); 0 at a neighbour.
    pub vks_built: usize,
}

/// What a node reads before a registry resync's session.
struct RegistryRead<'a> {
    rows: Vec<NamespaceRows>,
    /// At the neighbour the rows come from: each package's circuit JSON,
    /// read with its rows.
    circuits: BTreeMap<(Fr, String), Vec<u8>>,
    /// At the node resynced: the lock of every namespace it holds, held to
    /// its write.
    _locks: Vec<crate::pipeline::NamespaceGuard<'a>>,
}

// How a registry resync brings one node's registry level. The operator runs
// `sidecar-node sync-registry --lost <i> --from <j>` on all three nodes at
// once. Each node reads its registry rows (registry_check::NamespaceRows)
// under each namespace's lock: neighbour j also reads every package's circuit
// with them; node i takes the lock of every namespace it holds, in order,
// and holds them to the end of its write, so no registry body or round of
// those namespaces runs at it meanwhile. Then the mesh lock, one session,
// the handshake on (i, j), and the three nodes send each other their rows,
// as the registry check does. Every node compares j's rows with the third
// node's: a row they differ on refuses at all three (409), since node i would
// take rows only one node vouches for; then every node derives the same plan
// from node i's rows and the agreed ones (`registry_plan`), refusing alike
// what the scope cannot bring level. Node j sends node i the circuit of
// every package in the plan; node i builds each vk itself under its own CRS
// (or keeps its own, for a circuit it holds byte for byte), requires it to
// hash to the agreed vk_hash, writes each namespace's packages with the
// agreed manifest, disabled flag and `seq`, advances the namespace's `seq`
// one commit per step (the store's rule) to the agreed one, and sends both
// neighbours its verdict. Its `namespaces` rows keep their nsk_app shares:
// the share is each node's own, and no neighbour holds it. The rows are
// public, so they travel in the clear on the pinned-TLS mesh; nothing here
// rebuilds a pair or runs a circuit, and the write is idempotent, so a
// failed resync is rerun as it stands.
/// The registry resync of node `lost` from its neighbour `from` over one
/// mesh session that `connect` opens (run on all three nodes at once). 400
/// for indices that are not two distinct nodes; 409 when `from` and the
/// third node hold different rows, naming each, or for a row the scope
/// cannot bring level ([`registry_plan`]); 400 at node `lost` (and, through
/// its verdict, at both neighbours) for a circuit that is missing, not the
/// plan's, or does not build to the agreed vk_hash; 500 when the mesh or the
/// store fails.
pub fn resync_registry<S, N>(
    node: &Node<S>,
    lost: usize,
    from: usize,
    connect: impl FnOnce(&crate::mesh_lock::MeshHeld) -> Result<N, Refusal>,
) -> Result<RegistryResync, Refusal>
where
    S: Store,
    N: Network,
{
    let me = node.index;
    let pre = (|| -> Result<RegistryRead<'_>, Refusal> {
        if lost >= NODES || from >= NODES || lost == from {
            return Err(Refusal::bad_request(format!(
                "registry resync: `lost` {lost} and `from` {from} are not two distinct node \
                 indices (0, 1 or 2)"
            )));
        }
        let mut namespaces = node.store.namespaces()?;
        namespaces.sort();
        let mut read = RegistryRead {
            rows: Vec::new(),
            circuits: BTreeMap::new(),
            _locks: Vec::new(),
        };
        for ns in namespaces {
            let lock = node.lock_namespace(ns);
            read.rows.extend(NamespaceRows::read(&node.store, ns)?);
            if me == from {
                for name in node.store.package_names(ns)? {
                    if let Some(pkg) = node.store.package(ns, &name)? {
                        read.circuits.insert((ns, name), pkg.circuit_json);
                    }
                }
            }
            if me == lost {
                read._locks.push(lock);
            }
        }
        Ok(read)
    })();
    let hs = Handshake::build(session_id(), registry_session_body(lost, from), &[], &[]);
    let mesh = node.lock_mesh();
    let net = connect(&mesh)?;
    if net.id() != me {
        return Err(Refusal::mpc_failure(format!(
            "the mesh gives this node party id {}, not its index {me}",
            net.id()
        )));
    }
    let RegistryRead {
        rows,
        circuits,
        _locks,
    } = match pre {
        Err(refusal) => return Err(handshake::exchange_refusing(&net, &hs, refusal)),
        Ok(read) => {
            handshake::exchange(&net, &hs)?;
            read
        }
    };
    let all = registry_check::exchange_rows(&net, me, rows)?;
    let third = (0..NODES)
        .find(|i| *i != lost && *i != from)
        .expect("three nodes");
    let names = registry_check::node_names();
    let pair = registry_check::compare(
        &[names[from].clone(), names[third].clone()],
        &[all[from].clone(), all[third].clone()],
    );
    if !pair.is_empty() {
        let rows: Vec<String> = pair.iter().map(ToString::to_string).collect();
        return Err(Refusal::conflict(format!(
            "registry resync of node {lost} from node {from}: node {from} and node {third} hold \
             different registry rows, so node {lost} is repaired from neither ({}); bring them \
             level first (DESIGN.md, \"A registry body only some nodes committed\")",
            rows.join("; ")
        )));
    }
    let plan = registry_plan(&all[lost], &all[from]).map_err(|r| {
        Refusal::conflict(format!(
            "node {lost}: {}",
            r.message.trim_start_matches("registry resync: ")
        ))
    })?;
    let repaired = registry_check::compare(&names, &all);
    let mut report = RegistryResync {
        lost,
        from,
        repaired,
        namespaces: plan.len(),
        packages: plan.iter().map(|p| p.packages.len()).sum(),
        vks_built: 0,
    };
    if me == from {
        let mut sent = Vec::new();
        for p in &plan {
            for pkg in &p.packages {
                let circuit = circuits
                    .get(&(p.namespace, pkg.name.clone()))
                    .ok_or_else(|| {
                        Refusal::mpc_failure(format!(
                            "registry resync: package `{}` of namespace {} was not read with \
                             its rows",
                            pkg.name,
                            fr_to_hex(p.namespace)
                        ))
                    })?;
                sent.push(RegistryCircuit {
                    namespace: FieldHex(p.namespace),
                    name: pkg.name.clone(),
                    circuit: HexBytes(circuit.clone()),
                });
            }
        }
        send_json(&net, lost, "registry circuits", &sent)?;
    }
    if me == lost {
        let result = recv_json::<Vec<RegistryCircuit>, _>(&net, from, "registry circuits")
            .and_then(|sent| write_registry(node, from, third, &plan, sent));
        let verdict = Verdict {
            accepted: result.is_ok(),
            refusal: result.as_ref().err().map(|r| r.message.clone()),
        };
        for peer in [from, third] {
            send_json(&net, peer, "registry resync verdict", &verdict)?;
        }
        report.vks_built = result?;
    } else {
        let verdict: Verdict = recv_json(&net, lost, "registry resync verdict")?;
        if !verdict.accepted {
            return Err(Refusal::bad_request(format!(
                "node {lost} refused the registry resync: {}",
                verdict.refusal.unwrap_or_default()
            )));
        }
    }
    tracing::info!(
        lost,
        from,
        repaired = report.repaired.len(),
        namespaces = report.namespaces,
        packages = report.packages,
        vks_built = report.vks_built,
        "registry resync done"
    );
    Ok(report)
}

/// Node `lost` writes `plan` with the circuits `sent` by node `from`: a
/// contract manifest's hash recomputed from its document, which must name
/// exactly the plan's packages under their vk hashes; each package's vk
/// built here (or kept, for a circuit it holds byte for byte) and required to
/// hash to the agreed vk_hash; every row built before any is written.
/// Returns how many vks it built.
fn write_registry<S: Store>(
    node: &Node<S>,
    from: usize,
    third: usize,
    plan: &[RegistryPlan],
    sent: Vec<RegistryCircuit>,
) -> Result<usize, Refusal> {
    let refuse = |why: String| Refusal::bad_request(format!("registry resync: {why}"));
    let mut circuits: BTreeMap<(Fr, String), Vec<u8>> = BTreeMap::new();
    for c in sent {
        let at = (c.namespace.fr(), c.name);
        if circuits.insert(at.clone(), c.circuit.0).is_some() {
            return Err(refuse(format!(
                "node {from} sent package `{}` of namespace {} twice",
                at.1,
                fr_to_hex(at.0)
            )));
        }
    }
    let mut built = 0;
    let mut staged = Vec::new();
    for p in plan {
        let held = match &p.manifest {
            Some(m) => {
                check_manifest_rows(m, &p.packages).map_err(|why| {
                    refuse(format!(
                        "the contract manifest nodes {from} and {third} hold for namespace {} \
                         {why}",
                        fr_to_hex(p.namespace)
                    ))
                })?;
                m.manifest_hash.fr()
            }
            None => node
                .store
                .contract_manifest(p.namespace)?
                .map(|m| m.manifest_hash)
                .ok_or_else(|| {
                    refuse(format!(
                        "namespace {} holds no contract manifest here",
                        fr_to_hex(p.namespace)
                    ))
                })?,
        };
        let mut rows = Vec::new();
        for pkg in &p.packages {
            let what = format!(
                "package `{}` of namespace {}",
                pkg.name,
                fr_to_hex(p.namespace)
            );
            let circuit_json = circuits
                .remove(&(p.namespace, pkg.name.clone()))
                .ok_or_else(|| refuse(format!("node {from} sent no circuit of {what}")))?;
            let vk_hash = pkg.vk_hash.fr();
            let vk = match node.store.package(p.namespace, &pkg.name)? {
                Some(own) if own.circuit_json == circuit_json && own.vk_hash == vk_hash => own.vk,
                _ => {
                    built += 1;
                    build_vk(node, &pkg.name, &circuit_json, vk_hash).map_err(|why| {
                        refuse(format!(
                            "node {from}'s circuit of {what} {why}, which nodes {from} and \
                             {third} hold"
                        ))
                    })?
                }
            };
            rows.push(PackageRow {
                name: pkg.name.clone(),
                manifest_hash: held,
                circuit_json,
                manifest: pkg.manifest.clone(),
                vk,
                vk_hash,
                disabled: pkg.disabled,
                seq: pkg.seq,
            });
        }
        staged.push((p, rows));
    }
    if let Some(((ns, name), _)) = circuits.into_iter().next() {
        return Err(refuse(format!(
            "node {from} sent package `{name}` of namespace {}, which the plan does not name",
            fr_to_hex(ns)
        )));
    }
    for (p, rows) in staged {
        let (held, agreed) = p.seq;
        let mut txn = node.store.begin(p.namespace);
        if let Some(m) = &p.manifest {
            txn.put_manifest(ManifestRow::from(m));
        }
        for row in rows {
            txn.put_package(row);
        }
        if agreed > held {
            txn.advance_seq(held + 1);
        }
        node.store.commit(txn)?;
        for seq in held + 2..=agreed {
            let mut txn = node.store.begin(p.namespace);
            txn.advance_seq(seq);
            node.store.commit(txn)?;
        }
    }
    Ok(built)
}

/// Why the manifest rows `m` do not hold together with the `packages` the
/// other two hold under it: its hash recomputed from its document, the
/// document's checks, and its packages (names and vk hashes) against the
/// rows.
fn check_manifest_rows(m: &ManifestRows, packages: &[PackageRows]) -> Result<(), String> {
    let hash = manifest_hash(&m.document).map_err(|r| r.message)?;
    if hash != m.manifest_hash.fr() {
        return Err(format!(
            "hashes to {}, not the {} stored with it",
            fr_to_hex(hash),
            m.manifest_hash
        ));
    }
    let checked = ContractManifest::parse(&m.document)
        .and_then(ContractManifest::check)
        .map_err(|r| format!("does not pass REGISTER's checks ({})", r.message))?;
    let named: BTreeMap<&str, Fr> = checked
        .packages()
        .map(|(p, _)| (p.name.as_str(), checked.vk_hash(p)))
        .collect();
    let rows: BTreeMap<&str, Fr> = packages
        .iter()
        .map(|p| (p.name.as_str(), p.vk_hash.fr()))
        .collect();
    if named != rows {
        return Err("names other packages or vk hashes than the package rows".into());
    }
    Ok(())
}

/// The vk of circuit `name` (its JSON as a node stores it) under this
/// node's CRS, as REGISTER builds it, in a `packages` row's byte format;
/// `Err` saying why when it does not build or hash to `vk_hash`.
fn build_vk<S: Store>(
    node: &Node<S>,
    name: &str,
    circuit_json: &[u8],
    vk_hash: Fr,
) -> Result<Vec<u8>, String> {
    let artifact = Artifact::from_json(name, circuit_json)
        .map_err(|e| format!("is not a compiled Noir circuit ({e:#})"))?;
    let needed = crs::crs_points(artifact.circuit_size);
    let held = node.crs.prover.monomials.len();
    if needed > held {
        return Err(format!(
            "needs {needed} CRS points, and this node holds {held}"
        ));
    }
    let circuit = Circuit::new(artifact, &node.crs.prover)
        .map_err(|e| format!("builds no verification key ({e:#})"))?;
    if circuit.vk_hash != vk_hash {
        return Err(format!(
            "builds to vk_hash {}, not the {}",
            fr_to_hex(circuit.vk_hash),
            fr_to_hex(vk_hash)
        ));
    }
    Ok(circuit.vk.to_buffer())
}
