//! Rebuilding the orchestrator's registry copy from the three nodes
//! (`sidecar-orchestrator sync-registry`, or `--sync-registry` at start): read
//! every namespace and package the nodes hold over the node leg, require the
//! three to agree on every row, recompute each package's vk from its circuit,
//! and write a fresh copy that replaces the old one. And the start-up check
//! ([`check_agreement`]): the same reads, compared row by row between the
//! three nodes and the copy, writing nothing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use eyre::{Context, bail, ensure, eyre};
use serde::de::DeserializeOwned;
use sidecar_core::bind::Share;
use sidecar_core::crs::Crs;
use sidecar_core::field::{Fr, fr_to_hex};
use sidecar_core::grumpkin::point_from_wire;
use sidecar_core::local::LocalStore;
use sidecar_core::manifest::contract::{ContractManifest, manifest_hash};
use sidecar_core::register::{
    ContractManifestResponse, NamespaceResponse, NamespacesResponse, PackageNamesResponse,
    PackageResponse,
};
use sidecar_core::registry_check::{self, NamespaceRows, PackageRows, RegistryCheck};
use sidecar_core::request::NODES;
use sidecar_core::schnorr::check_name;
use sidecar_core::store::{ManifestRow, NamespaceRow, PackageRow, Store, StoreRead};

use crate::nodes::{MAX_REGISTRY_ANSWER_BYTES, Nodes, Reply, all_answers, each_answer};
use crate::registry;

/// What a sync wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Synced {
    pub namespaces: usize,
    pub packages: usize,
}

/// One namespace as the three nodes agree on it.
struct Agreed {
    info: NamespaceResponse,
    manifest: ManifestRow,
    packages: Vec<PackageRow>,
}

// How the registry copy is rebuilt. The nodes are the record
// (invariant 12: the copy holds nothing they do not), so a sync reads every
// row from them: `GET /v1/namespaces`, then per namespace `GET
// /v1/namespaces/{ns}`, `GET /v1/namespaces/{ns}/manifest` and `GET
// /v1/packages/{ns}`, then each package by name. The three nodes must give
// identical answers for every read (owner, seq, npk_app_hash; the contract
// manifest; each package's circuit, manifest, vk, vk_hash, disabled flag and
// seq), or the sync stops naming the read and the node that differs and
// writes nothing: the GETs carry no node signatures, so agreement of the three
// over mutual TLS is what the copy rests on, as for every other answer the
// orchestrator relays. Each package's vk is then recomputed from its circuit
// under the orchestrator's CRS and must hash to the agreed vk_hash (the copy
// keeps the orchestrator's own vk, as REGISTER does), and its manifest must
// check against its ABI; the contract manifest must hash to its manifest hash,
// pass REGISTER's checks and name exactly the packages under their vk hashes.
// The rows are written into a fresh local store beside the copy
// (`<path>.sync`) in the nodes' transaction shapes (the namespace row at seq
// 0 with its contract manifest and packages, then one transaction per later
// seq), and that
// directory replaces the copy only when it is whole, so a failed sync leaves
// the old copy as it was. The old copy is opened first, which refuses while a
// running orchestrator holds it: stop the orchestrator, or sync at its start.
// A sync costs one vk build per package (seconds each) and one synced log
// record per seq step, which only matters for a namespace with thousands of
// registry bodies.
/// Rebuild the registry copy in `dir` from the three nodes, under `crs`.
pub async fn sync_registry(nodes: &Nodes, crs: &Crs, dir: &Path) -> eyre::Result<Synced> {
    settle_interrupted_swap(dir)?;
    // Hold the current copy (and refuse while another process holds it)
    // until the new one is in place.
    let current = LocalStore::open(dir).wrap_err("opening the registry copy to replace it")?;
    // Registry rows carry circuits: the larger answer class.
    let nodes = &nodes.lookups().with_max_answer(MAX_REGISTRY_ANSWER_BYTES);
    let mut agreed = Vec::new();
    let list: NamespacesResponse = agree("/v1/namespaces", nodes.get("/v1/namespaces").await)?;
    for namespace in list.namespaces {
        let ns = fr_to_hex(namespace.fr());
        let path = format!("/v1/namespaces/{ns}");
        let info: NamespaceResponse = agree(&path, nodes.get(&path).await)?;
        ensure!(
            info.namespace == namespace,
            "GET {path}: the nodes answer namespace {}",
            info.namespace
        );
        let path = format!("/v1/namespaces/{ns}/manifest");
        let manifest: ContractManifestResponse = agree(&path, nodes.get(&path).await)?;
        let path = format!("/v1/packages/{ns}");
        let names: PackageNamesResponse = agree(&path, nodes.get(&path).await)?;
        let mut packages = Vec::new();
        for name in names.packages {
            let path = format!("/v1/packages/{ns}/{name}");
            let pkg: PackageResponse = agree(&path, nodes.get(&path).await)?;
            ensure!(
                pkg.namespace == namespace && pkg.name == name,
                "GET {path}: the nodes answer package `{}` of namespace {}",
                pkg.name,
                pkg.namespace
            );
            packages.push(pkg);
        }
        let manifest = check_manifest(&ns, manifest, &packages)?;
        let crs = crs.clone();
        let packages = tokio::task::spawn_blocking(move || rebuild(&crs, packages))
            .await
            .wrap_err("the vk builds failed")??;
        agreed.push(Agreed {
            info,
            manifest,
            packages,
        });
    }
    let synced = Synced {
        namespaces: agreed.len(),
        packages: agreed.iter().map(|a| a.packages.len()).sum(),
    };
    let fresh = sibling(dir, "sync");
    let dir_owned = dir.to_path_buf();
    tokio::task::spawn_blocking(move || write_copy(&fresh, &agreed, &dir_owned))
        .await
        .wrap_err("writing the registry copy failed")??;
    drop(current);
    tracing::info!(
        registry = %dir.display(),
        namespaces = synced.namespaces,
        packages = synced.packages,
        "registry copy rebuilt from the three nodes"
    );
    Ok(synced)
}

/// The holder name of the orchestrator's copy in [`check_agreement`]'s
/// report, beside "node 0" to "node 2".
pub const COPY: &str = "the copy";

// Operator knob: DESIGN.md, "Configuration reference" (registry check
// bounds; no knob). The check reads what the nodes list, so one node chooses
// how many namespaces and package names it reads and how large each answer
// is. Each package answer is reduced at once to the row it is compared by
// (its circuit dropped), and the rows kept of one node's answers are bounded:
// an honest registry's rows are a few KiB per namespace, so 256 MiB is far
// above any, and a node past it stops the run (unread, naming the node). The
// whole run is bounded by five minutes, under the timer's ten, so a node
// that answers each read slowly cannot stall the start or pile up runs.
/// The longest one run of the registry check may take.
pub const REGISTRY_CHECK_DEADLINE: Duration = Duration::from_secs(300);
/// The most bytes of compared rows one run keeps of one node's answers.
pub const MAX_CHECK_ROW_BYTES: usize = 256 * 1024 * 1024;

/// Compare the registry rows of the three nodes, read over their
/// mutual-TLS legs as [`sync_registry`] reads them, with each other and with
/// the copy `copy`: every namespace any of them holds, and every package
/// name under it (no vk is built). Writes nothing. Fails when a node does not
/// answer a read of a row it lists, lists a name that is no package name,
/// sends rows past [`MAX_CHECK_ROW_BYTES`], or the run passes
/// [`REGISTRY_CHECK_DEADLINE`].
pub async fn check_agreement(nodes: &Nodes, copy: &LocalStore) -> eyre::Result<RegistryCheck> {
    tokio::time::timeout(REGISTRY_CHECK_DEADLINE, compare_rows(nodes, copy))
        .await
        .map_err(|_| {
            eyre!("the registry check did not finish within {REGISTRY_CHECK_DEADLINE:?}")
        })?
}

/// The bytes a kept row costs, as JSON.
fn kept_bytes<T: serde::Serialize>(row: &T) -> usize {
    serde_json::to_vec(row).map_or(0, |b| b.len())
}

async fn compare_rows(nodes: &Nodes, copy: &LocalStore) -> eyre::Result<RegistryCheck> {
    let nodes = &nodes.lookups().with_max_answer(MAX_REGISTRY_ANSWER_BYTES);
    let path = "/v1/namespaces";
    let lists: [NamespacesResponse; NODES] =
        all_answers(nodes.get(path).await).map_err(|r| eyre!("GET {path}: {r}"))?;
    let listed = |i: usize, ns: Fr| lists[i].namespaces.iter().any(|n| n.fr() == ns);
    let union: BTreeSet<Fr> = lists
        .iter()
        .flat_map(|l| l.namespaces.iter().map(|n| n.fr()))
        .collect();
    let mut kept = [0usize; NODES];
    let mut keep = |i: usize, bytes: usize| -> eyre::Result<()> {
        kept[i] += bytes;
        ensure!(
            kept[i] <= MAX_CHECK_ROW_BYTES,
            "node {i}'s registry rows pass {MAX_CHECK_ROW_BYTES} bytes; the check stops"
        );
        Ok(())
    };
    let mut rows: Vec<Vec<NamespaceRows>> = vec![Vec::new(); NODES + 1];
    for namespace in union {
        let ns = fr_to_hex(namespace);
        let path = format!("/v1/namespaces/{ns}");
        let infos = each_answer::<NamespaceResponse>(nodes.get(&path).await);
        let manifest_path = format!("/v1/namespaces/{ns}/manifest");
        let manifests = each_answer::<ContractManifestResponse>(nodes.get(&manifest_path).await);
        let names_path = format!("/v1/packages/{ns}");
        let names = each_answer::<PackageNamesResponse>(nodes.get(&names_path).await);
        let mut held = Vec::new();
        for (i, ((info, manifest), names)) in
            infos.into_iter().zip(manifests).zip(names).enumerate()
        {
            if !listed(i, namespace) {
                continue;
            }
            let info = info.map_err(|r| eyre!("GET {path}: {r}"))?;
            let manifest = manifest.map_err(|r| eyre!("GET {manifest_path}: {r}"))?;
            let names = names.map_err(|r| eyre!("GET {names_path}: {r}"))?;
            for name in &names.packages {
                check_name("packages", "package name", name)
                    .map_err(|r| eyre!("GET {names_path}: node {i}: {r}"))?;
            }
            keep(i, kept_bytes(&info) + kept_bytes(&manifest))?;
            held.push((i, info, manifest, names.packages, Vec::new()));
        }
        let every_name: BTreeSet<String> = held
            .iter()
            .flat_map(|(_, _, _, names, _)| names.iter().cloned())
            .collect();
        for name in every_name {
            let path = format!("/v1/packages/{ns}/{name}");
            let mut answers = each_answer::<PackageResponse>(nodes.get(&path).await).map(Some);
            for (i, _, _, names, packages) in &mut held {
                if names.contains(&name) {
                    let pkg = answers[*i].take().expect("one answer per node");
                    // the compared row only: the circuit is dropped here
                    let row = PackageRows::from(&pkg.map_err(|r| eyre!("GET {path}: {r}"))?);
                    keep(*i, kept_bytes(&row))?;
                    packages.push(row);
                }
            }
        }
        for (i, info, manifest, _, packages) in held {
            rows[i].push(NamespaceRows::from_answers(&info, &manifest, packages));
        }
    }
    let refused = |r: sidecar_core::Refusal| eyre!("reading the registry copy: {r}");
    for namespace in copy.namespaces().map_err(refused)? {
        rows[NODES].extend(NamespaceRows::read(copy, namespace).map_err(refused)?);
    }
    let mut holders = registry_check::node_names();
    holders.push(COPY.to_string());
    Ok(RegistryCheck::of(&holders, &rows))
}

/// The three replies to one read, which must parse and be equal.
fn agree<T: DeserializeOwned + PartialEq>(what: &str, replies: [Reply; NODES]) -> eyre::Result<T> {
    let [first, second, third] = all_answers::<T>(replies).map_err(|r| eyre!("GET {what}: {r}"))?;
    for (i, other) in [(1, &second), (2, &third)] {
        if *other != first {
            bail!("the nodes disagree on GET {what}: node {i}'s answer differs from node 0's");
        }
    }
    Ok(first)
}

/// The agreed contract manifest of namespace `ns` as the copy's row: its
/// document must hash to the manifest hash the nodes answer, pass REGISTER's
/// checks and name exactly the agreed packages under their vk hashes.
fn check_manifest(
    ns: &str,
    manifest: ContractManifestResponse,
    packages: &[PackageResponse],
) -> eyre::Result<ManifestRow> {
    let what = format!("the contract manifest of namespace {ns}");
    let hash = manifest_hash(&manifest.manifest).map_err(|r| eyre!("{what}: {r}"))?;
    ensure!(
        hash == manifest.manifest_hash.fr(),
        "{what} hashes to {}, the nodes answer {}",
        fr_to_hex(hash),
        manifest.manifest_hash
    );
    let checked = ContractManifest::parse(&manifest.manifest)
        .and_then(ContractManifest::check)
        .map_err(|r| eyre!("{what}: {r}"))?;
    let mut named: Vec<(String, Fr)> = checked
        .packages()
        .map(|(p, _)| (p.name.clone(), checked.vk_hash(p)))
        .collect();
    named.sort();
    let mut held: Vec<(String, Fr)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.vk_hash.fr()))
        .collect();
    held.sort();
    ensure!(
        named == held && packages.iter().all(|p| p.manifest_hash.fr() == hash),
        "{what} names other packages or vk hashes than the packages the nodes hold"
    );
    Ok(ManifestRow {
        manifest_hash: hash,
        document: manifest.manifest,
        seq: manifest.seq,
    })
}

/// The agreed packages as rows of the copy, each vk recomputed from its
/// circuit and checked against the agreed vk_hash, each manifest checked
/// against its ABI.
fn rebuild(crs: &Crs, packages: Vec<PackageResponse>) -> eyre::Result<Vec<PackageRow>> {
    let mut rows = Vec::with_capacity(packages.len());
    for pkg in packages {
        let what = format!(
            "package `{}` of namespace {}",
            pkg.name,
            fr_to_hex(pkg.namespace.fr())
        );
        let computed = registry::compute(crs, &pkg.name, &pkg.circuit)
            .map_err(|r| eyre!("{what}: {}", r.message))?;
        ensure!(
            computed.vk_hash == pkg.vk_hash.fr(),
            "{what}: the circuit builds to vk_hash {}, the nodes hold {}",
            fr_to_hex(computed.vk_hash),
            pkg.vk_hash
        );
        let row = PackageRow {
            name: pkg.name,
            manifest_hash: pkg.manifest_hash.fr(),
            circuit_json: computed.circuit_json,
            manifest: pkg.manifest,
            vk: computed.vk.to_buffer(),
            vk_hash: computed.vk_hash,
            disabled: pkg.disabled,
            seq: pkg.seq,
        };
        row.parse().map_err(|r| eyre!("{what}: {}", r.message))?;
        rows.push(row);
    }
    Ok(rows)
}

/// Write `agreed` into a fresh store at `fresh`, then put it in place of the
/// copy at `dir`.
fn write_copy(fresh: &Path, agreed: &[Agreed], dir: &Path) -> eyre::Result<()> {
    if fresh.exists() {
        std::fs::remove_dir_all(fresh)
            .wrap_err_with(|| format!("removing a stale {}", fresh.display()))?;
    }
    {
        let store = LocalStore::open(fresh)?;
        for Agreed {
            info,
            manifest,
            packages,
        } in agreed
        {
            let namespace = info.namespace.fr();
            let owner = point_from_wire(&info.owner_pubkey)
                .map_err(|e| eyre!("namespace {}: owner_pubkey: {e}", info.namespace))?;
            let refused = |r: sidecar_core::Refusal| {
                eyre!("namespace {}: the copy refused a row: {r}", info.namespace)
            };
            let mut txn = store.begin(namespace);
            txn.register_namespace(NamespaceRow {
                owner_pubkey: owner,
                nsk_app: Share::default(),
                npk_app_hash: info.npk_app_hash.fr(),
                seq: 0,
            });
            txn.put_manifest(manifest.clone());
            for row in packages {
                txn.put_package(row.clone());
            }
            store.commit(txn).map_err(refused)?;
            for seq in 1..=info.seq {
                let mut txn = store.begin(namespace);
                txn.advance_seq(seq);
                store.commit(txn).map_err(refused)?;
            }
            let written = store.namespace(namespace).map_err(refused)?;
            ensure!(
                written.is_some_and(|row| row.seq == info.seq),
                "namespace {}: the copy does not read back seq {}",
                info.namespace,
                info.seq
            );
        }
    }
    let old = sibling(dir, "old");
    if old.exists() {
        std::fs::remove_dir_all(&old)
            .wrap_err_with(|| format!("removing a stale {}", old.display()))?;
    }
    std::fs::rename(dir, &old).wrap_err_with(|| format!("moving {} aside", dir.display()))?;
    std::fs::rename(fresh, dir).wrap_err_with(|| {
        format!(
            "moving the rebuilt copy {} into place (the old copy is {})",
            fresh.display(),
            old.display()
        )
    })?;
    std::fs::remove_dir_all(&old).wrap_err_with(|| format!("removing {}", old.display()))?;
    Ok(())
}

// The swap at the end of a sync is two renames (`dir` to `<dir>.old`, then
// `<dir>.sync` to `dir`) and the removal of `<dir>.old`. A crash between the
// renames leaves no `dir`, and opening the copy would create an empty one: an
// orchestrator on it refuses every execute and admits seq 0 REGISTERs for
// namespaces the nodes hold. So whoever opens the copy settles the swap
// first: with `dir` absent the old copy goes back in place (the sync is
// rerun to rebuild it); with `dir` present the rebuilt copy is already in
// place and only the old one's removal was cut short.
/// Settle a sync's swap a crash interrupted, before the copy at `dir` is
/// opened.
pub fn settle_interrupted_swap(dir: &Path) -> eyre::Result<()> {
    let old = sibling(dir, "old");
    if !old.exists() {
        return Ok(());
    }
    // A sync still running holds the old copy's lock until its swap ends.
    let lock = old.join("store.lock");
    let _held = match std::fs::File::open(&lock) {
        Ok(file) => {
            ensure!(
                file.try_lock().is_ok(),
                "a sync-registry is replacing the copy {} now; wait for it to end",
                dir.display()
            );
            Some(file)
        }
        Err(_) => None,
    };
    if dir.exists() {
        std::fs::remove_dir_all(&old)
            .wrap_err_with(|| format!("removing {} after a sync", old.display()))?;
        tracing::warn!(
            registry = %dir.display(),
            "an interrupted sync-registry had put the rebuilt copy in place; removed the old one"
        );
    } else {
        std::fs::rename(&old, dir)
            .wrap_err_with(|| format!("moving {} back to {}", old.display(), dir.display()))?;
        tracing::warn!(
            registry = %dir.display(),
            "an interrupted sync-registry had moved the copy aside; put it back \
             (rerun sync-registry to rebuild it)"
        );
    }
    Ok(())
}

/// `<dir>.<suffix>`, beside `dir`.
fn sibling(dir: &Path, suffix: &str) -> PathBuf {
    let mut name = dir.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{suffix}"));
    dir.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidecar_test_fixtures::dirs::TempDir;

    fn mark(dir: &Path, name: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), b"").unwrap();
    }

    #[test]
    fn a_swap_cut_between_the_renames_puts_the_old_copy_back() {
        let tmp = TempDir::new("swap-back");
        let dir = tmp.path().join("registry");
        mark(&sibling(&dir, "old"), "old-copy");
        mark(&sibling(&dir, "sync"), "rebuilt");
        settle_interrupted_swap(&dir).unwrap();
        assert!(dir.join("old-copy").exists());
        assert!(!sibling(&dir, "old").exists());
    }

    #[test]
    fn a_swap_cut_after_the_renames_removes_the_old_copy() {
        let tmp = TempDir::new("swap-done");
        let dir = tmp.path().join("registry");
        mark(&sibling(&dir, "old"), "old-copy");
        mark(&dir, "rebuilt");
        settle_interrupted_swap(&dir).unwrap();
        assert!(dir.join("rebuilt").exists());
        assert!(!sibling(&dir, "old").exists());
        // Nothing to settle: nothing changes.
        settle_interrupted_swap(&dir).unwrap();
        assert!(dir.join("rebuilt").exists());
    }
}
