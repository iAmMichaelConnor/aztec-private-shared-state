//! The replacement of a tip namespace's contract manifest (ARCHITECTURE.md
//! section 7, "Upgrades"): what a manifest message may change under
//! `upgrades` `circuits` or `contract`, checked against the version the
//! namespace holds.
//!
//! The contract's code reads its state at the slots and in the layouts the
//! held version states, and the nodes key every stored version of every
//! state key by them, so a replacement may change the circuits (and drop
//! packages) but nothing the stored state depends on. The nodes cannot
//! check what a new circuit means: that is the upgrade authority's
//! responsibility, and the pins the contract holds decide which version
//! runs.

use super::*;

/// The rules a replacement contract manifest `new` must pass against `held`,
/// the newest version the namespace holds (400, naming the field):
///
/// 1. `held` is upgradable (`upgrades` `circuits` or `contract`); a `fixed`
///    namespace's contract manifest never changes.
/// 2. The contract-level facts are the held ones: `upgrades`, `node_keys`,
///    the class id, the package capacity, `queue` (its slot, stale period
///    and stale-period slot), `storage`, the `state_keys` map (the same
///    names at the same slots), `plain_reads` and `init`. The contract's
///    code has not changed, so none of these can have.
/// 3. Each state key keeps its layout: the same state mode, flat length,
///    and for a tree the same depth, leaf length, header, access, keyed
///    flag and capacity, so every stored version loads unchanged under the
///    new circuits. Migration rounds do not exist: a change of layout is a
///    new deployment.
/// 4. The intake family is unchanged: queued requests and stored receipts
///    belong to it.
///
/// Packages may be dropped, and their circuits and circuit manifests
/// changed within these rules. The package bound of an upgradable list is
/// the document's own check ([`max_upgradable_packages`]).
///
/// A class upgrade (another `contract.class_id`, under `upgrades: contract`
/// only) relaxes rule 2: the new code may move what only it reads, so
/// `queue`, `storage.configured`, `storage.shared_onchain`, `plain_reads`
/// and `init` may change (the generator recomputes them from the new
/// artifact; the stale period stays finite, which every upgradable
/// manifest's own check requires), and `node_keys` may go from `fixed` to
/// `rotating` (a never-written key-epoch slot reads as epoch 0, a fixed key
/// set's state). Never: `upgrades`, `node_keys` from `rotating` to `fixed`
/// (a departed node's keys would verify again), `storage.circuit_pins` and
/// the package capacity (both classes read the same stored pins across the
/// switch, at that slot and that width), and rules 3 and 4.
pub fn check_upgrade(
    held: &CheckedContractManifest,
    new: &CheckedContractManifest,
) -> Result<(), Refusal> {
    let (h, n) = (&held.document, &new.document);
    check_upgradable(h.upgrades)?;
    let class = |m: &ContractManifest| m.contract.as_ref().map(|c| c.class_id);
    let new_class = class(h) != class(n);
    if new_class && h.upgrades != Upgrades::Contract {
        return bad(
            "contract.class_id",
            format!(
                "a circuit upgrade keeps the contract's class (upgrades `{}`); the class id \
                 differs from the held contract manifest's",
                h.upgrades.as_str()
            ),
        );
    }
    let capacity = |m: &ContractManifest| m.contract.as_ref().and_then(|c| c.package_capacity);
    let pins = |m: &ContractManifest| m.storage.as_ref().and_then(|s| s.circuit_pins);
    let fixed_to_rotating =
        h.node_keys == NodeKeysAxis::Fixed && n.node_keys == NodeKeysAxis::Rotating;
    let mut facts = vec![
        ("upgrades", h.upgrades == n.upgrades),
        (
            "node_keys",
            h.node_keys == n.node_keys || (new_class && fixed_to_rotating),
        ),
        ("contract.package_capacity", capacity(h) == capacity(n)),
        ("storage.circuit_pins", pins(h) == pins(n)),
        ("state_keys", h.state_keys == n.state_keys),
    ];
    if !new_class {
        facts.extend([
            ("queue", h.queue == n.queue),
            ("storage", h.storage == n.storage),
            ("plain_reads", h.plain_reads == n.plain_reads),
            ("init", h.init == n.init),
        ]);
    }
    for (field, same) in facts {
        if !same {
            let why = if new_class {
                "a class upgrade keeps the state keys, the circuit pins' slot and width, \
                 `upgrades`, and a rotating key set"
            } else {
                "a circuit upgrade changes the circuits, not the contract's facts"
            };
            return bad(
                field,
                format!("differs from the held contract manifest's; {why}"),
            );
        }
    }
    let (held_keys, new_keys) = (key_layouts(held)?, key_layouts(new)?);
    for (name, layout) in &new_keys {
        match held_keys.get(name) {
            Some(theirs) if theirs == layout => {}
            Some((theirs, _)) => {
                return bad(
                    format!("state_keys.{name}"),
                    format!(
                        "the new circuits give it {} (length {:?}), the held ones {theirs} \
                         (length {:?}); every stored version of a key must load unchanged, and \
                         there are no migration rounds",
                        layout.0, layout.1, held_keys[name].1
                    ),
                );
            }
            None => {
                return bad(
                    format!("state_keys.{name}"),
                    "a new state key needs an init for it; not built",
                );
            }
        }
    }
    if intake_family(held) != intake_family(new) {
        return bad(
            "packages",
            "the intake family differs from the held contract manifest's (non-secret-shared or \
             secret-shared); queued requests and stored receipts belong to it",
        );
    }
    Ok(())
}

/// Rule 1 of [`check_upgrade`] alone: a namespace whose held contract
/// manifest says `upgrades` `held` takes a replacement (400 under `fixed`).
pub fn check_upgradable(held: Upgrades) -> Result<(), Refusal> {
    if held.upgradable() {
        return Ok(());
    }
    bad(
        "upgrades",
        "the namespace's contract manifest says upgrades `fixed`: its contract's address \
         commits to it, so a different one needs a new deployment; the same one re-enables \
         its packages",
    )
}

/// The intake family of a contract manifest: whether each queued package
/// that reads a key takes a secret-shared intake (an init, which reads no
/// key, belongs to none).
fn intake_family(cm: &CheckedContractManifest) -> BTreeSet<bool> {
    cm.manifests
        .iter()
        .filter(|m| m.state_keys.reads > 0)
        .filter_map(|m| m.queued_intake().map(|i| i.shared()))
        .collect()
}
