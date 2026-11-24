//! The contract manifest: parsing, the hashes and the checks across its
//! packages, on the example apps' own circuit manifests.

use serde_json::{Value, json};

use super::*;
use crate::error::ErrorClass;
use crate::testing::artifacts::repo;
use crate::testing::manifest as example;

fn slot(n: u64) -> Value {
    json!(FieldHex::from(n))
}

fn package(example_dir: &str, name: &str, circuit: &str, reads: &[&str], writes: &[&str]) -> Value {
    json!({
        "name": name,
        "circuit": circuit,
        "state_keys": { "reads": reads, "writes": writes },
        "manifest": example(example_dir, name),
    })
}

/// The AMM tip's non-secret-shared deployment: the init, the swap under
/// on-chain intake and its receipt intake as an alias.
fn amm_tip() -> Value {
    let mut receipt = package(
        "amm-tip",
        "amm_swap_tip_receipt",
        "amm_swap_tip",
        &["pool"],
        &["pool"],
    );
    receipt["alias_of"] = json!("amm_swap_tip");
    json!({
        "contract_manifest": 1,
        "name": "amm_tip",
        "node_keys": "rotating",
        "upgrades": "fixed",
        "contract": { "class_id": slot(0xc1a55), "package_capacity": 2 },
        "queue": { "slot": slot(12), "stale_blocks": 50, "stale_blocks_slot": slot(1) },
        "storage": { "configured": slot(11) },
        "state_keys": { "pool": slot(16) },
        "init": { "package": "amm_init_tip", "input_slots": [] },
        "circuits": {
            "amm_init_tip": { "vk_hash": slot(0xa1) },
            "amm_swap_tip": { "vk_hash": slot(0xa2) }
        },
        "packages": [
            package("amm-tip", "amm_init_tip", "amm_init_tip", &[], &["pool"]),
            package("amm-tip", "amm_swap_tip", "amm_swap_tip", &["pool"], &["pool"]),
            receipt,
        ]
    })
}

/// The lending tip's init and deposit, both on the market tree.
fn lending() -> Value {
    json!({
        "contract_manifest": 1,
        "name": "lending_tip",
        "node_keys": "fixed",
        "upgrades": "fixed",
        "contract": { "class_id": slot(0xc1a56), "package_capacity": 11 },
        "queue": { "slot": slot(12), "stale_blocks": 50, "stale_blocks_slot": slot(1) },
        "storage": { "configured": slot(11) },
        "state_keys": { "market": slot(16) },
        "init": { "package": "lending_init", "input_slots": [slot(7)] },
        "circuits": {
            "lending_init": { "vk_hash": slot(0xb1) },
            "deposit_shared": { "vk_hash": slot(0xb2) }
        },
        "packages": [
            package("lending-tip", "lending_init", "lending_init", &[], &["market"]),
            package("lending-tip", "deposit_shared", "deposit_shared", &["market"], &["market"]),
        ]
    })
}

/// The sidecar path: the AMM example's seed round, intake direct.
fn sidecar() -> Value {
    json!({
        "contract_manifest": 1,
        "name": "amm",
        "node_keys": "fixed",
        "upgrades": "fixed",
        "circuits": { "pss_seed": { "vk_hash": slot(0xc1) } },
        "packages": [
            { "name": "pss_seed", "circuit": "pss_seed", "manifest": example("amm", "pss_seed") }
        ]
    })
}

fn check(v: &Value) -> Result<CheckedContractManifest, Refusal> {
    ContractManifest::parse(v)?.check()
}

fn refused(v: Value, needle: &str) {
    crate::error::assert_refused(check(&v), ErrorClass::BadRequest, &[needle]);
}

#[test]
fn the_examples_check_and_round_trip() {
    for v in [amm_tip(), lending(), sidecar()] {
        let checked = check(&v).unwrap();
        assert_eq!(checked.manifests.len(), checked.document.packages.len());
        assert_eq!(serde_json::to_value(&checked.document).unwrap(), v);
    }
    let checked = check(&amm_tip()).unwrap();
    let (receipt, m) = checked.package("amm_swap_tip_receipt").unwrap();
    assert!(!receipt.listed());
    assert_eq!(m.intake, Intake::Receipt);
    assert_eq!(checked.vk_hash(receipt), Fr::from(0xa2u64));
}

#[test]
fn the_packages_hash_runs_over_the_listed_packages() {
    let checked = check(&amm_tip()).unwrap();
    let h = |prev: Fr, name: &str, vk: u64| {
        poseidon2_hash(&[prev, poseidon2_hash_bytes(name.as_bytes()), Fr::from(vk)])
    };
    let expected = h(
        h(Fr::from(0u64), "amm_init_tip", 0xa1),
        "amm_swap_tip",
        0xa2,
    );
    assert_eq!(checked.packages_hash(), expected);
    assert_eq!(packages_hash([]), Fr::from(0u64));
}

#[test]
fn the_manifest_hash_is_over_the_canonical_json() {
    let v = amm_tip();
    let canonical = canonical_json(&v).unwrap();
    assert_eq!(
        manifest_hash(&v).unwrap(),
        poseidon2_hash_bytes(canonical.as_bytes())
    );
    // key order does not matter; any other byte does
    let reordered: Value =
        serde_json::from_str(&serde_json::to_string_pretty(&v).unwrap()).unwrap();
    assert_eq!(
        manifest_hash(&reordered).unwrap(),
        manifest_hash(&v).unwrap()
    );
    let mut other = v.clone();
    other["name"] = json!("amm_tip2");
    assert_ne!(manifest_hash(&other).unwrap(), manifest_hash(&v).unwrap());
}

#[test]
fn the_upgradable_bound_follows_the_public_writes() {
    assert_eq!(max_upgradable_packages(Upgrades::Fixed), None);
    assert_eq!(max_upgradable_packages(Upgrades::Circuits), Some(14));
    assert_eq!(max_upgradable_packages(Upgrades::Contract), Some(13));
    assert_eq!(upgrade_writes(Upgrades::Contract, 13), Some(62));
    assert_eq!(upgrade_writes(Upgrades::Circuits, 14), Some(62));
    assert_eq!(upgrade_writes(Upgrades::Circuits, 15), Some(66));

    let mut v = lending();
    v["upgrades"] = json!("contract");
    v["storage"]["circuit_pins"] = slot(20);
    check(&v).unwrap();
    v["contract"]["package_capacity"] = json!(14);
    refused(
        v.clone(),
        "field `upgrades`: `contract` with a package list of 14: one upgrade writes 66 public \
         slots (62 at 13 packages)",
    );
    v["upgrades"] = json!("circuits");
    check(&v).unwrap();
    v["upgrades"] = json!("fixed");
    v["storage"].as_object_mut().unwrap().remove("circuit_pins");
    v["contract"]["package_capacity"] = json!(32);
    check(&v).unwrap();
    // a stale period is needed once circuits can be replaced
    let mut v = lending();
    v["upgrades"] = json!("circuits");
    v["storage"]["circuit_pins"] = slot(20);
    v["queue"]["stale_blocks"] = Value::Null;
    refused(
        v,
        "field `queue.stale_blocks`: null under upgrades `circuits`",
    );
}

#[test]
fn packages_and_circuits_refer_to_each_other() {
    let mut v = amm_tip();
    v["packages"][1]["circuit"] = json!("amm_swap");
    refused(
        v,
        "field `packages[1].circuit`: `amm_swap` is not an entry of `circuits`",
    );
    let mut v = amm_tip();
    v["circuits"]["unused"] = json!({ "vk_hash": slot(1) });
    refused(v, "field `circuits.unused`: no package runs this circuit");
    let mut v = amm_tip();
    v["packages"][2]["name"] = json!("amm_swap_tip");
    v["packages"][2]["manifest"]["circuit"] = json!("amm_swap_tip");
    refused(v, "field `packages[2].name`: `amm_swap_tip` appears twice");
    let mut v = amm_tip();
    v["packages"][1]["manifest"]["circuit"] = json!("amm_swap");
    refused(
        v,
        "field `packages[1].manifest.circuit`: `amm_swap` is not the package name `amm_swap_tip`",
    );
    let mut v = amm_tip();
    v["packages"][0]["manifest"]["witness"][0]["from"] = json!({ "SAMPLE": 0 });
    refused(v, "field `packages[0].manifest.witness[0].from");
    let mut v = amm_tip();
    v["packages"][1]["name"] = json!("amm swap");
    refused(v, "field `packages[1].name`: package name");
}

#[test]
fn an_alias_names_a_listed_package_on_its_circuit() {
    let mut v = amm_tip();
    v["packages"][2]["alias_of"] = json!("amm_init_tip");
    refused(
        v,
        "field `packages[2].alias_of`: `amm_init_tip` runs circuit `amm_init_tip`, not `amm_swap_tip`",
    );
    let mut v = amm_tip();
    v["packages"][2]["alias_of"] = json!("nothing");
    refused(
        v,
        "field `packages[2].alias_of`: `nothing` is not a listed package",
    );
    let mut v = amm_tip();
    v["packages"][1]["alias_of"] = json!("amm_swap_tip_receipt");
    refused(
        v,
        "field `packages[1].alias_of`: `amm_swap_tip_receipt` is not a listed package",
    );
    // the alias does not count against the capacity; a third listed package does
    let mut v = amm_tip();
    v["packages"][2].as_object_mut().unwrap().remove("alias_of");
    refused(
        v,
        "field `packages`: 3 listed packages; the contract's list holds 2 (`contract.package_capacity`)",
    );
    let mut v = amm_tip();
    let many: Vec<Value> = (0..33).map(|_| v["packages"][0].clone()).collect();
    v["packages"] = json!(many);
    refused(
        v,
        "field `packages`: 33 packages; a contract manifest holds at most 32",
    );
    let mut v = amm_tip();
    v["packages"] = json!([]);
    v["circuits"] = json!({});
    refused(
        v,
        "field `packages`: a contract manifest holds at least one package",
    );
}

#[test]
fn the_sections_follow_the_packages() {
    let mut v = amm_tip();
    v.as_object_mut().unwrap().remove("queue");
    refused(v, "field `queue`: missing");
    let mut v = amm_tip();
    v.as_object_mut().unwrap().remove("storage");
    refused(v, "field `storage`: missing");
    let mut v = amm_tip();
    v["contract"]
        .as_object_mut()
        .unwrap()
        .remove("package_capacity");
    refused(v, "field `contract.package_capacity`: missing");
    let mut v = amm_tip();
    v.as_object_mut().unwrap().remove("contract");
    refused(v, "field `contract.package_capacity`: missing");
    for (field, value) in [
        ("queue", amm_tip()["queue"].clone()),
        ("storage", amm_tip()["storage"].clone()),
        ("state_keys", json!({ "pool": slot(16) })),
        ("plain_reads", json!({ "price": slot(3) })),
        ("init", amm_tip()["init"].clone()),
        ("upgrades", json!("circuits")),
        ("upgrades", json!("contract")),
    ] {
        let mut v = sidecar();
        v[field] = value;
        refused(v, &format!("field `{field}`: only with a queued package"));
    }
    let mut v = sidecar();
    v["packages"][0]["state_keys"] = json!({ "reads": [], "writes": ["seed"] });
    refused(
        v,
        "field `packages[0].state_keys`: only for a package of a queued intake",
    );
    let mut v = amm_tip();
    v["packages"][1]
        .as_object_mut()
        .unwrap()
        .remove("state_keys");
    refused(v, "field `packages[1].state_keys`: missing");
    let mut v = amm_tip();
    v["storage"]["shared_onchain"] = slot(14);
    refused(
        v,
        "field `storage.shared_onchain`: only with a package of secret-shared on-chain",
    );
    let mut v = amm_tip();
    v["storage"]["circuit_pins"] = slot(20);
    refused(
        v,
        "field `storage.circuit_pins`: only under upgrades `circuits` or `contract`",
    );
    let mut v = amm_tip();
    v["upgrades"] = json!("circuits");
    refused(v, "field `storage.circuit_pins`: missing");
    let mut v = amm_tip();
    v["queue"]["stale_blocks"] = json!(0);
    refused(v, "stale_blocks");
    let mut v = amm_tip();
    v["queue"].as_object_mut().unwrap().remove("stale_blocks");
    refused(v, "stale_blocks");
    let mut v = amm_tip();
    v["queue"]["stale_blocks"] = json!(u64::from(u32::MAX) + 1);
    refused(
        v,
        "field `queue.stale_blocks`: 4294967296 is above 4294967295",
    );
    let mut v = amm_tip();
    v["plain_reads"] = json!({ "price": slot(3) });
    refused(
        v,
        "field `plain_reads.price`: no package has a pinned read filling this parameter",
    );
}

#[test]
fn the_init_round_is_listed_and_only_writes() {
    let mut v = amm_tip();
    v["init"]["package"] = json!("amm_swap_tip");
    refused(
        v,
        "field `init.package`: `amm_swap_tip` must take a queued intake, read no key and write at least one",
    );
    let mut v = amm_tip();
    v["init"]["package"] = json!("amm_swap_tip_receipt");
    refused(
        v,
        "field `init.package`: `amm_swap_tip_receipt` is an alias",
    );
    let mut v = amm_tip();
    v["init"]["package"] = json!("nothing");
    refused(v, "field `init.package`: `nothing` is not a package");
}

#[test]
fn every_named_key_has_a_slot_and_a_writer() {
    let mut v = amm_tip();
    v["packages"][1]["state_keys"]["reads"] = json!(["pool", "extra"]);
    refused(
        v,
        "field `packages[1].state_keys`: 2 reads and 1 writes; the circuit manifest takes 1 and 1",
    );
    let mut v = amm_tip();
    v["packages"][1]["state_keys"]["writes"] = json!(["book"]);
    refused(
        v,
        "field `packages[1].state_keys`: `book` is not a key of the top-level `state_keys`",
    );
    let mut v = amm_tip();
    v["state_keys"]["book"] = slot(17);
    refused(
        v,
        "field `state_keys.book`: no package reads or writes this key",
    );
    let mut v = amm_tip();
    v["state_keys"]["book"] = slot(17);
    for p in 1..3 {
        v["packages"][p]["state_keys"]["reads"] = json!(["book"]);
    }
    refused(
        v,
        "field `packages[1].state_keys.reads`: `book` is written by no package",
    );
}

#[test]
fn every_package_on_a_key_agrees_on_its_layout() {
    // a flat key read at another length
    let mut v = amm_tip();
    for w in [9, 10] {
        v["packages"][1]["manifest"]["witness"][w]["from"]["len"] = json!(4);
    }
    v["packages"][1]["manifest"]["outputs"][0]["len"] = json!(4);
    refused(
        v,
        "key `pool`: package `amm_swap_tip` loads or stores it at length 4, package `amm_init_tip` at 3",
    );
    // within one package
    let mut v = amm_tip();
    v["packages"][1]["manifest"]["witness"][9]["from"]["len"] = json!(4);
    refused(v, "field `packages[1].manifest");
    // another state mode
    let mut v = amm_tip();
    v["packages"][0]["manifest"]["state"]["$state_keys.writes[0]"] = json!("chain");
    refused(
        v,
        "key `pool`: package `amm_swap_tip` gives it `node` flat, package `amm_init_tip` `chain` flat",
    );
    // another tree shape
    let mut v = lending();
    v["packages"][1]["manifest"]["tree"]["$state_keys.reads[0]"]["depth"] = json!(15);
    refused(
        v,
        "key `market`: package `deposit_shared` gives it `node` tree of depth 15",
    );
    // a tree stored back at another key
    let mut v = lending();
    v["state_keys"]["book"] = slot(17);
    v["packages"][1]["state_keys"]["writes"] = json!(["book"]);
    refused(
        v,
        "field `packages[1].manifest.tree`: the tree loaded at $state_keys.reads[0] (key `market`) is \
         stored back at $state_keys.writes[0] (key `book`)",
    );
}

#[test]
fn one_intake_family_per_namespace() {
    let mut v = amm_tip();
    let mut shared = package(
        "amm-tip",
        "amm_swap_tip_shared",
        "amm_swap_tip_shared",
        &["pool"],
        &["pool"],
    );
    shared["manifest"] = example("amm-tip", "amm_swap_tip_shared");
    v["packages"].as_array_mut().unwrap().push(shared);
    v["circuits"]["amm_swap_tip_shared"] = json!({ "vk_hash": slot(0xa3) });
    v["contract"]["package_capacity"] = json!(3);
    refused(
        v,
        "field `packages`: package `amm_swap_tip` (on-chain intake `onchain`) and package \
         `amm_swap_tip_shared` (secret-shared receipt intake `shared_receipt`)",
    );
}

// ---- test vector ----

const VECTOR: &str = "testvectors/contract_manifest.json";

fn vector() -> Value {
    let document = amm_tip();
    let checked = check(&document).unwrap();
    let name_hashes: serde_json::Map<String, Value> = checked
        .document
        .packages
        .iter()
        .map(|p| {
            (
                p.name.clone(),
                json!(FieldHex(poseidon2_hash_bytes(p.name.as_bytes()))),
            )
        })
        .collect();
    json!({
        "comment": "The contract manifest of examples/amm-tip's non-secret-shared deployment (vk hashes, class id and slots made up). manifest_hash = poseidon2_hash_bytes(JCS(manifest)), jcs the RFC 8785 serialisation; packages_hash: h = 0, then for each package without alias_of in order h = poseidon2([h, poseidon2_hash_bytes(name), circuits[circuit].vk_hash]).",
        "manifest": document,
        "jcs": canonical_json(&document).unwrap(),
        "name_hashes": name_hashes,
        "manifest_hash": FieldHex(manifest_hash(&document).unwrap()),
        "packages_hash": FieldHex(checked.packages_hash()),
    })
}

/// The committed vector is what this code computes.
#[test]
fn the_contract_manifest_vector_matches() {
    let text = std::fs::read_to_string(repo().join(VECTOR)).unwrap();
    let committed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(committed, vector(), "rerun write_contract_manifest_vector");
}

/// `cargo test -p sidecar-core write_contract_manifest_vector -- --ignored`.
#[test]
#[ignore = "writes testvectors/; run on purpose"]
fn write_contract_manifest_vector() {
    let text = serde_json::to_string_pretty(&vector()).unwrap() + "\n";
    std::fs::write(repo().join(VECTOR), text).unwrap();
}

/// The AMM tip's deployment under `upgrades: circuits`, its pins at slot 20.
fn upgradable() -> Value {
    let mut v = amm_tip();
    v["upgrades"] = json!("circuits");
    v["storage"]["circuit_pins"] = slot(20);
    v
}

fn upgrade(held: &Value, new: &Value) -> Result<(), Refusal> {
    check_upgrade(&check(held).unwrap(), &check(new).unwrap())
}

fn upgrade_refused(held: &Value, new: Value, needle: &str) {
    let err = upgrade(held, &new).unwrap_err();
    assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
    assert!(
        err.message.contains(needle),
        "`{}` lacks `{needle}`",
        err.message
    );
}

// A replacement that changes a circuit, its label or drops an alias keeps
// every contract-level fact and every key's layout: accepted.
#[test]
fn an_upgrade_may_change_circuits_and_drop_packages() {
    let held = upgradable();
    let mut new = held.clone();
    new["circuits"]["amm_swap_tip"]["vk_hash"] = slot(0xa3);
    new["name"] = json!("amm_tip next");
    upgrade(&held, &new).unwrap();
    let mut dropped = held.clone();
    dropped["packages"].as_array_mut().unwrap().pop();
    upgrade(&held, &dropped).unwrap();
}

// Under `fixed` nothing may change, and no contract-level fact may change
// under `circuits`.
#[test]
fn an_upgrade_keeps_the_contract_level_facts() {
    upgrade_refused(
        &amm_tip(),
        amm_tip(),
        "field `upgrades`: the namespace's contract manifest says upgrades `fixed`",
    );
    let held = upgradable();
    let mut new = held.clone();
    new["contract"]["class_id"] = slot(0xc1a57);
    upgrade_refused(
        &held,
        new,
        "field `contract.class_id`: a circuit upgrade keeps the contract's class",
    );
    for (field, value) in [
        (
            "queue",
            json!({ "slot": slot(13), "stale_blocks": 50, "stale_blocks_slot": slot(1) }),
        ),
        (
            "storage",
            json!({ "configured": slot(14), "circuit_pins": slot(20) }),
        ),
        ("state_keys", json!({ "pool": slot(17) })),
        ("node_keys", json!("fixed")),
        ("upgrades", json!("contract")),
    ] {
        let mut new = held.clone();
        new[field] = value;
        upgrade_refused(
            &held,
            new,
            &format!("field `{field}`: differs from the held"),
        );
    }
}

// A key's layout must stay: here the swap would store the pool at another
// length.
#[test]
fn an_upgrade_keeps_each_keys_layout() {
    let held = upgradable();
    let mut new = held.clone();
    for p in [0, 1, 2] {
        let outputs = new["packages"][p]["manifest"]["outputs"]
            .as_array_mut()
            .unwrap();
        for o in outputs {
            if o.get("len").is_some() {
                o["len"] = json!(4);
            }
        }
    }
    match check(&new) {
        Ok(_) => upgrade_refused(&held, new, "field `state_keys.pool`"),
        // the circuit manifests themselves refuse the length: no upgrade
        // can reach the state check with it
        Err(e) => assert_eq!(e.class, ErrorClass::BadRequest),
    }
}

// Under `contract` a class upgrade may move what only the code reads and
// turn a fixed key set into key epochs; it keeps the state keys, the pins'
// slot and width, `upgrades`, and a rotating key set.
#[test]
fn a_class_upgrade_keeps_the_state_and_the_pins() {
    let mut held = upgradable();
    held["upgrades"] = json!("contract");
    held["node_keys"] = json!("fixed");
    let mut moved = held.clone();
    moved["contract"]["class_id"] = slot(0xc1a57);
    moved["queue"]["slot"] = slot(13);
    moved["queue"]["stale_blocks"] = json!(80);
    moved["storage"]["configured"] = slot(15);
    moved["node_keys"] = json!("rotating");
    upgrade(&held, &moved).unwrap();
    // the same moves without a new class are refused
    let mut same_class = moved.clone();
    same_class["contract"]["class_id"] = held["contract"]["class_id"].clone();
    upgrade_refused(
        &held,
        same_class,
        "differs from the held contract manifest's; a circuit upgrade",
    );
    for (field, value) in [
        ("state_keys", json!({ "pool": slot(17) })),
        (
            "storage",
            json!({ "configured": slot(11), "circuit_pins": slot(21) }),
        ),
        ("upgrades", json!("circuits")),
    ] {
        let mut new = moved.clone();
        new[field] = value;
        upgrade_refused(&held, new, "a class upgrade keeps");
    }
    let mut capacity = moved.clone();
    capacity["contract"]["package_capacity"] = json!(3);
    upgrade_refused(&held, capacity, "field `contract.package_capacity`");
    // rotating to fixed: never
    let mut rotating = held.clone();
    rotating["node_keys"] = json!("rotating");
    let mut back = moved.clone();
    back["node_keys"] = json!("fixed");
    upgrade_refused(&rotating, back, "field `node_keys`");
}
