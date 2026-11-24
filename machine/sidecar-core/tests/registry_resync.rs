//! The registry resync on three in-process nodes (sidecar-core's `testing`
//! harness: mpc_net's local network, one thread per node), over the compiled
//! AMM circuits: a namespace registered at seq 0 at all three (its nsk_app
//! pairs from the registration circuit), then a REGISTER of another contract
//! manifest node 2 failed to commit, a third one node 2 refused (its seq was
//! then behind) and a DISABLE node 1 failed to commit.
//!
//! - While nodes 0 and 1 differ, a registry resync of node 2 from either is
//!   refused at all three nodes, naming the rows they differ on, and writes
//!   nothing; so is a resync naming one node twice.
//! - Once the DISABLE is resent (node 1 commits it), node 2, three bodies
//!   behind, is resynced from node 1: it takes the other two's contract
//!   manifest with its three packages (the disabled one among them), builds
//!   the two vks it did not hold itself (the rows then equal the other two's
//!   byte for byte), advances its seq to 3
//!   and keeps its own nsk_app share; the registry check then finds no
//!   divergence, a request naming the disabled circuit is refused at step 3
//!   at all three, and a second resync writes nothing.
//!
//! Needs `scripts/prepare-data.sh` (examples/amm's circuits and the CRS under
//! machine/data, or DATA_DIR); every test fails naming the missing file if it
//! is absent, so a passing run proves it ran. Run with `--release`.

use sidecar_core::error::{ErrorClass, Refusal};
use sidecar_core::field::Fr;
use sidecar_core::register::ManifestMessage;
use sidecar_core::registry::Signed;
use sidecar_core::request::NODES;
use sidecar_core::resync::RegistryResync;
use sidecar_core::store::StoreRead;
use sidecar_core::testing::{
    Fixture, Network, TestPackage, manifest, owner_secret, request, serial, sign_message, views,
};

const AMM: u64 = 0xc0ffee;
const SEED_KEY: &str = "0xa001";
const CIRCUITS: [&str; 3] = ["pss_seed", "amm_init", "amm_swap"];

fn ns() -> Fr {
    Fr::from(AMM)
}

fn fixture() -> &'static Fixture {
    sidecar_core::testing::fixture(&CIRCUITS).expect(
        "the registry resync tests need scripts/prepare-data.sh's AMM circuits and CRS (see \
         the SKIPPED line above)",
    )
}

/// A manifest message of the AMM circuits `names` at `seq` (the sidecar
/// path, where a later contract manifest replaces the stored one), signed
/// by the namespace owner.
fn signed_register(
    net: &mut Network,
    fx: &Fixture,
    names: &[&str],
    seq: u64,
) -> Signed<ManifestMessage> {
    let packages: Vec<TestPackage> = names
        .iter()
        .map(|name| TestPackage::new(name, manifest("amm", name)))
        .collect();
    let body = Network::manifest_message(fx, AMM, "amm", &packages, None, seq);
    sign_message(body, owner_secret(), &mut net.rng)
}

/// Three nodes whose registries diverged: the contract manifest of
/// `pss_seed` at seq 0 everywhere; at seq 1 one of `pss_seed` and
/// `amm_init`, whose commit failed at node 2; at seq 2 one of all three
/// circuits, which node 2 refused as out of order; at seq 3 the DISABLE of
/// `pss_seed`, whose commit failed at node 1. Node 0 holds seq 3, node 1
/// seq 2, node 2 seq 0. Returns the network and the DISABLE body, for its
/// resend.
fn diverged(fx: &Fixture, seed: u64) -> (Network, Signed<sidecar_core::register::DisableRequest>) {
    let mut net = Network::new(fx, seed);
    net.register(fx, AMM, "amm", &CIRCUITS[..1]);
    let init = signed_register(&mut net, fx, &CIRCUITS[..2], 1);
    net.nodes[2].store.fail_next_commit();
    for (i, answer) in net.register_each([&init; NODES]).into_iter().enumerate() {
        assert_eq!(
            answer.is_ok(),
            i < 2,
            "REGISTER amm_init: node {i}: {answer:?}"
        );
    }
    let swap = signed_register(&mut net, fx, &CIRCUITS, 2);
    for (i, answer) in net.register_each([&swap; NODES]).into_iter().enumerate() {
        assert_eq!(
            answer.is_ok(),
            i < 2,
            "REGISTER amm_swap: node {i}: {answer:?}"
        );
    }
    let disable = net.signed_disable(AMM, "pss_seed", 3);
    net.nodes[1].store.fail_next_commit();
    for (i, answer) in net.disable_each(&disable).into_iter().enumerate() {
        assert_eq!(
            answer.is_ok(),
            i == 0,
            "DISABLE pss_seed: node {i}: {answer:?}"
        );
    }
    let seqs: Vec<u64> = net
        .nodes
        .iter()
        .map(|n| n.store.namespace(ns()).unwrap().unwrap().seq)
        .collect();
    assert_eq!(seqs, [3, 2, 0]);
    (net, disable)
}

fn refusals(found: Vec<Result<RegistryResync, Refusal>>) -> Vec<Refusal> {
    found
        .into_iter()
        .enumerate()
        .map(|(i, r)| r.err().unwrap_or_else(|| panic!("node {i} resynced")))
        .collect()
}

#[test]
fn a_registry_resync_from_a_pair_that_differs_is_refused_and_writes_nothing() {
    let _serial = serial();
    let fx = fixture();
    let (net, _) = diverged(fx, 31);
    let before = net.snapshots();

    for from in [0, 1] {
        for (i, err) in refusals(net.resync_registry(2, from))
            .into_iter()
            .enumerate()
        {
            eprintln!("REFUSED registry resync of node 2 from node {from}: node {i}: {err}");
            assert_eq!(err.class, ErrorClass::Conflict, "{err}");
            assert!(
                err.message.contains("hold different registry rows")
                    && err.message.contains("the namespace row: ")
                    && err.message.contains("package `pss_seed`: "),
                "node {i}: {err}"
            );
        }
    }
    for (i, err) in refusals(net.resync_registry(1, 1)).into_iter().enumerate() {
        assert_eq!(err.class, ErrorClass::BadRequest, "node {i}: {err}");
        assert!(
            err.message.contains("are not two distinct node indices"),
            "node {i}: {err}"
        );
    }
    assert!(net.snapshots() == before, "a refused resync wrote a row");
}

#[test]
fn a_node_several_registry_bodies_behind_is_resynced_from_a_neighbour() {
    let _serial = serial();
    let fx = fixture();
    let (mut net, disable) = diverged(fx, 32);
    let disabled = "`pss_seed` is disabled under namespace";

    // The resend levels node 1 (node 0 answers it unchanged; node 2, three
    // bodies behind, refuses it as out of order).
    for (i, answer) in net.disable_each(&disable).into_iter().enumerate() {
        assert_eq!(
            answer.is_ok(),
            i < 2,
            "resent DISABLE: node {i}: {answer:?}"
        );
    }
    let row_before = net.nodes[2].store.namespace(ns()).unwrap().unwrap();

    let found: Vec<RegistryResync> = net
        .resync_registry(2, 1)
        .into_iter()
        .enumerate()
        .map(|(i, r)| r.unwrap_or_else(|e| panic!("registry resync: node {i}: {e}")))
        .collect();
    for (i, report) in found.iter().enumerate() {
        let text: Vec<String> = report.repaired.iter().map(ToString::to_string).collect();
        eprintln!("REGISTRY RESYNC node {i}: {report:?}");
        assert_eq!((report.lost, report.from), (2, 1));
        assert_eq!((report.namespaces, report.packages), (1, 3), "node {i}");
        assert_eq!(report.vks_built, if i == 2 { 2 } else { 0 }, "node {i}");
        assert_eq!(text.len(), 4, "node {i}: {text:#?}");
        assert!(
            text[0].contains("the namespace row: node 0 and node 1 hold seq 3, ")
                && text[0].contains("; node 2 holds seq 0, "),
            "node {i}: {}",
            text[0]
        );
        assert_eq!(report.repaired, found[0].repaired, "node {i}");
    }

    // Node 2's rows are the other two's, vks included; its share is its own.
    let store = &net.nodes[2].store;
    let row = store.namespace(ns()).unwrap().unwrap();
    assert_eq!(row.seq, 3);
    assert!(
        store.contract_manifest(ns()).unwrap()
            == net.nodes[1].store.contract_manifest(ns()).unwrap(),
        "node 2 holds another contract manifest than node 1"
    );
    assert_eq!(row.nsk_app, row_before.nsk_app, "the nsk_app share changed");
    assert_eq!(
        (row.owner_pubkey, row.npk_app_hash),
        (row_before.owner_pubkey, row_before.npk_app_hash)
    );
    for name in CIRCUITS {
        let held = store.package(ns(), name).unwrap();
        for other in [0, 1] {
            assert!(
                held == net.nodes[other].store.package(ns(), name).unwrap(),
                "package `{name}` at node 2 is not node {other}'s"
            );
        }
    }
    for (i, check) in net.check_registry(None).into_iter().enumerate() {
        let check = check.unwrap_or_else(|e| panic!("registry check: node {i}: {e}"));
        assert_eq!((check.namespaces, check.packages), (1, 3));
        assert!(
            check.divergences.is_empty(),
            "node {i}: {:?}",
            check.divergences
        );
    }
    let seed = request(AMM, "pss_seed", net.id(), &[], &[], &[SEED_KEY]);
    net.refused(
        "a seed after the registry resync",
        views(&seed),
        ErrorClass::BadRequest,
        disabled,
    );

    // A second resync finds nothing to do and writes nothing.
    let after = net.snapshots();
    for (i, r) in net.resync_registry(2, 0).into_iter().enumerate() {
        let r = r.unwrap_or_else(|e| panic!("second registry resync: node {i}: {e}"));
        assert!(r.repaired.is_empty(), "node {i}: {r:?}");
        assert_eq!((r.namespaces, r.packages, r.vks_built), (0, 0, 0));
    }
    assert!(
        net.snapshots() == after,
        "a resync with nothing to do wrote"
    );
}
