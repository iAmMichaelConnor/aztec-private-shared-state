use super::*;
use crate::abi::check_manifest_value;
use crate::keys::label_field;

#[test]
fn result_domain_is_ascii_sidecar_result() {
    let bytes = RESULT_DOMAIN.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap();
    assert_eq!(&bytes[start..], b"sidecar.result");
    assert_eq!(Fr::from(RESULT_DOMAIN), label_field(b"sidecar.result"));
}

#[test]
fn the_result_message_binds_every_part() {
    let ns = Fr::from(0x1f2eu64);
    let id = RequestId::from(7u64);
    let commitments = [Fr::from(11u64), Fr::from(12u64)];
    let base = result_message(ns, id, &commitments, 1, Fr::from(5u64));
    assert_eq!(
        base,
        poseidon2_hash(&[
            Fr::from(RESULT_DOMAIN),
            ns,
            id.fr(),
            commitments[0],
            commitments[1],
            Fr::from(1u64),
            Fr::from(5u64)
        ])
    );
    for other in [
        result_message(Fr::from(1u64), id, &commitments, 1, Fr::from(5u64)),
        result_message(ns, RequestId::from(8u64), &commitments, 1, Fr::from(5u64)),
        result_message(ns, id, &commitments[..1], 1, Fr::from(5u64)),
        result_message(ns, id, &[commitments[1], commitments[0]], 1, Fr::from(5u64)),
        result_message(ns, id, &commitments, 2, Fr::from(5u64)),
        result_message(ns, id, &commitments, 1, Fr::zero()),
    ] {
        assert_ne!(other, base);
    }
    assert_eq!(sealed_hash(&[]), Fr::zero());
    assert_eq!(
        sealed_hash(&[Fr::from(3u64)]),
        poseidon2_hash(&[Fr::from(3u64)])
    );
}

// Invariant 11 on the application path: the sources a round binds from
// serve the vectors step 8 loaded, and the fixed key nsk_app is the
// namespace row's share, so the master share the node holds (for the
// registration circuit) never reaches an application witness.
#[test]
fn an_application_round_binds_nsk_app_and_never_the_master() {
    use crate::abi::tests::{amm_swap_abi, manifest_json};
    use crate::store::MemoryStore;
    use crate::store::testing::{namespace_row, node_keys, ns, round, shared};

    let dir = sidecar_test_fixtures::dirs::data_dir();
    let (g1, g2) = (dir.join("bn254_g1.dat"), dir.join("bn254_g2.dat"));
    if !g1.exists() || !g2.exists() {
        crate::testing::artifacts::missing(format!(
            "{} is missing; run scripts/prepare-data.sh (or set DATA_DIR)",
            dir.display()
        ));
        return;
    }
    let size = registry::registration_artifact().unwrap().circuit_size;
    let crs = Crs::read(&g1, &g2, size).unwrap();
    let master = Share::new(Fr::from(0x6d61u64), Fr::from(0x7374u64));
    let node = Node::new(0, node_keys(), master, MemoryStore::new(), crs).unwrap();

    // The namespace's nsk_app share and a node-held pool.
    let row = namespace_row(70);
    let mut txn = node.store.begin(ns());
    txn.register_namespace(row.clone());
    node.store.commit(txn).unwrap();
    let pool = vec![shared(10), shared(20), shared(30)];
    round(
        &node.store,
        1,
        &[],
        &[],
        &[("0xa002", pool.clone(), Fr::from(0xa1u64))],
    )
    .unwrap();

    // amm_swap loads the pool and nsk_app.
    let (manifest, shape) =
        check_manifest_value(&manifest_json("amm_swap"), &amm_swap_abi()).unwrap();
    let req = NodeRequest::from_json(
        &serde_json::json!({
            "namespace": fr_to_hex(ns()), "circuit": "amm_swap",
            "request_id": "0x41d30000000000000000000000000003",
            "public": {"amount_in": "0x2710", "direction": "0x0", "in0_nonce": "0x0d935b18"},
            "state_keys": {"reads": ["0xa002"], "writes": ["0xa002"]}
        })
        .to_string(),
    )
    .unwrap();
    let keys = node.keys();
    let holding = node.holders().choose(&manifest).unwrap();
    let at = StateCtx {
        store: &node.store,
        keys: &keys,
        node: node.index,
        namespace: req.namespace.fr(),
        manifest: &manifest,
        shape: &shape,
        req: &req,
        requester: None,
        chain: None,
        public_inputs: &[],
    };
    let loaded = open_and_load(&node, &at, &holding).unwrap();
    let mut sources = RoundSources::check(
        &node,
        &keys,
        &req,
        manifest.intake.share_source(),
        &loaded.values,
    );
    let bound = bind::bind(&shape, &manifest, &req, &mut sources).unwrap();

    assert_eq!(bound.input["nsk_app"], Elem::Shared(row.nsk_app));
    assert_eq!(bound.input["in0_fields[0]"], pool[0]);
    let mut shared_elements = 0;
    for (key, value) in &bound.input {
        if let Elem::Shared(share) = value {
            shared_elements += 1;
            assert_ne!(*share, master, "`{key}` holds the master share");
            for half in [share.a, share.b] {
                assert!(
                    half != master.a && half != master.b,
                    "`{key}` holds half of the master share"
                );
            }
        }
    }
    assert!(shared_elements >= 5, "{shared_elements} shared elements");
    let read_keys: Vec<&str> = bound.reads.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(read_keys, ["0xa002", "nsk_app"]);
}

#[test]
fn result_signatures_verify_and_are_deterministic() {
    let keys = crate::keys::tests::sample_keys(2);
    let message = Fr::from(0xabcu64);
    let a = sign_result(&keys, message);
    assert_eq!(a, sign_result(&keys, message));
    assert!(verify(keys.sig_pk(), a, message));
    assert_ne!(a, sign_result(&keys, message + Fr::from(1u64)));
    assert!(!verify(
        crate::keys::tests::sample_keys(0).sig_pk(),
        a,
        message
    ));
}

// A fresh node loads a package's circuit from the vk its row stores: the
// first request's step 3 builds no vk, the loaded key is the stored one,
// the next request hits the cache, as does each held version's, and a row whose vk does not hash to its
// vk_hash, or does not decode, is refused (500) and not cached.
#[test]
fn a_fresh_node_loads_a_circuit_from_its_stored_vk() {
    use crate::store::MemoryStore;
    use crate::store::testing::{node_keys, ns};

    let dir = sidecar_test_fixtures::dirs::data_dir();
    let (g1, g2) = (dir.join("bn254_g1.dat"), dir.join("bn254_g2.dat"));
    let json_path = dir.join("circuits/pss_seed.json");
    if let Some(missing) = [&g1, &g2, &json_path].into_iter().find(|p| !p.exists()) {
        crate::testing::artifacts::missing(format!(
            "{} is missing; run scripts/prepare-data.sh (or set DATA_DIR)",
            missing.display()
        ));
        return;
    }
    let json = std::fs::read(&json_path).unwrap();
    let artifact = Artifact::from_json("pss_seed", &json).unwrap();
    let size =
        crate::crs::crs_circuit_size([&artifact, &registry::registration_artifact().unwrap()]);
    let crs = Crs::read(&g1, &g2, size).unwrap();
    // The row REGISTER writes: the vk built once from the circuit.
    let built = Circuit::new(artifact, &crs.prover).unwrap();
    let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/amm/manifests/pss_seed.json");
    let pkg = PackageRow {
        name: "pss_seed".into(),
        manifest_hash: Fr::from(1u64),
        circuit_json: json,
        manifest: serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap(),
        vk: built.vk.to_buffer(),
        vk_hash: built.vk_hash,
        disabled: false,
        seq: 0,
    };

    let fresh = || {
        Node::new(
            0,
            node_keys(),
            Share::default(),
            MemoryStore::new(),
            crs.clone(),
        )
    };
    let node = fresh().unwrap();
    let before = crate::crs::vk_builds_on_this_thread();
    let loaded = node.loaded(ns(), &pkg).unwrap();
    assert_eq!(
        crate::crs::vk_builds_on_this_thread(),
        before,
        "the first load built a vk"
    );
    assert_eq!(loaded.circuit.vk.to_buffer(), pkg.vk);
    assert_eq!(loaded.circuit.vk_hash, pkg.vk_hash);
    assert_eq!(
        loaded.circuit.public_input_count(),
        built.public_input_count()
    );
    assert!(Arc::ptr_eq(&node.loaded(ns(), &pkg).unwrap(), &loaded));
    // another held version of the name, the circuit unchanged: each version
    // keeps its own entry, so rounds alternating between them reload nothing
    let next = PackageRow {
        manifest_hash: Fr::from(2u64),
        seq: 1,
        ..pkg.clone()
    };
    let other = node.loaded(ns(), &next).unwrap();
    assert!(!Arc::ptr_eq(&other, &loaded));
    assert!(Arc::ptr_eq(&node.loaded(ns(), &pkg).unwrap(), &loaded));
    assert!(Arc::ptr_eq(&node.loaded(ns(), &next).unwrap(), &other));

    let node = fresh().unwrap();
    let wrong_hash = PackageRow {
        vk_hash: pkg.vk_hash + Fr::from(1u64),
        ..pkg.clone()
    };
    let err = node.loaded(ns(), &wrong_hash).err().unwrap();
    assert_eq!(err.class, crate::error::ErrorClass::MpcFailure);
    assert!(err.message.contains("hashes to"), "{err}");
    let truncated = PackageRow {
        vk: pkg.vk[..pkg.vk.len() - 32].to_vec(),
        ..pkg.clone()
    };
    let err = node.loaded(ns(), &truncated).err().unwrap();
    assert!(
        err.message.contains("decoding the stored verification key"),
        "{err}"
    );
    assert!(node.circuits.lock().unwrap().is_empty());
    // The one vk built since is the second node's registration circuit
    // (`Node::new`); the refused loads built none.
    assert_eq!(crate::crs::vk_builds_on_this_thread(), before + 1);
}

// A node whose store holds an import whose checks have not passed signs and
// writes nothing: REGISTER and DISABLE are refused (500) before any check,
// as a round is; cleared, the same DISABLE reaches the registry's checks.
#[test]
fn an_unverified_store_takes_no_registry_body() {
    use crate::register::{DisableRequest, Signature};
    use crate::registry::Signed;
    use crate::store::MemoryStore;
    use crate::store::testing::{node_keys, ns};

    let dir = sidecar_test_fixtures::dirs::data_dir();
    let (g1, g2) = (dir.join("bn254_g1.dat"), dir.join("bn254_g2.dat"));
    if !g1.exists() || !g2.exists() {
        crate::testing::artifacts::missing(format!(
            "{} is missing; run scripts/prepare-data.sh (or set DATA_DIR)",
            dir.display()
        ));
        return;
    }
    let size = registry::registration_artifact().unwrap().circuit_size;
    let crs = Crs::read(&g1, &g2, size).unwrap();
    let node = Node::new(0, node_keys(), Share::default(), MemoryStore::new(), crs).unwrap();
    let body = Signed::new(DisableRequest {
        namespace: FieldHex(ns()),
        circuit: "pss_seed".into(),
        owner_pubkey: crate::grumpkin::point_to_wire(crate::schnorr::public_key(
            crate::grumpkin::Fq::from(5u64),
        )),
        seq: 1,
        signature: Signature::default(),
    })
    .unwrap();
    let mut rng = <ark_std::rand::rngs::StdRng as ark_std::rand::SeedableRng>::seed_from_u64(1);
    node.mark_unverified(Some("an import")).unwrap();
    let err = node.disable(&body, &mut rng).unwrap_err();
    assert_eq!(err.class, crate::error::ErrorClass::MpcFailure, "{err}");
    assert!(err.message.contains("checks have not passed"), "{err}");
    node.mark_unverified(None).unwrap();
    let err = node.disable(&body, &mut rng).unwrap_err();
    assert!(err.message.contains("does not verify"), "{err}");
}
