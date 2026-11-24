//! The node's process shell without a proving round: mutual TLS on the API,
//! `GET /v1/nodes` against the key files `setup` writes (over the real mesh,
//! and the dealer), the receipt routes' refusals, the registry listings, the one
//! error shape, the admin socket, and the config's store backends.
//!
//! Needs the CRS of `scripts/prepare-data.sh` (machine/data, or DATA_DIR); a
//! test fails naming what is missing. Run with `--release`.

mod common;

use std::thread;
use std::time::Duration;

use common::*;
use sidecar_core::ErrorClass;
use sidecar_core::field::FieldHex;
use sidecar_core::keys::KeyFiles;
use sidecar_core::register::{
    ContractManifestResponse, NamespaceResponse, NamespacesResponse, PackageNamesResponse,
};
use sidecar_core::response::NodePublicKeys;
use sidecar_core::store::{ManifestRow, NamespaceRow, PackageRow, Store};
use sidecar_core::{Fr, Refusal};
use sidecar_node::admin::{self, AdminRequest};
use sidecar_node::client::ApiClient;
use sidecar_node::{Mesh, setup, tls};

fn sample_keys(seed: u64) -> sidecar_core::keys::NodeKeys {
    use rand::SeedableRng;
    sidecar_core::keys::NodeKeys::generate(&mut rand::rngs::StdRng::seed_from_u64(seed))
}

/// The TLS handshake refused the client with `alert` (not any other failure
/// to connect).
fn refused_in_handshake(err: impl std::fmt::Display, alert: &str) {
    let text = format!("{err:#}");
    assert!(
        text.contains(&format!("received fatal alert: {alert}")),
        "{text}"
    );
}

/// (1) Only a client with a certificate under the deployment CA is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_client_under_the_deployment_ca_is_served() {
    let crs = require_crs(&[]);
    let tmp = TempDir::new("mtls");
    let certs = dev_certs(tmp.path());
    let [mesh, _, _] = meshes();
    let node = start_node(
        0,
        sample_keys(1),
        Default::default(),
        crs,
        mesh,
        &certs,
        tmp.path(),
    )
    .await;

    // The orchestrator's certificate is served.
    let answer = orchestrator(&certs, &node).get("/v1/nodes").await.unwrap();
    assert_eq!(answer.status, 200);

    // No client certificate: refused in the handshake, no route runs.
    let ca = certs.join("https-ca.pem");
    let anonymous = ApiClient::new(
        node.running.api_addr,
        "localhost",
        tls::client_config(&ca, None).unwrap(),
    )
    .unwrap();
    let err = anonymous.get("/v1/nodes").await.unwrap_err();
    refused_in_handshake(err, "CertificateRequired");

    // A client certificate under another CA.
    let other = dev_certs(&tmp.path().join("other"));
    let stranger = ApiClient::new(
        node.running.api_addr,
        "localhost",
        tls::client_config(
            &ca,
            Some((
                &other.join("https-orchestrator.pem"),
                &other.join("https-orchestrator-key.pem"),
            )),
        )
        .unwrap(),
    )
    .unwrap();
    let err = stranger.get("/v1/nodes").await.unwrap_err();
    refused_in_handshake(err, "DecryptError");

    // A certificate under the right CA without the clientAuth usage (a node's
    // server certificate).
    let impostor = ApiClient::new(
        node.running.api_addr,
        "localhost",
        tls::client_config(
            &ca,
            Some((
                &certs.join("https-node1.pem"),
                &certs.join("https-node1-key.pem"),
            )),
        )
        .unwrap(),
    )
    .unwrap();
    let err = impostor.get("/v1/nodes").await.unwrap_err();
    refused_in_handshake(err, "UnsupportedCertificate");

    // And the orchestrator is still served after the refusals.
    let answer = orchestrator(&certs, &node).get("/v1/nodes").await.unwrap();
    assert_eq!(answer.status, 200);
}

/// Run `setup` on the three key directories at once, over the real mesh.
fn setup_three(dirs: &[KeyFiles; 3], force: bool) -> [eyre::Result<NodePublicKeys>; 3] {
    let meshes = meshes();
    thread::scope(|s| {
        let handles: Vec<_> = (0..3)
            .map(|i| {
                let (files, mesh) = (&dirs[i], &meshes[i]);
                s.spawn(move || setup::setup(files, mesh, force))
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        results.try_into().unwrap_or_else(|_| unreachable!())
    })
}

/// The three master shares form one replicated sharing: node i's `b` is node
/// i-1's `a`.
fn assert_consistent(dirs: &[KeyFiles; 3]) -> Fr {
    let shares = dirs.clone().map(|d| setup::read_master_share(&d).unwrap());
    for i in 0..3 {
        assert_eq!(
            shares[i].b,
            shares[(i + 2) % 3].a,
            "node {i}'s master share"
        );
    }
    shares[0].a + shares[1].a + shares[2].a
}

/// (2) `GET /v1/nodes` answers the public keys of the key files `setup` wrote;
/// two setups give different keys; setup never overwrites without `--force`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nodes_answers_the_keys_setup_wrote() {
    let crs = require_crs(&[]);
    let tmp = TempDir::new("setup");
    let certs = dev_certs(tmp.path());
    let dirs = [0, 1, 2].map(|i| KeyFiles::new(tmp.path().join(format!("keys{i}"))));

    let first = {
        let dirs = dirs.clone();
        tokio::task::spawn_blocking(move || setup_three(&dirs, false).map(|r| r.unwrap()))
            .await
            .unwrap()
    };
    let master = assert_consistent(&dirs);
    for (i, keys) in first.iter().enumerate() {
        assert_eq!(dirs[i].read().unwrap().public_keys(), *keys);
        assert_ne!(keys.enc, keys.sig, "node {i}: enc and sig are one key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dirs[i].master_share_path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
    assert!(first[0].enc != first[1].enc && first[1].enc != first[2].enc);

    // Each node answers its own key files' keys.
    for i in 0..3 {
        let (keys, share) = setup::load(dirs[i].dir()).unwrap();
        let node = start_node(
            i,
            keys,
            share,
            crs.clone(),
            meshes()[i].clone(),
            &certs,
            tmp.path(),
        )
        .await;
        let answer = orchestrator(&certs, &node).get("/v1/nodes").await.unwrap();
        let served: NodePublicKeys = answer.json().unwrap().unwrap();
        assert_eq!(served, first[i], "node {i}");
        let text = String::from_utf8(answer.body.clone()).unwrap();
        assert!(text.contains("\"enc\":{\"x\":\"0x") && text.contains("\"sig\":{\"x\":\"0x"));
        eprintln!("GET /v1/nodes on node {i}: {text}");
    }

    // Without --force, setup refuses on any node and writes nothing.
    let again = {
        let dirs = dirs.clone();
        tokio::task::spawn_blocking(move || {
            setup::setup(&dirs[0], &meshes()[0], false).unwrap_err()
        })
        .await
        .unwrap()
    };
    assert!(
        format!("{again:#}").contains("without --force"),
        "{again:#}"
    );
    assert_eq!(dirs[0].read().unwrap().public_keys(), first[0]);

    // A second setup with --force gives three new key pairs and a new master.
    let second = {
        let dirs = dirs.clone();
        tokio::task::spawn_blocking(move || setup_three(&dirs, true).map(|r| r.unwrap()))
            .await
            .unwrap()
    };
    let master2 = assert_consistent(&dirs);
    assert_ne!(master, master2);
    for i in 0..3 {
        assert_ne!(second[i].enc, first[i].enc, "node {i}: enc");
        assert_ne!(second[i].sig, first[i].sig, "node {i}: sig");
        assert_eq!(dirs[i].read().unwrap().public_keys(), second[i]);
    }

    // The development dealer writes a consistent sharing too.
    let dealt = [0, 1, 2].map(|i| KeyFiles::new(tmp.path().join(format!("dealt{i}"))));
    let keys = setup::setup_dealer([&dealt[0], &dealt[1], &dealt[2]], false).unwrap();
    assert_consistent(&dealt);
    for i in 0..3 {
        assert_eq!(dealt[i].read().unwrap().public_keys(), keys[i]);
    }
    assert!(setup::setup_dealer([&dealt[0], &dealt[1], &dealt[2]], false).is_err());
}

/// (5) The receipt routes refuse a malformed body (400) and an unknown
/// receipt (404) in the one error shape (tests/receipts.rs signs them);
/// unknown routes and methods answer the same shape; bad bodies are 400
/// naming the problem.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receipt_refusals_and_every_error_have_one_shape() {
    let crs = require_crs(&[]);
    let tmp = TempDir::new("routes");
    let certs = dev_certs(tmp.path());
    // A lone node: an execute it refuses at resolution still opens the mesh
    // to send its refusal as its handshake verdict, which fails here after
    // the connect timeout, kept short.
    let [mesh, _, _] = meshes();
    let mesh = Mesh::new(
        mesh.config()
            .clone()
            .with_timeouts(Duration::from_millis(500), Duration::from_secs(600)),
    );
    let node = start_node(
        0,
        sample_keys(2),
        Default::default(),
        crs,
        mesh,
        &certs,
        tmp.path(),
    )
    .await;
    let client = orchestrator(&certs, &node);

    let refusal = |answer: sidecar_node::client::Answer| -> Refusal {
        answer.json::<serde_json::Value>().unwrap().unwrap_err()
    };
    let receipt = client.post_raw("/v1/receipt", "{}").await.unwrap();
    assert_eq!(receipt.status, 400);
    let r = refusal(receipt);
    assert_eq!(r.class, ErrorClass::BadRequest);
    assert!(r.message.contains("missing field"), "{r}");
    let unknown = client.get("/v1/receipt/0x1/0x2").await.unwrap();
    assert_eq!(unknown.status, 404);
    assert!(refusal(unknown).message.contains("no receipt"));
    let bad_id = client.get("/v1/receipt/0x1/0xzz").await.unwrap();
    assert!(refusal(bad_id).message.contains("path `request_id`"));

    for (method, path) in [
        ("GET", "/v1/nope"),
        ("GET", "/v1/execute"),
        ("POST", "/v1/nodes"),
    ] {
        let answer = client
            .call(method.parse().unwrap(), path, Some(b"{}".to_vec()))
            .await
            .unwrap();
        assert_eq!(answer.status, 404, "{method} {path}");
        assert_eq!(refusal(answer).class, ErrorClass::NotFound);
    }

    let bad = client
        .post_raw("/v1/execute", "{\"namespace\": 1}")
        .await
        .unwrap();
    assert_eq!(bad.status, 400);
    eprintln!("a malformed execute body: {}", refusal(bad));
    let bad = client.post_raw("/v1/fetch", "not json").await.unwrap();
    assert_eq!(refusal(bad).class, ErrorClass::BadRequest);
    let bad = client.get("/v1/namespaces/0xzz").await.unwrap();
    assert_eq!(refusal(bad).class, ErrorClass::BadRequest);

    // The registry listings: none yet, then the namespaces and package names
    // the store holds, in order; an unknown namespace's listing is 404.
    let listed: NamespacesResponse = client
        .get("/v1/namespaces")
        .await
        .unwrap()
        .json()
        .unwrap()
        .unwrap();
    assert!(listed.namespaces.is_empty());
    for (namespace, names) in [(0x77u64, &["seed", "b"][..]), (0x5u64, &["a"][..])] {
        let store = &node.app.node.store;
        let mut txn = store.begin(Fr::from(namespace));
        txn.register_namespace(NamespaceRow {
            owner_pubkey: sidecar_core::schnorr::public_key(sidecar_core::grumpkin::Fq::from(9u64)),
            nsk_app: Default::default(),
            npk_app_hash: Fr::from(1u64),
            seq: 0,
        });
        txn.put_manifest(ManifestRow {
            manifest_hash: Fr::from(3u64),
            document: serde_json::json!({"contract_manifest": 1}),
            seq: 0,
        });
        for name in names {
            txn.put_package(PackageRow {
                name: name.to_string(),
                manifest_hash: Fr::from(3u64),
                circuit_json: b"{}".to_vec(),
                manifest: serde_json::json!({}),
                vk: vec![],
                vk_hash: Fr::from(2u64),
                disabled: false,
                seq: 0,
            });
        }
        store.commit(txn).unwrap();
    }
    let listed: NamespacesResponse = client
        .get("/v1/namespaces")
        .await
        .unwrap()
        .json()
        .unwrap()
        .unwrap();
    assert_eq!(
        listed.namespaces,
        [FieldHex::from(0x5), FieldHex::from(0x77)]
    );
    let names: PackageNamesResponse = client
        .get("/v1/packages/0x77")
        .await
        .unwrap()
        .json()
        .unwrap()
        .unwrap();
    assert_eq!(names.namespace, FieldHex::from(0x77));
    assert_eq!(names.packages, ["b", "seed"]);
    let unknown = client.get("/v1/packages/0x1234").await.unwrap();
    assert_eq!(refusal(unknown).class, ErrorClass::NotFound);
    // the contract manifest as stored, and its hash on the namespace's GET
    let manifest: ContractManifestResponse = client
        .get("/v1/namespaces/0x77/manifest")
        .await
        .unwrap()
        .json()
        .unwrap()
        .unwrap();
    assert_eq!(
        (manifest.manifest_hash, manifest.seq),
        (FieldHex::from(3), 0)
    );
    assert_eq!(
        manifest.manifest,
        serde_json::json!({"contract_manifest": 1})
    );
    let info: NamespaceResponse = client
        .get("/v1/namespaces/0x77")
        .await
        .unwrap()
        .json()
        .unwrap()
        .unwrap();
    assert_eq!(info.manifest_hash, FieldHex::from(3));
    let unknown = client.get("/v1/namespaces/0x1234/manifest").await.unwrap();
    assert_eq!(refusal(unknown).class, ErrorClass::NotFound);

    // Unknown namespace, package and request: 404.
    let unknown = client.get("/v1/namespaces/0x1234").await.unwrap();
    assert_eq!(refusal(unknown).class, ErrorClass::NotFound);
    let unknown = client.get("/v1/packages/0x1234/amm_swap").await.unwrap();
    assert_eq!(refusal(unknown).class, ErrorClass::NotFound);
    // A name that is no name is 400 on every store (Postgres takes no NUL).
    let nul = client.get("/v1/packages/0x1234/amm%00swap").await.unwrap();
    assert_eq!(nul.status, 400);
    assert!(refusal(nul).message.contains("field `name`"));
    let tree = client
        .post(
            "/v1/tree",
            &serde_json::json!({"namespace": "0x1234", "key": "po\u{0}ol",
                "commitment": "0x1", "depth": 1, "indices": []}),
        )
        .await
        .unwrap();
    assert_eq!(tree.status, 400);
    assert!(refusal(tree).message.contains("field `key`"), "tree");
    let unknown = client
        .post(
            "/v1/fetch",
            &serde_json::json!({"namespace": "0x1234", "request_id": "0x99"}),
        )
        .await
        .unwrap();
    assert_eq!(unknown.status, 404);
    // An execute naming an unregistered circuit is refused at resolution.
    let unregistered = client
        .post(
            "/v1/execute",
            &serde_json::json!({
                "namespace": "0x1234",
                "circuit": "amm_swap",
                "request_id": "0x99",
                "public": {},
                "state_keys": {"reads": [], "writes": []},
            }),
        )
        .await
        .unwrap();
    let r = refusal(unregistered);
    assert_eq!(r.class, ErrorClass::BadRequest);
    assert!(r.message.contains("not registered"), "{r}");
}

/// The admin socket answers `prune` and refuses an unknown request id, lives
/// in the run directory with owner-only permissions, and a second node cannot
/// take over a live socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_admin_socket_is_local_and_owner_only() {
    let crs = require_crs(&[]);
    let tmp = TempDir::new("admin");
    let certs = dev_certs(tmp.path());
    let [mesh, _, _] = meshes();
    let node = start_node(
        0,
        sample_keys(3),
        Default::default(),
        crs,
        mesh.clone(),
        &certs,
        tmp.path(),
    )
    .await;
    let socket = node.running.admin_socket.clone();
    assert!(socket.starts_with(tmp.path()));
    {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let meta = std::fs::metadata(&socket).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let dir = std::fs::metadata(socket.parent().unwrap()).unwrap();
        assert_eq!(dir.permissions().mode() & 0o777, 0o700);
    }

    let pruned = admin::call_async(socket.clone(), AdminRequest::Prune)
        .await
        .unwrap();
    assert!(pruned.ok);
    assert_eq!(pruned.pruned, Some(0));

    let refused = admin::call_async(
        socket.clone(),
        AdminRequest::Restore {
            namespace: FieldHex::from(0x1234u64),
            request_id: 7u64.into(),
        },
    )
    .await
    .unwrap();
    assert!(!refused.ok);
    assert_eq!(refused.refusal.unwrap().class, ErrorClass::NotFound);

    // A malformed command is answered, not dropped.
    let bad = tokio::task::spawn_blocking({
        let socket = socket.clone();
        move || {
            use std::io::{BufRead, BufReader, Write};
            let mut s = std::os::unix::net::UnixStream::connect(&socket).unwrap();
            s.write_all(b"{\"op\": \"drop_tables\"}\n").unwrap();
            let mut line = String::new();
            BufReader::new(s).read_line(&mut line).unwrap();
            line
        }
    })
    .await
    .unwrap();
    let bad: admin::AdminResponse = serde_json::from_str(bad.trim()).unwrap();
    assert_eq!(bad.refusal.unwrap().class, ErrorClass::BadRequest);

    // The admin commands are not routes of the API listener.
    let client = orchestrator(&certs, &node);
    let restore = serde_json::json!({"op": "restore", "namespace": "0x1234", "request_id": "0x7"});
    for path in [
        "/v1/restore",
        "/v1/admin/restore",
        "/admin",
        "/v1/prune",
        "/",
    ] {
        let answer = client.post(path, &restore).await.unwrap();
        assert_eq!(answer.status, 404, "POST {path}");
    }

    // A second node on the same socket refuses to start while this one runs.
    let err = admin::bind(&socket).unwrap_err();
    assert!(format!("{err:#}").contains("already running"), "{err:#}");
    drop(node);
    assert!(!socket.exists(), "the socket outlived its node");
}
