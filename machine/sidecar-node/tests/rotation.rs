//! `sidecar-node rotate-enc` against a running node: the key files it writes,
//! its refusal inside the grace window, the printed keys against
//! `GET /v1/nodes`, and the retirement of the previous key when the window
//! lapses (on the timer and at start), under a clock the test controls, and
//! not while a queued secret-shared receipt request still needs it; and the
//! `requests` pruning job, which reads the same clock.
//!
//! Needs the CRS of `scripts/prepare-data.sh` (machine/data, or DATA_DIR); a
//! test fails naming what is missing. Run with `--release`.

mod common;

use std::path::Path;
use std::process::Output;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use rand::rngs::OsRng;
use serde_json::Value;
use sidecar_core::envelope::{EnvelopeAd, seal_envelope};
use sidecar_core::epochs::EncKeyObservation;
use sidecar_core::field::{FieldHex, Fr};
use sidecar_core::keys::{KeyFiles, NodeKeys};
use sidecar_core::pipeline::{Node, VerifierRows};
use sidecar_core::request::NodeSharedInput;
use sidecar_core::response::NodePublicKeys;
use sidecar_core::store::testing::{id, new_request, ns, receipt_row};
use sidecar_core::store::{MemoryStore, NamespaceRow, ReceiptRow, Store, StoreRead};
use sidecar_core::{ErrorClass, Refusal};
use sidecar_node::admin::{AdminRequest, call_async};
use sidecar_node::receipt::{ReceiptChain, ReceiptConfig, Receipts};
use sidecar_node::rotation::{self, KeyRotation, key_id_hex};
use sidecar_node::server::{self, App, StartOptions};
use sidecar_node::{Mesh, tls};
use sidecar_tip::Standing;

const DAY: u64 = 24 * 60 * 60;
const GRACE: u64 = 30 * DAY;
const T0: u64 = 1_800_000_000;

/// A node on MemoryStore whose keys live in `files`, with a grace window of
/// 30 days, a retirement check every 50 ms and the test's clock.
async fn start(
    files: &KeyFiles,
    clock: &Arc<AtomicU64>,
    crs: sidecar_core::crs::Crs,
    mesh: Mesh,
    certs: &Path,
    run_dir: &Path,
) -> Started {
    let keys = files.read().unwrap();
    let node = Node::new(0, keys, Default::default(), MemoryStore::new(), crs).unwrap();
    let mut rotation = KeyRotation::new(files.clone(), GRACE);
    rotation.check_interval = Duration::from_millis(50);
    let now = clock.clone();
    let app = Arc::new(
        App::new(node, mesh, rotation).with_clock(Arc::new(move || now.load(Ordering::SeqCst))),
    );
    let running = server::start(
        app.clone(),
        StartOptions {
            api_listen: "127.0.0.1:0".parse().unwrap(),
            tls: tls::server_config(&node_tls(certs, 0)).unwrap(),
            admin_socket: run_dir.join("node0/admin.sock"),
            prune_interval: None,
        },
    )
    .await
    .unwrap();
    Started { app, running }
}

/// A node config the `rotate-enc` command reads: only its party and its admin
/// socket matter to the command.
fn write_config(dir: &Path, node: &Started, keys: &KeyFiles) -> std::path::PathBuf {
    let path = dir.join("node0.toml");
    let text = format!(
        "party = 0\napi_listen = \"{}\"\nmesh_config = \"party0.toml\"\nkey_dir = \"{}\"\n\
         run_dir = \"{}\"\nadmin_socket = \"{}\"\nenc_grace_days = 30\n\
         [tls]\nca = \"ca.pem\"\ncert = \"node.pem\"\nkey = \"node-key.pem\"\n\
         [store]\nbackend = \"memory\"\n[crs]\ng1 = \"g1.dat\"\ng2 = \"g2.dat\"\n",
        node.running.api_addr,
        keys.dir().display(),
        dir.display(),
        node.running.admin_socket.display(),
    );
    std::fs::write(&path, text).unwrap();
    path
}

/// Run `sidecar-node rotate-enc` (with `--force` when asked) on a blocking
/// thread.
async fn rotate_enc(config: &Path, force: bool) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_sidecar-node"));
    cmd.arg("rotate-enc").arg("--config").arg(config);
    if force {
        cmd.arg("--force");
    }
    cmd.env("RUST_LOG", "warn");
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

/// The JSON line a successful `rotate-enc` prints.
fn printed(out: &Output) -> Value {
    assert!(
        out.status.success(),
        "rotate-enc failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    let line = stdout.lines().last().expect("rotate-enc printed a line");
    serde_json::from_str(line).unwrap()
}

async fn served_keys(certs: &Path, node: &Started) -> NodePublicKeys {
    orchestrator(certs, node)
        .get("/v1/nodes")
        .await
        .unwrap()
        .json()
        .unwrap()
        .unwrap()
}

fn printed_keys(line: &Value) -> NodePublicKeys {
    serde_json::from_value(serde_json::json!({"enc": line["enc"], "sig": line["sig"]})).unwrap()
}

/// Wait (up to 10 s) until `done` holds.
async fn eventually(what: &str, done: impl Fn() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out: {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotate_enc_keeps_the_previous_key_for_the_grace_window() {
    let crs = require_crs(&[]);
    let tmp = TempDir::new("rotate");
    let certs = dev_certs(tmp.path());
    let [mesh, _, _] = meshes();
    let files = KeyFiles::new(tmp.path().join("keys"));
    let original: NodeKeys = {
        use rand::SeedableRng;
        NodeKeys::generate(&mut rand::rngs::StdRng::seed_from_u64(0x707a7e))
    };
    files.write(&original).unwrap();
    let clock = Arc::new(AtomicU64::new(T0));
    let node = start(
        &files,
        &clock,
        crs.clone(),
        mesh.clone(),
        &certs,
        tmp.path(),
    )
    .await;
    let config = write_config(tmp.path(), &node, &files);
    assert_eq!(
        served_keys(&certs, &node).await,
        original.public_keys(),
        "before the rotation"
    );

    // rotate-enc: a new enc key, the old one kept as previous with the time.
    let line = printed(&rotate_enc(&config, false).await);
    assert_eq!(line["party"], 0);
    let on_disk = files.read().unwrap();
    assert_ne!(on_disk.enc_scalar(), original.enc_scalar());
    assert_eq!(
        on_disk.sig_scalar(),
        original.sig_scalar(),
        "sig never rotates"
    );
    assert_eq!(on_disk.previous_enc_scalar(), Some(original.enc_scalar()));
    assert_eq!(on_disk.rotated_at(), Some(T0));
    assert!(files.previous_enc_path().exists() && files.rotated_at_path().exists());
    assert_eq!(line["key_id"], key_id_hex(&on_disk.key_id()));
    assert_eq!(line["previous_key_id"], key_id_hex(&original.key_id()));
    assert_eq!(line["previous_retires_at"], T0 + GRACE);
    // The printed keys are what the node now serves and runs with.
    let rotated = printed_keys(&line);
    assert_eq!(rotated, on_disk.public_keys());
    assert_eq!(served_keys(&certs, &node).await, rotated);
    assert_ne!(rotated.enc, original.public_keys().enc);
    assert_eq!(rotated.sig, original.public_keys().sig);
    let live = node.app.node.keys();
    assert_eq!(live.enc_scalar(), on_disk.enc_scalar());
    assert_eq!(live.previous_enc_pk(), Some(original.enc_pk()));

    // A second rotation inside the window is refused and changes nothing.
    clock.store(T0 + GRACE - 1, Ordering::SeqCst);
    let refused = rotate_enc(&config, false).await;
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("inside its grace window") && stderr.contains("--force"),
        "{stderr}"
    );
    let unchanged = files.read().unwrap();
    assert_eq!(unchanged.enc_scalar(), on_disk.enc_scalar());
    assert_eq!(unchanged.previous_enc_scalar(), Some(original.enc_scalar()));
    assert_eq!(served_keys(&certs, &node).await, rotated);

    // One second before the window ends the timer keeps the previous key.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(files.previous_enc_path().exists());
    assert!(node.app.node.keys().previous_enc_pk().is_some());

    // When the window lapses the timer retires it: files and running keys.
    clock.store(T0 + GRACE, Ordering::SeqCst);
    eventually("the previous key is retired", || {
        !files.previous_enc_path().exists() && node.app.node.keys().previous_enc_pk().is_none()
    })
    .await;
    assert!(!files.rotated_at_path().exists());
    let retired = files.read().unwrap();
    assert_eq!(retired.enc_scalar(), on_disk.enc_scalar());
    assert_eq!(retired.previous_enc_scalar(), None);
    assert_eq!(
        node.app.node.keys().seal_key_for(&original.key_id()),
        None,
        "a third under the retired key no longer opens"
    );
    assert_eq!(served_keys(&certs, &node).await, rotated);

    // With no window open, rotate-enc needs no --force; inside the new window
    // --force rotates again and drops the key it replaced at once.
    let t1 = T0 + GRACE + DAY;
    clock.store(t1, Ordering::SeqCst);
    let second = printed(&rotate_enc(&config, false).await);
    assert_eq!(second["previous_key_id"], line["key_id"]);
    clock.store(t1 + 60, Ordering::SeqCst);
    let third = printed(&rotate_enc(&config, true).await);
    assert_eq!(third["previous_key_id"], second["key_id"]);
    assert_eq!(third["previous_retires_at"], t1 + 60 + GRACE);
    let forced = files.read().unwrap();
    assert_eq!(forced.rotated_at(), Some(t1 + 60));
    assert_eq!(forced.seal_key_for(&on_disk.key_id()), None);
    assert_eq!(served_keys(&certs, &node).await, printed_keys(&third));

    // The window survives a restart, and a node started after it lapsed
    // retires the previous key before it serves.
    drop(node);
    clock.store(t1 + 60 + GRACE - 1, Ordering::SeqCst);
    let node = start(
        &files,
        &clock,
        crs.clone(),
        mesh.clone(),
        &certs,
        tmp.path(),
    )
    .await;
    assert!(node.app.node.keys().previous_enc_pk().is_some());
    drop(node);
    clock.store(t1 + 60 + GRACE, Ordering::SeqCst);
    let node = start(&files, &clock, crs, mesh, &certs, tmp.path()).await;
    assert!(node.app.node.keys().previous_enc_pk().is_none());
    assert!(!files.previous_enc_path().exists());
    assert_eq!(served_keys(&certs, &node).await, printed_keys(&third));
}

/// The pruning job (`sidecar-node prune` and the timer) reads the node's
/// clock, the one rotation and retirement read: a row created at T0 is kept
/// while the node's clock is inside the 30-day window and pruned once it is
/// past it. The test clock runs ahead of the system clock, so a job on the
/// system clock would keep the row.
/// Run `sidecar-node sign-enc-key` for `namespace` at `epoch` on a blocking
/// thread.
async fn sign_enc_key(config: &Path, namespace: Fr, epoch: u32) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_sidecar-node"));
    cmd.arg("sign-enc-key")
        .arg("--config")
        .arg(config)
        .arg("--namespace")
        .arg(sidecar_core::field::fr_to_hex(namespace))
        .arg("--epoch")
        .arg(epoch.to_string());
    cmd.env("RUST_LOG", "warn");
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

// Secret-shared on-chain intake's key in a contract: `sign-enc-key` keeps the
// current enc scalar pending as the epoch's in that contract (key files and
// running keys) and prints the contract's `rotate_enc_key` arguments, whose
// signature verifies under the sig key over the rotation message; signing
// the epoch again under the same scalar answers the same key, and after
// `rotate-enc` it replaces the pending scalar with the new one; epoch 0 is
// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_enc_key_keeps_the_contract_epoch_pending_and_signs_its_rotation() {
    let crs = require_crs(&[]);
    let tmp = TempDir::new("sign-enc-key");
    let certs = dev_certs(tmp.path());
    let [mesh, _, _] = meshes();
    let files = KeyFiles::new(tmp.path().join("keys"));
    let original: NodeKeys = {
        use rand::SeedableRng;
        NodeKeys::generate(&mut rand::rngs::StdRng::seed_from_u64(0x5e1e))
    };
    files.write(&original).unwrap();
    let clock = Arc::new(AtomicU64::new(T0));
    let node = start(&files, &clock, crs, mesh, &certs, tmp.path()).await;
    let config = write_config(tmp.path(), &node, &files);
    let contract = Fr::from(0xc0ffeeu64);

    let line = printed(&sign_enc_key(&config, contract, 1).await);
    assert_eq!(line["index"], 0);
    assert_eq!(line["epoch"], 1);
    let enc: sidecar_core::request::GrumpkinPoint =
        serde_json::from_value(line["enc"].clone()).unwrap();
    assert_eq!(enc, original.public_keys().enc);
    let signature: sidecar_core::register::Signature =
        serde_json::from_value(line["signature"].clone()).unwrap();
    let message = sidecar_tip::enc_rotation_message(
        contract,
        0,
        sidecar_core::grumpkin::coordinates(original.enc_pk()),
        1,
    );
    assert!(sidecar_core::schnorr::verify(
        original.sig_pk(),
        signature,
        message
    ));
    let held = files.read().unwrap();
    assert_eq!(held.epochs().pending(contract), [1]);
    assert_eq!(
        held.epochs().scalar(contract, 1),
        Some(original.enc_scalar())
    );
    assert_eq!(
        node.app.node.keys().epochs().scalar(contract, 1),
        Some(original.enc_scalar())
    );
    let again = printed(&sign_enc_key(&config, contract, 1).await);
    assert_eq!(again["enc"], line["enc"]);

    // the rotation never landed: after rotate-enc the same epoch is signed
    // again under the new scalar, which replaces the pending one
    let rotated = printed(&rotate_enc(&config, false).await);
    let resigned = printed(&sign_enc_key(&config, contract, 1).await);
    assert_eq!(resigned["enc"], rotated["enc"]);
    assert_eq!(resigned["epoch"], 1);
    let held = files.read().unwrap();
    assert_eq!(held.epochs().epochs(contract), vec![1]);
    assert_eq!(held.epochs().pending(contract), [1]);
    assert_eq!(held.epochs().scalar(contract, 1), Some(held.enc_scalar()));
    assert_eq!(
        node.app.node.keys().epochs().scalar(contract, 1),
        Some(held.enc_scalar())
    );

    let zero = sign_enc_key(&config, contract, 0).await;
    assert!(!zero.status.success());
    assert!(String::from_utf8_lossy(&zero.stderr).contains("epoch"));
}

/// The chain view of the landing test: the contract's stored key for node 0
/// and its queue's head and tail, which the test sets.
struct StoredKey {
    at: Mutex<Option<EncKeyObservation>>,
}

impl ReceiptChain for StoredKey {
    fn current_block(&self, _claimed: u32) -> Result<u32, Refusal> {
        Ok(500)
    }

    fn settled(&self) -> Result<Option<u64>, Refusal> {
        Ok(Some(500))
    }

    fn standings(
        &self,
        _: &dyn VerifierRows,
        _: u64,
        _: Fr,
        ids: &[Fr],
    ) -> Result<Option<Vec<Standing>>, Refusal> {
        Ok(Some(vec![Standing::Unknown; ids.len()]))
    }

    fn enc_key(
        &self,
        _: &dyn VerifierRows,
        _: Fr,
        i: usize,
    ) -> Result<Option<EncKeyObservation>, Refusal> {
        assert_eq!(i, 0, "node 0 reads its own key");
        Ok(*self.at.lock().unwrap())
    }
}

/// Record on landing: a signed rotation stays pending until the pruning job
/// sees the contract store the node's key at that epoch, then it is
/// recorded (key files and running keys) and the epoch is refused under
/// another scalar; a rotation that never lands blocks nothing, since
/// signing its epoch again replaces it; a contract two epochs on retires
/// the oldest scalar once the head reaches the tail read then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rotation_is_recorded_when_the_pruning_job_sees_it_land() {
    let crs = require_crs(&[]);
    let tmp = TempDir::new("enclanding");
    let [mesh, _, _] = meshes();
    let files = KeyFiles::new(tmp.path().join("keys"));
    let original: NodeKeys = {
        use rand::SeedableRng;
        NodeKeys::generate(&mut rand::rngs::StdRng::seed_from_u64(0x1a4d))
    };
    files.write(&original).unwrap();
    let node = Node::new(
        0,
        original.clone(),
        Default::default(),
        MemoryStore::new(),
        crs,
    )
    .unwrap();
    let chain = Arc::new(StoredKey {
        at: Mutex::new(None),
    });
    let clock = Arc::new(AtomicU64::new(T0));
    let now = clock.clone();
    let app = App::new(node, mesh, KeyRotation::new(files.clone(), GRACE))
        .with_receipts(Receipts::with_chain(
            ReceiptConfig::default(),
            chain.clone(),
        ))
        .with_clock(Arc::new(move || now.load(Ordering::SeqCst)));
    let contract = Fr::from(0xc0ffeeu64);
    let store = |epoch: u32, keys: &NodeKeys, head: u64, tail: u64| {
        *chain.at.lock().unwrap() = Some(EncKeyObservation {
            epoch,
            pk: sidecar_core::grumpkin::coordinates(keys.enc_pk()),
            head,
            tail,
        });
    };
    let prune = || {
        let pruned = sidecar_node::admin::prune(&app).unwrap();
        assert!(pruned.epochs.len() <= 1, "{:?}", pruned.epochs);
        pruned.epochs.into_iter().next()
    };
    let pending = || files.read().unwrap().epochs().pending(contract);

    // signed, not landed: the chain view not answering, then answering
    // epoch 0, leaves it pending
    let signed = rotation::sign_enc_key(&app, contract, 1).unwrap();
    assert_eq!(signed.enc, original.public_keys().enc);
    assert_eq!(pending(), [1]);
    assert_eq!(prune(), None);
    store(0, &original, 0, 0);
    let seen = prune().unwrap();
    assert_eq!((seen.stored_epoch, seen.recorded.len()), (0, 0));
    assert_eq!(pending(), [1]);

    // the rotation lands: recorded on disk and in the running keys
    store(1, &original, 0, 0);
    let seen = prune().unwrap();
    assert_eq!((seen.stored_epoch, seen.recorded), (1, vec![1]));
    assert!(pending().is_empty());
    assert!(app.node.keys().epochs().pending(contract).is_empty());
    assert_eq!(
        files.read().unwrap().epochs().scalar(contract, 1),
        Some(original.enc_scalar())
    );
    // the landed epoch answers again under its scalar, and after rotate-enc
    // it is refused under the new one
    let again = rotation::sign_enc_key(&app, contract, 1).unwrap();
    assert_eq!((again.enc, again.epoch), (signed.enc, 1));
    assert!(pending().is_empty());
    rotation::rotate_enc(&app, false).unwrap();
    let refusal = rotation::sign_enc_key(&app, contract, 1).unwrap_err();
    assert_eq!(refusal.class, ErrorClass::Conflict);
    assert!(
        refusal.message.contains("landed under another key"),
        "{refusal}"
    );

    // epoch 2 is signed under the new scalar and abandoned: the pruning job
    // leaves it pending while the contract stays at epoch 1, and after
    // another rotate-enc signing epoch 2 again replaces it, nothing cleared
    let abandoned = rotation::sign_enc_key(&app, contract, 2).unwrap();
    assert_eq!(pending(), [2]);
    assert_eq!(prune().unwrap().recorded, Vec::<u32>::new());
    assert_eq!(pending(), [2]);
    rotation::rotate_enc(&app, true).unwrap();
    let second = rotation::sign_enc_key(&app, contract, 2).unwrap();
    assert_ne!(second.enc, abandoned.enc);
    assert_eq!(pending(), [2]);
    let current = app.node.keys().as_ref().clone();
    assert_eq!(
        files.read().unwrap().epochs().scalar(contract, 2),
        Some(current.enc_scalar())
    );

    // epochs 2 and 3 land (3 under the same key, at a contract two epochs
    // past epoch 1) with requests 4..7 queued: both recorded, epoch 1 kept
    // until the head reaches 7
    rotation::sign_enc_key(&app, contract, 3).unwrap();
    store(3, &current, 4, 7);
    let seen = prune().unwrap();
    assert_eq!((seen.recorded, seen.retired), (vec![2, 3], vec![]));
    assert_eq!(files.read().unwrap().epochs().epochs(contract), [1, 2, 3]);
    store(3, &current, 7, 9);
    assert_eq!(prune().unwrap().retired, [1]);
    let held = files.read().unwrap();
    assert_eq!(held.epochs().epochs(contract), [2, 3]);
    assert!(held.epochs().pending(contract).is_empty());
    assert_eq!(app.node.keys().epochs(), held.epochs());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pruning_job_reads_the_node_clock() {
    let crs = require_crs(&[]);
    let tmp = TempDir::new("pruneclk");
    let certs = dev_certs(tmp.path());
    let [mesh, _, _] = meshes();
    let files = KeyFiles::new(tmp.path().join("keys"));
    let keys: NodeKeys = {
        use rand::SeedableRng;
        NodeKeys::generate(&mut rand::rngs::StdRng::seed_from_u64(0x707a80))
    };
    files.write(&keys).unwrap();
    let clock = Arc::new(AtomicU64::new(T0));
    let node = start(&files, &clock, crs, mesh, &certs, tmp.path()).await;
    let retention = node.app.node.retention_secs;
    assert_eq!(retention, GRACE, "the default retention is 30 days");
    assert!(
        sidecar_core::pipeline::unix_now() + retention < T0,
        "the test clock must run ahead of the system clock by more than the window"
    );
    let store = &node.app.node.store;
    let mut txn = store.begin(ns());
    txn.put_request(new_request(1, T0));
    store.commit(txn).unwrap();
    let prune = || call_async(node.running.admin_socket.clone(), AdminRequest::Prune);

    // At the window's end the row is still inside it (pruned are rows created
    // strictly before now - retention).
    clock.store(T0 + retention, Ordering::SeqCst);
    let answer = prune().await.unwrap();
    assert!(answer.ok, "{:?}", answer.refusal);
    assert_eq!(answer.pruned, Some(0));
    assert!(store.request(ns(), id(1)).unwrap().is_some());

    // One second later it is past it, by the node's clock.
    clock.store(T0 + retention + 1, Ordering::SeqCst);
    let answer = prune().await.unwrap();
    assert!(answer.ok, "{:?}", answer.refusal);
    assert_eq!(answer.pruned, Some(1));
    assert!(store.request(ns(), id(1)).unwrap().is_none());
}

/// The chain view of the retirement test: the node's own block, and one
/// standing the test sets for every request it is asked about.
struct OneStanding {
    block: u64,
    standing: Mutex<Standing>,
}

impl ReceiptChain for OneStanding {
    fn current_block(&self, _claimed: u32) -> Result<u32, Refusal> {
        Ok(self.block as u32)
    }

    fn settled(&self) -> Result<Option<u64>, Refusal> {
        Ok(Some(self.block))
    }

    fn standings(
        &self,
        _: &dyn VerifierRows,
        _: u64,
        _: Fr,
        ids: &[Fr],
    ) -> Result<Option<Vec<Standing>>, Refusal> {
        Ok(Some(vec![*self.standing.lock().unwrap(); ids.len()]))
    }
}

/// A secret-shared receipt row of `n` whose one envelope to node 0 is sealed to
/// `enc_pk`, expiring at `expiry_block`.
fn shared_row(n: u64, enc_pk: sidecar_core::grumpkin::Point, expiry_block: u64) -> ReceiptRow {
    let mut row = receipt_row(n, expiry_block, Some(10));
    let ad = EnvelopeAd::for_intake(ns(), row.request_id, &row.circuit, "amount");
    let share = seal_envelope(enc_pk, 0, &ad, [Fr::from(n), Fr::from(n + 1)], &mut OsRng);
    row.user_nonce = None;
    row.shares = vec![NodeSharedInput {
        name: "amount".into(),
        share,
        share_hashes: [FieldHex(share.hash()); 3],
    }];
    row
}

/// Past its grace window the previous enc key is kept while a stored secret-shared
/// receipt row whose envelope opens only under it may still reach the head
/// (queued, or not yet seen before its expiry), and `rotate-enc` refuses
/// without `--force`; a row sealed to the current key holds nothing. Once
/// the head has passed the request the retirement check retires the key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_queued_shared_receipt_holds_the_previous_key_until_the_head_passes_it() {
    let crs = require_crs(&[]);
    let tmp = TempDir::new("rotheld");
    let [mesh, _, _] = meshes();
    let files = KeyFiles::new(tmp.path().join("keys"));
    let original: NodeKeys = {
        use rand::SeedableRng;
        NodeKeys::generate(&mut rand::rngs::StdRng::seed_from_u64(0x707a81))
    };
    files.write(&original).unwrap();
    let node = Node::new(
        0,
        original.clone(),
        Default::default(),
        MemoryStore::new(),
        crs,
    )
    .unwrap();
    let mut txn = node.store.begin(ns());
    txn.register_namespace(NamespaceRow {
        owner_pubkey: sidecar_core::schnorr::public_key(sidecar_core::grumpkin::Fq::from(9u64)),
        nsk_app: Default::default(),
        npk_app_hash: Fr::from(1u64),
        seq: 0,
    });
    node.store.commit(txn).unwrap();
    let chain = Arc::new(OneStanding {
        block: 500,
        standing: Mutex::new(Standing::Queued { index: 3 }),
    });
    let clock = Arc::new(AtomicU64::new(T0));
    let now = clock.clone();
    let app = App::new(node, mesh, KeyRotation::new(files.clone(), GRACE))
        .with_receipts(Receipts::with_chain(
            ReceiptConfig::default(),
            chain.clone(),
        ))
        .with_clock(Arc::new(move || now.load(Ordering::SeqCst)));

    // a receipt signed before the rotation, sealed to the key that becomes
    // the previous one, and one sealed to the new key after it
    let old = shared_row(1, original.enc_pk(), 400);
    app.node.store.put_receipt(ns(), old.clone()).unwrap();
    rotation::rotate_enc(&app, false).unwrap();
    let new_pk = app.node.keys().enc_pk();
    app.node
        .store
        .put_receipt(ns(), shared_row(2, new_pk, 900))
        .unwrap();
    let held = || rotation::held_by_queued_receipts(&app).unwrap();
    assert_eq!(held(), [(ns(), old.request_id)]);

    // past the window, queued: kept, and a second rotation refused
    clock.store(T0 + GRACE + 1, Ordering::SeqCst);
    assert_eq!(rotation::retire_lapsed(&app).unwrap(), None);
    assert!(app.node.keys().previous_key_id().is_some());
    assert!(files.previous_enc_path().exists());
    let refusal = rotation::rotate_enc(&app, false).unwrap_err();
    assert_eq!(refusal.class, ErrorClass::Conflict);
    assert!(
        refusal
            .message
            .contains("held by 1 queued secret-shared receipt"),
        "{refusal}"
    );

    // not seen yet, at block 500: before an expiry of 600 it may still be
    // queued; past one of 400 it never can
    *chain.standing.lock().unwrap() = Standing::NotSeen;
    let pending = shared_row(3, original.enc_pk(), 600);
    app.node.store.put_receipt(ns(), pending.clone()).unwrap();
    assert_eq!(held(), [(ns(), pending.request_id)]);
    assert_eq!(rotation::retire_lapsed(&app).unwrap(), None);

    // the head has passed both: the previous key retires
    *chain.standing.lock().unwrap() = Standing::Done;
    assert!(held().is_empty());
    let previous = key_id_hex(&original.key_id());
    assert_eq!(rotation::retire_lapsed(&app).unwrap(), Some(previous));
    assert!(app.node.keys().previous_key_id().is_none());
    assert!(!files.previous_enc_path().exists());
    assert!(held().is_empty());
}
