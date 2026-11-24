//! The tip's receipt signer over the node's mutual-TLS API: a receipt
//! is signed over the stated message and verifies under the node's `sig`
//! key; invalid inputs, an `intake: direct` or `intake: onchain` package, an unknown
//! or disabled circuit and an expiry out of bounds are refused (400) with
//! nothing stored; the same inputs twice give the same request id and the
//! same answer, a later expiry re-signs and an earlier one is refused (409);
//! `GET /v1/receipt/...` serves the stored row. With the node's own chain
//! view (an in-memory Aztec node), the signer checks the expiry against the
//! chain's block, not the body's, and the pruning job, past `expiry_block +
//! stale_blocks`, prunes a receipt whose request never reached the queue or
//! is done and keeps a queued one until `done` is written, and marks a
//! node-held tip key no round commits on against the node's chain view and
//! deletes its orphans once the settled block passes them; a node whose
//! Aztec node does not answer prunes nothing, and a node without `[tip]`
//! signs no receipt (400, named) and prunes nothing. Under secret-shared receipt
//! intake (testvectors/shared_intake.json, the nodes holding keys.json's
//! keys) each node signs C with the vector's signature and keeps its own
//! envelopes and no plaintext shared input; an envelope that does not hash
//! to its share hash, does not open at the node, or opens only under the
//! node's previous `enc` key, and pairs that miss the node's summand
//! commitment, are refused (400) with nothing stored, and a repeat with
//! other envelopes is refused (409). The receipt check's own refusals are
//! sidecar-tip's (`intake::route`).
//!
//! The packages are written into the node's store directly (no REGISTER and
//! no proof: the route reads only the manifest and the ABI), each after
//! REGISTER's manifest and layout checks. Needs the CRS of
//! `scripts/prepare-data.sh` for the node's registration circuit (a test
//! fails naming what is missing). Run with `--release`.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use common::*;
use serde_json::{Value, json};
use sidecar_core::ErrorClass;
use sidecar_core::bind::Share;
use sidecar_core::derived::Kind;
use sidecar_core::field::{FieldHex, Fr, fr_from_hex};
use sidecar_core::keys::NodeKeys;
use sidecar_core::pipeline::Node;
use sidecar_core::register::Signature;
use sidecar_core::request::Full;
use sidecar_core::store::{MemoryStore, NamespaceRow, PackageRow, Store};
use sidecar_core::{Refusal, schnorr};
use sidecar_node::admin::{self, AdminRequest};
use sidecar_node::client::ApiClient;
use sidecar_node::receipt::NO_TIP_SECTION;
use sidecar_node::receipt::{ReceiptChain, ReceiptConfig, Receipts};
use sidecar_node::server::App;
use sidecar_test_fixtures::receipts::{NS, VK_HASH, abi, manifest, manifest_row, package};
use sidecar_test_fixtures::vectors::{hex_value, node_keys, shared_intake, shared_receipt_client};
use sidecar_tip::chain::rpc::RpcError;
use sidecar_tip::testing::MemoryChain;
use sidecar_tip::{
    QueueLayout, QueueTarget, ReceiptAnswer, ReceiptChainView, ReceiptRequest, Standing,
    StoredReceipt, Transport, chain_request_id, inputs_hash, receipt_message,
    shared_receipt_message, verify_receipt,
};

fn keys() -> NodeKeys {
    use rand::SeedableRng;
    NodeKeys::generate(&mut rand::rngs::StdRng::seed_from_u64(0x7ec))
}

// An intake direct manifest over the on-chain intake's ABI.
fn manifest_direct() -> Value {
    json!({"manifest": 1, "circuit": "swap_direct", "namespace_param": "namespace",
      "state_keys": {"reads": 0, "writes": 0},
      "witness": [
        {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
        {"param": "vk_hash", "from": {"PUBLIC": "vk_hash"}},
        {"param": "in_slots", "from": {"PUBLIC": "in_slots"}},
        {"param": "out_slots", "from": {"PUBLIC": "out_slots"}},
        {"param": "amount_in", "from": {"PUBLIC": "amount_in"}},
        {"param": "direction", "from": {"PUBLIC": "direction"}},
        {"param": "min_out", "from": {"PUBLIC": "min_out"}},
        {"param": "partial_note", "from": {"PUBLIC": "partial_note"}},
        {"param": "user_nonce", "from": {"PUBLIC": "user_nonce"}},
        {"param": "pool", "from": {"SAMPLE": 2}},
        {"param": "r_old", "from": {"SAMPLE": 1}},
        {"param": "r_new", "from": {"SAMPLE": 1}},
        {"param": "nsk_app", "from": {"LOAD": "nsk_app", "slice": [0, 1], "len": 1}}
      ],
      "outputs": [], "state": {}})
}

// testvectors/receipt_route.json: the receipt route on the AMM tip's receipt-intake
// manifest (examples/amm-tip/manifests/amm_swap_tip_receipt.json), whose
// vk_hash and user_nonce are the reserved operands, with the circuit's
// ABI and the vk hash the vector registers it under.
fn route_vector() -> Value {
    let text = std::fs::read_to_string(repo().join("testvectors/receipt_route.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// Write the namespace and its packages into `store`: `swap`
/// (`intake: receipt`), `swap_onchain`, `swap_direct`, the disabled `swap_off`,
/// and `amm_swap_tip_receipt` (the example's receipt-intake manifest). The
/// contract manifest row they belong to is the receipt-intake package's
/// alone, under a stale period of 50 blocks: the route reads only its stale
/// period, and the store does not compare the document with the package
/// rows.
fn seed<S: Store>(store: &S) {
    let mut txn = store.begin(Fr::from(NS));
    txn.register_namespace(NamespaceRow {
        owner_pubkey: schnorr::public_key(sidecar_core::grumpkin::Fq::from(9u64)),
        nsk_app: Default::default(),
        npk_app_hash: Fr::from(1u64),
        seq: 0,
    });
    let route = route_vector();
    let text = std::fs::read_to_string(repo().join(route["manifest"].as_str().unwrap())).unwrap();
    let row = manifest_row(
        &[("amm_swap_tip_receipt", serde_json::from_str(&text).unwrap())],
        Some(50),
    );
    txn.put_manifest(row.clone());
    txn.put_package(PackageRow {
        name: "amm_swap_tip_receipt".into(),
        manifest_hash: row.manifest_hash,
        circuit_json: serde_json::to_vec(&json!({"abi": route["abi"]})).unwrap(),
        manifest: serde_json::from_str(&text).unwrap(),
        vk: vec![],
        vk_hash: fr_from_hex(route["vk_hash"].as_str().unwrap()).unwrap(),
        disabled: false,
        seq: 0,
    });
    for (name, manifest, abi, disabled) in [
        ("swap", manifest("receipt"), abi(), false),
        ("swap_onchain", manifest("onchain"), abi(), false),
        ("swap_direct", manifest_direct(), abi(), false),
        ("swap_off", manifest("receipt"), abi(), true),
    ] {
        txn.put_package(package(name, manifest, abi, disabled, &row));
    }
    store.commit(txn).unwrap();
    seed_shared(store);
}

/// The vector's namespace with its one package, `shared_receipt_round`
/// (`intake: shared_receipt`), written as REGISTER would write it, so the
/// test needs no REGISTER round trip.
fn seed_shared<S: Store>(store: &S) {
    let v = shared_intake();
    let mut txn = store.begin(hex_value(&v["namespace"]));
    txn.register_namespace(NamespaceRow {
        owner_pubkey: schnorr::public_key(sidecar_core::grumpkin::Fq::from(9u64)),
        nsk_app: Default::default(),
        npk_app_hash: Fr::from(1u64),
        seq: 0,
    });
    let text = std::fs::read_to_string(repo().join(v["manifest"].as_str().unwrap())).unwrap();
    let manifest: Value = serde_json::from_str(&text).unwrap();
    let row = manifest_row(&[(v["circuit"].as_str().unwrap(), manifest)], Some(50));
    txn.put_manifest(row.clone());
    txn.put_package(PackageRow {
        name: v["circuit"].as_str().unwrap().into(),
        manifest_hash: row.manifest_hash,
        circuit_json: serde_json::to_vec(&json!({"abi": v["abi"]})).unwrap(),
        manifest: serde_json::from_str(&text).unwrap(),
        vk: vec![],
        vk_hash: hex_value(&v["vk_hash"]),
        disabled: false,
        seq: 0,
    });
    store.commit(txn).unwrap();
}

/// The client's body of the vector's request.
fn shared_request() -> ReceiptRequest<Full> {
    sidecar_core::error::parse_json(&shared_receipt_client().to_string()).unwrap()
}

/// Node `i`'s body of the vector's request, with the vector's expiry.
fn shared_body(i: usize) -> Value {
    let mut req = shared_request();
    req.expiry_block = Some(1300);
    serde_json::to_value(req.project(i)).unwrap()
}

struct Fixture {
    _tmp: TempDir,
    node: Started,
    client: ApiClient,
}

/// The chain view the route tests sign under: the block the body claims
/// stands for the node's own Aztec node's, and no queue is read.
struct ClaimedBlock;

impl ReceiptChain for ClaimedBlock {
    fn current_block(&self, claimed: u32) -> Result<u32, Refusal> {
        Ok(claimed)
    }

    fn settled(&self) -> Result<Option<u64>, Refusal> {
        Ok(None)
    }

    fn standings(
        &self,
        _: &dyn sidecar_core::pipeline::VerifierRows,
        _: u64,
        _: Fr,
        _: &[Fr],
    ) -> Result<Option<Vec<Standing>>, Refusal> {
        Ok(None)
    }
}

/// A node whose chain is at the block each body claims.
async fn fixture(label: &str) -> Fixture {
    fixture_with(label, claimed_block()).await
}

fn claimed_block() -> Receipts {
    Receipts::with_chain(ReceiptConfig::default(), Arc::new(ClaimedBlock))
}

async fn fixture_with(label: &str, receipts: Receipts) -> Fixture {
    fixture_on(label, 0, keys(), receipts).await
}

/// Node `i` with `keys`.
async fn fixture_on(label: &str, i: usize, keys: NodeKeys, receipts: Receipts) -> Fixture {
    fixture_master(label, i, keys, Default::default(), receipts).await
}

/// Node `i` with `keys` and the master share `master`.
async fn fixture_master(
    label: &str,
    i: usize,
    keys: NodeKeys,
    master: Share,
    receipts: Receipts,
) -> Fixture {
    let crs = require_crs(&[]);
    let tmp = TempDir::new(label);
    let certs = dev_certs(tmp.path());
    let mesh = meshes().into_iter().nth(i).unwrap();
    let node = Node::new(i, keys, master, MemoryStore::new(), crs).unwrap();
    seed(&node.store);
    let files = key_files(&tmp.path().join(format!("keys{i}")), &node.keys());
    let app = App::new(node, mesh, rotation(files)).with_receipts(receipts);
    let node = serve_app(app, &certs, tmp.path()).await;
    let client = orchestrator(&certs, &node);
    Fixture {
        _tmp: tmp,
        node,
        client,
    }
}

/// The namespace's queue in the in-memory Aztec node.
fn queue() -> QueueTarget {
    QueueTarget {
        contract: Fr::from(NS),
        layout: QueueLayout::new(Fr::from(12u64)),
    }
}

/// The node's own Aztec node, which a test can silence.
struct Aztec {
    chain: Arc<MemoryChain>,
    down: AtomicBool,
}

impl Aztec {
    fn new(tip: u64) -> Arc<Self> {
        Arc::new(Aztec {
            chain: Arc::new(MemoryChain::new(tip)),
            down: AtomicBool::new(false),
        })
    }

    /// Enqueue `ids` from index 0 with the head at `head`, each seen, and
    /// `done` written below the head (applied).
    fn queue(&self, ids: &[Fr], head: u64) {
        let q = queue();
        self.chain.write_queue(q.contract, q.layout, ids, head, 0);
        for (index, id) in ids.iter().enumerate() {
            self.chain
                .set_storage(q.contract, q.layout.seen(*id), Fr::from(1u64));
            let done = if (index as u64) < head { 1u64 } else { 0 };
            self.chain
                .set_storage(q.contract, q.layout.done(index as u64), Fr::from(done));
        }
    }
}

impl Transport for Aztec {
    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        if self.down.load(Ordering::SeqCst) {
            return Err(RpcError::Transport("connection refused".into()));
        }
        self.chain.call(method, params).await
    }
}

/// A node with `[tip]`: its chain view reads `aztec`.
async fn chain_fixture(label: &str, aztec: &Arc<Aztec>) -> Fixture {
    let view = ReceiptChainView::new(aztec.clone(), [Fr::from(NS)]).unwrap();
    let chain: Arc<dyn ReceiptChain> = Arc::new(view);
    fixture_with(label, Receipts::with_chain(ReceiptConfig::default(), chain)).await
}

fn body(circuit: &str, inputs: Value, nonce: &str, current: u32, expiry: Option<u32>) -> Value {
    let mut body = json!({
        "namespace": FieldHex::from(NS),
        "circuit": circuit,
        "inputs": inputs,
        "user_nonce": nonce,
        "current_block": current,
    });
    if let Some(expiry) = expiry {
        body["expiry_block"] = expiry.into();
    }
    body
}

fn swap(nonce: &str, current: u32, expiry: u32) -> Value {
    body(
        "swap",
        json!({"amount_in": "0x1388", "direction": "0x1", "min_out": "0x0fa0", "partial_note": "0x9a"}),
        nonce,
        current,
        Some(expiry),
    )
}

impl Fixture {
    async fn post(&self, body: &Value) -> Result<ReceiptAnswer, Refusal> {
        self.client
            .post("/v1/receipt", body)
            .await
            .unwrap()
            .json()
            .unwrap()
    }

    async fn stored(&self, request_id: Fr) -> Result<StoredReceipt, Refusal> {
        self.stored_under(Fr::from(NS), request_id).await
    }

    async fn stored_under(&self, namespace: Fr, request_id: Fr) -> Result<StoredReceipt, Refusal> {
        self.client
            .get(&format!(
                "/v1/receipt/{}/{}",
                FieldHex(namespace),
                FieldHex(request_id)
            ))
            .await
            .unwrap()
            .json()
            .unwrap()
    }

    async fn prune(&self) -> admin::AdminResponse {
        admin::call_async(self.node.running.admin_socket.clone(), AdminRequest::Prune)
            .await
            .unwrap()
    }

    /// Move the node's settled block (the finalized tip, as its own chain
    /// view reads it) to `block`: the view reads the proven tip at `block`,
    /// then the proven tip moves one past it, which finalizes `block` (the
    /// in-memory node's finalized tip trails the proven tip by one proof),
    /// and the next run's read sees it. The proposed tip stays ahead of
    /// both.
    async fn settle(&self, aztec: &Aztec, block: u64) {
        aztec.chain.set_tip(aztec.chain.node().tip().max(block + 1));
        aztec.chain.node().set_proven(block);
        let app = self.node.app.clone();
        let read = tokio::task::spawn_blocking(move || app.receipts.chain.settled());
        read.await.unwrap().unwrap();
        aztec.chain.node().set_proven(block + 1);
    }

    /// Prune and answer (pruned, kept) receipts, or the reason none were.
    async fn prune_receipts(&self) -> Result<(usize, usize), String> {
        let answer = self.prune().await;
        assert!(answer.ok, "{answer:?}");
        match (answer.pruned_receipts, answer.kept_receipts) {
            (Some(pruned), Some(kept)) => Ok((pruned, kept)),
            _ => Err(answer.receipts_not_pruned.expect("a reason")),
        }
    }

    async fn has(&self, request_id: Fr) -> bool {
        match self.stored(request_id).await {
            Ok(_) => true,
            Err(r) if r.class == ErrorClass::NotFound => false,
            Err(r) => panic!("{r}"),
        }
    }

    fn store(&self) -> &MemoryStore {
        &self.node.app.node.store
    }
}

fn refused(result: Result<ReceiptAnswer, Refusal>, class: ErrorClass, needle: &str) {
    let err = result.unwrap_err();
    assert_eq!(err.class, class, "{err}");
    assert!(err.message.contains(needle), "`{err}` lacks `{needle}`");
}

/// A receipt is signed over poseidon2(RECEIPT_DOMAIN, request_id,
/// inputs_hash, expiry_block) with the node's `sig` key, for the content
/// request id the contract computes; the GET serves the stored inputs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receipt_is_signed_verifiable_and_served() {
    let fx = fixture("rcpt-sign").await;
    let answer = fx.post(&swap("0x01", 1000, 1300)).await.unwrap();
    let inputs = [
        Fr::from(5000u64),
        Fr::from(1u64),
        Fr::from(4000u64),
        Fr::from(0x9au64),
    ];
    let id = chain_request_id(Fr::from(NS), Fr::from(VK_HASH), &inputs, Fr::from(1u64));
    assert_eq!(answer.request_id.fr(), id);
    assert_eq!(answer.inputs_hash.fr(), inputs_hash(&inputs));
    assert_eq!(answer.expiry_block, 1300);
    let sig_pk = keys().sig_pk();
    assert!(verify_receipt(
        sig_pk,
        answer.signature,
        id,
        answer.inputs_hash.fr(),
        1300
    ));
    assert!(schnorr::verify(
        sig_pk,
        answer.signature,
        receipt_message(id, answer.inputs_hash.fr(), 1300)
    ));
    // the node's key is the one GET /v1/nodes serves
    let served: sidecar_core::response::NodePublicKeys = fx
        .client
        .get("/v1/nodes")
        .await
        .unwrap()
        .json()
        .unwrap()
        .unwrap();
    assert_eq!(served.sig, sidecar_core::grumpkin::point_to_wire(sig_pk));

    let stored = fx.stored(id).await.unwrap();
    assert_eq!(stored.namespace, FieldHex::from(NS));
    assert_eq!(stored.request_id.fr(), id);
    assert_eq!(stored.circuit, "swap");
    assert_eq!(stored.vk_hash, FieldHex::from(VK_HASH));
    assert_eq!(
        stored.inputs.iter().map(|f| f.fr()).collect::<Vec<_>>(),
        inputs
    );
    assert_eq!(stored.inputs_hash, answer.inputs_hash);
    assert_eq!(stored.user_nonce, Some(FieldHex::from(1)));
    assert!(stored.shared_inputs.is_empty());
    assert_eq!((stored.expiry_block, stored.stale_blocks), (1300, Some(50)));
    assert_eq!(stored.signature, answer.signature);
    // another nonce is another request
    let other = fx.post(&swap("0x02", 1000, 1300)).await.unwrap();
    assert_ne!(other.request_id, answer.request_id);
    assert_eq!(
        fx.stored(Fr::from(7u64)).await.unwrap_err().class,
        ErrorClass::NotFound
    );
}

/// On the AMM tip's receipt-intake manifest the node hashes the four app
/// inputs only (the swap's three and the partial note; vk_hash and
/// user_nonce are reserved operands), takes vk_hash from
/// the package, and refuses a body that supplies either, or names a
/// requester.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_route_hashes_the_app_inputs_and_fills_vk_hash_itself() {
    let fx = fixture("rcpt-reserved").await;
    let route = route_vector();
    let f = |v: &Value| fr_from_hex(v.as_str().unwrap()).unwrap();
    let inputs: Vec<Fr> = route["inputs"].as_array().unwrap().iter().map(f).collect();
    assert_eq!(inputs, [5000u64, 1, 4000, 0x5eed].map(Fr::from));
    let nonce = route["body"]["user_nonce"].as_str().unwrap();
    let req = body(
        "amm_swap_tip_receipt",
        route["body"]["inputs"].clone(),
        nonce,
        1000,
        Some(1300),
    );
    let answer = fx.post(&req).await.unwrap();
    assert_eq!(answer.inputs_hash.fr(), f(&route["inputs_hash"]));
    let vk_hash = f(&route["vk_hash"]);
    let id = chain_request_id(Fr::from(NS), vk_hash, &inputs, fr_from_hex(nonce).unwrap());
    assert_eq!(answer.request_id.fr(), id);
    assert!(verify_receipt(
        keys().sig_pk(),
        answer.signature,
        id,
        answer.inputs_hash.fr(),
        1300
    ));
    let stored = fx.stored(id).await.unwrap();
    assert_eq!(stored.vk_hash.fr(), vk_hash);
    // the hidden requester: neither the body nor the stored receipt names
    // an address
    let audit = sidecar_tip::audit::Requesters::new([fr_from_hex(
        "0x0b7e3a1f00c0ffee00000000000000000000000000000000000000000000beef",
    )
    .unwrap()]);
    audit.assert_absent_in("receipt body", &req);
    audit.assert_absent_in("stored receipt", &stored);
    assert_eq!(
        stored.inputs.iter().map(|x| x.fr()).collect::<Vec<_>>(),
        inputs
    );

    // a body naming vk_hash is refused (the node fills it), and so is one
    // naming a reserved value among its inputs; nothing more is stored
    let before = fx.store().snapshot();
    let mut with_vk = req.clone();
    with_vk["vk_hash"] = json!("0x01");
    refused(
        fx.post(&with_vk).await,
        ErrorClass::BadRequest,
        "unknown field `vk_hash`",
    );
    let mut with_user = req.clone();
    with_user["user"] = json!("0xbeef");
    refused(
        fx.post(&with_user).await,
        ErrorClass::BadRequest,
        "unknown field `user`",
    );
    for name in ["vk_hash", "user", "user_nonce"] {
        let mut extra = req.clone();
        extra["user_nonce"] = json!("0x77");
        extra["inputs"][name] = json!("0x01");
        refused(
            fx.post(&extra).await,
            ErrorClass::BadRequest,
            &format!("field `inputs.{name}`: unexpected"),
        );
    }
    assert_eq!(
        fx.store().snapshot(),
        before,
        "a refused receipt stored something"
    );
}

/// Every refusal comes before anything is stored or signed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_requests_are_refused_and_nothing_is_stored() {
    let fx = fixture("rcpt-bad").await;
    let before = fx.store().snapshot();
    let swap_with = |inputs: Value| body("swap", inputs, "0x01", 1000, Some(1300));
    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "a bool out of range",
            swap_with(
                json!({"amount_in": "0x1388", "direction": "0x2", "min_out": "0x0fa0", "partial_note": "0x9a"}),
            ),
            "does not fit in 1 bit",
        ),
        (
            "a missing input",
            swap_with(json!({"amount_in": "0x1388"})),
            "field `inputs.direction`: missing",
        ),
        (
            "an extra input",
            swap_with(
                json!({"amount_in": "0x1", "direction": "0x0", "min_out": "0x0", "partial_note": "0x9a", "pool": "0x1"}),
            ),
            "field `inputs.pool`: unexpected",
        ),
        (
            "an intake: direct package",
            body(
                "swap_direct",
                json!({"amount_in": "0x1", "direction": "0x0", "min_out": "0x0fa0", "partial_note": "0x9a"}),
                "0x01",
                1000,
                Some(1300),
            ),
            "`intake: direct`",
        ),
        (
            "an intake: onchain package",
            body(
                "swap_onchain",
                json!({"amount_in": "0x1", "direction": "0x0", "min_out": "0x0fa0", "partial_note": "0x9a"}),
                "0x01",
                1000,
                Some(1300),
            ),
            "`intake: onchain`",
        ),
        (
            "an unknown circuit",
            body("nope", json!({}), "0x01", 1000, Some(1300)),
            "is not registered",
        ),
        (
            "a disabled circuit",
            body(
                "swap_off",
                json!({"amount_in": "0x1", "direction": "0x0", "min_out": "0x0fa0", "partial_note": "0x9a"}),
                "0x01",
                1000,
                Some(1300),
            ),
            "is disabled",
        ),
        (
            "no expiry",
            body(
                "swap",
                json!({"amount_in": "0x1", "direction": "0x0", "min_out": "0x0fa0", "partial_note": "0x9a"}),
                "0x01",
                1000,
                None,
            ),
            "field `expiry_block`: missing",
        ),
        (
            "an expiry at the current block",
            swap("0x01", 1000, 1000),
            "not after",
        ),
        (
            "an expiry too far ahead",
            swap("0x01", 1000, 1311),
            "at most 310 ahead",
        ),
    ];
    for (what, body, needle) in cases {
        let err = fx.post(&body).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "{what}: {err}");
        assert!(
            err.message.contains(needle),
            "{what}: `{err}` lacks `{needle}`"
        );
    }
    // a body that is not a receipt request
    let answer = fx
        .client
        .post_raw("/v1/receipt", r#"{"namespace": "0x1"}"#)
        .await
        .unwrap();
    assert_eq!(answer.status, 400);
    assert_eq!(
        fx.store().snapshot(),
        before,
        "a refused receipt stored something"
    );
    // the bound is TTL plus allowance: 310 blocks ahead is signed
    fx.post(&swap("0x01", 1000, 1310)).await.unwrap();
    assert_ne!(fx.store().snapshot(), before);
}

/// The same inputs twice: the same request id and the stored answer; a
/// later expiry re-signs and replaces the row; an earlier one is 409.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_receipt_is_idempotent_and_may_only_extend() {
    let fx = fixture("rcpt-twice").await;
    let first = fx.post(&swap("0x05", 1000, 1300)).await.unwrap();
    let again = fx.post(&swap("0x05", 1000, 1300)).await.unwrap();
    assert_eq!(again, first);
    // the same expiry from a later current block is the same receipt
    assert_eq!(fx.post(&swap("0x05", 1100, 1300)).await.unwrap(), first);
    let id = first.request_id.fr();
    // a later expiry: a new signature, the row follows
    let later = fx.post(&swap("0x05", 1200, 1500)).await.unwrap();
    assert_eq!(later.request_id, first.request_id);
    assert_eq!(later.expiry_block, 1500);
    assert_ne!(later.signature, first.signature);
    assert!(verify_receipt(
        keys().sig_pk(),
        later.signature,
        id,
        later.inputs_hash.fr(),
        1500
    ));
    let stored = fx.stored(id).await.unwrap();
    assert_eq!(
        (stored.expiry_block, stored.signature),
        (1500, later.signature)
    );
    // an earlier one is refused and changes nothing
    refused(
        fx.post(&swap("0x05", 1200, 1400)).await,
        ErrorClass::Conflict,
        "later expiry 1500",
    );
    assert_eq!(fx.stored(id).await.unwrap(), stored);
}

/// A node without `[tip]` refuses every receipt request, under either
/// intake, naming why, and stores nothing; its pruning prunes nothing and
/// says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_tip_no_receipt_is_signed_or_pruned() {
    let fx = fixture_with("rcpt-notip", Receipts::default()).await;
    for body in [swap("0x01", 1000, 1300), shared_body(0)] {
        let err = fx.post(&body).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
        assert_eq!(err.message, NO_TIP_SECTION);
    }
    let answer = fx.prune().await;
    assert!(answer.ok);
    assert_eq!((answer.pruned, answer.pruned_receipts), (Some(0), None));
    let why = answer.receipts_not_pruned.unwrap();
    assert!(why.contains("no [tip] section"), "{why}");
    let plain = chain_request_id(
        Fr::from(NS),
        Fr::from(VK_HASH),
        &[
            Fr::from(5000u64),
            Fr::from(1u64),
            Fr::from(4000u64),
            Fr::from(0x9au64),
        ],
        Fr::from(1u64),
    );
    assert!(!fx.has(plain).await);
    let v = shared_intake();
    let shared = fx
        .stored_under(
            hex_value(&v["namespace"]),
            hex_value(&v["chain_request_id"]),
        )
        .await;
    assert_eq!(shared.unwrap_err().class, ErrorClass::NotFound);
}

/// Each node signs the vector's receipt over C and the sharing digest D,
/// byte for byte (the derived nonce), after its pairs and salts passed its
/// check against the summand commitments, and it verifies under the node's
/// `sig` key; the row it keeps holds the clear input, C, its own envelopes
/// of the circuit's shared inputs and the three share hashes, and no salts'
/// envelope, plaintext shared value, share, salt or requester.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_receipt_signs_c_as_the_vector_does() {
    let v = shared_intake();
    let namespace = hex_value(&v["namespace"]);
    let id = hex_value(&v["chain_request_id"]);
    let c = hex_value(&v["inputs_commitment"]);
    let d = hex_value(&v["sharing_digest"]);
    let request = shared_request();
    // every plaintext the client shared, and every node's pair of it
    let mut secrets: Vec<Fr> = v["values"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(name, _)| *name != "position")
        .map(|(_, value)| hex_value(value))
        .collect();
    for envelope in v["envelopes"].as_array().unwrap() {
        for node in envelope["nodes"].as_array().unwrap() {
            secrets.extend(node["pair"].as_array().unwrap().iter().map(hex_value));
        }
    }
    for i in 0..3 {
        let fx = fixture_on(
            &format!("rcpt-shared{i}"),
            i,
            node_keys()[i].clone(),
            claimed_block(),
        )
        .await;
        let answer = fx.post(&shared_body(i)).await.unwrap();
        assert_eq!(answer.request_id.fr(), id);
        assert_eq!(answer.inputs_hash.fr(), c);
        assert_eq!(answer.expiry_block, 1300);
        let want: Signature =
            serde_json::from_value(v["receipt"]["signatures"][i].clone()).unwrap();
        assert_eq!(answer.signature, want, "node {i}");
        // never a pair or a salt
        let answered = serde_json::to_string(&answer).unwrap();
        for secret in &secrets {
            assert!(!answered.contains(&FieldHex(*secret).to_string()));
        }
        let message = shared_receipt_message(id, c, 1300, d);
        assert_eq!(message, hex_value(&v["receipt"]["message"]));
        assert!(sidecar_core::schnorr::verify(
            node_keys()[i].sig_pk(),
            answer.signature,
            message
        ));
        // not a receipt over C alone
        assert!(!verify_receipt(
            node_keys()[i].sig_pk(),
            answer.signature,
            id,
            c,
            1300
        ));

        let stored = fx.stored_under(namespace, id).await.unwrap();
        assert_eq!(stored.inputs, [FieldHex::from(7)]);
        assert_eq!(stored.inputs_hash.fr(), c);
        assert_eq!(stored.user_nonce, None);
        let mut kept = request.project(i).shared_inputs;
        assert_eq!(kept.pop().unwrap().name, sidecar_tip::SUMMAND_SALT);
        assert_eq!(stored.shared_inputs, kept);
        // the row itself: every field is the clear input, C, an id, the
        // expiry, the signature or this node's envelopes and hashes
        let row = fx.store().receipt(namespace, id).unwrap().unwrap();
        assert_eq!(row.inputs, [Fr::from(7u64)]);
        assert_eq!(row.user_nonce, None);
        assert_eq!(row.shares, stored.shared_inputs);
        assert_eq!(row.signature, answer.signature);
        let text = serde_json::to_string(&stored).unwrap();
        for secret in &secrets {
            assert!(
                !text.contains(&FieldHex(*secret).to_string()),
                "node {i} keeps a plaintext {secret}"
            );
        }
        for word in ["user", "requester"] {
            assert!(!text.contains(word), "node {i}'s row names a {word}");
        }
        // the same body again: the same answer
        assert_eq!(fx.post(&shared_body(i)).await.unwrap(), answer);
    }
}

/// Set a shared receipt body's sharing digest to the one over its summand
/// commitments, the vector's layout and the body's clear position.
fn redigest(b: &mut Value) {
    let v = shared_intake();
    let kinds: Vec<Kind> = v["value_kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            if hex_value(k) == Fr::from(0u64) {
                Kind::Clear
            } else {
                Kind::Chosen
            }
        })
        .collect();
    let commitments: [Fr; 3] = std::array::from_fn(|k| hex_value(&b["summand_commitments"][k]));
    let clear = [hex_value(&b["inputs"]["position"])];
    b["sharing_digest"] = json!(FieldHex(sidecar_tip::sharing_digest(
        &commitments,
        &kinds,
        &clear
    )));
}

/// An envelope that does not hash to this node's share hash, one sealed to
/// another node or under another C (another chain request), a summand
/// commitment this node's pairs and salts miss (with a consistent digest),
/// one sealed to the node's previous `enc` key, and a repeat under the same
/// C with other envelopes or clear inputs are refused, all but the repeat
/// with nothing stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bad_shared_receipt_is_refused() {
    let v = shared_intake();
    let namespace = hex_value(&v["namespace"]);
    let id = hex_value(&v["chain_request_id"]);
    let fx = fixture_on(
        "rcpt-shared-bad",
        1,
        node_keys()[1].clone(),
        claimed_block(),
    )
    .await;
    type Edit = fn(&mut Value);
    let cases: [(Edit, &str); 4] = [
        (
            // node 1 holds s_1: it refuses a request whose S_1 misses it
            // (D over the moved commitment)
            |b| {
                b["summand_commitments"][1] = json!(FieldHex(
                    hex_value(&b["summand_commitments"][1]) + Fr::from(1u64)
                ));
                redigest(b);
            },
            "field `summand_commitments[1]`: the summands and salt node 1's envelopes open to do not hash to it",
        ),
        (
            |b| b["shared_inputs"][2]["share_hashes"][1] = json!("0x01"),
            "field `shared_inputs[2]` (`$outcome_key`): the envelope to node 1 does not hash to share_hashes[1]",
        ),
        (
            // node 0's envelopes, under hashes that match them
            |b| {
                let node0 = shared_body(0);
                for (k, input) in b["shared_inputs"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .enumerate()
                {
                    input["share"] = node0["shared_inputs"][k]["share"].clone();
                    input["share_hashes"][1] = node0["shared_inputs"][k]["share_hashes"][0].clone();
                }
            },
            "shared input `amount`: the envelope to node 1 does not decrypt",
        ),
        (
            // another C: another chain request id, so another associated data
            |b| b["inputs_hash"] = json!("0x01"),
            "shared input `amount`: the envelope to node 1 does not decrypt",
        ),
    ];
    for (edit, needle) in cases {
        let mut body = shared_body(1);
        edit(&mut body);
        refused(fx.post(&body).await, ErrorClass::BadRequest, needle);
    }
    let err = fx.stored_under(namespace, id).await.unwrap_err();
    assert_eq!(err.class, ErrorClass::NotFound);

    // stored once; then the same C with other clear inputs (and the D over
    // them), or with node 1's pair of `amount` sealed again under a fresh
    // ephemeral key: 409
    fx.post(&shared_body(1)).await.unwrap();
    let stored = fx.stored_under(namespace, id).await.unwrap();
    let mut other_inputs = shared_body(1);
    other_inputs["inputs"]["position"] = json!("0x08");
    redigest(&mut other_inputs);
    let pair = v["envelopes"][0]["nodes"][1]["pair"]
        .as_array()
        .unwrap()
        .iter()
        .map(hex_value)
        .collect::<Vec<_>>();
    let ad = sidecar_core::envelope::EnvelopeAd::for_intake(
        namespace,
        id,
        "shared_receipt_round",
        "amount",
    );
    let resealed = sidecar_core::envelope::seal_envelope_with(
        node_keys()[1].enc_pk(),
        1,
        &ad,
        [pair[0], pair[1]],
        Fr::from(0x5eedu64),
    );
    let mut other_envelope = shared_body(1);
    other_envelope["shared_inputs"][0]["share"] = serde_json::to_value(resealed).unwrap();
    other_envelope["shared_inputs"][0]["share_hashes"][1] = json!(FieldHex(resealed.hash()));
    for body in [other_inputs, other_envelope] {
        refused(
            fx.post(&body).await,
            ErrorClass::Conflict,
            "is stored with other clear inputs or envelopes",
        );
    }
    assert_eq!(fx.stored_under(namespace, id).await.unwrap(), stored);

    // the node rotates its enc key (now, so its grace window runs): the
    // vector's envelopes now open only under the previous key, and a node
    // keeps no envelope it may not open after the grace window
    let rotated = node_keys()[1]
        .clone()
        .rotate_enc(
            sidecar_core::grumpkin::Fq::from(0x0e1cu64),
            sidecar_core::pipeline::unix_now(),
        )
        .unwrap();
    let fx = fixture_on("rcpt-shared-rot", 1, rotated, claimed_block()).await;
    refused(
        fx.post(&shared_body(1)).await,
        ErrorClass::BadRequest,
        "shared input `amount`: the envelope to node 1 is sealed to this node's previous enc key",
    );
    let err = fx.stored_under(namespace, id).await.unwrap_err();
    assert_eq!(err.class, ErrorClass::NotFound);
}

/// With the node's own chain view: the signer takes the chain's block, not
/// the body's; past `expiry_block + stale_blocks` (the manifest's 50) a
/// receipt whose request never reached the queue is pruned, a done one is
/// pruned, and a queued one keeps its inputs, behind any backlog, until
/// `done` is written for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pruning_keeps_a_queued_request_until_it_is_done() {
    let aztec = Aztec::new(1000);
    let fx = chain_fixture("rcpt-queued", &aztec).await;
    // the body's claimed block is ignored: the chain is at 1000
    refused(
        fx.post(&swap("0x09", 9000, 9300)).await,
        ErrorClass::BadRequest,
        "after the current block 1000",
    );
    let queued = fx.post(&swap("0x01", 0, 1300)).await.unwrap(); // window to 1350
    let never = fx.post(&swap("0x02", 0, 1300)).await.unwrap();
    let done = fx.post(&swap("0x03", 0, 1300)).await.unwrap();
    let late = fx.post(&swap("0x04", 0, 1310)).await.unwrap(); // window to 1360
    let [queued, never, done, late] = [queued, never, done, late].map(|a| a.request_id.fr());
    // the queue: done applied at index 0, then a backlog, then queued
    let backlog: Vec<Fr> = (0..6u64).map(|n| Fr::from(0xb000 + n)).collect();
    let mut ids = vec![done];
    ids.extend(&backlog);
    ids.push(queued);
    aztec.queue(&ids, 1);

    // windows are counted at the settled block: the proposed tip past every
    // window lists nothing while the settled block is inside them
    aztec.chain.set_tip(1400);
    assert_eq!(fx.prune_receipts().await, Ok((0, 0)));
    fx.settle(&aztec, 1350).await;
    assert_eq!(fx.prune_receipts().await, Ok((0, 0)));
    // one block past: never-queued and done go, queued stays
    fx.settle(&aztec, 1351).await;
    assert_eq!(fx.prune_receipts().await, Ok((2, 1)));
    assert!(!fx.has(never).await && !fx.has(done).await);
    assert!(fx.has(queued).await && fx.has(late).await);
    // long past its window, still behind the backlog: kept
    fx.settle(&aztec, 5000).await;
    assert_eq!(fx.prune_receipts().await, Ok((1, 1)));
    assert!(fx.has(queued).await && !fx.has(late).await);
    // the backlog is served and queued becomes the head: still kept
    aztec.queue(&ids, 7);
    assert_eq!(fx.prune_receipts().await, Ok((0, 1)));
    let stored = fx.stored(queued).await.unwrap();
    assert_eq!(stored.request_id.fr(), queued);
    // done[7] written (the head moves past it) in a proposed block above the
    // settled block, which a replacement may still drop: kept
    let q = queue();
    aztec
        .chain
        .set_storage_at(5003, q.contract, q.layout.head_index(), Fr::from(8u64));
    aztec
        .chain
        .set_storage_at(5003, q.contract, q.layout.done(7), Fr::from(1u64));
    aztec.chain.set_tip(5010);
    assert_eq!(fx.prune_receipts().await, Ok((0, 1)));
    // the settled block passes it: pruned
    fx.settle(&aztec, 5010).await;
    assert_eq!(fx.prune_receipts().await, Ok((1, 0)));
    assert!(!fx.has(queued).await);
}

/// The pruning job's node-held half, on a key no round commits on: rounds
/// at block 100 leave A canonical in the pool slot and B and B' live on it;
/// on the chain B' lands and the head moves past their entry. Each run marks
/// the key against the node's own chain view (the slot and the head) and
/// deletes the orphans only once the settled block is
/// past the block they were first marked orphan at, however far ahead the
/// proposed tip runs; a run whose chain view does not answer changes
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pruning_marks_and_prunes_an_idle_node_held_key() {
    use sidecar_core::store::StoreRead;
    use sidecar_core::store::VersionStatus::{Canonical, Live, Orphan};
    use sidecar_core::store::rules::{self, VersionView};
    use sidecar_core::store::testing::{new_request, version};
    let aztec = Aztec::new(100);
    let fx = chain_fixture("rcpt-versions", &aztec).await;
    let (store, ns) = (&fx.node.app.node.store, Fr::from(NS));
    let (pool, slot) = ("0xa002", Fr::from(0xa002u64));
    let (a, b, b2) = (0xa0u64, 0xb0u64, 0xb2u64);
    for (n, v, slot_c, head) in [
        (1u8, version(pool, a, 0, 0, 1), 0u64, 0u64),
        (2, version(pool, b, a, 1, 2), a, 1),
        (3, version(pool, b2, a, 1, 3), a, 1),
    ] {
        let mut txn = store.begin(ns);
        let view = VersionView {
            slot: Fr::from(slot_c),
            head,
            block: 100,
            settled: 90,
            ..Default::default()
        };
        rules::stage_versions(store, &mut txn, pool, Some(v), &view).unwrap();
        txn.put_request(new_request(n, 1000 + n as u64));
        store.commit(txn).unwrap();
    }
    let held = || -> Vec<(Fr, _, u64)> {
        store
            .tip_versions(ns, pool)
            .unwrap()
            .into_iter()
            .map(|v| (v.commitment, v.status, v.block))
            .collect()
    };
    let f = Fr::from;
    assert_eq!(
        held(),
        [
            (f(a), Canonical, 100),
            (f(b), Live, 100),
            (f(b2), Live, 100)
        ]
    );
    let prune_versions = || async {
        let answer = fx.prune().await;
        assert!(answer.ok, "{answer:?}");
        answer.pruned_versions.expect("the versions' count")
    };

    // B' lands at 120 and the head moves past entry 1
    let q = queue();
    aztec
        .chain
        .write_queue(q.contract, q.layout, &[f(1), f(2)], 2, 120);
    aztec.chain.set_storage(q.contract, slot, f(b2));
    aztec.chain.set_tip(130);
    aztec.chain.node().set_proven(110);
    assert_eq!(prune_versions().await, 0);
    assert_eq!(
        held(),
        [
            (f(a), Orphan, 130),
            (f(b), Orphan, 130),
            (f(b2), Canonical, 130)
        ]
    );
    // the proposed tip far ahead, the proven tip at the orphans' block (the
    // one before it 110): kept
    let far = 300;
    aztec.chain.set_tip(far);
    aztec.chain.node().set_proven(130);
    assert_eq!(prune_versions().await, 0);
    assert_eq!(held().len(), 3);
    // the proven tip moves on, but a silent Aztec node: nothing changes
    aztec.chain.node().set_proven(131);
    aztec.down.store(true, Ordering::SeqCst);
    assert_eq!(prune_versions().await, 0);
    assert_eq!(held().len(), 3);
    // answering again: the settled block is 130, the orphans' own
    // block, so they are kept until it passes them
    aztec.down.store(false, Ordering::SeqCst);
    assert_eq!(prune_versions().await, 0);
    assert_eq!(held().len(), 3);
    aztec.chain.node().set_proven(140);
    assert_eq!(prune_versions().await, 2);
    assert_eq!(held(), [(f(b2), Canonical, far)]);
}

/// A node whose Aztec node does not answer keeps every receipt (and says
/// why) and signs none; once it answers again the pruning resumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_chain_view_keeps_every_receipt() {
    let aztec = Aztec::new(1000);
    let fx = chain_fixture("rcpt-down", &aztec).await;
    let never = fx
        .post(&swap("0x01", 0, 1300))
        .await
        .unwrap()
        .request_id
        .fr();
    aztec.chain.set_tip(2000);
    aztec.down.store(true, Ordering::SeqCst);
    let why = fx.prune_receipts().await.unwrap_err();
    assert!(why.contains("this node's Aztec node"), "{why}");
    assert!(fx.has(never).await);
    refused(
        fx.post(&swap("0x02", 0, 2100)).await,
        ErrorClass::BadRequest,
        "receipt signer: no current block",
    );
    aztec.down.store(false, Ordering::SeqCst);
    fx.settle(&aztec, 2000).await;
    assert_eq!(fx.prune_receipts().await, Ok((1, 0)));
    assert!(!fx.has(never).await);
}
