use super::*;
use crate::error::ErrorClass;
use crate::grumpkin::{fixed_base_mul, scalar_from_field};
use crate::keys::NodeKeys;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;

mod imports;
mod receipts;
mod registry;
mod requests;
mod values;
mod versions;

pub use imports::*;
pub use receipts::*;
pub use registry::*;
pub use requests::*;
pub use values::*;
pub use versions::*;

pub const NS: u64 = 0x1f2e;

/// A store over `S` whose next commit can be made to fail (500, storing
/// nothing), as when a node's database refuses or the node stops at
/// commit while the others commit, and which can answer that it holds
/// no `values` table, as the local store.
#[derive(Default)]
pub struct Flaky<S = MemoryStore> {
    inner: S,
    fail_next_commit: std::sync::atomic::AtomicBool,
    without_values: bool,
}

impl<S> Flaky<S> {
    /// `inner`, whose commits succeed.
    pub fn new(inner: S) -> Self {
        Flaky {
            inner,
            fail_next_commit: Default::default(),
            without_values: false,
        }
    }

    /// `inner`, answering that it holds no `values` table.
    pub fn without_values(inner: S) -> Self {
        Flaky {
            without_values: true,
            ..Self::new(inner)
        }
    }

    /// The wrapped store.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Refuse the next commit (500), storing nothing.
    pub fn fail_next_commit(&self) {
        self.fail_next_commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Flaky<MemoryStore> {
    /// Every table, for comparing before and after a request.
    pub fn snapshot(&self) -> MemorySnapshot {
        self.inner.snapshot()
    }
}

impl<S: StoreRead> StoreRead for Flaky<S> {
    fn namespace(&self, ns: Fr) -> Result<Option<NamespaceRow>, Refusal> {
        self.inner.namespace(ns)
    }
    fn contract_manifest(&self, ns: Fr) -> Result<Option<ManifestRow>, Refusal> {
        self.inner.contract_manifest(ns)
    }
    fn contract_manifests(&self, ns: Fr) -> Result<Vec<ManifestRow>, Refusal> {
        self.inner.contract_manifests(ns)
    }
    fn package_in(&self, ns: Fr, hash: Fr, name: &str) -> Result<Option<PackageRow>, Refusal> {
        self.inner.package_in(ns, hash, name)
    }
    fn package(&self, ns: Fr, name: &str) -> Result<Option<PackageRow>, Refusal> {
        self.inner.package(ns, name)
    }
    fn consumed(&self, ns: Fr, note_hash: Fr) -> Result<Option<ConsumedRow>, Refusal> {
        self.inner.consumed(ns, note_hash)
    }
    fn request(&self, ns: Fr, id: RequestId) -> Result<Option<RequestRow>, Refusal> {
        self.inner.request(ns, id)
    }
    fn value(&self, ns: Fr, key: &str) -> Result<Option<ValueRow>, Refusal> {
        self.inner.value(ns, key)
    }
    fn dead_record(&self, ns: Fr, note_hash: Fr) -> Result<Option<DeadRecord>, Refusal> {
        self.inner.dead_record(ns, note_hash)
    }
    fn tip_version(&self, ns: Fr, key: &str, c: Fr) -> Result<Option<TipVersion>, Refusal> {
        self.inner.tip_version(ns, key, c)
    }
    fn tip_versions(&self, ns: Fr, key: &str) -> Result<Vec<TipVersion>, Refusal> {
        self.inner.tip_versions(ns, key)
    }
    fn tip_node(&self, ns: Fr, key: &str, hash: Fr) -> Result<Option<StoredNode>, Refusal> {
        self.inner.tip_node(ns, key, hash)
    }
    fn blob(&self, ns: Fr, key: &str, name: &str) -> Result<Option<Vec<u8>>, Refusal> {
        self.inner.blob(ns, key, name)
    }
    fn blob_names(&self, ns: Fr, key: &str) -> Result<Vec<String>, Refusal> {
        self.inner.blob_names(ns, key)
    }
    fn chain_request(&self, ns: Fr, chain: Fr) -> Result<Option<RequestRow>, Refusal> {
        self.inner.chain_request(ns, chain)
    }
    fn load_nsk_app(&self, ns: Fr) -> Result<Option<Share>, Refusal> {
        self.inner.load_nsk_app(ns)
    }
}

impl<S: Store> Store for Flaky<S> {
    fn begin(&self, ns: Fr) -> Txn {
        self.inner.begin(ns)
    }
    fn commit(&self, txn: Txn) -> Result<(), Refusal> {
        if self
            .fail_next_commit
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Refusal::mpc_failure(
                "store: the node stopped before commit",
            ));
        }
        self.inner.commit(txn)
    }
    fn prune_requests(&self, older_than: u64) -> Result<usize, Refusal> {
        self.inner.prune_requests(older_than)
    }
    fn holds_values(&self) -> bool {
        !self.without_values && self.inner.holds_values()
    }
    fn namespaces(&self) -> Result<Vec<Fr>, Refusal> {
        self.inner.namespaces()
    }
    fn package_names(&self, ns: Fr) -> Result<Vec<String>, Refusal> {
        self.inner.package_names(ns)
    }
    fn tip_keys(&self, ns: Fr) -> Result<Vec<String>, Refusal> {
        self.inner.tip_keys(ns)
    }
    fn value_keys(&self, ns: Fr) -> Result<Vec<String>, Refusal> {
        self.inner.value_keys(ns)
    }
    fn blob_keys(&self, ns: Fr) -> Result<Vec<String>, Refusal> {
        self.inner.blob_keys(ns)
    }
    fn consumed_rows(&self, ns: Fr) -> Result<Vec<ConsumedRow>, Refusal> {
        self.inner.consumed_rows(ns)
    }
    fn receipts(&self, ns: Fr) -> Result<Vec<ReceiptRow>, Refusal> {
        self.inner.receipts(ns)
    }
    fn requests(&self, ns: Fr) -> Result<Vec<RequestRow>, Refusal> {
        self.inner.requests(ns)
    }
    fn dead_records(&self, ns: Fr) -> Result<Vec<DeadRecord>, Refusal> {
        self.inner.dead_records(ns)
    }
    fn receipt(&self, ns: Fr, id: Fr) -> Result<Option<ReceiptRow>, Refusal> {
        self.inner.receipt(ns, id)
    }
    fn put_receipt(&self, ns: Fr, row: ReceiptRow) -> Result<(), Refusal> {
        self.inner.put_receipt(ns, row)
    }
    fn expired_receipts(&self, block: u64) -> Result<Vec<(Fr, Fr)>, Refusal> {
        self.inner.expired_receipts(block)
    }
    fn prune_receipts(&self, block: u64, ids: &[(Fr, Fr)]) -> Result<usize, Refusal> {
        self.inner.prune_receipts(block, ids)
    }
}

/// How far the test chains' settled block runs behind the block a view is
/// read at: a view at block `b` carries `b - PROVING_LAG` as its settled
/// block (`rules::VersionView::settled`).
pub const PROVING_LAG: u64 = 64;

/// The view at `block` of a slot holding `slot` with the queue's head at
/// `head`, its settled block [`PROVING_LAG`] behind.
pub fn view(slot: u64, head: u64, block: u64) -> rules::VersionView {
    rules::VersionView {
        slot: Fr::from(slot),
        head,
        block,
        settled: block.saturating_sub(PROVING_LAG),
        ..Default::default()
    }
}

pub fn ns() -> Fr {
    Fr::from(NS)
}

pub fn id(n: u8) -> RequestId {
    RequestId::from_u128_bytes([n; 16])
}

/// Node 0's keys of the sample deployment (testvectors/keys.json).
pub fn node_keys() -> NodeKeys {
    NodeKeys::generate(&mut StdRng::seed_from_u64(0x5c4e_6b00))
}

pub fn shared(a: u64) -> Elem {
    Elem::Shared(Share::new(Fr::from(a), Fr::from(a + 1)))
}

pub fn new_request(n: u8, created_at: u64) -> NewRequest {
    NewRequest {
        request_id: id(n),
        body_hash: Fr::from(n as u64),
        vk_hash: Fr::from(0xc1u64),
        proof: vec![n; 4],
        public_inputs: vec![Fr::from(1u64)],
        stored_keys: vec![],
        created_keys: vec![],
        signature: None,
        created_at,
        chain_request_id: None,
    }
}

/// Commit a round `n` that loads `loads`, consumes `consumes` and stores
/// `(key, vec, note_hash)` under the node-held keys of `stores`.
pub fn round<S: Store + ?Sized>(
    store: &S,
    n: u8,
    loads: &[&str],
    consumes: &[Fr],
    stores: &[(&str, Vec<Elem>, Fr)],
) -> Result<(), Refusal> {
    let keys = node_keys();
    let mut txn = store.begin(ns());
    for key in loads {
        txn.loaded(key);
    }
    for note_hash in consumes {
        txn.consume(ConsumedRow {
            note_hash: *note_hash,
            circuit: Fr::from(0xc1u64),
            request_id: id(n),
        });
    }
    let mut request = new_request(n, 1000 + n as u64);
    for (key, vec, note_hash) in stores {
        if store.value(ns(), key)?.is_none() {
            request.created_keys.push(key.to_string());
        }
        rules::stage_store(store, &keys, &mut txn, key, vec.clone(), *note_hash)?;
    }
    request.stored_keys = stores.iter().map(|s| s.0.to_string()).collect();
    txn.put_request(request);
    store.commit(txn)
}

/// Commit a client-held round `n`: it consumes `consumes` and creates one
/// record third per `(key, note_hash)` of `records`.
pub fn client_round<S: Store + ?Sized>(
    store: &S,
    n: u8,
    consumes: &[Fr],
    records: &[(&str, Fr)],
) -> Result<(), Refusal> {
    let mut txn = store.begin(ns());
    for note_hash in consumes {
        txn.consume(ConsumedRow {
            note_hash: *note_hash,
            circuit: Fr::from(0xc1u64),
            request_id: id(n),
        });
    }
    for (key, note_hash) in records {
        txn.add_record(key, *note_hash, vec![n, 1, 2]);
    }
    txn.put_request(new_request(n, 1000 + n as u64));
    store.commit(txn)
}

/// A version of the tip key `key` under `commitment`, computed for entry
/// `index` on `parent` by round `n`, live at `block`.
pub fn version(key: &str, commitment: u64, parent: u64, index: u64, n: u8) -> TipVersion {
    TipVersion {
        key: key.to_string(),
        commitment: Fr::from(commitment),
        parent: Fr::from(parent),
        index,
        request_id: id(n),
        vec: vec![shared(commitment), Elem::Public(Fr::from(index))],
        tree: None,
        status: VersionStatus::Live,
        block: 0,
        block_hash: Fr::from(0u64),
    }
}

/// Commit a node-held tip round `n` on `key`: it creates `new` (if any)
/// and marks and prunes the key's versions under the chain `view`
/// ([`rules::stage_versions`]).
pub fn tip_round<S: Store + ?Sized>(
    store: &S,
    n: u8,
    key: &str,
    new: Option<TipVersion>,
    view: rules::VersionView,
) -> Result<(), Refusal> {
    let mut txn = store.begin(ns());
    rules::stage_versions(store, &mut txn, key, new, &view)?;
    txn.put_request(new_request(n, 1000 + n as u64));
    store.commit(txn)
}

pub fn internal(result: Result<(), Refusal>, needle: &str) {
    let err = result.unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    assert!(
        err.message.contains(needle),
        "`{}` lacks `{needle}`",
        err.message
    );
}

pub fn conflict(result: Result<(), Refusal>, needle: &str) {
    let err = result.unwrap_err();
    assert_eq!(err.class, ErrorClass::Conflict, "{err}");
    assert!(
        err.message.contains(needle),
        "`{}` lacks `{needle}`",
        err.message
    );
}

/// A contract manifest row; the store keeps the document as given.
pub fn manifest_row(hash: u64, seq: u64) -> ManifestRow {
    ManifestRow {
        manifest_hash: Fr::from(hash),
        document: serde_json::json!({"contract_manifest": 1, "name": format!("m{hash}")}),
        seq,
    }
}

pub fn namespace_row(seed: u64) -> NamespaceRow {
    NamespaceRow {
        owner_pubkey: fixed_base_mul(scalar_from_field(Fr::from(seed))),
        nsk_app: Share::new(Fr::from(seed), Fr::from(seed + 1)),
        npk_app_hash: Fr::from(seed * 7),
        seq: 0,
    }
}

/// One case of the suite.
pub type Case<S> = (&'static str, fn(&S));

/// The cases every backend passes, `values` or not.
pub fn cases_without_values<S: Store>() -> Vec<Case<S>> {
    vec![
        (
            "nsk_app_row_is_written_once_and_read_only_under_its_namespace",
            nsk_app_row_is_written_once_and_read_only_under_its_namespace::<S>,
        ),
        (
            "registry_seq_advances_by_one",
            registry_seq_advances_by_one::<S>,
        ),
        (
            "a_repair_replaces_only_the_share",
            a_repair_replaces_only_the_share::<S>,
        ),
        ("packages_and_disable", packages_and_disable::<S>),
        (
            "upgradable_namespaces_keep_their_newest_versions",
            upgradable_namespaces_keep_their_newest_versions::<S>,
        ),
        (
            "a_namespace_import_writes_every_held_version",
            a_namespace_import_writes_every_held_version::<S>,
        ),
        (
            "namespaces_and_package_names_are_listed",
            namespaces_and_package_names_are_listed::<S>,
        ),
        (
            "a_reused_request_id_is_refused",
            a_reused_request_id_is_refused::<S>,
        ),
        (
            "prune_requests_by_age_keeps_the_consumed_set",
            prune_requests_by_age_keeps_the_consumed_set::<S>,
        ),
        (
            "client_records_are_kept_in_the_request_row",
            client_records_are_kept_in_the_request_row::<S>,
        ),
        ("a_request_row_round_trips", a_request_row_round_trips::<S>),
        (
            "a_chain_request_id_round_trips",
            a_chain_request_id_round_trips::<S>,
        ),
        (
            "fetch_by_chain_request_id_answers_the_latest_row",
            fetch_by_chain_request_id_answers_the_latest_row::<S>,
        ),
        (
            "a_dropped_transaction_leaves_nothing",
            a_dropped_transaction_leaves_nothing::<S>,
        ),
        (
            "a_refused_commit_leaves_nothing",
            a_refused_commit_leaves_nothing::<S>,
        ),
        (
            "a_client_held_rollback_deletes_only_its_consumed_entries",
            a_client_held_rollback_deletes_only_its_consumed_entries::<S>,
        ),
        (
            "a_rollback_marks_the_records_it_created_dead",
            a_rollback_marks_the_records_it_created_dead::<S>,
        ),
        (
            "a_rolled_back_tip_attempt_is_replaced_by_its_rerun",
            a_rolled_back_tip_attempt_is_replaced_by_its_rerun::<S>,
        ),
        ("a_receipt_row_round_trips", a_receipt_row_round_trips::<S>),
        (
            "receipts_are_pruned_only_past_expiry_and_stale_period",
            receipts_are_pruned_only_past_expiry_and_stale_period::<S>,
        ),
        (
            "an_import_writes_a_namespace_the_store_does_not_hold",
            an_import_writes_a_namespace_the_store_does_not_hold::<S>,
        ),
        (
            "consumed_rows_and_receipts_are_listed_by_namespace",
            consumed_rows_and_receipts_are_listed_by_namespace::<S>,
        ),
        (
            "an_import_writes_requests_and_dead_records_as_they_stand",
            an_import_writes_requests_and_dead_records_as_they_stand::<S>,
        ),
    ]
}

/// The cases that need the `values` table (node-held keys).
pub fn cases_with_values<S: Store>() -> Vec<Case<S>> {
    vec![
        (
            "blobs_are_written_listed_and_deleted",
            blobs_are_written_listed_and_deleted::<S>,
        ),
        ("a_large_blob_round_trips", a_large_blob_round_trips::<S>),
        (
            "write_requires_read_or_consumed",
            write_requires_read_or_consumed::<S>,
        ),
        (
            "a_staged_write_is_checked_again_at_commit",
            a_staged_write_is_checked_again_at_commit::<S>,
        ),
        (
            "replaced_vector_is_sealed_and_restore_brings_it_back",
            replaced_vector_is_sealed_and_restore_brings_it_back::<S>,
        ),
        (
            "a_rollback_deletes_created_rows_and_every_consumed_entry",
            a_rollback_deletes_created_rows_and_every_consumed_entry::<S>,
        ),
        (
            "a_round_may_not_store_a_consumed_state",
            a_round_may_not_store_a_consumed_state::<S>,
        ),
        (
            "a_replacement_without_its_sealed_vector_is_refused",
            a_replacement_without_its_sealed_vector_is_refused::<S>,
        ),
        (
            "a_dropped_node_held_transaction_leaves_nothing",
            a_dropped_node_held_transaction_leaves_nothing::<S>,
        ),
        (
            "a_request_row_with_replaced_vectors_round_trips",
            a_request_row_with_replaced_vectors_round_trips::<S>,
        ),
        (
            "restore_opens_replaced_vectors_across_an_enc_rotation",
            restore_opens_replaced_vectors_across_an_enc_rotation::<S>,
        ),
        (
            "a_tip_version_is_written_once_and_never_overwritten",
            a_tip_version_is_written_once_and_never_overwritten::<S>,
        ),
        (
            "tip_versions_follow_the_chain_and_are_pruned_after_the_retention_depth",
            tip_versions_follow_the_chain_and_are_pruned_after_the_retention_depth::<S>,
        ),
        (
            "an_orphan_is_kept_for_the_retention_depth_after_it_turned_orphan",
            an_orphan_is_kept_for_the_retention_depth_after_it_turned_orphan::<S>,
        ),
        (
            "retention_counts_from_the_settled_block",
            retention_counts_from_the_settled_block::<S>,
        ),
        (
            "a_mark_on_a_replaced_block_is_marked_again",
            a_mark_on_a_replaced_block_is_marked_again::<S>,
        ),
        (
            "an_orphan_keeps_the_block_it_was_first_marked_orphan_at",
            an_orphan_keeps_the_block_it_was_first_marked_orphan_at::<S>,
        ),
        (
            "the_prune_pass_marks_and_prunes_keys_without_a_round",
            the_prune_pass_marks_and_prunes_keys_without_a_round::<S>,
        ),
        (
            "tree_nodes_are_shared_by_versions_and_pruned_by_reachability",
            tree_nodes_are_shared_by_versions_and_pruned_by_reachability::<S>,
        ),
        (
            "an_import_writes_versions_and_tree_nodes_and_lists_the_keys",
            an_import_writes_versions_and_tree_nodes_and_lists_the_keys::<S>,
        ),
        (
            "an_import_writes_values_rows_with_their_writers",
            an_import_writes_values_rows_with_their_writers::<S>,
        ),
        (
            "a_key_import_replaces_one_key_s_versions_and_tree",
            a_key_import_replaces_one_key_s_versions_and_tree::<S>,
        ),
        (
            "a_tip_attempt_s_rollback_deletes_its_versions",
            a_tip_attempt_s_rollback_deletes_its_versions::<S>,
        ),
        (
            "an_oblivious_version_is_not_rolled_back",
            an_oblivious_version_is_not_rolled_back::<S>,
        ),
    ]
}

fn run<S: Store>(cases: Vec<Case<S>>, make: impl Fn() -> S) -> usize {
    let count = cases.len();
    for (name, case) in cases {
        eprintln!("store suite: {name}");
        case(&make());
    }
    count
}

/// Every case on a backend with every table; `make` returns a fresh,
/// empty store per case. Returns how many cases ran.
pub fn suite<S: Store>(make: impl Fn() -> S) -> usize {
    let mut cases = cases_without_values::<S>();
    cases.extend(cases_with_values::<S>());
    run(cases, make)
}

/// The cases for a backend without `values` (every key client-held), and
/// the check that it refuses a node-held write. Returns how many ran.
pub fn suite_without_values<S: Store>(make: impl Fn() -> S) -> usize {
    let mut cases = cases_without_values::<S>();
    cases.push((
        "a_node_held_write_is_refused",
        a_node_held_write_is_refused::<S>,
    ));
    run(cases, make)
}
