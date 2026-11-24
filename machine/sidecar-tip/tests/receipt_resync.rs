//! How a resync carries receipt rows on three in-process nodes that take the
//! tip's receipt resync hook (`sidecar_tip::receipt_resync`, from the
//! intakes), over sidecar-core's `testing` harness with real MPC proofs of
//! the registration and audit circuits: a namespace registered at seq 0 and
//! receipt rows at every node (receipt intake rows signed by each node's own
//! key, and a secret-shared receipt intake row).
//!
//! - A node's store deleted with its key directory kept is resynced from its
//!   two neighbours: the receipt intake row both hold alike with valid
//!   signatures comes back, signed again by the lost node to the bytes it
//!   first signed. A row one neighbour holds alone, or whose signature
//!   fails, is left out, and so is the secret-shared receipt intake row: its
//!   envelope was sealed to the lost node alone, so its queued request
//!   cannot run there and is skipped after `stale_blocks`.
//! - A store backed up, then lost after a receipt intake row was written
//!   since, is restored by a delta resync: that row comes from the
//!   neighbours, and the rows no neighbour sends (the secret-shared receipt
//!   intake row, and the row the neighbours do not hold alike) from the
//!   backup.
//!
//! The rest of node recovery is sidecar-core's `tests/recovery.rs`.
//!
//! Needs `scripts/prepare-data.sh` (examples/amm's `pss_seed` and the CRS
//! under machine/data, or DATA_DIR); every test fails naming the missing
//! file if it is absent, so a passing run proves it ran. Run with
//! `--release`.

use sidecar_core::audit;
use sidecar_core::backup;
use sidecar_core::error::Refusal;
use sidecar_core::field::Fr;
use sidecar_core::pipeline::Node;
use sidecar_core::resync::{ResyncReport, Scope};
use sidecar_core::store::rules::VersionView;
use sidecar_core::store::testing::shared_receipt_row;
use sidecar_core::store::{ReceiptRow, Store};
use sidecar_core::testing::{Fixture, Network, TestStore, serial};
use sidecar_tip::{chain_request_id, inputs_hash, sign_receipt};

const NS: u64 = 0xc0ffee;

fn ns() -> Fr {
    Fr::from(NS)
}

fn f(x: u64) -> Fr {
    Fr::from(x)
}

fn fixture() -> &'static Fixture {
    sidecar_core::testing::fixture(&["pss_seed"]).expect(
        "the receipt resync tests need scripts/prepare-data.sh's pss_seed and CRS (see the \
         SKIPPED line above)",
    )
}

/// The chain view of a node that reads none: every version stays as marked.
fn unread(_: Fr, _: &[String]) -> Result<Option<Vec<VersionView>>, Refusal> {
    Ok(None)
}

/// Node `node`'s receipt intake row `n`, signed with its own key.
fn plain_receipt(node: &Node<TestStore>, n: u64) -> ReceiptRow {
    let (vk_hash, inputs, nonce) = (f(0xc1), vec![f(n), f(n + 1)], f(0x77 + n));
    let request_id = chain_request_id(ns(), vk_hash, &inputs, nonce);
    let hash = inputs_hash(&inputs);
    ReceiptRow {
        request_id,
        circuit: "pss_seed".into(),
        vk_hash,
        inputs,
        inputs_hash: hash,
        user_nonce: Some(nonce),
        shares: vec![],
        expiry_block: 500,
        stale_blocks: Some(50),
        signature: sign_receipt(node.keys().sig_scalar(), request_id, hash, 500),
    }
}

/// Three nodes with the tip's receipt resync hook, the namespace registered
/// and the receipt rows stored: receipt intake row 1 at every node, row 2 at
/// node 0 only, row 3 at every node but with node 2's signature broken, and
/// a secret-shared receipt intake row at every node.
fn network(fx: &Fixture, seed: u64) -> Network {
    let mut net = Network::new(fx, seed);
    net.with_receipt_resync(sidecar_tip::receipt_resync());
    net.register(fx, NS, "amm", &["pss_seed"]);
    for (i, node) in net.nodes.iter().enumerate() {
        let mut rows = vec![plain_receipt(node, 1), shared_receipt_row(9, 500, Some(50))];
        if i == 0 {
            rows.push(plain_receipt(node, 2));
        }
        let mut broken = plain_receipt(node, 3);
        if i == 2 {
            broken.signature = plain_receipt(node, 4).signature;
        }
        rows.push(broken);
        for row in rows {
            node.store.put_receipt(ns(), row).unwrap();
        }
    }
    net
}

#[test]
fn a_lost_store_keeps_the_receipt_rows_both_neighbours_hold_alike() {
    let _serial = serial();
    let fx = fixture();
    let mut net = network(fx, 12);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let lost = 1;
    let receipts_before = net.nodes[lost].store.receipts(ns()).unwrap();
    assert_eq!(receipts_before.len(), 3, "rows 1 and 3, and the shared row");
    net.lose_store(fx, lost);

    let reports: Vec<ResyncReport> = net
        .resync(&circuit, lost, &Scope::Store, None, &unread, |_, _| {})
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    for r in &reports {
        assert!(r.passed(), "{r:?}");
    }
    let imported = &reports[lost].imported;
    // rows 1 and 3 from node 0, rows 1 and 3 from node 2 (2 only at node 0):
    // row 1 kept, row 2 (one neighbour) and row 3 (a broken signature) left
    // out
    assert_eq!(
        (imported.receipts, imported.receipts_left_out),
        (1, 2),
        "{imported:?}"
    );
    assert_eq!(reports[0].imported.receipts, 3, "node 0 sent rows 1 to 3");
    // row 1 comes back as the lost node first signed it
    let row = plain_receipt(&net.nodes[lost], 1);
    assert_eq!(
        net.nodes[lost].store.receipts(ns()).unwrap(),
        std::slice::from_ref(&row)
    );
    assert!(receipts_before.contains(&row));
    // the secret-shared receipt intake row is not sent
    let shared = shared_receipt_row(9, 500, Some(50)).request_id;
    assert!(
        net.nodes[lost]
            .store
            .receipt(ns(), shared)
            .unwrap()
            .is_none()
    );
    assert!(net.nodes[0].store.receipt(ns(), shared).unwrap().is_some());
}

#[test]
fn a_restored_backup_takes_the_receipt_rows_no_neighbour_sends_from_the_backup() {
    let _serial = serial();
    let fx = fixture();
    let mut net = network(fx, 16);
    let circuit = audit::audit_circuit(&fx.crs).unwrap();
    let lost = 1;
    let backup = backup::export(&net.nodes[lost], &unread).unwrap();
    assert_eq!(backup.counts().receipts, 3);
    // after the backup: receipt intake row 5 at every node
    for node in &net.nodes {
        node.store
            .put_receipt(ns(), plain_receipt(node, 5))
            .unwrap();
    }
    let receipts_before = net.nodes[lost].store.receipts(ns()).unwrap();
    net.lose_store(fx, lost);

    for r in net.resync(
        &circuit,
        lost,
        &Scope::Delta,
        Some(&backup),
        &unread,
        |_, _| {},
    ) {
        let r = r.unwrap();
        assert!(r.passed(), "{r:?}");
    }
    // every receipt row is back: rows 1 and 5 from the neighbours, the
    // secret-shared receipt intake row and row 3 (whose neighbours' copies
    // differ) from the backup
    let store = &net.nodes[lost].store;
    assert_eq!(store.receipts(ns()).unwrap(), receipts_before);
    assert_eq!(receipts_before.len(), 4);
}
