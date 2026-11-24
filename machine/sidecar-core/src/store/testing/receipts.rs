//! The suite's cases for the `receipts` table.

use super::*;

/// A receipt row with `n` in every field, expiring at `expiry_block`.
pub fn receipt_row(n: u64, expiry_block: u64, stale_blocks: Option<u64>) -> ReceiptRow {
    ReceiptRow {
        request_id: Fr::from(0x7000 + n),
        circuit: format!("circuit_{n}"),
        vk_hash: Fr::from(0xc1u64),
        inputs: vec![Fr::from(n), -Fr::from(n)],
        inputs_hash: Fr::from(0x1000 + n),
        user_nonce: Some(Fr::from(n * 3)),
        shares: vec![],
        expiry_block,
        stale_blocks,
        signature: Signature {
            s: [
                crate::field::FieldHex::from(n),
                crate::field::FieldHex::from(n + 1),
            ],
            e: [
                crate::field::FieldHex::from(n + 2),
                crate::field::FieldHex::from(n + 3),
            ],
        },
    }
}

/// A secret-shared receipt intake row with `n` in every field: no nonce, and this node's envelopes of two shared inputs with their three
/// share hashes.
pub fn shared_receipt_row(n: u64, expiry_block: u64, stale_blocks: Option<u64>) -> ReceiptRow {
    use crate::field::FieldHex;
    use crate::request::{GrumpkinPoint, ShareCiphertext};
    let share = |k: u64| NodeSharedInput {
        name: format!("input_{k}"),
        share: ShareCiphertext {
            eph: GrumpkinPoint {
                x: FieldHex::from(n + k),
                y: FieldHex(-Fr::from(n + k)),
            },
            ct: [FieldHex::from(n + k + 1), FieldHex::from(n + k + 2)],
            tag: FieldHex::from(n + k + 3),
        },
        share_hashes: [4, 5, 6].map(|h| FieldHex::from(n * 10 + k + h)),
    };
    ReceiptRow {
        user_nonce: None,
        shares: vec![share(0), share(1)],
        ..receipt_row(n, expiry_block, stale_blocks)
    }
}

/// Every field of a receipt row reads back as written, under its
/// namespace only; a second write replaces it.
pub fn a_receipt_row_round_trips<S: Store>(store: &S) {
    let row = receipt_row(1, 1000, Some(50));
    assert!(store.receipt(ns(), row.request_id).unwrap().is_none());
    store.put_receipt(ns(), row.clone()).unwrap();
    assert_eq!(
        store.receipt(ns(), row.request_id).unwrap(),
        Some(row.clone())
    );
    assert!(
        store
            .receipt(ns() + Fr::from(1u64), row.request_id)
            .unwrap()
            .is_none()
    );
    // no inputs, no stale period, the largest values a column holds
    let empty = ReceiptRow {
        inputs: vec![],
        stale_blocks: None,
        expiry_block: u64::from(u32::MAX),
        ..receipt_row(2, 0, None)
    };
    store.put_receipt(ns(), empty.clone()).unwrap();
    assert_eq!(store.receipt(ns(), empty.request_id).unwrap(), Some(empty));
    // a secret-shared receipt intake row: no requester, this node's envelopes
    let shared = shared_receipt_row(3, 1000, Some(50));
    store.put_receipt(ns(), shared.clone()).unwrap();
    assert_eq!(
        store.receipt(ns(), shared.request_id).unwrap(),
        Some(shared)
    );
    let later = ReceiptRow {
        expiry_block: 1300,
        signature: receipt_row(9, 0, None).signature,
        ..row.clone()
    };
    store.put_receipt(ns(), later.clone()).unwrap();
    assert_eq!(store.receipt(ns(), row.request_id).unwrap(), Some(later));
    // the receipts table is not the requests table
    assert!(
        store
            .request(ns(), RequestId(row.request_id))
            .unwrap()
            .is_none()
    );
}

/// The pruning rule's store half: a row is listed only once
/// `expiry_block + stale_blocks` is below the block, and a row without a
/// stale period once `expiry_block + UNSKIPPED_KEEP_BLOCKS` is;
/// `prune_receipts` deletes only the listed ids
/// it is given that are still past their window (not an id the job
/// keeps, not a row re-signed with a later expiry since); other tables
/// are untouched.
pub fn receipts_are_pruned_only_past_expiry_and_stale_period<S: Store>(store: &S) {
    let early = receipt_row(1, 100, Some(50)); // kept through block 150
    let late = receipt_row(2, 200, Some(50)); // kept through block 250
    // kept through block 170
    let unskipped = receipt_row(3, 170 - crate::store::UNSKIPPED_KEEP_BLOCKS, None);
    let queued = receipt_row(4, 100, Some(50)); // the job keeps it
    for row in [&early, &late, &unskipped, &queued] {
        store.put_receipt(ns(), row.clone()).unwrap();
    }
    let other_ns = ns() + Fr::from(1u64);
    store.put_receipt(other_ns, early.clone()).unwrap();
    round(store, 1, &[], &[], &[]).unwrap();
    let has = |ns: Fr, row: &ReceiptRow| store.receipt(ns, row.request_id).unwrap().is_some();
    let expired = |block: u64| {
        let mut ids = store.expired_receipts(block).unwrap();
        ids.sort();
        ids
    };
    let key = |ns: Fr, row: &ReceiptRow| (ns, row.request_id);

    assert_eq!(expired(0), []);
    // past the expiry, inside the stale window: not listed, not pruned
    assert_eq!(expired(101), []);
    assert_eq!(expired(150), []);
    assert_eq!(store.prune_receipts(150, &[key(ns(), &early)]).unwrap(), 0);
    assert!(has(ns(), &early) && has(other_ns, &early));
    // one block past expiry + stale: listed in every namespace
    let mut want = vec![key(ns(), &early), key(ns(), &queued), key(other_ns, &early)];
    want.sort();
    assert_eq!(expired(151), want);
    // only the ids given go; the one the job keeps stays
    let pruned = [key(ns(), &early), key(other_ns, &early)];
    assert_eq!(store.prune_receipts(151, &pruned).unwrap(), 2);
    assert!(!has(ns(), &early) && !has(other_ns, &early));
    assert!(has(ns(), &queued) && has(ns(), &late) && has(ns(), &unskipped));
    // an id with no row, or inside its window, is left alone
    assert_eq!(store.prune_receipts(151, &pruned).unwrap(), 0);
    assert_eq!(store.prune_receipts(151, &[key(ns(), &late)]).unwrap(), 0);
    // a row re-signed with a later expiry after it was listed stays
    let resigned = ReceiptRow {
        expiry_block: 400,
        ..queued.clone()
    };
    store.put_receipt(ns(), resigned).unwrap();
    assert_eq!(store.prune_receipts(151, &[key(ns(), &queued)]).unwrap(), 0);
    assert!(has(ns(), &queued));
    // the row with no stale period, once past its expiry and the margin
    assert_eq!(expired(170), []);
    assert_eq!(expired(171), [key(ns(), &unskipped)]);
    let all = [key(ns(), &late), key(ns(), &queued), key(ns(), &unskipped)];
    assert_eq!(store.prune_receipts(171, &all).unwrap(), 1);
    assert!(has(ns(), &late) && has(ns(), &queued) && !has(ns(), &unskipped));
    assert_eq!(store.prune_receipts(u64::MAX, &all).unwrap(), 2);
    assert!(!has(ns(), &late) && !has(ns(), &queued));
    assert!(store.request(ns(), id(1)).unwrap().is_some());
    assert_eq!(early.keep_until(), 150);
    assert!(!early.prunable_at(150) && early.prunable_at(151));
    assert_eq!(unskipped.keep_until(), 170);
    assert!(!unskipped.prunable_at(170) && unskipped.prunable_at(171));
}
