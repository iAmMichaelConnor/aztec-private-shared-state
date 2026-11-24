//! Checks the private-outcome vectors of testvectors/outcome.json with the
//! functions the round circuits call (noir/pss_core's
//! `tip::outcome`): for each case the machine request id, the request's
//! partial note, the completed note hash, the AEAD nonce of that note hash,
//! the ciphertext and tag, `encrypt_outcome` and the outcome log's padding
//! (`log_padding` at each position past the ciphertext); the partial-note
//! case (the partial commitment, the completed note hash, the completion log
//! tag and `encrypt_outcome`); the mismatch case (`encrypt_mismatch`: the
//! code alone, its note hash, the mismatch domain's nonce and the
//! ciphertext, and the opened domain's nonce of the same note hash); the
//! delivery handle's log tag (`tip::handle::handle_tag`); and
//! testvectors/secret_store.json's per-request derivations. Prover.toml is written from the vector files by pss-client's
//! test/outcome.test.ts; `nargo execute` fails on any disagreement.

use pss_core::tip::handle::{handle_tag, PSS_HANDLE_TAG};
use pss_core::tip::outcome::{
    completed_note_hash, completion_log_tag, encrypt, encrypt_mismatch, encrypt_outcome, log_padding,
    machine_request_id, outcome_nonce, partial_commitment, PSS_ATTEMPT, seal_nonce, SIDECAR_MISMATCH_AD,
    SIDECAR_OUTCOME_AD,
};
use total::hash::p2_hash;

/// The fields of a v6 private log after its tag: the note hash, the
/// ciphertext, then the padding.
global LOG_FIELDS: u32 = 15;

/// One outcome case: R old commitments, Q pinned values, N plaintext fields
/// (L = N + 1 ciphertext fields), D padding fields (LOG_FIELDS - 1 - L).
struct OutcomeVector<let R: u32, let Q: u32, let N: u32, let L: u32, let D: u32> {
    chain_request_id: Field,
    old_commitments: [Field; R],
    pinned: [Field; Q],
    machine_request_id: Field,
    outcome_key: Field,
    nonce: Field,
    plaintext: [Field; N],
    ciphertext: [Field; L],
    owner: Field,
    rho: Field,
    partial_note: Field,
    storage_slot: Field,
    note_hash: Field,
    outcome_tag: Field,
    padding: [Field; D],
}

/// A case without pinned reads: an entry point takes no zero-length array,
/// so the program passes `[]` itself (Prover.toml omits `pinned`).
struct UnpinnedVector<let R: u32, let N: u32, let L: u32, let D: u32> {
    chain_request_id: Field,
    old_commitments: [Field; R],
    machine_request_id: Field,
    outcome_key: Field,
    nonce: Field,
    plaintext: [Field; N],
    ciphertext: [Field; L],
    owner: Field,
    rho: Field,
    partial_note: Field,
    storage_slot: Field,
    note_hash: Field,
    outcome_tag: Field,
    padding: [Field; D],
}

/// The partial-note case: an AMM-shaped outcome `[code, amount_out]`.
struct PartialVector {
    owner: Field,
    rho: Field,
    partial_note: Field,
    storage_slot: Field,
    request_id: Field,
    outcome_key: Field,
    plaintext: [Field; 2],
    ciphertext: [Field; 3],
    note_hash: Field,
    completion_log_tag: Field,
}

/// The mismatch case: a lending-shaped round whose shares do not open C,
/// which seals its code alone (`[code, 0, …]`, seven fields).
struct MismatchVector {
    code: Field,
    owner: Field,
    rho: Field,
    partial_note: Field,
    storage_slot: Field,
    request_id: Field,
    outcome_key: Field,
    plaintext: [Field; 7],
    note_hash: Field,
    nonce: Field,
    opened_nonce: Field,
    ciphertext: [Field; 8],
}

/// The handle-tag case: a delivery's log tag under a handle key for the
/// delivering round's chain request id.
struct HandleVector {
    key: Field,
    request_id: Field,
    tag: Field,
}

/// testvectors/secret_store.json: the labels, the wallet, the namespace and
/// the owner, and for n = 0, 1, 2 each derivation.
struct SecretVectors {
    pss_partial_randomness: Field,
    pss_outcome_key: Field,
    pss_outcome_tag: Field,
    wallet_secret: Field,
    namespace: Field,
    owner: Field,
    rho: [Field; 3],
    outcome_key: [Field; 3],
    outcome_tag: [Field; 3],
    partial_note: [Field; 3],
    completion_log_tag: [Field; 3],
}

fn derive(label: Field, s: SecretVectors, n: u32) -> Field {
    p2_hash([label, s.wallet_secret, s.namespace, n as Field])
}

fn check<let R: u32, let Q: u32, let N: u32, let D: u32>(v: OutcomeVector<R, Q, N, N + 1, D>) {
    let mrid = machine_request_id(v.chain_request_id, v.old_commitments, v.pinned);
    assert_eq(mrid, v.machine_request_id, "machine_request_id");
    let p = partial_commitment(v.owner, v.rho);
    assert_eq(p, v.partial_note, "partial_note");
    assert_eq(
        completed_note_hash(v.storage_slot, p, v.plaintext, v.chain_request_id),
        v.note_hash,
        "note_hash",
    );
    assert_eq(outcome_nonce(v.note_hash), v.nonce, "nonce");
    assert_eq(encrypt(v.plaintext, v.outcome_key, v.note_hash), v.ciphertext, "ciphertext");
    let sealed = encrypt_outcome(v.plaintext, v.outcome_key, p, v.storage_slot, v.chain_request_id);
    assert_eq(sealed.note_hash, v.note_hash, "encrypt_outcome note_hash");
    assert_eq(sealed.ciphertext, v.ciphertext, "encrypt_outcome ciphertext");
    assert_eq(1 + (N + 1) + D, LOG_FIELDS, "padding length");
    for k in 0..D {
        assert_eq(log_padding(v.outcome_tag, 1 + (N + 1) + k), v.padding[k], "padding");
    }
}

fn main(
    pss_attempt: Field,
    sidecar_outcome_ad: Field,
    sidecar_mismatch_ad: Field,
    pss_handle_tag: Field,
    amm: UnpinnedVector<1, 2, 3, 11>,
    lending: OutcomeVector<1, 1, 7, 8, 6>,
    partial: PartialVector,
    mismatch: MismatchVector,
    handle: HandleVector,
    secrets: SecretVectors,
) {
    assert_eq(pss_attempt, PSS_ATTEMPT);
    assert_eq(sidecar_outcome_ad, SIDECAR_OUTCOME_AD);
    assert_eq(sidecar_mismatch_ad, SIDECAR_MISMATCH_AD);
    assert_eq(pss_handle_tag, PSS_HANDLE_TAG);
    check(
        OutcomeVector {
            chain_request_id: amm.chain_request_id,
            old_commitments: amm.old_commitments,
            pinned: [],
            machine_request_id: amm.machine_request_id,
            outcome_key: amm.outcome_key,
            nonce: amm.nonce,
            plaintext: amm.plaintext,
            ciphertext: amm.ciphertext,
            owner: amm.owner,
            rho: amm.rho,
            partial_note: amm.partial_note,
            storage_slot: amm.storage_slot,
            note_hash: amm.note_hash,
            outcome_tag: amm.outcome_tag,
            padding: amm.padding,
        },
    );
    check(lending);
    let p = partial_commitment(partial.owner, partial.rho);
    assert_eq(p, partial.partial_note, "partial_note");
    assert_eq(
        completed_note_hash(partial.storage_slot, p, partial.plaintext, partial.request_id),
        partial.note_hash,
        "completed note_hash",
    );
    assert_eq(completion_log_tag(p), partial.completion_log_tag, "completion_log_tag");
    let sealed = encrypt_outcome(partial.plaintext, partial.outcome_key, p, partial.storage_slot, partial.request_id);
    assert_eq(sealed.note_hash, partial.note_hash, "encrypt_outcome completed note_hash");
    assert_eq(sealed.ciphertext, partial.ciphertext, "encrypt_outcome partial ciphertext");
    let m = mismatch;
    let pm = partial_commitment(m.owner, m.rho);
    assert_eq(pm, m.partial_note, "mismatch partial_note");
    assert_eq(m.plaintext, [m.code, 0, 0, 0, 0, 0, 0], "mismatch plaintext");
    assert_eq(completed_note_hash(m.storage_slot, pm, m.plaintext, m.request_id), m.note_hash, "mismatch note_hash");
    assert_eq(seal_nonce(m.note_hash, false), m.nonce, "mismatch nonce");
    assert_eq(seal_nonce(m.note_hash, true), m.opened_nonce, "mismatch opened_nonce");
    let sealed = encrypt_mismatch::<7>(m.code, m.outcome_key, pm, m.storage_slot, m.request_id);
    assert_eq(sealed.note_hash, m.note_hash, "encrypt_mismatch note_hash");
    assert_eq(sealed.ciphertext, m.ciphertext, "encrypt_mismatch ciphertext");
    assert_eq(handle_tag(handle.key, handle.request_id), handle.tag, "handle tag");
    for n in 0..3 {
        assert_eq(derive(secrets.pss_partial_randomness, secrets, n), secrets.rho[n], "rho");
        assert_eq(derive(secrets.pss_outcome_key, secrets, n), secrets.outcome_key[n], "outcome_key");
        assert_eq(derive(secrets.pss_outcome_tag, secrets, n), secrets.outcome_tag[n], "outcome_tag");
        let pn = partial_commitment(secrets.owner, secrets.rho[n]);
        assert_eq(pn, secrets.partial_note[n], "secrets partial_note");
        assert_eq(completion_log_tag(pn), secrets.completion_log_tag[n], "secrets completion_log_tag");
    }
}
