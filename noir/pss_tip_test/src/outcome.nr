//! Private outcomes as a tip suite lands and reads them: the result the
//! relayer lands for what a round circuit outputs (pss_core's `Private`),
//! the three nodes' signatures over it, and an outcome log opened as its
//! recipient does. Every suite that computes its rounds with the circuits'
//! own functions lands them through these. A suite that stands in for a
//! round whose shares do not open C seals it with pss_core's
//! `outcome::encrypt_mismatch`, the seal the round itself makes.
use crate::result_signatures;
use pss_core::tip::outcome::{Private, seal_nonce};
use pss_public_contract::NODES;
use pss_public_contract::outcome::{OutcomeApply, OutcomeResult};
use pss_public_contract::result::ResultSignature;
use pss_utils::ae::AE;

/// The result the relayer lands for the round outputs `o` (what the round
/// circuit outputs), with the round's pinned values `reads` in the
/// manifest's `public_reads` order (`[]` without pinned reads).
pub fn outcome_result<let R: u32, let W: u32, let T: u32, let H: u32, let L: u32, let Q: u32>(
    o: Private<R, W, T, H, L>,
    reads: [Field; Q],
) -> OutcomeResult<R, W, Q, H, L> {
    OutcomeResult {
        apply: OutcomeApply::new(o.request_id, o.old_commitments, o.new_commitments, reads),
        outcome_tag: o.outcome_tag,
        note_hashes: o.note_hashes,
        ciphertext: o.ciphertext,
    }
}

/// The three nodes' signatures over the round outputs `o` in `namespace`
/// (`result_signatures`), with the pinned values `reads` and the state
/// mode's `sealed_hashes` (`NodeHeld {}.sealed_hashes()` under node-held
/// state).
pub unconstrained fn outcome_signatures<let R: u32, let W: u32, let T: u32, let H: u32, let L: u32, let Q: u32>(
    namespace: Field,
    o: Private<R, W, T, H, L>,
    reads: [Field; Q],
    sealed_hashes: [Field; NODES],
) -> [ResultSignature; NODES] {
    result_signatures(namespace, o.request_id, o.old_commitments, reads, o.new_commitments, sealed_hashes)
}

/// Open an outcome log, `[siloed tag, note hash, ciphertext[N], AEAD tag,
/// padding…]` (an outcome log or a delivery log), under `key` as its
/// recipient does (pss-client's `openOutcome`): the N plaintext fields,
/// decrypted under the nonce of the note hash the log carries, in the
/// opened domain, or, when the tag does not match there, in the mismatch
/// domain, where a round whose shares did not open C sealed `[mismatch
/// code, 0, …]`. A delivery opens in the first. Fails when the AEAD tag
/// verifies under neither.
pub unconstrained fn open_outcome_log<let N: u32, let M: u32>(log: BoundedVec<Field, M>, key: Field) -> [Field; N] {
    let mut body = [0; N];
    for i in 0..N {
        body[i] = log.get(2 + i);
    }
    let (tag, note_hash) = (log.get(2 + N), log.get(1));
    let (opened, ok) = AE::open(body, tag, key, seal_nonce(note_hash, true));
    if ok {
        opened
    } else {
        AE::decrypt(body, tag, key, seal_nonce(note_hash, false))
    }
}

mod test {
    use super::{open_outcome_log, outcome_result};
    use pss_core::tip::outcome::{encrypt, encrypt_mismatch, encrypt_outcome, Private};

    global ROUND: Private<1, 1, 0, 1, 3> = Private {
        request_id: 0x1d,
        machine_request_id: 0x3a,
        old_commitments: [0x0c],
        new_commitments: [0x1c],
        npk_app_hash: 0x9b,
        new_hashes: [],
        outcome_tag: 0x7a,
        note_hashes: [0x4a],
        ciphertext: [0xc0, 0xc1, 0xc2],
    };

    // The landed result carries the outputs' request id, commitments, tag,
    // note hashes and ciphertext, and the pinned values after the new
    // commitments.
    #[test]
    fn the_result_is_the_round_outputs() {
        let r = outcome_result(ROUND, [0x77]);
        assert_eq(r.apply.request_id, 0x1d);
        assert_eq(r.apply.old_commitments, [0x0c]);
        assert_eq(r.apply.new_commitments(), [0x1c]);
        assert_eq(r.apply.reads(), [0x77]);
        assert_eq(r.outcome_tag, 0x7a);
        assert_eq(r.note_hashes, [0x4a]);
        assert_eq(r.ciphertext, [0xc0, 0xc1, 0xc2]);
    }

    // A log laid out as the contract emits it opens to the encrypted
    // fields under the note hash it carries.
    #[test]
    unconstrained fn a_log_opens_to_its_plaintext() {
        let e = encrypt_outcome([5, 7], 0x6b6b, 0x9a, 0x2a, 0x1d);
        let ct = e.ciphertext;
        let log = BoundedVec::<Field, 16>::from_array([0xaa, e.note_hash, ct[0], ct[1], ct[2], 0, 0]);
        let fields: [Field; 2] = open_outcome_log(log, 0x6b6b);
        assert_eq(fields, [5, 7]);
    }

    // A round whose shares did not open C sealed its mismatch code alone in
    // the mismatch domain: its log opens to that code.
    #[test]
    unconstrained fn a_mismatch_log_opens_to_its_code_alone() {
        let e = encrypt_mismatch::<2>(14, 0x6b6b, 0x9a, 0x2a, 0x1d);
        let ct = e.ciphertext;
        let log = BoundedVec::<Field, 16>::from_array([0xaa, e.note_hash, ct[0], ct[1], ct[2], 0, 0]);
        let fields: [Field; 2] = open_outcome_log(log, 0x6b6b);
        assert_eq(fields, [14, 0]);
    }

    #[test(should_fail_with = "ae: tag mismatch")]
    unconstrained fn a_log_under_another_key_does_not_open() {
        let ct = encrypt([5, 7], 0x6b6b, 0x3a);
        let log = BoundedVec::<Field, 16>::from_array([0xaa, 0x3a, ct[0], ct[1], ct[2], 0, 0]);
        let _: [Field; 2] = open_outcome_log(log, 0x6b6c);
    }

    #[test(should_fail_with = "ae: tag mismatch")]
    unconstrained fn a_log_under_another_note_hash_does_not_open() {
        let ct = encrypt([5, 7], 0x6b6b, 0x3a);
        let log = BoundedVec::<Field, 16>::from_array([0xaa, 0x3b, ct[0], ct[1], ct[2], 0, 0]);
        let _: [Field; 2] = open_outcome_log(log, 0x6b6b);
    }
}
