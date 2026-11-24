//! Private outcomes inside the MPC (docs/ARCHITECTURE.md section 6, "Private
//! outcomes"): what a secret-shared-intake
//! round computes so that its outcome reaches only the user, and in a form the
//! user can open.
//!
//! Value delivery is partial-note completion: the user commits a partial
//! note `P = partial_commitment(owner, rho)` in its request (the reserved
//! shared value `$partial_note`, `SharedIntake::partial`), and the round
//! completes it inside the co-SNARK, outputting the completed note's hash. The
//! round derives no randomness and sees no owner.
//!
//! - `machine_request_id`: the attempt's id, from the chain request id, the
//!   old commitments and the pinned values (all public to the round); the
//!   round outputs it, the contract recomputes it, the nodes sign under it.
//! - `seal_nonce`: the AEAD nonce of a sealed plaintext, a hash of the
//!   completed note hash that commits to exactly that plaintext, under one
//!   domain when the round's shares open C and another when they do not.
//!   One nonce therefore only ever seals one plaintext, whatever the
//!   blinding, the rerun or the shares. `outcome_nonce` is the first.
//! - `encrypt`: a plaintext under a key with the Poseidon2 duplex AEAD of
//!   `pss_utils` (`ae.nr`), nonce `outcome_nonce(note_hash)`, `note_hash`
//!   the hash of the note that packs that plaintext; returns the
//!   ciphertext and then the tag.
//! - `partial_commitment`, `completed_note_hash`, `completion_log_tag`:
//!   aztec-nr v6's partial-note convention (`uint_note.nr`), the commitment
//!   over the private part `[owner, randomness]`, the completed note's hash
//!   over `[storage_slot, P, fields…, request_id]`, and the tag of a public
//!   completion's log. A note packs at most `MAX_NOTE_PACKED_LEN` fields,
//!   `request_id` last.
//! - `encrypt_outcome`: the completed note's hash and the ciphertext under
//!   its nonce at once; `encrypt_mismatch` the same for the app's mismatch
//!   code alone, what a round whose shares do not open C seals; and
//!   `Private`, the round's public outputs.
//! - `finish`: a secret-shared-intake round's outputs from what it leaves at
//!   its key (`super::outputs::Written`), its pinned values and its outcome
//!   plaintext, the completed note packing the plaintext and `request_id`.
//! - `log_padding`: the padding field at each position of a private log
//!   past its data, a function of the log's tag; the contract library pads
//!   the outcome log with it (pss_public_contract `outcome::outcome_log`).
//!
//! Every function here is permutation black boxes, selects and additions: total, with
//! no failure source, and runs in co-noir. testvectors/outcome.json holds the
//! known answers, which testvectors/noir/outcome_vectors checks with these
//! functions and pss-client's test/outcome.test.ts with the client's own.
use crate::effects;
use super::intake::SharedIntake;
use super::outputs::{Finished, Written};
use pss_utils::ae::AE;
use protocol_types::constants::DOM_SEP__NOTE_HASH;
use total::core::select_field;
use total::hash::{p2_hash, p2_hash_sep};

/// ASCII "sidecar.attempt" as a big-endian integer: the machine request id's
/// domain (pss_public_contract re-exports it; sidecar-tip's ids.rs and
/// pss-client's PSS_ATTEMPT hold the same value).
pub global PSS_ATTEMPT: Field = 0x736964656361722e617474656d7074;

/// ASCII "sidecar.outcome" as a big-endian integer: the AEAD nonce's domain
/// of an outcome whose shares open C, and of every delivery.
pub global SIDECAR_OUTCOME_AD: Field = 0x736964656361722e6f7574636f6d65;

/// ASCII "sidecar.mismatch" as a big-endian integer: the outcome AEAD
/// nonce's domain in a round whose shares do not open C.
pub global SIDECAR_MISMATCH_AD: Field = 0x736964656361722e6d69736d61746368;

/// aztec-nr v6's domain separator of a partial note's commitment
/// (`note::partial_note::DOM_SEP__PARTIAL_NOTE_COMMITMENT`).
pub global DOM_SEP__PARTIAL_NOTE_COMMITMENT: u32 = 568912195;

/// aztec-nr v6's domain separator of a partial note's completion log tag
/// (`note::partial_note::DOM_SEP__NOTE_COMPLETION_LOG_TAG`).
pub global DOM_SEP__NOTE_COMPLETION_LOG_TAG: u32 = 3372669888;

/// The most fields a note packs (aztec-nr v6 `messages::logs::note::
/// MAX_NOTE_PACKED_LEN`: the 12-field message plaintext less the metadata
/// field and `owner`, `storage_slot`, `randomness`). A longer note can be
/// neither delivered by a private note message nor completed by a log, so
/// a completed note holds at most seven outcome fields and `request_id`.
pub global MAX_NOTE_PACKED_LEN: u32 = 8;

/// The machine request id of one attempt, `poseidon2([PSS_ATTEMPT,
/// chain_request_id, old commitments…, pinned values…])`, the pinned values
/// in the manifest's `public_reads` order (`[]` without pinned reads). A
/// recompute against another state or at a moved pinned value is another
/// attempt with another id. Total.
pub fn machine_request_id<let R: u32, let Q: u32>(
    chain_request_id: Field,
    old_commitments: [Field; R],
    pinned_values: [Field; Q],
) -> Field {
    p2_hash([PSS_ATTEMPT, chain_request_id].concat(old_commitments).concat(pinned_values))
}

/// The AEAD nonce of a sealed plaintext: `poseidon2([note_hash,
/// SIDECAR_OUTCOME_AD])` when the round's shares open C, `poseidon2([
/// note_hash, SIDECAR_MISMATCH_AD])` when they do not. `note_hash` is the
/// hash of the completed note that packs the plaintext
/// (`completed_note_hash`), so it commits to the plaintext: under one key,
/// one nonce only ever seals one plaintext (Poseidon2 collision resistance),
/// whatever blinding a run draws, however often nodes rerun a round and
/// whatever shares they bring. This matters because in the duplex the first
/// block's keystream depends only on the key, the nonce and the length: two
/// plaintexts under one key and nonce would show their difference. Equal
/// plaintexts give equal ciphertexts, which show nothing the equal public
/// note hashes do not. Total: one select and one permutation.
pub fn seal_nonce(note_hash: Field, opened: bool) -> Field {
    p2_hash([note_hash, select_field(opened, SIDECAR_OUTCOME_AD, SIDECAR_MISMATCH_AD)])
}

/// The nonce of a plaintext whose round's shares open C,
/// `seal_nonce(note_hash, true)`: every outcome a user reads and every
/// delivery is sealed under it. Total.
pub fn outcome_nonce(note_hash: Field) -> Field {
    seal_nonce(note_hash, true)
}

/// `plaintext` encrypted under `key` with `nonce`: `[ct_0, …, ct_{N-1},
/// tag]`, `pss_utils`' `AE::encrypt` (N fields in ceil(N / 3) duplex
/// blocks). Total: no failure path, whatever the key.
fn encrypt_under<let N: u32>(plaintext: [Field; N], key: Field, nonce: Field) -> [Field; N + 1] {
    let (ciphertext, tag) = AE::encrypt(plaintext, key, nonce);
    ciphertext.concat([tag])
}

/// `plaintext` encrypted under `key` with `outcome_nonce(note_hash)`.
/// `note_hash` must be the hash of the note that packs `plaintext`, so that
/// the nonce commits to it: `encrypt_outcome` and `super::handle`'s
/// deliveries pass the note hash they output. Total.
pub fn encrypt<let N: u32>(plaintext: [Field; N], key: Field, note_hash: Field) -> [Field; N + 1] {
    encrypt_under(plaintext, key, outcome_nonce(note_hash))
}

/// `fields` when `shows`, and otherwise `[otherwise, 0, …]`: the plaintext
/// a round seals. An outcome shows its fields when the shares open C and
/// the app's mismatch code alone when they do not; a delivery shows its
/// fields when it delivers and zeros when it does not. Total: N selects.
pub(crate) fn shown<let N: u32>(shows: bool, otherwise: Field, fields: [Field; N]) -> [Field; N] {
    std::static_assert(N > 0, "a sealed plaintext has at least one field");
    let mut out = [0; N];
    out[0] = select_field(shows, fields[0], otherwise);
    for i in 1..N {
        out[i] = select_field(shows, fields[i], 0);
    }
    out
}

/// A partial note's commitment, `poseidon2_hash_with_separator([owner,
/// randomness], DOM_SEP__PARTIAL_NOTE_COMMITMENT)` (aztec-nr v6
/// `uint_note.nr` `compute_partial_commitment`): the private part of a note
/// whose other fields a round completes. The user computes it in its
/// request function from its `owner` address and the randomness `rho` its
/// client derives; nobody who lacks `rho` can tell the owner from it. Total.
pub fn partial_commitment(owner: Field, randomness: Field) -> Field {
    p2_hash_sep([owner, randomness], DOM_SEP__PARTIAL_NOTE_COMMITMENT as Field)
}

/// The hash of the note that completes the partial note `partial` at
/// `storage_slot` with the outcome `fields` and the chain request id:
/// `poseidon2_hash_with_separator([storage_slot, partial, fields…,
/// request_id], DOM_SEP__NOTE_HASH)` (aztec-nr `note::utils::
/// compute_note_hash(storage_slot, [partial, fields…, request_id])`, the
/// second step of `uint_note.nr`'s two-step hash). A `#[custom_note]` whose
/// `compute_note_hash(owner, storage_slot, randomness)` performs both steps
/// hashes to the same value for a note `[fields…, request_id]`, so the
/// owner's PXE stores the completed note as an ordinary note.
///
/// `request_id` is last: it is never zero (a public completion's log would
/// lose a trailing zero), and it names the request the note answers. The
/// note packs `N + 1` fields, at most `MAX_NOTE_PACKED_LEN`. Total.
pub fn completed_note_hash<let N: u32>(
    storage_slot: Field,
    partial: Field,
    fields: [Field; N],
    request_id: Field,
) -> Field {
    std::static_assert(
        N + 1 <= MAX_NOTE_PACKED_LEN,
        "a completed note packs at most eight fields, request_id last",
    );
    p2_hash_sep(
        [storage_slot, partial].concat(fields).concat([request_id]),
        DOM_SEP__NOTE_HASH as Field,
    )
}

/// The tag of a public completion's log, `poseidon2_hash_with_separator(
/// [partial], DOM_SEP__NOTE_COMPLETION_LOG_TAG)` (aztec-nr `compute_log_tag`):
/// the owner's PXE, told of the partial note by a partial-note message,
/// finds the completion under it. Total.
pub fn completion_log_tag(partial: Field) -> Field {
    p2_hash_sep([partial], DOM_SEP__NOTE_COMPLETION_LOG_TAG as Field)
}

/// The padding field at position `i` of a private log emitted under `tag`
/// (the tag the contract passes, before the kernel silos it), counting from
/// the first field after the tag: `poseidon2([tag, i])`. A log the library
/// pads to the full v6 private log takes this value at every position past
/// its data, so its padding is a function of its tag and its data length:
/// whoever submits the transaction chooses none of it, and it carries
/// nothing. Total.
pub fn log_padding(tag: Field, i: u32) -> Field {
    p2_hash([tag, i as Field])
}

/// One sealed outcome: the hash of the completed note and the ciphertext of
/// the plaintext it packs, with the AEAD tag, under the nonce of that note
/// hash.
pub struct EncryptedOutcome<let L: u32> {
    pub note_hash: Field,
    pub ciphertext: [Field; L],
}

/// Encrypt an outcome whose round's shares open C: complete the request's
/// partial note `partial` at the app's `storage_slot` with the plaintext's
/// fields and the chain `request_id` (`completed_note_hash`: the completed
/// note packs `[plaintext…, request_id]`), and encrypt `plaintext` under
/// `outcome_key` with that note hash's nonce (`outcome_nonce`). Total.
pub fn encrypt_outcome<let N: u32>(
    plaintext: [Field; N],
    outcome_key: Field,
    partial: Field,
    storage_slot: Field,
    request_id: Field,
) -> EncryptedOutcome<N + 1> {
    seal(true, 0, plaintext, outcome_key, partial, storage_slot, request_id)
}

/// What a round whose shares do not open C seals: the N-field plaintext
/// `[mismatch, 0, …]`, the app's mismatch code alone, its completed note
/// and its ciphertext under the mismatch domain's nonce (`seal_nonce(_,
/// false)`), exactly as `finish` seals it. Total.
pub fn encrypt_mismatch<let N: u32>(
    mismatch: Field,
    outcome_key: Field,
    partial: Field,
    storage_slot: Field,
    request_id: Field,
) -> EncryptedOutcome<N + 1> {
    seal(false, mismatch, [0; N], outcome_key, partial, storage_slot, request_id)
}

/// The one seal of an outcome: the plaintext `shown(opened, mismatch,
/// fields)`, the completed note over it and its ciphertext under
/// `seal_nonce(note_hash, opened)`. Total.
fn seal<let N: u32>(
    opened: bool,
    mismatch: Field,
    fields: [Field; N],
    outcome_key: Field,
    partial: Field,
    storage_slot: Field,
    request_id: Field,
) -> EncryptedOutcome<N + 1> {
    let plaintext = shown(opened, mismatch, fields);
    let note_hash = completed_note_hash(storage_slot, partial, plaintext, request_id);
    EncryptedOutcome { note_hash, ciphertext: encrypt_under(plaintext, outcome_key, seal_nonce(note_hash, opened)) }
}

/// The public outputs of a round under private outcomes, after its public
/// parameters `[namespace, vk_hash, in_slots, out_slots, pinned reads]`, in
/// the order pss_public_contract's `outcome::outcome_public_inputs` rebuilds
/// them: `[request_id, machine_request_id, old_commitments[R],
/// new_commitments[W], npk_app_hash, new_hashes[T], outcome_tag,
/// note_hashes[H], ciphertext[L]]`. `ok`, the code and the app outputs are
/// not among them: they are inside the ciphertext.
pub struct Private<let R: u32, let W: u32, let T: u32, let H: u32, let L: u32> {
    /// the chain request id over C (`super::intake::shared`); apply requires
    /// it to equal requests[head]
    pub request_id: Field,
    /// `machine_request_id(request_id, old_commitments, pinned values)`
    pub machine_request_id: Field,
    pub old_commitments: [Field; R],
    /// every new commitment under a fresh blinding, whatever `ok` is
    pub new_commitments: [Field; W],
    pub npk_app_hash: Field,
    /// the new leaf hashes of a tree-valued key the round writes, in slot
    /// order (the manifest's `tree` `new_hashes`), from which the nodes
    /// rebuild their clear tree; none (T = 0) for a flat key. Hiding: each
    /// written leaf carries a fresh blinding
    pub new_hashes: [Field; T],
    /// `$outcome_tag`: the log's tag, which the kernel silos with the
    /// contract address
    pub outcome_tag: Field,
    pub note_hashes: [Field; H],
    pub ciphertext: [Field; L],
}

/// Finish a round under private outcomes: the machine request id over the
/// secret-shared chain request id (`SharedIntake::request_id`), the commitment the
/// round read and the `pinned` values (the manifest's `public_reads` order,
/// `[]` without pinned reads); `fields`, the outcome plaintext (`code` first),
/// or, when the shares did not open C (`opened` false), the app's
/// `mismatch` code alone, sealed (`seal`): the request's partial note
/// (`SharedIntake::partial`) completed at the app's `storage_slot` with the
/// plaintext and the chain request id (`completed_note_hash`; the note
/// packs `[fields…, request_id]`, so `N` is at most seven), and the
/// plaintext encrypted under the nonce of that note hash in the opened or
/// the mismatch domain (`seal_nonce`); and `Private` over the one key the
/// round reads and writes (`written`, with its new leaf hashes when it is a
/// tree). Crate-visible: `opened` and `mismatch` come only from
/// `super::family`'s `Checked`, which only the intake's check makes. The
/// main ends in `Finished::stored`.
///
/// Constraints: the machine request id, the secret-shared request id, the
/// note hash, the nonce and the AEAD (permutations, selects and additions)
/// and npk_app_hash (the std scalar decomposition of nsk_app,
/// hint-satisfiable for every Field, and one fixed-base multi_scalar_mul,
/// which cannot fail). No assert.
pub(crate) fn finish<S, let T: u32, let Q: u32, let N: u32>(
    written: S,
    namespace: Field,
    vk_hash: Field,
    shared: SharedIntake,
    opened: bool,
    mismatch: Field,
    pinned: [Field; Q],
    fields: [Field; N],
    storage_slot: Field,
    nsk_app: Field,
) -> Finished<S, Private<1, 1, T, 1, N + 1>>
where
    S: Written<T>,
{
    let request_id = shared.request_id(namespace, vk_hash);
    let attempt = machine_request_id(request_id, [written.commitments().0], pinned);
    let sealed = seal(opened, mismatch, fields, shared.outcome_key, shared.partial, storage_slot, request_id);
    private_outputs(written, request_id, attempt, shared, sealed, nsk_app)
}

/// `Private` over the key `written`, the attempt and the sealed outcome.
fn private_outputs<S, let T: u32, let L: u32>(
    written: S,
    request_id: Field,
    attempt: Field,
    shared: SharedIntake,
    sealed: EncryptedOutcome<L>,
    nsk_app: Field,
) -> Finished<S, Private<1, 1, T, 1, L>>
where
    S: Written<T>,
{
    let (old_c, new_c) = written.commitments();
    let outputs = Private {
        request_id,
        machine_request_id: attempt,
        old_commitments: [old_c],
        new_commitments: [new_c],
        npk_app_hash: effects::npk_app_hash(nsk_app),
        new_hashes: written.leaf_hashes(),
        outcome_tag: shared.outcome_tag,
        note_hashes: [sealed.note_hash],
        ciphertext: sealed.ciphertext,
    };
    Finished { written, outputs }
}

/// The public outputs of a round under private outcomes with K public
/// values of the attempt after the ciphertext, which the app's contract
/// takes with the result and its `apply` reads (pss_public_contract's
/// `outcome::Private::valued`; the manifest's `app_values` names them):
/// e.g. the inputs-opened bit of an app that escrows. `Private`'s fields in
/// its order, then the K
/// values; flat, so its return paths are `Private`'s and then
/// `app_values[0..K]`. A value is public, so it must be one the app may
/// show: never an amount, an owner or anything of the outcome.
pub struct Valued<let R: u32, let W: u32, let T: u32, let H: u32, let L: u32, let K: u32> {
    pub request_id: Field,
    pub machine_request_id: Field,
    pub old_commitments: [Field; R],
    pub new_commitments: [Field; W],
    pub npk_app_hash: Field,
    pub new_hashes: [Field; T],
    pub outcome_tag: Field,
    pub note_hashes: [Field; H],
    pub ciphertext: [Field; L],
    pub app_values: [Field; K],
}

impl<S, let R: u32, let W: u32, let T: u32, let H: u32, let L: u32> Finished<S, Private<R, W, T, H, L>> {
    /// The round with K public values for the app's contract after its
    /// outputs (`Valued`). No constraint.
    pub fn valued<let K: u32>(self, app_values: [Field; K]) -> Finished<S, Valued<R, W, T, H, L, K>> {
        let o = self.outputs;
        Finished {
            written: self.written,
            outputs: Valued {
                request_id: o.request_id,
                machine_request_id: o.machine_request_id,
                old_commitments: o.old_commitments,
                new_commitments: o.new_commitments,
                npk_app_hash: o.npk_app_hash,
                new_hashes: o.new_hashes,
                outcome_tag: o.outcome_tag,
                note_hashes: o.note_hashes,
                ciphertext: o.ciphertext,
                app_values,
            },
        }
    }
}

mod tests {
    use super::{
        completed_note_hash, completion_log_tag, DOM_SEP__NOTE_COMPLETION_LOG_TAG,
        DOM_SEP__PARTIAL_NOTE_COMMITMENT, encrypt, encrypt_mismatch, encrypt_outcome, finish, log_padding,
        machine_request_id, outcome_nonce, partial_commitment, PSS_ATTEMPT, seal_nonce, shown,
        SIDECAR_MISMATCH_AD, SIDECAR_OUTCOME_AD,
    };
    use crate::effects;
    use crate::tip::intake::{shared, SharedIntake};
    use crate::tip::slot;
    use pss_utils::ae::AE;
    use protocol_types::constants::DOM_SEP__NOTE_HASH;
    use protocol_types::hash::{compute_log_tag, poseidon2_hash, poseidon2_hash_with_separator};
    use crate::test_support::ascii;

    global NS: Field = 0xc0ffee;
    global VK: Field = 0x5a;
    global NSK_APP: Field = 777;
    /// The outcome key, and a note hash the tests encrypt under.
    global KEY: Field = 0x6b;
    global NOTE: Field = 0x3a;

    fn intake() -> SharedIntake {
        SharedIntake {
            inputs_hash: 0xc,
            partial: partial_commitment(0xa11ce, 0x5eed),
            outcome_key: KEY,
            outcome_tag: 0x7a,
            blinding: 0xb1,
        }
    }

    #[test]
    fn the_domains_are_the_labels() {
        assert_eq(ascii("sidecar.attempt"), PSS_ATTEMPT);
        assert_eq(ascii("sidecar.outcome"), SIDECAR_OUTCOME_AD);
        assert_eq(ascii("sidecar.mismatch"), SIDECAR_MISMATCH_AD);
    }

    #[test]
    fn the_derivations_are_poseidon2_of_their_preimages() {
        assert_eq(
            machine_request_id(0x1d, [0x0c, 0x0d], [0x7d0]),
            poseidon2_hash([PSS_ATTEMPT, 0x1d, 0x0c, 0x0d, 0x7d0]),
        );
        assert_eq(machine_request_id(0x1d, [0x0c], []), poseidon2_hash([PSS_ATTEMPT, 0x1d, 0x0c]));
        assert_eq(log_padding(0x7a, 5), poseidon2_hash([0x7a, 5]));
        assert_eq(log_padding(0x7a, 14), poseidon2_hash([0x7a, 14]));
    }

    // The nonce is the note hash under one of two labels: "sidecar.outcome"
    // when the shares open C, "sidecar.mismatch" when they do not. One note
    // hash gives two nonces, and the two domains never meet.
    #[test]
    fn the_nonce_is_the_note_hash_under_its_domain() {
        assert_eq(seal_nonce(NOTE, true), poseidon2_hash([NOTE, ascii("sidecar.outcome")]));
        assert_eq(seal_nonce(NOTE, false), poseidon2_hash([NOTE, ascii("sidecar.mismatch")]));
        assert_eq(outcome_nonce(NOTE), seal_nonce(NOTE, true));
        assert(seal_nonce(NOTE, true) != seal_nonce(NOTE, false));
        assert(outcome_nonce(NOTE) != outcome_nonce(NOTE + 1));
    }

    // aztec-nr's partial-note convention: the commitment over [owner,
    // randomness] under its separator, the completed hash as compute_note_hash
    // over [P, fields…, request_id], the completion tag as compute_log_tag.
    #[test]
    fn the_partial_note_hashes_are_aztec_nrs() {
        assert_eq(DOM_SEP__PARTIAL_NOTE_COMMITMENT, 568912195);
        assert_eq(DOM_SEP__NOTE_COMPLETION_LOG_TAG, 3372669888);
        let p = partial_commitment(0xa11ce, 0x5eed);
        assert_eq(p, poseidon2_hash_with_separator([0xa11ce, 0x5eed], 568912195));
        assert_eq(
            completed_note_hash(0x2a, p, [0, 24000], 0x1d),
            poseidon2_hash_with_separator([0x2a, p, 0, 24000, 0x1d], DOM_SEP__NOTE_HASH),
        );
        assert_eq(completion_log_tag(p), compute_log_tag(p, 3372669888));
        // another owner or randomness, another commitment
        assert(partial_commitment(0xb0b, 0x5eed) != p);
        assert(partial_commitment(0xa11ce, 0x5eee) != p);
    }

    // Seven outcome fields and request_id: eight packed fields, the cap.
    #[test]
    fn seven_outcome_fields_fill_the_note() {
        let h = completed_note_hash(0x2a, 0x9, [0, 1, 2, 3, 4, 5, 6], 0x1d);
        assert_eq(
            h,
            poseidon2_hash_with_separator([0x2a, 0x9, 0, 1, 2, 3, 4, 5, 6, 0x1d], DOM_SEP__NOTE_HASH),
        );
    }

    // The ciphertext opens with the key under its note hash's nonce, and
    // only there: another note hash's nonce does not open it. A seven-field
    // outcome (lending's) is three blocks, eight fields with the tag.
    #[test]
    fn the_ciphertext_opens_with_the_key_under_its_note_hash() {
        let pt = [1, 0, 7, 0, 100, 200, 50];
        let ct = encrypt(pt, KEY, NOTE);
        let mut body = [0; 7];
        for i in 0..7 {
            body[i] = ct[i];
        }
        assert_eq(AE::decrypt(body, ct[7], KEY, outcome_nonce(NOTE)), pt);
    }

    #[test(should_fail_with = "ae: tag mismatch")]
    fn another_note_hashs_nonce_does_not_open_it() {
        let ct = encrypt([1, 4, 25000], KEY, NOTE);
        let _ = AE::decrypt([ct[0], ct[1], ct[2]], ct[3], KEY, outcome_nonce(0x3b));
    }

    // Under one key and one nonce, the ciphertext difference would be the
    // plaintext difference; under two note hashes' nonces it is not.
    #[test]
    fn two_note_hashes_do_not_share_a_keystream() {
        let a = encrypt([1, 0, 25000], KEY, NOTE);
        let b = encrypt([1, 0, 26000], KEY, 0x3b);
        assert(b[2] - a[2] != 1000);
        // under one nonce they would
        let c = encrypt([1, 0, 26000], KEY, NOTE);
        assert_eq(c[2] - a[2], 1000);
    }

    #[test]
    fn encrypt_outcome_is_the_completed_note_hash_and_the_ciphertext_under_its_nonce() {
        let p = partial_commitment(0xa11ce, 0x5eed);
        let s = encrypt_outcome([0, 25000], KEY, p, 0x2a, 0x1d);
        assert_eq(s.note_hash, completed_note_hash(0x2a, p, [0, 25000], 0x1d));
        assert_eq(s.ciphertext, encrypt([0, 25000], KEY, s.note_hash));
    }

    // A mismatch seal: the code alone, its note over that, under the
    // mismatch domain's nonce of that note hash. The same plaintext sealed
    // as an opened outcome has the same note hash and another ciphertext.
    #[test]
    fn encrypt_mismatch_is_the_code_alone_under_the_mismatch_nonce() {
        let p = partial_commitment(0xa11ce, 0x5eed);
        let m = encrypt_mismatch::<3>(9, KEY, p, 0x2a, 0x1d);
        assert_eq(m.note_hash, completed_note_hash(0x2a, p, [9, 0, 0], 0x1d));
        let (ct, tag) = AE::encrypt([9, 0, 0], KEY, seal_nonce(m.note_hash, false));
        assert_eq(m.ciphertext, ct.concat([tag]));
        assert_eq(AE::decrypt(ct, tag, KEY, poseidon2_hash([m.note_hash, ascii("sidecar.mismatch")])), [9, 0, 0]);
        let o = encrypt_outcome([9, 0, 0], KEY, p, 0x2a, 0x1d);
        assert_eq(o.note_hash, m.note_hash);
        assert(o.ciphertext != m.ciphertext);
    }

    // A round's outputs under private outcomes: the attempt over the secret-shared
    // request id, the commitment read and the pinned values; the plaintext
    // encrypted under its note hash's nonce and the request's partial note
    // completed with it and the request id.
    #[test]
    fn finish_completes_the_partial_note_over_the_written_key() {
        let round = slot::create(NS, 0xa002, [7, 8], 6);
        let f = finish(round, NS, VK, intake(), true, 9, [0x7d0], [0, 25000], 0x2a, NSK_APP);
        let o = f.outputs;
        assert_eq(o.request_id, shared(NS, VK, 0xc));
        let attempt = machine_request_id(o.request_id, [0], [0x7d0]);
        assert_eq(o.machine_request_id, attempt);
        assert_eq(o.old_commitments, [0]);
        assert_eq(o.new_commitments, [round.new_c]);
        assert_eq(o.npk_app_hash, effects::npk_app_hash(NSK_APP));
        assert_eq(o.new_hashes, []);
        assert_eq(o.outcome_tag, 0x7a);
        let sealed = encrypt_outcome([0, 25000], KEY, intake().partial, 0x2a, o.request_id);
        assert_eq(o.note_hashes, [sealed.note_hash]);
        assert_eq(o.ciphertext, sealed.ciphertext);
        assert_eq(o.ciphertext, encrypt([0, 25000], KEY, o.note_hashes[0]));
    }

    // Two runs of one attempt (one request, one old commitment, one set of
    // pinned values) draw two fresh blindings, so an outcome that carries a
    // value under the new blinding (lending's new leaf hash) differs between
    // them. Each run's nonce is its own note hash's, so the two plaintexts
    // never share a key and a nonce: the ciphertexts' difference is not the
    // plaintexts'.
    #[test]
    fn two_runs_of_one_attempt_with_different_plaintexts_use_different_nonces() {
        let first = slot::load(NS, 0xa002, 0xa002, [7, 8], 333, 444).finish_private(true, total::ctl::Outcome::good(), [9, 9]);
        let second = slot::load(NS, 0xa002, 0xa002, [7, 8], 333, 555).finish_private(true, total::ctl::Outcome::good(), [9, 9]);
        assert_eq(first.old_c, second.old_c);
        assert(first.new_c != second.new_c);
        let a = finish(first, NS, VK, intake(), true, 9, [0x7d0], [0, 25000, first.new_c], 0x2a, NSK_APP).outputs;
        let b = finish(second, NS, VK, intake(), true, 9, [0x7d0], [0, 25000, second.new_c], 0x2a, NSK_APP).outputs;
        // one attempt
        assert_eq(a.machine_request_id, b.machine_request_id);
        // two note hashes, two nonces
        assert(a.note_hashes[0] != b.note_hashes[0]);
        assert(outcome_nonce(a.note_hashes[0]) != outcome_nonce(b.note_hashes[0]));
        // the first block's difference is not the plaintexts'; under one
        // nonce it would be
        assert(b.ciphertext[2] - a.ciphertext[2] != second.new_c - first.new_c);
        let same = encrypt([0, 25000, second.new_c], KEY, a.note_hashes[0]);
        assert_eq(same[2] - a.ciphertext[2], second.new_c - first.new_c);
    }

    // A round whose shares do not open C seals the mismatch code alone,
    // whatever it computed, under the mismatch domain's nonce of its own
    // note hash (`encrypt_mismatch`).
    #[test]
    fn a_round_that_does_not_open_seals_the_mismatch_code_alone() {
        let round = slot::create(NS, 0xa002, [7, 8], 6);
        let honest = finish(round, NS, VK, intake(), true, 9, [0x7d0], [0, 25000, 3], 0x2a, NSK_APP).outputs;
        let forced = finish(round, NS, VK, intake(), false, 9, [0x7d0], [5, 26000, 4], 0x2a, NSK_APP).outputs;
        // one attempt: one machine request id
        assert_eq(forced.machine_request_id, honest.machine_request_id);
        let m = encrypt_mismatch::<3>(9, KEY, intake().partial, 0x2a, forced.request_id);
        assert_eq(forced.note_hashes, [m.note_hash]);
        assert_eq(forced.ciphertext, m.ciphertext);
        // the honest ciphertext less the forced one is not the plaintext
        // difference
        assert(honest.ciphertext[1] - forced.ciphertext[1] != 25000);
    }

    #[test]
    fn shown_is_the_fields_or_the_code_alone() {
        assert_eq(shown(false, 9, [5, 26000, 4]), [9, 0, 0]);
        assert_eq(shown(true, 9, [5, 26000, 4]), [5, 26000, 4]);
        assert_eq(shown(false, 0, [5, 26000, 4]), [0, 0, 0]);
        assert_eq(shown(false, 9, [5]), [9]);
    }
}
