//! Contract side of private shared state at the tip of the chain: the
//! library an app contract builds its queue and its result transaction from.
//!
//! What it holds (docs/ARCHITECTURE.md section 6):
//! - `app`: the app skeleton, the round table's `TipRound` and `StateKeys` that
//!   every entry point below takes;
//! - `queue`: the queue's storage (`requests`, `tail`, `head` with its
//!   clock `head_since`, the `request_id -> seen` mapping and `done`), the
//!   commitment slots, and the bodies of `append()` and `skip()`;
//! - `intake`: the chain request id and on-chain intake (the request log
//!   around `append`); `receipt`: receipt intake (the three node receipts
//!   and the expiry check); `shared_intake`: the secret-shared intakes' inputs
//!   commitment `C`, their chain request id and secret-shared receipt intake (the
//!   user's sharing proved to open `C`, and the three receipts over `C` and
//!   the sharing's digest); `shared_onchain`: secret-shared on-chain intake (the
//!   nodes' `enc` keys and epochs in public storage with their rotation, the
//!   encoded request log, the stored data hash and the epoch bound at
//!   `append`);
//! - `result`: the result transaction, private `check_round` (the vk pin,
//!   the proof over the outputs brick's public-input layout, whose request
//!   id the proof outputs, and the three result-signature checks) and
//!   public `apply_round` (pinned reads first, then the head and slot
//!   checks, the writes and `done[index]`), over two seams: the outputs
//!   (`Outputs` and `Lands`: public outputs as `TipResult`, or
//!   `PartialResult` whose `completing` lands its partial note in public,
//!   for the non-secret-shared intakes) and the state mode (`Sealing`:
//!   `NodeHeld` or `chain_state`'s thirds);
//! - `outcome`: private outcomes (the secret-shared intakes), the other
//!   outputs brick: `Private` (the revertible phase, the proof, the outcome
//!   note hashes and the padded outcome log; the completed note is the
//!   value note, nothing runs after the log), `OutcomeApply` (every
//!   commitment written, no `ok`) and `deliver_outcome_note` (or
//!   `deliver_outcome_into`, over the app's outcome-note set) for the app's
//!   outcome-note utility;
//! - `partial_note`: partial-note delivery, the app's outcome note
//!   (`#[outcome_note]`: its hash and canonical nullifier), the request side (`commit` with
//!   its use nullifier, `deliver_partial_note`, and `commit_with`,
//!   `deliver_partial_note_with` for a note whose commitment binds private
//!   content), the public completion (`complete_in_public`, for `apply` and
//!   for a refund in `skip()`), and the spend of a chained note
//!   (`assert_owned`, `redeem`);
//! - `token`: tokens and escrow, public custody with the user's claim a note
//!   of the app's: in (`take`), the refund notes a request commits
//!   (`commit_refunds`, the `Refunds` record) and completes in `skip()`
//!   (`refund_skipped`) and `apply` (`settle_applied`), out (`prepare_note`
//!   and `pay`: a token partial note the app completes; `pay_public`), the
//!   payable-balance read (`public_balance`) and the `UsageDeposit` pin;
//! - `hatch`: the escape hatch, a state variable of one slot (`Hatch`): the
//!   clock every request (`queued`) and landing (`landed`, which also emits
//!   the round's exit tags as nullifiers) keeps, the opening (`open`) and
//!   the private exit on the sender's newest note of an entry (`exit`, over
//!   the app's `ExitNote`);
//! - `init`: the init round outside the queue (`process_init`,
//!   `apply_init`), checked as a result is;
//! - `chain_state`: chain-held state, the opt-in option: the `Sealing` of
//!   the sealed thirds (their hashes in the signed messages and the
//!   sealed-thirds log of every apply and of the init, tagged under its
//!   `PSS_STATE`), which a chain-held app hands the entry points in place
//!   of `NodeHeld {}`;
//! - `logs`: reading a contract's own public log back by tag (the request
//!   log, the sealed-thirds log), for an app's `log_in_tx` utility;
//! - `view`: `TipState`, the app's one state view (`get_state`): its
//!   Config, the configured pins, the queue's head and tail, its commitment
//!   slots and keys and the outcome notes' slot;
//! - `configure`: the deployment, a constructor that pins the circuits
//!   (`TipPins`: the stale policy, the node `sig` keys and the circuit pins,
//!   `CircuitPins`: the contract manifest's hash, the package list and each
//!   package's vk hash, so the address commits to them) and a once-only
//!   `configure` of `npk_app_hash`, checked against the three node
//!   signatures over the contract manifest's REGISTER answer, that stores
//!   `Configured` (the pins with `npk_app_hash`), which every other private
//!   function reads and which asserts `configured`; a public function reads
//!   a stored record's head alone (`read_head_in_public`; `skip()`'s stale
//!   period, `stale_blocks_in_public`; `read_stored_head` at a raw slot, the
//!   key epoch check's);
//! - `signing_keys`: the `node_keys` axis, where the `sig` keys every node
//!   signature is checked under come from (`SigningKeys`), named by the
//!   app's round table rows: `FixedKeys`, the constructor's keys for the
//!   life of the contract, or `key_epoch`'s `KeyEpochs`;
//! - `key_epoch`: the key epochs, the numbered key set (the nodes' `sig` and
//!   `enc` keys together) every node signature is checked under, its
//!   rotation by two of the three current nodes (`check_rotation`,
//!   `install`) and the grace window of the previous set (`signing_keys`,
//!   `assert_epoch`), stored at the library's own slot;
//! - `upgrades`: the `upgrades` axis, where the circuit pins a private
//!   function verifies under come from (`CircuitsInForce`): `FixedCircuits`,
//!   the constructor's pins for the life of the contract, or
//!   `CircuitUpgrades`, pins an upgrade authority the app names may replace
//!   after a delay (aztec-nr's `DelayedPublicMutable`);
//! - `config`: `TipConfig`, the pins the intake, result and init bodies
//!   read (the stale policy, the node `sig` keys and `npk_app_hash`), from
//!   `Configured::config`; `domains`: every domain constant and log-tag
//!   separator of the secret-shared path.
//!
//! Everything here is a plain function, a trait or a storage type, as in
//! `pss_contract`: an `#[aztec]` app contract declares the storage and writes
//! one-line `#[external]` wrappers around the bodies, so a contract composes
//! this library and `pss_contract` freely. `../pss_public_contract_test` is the
//! minimal such contract and the library's contract-level TXE suite.
pub mod app;
pub mod chain_state;
pub mod config;
pub mod configure;
pub mod domains;
pub mod handle;
pub mod hatch;
pub mod init;
pub mod intake;
pub mod key_epoch;
pub mod logs;
pub mod outcome;
pub mod partial_note;
pub mod queue;
pub mod receipt;
pub mod result;
pub mod shared_intake;
pub mod shared_onchain;
pub mod signing_keys;
pub mod token;
pub mod upgrades;
pub mod view;

pub use app::{StateKeys, TipRound};
pub use config::{DEFAULT_STALE_BLOCKS, NODES, StaleBlocks, TipConfig};
pub use configure::{
    assert_configured_in_public, assert_deployed, CircuitPins, Configured, ConfiguredHead,
    is_head_of, package_hash, read_head_in_public, read_in_public, read_stored_head, RegistryAnswer,
    stale_blocks_in_public, TipPins,
};
pub use domains::{
    MANIFEST_DOMAIN, PSS_ATTEMPT, PSS_ENC_ROTATE, PSS_ROTATE_KEYS, RECEIPT_DOMAIN, REQUEST_DOMAIN,
    RESULT_DOMAIN,
};
pub use hatch::{ExitNote, Hatch, HatchState};
pub use intake::{
    chain_request_id, inputs_hash, is_u128, is_u64, onchain_request, PlainRequest, request_log_tag,
    TWO_POW_128, TWO_POW_64,
};
pub use key_epoch::{EncKeys, KeyEpochs, KeySet, NoEncKeys, NODE_KEYS_SLOT, NodeKeys};
pub use outcome::{deliver_outcome_into, deliver_outcome_note, OutcomeApply, OutcomeResult, OutcomeTx, Private};
pub use queue::{
    assert_initialised, assert_ready, CommitmentSlot, DONE_APPLIED, DONE_PENDING, DONE_SKIPPED, Head, initialised,
    Queue,
};
pub use receipt::{
    check_epoch_receipts, check_receipts, Receipt, receipt_message, receipt_request, shared_receipt_message,
};
pub use result::{
    apply_round, check_round, Lands, no_pinned_reads, NodeHeld, Outputs, PartialResult,
    ResultSignature, Sealing, TipResult, Transition,
};
pub use shared_intake::{
    CHOSEN, CLEAR, inputs_commitment, Layout, opened_sharing, outcome_request, ReceiptRequest,
    shared_chain_request_id, shared_receipt_request, SharedReceiptArgs, SharedRequest, Sharing,
};
pub use shared_onchain::{
    check_enc_rotation, enc_rotation_message, EncKey, shared_onchain_request, SharedOnchain, SharedOnchainArgs,
    SharedOnchainRequest,
};
pub use signing_keys::{FixedKeys, RetiresEncKeys, SigningKeys};
pub use token::{Refunds, UsageDeposit};
pub use upgrades::{
    CircuitsInForce, CircuitUpgrades, DEFAULT_UPGRADE_DELAY, FixedCircuits, UpgradeAuthority, UpgradedPins,
    UpgradesAxis, UpgradesCircuits, UpgradesContract,
};
pub use view::TipState;

mod test {
    use aztec::protocol::hash::{poseidon2_hash, poseidon2_hash_with_separator};
    use total::hash::{p2_hash, p2_hash_sep};

    // total's fixed-length Poseidon2, which the library hashes with where a
    // value must be computed without a failure source, is Aztec's digest on a
    // chain request id preimage (namespace, vk_hash, inputs_hash, user_nonce).
    #[test]
    fn total_poseidon2_is_aztec_poseidon2_on_a_chain_request_id_preimage() {
        let preimage = [0x0a11ce, 0x7b, 0x1c, 3];
        assert_eq(p2_hash(preimage), poseidon2_hash(preimage));
        // an arbitrary u32 separator, passed as total takes it (a Field)
        assert_eq(
            p2_hash_sep(preimage, 0x50535301),
            poseidon2_hash_with_separator(preimage, 0x50535301 as u32),
        );
    }
}
