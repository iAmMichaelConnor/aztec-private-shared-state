//! The AMM tip contract's types, pins and plain functions, outside the
//! `#[aztec]` module so the tests import them directly.
use aztec::protocol::traits::{Deserialize, Packable, Serialize};
use aztec::context::PublicContext;
use pss_public_contract::{CommitmentSlot, Configured, DEFAULT_UPGRADE_DELAY, is_u64, KeyEpochs, package_hash, SharedOnchain, StateKeys, TipPins, TipRound};
use pss_public_contract::outcome::{OutcomeApply, OutcomeResult};
use pss_public_contract::partial_note::outcome_note;
use pss_public_contract::result::PartialResult;

/// The swap's inputs, `[amount_in, direction, min_out]`, in ABI order:
/// what `valid_swap` checks and the swap rounds trade on.
pub global SWAP_INPUTS: u32 = 3;

/// The non-secret-shared swap's app inputs, the swap's inputs and then the
/// request's partial note, `[amount_in, direction, min_out, partial_note]`
/// (examples/amm-tip/circuits amm_swap_tip): what `inputs_hash` covers and
/// the on-chain intake's request log carries.
pub global PLAIN_SWAP_INPUTS: u32 = SWAP_INPUTS + 1;

/// The longest public log the contract emits: an on-chain intake swap's
/// request log, `[amount_in, direction, min_out, partial_note, user_nonce]`
/// after the tag (`log_in_tx` reads it). `apply`'s completion log is
/// `[storage_slot, code, amount_out, request_id]`, shorter (the pool is
/// node-held: `apply` and `apply_init` log no state).
pub global MAX_LOG_FIELDS: u32 = PLAIN_SWAP_INPUTS + 1;

// BRICK outputs = public (pss_public_contract::result::PartialResult). Alternatives:
// private (SwapSharedResult below, the secret-shared swap's). docs/design-guide/BRICKS.md#outputs
/// One swap round's result under the non-secret-shared intakes, as
/// `process_result` checks it and `apply` lands it: the request's partial
/// note, one key read and written (the pool), no pinned public reads, two
/// app outputs (`code`, `amount_out`; `ok` is the result's own field).
pub type SwapResult = PartialResult<1, 1, 0, 2>;

/// The values the secret-shared swap's inputs commitment C covers before its
/// blinding, in the round's ABI order: `[amount_in, direction, min_out,
/// partial_note, outcome_key, outcome_tag]` (examples/amm-tip/circuits
/// amm_swap_tip_shared), what `swap_shared` hashes; it computes
/// `partial_note` from the sender and `rho` itself.
pub global SHARED_VALUES: u32 = SWAP_INPUTS + 3;

/// The secret-shared swap's outcome ciphertext length, `[code, amount_out]`
/// and the AEAD tag: the circuits' own `CIPHERTEXT_LEN` (circuits/amm_tip
/// shared.nr), so the contract and the round cannot disagree.
pub use swap_circuit::shared::CIPHERTEXT_LEN as OUTCOME_CIPHERTEXT;

/// The slot the secret-shared round hashes each completed note at, the
/// circuits' own `OUTCOME_SLOT`, which `process_result_shared` checks is
/// the `outcome_notes` slot (`Private::of`).
pub use swap_circuit::shared::OUTCOME_SLOT;

// BRICK outputs = private (pss_public_contract::outcome::OutcomeResult). Alternatives:
// public (SwapResult above, the non-secret-shared swap's). docs/design-guide/BRICKS.md#outputs
/// One secret-shared swap's result under private outcomes, as
/// `process_result_shared` takes it: the pool read and written, no pinned
/// read, one completed note hash and the three-field ciphertext.
pub type SwapSharedResult = OutcomeResult<1, 1, 0, 1, OUTCOME_CIPHERTEXT>;

/// What `apply_shared` lands: the request id and the pool's commitments.
pub type SwapSharedApply = OutcomeApply<1, 1, 0>;

/// The packages a deployment lists: its capacity, the length of the
/// constructor's package list. Two: the init and one entry of the swap
/// round, the non-secret-shared one (`PLAIN_PACKAGES`) or the secret-shared one
/// (`SHARED_PACKAGES`), since one namespace takes one intake family per
/// key (README "Deployment").
pub global PACKAGES: u32 = 2;

/// The delay of a circuit upgrade (pss_public_contract `upgrades`): one
/// day, the library's default (`DEFAULT_UPGRADE_DELAY`, its DEV DECISION).
pub global UPGRADE_DELAY: u64 = DEFAULT_UPGRADE_DELAY;

/// The package name hashes (`package_hash` of each manifest's `circuit`):
/// `amm_init_tip`, the init round (`init_pool`);
pub global AMM_INIT_TIP_PACKAGE: Field = package_hash("amm_init_tip");
/// `amm_swap_tip`, the swap (`swap`, `swap_with_receipts`, `process_result`):
/// one compiled circuit for both non-secret-shared intakes, which the network also
/// registers as `amm_swap_tip_receipt` (the same vk) for receipt intake.
pub global AMM_SWAP_TIP_PACKAGE: Field = package_hash("amm_swap_tip");

/// `amm_swap_tip_shared`, the swap's secret-shared-intake entry (`swap_shared`,
/// `process_result_shared`): its own compiled circuit, since its public
/// inputs carry the private outcome in place of the non-secret-shared
/// outputs.
pub global AMM_SWAP_TIP_SHARED_PACKAGE: Field = package_hash("amm_swap_tip_shared");

/// The non-secret-shared deployment's package list, in REGISTER order: the init, the
/// swap (README "Deployment").
pub global PLAIN_PACKAGES: [Field; PACKAGES] = [AMM_INIT_TIP_PACKAGE, AMM_SWAP_TIP_PACKAGE];

/// The secret-shared deployment's package list, in REGISTER order: the init (a
/// non-secret-shared round that reads no key, so it sits beside a secret-shared writer), the
/// secret-shared swap.
pub global SHARED_PACKAGES: [Field; PACKAGES] =
    [AMM_INIT_TIP_PACKAGE, AMM_SWAP_TIP_SHARED_PACKAGE];

/// The constructor's pins: the library's `TipPins` (the stale period, the
/// three node `sig` keys, the contract manifest's hash, the package list and
/// each package's vk hash). Nothing here depends on the namespace, so the address is known before
/// any REGISTER, and it commits to the circuits; `configure` adds
/// `npk_app_hash` (pss_public_contract `configure`).
///
/// DEV DECISION: what the Config pins, default the `TipPins`, fixed at
/// deployment in a `PublicImmutable`; a new circuit, a new network or a new
/// stale period is a new deployment. It pins no node `enc` keys: neither
/// non-secret-shared on-chain intake nor secret-shared receipt intake
/// encrypts to the nodes in the contract (DECISIONS.md, "On-chain intake"),
/// and `enc` rotates while this pin could not (see `TipConfig`). A
/// deployment with a real token pins the token here too, for `redeem`'s
/// payout. Design guide: "init strategy".
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct Config {
    /// the stale period, the node `sig` keys and the circuit pins (the
    /// contract manifest's hash, the package list and the vk hashes)
    pub tip: TipPins<PACKAGES>,
}

// BRICK node_keys = rotating (pss_public_contract::KeyEpochs): the rows, check_enc_rotation and the
// state view name the brick through Keys alone, with rotate_keys, set_node_keys, assert_key_epoch and
// get_node_keys in main.nr. Alternatives: fixed (FixedKeys here, none of the four; examples/credits-tip).
// docs/design-guide/BRICKS.md#node_keys
// BRICK intake = shared_onchain (pss_public_contract::SharedOnchain): the node enc keys Keys names, which
// set_node_keys hands Keys::install and the intake requires (RetiresEncKeys). Alternatives: onchain, receipt,
// shared_receipt (KeyEpochs<NoEncKeys>, in a contract without the intake). docs/design-guide/BRICKS.md#intake
/// The node-keys brick every node signature is checked under: key epochs,
/// which the contract's `rotate_keys` moves, over the contract's
/// `SharedOnchain` (secret-shared on-chain intake), whose replaced nodes'
/// `enc` keys `set_node_keys` voids (`Keys::install`).
pub type Keys = KeyEpochs<SharedOnchain<PublicContext>>;

/// The AMM's round table: one row per compiled circuit, its vk pin (the
/// constructor's; 0 when the deployment does not list it) and the pool
/// key. The swap is one compiled circuit for both non-secret-shared intakes and one
/// for the secret-shared intake, so it has two rows, of which a deployment lists
/// one. Every row checks node signatures under the node-keys brick, `Keys`.
pub struct Rounds<C> {
    /// `amm_init_tip`: creates the pool key, outside the queue
    pub init: TipRound<C, 0, 1, Keys>,
    /// `amm_swap_tip`, the swap under either non-secret-shared intake
    pub swap: TipRound<C, 1, 1, Keys>,
    /// `amm_swap_tip_shared`, the swap under secret-shared receipt intake
    pub swap_shared: TipRound<C, 1, 1, Keys>,
}

/// The round table over the stored `Configured` and the pool slot; every
/// row asserts the contract is configured. The private functions take their
/// rows from it; the public applies take only the rows' keys, which come
/// from the slot alone (`init_state_keys`, `pool_state_keys`), so they read no pin.
pub fn rounds<C>(tip: Configured<PACKAGES>, pool: CommitmentSlot<C>) -> Rounds<C> {
    Rounds {
        init: tip.round(AMM_INIT_TIP_PACKAGE, init_state_keys(pool)),
        swap: tip.round(AMM_SWAP_TIP_PACKAGE, pool_state_keys(pool)),
        swap_shared: tip.round(AMM_SWAP_TIP_SHARED_PACKAGE, pool_state_keys(pool)),
    }
}

/// The init round's keys: it creates the pool key.
pub fn init_state_keys<C>(pool: CommitmentSlot<C>) -> StateKeys<C, 0, 1> {
    StateKeys::create([pool])
}

/// The swap's keys, under every intake: it reads and writes the pool alone.
pub fn pool_state_keys<C>(pool: CommitmentSlot<C>) -> StateKeys<C, 1, 1> {
    StateKeys::one(pool)
}

/// The static validity of a swap request, `[amount_in, direction,
/// min_out]`, which every intake function asserts before anything is
/// queued (secret-shared receipt intake over the swap inputs among C's values, in
/// the user's PXE; the non-secret-shared intakes through `valid_plain_swap`): a non-zero `amount_in` below 2^64, a `direction` of 0
/// or 1 and a `min_out` below 2^64. It sees the inputs only, as intake
/// requires; the partial note and the reserved values are not checked.
///
/// DEV DECISION: intake refuses exactly the requests the total circuit
/// would answer with codes 1, 2, 3 and an over-wide `min_out`, so those
/// never cost a round; whether a trade succeeds against the pool (codes 4
/// to 8) depends on the secret state and stays the circuit's `ok`. A
/// `min_out` of 0 sets no limit. Looser (no check): every malformed request
/// costs the network a round and lands as an `ok = 0` no-op. Stricter
/// checks would have to be state-free. Design guide: "access control".
pub fn valid_swap(swap: [Field; SWAP_INPUTS]) -> bool {
    let amount_in = swap[0];
    let direction = swap[1];
    let min_out = swap[2];
    (amount_in != 0)
        & is_u64(amount_in)
        & ((direction == 0) | (direction == 1))
        & is_u64(min_out)
}

/// `valid_swap` over the non-secret-shared swap's inputs `[amount_in,
/// direction, min_out, partial_note]`.
pub fn valid_plain_swap(inputs: [Field; PLAIN_SWAP_INPUTS]) -> bool {
    valid_swap([inputs[0], inputs[1], inputs[2]])
}

/// The completed note of a swap, the trader's value note (docs/ARCHITECTURE.md
/// section 6, "Partial-note delivery"): the outcome `[code,
/// amount_out]` and the chain request id last, three packed fields, at the
/// contract's `outcome_notes` slot. The trader's request commits the partial
/// note `partial_commitment(owner, rho)` from its own address and its
/// client's `rho`. Under a secret-shared intake the round completes it
/// inside the co-SNARK (`pss_core::tip::outcome::finish`) and the trader's
/// client hands the note to its PXE (`deliver_outcome`, randomness `rho`);
/// under the non-secret-shared intakes `apply` completes it in public
/// (`pss_public_contract::result::PartialResult::completing`) and the trader's
/// PXE, told of the partial note by the request's message, finds the
/// completion log itself. The library's outcome note
/// (`pss_public_contract::partial_note::outcome_note`: both steps of
/// aztec-nr's two-step hash, the canonical nullifier), so the completed
/// note is an ordinary note of the owner's, and `redeem` spends it once (the note is not chained: nothing else
/// reads it). `code = 0` says the swap traded; a failed swap's note says
/// why, with `amount_out = 0`.
#[derive(Deserialize, Eq, Packable, Serialize)]
#[outcome_note]
pub struct SwapOutcomeNote {
    pub code: Field,
    pub amount_out: Field,
    pub request_id: Field,
}

/// How many swap notes an owner's PXE holds, and the first one (a zero note
/// when there is none), as the contract's `swap_notes` utility reports them.
#[derive(Deserialize, Eq, Serialize)]
pub struct SwapNotes {
    pub count: u32,
    pub first: SwapOutcomeNote,
}

