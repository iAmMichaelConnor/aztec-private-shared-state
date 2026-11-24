//! The counter contract's app part: the package names, the pins, the round
//! table, the validity check and the outcome note. Outside the `#[aztec]`
//! module so the tests import them directly.
use aztec::protocol::traits::{Deserialize, Packable, Serialize};
use pss_public_contract::{CommitmentSlot, Configured, is_u64, KeyEpochs, NoEncKeys, package_hash, StateKeys, TipPins, TipRound};
use pss_public_contract::outcome::{OutcomeApply, OutcomeResult};
use pss_public_contract::partial_note::outcome_note;

/// The outcome ciphertext's length: the circuits' own (counter_tip
/// shared.nr), so the contract and the round cannot disagree.
pub use counter_circuit::shared::CIPHERTEXT_LEN as OUTCOME_CIPHERTEXT;

/// The slot the add round hashes each completed note at, the circuits' own
/// `OUTCOME_SLOT`, which `process_result` checks is the `outcome_notes` slot
/// (`Private::of`).
pub use counter_circuit::shared::OUTCOME_SLOT;

/// The packages a deployment lists: the init and the add.
pub global PACKAGES: u32 = 2;

/// The package name hashes (`package_hash` of each manifest's `circuit`):
/// `counter_init` (`init_counter`);
pub global COUNTER_INIT_PACKAGE: Field = package_hash("counter_init");
/// `counter_add` (`add`, `process_result`).
pub global COUNTER_ADD_PACKAGE: Field = package_hash("counter_add");

/// The constructor's pins: the library's `TipPins` (the stale period, the
/// node `sig` keys, the contract manifest's hash, the package list in
/// REGISTER order and each package's vk hash), so the address commits to the
/// circuits; `configure` adds `npk_app_hash`.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct Config {
    pub tip: TipPins<PACKAGES>,
}

// BRICK node_keys = rotating (pss_public_contract::KeyEpochs): the rows and the state view name the
// brick through Keys alone, with rotate_keys, set_node_keys, assert_key_epoch and get_node_keys in
// main.nr. Alternatives: fixed (FixedKeys here, none of the four; examples/credits-tip).
// docs/design-guide/BRICKS.md#node_keys
/// The node-keys brick every node signature is checked under: key epochs,
/// which the contract's `rotate_keys` moves. The contract holds no node
/// `enc` keys (no secret-shared on-chain intake): `NoEncKeys`, which
/// `set_node_keys` hands `Keys::install`.
pub type Keys = KeyEpochs<NoEncKeys>;

/// The round table: one row per circuit, its vk pin and the counter key.
pub struct Rounds<C> {
    /// `counter_init`: creates the counter key, outside the queue
    pub init: TipRound<C, 0, 1, Keys>,
    /// `counter_add`: reads and writes the counter key
    pub add: TipRound<C, 1, 1, Keys>,
}

/// The round table over the circuits in force and the counter slot.
pub fn rounds<C>(tip: Configured<PACKAGES>, counter: CommitmentSlot<C>) -> Rounds<C> {
    Rounds {
        init: tip.round(COUNTER_INIT_PACKAGE, init_state_keys(counter)),
        add: tip.round(COUNTER_ADD_PACKAGE, counter_state_keys(counter)),
    }
}

/// The init round's keys: it creates the counter key.
pub fn init_state_keys<C>(counter: CommitmentSlot<C>) -> StateKeys<C, 0, 1> {
    StateKeys::create([counter])
}

/// The add round's keys: it reads and writes the counter key.
pub fn counter_state_keys<C>(counter: CommitmentSlot<C>) -> StateKeys<C, 1, 1> {
    StateKeys::one(counter)
}

/// The add round's result under private outcomes: the counter read and
/// written, no pinned read, one completed note hash and the ciphertext.
pub type AddResult = OutcomeResult<1, 1, 0, 1, OUTCOME_CIPHERTEXT>;

/// What `apply_result` lands: the request id and the counter's commitments.
pub type AddApply = OutcomeApply<1, 1, 0>;

/// The static validity of an add request, `[amount]`, asserted in the
/// requester's PXE before anything is queued.
///
/// DEV DECISION: intake refuses an amount that is not a u64, which the
/// circuit would answer with code 2; whether the sum overflows depends on
/// the secret total and stays the circuit's outcome. Design guide: "access
/// control".
pub fn valid_add(inputs: [Field; 1]) -> bool {
    is_u64(inputs[0])
}

/// The completed note of an add, the requester's record of its round: the
/// outcome `[code, total]` and the chain request id, at the contract's
/// `outcome_notes` slot. The round completes it inside the co-SNARK and the
/// requester's client hands it to its PXE (`deliver_outcome`). An ordinary
/// note of the owner's (`outcome_note`); nothing spends it.
#[derive(Deserialize, Eq, Packable, Serialize)]
#[outcome_note]
pub struct AddOutcomeNote {
    pub code: Field,
    pub total: Field,
    pub request_id: Field,
}
