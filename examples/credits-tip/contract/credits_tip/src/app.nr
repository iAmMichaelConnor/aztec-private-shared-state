//! The credits tip contract's types, pins and plain functions, outside the
//! `#[aztec]` module so the tests import them directly.
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash_with_separator;
use aztec::protocol::traits::{Deserialize, Packable, Serialize, ToField};
use pss_public_contract::{CommitmentSlot, Configured, FixedKeys, is_u64, package_hash, StateKeys, TipPins, TipRound};
use pss_public_contract::outcome::{OutcomeApply, OutcomeResult};
use pss_public_contract::partial_note::outcome_note;

/// The outcome ciphertext's length, the four outcome fields `[code, round, a,
/// b]` and the AEAD tag: the circuits' own `CIPHERTEXT_LEN` (circuits/credits_tip
/// shared.nr), so the contract and the rounds cannot disagree.
pub use credits_circuit::shared::CIPHERTEXT_LEN as OUTCOME_CIPHERTEXT;

/// The slot the rounds hash each completed note at, the circuits' own
/// `OUTCOME_SLOT`, which `process_result` checks is the `outcome_notes` slot
/// (`Private::of`).
pub use credits_circuit::shared::OUTCOME_SLOT;
use credits_circuit::ledger::AMOUNT_BITS;

/// The packages a deployment lists: the init and the four queued rounds.
pub global PACKAGES: u32 = 5;

/// The package name hashes (`package_hash` of each manifest's `circuit`):
/// `credits_init`, the init round (`init_ledger`);
pub global CREDITS_INIT_PACKAGE: Field = package_hash("credits_init");
/// `pay` (`pay`);
pub global PAY_PACKAGE: Field = package_hash("pay");
/// `claim` (`claim`);
pub global CLAIM_PACKAGE: Field = package_hash("claim");
/// `view` (`view_balance`);
pub global VIEW_PACKAGE: Field = package_hash("view");
/// `move` (`move_credit`).
pub global MOVE_PACKAGE: Field = package_hash("move");

/// The deployment's package list, in REGISTER order (circuits/circuits.env's
/// round order): the init (a non-secret-shared round that reads no key, so it
/// sits beside the secret-shared writers), then the four queued rounds, each
/// under secret-shared receipt intake.
pub global CREDITS_PACKAGES: [Field; PACKAGES] =
    [CREDITS_INIT_PACKAGE, PAY_PACKAGE, CLAIM_PACKAGE, VIEW_PACKAGE, MOVE_PACKAGE];

/// The queued rounds' indices in the round table (`queued_round`): each round's
/// place in `CREDITS_PACKAGES`, its REGISTER seq. The relayer names a
/// result's round by it (`process_result`), a private argument the chain
/// never sees, and every outcome note names its round by it (`round`): the
/// circuits' own constants (circuits/credits_tip ledger.nr).
pub use credits_circuit::ledger::{ROUND_CLAIM, ROUND_MOVE, ROUND_PAY, ROUND_VIEW};

/// The constructor's pins: the library's `TipPins` (the stale period, the
/// three node `sig` keys, the contract manifest's hash, the package list and
/// each package's vk hash), so the address commits to the circuits and the
/// manifest; `configure` adds `npk_app_hash`.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct Config {
    pub tip: TipPins<PACKAGES>,
}

// BRICK node_keys = fixed (pss_public_contract::FixedKeys): every node signature is checked under the
// constructor's keys, and the contract declares no rotation. Alternatives: rotating (KeyEpochs here,
// with rotate_keys, set_node_keys, assert_key_epoch and get_node_keys; examples/amm-tip).
// docs/design-guide/BRICKS.md#node_keys
/// The node-keys brick every node signature is checked under, named once
/// here for the rows and the state view: the constructor's keys.
pub type Keys = FixedKeys;

/// The init round's row: `credits_init` creates the ledger key, outside the
/// queue.
pub fn init_round<C>(tip: Configured<PACKAGES>, ledger: CommitmentSlot<C>) -> TipRound<C, 0, 1, Keys> {
    tip.round(CREDITS_INIT_PACKAGE, init_state_keys(ledger))
}

/// The init round's keys: it creates the ledger key. The init's row takes
/// them, and so does `apply_init`, which reads no pin.
pub fn init_state_keys<C>(ledger: CommitmentSlot<C>) -> StateKeys<C, 0, 1> {
    StateKeys::create([ledger])
}

/// Every queued round's keys: it reads and writes the ledger alone. The
/// rows take them, and so does `apply_result`, which reads no pin.
pub fn ledger_state_keys<C>(ledger: CommitmentSlot<C>) -> StateKeys<C, 1, 1> {
    StateKeys::one(ledger)
}

/// The row of queued round `round` (a `ROUND_*` index) over the ledger key.
/// Every queued round reads and writes the ledger alone, under the same
/// public-input layout, so one row type serves them all. Asserts the
/// contract is configured.
pub fn queued_round<C>(tip: Configured<PACKAGES>, ledger: CommitmentSlot<C>, round: u32) -> TipRound<C, 1, 1, Keys> {
    assert((round != 0) & (round < PACKAGES), "not a queued round");
    tip.round(CREDITS_PACKAGES[round], ledger_state_keys(ledger))
}

/// One round's result under private outcomes, as `process_result` takes it:
/// the ledger read and written, no pinned read, one completed note hash and
/// the five-field ciphertext. No leaf hash: a keyed map's rounds output none.
pub type CreditsResult = OutcomeResult<1, 1, 0, 1, OUTCOME_CIPHERTEXT>;

/// What `apply_result` lands: the request id and the ledger's commitments.
pub type CreditsApply = OutcomeApply<1, 1, 0>;

/// The separator of a handle: `payee_handle(owner, secret) =
/// poseidon2_hash_with_separator([owner, secret], DOM_SEP__CREDITS_HANDLE)`
/// ("crhd").
pub global DOM_SEP__CREDITS_HANDLE: u32 = 0x63726864;

/// The separator of a map key: `map_key(handle) =
/// poseidon2_hash_with_separator([handle], DOM_SEP__CREDITS_MAP_KEY)`
/// ("crmk").
pub global DOM_SEP__CREDITS_MAP_KEY: u32 = 0x63726d6b;

/// The handle an owner hands out to be paid: a hash of its address and a
/// secret of its own. A payer passes it to `pay` or `move_credit`; `claim`,
/// `view_balance` and `move_credit` compute the sender's own from the sender
/// and the secret (`own_map_key`), so only the owner can name its own entry in
/// a round that reads or spends it.
///
/// DEV DECISION: who may claim, look up or move a handle's credit, default
/// the sender whose address and secret hash to it. Alternatives: a handle
/// bound to a public key whose signature the request function checks (a
/// handle given to another account), or one spent by any holder of the secret
/// (a bearer handle: the secret alone, no address). The circuit checks
/// presence and balance only; the authority is the request function's, as in
/// every example (invariant 0). Design guide: "access control".
pub fn payee_handle(owner: AztecAddress, secret: Field) -> Field {
    poseidon2_hash_with_separator([owner.to_field(), secret], DOM_SEP__CREDITS_HANDLE)
}

/// The key a handle has in the map: a hash of the handle. Every request
/// function puts its keys through this one function, so every key that
/// reaches the map is a hash output and no caller chooses a key's bits. The
/// map's path is a key's low 64 bits (pss_core `tip::map`), so a raw key
/// would let anyone block a known key with one request (`pay(K + 2^64, 1)`
/// lands on K's path and takes it); through the hash, landing on a known
/// key's path costs a 2^64 search. Shares of another field than the key C
/// commits do not get past the hash either: a round whose shares do not
/// open C inserts no key (pss_core `Map::update_private`). Asserts the handle nonzero ("invalid
/// inputs"): no `payee_handle` is 0, so a zero handle is a payer's missing
/// argument, refused in its PXE before anything is queued.
pub fn map_key(handle: Field) -> Field {
    assert(handle != 0, "invalid inputs");
    poseidon2_hash_with_separator([handle], DOM_SEP__CREDITS_MAP_KEY)
}

/// The sender's own map key: `map_key(payee_handle(owner, secret))`, the key
/// a payer reaches by paying the owner's handle.
pub fn own_map_key(owner: AztecAddress, secret: Field) -> Field {
    map_key(payee_handle(owner, secret))
}

/// A nonzero u64: what the ledger takes as an amount (code 2 otherwise).
fn valid_amount(amount: Field) -> bool {
    std::static_assert(AMOUNT_BITS == 64, "an amount is a u64");
    (amount != 0) & is_u64(amount)
}

/// The static validity of a pay request, `[key, amount]` (the key
/// `map_key(handle)`, which refuses the handle 0): a nonzero u64 amount.
/// Asserted in the payer's PXE before anything is queued, the only place a
/// shared input is checked before its round.
///
/// DEV DECISION: intake refuses exactly the requests the circuit would answer
/// with code 2 (the amount), and the handle 0, which no `payee_handle` gives
/// (`map_key`); whether the key's leaf is taken or the balance would overflow
/// depends on the secret map and stays the circuit's outcome. Design guide:
/// "access control".
pub fn valid_pay(inputs: [Field; 2]) -> bool {
    valid_amount(inputs[1])
}

/// A claim, `[key, amount]`: the amount a nonzero u64 (the key is the
/// sender's own, `own_map_key`).
pub fn valid_claim(inputs: [Field; 2]) -> bool {
    valid_amount(inputs[1])
}

/// A view, `[key]`: nothing to check (the key is the sender's own).
pub fn valid_view(_inputs: [Field; 1]) -> bool {
    true
}

/// A move, `[from, to, amount]` (`to` the `map_key` of the destination's
/// handle): the destination another key than the source (code 7 otherwise),
/// the amount a nonzero u64.
pub fn valid_move(inputs: [Field; 3]) -> bool {
    (inputs[1] != inputs[0]) & valid_amount(inputs[2])
}

/// The completed note of a round, the requester's outcome note (docs/ARCHITECTURE.md
/// section 6, "Partial-note delivery"): the outcome `[code,
/// round, a, b]` (README "The ledger": `pay` `[code, ROUND_PAY, amount, 0]`,
/// `claim` `[code, ROUND_CLAIM, amount, balance left]`, `view` `[code,
/// ROUND_VIEW, present, balance]`, `move` `[code, ROUND_MOVE, amount, source
/// balance left]`) and the chain request id last, five packed fields, at the
/// contract's `outcome_notes` slot. `round` tells a claim's note, whose
/// amount is its owner's, from a pay's, whose amount the payer gave. The round completes it
/// inside the co-SNARK (`pss_core::tip::outcome::finish`) and the
/// requester's client hands it to its PXE (`deliver_outcome`, randomness
/// `rho`). The library's outcome note
/// (`pss_public_contract::partial_note::outcome_note`: both steps of
/// aztec-nr's two-step hash, the canonical nullifier), so the completed
/// note is an ordinary note of the owner's.
#[derive(Deserialize, Eq, Packable, Serialize)]
#[outcome_note]
pub struct CreditOutcomeNote {
    pub code: Field,
    pub round: Field,
    pub a: Field,
    pub b: Field,
    pub request_id: Field,
}

/// How many outcome notes an owner's PXE holds, and the first one (a zero
/// note when there is none), as the contract's `credit_notes` utility
/// reports them.
#[derive(Deserialize, Eq, Serialize)]
pub struct CreditNotes {
    pub count: u32,
    pub first: CreditOutcomeNote,
}
