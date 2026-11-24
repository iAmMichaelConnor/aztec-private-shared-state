//! The test contract's types outside the `#[aztec]` module: the oracle pin,
//! the round table's wide row, the result shapes and the completed note.
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::{Deserialize, Packable, Serialize};
use pss_public_contract::chain_state::SealedThirds;
use aztec::context::PublicContext;
use pss_public_contract::{CommitmentSlot, KeyEpochs, SharedOnchain, StateKeys, TipConfig, TipRound};
use pss_public_contract::outcome::{OutcomeApply, OutcomeResult};
use pss_public_contract::hatch::ExitNote;
use pss_public_contract::partial_note::outcome_note;
use pss_public_contract::result::{PartialResult, TipResult};

/// Where `apply`'s pinned reads go, set once after deployment
/// (`set_oracle`), as an app pins its read targets in its Config: the
/// contract, the selector of the function `apply` reads (`get_price()`
/// unless a test pins another) and the read's gas bound.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct OraclePin {
    pub target: AztecAddress,
    pub selector: Field,
    pub l2_gas: u32,
}

/// The result shape of `process_result` and `apply`: the pool read and
/// written, one pinned read (`get_price()` on the oracle pin), two app
/// outputs.
pub type PoolResult = TipResult<1, 1, 1, 2>;

/// Its sealed thirds: one chain-held output (the pool) of five fields per
/// node.
pub type PoolThirds = SealedThirds<1, 5>;

/// The test contract's node-keys brick: key epochs over its `SharedOnchain`
/// (secret-shared on-chain intake), whose replaced nodes' `enc` keys
/// `set_node_keys` voids.
pub type Keys = KeyEpochs<SharedOnchain<PublicContext>>;

/// A row of the test contract's round table: its node signatures are checked
/// under key epochs (`Keys`), which `rotate_keys` moves.
pub type Row<C, let R: u32, let W: u32> = TipRound<C, R, W, Keys>;

/// The wide round's row of the test contract's round table, which both its
/// halves take (`process_result_wide` the row, `apply_wide` its keys): the
/// pool round's vk hash, and the keys read in the order [book, pool] and
/// written in the order [pool, book, fresh] (`fresh` a create).
pub fn wide_round<C>(
    vk_hash: Field,
    tip: TipConfig,
    pool: CommitmentSlot<C>,
    book: CommitmentSlot<C>,
    fresh: CommitmentSlot<C>,
) -> Row<C, 2, 3> {
    TipRound { vk_hash, tip, state_keys: StateKeys { reads: [book, pool], writes: [pool, book, fresh] } }
}

/// The wide result shape: two keys read in the order [book, pool], three
/// written in the order [pool, book, fresh] (`fresh` read by no round, a
/// create), two pinned reads (`get_value(1)` and `get_value(2)`), one app
/// output, under node-held state (no sealed thirds, no state log).
pub type WideResult = TipResult<2, 3, 2, 1>;

/// The node-held round's result shape: `held` read and
/// written, no pinned read, two app outputs, no sealed thirds.
pub type HeldResult = TipResult<1, 1, 0, 2>;

/// The init round's one app input (as lending's `liquidity`), a constant of
/// the app; the init request id covers it.
pub global HELD_INIT_INPUTS: [Field; 1] = [1000];

/// The chain-held init round's app inputs: none (as the AMM's
/// `amm_init_tip`), so its init request id differs from the node-held
/// init's (`HELD_INIT_INPUTS`) under the same init vk hash.
pub global POOL_INIT_INPUTS: [Field; 0] = [];

/// The partial-note delivery suite's types (`test_partial.nr`).
///
/// The completed note of a partial-note round, the app's note type: the
/// outcome `[code, amount]` (as the AMM's `[code, amount_out]`) and the
/// chain request id last, three packed fields. The library's outcome note
/// (`pss_public_contract::partial_note::outcome_note`), so a note completed
/// by the round, by `apply` or created whole hashes alike; its nullifier is
/// the canonical one. `partial_outcomes` holds the completed notes, the refund
/// notes (`[0, amount, request_id]`) among them.
#[derive(Deserialize, Eq, Packable, Serialize)]
#[outcome_note]
pub struct PartialOutcome {
    pub code: Field,
    pub amount: Field,
    pub request_id: Field,
}

/// The test's exit rule (`test_hatch.nr`): a completed note names the
/// entry its amount gives, so a test chooses the entry by the outcome it
/// lands (an app's note names a leaf index of its own).
impl ExitNote for PartialOutcome {
    fn entry(self) -> Field {
        self.amount
    }

    fn request_id(self) -> Field {
        self.request_id
    }
}

/// How many completed notes an owner holds, and the first two (a zero note
/// where there is none), in the PXE's order.
#[derive(Deserialize, Eq, Serialize)]
pub struct PartialOutcomes {
    pub count: u32,
    pub first: PartialOutcome,
    pub second: PartialOutcome,
}

impl PartialOutcomes {
    /// Whether `note` is among the first two.
    pub fn holds(self, note: PartialOutcome) -> bool {
        (self.first == note) | (self.second == note)
    }
}

/// The public-completion round's result shape (`process_result_partial`
/// over `held`): `held` read and written, no pinned read, the app outputs
/// `[code, amount]`, and the request's partial note after `ok`.
pub type PartialHeldResult = PartialResult<1, 1, 0, 2>;

/// The private-outcome round's result shape (`process_result_private` over
/// `held`, `process_result_private_sealed` over `pool`): the key read and
/// written, no pinned read, one completed note hash and a three-field
/// ciphertext (the outcome `[code, amount]` and the AEAD tag), as the AMM's
/// outcome `[code, amount_out]` has.
pub type OutcomeRound = OutcomeResult<1, 1, 0, 1, 3>;

/// What its `apply_round` lands: the request id and the commitments only.
pub type OutcomeApplyRound = OutcomeApply<1, 1, 0>;

/// A request's escrow, recorded beside the queue entry by the request's
/// public wrapper: the refund note `skip()` or `apply` completes in public,
/// and the amount escrowed (public, as the transfer funding it is).
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct Escrow {
    pub refund_note: Field,
    pub amount: Field,
}
