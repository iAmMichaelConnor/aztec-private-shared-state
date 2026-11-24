//! The lending market's types, pins and plain functions, which both
//! contracts (`lending_tip`, `lending_tip_oblivious`) and their tests import.
use aztec::context::PrivateContext;
use aztec::macros::notes::custom_note;
use aztec::note::note_interface::NoteHash;
use aztec::note::utils::compute_note_hash;
use aztec::protocol::abis::function_selector::FunctionSelector;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::{Deserialize, Packable, Serialize};
use pss_public_contract::{
    check_round, CommitmentSlot, Configured, ExitNote, is_u128, package_hash, SigningKeys, StateKeys, NodeHeld, TipPins,
    TipRound, UsageDeposit,
};
use pss_public_contract::handle::{Delivered, Delivery};
use pss_public_contract::outcome::{OutcomeApply, OutcomeResult, Private};
use pss_public_contract::partial_note::{self, outcome_note};
use pss_public_contract::result::{AppliedResult, Freshness, PartialResult, PinnedRead, ResultSignature};

/// The book's depth D, a liquidation's probe width K and the keeper round's
/// window W, and the shared outcome's fields, ciphertext length and note
/// slot: the circuits' own definitions (circuits/lending_tip market.nr,
/// rounds.nr and shared.nr, which hold the choices), so the contract and the
/// rounds cannot disagree. A position index is in 1 .. 2^D - 1; a scan reads
/// `start .. start + W - 1`.
pub use lending_tip_circuit::market::{
    CLOCK_BAND, DEPTH, INDEX_ONE, KIND_BORROWER, KIND_LENDER, OWNER_SLOTS, PROBES, WINDOW,
};
/// The rounds' code for shares that do not open C, and a payout's asset bit
/// (circuits/lending_tip market.nr), for the contract's tests.
pub use lending_tip_circuit::market::{ASSET_BIT, CODE_INPUTS_MISMATCH};
pub use lending_tip_circuit::rounds::OUTCOME_FIELDS;
pub use lending_tip_circuit::shared::{CIPHERTEXT_LEN as OUTCOME_CIPHERTEXT, DELIVERIES, DELIVERY_LEN, EXIT_TAGS, OUTCOME_SLOT};

/// 2^D, the first index the book cannot hold.
pub global TWO_POW_DEPTH: Field = (1 << DEPTH) as Field;

/// The owner-bound rounds' app inputs, `[position, amount]`, in ABI order:
/// what C covers before the request's partial note.
pub global OWNER_INPUTS: u32 = 2;

/// What C covers before the request's partial note in a request that carries
/// the owner's delivery handle (pss_public_contract `handle`), the owner
/// rounds on a borrower position: the app inputs, then `[handle_partial,
/// handle_key]`.
pub global HANDLED_INPUTS: u32 = OWNER_INPUTS + 2;

/// The non-secret-shared deposit's inputs, `[position, amount,
/// partial_note]`: what `inputs_hash` covers and on-chain intake's log
/// carries before the request's `user_nonce` (the partial note a PUBLIC
/// `$partial_note`, hiding its owner behind the client's randomness).
pub global PLAIN_DEPOSIT_INPUTS: u32 = 3;

/// The liquidation's app inputs, `[p_1, .., p_{K-1}, count, budget]`.
pub global LIQUIDATE_INPUTS: u32 = PROBES + 1;

/// The longest log `log_in_tx` returns: a completion log's slot, the note's
/// seven fields and the request id after the tag (a request log's inputs
/// and nonce are four).
pub global MAX_LOG_FIELDS: u32 = 9;

// BRICK outputs = public (pss_public_contract::result::PartialResult), the non-secret-shared
// deposit's. Alternatives: private (SharedResult below). docs/design-guide/BRICKS.md#outputs
/// A non-secret-shared owner-bound round's result (the deposit), under
/// either non-secret-shared intake, with partial-note delivery
/// (pss_public_contract `PartialResult`): the request's partial note, which
/// the round echoes after `ok` and `apply` completes in public; the market
/// read and written, the three pinned values of the two reads every lending
/// round makes (the price and its epoch from `get_price_epoch()` on the
/// Config's oracle, the clock from this contract's `clock()`), and the
/// circuit's six owner outputs (`OwnerNoteOutputs`): `code`, `position` (the
/// position's index, an opening deposit's assigned one; 0 when not ok),
/// `mask` (the position's kind marker), `payout` (what the note pays) and
/// the header's and the position's new leaf hashes, which the proof binds
/// and the contract passes through.
pub type OwnerResult = PartialResult<1, 1, 3, 6>;

/// The packages one deployment lists: its capacity, the length of the
/// constructor's package list. A deployment takes the init and one intake
/// family's rounds (REGISTER's one family per key): the non-secret-shared list
/// (`PLAIN_PACKAGES`, two) or the secret-shared list (`SHARED_PACKAGES`, eleven) under
/// `lending_tip`, the oblivious list (`OBLIVIOUS_PACKAGES`, eleven) under
/// `lending_tip_oblivious`.
pub global PACKAGES: u32 = 11;

/// The package name hashes (`package_hash` of each manifest's `circuit`):
/// `lending_init`, the init round (`init_market`);
pub global LENDING_INIT_PACKAGE: Field = package_hash("lending_init");
/// `deposit`, the non-secret-shared deposit (`deposit`, `deposit_with_receipts`,
/// `process_result`): one compiled circuit for both non-secret-shared intakes, which the
/// network also registers as `deposit_receipt` (the same vk) for receipt
/// intake;
pub global DEPOSIT_PACKAGE: Field = package_hash("deposit");
/// `deposit_shared` (`deposit_shared`, `process_shared(ROUND_DEPOSIT, ...)`);
pub global DEPOSIT_SHARED_PACKAGE: Field = package_hash("deposit_shared");
/// `withdraw_shared` (`withdraw_shared`, `process_shared(ROUND_WITHDRAW, ...)`);
pub global WITHDRAW_SHARED_PACKAGE: Field = package_hash("withdraw_shared");
/// `supply_shared` (`supply_shared`, `process_shared(ROUND_SUPPLY, ...)`);
pub global SUPPLY_SHARED_PACKAGE: Field = package_hash("supply_shared");
/// `withdraw_supply_shared` (`withdraw_supply_shared`, `process_shared(ROUND_WITHDRAW_SUPPLY, ...)`);
pub global WITHDRAW_SUPPLY_SHARED_PACKAGE: Field = package_hash("withdraw_supply_shared");
/// `quote_shared` (`quote_shared`, `process_header_shared(ROUND_QUOTE, ...)`).
pub global QUOTE_SHARED_PACKAGE: Field = package_hash("quote_shared");
/// `borrow_shared` (`borrow_shared`, `process_shared(ROUND_BORROW, ...)`);
pub global BORROW_SHARED_PACKAGE: Field = package_hash("borrow_shared");
/// `repay_shared` (`repay_shared`, `process_shared(ROUND_REPAY, ...)`);
pub global REPAY_SHARED_PACKAGE: Field = package_hash("repay_shared");
/// `view_shared` (`view_shared`, `process_shared(ROUND_VIEW, ...)`);
pub global VIEW_SHARED_PACKAGE: Field = package_hash("view_shared");
/// `liquidate_shared` (`liquidate_shared`, `process_shared(ROUND_LIQUIDATE, ...)`);
pub global LIQUIDATE_SHARED_PACKAGE: Field = package_hash("liquidate_shared");
/// `scan_shared`, the keeper round (`scan_shared`, `process_header_shared(ROUND_SCAN, ...)`).
pub global SCAN_SHARED_PACKAGE: Field = package_hash("scan_shared");

/// The oblivious deployment's package names (docs/ARCHITECTURE.md section 6,
/// "The oblivious tree"; README "Deployment"): the same rounds compiled over a
/// book with `access: oblivious`, one artifact each (`<round>_oblivious`),
/// landed through the secret-shared rounds' `process_shared` and
/// `process_header_shared` (their public-input layout, with zero leaf hashes)
/// of `lending_tip_oblivious`, whose round table (`RoundTable::oblivious`)
/// names them. `lending_init_oblivious` is its init.
pub global LENDING_INIT_OBLIVIOUS_PACKAGE: Field = package_hash("lending_init_oblivious");
pub global DEPOSIT_OBLIVIOUS_PACKAGE: Field = package_hash("deposit_oblivious");
pub global BORROW_OBLIVIOUS_PACKAGE: Field = package_hash("borrow_oblivious");
pub global REPAY_OBLIVIOUS_PACKAGE: Field = package_hash("repay_oblivious");
pub global VIEW_OBLIVIOUS_PACKAGE: Field = package_hash("view_oblivious");
pub global LIQUIDATE_OBLIVIOUS_PACKAGE: Field = package_hash("liquidate_oblivious");
pub global SCAN_OBLIVIOUS_PACKAGE: Field = package_hash("scan_oblivious");
pub global WITHDRAW_OBLIVIOUS_PACKAGE: Field = package_hash("withdraw_oblivious");
pub global SUPPLY_OBLIVIOUS_PACKAGE: Field = package_hash("supply_oblivious");
pub global WITHDRAW_SUPPLY_OBLIVIOUS_PACKAGE: Field = package_hash("withdraw_supply_oblivious");
pub global QUOTE_OBLIVIOUS_PACKAGE: Field = package_hash("quote_oblivious");

/// The non-secret-shared deployment's package list, in REGISTER order: the init, then
/// the deposit (README "Deployment"). The non-secret-shared intakes run on this one
/// round, the non-secret-shared-path test; every round runs under secret-shared receipt intake.
pub global PLAIN_PACKAGES: [Field; PACKAGES] = [LENDING_INIT_PACKAGE, DEPOSIT_PACKAGE, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// The secret-shared deployment's package list, in REGISTER order: the init (a
/// non-secret-shared package that reads no key, which REGISTER lets sit beside secret-shared
/// rounds), then the secret-shared entries of deposit, borrow, repay, view
/// and liquidate, the keeper's scan, withdraw, and the lenders' supply,
/// withdraw_supply and quote (README "Deployment"). A round added to the
/// market goes at the end, so every listed package keeps its place
/// (REGISTER's seq).
pub global SHARED_PACKAGES: [Field; PACKAGES] = [
    LENDING_INIT_PACKAGE, DEPOSIT_SHARED_PACKAGE, BORROW_SHARED_PACKAGE, REPAY_SHARED_PACKAGE,
    VIEW_SHARED_PACKAGE, LIQUIDATE_SHARED_PACKAGE, SCAN_SHARED_PACKAGE, WITHDRAW_SHARED_PACKAGE,
    SUPPLY_SHARED_PACKAGE, WITHDRAW_SUPPLY_SHARED_PACKAGE, QUOTE_SHARED_PACKAGE,
];

/// The oblivious deployment's package list, in REGISTER order: the oblivious
/// init, then the oblivious entry of every round in the secret-shared list's
/// order (README "Deployment").
pub global OBLIVIOUS_PACKAGES: [Field; PACKAGES] = [
    LENDING_INIT_OBLIVIOUS_PACKAGE, DEPOSIT_OBLIVIOUS_PACKAGE, BORROW_OBLIVIOUS_PACKAGE, REPAY_OBLIVIOUS_PACKAGE,
    VIEW_OBLIVIOUS_PACKAGE, LIQUIDATE_OBLIVIOUS_PACKAGE, SCAN_OBLIVIOUS_PACKAGE, WITHDRAW_OBLIVIOUS_PACKAGE,
    SUPPLY_OBLIVIOUS_PACKAGE, WITHDRAW_SUPPLY_OBLIVIOUS_PACKAGE, QUOTE_OBLIVIOUS_PACKAGE,
];

// BRICK outputs = private (pss_public_contract::outcome::OutcomeResult), every secret-shared
// round's. Alternatives: public (OwnerResult above). docs/design-guide/BRICKS.md#outputs
/// A secret-shared round's result (pss_public_contract `outcome`): the market read
/// and written, the price, its epoch and the clock, the completed note's hash and the
/// 8-field ciphertext; the same type for every round type. The tree's new
/// leaf hashes are the next argument of `process_shared` (two for an
/// owner-bound round, `PROBES` for a liquidation) or `process_header_shared`
/// (one, the header's, for a scan or a quote); then the app values (the
/// round's `EXIT_TAGS` exit tags, the book's append index when the round
/// has a position slot, and the inputs-opened bit: pss_public_contract's
/// `outcome::Private`), of which `apply_shared` takes the tags and the
/// bit.
pub type SharedResult = OutcomeResult<1, 1, 3, 1, OUTCOME_CIPHERTEXT>;

/// What every secret-shared round's `apply` lands: the request id, the market's
/// old and new commitments, the price, its epoch and the clock. One type, so
/// the public call is the same for every round type.
pub type SharedApply = OutcomeApply<1, 1, 3>;

/// The deliveries every secret-shared round's result carries after its app
/// values (pss_public_contract `handle::Delivered`): one, a liquidation's
/// notice to the liquidated position's owner (its delivery handle completed
/// with the position after the liquidation) or a filler, the same shape for
/// every round type, so every result pushes two note hashes and emits two
/// logs. The next argument of `process_shared` and `process_header_shared`
/// after the app values.
pub type SharedDeliveries = [Delivery<DELIVERY_LEN>; DELIVERIES];

/// The constructor's pins: the library's `TipPins` (the stale period, the
/// three node `sig` keys, the contract manifest's hash, the package list and
/// each package's vk hash) and the market's own constants: its two tokens and the usage deposit. Nothing here depends on the namespace, so
/// the address is known before any REGISTER, and it commits to the
/// circuits; `configure` adds `npk_app_hash` (pss_public_contract
/// `configure`).
///
/// DEV DECISION: what the Config pins, fixed at deployment in a `PublicImmutable`,
/// so nobody can change it; a new circuit, oracle, network, stale period or
/// seeded liquidity is a new deployment; default the
/// `TipPins`, the seeded liquidity the init proof must state and the oracle
/// address, the two tokens and the usage deposit. The node `enc` keys of
/// the secret-shared on-chain intake are not pinned here: they rotate with
/// the key epochs (pss_public_contract `shared_onchain`).
/// Deploy the oracle and the tokens first: the oracle's address goes here
/// and into every round manifest's price read. Design guide: "init
/// strategy".
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct Config {
    /// The seeded liquidity, the `lending_init` circuit's
    /// public input `liquidity` (a u128 of the borrowed asset),
    /// pinned here, so `init_market` verifies the init proof against the
    /// amount the deployment funds the market with and no caller chooses
    /// it, and the init request id covers it (`init_request_id`). The
    /// deployment funds this contract's public balance of the borrowed
    /// asset with it (the token's `mint_to_public` or `transfer_in_public`
    /// to this address) before the init round lands: `apply_init` refuses
    /// while the balance holds less, and `fund` refuses before the init, so
    /// no user's credit can stand in for the liquidity.
    pub init_liquidity: Field,
    /// The oracle, the target of the price read that `apply`
    /// and `apply_shared` re-make and the `contract` of
    /// every round manifest's `public_reads`, pinned
    /// here, never taken from a result or a caller (a caller-chosen target
    /// returns whatever price the caller's proof used; see the library's
    /// `PinnedRead`). The manifests carry the same address as a literal
    /// the deployment writes in (the README's "Manifests"); the two must
    /// agree, or the network reads one price and `apply` another and every
    /// result reverts (liveness only, never a wrong price). The
    /// oracle is also a liveness trust assumption of the queue: its owner,
    /// who sets the price and can upgrade it, can make every `apply`
    /// fail (two new epochs before the round lands, a revert, a read that
    /// exhausts its gas bound) until the head is skipped, but never land a
    /// wrong price.
    pub oracle: AztecAddress,
    /// The collateral asset's token (pss_public_contract `token`: the
    /// reference token's interface, examples/token): a deposit escrows it at
    /// request, and a liquidation's seize and a failed deposit's return are
    /// paid in it. This contract holds it in its public balance.
    pub collateral: AztecAddress,
    /// The borrowed asset's token: the seeded liquidity, a borrow's payout,
    /// a repayment's and a liquidation budget's escrow, and the usage
    /// deposit. This contract holds it in its public balance.
    pub borrowed: AztecAddress,
    /// The usage deposit every request pays (pss_public_contract
    /// `UsageDeposit`), in the borrowed asset (the constructor checks it).
    ///
    /// DEV DECISION: the lending market's usage deposit, default the
    /// borrowed asset, kept by the protocol on every round that serves its
    /// request (`kept = true`), refunded by `skip()` and by a round whose
    /// shares did not open C (which served nobody); the amount is the
    /// deployment's. Why: the market's own asset makes the deposit the
    /// protocol's revenue in the unit it lends, the cryptoeconomics of a
    /// self-sustaining market (the deposits kept are counted in
    /// `kept_deposits`, in this contract's public balance beside the
    /// liquidity, until `sweep_deposits` pays them to `treasury`).
    /// Consequences: every request costs `amount` of the borrowed asset, so
    /// a first-time borrower needs a little of the asset it is about to
    /// borrow, and a liquidator pays it beside its budget. Alternatives: a
    /// third, protocol token (one more token to hold, the revenue in the
    /// protocol's own unit), or `kept = false` (the library's default: no
    /// revenue, the deposit only a lock-up). A deposit kept on skip, or on a
    /// round that served nobody, is forbidden (invariant 0). Design guide:
    /// "anti-spam".
    pub deposit: UsageDeposit,
    /// Who receives the kept usage deposits: `sweep_deposits()` pays them
    /// to this address's public balance of the borrowed asset.
    ///
    /// DEV DECISION: the protocol's revenue goes to a treasury pin, default
    /// here, swept in public by anyone (examples/lending-tip/README.md,
    /// "Tokens", "The usage deposit"). Why: the network (three nodes, the
    /// orchestrator, the relayer, the price feed) is run by someone, and a
    /// self-sustaining market pays them from its own usage, in its own asset;
    /// the sweep moves the kept count only, never an escrow or the pool.
    /// Consequences: the lenders' return is the borrowers' interest alone;
    /// whoever controls the treasury address receives the deposits (a pin:
    /// nobody changes it after deployment). Alternative: credit the kept
    /// deposits to the lenders by adding them to the liquidity in every
    /// applying round, which needs the deposit as a public input of every round
    /// and a destination for the failed rounds, which write nothing; a reserve
    /// factor on interest (a share of accrual to the treasury) is a later knob.
    pub treasury: AztecAddress,
    /// T_LIVE, the escape hatch's liveness period in blocks: `open_hatch()`
    /// opens the hatch once the market has starved this many blocks, that
    /// is had demand (a queued request or a `poke()`) and no landed round
    /// since (pss_public_contract `HatchState::starving_since`, which
    /// `skip()` never touches;
    /// examples/lending-tip/README.md, "The escape hatch", "The trigger").
    ///
    /// DEV DECISION: how long a market waits without an apply before its
    /// owners may exit without the network, default 20,000 blocks (about
    /// eight days at a 36-second block), a pin so a deployment chooses it
    /// and nobody changes it after (the contract checks it; no circuit
    /// does). Why: the hatch never closes (a market that comes back is a new
    /// deployment), so the period must be far longer than any outage the
    /// network recovers from (a relayer restart, an orchestrator upgrade, a
    /// node replacement), and a live network lands a round within the stale
    /// period of a request, which stops the clock. Consequences: a frozen
    /// market keeps its owners' collateral and supply for T_LIVE blocks
    /// before the first exit, and no interest accrues for them meanwhile
    /// (the exit pays each note's values as of its last round); anyone may
    /// start the clock on a quiet market (`poke()`), so a market with no
    /// requests for T_LIVE blocks needs one landed round in that time (a
    /// keeper's scan is enough) or it may be frozen. It must be at least the
    /// stale period (the constructor checks it). Alternative: a shorter
    /// period for a market whose users value exit over continuity (a false
    /// opening needs a network that landed nothing for the whole period
    /// after the clock started), or a governance-free longer one.
    pub t_live: u32,
    /// the stale period, the node `sig` keys and the circuit pins (the
    /// contract manifest's hash, the package list and the vk hashes); last, after the members the public functions read
    /// (`ConfigPublic`)
    pub tip: TipPins<PACKAGES>,
}

/// The head of the stored Config: its members before `tip`, in their order,
/// which is all the public functions read of it (the tokens, the oracle, the
/// usage deposit, the treasury, T_LIVE and the seeded liquidity). They read
/// it alone (pss_public_contract `read_head_in_public`: nine storage reads
/// where the whole Config is 39); a private function reads the whole Config.
/// The Config's members must start with these, in this order
/// (lending_tip_test pins it with `is_head_of`).
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct ConfigPublic {
    pub init_liquidity: Field,
    pub oracle: AztecAddress,
    pub collateral: AztecAddress,
    pub borrowed: AztecAddress,
    pub deposit: UsageDeposit,
    pub treasury: AztecAddress,
    pub t_live: u32,
}

impl Config {
    /// The head the public functions read (`ConfigPublic`).
    pub fn public(self) -> ConfigPublic {
        ConfigPublic {
            init_liquidity: self.init_liquidity,
            oracle: self.oracle,
            collateral: self.collateral,
            borrowed: self.borrowed,
            deposit: self.deposit,
            treasury: self.treasury,
            t_live: self.t_live,
        }
    }

    /// The constructor's check: the library's pins, one intake family per
    /// deployment, the usage deposit paid in the borrowed asset (the DEV
    /// DECISION above), skipping enabled, and T_LIVE at least the stale
    /// period. Skipping is required: once the hatch opens no round lands, so
    /// `skip()` is the only way a queued request's escrow and deposit come
    /// back (`exit` pays positions only).
    ///
    /// One intake family: the non-secret-shared deposit (`DEPOSIT_PACKAGE`)
    /// is listed beside no secret-shared round. REGISTER keeps the same rule
    /// per key; this keeps it in the contract too, because the plain
    /// deposit's leaves hold no exit tag: beside the tagged rounds it would
    /// open positions that no later round can write (their tag is 0, which a
    /// landing refuses) and rewrite tagged positions under their old tag.
    pub fn assert_valid(self) {
        self.tip.assert_valid();
        let mut plain = false;
        let mut shared = false;
        for p in self.tip.circuits.packages {
            if p == DEPOSIT_PACKAGE {
                plain = true;
            } else if (p != 0) & (p != LENDING_INIT_PACKAGE) & (p != LENDING_INIT_OBLIVIOUS_PACKAGE) {
                shared = true;
            }
        }
        assert(!(plain & shared), "the plain deposit is listed beside a secret-shared round");
        assert(
            (self.deposit.amount == 0) | (self.deposit.token == self.borrowed),
            "the usage deposit is paid in the borrowed asset",
        );
        assert(self.tip.stale_blocks.enabled, "the market requires skipping");
        assert(self.t_live >= self.tip.stale_blocks.blocks, "T_LIVE is below the stale period");
    }
}

/// The authwit nonces of `fund`'s two token transfers, the collateral
/// asset's and the borrowed asset's (unused for an amount of 0). The
/// sender's authwits name this contract as caller and these nonces; each is
/// single-use in the token.
#[derive(Deserialize, Eq, Serialize)]
pub struct Nonces {
    pub collateral: Field,
    pub borrowed: Field,
}

/// The secret-shared rounds' indices in the round table (`RoundTable::round`):
/// each round's place in `SHARED_PACKAGES` and `OBLIVIOUS_PACKAGES`, its
/// REGISTER seq. The relayer names a result's round by it
/// (`process_shared`, `process_header_shared`), a private argument the chain
/// never sees.
pub global ROUND_DEPOSIT: u32 = 1;
pub global ROUND_BORROW: u32 = 2;
pub global ROUND_REPAY: u32 = 3;
pub global ROUND_VIEW: u32 = 4;
pub global ROUND_LIQUIDATE: u32 = 5;
pub global ROUND_SCAN: u32 = 6;
pub global ROUND_WITHDRAW: u32 = 7;
pub global ROUND_SUPPLY: u32 = 8;
pub global ROUND_WITHDRAW_SUPPLY: u32 = 9;
pub global ROUND_QUOTE: u32 = 10;

// BRICK shape = tree, tree_oblivious: each contract names its tree access once, in its round table
// (RoundTable::clear in lending_tip, RoundTable::oblivious in lending_tip_oblivious), as each manifest's
// tree entry names it for the machine. Alternatives: flat, map_oblivious. docs/design-guide/BRICKS.md#shape
/// A contract's round table: the package names its rows resolve to, which
/// its tree access fixes (the clear deployments' `SHARED_PACKAGES` and init,
/// or `OBLIVIOUS_PACKAGES`), and the node-keys brick `K` every row checks
/// node signatures under. Each row is the vk pin of its package (the
/// constructor's; 0 when the deployment does not list it, which refuses the
/// round) and the market key. The private functions take their rows from it;
/// the public applies take only the rows' keys, which come from the slot
/// alone (`init_state_keys`, `market_state_keys`), so they read no pin.
pub struct RoundTable<K> {
    init: Field,
    rounds: [Field; PACKAGES],
}

impl<K> RoundTable<K> {
    /// The clear deployments' table (`lending_tip`): the init
    /// `lending_init`, the secret-shared rounds by `SHARED_PACKAGES`.
    pub fn clear() -> Self {
        RoundTable { init: LENDING_INIT_PACKAGE, rounds: SHARED_PACKAGES }
    }

    /// The oblivious deployment's table (`lending_tip_oblivious`): the init
    /// `lending_init_oblivious`, the rounds by `OBLIVIOUS_PACKAGES`.
    pub fn oblivious() -> Self {
        RoundTable { init: LENDING_INIT_OBLIVIOUS_PACKAGE, rounds: OBLIVIOUS_PACKAGES }
    }

    /// The init round's row: it creates the market key, outside the queue.
    /// Asserts configured.
    pub fn init<C>(self, tip: Configured<PACKAGES>, market: CommitmentSlot<C>) -> TipRound<C, 0, 1, K> {
        tip.round(self.init, init_state_keys(market))
    }

    /// The row of secret-shared round `round` (a `ROUND_*` index) over the
    /// market key. Every secret-shared round reads and writes the market
    /// alone, so one row type serves them all. Asserts configured.
    pub fn round<C>(self, tip: Configured<PACKAGES>, market: CommitmentSlot<C>, round: u32) -> TipRound<C, 1, 1, K> {
        assert((round != 0) & (round < PACKAGES), "not a secret-shared round");
        tip.round(self.rounds[round], market_state_keys(market))
    }
}

/// The init round's keys: it creates the market key.
pub fn init_state_keys<C>(market: CommitmentSlot<C>) -> StateKeys<C, 0, 1> {
    StateKeys::create([market])
}

/// Every queued round's keys: it reads and writes the market alone.
pub fn market_state_keys<C>(market: CommitmentSlot<C>) -> StateKeys<C, 1, 1> {
    StateKeys::one(market)
}

/// A lending note: the user's partial note completed with a round's
/// outcome (docs/ARCHITECTURE.md section 6, "Partial-note delivery"):
/// `[code, position, mask, x, y, payout, aux]` and the chain request id
/// last, eight packed fields (aztec-nr's cap), at the contract's
/// `outcome_notes` slot. The user's request commits the partial note
/// `partial_commitment(owner, rho)` from its own address and its client's
/// `rho`; a secret-shared round completes it inside the co-SNARK
/// (`pss_core::tip::outcome::finish`) and the user's client hands the note
/// to its PXE (`deliver_outcome`, randomness `rho`); the non-secret-shared
/// deposit's `apply` completes it in public. The library's outcome note
/// (`pss_public_contract::partial_note::outcome_note`: both steps of
/// aztec-nr's two-step hash, the canonical nullifier), so the completed note
/// is an ordinary note of the owner's; nothing nullifies it.
///
/// One note type for every round (the hidden round type), so what a note
/// confers is in its fields:
/// - ownership: a note with `position != 0` is an owner note of that
///   position, and the contract's request functions on the position require
///   one of the sender's (`assert_holds`). The round names the position
///   exactly when it vouches for the requester's leaf: on success, and on a
///   failure after the placement and the leaf's own checks (a borrow
///   refused at the limit), never on a failed opening, whose index nobody
///   opened (examples/lending-tip/README.md, "Notes: ownership, the owner's
///   view and value"). The note is never nullified, so every note of a position
///   keeps its owner able to act (an index is never reassigned and a position
///   is not transferable);
/// - the owner's view: its collateral `x` and debt `y` after the round (a
///   liquidation since then leaves it stale, and the liquidation's notice is
///   the position's newest note);
/// - the exit (`ExitNote`): the note's exit tag, `exit_tag(partial_commitment(
///   owner, randomness), request_id, position)`, is the one the round stored
///   in the position's leaf, so the escape hatch's `exit` spends it once,
///   and only while the note is the position's newest (pss_public_contract
///   `hatch`);
/// - value: `settlement`, which `redeem` pays once (its redeem nullifier,
///   the note staying readable).
#[derive(Deserialize, Eq, Packable, Serialize)]
#[outcome_note]
pub struct LendingOutcome {
    /// 0 when the request applied, else the first failing check (14 for
    /// shares that do not open C)
    pub code: Field,
    /// an owner round's position (an opening deposit's assigned one) when
    /// the round vouches for it; 0 for a liquidation, a scan, a failed
    /// opening, and a failure in the placement or the position's checks
    pub position: Field,
    /// a borrower note's index at touch (never 0: the borrower kind's
    /// marker), a lender note's 0; a liquidation's liquidated probes; a
    /// scan's report, bit j set when position start + j is unhealthy at the
    /// price; a quote's borrow index
    pub mask: Field,
    /// the position's collateral (a lender's: its shares) after the round
    /// when the note names a position (0 in a non-secret-shared deposit's
    /// note), a liquidation's total seize (paid in the collateral asset),
    /// else 0
    pub x: Field,
    /// the position's debt (a lender's: its shares' value) after the round
    /// (0 in a non-secret-shared deposit's note), a liquidation's total
    /// repay, a scan's start, or a quote's supply index
    pub y: Field,
    /// what `redeem` pays, `amount + 2^128 * asset` (asset 0 the borrowed
    /// asset, 1 the collateral asset; lending_tip market.nr `payout`): a
    /// borrow's amount, a withdrawal's (collateral), a repayment's excess
    /// over the debt, a liquidation's unused budget, and every refund of a
    /// round that did not apply (a deposit's amount in collateral, a
    /// repayment's amount or a liquidation's budget in the borrowed asset),
    /// else 0
    pub payout: Field,
    /// a scan's occupied positions; a quote's utilisation in bps; else 0
    pub aux: Field,
    /// the chain request id the note answers, never zero
    pub request_id: Field,
}

impl LendingOutcome {
    /// The zero note (what `outcome_notes` reports when there is none).
    pub fn none() -> Self {
        LendingOutcome { code: 0, position: 0, mask: 0, x: 0, y: 0, payout: 0, aux: 0, request_id: 0 }
    }

    /// Whether the note confers ownership of `position`: it names that
    /// position (a liquidation's, a scan's and a failed opening's notes name
    /// position 0; the round names a position only when it vouches for it).
    pub fn owns(self, position: Field) -> bool {
        (self.position == position) & (position != 0)
    }

    /// Whether the note is of position kind `kind` (`KIND_BORROWER`: its
    /// mask, the index at touch, is not 0; `KIND_LENDER`: it is 0; 0: either
    /// kind). A hint for the private function, which saves a round the
    /// circuit would refuse with code 5: a position never changes kind.
    pub fn of_kind(self, kind: Field) -> bool {
        (kind == 0) | ((kind == KIND_BORROWER) & (self.mask != 0)) | ((kind == KIND_LENDER) & (self.mask == 0))
    }

    /// What `redeem` pays on this note, `(collateral, borrowed)`: `payout`'s
    /// amount (its low 128 bits) in the asset its bit names, and `x` in the
    /// collateral asset when the note names no position (a liquidation's
    /// seize; a scan's note reports x = 0). A note that names a position has
    /// the position's collateral in x, which stays in the book. The
    /// circuits' rule (lending_tip rounds.nr `OUTCOME_FIELDS`, market.nr
    /// `payout`); every amount is a u128 the round computed from u128s, and
    /// no round pays a seize and a payout of the collateral asset together.
    ///
    /// This pays the `x` of every note that names no position, so the
    /// circuits build every report through lending_tip's `rounds::Report`,
    /// whose constructors give only a liquidation's report no position and
    /// an `x` (a scan's and a quote's carry `x = 0`, and a round that does
    /// not apply reports no position and `x = 0` unless it vouches for one).
    pub fn settlement(self) -> (u128, u128) {
        let amount = self.payout as u128;
        let in_collateral = self.payout != amount as Field;
        let seize = if self.position == 0 { self.x as u128 } else { 0 };
        if in_collateral {
            (seize + amount, 0)
        } else {
            (seize, amount)
        }
    }
}

/// The exit names the note's position (0 for a note that names none) and
/// its request (pss_public_contract `hatch`).
impl ExitNote for LendingOutcome {
    fn entry(self) -> Field {
        self.position
    }

    fn request_id(self) -> Field {
        self.request_id
    }
}

/// The fields a non-secret-shared owner round's `apply` completes the
/// request's partial note with, from its public outputs `[code, position,
/// mask, payout, header hash, position hash]`: `[code, position, mask, 0,
/// 0, payout, 0]` (the circuit reports position, mask and payout 0 when the
/// round did not apply). The note confers the position as the secret-shared
/// round's does; it reports no collateral or debt, which the public
/// completion log would publish, so it has nothing to exit.
pub fn owner_note_fields(applied: AppliedResult<6>) -> [Field; OUTCOME_FIELDS] {
    let out = applied.app_outputs;
    [out[0], out[1], out[2], 0, 0, out[3], 0]
}

/// A credit: the owner's private balance in this market, `collateral` of
/// the collateral asset and `borrowed` of the borrowed asset, held in the
/// market's public balances and owed to whoever holds the note
/// (pss_public_contract `token`; examples/lending-tip/README.md,
/// "Tokens"). Made by `fund` (tokens in, amounts public,
/// unlinked to any request), by `redeem` (a round's settlement, private), as
/// the change of every spend, and by the completion of a refund note;
/// spent whole, one note per transaction, by every request (its escrow and
/// the usage deposit), by `withdraw_funds` (tokens out) and by
/// `merge_credits`. `request_id` is the request whose refund the note is
/// (completed in public by `skip()` or `apply`), 0 for a credit made in
/// private.
///
/// The hash: `compute_note_hash(storage_slot, [partial_commitment_with(owner,
/// randomness, [collateral, borrowed]), request_id])` (pss_public_contract
/// `partial_note`), so the amounts are private content of the partial note
/// a refund is: a request commits its refund notes with the amounts inside
/// the commitment, and `skip()` completes them with the request id as the
/// only public field. A credit made whole in private hashes the same way.
/// Its nullifier is the canonical one.
#[derive(Deserialize, Eq, Packable, Serialize)]
#[custom_note]
pub struct Credit {
    /// the collateral asset's amount
    pub collateral: u128,
    /// the borrowed asset's amount
    pub borrowed: u128,
    /// the request a refund note answers; 0 for a credit made in private
    pub request_id: Field,
}

impl NoteHash for Credit {
    fn compute_note_hash(self, owner: AztecAddress, storage_slot: Field, randomness: Field) -> Field {
        let partial = partial_note::partial_commitment_with(
            owner,
            randomness,
            [self.collateral as Field, self.borrowed as Field],
        );
        compute_note_hash(storage_slot, [partial, self.request_id])
    }

    fn compute_nullifier(
        self,
        context: &mut PrivateContext,
        owner: AztecAddress,
        note_hash_for_nullification: Field,
    ) -> Field {
        partial_note::nullifier(context, owner, note_hash_for_nullification)
    }

    unconstrained fn compute_nullifier_unconstrained(
        self,
        owner: AztecAddress,
        note_hash_for_nullification: Field,
    ) -> Option<Field> {
        partial_note::nullifier_unconstrained(owner, note_hash_for_nullification)
    }
}

impl Credit {
    /// A credit made in private (not a refund).
    pub fn of(collateral: u128, borrowed: u128) -> Self {
        Credit { collateral, borrowed, request_id: 0 }
    }

    /// The private content of a refund note returning `collateral` and
    /// `borrowed`: the first two packed fields, which the refund note's
    /// commitment binds.
    pub fn content(collateral: u128, borrowed: u128) -> [Field; 2] {
        [collateral as Field, borrowed as Field]
    }
}

/// What a request takes from the sender's credit, by asset: the escrow (a
/// deposit's amount in the collateral asset; a repayment's, a supply's or a
/// liquidation budget's in the borrowed asset; nothing for every other
/// round type) and, beside it, the usage deposit in the borrowed asset.
#[derive(Deserialize, Eq, Serialize)]
pub struct Draw {
    /// the escrow in the collateral asset (a deposit's amount, else 0)
    pub collateral: u128,
    /// the escrow in the borrowed asset (a repayment's, a supply's or a
    /// liquidation budget's amount, else 0)
    pub borrowed: u128,
    /// the usage deposit (the Config's amount)
    pub deposit: u128,
}

impl Draw {
    /// What the credit note spent must cover, `(collateral, borrowed)`.
    pub fn total(self) -> (u128, u128) {
        (self.collateral, self.borrowed + self.deposit)
    }
}

/// How many lending notes an owner's PXE holds, and the first one (a zero
/// note when there is none), as `outcome_notes` reports it.
#[derive(Deserialize, Eq, Serialize)]
pub struct OutcomeNotes {
    pub count: u32,
    pub first: LendingOutcome,
}

/// A position index a request may name: nonzero and below 2^D.
fn named(position: Field) -> bool {
    (position != 0) & position.lt(TWO_POW_DEPTH)
}

/// A nonzero u128 amount.
fn amount_ok(amount: Field) -> bool {
    (amount != 0) & is_u128(amount)
}

/// The static validity of a deposit or a supply, `[position, amount]`, which every
/// intake function asserts before anything is queued (the secret-shared
/// intakes over the app inputs among C's values): a position below 2^D (0
/// opens a new one) and a non-zero `amount` below 2^128. The partial note
/// and the reserved values are not checked: the request function computes
/// the partial note itself.
///
/// DEV DECISION: intake refuses exactly the requests the circuits would
/// answer with codes 1 (amount not a u128), 2 (amount zero) and 3 (a
/// position out of range, position 0 outside an opening deposit, a count
/// outside 1 .. K - 1) and 15 (a position named twice), the index rules of
/// a tree-valued key (docs/ARCHITECTURE.md section 6), so those never cost a
/// round. Code 6 (no price) does not apply at intake: the price is not a
/// request input but the oracle's value when the round runs. A full book
/// (code 16) is the scheduler's to decide, and everything else depends on
/// the secret state and stays the circuit's `ok`. Looser (no check): every
/// malformed request costs a round and lands as an ok = 0 no-op. Design
/// guide: "access control".
///
/// Over C's values before the partial note, `[position, amount]` and
/// whatever follows them (a request's delivery handle, which no static rule
/// reads: the request function computes its partial commitment itself).
pub fn valid_deposit<let N: u32>(inputs: [Field; N]) -> bool {
    inputs[0].lt(TWO_POW_DEPTH) & amount_ok(inputs[1])
}

/// `valid_deposit` over the non-secret-shared deposit's inputs `[position,
/// amount, partial_note]`.
pub fn valid_plain_deposit(inputs: [Field; PLAIN_DEPOSIT_INPUTS]) -> bool {
    valid_deposit([inputs[0], inputs[1]])
}

/// The static validity of the oblivious deployment's opening rounds'
/// requests (`lending_tip_oblivious`'s `deposit_shared` and `supply_shared`:
/// `[position, opens, amount]`): `valid_deposit`'s rule on the position and the amount, and the
/// public opening flag a 0 or 1 that is 1 exactly when the position is 0
/// (the position is shared, so the flag tells the nodes which slot opens;
/// the circuit refuses a flag that disagrees, code 4).
/// Over the values before the partial note, `[position, opens, amount]`
/// and the request's delivery handle after them.
pub fn valid_oblivious_opening<let N: u32>(inputs: [Field; N]) -> bool {
    let opens = inputs[1];
    valid_deposit([inputs[0], inputs[2]]) & ((opens == 0) | (opens == 1)) & ((opens == 1) == (inputs[0] == 0))
}

/// The static validity of a withdrawal, a borrow, a repayment or a
/// withdrawal of supply, `[position, amount]` (`[position, shares]`): a
/// position in 1 .. 2^D - 1 and a non-zero u128 amount (codes 3, 2, 1),
/// whatever follows them (a request's delivery handle).
pub fn valid_owner_request<let N: u32>(inputs: [Field; N]) -> bool {
    named(inputs[0]) & amount_ok(inputs[1])
}

/// The static validity of a quote: none (it takes no app input).
pub fn valid_quote(_inputs: [Field; 0]) -> bool {
    true
}

/// The static validity of a view, `[position]` and its delivery handle: a
/// position in 1 .. 2^D - 1 (code 3).
pub fn valid_view<let N: u32>(inputs: [Field; N]) -> bool {
    named(inputs[0])
}

/// The static validity of a scan, `[start]`: a start below 2^D and a
/// multiple of W (code 3), so a scan never names a window the book cannot
/// hold.
pub fn valid_scan(inputs: [Field; 1]) -> bool {
    let start = inputs[0];
    let ok = start.lt(TWO_POW_DEPTH);
    // start < 2^D fits 32 bits, so the cast is exact when ok
    ok & ((start as u32) % WINDOW == 0)
}

/// The static validity of a liquidation, `[p_1, .., p_{K-1}, count,
/// budget]`: a non-zero u128 budget (codes 1, 2), a count in 1 .. K - 1 and
/// each of the first `count` positions in 1 .. 2^D - 1 and named once
/// (codes 3 and 15). The positions past the count are not read. Whether a
/// position is unhealthy is the state's and the price's: the circuit's mask.
pub fn valid_liquidation(inputs: [Field; LIQUIDATE_INPUTS]) -> bool {
    let count = inputs[PROBES - 1];
    let mut ok = amount_ok(inputs[PROBES]) & (count != 0) & count.lt(PROBES as Field);
    for k in 0..PROBES - 1 {
        let used = (k as Field).lt(count);
        ok = ok & (!used | named(inputs[k]));
        for j in 0..PROBES - 1 {
            if j < k {
                ok = ok & !(used & (inputs[j] == inputs[k]));
            }
        }
    }
    ok
}

/// The pinned price read, which every lending round makes (so that every
/// round's apply is the same): an epoch read of `get_price_epoch()` on the
/// oracle, no arguments, under the library's default gas bound (three
/// storage reads). The round lands at the oracle's current epoch or the one
/// before it (the manifests' `"freshness": "epoch"`, `"epoch_param":
/// "price_epoch"`), so a price published while the round is proved does not
/// force a recompute.
pub fn price_read(oracle: AztecAddress) -> PinnedRead<0> {
    PinnedRead::new(
        oracle,
        comptime { FunctionSelector::from_signature("get_price_epoch()") },
        [],
    )
        .with_freshness(Freshness::epoch())
}

/// The pinned clock read, which every lending round makes beside the price
/// (examples/lending-tip/README.md, "Interest", "The clock"): this contract's
/// own `clock()`, the L2 block number, under a tolerance of CLOCK_BAND
/// blocks (the manifests' `"freshness": "tolerance"`, `"band": {"absolute":
/// "128"}`): the round lands while its clock is within CLOCK_BAND blocks of
/// the block `apply` runs in, ahead of it or behind. The rounds accrue
/// interest to that clock and never move the last accrual back, so the
/// band lets the network place an accrual within CLOCK_BAND blocks of the
/// chain's clock (shifting up to rate * CLOCK_BAND of interest between
/// adjacent rounds' parties) and bring forward at most CLOCK_BAND blocks of
/// interest in total, once. The read targets the market itself, never the
/// oracle, so the oracle's owner cannot move time.
pub fn clock_read(market: AztecAddress) -> PinnedRead<0> {
    PinnedRead::new(market, comptime { FunctionSelector::from_signature("clock()") }, [])
        .with_freshness(Freshness::absolute(CLOCK_BAND as u128))
}

/// The private half of a secret-shared result (`process_shared`,
/// `process_header_shared`): check the result against its round's row
/// (`RoundTable::round`; pss_public_contract `check_round`:
/// the vk pin, the binding, the proof and the three node signatures, under
/// node-held state, the capsule scoped to `scope`, the submitter), its
/// tree's `T` new leaf hashes, its app values (the round's `EXIT_TAGS` exit
/// tags, then `T` values: the book's append index when the round has a
/// position slot, and the inputs-opened bit last) and its deliveries
/// (`SharedDeliveries`, whose note hashes and logs it lands after the
/// outcome's). Returns `apply_shared`'s arguments: what it lands, the bit
/// and the exit tags, which the landing emits as nullifiers
/// (pss_public_contract `Hatch::landed`). The append index stays in the
/// proof: carried in the public call it would show the number of positions
/// and whether a round was an applied opening.
pub fn check_shared<K, let T: u32>(
    context: &mut PrivateContext,
    row: TipRound<&mut PrivateContext, 1, 1, K>,
    scope: AztecAddress,
    result: SharedResult,
    new_hashes: [Field; T],
    values: [Field; EXIT_TAGS + T],
    deliveries: SharedDeliveries,
    signatures: [ResultSignature; 3],
    outcome_notes_slot: Field,
) -> (SharedApply, Field, [Field; EXIT_TAGS])
where
    K: SigningKeys,
{
    let outputs = Private::of(result, outcome_notes_slot, OUTCOME_SLOT).tree(new_hashes).valued(values);
    let apply = check_round(
        row,
        context,
        scope,
        Delivered::of(outputs, deliveries),
        NodeHeld {},
        signatures,
    );
    let mut tags = [0; EXIT_TAGS];
    for i in 0..EXIT_TAGS {
        tags[i] = values[i];
    }
    (apply, values[EXIT_TAGS + T - 1], tags)
}

/// What an exit pays on its note (examples/lending-tip/README.md, "The
/// escape hatch", "The exit rule"), `(collateral out, borrowed out, borrowed in)`: a
/// borrower note (mask, the index at touch, nonzero) repays its debt `y` in
/// the borrowed asset and takes its collateral `x`; a lender note takes its
/// shares' value `y`, as of the note's round (no interest since).
pub fn exit_amounts(note: LendingOutcome) -> (u128, u128, u128) {
    if note.mask != 0 {
        (note.x as u128, 0, note.y as u128)
    } else {
        (0, note.y as u128, 0)
    }
}
