use aztec::macros::aztec;
use lending_market::app::RoundTable;
use pss_public_contract::{KeyEpochs, NoEncKeys};

// BRICK node_keys = rotating (pss_public_contract::KeyEpochs): the rows and the state view name the brick
// through Keys alone, with rotate_keys, set_node_keys, assert_key_epoch and get_node_keys below.
// Alternatives: fixed (FixedKeys here, none of the four; examples/credits-tip).
// docs/design-guide/BRICKS.md#node_keys
/// The node-keys brick every node signature is checked under: key epochs,
/// which `rotate_keys` moves, over no node `enc` keys (`NoEncKeys`: this
/// contract has no secret-shared on-chain intake).
pub type Keys = KeyEpochs<NoEncKeys>;

/// The round table: the oblivious tree's package names (lending_market
/// `RoundTable::oblivious`), the tree access this contract is for.
pub global ROUNDS: RoundTable<Keys> = RoundTable::oblivious();

/// Lending at the tip of the chain over the oblivious tree
/// (docs/ARCHITECTURE.md section 6, "The oblivious tree"; lending_market's module doc: the market,
/// ownership by note, the liquidated owner's notice, tokens and credits):
/// the nodes hold the book in an oblivious RAM and never see which leaves a
/// round touches, so a request's position is shared in its C; an opening
/// (a deposit or a supply into position 0) also names the public opening
/// flag `opens`, 1 exactly when the position is 0, which tells the nodes
/// which slot opens. The same market over the clear tree is `lending_tip`,
/// over the same library; this contract has its one deployment
/// (`OBLIVIOUS_PACKAGES`: `lending_init_oblivious` and every round's
/// `<round>_oblivious` package), every round under secret-shared receipt
/// intake.
///
/// Its functions are `lending_tip`'s for that deployment, declared alike,
/// with the same names and signatures: `constructor`, `configure`,
/// `init_market`, the credits (`fund`, `withdraw_funds`, `merge_credits`,
/// `credit_balance`), the secret-shared request functions (`deposit_shared`,
/// `withdraw_shared`, `borrow_shared`, `repay_shared`, `supply_shared`,
/// `withdraw_supply_shared`, `view_shared`, `quote_shared`,
/// `liquidate_shared`, `scan_shared`), `process_shared`,
/// `process_header_shared`, `redeem`, the key epochs, `skip`, the escape
/// hatch, `sweep_deposits` and the views and utilities; but the request
/// functions on a position take the position shared under the round's
/// oblivious layout (one more summand vector in `sharing`), and
/// `deposit_shared` and `supply_shared` take `opens` after the position.
/// It has neither the non-secret-shared deposit nor secret-shared on-chain
/// intake (no circuit of either runs over the oblivious tree).
#[aztec]
pub contract LendingTipOblivious {
    use crate::{Keys, ROUNDS};
    use lending_market::app::{
        check_shared, Config, Credit, Draw, EXIT_TAGS, HANDLED_INPUTS, KIND_BORROWER, KIND_LENDER, LendingOutcome,
        MAX_LOG_FIELDS, Nonces, OutcomeNotes, OWNER_INPUTS, OWNER_SLOTS, PACKAGES, PROBES, ROUND_BORROW,
        ROUND_DEPOSIT, ROUND_LIQUIDATE, ROUND_QUOTE, ROUND_REPAY, ROUND_SCAN, ROUND_SUPPLY, ROUND_VIEW,
        ROUND_WITHDRAW, ROUND_WITHDRAW_SUPPLY, SharedApply, SharedDeliveries, SharedResult, valid_liquidation,
        valid_oblivious_opening, valid_owner_request, valid_quote, valid_scan, valid_view,
    };
    use lending_market::layouts::{
        BORROW_OBLIVIOUS_LAYOUT, DEPOSIT_OBLIVIOUS_LAYOUT, LIQUIDATE_OBLIVIOUS_LAYOUT, QUOTE_OBLIVIOUS_LAYOUT,
        REPAY_OBLIVIOUS_LAYOUT, SCAN_OBLIVIOUS_LAYOUT, SUPPLY_OBLIVIOUS_LAYOUT, VIEW_OBLIVIOUS_LAYOUT,
        WITHDRAW_OBLIVIOUS_LAYOUT, WITHDRAW_SUPPLY_OBLIVIOUS_LAYOUT,
    };
    use lending_market::request::{Escrow, Holds, with_handle};
    use lending_market::storage::LendingStorage;
    use aztec::macros::{
        functions::{external, initializer, internal, only_self, view},
        storage::storage,
    };
    use aztec::context::PrivateContext;
    use aztec::protocol::address::AztecAddress;
    use aztec::state_vars::{Map, Owned, PrivateSet, PublicImmutable, PublicMutable, StateVariable};
    use pss_public_contract::{
        CircuitsInForce, CommitmentSlot, configure, Configured, FixedCircuits, init, key_epoch, KeySet, Layout, logs,
        NodeHeld, NodeKeys, NoEncKeys, Queue, Receipt, ReceiptRequest, Refunds, RegistryAnswer, SharedReceiptArgs,
        SharedRequest, Sharing, TipRound, TipState,
    };
    use pss_public_contract::outcome::{deliver_outcome_into, OutcomeTx};
    use pss_public_contract::hatch::{Hatch, HatchState};
    use pss_public_contract::result::ResultSignature;

    // lending_market's LendingStorage, in its order
    #[storage]
    struct Storage<Context> {
        outcome_notes: Owned<PrivateSet<LendingOutcome, Context>, Context>,
        config: PublicImmutable<Config, Context>,
        configured: PublicImmutable<Configured<PACKAGES>, Context>,
        queue: Queue<Context>,
        market: CommitmentSlot<Context>,
        refunds: Map<u64, PublicMutable<Refunds, Context>, Context>,
        kept_deposits: PublicMutable<u128, Context>,
        credits: Owned<PrivateSet<Credit, Context>, Context>,
        hatch: Hatch<Context>,
    }

    impl<Context> Storage<Context> {
        /// The members lending_market's bodies read.
        fn lending(self) -> LendingStorage<Context> {
            LendingStorage {
                outcome_notes: self.outcome_notes,
                config: self.config,
                configured: self.configured,
                queue: self.queue,
                market: self.market,
                refunds: self.refunds,
                kept_deposits: self.kept_deposits,
                credits: self.credits,
                hatch: self.hatch,
            }
        }
    }

    #[external("public")]
    #[initializer]
    fn constructor(config: Config) {
        config.assert_valid();
        self.storage.config.initialize(config);
    }

    // -----------------------------------------------------------------------
    // Configure: the REGISTER answer, once
    // -----------------------------------------------------------------------

    /// pss_public_contract::configure::configure; `set_configured` stores it
    /// once.
    #[external("private")]
    fn configure(npk_app_hash: Field, answer: RegistryAnswer) {
        let configured = configure::configure(
            self.context,
            self.storage.config.read().tip,
            npk_app_hash,
            answer,
        );
        self.enqueue_self.set_configured(configured);
    }

    /// The public half of `configure`: stores `Configured` once.
    #[external("public")]
    #[only_self]
    fn set_configured(configured: Configured<PACKAGES>) {
        self.storage.configured.initialize(configured);
    }

    // -----------------------------------------------------------------------
    // Upgrades: the circuit pins in force
    // -----------------------------------------------------------------------

    /// The stored `Configured` under the circuit pins in force, which every
    /// round function builds its round table row from: the one place the
    /// contract names its upgrades brick.
    #[internal("private")]
    fn configured_in_force() -> Configured<PACKAGES> {
        // BRICK upgrades = fixed (pss_public_contract::FixedCircuits): the constructor's pins as stored, for the
        // life of the contract. Alternatives: circuits, contract (CircuitUpgrades::in_force here, with its storage,
        // upgrade_circuits and assert_upgrade_class; examples/amm-tip). docs/design-guide/BRICKS.md#upgrades
        FixedCircuits {}.in_force(self.storage.configured.read())
    }

    /// The row of secret-shared round `round` (a `ROUND_*` index) in the
    /// round table. A contract library method, since an internal function
    /// cannot return a row (it holds the context).
    #[contract_library_method]
    fn shared_row(context: &mut PrivateContext, round: u32) -> TipRound<&mut PrivateContext, 1, 1, Keys> {
        ROUNDS.round(CallInternal { context }.configured_in_force(), Storage::init(context).market, round)
    }

    // -----------------------------------------------------------------------
    // Init: the lending_init round, once, outside the queue
    // -----------------------------------------------------------------------

    /// Land the init round (the library's `process_init`, the never-queued
    /// init documented in pss_public_contract's `init`): verify the
    /// `lending_init` proof, with the Config's liquidity and the book
    /// header's new leaf hash (`new_hashes`, the init layout's tail), under
    /// the pinned init vk and the three nodes' result signatures over `new_c`
    /// (node-held: no sealed thirds), under the init request id of the
    /// inputs `[liquidity]`, then enqueue `apply_init`. The relayer stages
    /// the (vk, proof) capsule as for a result.
    #[external("private")]
    fn init_market(new_c: Field, new_hashes: [Field; 1], signatures: [ResultSignature; 3]) {
        let request_id = init::process_init(
            ROUNDS.init(self.internal.configured_in_force(), self.storage.market),
            self.context,
            self.msg_sender(),
            [self.storage.config.read().init_liquidity],
            [new_c],
            new_hashes,
            NodeHeld {},
            signatures,
        );
        self.enqueue_self.apply_init(request_id, new_c);
    }

    /// lending_market `LendingStorage::apply_init`.
    #[external("public")]
    #[only_self]
    fn apply_init(request_id: Field, new_c: Field) {
        self.storage.lending().apply_init(self.context, request_id, new_c);
    }

    // -----------------------------------------------------------------------
    // Credits: the private app balance (lending_market app::Credit)
    // -----------------------------------------------------------------------

    /// lending_market `LendingStorage::escrow`, from the sender's credit.
    #[internal("private")]
    fn escrow(draw: Draw, rho: Field) -> Refunds {
        self.storage.lending().escrow(self.context, self.msg_sender(), draw, rho)
    }

    /// A request's escrow and usage deposit (`escrow`), then receipt intake's
    /// wrapper `append_receipt` enqueued with the request id, the expiry
    /// block and the `Refunds`: the tail of the receipt intake deposit and of
    /// every secret-shared receipt request function.
    #[internal("private")]
    fn queue_receipt(request_id: Field, expiry_block: u32, draw: Draw, rho: Field) {
        let refunds = self.internal.escrow(draw, rho);
        self.enqueue_self.append_receipt(request_id, expiry_block, refunds);
    }

    /// lending_market `LendingStorage::fund`, then its public half
    /// `assert_initialised`.
    #[external("private")]
    fn fund(collateral: u128, borrowed: u128, nonces: Nonces) {
        self.storage.lending().fund(self.context, self.msg_sender(), collateral, borrowed, nonces);
        self.enqueue_self.assert_initialised();
    }

    /// The public half of `fund`: refuse before the init round has landed
    /// ("state not initialised", `pss_public_contract::assert_initialised`).
    #[external("public")]
    #[only_self]
    fn assert_initialised() {
        pss_public_contract::assert_initialised(self.storage.market);
    }

    /// lending_market `LendingStorage::merge_credits`.
    #[external("private")]
    fn merge_credits() {
        self.storage.lending().merge_credits(self.msg_sender());
    }

    /// lending_market `LendingStorage::withdraw_funds`, then its public half
    /// `pay_withdrawal`.
    #[external("private")]
    fn withdraw_funds(collateral: u128, borrowed: u128) {
        let (collateral_note, borrowed_note) =
            self.storage.lending().withdraw_funds(self.context, self.msg_sender(), collateral, borrowed);
        self.enqueue_self.pay_withdrawal(collateral, collateral_note, borrowed, borrowed_note);
    }

    /// lending_market `LendingStorage::pay_withdrawal`.
    #[external("public")]
    #[only_self]
    fn pay_withdrawal(collateral: u128, collateral_note: Field, borrowed: u128, borrowed_note: Field) {
        self.storage.lending().pay_withdrawal(self.context, collateral, collateral_note, borrowed, borrowed_note);
    }

    // -----------------------------------------------------------------------
    // Intake (secret-shared receipt intake, `intake: shared_receipt`)
    // -----------------------------------------------------------------------
    //
    // Each request function takes the app inputs, the position (a
    // liquidation's probes) shared under the round's oblivious layout and an
    // opening's public flag `opens` beside it (a request on a borrower
    // position also its delivery handle's `handle_rho` and `handle_key`),
    // `rho` (the randomness the client derives for this request), the
    // outcome key and tag, the sharing (the summand vectors the nodes hold,
    // under the round's layout, the generated `layouts`' global of its
    // package), the expiry block and the three node receipts as private
    // arguments, and is one call of `shared_request` naming its round, the
    // note it needs (`Holds`), its app inputs, layout and validity check,
    // and its escrow (`Escrow`): lending_market `LendingStorage::request`,
    // then `escrow` and receipt intake's wrapper `append_receipt` with the
    // request id, the expiry block and the `Refunds`: one public call for
    // every round type, holding no input, no token and no amount, so the
    // round type's escrow class (a deposit escrows the collateral asset, a
    // repayment, a supply and a liquidation the borrowed asset, every other
    // round nothing) stays private. `msg_sender` is read in private only,
    // into nothing public; the round never sees an owner.

    /// The body of every secret-shared request function (`request`, its
    /// `SharedReceiptArgs`): lending_market `LendingStorage::request` on the
    /// row of `round`, then the escrow and the request queued through
    /// receipt intake's public wrapper (`queue_receipt`). A contract library
    /// method, since an internal function cannot be generic: it builds the
    /// storage and the internal calls from the request function's context,
    /// as aztec-nr's internal functions build their `self`.
    #[contract_library_method]
    fn shared_request<I, let N: u32, let Q: u32, let X: u32, Env>(
        context: &mut PrivateContext,
        round: u32,
        holds: Holds,
        inputs: [Field; N],
        layout: Layout<N + 3, Q, X>,
        request: I,
        valid: fn[Env]([Field; N]) -> bool,
        escrow: Escrow,
    )
    where
        I: SharedRequest<ReceiptRequest, Keys>,
    {
        let row = shared_row(context, round);
        let (queued, draw, rho): (ReceiptRequest, Draw, Field) =
            Storage::init(context).lending().request(context, row, holds, inputs, layout, request, valid, escrow);
        CallInternal { context }.queue_receipt(queued.request_id, queued.expiry_block, draw, rho);
    }

    /// Queue a secret-shared deposit of `amount` into `position` (0 opens a
    /// new position; another requires the sender's note of it), `amount` of
    /// the collateral asset escrowed here (returned through the round's note
    /// when the deposit does not apply). The round's note is the sender's
    /// first note of a new position, or its next note of this one. The
    /// position travels shared, so the request also names the public opening
    /// flag `opens` (1 exactly when `position` is 0), which C commits to with
    /// the position and the amount (`valid_oblivious_opening`): the nodes read
    /// the flag, never the position (`DEPOSIT_OBLIVIOUS_LAYOUT`).
    #[external("private")]
    fn deposit_shared(
        position: Field,
        opens: Field,
        amount: Field,
        handle_rho: Field,
        handle_key: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<8>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_DEPOSIT, Holds::note_or_open(position, KIND_BORROWER),
            with_handle(self.msg_sender(), [position, opens, amount], handle_rho, handle_key),
            DEPOSIT_OBLIVIOUS_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_oblivious_opening::<5>, Escrow::collateral(amount),
        );
    }

    /// Queue a secret-shared borrow of `amount` against `position`, whose note
    /// the sender holds; the payout, the amount when the round is ok, is the
    /// round's note's, which the sender redeems. Escrows nothing; pays the
    /// usage deposit.
    #[external("private")]
    fn borrow_shared(
        position: Field,
        amount: Field,
        handle_rho: Field,
        handle_key: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<8>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_BORROW, Holds::note(position, KIND_BORROWER),
            with_handle(self.msg_sender(), [position, amount], handle_rho, handle_key),
            BORROW_OBLIVIOUS_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_owner_request::<HANDLED_INPUTS>, Escrow::none(),
        );
    }

    /// Queue a secret-shared withdrawal of `amount` of `position`'s
    /// collateral, whose note the sender holds; the payout, the amount in the
    /// collateral asset when the round is ok (the position stays at or above
    /// the borrow limit), is the round's note's, which the sender redeems.
    /// Escrows nothing; pays the usage deposit.
    #[external("private")]
    fn withdraw_shared(
        position: Field,
        amount: Field,
        handle_rho: Field,
        handle_key: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<8>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_WITHDRAW, Holds::note(position, KIND_BORROWER),
            with_handle(self.msg_sender(), [position, amount], handle_rho, handle_key),
            WITHDRAW_OBLIVIOUS_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_owner_request::<HANDLED_INPUTS>, Escrow::none(),
        );
    }

    /// Queue a secret-shared repayment of `amount` of `position`'s debt,
    /// whose note the sender holds, escrowed here in the borrowed asset; the
    /// round repays at most the debt and returns the excess (and the whole
    /// amount when it does not apply) through its note.
    #[external("private")]
    fn repay_shared(
        position: Field,
        amount: Field,
        handle_rho: Field,
        handle_key: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<8>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_REPAY, Holds::note(position, KIND_BORROWER),
            with_handle(self.msg_sender(), [position, amount], handle_rho, handle_key),
            REPAY_OBLIVIOUS_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_owner_request::<HANDLED_INPUTS>, Escrow::borrowed(amount),
        );
    }

    /// Queue a secret-shared view of `position`, whose note the sender holds:
    /// the round reports its collateral and debt in a fresh note, the
    /// position's newest, and changes nothing but blindings, its delivery
    /// handle and its exit tag. How an owner refreshes its view.
    #[external("private")]
    fn view_shared(
        position: Field,
        handle_rho: Field,
        handle_key: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<7>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_VIEW, Holds::note(position, 0),
            with_handle(self.msg_sender(), [position], handle_rho, handle_key),
            VIEW_OBLIVIOUS_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_view::<3>, Escrow::none(),
        );
    }

    /// Queue a secret-shared liquidation of the first `count` of `positions`,
    /// repaying at most `budget` of the borrowed asset, which the sender
    /// escrows here: the round's note, the sender's, carries the total seize
    /// (collateral asset) and the unused budget (borrowed asset), which it
    /// redeems. Open to anyone: no note is required. Each liquidated owner is
    /// notified: the round completes the delivery handle the position's
    /// leaf holds (its owner's last request left it) with the position after
    /// the liquidation, so the owner holds a current note of the position
    /// without a round of its own; a position whose handle a liquidation
    /// already used notifies nobody until its owner's next request.
    #[external("private")]
    fn liquidate_shared(
        positions: [Field; PROBES - 1],
        count: Field,
        budget: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<6>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_LIQUIDATE, Holds::anyone(),
            positions.concat([count, budget]),
            LIQUIDATE_OBLIVIOUS_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_liquidation, Escrow::borrowed(budget),
        );
    }

    /// Queue a secret-shared scan, the keeper round: the window of `WINDOW`
    /// positions from `start` (below 2^D, a multiple of W), whose health
    /// bits at the pinned price and occupied count reach the sender's note
    /// only. Anyone may ask; it pays the usage deposit.
    #[external("private")]
    fn scan_shared(
        start: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<4>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_SCAN, Holds::anyone(),
            [start],
            SCAN_OBLIVIOUS_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_scan, Escrow::none(),
        );
    }

    /// Queue a secret-shared supply of `amount` of the borrowed asset, a
    /// lender's, into `position` (0 opens a new lender position; another
    /// requires the sender's lender note of it), escrowed here; the round
    /// mints shares at the pool's value and returns the amount through its
    /// note when it does not apply. As `deposit_shared`, the request names
    /// the public opening flag `opens` beside the shared position
    /// (`SUPPLY_OBLIVIOUS_LAYOUT`).
    #[external("private")]
    fn supply_shared(
        position: Field,
        opens: Field,
        amount: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<6>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_SUPPLY, Holds::note_or_open(position, KIND_LENDER),
            [position, opens, amount],
            SUPPLY_OBLIVIOUS_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_oblivious_opening::<3>, Escrow::borrowed(amount),
        );
    }

    /// Queue a secret-shared withdrawal of `shares` of `position`, a lender
    /// position whose note the sender holds; the payout, the shares' value
    /// in the borrowed asset when the round is ok (the liquidity covers it),
    /// is the round's note's, which the sender redeems. Escrows nothing; pays
    /// the usage deposit.
    #[external("private")]
    fn withdraw_supply_shared(
        position: Field,
        shares: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<6>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_WITHDRAW_SUPPLY, Holds::note(position, KIND_LENDER),
            [position, shares],
            WITHDRAW_SUPPLY_OBLIVIOUS_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_owner_request::<OWNER_INPUTS>, Escrow::none(),
        );
    }

    /// Queue a secret-shared quote of the market's rates (the borrow index,
    /// the supply index and the utilisation), which reach the sender's note
    /// only. Anyone may ask; it takes no app input and pays the usage
    /// deposit.
    #[external("private")]
    fn quote_shared(
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<4>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_QUOTE, Holds::anyone(),
            [],
            QUOTE_OBLIVIOUS_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_quote, Escrow::none(),
        );
    }

    /// lending_market `LendingStorage::append_receipt`.
    #[external("public")]
    #[only_self]
    fn append_receipt(request_id: Field, expiry_block: u32, refunds: Refunds) {
        self.storage.lending().append_receipt(request_id, expiry_block, refunds);
    }

    // -----------------------------------------------------------------------
    // The key epochs (pss_public_contract `key_epoch`)
    // -----------------------------------------------------------------------

    /// pss_public_contract::key_epoch::check_rotation.
    #[external("private")]
    fn rotate_keys(epoch: u32, keys: KeySet, signatures: [ResultSignature; 3]) {
        // BRICK node_keys = rotating (pss_public_contract::key_epoch::check_rotation), with Keys = KeyEpochs
        // (above the contract) and set_node_keys, assert_key_epoch and get_node_keys below. Alternatives:
        // fixed (Keys = FixedKeys, none of the four; examples/credits-tip). docs/design-guide/BRICKS.md#node_keys
        let config = self.storage.configured.read().config();
        let node_keys = key_epoch::check_rotation(self.context, config, epoch, keys, signatures);
        self.enqueue_self.set_node_keys(node_keys);
    }

    /// pss_public_contract::KeyEpochs::install; no enc keys to void
    /// (`NoEncKeys`).
    #[external("public")]
    #[only_self]
    fn set_node_keys(node_keys: NodeKeys) {
        // the enc keys Keys names: none, this contract has no secret-shared on-chain intake (lending_tip
        // installs over its SharedOnchain)
        Keys::install(self.context, node_keys, NoEncKeys {});
    }

    /// pss_public_contract::key_epoch::assert_epoch.
    #[external("public")]
    #[only_self]
    fn assert_key_epoch(epoch: u32, current_only: bool) {
        key_epoch::assert_epoch(self.context, epoch, current_only);
    }

    /// pss_public_contract::key_epoch::stored.
    #[external("public")]
    #[view]
    fn get_node_keys() -> NodeKeys {
        key_epoch::stored(self.context)
    }

    // -----------------------------------------------------------------------
    // The secret-shared rounds' result transaction (private outcomes,
    // partial-note delivery)
    // -----------------------------------------------------------------------
    //
    // Two wrappers, one per public-input shape, over the row of the round in
    // the round table (`round`, a `ROUND_*` index): the round is a private
    // argument, so the chain sees the one `apply_shared` whatever the round
    // type. Each is lending_market's `check_shared`, the library's
    // `check_round` over the row with the round's private outcome and its
    // delivery (`handle::Delivered` over `outcome::Private`): it verifies the
    // proof over the result, the book's new leaf hashes (private arguments
    // the proof binds, which nothing stores), the outcome, the app values
    // (the exit tags, the book's append index and the inputs-opened bit) and
    // the delivery (`SharedDeliveries`, the proof's last public inputs),
    // checks the three result signatures, pushes the completed note's hash
    // (the requester's partial note, completed by the round), emits the
    // outcome log padded to 16 fields, pushes the delivery's note hash and
    // emits its log (a liquidated owner's notice, else a filler) and enqueues
    // `apply_shared` with the bit and the exit tags, which it emits as
    // nullifiers in the public call that moves the commitment; nothing runs
    // after the log and no other contract is called. The row's pin selects
    // the circuit, so a round named with the other shape verifies no proof.
    // Anyone may submit; the relayer does, and it sees ciphertext, hashes
    // and the values only: no owner, amount or partial note.

    /// A result of an owner-bound round (`ROUND_DEPOSIT`, `ROUND_BORROW`,
    /// `ROUND_REPAY`, `ROUND_VIEW`, `ROUND_WITHDRAW`, `ROUND_SUPPLY`,
    /// `ROUND_WITHDRAW_SUPPLY`: the header's and the position's new leaf
    /// hashes) or of a liquidation (`ROUND_LIQUIDATE`: the header's and each
    /// probe's leaf hash; `PROBES` of them), with its app values: the exit
    /// tags, the book's append index and the bit.
    #[external("private")]
    fn process_shared(
        round: u32,
        result: SharedResult,
        new_hashes: [Field; PROBES],
        values: [Field; EXIT_TAGS + PROBES],
        deliveries: SharedDeliveries,
        signatures: [ResultSignature; 3],
    ) {
        // owner rounds and liquidations land through one layout of PROBES slots
        std::static_assert(PROBES == OWNER_SLOTS, "an owner round and a liquidation have one result layout");
        assert((round != ROUND_SCAN) & (round != ROUND_QUOTE), "a header-only round lands through process_header_shared");
        let (apply, opened, tags) = check_shared(
            self.context,
            shared_row(self.context, round),
            self.msg_sender(),
            result,
            new_hashes,
            values,
            deliveries,
            signatures,
            self.storage.outcome_notes.get_storage_slot(),
        );
        self.enqueue_self.apply_shared(apply, opened, tags);
    }

    /// A result of a header-only round (`ROUND_SCAN`, `ROUND_QUOTE`): the
    /// header's new leaf hash, and its app values: the exit tags (fillers)
    /// and the bit.
    #[external("private")]
    fn process_header_shared(
        round: u32,
        result: SharedResult,
        new_hashes: [Field; 1],
        values: [Field; EXIT_TAGS + 1],
        deliveries: SharedDeliveries,
        signatures: [ResultSignature; 3],
    ) {
        assert((round == ROUND_SCAN) | (round == ROUND_QUOTE), "an owner-bound round lands through process_shared");
        let (apply, opened, tags) = check_shared(
            self.context,
            shared_row(self.context, round),
            self.msg_sender(),
            result,
            new_hashes,
            values,
            deliveries,
            signatures,
            self.storage.outcome_notes.get_storage_slot(),
        );
        self.enqueue_self.apply_shared(apply, opened, tags);
    }

    /// lending_market `LendingStorage::apply_shared`.
    #[external("public")]
    #[only_self]
    fn apply_shared(apply: SharedApply, opened: Field, tags: [Field; EXIT_TAGS]) {
        self.storage.lending().apply_shared(self.context, apply, opened, tags);
    }

    /// lending_market `LendingStorage::redeem`, of the caller's note.
    #[external("private")]
    fn redeem(request_id: Field) {
        self.storage.lending().redeem(self.context, self.msg_sender(), request_id);
    }

    // -----------------------------------------------------------------------
    // The escape hatch (examples/lending-tip/README.md, "The escape hatch")
    // -----------------------------------------------------------------------

    /// lending_market `LendingStorage::open_hatch`.
    #[external("public")]
    fn open_hatch() {
        self.storage.lending().open_hatch(self.context);
    }

    /// lending_market `LendingStorage::poke`.
    #[external("public")]
    fn poke() {
        self.storage.lending().poke();
    }

    /// lending_market `LendingStorage::exit`, on the sender's note.
    #[external("private")]
    fn exit(position: Field, request_id: Field) {
        self.storage.lending().exit(self.msg_sender(), position, request_id);
    }

    /// The escape hatch's state: whether it is open and the block the
    /// market started starving at (the keeper-side check, pss-client
    /// `hatchReady`, reads it).
    #[external("public")]
    #[view]
    fn get_hatch() -> HatchState {
        self.storage.hatch.state()
    }

    /// The outcome-note utility: hand `owner`'s PXE the completed note of a
    /// secret-shared round that the client rebuilt from the outcome log of
    /// transaction `tx` (`packed` = `[code, position, mask, x, y, payout,
    /// aux, request_id]`, `rho` the request's randomness, so the note
    /// completes the partial note `partial_commitment(owner, rho)`;
    /// pss_public_contract `deliver_outcome_into`). A note whose hash is not
    /// among the transaction's is not stored. The non-secret-shared deposit's
    /// note needs no utility: the owner's PXE completes it from the
    /// completion log.
    #[external("utility")]
    unconstrained fn deliver_outcome(owner: AztecAddress, rho: Field, packed: [Field; 8], tx: OutcomeTx) {
        deliver_outcome_into(self.storage.outcome_notes, self.address, _compute_note_hash, _compute_note_nullifier, owner, rho, packed, tx);
    }

    /// lending_market `LendingStorage::outcome_notes`.
    #[external("utility")]
    unconstrained fn outcome_notes(owner: AztecAddress) -> OutcomeNotes {
        self.storage.lending().outcome_notes(owner)
    }

    /// lending_market `LendingStorage::skip`.
    #[external("public")]
    fn skip() {
        self.storage.lending().skip(self.context);
    }

    /// lending_market `LendingStorage::sweep_deposits`.
    #[external("public")]
    fn sweep_deposits() {
        self.storage.lending().sweep_deposits(self.context);
    }

    /// The market's clock: the block number this public call runs in, the
    /// time interest accrues by. Every round's second pinned read (the
    /// manifests' `clock` read, lending_market `app::clock_read`), simulated
    /// by the scheduler at its snapshot and re-made by `apply` under a
    /// tolerance of CLOCK_BAND blocks. On the market itself, so no other
    /// contract's owner can move it.
    #[external("public")]
    #[view]
    fn clock() -> Field {
        self.context.block_number() as Field
    }

    /// Request `index`'s two refund notes (zero for an index never queued).
    #[external("public")]
    #[view]
    fn refunds_at(index: u64) -> Refunds {
        self.storage.refunds.at(index).read()
    }

    /// lending_market `LendingStorage::credit_balance`.
    #[external("utility")]
    unconstrained fn credit_balance(owner: AztecAddress, asset: Field) -> u128 {
        self.storage.lending().credit_balance(owner, asset)
    }

    /// The usage deposits kept and not yet swept, in the borrowed asset.
    #[external("public")]
    #[view]
    fn get_kept_deposits() -> u128 {
        self.storage.kept_deposits.read()
    }

    // -----------------------------------------------------------------------
    // Views
    // -----------------------------------------------------------------------

    /// pss_public_contract::view::TipState::read, over the market slot and the
    /// outcome notes' slot; its type reports the bricks, `Keys` and
    /// `FixedCircuits` (the contract manifest's node_keys and upgrades).
    #[external("public")]
    #[view]
    fn get_state() -> TipState<Config, 1, Keys, FixedCircuits> {
        TipState::read(
            self.context,
            self.storage.config,
            self.storage.configured,
            self.storage.queue,
            [self.storage.market],
            self.storage.outcome_notes.get_storage_slot(),
        )
    }

    /// pss_public_contract::queue::Queue::request_at.
    #[external("public")]
    #[view]
    fn request_at(index: u64) -> Field {
        self.storage.queue.request_at(index)
    }

    /// pss_public_contract::queue::Queue::done_at.
    #[external("public")]
    #[view]
    fn done_at(index: u64) -> u8 {
        self.storage.queue.done_at(index)
    }

    /// pss_public_contract::logs::log_in_tx: a public completion's log (a skipped or unopened request's refund notes).
    #[external("utility")]
    unconstrained fn log_in_tx(tx_hash: Field, tag: Field) -> BoundedVec<Field, MAX_LOG_FIELDS> {
        logs::log_in_tx(self.address, tx_hash, tag)
    }

}
