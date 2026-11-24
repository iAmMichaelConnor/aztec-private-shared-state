use aztec::context::PublicContext;
use aztec::macros::aztec;
use lending_market::app::RoundTable;
use pss_public_contract::{KeyEpochs, SharedOnchain};

// BRICK node_keys = rotating (pss_public_contract::KeyEpochs): the rows, check_enc_rotation and the
// state view name the brick through Keys alone, with rotate_keys, set_node_keys, assert_key_epoch and
// get_node_keys below. Alternatives: fixed (FixedKeys here, none of the four; examples/credits-tip).
// docs/design-guide/BRICKS.md#node_keys
// BRICK intake = shared_onchain (pss_public_contract::SharedOnchain): the node enc keys Keys names, which
// set_node_keys hands Keys::install and the intake requires (RetiresEncKeys). Alternatives: onchain, receipt,
// shared_receipt (KeyEpochs<NoEncKeys>, as lending_tip_oblivious). docs/design-guide/BRICKS.md#intake
/// The node-keys brick every node signature is checked under: key epochs,
/// which `rotate_keys` moves, over the contract's `SharedOnchain`
/// (secret-shared on-chain intake), whose replaced nodes' `enc` keys
/// `set_node_keys` voids (`Keys::install`).
pub type Keys = KeyEpochs<SharedOnchain<PublicContext>>;

/// The round table: the clear tree's package names (lending_market
/// `RoundTable::clear`), the tree access this contract is for.
pub global ROUNDS: RoundTable<Keys> = RoundTable::clear();

/// Lending at the tip of the chain over the clear tree (lending_market's
/// module doc: the market, ownership by note, the liquidated owner's notice,
/// tokens and credits): the nodes see which leaves a round touches, and a
/// request's position is clear in its C. The same market over the oblivious
/// tree is `lending_tip_oblivious`, over the same library.
///
/// How to read this contract: it carries every intake so that each can be
/// seen and run from one place, and a deployment's manifests select which it
/// uses. That is the example's choice. An app picks one intake
/// (docs/design-guide/README.md) and declares only the entry points of the
/// bricks it picked.
///
/// Two deployments of this contract, one intake family each (REGISTER's one
/// family per key): the secret-shared deployment (`SHARED_PACKAGES`, the
/// examples' default) runs every round under secret-shared receipt intake with
/// private outcomes delivered by partial-note completion: the amounts and the
/// user's partial note are shared, the round completes the note inside the
/// co-SNARK and the outcome reaches only the user (its note and an encrypted
/// log), and every round type goes through one `apply` with the same
/// arguments, the same price read and the same effects (one exit-tag
/// nullifier among them, a tag or a filler: nothing public names a
/// position); `redeem` pays a note's settlement in tokens. The non-secret-shared
/// deployment (`PLAIN_PACKAGES`) runs the deposit, the non-secret-shared-path
/// test, under both non-secret-shared intakes (on-chain intake and receipt
/// intake, one compiled circuit) with public outputs, its note completed in
/// public by `apply`.
///
/// Functions:
/// - `constructor(config)`: the pins that do not depend on the namespace
///   (`Config`: the stale period, the node `sig` keys, the contract
///   manifest's hash, the package list and each package's vk hash, so the
///   address commits to the circuits, the manifest, the seeded liquidity and
///   the oracle);
/// - `configure(npk_app_hash, answer)`: once, anyone, after the contract
///   manifest was registered under this address: checks the three nodes'
///   signatures of its REGISTER answer over the constructor's manifest hash
///   and package list and stores `npk_app_hash` beside the constructor's pins
///   (pss_public_contract `configure`); every function below refuses until
///   it has landed;
/// - `init_market(new_c, new_hashes, signatures)`: lands the `lending_init`
///   round once, outside the queue, while the market slot is empty;
/// - `deposit(position, amount, rho, user_nonce)` (position 0 opens a new
///   position): on-chain intake, the inputs `[position, amount, P]` to the
///   chain in the request log, the partial note's message to the sender's
///   PXE offchain; `deposit_with_receipts(position, amount, rho, user_nonce,
///   expiry_block, receipts)`: receipt intake, three node receipts checked
///   here, the inputs off the chain; every request function reads msg_sender
///   only in private, as the owner of the note it opens, of the partial note
///   it commits, of the credit note its escrow and deposit come from and of
///   the refund notes, into nothing public;
/// - `process_result(round, signatures)`: verifies one deposit's result,
///   whichever non-secret-shared intake queued it (one compiled circuit,
///   `deposit`, serves both), and enqueues `apply`, which re-reads the price,
///   lands the result and completes the request's partial note in public;
/// - secret-shared receipt intake: `deposit_shared`, `withdraw_shared`,
///   `borrow_shared`, `repay_shared`, `supply_shared`,
///   `withdraw_supply_shared`, `view_shared`, `quote_shared`,
///   `liquidate_shared` and `scan_shared` (the keeper round: anyone, a window
///   of the book reported as a private outcome) open the sender's note of the
///   position (the owner-bound rounds on an open position), commit the
///   partial note, prove that the sharing opens C, check the three node
///   receipts over C and its digest, draw the escrow and the deposit from the
///   sender's credit (`escrow`), and enqueue receipt intake's wrapper
///   `append_receipt(request_id, expiry_block, refunds)`; `process_shared`
///   and `process_header_shared` (the round named by its `ROUND_*` index)
///   verify one round's private outcome (the completed note's hash and the
///   outcome log), the inputs-opened bit and its delivery (a liquidation's
///   notice or a filler: a second note hash and log) and enqueue
///   `apply_shared(apply, opened, tags)`, which re-reads the price, writes
///   the new commitment, emits the round's exit tags (pss_public_contract
///   `Hatch::landed`) and settles the deposit (and completes the escrow's
///   refund note when the shares did not open C); `redeem(request_id)` spends
///   the caller's note of that request once (its redeem nullifier; the note
///   stays readable) and credits its settlement to the caller;
///   `deliver_outcome` and `outcome_notes` are the client's utilities;
/// - secret-shared on-chain intake, the deposit only: `deposit_shared_onchain`
///   reads the nodes' `enc` keys at its anchor block, puts the encoded shares
///   in one private log, escrows as `deposit_shared` and enqueues
///   `append_onchain_shared(request_id, data_hash, epochs, refunds)`; the
///   round is `deposit_shared`'s (one compiled circuit, which the network
///   also registers as `deposit_shared_onchain`) and lands through
///   `process_shared(ROUND_DEPOSIT, ...)`; `rotate_enc_key(i, key,
///   signature)` sets node i's key in this contract, and `get_enc_key`,
///   `get_data_hash` read them back;
/// - `skip()`: anyone drops a head older than `stale_blocks`, which returns
///   its escrow and deposit by completing their refund notes;
/// - the escape hatch (examples/lending-tip/README.md, "The escape
///   hatch", pss_public_contract `hatch`), on every deployment: `poke()` (anyone
///   starts the starving clock), `open_hatch()` (anyone, once the market has
///   starved T_LIVE blocks), `exit(position, request_id)` (private only: the
///   owner's newest note of the position, its exit tag pushed once) and
///   `get_hatch()`; `sweep_deposits()`: anyone pays the kept usage deposits
///   to the Config's treasury;
/// - credits: `fund(collateral, borrowed, nonces)`, `withdraw_funds(
///   collateral, borrowed)` (paid by `pay_withdrawal`), `merge_credits()`,
///   and the utility `credit_balance(owner, asset)`;
/// - `get_state()`, one view of every read that takes no argument (the
///   library's `TipState`), the per-index views `request_at` and `done_at`,
///   and `log_in_tx`, a utility that reads this contract's public log under
///   a tag (a request log, or a public completion's log).
///
/// The functions both contracts have are declared alike in both, with the
/// same signatures, and are each one call into lending_market's
/// `LendingStorage` (or pss_public_contract's app skeleton) over the round
/// table; the clear tree's own are the plain deposit's, the secret-shared
/// on-chain deposit's and the enc keys'.
#[aztec]
pub contract LendingTip {
    use crate::{Keys, ROUNDS};
    use lending_market::app::{
        check_shared, Config, ConfigPublic, DEPOSIT_PACKAGE, EXIT_TAGS, HANDLED_INPUTS, KIND_BORROWER, KIND_LENDER,
        LendingOutcome, market_state_keys, MAX_LOG_FIELDS, Nonces, OutcomeNotes, OWNER_INPUTS, OWNER_SLOTS,
        owner_note_fields, OwnerResult, PACKAGES, PLAIN_DEPOSIT_INPUTS, clock_read, price_read, PROBES, ROUND_BORROW,
        ROUND_DEPOSIT, ROUND_LIQUIDATE, ROUND_QUOTE, ROUND_REPAY, ROUND_SCAN, ROUND_SUPPLY, ROUND_VIEW,
        ROUND_WITHDRAW, ROUND_WITHDRAW_SUPPLY, SharedApply, SharedDeliveries, SharedResult, valid_deposit,
        valid_liquidation, valid_owner_request, valid_plain_deposit, valid_quote, valid_scan, valid_view, Credit, Draw,
    };
    use lending_market::layouts::{
        BORROW_SHARED_LAYOUT, DEPOSIT_SHARED_LAYOUT, DEPOSIT_SHARED_ONCHAIN_LAYOUT, LIQUIDATE_SHARED_LAYOUT,
        QUOTE_SHARED_LAYOUT, REPAY_SHARED_LAYOUT, SCAN_SHARED_LAYOUT, SUPPLY_SHARED_LAYOUT, VIEW_SHARED_LAYOUT,
        WITHDRAW_SHARED_LAYOUT, WITHDRAW_SUPPLY_SHARED_LAYOUT,
    };
    use lending_market::request::{Escrow, Holds, with_handle};
    use lending_market::storage::LendingStorage;
    use aztec::macros::{
        functions::{external, initializer, internal, only_self, view},
        storage::storage,
    };
    use aztec::context::PrivateContext;
    use aztec::messages::delivery::MessageDelivery;
    use aztec::protocol::address::AztecAddress;
    use aztec::state_vars::{Map, Owned, PrivateSet, PublicImmutable, PublicMutable, StateVariable};
    use pss_public_contract::{
        apply_round, assert_ready, check_enc_rotation, check_round, CircuitsInForce, CommitmentSlot, configure,
        Configured, EncKey, FixedCircuits, init, key_epoch, KeySet, Layout, logs, NodeHeld, NodeKeys,
        onchain_request, PlainRequest, Queue, Receipt, receipt_request, read_head_in_public, ReceiptRequest, Refunds,
        RegistryAnswer, SharedOnchain, SharedOnchainArgs, SharedOnchainRequest, SharedReceiptArgs, SharedRequest,
        Sharing, TipRound, TipState, token,
    };
    use pss_public_contract::outcome::{deliver_outcome_into, OutcomeTx};
    use pss_public_contract::hatch::{Hatch, HatchState};
    use pss_public_contract::partial_note;
    use pss_public_contract::result::ResultSignature;

    // lending_market's LendingStorage, in its order, with secret-shared
    // on-chain intake's storage after `market`
    #[storage]
    struct Storage<Context> {
        outcome_notes: Owned<PrivateSet<LendingOutcome, Context>, Context>,
        config: PublicImmutable<Config, Context>,
        configured: PublicImmutable<Configured<PACKAGES>, Context>,
        queue: Queue<Context>,
        market: CommitmentSlot<Context>,
        // secret-shared on-chain intake's storage (pss_public_contract
        // `shared_onchain`): the nodes' `enc` keys and epochs, and the hash
        // of each request's log; the machine's `shared_onchain_slot` is its
        // storage slot.
        shared_onchain: SharedOnchain<Context>,
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

    /// A request's escrow and usage deposit (`escrow`), then secret-shared
    /// on-chain intake's wrapper `append_onchain_shared` enqueued with the
    /// request id, the log's data hash and epochs and the `Refunds`: the
    /// queueing of `deposit_shared_onchain`.
    #[internal("private")]
    fn queue_onchain_shared(request: SharedOnchainRequest, draw: Draw, rho: Field) {
        let refunds = self.internal.escrow(draw, rho);
        self.enqueue_self.append_onchain_shared(request.request_id, request.data_hash, request.epochs, refunds);
    }

    /// The sender's partial note from `rho`, its use nullifier pushed, and
    /// told to the sender's PXE offchain: the non-secret-shared deposit's,
    /// which its `apply` completes in public.
    #[internal("private")]
    fn commit_plain_partial(rho: Field) -> Field {
        let sender = self.msg_sender();
        // BRICK value = partial (pss_public_contract::partial_note::commit), completed in public by
        // apply. Alternatives: none (no note). docs/design-guide/BRICKS.md#value
        let partial = partial_note::commit(self.context, sender, rho);
        partial_note::deliver_partial_note::<LendingOutcome, _>(
            self.context,
            sender,
            rho,
            partial,
            MessageDelivery::offchain(),
        );
        partial
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
    // Intake (the non-secret-shared intakes: the deposit)
    // -----------------------------------------------------------------------

    /// The non-secret-shared deposit's row (`deposit`, both non-secret-shared
    /// intakes): refused on a deployment that does not list the package.
    #[contract_library_method]
    fn plain_row(context: &mut PrivateContext) -> TipRound<&mut PrivateContext, 1, 1, Keys> {
        CallInternal { context }.configured_in_force().round(DEPOSIT_PACKAGE, market_state_keys(Storage::init(context).market))
    }

    /// On-chain intake (`intake: onchain`): queue a deposit of `amount`
    /// collateral into `position`, or, with position 0, into a new position
    /// the scheduler assigns. A deposit into an open position requires the
    /// sender's note of it (`assert_holds`); an opening is open to anyone.
    /// The request commits the sender's partial note `P =
    /// partial_commitment(msg_sender, rho)` (`partial_note::commit`, its use
    /// nullifier pushed) and tells the sender's PXE of it offchain
    /// (`partial_note::deliver_partial_note`; the client hands the send
    /// result's offchain message to `offchain_receive`), so the PXE completes
    /// the note when `apply` emits its completion log. The inputs `[position,
    /// amount, P]` go to the chain in the request log, followed by the
    /// request's `user_nonce`: `P` hides the owner behind `rho`, and no
    /// request names its requester's address.
    ///
    /// DEV DECISION: how the request's partial-note message reaches the
    /// sender's PXE, default offchain (`MessageDelivery::offchain()`): no
    /// log, nothing on chain; a client that loses the message before the
    /// completion recovers the note by rescanning the completion tag from the
    /// re-derived `rho`. Alternative: `MessageDelivery::onchain_unconstrained()`
    /// (one more private log, DA gas), for a PXE that must recover from the
    /// chain alone. Design: docs/ARCHITECTURE.md section 6, "Completion in a public function".
    ///
    /// The sender escrows `amount` of the collateral asset and pays the usage
    /// deposit from its credit (`escrow`); the refund notes are the
    /// sender's. A deposit that does not apply (`ok = 0`, public) gets its
    /// escrow's refund note completed by `apply`.
    #[external("private")]
    fn deposit(position: Field, amount: Field, rho: Field, user_nonce: Field) {
        let config = self.storage.config.read();
        let round = plain_row(self.context);
        self.storage.lending().assert_holds(self.msg_sender(), Holds::note_or_open(position, KIND_BORROWER));
        let partial = self.internal.commit_plain_partial(rho);
        // BRICK intake = onchain (pss_public_contract::onchain_request). Alternatives: receipt,
        // shared_receipt, shared_onchain (the other deposit entry points). docs/design-guide/BRICKS.md#intake
        let (request_id, plain) = onchain_request(
            self.context,
            round,
            [position, amount, partial],
            user_nonce,
            valid_plain_deposit,
        );
        let refunds = self.internal.escrow(Escrow::collateral(amount).draw(config), rho);
        self.enqueue_self.append_onchain(request_id, plain, refunds);
    }

    #[external("public")]
    #[only_self]
    fn append_onchain(
        request_id: Field,
        plain: PlainRequest<PLAIN_DEPOSIT_INPUTS>,
        refunds: Refunds,
    ) {
        assert_ready(self.context, self.storage.configured, self.storage.market);
        self.storage.hatch.queued();
        let index = self.storage.queue.append_onchain(request_id, plain);
        self.storage.refunds.at(index).write(refunds);
    }

    /// Receipt intake (`intake: receipt`): queue the same deposit, whose
    /// inputs `[position, amount, P]` the three nodes signed receipts for;
    /// only the request id and the expiry block go to the chain. The note
    /// check and the partial note as `deposit`. Refused when the inputs fail
    /// `valid_deposit`, the sender holds no note of a named position or a
    /// receipt does not verify, and in the public part when the receipt has
    /// expired, the market is not initialised or the request id was seen (a
    /// receipt is single-use). Escrows and pays as `deposit`.
    #[external("private")]
    fn deposit_with_receipts(
        position: Field,
        amount: Field,
        rho: Field,
        user_nonce: Field,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        let config = self.storage.config.read();
        let round = plain_row(self.context);
        self.storage.lending().assert_holds(self.msg_sender(), Holds::note_or_open(position, KIND_BORROWER));
        let partial = self.internal.commit_plain_partial(rho);
        // BRICK intake = receipt (pss_public_contract::receipt_request). Alternatives: onchain,
        // shared_receipt, shared_onchain (the other deposit entry points). docs/design-guide/BRICKS.md#intake
        let request_id = receipt_request(
            self.context,
            round,
            [position, amount, partial],
            user_nonce,
            expiry_block,
            receipts,
            valid_plain_deposit,
        );
        self.internal.queue_receipt(request_id, expiry_block, Escrow::collateral(amount).draw(config), rho);
    }

    // -----------------------------------------------------------------------
    // Intake (secret-shared receipt intake, `intake: shared_receipt`)
    // -----------------------------------------------------------------------
    //
    // Each request function takes the app inputs (a request on a borrower
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

    /// The body of every secret-shared request function, under either
    /// secret-shared intake (`request`: `SharedReceiptArgs` or
    /// `SharedOnchainArgs`): lending_market `LendingStorage::request` on the
    /// row of `round`, then the escrow and the request queued through the
    /// intake's public wrapper (`Queued`). A contract library method, since
    /// an internal function cannot be generic: it builds the storage and the
    /// internal calls from the request function's context, as aztec-nr's
    /// internal functions build their `self`.
    #[contract_library_method]
    fn shared_request<T, I, let N: u32, let Q: u32, let X: u32, Env>(
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
        I: SharedRequest<T, Keys>,
        T: Queued,
    {
        let row = shared_row(context, round);
        let (queued, draw, rho): (T, Draw, Field) =
            Storage::init(context).lending().request(context, row, holds, inputs, layout, request, valid, escrow);
        queued.queue(context, draw, rho);
    }

    /// How a secret-shared request is queued, one implementation per
    /// intake's public wrapper: its escrow and usage deposit (`escrow`), then
    /// `append_receipt` (`ReceiptRequest`) or `append_onchain_shared`
    /// (`SharedOnchainRequest`) enqueued with the refund notes.
    trait Queued {
        fn queue(self, context: &mut PrivateContext, draw: Draw, rho: Field);
    }

    impl Queued for ReceiptRequest {
        fn queue(self, context: &mut PrivateContext, draw: Draw, rho: Field) {
            CallInternal { context }.queue_receipt(self.request_id, self.expiry_block, draw, rho);
        }
    }

    impl Queued for SharedOnchainRequest {
        fn queue(self, context: &mut PrivateContext, draw: Draw, rho: Field) {
            CallInternal { context }.queue_onchain_shared(self, draw, rho);
        }
    }

    /// Queue a secret-shared deposit of `amount` into `position` (0 opens a
    /// new position; another requires the sender's note of it), `amount` of
    /// the collateral asset escrowed here (returned through the round's note
    /// when the deposit does not apply). The round's note is the sender's
    /// first note of a new position, or its next note of this one.
    #[external("private")]
    fn deposit_shared(
        position: Field,
        amount: Field,
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
            self.context, ROUND_DEPOSIT, Holds::note_or_open(position, KIND_BORROWER),
            with_handle(self.msg_sender(), [position, amount], handle_rho, handle_key),
            DEPOSIT_SHARED_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_deposit::<HANDLED_INPUTS>, Escrow::collateral(amount),
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
        sharing: Sharing<7>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_BORROW, Holds::note(position, KIND_BORROWER),
            with_handle(self.msg_sender(), [position, amount], handle_rho, handle_key),
            BORROW_SHARED_LAYOUT,
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
        sharing: Sharing<7>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_WITHDRAW, Holds::note(position, KIND_BORROWER),
            with_handle(self.msg_sender(), [position, amount], handle_rho, handle_key),
            WITHDRAW_SHARED_LAYOUT,
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
        sharing: Sharing<7>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_REPAY, Holds::note(position, KIND_BORROWER),
            with_handle(self.msg_sender(), [position, amount], handle_rho, handle_key),
            REPAY_SHARED_LAYOUT,
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
        sharing: Sharing<6>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_VIEW, Holds::note(position, 0),
            with_handle(self.msg_sender(), [position], handle_rho, handle_key),
            VIEW_SHARED_LAYOUT,
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
        sharing: Sharing<5>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_LIQUIDATE, Holds::anyone(),
            positions.concat([count, budget]),
            LIQUIDATE_SHARED_LAYOUT,
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
            SCAN_SHARED_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_scan, Escrow::none(),
        );
    }

    /// Queue a secret-shared supply of `amount` of the borrowed asset, a
    /// lender's, into `position` (0 opens a new lender position; another
    /// requires the sender's lender note of it), escrowed here; the round
    /// mints shares at the pool's value and returns the amount through its
    /// note when it does not apply.
    #[external("private")]
    fn supply_shared(
        position: Field,
        amount: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<5>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_SUPPLY, Holds::note_or_open(position, KIND_LENDER),
            [position, amount],
            SUPPLY_SHARED_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_deposit::<OWNER_INPUTS>, Escrow::borrowed(amount),
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
        sharing: Sharing<5>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        shared_request(
            self.context, ROUND_WITHDRAW_SUPPLY, Holds::note(position, KIND_LENDER),
            [position, shares],
            WITHDRAW_SUPPLY_SHARED_LAYOUT,
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
            QUOTE_SHARED_LAYOUT,
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
    // Intake (secret-shared on-chain intake, `intake: shared_onchain`: the deposit)
    // -----------------------------------------------------------------------

    /// Queue a secret-shared deposit with no off-chain step: the values
    /// `deposit_shared` takes, with `eph`, the ephemeral secret (fresh, used
    /// once), in place of the sharing and the receipts. The note check and
    /// the partial note as `deposit_shared`. The library reads the three
    /// nodes' keys at the anchor block, checks `valid_deposit`, computes C
    /// and the request id, emits one private log of the encoded shares
    /// (`DEPOSIT_SHARED_ONCHAIN_LAYOUT`: `position` clear; the amount, the partial
    /// note and the outcome key and tag chosen, one correction each, since
    /// the key and tag are the client's derivations) and returns the log's
    /// hash and epochs, which `append_onchain_shared` stores beside the queue
    /// entry.
    ///
    /// DEV DECISION: which rounds take secret-shared on-chain intake. Default: the
    /// deposit only, the example's case of the intake; every round keeps
    /// secret-shared receipt intake, the default. The intake is visible per request
    /// (a private log and its own public call), so a request under it shows
    /// that it is a deposit, and its `position` is clear in the log (an
    /// opening deposit's 0 included), as it is to the nodes under secret-shared
    /// receipt intake. An app that wants the round type hidden under this
    /// intake gives every round a secret-shared on-chain request function with
    /// the same public call. Recommended: keep for the example.
    #[external("private")]
    fn deposit_shared_onchain(
        position: Field,
        amount: Field,
        handle_rho: Field,
        handle_key: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        eph: Field,
    ) {
        let slot = self.storage.shared_onchain.get_storage_slot();
        shared_request(
            self.context, ROUND_DEPOSIT, Holds::note_or_open(position, KIND_BORROWER),
            with_handle(self.msg_sender(), [position, amount], handle_rho, handle_key),
            DEPOSIT_SHARED_ONCHAIN_LAYOUT,
            SharedOnchainArgs { rho, outcome_key, outcome_tag, slot, eph },
            valid_deposit::<HANDLED_INPUTS>, Escrow::collateral(amount),
        );
    }

    #[external("public")]
    #[only_self]
    fn append_onchain_shared(
        request_id: Field,
        data_hash: Field,
        epochs: [u32; 3],
        refunds: Refunds,
    ) {
        assert_ready(self.context, self.storage.configured, self.storage.market);
        self.storage.hatch.queued();
        let index = self.storage.shared_onchain.append(self.storage.queue, request_id, data_hash, epochs);
        self.storage.refunds.at(index).write(refunds);
    }

    /// pss_public_contract::shared_onchain::check_enc_rotation.
    #[external("private")]
    fn rotate_enc_key(i: u32, key: EncKey, signature: Receipt) {
        // BRICK intake = shared_onchain (pss_public_contract::check_enc_rotation): this entry point and
        // set_enc_key serve that intake only. Alternatives: onchain, receipt, shared_receipt (none
        // declares them). docs/design-guide/BRICKS.md#intake
        check_enc_rotation::<Keys>(self.context, self.storage.configured.read().config(), i, key, signature);
        self.enqueue_self.set_enc_key(i, key);
    }

    /// pss_public_contract::shared_onchain::SharedOnchain::rotate.
    #[external("public")]
    #[only_self]
    fn set_enc_key(i: u32, key: EncKey) {
        self.storage.shared_onchain.rotate(i, key);
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

    /// pss_public_contract::KeyEpochs::install, which voids every replaced
    /// node's enc key in `shared_onchain` with the install.
    #[external("public")]
    #[only_self]
    fn set_node_keys(node_keys: NodeKeys) {
        // the enc keys Keys names, which the install voids for a replaced node; NoEncKeys {} under
        // KeyEpochs<NoEncKeys>, in a contract without secret-shared on-chain intake (lending_tip_oblivious)
        Keys::install(self.context, node_keys, self.storage.shared_onchain);
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
    // The result transaction
    // -----------------------------------------------------------------------

    /// A deposit's result, whichever non-secret-shared intake queued it: the library
    /// pins the deposit vk, verifies the proof over `[namespace, vk_hash,
    /// in_slots, out_slots, price, price_epoch, clock, request_id, old_c,
    /// new_c, npk_app_hash, ok, partial_note, code, position, mask, payout,
    /// new_hashes]` (the
    /// market key for both slots; the proof outputs the request id over the
    /// private inputs, which `apply` compares with the queue's head, and the
    /// request's partial note, which `apply` completes) and checks the three
    /// result signatures (node-held: no sealed thirds); then `apply` lands
    /// it. Anyone may submit; the operator's relayer does by default.
    #[external("private")]
    fn process_result(round: OwnerResult, signatures: [ResultSignature; 3]) {
        let checked = check_round(
            plain_row(self.context),
            self.context,
            self.msg_sender(),
            round,
            NodeHeld {},
            signatures,
        );
        self.enqueue_self.apply(checked);
    }

    /// Land a checked deposit result: first the pinned reads, a static call
    /// of the oracle's `get_price_epoch()` that must accept the circuit's
    /// price and epoch (the current epoch at its price, or the one before at
    /// the previous price; "pinned epoch too old" or "pinned read changed"
    /// otherwise) and one of this contract's `clock()` that must be within
    /// CLOCK_BAND blocks of the circuit's clock ("pinned read outside its
    /// band" otherwise), then the library checks `requests[head] == request_id`
    /// and `market == old_c`, writes `new_c` when ok (a no-op when not),
    /// moves the head and writes `done[index]`; the request's partial note is
    /// then completed in public, on every round (pss_public_contract
    /// `partial_note::complete_in_public`: the completion log `[slot,
    /// fields…, request_id]` under the note's completion tag and the
    /// completed note's hash), with `owner_note_fields`: the code, the
    /// position, its kind marker and the payout, so the owner's PXE holds its
    /// position note; last, the request's refunds are settled (pss_public_contract
    /// `token::settle_applied`): the escrow's refund note completed when the
    /// deposit did not apply (`ok` is public under this intake), the usage
    /// deposit kept or its refund note completed per the Config.
    ///
    /// DEV DECISION: how the non-secret-shared deposit's outcome reaches the
    /// user, default the public completion of its partial note (no outcome
    /// stored by queue index; DECISIONS.md, "Non-secret-shared intakes: public
    /// outputs"). The note confers the position like a secret-shared round's,
    /// and the completion log is public anyway, as the result transaction's
    /// arguments are; the owner stays hidden behind `rho`. The note reports no
    /// collateral or debt, which the log would publish. Alternative: store the
    /// outputs by queue index (no note: a deposit of this intake would then
    /// confer nothing, and its owner could not act on the position under the
    /// secret-shared rounds). Design: docs/ARCHITECTURE.md section 6,
    /// "Completion in a public function".
    #[external("public")]
    #[only_self]
    fn apply(round: OwnerResult) {
        // the Config is immutable, so reading it before the call is safe
        let config: ConfigPublic = read_head_in_public(self.context, self.storage.config);
        let applied = apply_round(
            self.context,
            self.storage.queue,
            [price_read(config.oracle), clock_read(self.context.this_address())],
            market_state_keys(self.storage.market),
            round.result,
            NodeHeld {},
        );
        // the plain deposit's leaves hold no exit tag
        self.storage.hatch.landed(self.storage.queue, true, []);
        // the completion: a log and a note hash, no external call
        // BRICK value = partial (pss_public_contract::partial_note::complete_in_public), the
        // non-secret-shared deposit's note completed in public. Alternatives: none (no note). docs/design-guide/BRICKS.md#value
        partial_note::complete_in_public(
            self.context,
            self.storage.outcome_notes.get_storage_slot(),
            round.partial_note,
            owner_note_fields(applied),
            applied.request_id,
        );
        // the settlement: refund-note completions, no token call
        let refunds = self.storage.refunds.at(applied.index).read();
        let kept = token::settle_applied(
            self.context,
            self.storage.credits.get_storage_slot(),
            refunds,
            config.deposit,
            applied.request_id,
            !applied.ok,
            true,
        );
        self.storage.kept_deposits.write(self.storage.kept_deposits.read() + kept);
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

    /// pss_public_contract::shared_onchain::SharedOnchain::enc_key.
    #[external("public")]
    #[view]
    fn get_enc_key(i: u32) -> EncKey {
        self.storage.shared_onchain.enc_key(i)
    }

    /// pss_public_contract::shared_onchain::SharedOnchain::data_hash.
    #[external("public")]
    #[view]
    fn get_data_hash(request_id: Field) -> Field {
        self.storage.shared_onchain.data_hash(request_id)
    }

    /// pss_public_contract::logs::log_in_tx: an on-chain deposit's request log, or a deposit's completion log.
    #[external("utility")]
    unconstrained fn log_in_tx(tx_hash: Field, tag: Field) -> BoundedVec<Field, MAX_LOG_FIELDS> {
        logs::log_in_tx(self.address, tx_hash, tag)
    }
}
