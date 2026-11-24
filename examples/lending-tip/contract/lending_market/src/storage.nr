//! The bodies both contracts share, over the storage both declare: each
//! contract's `#[storage]` struct holds these members, in this order, before
//! and after its own (`lending_tip` adds `shared_onchain` after `market`),
//! and its `Storage::lending()` hands them here. An entry point of either
//! contract is a call of one method below, then the enqueue of its public
//! half where it has one (the enqueue names the contract's own interface,
//! so it stays in the contract).
use crate::app::{
    clock_read, Config, ConfigPublic, Credit, Draw, EXIT_TAGS, exit_amounts, init_state_keys, LendingOutcome,
    market_state_keys, Nonces, OutcomeNotes, PACKAGES, price_read, SharedApply,
};
use crate::request::{Escrow, Holds};
use aztec::context::{PrivateContext, PublicContext, UtilityContext};
use aztec::messages::delivery::MessageDelivery;
use aztec::note::{
    note_getter_options::{NoteGetterOptions, SortOrder}, note_interface::NoteProperties,
    note_viewer_options::NoteViewerOptions,
};
use aztec::protocol::address::AztecAddress;
use aztec::state_vars::{Map, Owned, PrivateSet, PublicImmutable, PublicMutable, StateVariable};
use aztec::utils::comparison::Comparator;
use pss_public_contract::{
    apply_round, assert_configured_in_public, CommitmentSlot, Configured, init, Layout, NodeHeld, outcome_request,
    Queue, read_head_in_public, Refunds, SharedRequest, SigningKeys, stale_blocks_in_public, TipRound, token,
};
use pss_public_contract::hatch::Hatch;
use pss_public_contract::partial_note;

/// The storage members both contracts declare (their `Storage`'s, but
/// `lending_tip`'s `shared_onchain`).
pub struct LendingStorage<Context> {
    /// the lending notes, by owner (whoever committed the request's partial
    /// note): every round's completed note. First in `Storage`, so its slot
    /// (1, the circuits' OUTCOME_SLOT, which `check_shared` checks is this
    /// slot) does not move when another member's size changes
    pub outcome_notes: Owned<PrivateSet<LendingOutcome, Context>, Context>,
    /// the constructor's pins
    pub config: PublicImmutable<Config, Context>,
    /// configure's: the constructor's pins with npk_app_hash, which every
    /// other function reads
    pub configured: PublicImmutable<Configured<PACKAGES>, Context>,
    pub queue: Queue<Context>,
    /// The market key. The machine key of the book ($state_keys.reads[0]
    /// and $state_keys.writes[0] in every manifest) is this slot's storage
    /// slot, the Aztec "key = storage slot" mapping that sidecar-tip's chain
    /// reader reads the commitment by; the circuits bind it into the leaf
    /// hashes, old_c and new_c (in_slots, out_slots) and the contract passes
    /// it for both, so a proof over another key does not verify. The library
    /// takes the key from the slot (`check_round` reads its storage slot).
    /// 0 while the market is uninitialised; written by `init_market` once
    /// and by every ok apply.
    pub market: CommitmentSlot<Context>,
    /// each queued request's two refund notes, by queue index
    /// (pss_public_contract `token::Refunds`), which `skip()` and `apply`
    /// complete; commitments only: no token, no amount
    pub refunds: Map<u64, PublicMutable<Refunds, Context>, Context>,
    /// the usage deposits kept (rounds that served their request) and not
    /// yet swept to the treasury, in the borrowed asset, part of the
    /// contract's public balance of it
    pub kept_deposits: PublicMutable<u128, Context>,
    /// the credits, by owner (app::Credit): each user's private balance in
    /// the market, which requests spend for their escrow and usage deposit
    /// and refunds complete into
    pub credits: Owned<PrivateSet<Credit, Context>, Context>,
    /// the escape hatch (examples/lending-tip/README.md, "The escape hatch";
    /// pss_public_contract `hatch`): the block the market started starving
    /// at (0: not starving) and whether the hatch is open, one slot
    pub hatch: Hatch<Context>,
}

impl LendingStorage<&mut PrivateContext> {
    /// Require what `holds` asks of `sender` (`request::Holds`): nothing
    /// unless `holds.required`; else a note of `holds.position` of kind
    /// `holds.kind` (`KIND_BORROWER`, `KIND_LENDER`, or 0 for either: the
    /// note's mask, a hint that saves a round the circuit refuses with code
    /// 5): one of its lending notes that names that position
    /// (`LendingOutcome::owns`: the round vouched for the position, on
    /// success or on a failure after the position's own checks), read with
    /// its inclusion check against the anchor block and not nullified
    /// (pss_public_contract `partial_note::assert_owned`). Every request
    /// function on an open position calls it before it commits the request's
    /// partial note to the sender, so a position's next note is its owner's
    /// again and the round never sees an owner. Any note of the position will
    /// do, a stale one included: the leaf is the authority, and the round's
    /// own checks (health, debt) hold at its turn.
    ///
    /// DEV DECISION: who may act on a position, default its note's owner as
    /// the sender (`owner == msg_sender`), for deposit, withdraw, borrow,
    /// repay, supply, withdraw_supply and view; an opening deposit or supply,
    /// a liquidation, a scan and a quote are open to anyone.
    /// Why: the note is the position's only authorisation and nothing in the
    /// round or the book names an owner, so invariant 0 holds with every node
    /// secret leaked. Consequences: a position cannot be delegated or
    /// transferred (every note of it authorises its holder for as long as the
    /// book lives, so an index is never reassigned); depositing to or repaying
    /// someone else's position is refused here. Alternative: an authwit from
    /// the note's owner (a delegate acts on the position), or a generation
    /// element in the leaf that a transfer bumps. Design:
    /// docs/DECISIONS.md section 10, "The request-side
    /// owner is `msg_sender`".
    pub fn assert_holds(self, sender: AztecAddress, holds: Holds) {
        if holds.required {
            assert(holds.position != 0, "position 0 names no position");
            let p = LendingOutcome::properties();
            let notes = self.outcome_notes.at(sender).get_notes(
                NoteGetterOptions::new()
                    .select(p.position, Comparator.EQ, holds.position)
                    .set_limit(1),
            );
            assert(notes.len() == 1, "the sender holds no note of this position");
            let held = notes.get(0);
            assert(held.note.owns(holds.position), "the note does not confer the position");
            assert(held.note.of_kind(holds.kind), "the position is not of this request's kind");
            // BRICK note-ownership (pss_public_contract::partial_note::assert_owned), for every request on an
            // open position. No alternative; rounds anyone may make (an opening deposit, a liquidation, a
            // scan) leave it out. docs/design-guide/BRICKS.md#other-bricks
            partial_note::assert_owned(held, sender);
        }
    }

    /// The body of every secret-shared request function (README "Requests and rounds"),
    /// under either secret-shared intake (`request`, pss_public_contract's
    /// `SharedRequest`: `SharedReceiptArgs` or `SharedOnchainArgs`): on the
    /// round of `row`, the sender's note `holds` names, then the request on
    /// `inputs` under `layout` (`outcome_request`: the static validity
    /// `valid`, the partial note committed to the sender, C and the
    /// intake's check). Returns the queued request and what its escrow and
    /// usage deposit draw with the request's `rho`, which the contract's
    /// `escrow` takes before it enqueues the intake's public wrapper.
    pub fn request<K, T, I, let N: u32, let Q: u32, let X: u32, Env>(
        self,
        context: &mut PrivateContext,
        row: TipRound<&mut PrivateContext, 1, 1, K>,
        holds: Holds,
        inputs: [Field; N],
        layout: Layout<N + 3, Q, X>,
        request: I,
        valid: fn[Env]([Field; N]) -> bool,
        escrow: Escrow,
    ) -> (T, Draw, Field)
    where
        K: SigningKeys,
        I: SharedRequest<T, K>,
    {
        let config = self.config.read();
        let sender = context.maybe_msg_sender().unwrap();
        self.assert_holds(sender, holds);
        let rho = request.rho();
        // BRICK intake = shared_receipt, shared_onchain (pss_public_contract::outcome_request), the body of
        // every *_shared request function and of deposit_shared_onchain. Alternatives: onchain, receipt
        // (lending_tip's plain deposit entry points). docs/design-guide/BRICKS.md#intake
        let queued: T = outcome_request(context, row, sender, inputs, layout, request, valid);
        (queued, escrow.draw(config), rho)
    }

    /// A request's escrow and usage deposit, from the sender's credit, in its
    /// private function after the request's static validity has passed:
    /// spend (nullify) one of the sender's credit notes that covers
    /// `draw.total()`, return the change as a new credit note, and commit the
    /// two refund notes (pss_public_contract `token::commit_refunds`): the
    /// escrow's, whose private content is the escrowed amounts, and the usage
    /// deposit's, under randomness derived from the request's `rho`. Returns
    /// the `Refunds` the public wrapper records. The effects are the same for
    /// every round type and every amount, an escrow of nothing included: one
    /// nullifier and one note for the credit, two use nullifiers and three
    /// on-chain messages (the change note's and the two refund notes'); no
    /// token call and nothing public. Refused ("no credit note of the
    /// sender's covers the request") when no single note covers it: a
    /// request draws on one note, so a user merges its notes first
    /// (`merge_credits`). It runs only in the revertible phase, as
    /// `withdraw_funds` and `exit` do: the spent credit and the refund notes
    /// must never land without the public wrapper that queues the request
    /// and records the refunds, or a wrapper that reverts (an expired
    /// receipt, an opened hatch) would take the escrow with it.
    ///
    /// DEV DECISION: how the credit notes and the refund notes' partial-note
    /// messages reach the owner's PXE, default `MessageDelivery::
    /// onchain_unconstrained()` (the user is sender and recipient, so
    /// nothing is gained by constraining it). Why: a refund note's amount is
    /// private content no client can recompute, so a client that lost its
    /// state must find it on chain: under this default the request
    /// transaction holds both refund notes' messages and the change note's,
    /// and a PXE restored from the account's keys alone finds them and
    /// stores each refund note when `skip()` or `apply` completes it (the
    /// refund recovery route; examples/lending-tip/README.md, "Tokens",
    /// "Refunds by public functions"). Consequences: three private logs in
    /// every request transaction (DA gas), the same for every round type.
    /// Alternative: offchain delivery (no logs; the client hands the messages
    /// to `offchain_receive` and must keep each refund's amount itself, or lose
    /// the refund with its state).
    pub fn escrow(self, context: &mut PrivateContext, sender: AztecAddress, draw: Draw, rho: Field) -> Refunds {
        assert(context.in_revertible_phase(), "a request runs only in the revertible phase");
        let (collateral, borrowed) = draw.total();
        let p = Credit::properties();
        let spent = self.credits.at(sender).pop_notes(
            NoteGetterOptions::new()
                .select(p.collateral, Comparator.GTE, collateral)
                .select(p.borrowed, Comparator.GTE, borrowed)
                .set_limit(1),
        );
        assert(spent.len() == 1, "no credit note of the sender's covers the request");
        let credit = spent.get(0);
        self.credits.at(sender).insert(Credit::of(credit.collateral - collateral, credit.borrowed - borrowed)).deliver(
            MessageDelivery::onchain_unconstrained(),
        );
        // BRICK token-escrow (pss_public_contract::token::commit_refunds), with take in fund, prepare_note
        // and pay in withdraw_funds, refund_skipped in skip and settle_applied in apply. No alternative;
        // an app that moves no token leaves it out (examples/amm-tip). docs/design-guide/BRICKS.md#other-bricks
        token::commit_refunds::<Credit, _, 2>(
            context,
            sender,
            rho,
            Credit::content(draw.collateral, draw.borrowed),
            Credit::content(0, draw.deposit),
            MessageDelivery::onchain_unconstrained(),
        )
    }

    /// Fund `sender`'s private balance in the market: move `collateral` of
    /// the collateral asset and `borrowed` of the borrowed asset from its
    /// private balances into the market's public ones (pss_public_contract
    /// `token::take`, under the authwit nonces `nonces`; an amount of 0
    /// moves nothing) and credit it a note for both (`Credit`, delivered on
    /// chain). A transaction of its own: its amounts are public, as the
    /// token transfers are, and nothing links them to the requests the
    /// credit later pays for. Refused when both amounts are 0, and in its
    /// public half (`assert_initialised`) before the init round has landed:
    /// the init checks the seeded liquidity against the public balance, which
    /// must then hold nothing owed to a user.
    pub fn fund(
        self,
        context: &mut PrivateContext,
        sender: AztecAddress,
        collateral: u128,
        borrowed: u128,
        nonces: Nonces,
    ) {
        assert((collateral != 0) | (borrowed != 0), "nothing to fund");
        let config = self.config.read();
        token::take(context, config.collateral, sender, collateral, nonces.collateral);
        token::take(context, config.borrowed, sender, borrowed, nonces.borrowed);
        self.credits.at(sender).insert(Credit::of(collateral, borrowed)).deliver(
            MessageDelivery::onchain_unconstrained(),
        );
    }

    /// Merge up to four of `sender`'s credit notes into one (their
    /// nullifiers and one note: no amount public), so a request can draw on
    /// the sum. Refused when the sender holds fewer than two.
    pub fn merge_credits(self, sender: AztecAddress) {
        let notes = self.credits.at(sender).pop_notes(NoteGetterOptions::new().set_limit(4));
        assert(notes.len() > 1, "fewer than two credit notes to merge");
        let mut collateral = 0;
        let mut borrowed = 0;
        for i in 0..4 {
            if i < notes.len() {
                let note = notes.get(i);
                collateral += note.collateral;
                borrowed += note.borrowed;
            }
        }
        self.credits.at(sender).insert(Credit::of(collateral, borrowed)).deliver(
            MessageDelivery::onchain_unconstrained(),
        );
    }

    /// Withdraw `collateral` of the collateral asset and `borrowed` of the
    /// borrowed asset from `sender`'s credit as tokens: spend one of its
    /// credit notes that covers both, return the change as a new one, and
    /// prepare a token partial note of the sender's for each nonzero amount
    /// (pss_public_contract `token::prepare_note`), returned for the public
    /// half (`pay_withdrawal`) to complete from the market's public
    /// balances. The amounts are public, as the payment from a public balance
    /// is; the owner is hidden and nothing links the withdrawal to a request
    /// or a redeem but its timing. Refused when both amounts are 0 or no
    /// single credit note covers them.
    ///
    /// It runs only in the revertible phase: its public half is the only
    /// guard of the payable balance, so the new credit note must not land
    /// without it (the library asserts the same of a private outcome).
    pub fn withdraw_funds(
        self,
        context: &mut PrivateContext,
        sender: AztecAddress,
        collateral: u128,
        borrowed: u128,
    ) -> (Field, Field) {
        assert(context.in_revertible_phase(), "a withdrawal runs only in the revertible phase");
        assert((collateral != 0) | (borrowed != 0), "nothing to withdraw");
        let config = self.config.read();
        let p = Credit::properties();
        let spent = self.credits.at(sender).pop_notes(
            NoteGetterOptions::new()
                .select(p.collateral, Comparator.GTE, collateral)
                .select(p.borrowed, Comparator.GTE, borrowed)
                .set_limit(1),
        );
        assert(spent.len() == 1, "no credit note of the sender's covers the withdrawal");
        let credit = spent.get(0);
        self.credits.at(sender).insert(Credit::of(credit.collateral - collateral, credit.borrowed - borrowed)).deliver(
            MessageDelivery::onchain_unconstrained(),
        );
        let mut collateral_note = 0;
        if collateral != 0 {
            collateral_note = token::prepare_note(context, config.collateral, sender);
        }
        let mut borrowed_note = 0;
        if borrowed != 0 {
            borrowed_note = token::prepare_note(context, config.borrowed, sender);
        }
        (collateral_note, borrowed_note)
    }

    /// Redeem `owner`'s note of request `request_id` in its own transaction:
    /// read the note from the owner's notes (its inclusion checked), push its
    /// redeem nullifier (pss_public_contract `partial_note::redeem`: the
    /// canonical nullifier's preimage under its own separator, so the note
    /// stays readable and keeps conferring its position, and a second redeem
    /// of it is refused), and credit its settlement
    /// (`LendingOutcome::settlement`: the payout's amount in the asset its
    /// bit names, and a liquidation's seize in the collateral asset) to the
    /// owner as a credit note (`Credit`), which the next request spends or
    /// `withdraw_funds` turns into tokens. Refused when the caller holds no
    /// note of that request or the note pays nothing. Only the note's owner
    /// can redeem it. A caller holds two notes of one request after
    /// liquidating its own position: the liquidation's (position 0), which
    /// pays, and the notice of its position, which pays nothing; the read
    /// sorts by position, so the redeem takes the liquidation's whatever
    /// order the PXE keeps them in. The transaction shows a nullifier, a note
    /// hash and an on-chain message: no amount, no public call, no owner.
    pub fn redeem(self, context: &mut PrivateContext, owner: AztecAddress, request_id: Field) {
        let p = LendingOutcome::properties();
        let notes = self.outcome_notes.at(owner).get_notes(
            NoteGetterOptions::new()
                .select(p.request_id, Comparator.EQ, request_id)
                .sort(p.position, SortOrder.ASC)
                .set_limit(1),
        );
        assert(notes.len() == 1, "no note of this request to redeem");
        let held = notes.get(0);
        let (collateral, borrowed) = held.note.settlement();
        assert((collateral != 0) | (borrowed != 0), "the note has nothing to redeem");
        partial_note::redeem(context, held, owner);
        self.credits.at(owner).insert(Credit::of(collateral, borrowed)).deliver(
            MessageDelivery::onchain_unconstrained(),
        );
    }

    /// Exit a frozen market on `owner`'s newest note of `position`, the note
    /// of request `request_id`, with no node, no signature and no public
    /// call: read the note (its inclusion checked) and push its exit tag
    /// (pss_public_contract `Hatch::exit`: the note is the sender's and names
    /// the position, and the hatch was open at the transaction's anchor
    /// block). The tag is the one the note's round stored in the position's
    /// leaf, and every later write of the leaf spent it, so the exit
    /// succeeds once and only on the position's newest note: an older note,
    /// a note a liquidation replaced (whose notice is the newest note) and a
    /// second exit push a nullifier that exists, and are refused. The
    /// request id picks the note: a self-liquidator holds two notes of one
    /// request, the liquidation's (position 0) and the notice.
    ///
    /// What the note is owed is settled in the owner's credit, privately,
    /// as `redeem` settles a round (`exit_amounts`): a borrower note repays
    /// its debt `y` from one of the owner's credit notes covering it and is
    /// credited its collateral `x` (one change note for both); a lender note
    /// is credited its shares' value `y`. `withdraw_funds` turns the credit
    /// into tokens. No interest since the note's round is charged or paid:
    /// the frozen header's borrow index is the nodes', so the hatch's
    /// liveness cost is the market's rate over each party's last interval.
    /// The transaction shows one nullifier of the tag's, a credit's
    /// nullifier when the note repays a debt, a note hash and an on-chain
    /// message: no position, no amount and no public call, so nobody tells
    /// which position left.
    pub fn exit(self, owner: AztecAddress, position: Field, request_id: Field) {
        let p = LendingOutcome::properties();
        let notes = self.outcome_notes.at(owner).get_notes(
            NoteGetterOptions::new()
                .select(p.position, Comparator.EQ, position)
                .select(p.request_id, Comparator.EQ, request_id)
                .set_limit(1),
        );
        assert(notes.len() == 1, "the sender holds no note of this position and request");
        let held = notes.get(0);
        let (collateral, borrowed, repay) = exit_amounts(held.note);
        assert((collateral != 0) | (borrowed != 0), "the note has nothing to exit");
        // BRICK escape-hatch (pss_public_contract::hatch::Hatch::exit): the note's exit tag, pushed
        // once, with Hatch::landed in every apply. No alternative; an app without per-owner entries
        // exits by a rule of its own. docs/design-guide/BRICKS.md#other-bricks
        self.hatch.exit(held, owner);
        let mut credit = Credit::of(collateral, borrowed);
        if repay != 0 {
            let spent = self.credits.at(owner).pop_notes(
                NoteGetterOptions::new().select(Credit::properties().borrowed, Comparator.GTE, repay).set_limit(1),
            );
            assert(spent.len() == 1, "no credit note of the sender's covers the note's debt");
            let c = spent.get(0);
            credit = Credit::of(c.collateral + collateral, c.borrowed - repay + borrowed);
        }
        self.credits.at(owner).insert(credit).deliver(MessageDelivery::onchain_unconstrained());
    }
}

impl LendingStorage<PublicContext> {
    /// The public half of `init_market`: require the contract's public
    /// balance of the borrowed asset to hold the Config's seeded liquidity
    /// ("the seeded liquidity is not in the public balance"; `fund` refuses
    /// before the init, so nothing in that balance is owed to a user yet),
    /// write the first commitment while the slot is empty ("already
    /// initialised" otherwise). Touches no queue storage and not the hatch:
    /// its clock cannot start before the init (every request wrapper and
    /// `poke()` require an initialised market), so the hatch cannot be open
    /// when the init lands.
    pub fn apply_init(self, context: PublicContext, request_id: Field, new_c: Field) {
        let config: ConfigPublic = read_head_in_public(context, self.config);
        assert(
            config.init_liquidity as u128 <= token::public_balance(context, config.borrowed),
            "the seeded liquidity is not in the public balance",
        );
        init::apply_init(context, init_state_keys(self.market), request_id, [new_c], NodeHeld {});
    }

    /// The public half of `withdraw_funds`: pay `collateral` of the
    /// collateral asset into `collateral_note` and `borrowed` of the
    /// borrowed asset into `borrowed_note`, from the contract's public
    /// balances (nothing for a zero amount). A payment of credit never draws
    /// on the kept usage deposits not yet swept (the treasury's): the
    /// borrowed asset's payable balance is its public balance less them.
    /// The rest of each balance backs the market's book and every credit
    /// and refund note together, whose amounts are private, so no public
    /// total separates them (examples/lending-tip/README.md, "Tokens").
    pub fn pay_withdrawal(
        self,
        context: PublicContext,
        collateral: u128,
        collateral_note: Field,
        borrowed: u128,
        borrowed_note: Field,
    ) {
        let config: ConfigPublic = read_head_in_public(context, self.config);
        let kept = self.kept_deposits.read();
        assert(
            (borrowed == 0) | (borrowed + kept <= token::public_balance(context, config.borrowed)),
            "the payout exceeds the payable balance",
        );
        token::pay(context, config.collateral, collateral, collateral_note);
        token::pay(context, config.borrowed, borrowed, borrowed_note);
    }

    /// The public request wrapper of the receipt route, the receipt intake
    /// deposit's and every secret-shared round's: queue the request id until
    /// `expiry_block` and record its two refund notes beside it. The same
    /// call, with one argument shape and the same writes, for every
    /// secret-shared round type: the request id, the expiry and two
    /// commitments that hide their owner, class and amounts.
    pub fn append_receipt(self, request_id: Field, expiry_block: u32, refunds: Refunds) {
        let index = self.queue.append_receipt(self.configured, self.market, request_id, expiry_block);
        self.hatch.queued();
        self.refunds.at(index).write(refunds);
    }

    /// Land a checked shared result: the pinned price and clock reads first
    /// (a static call of the oracle's `get_price_epoch()` that must accept
    /// the circuit's price and epoch, and one of the contract's `clock()`
    /// within CLOCK_BAND blocks of the circuit's clock), then the head and
    /// slot checks, the new commitment written whatever the outcome (there is
    /// no public `ok`: every round re-blinds the book), the head moved and
    /// `done[index]` applied; then the hatch's landing (pss_public_contract
    /// `Hatch::landed`: refused once the hatch is open, the round's exit tags
    /// emitted as nullifiers, so a tag is spent exactly when its leaf is
    /// replaced, and the clock stopped when the round served its request);
    /// then the usage deposit kept or refunded per the Config. The escrow is
    /// settled by the round's note, which `redeem` credits, except when the
    /// request's shares did not open C (`opened` 0, the proof's
    /// inputs-opened bit): that round's note cannot carry the user's refund
    /// (its owner is not the one the user committed), so the escrow's refund
    /// note is completed here, for the amount its commitment binds and with
    /// nothing public but the request id, and so is the deposit's, since
    /// the round served nobody: a request the nodes make fail on C costs
    /// its user nothing (examples/lending-tip/README.md, "Tokens", "The
    /// inputs-opened bit"). The one apply of every secret-shared round type,
    /// with the same arguments and, but for those refunds, the same effects.
    pub fn apply_shared(self, context: PublicContext, apply: SharedApply, opened: Field, tags: [Field; EXIT_TAGS]) {
        let config: ConfigPublic = read_head_in_public(context, self.config);
        let index = apply_round(
            context,
            self.queue,
            [price_read(config.oracle), clock_read(context.this_address())],
            market_state_keys(self.market),
            apply,
            NodeHeld {},
        )
            .index;
        // BRICK escape-hatch (pss_public_contract::hatch::Hatch::landed), with queued in every request
        // wrapper and poke, open in open_hatch and exit. No alternative; an app without per-owner
        // entries keeps the clock and the opening alone. docs/design-guide/BRICKS.md#other-bricks
        // a round whose shares did not open C served nobody and leaves the starving clock running
        self.hatch.landed(self.queue, opened != 0, tags);
        let refunds = self.refunds.at(index).read();
        let kept = token::settle_applied(
            context,
            self.credits.get_storage_slot(),
            refunds,
            config.deposit,
            apply.request_id,
            opened == 0,
            opened != 0,
        );
        self.kept_deposits.write(self.kept_deposits.read() + kept);
    }

    /// Open the escape hatch, once and for good: anyone may call it when the
    /// market is provably frozen, that is when it has starved for T_LIVE
    /// blocks (pss_public_contract `Hatch::open`: demand, a queued request or
    /// a `poke()`, and no landed round that served its request since). Only
    /// the nodes stop the clock, by landing a round; `skip()` never touches
    /// it, so a frozen network's skipped heads never read as liveness, and
    /// nobody but the nodes can hold the hatch shut. Once open, every request
    /// wrapper and every apply refuses, `skip()` keeps refunding what is
    /// queued, `redeem` keeps paying, and each owner may `exit`; a market
    /// that comes back is a new deployment.
    pub fn open_hatch(self, context: PublicContext) {
        let config: ConfigPublic = read_head_in_public(context, self.config);
        self.hatch.open(config.t_live);
    }

    /// Start the starving clock on a market whose clock is not running
    /// (`Hatch::queued`; a no-op while it runs), an empty queue included:
    /// anyone may, once the market is initialised. Then unless a round lands
    /// within T_LIVE blocks, anyone may `open_hatch()`. How a market whose
    /// nodes stopped signing receipts (so no request can be queued) still
    /// opens; on a live market, any landed round stops the clock (a keeper's
    /// scan is enough).
    pub fn poke(self) {
        pss_public_contract::assert_initialised(self.market);
        self.hatch.queued();
    }

    /// Drop the head once it has sat `stale_blocks` blocks (the configured
    /// pins'); anyone may call it, once the contract is configured. The
    /// skipped request gets back what it put in, its escrow and its usage
    /// deposit, by the completion of its two refund notes (pss_public_contract
    /// `token::refund_skipped`): a public completion with the request id as
    /// its only public field and no token call, never a round, so no refund
    /// waits on the nodes and none can fail for want of balance.
    pub fn skip(self, context: PublicContext) {
        let stale_blocks = stale_blocks_in_public(context, self.configured);
        let index = self.queue.skip(stale_blocks);
        let refunds = self.refunds.at(index).read();
        let request_id = self.queue.request_at(index);
        token::refund_skipped(context, self.credits.get_storage_slot(), refunds, request_id);
    }

    /// Pay the kept usage deposits to the Config's treasury (its public
    /// balance of the borrowed asset) and reset their count. Anyone may call
    /// it; it pays only the treasury pin, and only the kept count: each kept
    /// deposit was drawn from a credit and never refunded, so the count is
    /// exactly the public balance the treasury owns, and no credit, refund
    /// or position is paid from it.
    pub fn sweep_deposits(self, context: PublicContext) {
        assert_configured_in_public(context, self.configured);
        let config: ConfigPublic = read_head_in_public(context, self.config);
        let kept = self.kept_deposits.read();
        assert(
            kept <= token::public_balance(context, config.borrowed),
            "the kept deposits are not in the public balance",
        );
        self.kept_deposits.write(0);
        token::pay_public(context, config.borrowed, config.treasury, kept);
    }
}

impl LendingStorage<UtilityContext> {
    /// The lending notes `owner`'s PXE holds: their count and the first.
    pub unconstrained fn outcome_notes(self, owner: AztecAddress) -> OutcomeNotes {
        let notes = self.outcome_notes.at(owner).view_notes(NoteViewerOptions::new());
        let first = if notes.len() == 0 { LendingOutcome::none() } else { notes.get(0) };
        OutcomeNotes { count: notes.len(), first }
    }

    /// The sum of `owner`'s credit notes in its PXE (at most a page of ten)
    /// in the asset `asset` names (0 the borrowed asset, 1 the collateral
    /// asset: a payout's asset bit), the client's read of its private
    /// balance in the market.
    pub unconstrained fn credit_balance(self, owner: AztecAddress, asset: Field) -> u128 {
        let notes = self.credits.at(owner).view_notes(NoteViewerOptions::new());
        let mut total = 0;
        for i in 0..notes.len() {
            let note = notes.get(i);
            total += if asset == 0 { note.borrowed } else { note.collateral };
        }
        total
    }
}
