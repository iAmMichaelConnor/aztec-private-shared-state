//! Tokens and escrow at the tip (docs/ARCHITECTURE.md section 6, "Tokens and
//! escrow" and "The refund rule"): how value
//! enters the app contract, how a queued request escrows it with nothing on
//! chain naming the requester, its class or its amount, and how it comes
//! back out.
//!
//! Custody is public: the app contract holds every token it takes in its own
//! public balance of that token, so no key but the contract's code moves
//! them (private custody would need a note key some operator holds, which
//! concentrates the funds behind that key). The user's claim on that balance
//! is private: a note of the app's own type (e.g. lending's `Credit`), which the
//! app creates, splits and nullifies in the user's private functions. Three
//! token steps, each one call into the token, and the escrow between them in
//! the app's notes alone:
//!
//! - In (`take`): the user's private function moves `amount` from the user's
//!   private balance to the app's public balance (the token's
//!   `transfer_to_public`), under the user's authwit for that exact call:
//!   the token sees the app contract as its caller, and the public effect is
//!   the token's `_increase_public_balance(app, amount)`. The amount and the
//!   token are public; the user is not. The app credits the user a note for
//!   it in the same transaction (e.g. lending's `fund`), unlinked to any request.
//! - Escrow, at request time: the request's private function spends the
//!   user's credit note for the escrow and the usage deposit and returns the
//!   change as a new one (nullifiers and a note: private effects only), and
//!   commits the two refund notes (`commit_refunds`, below); no token call,
//!   so no request shows a token, an amount or a class.
//! - A note to pay into (`prepare_note`): a token partial note of the
//!   user's (the token's `prepare_private_balance_increase(owner)`), the app
//!   its designated completer. The token draws the note's randomness and
//!   tells the owner's PXE of it by an on-chain message. Its commitment is
//!   public and hides the owner.
//! - Out, in a public function (`pay`): the token's
//!   `finalize_transfer_to_private(amount, note)` from the app's public
//!   balance completes the note; the amount is public, the owner hidden. A
//!   zero amount pays nothing (the token cannot complete a note with 0).
//!   An app pays out this way when a user withdraws credit (e.g. lending's
//!   `withdraw_funds`), and pays a pinned public recipient with `pay_public`
//!   (e.g. lending's treasury).
//!
//! Refunds. A request records its two refund notes beside its queue entry
//! (`Refunds`): partial notes of the app's own note type, committed by the
//! request with the amount as private content (`partial_note::
//! partial_commitment_with`), the escrow's and the usage deposit's. The
//! refund rule: a refund is completed by a public function, never by a
//! round, a node signature or any off-chain step. A compromised network
//! cannot take the refund (invariant 0). With the stale period enabled and
//! an app skip wrapper that calls `refund_skipped`, a dead or compromised
//! network cannot freeze either refund. `refund_skipped` completes both
//! notes. `settle_applied` (in the app's `apply`) completes the deposit's
//! unless the app keeps it, per the
//! `UsageDeposit`'s choice (never for a round whose inputs did not open
//! C, which served nobody), and the escrow's only where the round consumed
//! nothing (a public `ok = false`, or the inputs-opened bit 0); a round
//! with private outcomes settles the escrow inside its completed note (the
//! app's own payout, docs/ARCHITECTURE.md section 6, "The refund rule"). A
//! completion publishes the request id and nothing else: no token, no
//! amount. Completing a refund moves no
//! token (the value stays in the app's public balance, now owed to the
//! refund note's owner as credit), so no payment out can make a refund
//! fail.
//!
//! Calls. A token call is an external call, so a public function that pays
//! makes it after its storage reads. The token is pinned at deployment and
//! its finalize makes no call back into the app (the reference token's does
//! not), so no interleaving with the queue is possible; an app that pins a
//! token that calls back must re-check `apply`'s ordering rule
//! (`crate::result`).
//!
//! The selectors are the reference token's (aztec-nr v6.0.0
//! `token_contract`, vendored in examples/token): `transfer_to_public(from,
//! to, amount, authwit_nonce)`, `prepare_private_balance_increase(to)`,
//! `finalize_transfer_to_private(amount, partial_note)`. A token with other
//! names for these steps (the aztec-standards token) is one more
//! implementation of `take`, `prepare_note` and `pay`.
use crate::partial_note;
use aztec::context::{PrivateContext, PublicContext};
use aztec::context::gas::GasOpts;
use aztec::messages::delivery::MessageDeliveryBuilder;
use aztec::note::note_interface::NoteType;
use aztec::protocol::abis::function_selector::FunctionSelector;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash_with_separator;
use aztec::protocol::traits::{Deserialize, Packable, Serialize, ToField};

/// The reference token's `transfer_to_public(from, to, amount,
/// authwit_nonce)`: private, `from`'s private balance to `to`'s public one.
pub global TRANSFER_TO_PUBLIC: FunctionSelector =
    comptime { FunctionSelector::from_signature("transfer_to_public((Field),(Field),u128,Field)") };

/// The reference token's `prepare_private_balance_increase(to)`: private,
/// returns the partial note `{ commitment }` whose completer is the caller.
pub global PREPARE_PRIVATE_BALANCE_INCREASE: FunctionSelector =
    comptime { FunctionSelector::from_signature("prepare_private_balance_increase((Field))") };

/// The reference token's `finalize_transfer_to_private(amount,
/// partial_note)`: public, from the caller's public balance into the note.
pub global FINALIZE_TRANSFER_TO_PRIVATE: FunctionSelector =
    comptime { FunctionSelector::from_signature("finalize_transfer_to_private(u128,(Field))") };

/// The reference token's `transfer_in_public(from, to, amount,
/// authwit_nonce)`: public, `from`'s public balance to `to`'s; no authwit
/// when `from` is the caller (nonce 0).
pub global TRANSFER_IN_PUBLIC: FunctionSelector =
    comptime { FunctionSelector::from_signature("transfer_in_public((Field),(Field),u128,Field)") };

/// The reference token's `balance_of_public(owner)`: a public view.
pub global BALANCE_OF_PUBLIC: FunctionSelector =
    comptime { FunctionSelector::from_signature("balance_of_public((Field))") };

/// The usage deposit (docs/DECISIONS.md section 12): the queue's anti-spam.
/// In an app that takes a usage deposit, each request pays `amount` of
/// `token` in its private function before it enqueues (for example from the
/// sender's credit note, beside any escrow). The deposit is pinned in the
/// app's Config and equal on every request. With the stale period enabled,
/// the skip wrapper returns it by calling `refund_skipped`.
///
/// DEV DECISION: whether a round that runs keeps the deposit (`kept`),
/// default false: the deposit is refunded by `apply` too, so a request costs
/// the user only the time its deposit is locked, and spam costs the
/// spammer that lock-up and its transaction fees. `kept = true` makes the
/// deposit the protocol's revenue on every round that serves its request
/// (a request then costs `amount`; the deposits accumulate in the app's
/// public balance for the app to count and use). `refund_skipped` returns
/// the deposit regardless of `kept`. `settle_applied` also returns it when
/// the round's shares did not open `C` (`served = false`). Keeping it on skip,
/// or on a round that served nobody (a stake
/// that a network which never serves the request takes), is forbidden in
/// every app: a liveness failure must not reach funds (invariant 0).
/// An `amount` of 0 charges nothing (its refund note completes with
/// nothing). Design guide: "anti-spam".
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct UsageDeposit {
    /// the token the deposit is paid in
    pub token: AztecAddress,
    /// what every request pays, in the token's units
    pub amount: u128,
    /// whether `apply` keeps the deposit (false: refunds it)
    pub kept: bool,
}

impl UsageDeposit {
    /// No deposit: requests are free beyond their fees.
    pub fn none() -> Self {
        UsageDeposit { token: AztecAddress::zero(), amount: 0, kept: false }
    }
}

/// ASCII "pss.refund_escrow" read big-endian: the separator of an escrow
/// refund note's randomness (`refund_randomness`).
pub global PSS_REFUND_ESCROW: Field = 0x7073732e726566756e645f657363726f77;

/// ASCII "pss.refund_deposit" read big-endian: the separator of a usage
/// deposit refund note's randomness (`refund_randomness`).
pub global PSS_REFUND_DEPOSIT: Field = 0x7073732e726566756e645f6465706f736974;

/// A request's two refund notes, recorded by its public wrapper beside its
/// queue entry (the app keeps it by queue index): the commitments of the
/// partial notes that return its escrow (`escrow`) and its usage deposit
/// (`deposit`), each of the app's own note type with its amounts as private
/// content (`partial_note::partial_commitment_with`). Every request records
/// both, an escrow of nothing included, so the record, the wrapper's
/// arguments and every completion have one shape for every round type; the
/// commitments hide the owner, the class and the amounts.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct Refunds {
    pub escrow: Field,
    pub deposit: Field,
}

impl Refunds {
    /// No refund notes (an index never queued reads as this).
    pub fn none() -> Self {
        Refunds { escrow: 0, deposit: 0 }
    }
}

/// The randomness of a request's two refund notes, from the request's own
/// `rho` (the randomness of its outcome's partial note, which the client
/// derives per request): `(poseidon2_hash_with_separator([rho],
/// PSS_REFUND_ESCROW), poseidon2_hash_with_separator([rho],
/// PSS_REFUND_DEPOSIT))`. Derived in the request function, so the client
/// supplies one randomness per request and re-derives all three from its
/// request counter (pss-client `refundRandomness`); each is used once,
/// since `rho` is.
pub fn refund_randomness(rho: Field) -> (Field, Field) {
    (
        poseidon2_hash_with_separator([rho], PSS_REFUND_ESCROW),
        poseidon2_hash_with_separator([rho], PSS_REFUND_DEPOSIT),
    )
}

/// Commit a request's two refund notes, owned by `owner`, in its private
/// function: the escrow's with the private content `escrow` and the usage
/// deposit's with `deposit` (the app note type `Note`'s first packed fields,
/// its amounts), under `refund_randomness(rho)`, each with its use
/// nullifier (`partial_note::commit_with`); and tell the owner's PXE of
/// both, content included, under `delivery` (`partial_note::
/// deliver_partial_note_with`). Returns the `Refunds` for the public
/// wrapper. The same effects whatever the amounts: two nullifiers and two
/// messages.
///
/// The recovery route: the content (the amounts) is in no commitment a
/// client can recompute without it, so a client that lost its state must
/// find it again. Under `MessageDelivery::onchain_unconstrained()` (the
/// app's choice, a DEV DECISION in each app) the request transaction carries
/// both messages, so the owner's PXE, restored from its keys alone, finds
/// each pending refund note on chain and stores the note when its
/// completion log appears; the client needs nothing but its keys.
pub fn commit_refunds<Note, D, let M: u32>(
    context: &mut PrivateContext,
    owner: AztecAddress,
    rho: Field,
    escrow: [Field; M],
    deposit: [Field; M],
    delivery: D,
) -> Refunds
where
    Note: NoteType,
    D: MessageDeliveryBuilder,
{
    let (rho_escrow, rho_deposit) = refund_randomness(rho);
    let escrow_note = partial_note::commit_with(context, owner, rho_escrow, escrow);
    let deposit_note = partial_note::commit_with(context, owner, rho_deposit, deposit);
    partial_note::deliver_partial_note_with::<Note, D, M>(context, owner, rho_escrow, escrow_note, escrow, delivery);
    partial_note::deliver_partial_note_with::<Note, D, M>(context, owner, rho_deposit, deposit_note, deposit, delivery);
    Refunds { escrow: escrow_note, deposit: deposit_note }
}

/// Move `amount` of `token` from `from`'s private balance to this contract's
/// public balance (the token's `transfer_to_public`), in the user's private
/// function (e.g. lending's `fund`). `from`'s authwit for this call (caller this contract,
/// `authwit_nonce` single-use) must be in the transaction, or the token
/// reverts; so must the balance. A zero amount moves nothing and calls
/// nothing.
pub fn take(
    context: &mut PrivateContext,
    token: AztecAddress,
    from: AztecAddress,
    amount: u128,
    authwit_nonce: Field,
) {
    if amount != 0 {
        let to = context.this_address();
        let _: () = context
            .call_private_function(
                token,
                TRANSFER_TO_PUBLIC,
                [from.to_field(), to.to_field(), amount as Field, authwit_nonce],
            )
            .get_preimage();
    }
}

/// A token partial note of `owner`'s that this contract completes later
/// (`pay`; e.g. lending's `withdraw_funds`): the token's
/// `prepare_private_balance_increase(owner)`, called
/// from this contract, so this contract is its completer. Returns the
/// note's commitment (public; it hides `owner`). The token draws its
/// randomness and delivers its partial-note message to `owner` on chain.
pub fn prepare_note(context: &mut PrivateContext, token: AztecAddress, owner: AztecAddress) -> Field {
    let note: [Field; 1] = context
        .call_private_function(token, PREPARE_PRIVATE_BALANCE_INCREASE, [owner.to_field()])
        .get_preimage();
    note[0]
}

/// Pay `amount` of `token` from this contract's public balance into the
/// token partial note `note` (the token's `finalize_transfer_to_private`),
/// in a public function. Nothing when `amount` or `note` is 0. Reverts when
/// the balance is short, or when `note` was not prepared with this contract
/// as its completer.
pub fn pay(context: PublicContext, token: AztecAddress, amount: u128, note: Field) {
    if (amount != 0) & (note != 0) {
        // Safety: a public call; the token reverts the transaction when it
        // cannot pay, and `finalize_transfer_to_private` returns nothing
        unsafe { call_finalize(context, token, amount, note) };
    }
}

/// Pay `amount` of `token` from this contract's public balance to `to`'s
/// public balance (the token's `transfer_in_public` with this contract as
/// `from`), in a public function: an app's payment to a pinned public
/// recipient (e.g. lending's sweep of its kept usage deposits to its
/// treasury).
/// Nothing when `amount` is 0. Reverts when the balance is short.
pub fn pay_public(context: PublicContext, token: AztecAddress, to: AztecAddress, amount: u128) {
    if amount != 0 {
        // Safety: a public call; the token reverts the transaction when it
        // cannot pay, and `transfer_in_public` returns nothing
        unsafe { call_transfer_in_public(context, token, to, amount) };
    }
}

/// This contract's public balance of `token` (the token's
/// `balance_of_public`, a static call), in a public function: what an app's
/// guard on its payable balance reads (e.g. lending's `balance - kept`).
pub fn public_balance(context: PublicContext, token: AztecAddress) -> u128 {
    // Safety: a public function is bytecode the AVM proves, and the field is
    // the return data the AVM's static call produced
    unsafe { static_balance_of(context, token, context.this_address()) }
}

unconstrained fn call_transfer_in_public(context: PublicContext, token: AztecAddress, to: AztecAddress, amount: u128) {
    let from = context.this_address();
    let _ = context.call_public_function(
        token,
        TRANSFER_IN_PUBLIC,
        [from.to_field(), to.to_field(), amount as Field, 0],
        GasOpts::default(),
    );
}

unconstrained fn static_balance_of(context: PublicContext, token: AztecAddress, owner: AztecAddress) -> u128 {
    let returned = context.static_call_public_function(token, BALANCE_OF_PUBLIC, [owner.to_field()], GasOpts::default());
    returned[0] as u128
}

/// The token's `finalize_transfer_to_private(amount, note)`, a public call
/// under the caller's gas.
unconstrained fn call_finalize(context: PublicContext, token: AztecAddress, amount: u128, note: Field) {
    let _ = context.call_public_function(
        token,
        FINALIZE_TRANSFER_TO_PRIVATE,
        [amount as Field, note],
        GasOpts::default(),
    );
}

/// The refunds of a skipped request, in the app's `skip()` after the queue
/// dropped its head: both refund notes completed in public at the app note
/// type's `storage_slot` with no public field but `request_id`
/// (`partial_note::complete_in_public`), the escrow in full and the usage
/// deposit, whatever the deposit's `kept`: a request no round served always
/// gets back what it put in. Moves no token and makes no external call.
pub fn refund_skipped(context: PublicContext, storage_slot: Field, refunds: Refunds, request_id: Field) {
    partial_note::complete_in_public(context, storage_slot, refunds.escrow, [], request_id);
    partial_note::complete_in_public(context, storage_slot, refunds.deposit, [], request_id);
}

/// The settlement of a request whose round landed, in the app's `apply`
/// after the library's apply. `served`: the round served the request, false
/// only when a secret-shared request's shares did not open C (its
/// inputs-opened bit 0), which the nodes can force on any request, so such
/// a round is no service. `escrow_unused`: a public outcome saying the round
/// consumed nothing (`ok = false` under public outputs; implied when not
/// `served`). The escrow's refund note is completed when `escrow_unused` or
/// not `served`, otherwise the round's completed note carries what it
/// returns; the usage deposit's is completed unless the app keeps the
/// deposit (`UsageDeposit::kept`) and the round `served` the request, so no
/// deposit is kept for a round that served nobody (invariant 0: the nodes
/// cannot turn a request into revenue by failing it). Returns the deposit
/// kept (0 when refunded), for the app's revenue count. Moves no token and
/// makes no external call.
pub fn settle_applied(
    context: PublicContext,
    storage_slot: Field,
    refunds: Refunds,
    deposit: UsageDeposit,
    request_id: Field,
    escrow_unused: bool,
    served: bool,
) -> u128 {
    if escrow_unused | !served {
        partial_note::complete_in_public(context, storage_slot, refunds.escrow, [], request_id);
    }
    if deposit.kept & served {
        deposit.amount
    } else {
        partial_note::complete_in_public(context, storage_slot, refunds.deposit, [], request_id);
        0
    }
}

mod test {
    use super::{PSS_REFUND_DEPOSIT, PSS_REFUND_ESCROW, refund_randomness};
    use aztec::protocol::hash::poseidon2_hash;
    use pss_core::test_support::ascii;

    #[test]
    fn the_separators_are_their_labels() {
        assert_eq(ascii("pss.refund_escrow"), PSS_REFUND_ESCROW);
        assert_eq(ascii("pss.refund_deposit"), PSS_REFUND_DEPOSIT);
    }

    #[test]
    fn the_refund_randomness_is_poseidon2_of_rho_under_its_separators() {
        let (e, d) = refund_randomness(0x9a01);
        assert_eq(e, poseidon2_hash([PSS_REFUND_ESCROW, 0x9a01]));
        assert_eq(d, poseidon2_hash([PSS_REFUND_DEPOSIT, 0x9a01]));
        assert(e != d);
    }
}
