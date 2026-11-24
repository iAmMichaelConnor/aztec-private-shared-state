use aztec::macros::aztec;

pub mod app;
pub mod layouts;

/// Credits paid to a key at the tip of the chain (examples/credits-tip
/// README; docs/ARCHITECTURE.md section 6, "The oblivious sparse map"): a ledger from a
/// key, the hash of the handle a payee hands out, to its unclaimed balance,
/// held by the network as one keyed oblivious map (state mode `node`, `tree`
/// `access: oblivious, keyed: true`), whose root's commitment lives in the
/// public slot `ledger`. Every round runs under secret-shared receipt intake
/// with a private outcome delivered by partial-note completion: the keys and
/// the amount are shared among the nodes, no node learns which entry a round
/// touches or whether it inserted, and the round completes the requester's
/// partial note inside the co-SNARK with `[code, round, a, b, request_id]`.
///
/// Functions:
/// - `constructor(config)`: the pins that do not depend on the namespace
///   (`Config`: the stale period, the node `sig` keys, the contract
///   manifest's hash, the package list and each package's vk hash);
/// - `configure(npk_app_hash, answer)`: once, anyone, after the contract
///   manifest was registered under this address (pss_public_contract
///   `configure`); every function below refuses until it has landed;
/// - `init_ledger(new_c, signatures)`: lands the `credits_init` round once,
///   outside the queue, while the ledger slot is empty;
/// - `pay(handle, amount, ...)`: anyone credits `amount` to the key
///   `map_key(handle)`; `claim(secret, amount, ...)`, `view_balance(secret,
///   ...)` and `move_credit(secret, to, amount, ...)`: the owner of the key
///   `own_map_key(sender, secret)` claims from it, looks it up (the
///   prove-absent round) or moves credit to the key of the handle `to`. No
///   caller-chosen field reaches the map: every key is `map_key`'s hash.
///   Each commits the sender's partial note from `rho`, checks the three
///   node receipts over C and enqueues the one public wrapper
///   `append_receipt(request_id, expiry_block)`, so the public call tells no
///   round type;
/// - `process_result(round, result, signatures)`: verifies one round's result
///   under its row's vk pin, lands the completed note and the outcome log,
///   and enqueues `apply_result`, the one apply of every round type;
/// - `skip()`, the views `get_state`, `request_at`, `done_at`, and the
///   utilities `deliver_outcome` and `credit_notes`.
///
/// A fixed key set (`app::Keys` is `FixedKeys`): every node
/// signature is checked under the constructor's keys for the life of the
/// contract, so it has no key-epoch slot and no rotation entry point, and a
/// node replacement means redeploying it under a new salt.
///
/// Every function is one call into pss_public_contract's app skeleton over
/// the round table (`app::queued_round`); the app's own parts are in `app`: the
/// package names, the Config pins, the key derivation (`payee_handle`,
/// `map_key`, `own_map_key`), the validity checks and the
/// `CreditOutcomeNote`.
///
/// No token moves: a completed note is its requester's record of the round
/// (a claim's says what was claimed), and nothing pays it out.
///
/// Trust model: semi-honest MPC (two colluding nodes open every key and
/// balance; a key authorises nothing, the request function does); the chain
/// trusts the proofs and the three node signatures, never the operator or
/// the relayer, who can only delay.
#[aztec]
pub contract CreditsTip {
    use crate::app::{
        Config, CreditNotes, CreditOutcomeNote, CreditsApply, CreditsResult, init_state_keys, init_round,
        Keys, ledger_state_keys, map_key, OUTCOME_SLOT, own_map_key, PACKAGES, queued_round, ROUND_CLAIM, ROUND_MOVE, ROUND_PAY, ROUND_VIEW, valid_claim,
        valid_move, valid_pay, valid_view,
    };
    use crate::layouts::{CLAIM_LAYOUT, MOVE_LAYOUT, PAY_LAYOUT, VIEW_LAYOUT};
    use aztec::macros::{functions::{external, initializer, internal, only_self, view}, storage::storage};
    use aztec::note::note_viewer_options::NoteViewerOptions;
    use aztec::protocol::address::AztecAddress;
    use aztec::state_vars::{Owned, PrivateSet, PublicImmutable, StateVariable};
    use pss_public_contract::{
        apply_round, check_round, CircuitsInForce, CommitmentSlot, configure, Configured,
        FixedCircuits, init,
        no_pinned_reads, NodeHeld, Queue, Receipt, RegistryAnswer,
        outcome_request, ReceiptRequest, SharedReceiptArgs, Sharing, stale_blocks_in_public, TipState,
    };
    use pss_public_contract::outcome::{deliver_outcome_into, OutcomeTx, Private};
    use pss_public_contract::result::ResultSignature;

    #[storage]
    struct Storage<Context> {
        // every round's completed notes, by owner (whoever committed the
        // request's partial note). The round circuits hash each note at
        // this slot (credits_tip shared.nr OUTCOME_SLOT, 1, which
        // `process_result` checks is this slot), so it comes first: its slot
        // does not move when the Config's size does.
        outcome_notes: Owned<PrivateSet<CreditOutcomeNote, Context>, Context>,
        // the constructor's pins
        config: PublicImmutable<Config, Context>,
        // configure's: the constructor's pins with npk_app_hash
        configured: PublicImmutable<Configured<PACKAGES>, Context>,
        queue: Queue<Context>,
        // The ledger key. The machine key of the keyed map ($state_keys.reads[0]
        // and $state_keys.writes[0] in every manifest, the `tree` entry's key) is
        // this slot's storage slot, the Aztec "key = storage slot"; the
        // circuits bind it into the commitments (in_slots, out_slots), which
        // commit to the map's root. 0 until `init_ledger`; written by every
        // round, whatever its outcome (the rounds re-blind the leaves they
        // hold).
        ledger: CommitmentSlot<Context>,
    }

    #[external("public")]
    #[initializer]
    fn constructor(config: Config) {
        config.tip.assert_valid();
        self.storage.config.initialize(config);
    }

    // -----------------------------------------------------------------------
    // Configure: the REGISTER answer, once
    // -----------------------------------------------------------------------

    /// pss_public_contract::configure::configure; `set_configured` stores it once.
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

    // -----------------------------------------------------------------------
    // Init: the credits_init round, once, outside the queue
    // -----------------------------------------------------------------------

    /// Land the init round (the library's `process_init`): verify the
    /// `credits_init` proof (public inputs `[namespace, vk_hash, out_slots[0]
    /// = the ledger key, request_id, old_c = 0, new_c, npk_app_hash]`: the
    /// commitment of the empty map) under the pinned init vk and the three
    /// nodes' result signatures over `new_c` (node-held: no sealed thirds),
    /// under the init request id with no inputs, then enqueue `apply_init`.
    #[external("private")]
    fn init_ledger(new_c: Field, signatures: [ResultSignature; 3]) {
        let request_id = init::process_init(
            init_round(self.internal.configured_in_force(), self.storage.ledger),
            self.context,
            self.msg_sender(),
            [],
            [new_c],
            [],
            NodeHeld {},
            signatures,
        );
        self.enqueue_self.apply_init(request_id, new_c);
    }

    /// The public half of `init_ledger`: write the first commitment while
    /// the slot is empty ("already initialised" otherwise). Logs nothing and
    /// touches no queue storage.
    #[external("public")]
    #[only_self]
    fn apply_init(request_id: Field, new_c: Field) {
        init::apply_init(self.context, init_state_keys(self.storage.ledger), request_id, [new_c], NodeHeld {});
    }

    // -----------------------------------------------------------------------
    // Intake: secret-shared receipt intake, one public wrapper for every round
    // -----------------------------------------------------------------------

    /// Credit `amount` to the key of `handle`, `key = map_key(handle)` (`pay`:
    /// an insert where the key is absent, an addition where present; nobody
    /// but the circuit learns which). Anyone may pay any handle; the key is
    /// computed here, never an argument, so a payer cannot name another key's
    /// path. The function commits the sender's partial note `P =
    /// partial_commitment(msg_sender, rho)` with its use nullifier, checks
    /// `valid_pay`, proves that `sharing` (the summand vectors the nodes
    /// hold, `PAY_LAYOUT`) opens C over `[key, amount, P,
    /// outcome_key, outcome_tag]`, computes the request id, checks the three
    /// receipts over C and the sharing's digest and enqueues `append_receipt`
    /// with the request id and the expiry block only. A request whose shares
    /// do not open C is never queued. The payer's note says `[code, ROUND_PAY, amount, 0]`: nothing of the
    /// payee's balance.
    #[external("private")]
    fn pay(
        handle: Field,
        amount: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<6>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        let row = queued_round(self.internal.configured_in_force(), self.storage.ledger, ROUND_PAY);
        // BRICK intake = shared_receipt (pss_public_contract::SharedReceiptArgs), in every request function
        // here. Alternatives: shared_onchain (SharedOnchainArgs in a request function of its own).
        // docs/design-guide/BRICKS.md#intake
        let r: ReceiptRequest = outcome_request(
            self.context,
            row,
            self.msg_sender(),
            [map_key(handle), amount],
            PAY_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_pay,
        );
        self.enqueue_self.append_receipt(r.request_id, r.expiry_block);
    }

    /// Claim `amount` from the sender's key `own_map_key(msg_sender, secret)`
    /// (`claim`: the key present with the balance, else a flagged no-op whose
    /// note says why: code 4 absent, 5 below the amount). As `pay` (under
    /// `CLAIM_LAYOUT`), with the key computed here, never an argument; the note says `[code, ROUND_CLAIM, amount,
    /// balance left]`.
    #[external("private")]
    fn claim(
        secret: Field,
        amount: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<6>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        let row = queued_round(self.internal.configured_in_force(), self.storage.ledger, ROUND_CLAIM);
        let sender = self.msg_sender();
        let r: ReceiptRequest = outcome_request(
            self.context,
            row,
            sender,
            [own_map_key(sender, secret), amount],
            CLAIM_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_claim,
        );
        self.enqueue_self.append_receipt(r.request_id, r.expiry_block);
    }

    /// Look the sender's key up (`view`, the prove-absent round): the note
    /// says `[code, ROUND_VIEW, present, balance]`, `present` 0 proving the key is not in
    /// the map. Writes nothing but re-blinds a present leaf, so on chain a
    /// view looks like any other round. As `claim`, under `VIEW_LAYOUT`.
    #[external("private")]
    fn view_balance(
        secret: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<5>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        let row = queued_round(self.internal.configured_in_force(), self.storage.ledger, ROUND_VIEW);
        let sender = self.msg_sender();
        let r: ReceiptRequest = outcome_request(
            self.context,
            row,
            sender,
            [own_map_key(sender, secret)],
            VIEW_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_view,
        );
        self.enqueue_self.append_receipt(r.request_id, r.expiry_block);
    }

    /// Move `amount` from the sender's key `own_map_key(msg_sender, secret)` to
    /// the key of the handle `to`, `map_key(to)` (`move`: the source present
    /// with the balance, the destination inserted when absent). As `claim`,
    /// with `valid_move` (the destination another key) and `MOVE_LAYOUT`; the note says `[code, ROUND_MOVE, amount, source balance
    /// left]`.
    #[external("private")]
    fn move_credit(
        secret: Field,
        to: Field,
        amount: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<7>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        let row = queued_round(self.internal.configured_in_force(), self.storage.ledger, ROUND_MOVE);
        let sender = self.msg_sender();
        let r: ReceiptRequest = outcome_request(
            self.context,
            row,
            sender,
            [own_map_key(sender, secret), map_key(to), amount],
            MOVE_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_move,
        );
        self.enqueue_self.append_receipt(r.request_id, r.expiry_block);
    }

    /// The public half of every request: refuses before `configure` and while
    /// the ledger is uninitialised, then the library's `append_before` (the
    /// receipt's expiry, the request id not seen).
    #[external("public")]
    #[only_self]
    fn append_receipt(request_id: Field, expiry_block: u32) {
        let _ = self.storage.queue.append_receipt(self.storage.configured, self.storage.ledger, request_id, expiry_block);
    }

    // -----------------------------------------------------------------------
    // The result transaction
    // -----------------------------------------------------------------------

    /// One round's result under private outcomes, named by its `ROUND_*`
    /// index (a private argument): the library pins the round's vk, verifies
    /// the proof over `[namespace, vk_hash, in_slots, out_slots, request_id,
    /// machine_request_id, old_c, new_c, npk_app_hash, outcome_tag,
    /// note_hash, ciphertext[5]]` (the machine request id computed here),
    /// checks the three result signatures, pushes the completed note's hash
    /// and emits the outcome log; nothing runs after the log and no other
    /// contract is called. The row's pin selects the circuit, so a result
    /// named with another round verifies no proof. Anyone may submit; the
    /// relayer does, and it sees ciphertext and hashes only.
    #[external("private")]
    fn process_result(round: u32, result: CreditsResult, signatures: [ResultSignature; 3]) {
        let apply = check_round(
            queued_round(self.internal.configured_in_force(), self.storage.ledger, round),
            self.context,
            self.msg_sender(),
            Private::of(result, self.storage.outcome_notes.get_storage_slot(), OUTCOME_SLOT),
            NodeHeld {},
            signatures,
        );
        self.enqueue_self.apply_result(apply);
    }

    /// Land a checked round, whichever it was: the library checks
    /// `requests[head] == request_id` and `ledger == old_c`, writes `new_c`
    /// whatever the outcome (there is no public `ok`), moves the head and
    /// writes `done[index]`. It stores no outcome and logs nothing: every
    /// round type lands through this one function with the same arguments.
    #[external("public")]
    #[only_self]
    fn apply_result(apply: CreditsApply) {
        let _ = apply_round(
            self.context,
            self.storage.queue,
            no_pinned_reads(),
            ledger_state_keys(self.storage.ledger),
            apply,
            NodeHeld {},
        );
    }

    /// Drop the head once it has sat `stale_blocks` blocks (the configured
    /// pins'); anyone may call it, once the contract is configured.
    #[external("public")]
    fn skip() {
        let stale_blocks = stale_blocks_in_public(self.context, self.storage.configured);
        let _ = self.storage.queue.skip(stale_blocks);
    }

    // -----------------------------------------------------------------------
    // Views and utilities
    // -----------------------------------------------------------------------

    /// pss_public_contract::view::TipState::read, over the ledger slot and the
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
            [self.storage.ledger],
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

    /// The outcome-note utility: hand `owner`'s PXE the completed note its
    /// client rebuilt from the outcome log of transaction `tx` (`packed` =
    /// `[code, round, a, b, request_id]`, `rho` the request's randomness). A note
    /// whose hash is not among the transaction's is not stored.
    #[external("utility")]
    unconstrained fn deliver_outcome(owner: AztecAddress, rho: Field, packed: [Field; 5], tx: OutcomeTx) {
        deliver_outcome_into(self.storage.outcome_notes, self.address, _compute_note_hash, _compute_note_nullifier, owner, rho, packed, tx);
    }

    /// The outcome notes `owner`'s PXE holds, and the first of them.
    #[external("utility")]
    unconstrained fn credit_notes(owner: AztecAddress) -> CreditNotes {
        let notes = self.storage.outcome_notes.at(owner).view_notes(NoteViewerOptions::new());
        let first = if notes.len() > 0 {
            notes.get(0)
        } else {
            CreditOutcomeNote { code: 0, round: 0, a: 0, b: 0, request_id: 0 }
        };
        CreditNotes { count: notes.len(), first }
    }
}
