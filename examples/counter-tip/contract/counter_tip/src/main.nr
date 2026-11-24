use aztec::macros::aztec;

pub mod app;
pub mod layouts;

/// A minimal example: a private running total that many users add to. It
/// moves no token. It is the smallest complete app on the default blueprint
/// (`tip-flat`, docs/design-guide/README.md): one node-held flat key, the
/// init round and one queued round (`add`) under secret-shared receipt
/// intake, whose private outcome completes the requester's partial note
/// with `[code, total, request_id]` inside the co-SNARK.
///
/// The app's own code is the request function `add` and, in `app`, the
/// round table, the validity check and the outcome note. Every other
/// function is one call into pss_public_contract, a wrapper an app copies
/// as it is (`#[external]` functions cannot be generic, so the library
/// cannot declare them).
#[aztec]
pub contract CounterTip {
    use crate::app::{AddApply, AddOutcomeNote, AddResult, Config, counter_state_keys, init_state_keys, Keys, OUTCOME_SLOT, PACKAGES, rounds, valid_add};
    use aztec::macros::{functions::{external, initializer, internal, only_self, view}, storage::storage};
    use aztec::protocol::address::AztecAddress;
    use aztec::state_vars::{Owned, PrivateSet, PublicImmutable, StateVariable};
    use crate::layouts::COUNTER_ADD_LAYOUT;
    use pss_public_contract::{
        apply_round, check_round, CircuitsInForce, CommitmentSlot, configure, Configured,
        FixedCircuits, init, key_epoch, KeySet, no_pinned_reads, NodeHeld, NodeKeys, NoEncKeys, outcome_request,
        Queue, Receipt, ReceiptRequest, RegistryAnswer, SharedReceiptArgs, Sharing, stale_blocks_in_public, TipState,
    };
    use pss_public_contract::outcome::{deliver_outcome_into, OutcomeTx, Private};
    use pss_public_contract::result::ResultSignature;

    #[storage]
    struct Storage<Context> {
        // every add's completed note, by owner. First, so its slot is the
        // circuits' OUTCOME_SLOT (1).
        outcome_notes: Owned<PrivateSet<AddOutcomeNote, Context>, Context>,
        config: PublicImmutable<Config, Context>,
        configured: PublicImmutable<Configured<PACKAGES>, Context>,
        queue: Queue<Context>,
        // the counter key: its storage slot is the machine key of every
        // manifest's $state_keys; its value the commitment of [total,
        // blinding], 0 until `init_counter`
        counter: CommitmentSlot<Context>,
    }

    // =======================================================================
    // The app's own function: the request
    // =======================================================================

    /// Add `amount` to the total. The amount, `rho` (the client's randomness
    /// for the requester's partial note), the outcome key and tag and
    /// `sharing` (the summand vectors the nodes hold, `COUNTER_ADD_LAYOUT`) are
    /// private arguments; only the request id and the expiry block reach the
    /// chain. The library commits the sender's partial note, checks
    /// `valid_add`, proves that the sharing opens C, computes the request id
    /// and checks the three node receipts over C and the sharing's digest. A
    /// request whose shares do not open C is never queued.
    #[external("private")]
    fn add(
        amount: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<5>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        let row = rounds(self.internal.configured_in_force(), self.storage.counter).add;
        // BRICK intake = shared_receipt (pss_public_contract::outcome_request). Alternatives: onchain,
        // receipt, shared_onchain (a request function of its own each). docs/design-guide/BRICKS.md#intake
        let r: ReceiptRequest = outcome_request(
            self.context,
            row,
            self.msg_sender(),
            [amount],
            COUNTER_ADD_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_add,
        );
        self.enqueue_self.append_receipt(r.request_id, r.expiry_block);
    }

    // =======================================================================
    // Library wrappers: one call each, the same in every tip app
    // =======================================================================

    #[external("public")]
    #[initializer]
    fn constructor(config: Config) {
        config.tip.assert_valid();
        self.storage.config.initialize(config);
    }

    /// The circuit pins every round row is built from.
    #[internal("private")]
    fn configured_in_force() -> Configured<PACKAGES> {
        // BRICK upgrades = fixed (pss_public_contract::FixedCircuits): the constructor's pins for good.
        // Alternatives: circuits, contract (CircuitUpgrades::in_force, with its storage and upgrade
        // functions; examples/amm-tip). docs/design-guide/BRICKS.md#upgrades
        FixedCircuits {}.in_force(self.storage.configured.read())
    }

    /// pss_public_contract::configure::configure, once.
    #[external("private")]
    fn configure(npk_app_hash: Field, answer: RegistryAnswer) {
        let configured = configure::configure(self.context, self.storage.config.read().tip, npk_app_hash, answer);
        self.enqueue_self.set_configured(configured);
    }

    #[external("public")]
    #[only_self]
    fn set_configured(configured: Configured<PACKAGES>) {
        self.storage.configured.initialize(configured);
    }

    /// pss_public_contract::init::process_init: land the init round once,
    /// outside the queue.
    #[external("private")]
    fn init_counter(new_c: Field, signatures: [ResultSignature; 3]) {
        let row = rounds(self.internal.configured_in_force(), self.storage.counter).init;
        // BRICK state = node (pss_public_contract::NodeHeld), also in every result body below.
        // Alternatives: chain (chain_state's SealedThirds in its place). docs/design-guide/BRICKS.md#state
        let request_id = init::process_init(row, self.context, self.msg_sender(), [], [new_c], [], NodeHeld {}, signatures);
        self.enqueue_self.apply_init(request_id, new_c);
    }

    #[external("public")]
    #[only_self]
    fn apply_init(request_id: Field, new_c: Field) {
        init::apply_init(self.context, init_state_keys(self.storage.counter), request_id, [new_c], NodeHeld {});
    }

    /// The public half of `add`: pss_public_contract's `Queue::append_receipt`
    /// (configured, the counter initialised, the receipt's expiry, the
    /// request id not seen).
    #[external("public")]
    #[only_self]
    fn append_receipt(request_id: Field, expiry_block: u32) {
        let _ = self.storage.queue.append_receipt(self.storage.configured, self.storage.counter, request_id, expiry_block);
    }

    /// pss_public_contract::check_round under private outcomes: verify the
    /// add's proof and the three result signatures, push the completed note
    /// hash and emit the outcome log. Anyone may submit; the relayer does.
    #[external("private")]
    fn process_result(result: AddResult, signatures: [ResultSignature; 3]) {
        let row = rounds(self.internal.configured_in_force(), self.storage.counter).add;
        let apply = check_round(row, self.context, self.msg_sender(), Private::of(result, self.storage.outcome_notes.get_storage_slot(), OUTCOME_SLOT), NodeHeld {}, signatures);
        self.enqueue_self.apply_result(apply);
    }

    /// pss_public_contract::apply_round: the head and the old commitment
    /// checked, the new commitment written, the head moved.
    #[external("public")]
    #[only_self]
    fn apply_result(apply: AddApply) {
        let _ = apply_round(self.context, self.storage.queue, no_pinned_reads(), counter_state_keys(self.storage.counter), apply, NodeHeld {});
    }

    /// pss_public_contract::queue::Queue::skip: anyone drops a stale head.
    #[external("public")]
    fn skip() {
        let _ = self.storage.queue.skip(stale_blocks_in_public(self.context, self.storage.configured));
    }

    /// pss_public_contract::key_epoch::check_rotation.
    #[external("private")]
    fn rotate_keys(epoch: u32, keys: KeySet, signatures: [ResultSignature; 3]) {
        let config = self.storage.configured.read().config();
        let node_keys = key_epoch::check_rotation(self.context, config, epoch, keys, signatures);
        self.enqueue_self.set_node_keys(node_keys);
    }

    #[external("public")]
    #[only_self]
    fn set_node_keys(node_keys: NodeKeys) {
        // the enc keys Keys names: none, as no package takes secret-shared on-chain intake (under it, Keys is
        // KeyEpochs<SharedOnchain<PublicContext>> and this hands Keys::install the contract's SharedOnchain)
        Keys::install(self.context, node_keys, NoEncKeys {});
    }

    #[external("public")]
    #[only_self]
    fn assert_key_epoch(epoch: u32, current_only: bool) {
        key_epoch::assert_epoch(self.context, epoch, current_only);
    }

    #[external("public")]
    #[view]
    fn get_node_keys() -> NodeKeys {
        key_epoch::stored(self.context)
    }

    #[external("public")]
    #[view]
    fn get_state() -> TipState<Config, 1, Keys, FixedCircuits> {
        TipState::read(
            self.context,
            self.storage.config,
            self.storage.configured,
            self.storage.queue,
            [self.storage.counter],
            self.storage.outcome_notes.get_storage_slot(),
        )
    }

    #[external("public")]
    #[view]
    fn request_at(index: u64) -> Field {
        self.storage.queue.request_at(index)
    }

    #[external("public")]
    #[view]
    fn done_at(index: u64) -> u8 {
        self.storage.queue.done_at(index)
    }

    /// pss_public_contract::outcome::deliver_outcome_into: hand `owner`'s PXE
    /// the completed note its client rebuilt from the outcome log of `tx`
    /// (`packed` = `[code, total, request_id]`).
    #[external("utility")]
    unconstrained fn deliver_outcome(owner: AztecAddress, rho: Field, packed: [Field; 3], tx: OutcomeTx) {
        deliver_outcome_into(self.storage.outcome_notes, self.address, _compute_note_hash, _compute_note_nullifier, owner, rho, packed, tx);
    }
}
