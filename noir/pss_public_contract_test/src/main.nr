use aztec::macros::aztec;

mod attempt;
mod nodes;
mod rounds;
mod test;
mod test_intake;
mod test_receipt;
mod test_shared_receipt;
mod test_shared_onchain;
mod test_node_held;
mod test_chain_held;
mod test_outcome;
mod test_result;
mod test_freshness;
mod test_partial;
mod test_key_epoch;
mod test_hatch;

/// The static-validity predicate of the test contract's request functions,
/// for inputs shaped like an AMM swap's `[amount_in, direction]`: a
/// non-zero amount below 2^64 and a direction of 0 or 1. It sees the inputs
/// only, as intake requires.
pub fn valid_inputs(inputs: [Field; 2]) -> bool {
    let amount_in = inputs[0];
    let direction = inputs[1];
    (amount_in != 0) & amount_in.lt(0x10000000000000000) & ((direction == 0) | (direction == 1))
}

/// The minimal app contract on `pss_public_contract`, and the library's
/// contract-level TXE suite (`test.nr`): storage as an app declares it, and
/// the one-line wrappers an app writes around the library's `append` and
/// `skip()`. It is a package of its own beside the library because nargo
/// 1.0.0-rc.3 refuses a package nested inside another, and the library
/// cannot depend on a contract that depends on it. `request` stands in for
/// an intake function: it enqueues `append` with an id the test chooses,
/// where a real intake function computes the id from the inputs and checks
/// them first; `request_onchain` and `request_with_receipts` are the two
/// real intake functions (on-chain intake and receipt intake) an app writes
/// around the library, both under the pool round's vk hash (one compiled
/// circuit serves both non-secret-shared intakes), and `request_shared` secret-shared receipt
/// intake's (`test_shared_receipt.nr`), under the private-outcome circuit's
/// vk hash; `request_shared_onchain` is secret-shared on-chain intake's
/// (`test_shared_onchain.nr`) under the same row, with the nodes' `enc` keys
/// in `shared_onchain` and their rotation (`rotate_enc_key`, `set_enc_key`).
///
/// The result transaction (`test_result.nr`), both state options of the
/// library: `process_result`, whichever non-secret-shared intake queued the request
/// (the circuit outputs the request id), under chain-held state (the sealed
/// thirds handed to `check_round` and `apply_round`) and enqueuing `apply`, for a circuit with one
/// chain-held key read and written (the `pool` slot, whose storage slot is
/// the key), two app inputs, one pinned read (on the `oracle` pin, another
/// instance of this contract), two app outputs and one sealed third of five
/// fields per node (`PoolResult`, `PoolThirds`). `apply`'s hook stores the
/// app outputs by queue index. `process_result_wide` and `apply_wide` call
/// `check_round` and `apply_round` under node-held state
/// for `WideResult`, three keys (the table's `wide_round`) and no thirds.
///
/// Chain-held state end to end (`test_chain_held.nr`): `init_pool` and
/// `apply_init_pool`, the init round under chain-held state (`process_init`
/// and `apply_init` with the thirds), create the
/// `pool` key with its first thirds (no init input, `POOL_INIT_INPUTS`, under
/// the init circuit's vk hash); `process_result_private_sealed` and
/// `apply_private_sealed`, the private-outcome round over `pool` under
/// chain-held state (`check_round`, `apply_round` with the thirds), land a
/// completed note and log the round's thirds.
///
/// Node-held state end to end (`test_node_held.nr`): `init_held` and
/// `apply_init_held`, the init round under node-held state, create the
/// `held` key (one init input, `HELD_INIT_INPUTS`, under the init circuit's
/// vk hash); `process_result_held` and `apply_held`, a round under its own
/// vk hash (`held_vk_hash`) under node-held state, read and write it, with
/// no pinned read (`HeldResult`). Neither signs over nor logs any sealed
/// third.
///
/// Private outcomes (`test_outcome.nr`, `test_partial.nr`):
/// `process_result_private` and `apply_private`, a secret-shared-intake round
/// over `held` under its own vk hash (`OutcomeRound`), whose outcome is the
/// hash of the request's partial note completed by the round (a
/// `PartialOutcome`) and the outcome log; `deliver_partial_outcome`, the
/// outcome-note utility through which the user hands its PXE the completed
/// note, and `partial_notes`, what the PXE then holds.
///
/// The escape hatch (`test_hatch.nr`): `hatch_queued`, `hatch_landed`,
/// `hatch_open`, `get_hatch` and `hatch_exit`, the library's `Hatch` bodies
/// over the `hatch` slot, the exit on a completed note (`PartialOutcome`,
/// whose amount stands for the entry it names).
///
/// Test-only parts no app has: the oracle side (`set_price`, `get_price`,
/// `get_value`, `get_none`, `get_pair`, `set_burn`, and `set_reentry`, which
/// turns `get_price` into a mock that calls `skip()` on the app, reverts or
/// burns gas), the probes (`try_*`, each a
/// public function that makes one of the app's refusable calls as a nested
/// call and returns whether it succeeded, so a test can watch a refusal
/// without the transaction reverting), and the utility functions that read
/// a settled transaction's effects.
#[aztec]
pub contract PssPublicTest {
    use crate::attempt::{attempt, burn_l2_gas};
    use pss_tip_test::{PROBE_DA_GAS, PROBE_L2_GAS};
    use pss_tip_test::shape::{log_fields, summarize, TxSummary};
    use crate::rounds::{
        Escrow, HELD_INIT_INPUTS, HeldResult, OraclePin, OutcomeApplyRound, OutcomeRound,
        PartialHeldResult, PartialOutcome, PartialOutcomes, POOL_INIT_INPUTS, PoolResult,
        Keys, PoolThirds, Row, wide_round, WideResult,
    };
    use aztec::messages::delivery::MessageDelivery;
    use aztec::note::note_getter_options::NoteGetterOptions;
    use pss_public_contract::{
        chain_request_id, inputs_commitment, inputs_hash, NodeHeld, shared_chain_request_id,
    };
    use pss_public_contract::partial_note;
    use pss_public_contract::hatch::{Hatch, HatchState};
    use aztec::macros::{functions::{external, initializer, only_self, view}, storage::storage};
    use aztec::note::{note_interface::NoteType, note_viewer_options::NoteViewerOptions};
    use aztec::oracle::message_processing::get_tx_effect;
    use aztec::protocol::abis::function_selector::FunctionSelector;
    use aztec::protocol::address::AztecAddress;
    use aztec::protocol::traits::FromField;
    use aztec::state_vars::{Map, Owned, PrivateSet, PublicImmutable, PublicMutable, StateVariable};
    use pss_public_contract::{
        apply_round, check_round, CommitmentSlot, FixedCircuits, Head, KeyEpochs, StateKeys, KeySet, no_pinned_reads, NodeKeys,
        onchain_request, PlainRequest, Queue, Receipt, receipt_request, shared_receipt_request, Sharing,
        TipConfig, TipRound, TipState,
    };
    use pss_public_contract::key_epoch;
    use pss_public_contract::shared_onchain::{
        check_enc_rotation, EncKey, shared_onchain_request, SharedOnchain,
    };
    use pss_public_contract::init::{apply_init, process_init};
    use pss_public_contract::outcome::{deliver_outcome_note, OutcomeTx, Private};
    use pss_public_contract::result::{assert_pinned_reads, Freshness, PinnedRead, ResultSignature};
    use pss_tip_test::audit::assert_tx_names_no_requester;

    /// The test-only modes of the oracle's `get_price`, set by `set_reentry`
    /// (never in an app). Default `REENTER_NONE`: `get_price` only reads the
    /// price. `REENTER_PROPAGATE`: `get_price` calls `skip()` on the target
    /// with aztec-nr's `self.call`, which rethrows a revert.
    /// `REENTER_SWALLOW`: it makes the same call with `attempt`, ignores a
    /// revert, and returns the price only when the skip reverted (the price
    /// plus one when it landed), so a result signed at the price applies
    /// only if the re-entrant skip did nothing. These stand for a pinned
    /// read target that tries to re-enter the queue during `apply`, which an
    /// app's own pin choice should rule out; the suite shows the library
    /// holds even when it does not. `READ_REVERT`: `get_price` reverts.
    /// `READ_BURN`: it spends the L2 gas `set_burn` set before it returns the
    /// price, so it halts exceptionally when its allotment is smaller.
    pub global REENTER_NONE: u8 = 0;

    /// Where `outputs` keeps a request's escrow: at `ESCROW_AT + index`,
    /// far past every index a suite reaches.
    pub global ESCROW_AT: u64 = 0x100000000;
    pub global REENTER_PROPAGATE: u8 = 1;
    pub global REENTER_SWALLOW: u8 = 2;
    pub global READ_REVERT: u8 = 3;
    pub global READ_BURN: u8 = 4;

    /// The gas the swallowing mock gives its re-entrant `skip()` (a
    /// test-only knob): 1,000,000 L2 and 100,000 DA, far more
    /// than `skip()` uses, and bounded rather than everything left: the AVM
    /// halts the static `skip()` exceptionally at its storage write, which
    /// consumes the whole allotment, so `get_price` and `apply` keep only
    /// what was not allotted (the transaction's DA limit is 786,432); the
    /// test pins the read with more L2 gas than this
    /// (`SWALLOWING_READ_L2_GAS`). Too small and the skip would run out of gas
    /// before it reaches the static-call rule; a direct `skip()` at the same
    /// moment lands in the propagating test.
    pub global REENTRANT_SKIP_L2_GAS: u32 = 1000000;
    pub global REENTRANT_SKIP_DA_GAS: u32 = 100000;

    #[storage]
    struct Storage<Context> {
        config: PublicImmutable<TipConfig, Context>,
        // the vk hashes pinned at deployment, as an app pins each circuit's:
        // the pool round's, one circuit for both intake functions' requests
        // (and the wide round's), and the node-held round's
        vk_hash: PublicImmutable<Field, Context>,
        held_vk_hash: PublicImmutable<Field, Context>,
        queue: Queue<Context>,
        // one commitment slot, as for a manifest with one chain-held key;
        // only `apply`, `apply_init_pool` and `apply_private_sealed` write it,
        // so the queue's functions leave it at 0
        pool: CommitmentSlot<Context>,
        // the wide round's two other keys: `book`, read and written, and
        // `fresh`, written only
        book: CommitmentSlot<Context>,
        fresh: CommitmentSlot<Context>,
        // where `apply`'s pinned reads go (`OraclePin`)
        oracle: PublicImmutable<OraclePin, Context>,
        // what the app hook stores: the app outputs of each applied index
        outputs: Map<u64, PublicMutable<[Field; 2], Context>, Context>,
        // the oracle side: the value `get_price()` returns
        price: PublicMutable<Field, Context>,
        // the oracle side, as a re-entrant mock: whose `skip()` `get_price()`
        // calls, and how (`REENTER_*`)
        reenter_target: PublicMutable<AztecAddress, Context>,
        reenter_mode: PublicMutable<u8, Context>,
        // the oracle side: the L2 gas `get_price` spends under `READ_BURN`
        burn: PublicMutable<u32, Context>,
        // the node-held key: `apply_init_held` creates it, `apply_held` reads
        // and writes it
        held: CommitmentSlot<Context>,
        // the init circuit's vk hash, pinned once after deployment
        // (`set_init_vk_hash`), as `oracle` is, so the constructor keeps the
        // arguments every suite deploys this contract with
        init_vk_hash: PublicImmutable<Field, Context>,
        // the private-outcome circuit's vk hash, pinned once after deployment
        // (`set_outcome_vk_hash`), and the completed notes: those its rounds
        // complete inside the co-SNARK and those `apply_partial` and
        // `skip_refunding` complete in public (`test_partial.nr`), the refund
        // notes (`[0, amount, request_id]`) among them. Each request's escrow
        // `[refund_note, amount]` is kept in `outputs` at `ESCROW_AT + index`
        // (an app keeps its own map; this contract is at the compiler's
        // type-size limit)
        outcome_vk_hash: PublicImmutable<Field, Context>,
        partial_outcomes: Owned<PrivateSet<PartialOutcome, Context>, Context>,
        // the epoch source (`test_freshness.nr`): its current value, epoch
        // and the previous epoch's value, all 0 until `open_epoch`
        epoch_value: PublicMutable<Field, Context>,
        epoch: PublicMutable<Field, Context>,
        epoch_previous: PublicMutable<Field, Context>,
        // secret-shared on-chain intake: the nodes' enc keys and epochs, and each
        // request's data hash (last, so no other slot moves)
        shared_onchain: SharedOnchain<Context>,
        // the escape hatch (`test_hatch.nr`): its clock and open flag, one
        // slot (last, so no other slot moves)
        hatch: Hatch<Context>,
    }

    #[external("public")]
    #[initializer]
    fn constructor(config: TipConfig, vk_hash: Field, held_vk_hash: Field) {
        self.storage.config.initialize(config);
        self.storage.vk_hash.initialize(vk_hash);
        self.storage.held_vk_hash.initialize(held_vk_hash);
    }

    // On-chain intake: the inputs and user_nonce go to the chain in the
    // request log. (`inputs` is the name aztec-nr's private macro gives the
    // context inputs, hence `app_inputs`.)
    #[external("private")]
    fn request_onchain(app_inputs: [Field; 2], user_nonce: Field) {
        let round: Row<_, 1, 1> = TipRound::one(
            self.storage.vk_hash.read(),
            self.storage.config.read(),
            self.storage.pool,
        );
        let (request_id, plain) = onchain_request(
            self.context,
            round,
            app_inputs,
            user_nonce,
            crate::valid_inputs,
        );
        self.enqueue_self.append_onchain(request_id, plain);
    }

    #[external("public")]
    #[only_self]
    fn append_onchain(request_id: Field, plain: PlainRequest<2>) {
        let _ = self.storage.queue.append_onchain(request_id, plain);
    }

    // Receipt intake: three node receipts checked here; only the request id and the
    // expiry block go to the chain.
    #[external("private")]
    fn request_with_receipts(
        app_inputs: [Field; 2],
        user_nonce: Field,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        let round: Row<_, 1, 1> = TipRound::one(
            self.storage.vk_hash.read(),
            self.storage.config.read(),
            self.storage.pool,
        );
        let request_id = receipt_request(
            self.context,
            round,
            app_inputs,
            user_nonce,
            expiry_block,
            receipts,
            crate::valid_inputs,
        );
        self.enqueue_self.append_receipt(request_id, expiry_block);
    }

    #[external("public")]
    #[only_self]
    fn append_receipt(request_id: Field, expiry_block: u32) {
        let _ = self.storage.queue.append_before(request_id, expiry_block);
    }

    // Secret-shared receipt intake: the sharing proved to open C, the receipts
    // over C and its digest, and the request enqueues the same wrapper as
    // receipt intake, with the request id and the expiry block only, under
    // the private-outcome round's row (the one `process_result_private`
    // takes). `values` are C's in its order, [amount_in, direction,
    // recipient, outcome_key, outcome_tag], every one shared (the layout
    // secret-shared on-chain intake takes too), and `sharing` their summand
    // vectors with the blinding's last (`test_shared_receipt`).
    #[external("private")]
    fn request_shared(values: [Field; 5], sharing: Sharing<6>, expiry_block: u32, receipts: [Receipt; 3]) {
        let round: Row<_, 1, 1> = TipRound::one(
            self.storage.outcome_vk_hash.read(),
            self.storage.config.read(),
            self.storage.held,
        );
        let request_id = shared_receipt_request(
            self.context,
            round,
            crate::test_shared_onchain::LAYOUT,
            values,
            sharing,
            expiry_block,
            receipts,
            crate::valid_inputs,
        );
        self.enqueue_self.append_receipt(request_id, expiry_block);
    }

    // Secret-shared on-chain intake: the request log of the encoded shares under
    // the nodes' keys at the anchor, the data hash and the epochs to the
    // public wrapper, under the private-outcome round's row. `values` are C's
    // in its order, [amount_in, direction, recipient, outcome_key,
    // outcome_tag], every one the user's (`test_shared_onchain`).
    #[external("private")]
    fn request_shared_onchain(values: [Field; 5], eph: Field) {
        let round: Row<_, 1, 1> = TipRound::one(
            self.storage.outcome_vk_hash.read(),
            self.storage.config.read(),
            self.storage.held,
        );
        let r = shared_onchain_request(
            self.context,
            round,
            self.storage.shared_onchain.get_storage_slot(),
            crate::test_shared_onchain::LAYOUT,
            values,
            eph,
            crate::valid_inputs,
        );
        self.enqueue_self.append_onchain_shared(r.request_id, r.data_hash, r.epochs);
    }

    #[external("public")]
    #[only_self]
    fn append_onchain_shared(request_id: Field, data_hash: Field, epochs: [u32; 3]) {
        let _ = self.storage.shared_onchain.append(self.storage.queue, request_id, data_hash, epochs);
    }

    // A node's enc key rotation: its signature checked here under its sig
    // key of the current key epoch, the epoch at the public write.
    #[external("private")]
    fn rotate_enc_key(i: u32, key: EncKey, signature: Receipt) {
        check_enc_rotation::<Keys>(self.context, self.storage.config.read(), i, key, signature);
        self.enqueue_self.set_enc_key(i, key);
    }

    // The key epochs (`key_epoch`): a new key set signed by two of the
    // current nodes, installed at the stored epoch + 1, voiding a replaced
    // node's enc key in `shared_onchain`; and the grace window check every
    // signature-verifying function enqueues.
    #[external("private")]
    fn rotate_keys(epoch: u32, keys: KeySet, signatures: [ResultSignature; 3]) {
        let node_keys =
            key_epoch::check_rotation(self.context, self.storage.config.read(), epoch, keys, signatures);
        self.enqueue_self.set_node_keys(node_keys);
    }

    #[external("public")]
    #[only_self]
    fn set_node_keys(node_keys: NodeKeys) {
        Keys::install(self.context, node_keys, self.storage.shared_onchain);
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
    #[only_self]
    fn set_enc_key(i: u32, key: EncKey) {
        self.storage.shared_onchain.rotate(i, key);
    }

    #[external("public")]
    #[view]
    fn get_enc_key(i: u32) -> EncKey {
        self.storage.shared_onchain.enc_key(i)
    }

    #[external("public")]
    #[view]
    fn get_data_hash(request_id: Field) -> Field {
        self.storage.shared_onchain.data_hash(request_id)
    }

    #[external("private")]
    fn request(request_id: Field) {
        self.enqueue_self.append(request_id);
    }

    #[external("public")]
    #[only_self]
    fn append(request_id: Field) {
        let _ = self.storage.queue.append(request_id);
    }

    #[external("public")]
    fn skip() {
        let _ = self.storage.queue.skip(self.storage.config.read().stale_blocks);
    }

    /// The library's state view, as a tip app's `get_state` returns it, so
    /// pss_tip_test's `QueueReader` reads this contract as it reads an app:
    /// the Config, no configured head (this contract has no `configure`, so
    /// all zero), the queue's head and tail, the four commitment
    /// slots (`pool`, `book`, `fresh`, `held`) with their keys, and the
    /// outcome notes' slot.
    #[external("public")]
    #[view]
    fn get_state() -> TipState<TipConfig, 4, Keys, FixedCircuits> {
        let s = self.storage;
        TipState {
            config: s.config.read(),
            configured: std::mem::zeroed(),
            head: s.queue.get_head(),
            tail: s.queue.get_tail(),
            commitments: [s.pool.read(), s.book.read(), s.fresh.read(), s.held.read()],
            state_keys: [
                s.pool.get_storage_slot(),
                s.book.get_storage_slot(),
                s.fresh.get_storage_slot(),
                s.held.get_storage_slot(),
            ],
            outcome_slot: s.partial_outcomes.get_storage_slot(),
            node_keys: KeyEpochs {},
            upgrades: FixedCircuits {},
        }
    }

    #[external("public")]
    #[view]
    fn get_head() -> Head {
        self.storage.queue.get_head()
    }

    #[external("public")]
    #[view]
    fn get_tail() -> u64 {
        self.storage.queue.get_tail()
    }

    #[external("public")]
    #[view]
    fn request_at(index: u64) -> Field {
        self.storage.queue.request_at(index)
    }

    #[external("public")]
    #[view]
    fn is_seen(request_id: Field) -> bool {
        self.storage.queue.is_seen(request_id)
    }

    #[external("public")]
    #[view]
    fn done_at(index: u64) -> u8 {
        self.storage.queue.done_at(index)
    }

    #[external("public")]
    #[view]
    fn get_pool() -> Field {
        self.storage.pool.read()
    }

    #[external("public")]
    #[view]
    fn get_book() -> Field {
        self.storage.book.read()
    }

    #[external("public")]
    #[view]
    fn get_fresh() -> Field {
        self.storage.fresh.read()
    }

    #[external("public")]
    #[view]
    fn get_held() -> Field {
        self.storage.held.read()
    }

    // The escape hatch's bodies (`test_hatch.nr`), as an app's request
    // wrappers, landings, `open_hatch()` and `exit` call them. A test drives
    // the clock and the tags directly; an app passes a landing's
    // proof-bound tags.
    #[external("public")]
    fn hatch_queued() {
        self.storage.hatch.queued();
    }

    #[external("public")]
    fn hatch_landed(served: bool, tags: [Field; 2]) {
        self.storage.hatch.landed(self.storage.queue, served, tags);
    }

    #[external("public")]
    fn hatch_open(t_live: u32) {
        self.storage.hatch.open(t_live);
    }

    #[external("public")]
    #[view]
    fn get_hatch() -> HatchState {
        self.storage.hatch.state()
    }

    // The exit on `owner`'s first completed note (`PartialOutcome`, whose
    // amount stands for the entry it names), by the sender.
    #[external("private")]
    fn hatch_exit(owner: AztecAddress) {
        let notes = self.storage.partial_outcomes.at(owner).get_notes(NoteGetterOptions::new().set_limit(1));
        assert(notes.len() == 1, "no completed note to exit on");
        self.storage.hatch.exit(notes.get(0), self.msg_sender());
    }

    #[external("public")]
    fn set_oracle(pin: OraclePin) {
        self.storage.oracle.initialize(pin);
    }

    #[external("public")]
    fn set_init_vk_hash(vk_hash: Field) {
        self.storage.init_vk_hash.initialize(vk_hash);
    }

    #[external("public")]
    fn set_outcome_vk_hash(vk_hash: Field) {
        self.storage.outcome_vk_hash.initialize(vk_hash);
    }

    // The pool round's result, whichever non-secret-shared intake queued its request.
    #[external("private")]
    fn process_result(result: PoolResult, sealed: PoolThirds, signatures: [ResultSignature; 3]) {
        let round: Row<_, 1, 1> = TipRound::one(
            self.storage.vk_hash.read(),
            self.storage.config.read(),
            self.storage.pool,
        );
        let checked = check_round(
            round,
            self.context,
            self.msg_sender(),
            result,
            sealed,
            signatures,
        );
        self.enqueue_self.apply(checked, sealed);
    }

    // The wide round, under the pool round's vk hash: the table's
    // `wide_round`, keys read [book, pool], written [pool, book, fresh].
    #[external("private")]
    fn process_result_wide(round: WideResult, signatures: [ResultSignature; 3]) {
        let row = wide_round(
            self.storage.vk_hash.read(),
            self.storage.config.read(),
            self.storage.pool,
            self.storage.book,
            self.storage.fresh,
        );
        let checked = check_round(
            row,
            self.context,
            self.msg_sender(),
            round,
            NodeHeld {},
            signatures,
        );
        self.enqueue_self.apply_wide(checked);
    }

    #[external("public")]
    #[only_self]
    fn apply(result: PoolResult, sealed: PoolThirds) {
        // immutable, so reading it before the pinned call is safe
        let oracle = self.storage.oracle.read();
        let pinned = [
            PinnedRead {
                target: oracle.target,
                selector: FunctionSelector::from_field(oracle.selector),
                args: [],
                l2_gas: oracle.l2_gas,
                freshness: Freshness::exact(),
            },
        ];
        let applied = apply_round(
            self.context,
            self.storage.queue,
            pinned,
            StateKeys::one(self.storage.pool),
            result,
            sealed,
        );
        // the app hook: storage only
        self.storage.outputs.at(applied.index).write(applied.app_outputs);
    }

    // Chain-held state: the init round creates `pool`, outside the queue; the
    // nodes sign over its first thirds and `apply_init_pool` logs them under
    // the init request id.
    #[external("private")]
    fn init_pool(new_c: Field, sealed: PoolThirds, signatures: [ResultSignature; 3]) {
        let round: Row<_, 0, 1> = TipRound {
            vk_hash: self.storage.init_vk_hash.read(),
            tip: self.storage.config.read(),
            state_keys: StateKeys::create([self.storage.pool]),
        };
        let request_id = process_init(
            round,
            self.context,
            self.msg_sender(),
            POOL_INIT_INPUTS,
            [new_c],
            [],
            sealed,
            signatures,
        );
        self.enqueue_self.apply_init_pool(request_id, new_c, sealed);
    }

    #[external("public")]
    #[only_self]
    fn apply_init_pool(request_id: Field, new_c: Field, sealed: PoolThirds) {
        apply_init(
            self.context,
            StateKeys::create([self.storage.pool]),
            request_id,
            [new_c],
            sealed,
        );
    }

    // Chain-held private outcomes: the private-outcome round over `pool`,
    // under the outcome circuit's vk hash, with no pinned read; the nodes sign
    // over the round's thirds and `apply_private_sealed` logs them after its
    // write.
    #[external("private")]
    fn process_result_private_sealed(result: OutcomeRound, sealed: PoolThirds, signatures: [ResultSignature; 3]) {
        let round: Row<_, 1, 1> = TipRound::one(
            self.storage.outcome_vk_hash.read(),
            self.storage.config.read(),
            self.storage.pool,
        );
        let apply = check_round(
            round,
            self.context,
            self.msg_sender(),
            // the tests hash each completed note at the set's own slot
            Private::of(result, self.storage.partial_outcomes.get_storage_slot(), self.storage.partial_outcomes.get_storage_slot()),
            sealed,
            signatures,
        );
        self.enqueue_self.apply_private_sealed(apply, sealed);
    }

    #[external("public")]
    #[only_self]
    fn apply_private_sealed(apply: OutcomeApplyRound, sealed: PoolThirds) {
        let _ = apply_round(
            self.context,
            self.storage.queue,
            no_pinned_reads(),
            StateKeys::one(self.storage.pool),
            apply,
            sealed,
        );
    }

    // ---- partial-note delivery (test_partial.nr) ---------------------------
    //
    // A non-secret-shared request under the public completion: the request
    // function commits the partial note from `owner` and `rho` (pushing its
    // use nullifier), tells the owner's PXE of it offchain, and queues the
    // chain request id over the inputs `[app_inputs…, P]` under the
    // node-held round's vk hash; `process_result_partial` and
    // `apply_partial` land the result and complete the note in public.
    //
    // `chained`: the request opens a completed note of `owner`'s (read with
    // its inclusion check, not nullified), requires it to be the sender's and
    // to report success (`code = 0`), and commits the next partial note to
    // the same owner; the round never sees an owner. A non-zero `escrow`: a
    // second partial note, the refund, committed under `rho_refund` and
    // recorded by the public wrapper beside the queue entry with the
    // escrowed amount; `skip_refunding` completes it for the full amount,
    // `apply_partial` for none (the round's note carries the settlement).
    // (One function for the three cases here; an app writes one per round
    // type.)
    #[external("private")]
    fn request_partial(
        app_inputs: [Field; 2],
        owner: AztecAddress,
        rho: Field,
        user_nonce: Field,
        chained: bool,
        rho_refund: Field,
        escrow: Field,
    ) {
        if chained {
            let notes = self.storage.partial_outcomes.at(owner).get_notes(NoteGetterOptions::new().set_limit(1));
            assert(notes.len() == 1, "no completed note to chain from");
            let held = notes.get(0);
            partial_note::assert_owned(held, self.msg_sender());
            assert(held.note.code == 0, "the note does not report success");
        }
        let p = partial_note::commit(self.context, owner, rho);
        partial_note::deliver_partial_note::<PartialOutcome, _>(self.context, owner, rho, p, MessageDelivery::offchain());
        let mut refund = 0;
        if escrow != 0 {
            refund = partial_note::commit(self.context, owner, rho_refund);
            partial_note::deliver_partial_note::<PartialOutcome, _>(
                self.context,
                owner,
                rho_refund,
                refund,
                MessageDelivery::offchain(),
            );
        }
        let id = chain_request_id(
            self.context.this_address(),
            self.storage.held_vk_hash.read(),
            inputs_hash(app_inputs.concat([p])),
            user_nonce,
        );
        self.enqueue_self.append_escrow(id, Escrow { refund_note: refund, amount: escrow });
    }

    #[external("public")]
    #[only_self]
    fn append_escrow(request_id: Field, escrow: Escrow) {
        let index = self.storage.queue.append(request_id);
        self.storage.outputs.at(ESCROW_AT + index).write([escrow.refund_note, escrow.amount]);
    }

    // `skip()` with refunds: the skipped request's escrow is completed in
    // public for its full amount.
    #[external("public")]
    fn skip_refunding() {
        let index = self.storage.queue.skip(self.storage.config.read().stale_blocks);
        let request_id = self.storage.queue.request_at(index);
        let escrow = self.storage.outputs.at(ESCROW_AT + index).read();
        if escrow[0] != 0 {
            partial_note::complete_in_public(
                self.context,
                self.storage.partial_outcomes.get_storage_slot(),
                escrow[0],
                [0, escrow[1]],
                request_id,
            );
        }
    }

    // A secret-shared request under the private completion: the partial
    // note committed the same way (no message: the client delivers the
    // completed note itself), `C = poseidon2([app_inputs…, P, outcome_key,
    // outcome_tag, blinding])` and the secret-shared chain request id under
    // the outcome circuit's vk hash. (The receipts and the static validity
    // are `test_shared_receipt.nr`'s.)
    #[external("private")]
    fn request_partial_private(
        app_inputs: [Field; 2],
        owner: AztecAddress,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        blinding: Field,
    ) {
        let p = partial_note::commit(self.context, owner, rho);
        let c = inputs_commitment(app_inputs.concat([p, outcome_key, outcome_tag]), blinding);
        let id = shared_chain_request_id(
            self.context.this_address(),
            self.storage.outcome_vk_hash.read(),
            c,
        );
        self.enqueue_self.append(id);
    }

    // The public completion's result over `held`, under the node-held
    // round's vk hash, with the request's partial note after `ok`.
    #[external("private")]
    fn process_result_partial(result: PartialHeldResult, signatures: [ResultSignature; 3]) {
        let round: Row<_, 1, 1> = TipRound::one(
            self.storage.held_vk_hash.read(),
            self.storage.config.read(),
            self.storage.held,
        );
        let checked = check_round(round, self.context, self.msg_sender(), result, NodeHeld {}, signatures);
        self.enqueue_self.apply_partial(checked);
    }

    // Lands the result and completes its partial note in
    // `partial_outcomes`, on every round; a request with an escrow also has
    // its refund note completed, for none.
    #[external("public")]
    #[only_self]
    fn apply_partial(result: PartialHeldResult) {
        let applied = apply_round(
            self.context,
            self.storage.queue,
            no_pinned_reads(),
            StateKeys::one(self.storage.held),
            result.completing(self.storage.partial_outcomes.get_storage_slot()),
            NodeHeld {},
        );
        let escrow = self.storage.outputs.at(ESCROW_AT + applied.index).read();
        if escrow[0] != 0 {
            partial_note::complete_in_public(
                self.context,
                self.storage.partial_outcomes.get_storage_slot(),
                escrow[0],
                [0, 0],
                applied.request_id,
            );
        }
    }

    /// The outcome-note utility under the private completion: hand the PXE
    /// the completed note `[code, amount, request_id]` of `owner`, with the
    /// request's `rho`, from transaction `tx`.
    #[external("utility")]
    unconstrained fn deliver_partial_outcome(owner: AztecAddress, rho: Field, packed: [Field; 3], tx: OutcomeTx) {
        deliver_outcome_note(
            self.context.this_address(),
            _compute_note_hash,
            _compute_note_nullifier,
            PartialOutcome::get_id(),
            owner,
            self.storage.partial_outcomes.get_storage_slot(),
            rho,
            packed,
            tx,
        );
    }

    // Spend a chained note's value once: the redeem nullifier over the
    // sender's first completed note, which stays readable.
    #[external("private")]
    fn redeem(owner: AztecAddress) {
        let notes = self.storage.partial_outcomes.at(owner).get_notes(NoteGetterOptions::new().set_limit(1));
        assert(notes.len() == 1, "no completed note to redeem");
        partial_note::redeem(self.context, notes.get(0), self.msg_sender());
    }

    /// The storage slot of the completed notes.
    #[external("utility")]
    unconstrained fn partial_slot() -> Field {
        self.storage.partial_outcomes.get_storage_slot()
    }

    /// The completed notes `owner`'s PXE holds.
    #[external("utility")]
    unconstrained fn partial_notes(owner: AztecAddress) -> PartialOutcomes {
        let notes = self.storage.partial_outcomes.at(owner).view_notes(NoteViewerOptions::new());
        let none = PartialOutcome { code: 0, amount: 0, request_id: 0 };
        let first = if notes.len() > 0 { notes.get(0) } else { none };
        let second = if notes.len() > 1 { notes.get(1) } else { none };
        PartialOutcomes { count: notes.len(), first, second }
    }

    #[external("public")]
    #[only_self]
    fn apply_wide(round: WideResult) {
        let oracle = self.storage.oracle.read();
        let get_value = comptime { FunctionSelector::from_signature("get_value(Field)") };
        let pinned = [
            PinnedRead::new(oracle.target, get_value, [1]),
            PinnedRead::new(oracle.target, get_value, [2]),
        ];
        let state_keys = wide_round(
            self.storage.vk_hash.read(),
            self.storage.config.read(),
            self.storage.pool,
            self.storage.book,
            self.storage.fresh,
        )
            .state_keys;
        let applied = apply_round(
            self.context,
            self.storage.queue,
            pinned,
            state_keys,
            round,
            NodeHeld {},
        );
        self.storage.outputs.at(applied.index).write([applied.app_outputs[0], 0]);
    }

    // Node-held state: the init round creates `held`, outside the queue.
    #[external("private")]
    fn init_held(new_c: Field, signatures: [ResultSignature; 3]) {
        let round: Row<_, 0, 1> = TipRound {
            vk_hash: self.storage.init_vk_hash.read(),
            tip: self.storage.config.read(),
            state_keys: StateKeys::create([self.storage.held]),
        };
        let request_id = process_init(
            round,
            self.context,
            self.msg_sender(),
            HELD_INIT_INPUTS,
            [new_c],
            [],
            NodeHeld {},
            signatures,
        );
        self.enqueue_self.apply_init_held(request_id, new_c);
    }

    #[external("public")]
    #[only_self]
    fn apply_init_held(request_id: Field, new_c: Field) {
        apply_init(
            self.context,
            StateKeys::create([self.storage.held]),
            request_id,
            [new_c],
            NodeHeld {},
        );
    }

    // Node-held state: a round over `held`, under its own circuit's vk hash,
    // with no pinned read.
    #[external("private")]
    fn process_result_held(result: HeldResult, signatures: [ResultSignature; 3]) {
        let round: Row<_, 1, 1> = TipRound::one(
            self.storage.held_vk_hash.read(),
            self.storage.config.read(),
            self.storage.held,
        );
        let checked = check_round(
            round,
            self.context,
            self.msg_sender(),
            result,
            NodeHeld {},
            signatures,
        );
        self.enqueue_self.apply_held(checked);
    }

    #[external("public")]
    #[only_self]
    fn apply_held(result: HeldResult) {
        let applied = apply_round(
            self.context,
            self.storage.queue,
            no_pinned_reads(),
            StateKeys::one(self.storage.held),
            result,
            NodeHeld {},
        );
        self.storage.outputs.at(applied.index).write(applied.app_outputs);
    }

    // Private outcomes: a secret-shared-intake round over `held`, under the outcome
    // circuit's vk hash, with no pinned read; the outcome is the completed
    // note's hash and the outcome log, and `apply_private` writes
    // the new commitment whatever the outcome.
    #[external("private")]
    fn process_result_private(result: OutcomeRound, signatures: [ResultSignature; 3]) {
        let round: Row<_, 1, 1> = TipRound::one(
            self.storage.outcome_vk_hash.read(),
            self.storage.config.read(),
            self.storage.held,
        );
        let apply = check_round(
            round,
            self.context,
            self.msg_sender(),
            // the tests hash each completed note at the set's own slot
            Private::of(result, self.storage.partial_outcomes.get_storage_slot(), self.storage.partial_outcomes.get_storage_slot()),
            NodeHeld {},
            signatures,
        );
        self.enqueue_self.apply_private(apply);
    }

    #[external("public")]
    #[only_self]
    fn apply_private(apply: OutcomeApplyRound) {
        let _ = apply_round(
            self.context,
            self.storage.queue,
            no_pinned_reads(),
            StateKeys::one(self.storage.held),
            apply,
            NodeHeld {},
        );
    }

    #[external("public")]
    fn set_price(price: Field) {
        self.storage.price.write(price);
    }

    #[external("public")]
    fn set_reentry(target: AztecAddress, mode: u8) {
        self.storage.reenter_target.write(target);
        self.storage.reenter_mode.write(mode);
    }

    #[external("public")]
    fn set_burn(l2_gas: u32) {
        self.storage.burn.write(l2_gas);
    }

    // The pinned read. `apply` calls it statically, so any call it makes is
    // static too: a re-entrant `skip()` from here meets the AVM's static-call
    // rule at its first storage write.
    #[external("public")]
    #[view]
    fn get_price() -> Field {
        let price = self.storage.price.read();
        let mode = self.storage.reenter_mode.read();
        if mode == REENTER_PROPAGATE {
            self.call(PssPublicTest::at(self.storage.reenter_target.read()).skip());
            price
        } else if mode == REENTER_SWALLOW {
            let skip = PssPublicTest::at(self.storage.reenter_target.read()).skip();
            if attempt(skip, REENTRANT_SKIP_L2_GAS, REENTRANT_SKIP_DA_GAS) {
                price + 1
            } else {
                price
            }
        } else if mode == READ_REVERT {
            assert(false, "the oracle reverts");
            price
        } else if mode == READ_BURN {
            burn_l2_gas(self.context, self.storage.burn.read());
            price
        } else {
            price
        }
    }

    // The wide round's two pinned reads: the price plus `k`.
    #[external("public")]
    #[view]
    fn get_value(k: Field) -> Field {
        self.storage.price.read() + k
    }

    // A read target that returns no field, and one that returns two.
    #[external("public")]
    #[view]
    fn get_none() {}

    #[external("public")]
    #[view]
    fn get_pair() -> [Field; 2] {
        let price = self.storage.price.read();
        [price, price]
    }

    // ---- the freshness policies (test-only, `test_freshness.nr`) ---------
    //
    // An epoch source, and two check entries that make this contract's own
    // reads pinned under a policy (`assert_pinned_reads`), as `apply` does.

    /// Open a new epoch at `value`: the current value becomes the previous
    /// one, the epoch counts up.
    #[external("public")]
    fn open_epoch(value: Field) {
        self.storage.epoch_previous.write(self.storage.epoch_value.read());
        self.storage.epoch_value.write(value);
        self.storage.epoch.write(self.storage.epoch.read() + 1);
    }

    /// The epoch source's read: [value, epoch, previous].
    #[external("public")]
    #[view]
    fn get_epoch_value() -> [Field; 3] {
        [
            self.storage.epoch_value.read(),
            self.storage.epoch.read(),
            self.storage.epoch_previous.read(),
        ]
    }

    /// Pin `get_price()` under `freshness` (exact or a tolerance) at
    /// `value`: reverts as `apply` would.
    #[external("public")]
    #[view]
    fn check_pinned(freshness: Freshness, value: Field) {
        let selector = comptime { FunctionSelector::from_signature("get_price()") };
        let read = PinnedRead::new(self.address, selector, []).with_freshness(freshness);
        assert_pinned_reads(self.context, [read], [value]);
    }

    /// Pin `get_epoch_value()` as an epoch read at `value` and `epoch`.
    #[external("public")]
    #[view]
    fn check_pinned_epoch(value: Field, epoch: Field) {
        let selector = comptime { FunctionSelector::from_signature("get_epoch_value()") };
        let read = PinnedRead::new(self.address, selector, []).with_freshness(Freshness::epoch());
        assert_pinned_reads(self.context, [read], [value, epoch]);
    }

    /// The app outputs `apply` stored at a queue index, under the name of a
    /// tip app's per-index outcome view.
    #[external("public")]
    #[view]
    fn outcome_at(index: u64) -> [Field; 2] {
        self.storage.outputs.at(index).read()
    }

    // ---- probes (test-only) ----------------------------------------------
    //
    // Test-only, never in an app: each probe makes one call
    // of the contract at `target` as a nested call and returns whether it
    // succeeded, so a test sees a refusal and then reads the state in the
    // same test. Called on `target` itself, the nested call's msg_sender is
    // the contract, so `#[only_self]` passes and the probe reaches the
    // library's own checks; called from another instance, it meets
    // `#[only_self]`. A probe is a public function anyone may call, so it
    // would let anyone run `apply` without `process_result` or `append`
    // without intake: an app that kept one would have no queue rules left.

    #[external("public")]
    fn try_append(target: AztecAddress, request_id: Field) -> bool {
        attempt(PssPublicTest::at(target).append(request_id), PROBE_L2_GAS, PROBE_DA_GAS)
    }

    #[external("public")]
    fn try_append_onchain(target: AztecAddress, request_id: Field, plain: PlainRequest<2>) -> bool {
        attempt(PssPublicTest::at(target).append_onchain(request_id, plain), PROBE_L2_GAS, PROBE_DA_GAS)
    }

    #[external("public")]
    fn try_append_receipt(target: AztecAddress, request_id: Field, expiry_block: u32) -> bool {
        attempt(PssPublicTest::at(target).append_receipt(request_id, expiry_block), PROBE_L2_GAS, PROBE_DA_GAS)
    }

    #[external("public")]
    fn try_append_onchain_shared(target: AztecAddress, request_id: Field, data_hash: Field, epochs: [u32; 3]) -> bool {
        attempt(
            PssPublicTest::at(target).append_onchain_shared(request_id, data_hash, epochs),
            PROBE_L2_GAS,
            PROBE_DA_GAS,
        )
    }

    #[external("public")]
    fn try_set_enc_key(target: AztecAddress, i: u32, key: EncKey) -> bool {
        attempt(PssPublicTest::at(target).set_enc_key(i, key), PROBE_L2_GAS, PROBE_DA_GAS)
    }

    #[external("public")]
    fn try_skip(target: AztecAddress) -> bool {
        attempt(PssPublicTest::at(target).skip(), PROBE_L2_GAS, PROBE_DA_GAS)
    }

    #[external("public")]
    fn try_apply(target: AztecAddress, result: PoolResult, sealed: PoolThirds) -> bool {
        attempt(PssPublicTest::at(target).apply(result, sealed), PROBE_L2_GAS, PROBE_DA_GAS)
    }

    #[external("public")]
    fn try_apply_wide(target: AztecAddress, round: WideResult) -> bool {
        attempt(PssPublicTest::at(target).apply_wide(round), PROBE_L2_GAS, PROBE_DA_GAS)
    }

    #[external("public")]
    fn try_apply_held(target: AztecAddress, result: HeldResult) -> bool {
        attempt(PssPublicTest::at(target).apply_held(result), PROBE_L2_GAS, PROBE_DA_GAS)
    }

    #[external("public")]
    fn try_apply_private(target: AztecAddress, apply: OutcomeApplyRound) -> bool {
        attempt(PssPublicTest::at(target).apply_private(apply), PROBE_L2_GAS, PROBE_DA_GAS)
    }

    #[external("public")]
    fn try_apply_init_held(target: AztecAddress, request_id: Field, new_c: Field) -> bool {
        attempt(PssPublicTest::at(target).apply_init_held(request_id, new_c), PROBE_L2_GAS, PROBE_DA_GAS)
    }

    // ---- reading a settled transaction (test-only) -------------------------

    /// The requester audit of transaction `tx_hash` (pss_tip_test `audit`):
    /// fails when one of `accounts` appears anywhere in its effect; true
    /// otherwise. Any contract's suite calls it on a deployed instance.
    #[external("utility")]
    unconstrained fn tx_names_no_requester(tx_hash: Field, accounts: [AztecAddress; 4]) -> bool {
        assert_tx_names_no_requester(get_tx_effect(tx_hash).expect(f"no such transaction"), accounts);
        true
    }

    /// Every side effect of transaction `tx_hash`, counted by kind, with the
    /// heads of its public logs.
    #[external("utility")]
    unconstrained fn tx_summary(tx_hash: Field) -> TxSummary {
        summarize(get_tx_effect(tx_hash).expect(f"no such transaction"))
    }

    /// The fields after the tag of the sealed-thirds log that this contract
    /// emitted in transaction `tx_hash` under `tag` (the new commitment, then
    /// the three thirds: 16 fields), as the chain reader fetches it; fails if
    /// there is none.
    #[external("utility")]
    unconstrained fn sealed_log(tx_hash: Field, tag: Field) -> [Field; 16] {
        log_fields(get_tx_effect(tx_hash).expect(f"no such transaction"), self.address, tag)
    }

    /// The fields after the tag of the on-chain request log that this contract
    /// emitted in transaction `tx_hash` under `tag` (inputs, user_nonce: 3
    /// fields for two inputs); fails if there is none.
    #[external("utility")]
    unconstrained fn request_log(tx_hash: Field, tag: Field) -> [Field; 3] {
        log_fields(get_tx_effect(tx_hash).expect(f"no such transaction"), self.address, tag)
    }

    /// The fields after the tag of the completion log that this contract
    /// emitted in transaction `tx_hash` under `tag` (`[storage_slot, code,
    /// amount, request_id]`); fails if there is none.
    #[external("utility")]
    unconstrained fn completion_log(tx_hash: Field, tag: Field) -> [Field; 4] {
        log_fields(get_tx_effect(tx_hash).expect(f"no such transaction"), self.address, tag)
    }
}
