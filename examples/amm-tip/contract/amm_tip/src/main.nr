use aztec::macros::aztec;

pub mod app;
pub mod class;
pub mod layouts;

/// How to read this contract: it carries every intake so that each can be
/// seen and run from one place, and a deployment's manifests select which it
/// uses. That is the example's choice. An app picks one intake
/// (docs/design-guide/README.md) and declares only the entry points of the
/// bricks it picked.
///
/// The AMM at the tip of the chain: a constant-product pool whose reserves
/// are private shared state held by the network in state mode `node`
/// (docs/ARCHITECTURE.md section 6, "The examples on node-held state"): the
/// three nodes keep the
/// pool as Rep3 pairs, versioned by commitment, and the chain holds only the
/// commitment. The pool is one machine key whose commitment lives in the
/// public slot `pool`; swaps are queued requests that the network serves in queue
/// order, each proved by a total circuit, so a swap that cannot trade still
/// lands. Every swap delivers by partial-note completion: the trader's
/// request commits a partial note from its own address and its client's
/// randomness, and the network completes it with `[code, amount_out,
/// request_id]`, so the trader's note lands with the result under an owner
/// nobody but the trader sees; the trader spends it with `redeem`. Under the
/// non-secret-shared intakes the round's outputs are public (a swap that
/// cannot trade lands as a no-op with `ok = 0` and a code) and `apply`
/// completes the note in public; under secret-shared receipt intake every
/// request input is secret-shared and the outcome is private: the round
/// completes the note inside the co-SNARK, and the result transaction lands
/// the completed note and an encrypted log for the trader, with no amount
/// or owner shown to the nodes, the orchestrator or the relayer;
/// secret-shared on-chain intake queues the same secret-shared swap with
/// no off-chain step (the encoded shares in a private log, the nodes' `enc`
/// keys in this contract's storage). A deployment lists the init and one
/// entry of the swap, non-secret-shared or secret-shared (one intake family per key); a secret-shared
/// deployment may register the secret-shared swap under both secret-shared intakes.
///
/// Functions:
/// - `constructor(config, upgrade_authority)`: the pins that do not depend
///   on the namespace (`Config`: the stale period, the node `sig` keys and
///   the circuit pins: the contract manifest's hash, the package list and
///   each package's vk hash, so the address commits to the circuits and the
///   manifest) and the address that may upgrade the circuits;
/// - `upgrade_circuits(circuits)`: the upgrade authority schedules new
///   circuit pins, in force one day later (`UPGRADE_DELAY`); every round
///   function verifies under the pins in force at its anchor block and
///   enqueues `assert_upgrade_class`, which refuses pins of another class
///   than the one running;
/// - `upgrade_contract(new_class_id, circuits)`: the upgrade authority
///   schedules the instance's move to another contract class and the pins
///   that belong to it, both in force one day later; `get_class_version`
///   says which build of this contract runs (`class`);
/// - `configure(npk_app_hash, answer)`: once, anyone, after the contract
///   manifest was registered under this address: checks the three nodes'
///   signatures of its REGISTER answer over the constructor's manifest hash
///   and package list and stores `npk_app_hash` beside the constructor's pins
///   (pss_public_contract `configure`); every function below refuses until
///   it has landed;
/// - `init_pool(new_c, signatures)`: lands the `amm_init_tip` round once,
///   outside the queue, while the pool slot is empty; the scheduler sends
///   the round once `configure` has landed;
/// - `swap(amount_in, direction, min_out, rho, user_nonce)`: on-chain
///   intake: the partial note is committed from the sender and `rho` (its
///   use nullifier pushed) and told to the sender's PXE offchain, and the
///   inputs `[amount_in, direction, min_out, P]` go to the chain in the
///   request log;
/// - `swap_with_receipts(amount_in, direction, min_out, rho, user_nonce,
///   expiry_block, receipts)`: receipt intake: the same partial note, three
///   node receipts checked here, the inputs off the chain;
/// - `process_result(round, signatures)`: verifies one swap's result,
///   whichever non-secret-shared intake queued it (one compiled circuit, `amm_swap_tip`,
///   serves both), and enqueues `apply`, which lands it and completes the
///   trader's partial note in public;
/// - `swap_shared(amount_in, direction, min_out, rho, outcome_key,
///   outcome_tag, sharing, expiry_block, receipts)`: secret-shared receipt
///   intake: the partial note is committed from the sender and `rho` (its
///   use nullifier pushed), three node receipts over the inputs commitment
///   C are checked here, and only the request id and the expiry block reach
///   the chain, through the same public wrapper as receipt intake's;
/// - `swap_shared_onchain(amount_in, direction, min_out, rho, outcome_key,
///   outcome_tag, eph)`: secret-shared on-chain intake (the outcome key
///   and tag derived by the client, chosen in the encoding), the same
///   round (one compiled circuit, `amm_swap_tip_shared`, which the network
///   also registers as `amm_swap_tip_shared_onchain`): the request function
///   reads the nodes' `enc` keys at its anchor block, puts the encoded
///   shares in one private log and enqueues `append_onchain_shared` with the
///   request id, the log's hash and the epochs it names;
///   `rotate_enc_key(i, key, signature)` sets node i's key in this contract
///   (its signature under its pinned `sig` key, the epoch the stored one +
///   1), and `get_enc_key`, `get_data_hash` read them back;
/// - `process_result_shared(result, signatures)`: verifies one secret-shared
///   swap's result (`amm_swap_tip_shared`, whichever secret-shared intake queued
///   it), lands its completed note and outcome log, and enqueues
///   `apply_shared`, which writes the pool's new commitment and finishes the
///   head; it makes no call into another contract;
/// - `redeem(request_id)`: the trader spends its completed note of that
///   request once (the note nullified) and takes its `amount_out`;
/// - `skip()`: anyone drops a head older than `stale_blocks`;
/// - `get_state()`, one view of every read that takes no argument (the
///   library's `TipState`) and the per-index views `request_at` and
///   `done_at`;
///   `log_in_tx`, a utility that reads this contract's log under a tag (the
///   on-chain intake request log, or `apply`'s completion log), the outcome-note
///   utility `deliver_outcome` and `swap_notes`, the notes an owner's PXE
///   holds.
///
/// Every function is one call into pss_public_contract's app skeleton over
/// the round table (`app::rounds`, one row per package name); the app's
/// own parts are in `app`: the package names, the Config pins,
/// `valid_swap` and the `SwapOutcomeNote`.
///
/// No token moves: the completed note is the trader's credit, and `redeem`
/// spends it. With a real token the AMM's public balance pays the amount into a
/// token partial note of the trader's at `redeem` (public custody and the
/// user's own redeem, docs/DECISIONS.md section 10, "Token custody is public,
/// settled by the user's own redeem"), never in the result transaction.
///
/// Trust model: semi-honest MPC (collusion of the nodes reveals the
/// reserves); the chain trusts the proofs and the three node signatures,
/// never the operator or the relayer, who can only delay.
#[aztec]
pub contract AmmTip {
    use crate::app::{
        Config, init_state_keys, Keys, UPGRADE_DELAY, MAX_LOG_FIELDS, OUTCOME_SLOT, PACKAGES, PLAIN_SWAP_INPUTS, pool_state_keys, rounds, SwapNotes,
        SwapOutcomeNote, SwapResult, SwapSharedApply, SwapSharedResult, valid_plain_swap,
        valid_swap,
    };
    use crate::layouts::{AMM_SWAP_TIP_SHARED_LAYOUT, AMM_SWAP_TIP_SHARED_ONCHAIN_LAYOUT};
    use aztec::messages::delivery::MessageDelivery;
    use aztec::macros::{
        functions::{external, initializer, internal, only_self, view}, storage::storage,
    };
    use aztec::note::{
        note_getter_options::NoteGetterOptions, note_interface::NoteProperties,
        note_viewer_options::NoteViewerOptions,
    };
    use aztec::protocol::address::AztecAddress;
    use aztec::state_vars::{Owned, PrivateSet, PublicImmutable, StateVariable};
    use aztec::utils::comparison::Comparator;
    use pss_public_contract::{
        apply_round, assert_ready, check_enc_rotation, check_round, CircuitPins, CircuitsInForce, CircuitUpgrades, CommitmentSlot, configure, Configured, EncKey, init, key_epoch, KeySet, logs,
        no_pinned_reads, NodeHeld, NodeKeys, onchain_request, PlainRequest, Queue, Receipt, receipt_request,
        outcome_request, ReceiptRequest, RegistryAnswer, SharedOnchain, SharedOnchainArgs, SharedOnchainRequest,
        SharedReceiptArgs, Sharing, stale_blocks_in_public, TipState,
        UpgradesContract,
    };
    use pss_public_contract::outcome::{deliver_outcome_into, OutcomeTx, Private};
    use pss_public_contract::partial_note;
    use pss_public_contract::result::ResultSignature;

    #[storage]
    struct Storage<Context> {
        // the swaps' completed notes, by owner (whoever committed the
        // request's partial note). The secret-shared round circuit hashes
        // each note at this slot (amm_tip shared.nr OUTCOME_SLOT, 1, which
        // `process_result_shared` checks is this slot) and `apply` completes
        // the non-secret-shared swap's note at it, so it comes first: its
        // slot does not move when the Config's size does.
        outcome_notes: Owned<PrivateSet<SwapOutcomeNote, Context>, Context>,
        // the constructor's pins
        config: PublicImmutable<Config, Context>,
        // configure's: the constructor's pins with npk_app_hash, which
        // every other function reads
        configured: PublicImmutable<Configured<PACKAGES>, Context>,
        queue: Queue<Context>,
        // The pool key. The machine key of the pool
        // ($state_keys.reads[0] and $state_keys.writes[0] in every manifest) is this
        // slot's storage slot, the Aztec "key = storage slot" mapping
        // that sidecar-tip's chain reader reads the commitment by; the
        // circuits bind it into old_c and new_c (in_slots, out_slots) and
        // the contract passes it for both, so a proof over another key does
        // not verify. The library takes the key from
        // the slot (`process_result_*` read its storage slot).
        //
        // 0 while the pool is uninitialised; written by `init_pool` once
        // and by `apply` on every ok swap.
        pool: CommitmentSlot<Context>,
        // secret-shared on-chain intake's storage (pss_public_contract
        // `shared_onchain`): the nodes' `enc` keys and epochs, and the hash
        // of each request's log; the machine's `shared_onchain_slot` is its
        // storage slot.
        shared_onchain: SharedOnchain<Context>,
        // The circuit pins upgrades schedule and the upgrade authority
        // (pss_public_contract `upgrades`); the contract manifest's
        // `storage.circuit_pins` is its storage slot. Last, so no other slot
        // moves.
        circuit_upgrades: CircuitUpgrades<PACKAGES, UPGRADE_DELAY, Context>,
    }

    #[external("public")]
    #[initializer]
    fn constructor(config: Config, upgrade_authority: AztecAddress) {
        config.tip.assert_valid();
        self.storage.config.initialize(config);
        self.storage.circuit_upgrades.init(upgrade_authority);
    }

    // -----------------------------------------------------------------------
    // Upgrades: the circuit pins in force, and their upgrade
    // -----------------------------------------------------------------------

    /// The stored `Configured` under the circuit pins in force, which every
    /// round function builds its round table row from: the upgraded pins
    /// once an upgrade took effect, the constructor's before.
    #[internal("private")]
    fn configured_in_force() -> Configured<PACKAGES> {
        // BRICK upgrades = contract (pss_public_contract::CircuitUpgrades::in_force), with upgrade_circuits,
        // upgrade_contract and assert_upgrade_class below. Alternatives: circuits (no upgrade_contract),
        // fixed (FixedCircuits: the stored Configured as it is; examples/credits-tip). docs/design-guide/BRICKS.md#upgrades
        self.storage.circuit_upgrades.in_force(self.storage.configured.read())
    }

    /// pss_public_contract::upgrades::CircuitUpgrades::upgrade_circuits:
    /// the upgrade authority schedules new circuit pins (the new contract
    /// manifest's hash, the package list and the vk hashes), in force after
    /// `UPGRADE_DELAY`.
    #[external("public")]
    fn upgrade_circuits(circuits: CircuitPins<PACKAGES>) {
        self.storage.circuit_upgrades.upgrade_circuits(self.msg_sender(), circuits);
    }

    /// pss_public_contract::upgrades::CircuitUpgrades::upgrade_contract:
    /// the upgrade authority schedules this instance's move to the
    /// registered class `new_class_id` and the pins of the contract manifest
    /// built for it, both in force after `UPGRADE_DELAY` (the instance's
    /// class-update delay is Aztec's default, the same day).
    #[external("public")]
    fn upgrade_contract(new_class_id: Field, circuits: CircuitPins<PACKAGES>) {
        self.storage.circuit_upgrades.upgrade_contract(self.msg_sender(), new_class_id, circuits);
    }

    /// pss_public_contract::upgrades::CircuitUpgrades::assert_class, which
    /// every round function enqueues (`configured_in_force`).
    #[external("public")]
    #[only_self]
    fn assert_upgrade_class(class_id: Field) {
        self.storage.circuit_upgrades.assert_class(class_id);
    }

    /// Which build of this contract runs: `class::CLASS_VERSION`, 1 here
    /// and 2 in the second class the e2e's class upgrade moves to, compiled
    /// from these sources (`class`).
    #[external("public")]
    #[view]
    fn get_class_version() -> Field {
        crate::class::CLASS_VERSION
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
    // Init: the amm_init_tip round, once, outside the queue
    // -----------------------------------------------------------------------

    /// Land the init round (the library's `process_init`, the never-queued init
    /// documented in pss_public_contract's `init`): verify the
    /// `amm_init_tip` proof (public inputs `[namespace, vk_hash, out_slots[0] =
    /// the pool key, request_id, old_c = 0, new_c, npk_app_hash]`) under the
    /// pinned init vk and the three nodes' result signatures over `new_c`
    /// (node-held: no sealed thirds, each message ending in 0), under the init
    /// request id (`init::init_request_id` with no inputs), then enqueue
    /// `apply_init`. The scheduler sends the round once `configure` has
    /// landed; the relayer stages the (vk, proof) capsule as for
    /// `process_result`.
    #[external("private")]
    fn init_pool(new_c: Field, signatures: [ResultSignature; 3]) {
        let round = rounds(self.internal.configured_in_force(), self.storage.pool).init;
        // BRICK state = node (pss_public_contract::NodeHeld), also in every result body below.
        // Alternatives: chain (chain_state's SealedThirds in its place). docs/design-guide/BRICKS.md#state
        let request_id = init::process_init(
            round,
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

    /// The public half of `init_pool`: write the first commitment while the
    /// slot is empty ("already initialised" otherwise). Logs nothing (the
    /// nodes hold the pool's first version under this commitment) and
    /// touches no queue storage.
    #[external("public")]
    #[only_self]
    fn apply_init(request_id: Field, new_c: Field) {
        init::apply_init(self.context, init_state_keys(self.storage.pool), request_id, [new_c], NodeHeld {});
    }

    // -----------------------------------------------------------------------
    // Intake
    // -----------------------------------------------------------------------

    /// On-chain intake (`intake: onchain`): queue a swap whose inputs and
    /// nonce go to the chain in the request log. The request commits the
    /// sender's partial note `P = partial_commitment(msg_sender, rho)`
    /// (`partial_note::commit`, its use nullifier pushed) and tells the
    /// sender's PXE of it offchain (`partial_note::deliver_partial_note`; the
    /// client hands the send result's offchain message to
    /// `offchain_receive`), so the PXE completes the note when `apply` emits
    /// its completion log. The inputs `[amount_in, direction, min_out, P]`
    /// go to the chain in the request log, followed by `user_nonce`: `P`
    /// hides the owner behind `rho`, and no request names its requester's
    /// address. Refused before anything is queued when the inputs fail
    /// `valid_swap`, and in the public part when the pool is not
    /// initialised or the request id was seen.
    ///
    /// DEV DECISION: how the request's partial-note message reaches the
    /// sender's PXE, default offchain (`MessageDelivery::offchain()`): no
    /// log, nothing on chain; a client that loses the message before the
    /// completion recovers the note by rescanning the completion tag from the
    /// re-derived `rho`. Alternative: `MessageDelivery::onchain_unconstrained()`
    /// (one more private log, DA gas), for a PXE that must recover from the
    /// chain alone. Design: docs/ARCHITECTURE.md section 6, "Completion in a public function".
    #[external("private")]
    fn swap(amount_in: Field, direction: Field, min_out: Field, rho: Field, user_nonce: Field) {
        let round = rounds(self.internal.configured_in_force(), self.storage.pool).swap;
        let partial = self.internal.commit_partial(rho);
        // BRICK intake = onchain (pss_public_contract::onchain_request). Alternatives:
        // receipt, shared_receipt, shared_onchain (the other entry points). docs/design-guide/BRICKS.md#intake
        let (request_id, plain) = onchain_request(
            self.context,
            round,
            [amount_in, direction, min_out, partial],
            user_nonce,
            valid_plain_swap,
        );
        self.enqueue_self.append_onchain(request_id, plain);
    }

    /// The sender's partial note from `rho`, its use nullifier pushed, and
    /// told to the sender's PXE offchain (the non-secret-shared swaps'
    /// public completion).
    #[internal("private")]
    fn commit_partial(rho: Field) -> Field {
        let sender = self.msg_sender();
        // BRICK value = partial (pss_public_contract::partial_note::commit), completed in public by apply.
        // Alternatives: none (no note). docs/design-guide/BRICKS.md#value
        let partial = partial_note::commit(self.context, sender, rho);
        partial_note::deliver_partial_note::<SwapOutcomeNote, _>(
            self.context,
            sender,
            rho,
            partial,
            MessageDelivery::offchain(),
        );
        partial
    }

    #[external("public")]
    #[only_self]
    fn append_onchain(request_id: Field, plain: PlainRequest<PLAIN_SWAP_INPUTS>) {
        assert_ready(self.context, self.storage.configured, self.storage.pool);
        let _ = self.storage.queue.append_onchain(request_id, plain);
    }

    /// Receipt intake (`intake: receipt`): queue a swap whose inputs
    /// `[amount_in, direction, min_out, P]` the three nodes signed receipts
    /// for; only the request id and the expiry block go to the chain. The
    /// partial note as `swap`. Refused when the inputs fail `valid_swap` or a
    /// receipt does not verify, and in the public part when the receipt has
    /// expired, the pool is not initialised or the request id was seen (a
    /// receipt is single-use).
    #[external("private")]
    fn swap_with_receipts(
        amount_in: Field,
        direction: Field,
        min_out: Field,
        rho: Field,
        user_nonce: Field,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        let round = rounds(self.internal.configured_in_force(), self.storage.pool).swap;
        let partial = self.internal.commit_partial(rho);
        // BRICK intake = receipt (pss_public_contract::receipt_request). Alternatives:
        // onchain, shared_receipt, shared_onchain (the other entry points). docs/design-guide/BRICKS.md#intake
        let request_id = receipt_request(
            self.context,
            round,
            [amount_in, direction, min_out, partial],
            user_nonce,
            expiry_block,
            receipts,
            valid_plain_swap,
        );
        self.enqueue_self.append_receipt(request_id, expiry_block);
    }

    #[external("public")]
    #[only_self]
    fn append_receipt(request_id: Field, expiry_block: u32) {
        let _ = self.storage.queue.append_receipt(self.storage.configured, self.storage.pool, request_id, expiry_block);
    }

    /// Secret-shared receipt intake (`intake: shared_receipt`): queue a swap whose
    /// inputs the user secret-shared among the nodes, which signed receipts
    /// over the inputs commitment C without seeing a shared input. The swap
    /// inputs, `rho` (the randomness the client derives for this request),
    /// the outcome key and tag and `sharing` (the summand vectors the nodes
    /// hold, `AMM_SWAP_TIP_SHARED_LAYOUT`) are private arguments and none reaches the
    /// chain. The function commits the trader's partial note `P
    /// = partial_commitment(msg_sender, rho)` and pushes its use nullifier
    /// (`partial_note::commit`): the completed note will be the sender's,
    /// and no request can name a partial note its sender cannot open. C's
    /// values are `[amount_in, direction, min_out, P, outcome_key,
    /// outcome_tag]`; the library checks `valid_swap` over the swap inputs,
    /// proves that the sharing opens C, computes the request id over C (the
    /// namespace this address) and checks the three receipts over C and the
    /// sharing's digest, so a request whose shares do not open C is never
    /// queued; the public call is receipt intake's
    /// `append_receipt`, with the request id and the expiry block only. The
    /// sender's address enters nothing but `P`.
    ///
    /// DEV DECISION: whose note the swap completes, default the sender's
    /// (`owner = msg_sender`), so a request can pay only its own sender.
    /// Any account in the trader's PXE could own it instead (the owner an
    /// argument), at no cost to the nodes' view (they see `P` only); the
    /// default keeps the request function free of an owner argument that
    /// a wallet could fill wrongly. Design: docs/DECISIONS.md section 10, "The
    /// request-side owner is `msg_sender`".
    #[external("private")]
    fn swap_shared(
        amount_in: Field,
        direction: Field,
        min_out: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        sharing: Sharing<7>,
        expiry_block: u32,
        receipts: [Receipt; 3],
    ) {
        let round = rounds(self.internal.configured_in_force(), self.storage.pool).swap_shared;
        // BRICK intake = shared_receipt (pss_public_contract::outcome_request). Alternatives:
        // onchain, receipt, shared_onchain (the other entry points). docs/design-guide/BRICKS.md#intake
        let r: ReceiptRequest = outcome_request(
            self.context,
            round,
            self.msg_sender(),
            [amount_in, direction, min_out],
            AMM_SWAP_TIP_SHARED_LAYOUT,
            SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block, receipts },
            valid_swap,
        );
        self.enqueue_self.append_receipt(r.request_id, r.expiry_block);
    }

    /// Secret-shared on-chain intake (`intake: shared_onchain`): queue the same
    /// secret-shared swap with no off-chain step. The arguments are
    /// `swap_shared`'s but for the blinding, from `eph`, the ephemeral
    /// secret (fresh, used once); the outcome key and tag are the client's
    /// per-request derivations, as under `swap_shared`. The function commits
    /// the sender's partial note from `rho` as `swap_shared` does; the
    /// library reads the three nodes' keys at the anchor block, checks
    /// `valid_swap` over the swap inputs, computes C and the request id,
    /// emits one private log of the encoded shares (`AMM_SWAP_TIP_SHARED_ONCHAIN_LAYOUT`:
    /// every value of C chosen, one correction each) and returns the log's hash and epochs,
    /// which `append_onchain_shared` stores beside the queue entry. No input
    /// reaches public calldata. Refused when a node has no key in this
    /// contract or the inputs fail `valid_swap`, and in the public part when
    /// a named epoch is older than the one before the stored one, the pool
    /// is not initialised or the request id was seen.
    #[external("private")]
    fn swap_shared_onchain(
        amount_in: Field,
        direction: Field,
        min_out: Field,
        rho: Field,
        outcome_key: Field,
        outcome_tag: Field,
        eph: Field,
    ) {
        let round = rounds(self.internal.configured_in_force(), self.storage.pool).swap_shared;
        let slot = self.storage.shared_onchain.get_storage_slot();
        // BRICK intake = shared_onchain (pss_public_contract::SharedOnchainArgs). Alternatives:
        // onchain, receipt, shared_receipt (the other entry points). docs/design-guide/BRICKS.md#intake
        let r: SharedOnchainRequest = outcome_request(
            self.context,
            round,
            self.msg_sender(),
            [amount_in, direction, min_out],
            AMM_SWAP_TIP_SHARED_ONCHAIN_LAYOUT,
            SharedOnchainArgs { rho, outcome_key, outcome_tag, slot, eph },
            valid_swap,
        );
        self.enqueue_self.append_onchain_shared(r.request_id, r.data_hash, r.epochs);
    }

    #[external("public")]
    #[only_self]
    fn append_onchain_shared(request_id: Field, data_hash: Field, epochs: [u32; 3]) {
        assert_ready(self.context, self.storage.configured, self.storage.pool);
        let _ = self.storage.shared_onchain.append(self.storage.queue, request_id, data_hash, epochs);
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
        // (app.nr) and set_node_keys, assert_key_epoch and get_node_keys below. Alternatives: fixed
        // (Keys = FixedKeys, none of the four; examples/credits-tip). docs/design-guide/BRICKS.md#node_keys
        let config = self.storage.configured.read().config();
        let node_keys = key_epoch::check_rotation(self.context, config, epoch, keys, signatures);
        self.enqueue_self.set_node_keys(node_keys);
    }

    /// pss_public_contract::KeyEpochs::install, which voids every replaced
    /// node's enc key in `shared_onchain` with the install.
    #[external("public")]
    #[only_self]
    fn set_node_keys(node_keys: NodeKeys) {
        // the enc keys Keys names (app.nr), which the install voids for a replaced node; NoEncKeys {} under
        // KeyEpochs<NoEncKeys>, in a contract without secret-shared on-chain intake
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

    /// A swap's result, whichever non-secret-shared intake queued it: the circuit
    /// outputs the request id and takes the vk hash as a public input, so
    /// the library pins the vk, verifies the proof over `[namespace,
    /// vk_hash, in_slots, out_slots, request_id, old_c, new_c, npk_app_hash,
    /// ok, partial_note, code, amount_out]` (the pool key for both slots, no
    /// pinned reads) and checks the three result signatures (node-held: no
    /// sealed thirds); a failed swap must keep the pool's commitment
    /// (`new_c == old_c`, the library's failed-round rule). Then `apply`,
    /// whose queue check binds the request id, lands it. Anyone may submit;
    /// the operator's relayer does by default.
    #[external("private")]
    fn process_result(round: SwapResult, signatures: [ResultSignature; 3]) {
        let checked = check_round(
            rounds(self.internal.configured_in_force(), self.storage.pool).swap,
            self.context,
            self.msg_sender(),
            round,
            NodeHeld {},
            signatures,
        );
        self.enqueue_self.apply(checked);
    }

    /// Land a checked swap result: the library checks
    /// `requests[head] == request_id` and `pool == old_c`, writes `new_c`
    /// when ok (a no-op when not), moves the head and writes `done[index]`,
    /// then completes the trader's partial note at `outcome_notes` with
    /// `[code, amount_out, request_id]`: the completion log under the partial
    /// note's completion tag and the completed note's hash, on every round
    /// whatever `ok` is (a failed swap's note says why, with `amount_out =
    /// 0`). The world sees the outcome and `P`, never the owner. It stores
    /// nothing else and makes no external call.
    #[external("public")]
    #[only_self]
    fn apply(round: SwapResult) {
        // BRICK value = partial (pss_public_contract::result::PartialResult::completing), the note completed
        // in public. Alternatives: none (no note). docs/design-guide/BRICKS.md#value
        let _ = apply_round(
            self.context,
            self.storage.queue,
            no_pinned_reads(),
            pool_state_keys(self.storage.pool),
            round.completing(self.storage.outcome_notes.get_storage_slot()),
            NodeHeld {},
        );
    }

    /// A secret-shared swap's result, under private outcomes with partial-note
    /// delivery: the library pins the
    /// `amm_swap_tip_shared` vk, verifies the proof over `[namespace,
    /// vk_hash, in_slots, out_slots, request_id, machine_request_id, old_c,
    /// new_c, npk_app_hash, outcome_tag, note_hash, ciphertext[3]]` (the
    /// machine request id computed here), checks the three result
    /// signatures, pushes the completed note's hash (the trader's partial
    /// note completed by the round with `[code, amount_out, request_id]`)
    /// and emits the outcome log; nothing runs after the log and no other
    /// contract is called. `apply_shared` then writes the pool's new
    /// commitment. Anyone may submit; the operator's relayer does by default,
    /// and it sees ciphertext and hashes only.
    #[external("private")]
    fn process_result_shared(result: SwapSharedResult, signatures: [ResultSignature; 3]) {
        // BRICK outputs = private (pss_public_contract::outcome::Private). Alternatives: public
        // (process_result, the non-secret-shared intakes only). docs/design-guide/BRICKS.md#outputs
        let apply = check_round(
            rounds(self.internal.configured_in_force(), self.storage.pool).swap_shared,
            self.context,
            self.msg_sender(),
            Private::of(result, self.storage.outcome_notes.get_storage_slot(), OUTCOME_SLOT),
            NodeHeld {},
            signatures,
        );
        self.enqueue_self.apply_shared(apply);
    }

    /// Land a checked secret-shared swap: the library checks `requests[head] ==
    /// request_id` and `pool == old_c`, writes `new_c` whatever the outcome
    /// (the round re-blinds the pool on every outcome, and there is no
    /// public `ok`), moves the head and writes `done[index]`. It stores no
    /// outcome and logs nothing.
    #[external("public")]
    #[only_self]
    fn apply_shared(apply: SwapSharedApply) {
        let _ = apply_round(
            self.context,
            self.storage.queue,
            no_pinned_reads(),
            pool_state_keys(self.storage.pool),
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
    // The trader's spend
    // -----------------------------------------------------------------------

    /// Spend the sender's completed swap note of request `request_id` once:
    /// read it from the sender's notes (its inclusion checked), nullify it
    /// with the sender's keys, and return its `amount_out`. Refused when the
    /// sender holds no note of that request (none delivered, or redeemed
    /// already: the nullified note is gone) or the note has nothing to pay
    /// (a failed swap's, `amount_out = 0`). Nobody but the note's owner can
    /// redeem it, and the redeem's nullifier links to no transaction of the
    /// request or the result.
    ///
    /// DEV DECISION: what a redeem pays, default nothing beyond the note's
    /// own spend (the example has no token: the note is the trader's credit
    /// and `redeem` returns its amount to the caller's own contract logic).
    /// A deployment with a real token enqueues a public payout here: the
    /// AMM's public token balance completes a token partial note of the
    /// trader's for `amount_out` (amount public at redeem time, unlinked to
    /// the request, recipient hidden). Paying in the result transaction
    /// instead would show the relayer the amount. Design:
    /// docs/DECISIONS.md section 10, "Token custody is
    /// public, settled by the user's own redeem".
    #[external("private")]
    fn redeem(request_id: Field) -> Field {
        let options = NoteGetterOptions::new()
            .select(SwapOutcomeNote::properties().request_id, Comparator.EQ, request_id)
            .set_limit(1);
        let notes = self.storage.outcome_notes.at(self.msg_sender()).pop_notes(options);
        assert(notes.len() == 1, "no swap note of this request to redeem");
        let note = notes.get(0);
        assert(note.amount_out != 0, "the swap note has nothing to redeem");
        note.amount_out
    }

    // -----------------------------------------------------------------------
    // Views
    // -----------------------------------------------------------------------

    /// pss_public_contract::view::TipState::read, over the pool slot and the
    /// outcome notes' slot; its type reports the bricks, `Keys` and
    /// `UpgradesContract` (the contract manifest's node_keys and upgrades).
    #[external("public")]
    #[view]
    fn get_state() -> TipState<Config, 1, Keys, UpgradesContract> {
        TipState::read(
            self.context,
            self.storage.config,
            self.storage.configured,
            self.storage.queue,
            [self.storage.pool],
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

    /// pss_public_contract::logs::log_in_tx: an on-chain swap's request log, or apply's completion log.
    #[external("utility")]
    unconstrained fn log_in_tx(tx_hash: Field, tag: Field) -> BoundedVec<Field, MAX_LOG_FIELDS> {
        logs::log_in_tx(self.address, tx_hash, tag)
    }

    /// The outcome-note utility: hand `owner`'s PXE the completed note of a
    /// secret-shared swap that the trader's client rebuilt from the outcome
    /// log of transaction `tx` (`packed` = `[code, amount_out, request_id]`,
    /// `rho` the request's randomness, so the note completes the partial
    /// note `partial_commitment(owner, rho)`). A note whose hash is not among
    /// the transaction's is not stored.
    #[external("utility")]
    unconstrained fn deliver_outcome(owner: AztecAddress, rho: Field, packed: [Field; 3], tx: OutcomeTx) {
        deliver_outcome_into(self.storage.outcome_notes, self.address, _compute_note_hash, _compute_note_nullifier, owner, rho, packed, tx);
    }

    /// The swap notes `owner`'s PXE holds, and the first of them.
    #[external("utility")]
    unconstrained fn swap_notes(owner: AztecAddress) -> SwapNotes {
        let notes = self.storage.outcome_notes.at(owner).view_notes(NoteViewerOptions::new());
        let first = if notes.len() > 0 {
            notes.get(0)
        } else {
            SwapOutcomeNote { code: 0, amount_out: 0, request_id: 0 }
        };
        SwapNotes { count: notes.len(), first }
    }
}
