use aztec::macros::aztec;

/// A constant-product AMM whose reserves exist only as a private shared
/// state (PSS) note: an MPC network holds the pool's preimage as secret
/// shares and proves every change with a collaborative UltraHonk ZK proof
/// (a co-SNARK) that this contract verifies in-circuit. No tokens move in
/// this example; `swap` is where transfers would go.
///
/// Trust model: semi-honest MPC (collusion of the nodes reveals the
/// reserves); the chain trusts only the proofs, never the operator.
///
/// Notes held by the network (slots are domain separators inside the
/// note-hash preimage, agreed with the circuits; no storage is allocated):
/// - `SEED_SLOT`: one field of randomness nobody knows (`pss_seed`);
/// - `POOL_SLOT`: `[reserve_x, reserve_y]` (`amm_init`, then `amm_swap` or
///   `amm_swap_total`).
///
/// Two swap entrypoints spend the same pool note: `swap` takes the
/// asserting `amm_swap` proof (a bad request has no proof; the nodes refuse
/// it 422), `swap_total` the total `amm_swap_total` proof (a bad request
/// proves with ok = 0 and lands as a no-op).
///
/// This contract has no storage and no public functions. Its `Config`
/// (vk hashes and network identity) is pushed as a raw note hash, the
/// anchor, and every later call proves it exists with a read request (see
/// `pss_contract::anchor`).
///
/// Ordering is enforced without a phase variable:
/// - `init_pool` pushes a single-use nullifier, so it runs once;
/// - `start_pool` spends the seed note, so it runs once, and only after
///   `init_pool` (the anchor and the seed must exist);
/// - `swap` and `swap_total` spend the current pool note, which exists
///   only after `start_pool`; a stale pool note re-derives a spent
///   nullifier.
///
/// The total swap lives in this contract, not in a contract
/// of its own. It reads and writes the same pool note under the same
/// slot, owner, network pin and anchor; only its proof, its public-input
/// shape (three app outputs) and what it does with them differ, which is
/// one function and one vk pin. A separate contract would duplicate the
/// Config, the anchor and the seed and init rounds for no gain. Both
/// entrypoints stay open, so a trader picks the failure mode; a deployment
/// that wants only the total swap pins `swap_vk_hash` to 0, which no vk
/// hashes to.
#[aztec]
pub contract AmmPss {
    use aztec::context::PrivateContext;
    use aztec::macros::functions::external;
    use aztec::protocol::address::AztecAddress;
    use aztec::protocol::hash::poseidon2_hash_with_separator;
    use aztec::protocol::traits::{Deserialize, Packable, Serialize};
    use pss_contract::{apply, apply_seed, assert_anchored, PssConfig, PssEffects, push_once};

    // The keys: these slots are the request keys of the
    // machine ($state_keys.reads / $state_keys.writes) and the storage slots in the
    // note hashes; the contract passes them as in_slots / out_slots, so a
    // proof over other keys is rejected. Both keys are node-held.
    global SEED_SLOT: Field = 0xa001;
    global POOL_SLOT: Field = 0xa002;

    // Domain separators for the raw note hash and single-use nullifier
    // this contract invents ("AMM" + index).
    global DOM_SEP__AMM_ANCHOR: u32 = 0x414d4d01;
    global DOM_SEP__AMM_ONCE: u32 = 0x414d4d02;
    global ONCE_INIT: Field = 1;

    /// The deployment pins: every field is fixed at
    /// `init_pool` and anchored; changing one means a new deployment.
    /// - `operator` may anchor and start the pool (trusted for liveness
    ///   only: it cannot change the reserves or the circuits);
    /// - `owner` must equal the manifests' `owner` const, which the
    ///   circuits bake into every note hash;
    /// - `npk_app_hash` is the value the namespace's first REGISTER
    ///   returned: only that network can nullify the pool notes;
    /// - the vk hashes name the only circuits whose proofs are accepted;
    ///   register first, then pin the hashes the nodes agreed on;
    ///   `swap_vk_hash` is `amm_swap`'s, `swap_total_vk_hash`
    ///   `amm_swap_total`'s.
    ///
    /// The anchor preimage is public: every caller passes
    /// the Config as an argument, so the operator publishes it with the
    /// anchor's nonce. Put nothing secret here.
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct Config {
        pub operator: AztecAddress,
        pub owner: Field,
        pub npk_app_hash: Field,
        pub seed_vk_hash: Field,
        pub init_vk_hash: Field,
        pub swap_vk_hash: Field,
        pub swap_total_vk_hash: Field,
    }

    /// What a total swap did, read from the `amm_swap_total` proof's app
    /// outputs and returned to the caller: `ok` (the trade happened),
    /// `code` (0 when ok, else the first failing check, the `CODE_*` of
    /// examples/amm-swap-total's amm_total library: 1 zero input, 2 amount
    /// not a u64, 3 direction not 0 or 1, 4 the input reserve overflows, 5
    /// the output rounds to zero, 6 the output drains the pool, 7 a reserve
    /// in the note is not a u64) and `amount_out` (0 when not ok).
    #[derive(Deserialize, Eq, Serialize)]
    pub struct SwapOutcome {
        pub ok: bool,
        pub code: Field,
        pub amount_out: Field,
    }

    #[contract_library_method]
    fn anchor_hash(config: Config) -> Field {
        poseidon2_hash_with_separator(config.pack(), DOM_SEP__AMM_ANCHOR)
    }

    #[contract_library_method]
    fn pss_config(config: Config) -> PssConfig {
        PssConfig { owner: config.owner, npk_app_hash: config.npk_app_hash }
    }

    /// The body both swaps share: the Config's anchor, then `apply` of a
    /// pool-to-pool round with the public inputs `[amount_in, direction]`,
    /// under `vk_hash` (`swap_vk_hash` or `swap_total_vk_hash`).
    #[contract_library_method]
    fn apply_swap<let A: u32>(
        context: &mut PrivateContext,
        sender: AztecAddress,
        config: Config,
        anchor_nonce: Field,
        vk_hash: Field,
        amount_in: Field,
        direction: Field,
        effects: PssEffects<1, 1, A>,
    ) {
        assert_anchored(context, anchor_hash(config), anchor_nonce);
        // BRICK path = sidecar (pss_contract::apply): the user's own private function verifies the round
        // and applies its effects. Alternatives: tip (a public queue and a relayer: examples/amm-tip).
        // docs/design-guide/BRICKS.md#path
        apply(
            context,
            sender,
            vk_hash,
            pss_config(config),
            [POOL_SLOT],
            [POOL_SLOT],
            [amount_in, direction],
            effects,
        );
    }

    /// Anchor the seed note (the `pss_seed` proof) and the pool's Config.
    /// Once per deployment, by whoever calls first: `config` is the caller's
    /// own argument, so the operator check only makes the caller name
    /// itself. A watcher who calls first owns the deployment, and the
    /// operator redeploys (no funds and no state are at risk before the
    /// pool starts). Binding the operator takes an initializer that stores
    /// it, so the address commits to it.
    ///
    /// Nonce-mining indices. Note hashes pushed, in order:
    /// 0 = seed note, 1 = anchor. Clients mine the protocol nonce of each
    /// from this tx's effects by that index.
    #[external("private")]
    fn init_pool(config: Config, seed_note_hash: Field) {
        assert_eq(self.msg_sender(), config.operator, "only the operator");

        apply_seed(
            self.context,
            self.msg_sender(),
            config.seed_vk_hash,
            pss_config(config),
            SEED_SLOT,
            seed_note_hash,
        );

        // The once-nullifier makes init_pool single-use and
        // publicly marks it as done; its separator is this contract's own.
        push_once(self.context, DOM_SEP__AMM_ONCE, ONCE_INIT);
        self.context.push_note_hash(anchor_hash(config));
    }

    /// Create the pool from the seed (the `amm_init` proof): the network
    /// spends the seed note and stores reserves derived from it, so the
    /// starting price is unknown to everyone. Operator only.
    ///
    /// The `amm_init` effects arrive field by field, in `PssEffects` order
    /// minus `app_outputs`: an empty array cannot be a function argument,
    /// so a `PssEffects<1, 1, 0>` argument is not allowed.
    ///
    /// Nonce-mining indices. Note hashes pushed, in order:
    /// 0 = pool note.
    #[external("private")]
    fn start_pool(
        config: Config,
        anchor_nonce: Field,
        read_leaves: [Field; 1],
        nullifiers: [Field; 1],
        new_note_hashes: [Field; 1],
        npk_app_hash: Field,
    ) {
        assert_eq(self.msg_sender(), config.operator, "only the operator");
        assert_anchored(self.context, anchor_hash(config), anchor_nonce);

        apply(
            self.context,
            self.msg_sender(),
            config.init_vk_hash,
            pss_config(config),
            [SEED_SLOT],
            [POOL_SLOT],
            [],
            PssEffects { read_leaves, nullifiers, new_note_hashes, npk_app_hash, app_outputs: [] },
        );
    }

    /// Swap `amount_in` of x for y (`direction` = 0) or y for x (1) (the
    /// `amm_swap` proof). Any caller. The proof binds
    /// `effects.app_outputs[0]` = amount_out, which the caller's PXE
    /// verifies; a token transfer would use it here.
    ///
    /// Nonce-mining indices. Note hashes pushed, in order:
    /// 0 = new pool note. A token transfer added here must push its notes
    /// after `apply`, or the pool note's index changes.
    #[external("private")]
    fn swap(
        config: Config,
        anchor_nonce: Field,
        amount_in: Field,
        direction: Field,
        effects: PssEffects<1, 1, 1>,
    ) {
        // The app hook: reject inputs the circuit would
        // reject before any work; slippage limits on amount_out go after
        // apply.
        assert((direction == 0) | (direction == 1), "direction must be 0 or 1");
        assert(amount_in != 0, "amount_in must not be zero");
        apply_swap(
            self.context,
            self.msg_sender(),
            config,
            anchor_nonce,
            config.swap_vk_hash,
            amount_in,
            direction,
            effects,
        );
    }

    /// Swap with the total circuit (the `amm_swap_total` proof). Any
    /// caller. `amount_in` and `direction` are raw Fields bound into the
    /// proof as public inputs; the contract checks neither, because the
    /// circuit reports every bad value as a code. The proof's app outputs
    /// are [ok, code, amount_out]. Whatever `ok` says, `apply` spends the
    /// pool note and pushes the new one, so the transaction lands:
    /// - ok = 1: the trade. The new note holds the traded reserves, and a
    ///   token transfer of `amount_in` in and `amount_out` out would go
    ///   here, after `apply` and only when `outcome.ok`.
    /// - ok = 0: the no-op. The new note holds the old reserves under a
    ///   fresh blinding (DECISIONS.md, "CONSUME is `once` or `never`"), nothing moves, and
    ///   the pool goes on from the new note.
    /// Returns the outcome, for the caller's simulation and for a
    /// contract that calls this one.
    ///
    /// No app hook: `swap` rejects a zero amount or a bad
    /// direction before any work; here those are codes 1 and 3, and a
    /// revert would strand a round the nodes have already committed (the
    /// pool row ahead of the chain until FETCH or rollback). A slippage
    /// limit belongs in the circuit as a code for the same reason, not in
    /// a contract assert; amm_total has no slippage code.
    ///
    /// The outcome encoding is re-checked (ok is 0 or 1, code
    /// is 0 exactly when ok, amount_out is 0 when not ok). A valid
    /// amm_swap_total proof always satisfies these, so they never revert a
    /// landed swap; they make a circuit change that broke the encoding fail
    /// here instead of moving tokens on a wrong branch, for a few gates.
    ///
    /// Nonce-mining indices. Note hashes pushed, in order:
    /// 0 = new pool note, on either outcome. A token transfer added here
    /// must push its notes after `apply`, or the pool note's index changes.
    #[external("private")]
    fn swap_total(
        config: Config,
        anchor_nonce: Field,
        amount_in: Field,
        direction: Field,
        effects: PssEffects<1, 1, 3>,
    ) -> SwapOutcome {
        apply_swap(
            self.context,
            self.msg_sender(),
            config,
            anchor_nonce,
            config.swap_total_vk_hash,
            amount_in,
            direction,
            effects,
        );

        let ok = effects.app_outputs[0];
        let code = effects.app_outputs[1];
        let amount_out = effects.app_outputs[2];
        assert((ok == 0) | (ok == 1), "ok must be 0 or 1");
        assert((ok == 1) == (code == 0), "code must be 0 exactly when ok");
        assert((ok == 1) | (amount_out == 0), "a failed swap pays out nothing");
        SwapOutcome { ok: ok == 1, code, amount_out }
    }
}
