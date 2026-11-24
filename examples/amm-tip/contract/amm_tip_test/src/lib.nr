//! TXE tests for the AmmTip contract: the deployment (the constructor's Config,
//! the once-only `configure` and every refusal before it, test_configure.nr),
//! the init round outside the queue (once), both non-secret-shared intakes (on-chain intake
//! with its non-secret-shared request log, receipt intake with three node receipts) of the
//! one swap round, each committing the trader's partial note and telling the
//! trader's PXE of it offchain, the result transaction for either on
//! node-held state (an ok = 1 swap that writes the new commitment, an ok = 0
//! no-op that keeps it so the next swap lands on the same commitment, the
//! public completion of the trader's note on every round, no state log), the
//! trader's `redeem` of the completed note, the refusals of `apply` (a wrong
//! head, a call from outside) and `skip()` after `stale_blocks`.
//! test_table.nr runs the README's three-swap scenario with the circuits' own
//! rounds; test_refusals.nr holds the further refusals of `process_result`
//! and init (see its header).
//!
//! The proofs: recursive proof verification is a no-op during TXE witness
//! execution (as in the library's suite), so the staged capsule carries a
//! dummy vk whose hash the Config pins and a zero proof; the vk pin in front
//! of the verification runs for real, and so does everything after it. The
//! signatures are real: the nodes are testvectors/keys.json's, signing with
//! `pss_tip_test`'s signer, so every receipt and result signature verifies in-circuit
//! as a node's would; under node-held state each result message ends in
//! `H(sealed_i) = 0`.
//!
//! Refusals: every check is an assertion, so a refused transaction reverts
//! as a whole and a TXE test that expects the failure ends at it; nothing
//! after the refused call runs. What each kind of refusal leaves is shown
//! as follows.
//!
//! - `skip()`, the app's one open public function: through a probe, as in
//!   the library's suite. The tip suites' probe (`PssProbe`, deployed
//!   beside the app by `setup_with_probe`) makes the app's
//!   `skip()` as a nested call and reports its revert instead of
//!   rethrowing it, so the test reads the state afterwards
//!   (`s.queue().assert_refused_without_effect`, pss_tip_test `queue`: the
//!   full snapshot before and after, and no log, note or message in the
//!   probe's transaction), then makes the call itself, which fails with the
//!   expected message.
//! - `apply`, `apply_init`, `append_onchain` and `append_receipt`: these
//!   are `#[only_self]` and reached only from the app's own private
//!   functions in the same transaction, so no probe outside the app can
//!   make the call, and the app keeps none (a probe in an app is an open
//!   door past its queue rules). A refusal there reverts the transaction
//!   whose private part enqueued it, and the AVM discards every write and
//!   log of a reverted app-logic phase; the library's suite shows the same
//!   bodies (`apply_round`, `append`, `append_before`) leave the queue and
//!   the slot unchanged when refused inside a transaction that goes on.
//!   Each test here pins the queue and slot right before the refused call
//!   (`assert_state`), so the refusal is of exactly that state, and the
//!   accepted-path tests show the same state moving only on success.
//! - The private refusals (the static checks, the receipts, every check of
//!   `process_result` and `init_pool`): no transaction at all, so nothing
//!   reaches the chain.
//!
//! The secret-shared deployment (test_shared.nr): the init and the swap's
//! secret-shared-intake entry; every secret-shared round is computed by the
//! circuits' own `swap_round` under `SharedIntake` over the trader's partial note, so the
//! completed note hash and the ciphertext the contract lands are the ones
//! the round circuit outputs, and the trader delivers and redeems the note
//! as its client does.
//!
//! The rounds: where a test needs a real round's numbers (the three-swap
//! table), it computes them with the circuits' own
//! `swap_round` (the `amm_tip` circuit library) and pss_core's slot
//! `commitment` over
//! the deployed namespace and the pool key, so the commitments, amounts and
//! codes the contract lands are the ones the round circuits would output.
//! Elsewhere the commitments are stand-ins (`C_INIT`, `C1`, `C2`): the
//! contract compares and stores them and never recomputes one.
mod test_configure;
mod test_init;
mod test_intake;
mod test_receipt_vector;
mod test_refusals;
mod test_result;
mod test_round_shape;
mod test_shared;
mod test_shared_onchain;
mod test_table;
mod test_upgrade;

use amm_tip::AmmTip;
use amm_tip::app::{
    AMM_INIT_TIP_PACKAGE, AMM_SWAP_TIP_PACKAGE, AMM_SWAP_TIP_SHARED_PACKAGE, Config, Keys, PACKAGES,
    PLAIN_PACKAGES, PLAIN_SWAP_INPUTS, SHARED_PACKAGES, SHARED_VALUES, SwapNotes, SwapOutcomeNote,
    SwapResult, SwapSharedResult,
};
use amm_tip::layouts::AMM_SWAP_TIP_SHARED_LAYOUT;
use amm_tip_circuit::shared::{OUTCOME_SLOT, SharedRound};
use amm_tip_circuit::tip::swap_round;
use aztec::protocol::abis::gas::Gas;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash;
use aztec::protocol::traits::ToField;
use aztec::test::helpers::test_environment::TestEnvironment;
use aztec::test::helpers::txe_oracles;
use aztec::context::UtilityContext;
use aztec::messages::processing::offchain::{MAX_OFFCHAIN_MESSAGES_PER_RECEIVE_CALL, OffchainMessage};
use aztec::state_vars::{PublicImmutable, StateVariable};
use pss_core::tip::intake::SharedIntake;
use pss_core::tip::slot::load;
use pss_public_contract::{
    chain_request_id, Configured, inputs_commitment, inputs_hash, Queue, Receipt, receipt_message,
    RegistryAnswer, shared_chain_request_id, StaleBlocks, UpgradesContract,
};
use pss_public_contract::init::init_request_id;
use pss_public_contract::outcome::OutcomeApply;
use pss_public_contract::partial_note::{completion_log_tag, partial_commitment};
use pss_public_contract::result::{NodeHeld, PartialResult, ResultSignature, Sealing, TipResult};
use pss_probe::PssProbe;
pub use pss_tip_test::last_tx;
use pss_tip_test::nodes::receipts;
use pss_tip_test::outcome::{open_outcome_log, outcome_result, outcome_signatures};
use pss_tip_test::{configure_answer, result_signatures, tip_pins};
use pss_tip_test::queue::QueueReader;
use pss_tip_test::shape::{kind_options, last_tx_shape};
use pss_tip_test::sharing::{shared_receipts, sharing_of};

/// The stale period the tests deploy with: short, so they mine few blocks;
/// the rule is the same at the manifests' 50.
pub global STALE: u32 = 4;
/// The network identity `configure` pins (a stand-in: no round runs here).
pub global NPK_APP_HASH: Field = 0x9b9b;

// the pool commitments the stand-in rounds produce
pub global C_INIT: Field = 0xc0;
pub global C1: Field = 0xc1;
pub global C2: Field = 0xc2;

// a swap: sell 25000 x with min_out 33000 (the circuits' Prover.toml)
pub global AMOUNT_IN: Field = 25000;
pub global DIRECTION: Field = 0;
pub global MIN_OUT: Field = 33000;
pub global AMOUNT_OUT: Field = 33450;
pub global NONCE_A: Field = 0xa1;
pub global NONCE_B: Field = 0xb2;
pub global NONCE_C: Field = 0xc3;
pub use pss_public_contract::TWO_POW_64;

// one dummy vk per circuit, so each pin is tested against the other's proofs
pub unconstrained fn init_vk() -> [Field; 115] {
    [5; 115]
}

pub unconstrained fn swap_vk() -> [Field; 115] {
    [7; 115]
}

pub unconstrained fn shared_vk() -> [Field; 115] {
    [9; 115]
}

/// The vk hash of each circuit, which the constructor pins and the test
/// network's REGISTER answer signs over.
pub struct Vks {
    pub init_vk_hash: Field,
    pub swap_vk_hash: Field,
    pub shared_vk_hash: Field,
}

pub unconstrained fn vks() -> Vks {
    Vks {
        init_vk_hash: poseidon2_hash(init_vk()),
        swap_vk_hash: poseidon2_hash(swap_vk()),
        shared_vk_hash: poseidon2_hash(shared_vk()),
    }
}

/// The vk hash of the package named `name`: its circuit's (0 for 0, the
/// end of a list, and for a name that is no package of the contract).
pub unconstrained fn vk_hash_of(name: Field) -> Field {
    let v = vks();
    if name == AMM_INIT_TIP_PACKAGE {
        v.init_vk_hash
    } else if name == AMM_SWAP_TIP_PACKAGE {
        v.swap_vk_hash
    } else if name == AMM_SWAP_TIP_SHARED_PACKAGE {
        v.shared_vk_hash
    } else {
        0
    }
}

/// The vk hash of each place of `packages`, as the constructor pins them.
pub unconstrained fn vk_hashes_of(packages: [Field; PACKAGES]) -> [Field; PACKAGES] {
    packages.map(|name| vk_hash_of(name))
}

pub struct Setup {
    pub env: TestEnvironment,
    pub deployer: AztecAddress,
    /// the trader of most tests (trader A of the three-swap table)
    pub user: AztecAddress,
    /// a second trader (trader B of the three-swap table)
    pub trader_b: AztecAddress,
    pub relayer: AztecAddress,
    /// the upgrade authority the constructor pins (test_upgrade.nr)
    pub authority: AztecAddress,
    pub app: AztecAddress,
    pub config: Config,
    pub vks: Vks,
    /// the probe contract (`setup_with_probe`), else the zero address
    pub probe: AztecAddress,
}

/// The non-secret-shared test deployment's Config: the test network's keys, the short
/// stale period and the non-secret-shared package list.
pub unconstrained fn config() -> Config {
    config_of(PLAIN_PACKAGES)
}

/// A Config of the package list `packages`, each listed package's vk hash
/// pinned beside it.
pub unconstrained fn config_of(packages: [Field; PACKAGES]) -> Config {
    Config { tip: tip_pins(StaleBlocks::after(STALE), packages, vk_hashes_of(packages)) }
}

/// Deploy the non-secret-shared test deployment and configure it; the pool is not
/// initialised.
pub unconstrained fn deploy() -> Setup {
    deploy_with(false)
}

/// `deploy()`, and when `with_probe` the probe beside it.
pub unconstrained fn deploy_with(with_probe: bool) -> Setup {
    let s = deploy_unconfigured(config(), with_probe);
    configure(s);
    s
}

/// Deploy the contract with `config` (and the probe, when `with_probe`)
/// without configuring it.
pub unconstrained fn deploy_unconfigured(config: Config, with_probe: bool) -> Setup {
    deploy_unconfigured_in(TestEnvironment::new(), config, with_probe)
}

/// `deploy_unconfigured` in `env`.
pub unconstrained fn deploy_unconfigured_in(
    mut env: TestEnvironment,
    config: Config,
    with_probe: bool,
) -> Setup {
    let deployer = env.create_light_account();
    let user = env.create_light_account();
    let relayer = env.create_light_account();
    let trader_b = env.create_light_account();
    let authority = env.create_light_account();
    let app = env.deploy("../amm_tip@amm_tip/AmmTip").with_public_initializer(
        deployer,
        AmmTip::interface().constructor(config, authority),
    );
    let probe = if with_probe {
        env.deploy(PROBE).without_initializer()
    } else {
        AztecAddress::zero()
    };
    Setup { env, deployer, user, trader_b, relayer, authority, app, config, vks: vks(), probe }
}

/// Deploy the secret-shared deployment (the init and the secret-shared swap)
/// with the probe and configure it with the network's answers; the pool is
/// not initialised.
pub unconstrained fn deploy_shared() -> Setup {
    let s = deploy_unconfigured_in(TestEnvironment::new(), config_of(SHARED_PACKAGES), true);
    configure(s);
    s
}

/// The test network's REGISTER answer for the deployment's contract
/// manifest, at seq 0, signed over the constructor's manifest hash and list.
pub unconstrained fn answer_for(s: Setup) -> RegistryAnswer {
    configure_answer(s.app, s.config.tip, NPK_APP_HASH)
}

/// Configure the deployment with the network's answer, sent by the relayer
/// (anyone may).
pub unconstrained fn configure(s: Setup) {
    configure_with(s, answer_for(s));
}

pub unconstrained fn configure_with(s: Setup, answer: RegistryAnswer) {
    s.env.call_private(s.relayer, AmmTip::at(s.app).configure(NPK_APP_HASH, answer));
}

/// Deploy and land the init round (pool = C_INIT).
pub unconstrained fn setup() -> Setup {
    let s = deploy();
    init(s, C_INIT);
    s
}

/// `setup()` with the probe deployed beside the app.
pub unconstrained fn setup_with_probe() -> Setup {
    let s = deploy_with(true);
    init(s, C_INIT);
    s
}

// ---- state readers ---------------------------------------------------------

impl Setup {
    /// The app's queue and pool as the suite reads them (pss_tip_test
    /// `queue`): the state view, the head and the tail, each entry's request
    /// id and done code, and the post-condition of a refused call. The app
    /// stores no outcome by queue index (every swap delivers its note), so
    /// the reader's outcome type is a bare Field it never reads.
    pub unconstrained fn queue(self) -> QueueReader<Config, 1, Field, Keys, UpgradesContract> {
        QueueReader::at(self.env, self.app)
    }
}

pub unconstrained fn pool(s: Setup) -> Field {
    s.queue().commitment(0)
}

pub unconstrained fn pool_key(s: Setup) -> Field {
    s.queue().state().state_keys[0]
}

/// The queue's `seen[request_id]`, read from the app's storage (no view
/// reads it) in a utility context, which leaves the last transaction as it
/// was.
pub unconstrained fn is_seen(s: Setup, request_id: Field) -> bool {
    s.env.utility_context_at(s.app, |context| {
        let queue: Queue<UtilityContext> = Queue::new(context, AmmTip::storage_layout().queue.slot);
        queue.is_seen(request_id)
    })
}

/// The stored `Configured`, whole, read from the app's storage in a utility
/// context (the state view returns its head).
pub unconstrained fn stored_configured(s: Setup) -> Configured<PACKAGES> {
    s.env.utility_context_at(s.app, |context| {
        let configured: PublicImmutable<Configured<PACKAGES>, UtilityContext> =
            PublicImmutable::new(context, AmmTip::storage_layout().configured.slot);
        configured.read()
    })
}

/// The queue and slot state a refused call must leave: head index, tail and
/// pool commitment.
pub unconstrained fn assert_state(s: Setup, head_index: u64, tail_: u64, pool_: Field) {
    let state = s.queue().state();
    assert_eq(state.head.index, head_index);
    assert_eq(state.tail, tail_);
    assert_eq(state.commitments[0], pool_);
}

// ---- the probe ---------------------------------------------------------------

/// The tip suites' probe (`PssProbe`, test-only), deployed beside the app
/// uninitialised: its `try_skip(target)` calls `skip()` on `target` (the
/// selector of `skip()` is the same in every contract) as a nested call and
/// returns whether it landed, and its utilities read a settled transaction.
/// An app never deploys or trusts it: it only calls the app's open
/// `skip()`, as any account may.
pub global PROBE: str<45> = "../../../../noir/pss_probe@pss_probe/PssProbe";

/// Probe `skip()`: the probe calls the app's `skip()` as a nested call, in
/// a transaction of the user's; true when the skip landed.
pub unconstrained fn try_skip(s: Setup) -> bool {
    s.env.call_public(s.user, PssProbe::at(s.probe).try_skip(s.app))
}

/// The fields after the tag of the public log the app emitted under `tag` in
/// the last transaction (its `log_in_tx` utility); fails if there is none or
/// it has another length.
pub unconstrained fn last_tx_log<let N: u32>(s: Setup, tag: Field) -> [Field; N] {
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let fields = s.env.execute_utility(AmmTip::at(s.app).log_in_tx(tx_hash, tag));
    assert(fields.len() != 0, "no log with this tag from the app");
    assert_eq(fields.len(), N, "the log has another length");
    let mut out = [0; N];
    for k in 0..N {
        out[k] = fields.get(k);
    }
    out
}

/// Whether the last transaction emitted no public log at all, read through
/// the probe's `tx_summary` (`setup_with_probe`): an init on node-held state
/// logs nothing.
pub unconstrained fn no_public_log(s: Setup) -> bool {
    assert(s.probe != AztecAddress::zero(), "no_public_log reads through the probe");
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    s.env.execute_utility(PssProbe::at(s.probe).tx_summary(tx_hash)).public_logs == 0
}

// ---- the network's side ----------------------------------------------------

/// Stage the (vk, proof) capsule `process_result` and `init_pool` load,
/// under the relayer as scope.
pub unconstrained fn stage_proof(s: Setup, vk: [Field; 115]) {
    pss_tip_test::stage_proof(s.env, s.app, s.relayer, vk);
}

/// The three nodes' signatures over a result for `request_id`, read at
/// `old_c` and leaving `new_c`: node i signs poseidon2(RESULT_DOMAIN,
/// namespace, machine request id, new_c, i, 0), 0 being node-held state's
/// sealed-third hash.
pub unconstrained fn signatures(
    s: Setup,
    request_id: Field,
    old_c: Field,
    new_c: Field,
) -> [ResultSignature; 3] {
    result_signatures(
        s.app.to_field(),
        request_id,
        [old_c],
        [],
        [new_c],
        NodeHeld {}.sealed_hashes(),
    )
}

// ---- init ------------------------------------------------------------------

pub unconstrained fn init_id(s: Setup) -> Field {
    init_request_id(s.app, s.vks.init_vk_hash, [])
}

/// Land an init result leaving `new_c`, signed for the empty slot.
pub unconstrained fn init(s: Setup, new_c: Field) {
    init_with(s, init_vk(), new_c, signatures(s, init_id(s), 0, new_c));
}

pub unconstrained fn init_with(
    s: Setup,
    vk: [Field; 115],
    new_c: Field,
    sigs: [ResultSignature; 3],
) {
    stage_proof(s, vk);
    s.env.call_private(s.relayer, AmmTip::at(s.app).init_pool(new_c, sigs));
}

// ---- partial notes ---------------------------------------------------------

/// The randomness the client derives for the trader's request with nonce
/// `nonce` (a stand-in for pss-client's `SecretStore` derivation): every
/// request of a trader in a test takes its own nonce, so no partial note is
/// used twice.
pub fn rho_of(nonce: Field) -> Field {
    0x9a00 + nonce
}

/// The partial note `trader`'s non-secret-shared request with nonce `nonce`
/// commits: `partial_commitment(trader, rho_of(nonce))`.
pub fn partial_for(trader: AztecAddress, nonce: Field) -> Field {
    partial_commitment(trader, rho_of(nonce))
}

/// The partial note of the user's non-secret-shared request with nonce `nonce`.
pub unconstrained fn user_partial(s: Setup, nonce: Field) -> Field {
    partial_for(s.user, nonce)
}

/// Hand the last call's offchain messages to the app's `offchain_receive`,
/// as a client hands its PXE the send result's `offchainMessages`. Returns
/// how many there were.
pub unconstrained fn receive_offchain(s: Setup) -> u32 {
    let messages = s.env.offchain_messages();
    let mut batch: BoundedVec<OffchainMessage, MAX_OFFCHAIN_MESSAGES_PER_RECEIVE_CALL> = BoundedVec::new();
    for i in 0..messages.len() {
        batch.push(messages.get(i));
    }
    s.env.execute_utility(AmmTip::at(s.app).offchain_receive(batch));
    messages.len()
}

/// The completion log `apply` emitted in the last transaction for the
/// partial note `partial`: `[storage_slot, code, amount_out, request_id]`.
pub unconstrained fn completion(s: Setup, partial: Field) -> [Field; 4] {
    last_tx_log(s, completion_log_tag(partial))
}

// ---- intake ----------------------------------------------------------------

pub unconstrained fn swap_inputs(amount_in: Field) -> [Field; 3] {
    [amount_in, DIRECTION, MIN_OUT]
}

/// The non-secret-shared swap's app inputs, what `inputs_hash` covers and
/// the on-chain intake's request log carries: the swap's `inputs` and then
/// the request's partial note.
pub fn plain_inputs(inputs: [Field; 3], partial: Field) -> [Field; PLAIN_SWAP_INPUTS] {
    inputs.concat([partial])
}

/// The chain request id of the user's swap, under either non-secret-shared intake (one
/// circuit, one vk hash).
pub unconstrained fn swap_id(s: Setup, amount_in: Field, nonce: Field) -> Field {
    request_id_of(s, s.user, swap_inputs(amount_in), nonce)
}

/// Queue the user's on-chain intake swap and hand its partial note's
/// offchain message to its PXE; returns its chain request id.
pub unconstrained fn swap(s: Setup, amount_in: Field, nonce: Field) -> Field {
    swap_as(s, s.user, swap_inputs(amount_in), nonce)
}

/// The three nodes' receipts over the user's receipt intake swap.
pub unconstrained fn node_receipts(
    s: Setup,
    amount_in: Field,
    nonce: Field,
    expiry: u32,
) -> [Receipt; 3] {
    receipts_for(s, s.user, swap_inputs(amount_in), nonce, expiry)
}

/// Queue the user's receipt intake swap with the given receipts and hand
/// its partial note's offchain message to its PXE.
pub unconstrained fn swap_with(
    s: Setup,
    amount_in: Field,
    nonce: Field,
    expiry: u32,
    r: [Receipt; 3],
) {
    s.env.call_private(
        s.user,
        AmmTip::at(s.app).swap_with_receipts(amount_in, DIRECTION, MIN_OUT, rho_of(nonce), nonce, expiry, r),
    );
    assert_eq(receive_offchain(s), 1);
}

/// Queue the user's receipt intake swap with three valid receipts; returns its id.
pub unconstrained fn swap_with_receipts(s: Setup, amount_in: Field, nonce: Field) -> Field {
    swap_with_receipts_as(s, s.user, swap_inputs(amount_in), nonce)
}

// ---- results ---------------------------------------------------------------

/// A swap round as the tests build it: the fields of `SwapResult` by name.
pub struct SwapRound {
    pub request_id: Field,
    /// the request's partial note, which the round echoes after `ok`
    pub partial: Field,
    pub old_c: Field,
    pub new_c: Field,
    pub ok: bool,
    pub code: Field,
    pub amount_out: Field,
}

impl SwapRound {
    pub fn result(self) -> SwapResult {
        PartialResult {
            partial_note: self.partial,
            result: TipResult::new(
                self.request_id,
                [self.old_c],
                [self.new_c],
                self.ok,
                [],
                [self.code, self.amount_out],
            ),
        }
    }

    /// The round for the request whose partial note is `partial`: every
    /// round that lands on a queued request carries the request's own (a
    /// stand-in round for a request that never lands carries 0).
    pub fn with_partial(self, partial: Field) -> Self {
        let mut r = self;
        r.partial = partial;
        r
    }

    /// The note `apply` completes for this round: `[code, amount_out,
    /// request_id]`, whatever `ok` is.
    pub fn note(self) -> SwapOutcomeNote {
        SwapOutcomeNote { code: self.code, amount_out: self.amount_out, request_id: self.request_id }
    }
}

/// A swap round's result: ok with AMOUNT_OUT, or a no-op with `code`
/// (new_c = old_c, the equal commitment of a failed non-secret-shared round, for which
/// the nodes create no version; amount_out = 0).
pub unconstrained fn ok_round(request_id: Field, old_c: Field, new_c: Field) -> SwapRound {
    SwapRound { request_id, partial: 0, old_c, new_c, ok: true, code: 0, amount_out: AMOUNT_OUT }
}

pub unconstrained fn failed_round(request_id: Field, old_c: Field, code: Field) -> SwapRound {
    SwapRound { request_id, partial: 0, old_c, new_c: old_c, ok: false, code, amount_out: 0 }
}

pub unconstrained fn round_signatures(s: Setup, r: SwapRound) -> [ResultSignature; 3] {
    signatures(s, r.request_id, r.old_c, r.new_c)
}

/// Submit a swap's result as the relayer, whichever non-secret-shared intake queued it,
/// correctly signed; returns the block it landed in.
pub unconstrained fn submit(s: Setup, r: SwapRound) -> u32 {
    submit_with(s, swap_vk(), r, round_signatures(s, r))
}

pub unconstrained fn mine_until_next_block_is(s: Setup, block: u32) {
    pss_tip_test::mine_until_next_block_is(s.env, block);
}

/// What the last transaction, `r`'s result, completed for `trader`: one
/// note hash and one public log, the completion log `[storage_slot, code,
/// amount_out, request_id]` under the partial note's completion tag (no
/// state log: node-held); `trader`'s PXE, told of the partial note
/// offchain at request, then holds `held` swap notes, `r.note()` among
/// them (the only one when `held` is 1).
pub unconstrained fn assert_completed(s: Setup, r: SwapRound, trader: AztecAddress, held: u32) {
    let effects = last_tx_shape(s.env);
    assert_eq(effects.note_hashes, 1);
    assert_eq(effects.public_logs, 1);
    assert_eq(completion(s, r.partial), [OUTCOME_SLOT, r.code, r.amount_out, r.request_id]);
    let notes = notes_of(s, trader);
    assert_eq(notes.count, held);
    if held == 1 {
        assert_eq(notes.first, r.note());
    }
}

// ---- any trader, any inputs ------------------------------------------------

/// The chain request id of `trader`'s swap of `inputs` = [amount_in,
/// direction, min_out] with `nonce`, under either non-secret-shared intake:
/// over the inputs and the partial note the request commits, which names
/// no account.
pub unconstrained fn request_id_of(s: Setup, trader: AztecAddress, inputs: [Field; 3], nonce: Field) -> Field {
    chain_request_id(
        s.app,
        s.vks.swap_vk_hash,
        inputs_hash(plain_inputs(inputs, partial_for(trader, nonce))),
        nonce,
    )
}

/// Queue `trader`'s on-chain intake swap of `inputs` and hand its partial
/// note's offchain message to its PXE; returns its id.
pub unconstrained fn swap_as(
    s: Setup,
    trader: AztecAddress,
    inputs: [Field; 3],
    nonce: Field,
) -> Field {
    s.env.call_private(
        trader,
        AmmTip::at(s.app).swap(inputs[0], inputs[1], inputs[2], rho_of(nonce), nonce),
    );
    assert_eq(receive_offchain(s), 1);
    request_id_of(s, trader, inputs, nonce)
}

/// The three nodes' receipts over `trader`'s receipt intake swap of
/// `inputs`, expiring at `expiry`.
pub unconstrained fn receipts_for(
    s: Setup,
    trader: AztecAddress,
    inputs: [Field; 3],
    nonce: Field,
    expiry: u32,
) -> [Receipt; 3] {
    let id = request_id_of(s, trader, inputs, nonce);
    receipts(receipt_message(id, inputs_hash(plain_inputs(inputs, partial_for(trader, nonce))), expiry))
}

/// Queue `trader`'s receipt intake swap of `inputs` with three valid
/// receipts expiring 10 blocks ahead and hand its partial note's offchain
/// message to its PXE; returns its id.
pub unconstrained fn swap_with_receipts_as(
    s: Setup,
    trader: AztecAddress,
    inputs: [Field; 3],
    nonce: Field,
) -> Field {
    let expiry = s.env.next_block_number() + 10;
    let r = receipts_for(s, trader, inputs, nonce, expiry);
    s.env.call_private(
        trader,
        AmmTip::at(s.app).swap_with_receipts(inputs[0], inputs[1], inputs[2], rho_of(nonce), nonce, expiry, r),
    );
    assert_eq(receive_offchain(s), 1);
    request_id_of(s, trader, inputs, nonce)
}

/// Submit a swap's result proved under `vk` and signed with `sigs`; returns
/// the block it landed in.
pub unconstrained fn submit_with(
    s: Setup,
    vk: [Field; 115],
    r: SwapRound,
    sigs: [ResultSignature; 3],
) -> u32 {
    stage_proof(s, vk);
    s.env.call_private(s.relayer, AmmTip::at(s.app).process_result(r.result(), sigs));
    s.env.last_block_number()
}

// ---- secret-shared receipt intake -------------------------------------------------
//
// The secret-shared deployment (`deploy_shared`): a request goes in as the
// trader's client sends it (three node receipts over C), a result as the
// relayer lands it, each round computed by the circuits' own `swap_round`
// over the deployed namespace and pool key, and each transaction sent under
// its kind's one gas setting.

/// The gas limits of each transaction kind, the app's one fee setting
/// (pss-client `AMM_TIP_FEE_SETTING`), the same for every swap: the gas the
/// kind's transactions used in the tip e2e, metered (test_round_shape.nr)
/// plus their AVM execution, with 25% headroom.
pub global REQUEST_GAS: Gas = Gas { da_gas: 2500, l2_gas: 1200000 };
pub global RESULT_GAS: Gas = Gas { da_gas: 2000, l2_gas: 1300000 };

/// The pool the init leaves on the secret-shared deployment (amm_init_tip's
/// Prover.toml).
pub global POOL: [Field; 2] = [1359373, 1852331];
/// The trader's outcome key and tag, and the nodes' app nullifier key the
/// rounds use.
pub global OUTCOME_KEY: Field = 0x6b6b;
pub global OUTCOME_TAG: Field = 0x7a7a;
pub global NSK_APP: Field = 777;
/// The randomness the trader's client derives for its partial note (one
/// per request: the use nullifier refuses a second request with the same
/// one from the same sender).
pub global RHO: Field = 0x5eed;

/// The partial note a request of `sender` under `rho` commits:
/// `partial_commitment(sender, rho)`, which the request function `swap_shared` computes itself.
pub unconstrained fn partial_of(sender: AztecAddress, rho: Field) -> Field {
    partial_commitment(sender, rho)
}

/// C's values for the user's swap of `inputs` under `rho`: `[amount_in,
/// direction, min_out, partial_note, outcome_key, outcome_tag]`.
pub unconstrained fn shared_values(s: Setup, inputs: [Field; 3], rho: Field) -> [Field; SHARED_VALUES] {
    shared_values_of(inputs, partial_of(s.user, rho))
}

/// C's values for a swap of `inputs` completing the partial note `partial`.
pub unconstrained fn shared_values_of(inputs: [Field; 3], partial: Field) -> [Field; SHARED_VALUES] {
    inputs.concat([partial, OUTCOME_KEY, OUTCOME_TAG])
}

/// Queue the user's secret-shared swap of `inputs` under `rho` and
/// `blinding`, its sharing under `AMM_SWAP_TIP_SHARED_LAYOUT`, with the three nodes'
/// receipts over C and the sharing's digest, expiring ten blocks
/// on, under the request gas setting; returns its chain request id,
/// poseidon2([namespace, vk_hash, C]), and its expiry block.
pub unconstrained fn request_shared(s: Setup, inputs: [Field; 3], rho: Field, blinding: Field) -> (Field, u32) {
    request_shared_as(s, s.user, inputs, rho, blinding)
}

/// `request_shared`, sent by `sender`, whose partial note it commits.
pub unconstrained fn request_shared_as(
    s: Setup,
    sender: AztecAddress,
    inputs: [Field; 3],
    rho: Field,
    blinding: Field,
) -> (Field, u32) {
    let values = shared_values_of(inputs, partial_of(sender, rho));
    let c = inputs_commitment(values, blinding);
    let sharing = sharing_of(AMM_SWAP_TIP_SHARED_LAYOUT, values, blinding);
    let id = shared_chain_request_id(s.app, s.vks.shared_vk_hash, c);
    let expiry = s.env.next_block_number() + 10;
    let r = shared_receipts(id, c, expiry, AMM_SWAP_TIP_SHARED_LAYOUT, values, sharing);
    s.env.call_private_opts(
        sender,
        kind_options(REQUEST_GAS),
        AmmTip::at(s.app).swap_shared(inputs[0], inputs[1], inputs[2], rho, OUTCOME_KEY, OUTCOME_TAG, sharing, expiry, r),
    );
    (id, expiry)
}

/// The round the circuit computes for the user's request of `inputs` under
/// `rho` and `blinding`, with shares that open under `shares_blinding` (the
/// request's own unless a test makes them disagree), on `reserves` under
/// `r_old`, sampling `r_new`.
pub unconstrained fn shared_round(
    s: Setup,
    inputs: [Field; 3],
    rho: Field,
    blinding: Field,
    shares_blinding: Field,
    reserves: [Field; 2],
    r_old: Field,
    r_new: Field,
) -> SharedRound {
    shared_round_of(s, inputs, partial_of(s.user, rho), blinding, shares_blinding, reserves, r_old, r_new)
}

/// `shared_round` for a request completing the partial note `partial`.
pub unconstrained fn shared_round_of(
    s: Setup,
    inputs: [Field; 3],
    partial: Field,
    blinding: Field,
    shares_blinding: Field,
    reserves: [Field; 2],
    r_old: Field,
    r_new: Field,
) -> SharedRound {
    let key = pool_key(s);
    let intake = SharedIntake {
        inputs_hash: inputs_commitment(shared_values_of(inputs, partial), blinding),
        partial,
        outcome_key: OUTCOME_KEY,
        outcome_tag: OUTCOME_TAG,
        blinding: shares_blinding,
    };
    swap_round(
        s.vks.shared_vk_hash,
        load(s.app.to_field(), key, key, reserves, r_old, r_new),
        inputs,
        intake,
        NSK_APP,
    )
}

/// The round's apply: its request id and the pool's old and new
/// commitments (the AMM pins no read).
pub unconstrained fn shared_apply(r: SharedRound) -> OutcomeApply<1, 1, 0> {
    outcome_result(r.outputs, []).apply
}

/// The relayer lands the round's result with the three nodes' signatures,
/// under the result gas setting; returns the block it landed in.
pub unconstrained fn submit_shared(s: Setup, r: SharedRound) -> u32 {
    let result: SwapSharedResult = outcome_result(r.outputs, []);
    let sigs = outcome_signatures(s.app.to_field(), r.outputs, [], NodeHeld {}.sealed_hashes());
    stage_proof(s, shared_vk());
    s.env.call_private_opts(
        s.relayer,
        kind_options(RESULT_GAS),
        AmmTip::at(s.app).process_result_shared(result, sigs),
    );
    s.env.last_block_number()
}

/// The last transaction's one private log, `[siloed tag, note hash,
/// ciphertext (3), padding (11)]`.
pub unconstrained fn outcome_log() -> BoundedVec<Field, 16> {
    let effects = txe_oracles::get_last_tx_effects();
    assert_eq(effects.private_logs.len(), 1);
    effects.private_logs.get(0)
}

/// Open the last transaction's outcome log as the trader does: its key, the
/// note hash the log carries; `[code, amount_out]`.
pub unconstrained fn opened_outcome() -> [Field; 2] {
    open_outcome_log(outcome_log(), OUTCOME_KEY)
}

/// Deliver the last transaction's completed note to `owner`'s PXE as its
/// client does: the opened outcome and the request id, under `rho`.
pub unconstrained fn deliver(s: Setup, owner: AztecAddress, rho: Field, request_id: Field) {
    let tx = last_tx();
    let packed = opened_outcome().concat([request_id]);
    s.env.execute_utility(AmmTip::at(s.app).deliver_outcome(owner, rho, packed, tx));
}

/// The swap notes `owner`'s PXE holds.
pub unconstrained fn notes_of(s: Setup, owner: AztecAddress) -> SwapNotes {
    s.env.execute_utility(AmmTip::at(s.app).swap_notes(owner))
}

/// `owner` redeems its note of request `request_id`; returns the amount.
pub unconstrained fn redeem(s: Setup, owner: AztecAddress, request_id: Field) -> Field {
    s.env.call_private(owner, AmmTip::at(s.app).redeem(request_id))
}
