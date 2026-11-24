//! TXE tests for the AmmPss contract: the Config anchor and its read request,
//! the PSS read requests, nullifiers and note pushes `apply` makes, the
//! single-use init flag, the swap hook, access control, and the total swap:
//! one landing for ok and for a failure, the no-op's continuation,
//! the two swap vk pins and the outcome encoding checks. The contract
//! has no storage and no getters, so every outcome is checked through tx
//! effects or a failure. Recursive proof verification is a no-op during
//! TXE witness execution, so the effect values are arbitrary constants;
//! the vk-hash pin in front of it runs for real.
use amm::AmmPss;
use amm::AmmPss::Config;
use amm::AmmPss::SwapOutcome;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::{poseidon2_hash, poseidon2_hash_with_separator};
use aztec::protocol::traits::Packable;
use aztec::test::helpers::test_environment::TestEnvironment;
use pss_contract::PssEffects;
use pss_tip_test::{dummy_vk, stage_proof};
use pss_tip_test::tx_effects::{
    assert_last_note_hashes, assert_last_nullifier, leaf, leaf_in_last_tx, nonce_in_last_tx,
};

// the contract artifact, compiled in its own package next to this one
global AMM: str<17> = "../amm@amm/AmmPss";

// The contract's domain separators and single-use flag, repeated here so
// the tests recompute every anchored value independently of the contract.
global DOM_SEP__AMM_ANCHOR: u32 = 0x414d4d01;
global DOM_SEP__AMM_ONCE: u32 = 0x414d4d02;
global ONCE_INIT: Field = 1;

// arbitrary MPC-side values, never checked by TXE (no-op verify). The
// note HASHES still flow through real tree inserts and read requests, and
// the nullifiers through the protocol's duplicate check.
global OWNER: Field = 0xafafaf;
global NPK_APP_HASH: Field = 0x9b9b;
global SEED_NOTE_HASH: Field = 0x5eed;
global SEED_NULLIFIER: Field = 0x05eed0;
global POOL_NOTE_HASH_0: Field = 0x9001;
global POOL_NOTE_HASH_1: Field = 0x9002;
global POOL_NOTE_HASH_2: Field = 0x9003;
global POOL_NULLIFIER_0: Field = 0x090010;
global POOL_NULLIFIER_1: Field = 0x090020;
global AMOUNT_IN: Field = 1000;
global AMOUNT_OUT: Field = 997;

// the total swap's vk, distinct from the swap's so each swap entrypoint's
// pin is tested against the other's proof
unconstrained fn total_vk() -> [Field; 115] {
    dummy_vk(8)
}

unconstrained fn make_config(operator: AztecAddress) -> Config {
    let vk_hash = poseidon2_hash(dummy_vk(7));
    Config {
        operator,
        owner: OWNER,
        npk_app_hash: NPK_APP_HASH,
        seed_vk_hash: vk_hash,
        init_vk_hash: vk_hash,
        swap_vk_hash: vk_hash,
        swap_total_vk_hash: poseidon2_hash(total_vk()),
    }
}

unconstrained fn anchor_hash(config: Config) -> Field {
    poseidon2_hash_with_separator(config.pack(), DOM_SEP__AMM_ANCHOR)
}

unconstrained fn once_nullifier(which: Field) -> Field {
    poseidon2_hash_with_separator([which], DOM_SEP__AMM_ONCE)
}

/// Everything a test needs to make the next call. Leaves are zero until
/// the call that creates the note has run.
pub struct Setup {
    env: TestEnvironment,
    contract_addr: AztecAddress,
    operator: AztecAddress,
    trader: AztecAddress,
    config: Config,
    anchor_nonce: Field,
    seed_leaf: Field,
    pool_leaf: Field,
}

unconstrained fn call_init_pool(
    env: TestEnvironment,
    contract_addr: AztecAddress,
    caller: AztecAddress,
    config: Config,
    vk: [Field; 115],
) {
    stage_proof(env, contract_addr, caller, vk);
    env.call_private(caller, AmmPss::at(contract_addr).init_pool(config, SEED_NOTE_HASH));
}

/// Deploy + init_pool, called by the operator.
unconstrained fn setup() -> Setup {
    let mut env = TestEnvironment::new();
    let operator = env.create_light_account();
    let trader = env.create_light_account();

    // the contract has no initializer; deploy it, then stage the capsule
    // at its (now known) address before calling init_pool
    let contract_addr = env.deploy(AMM).without_initializer();
    let config = make_config(operator);
    call_init_pool(env, contract_addr, operator, config, dummy_vk(7));

    // note 0 = seed, note 1 = anchor
    Setup {
        env,
        contract_addr,
        operator,
        trader,
        config,
        anchor_nonce: nonce_in_last_tx(1),
        seed_leaf: leaf_in_last_tx(0),
        pool_leaf: 0,
    }
}

unconstrained fn call_start_pool(s: Setup, caller: AztecAddress, npk_app_hash: Field) {
    stage_proof(s.env, s.contract_addr, caller, dummy_vk(7));
    s.env.call_private(
        caller,
        AmmPss::at(s.contract_addr).start_pool(
            s.config,
            s.anchor_nonce,
            [s.seed_leaf],
            [SEED_NULLIFIER],
            [POOL_NOTE_HASH_0],
            npk_app_hash,
        ),
    );
}

/// setup + start_pool: records the first pool leaf.
unconstrained fn setup_through_start_pool() -> Setup {
    let mut s = setup();
    call_start_pool(s, s.operator, NPK_APP_HASH);
    // note 0 = pool
    s.pool_leaf = leaf_in_last_tx(0);
    s
}

unconstrained fn call_swap(
    s: Setup,
    pool_leaf: Field,
    nullifier: Field,
    new_pool_note_hash: Field,
    amount_in: Field,
    direction: Field,
    vk: [Field; 115],
) {
    call_swap_from_network(
        s,
        pool_leaf,
        nullifier,
        new_pool_note_hash,
        amount_in,
        direction,
        vk,
        NPK_APP_HASH,
    );
}

unconstrained fn call_swap_from_network(
    s: Setup,
    pool_leaf: Field,
    nullifier: Field,
    new_pool_note_hash: Field,
    amount_in: Field,
    direction: Field,
    vk: [Field; 115],
    npk_app_hash: Field,
) {
    stage_proof(s.env, s.contract_addr, s.trader, vk);
    let effects = PssEffects {
        read_leaves: [pool_leaf],
        nullifiers: [nullifier],
        new_note_hashes: [new_pool_note_hash],
        npk_app_hash,
        app_outputs: [AMOUNT_OUT],
    };
    s.env.call_private(
        s.trader,
        AmmPss::at(s.contract_addr).swap(s.config, s.anchor_nonce, amount_in, direction, effects),
    );
}

/// The whole pool lifecycle with every PSS mechanism real except proof
/// validity: each call's note hashes land in the tree at the leaves
/// recomputed here, later calls read-request those leaves, and each
/// consumed note's nullifier is pushed.
#[test]
unconstrained fn full_pool_flow() {
    let s = setup();
    let c = s.contract_addr;
    assert_last_note_hashes([
        leaf(c, SEED_NOTE_HASH, nonce_in_last_tx(0)),
        leaf(c, anchor_hash(s.config), s.anchor_nonce),
    ]);
    assert_last_nullifier(c, once_nullifier(ONCE_INIT));

    // the operator turns the seed into the pool
    call_start_pool(s, s.operator, NPK_APP_HASH);
    let pool_leaf_0 = leaf(c, POOL_NOTE_HASH_0, nonce_in_last_tx(0));
    assert_last_note_hashes([pool_leaf_0]);
    assert_last_nullifier(c, SEED_NULLIFIER);

    // a trader swaps x for y, spending the first pool note
    call_swap(
        s,
        pool_leaf_0,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_1,
        AMOUNT_IN,
        0,
        dummy_vk(7),
    );
    let pool_leaf_1 = leaf(c, POOL_NOTE_HASH_1, nonce_in_last_tx(0));
    assert_last_note_hashes([pool_leaf_1]);
    assert_last_nullifier(c, POOL_NULLIFIER_0);

    // and y for x, spending the pool note the first swap created
    call_swap(
        s,
        pool_leaf_1,
        POOL_NULLIFIER_1,
        POOL_NOTE_HASH_2,
        AMOUNT_IN,
        1,
        dummy_vk(7),
    );
    assert_last_note_hashes([leaf(c, POOL_NOTE_HASH_2, nonce_in_last_tx(0))]);
    assert_last_nullifier(c, POOL_NULLIFIER_1);
}

// init_pool pushes a fixed single-use nullifier, so a second call is a
// duplicate the protocol rejects.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn init_pool_rejects_second_call() {
    let s = setup();
    call_init_pool(s.env, s.contract_addr, s.operator, s.config, dummy_vk(7));
}

#[test(should_fail_with = "only the operator")]
unconstrained fn init_pool_rejects_non_operator() {
    let mut env = TestEnvironment::new();
    let operator = env.create_light_account();
    let other = env.create_light_account();
    let contract_addr = env.deploy(AMM).without_initializer();
    call_init_pool(env, contract_addr, other, make_config(operator), dummy_vk(7));
}

#[test(should_fail_with = "unexpected verification key")]
unconstrained fn init_pool_rejects_wrong_vk() {
    let mut env = TestEnvironment::new();
    let operator = env.create_light_account();
    let contract_addr = env.deploy(AMM).without_initializer();
    // a VK whose poseidon2 hash is not the one the config pins
    call_init_pool(
        env,
        contract_addr,
        operator,
        make_config(operator),
        [9; 115],
    );
}

// A wrong anchor nonce makes the contract compose a leaf that is NOT in
// the note-hash tree, so the kernel read request fails.
#[test(should_fail_with = "Note hash read request at index 0 is reading an unknown note hash")]
unconstrained fn start_pool_rejects_wrong_anchor_nonce() {
    let mut s = setup();
    s.anchor_nonce = 0xbad;
    call_start_pool(s, s.operator, NPK_APP_HASH);
}

#[test(should_fail_with = "only the operator")]
unconstrained fn start_pool_rejects_non_operator() {
    // the msg_sender check fires before any note read
    let s = setup();
    call_start_pool(s, s.trader, NPK_APP_HASH);
}

// The effects must come from the network the Config pins.
#[test(should_fail_with = "unexpected network identity")]
unconstrained fn start_pool_rejects_other_network() {
    let s = setup();
    call_start_pool(s, s.operator, NPK_APP_HASH + 1);
}

// The seed note's nullifier is deterministic, so starting twice spends
// the seed twice.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn start_pool_rejects_second_call() {
    let s = setup_through_start_pool();
    call_start_pool(s, s.operator, NPK_APP_HASH);
}

// Replaying a spent pool note re-derives the SAME nullifier, so the
// protocol's duplicate-nullifier check rejects it; its leaf is still in
// the tree, so the read request alone would not.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn swap_rejects_replayed_pool() {
    let s = setup_through_start_pool();
    call_swap(
        s,
        s.pool_leaf,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_1,
        AMOUNT_IN,
        0,
        dummy_vk(7),
    );
    call_swap(
        s,
        s.pool_leaf,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_2,
        AMOUNT_IN,
        1,
        dummy_vk(7),
    );
}

// A pool leaf that was never created fails the read request after the
// anchor's (index 0).
#[test(should_fail_with = "Note hash read request at index 1 is reading an unknown note hash")]
unconstrained fn swap_rejects_unknown_pool_leaf() {
    let s = setup_through_start_pool();
    call_swap(
        s,
        0xbad,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_1,
        AMOUNT_IN,
        0,
        dummy_vk(7),
    );
}

// A swap's effects must come from the network the Config pins too.
#[test(should_fail_with = "unexpected network identity")]
unconstrained fn swap_rejects_other_network() {
    let s = setup_through_start_pool();
    call_swap_from_network(
        s,
        s.pool_leaf,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_1,
        AMOUNT_IN,
        0,
        dummy_vk(7),
        NPK_APP_HASH + 1,
    );
}

// A Config other than the anchored one (here: another network identity)
// composes an anchor leaf that is not in the tree.
#[test(should_fail_with = "Note hash read request at index 0 is reading an unknown note hash")]
unconstrained fn swap_rejects_unanchored_config() {
    let mut s = setup_through_start_pool();
    s.config.npk_app_hash = NPK_APP_HASH + 1;
    call_swap_from_network(
        s,
        s.pool_leaf,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_1,
        AMOUNT_IN,
        0,
        dummy_vk(7),
        NPK_APP_HASH + 1,
    );
}

#[test(should_fail_with = "unexpected verification key")]
unconstrained fn swap_rejects_wrong_vk() {
    let s = setup_through_start_pool();
    call_swap(
        s,
        s.pool_leaf,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_1,
        AMOUNT_IN,
        0,
        [9; 115],
    );
}

#[test(should_fail_with = "direction must be 0 or 1")]
unconstrained fn swap_rejects_direction_2() {
    let s = setup_through_start_pool();
    call_swap(
        s,
        s.pool_leaf,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_1,
        AMOUNT_IN,
        2,
        dummy_vk(7),
    );
}

#[test(should_fail_with = "amount_in must not be zero")]
unconstrained fn swap_rejects_zero_amount() {
    let s = setup_through_start_pool();
    call_swap(
        s,
        s.pool_leaf,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_1,
        0,
        0,
        dummy_vk(7),
    );
}

////////////// the total swap //////////////

unconstrained fn call_swap_total_from_network(
    s: Setup,
    pool_leaf: Field,
    nullifier: Field,
    new_pool_note_hash: Field,
    amount_in: Field,
    direction: Field,
    outputs: [Field; 3],
    vk: [Field; 115],
    npk_app_hash: Field,
) -> SwapOutcome {
    stage_proof(s.env, s.contract_addr, s.trader, vk);
    let effects = PssEffects {
        read_leaves: [pool_leaf],
        nullifiers: [nullifier],
        new_note_hashes: [new_pool_note_hash],
        npk_app_hash,
        app_outputs: outputs,
    };
    s.env.call_private(
        s.trader,
        AmmPss::at(s.contract_addr).swap_total(
            s.config,
            s.anchor_nonce,
            amount_in,
            direction,
            effects,
        ),
    )
}

/// A total swap on the first pool note with the app outputs
/// [ok, code, amount_out] the proof would carry.
unconstrained fn call_swap_total(
    s: Setup,
    amount_in: Field,
    direction: Field,
    outputs: [Field; 3],
) -> SwapOutcome {
    call_swap_total_from_network(
        s,
        s.pool_leaf,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_1,
        amount_in,
        direction,
        outputs,
        total_vk(),
        NPK_APP_HASH,
    )
}

/// A total swap that must land whatever ok says: the call returns the
/// outcome the proof reports, and the transaction spends the first pool
/// note and pushes exactly the new one (on ok = 0, the old reserves under
/// a fresh blinding; to the contract, a new note hash either way).
unconstrained fn assert_total_swap_lands(
    amount_in: Field,
    direction: Field,
    ok: Field,
    code: Field,
    amount_out: Field,
) {
    let s = setup_through_start_pool();
    let outcome = call_swap_total(s, amount_in, direction, [ok, code, amount_out]);
    assert_eq(outcome, SwapOutcome { ok: ok == 1, code, amount_out });
    assert_last_note_hashes([leaf(s.contract_addr, POOL_NOTE_HASH_1, nonce_in_last_tx(0))]);
    assert_last_nullifier(s.contract_addr, POOL_NULLIFIER_0);
}

#[test]
unconstrained fn swap_total_ok_trades() {
    assert_total_swap_lands(AMOUNT_IN, 0, 1, 0, AMOUNT_OUT);
}

// A failure lands as a no-op whatever its code: the contract checks only
// the encoding (ok, code, amount_out) and passes the code through, and the
// inputs reach nothing but the proof's public inputs. The bad direction
// (code 3) is one the asserting `swap` refuses in its hook (as it does the
// zero input of swap_total_no_op_then_trade, code 1); amm_swap has no proof
// for either.
#[test]
unconstrained fn swap_total_code_3_bad_direction_is_a_no_op() {
    assert_total_swap_lands(AMOUNT_IN, 2, 0, 3, 0);
}

// A no-op (code 1, a zero input) lands: it spends the first pool note and
// pushes the re-created one. After it the pool goes on from the re-created
// note: a trade spends it, through either entrypoint's pool logic (here the
// total one).
#[test]
unconstrained fn swap_total_no_op_then_trade() {
    let s = setup_through_start_pool();
    let c = s.contract_addr;
    let failed = call_swap_total(s, 0, 0, [0, 1, 0]);
    assert_eq(failed, SwapOutcome { ok: false, code: 1, amount_out: 0 });
    let pool_leaf_1 = leaf(c, POOL_NOTE_HASH_1, nonce_in_last_tx(0));
    assert_last_note_hashes([pool_leaf_1]);
    assert_last_nullifier(c, POOL_NULLIFIER_0);

    let traded = call_swap_total_from_network(
        s,
        pool_leaf_1,
        POOL_NULLIFIER_1,
        POOL_NOTE_HASH_2,
        AMOUNT_IN,
        1,
        [1, 0, AMOUNT_OUT],
        total_vk(),
        NPK_APP_HASH,
    );
    assert_eq(traded, SwapOutcome { ok: true, code: 0, amount_out: AMOUNT_OUT });
    assert_last_note_hashes([leaf(c, POOL_NOTE_HASH_2, nonce_in_last_tx(0))]);
    assert_last_nullifier(c, POOL_NULLIFIER_1);
}

// A no-op spends the pool note like a trade: the same note cannot answer
// a second swap.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn swap_total_rejects_pool_spent_by_a_no_op() {
    let s = setup_through_start_pool();
    let _ = call_swap_total(s, 0, 0, [0, 1, 0]);
    let _ = call_swap_total(s, AMOUNT_IN, 0, [1, 0, AMOUNT_OUT]);
}

// Each entrypoint takes only its own circuit's proof.
#[test(should_fail_with = "unexpected verification key")]
unconstrained fn swap_total_rejects_amm_swap_vk() {
    let s = setup_through_start_pool();
    let _ = call_swap_total_from_network(
        s,
        s.pool_leaf,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_1,
        AMOUNT_IN,
        0,
        [1, 0, AMOUNT_OUT],
        dummy_vk(7),
        NPK_APP_HASH,
    );
}

#[test(should_fail_with = "unexpected verification key")]
unconstrained fn swap_rejects_amm_swap_total_vk() {
    let s = setup_through_start_pool();
    call_swap(
        s,
        s.pool_leaf,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_1,
        AMOUNT_IN,
        0,
        total_vk(),
    );
}

#[test(should_fail_with = "unexpected network identity")]
unconstrained fn swap_total_rejects_other_network() {
    let s = setup_through_start_pool();
    let _ = call_swap_total_from_network(
        s,
        s.pool_leaf,
        POOL_NULLIFIER_0,
        POOL_NOTE_HASH_1,
        0,
        0,
        [0, 1, 0],
        total_vk(),
        NPK_APP_HASH + 1,
    );
}

// The outcome encoding checks. A valid amm_swap_total proof never
// carries these outputs; TXE's no-op verification lets them through to
// the contract's own checks.
#[test(should_fail_with = "ok must be 0 or 1")]
unconstrained fn swap_total_rejects_ok_2() {
    let s = setup_through_start_pool();
    let _ = call_swap_total(s, AMOUNT_IN, 0, [2, 0, AMOUNT_OUT]);
}

#[test(should_fail_with = "code must be 0 exactly when ok")]
unconstrained fn swap_total_rejects_failure_without_code() {
    let s = setup_through_start_pool();
    let _ = call_swap_total(s, 0, 0, [0, 0, 0]);
}

#[test(should_fail_with = "code must be 0 exactly when ok")]
unconstrained fn swap_total_rejects_trade_with_code() {
    let s = setup_through_start_pool();
    let _ = call_swap_total(s, AMOUNT_IN, 0, [1, 3, AMOUNT_OUT]);
}

#[test(should_fail_with = "a failed swap pays out nothing")]
unconstrained fn swap_total_rejects_failed_payout() {
    let s = setup_through_start_pool();
    let _ = call_swap_total(s, 0, 0, [0, 1, AMOUNT_OUT]);
}
