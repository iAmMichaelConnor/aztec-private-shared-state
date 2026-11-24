//! TXE tests for the MontyHall contract: the operator's Config note and the
//! player's Game note (created, delivered and read by their owners; the
//! happy paths pass only if each carries the pins the tests set), the
//! PSS read requests, nullifiers and note pushes `apply` makes for each
//! round, the network and verification-key pins, the door pin on the
//! open_door circuit's output, the player's door and switch notes, the
//! single-use flags, and access control (every call reads its caller's own
//! note, so another caller fails the read). Outcomes are checked through tx
//! effects or a failure. Recursive proof verification is a no-op during TXE
//! witness execution, so the network-side values are arbitrary constants;
//! the vk-hash pin in front of it runs for real.
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::{poseidon2_hash, poseidon2_hash_with_separator};
use aztec::test::helpers::test_environment::TestEnvironment;
use montyhall::MontyHall;
use montyhall::notes::{Config, DoorNote};
use pss_contract::PssEffects;
use pss_tip_test::{dummy_vk, stage_proof};
use pss_tip_test::tx_effects::{
    assert_last_note_hash_count, assert_last_note_hashes, assert_last_nullifier, leaf,
    leaf_in_last_tx, nonce_in_last_tx,
};

// the contract artifact, compiled in its own package next to this one
global MONTY_HALL: str<32> = "../montyhall@montyhall/MontyHall";

// The contract's single-use domain and flag, repeated here so the tests
// recompute every raw value independently of the contract. The door
// commitment is the circuit's (`DoorNote::commitment`), pinned by its
// known-answer test in the circuit library.
global DOM_SEP__MH_ONCE: u32 = 0x4d480005;
global ONCE_INIT: Field = 1;

// arbitrary network-side values, never checked by TXE (no-op verify). The
// note HASHES still flow through real tree inserts and read requests, and
// the nullifiers through the protocol's duplicate check.
global OWNER: Field = 0xafafaf;
global NPK_APP_HASH: Field = 0x9b9b;
global SEED_NOTE_HASH: Field = 0x5eed;
global SEED_NULLIFIER: Field = 0x05eed0;
global STATE_NOTE_HASH_0: Field = 0x57a7e0;
global STATE_NOTE_HASH_1: Field = 0x57a7e1;
global STATE_NULLIFIER_0: Field = 0x0111;
global STATE_NULLIFIER_1: Field = 0x0222;
global OPENED_DOOR: Field = 0;
global WIN: Field = 1;

// the player's choices and the randomness that hides the door
global DOOR: u8 = 2;
global DOOR_RANDOMNESS: Field = 0xd00d;
global SWITCH: bool = true;

unconstrained fn make_config(player: AztecAddress) -> Config {
    let vk_hash = poseidon2_hash(dummy_vk(7));
    Config {
        player,
        owner: OWNER,
        npk_app_hash: NPK_APP_HASH,
        seed_vk_hash: vk_hash,
        init_vk_hash: vk_hash,
        open_vk_hash: vk_hash,
        finish_vk_hash: vk_hash,
    }
}

unconstrained fn once_nullifier(which: Field) -> Field {
    poseidon2_hash_with_separator([which], DOM_SEP__MH_ONCE)
}

/// The commitment the open_door circuit outputs as `app_outputs[1]`, and
/// the note hash of the player's door note.
unconstrained fn door_commitment(door: u8, randomness: Field) -> Field {
    DoorNote { door, randomness }.commitment()
}

/// Everything a test needs to make the next call. `state_leaf` is the
/// current game-state leaf, zero until start_game has run.
pub struct Setup {
    env: TestEnvironment,
    contract_addr: AztecAddress,
    operator: AztecAddress,
    player: AztecAddress,
    config: Config,
    seed_leaf: Field,
    state_leaf: Field,
}

/// What a test may vary in a round's effects and proof.
pub struct Round {
    caller: AztecAddress,
    read_leaf: Field,
    nullifier: Field,
    npk_app_hash: Field,
    vk: [Field; 115],
}

unconstrained fn call_init_game(
    env: TestEnvironment,
    contract_addr: AztecAddress,
    caller: AztecAddress,
    config: Config,
    vk: [Field; 115],
) {
    stage_proof(env, contract_addr, caller, vk);
    env.call_private(caller, MontyHall::at(contract_addr).init_game(config, SEED_NOTE_HASH));
}

/// Deploy without init_game.
unconstrained fn deploy() -> Setup {
    let mut env = TestEnvironment::new();
    let operator = env.create_light_account();
    let player = env.create_light_account();
    // the contract has no initializer; deploy it, then stage capsules at
    // its (now known) address
    let contract_addr = env.deploy(MONTY_HALL).without_initializer();
    Setup {
        env,
        contract_addr,
        operator,
        player,
        config: make_config(player),
        seed_leaf: 0,
        state_leaf: 0,
    }
}

/// Deploy + init_game, called by the operator.
unconstrained fn setup() -> Setup {
    let mut s = deploy();
    call_init_game(s.env, s.contract_addr, s.operator, s.config, dummy_vk(7));
    // note 0 = seed, note 1 = the operator's Config note
    s.seed_leaf = leaf_in_last_tx(0);
    s
}

/// The start_game round as the operator makes it: spends the seed.
unconstrained fn start_round(s: Setup) -> Round {
    Round {
        caller: s.operator,
        read_leaf: s.seed_leaf,
        nullifier: SEED_NULLIFIER,
        npk_app_hash: NPK_APP_HASH,
        vk: dummy_vk(7),
    }
}

unconstrained fn call_start_game(s: Setup, r: Round) {
    stage_proof(s.env, s.contract_addr, r.caller, r.vk);
    s.env.call_private(
        r.caller,
        MontyHall::at(s.contract_addr).start_game(
            [r.read_leaf],
            [r.nullifier],
            [STATE_NOTE_HASH_0],
            r.npk_app_hash,
        ),
    );
}

/// setup + start_game: records the first game-state leaf.
unconstrained fn setup_through_start_game() -> Setup {
    let mut s = setup();
    call_start_game(s, start_round(s));
    // note 0 = game state, note 1 = the player's Game note
    s.state_leaf = leaf_in_last_tx(0);
    s
}

unconstrained fn call_choose_door(s: Setup, caller: AztecAddress, door: u8) {
    s.env.call_private(
        caller,
        MontyHall::at(s.contract_addr).choose_door(door, DOOR_RANDOMNESS),
    );
}

/// setup + start_game + the player's door note.
unconstrained fn setup_through_choose_door() -> Setup {
    let s = setup_through_start_game();
    call_choose_door(s, s.player, DOOR);
    s
}

/// The open_door round as the player makes it: spends the current state.
unconstrained fn open_round(s: Setup) -> Round {
    Round {
        caller: s.player,
        read_leaf: s.state_leaf,
        nullifier: STATE_NULLIFIER_0,
        npk_app_hash: NPK_APP_HASH,
        vk: dummy_vk(7),
    }
}

unconstrained fn call_open_door_with(s: Setup, r: Round, door_commitment: Field) {
    stage_proof(s.env, s.contract_addr, r.caller, r.vk);
    let effects = PssEffects {
        read_leaves: [r.read_leaf],
        nullifiers: [r.nullifier],
        new_note_hashes: [STATE_NOTE_HASH_1],
        npk_app_hash: r.npk_app_hash,
        app_outputs: [OPENED_DOOR, door_commitment],
    };
    s.env.call_private(
        r.caller,
        MontyHall::at(s.contract_addr).open_door(effects),
    );
}

/// open_door with the commitment of the door the player committed.
unconstrained fn call_open_door(s: Setup, r: Round) {
    call_open_door_with(s, r, door_commitment(DOOR, DOOR_RANDOMNESS));
}

/// setup + start_game + choose_door + open_door: records the post-open
/// game-state leaf.
unconstrained fn setup_through_open_door() -> Setup {
    let mut s = setup_through_choose_door();
    call_open_door(s, open_round(s));
    // note 0 = next game state
    s.state_leaf = leaf_in_last_tx(0);
    s
}

unconstrained fn call_switch_door(s: Setup, caller: AztecAddress) {
    s.env.call_private(
        caller,
        MontyHall::at(s.contract_addr).switch_door(SWITCH),
    );
}

/// The finish_game round as the player makes it: spends the current state.
unconstrained fn finish_round(s: Setup) -> Round {
    Round {
        caller: s.player,
        read_leaf: s.state_leaf,
        nullifier: STATE_NULLIFIER_1,
        npk_app_hash: NPK_APP_HASH,
        vk: dummy_vk(7),
    }
}

unconstrained fn call_finish_game(s: Setup, r: Round) {
    stage_proof(s.env, s.contract_addr, r.caller, r.vk);
    s.env.call_private(
        r.caller,
        MontyHall::at(s.contract_addr).finish_game(
            [r.read_leaf],
            [r.nullifier],
            r.npk_app_hash,
            [WIN],
        ),
    );
}

/// The whole game with every PSS mechanism real except proof validity:
/// each call's note hashes land in the tree at the leaves recomputed here,
/// later calls read-request those leaves (the network-held notes by value,
/// the Config, Game, door and switch notes through their owners' PXEs), and
/// each consumed note's nullifier is pushed.
#[test]
unconstrained fn full_game_flow() {
    let mut s = setup();
    let c = s.contract_addr;
    // the seed note, then the operator's Config note
    assert_last_note_hash_count(2);
    assert_eq(leaf_in_last_tx(0), leaf(c, SEED_NOTE_HASH, nonce_in_last_tx(0)));
    assert_last_nullifier(c, once_nullifier(ONCE_INIT));

    // the operator turns the seed into the game state and gives the player
    // the Game note
    call_start_game(s, start_round(s));
    let state_leaf_0 = leaf(c, STATE_NOTE_HASH_0, nonce_in_last_tx(0));
    assert_last_note_hash_count(2);
    assert_eq(leaf_in_last_tx(0), state_leaf_0);
    assert_last_nullifier(c, SEED_NULLIFIER);
    s.state_leaf = state_leaf_0;

    // the player's door note: its note hash is the door commitment
    call_choose_door(s, s.player, DOOR);
    assert_last_note_hashes(
        [
            leaf(
                c,
                door_commitment(DOOR, DOOR_RANDOMNESS),
                nonce_in_last_tx(0),
            ),
        ],
    );

    // the host opens a door, spending the first game state
    call_open_door(s, open_round(s));
    let state_leaf_1 = leaf(c, STATE_NOTE_HASH_1, nonce_in_last_tx(0));
    assert_last_note_hashes([state_leaf_1]);
    assert_last_nullifier(c, STATE_NULLIFIER_0);
    s.state_leaf = state_leaf_1;

    // the player's switch note
    call_switch_door(s, s.player);
    assert_last_note_hash_count(1);

    // the host reveals the result, spending the last state; nothing replaces it
    call_finish_game(s, finish_round(s));
    assert_last_note_hashes([]);
    assert_last_nullifier(c, STATE_NULLIFIER_1);
}

// The switch may be committed early: before the door and before open_door.
// It does not change the result.
#[test]
unconstrained fn switch_may_come_early() {
    let mut s = setup_through_start_game();
    call_switch_door(s, s.player);
    call_choose_door(s, s.player, DOOR);
    call_open_door(s, open_round(s));
    s.state_leaf = leaf_in_last_tx(0);
    call_finish_game(s, finish_round(s));
    assert_last_nullifier(s.contract_addr, STATE_NULLIFIER_1);
}

// ---- init_game ----

// init_game pushes a fixed single-use nullifier (and the Config's
// initialisation nullifier), so a second call is a duplicate the protocol
// rejects.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn init_game_rejects_second_call() {
    let s = setup();
    call_init_game(s.env, s.contract_addr, s.operator, s.config, dummy_vk(7));
}

// The Config's initialisation nullifier is per owner, so it would not stop
// another account; the once-nullifier is a constant and does: a second
// game cannot be seeded on this deployment.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn init_game_rejects_second_operator() {
    let s = setup();
    call_init_game(s.env, s.contract_addr, s.player, make_config(s.operator), dummy_vk(7));
}

// A zero player could never make its moves; the check fires before the
// proof is loaded.
#[test(should_fail_with = "player must not be zero")]
unconstrained fn init_game_rejects_zero_player() {
    let s = deploy();
    s.env.call_private(
        s.operator,
        MontyHall::at(s.contract_addr).init_game(make_config(AztecAddress::zero()), SEED_NOTE_HASH),
    );
}

#[test(should_fail_with = "unexpected verification key")]
unconstrained fn init_game_rejects_wrong_vk() {
    let s = deploy();
    // a VK whose poseidon2 hash is not the one the config pins
    call_init_game(s.env, s.contract_addr, s.operator, s.config, [9; 115]);
}

// ---- start_game ----

// The player holds no Config, so its start_game has no note to read.
#[test(should_fail_with = "Failed to get a note")]
unconstrained fn start_game_rejects_non_operator() {
    let s = setup();
    let mut r = start_round(s);
    r.caller = s.player;
    call_start_game(s, r);
}

// Without init_game there is no Config to read.
#[test(should_fail_with = "Failed to get a note")]
unconstrained fn start_game_rejects_before_init_game() {
    let s = deploy();
    call_start_game(s, start_round(s));
}

// A seed leaf that was never created fails its read request, the one after
// the Config note's.
#[test(should_fail_with = "Note hash read request at index 1 is reading an unknown note hash")]
unconstrained fn start_game_rejects_unknown_seed_leaf() {
    let s = setup();
    let mut r = start_round(s);
    r.read_leaf = 0xbad;
    call_start_game(s, r);
}

// The npk_app_hash is pinned at deployment: a round from another network
// is refused.
#[test(should_fail_with = "unexpected network identity")]
unconstrained fn start_game_rejects_other_network() {
    let s = setup();
    let mut r = start_round(s);
    r.npk_app_hash = NPK_APP_HASH + 1;
    call_start_game(s, r);
}

#[test(should_fail_with = "unexpected verification key")]
unconstrained fn start_game_rejects_wrong_vk() {
    let s = setup();
    let mut r = start_round(s);
    r.vk = [9; 115];
    call_start_game(s, r);
}

// The seed note's nullifier is deterministic, so starting twice spends
// the seed twice; a second Game note is never created.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn start_game_rejects_second_call() {
    let s = setup_through_start_game();
    call_start_game(s, start_round(s));
}

// ---- choose_door ----

// The operator holds no Game note, so it cannot commit a door.
#[test(should_fail_with = "Failed to get a note")]
unconstrained fn choose_door_rejects_non_player() {
    let s = setup_through_start_game();
    call_choose_door(s, s.operator, DOOR);
}

// Before start_game the player holds no Game note.
#[test(should_fail_with = "Failed to get a note")]
unconstrained fn choose_door_rejects_before_start_game() {
    let s = setup();
    call_choose_door(s, s.player, DOOR);
}

#[test(should_fail_with = "door out of range")]
unconstrained fn choose_door_rejects_door_out_of_range() {
    let s = setup_through_start_game();
    call_choose_door(s, s.player, 3);
}

// The door note is a PrivateImmutable: its initialisation nullifier makes
// a second choice a duplicate.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn choose_door_rejects_second_call() {
    let s = setup_through_choose_door();
    call_choose_door(s, s.player, DOOR - 1);
}

// ---- open_door ----

// The operator holds no Game note.
#[test(should_fail_with = "Failed to get a note")]
unconstrained fn open_door_rejects_operator() {
    let s = setup_through_choose_door();
    let mut r = open_round(s);
    r.caller = s.operator;
    call_open_door(s, r);
}

// Before start_game the player holds no Game note.
#[test(should_fail_with = "Failed to get a note")]
unconstrained fn open_door_rejects_before_start_game() {
    let s = setup();
    let mut r = open_round(s);
    r.read_leaf = 0xbad;
    call_open_door(s, r);
}

// Without choose_door the player has no door note to read.
#[test(should_fail_with = "Failed to get a note")]
unconstrained fn open_door_rejects_missing_door_choice() {
    let s = setup_through_start_game();
    call_open_door(s, open_round(s));
}

// A game-state leaf that was never created fails its read request, the one
// after the Game note's.
#[test(should_fail_with = "Note hash read request at index 1 is reading an unknown note hash")]
unconstrained fn open_door_rejects_unknown_state_leaf() {
    let s = setup_through_choose_door();
    let mut r = open_round(s);
    r.read_leaf = 0xbad;
    call_open_door(s, r);
}

// The network must have played the committed door: a proof whose door
// commitment is another door's is refused.
#[test(should_fail_with = "not the committed door")]
unconstrained fn open_door_rejects_other_door() {
    let s = setup_through_choose_door();
    call_open_door_with(s, open_round(s), door_commitment(DOOR - 1, DOOR_RANDOMNESS));
}

// ... and so is one over the right door with other randomness.
#[test(should_fail_with = "not the committed door")]
unconstrained fn open_door_rejects_other_door_randomness() {
    let s = setup_through_choose_door();
    call_open_door_with(s, open_round(s), door_commitment(DOOR, DOOR_RANDOMNESS + 1));
}

#[test(should_fail_with = "unexpected network identity")]
unconstrained fn open_door_rejects_other_network() {
    let s = setup_through_choose_door();
    let mut r = open_round(s);
    r.npk_app_hash = NPK_APP_HASH + 1;
    call_open_door(s, r);
}

#[test(should_fail_with = "unexpected verification key")]
unconstrained fn open_door_rejects_wrong_vk() {
    let s = setup_through_choose_door();
    let mut r = open_round(s);
    r.vk = [9; 115];
    call_open_door(s, r);
}

// Replaying a spent game state re-derives the SAME nullifier, so the
// protocol's duplicate check rejects it; its leaf is still in the tree,
// so the read request alone would not.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn open_door_rejects_replayed_state() {
    let s = setup_through_choose_door();
    call_open_door(s, open_round(s));
    call_open_door(s, open_round(s));
}

// ---- switch_door ----

// The operator holds no Game note.
#[test(should_fail_with = "Failed to get a note")]
unconstrained fn switch_door_rejects_non_player() {
    let s = setup_through_open_door();
    call_switch_door(s, s.operator);
}

// Before start_game the player holds no Game note.
#[test(should_fail_with = "Failed to get a note")]
unconstrained fn switch_door_rejects_before_start_game() {
    let s = setup();
    call_switch_door(s, s.player);
}

#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn switch_door_rejects_second_call() {
    let s = setup_through_open_door();
    call_switch_door(s, s.player);
    call_switch_door(s, s.player);
}

// ---- finish_game ----

// The operator holds no Game note.
#[test(should_fail_with = "Failed to get a note")]
unconstrained fn finish_game_rejects_operator() {
    let s = setup_through_open_door();
    call_switch_door(s, s.player);
    let mut r = finish_round(s);
    r.caller = s.operator;
    call_finish_game(s, r);
}

// Without switch_door there is no switch note, so the round has no app
// input to bind.
#[test(should_fail_with = "Failed to get a note")]
unconstrained fn finish_game_rejects_missing_switch_choice() {
    let s = setup_through_open_door();
    call_finish_game(s, finish_round(s));
}

// Finishing against the already-spent first game state: its leaf is
// still in the tree, but its nullifier is a duplicate.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn finish_game_rejects_replayed_state() {
    // s.state_leaf stays the first state's leaf
    let s = setup_through_choose_door();
    call_open_door(s, open_round(s));
    call_switch_door(s, s.player);
    let mut r = finish_round(s);
    r.nullifier = STATE_NULLIFIER_0;
    call_finish_game(s, r);
}

// The game is over after one finish: the last state is spent.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn finish_game_rejects_second_call() {
    let s = setup_through_open_door();
    call_switch_door(s, s.player);
    call_finish_game(s, finish_round(s));
    call_finish_game(s, finish_round(s));
}

#[test(should_fail_with = "unexpected network identity")]
unconstrained fn finish_game_rejects_other_network() {
    let s = setup_through_open_door();
    call_switch_door(s, s.player);
    let mut r = finish_round(s);
    r.npk_app_hash = NPK_APP_HASH + 1;
    call_finish_game(s, r);
}

#[test(should_fail_with = "unexpected verification key")]
unconstrained fn finish_game_rejects_wrong_vk() {
    let s = setup_through_open_door();
    call_switch_door(s, s.player);
    let mut r = finish_round(s);
    r.vk = [9; 115];
    call_finish_game(s, r);
}
