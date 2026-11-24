use pss_core::prng::Prng;

// The in-state phase machine: init -> opened -> finished. The round
// circuits assert the phase on the state they load, so a round is
// unprovable out of order whatever the contract or the client asks for.
// monty_hall_init writes STATE_INITIALIZED; monty_hall_open_door requires
// it and writes STATE_OPENED_DOOR; monty_hall_finish requires
// STATE_OPENED_DOOR and writes nothing: the state is nullified, and a
// nullified state is the finished game.
pub global STATE_INITIALIZED: Field = 0;
pub global STATE_OPENED_DOOR: Field = 1;

/// Fields in `GameState::as_field_array()`. The stored game-state value
/// is these fields plus the note's blinding, so its manifest `len` is
/// GAME_STATE_FIELDS + 1 = 10.
pub global GAME_STATE_FIELDS: u32 = 9;

/// The game state. On chain it exists only as a note hash over
/// `as_field_array()`. Between rounds its 9 fields and the blinding exist
/// only as secret shares: the round's STORE seals each node's third into a
/// state record the player carries and presents at the next round, so no
/// single party (a node, the orchestrator, the player) learns the winning
/// door before the game ends.
pub struct GameState {
    /// phase of the game logic (STATE_INITIALIZED / STATE_OPENED_DOOR);
    /// the round circuits assert it, so a round is unprovable out of
    /// order even if the contract were tricked into requesting it
    pub(crate) state: Field,
    /// deterministic in-state randomness (seeded at init); consumed when
    /// the host must coin-flip between two openable doors
    pub(crate) prng: Prng,
    pub(crate) winning_door: u8,
    pub(crate) chosen_door: u8,
    pub open_door: u8,
}

impl GameState {
    /// The state's embedding into a note preimage (inverse of
    /// `from_field_array`): [state, prng(5 fields), winning_door,
    /// chosen_door, open_door].
    pub fn as_field_array(self) -> [Field; GAME_STATE_FIELDS] {
        let prng = self.prng.as_field_array();
        [
            self.state,
            prng[0],
            prng[1],
            prng[2],
            prng[3],
            prng[4],
            self.winning_door as Field,
            self.chosen_door as Field,
            self.open_door as Field,
        ]
    }
    /// Inverse of `as_field_array`: reconstructs the state from a note
    /// preimage. No range asserts are needed: the array is always bound to
    /// a note hash whose preimage `as_field_array` produced in an earlier
    /// proven round, so a truncating cast can only make the hash check
    /// fail, never accept an out-of-range value.
    pub fn from_field_array(fields: [Field; GAME_STATE_FIELDS]) -> GameState {
        GameState {
            state: fields[0],
            prng: Prng::from_parts(
                [fields[1], fields[2], fields[3], fields[4]],
                fields[5] as u32,
            ),
            winning_door: fields[6] as u8,
            chosen_door: fields[7] as u8,
            open_door: fields[8] as u8,
        }
    }

    pub fn init(seed: Field) -> GameState {
        let mut prng = Prng::init(seed);
        // Widen to u64 before the modulo. A Field -> u8 truncation is
        // uniform over 256 values, and 256 % 3 == 1, so door 0 would win
        // 86/256 of games against 85/256 for doors 1 and 2. Field -> u64 is
        // uniform over 2^64, so the bias after % 3 is about 2^-64.
        let winning_door = (prng.get_field() as u64 % 3) as u8;

        let state = GameState {
            state: STATE_INITIALIZED,
            prng,
            winning_door,
            chosen_door: 0,
            open_door: 0,
        };

        state
    }

    // Returns the opened door and the new game state
    pub fn choose_door(mut state: Self, door: u8) -> (GameState, u8) {
        assert(state.state == STATE_INITIALIZED, "monty: no game to choose a door in");
        assert(door < 3, "monty: no such door");
        state.chosen_door = door;

        // Both blocks below are always evaluated (on shares nothing can
        // branch on the secret), so each must be correct and panic-free for
        // every input, not only in the case whose result is used: the
        // equal branch must never pick the winning door, and the not-equal
        // branch must not underflow u8 when winning == door. The PRNG
        // therefore advances by exactly one squeeze per choose_door call,
        // whether or not the coin flip is used.
        let calc_if_equal = {
            // Winning door == chosen door: open one of the two other doors,
            // chosen by a uniform coin flip (LSB of a fresh PRNG field).
            let rand = state.prng.get_field();
            let flip = (rand as u8) % 2;
            // the two non-winning doors: winning 0 -> {1,2}; 1 -> {0,2}; 2 -> {0,1}
            let lower = if state.winning_door == 0 { 1 } else { 0 };
            let higher = if state.winning_door == 2 { 1 } else { 2 };
            if flip == 0 {
                lower
            } else {
                higher
            }
        };

        let calc_if_not_equal = {
            // Winning door != chosen door: open the third door. The +3 and
            // % 3 keep the discarded evaluation underflow-free when
            // winning == door.
            (3 + 3 - state.winning_door - door) % 3 // 0,1 -> 2; 0,2 -> 1; 1,2 -> 0
        };

        state.open_door = if state.winning_door == door {
            calc_if_equal
        } else {
            calc_if_not_equal
        };
        state.state = STATE_OPENED_DOOR;
        let open_door = state.open_door;

        (state, open_door)
    }

    // Returns whether the player won or not
    pub fn switch(state: Self, switch: bool) -> bool {
        assert(state.state == STATE_OPENED_DOOR, "monty: no door opened yet");

        let user_door = if switch {
            3 - state.chosen_door - state.open_door // 0, 1 -> 2; 0, 2 -> 1; 1, 2 -> 0
        } else {
            state.chosen_door
        };
        user_door == state.winning_door
    }
}

#[test]
fn field_array_roundtrip() {
    let game = GameState::init(123);
    let (game, _) = GameState::choose_door(game, 1);
    let back = GameState::from_field_array(game.as_field_array());
    assert(back.as_field_array() == game.as_field_array());
    // and the reconstructed state behaves identically
    assert(GameState::switch(back, true) == GameState::switch(game, true));
}

// Sweep over many seeds and all doors: every (winning, chosen) pair must
// satisfy the Monty Hall invariants, with both switch values.
#[test]
fn test_all_winning_chosen_pairs() {
    // 30 seeds is plenty to hit every winning door and both coin flips;
    // seen_winning checks we actually covered all three.
    let mut seen_winning = [false; 3];
    for seed in 0..30 {
        let game = GameState::init(seed as Field);
        seen_winning[game.winning_door as u32] = true;
        for choice in 0..3 {
            let (game_after, opened) = GameState::choose_door(game, choice);
            // the host must never open the winning door nor the chosen door
            assert(opened < 3);
            assert(opened != game.winning_door);
            assert(opened != choice);
            // sticking wins iff the player already chose the winning door;
            // switching wins iff they hadn't
            let picked_winning = choice == game.winning_door;
            assert(GameState::switch(game_after, false) == picked_winning);
            assert(GameState::switch(game_after, true) == !picked_winning);
        }
    }
    assert(seen_winning[0] & seen_winning[1] & seen_winning[2]);
}

#[test]
fn test_equal_choice_coin_flip_covers_both_doors() {
    // when chosen == winning, the opened door is coin-flipped between the
    // two non-winning doors — over many seeds both must occur for every
    // winning door
    let mut seen = [[false; 3]; 3]; // seen[winning][opened]
    for seed in 0..60 {
        let game = GameState::init(seed as Field);
        let (_, opened) = GameState::choose_door(game, game.winning_door as u8);
        seen[game.winning_door as u32][opened as u32] = true;
    }
    assert(seen[0][1] & seen[0][2]);
    assert(seen[1][0] & seen[1][2]);
    assert(seen[2][0] & seen[2][1]);
}

#[test(should_fail_with = "monty: no such door")]
fn test_choose_door_out_of_range_rejected() {
    let game = GameState::init(123);
    let (_, _) = GameState::choose_door(game, 3);
}

#[test(should_fail_with = "monty: no game to choose a door in")]
fn test_choose_door_twice_rejected() {
    let game = GameState::init(123);
    let (game, _) = GameState::choose_door(game, 0);
    let (_, _) = GameState::choose_door(game, 0); // state machine forbids
}

#[test(should_fail_with = "monty: no door opened yet")]
fn test_switch_before_choose_rejected() {
    let game = GameState::init(123);
    let _ = GameState::switch(game, false);
}
