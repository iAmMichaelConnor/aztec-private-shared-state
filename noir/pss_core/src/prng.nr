// Derived from TaceoLabs/monty-hall-aztec (MIT; the root NOTICE).
//
// A deterministic PRNG over a Poseidon2 sponge (not SAFE-tagged: the state
// starts [seed, 0, 0, 0] with no IO pattern or domain separator), squeezing
// state[0..3] after each permutation. `position` is in 0..=3: a state
// rebuilt with `from_parts` keeps that invariant because its fields come
// from a proven note preimage `as_field_array` wrote.
pub struct Prng {
    pub(crate) state: [Field; 4],
    pub(crate) position: u32,
}

impl Prng {
    pub fn init(seed: Field) -> Prng {
        Prng { state: [seed, 0, 0, 0], position: 3 }
    }

    /// Reconstruct from a note preimage (see GameState::from_field_array)
    pub fn from_parts(state: [Field; 4], position: u32) -> Prng {
        Prng { state, position }
    }

    pub fn get_field(&mut self) -> Field {
        if self.position == 3 {
            self.state = std::hash::poseidon2_permutation(self.state);
            self.position = 0;
        }
        let result = self.state[self.position];
        self.position += 1;
        result
    }
}

impl Prng {
    /// The PRNG's embedding into a note preimage (inverse of
    /// `from_parts`): the 4 sponge-state fields followed by the squeeze
    /// position. Used by `GameState::as_field_array`.
    pub fn as_field_array(self) -> [Field; 5] {
        [self.state[0], self.state[1], self.state[2], self.state[3], self.position as Field]
    }
}

// KAT: pins the exact output sequence (incl. the wraparound at squeeze 4).
// A refactor of the sponge/permutation wiring must turn this red — the
// PRNG drives the on-chain-committed game state.
#[test]
fn kat_seed_1_first_four_squeezes() {
    let mut p = Prng::init(1);
    assert_eq(p.get_field(), 0x02a04ea402711ced2d4bc39608cc5350a7db4af98ec2950d4d1ec30334d6c2b4);
    assert_eq(p.get_field(), 0x0b9039204e2e27025672e86acd47656de1ccacf7d9c25c0f2d88ff24dd3d2077);
    assert_eq(p.get_field(), 0x01ddc55d5963f56b030d4b87c27e7ef4a803fd4b6333d074c37f5f501aff23ee);
    assert_eq(p.get_field(), 0x02e0e17c656fe5ce4db2eec847236f493636a2f6d88592733f64c08b450e4cea);
}
