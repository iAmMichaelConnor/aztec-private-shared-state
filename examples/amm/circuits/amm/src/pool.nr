use pss_core::prng::Prng;

/// Lowest starting reserve, default 1_000_000; `from_seed` adds a
/// pseudo-random offset below `SEED_RESERVE_SPAN` (default 1_000_000) to
/// it, so each reserve starts in [1e6, 2e6) and the starting price lies in
/// (0.5, 2), chosen by nobody. A wider span hides the price better and
/// allows extreme starting prices; changing either constant changes
/// amm_init's circuit and its vk hash.
global SEED_RESERVE_BASE: u64 = 1_000_000;
global SEED_RESERVE_SPAN: u64 = 1_000_000;

/// A constant-product pool whose reserves exist only as a PSS note. On
/// chain it is a note hash over `as_field_array()`; between rounds the
/// MPC nodes hold the two reserves as secret shares, so nobody learns
/// them, only the `amount_out` each swap reveals.
pub struct Pool {
    pub x: u64,
    pub y: u64,
}

impl Pool {
    /// Starting reserves drawn from the seed note, so the pool starts at a
    /// price nobody chose or knows.
    pub fn from_seed(seed: Field) -> Pool {
        let mut prng = Prng::init(seed);
        // Field->u64 truncation is uniform over 2^64, so the residual bias
        // of `% SEED_RESERVE_SPAN` is ~2^-44: negligible.
        let x = SEED_RESERVE_BASE + (prng.get_field() as u64 % SEED_RESERVE_SPAN);
        let y = SEED_RESERVE_BASE + (prng.get_field() as u64 % SEED_RESERVE_SPAN);
        Pool { x, y }
    }

    /// Swap `amount_in` of one asset for the other. `direction` false
    /// sells x for y, true sells y for x. Returns the new pool and the
    /// amount paid out:
    ///   out = r_out * in / (r_in + in)   (rounded down)
    /// Rounding down keeps the product of the reserves from decreasing.
    pub fn swap(self, amount_in: u64, direction: bool) -> (Pool, u64) {
        assert(amount_in > 0, "swap: zero input");
        let (r_in, r_out) = if direction { (self.y, self.x) } else { (self.x, self.y) };
        // u64 addition fails on overflow, so the new reserve fits a u64
        let new_in = r_in + amount_in;
        // r_out * in < 2^128, so the u128 product cannot overflow
        let out = ((r_out as u128) * (amount_in as u128) / (new_in as u128)) as u64;
        assert(out > 0, "swap: output rounds to zero");
        assert(out < r_out, "swap: output drains the pool");
        let new_out = r_out - out;
        let pool = if direction {
            Pool { x: new_out, y: new_in }
        } else {
            Pool { x: new_in, y: new_out }
        };
        (pool, out)
    }

    /// The pool's embedding into a note preimage: [x, y].
    pub fn as_field_array(self) -> [Field; 2] {
        [self.x as Field, self.y as Field]
    }

    /// Inverse of `as_field_array`. No range asserts needed: the array is
    /// always bound to a note hash whose preimage was produced by
    /// `as_field_array` in a previously PROVEN round, so a truncating
    /// cast can only make the hash check fail, never accept out-of-range
    /// values.
    pub fn from_field_array(fields: [Field; 2]) -> Pool {
        Pool { x: fields[0] as u64, y: fields[1] as u64 }
    }

    fn product(self) -> u128 {
        (self.x as u128) * (self.y as u128)
    }
}

#[test]
fn from_seed_reserves_in_range_and_vary() {
    let mut differs = false;
    let first = Pool::from_seed(0);
    for seed in 0..20 {
        let pool = Pool::from_seed(seed as Field);
        assert(pool.x >= SEED_RESERVE_BASE);
        assert(pool.x < SEED_RESERVE_BASE + SEED_RESERVE_SPAN);
        assert(pool.y >= SEED_RESERVE_BASE);
        assert(pool.y < SEED_RESERVE_BASE + SEED_RESERVE_SPAN);
        differs |= (pool.x != first.x) | (pool.y != first.y);
    }
    assert(differs);
}

#[test]
fn product_never_decreases() {
    // many seeds x a run of swaps of varying size, alternating direction
    for seed in 0..10 {
        let mut pool = Pool::from_seed(seed as Field);
        let mut prng = Prng::init(seed as Field + 1000);
        for i in 0..20 {
            // inputs from 1_000 up to ~1e6, i.e. up to about half the pool
            let amount_in = 1_000 + (prng.get_field() as u64 % 1_000_000);
            let before = pool.product();
            let (next, out) = pool.swap(amount_in, i % 2 == 1);
            assert(out > 0);
            assert(next.product() >= before);
            pool = next;
        }
    }
}

#[test]
fn swap_x_for_y() {
    let pool = Pool { x: 1_000_000, y: 2_000_000 };
    let (next, out) = pool.swap(1_000, false);
    // 2_000_000 * 1_000 / 1_001_000 = 1998.002 -> 1998
    assert_eq(out, 1998);
    assert_eq(next.x, 1_001_000);
    assert_eq(next.y, 2_000_000 - 1998);
}

#[test]
fn swap_y_for_x() {
    let pool = Pool { x: 1_000_000, y: 2_000_000 };
    let (next, out) = pool.swap(1_000, true);
    // 1_000_000 * 1_000 / 2_001_000 = 499.75 -> 499
    assert_eq(out, 499);
    assert_eq(next.x, 1_000_000 - 499);
    assert_eq(next.y, 2_001_000);
}

#[test]
fn round_trip_swap_does_not_profit() {
    // selling the proceeds straight back returns no more than was put in
    let pool = Pool::from_seed(7);
    let (pool, y_out) = pool.swap(50_000, false);
    let (_, x_back) = pool.swap(y_out, true);
    assert(x_back <= 50_000);
}

#[test]
fn field_array_round_trip() {
    let pool = Pool::from_seed(123);
    let (pool, _) = pool.swap(12_345, true);
    let back = Pool::from_field_array(pool.as_field_array());
    assert_eq(back.x, pool.x);
    assert_eq(back.y, pool.y);
    assert(back.as_field_array() == pool.as_field_array());
}

#[test(should_fail_with = "zero input")]
fn zero_input_rejected() {
    let _ = Pool { x: 1_000_000, y: 1_000_000 }.swap(0, false);
}

#[test(should_fail_with = "rounds to zero")]
fn dust_input_rejected() {
    // 1_000_000 * 1 / 2_000_001 rounds to 0
    let _ = Pool { x: 2_000_000, y: 1_000_000 }.swap(1, false);
}

#[test(should_fail_with = "attempt to add with overflow")]
fn oversize_input_rejected() {
    // the new input reserve would not fit a u64
    let _ = Pool { x: 1_000_000, y: 1_000_000 }.swap(0xffffffffffffffff, false);
}

#[test(should_fail_with = "drains the pool")]
fn empty_input_reserve_rejected() {
    // with r_in = 0 the formula pays out the whole of r_out
    let _ = Pool { x: 0, y: 1_000_000 }.swap(5, false);
}
