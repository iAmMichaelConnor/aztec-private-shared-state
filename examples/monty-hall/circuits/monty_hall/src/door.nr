//! The player's door: a secret-shared input (INPUT_SHARED) to
//! monty_hall_open_door, and its commitment.
//!
//! The player commits the door on chain before the round (the contract's
//! choose_door pushes `door_commitment(door, randomness)` as a raw note
//! hash). The round circuit takes door and randomness as shares,
//! recomputes the commitment and outputs it, and the contract
//! read-requests the leaf of that commitment, so the door the network
//! played is the door the player committed, and nobody but the player
//! sees it.

use protocol_types::hash::poseidon2_hash_with_separator;

/// The door commitment's domain separator, 0x4d480003 ("MH" 0003). The
/// contract's door note hashes with this exact separator
/// and input order, `[door, randomness]`, or the leaf it pins is not the
/// one the round outputs. Change it only together with the contract; it
/// also keeps the commitment apart from the contract's other hashes (the
/// Config, Game and switch notes' hashes, which are aztec-nr's default
/// note hash).
pub global DOM_SEP__MH_DOOR_CHOICE: u32 = 0x4d480003;

/// The commitment to the player's door:
/// `P2(DOM_SEP__MH_DOOR_CHOICE, door, randomness)`.
///
/// `randomness` keeps it hiding: there are only three doors, so without
/// it anyone could test all three. The contract computes it with
/// `door as Field`, which is the same value for a door below 3.
pub fn door_commitment(door: Field, randomness: Field) -> Field {
    poseidon2_hash_with_separator([door, randomness], DOM_SEP__MH_DOOR_CHOICE)
}

/// Assert that a secret-shared door is 0, 1 or 2 and return it as a u8.
///
/// `door * (door - 1) * (door - 2) == 0` holds exactly for the three
/// doors, costs two multiplications on shares and needs no bit
/// decomposition. The u8 cast after it is lossless; a cast alone would
/// map, say, 258 to 2.
pub fn assert_door(door: Field) -> u8 {
    assert(door * (door - 1) * (door - 2) == 0, "door out of range");
    door as u8
}

mod tests {
    use super::{assert_door, door_commitment};

    #[test]
    fn the_three_doors_pass() {
        assert_eq(assert_door(0), 0);
        assert_eq(assert_door(1), 1);
        assert_eq(assert_door(2), 2);
    }

    #[test(should_fail_with = "door out of range")]
    fn door_three_is_refused() {
        let _ = assert_door(3);
    }

    // 258 truncates to 2 as a u8, so only the field check refuses it
    #[test(should_fail_with = "door out of range")]
    fn a_door_that_truncates_into_range_is_refused() {
        let _ = assert_door(258);
    }

    #[test(should_fail_with = "door out of range")]
    fn minus_one_is_refused() {
        let _ = assert_door(-1);
    }

    // Known answer: the contract's door_commitment(1, 0x1234) must equal
    // this value. Regenerate only on a deliberate change of the separator.
    #[test]
    fn kat_door_commitment() {
        assert_eq(door_commitment(1, 0x1234), KAT_DOOR_COMMITMENT);
    }

    global KAT_DOOR_COMMITMENT: Field =
        0x182575f4e88c1a394f8b0e0588864cb89376e7e1ffb058bc515c48aba4b5d2e8;
}
