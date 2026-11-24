//! The example apps' requests as every test layer builds them, unsigned:
//! [`amm`] on node-held state (examples/amm) and [`monty`] on client-held
//! records (examples/monty-hall). Each builder takes the namespace and the
//! request id, so a suite chooses its own; a record-supplying request is
//! signed by the caller (`sign_as`) once its body is complete.

use rand::RngCore;
use rand::rngs::OsRng;
use sidecar_core::field::{FieldHex, RequestId};
use sidecar_core::request::StateRecord;
use sidecar_core::response::ResultRecord;
pub use sidecar_core::testing::{open, open_vec, owner_secret, request, sign_as, small, views};

/// The `in0_nonce` of the first round of each app; later rounds add 1, 2.
pub const NONCE: u64 = 0x0d935b18;

/// A fresh random request id.
pub fn random_id() -> RequestId {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    RequestId::from_u128_bytes(bytes)
}

/// A record of an answer as its owner presents it again: its three thirds
/// and their hashes.
pub fn present(record: &ResultRecord) -> StateRecord {
    StateRecord {
        key: record.key.clone(),
        note_hash: record.note_hash,
        record_hashes: record
            .c
            .clone()
            .map(|c| FieldHex(sidecar_core::record::record_hash(c.as_slice()).unwrap())),
        c: record.c.clone(),
    }
}

/// The AMM of examples/amm: a seed, the pool's init from it, swaps on the
/// pool, all node-held.
pub mod amm {
    use sidecar_core::field::{Fr, RequestId};
    use sidecar_core::request::Request;

    use super::{NONCE, request};

    pub const EXAMPLE: &str = "amm";
    pub const CIRCUITS: [&str; 3] = ["pss_seed", "amm_init", "amm_swap"];
    pub const SEED_KEY: &str = "0xa001";
    pub const POOL_KEY: &str = "0xa002";

    /// pss_seed onto the seed key.
    pub fn seed(namespace: u64, id: RequestId) -> Request {
        request(namespace, "pss_seed", id, &[], &[], &[SEED_KEY])
    }

    /// amm_init: the seed consumed, the pool written.
    pub fn init(namespace: u64, id: RequestId) -> Request {
        request(
            namespace,
            "amm_init",
            id,
            &[("in0_nonce", Fr::from(NONCE))],
            &[SEED_KEY],
            &[POOL_KEY],
        )
    }

    /// amm_swap of `amount_in`, token 0 in when `direction` is 0.
    pub fn swap(namespace: u64, id: RequestId, amount_in: u64, direction: u64) -> Request {
        request(
            namespace,
            "amm_swap",
            id,
            &[
                ("amount_in", Fr::from(amount_in)),
                ("direction", Fr::from(direction)),
                ("in0_nonce", Fr::from(NONCE)),
            ],
            &[POOL_KEY],
            &[POOL_KEY],
        )
    }

    /// The constant-product swap of examples/amm/circuits/amm: the amount out.
    pub fn swap_out(pool: [u64; 2], amount_in: u64, direction: bool) -> u64 {
        let (r_in, r_out) = if direction {
            (pool[1], pool[0])
        } else {
            (pool[0], pool[1])
        };
        ((r_out as u128) * (amount_in as u128) / ((r_in + amount_in) as u128)) as u64
    }

    /// The pool after a swap of `amount_in` paid `amount_out`.
    pub fn swapped(pool: [u64; 2], amount_in: u64, amount_out: u64, direction: bool) -> [u64; 2] {
        if direction {
            [pool[0] - amount_out, pool[1] + amount_in]
        } else {
            [pool[0] + amount_in, pool[1] - amount_out]
        }
    }
}

/// Monty Hall of examples/monty-hall: a seed record, the game's init from it,
/// open_door with the door as INPUT_SHARED values, finish; every record
/// client-held.
pub mod monty {
    use sidecar_core::field::{Fr, RequestId};
    use sidecar_core::grumpkin::{Fq, point_to_wire};
    use sidecar_core::request::{Request, StateRecord};
    use sidecar_core::schnorr::public_key;

    use super::{NONCE, request};

    pub const EXAMPLE: &str = "monty-hall";
    pub const CIRCUITS: [&str; 4] = [
        "pss_seed",
        "monty_hall_init",
        "monty_hall_open_door",
        "monty_hall_finish",
    ];
    pub const GAME_SEED_KEY: &str = "0xff01";
    pub const GAME_KEY: &str = "0xff02";

    // The game state's fields (examples/monty-hall/circuits/monty_hall):
    // [phase, prng state (4), prng position, winning_door, chosen_door,
    // open_door], then the blinding.
    pub const WINNING_DOOR: usize = 6;
    pub const CHOSEN_DOOR: usize = 7;
    /// The fields of the game state, the blinding included.
    pub const STATE_LEN: usize = 10;

    /// The player, who owns every record of the game.
    pub fn player() -> Fq {
        Fq::from(0x009a_7e12_u64)
    }

    /// Another key, which owns none.
    pub fn other() -> Fq {
        Fq::from(0x0bad_0bad_0badu64)
    }

    /// pss_seed onto the client-held seed key; it creates a record, so the
    /// caller names a requester and signs.
    pub fn seed(namespace: u64, id: RequestId) -> Request {
        request(namespace, "pss_seed", id, &[], &[], &[GAME_SEED_KEY])
    }

    /// monty_hall_init on `seed_record`.
    pub fn init(namespace: u64, id: RequestId, seed_record: &StateRecord) -> Request {
        let mut init = request(
            namespace,
            "monty_hall_init",
            id,
            &[("in0_nonce", Fr::from(NONCE))],
            &[GAME_SEED_KEY],
            &[GAME_KEY],
        );
        init.records = vec![seed_record.clone()];
        init
    }

    /// monty_hall_open_door on `game`, the player named as the requester (the
    /// envelopes' associated data covers it): the caller seals `door` and
    /// `door_randomness` to the nodes, then signs.
    pub fn open_door(namespace: u64, id: RequestId, game: &StateRecord) -> Request {
        let mut req = request(
            namespace,
            "monty_hall_open_door",
            id,
            &[("in0_nonce", Fr::from(NONCE + 1))],
            &[GAME_KEY],
            &[GAME_KEY],
        );
        req.records = vec![game.clone()];
        req.requester = Some(point_to_wire(public_key(player())));
        req
    }

    /// The door the player seals in open_door, and its blinding.
    pub fn door_inputs(door: u64) -> [(&'static str, Fr); 2] {
        [
            ("door", Fr::from(door)),
            ("door_randomness", Fr::from(0x4242u64)),
        ]
    }

    /// monty_hall_finish on `game`, switching doors.
    pub fn finish(namespace: u64, id: RequestId, game: &StateRecord) -> Request {
        let mut finish = request(
            namespace,
            "monty_hall_finish",
            id,
            &[
                ("in0_nonce", Fr::from(NONCE + 2)),
                ("switch", Fr::from(1u64)),
            ],
            &[GAME_KEY],
            &[],
        );
        finish.records = vec![game.clone()];
        finish
    }
}
