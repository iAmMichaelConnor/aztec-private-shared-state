//! The registration circuit: the one machine-defined circuit that receives a
//! node's master nullifier share. It runs at a namespace's `seq` 0 REGISTER,
//! through the same executor and self-verification as a round, and derives
//! the namespace's nullifier key:
//!
//!   nsk_app      = poseidon2_hash_with_separator([master, namespace], SIDECAR_NSK_APP)
//!   npk_app_hash = poseidon2_hash_with_separator([(nsk_app·G).x, (nsk_app·G).y], SIDECAR_NPK_APP)
//!
//! `nsk_app` leaves only as shares, through `TACEO_store("nsk_app", [nsk_app])`;
//! `npk_app_hash` is the proven public output a contract pins.
//!
//! Public inputs (2), in ACIR order: [namespace, npk_app_hash].

use poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurveScalar, fixed_base_scalar_mul};

// The derivation constants. SIDECAR_NSK_APP and SIDECAR_NPK_APP
// are ASCII "sidecar.nsk_app" and "sidecar.npk_app" read as big-endian
// integers, the machine's own separators (sidecar-core grumpkin.rs and
// pss_core aztec_note.nr carry the same values). The formula is fixed: one
// Poseidon2 hash of the master and the namespace, one fixed-base Grumpkin
// multiplication, one Poseidon2 hash of the point. Changing a constant or the
// formula changes this circuit's verification key and every namespace's
// npk_app_hash, so contracts pinned to the old values stop accepting rounds.
pub global SIDECAR_NSK_APP: Field = 0x736964656361722e6e736b5f617070;
pub global SIDECAR_NPK_APP: Field = 0x736964656361722e6e706b5f617070;

/// protocol_types' `poseidon2_hash_with_separator`: the sponge over
/// `[separator, inputs...]`.
fn hash_with_separator<let N: u32>(inputs: [Field; N], separator: Field) -> Field {
    let preimage = [separator].concat(inputs);
    Poseidon2::hash(preimage, N + 1)
}

/// The namespace's nullifier key and the hash of its public key.
pub fn derive(master: Field, namespace: Field) -> (Field, Field) {
    let nsk_app = hash_with_separator([master, namespace], SIDECAR_NSK_APP);
    // Every Field is a valid Grumpkin scalar (the BN254 scalar field is the
    // smaller one), so `from_field` loses nothing.
    let npk_app = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(nsk_app));
    (nsk_app, hash_with_separator([npk_app.x, npk_app.y], SIDECAR_NPK_APP))
}

#[oracle(TACEO_store)]
unconstrained fn store_oracle<let N: u32, let S: u32>(name: str<S>, values: [Field; N]) {}

unconstrained fn store_nsk_app(nsk_app: Field) {
    store_oracle("nsk_app", [nsk_app]);
}

fn main(master: Field, namespace: pub Field) -> pub Field {
    let (nsk_app, npk_app_hash) = derive(master, namespace);
    // Safety: TACEO_store only hands the share to the node; it returns
    // nothing and constrains nothing. The proof binds npk_app_hash to the
    // nsk_app computed here, and the node trusts its own circuit to store
    // the value it hashed.
    unsafe { store_nsk_app(nsk_app) };
    npk_app_hash
}

mod tests {
    use super::derive;

    // pss_core aztec_note.nr kat_register_derivation and
    // testvectors/npk_app_hash.json `pss_core_kat_register_derivation`.
    #[test]
    fn kat_register_derivation() {
        let (nsk_app, npk_app_hash) = derive(0x6d6173746572, 0xc0ffee);
        assert_eq(nsk_app, 0x02ae8d3b9b6a6b6e9e5b20349f68cedb428409d2884aa23c0d98bf4d13e04eda);
        assert_eq(
            npk_app_hash,
            0x1f21c078530872675c230b247bed26ffce80c76ab6eeb360895ca8cbd8b92e16,
        );
    }

    // testvectors/npk_app_hash.json `amm_like_namespace`.
    #[test]
    fn kat_amm_like_namespace() {
        let (nsk_app, npk_app_hash) = derive(
            0x0b0e5a1f6c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b,
            0x1f2ea9c0d1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829304a5b,
        );
        assert_eq(nsk_app, 0x0318ad493e97db73ebb150742ab9f13522a09b8ed990ef944ca3218460c69d71);
        assert_eq(
            npk_app_hash,
            0x182ba61dfa7c1cf2d6fcf42a6f9c0ff0828bd75976a14eecc88588bbcd7068e5,
        );
    }

    #[test]
    fn namespaces_get_different_keys() {
        let (a, ha) = derive(0x6d6173746572, 0xc0ffee);
        let (b, hb) = derive(0x6d6173746572, 0xc0ffef);
        assert(a != b);
        assert(ha != hb);
    }
}
