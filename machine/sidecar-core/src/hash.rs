//! Plain (non-MPC) Poseidon2 helpers shared by the node and the orchestrator.

use ark_ff::Zero;
use co_noir::Bn254G1;
use co_noir_common::keys::verification_key::VerifyingKeyBarretenberg;
use mpc_core::gadgets::poseidon2::Poseidon2;

use crate::field::Fr;

/// The Poseidon2 sponge hash that barretenberg, Noir's
/// `std::hash::poseidon2::Poseidon2::hash` and aztec.js `poseidon2Hash`
/// compute: width 4, rate 3, IV `len << 64` in the capacity element, one
/// output. Absorbing a full rate block and permuting is the same as the
/// cached sponge in barretenberg; an empty input still permutes once.
pub fn poseidon2_hash(inputs: &[Fr]) -> Fr {
    let permutation = Poseidon2::<Fr, 4, 5>::default();
    let mut state = [Fr::zero(); 4];
    state[3] = Fr::from((inputs.len() as u128) << 64);
    if inputs.is_empty() {
        permutation.permutation_in_place(&mut state);
    }
    for block in inputs.chunks(3) {
        for (lane, input) in state.iter_mut().zip(block) {
            *lane += input;
        }
        permutation.permutation_in_place(&mut state);
    }
    state[0]
}

/// `poseidon2_hash([separator, inputs...])`, as protocol_types'
/// `poseidon2_hash_with_separator`.
pub fn poseidon2_hash_with_separator(inputs: &[Fr], separator: u32) -> Fr {
    let mut all = Vec::with_capacity(inputs.len() + 1);
    all.push(Fr::from(separator));
    all.extend_from_slice(inputs);
    poseidon2_hash(&all)
}

/// What a contract pins for a circuit: the poseidon2 hash of the bb
/// verification-key fields (the 115 fields `bb write_vk --output_format
/// json` lists; aztec.js `poseidon2Hash(vk.fields)`).
pub fn vk_hash(vk: &VerifyingKeyBarretenberg<Bn254G1>) -> Fr {
    poseidon2_hash(&vk.to_field_elements())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::fr_from_hex;

    fn hex(s: &str) -> Fr {
        fr_from_hex(s).unwrap()
    }

    // Known answers computed with aztec.js 6.0.0 (`@aztec-labs/foundation`
    // poseidon2Hash / poseidon2HashWithSeparator).
    #[test]
    fn poseidon2_matches_aztec_js() {
        let one_to_five: Vec<Fr> = (1..=5u64).map(Fr::from).collect();
        assert_eq!(
            poseidon2_hash(&one_to_five),
            hex("0x2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db")
        );
        assert_eq!(
            poseidon2_hash(&[]),
            hex("0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e")
        );
        // siloNoteHash(0xc0ffee, 0x1234) with DOM_SEP__SILOED_NOTE_HASH
        assert_eq!(
            poseidon2_hash_with_separator(
                &[Fr::from(0xc0ffeeu64), Fr::from(0x1234u64)],
                3361878420
            ),
            hex("0x07b3cb8631f5db484a19696369f2ad2e123fa64cc0d95375db1ee76d87742014")
        );
    }
}
