//! The transaction the chain reader asks an Aztec node to simulate for a
//! pinned public read: one static public call `(contract, function, args)`,
//! made from the namespace contract, with nothing else in it.
//!
//! Aztec node 6.0.0 exposes one RPC that runs public code: `simulatePublicCalls(tx,
//! skipFeeEnforcement)`, which forks the world state at the latest proposed
//! block, builds the next block's globals on it and runs the transaction's
//! public calls through the AVM, returning each call's return values. It
//! takes a whole `Tx`: the private kernel tail's public inputs (as bytes),
//! a proof, contract-class log fields and the calldata of each public call.
//! The node does not verify the proof or the kernel output when it
//! simulates, so this module writes the smallest `Tx` the processor runs:
//! every field zero except the ones below. Its byte layout is that of
//! @aztec-labs/stdlib 6.0.0's `PrivateKernelTailCircuitPublicInputs.toBuffer`
//! (big-endian, fixed-size arrays, no padding); the tests compare it with the
//! bytes stdlib writes for the same call (tests/fixtures/pinned.json).

use serde_json::{Value, json};
use sidecar_core::Fr;
use sidecar_core::field::{fr_to_be_bytes, fr_to_hex};
use sidecar_core::hash::poseidon2_hash_with_separator;
use sidecar_core::schnorr::poseidon2_hash_bytes;

/// `DOM_SEP__PUBLIC_CALLDATA` of protocol_types v6.0.0: the calldata hash a
/// public call request carries.
pub const PUBLIC_CALLDATA: u32 = 2760353947;

/// The domain of the simulated transaction's nullifier, ASCII "PSPR". Not a
/// protocol constant: the processor needs a first nullifier (the transaction
/// hash is derived from it) that is not already in the nullifier tree.
pub const SIMULATION_NULLIFIER_DOMAIN: u32 = 0x5053_5052;

/// The length of the serialised `PrivateKernelTailCircuitPublicInputs` with
/// `forPublic` set.
pub const TAIL_LEN: usize = 82_774;

// Byte offsets in the serialised tail public inputs (stdlib 6.0.0):
//   0       isForPublic (1 byte)
//   1       constants.anchorBlockHeader (492 bytes)
//   493     constants.txContext.chainId, version (32 bytes each)
//   557     constants.txContext.gasSettings: gasLimits {daGas u32, l2Gas u32},
//           teardownGasLimits (565), maxFeesPerGas {feePerDaGas u128,
//           feePerL2Gas u128} (573), maxPriorityFeesPerGas (605)
//   637     constants.vkTreeRoot, 669 protocolContractsHash
//   701     gasUsed (8), 709 feePayer (32), 741 expirationTimestamp (u64)
//   749     forPublic.nonRevertibleAccumulatedData (40,964 bytes): 64 note
//           hashes, then the nullifiers (the first at 749 + 64·32 = 2797), ...
//   41713   forPublic.revertibleAccumulatedData: ..., then 32 public call
//           requests of 97 bytes each, the first at 41713 + 40964 − 32·97
//           = 79573: msgSender (32), contractAddress (32), isStaticCall (1),
//           calldataHash (32)
//   82677   forPublic.publicTeardownCallRequest (97)
const IS_FOR_PUBLIC: usize = 0;
const GAS_LIMITS: usize = 557;
const MAX_FEES_PER_GAS: usize = 573;
const FIRST_NULLIFIER: usize = 2797;
const CALL_REQUEST: usize = 79_573;

// The simulated transaction's gas and fees: gas limits
// of 786,432 DA gas (MAX_PROCESSABLE_DA_GAS_PER_CHECKPOINT) and 6,540,000 L2
// gas (MAX_PROCESSABLE_L2_GAS), no teardown, maximum fees of 10^20 per unit
// of each gas, no priority fee, no fee payer, and skipFeeEnforcement true.
// The node refuses a simulation whose maximum fees are below the next
// block's fees even when fee enforcement is skipped, and a pinned read must
// not fail for want of gas; with enforcement skipped nothing is charged. A
// read that needs more gas than a whole transaction may use reverts here as
// it would in `apply`.
const DA_GAS_LIMIT: u32 = 786_432;
const L2_GAS_LIMIT: u32 = 6_540_000;
const MAX_FEE_PER_GAS: u128 = 100_000_000_000_000_000_000;

/// The selector of a public function: the last 4 bytes of
/// `poseidon2_hash_bytes(signature)` (aztec.js `FunctionSelector.fromSignature`).
pub fn function_selector(signature: &str) -> u32 {
    let bytes = fr_to_be_bytes(poseidon2_hash_bytes(signature.as_bytes()));
    u32::from_be_bytes(bytes[28..32].try_into().expect("4 bytes"))
}

// The signature of a pinned read: a function name gets
// one `Field` parameter per entry of `args` (`get_price` with one arg is
// `get_price(Field)`); a `function` that contains "(" is taken as the full
// Noir signature (`request_at(u64)`). The selector hashes the parameter
// types, which a manifest's `args` (all field elements) do not carry, and
// the manifest accepts a bare identifier only, so every manifest read
// is a getter of Field parameters; the full form serves callers that build a
// `PublicRead` themselves. A getter with a `u64`, `bool` or struct parameter
// cannot be pinned through a manifest; one named wrongly reaches no function
// and the read fails (liveness only).
/// The signature the reader calls for `function` with `arg_count` arguments.
pub fn call_signature(function: &str, arg_count: usize) -> String {
    if function.contains('(') {
        function.to_string()
    } else {
        format!("{function}({})", vec!["Field"; arg_count].join(","))
    }
}

/// One static public call to simulate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulatedCall {
    /// The caller the called function sees as `msg_sender`.
    pub sender: Fr,
    pub contract: Fr,
    /// `[selector, args...]`.
    pub calldata: Vec<Fr>,
}

impl SimulatedCall {
    /// A call of `signature` on `contract` with `args`, made by `sender`.
    pub fn new(sender: Fr, contract: Fr, signature: &str, args: &[Fr]) -> Self {
        let mut calldata = vec![Fr::from(function_selector(signature))];
        calldata.extend_from_slice(args);
        SimulatedCall {
            sender,
            contract,
            calldata,
        }
    }

    /// `poseidon2_hash_with_separator(calldata, DOM_SEP__PUBLIC_CALLDATA)`.
    pub fn calldata_hash(&self) -> Fr {
        poseidon2_hash_with_separator(&self.calldata, PUBLIC_CALLDATA)
    }

    /// The transaction's first nullifier: fixed by the call, so equal calls
    /// make equal requests, and a hash, so it is in no nullifier tree.
    pub fn nullifier(&self) -> Fr {
        poseidon2_hash_with_separator(
            &[self.sender, self.contract, self.calldata_hash()],
            SIMULATION_NULLIFIER_DOMAIN,
        )
    }

    /// The serialised `PrivateKernelTailCircuitPublicInputs` of the
    /// transaction: [`TAIL_LEN`] bytes, zero except the flag, the gas, the
    /// first nullifier and one revertible static call request.
    pub fn tail_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; TAIL_LEN];
        out[IS_FOR_PUBLIC] = 1;
        out[GAS_LIMITS..GAS_LIMITS + 4].copy_from_slice(&DA_GAS_LIMIT.to_be_bytes());
        out[GAS_LIMITS + 4..GAS_LIMITS + 8].copy_from_slice(&L2_GAS_LIMIT.to_be_bytes());
        out[MAX_FEES_PER_GAS..MAX_FEES_PER_GAS + 16]
            .copy_from_slice(&MAX_FEE_PER_GAS.to_be_bytes());
        out[MAX_FEES_PER_GAS + 16..MAX_FEES_PER_GAS + 32]
            .copy_from_slice(&MAX_FEE_PER_GAS.to_be_bytes());
        out[FIRST_NULLIFIER..FIRST_NULLIFIER + 32]
            .copy_from_slice(&fr_to_be_bytes(self.nullifier()));
        let call = CALL_REQUEST;
        out[call..call + 32].copy_from_slice(&fr_to_be_bytes(self.sender));
        out[call + 32..call + 64].copy_from_slice(&fr_to_be_bytes(self.contract));
        out[call + 64] = 1; // isStaticCall
        out[call + 65..call + 97].copy_from_slice(&fr_to_be_bytes(self.calldata_hash()));
        out
    }

    /// The `params` of `node_simulatePublicCalls`: the `Tx` as its JSON
    /// schema reads it (buffers in base64; the node derives the hash) and
    /// `skipFeeEnforcement` true.
    pub fn params(&self) -> Value {
        json!([
            {
                "data": base64(&self.tail_bytes()),
                // an empty ChonkProof: a zero u32 length
                "chonkProof": base64(&[0, 0, 0, 0]),
                "contractClassLogFields": [],
                "publicFunctionCalldata": [{
                    "values": self.calldata.iter().map(|v| fr_to_hex(*v)).collect::<Vec<_>>(),
                    "hash": fr_to_hex(self.calldata_hash()),
                }],
            },
            true
        ])
    }
}

/// Standard base64 with padding (RFC 4648), the encoding of a buffer in the
/// node's JSON schemas.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> shift) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known answers from aztec.js 6.0.0 (`FunctionSelector.fromSignature`,
    // `computeCalldataHash`).
    #[test]
    fn selectors_and_calldata_hashes_match_aztec_js() {
        assert_eq!(function_selector("get_pool()"), 0xab5597c2);
        assert_eq!(function_selector("request_at(u64)"), 0x98ccd2dd);
        assert_eq!(function_selector("get_price(Field)"), 0x29d5a82f);
        assert_eq!(function_selector("get_tail()"), 0x45230436);
        let call = SimulatedCall::new(
            Fr::from(1u64),
            Fr::from(2u64),
            "request_at(u64)",
            &[Fr::from(1u64)],
        );
        assert_eq!(
            fr_to_hex(call.calldata_hash()),
            "0x1c9b29fcabd53e19c2c4863981945452655f91cda4e7e87295618ed52df91c29"
        );
    }

    #[test]
    fn a_bare_name_takes_field_parameters() {
        assert_eq!(call_signature("get_price", 1), "get_price(Field)");
        assert_eq!(call_signature("get_tail", 0), "get_tail()");
        assert_eq!(call_signature("pair", 2), "pair(Field,Field)");
        assert_eq!(call_signature("request_at(u64)", 1), "request_at(u64)");
    }

    #[test]
    fn base64_pads() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(&[0, 0, 0, 0]), "AAAAAA==");
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
    }
}
