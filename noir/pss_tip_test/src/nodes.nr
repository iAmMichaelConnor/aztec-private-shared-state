//! The test network: the three node keys of testvectors/keys.json (the
//! keys the machine's and pss-client's tests sign with) and a test-only
//! Schnorr signer in the encoding of noir-lang/schnorr v0.4.0, so a TXE suite
//! signs receipts and results over ids that depend on the deployed address
//! exactly as the nodes would.
use aztec::protocol::hash::poseidon2_hash;
use pss_public_contract::{NODES, Receipt};
use pss_public_contract::result::ResultSignature;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul};

// BEGIN written by scripts/gen-noir-vectors.py from testvectors/keys.json
/// Node i's `sig` scalar (testvectors/keys.json `nodes[i].sig`).
pub global NODE_SIG: [Field; NODES] = [
    0x13fe9f9afe81c099297a6efb7719c0150db4951a0d2326504ff01db08bfd0ea3,
    0x13a755b3c79842700b40de3b648a3fb55ed0c8fa19cdf390f26ea9e9255ec15e,
    0x1b1c5bc22e0b4c4ac876402115b29dca3fae102c3709ea2869004403bedec7b6,
];

/// Node i's `sig` public key (testvectors/keys.json `nodes[i].sig_pk`).
pub global NODE_SIG_PK: [EmbeddedCurvePoint; NODES] = [
    EmbeddedCurvePoint {
        x: 0x2b681809013b22f0d2db3b443103b7fffdd7fa834a008595320ac526ab30de44,
        y: 0x28de1717d62f6f9ebd274bd7e1dd72ad225657277893e174d4f437a53aeab182,
    },
    EmbeddedCurvePoint {
        x: 0x0b53299786c80b86efd037531a7f8c8b21cac11146c56854f315d608030c730b,
        y: 0x28c8b5e2974e1676c8a8e182b2f4ed5ae003e2cd3fdbbb333e4cab004d1d2bb4,
    },
    EmbeddedCurvePoint {
        x: 0x0510626ed26672208a7c0a9354eb21632b15278602f6e99673bd247bac8e3726,
        y: 0x0a6177e34014e1610da411dec54a91340cfadfcb5eb054f9944e655f195935eb,
    },
];
// END written by scripts/gen-noir-vectors.py

/// A key that is no node's: signs the "wrong key" receipts.
pub global OUTSIDER_SIG: Field = 0x0badc0ffee;

// ---- a test-only Schnorr signer -------------------------------------------
//
// noir-lang/schnorr v0.4.0 accepts (s, e) for key pk and message m iff
// e = poseidon2([DST, R.x, pk.x, pk.y, m]) with R = s·G + e·pk. With R = k·G
// and pk = sk·G that is s = k - sk·e modulo q, the Grumpkin group order (the
// BN254 base field modulus, larger than Noir's Field), so s is computed here
// in 256-bit integer arithmetic over four 64-bit limbs held in u128s.

global SCHNORR_CHALLENGE_DST: Field = 0x024c76938ed06b8ec1d9094b1013d190baa4011372f0604643bda812a63b832e;

/// q, little-endian 64-bit limbs.
global Q: [u128; 4] = [0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029];
global TWO_POW_64: u128 = 0x10000000000000000;

unconstrained fn limbs(x: Field) -> [u128; 4] {
    let bytes: [u8; 32] = x.to_le_bytes();
    let mut out = [0; 4];
    for i in 0..4 {
        let mut limb: u128 = 0;
        for j in 0..8 {
            limb += (bytes[8 * i + j] as u128) << ((8 * j) as u128);
        }
        out[i] = limb;
    }
    out
}

unconstrained fn geq(a: [u128; 4], b: [u128; 4]) -> bool {
    let mut result = true; // equal so far
    let mut decided = false;
    for k in 0..4 {
        let i = 3 - k;
        if !decided & (a[i] != b[i]) {
            result = a[i] > b[i];
            decided = true;
        }
    }
    result
}

// a + b for a, b < 2^255 (no carry out of the top limb)
unconstrained fn add(a: [u128; 4], b: [u128; 4]) -> [u128; 4] {
    let mut out = [0; 4];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let t = a[i] + b[i] + carry;
        out[i] = t % TWO_POW_64;
        carry = t / TWO_POW_64;
    }
    assert(carry == 0);
    out
}

// a - b for a >= b
unconstrained fn sub(a: [u128; 4], b: [u128; 4]) -> [u128; 4] {
    let mut out = [0; 4];
    let mut borrow: u128 = 0;
    for i in 0..4 {
        let t = a[i] + TWO_POW_64 - b[i] - borrow;
        if t >= TWO_POW_64 {
            out[i] = t - TWO_POW_64;
            borrow = 0;
        } else {
            out[i] = t;
            borrow = 1;
        }
    }
    assert(borrow == 0);
    out
}

// (a + b) mod q for a, b < q
unconstrained fn add_mod(a: [u128; 4], b: [u128; 4]) -> [u128; 4] {
    let s = add(a, b);
    if geq(s, Q) {
        sub(s, Q)
    } else {
        s
    }
}

// (a - b) mod q for a, b < q
unconstrained fn sub_mod(a: [u128; 4], b: [u128; 4]) -> [u128; 4] {
    if geq(a, b) {
        sub(a, b)
    } else {
        sub(add(a, Q), b)
    }
}

// (a · b) mod q for a, b < q, by double-and-add over the bits of b
unconstrained fn mul_mod(a: [u128; 4], b: [u128; 4]) -> [u128; 4] {
    let mut acc = [0; 4];
    for k in 0..256 {
        let bit = 255 - k;
        acc = add_mod(acc, acc);
        if (b[bit / 64] >> ((bit % 64) as u128)) % 2 == 1 {
            acc = add_mod(acc, a);
        }
    }
    acc
}

// a < 2^256 as [lo, hi] Fields: the low 128 bits and the rest
unconstrained fn to_lo_hi(a: [u128; 4]) -> [Field; 2] {
    [
        (a[0] as Field) + (a[1] as Field) * 0x10000000000000000,
        (a[2] as Field) + (a[3] as Field) * 0x10000000000000000,
    ]
}

unconstrained fn scalar(x: Field) -> EmbeddedCurveScalar {
    let lo_hi = to_lo_hi(limbs(x));
    EmbeddedCurveScalar::new(lo_hi[0], lo_hi[1])
}

/// The public key of the scalar `sk`.
pub unconstrained fn public_key(sk: Field) -> EmbeddedCurvePoint {
    fixed_base_scalar_mul(scalar(sk))
}

/// Sign `message` with the scalar `sk` (a Field, so below q) and a nonce
/// derived from both, as a node signs a receipt.
pub unconstrained fn sign(sk: Field, message: Field) -> Receipt {
    let pk = public_key(sk);
    let k = poseidon2_hash([sk, message, 0x6b]);
    let r = fixed_base_scalar_mul(scalar(k));
    let e = poseidon2_hash([SCHNORR_CHALLENGE_DST, r.x, pk.x, pk.y, message]);
    let s = sub_mod(limbs(k), mul_mod(limbs(sk), limbs(e)));
    Receipt { s: to_lo_hi(s), e: to_lo_hi(limbs(e)) }
}

/// The three nodes' receipts over `message`.
pub unconstrained fn receipts(message: Field) -> [Receipt; NODES] {
    [sign(NODE_SIG[0], message), sign(NODE_SIG[1], message), sign(NODE_SIG[2], message)]
}

/// A result signature with the scalar `sk` over `message`, as
/// `[s.lo, s.hi, e.lo, e.hi]`.
pub unconstrained fn sign_result(sk: Field, message: Field) -> ResultSignature {
    let r = sign(sk, message);
    [r.s[0], r.s[1], r.e[0], r.e[1]]
}
