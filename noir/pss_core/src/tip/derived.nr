//! Secret-shared on-chain intake's encoding, the derived intake shares
//! (docs/ARCHITECTURE.md section 6, "Secret-shared on-chain intake"): the user's
//! private function shares a request's values among the three nodes and puts
//! the encoded shares in one private log, which only the nodes open.
//!
//! ```text
//! PRF(k, j)   = poseidon2([k, j, SIDECAR_INTAKE_PRF])
//! E           = e·G,                 E.x in the log
//! s_i         = x(e·P_i)             node i: x(enc_i·E), the same for ±E
//! t_i         = PRF(s_i, 0)          the seed node i derives
//! w_i         = t_i + PRF(s_{i+1}, 1)   the wrap node i + 1 opens
//! a_{i,j}     = PRF(t_i, j + 2)      for the j-th shared value
//! shared x_j:  c_j = x_j − a_{0,j} − a_{1,j} − a_{2,j},  share 2 = a_{2,j} + c_j
//! blinding:    b = a_{0,m} + a_{1,m} + a_{2,m},           no correction
//! ```
//!
//! Indices are mod 3. Node i knows `t_i` and unwraps `t_{i-1} = w_{i-1} −
//! PRF(s_i, 1)`, so it holds the Rep3 pair `(a_i, a_{i-1})` of every shared
//! value, and lacks `t_{i+1}`, so it learns none.
//!
//! The values are the inputs commitment's (`C = poseidon2([values…,
//! blinding])`, `intake::commit`), in its order, each of one kind: `CLEAR`
//! (a clear app input, logged as is) or `CHOSEN` (a shared value the user
//! chooses: an INPUT_SHARED app input, the partial note, or the outcome key
//! and tag the client derives; one correction). The j-th shared value counts
//! the m shared values in that order and then `$blinding` (j = m), which the
//! encoding defines.
//!
//! The request log, after its tag `compute_log_tag(chain_request_id,
//! REQUEST_DOMAIN)` (the kernel silos it with the contract address), is
//! `REQUEST_LOG_LEN` fields:
//!
//! ```text
//! [C, epochs, E.x, w_0, w_1, w_2, clear values…, corrections…, padding…]
//! ```
//!
//! `epochs` packs the three named epochs (`pack_epochs`), the q clear values
//! and the m corrections follow in commitment order (`q + m <=
//! MAX_LOGGED_VALUES`), and position `i` past them holds
//! `outcome::log_padding(blinding, i)`: keyed by the request's `$blinding`,
//! which the encoding fixes and the world never sees, not by the tag, which
//! anyone computes from the public request id and could count the padding
//! with, so the log's visible shape is the same for every round type. The
//! data hash the contract stores beside the queue entry is `poseidon2` of the
//! whole body (`data_hash`).
//!
//! The PRF, the seeds, the wraps, the shares and the log are permutation
//! black boxes and additions, total; `encode` adds the key exchange
//! (`pss_utils::dh`), a fixed-base and three variable-base Grumpkin
//! multiplications, which fail on a key that is not a point. The contract
//! library calls `encode` from the user's private function; the machine
//! (sidecar-core `derived`) and pss-client compute the same values, which
//! testvectors/shared_onchain.json pins.
use crate::tip::outcome::log_padding;
use pss_utils::dh::{ecdh_x, public_key};
use std::embedded_curve_ops::EmbeddedCurvePoint;
use total::hash::p2_hash;

/// ASCII "sidecar.intake_prf" as a big-endian integer: the PRF's domain.
pub global SIDECAR_INTAKE_PRF: Field = 0x736964656361722e696e74616b655f707266;

/// The request log's length after its tag: the v6 private log's 15
/// (`PRIVATE_LOG_CIPHERTEXT_LEN`), so every request log has one length.
pub global REQUEST_LOG_LEN: u32 = 15;

/// The fields before the clear values: C, the epochs, E.x and the three
/// wraps.
pub global REQUEST_LOG_HEADER: u32 = 6;

/// At most this many clear values and corrections together fit one log.
pub global MAX_LOGGED_VALUES: u32 = 9;

/// A value's kind (module docs).
pub global CLEAR: u8 = 0;
pub global CHOSEN: u8 = 1;

/// A round's encoding layout: the kind of each of its M commitment values,
/// with Q the number of CLEAR ones and X of CHOSEN ones, so an app writes it
/// once as a global (`Layout { kinds: [CLEAR, CHOSEN, CHOSEN] }` is a
/// `Layout<3, 1, 2>`) and the sizes follow.
pub struct Layout<let M: u32, let Q: u32, let X: u32> {
    pub kinds: [u8; M],
}

impl<let M: u32, let Q: u32, let X: u32> Layout<M, Q, X> {
    /// `values` (C's, in its order) split by kind: the CLEAR values and the
    /// CHOSEN values, each in order. Total but for the assertions that every
    /// kind is CLEAR or CHOSEN and that Q and X count them, which a fixed
    /// layout decides at compile time.
    pub fn split(self, values: [Field; M]) -> ([Field; Q], [Field; X]) {
        let mut clear = [0; Q];
        let mut chosen = [0; X];
        let (mut q, mut x) = (0, 0);
        for p in 0..M {
            let kind = self.kinds[p];
            if kind == CLEAR {
                clear[q] = values[p];
                q += 1;
            } else {
                assert_eq(kind, CHOSEN, "a value kind is CLEAR or CHOSEN");
                chosen[x] = values[p];
                x += 1;
            }
        }
        assert_eq(q, Q, "Q is the number of CLEAR values");
        assert_eq(x, X, "X is the number of CHOSEN values");
        (clear, chosen)
    }
}

/// `PRF(k, j) = poseidon2([k, j, SIDECAR_INTAKE_PRF])`. Total.
pub fn prf(k: Field, j: Field) -> Field {
    p2_hash([k, j, SIDECAR_INTAKE_PRF])
}

/// The three named epochs in one field: `e_0 + e_1·2^32 + e_2·2^64`. Total.
pub fn pack_epochs(epochs: [u32; 3]) -> Field {
    epochs[0] as Field
        + epochs[1] as Field * 0x100000000
        + epochs[2] as Field * 0x10000000000000000
}

/// The seeds `t_i = PRF(s_i, 0)` of the three key-exchange secrets. Total.
pub fn seeds(secrets: [Field; 3]) -> [Field; 3] {
    secrets.map(|s| prf(s, 0))
}

/// The wraps `w_i = t_i + PRF(s_{i+1}, 1)`. Total.
pub fn wraps(secrets: [Field; 3]) -> [Field; 3] {
    let t = seeds(secrets);
    [t[0] + prf(secrets[1], 1), t[1] + prf(secrets[2], 1), t[2] + prf(secrets[0], 1)]
}

/// The three summands `a_{i,j}` of the j-th shared value before its
/// correction. Total.
pub fn summands(seeds: [Field; 3], j: u32) -> [Field; 3] {
    seeds.map(|t| prf(t, (j + 2) as Field))
}

/// One request's encoding: the blinding, the clear values and the
/// corrections in their log order.
pub struct Encoding<let Q: u32, let X: u32> {
    /// `$blinding`: the last shared value, defined by the encoding
    pub blinding: Field,
    /// the CLEAR values in order
    pub clear: [Field; Q],
    /// the corrections of the CHOSEN values in order
    pub corrections: [Field; X],
}

/// The encoding of `values` (each of the layout's kind) under the seeds of
/// the three key-exchange secrets. Total but for `Layout::split`'s
/// assertions, which a fixed layout decides at compile time.
pub fn shares_of<let M: u32, let Q: u32, let X: u32>(
    layout: Layout<M, Q, X>,
    values: [Field; M],
    secrets: [Field; 3],
) -> Encoding<Q, X> {
    let t = seeds(secrets);
    let (clear, chosen) = layout.split(values);
    let mut corrections = [0; X];
    for x in 0..X {
        // the x-th CHOSEN value is the x-th shared value
        let a = summands(t, x);
        corrections[x] = chosen[x] - (a[0] + a[1] + a[2]);
    }
    let b = summands(t, X);
    Encoding { blinding: b[0] + b[1] + b[2], clear, corrections }
}

/// The request log after its tag (module docs), padded with
/// `log_padding(blinding, i)`. Total.
pub fn request_log<let Q: u32, let X: u32>(
    blinding: Field,
    c: Field,
    epochs: Field,
    eph_x: Field,
    wraps: [Field; 3],
    clear: [Field; Q],
    corrections: [Field; X],
) -> [Field; REQUEST_LOG_LEN] {
    std::static_assert(
        Q + X <= MAX_LOGGED_VALUES,
        "the clear values and corrections do not fit one request log",
    );
    let mut log = [0; REQUEST_LOG_LEN];
    log[0] = c;
    log[1] = epochs;
    log[2] = eph_x;
    for i in 0..3 {
        log[3 + i] = wraps[i];
    }
    for i in 0..Q {
        log[REQUEST_LOG_HEADER + i] = clear[i];
    }
    for i in 0..X {
        log[REQUEST_LOG_HEADER + Q + i] = corrections[i];
    }
    for i in REQUEST_LOG_HEADER + Q + X..REQUEST_LOG_LEN {
        log[i] = log_padding(blinding, i);
    }
    log
}

/// The data hash stored beside the queue entry: `poseidon2` of the request
/// log after its tag. Total.
pub fn data_hash(log: [Field; REQUEST_LOG_LEN]) -> Field {
    p2_hash(log)
}

/// The key-exchange secrets `s_i = x(e·P_i)` and `E.x` of the ephemeral
/// secret `eph` with the nodes' keys. Fails on a key that is not a point.
pub fn key_exchange(eph: Field, keys: [EmbeddedCurvePoint; 3]) -> ([Field; 3], Field) {
    (keys.map(|k| ecdh_x(eph, k)), public_key(eph).x)
}

/// Node i's Rep3 pair `(x_i, x_{i-1})` of the j-th shared value from its
/// key-exchange secret, the wrap `w_{i-1}` and the value's correction (0 for
/// `$blinding`): what the machine derives, as the reference the vector
/// program and the contract test packages check; no circuit calls it. Total.
pub fn node_pair(i: u32, secret: Field, wrap_before: Field, j: u32, correction: Field) -> [Field; 2] {
    let own = prf(secret, 0);
    let before = wrap_before - prf(secret, 1);
    let mut pair = [prf(own, (j + 2) as Field), prf(before, (j + 2) as Field)];
    if i == 2 {
        pair[0] += correction;
    }
    if i == 0 {
        pair[1] += correction;
    }
    pair
}

mod tests {
    use super::{
        CHOSEN, CLEAR, data_hash, key_exchange, Layout, node_pair, pack_epochs, prf, request_log, REQUEST_LOG_LEN, shares_of, SIDECAR_INTAKE_PRF, summands, wraps,
    };
    use crate::tip::outcome::log_padding;
    use pss_utils::dh::public_key;
    use total::hash::p2_hash;
    use crate::test_support::ascii;

    // The kinds' numbers are the machine's (sidecar-tip `onchain_layout`
    // writes them so) and every example's layout pins: CLEAR 0, CHOSEN 1.
    #[test]
    fn the_kinds_are_numbered_as_the_machine_numbers_them() {
        assert_eq([CLEAR, CHOSEN], [0, 1]);
    }

    #[test]
    fn the_prf_domain_is_its_label() {
        assert_eq(SIDECAR_INTAKE_PRF, ascii("sidecar.intake_prf"));
        assert_eq(prf(7, 3), p2_hash([7, 3, SIDECAR_INTAKE_PRF]));
        assert_eq(pack_epochs([1, 2, 3]), 1 + 2 * 0x100000000 + 3 * 0x10000000000000000);
    }

    // Each node derives its pair of every shared value, the pairs are a
    // Rep3 sharing (node i's second element is node i - 1's first) and the
    // shares sum to the value: each shared value to the user's, `$blinding`
    // to the encoding's.
    #[test]
    fn every_node_derives_its_pair_and_the_pairs_reconstruct() {
        let node_secrets = [0x1111, 0x2222, 0x3333];
        let keys = node_secrets.map(|k| public_key(k));
        let eph = 0xe9e9;
        let (secrets, eph_x) = key_exchange(eph, keys);
        assert_eq(eph_x, public_key(eph).x);
        // what each node computes from E and its own scalar
        let e = public_key(eph);
        for i in 0..3 {
            assert_eq(secrets[i], pss_utils::dh::ecdh_x(node_secrets[i], e));
        }
        // [position (clear), amount, partial note, outcome key, outcome tag (chosen)]
        let layout: Layout<5, 1, 4> = Layout { kinds: [CLEAR, CHOSEN, CHOSEN, CHOSEN, CHOSEN] };
        let values = [7, 5000, 0xbeef, 0x6b, 0x7a];
        let enc = shares_of(layout, values, secrets);
        assert_eq(enc.clear, [7]);
        let w = wraps(secrets);
        // j over the shared values in order, then $blinding
        let shared = [values[1], values[2], values[3], values[4], enc.blinding];
        let c = enc.corrections;
        let corr = [c[0], c[1], c[2], c[3], 0];
        for j in 0..5 {
            let pairs = [0, 1, 2].map(|i| node_pair(i, secrets[i], w[(i + 2) % 3], j, corr[j]));
            for i in 0..3 {
                assert_eq(pairs[i][1], pairs[(i + 2) % 3][0]);
            }
            assert_eq(pairs[0][0] + pairs[1][0] + pairs[2][0], shared[j]);
        }
        // the blinding is the plain sum of its summands, after the four
        // shared values
        let t = secrets.map(|s| prf(s, 0));
        let a = summands(t, 4);
        assert_eq(enc.blinding, a[0] + a[1] + a[2]);
    }

    // A layout splits C's values by kind, each part in C's order.
    #[test]
    fn a_layout_splits_the_values_by_kind() {
        let layout: Layout<5, 2, 3> = Layout { kinds: [CHOSEN, CLEAR, CHOSEN, CLEAR, CHOSEN] };
        let (clear, chosen) = layout.split([1, 2, 3, 4, 5]);
        assert_eq(clear, [2, 4]);
        assert_eq(chosen, [1, 3, 5]);
    }

    #[test(should_fail_with = "Q is the number of CLEAR values")]
    fn a_layout_whose_counts_are_wrong_is_refused() {
        let layout: Layout<3, 2, 2> = Layout { kinds: [CLEAR, CHOSEN, CHOSEN] };
        let _ = layout.split([1, 2, 3]);
    }

    #[test]
    fn the_log_is_the_header_the_values_and_the_padding() {
        let blinding = 0xb11d;
        let log = request_log(blinding, 0xc, 0xe, 0xe1, [1, 2, 3], [7], [8, 9]);
        assert_eq(log.len(), REQUEST_LOG_LEN);
        assert_eq([log[0], log[1], log[2], log[3], log[4], log[5]], [0xc, 0xe, 0xe1, 1, 2, 3]);
        assert_eq([log[6], log[7], log[8]], [7, 8, 9]);
        for i in 9..REQUEST_LOG_LEN {
            assert_eq(log[i], log_padding(blinding, i));
        }
        assert_eq(data_hash(log), p2_hash(log));
    }
}
