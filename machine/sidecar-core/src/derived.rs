//! Secret-shared on-chain intake's derived intake shares (docs/ARCHITECTURE.md
//! section 6, "Secret-shared on-chain intake"): the encoding the user's private
//! function computes and logs, and node i's derivation of its Rep3 pair of
//! every shared value from the request log and its `enc` scalar for the
//! epoch the log names. `pss_core::tip::derived` is the same encoding in
//! Noir and pss-client's `intake-shared-onchain.ts` in TypeScript;
//! testvectors/shared_onchain.json pins all three.
//!
//! ```text
//! PRF(k, j)   = poseidon2([k, j, SIDECAR_INTAKE_PRF])
//! E           = e·G,                    E.x in the log
//! s_i         = x(e·P_i) = x(enc_i·E)   the same for ±E
//! t_i         = PRF(s_i, 0),   w_i = t_i + PRF(s_{i+1}, 1)
//! a_{i,j}     = PRF(t_i, j + 2)
//! shared x_j:   c_j = x_j − Σ_i a_{i,j}, node 2's summand a_{2,j} + c_j
//! blinding:     b = Σ_i a_{i,m}  (m shared values before it), no correction
//! log         = [C, epochs, E.x, w_0, w_1, w_2, clear…, corrections…, padding…]
//! data_hash   = poseidon2(log)
//! ```
//!
//! Node i knows `t_i` and unwraps `t_{i-1} = w_{i-1} − PRF(s_i, 1)`, so its
//! pair of the j-th shared value is `(a_{i,j}, a_{i-1,j})`, the correction
//! added where the summand is node 2's. A synthesised request carries the
//! log as a [`SharedLog`] in place of envelopes, with the encoding's order
//! of the circuit's INPUT_SHARED values and where each correction sits
//! (sidecar-tip's secret-shared on-chain intake builds it from the manifest); the
//! binder takes [`derived_share`] as node i's share of each.

use ark_ff::{Field, PrimeField, Zero};
use serde::{Deserialize, Serialize};

use crate::bind::Share;
use crate::error::Refusal;
use crate::field::{FieldHex, Fr};
use crate::grumpkin::{Fq, Point, coordinates, fixed_base_mul, mul, scalar_from_field};
use crate::hash::poseidon2_hash;
use crate::keys::{NodeKeys, label_field};
use crate::request::{NODES, next, prev};
use crate::schnorr::check_name;

/// The label of the PRF's domain.
pub const SIDECAR_INTAKE_PRF_LABEL: &[u8] = b"sidecar.intake_prf";

/// The request log's length after its tag: the v6 private log's 15.
pub const REQUEST_LOG_LEN: usize = 15;

/// The fields before the clear values: C, the epochs, E.x and the wraps.
pub const REQUEST_LOG_HEADER: usize = 6;

/// At most this many clear values and corrections together fit one log.
pub const MAX_LOGGED_VALUES: usize = REQUEST_LOG_LEN - REQUEST_LOG_HEADER;

/// `SIDECAR_INTAKE_PRF`: the bytes `sidecar.intake_prf` read big-endian.
pub fn sidecar_intake_prf() -> Fr {
    label_field(SIDECAR_INTAKE_PRF_LABEL)
}

/// `PRF(k, j) = poseidon2([k, j, SIDECAR_INTAKE_PRF])`.
pub fn prf(k: Fr, j: u64) -> Fr {
    poseidon2_hash(&[k, Fr::from(j), sidecar_intake_prf()])
}

/// The three named epochs in one field: `e_0 + e_1·2^32 + e_2·2^64`.
pub fn pack_epochs(epochs: [u32; NODES]) -> Fr {
    Fr::from(u128::from(epochs[0]) | u128::from(epochs[1]) << 32 | u128::from(epochs[2]) << 64)
}

/// The three epochs a packed field names; `None` when it is not three u32s.
pub fn unpack_epochs(packed: Fr) -> Option<[u32; NODES]> {
    let w = packed.into_bigint().0;
    if w[1] >> 32 != 0 || w[2] != 0 || w[3] != 0 {
        return None;
    }
    Some([w[0] as u32, (w[0] >> 32) as u32, w[1] as u32])
}

/// The seed `t = PRF(s, 0)` of a key-exchange secret.
pub fn seed(secret: Fr) -> Fr {
    prf(secret, 0)
}

/// The wraps `w_i = t_i + PRF(s_{i+1}, 1)` of the three secrets.
pub fn wraps(secrets: [Fr; NODES]) -> [Fr; NODES] {
    std::array::from_fn(|i| seed(secrets[i]) + prf(secrets[next(i)], 1))
}

/// The three summands `a_{i,j}` of the j-th shared value before its
/// correction.
pub fn summands(secrets: [Fr; NODES], j: usize) -> [Fr; NODES] {
    secrets.map(|s| prf(seed(s), j as u64 + 2))
}

/// A value's kind in the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A clear app input: logged as is.
    Clear,
    /// A shared value the user chooses (an INPUT_SHARED app input or a
    /// reserved value): one correction.
    Chosen,
}

impl Kind {
    /// The kind as a field element, as pss_core's `CLEAR` (0) and `CHOSEN`
    /// (1) and the sharing digest take it.
    pub fn field(self) -> Fr {
        match self {
            Kind::Clear => Fr::from(0u64),
            Kind::Chosen => Fr::from(1u64),
        }
    }
}

/// One request's encoding, as the user's private function computes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoding {
    /// `$blinding`, the last shared value, defined by the encoding.
    pub blinding: Fr,
    pub clear: Vec<Fr>,
    pub corrections: Vec<Fr>,
    /// `E.x`.
    pub eph_x: Fr,
    pub wraps: [Fr; NODES],
}

/// The key-exchange secrets `x(e·P_i)` of the ephemeral secret `eph` (a
/// field element read as a scalar, as pss_utils reads it) with the nodes'
/// keys, and `E.x`.
pub fn key_exchange(eph: Fr, keys: [Point; NODES]) -> ([Fr; NODES], Fr) {
    let scalar = scalar_from_field(eph);
    (
        keys.map(|k| coordinates(mul(k, scalar)).0),
        coordinates(fixed_base_mul(scalar)).0,
    )
}

/// The encoding of `values` (in the inputs commitment's order, each of
/// `kinds[p]`) under the ephemeral secret `eph` and the nodes' keys. Panics
/// when the lengths differ.
pub fn encode(kinds: &[Kind], values: &[Fr], eph: Fr, keys: [Point; NODES]) -> Encoding {
    assert_eq!(kinds.len(), values.len(), "one kind per value");
    let (secrets, eph_x) = key_exchange(eph, keys);
    let (mut clear, mut corrections, mut j) = (Vec::new(), Vec::new(), 0);
    for (kind, value) in kinds.iter().zip(values) {
        match kind {
            Kind::Clear => clear.push(*value),
            Kind::Chosen => {
                corrections.push(*value - summands(secrets, j).iter().sum::<Fr>());
                j += 1;
            }
        }
    }
    Encoding {
        blinding: summands(secrets, j).iter().sum(),
        clear,
        corrections,
        eph_x,
        wraps: wraps(secrets),
    }
}

/// The padding at position `i` of a private log under `tag`:
/// `poseidon2([tag, i])` (pss_core `tip::outcome::log_padding`).
pub fn log_padding(tag: Fr, i: usize) -> Fr {
    poseidon2_hash(&[tag, Fr::from(i as u64)])
}

/// The request log after its tag, padded with `log_padding(blinding, i)`
/// under the encoding's blinding (secret from the world, fixed by the
/// encoding; the tag follows from the public request id). Panics when the
/// clear values and corrections do not fit (more than [`MAX_LOGGED_VALUES`]).
pub fn request_log(c: Fr, epochs: [u32; NODES], encoding: &Encoding) -> Vec<Fr> {
    let mut log = vec![c, pack_epochs(epochs), encoding.eph_x];
    log.extend(encoding.wraps);
    log.extend(&encoding.clear);
    log.extend(&encoding.corrections);
    assert!(
        log.len() <= REQUEST_LOG_LEN,
        "{} clear values and corrections do not fit one request log",
        encoding.clear.len() + encoding.corrections.len()
    );
    for i in log.len()..REQUEST_LOG_LEN {
        log.push(log_padding(encoding.blinding, i));
    }
    log
}

/// The data hash the contract stores beside the queue entry: `poseidon2` of
/// the request log after its tag.
pub fn data_hash(log: &[Fr]) -> Fr {
    poseidon2_hash(log)
}

/// Node i's pair `(x_i, x_{i-1})` of the j-th shared value from its
/// key-exchange secret, the wrap `w_{i-1}` and the value's correction (zero
/// for `$blinding`).
pub fn node_pair(i: usize, secret: Fr, wrap_before: Fr, j: usize, correction: Fr) -> [Fr; 2] {
    let own = seed(secret);
    let before = wrap_before - prf(secret, 1);
    let mut pair = [prf(own, j as u64 + 2), prf(before, j as u64 + 2)];
    if i == 2 {
        pair[0] += correction;
    }
    if i == 0 {
        pair[1] += correction;
    }
    pair
}

/// A point with x-coordinate `x` (either root: the key exchange takes the
/// x-coordinate of the product, the same for `±E`); `None` when there is
/// none on the curve.
pub fn lift_x(x: Fr) -> Option<Point> {
    let y = (x * x * x - Fr::from(17u64)).sqrt()?;
    let point = Point::new_unchecked(x, y);
    (point.is_on_curve() && !x.is_zero()).then_some(point)
}

/// One INPUT_SHARED value of a circuit as secret-shared on-chain intake encodes it:
/// its name and, for a value the user chooses, the position in the log
/// (counting after the tag) of its correction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedInput {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correction: Option<usize>,
}

/// Secret-shared on-chain intake's request data as a synthesised request carries
/// it in place of envelopes: the request log after its tag as the chain
/// holds it (every node reads the same fields; each derives only its own
/// pairs), and every INPUT_SHARED value of the circuit in the encoding's
/// order (`j`), with where its correction sits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedLog {
    pub fields: Vec<FieldHex>,
    pub shared: Vec<DerivedInput>,
}

impl SharedLog {
    /// The request log's shape: [`REQUEST_LOG_LEN`] fields, the names once
    /// each, each passing [`check_name`] as every name of a request does,
    /// every correction in the value area of the log and at most once. 400
    /// naming the field otherwise.
    pub fn check(&self) -> Result<(), Refusal> {
        if self.fields.len() != REQUEST_LOG_LEN {
            return Err(Refusal::bad_request(format!(
                "field `shared_log.fields`: {} fields; a request log has {REQUEST_LOG_LEN} after its tag",
                self.fields.len()
            )));
        }
        let mut names = std::collections::BTreeSet::new();
        let mut at = std::collections::BTreeSet::new();
        for (k, input) in self.shared.iter().enumerate() {
            check_name(
                &format!("shared_log.shared[{k}].name"),
                "input name",
                &input.name,
            )?;
            if !names.insert(input.name.as_str()) {
                return Err(Refusal::bad_request(format!(
                    "field `shared_log.shared[{k}].name`: `{}` is duplicated",
                    input.name
                )));
            }
            if let Some(p) = input.correction
                && (!(REQUEST_LOG_HEADER..REQUEST_LOG_LEN).contains(&p) || !at.insert(p))
            {
                return Err(Refusal::bad_request(format!(
                    "field `shared_log.shared[{k}].correction`: position {p} is not a free \
                     value position of the log ({REQUEST_LOG_HEADER} to {})",
                    REQUEST_LOG_LEN - 1
                )));
            }
        }
        Ok(())
    }

    fn field(&self, i: usize) -> Fr {
        self.fields[i].fr()
    }

    /// The epoch the log names for node `i`; 400 when the packed field is
    /// not three epochs.
    pub fn epoch(&self, i: usize) -> Result<u32, Refusal> {
        unpack_epochs(self.field(1)).map(|e| e[i]).ok_or_else(|| {
            Refusal::bad_request("field `shared_log.fields[1]`: not three packed u32 epochs")
        })
    }

    /// The log's fields as field elements.
    pub fn frs(&self) -> Vec<Fr> {
        self.fields.iter().map(|f| f.fr()).collect()
    }
}

/// Node `i`'s Rep3 share of the shared value `name` of `log`, derived with
/// `scalar`, its `enc` scalar for the epoch the log names. 400 when the log
/// does not carry `name` or its `E.x` is not a point's.
pub fn derived_share(scalar: Fq, i: usize, log: &SharedLog, name: &str) -> Result<Share, Refusal> {
    let j = log
        .shared
        .iter()
        .position(|s| s.name == name)
        .ok_or_else(|| {
            Refusal::bad_request(format!("field `shared_log.shared`: missing `{name}`"))
        })?;
    let e = lift_x(log.field(2)).ok_or_else(|| {
        Refusal::bad_request("field `shared_log.fields[2]`: E.x is no point's x-coordinate")
    })?;
    let secret = coordinates(mul(e, scalar)).0;
    let correction = log.shared[j]
        .correction
        .map_or(Fr::zero(), |p| log.field(p));
    let wrap_before = log.field(3 + prev(i));
    let [a, b] = node_pair(i, secret, wrap_before, j, correction);
    Ok(Share::new(a, b))
}

/// The binder's share of `name` under secret-shared on-chain intake for node `i`
/// of `namespace`: [`derived_share`] with this node's scalar for the epoch
/// the log names for it ([`crate::epochs::EpochKeys`]). 400 when the node
/// holds none (never recorded, or retired) or the log does not derive.
pub fn node_share(
    keys: &NodeKeys,
    i: usize,
    namespace: Fr,
    log: &SharedLog,
    name: &str,
) -> Result<Share, Refusal> {
    let epoch = log.epoch(i)?;
    let scalar = keys.epochs().scalar(namespace, epoch).ok_or_else(|| {
        Refusal::bad_request(format!(
            "shared input `{name}`: the request log names epoch {epoch} for node {i}, and this \
             node holds no enc scalar of that epoch for namespace {} (never recorded, or retired)",
            FieldHex(namespace)
        ))
    })?;
    derived_share(scalar, i, log, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::random_scalar;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;

    #[test]
    fn the_epochs_pack_into_one_field_and_back() {
        let e = [1, u32::MAX, 7];
        assert_eq!(unpack_epochs(pack_epochs(e)), Some(e));
        assert_eq!(
            pack_epochs([1, 2, 3]),
            Fr::from(1u64) + Fr::from(2u64) * Fr::from(1u64 << 32) + Fr::from(3u128 << 64)
        );
        assert_eq!(unpack_epochs(Fr::from(1u128 << 96)), None);
        assert_eq!(unpack_epochs(-Fr::from(1u64)), None);
    }

    #[test]
    fn every_node_derives_its_pair_of_every_shared_value() {
        let mut rng = StdRng::seed_from_u64(7);
        let scalars: [Fq; NODES] = std::array::from_fn(|_| random_scalar(&mut rng));
        let keys = scalars.map(fixed_base_mul);
        let kinds = [
            Kind::Clear,
            Kind::Chosen,
            Kind::Chosen,
            Kind::Chosen,
            Kind::Chosen,
        ];
        let values = [7u64, 5000, 0xbeef, 0x6b, 0x7a].map(Fr::from);
        let enc = encode(&kinds, &values, Fr::from(0xe9e9u64), keys);
        assert_eq!(enc.clear, [Fr::from(7u64)]);
        assert_eq!(enc.corrections.len(), 4);
        let fields = request_log(Fr::from(0xcu64), [3, 4, 5], &enc);
        assert_eq!(fields.len(), REQUEST_LOG_LEN);
        assert_eq!(fields[11], log_padding(enc.blinding, 11));
        let log = SharedLog {
            fields: fields.iter().copied().map(FieldHex).collect(),
            shared: vec![
                DerivedInput {
                    name: "amount".into(),
                    correction: Some(7),
                },
                DerivedInput {
                    name: "$partial_note".into(),
                    correction: Some(8),
                },
                DerivedInput {
                    name: "$outcome_key".into(),
                    correction: Some(9),
                },
                DerivedInput {
                    name: "$outcome_tag".into(),
                    correction: Some(10),
                },
                DerivedInput {
                    name: "$blinding".into(),
                    correction: None,
                },
            ],
        };
        log.check().unwrap();
        assert_eq!([0, 1, 2].map(|i| log.epoch(i).unwrap()), [3, 4, 5]);
        let want = [values[1], values[2], values[3], values[4], enc.blinding];
        for (j, input) in log.shared.iter().enumerate() {
            let pairs: Vec<Share> = (0..NODES)
                .map(|i| derived_share(scalars[i], i, &log, &input.name).unwrap())
                .collect();
            for i in 0..NODES {
                assert_eq!(pairs[i].b, pairs[(i + 2) % NODES].a, "{}", input.name);
            }
            assert_eq!(
                pairs.iter().map(|p| p.a).sum::<Fr>(),
                want[j],
                "{}",
                input.name
            );
        }
        // a node's pair under another node's scalar is not its pair
        let wrong = derived_share(scalars[1], 0, &log, "amount").unwrap();
        assert_ne!(wrong, derived_share(scalars[0], 0, &log, "amount").unwrap());
        assert!(derived_share(scalars[0], 0, &log, "other").is_err());
    }

    #[test]
    fn a_malformed_log_is_refused() {
        let ok = SharedLog {
            fields: vec![FieldHex(Fr::from(1u64)); REQUEST_LOG_LEN],
            shared: vec![DerivedInput {
                name: "a".into(),
                correction: Some(6),
            }],
        };
        ok.check().unwrap();
        let mut short = ok.clone();
        short.fields.pop();
        assert!(
            short
                .check()
                .unwrap_err()
                .message
                .contains("15 after its tag")
        );
        let mut twice = ok.clone();
        twice.shared.push(DerivedInput {
            name: "b".into(),
            correction: Some(6),
        });
        assert!(twice.check().unwrap_err().message.contains("position 6"));
        let mut header = ok.clone();
        header.shared[0].correction = Some(5);
        assert!(header.check().is_err());
        let mut dup = ok.clone();
        dup.shared.push(DerivedInput {
            name: "a".into(),
            correction: None,
        });
        assert!(dup.check().unwrap_err().message.contains("duplicated"));
        // `a` and `a\0` would be two names; every name is visible ASCII.
        for bad in ["a\0", "", "a b"] {
            let mut named = ok.clone();
            named.shared[0].name = bad.into();
            let err = named.check().unwrap_err();
            assert!(
                err.message.contains("field `shared_log.shared[0].name`: "),
                "{err}"
            );
        }
        assert!(lift_x(Fr::zero()).is_none());
    }
}
