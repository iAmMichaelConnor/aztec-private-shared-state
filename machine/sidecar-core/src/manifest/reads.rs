//! Pinned public reads: the call, its freshness policy and its band.

use crate::field::{FieldHex, Fr, fr_to_be_bytes};
use crate::tree::fr_u64;

use super::*;

// A pinned read of the namespace's own contract (lending's `clock`) is
// written `"contract": "$self"`, never with the address: the address is the
// namespace, which derives from the constructor's arguments, and those
// commit to the contract manifest that holds this manifest. The machine
// substitutes the namespace when it runs the read, and REGISTER refuses a read
// that names the namespace by its address ([`refuse_own_address`]).
/// The contract a pinned read calls: `"$self"`, the namespace's own contract,
/// or an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadContract {
    /// `"$self"`: the namespace's own contract.
    Own,
    /// Another contract, by address.
    At(FieldHex),
}

/// The spelling of [`ReadContract::Own`].
pub const SELF_CONTRACT: &str = "$self";

impl ReadContract {
    /// The called address under `namespace`.
    pub fn address(self, namespace: Fr) -> Fr {
        match self {
            ReadContract::Own => namespace,
            ReadContract::At(address) => address.fr(),
        }
    }
}

impl From<Fr> for ReadContract {
    fn from(address: Fr) -> Self {
        ReadContract::At(FieldHex(address))
    }
}

impl Serialize for ReadContract {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ReadContract::Own => serializer.serialize_str(SELF_CONTRACT),
            ReadContract::At(address) => address.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ReadContract {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text == SELF_CONTRACT {
            return Ok(ReadContract::Own);
        }
        text.parse::<FieldHex>()
            .map(ReadContract::At)
            .map_err(|e| de::Error::custom(format!("{e}; the namespace's own contract is `$self`")))
    }
}

/// Refuse (400) a manifest whose pinned read names `namespace` by its
/// address: the namespace's own contract is written `$self`, so the manifest
/// never contains the address that derives from it.
pub fn refuse_own_address(manifest: &Manifest, namespace: Fr) -> Result<(), Refusal> {
    match manifest
        .public_reads
        .iter()
        .position(|r| r.contract == ReadContract::At(FieldHex(namespace)))
    {
        Some(q) => Err(Refusal::bad_request(format!(
            "field `public_reads[{q}].contract`: the namespace's own address; a read of the \
             namespace's own contract is written `$self`"
        ))),
        None => Ok(()),
    }
}

/// `{"contract", "function", "args", "param", "freshness", "epoch_param",
/// "band"}`: a nested public call whose returned value fills the public
/// parameter `param`, and the rule by which `apply` accepts that value later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRead {
    /// The called contract: `$self` or an address.
    pub contract: ReadContract,
    /// The public function's name.
    pub function: String,
    /// The call's arguments, pinned by the manifest.
    pub args: Vec<FieldHex>,
    /// The public parameter the returned value fills.
    pub param: String,
    /// When a value read earlier still counts: `exact` (the default),
    /// `epoch` or `tolerance`.
    #[serde(default, skip_serializing_if = "Freshness::is_exact")]
    pub freshness: Freshness,
    /// Under `epoch` only (and required there): the public parameter the
    /// value's epoch fills, right after `param` in the public inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_param: Option<String>,
    /// Under `tolerance` only (and required there): how far the value may
    /// have moved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub band: Option<Band>,
}

impl PublicRead {
    /// The public parameters the read fills, in public-input order: `param`,
    /// then `epoch_param` under `epoch`.
    pub fn params(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.param.as_str()).chain(self.epoch_param.as_deref())
    }

    /// How many fields the call returns: three under `epoch` (the value, its
    /// epoch, the value of the epoch before), else as many as `param` has.
    pub fn returns(&self, param_width: usize) -> usize {
        match self.freshness {
            Freshness::Epoch => 3,
            Freshness::Exact | Freshness::Tolerance => param_width,
        }
    }

    /// Whether `used`, the pinned values a round took for this read (its
    /// value, then its epoch under `epoch`), still counts against `current`,
    /// the values a read now gives in the same form, and `previous`, the
    /// value of the epoch before `current`'s (under `epoch` only): the rule
    /// `apply` checks (pss_public_contract `Freshness`), which the scheduler
    /// keeps an attempt by and the chain verifier admits a request by.
    ///
    /// - `exact`: `used` equals `current`.
    /// - `epoch`: both epochs are below 2^64 (else nothing is admitted, as
    ///   `apply` reverts), compared as integers; `used` is `current`, or
    ///   `used`'s epoch is the one before `current`'s and its value is
    ///   `previous`.
    /// - `tolerance`: both values are below 2^128 (else nothing is admitted,
    ///   as `apply` reverts) and `|used - current|` is
    ///   at most the absolute band, or at most `relative_bps / 10000` of the
    ///   current value.
    pub fn admits(&self, current: &[Fr], previous: Option<Fr>, used: &[Fr]) -> bool {
        match (self.freshness, &self.band) {
            (Freshness::Exact, _) => used == current,
            (Freshness::Epoch, _) => match (current, used) {
                ([now, epoch], [value, used_epoch]) => {
                    let (Some(epoch), Some(used_epoch)) = (fr_u64(*epoch), fr_u64(*used_epoch))
                    else {
                        return false;
                    };
                    if used_epoch == epoch {
                        value == now
                    } else {
                        used_epoch.checked_add(1) == Some(epoch) && previous == Some(*value)
                    }
                }
                _ => false,
            },
            (Freshness::Tolerance, Some(band)) => match (current, used) {
                ([current], [used]) => band.admits(*current, *used),
                _ => false,
            },
            (Freshness::Tolerance, None) => false,
        }
    }
}

// DEV DECISION: a pinned read's freshness, the app's choice per read,
// default `exact`; under `exact` a value that moves faster than a round
// lands keeps the head waiting until `skip()` (the user loses the request and
// its fee), while `epoch` and `tolerance` let a round land at a value the
// chain has moved past. Design guide: "pinned-read freshness".
// It sets when a value a round read earlier still lets the result land.
// `exact`: `apply` requires the value the circuit used; right for a value
// a trusted party moves rarely. `epoch`: the source publishes each value
// with an epoch counter and keeps the value of the epoch before; `apply`
// accepts the current epoch or the one before it, so a round lands as long
// as at most one new epoch opens between the scheduler's read and `apply`;
// right for a feed that updates often, if the source opens epochs no faster
// than a round lands. `tolerance`: `apply` accepts a value within an
// absolute or relative band of the current one; the app accepts that the
// round ran at a price that much off. Under `epoch` the circuit takes the
// epoch as one more public input; under `tolerance` the round may apply at a
// value up to the band away from the chain's.
/// The freshness policy of a pinned read (`public_reads[].freshness`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// `apply` requires the value the circuit used.
    #[default]
    Exact,
    /// `apply` accepts the source's current epoch or the one before it.
    Epoch,
    /// `apply` accepts a value within `band` of the current one.
    Tolerance,
}

impl Freshness {
    pub fn as_str(self) -> &'static str {
        match self {
            Freshness::Exact => "exact",
            Freshness::Epoch => "epoch",
            Freshness::Tolerance => "tolerance",
        }
    }

    fn is_exact(&self) -> bool {
        *self == Freshness::Exact
    }
}

/// The largest relative band, in basis points: 100%.
pub const MAX_RELATIVE_BPS: u32 = 10_000;

/// A tolerance read's band (`public_reads[].band`): `{"absolute": "<u128>"}`,
/// a decimal string, or `{"relative_bps": n}`, `n` in 1 ..= 10000 basis
/// points of the current value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Band {
    Absolute(#[serde(with = "decimal_u128")] u128),
    RelativeBps(u32),
}

impl Band {
    /// Whether `used` lies within the band of `current` (both below 2^128).
    pub fn admits(&self, current: Fr, used: Fr) -> bool {
        let (Some(c), Some(u)) = (fr_to_u128(current), fr_to_u128(used)) else {
            return false;
        };
        let diff = c.abs_diff(u);
        match *self {
            Band::Absolute(band) => diff <= band,
            // diff * 10000 <= bps * current, over the integers (below 2^142,
            // so in 256 bits)
            Band::RelativeBps(bps) => {
                let wide = |a: u128, b: u128| {
                    let (lo, hi) = (a & u64::MAX as u128, a >> 64);
                    // (hi * 2^64 + lo) * b as (high 128, low 128), b < 2^14
                    let low = lo * b;
                    let high = hi * b + (low >> 64);
                    (
                        high >> 64,
                        ((high & u64::MAX as u128) << 64) | (low & u64::MAX as u128),
                    )
                };
                wide(diff, MAX_RELATIVE_BPS as u128) <= wide(c, bps as u128)
            }
        }
    }
}

/// `value` as a u128, if it is below 2^128.
fn fr_to_u128(value: Fr) -> Option<u128> {
    let bytes = fr_to_be_bytes(value);
    bytes[..16]
        .iter()
        .all(|b| *b == 0)
        .then(|| u128::from_be_bytes(bytes[16..].try_into().expect("16 bytes")))
}

/// A u128 written as a decimal string (a band may exceed what a JSON number
/// carries exactly).
mod decimal_u128 {
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(de::Error::custom(format!(
                "`{text}` is not a decimal integer"
            )));
        }
        text.parse()
            .map_err(|_| de::Error::custom(format!("`{text}` does not fit 128 bits")))
    }
}
