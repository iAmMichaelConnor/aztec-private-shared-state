//! Witness sources: the reserved operands and shared names, PUBLIC operands,
//! LOAD, and the wire form of a source.

use std::str::FromStr;

use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::field::FieldHex;

use super::*;

// The reserved PUBLIC operands of a queued intake,
// `$vk_hash` and `$user_nonce`, beside `$namespace`. A queued request's
// circuit may take the values its chain request id commits to
// (`poseidon2(namespace, vk_hash, inputs_hash, user_nonce)`, so a
// receipt-intake circuit can output that id), and those values are not app inputs: the
// user does not choose `vk_hash` (the registered package's vk hash, filled by
// the machine, never by a request or a receipt body), and `user_nonce` sits
// beside the inputs in the request log or the stored receipt. Under a secret-shared
// intake the id commits to the inputs commitment instead (`poseidon2(namespace,
// vk_hash, C)`), which `$inputs_hash` names, filling one private Field
// parameter; `$user_nonce` is refused there and `$inputs_hash` under the
// non-secret-shared intakes. `$user` is refused under every intake: no request names
// its requester (docs/ARCHITECTURE.md section 6, "The hidden requester"). Naming them by reserved
// operand keeps them out of the app inputs
// `inputs_hash` hashes (sidecar-tip's `intake_inputs`), so the nodes, the
// client and the contract's intake function all hash the same list. The
// scheduler's synthesis places each value in the request's `public` map
// under the name of the parameter it fills, and the binder reads it from
// there (bind.rs). Each fills one whole Field parameter, public or private
// (the AMM receipt circuit keeps `user_nonce` private), at most once per manifest,
// never inside a PUBLIC list, and the parameter's name may not also be a
// request public name. Intake direct refuses them: a direct request has no
// chain request id. Naming such a value by an ordinary public name instead
// makes it an app input, so every hash a client and the contract compute
// over the inputs without it differs from the node's and no receipt
// verifies.
/// A reserved PUBLIC operand of a queued intake: a value the chain
/// request id commits to beside the app inputs, filled by the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReservedOperand {
    /// `$vk_hash`: the registered package's vk hash.
    VkHash,
    /// `$user_nonce`: the request's random salt.
    UserNonce,
    /// `$new_leaf`: the index the scheduler assigns a leaf a round opens in
    /// a tree-valued key (the append index of the version the round loads,
    /// 0 when the tree is full).
    NewLeaf,
    /// `$inputs_hash` (secret-shared intakes only): the inputs commitment `C` the
    /// chain request id commits to, a private witness the round checks the
    /// shared inputs against.
    InputsHash,
    /// `$partial_note` (non-secret-shared intakes, `outcome: partial`): the
    /// request's partial note, which the round returns right after `ok` and
    /// the app's `apply` completes in public. A clear app input covered by
    /// `inputs_hash`, carried in the request's inputs under the name of the
    /// parameter it fills; under a secret-shared intake it is the
    /// INPUT_SHARED [`SharedReserved::PartialNote`].
    PartialNote,
}

impl ReservedOperand {
    pub const ALL: [ReservedOperand; 5] = [
        ReservedOperand::VkHash,
        ReservedOperand::UserNonce,
        ReservedOperand::NewLeaf,
        ReservedOperand::InputsHash,
        ReservedOperand::PartialNote,
    ];

    /// Whether the operand is a clear app input the user supplies (the
    /// partial note), walked and hashed with the request public names under
    /// the name of the parameter it fills, rather than a value the machine
    /// or the request body fills.
    pub fn app_input(self) -> bool {
        self == ReservedOperand::PartialNote
    }

    /// The operand as a manifest spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            ReservedOperand::VkHash => "$vk_hash",
            ReservedOperand::UserNonce => "$user_nonce",
            ReservedOperand::NewLeaf => "$new_leaf",
            ReservedOperand::InputsHash => "$inputs_hash",
            ReservedOperand::PartialNote => "$partial_note",
        }
    }

    pub fn from_operand(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

impl fmt::Display for ReservedOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A reserved INPUT_SHARED name of a secret-shared intake: a value the user
/// chooses per request and shares with the app inputs (`$blinding` drawn at
/// random, or under secret-shared on-chain intake defined by the encoding). Each fills exactly one
/// private Field parameter of a secret-shared-intake manifest, and no other
/// manifest names one; every other `$` name under INPUT_SHARED is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SharedReserved {
    /// `$blinding`: the blinding of the inputs commitment `C`, its last
    /// element.
    Blinding,
    /// `$outcome_key`: the key the round encrypts the outcome under, which
    /// the client derives from the wallet secret and its request counter.
    OutcomeKey,
    /// `$outcome_tag`: the tag of the outcome log, derived as the key is.
    OutcomeTag,
    /// `$partial_note` (`outcome: partial`): the request's partial note,
    /// `poseidon2_hash_with_separator([owner, rho],
    /// DOM_SEP__PARTIAL_NOTE_COMMITMENT)`, which the round completes. The
    /// user's request function computes it.
    PartialNote,
}

impl SharedReserved {
    pub const ALL: [SharedReserved; 4] = [
        SharedReserved::Blinding,
        SharedReserved::OutcomeKey,
        SharedReserved::OutcomeTag,
        SharedReserved::PartialNote,
    ];

    /// The name as a manifest spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            SharedReserved::Blinding => "$blinding",
            SharedReserved::OutcomeKey => "$outcome_key",
            SharedReserved::OutcomeTag => "$outcome_tag",
            SharedReserved::PartialNote => "$partial_note",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// Whether the value is one of the values `C` commits to before the
    /// blinding (every reserved value but `$blinding`, `C`'s last element).
    pub fn committed(self) -> bool {
        self != SharedReserved::Blinding
    }
}

impl fmt::Display for SharedReserved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One PUBLIC operand: a request public name, `$namespace`, a request key
/// (`$state_keys.reads[i]` / `$state_keys.writes[j]`, which must then parse as a field
/// element), a reserved operand of a queued intake (`$vk_hash`,
/// `$user_nonce`, `$new_leaf`, `$inputs_hash`), or a constant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicOperand {
    /// A name in the request's `public` map.
    Name(String),
    /// `$namespace`: the request's namespace.
    Namespace,
    /// A request key. Never a fixed key: those are secret.
    Key(KeyRef),
    /// A reserved operand (queued intakes only): filled from the request's
    /// `public` map under the name of the parameter it fills.
    Reserved(ReservedOperand),
    /// `{"const": "0x..."}`.
    Const(FieldHex),
}

impl FromStr for PublicOperand {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "$namespace" {
            return Ok(PublicOperand::Namespace);
        }
        if s.starts_with("$state_keys.") {
            return s.parse().map(PublicOperand::Key);
        }
        if let Some(r) = ReservedOperand::from_operand(s) {
            return Ok(PublicOperand::Reserved(r));
        }
        if s == "$user" {
            return Err(
                "`$user` is refused under every intake: no request names its requester \
                 (the hidden requester); a non-secret-shared intake's chain request id commits \
                 to `$user_nonce` instead"
                    .into(),
            );
        }
        if s.starts_with('$') {
            return Err(format!(
                "`{s}` is not a request reference ($namespace, $state_keys.reads[i], $state_keys.writes[j], \
                 or under a queued intake $vk_hash, $user_nonce, $new_leaf, $inputs_hash)"
            ));
        }
        if s.is_empty() {
            return Err("an empty public name".into());
        }
        Ok(PublicOperand::Name(s.to_string()))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConstOperand {
    #[serde(rename = "const")]
    value: FieldHex,
}

impl Serialize for PublicOperand {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            PublicOperand::Name(n) => serializer.serialize_str(n),
            PublicOperand::Namespace => serializer.serialize_str("$namespace"),
            PublicOperand::Key(k) => serializer.collect_str(k),
            PublicOperand::Reserved(r) => serializer.serialize_str(r.as_str()),
            PublicOperand::Const(v) => ConstOperand { value: *v }.serialize(serializer),
        }
    }
}

struct OperandVisitor;

impl<'de> Visitor<'de> for OperandVisitor {
    type Value = PublicOperand;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "a public name, $namespace, a $state_keys reference, a reserved operand or {\"const\": ...}",
        )
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<PublicOperand, E> {
        v.parse().map_err(E::custom)
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<PublicOperand, A::Error> {
        let c = ConstOperand::deserialize(de::value::MapAccessDeserializer::new(map))?;
        Ok(PublicOperand::Const(c.value))
    }
}

impl<'de> Deserialize<'de> for PublicOperand {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(OperandVisitor)
    }
}

/// The operand of PUBLIC: one value, or a list of values for an array parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicSource {
    One(PublicOperand),
    List(Vec<PublicOperand>),
}

impl PublicSource {
    pub fn operands(&self) -> &[PublicOperand] {
        match self {
            PublicSource::One(op) => std::slice::from_ref(op),
            PublicSource::List(list) => list,
        }
    }
}

impl Serialize for PublicSource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            PublicSource::One(op) => op.serialize(serializer),
            PublicSource::List(list) => list.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for PublicSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SourceVisitor;
        impl<'de> Visitor<'de> for SourceVisitor {
            type Value = PublicSource;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a public operand or a list of them")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<PublicSource, E> {
                OperandVisitor.visit_str(v).map(PublicSource::One)
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<PublicSource, A::Error> {
                OperandVisitor.visit_map(map).map(PublicSource::One)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<PublicSource, A::Error> {
                let mut list = Vec::new();
                while let Some(op) = seq.next_element::<PublicOperand>()? {
                    list.push(op);
                }
                Ok(PublicSource::List(list))
            }
        }
        deserializer.deserialize_any(SourceVisitor)
    }
}

/// `{"LOAD": key, "slice": [a, b], "len": n}`: elements `[a, b)` of the value
/// stored at `key`, whose full stored length is `len`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Load {
    pub key: KeyRef,
    pub slice: [usize; 2],
    pub len: usize,
}

/// Where a witness parameter's value comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// PUBLIC: a public value; the only source that may fill a public parameter.
    Public(PublicSource),
    /// SAMPLE n: n fresh shared field elements nobody knows.
    Sample(usize),
    /// LOAD: a slice of a stored value.
    Load(Load),
    /// INPUT_SHARED name: the user's secret input of that name.
    InputShared(String),
}

impl Source {
    pub fn opcode(&self) -> &'static str {
        match self {
            Source::Public(_) => "PUBLIC",
            Source::Sample(_) => "SAMPLE",
            Source::Load(_) => "LOAD",
            Source::InputShared(_) => "INPUT_SHARED",
        }
    }
}

// The wire form of a source: one object whose opcode key names the source, plus
// LOAD's `slice` and `len`. Parsed through this struct so each opcode gets a precise
// error, and so a LOAD `create` gets its own message.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    #[serde(rename = "PUBLIC", default, skip_serializing_if = "Option::is_none")]
    public: Option<PublicSource>,
    #[serde(rename = "SAMPLE", default, skip_serializing_if = "Option::is_none")]
    sample: Option<usize>,
    #[serde(rename = "LOAD", default, skip_serializing_if = "Option::is_none")]
    load: Option<KeyRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    slice: Option<[usize; 2]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    len: Option<usize>,
    #[serde(
        rename = "INPUT_SHARED",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    input_shared: Option<String>,
    #[serde(default, skip_serializing)]
    create: Option<IgnoredAny>,
}

impl Serialize for Source {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw = match self {
            Source::Public(p) => RawSource {
                public: Some(p.clone()),
                ..Default::default()
            },
            Source::Sample(n) => RawSource {
                sample: Some(*n),
                ..Default::default()
            },
            Source::Load(l) => RawSource {
                load: Some(l.key),
                slice: Some(l.slice),
                len: Some(l.len),
                ..Default::default()
            },
            Source::InputShared(name) => RawSource {
                input_shared: Some(name.clone()),
                ..Default::default()
            },
        };
        raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Source {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawSource::deserialize(deserializer)?;
        let opcodes = [
            raw.public.is_some(),
            raw.sample.is_some(),
            raw.load.is_some(),
            raw.input_shared.is_some(),
        ];
        match opcodes.iter().filter(|x| **x).count() {
            0 => {
                return Err(de::Error::custom(
                    "no opcode: expected one of PUBLIC, SAMPLE, LOAD, INPUT_SHARED",
                ));
            }
            1 => {}
            _ => return Err(de::Error::custom("more than one opcode in one source")),
        }
        if raw.create.is_some() {
            return Err(de::Error::custom(
                "LOAD `create` is not part of the manifest: a fresh value enters the store through a SAMPLE parameter and STORE",
            ));
        }
        if let Some(key) = raw.load {
            let (Some(slice), Some(len)) = (raw.slice, raw.len) else {
                return Err(de::Error::custom("LOAD needs `slice` and `len`"));
            };
            return Ok(Source::Load(Load { key, slice, len }));
        }
        if raw.slice.is_some() || raw.len.is_some() {
            return Err(de::Error::custom("`slice` and `len` belong to LOAD only"));
        }
        Ok(match (raw.public, raw.sample, raw.input_shared) {
            (Some(p), _, _) => Source::Public(p),
            (_, Some(n), _) => Source::Sample(n),
            (_, _, Some(name)) => Source::InputShared(name),
            _ => unreachable!("exactly one opcode is present"),
        })
    }
}
