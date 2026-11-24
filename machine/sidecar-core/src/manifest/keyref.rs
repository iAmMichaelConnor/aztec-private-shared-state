//! Key references: the fixed keys and `$state_keys.reads[i]` / `$state_keys.writes[j]`,
//! with their text and serde forms.

use std::str::FromStr;

use super::*;

// The fixed keys. The only one is `nsk_app`: the namespace's
// app-siloed nullifier secret key, derived inside the MPC at the namespace's first
// REGISTER from each node's master nullifier share and held by the nodes in either
// state mode. Circuits that nullify take it by `LOAD nsk_app`, slice [0, 1], len 1.
// It never appears in `state` or `consume`, cannot be STOREd, and a request key may
// not equal it. The master secret itself is never a key and never enters a circuit.
/// A machine-defined key a manifest names directly, rather than a request key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FixedKey {
    NskApp,
}

impl FixedKey {
    pub fn name(self) -> &'static str {
        match self {
            FixedKey::NskApp => "nsk_app",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "nsk_app" => Some(FixedKey::NskApp),
            _ => None,
        }
    }

    /// The stored length of the fixed key's value.
    pub fn stored_len(self) -> usize {
        match self {
            FixedKey::NskApp => 1,
        }
    }
}

/// A key reference: `$state_keys.reads[i]`, `$state_keys.writes[j]` (supplied by the request)
/// or a fixed key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyRef {
    Read(usize),
    Write(usize),
    Fixed(FixedKey),
}

impl KeyRef {
    pub fn is_fixed(self) -> bool {
        matches!(self, KeyRef::Fixed(_))
    }
}

fn is_fixed_key_name(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-'))
}

fn parse_index(text: &str, prefix: &str) -> Option<usize> {
    let digits = text.strip_prefix(prefix)?.strip_suffix(']')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

impl FromStr for KeyRef {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(i) = parse_index(s, "$state_keys.reads[") {
            return Ok(KeyRef::Read(i));
        }
        if let Some(j) = parse_index(s, "$state_keys.writes[") {
            return Ok(KeyRef::Write(j));
        }
        if is_fixed_key_name(s) {
            return FixedKey::from_name(s)
                .map(KeyRef::Fixed)
                .ok_or_else(|| format!("`{s}` is not a fixed key; the only fixed key is nsk_app"));
        }
        Err(format!(
            "`{s}` is not a key reference ($state_keys.reads[i], $state_keys.writes[j] or nsk_app)"
        ))
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyRef::Read(i) => write!(f, "$state_keys.reads[{i}]"),
            KeyRef::Write(j) => write!(f, "$state_keys.writes[{j}]"),
            KeyRef::Fixed(k) => f.write_str(k.name()),
        }
    }
}

impl Serialize for KeyRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for KeyRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(de::Error::custom)
    }
}
