//! The error classes every endpoint answers with, and their HTTP codes.
//!
//! A refusal travels as `{"error": "<message>", "class": "<class>"}` on both legs,
//! so the orchestrator can pass a node's refusal on unchanged.

use std::fmt;

use serde::{Deserialize, Serialize};

// The error classes and their HTTP codes are part of the wire
// contract (docs/ARCHITECTURE.md section 8). Clients branch on `class`, not on the message
// text: 409 means "do not retry this body, FETCH or rebuild", 500 means "retry
// later or FETCH", 400/403/422 mean "the request itself is wrong". Adding a class
// is a protocol change for every client; reword messages freely.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// Malformed body, not a field element, an unknown circuit, a bad PUBLIC name,
    /// a wrong key count, a state record that does not open. Names the field.
    BadRequest,
    /// REGISTER under an owned namespace without a valid owner signature.
    Forbidden,
    /// Unknown package on GET, unknown request id on FETCH.
    NotFound,
    /// No value at a read key, consumed state, length mismatch, key occupied and
    /// not loaded, request id reused with a different body.
    Conflict,
    /// The proof does not verify: the circuit's constraints fail. Nothing stored.
    Unsatisfied,
    /// Mesh or proving failure, or the nodes disagree. Nothing stored.
    MpcFailure,
}

impl ErrorClass {
    /// The HTTP status code of this class.
    pub fn status(self) -> u16 {
        match self {
            ErrorClass::BadRequest => 400,
            ErrorClass::Forbidden => 403,
            ErrorClass::NotFound => 404,
            ErrorClass::Conflict => 409,
            ErrorClass::Unsatisfied => 422,
            ErrorClass::MpcFailure => 500,
        }
    }

    /// The wire name, as it appears in the `class` field.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorClass::BadRequest => "bad_request",
            ErrorClass::Forbidden => "forbidden",
            ErrorClass::NotFound => "not_found",
            ErrorClass::Conflict => "conflict",
            ErrorClass::Unsatisfied => "unsatisfied",
            ErrorClass::MpcFailure => "mpc_failure",
        }
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused request: its class and a message that names the offending field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    pub class: ErrorClass,
    #[serde(rename = "error")]
    pub message: String,
}

impl Refusal {
    pub fn new(class: ErrorClass, message: impl Into<String>) -> Self {
        Refusal {
            class,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(ErrorClass::BadRequest, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ErrorClass::Forbidden, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorClass::NotFound, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorClass::Conflict, message)
    }

    pub fn unsatisfied(message: impl Into<String>) -> Self {
        Self::new(ErrorClass::Unsatisfied, message)
    }

    pub fn mpc_failure(message: impl Into<String>) -> Self {
        Self::new(ErrorClass::MpcFailure, message)
    }

    /// The HTTP status code to answer with.
    pub fn status(&self) -> u16 {
        self.class.status()
    }

    /// The JSON body to answer with.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a refusal always serialises")
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.class, self.status(), self.message)
    }
}

impl std::error::Error for Refusal {}

/// Parse a JSON body into `T`, turning any serde error into a `bad_request` that
/// names the JSON path of the offending field, for example
/// "field `records[0].c[1]`: ...". The top-level path is reported as "body".
pub fn parse_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, Refusal> {
    let mut de = serde_json::Deserializer::from_str(text);
    let value = serde_path_to_error::deserialize(&mut de).map_err(path_refusal)?;
    // Trailing garbage after the JSON value is malformed too.
    de.end()
        .map_err(|e| Refusal::bad_request(format!("body: {e}")))?;
    Ok(value)
}

/// As [`parse_json`], from an already parsed JSON value (a manifest inside a
/// REGISTER body, for instance).
pub fn parse_value<T: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
) -> Result<T, Refusal> {
    serde_path_to_error::deserialize(value).map_err(path_refusal)
}

/// A `deserialize_with` for JSON objects read into a map: refuses a key that
/// appears twice, which serde_json would otherwise let the last one win.
pub(crate) fn unique_map<'de, D, K, V>(
    deserializer: D,
) -> Result<std::collections::BTreeMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: serde::Deserialize<'de> + Ord + fmt::Display,
    V: serde::Deserialize<'de>,
{
    struct MapVisitor<K, V>(std::marker::PhantomData<(K, V)>);
    impl<'de, K, V> serde::de::Visitor<'de> for MapVisitor<K, V>
    where
        K: serde::Deserialize<'de> + Ord + fmt::Display,
        V: serde::Deserialize<'de>,
    {
        type Value = std::collections::BTreeMap<K, V>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut out = std::collections::BTreeMap::new();
            while let Some(key) = map.next_key::<K>()? {
                if out.contains_key(&key) {
                    return Err(serde::de::Error::custom(format!("`{key}` appears twice")));
                }
                let value = map.next_value()?;
                out.insert(key, value);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_map(MapVisitor(std::marker::PhantomData))
}

fn path_refusal<E: fmt::Display>(error: serde_path_to_error::Error<E>) -> Refusal {
    let path = error.path().to_string();
    let inner = error.into_inner();
    if path == "." {
        Refusal::bad_request(format!("body: {inner}"))
    } else {
        Refusal::bad_request(format!("field `{path}`: {inner}"))
    }
}

/// Test assertion: `result` is a refusal of `class` whose message contains
/// every one of `needles`.
#[cfg(any(test, feature = "test-util"))]
pub fn assert_refused<T: fmt::Debug>(
    result: Result<T, Refusal>,
    class: ErrorClass,
    needles: &[&str],
) {
    let err = result.unwrap_err();
    assert_eq!(err.class, class, "{err}");
    for needle in needles {
        assert!(
            err.message.contains(needle),
            "`{}` lacks `{needle}`",
            err.message
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_has_its_status_name_and_constructor() {
        type Constructor = fn(&'static str) -> Refusal;
        let table: [(ErrorClass, u16, &str, Constructor); 6] = [
            (
                ErrorClass::BadRequest,
                400,
                "bad_request",
                Refusal::bad_request,
            ),
            (ErrorClass::Forbidden, 403, "forbidden", Refusal::forbidden),
            (ErrorClass::NotFound, 404, "not_found", Refusal::not_found),
            (ErrorClass::Conflict, 409, "conflict", Refusal::conflict),
            (
                ErrorClass::Unsatisfied,
                422,
                "unsatisfied",
                Refusal::unsatisfied,
            ),
            (
                ErrorClass::MpcFailure,
                500,
                "mpc_failure",
                Refusal::mpc_failure,
            ),
        ];
        for (class, status, name, constructor) in table {
            assert_eq!(class.status(), status);
            assert_eq!(class.as_str(), name);
            assert_eq!(serde_json::to_value(class).unwrap(), name);
            assert_eq!(Refusal::new(class, "why").status(), status);
            assert_eq!(constructor("why"), Refusal::new(class, "why"));
        }
    }

    #[test]
    fn refusal_json_shape() {
        let r = Refusal::conflict("request id reused with a different body");
        let json: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"error": "request id reused with a different body", "class": "conflict"})
        );
        let back: Refusal = serde_json::from_value(json).unwrap();
        assert_eq!(back, r);
        assert!(serde_json::from_str::<Refusal>(r#"{"error":"x","class":"teapot"}"#).is_err());
        assert!(
            serde_json::from_str::<Refusal>(r#"{"error":"x","class":"conflict","extra":1}"#)
                .is_err()
        );
    }
}
