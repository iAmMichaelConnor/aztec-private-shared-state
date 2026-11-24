//! The witness binder: fills co-noir's shared-input map from the manifest's
//! sources, walking the [`CircuitShape`] REGISTER produced (docs/ARCHITECTURE.md
//! section 7).
//!
//! It runs in two phases. [`check_request`] is pure: it checks the request against
//! the manifest and resolves every PUBLIC value, with the typed range checks, so
//! the orchestrator can run it before fanning out and every node runs it again.
//! [`bind`] then does that, reads every LOADed key once, decrypts every
//! INPUT_SHARED value through the caller's hook, and only then draws the SAMPLEs.
//! A request refused anywhere is refused before any randomness is drawn.
//!
//! The binder does not decide where a value comes from. The caller's [`Sources`]
//! resolves a key to the node's store or to the opened state record, applies the
//! consumed-set check, and decrypts shared inputs; the binder only calls it.

use std::collections::{BTreeMap, BTreeSet};

use co_noir_types::{Rep3SharedInput, Rep3Type};
use mpc_core::protocols::rep3::Rep3PrimeFieldShare;

use crate::abi::{CircuitShape, Leaf};
use crate::error::Refusal;
use crate::field::{Fr, fr_from_hex, fr_to_short_hex};
use crate::manifest::{FixedKey, KeyRef, Manifest, PublicOperand, PublicSource, Source};
use crate::request::{Request, View};

/// One node's replicated share of a field element.
pub type Share = Rep3PrimeFieldShare<Fr>;

/// One element of a stored vector or of the witness: public, or this node's share.
pub type Elem = Rep3Type<Fr>;

/// What the binder needs from the node. Each method is called only after the
/// request has passed [`check_request`].
pub trait Sources {
    /// The full stored vector at `key`. `keyref` is the manifest's reference to it;
    /// `key` is the request's key string for `$state_keys.reads[i]`, or the fixed key's
    /// name (`"nsk_app"`) for a fixed key, for which the implementation returns the
    /// namespace's derived key share (never the master). The implementation
    /// resolves node-held versus client-held and the consumed set; it is called
    /// once per key per round.
    fn load(&mut self, keyref: KeyRef, key: &str) -> Result<Vec<Elem>, Refusal>;

    /// One fresh share from the round's correlated randomness. Called once per
    /// sampled element, in manifest order.
    fn sample(&mut self) -> Share;

    /// This node's decrypted share pair of the shared input `name`.
    fn shared_input(&mut self, name: &str) -> Result<Share, Refusal>;
}

/// One key the round read, with the full vector it loaded.
#[derive(Clone, Debug, PartialEq)]
pub struct Read {
    pub keyref: KeyRef,
    /// The request's key string, or the fixed key's name.
    pub key: String,
    pub value: Vec<Elem>,
}

/// The result of [`bind`].
#[derive(Clone, Debug, PartialEq)]
pub struct Bound {
    /// co-noir's input map: witness key to value.
    pub input: Rep3SharedInput<Fr>,
    /// Every key read, once each, in first-use order; for CONSUME and the audit
    /// log.
    pub reads: Vec<Read>,
    /// How many shares were sampled.
    pub samples: usize,
}

/// The PUBLIC values of a request, resolved and range-checked by
/// [`check_request`]: one vector per parameter, `None` for a parameter another
/// source fills.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicValues {
    pub per_param: Vec<Option<Vec<Fr>>>,
}

impl PublicValues {
    /// The public parameters' values in public-input order: the prefix of the
    /// proof's public inputs before the return value.
    pub fn public_prefix(&self, shape: &CircuitShape) -> Vec<Fr> {
        shape
            .params
            .iter()
            .zip(&self.per_param)
            .filter(|(p, _)| p.public_index.is_some())
            .flat_map(|(_, v)| v.iter().flatten().copied())
            .collect()
    }
}

// The request key a key reference names, or the fixed key's name.
fn key_string<V: View>(request: &Request<V>, keyref: KeyRef) -> &str {
    match keyref {
        KeyRef::Read(i) => &request.state_keys.reads[i],
        KeyRef::Write(j) => &request.state_keys.writes[j],
        KeyRef::Fixed(k) => k.name(),
    }
}

/// The checks of a request against its manifest that need no stored value, and
/// the PUBLIC values. Works on either view of the request (the orchestrator's full
/// one or a node's). Every refusal is `bad_request` and names the field or
/// parameter:
///
/// - the request names the manifest's circuit and supplies exactly the declared
///   number of read and write keys, none equal to a fixed key;
/// - every PUBLIC value resolves: a request public name (`name`, or `name[i]` for
///   a wider parameter), `$namespace`, a request key (which must parse as a field
///   element), a reserved operand of a queued intake (the request public value under
///   the parameter's name) or a constant; every value lies in its ABI leaf's typed range; and
///   every request public value is used;
/// - the request carries exactly the shared inputs the manifest names.
pub fn check_request<V: View>(
    shape: &CircuitShape,
    manifest: &Manifest,
    request: &Request<V>,
) -> Result<PublicValues, Refusal> {
    if request.circuit != manifest.circuit {
        return Err(Refusal::bad_request(format!(
            "field `circuit`: `{}` is not the manifest's circuit `{}`",
            request.circuit, manifest.circuit
        )));
    }
    for (list, keys, want) in [
        (
            "reads",
            &request.state_keys.reads,
            manifest.state_keys.reads,
        ),
        (
            "writes",
            &request.state_keys.writes,
            manifest.state_keys.writes,
        ),
    ] {
        if keys.len() != want {
            return Err(Refusal::bad_request(format!(
                "field `state_keys.{list}`: circuit `{}` takes {want} key(s), the request has {}",
                manifest.circuit,
                keys.len()
            )));
        }
        // A request key may never equal a fixed key. The request
        // parser already refuses it; the binder refuses it again because the
        // fixed key nsk_app is loaded through the same `Sources::load` call as
        // request keys, and a request that named `nsk_app` as its own read key
        // would aim the namespace's nullifier key at a parameter of its choosing.
        // Keep both checks; adding a fixed key means adding its name to FixedKey,
        // which both checks read.
        for (i, key) in keys.iter().enumerate() {
            if FixedKey::from_name(key).is_some() {
                return Err(Refusal::bad_request(format!(
                    "field `state_keys.{list}[{i}]`: `{key}` is a fixed key"
                )));
            }
        }
    }

    let public: BTreeMap<String, Fr> = request.flatten_public()?.into_iter().collect();
    let mut used: BTreeSet<&str> = BTreeSet::new();
    let mut per_param = Vec::with_capacity(shape.params.len());
    let mut shared_names = BTreeSet::new();
    for param in &shape.params {
        let operands: Vec<(&PublicOperand, Option<usize>)> = match &param.source {
            Source::Public(PublicSource::One(op)) if param.width == 1 => vec![(op, None)],
            // One request name filling a wider parameter: `name[0]`, `name[1]`, ...
            Source::Public(PublicSource::One(op)) => {
                (0..param.width).map(|i| (op, Some(i))).collect()
            }
            Source::Public(PublicSource::List(ops)) => ops.iter().map(|op| (op, None)).collect(),
            Source::InputShared(name) => {
                shared_names.insert(name.as_str());
                per_param.push(None);
                continue;
            }
            _ => {
                per_param.push(None);
                continue;
            }
        };
        let mut values = Vec::with_capacity(param.width);
        for (i, ((op, index), leaf)) in operands.into_iter().zip(&param.leaves).enumerate() {
            let (what, value) = match op {
                PublicOperand::Name(name) => {
                    let key = match index {
                        Some(i) => format!("{name}[{i}]"),
                        None => name.clone(),
                    };
                    let Some((key, value)) = public.get_key_value(&key) else {
                        return Err(Refusal::bad_request(format!(
                            "field `public.{key}`: missing (parameter `{}`)",
                            param.name
                        )));
                    };
                    used.insert(key.as_str());
                    (format!("`public.{key}`"), *value)
                }
                // A reserved operand (queued intakes only): the value the
                // scheduler's synthesis placed under the parameter's own name
                // (the comment on manifest.rs's ReservedOperand). Each
                // fills one whole parameter, so the key is the parameter name.
                PublicOperand::Reserved(r) => {
                    let Some((key, value)) = public.get_key_value(param.name.as_str()) else {
                        return Err(Refusal::bad_request(format!(
                            "field `public.{}`: missing (parameter `{}` is filled by `{r}`, \
                             which the scheduler places under the parameter's name)",
                            param.name, param.name
                        )));
                    };
                    used.insert(key.as_str());
                    (format!("`public.{key}` ({r})"), *value)
                }
                PublicOperand::Namespace => ("`namespace`".to_string(), request.namespace.0),
                PublicOperand::Key(keyref) => {
                    let key = key_string(request, *keyref);
                    let value = fr_from_hex(key).map_err(|e| {
                        Refusal::bad_request(format!(
                            "field `{}`: {e}; the manifest feeds {keyref} into parameter `{}`, so it must be a field element",
                            keyref_field(*keyref),
                            param.name
                        ))
                    })?;
                    // The intake says which spellings of a key it admits
                    // ([`crate::intake::IntakeRules::admits_key_spelling`]).
                    let short = fr_to_short_hex(value);
                    if !manifest.intake.rules().admits_key_spelling(key, &short) {
                        return Err(Refusal::bad_request(format!(
                            "field `{}`: `{key}` feeds parameter `{}` and is spelled `{short}`; \
                             a key that is a field element is 0x and lowercase hex digits \
                             without leading zeros",
                            keyref_field(*keyref),
                            param.name
                        )));
                    }
                    (format!("`{}`", keyref_field(*keyref)), value)
                }
                PublicOperand::Const(c) => ("a manifest constant".to_string(), c.0),
            };
            // The typed range checks. Each PUBLIC value is checked
            // against its ABI leaf type before anything is loaded or sampled: bool
            // 1 bit, u<N> and i<N> N bits (on the value's bit length, so a
            // negative i<N> is its N-bit two's complement), each string byte 8
            // bits. A Field gets no check. Values from LOAD, SAMPLE and
            // INPUT_SHARED are shares and get no check here: a circuit that types
            // such a parameter as an integer must constrain it itself. Without
            // these checks an out-of-range value would run a full MPC round and
            // fail only at VERIFY (or, if the circuit never range-checks its
            // input, be proven as the wrapped value).
            if !leaf.admits(value) {
                let bits = match leaf {
                    Leaf::Bits(n) => *n,
                    Leaf::Field => unreachable!("a Field admits every value"),
                };
                let element = if param.width == 1 {
                    String::new()
                } else {
                    format!(" element {i}")
                };
                return Err(Refusal::bad_request(format!(
                    "parameter `{}`{element}: {what} does not fit in {bits} bit(s)",
                    param.name
                )));
            }
            values.push(value);
        }
        per_param.push(Some(values));
    }
    if let Some(extra) = public.keys().find(|k| !used.contains(k.as_str())) {
        let takes: Vec<String> = shape
            .params
            .iter()
            .filter_map(|p| match &p.source {
                Source::Public(s) => Some(s.operands().iter().filter_map(|op| match op {
                    PublicOperand::Name(n) => Some(n.clone()),
                    PublicOperand::Reserved(_) => Some(p.name.clone()),
                    _ => None,
                })),
                _ => None,
            })
            .flatten()
            .collect();
        return Err(Refusal::bad_request(format!(
            "field `public.{extra}`: unexpected; circuit `{}` takes {takes:?}",
            manifest.circuit
        )));
    }

    // The intake's row says where the shares come from: envelopes (and no
    // log), or the request log (`shared_log`, and no envelope).
    let given = manifest
        .intake
        .share_source()
        .given_names(request, manifest)?;
    if let Some(missing) = shared_names.iter().find(|n| !given.contains(*n)) {
        return Err(Refusal::bad_request(format!(
            "field `shared_inputs`: missing `{missing}`"
        )));
    }
    if let Some(extra) = given.iter().find(|n| !shared_names.contains(*n)) {
        return Err(Refusal::bad_request(format!(
            "field `shared_inputs`: unexpected `{extra}`; circuit `{}` takes {shared_names:?}",
            manifest.circuit
        )));
    }
    Ok(PublicValues { per_param })
}

fn keyref_field(keyref: KeyRef) -> String {
    match keyref {
        KeyRef::Read(i) => format!("state_keys.reads[{i}]"),
        KeyRef::Write(j) => format!("state_keys.writes[{j}]"),
        KeyRef::Fixed(k) => k.name().to_string(),
    }
}

/// Bind the witness: [`check_request`], then every LOAD and INPUT_SHARED through
/// `sources`, then the SAMPLEs, producing co-noir's input map in ABI declaration
/// order. `shape` is what REGISTER's [`crate::abi::check_manifest`] returned for
/// this manifest.
///
/// Refusals: those of [`check_request`]; a stored vector whose length is not the
/// manifest's `len` is `conflict` (409) and names the key; whatever `sources`
/// returns, unchanged.
pub fn bind<V: View, S: Sources + ?Sized>(
    shape: &CircuitShape,
    manifest: &Manifest,
    request: &Request<V>,
    sources: &mut S,
) -> Result<Bound, Refusal> {
    let public = check_request(shape, manifest, request)?;

    // Slices of one key share one read. Each key is loaded once,
    // the first time a LOAD names it, and every slice of it is cut from that one
    // vector, so a value split over several parameters (fields and blinding) is
    // always one consistent stored value, consumed once. The manifest parser
    // already requires every LOAD of a key to give the same `len`. Reads are
    // cached by key reference: two request keys with the same string are two
    // reads.
    let mut reads: Vec<Read> = Vec::new();
    let mut shared: BTreeMap<&str, Share> = BTreeMap::new();
    for param in &shape.params {
        match &param.source {
            Source::Load(load) if !reads.iter().any(|r| r.keyref == load.key) => {
                let key = key_string(request, load.key);
                let value = sources.load(load.key, key)?;
                if value.len() != load.len {
                    return Err(Refusal::conflict(format!(
                        "{} = `{key}`: the stored value has {} element(s), the manifest expects {}",
                        load.key,
                        value.len(),
                        load.len
                    )));
                }
                reads.push(Read {
                    keyref: load.key,
                    key: key.to_string(),
                    value,
                });
            }
            Source::InputShared(name) => {
                let share = sources.shared_input(name)?;
                shared.insert(name.as_str(), share);
            }
            _ => {}
        }
    }

    // The sample order. Every SAMPLE draws its elements in
    // manifest (ABI declaration) order, after every LOAD and INPUT_SHARED has
    // succeeded. The three nodes draw from correlated PRNGs, so they must draw
    // the same number of shares in the same order or their shares stop being a
    // sharing of one value; declaration order is the one order every node knows.
    // Drawing after the fallible sources means a refused request draws nothing.
    // Changing the order changes which sampled value lands in which parameter,
    // so all three nodes must change together.
    let mut input: Rep3SharedInput<Fr> = BTreeMap::new();
    let mut samples = 0;
    for (param, public) in shape.params.iter().zip(&public.per_param) {
        let values: Vec<Elem> = match &param.source {
            Source::Public(_) => public
                .as_ref()
                .expect("check_request resolves every PUBLIC parameter")
                .iter()
                .map(|v| Elem::Public(*v))
                .collect(),
            Source::Sample(n) => {
                samples += n;
                (0..*n).map(|_| Elem::Shared(sources.sample())).collect()
            }
            Source::Load(load) => {
                let read = reads
                    .iter()
                    .find(|r| r.keyref == load.key)
                    .expect("every LOADed key was read above");
                read.value[load.slice[0]..load.slice[1]].to_vec()
            }
            Source::InputShared(name) => vec![Elem::Shared(shared[name.as_str()])],
        };
        debug_assert_eq!(values.len(), param.keys.len());
        for (key, value) in param.keys.iter().zip(values) {
            if input.insert(key.clone(), value).is_some() {
                return Err(Refusal::bad_request(format!(
                    "witness key `{key}` (parameter `{}`) is bound twice",
                    param.name
                )));
            }
        }
    }
    Ok(Bound {
        input,
        reads,
        samples,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::check_manifest_value;
    use crate::abi::tests::{
        amm_init_abi, amm_swap_abi, array, boolean, compiled_abi, effects, example_manifest, field,
        manifest_json, pss_seed_abi,
    };
    use crate::error::ErrorClass;
    use crate::request::NodeRequest;
    use noirc_abi::Abi;
    use serde_json::{Value, json};

    const NAMESPACE: &str = "0x1f2ea9c0";
    const SEED_ID: &str = "0x7c1e0000000000000000000000000001";
    const INIT_ID: &str = "0x2a900000000000000000000000000002";
    const SWAP_ID: &str = "0x41d30000000000000000000000000003";
    const DOOR_ID: &str = "0xd0040000000000000000000000000004";
    const NONCE: &str = "0x0d935b18";

    fn share(a: u64, b: u64) -> Share {
        Share::new(Fr::from(a), Fr::from(b))
    }

    // A deterministic Sources: stored vectors by key, numbered samples, shared
    // inputs by name, and a log of every call.
    #[derive(Default)]
    struct Fake {
        store: BTreeMap<String, Vec<Elem>>,
        shared: BTreeMap<String, Share>,
        next_sample: u64,
        loads: Vec<(KeyRef, String)>,
        hooks: Vec<String>,
    }

    impl Fake {
        fn with(mut self, key: &str, value: Vec<Elem>) -> Self {
            self.store.insert(key.to_string(), value);
            self
        }
        fn calls(&self) -> usize {
            self.loads.len() + self.hooks.len() + self.next_sample as usize
        }
    }

    impl Sources for Fake {
        fn load(&mut self, keyref: KeyRef, key: &str) -> Result<Vec<Elem>, Refusal> {
            self.loads.push((keyref, key.to_string()));
            self.store
                .get(key)
                .cloned()
                .ok_or_else(|| Refusal::conflict(format!("{keyref} = `{key}`: no value")))
        }
        fn sample(&mut self) -> Share {
            self.next_sample += 1;
            share(100 + self.next_sample, 200 + self.next_sample)
        }
        fn shared_input(&mut self, name: &str) -> Result<Share, Refusal> {
            self.hooks.push(name.to_string());
            self.shared
                .get(name)
                .copied()
                .ok_or_else(|| Refusal::bad_request(format!("`{name}` does not decrypt")))
        }
    }

    fn shared(a: u64) -> Elem {
        Elem::Shared(share(a, a + 1))
    }

    fn nsk() -> Vec<Elem> {
        vec![shared(70)]
    }

    // Requests of the AMM example's rounds (examples/amm).
    fn seed_request() -> Value {
        json!({"namespace": NAMESPACE, "circuit": "pss_seed", "request_id": SEED_ID,
               "public": {}, "state_keys": {"reads": [], "writes": ["0xa001"]}})
    }
    fn init_request() -> Value {
        json!({"namespace": NAMESPACE, "circuit": "amm_init", "request_id": INIT_ID,
               "public": {"in0_nonce": NONCE}, "state_keys": {"reads": ["0xa001"], "writes": ["0xa002"]}})
    }
    fn swap_request() -> Value {
        json!({"namespace": NAMESPACE, "circuit": "amm_swap", "request_id": SWAP_ID,
               "public": {"amount_in": "0x2710", "direction": "0x0", "in0_nonce": NONCE},
               "state_keys": {"reads": ["0xa002"], "writes": ["0xa002"]}})
    }

    fn node_request(body: &Value) -> NodeRequest {
        NodeRequest::from_json(&body.to_string()).unwrap()
    }

    fn setup(name: &str, abi: &Abi) -> (Manifest, CircuitShape) {
        check_manifest_value(&manifest_json(name), abi).unwrap()
    }

    fn pool() -> Vec<Elem> {
        vec![shared(10), shared(20), shared(30)]
    }

    fn bind_swap(body: &Value, sources: &mut Fake) -> Result<Bound, Refusal> {
        let (m, shape) = setup("amm_swap", &amm_swap_abi());
        bind(&shape, &m, &node_request(body), sources)
    }

    // The witness keys and their Public/Shared tags, in key order.
    fn tags(bound: &Bound) -> Vec<(&str, &str)> {
        bound
            .input
            .iter()
            .map(|(k, v)| {
                let tag = match v {
                    Elem::Public(_) => "Public",
                    Elem::Shared(_) => "Shared",
                };
                (k.as_str(), tag)
            })
            .collect()
    }

    fn sorted(mut v: Vec<(&'static str, &'static str)>) -> Vec<(&'static str, &'static str)> {
        v.sort();
        v
    }

    fn refused(result: Result<Bound, Refusal>, class: ErrorClass, needles: &[&str]) {
        crate::error::assert_refused(result, class, needles);
    }

    fn public(v: u64) -> Elem {
        Elem::Public(Fr::from(v))
    }

    // amm_swap binds these keys and tags: the public prefix and in0_nonce
    // Public, the pool fields as stored, the blinding, the sampled
    // out0_randomness and nsk_app Shared.
    #[test]
    fn amm_swap_binds_its_keys_and_tags() {
        let mut fake = Fake::default()
            .with("0xa002", pool())
            .with("nsk_app", nsk());
        let bound = bind_swap(&swap_request(), &mut fake).unwrap();
        assert_eq!(
            tags(&bound),
            sorted(vec![
                ("namespace", "Public"),
                ("owner", "Public"),
                ("in_slots", "Public"),
                ("out_slots", "Public"),
                ("amount_in", "Public"),
                ("direction", "Public"),
                ("in0_fields[0]", "Shared"),
                ("in0_fields[1]", "Shared"),
                ("in0_randomness", "Shared"),
                ("in0_nonce", "Public"),
                ("out0_randomness", "Shared"),
                ("nsk_app", "Shared"),
            ])
        );
        let i = &bound.input;
        assert_eq!(i["namespace"], public(0x1f2ea9c0));
        assert_eq!(i["owner"], public(0xafafaf));
        assert_eq!(i["in_slots"], public(0xa002));
        assert_eq!(i["out_slots"], public(0xa002));
        assert_eq!(i["amount_in"], public(0x2710));
        assert_eq!(i["direction"], public(0));
        assert_eq!(i["in0_nonce"], public(0x0d935b18));
        assert_eq!(i["in0_fields[0]"], shared(10));
        assert_eq!(i["in0_fields[1]"], shared(20));
        assert_eq!(i["in0_randomness"], shared(30));
        assert_eq!(i["out0_randomness"], Elem::Shared(share(101, 201)));
        assert_eq!(i["nsk_app"], shared(70));
        assert_eq!(bound.samples, 1);
        // One read per key, though two slices cut the pool; nsk_app through the
        // same call.
        assert_eq!(
            fake.loads,
            vec![
                (KeyRef::Read(0), "0xa002".to_string()),
                (KeyRef::Fixed(FixedKey::NskApp), "nsk_app".to_string())
            ]
        );
        let keys: Vec<&str> = bound.reads.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, vec!["0xa002", "nsk_app"]);
        assert_eq!(bound.reads[0].value, pool());
    }

    #[test]
    fn pss_seed_and_amm_init_bind_by_their_rules() {
        let (m, shape) = setup("pss_seed", &pss_seed_abi());
        let mut fake = Fake::default();
        let bound = bind(&shape, &m, &node_request(&seed_request()), &mut fake).unwrap();
        assert_eq!(
            tags(&bound),
            sorted(vec![
                ("namespace", "Public"),
                ("owner", "Public"),
                ("out_slots", "Public"),
                ("out0_randomness", "Shared"),
                ("rand_seed", "Shared"),
            ])
        );
        // Samples in manifest order: out0_randomness first, then rand_seed.
        assert_eq!(
            bound.input["out0_randomness"],
            Elem::Shared(share(101, 201))
        );
        assert_eq!(bound.input["rand_seed"], Elem::Shared(share(102, 202)));
        assert_eq!(bound.samples, 2);
        assert!(bound.reads.is_empty());

        let (m, shape) = setup("amm_init", &amm_init_abi());
        let mut fake = Fake::default()
            .with("0xa001", vec![shared(1), shared(2)])
            .with("nsk_app", nsk());
        let bound = bind(&shape, &m, &node_request(&init_request()), &mut fake).unwrap();
        assert_eq!(
            tags(&bound),
            sorted(vec![
                ("namespace", "Public"),
                ("owner", "Public"),
                ("in_slots", "Public"),
                ("out_slots", "Public"),
                ("in0_fields", "Shared"),
                ("in0_randomness", "Shared"),
                ("in0_nonce", "Public"),
                ("out0_randomness", "Shared"),
                ("nsk_app", "Shared"),
            ])
        );
        assert_eq!(bound.input["in_slots"], public(0xa001));
        assert_eq!(bound.input["out_slots"], public(0xa002));
        assert_eq!(bound.input["in0_fields"], shared(1));
        assert_eq!(bound.input["in0_randomness"], shared(2));
        assert_eq!(bound.samples, 1);
    }

    // The compiled ABIs, when present, bind to the same keys as the inline ones.
    #[test]
    fn the_compiled_amm_abis_bind_the_same_keys() {
        for (name, body, inline) in [
            ("pss_seed", seed_request(), pss_seed_abi()),
            ("amm_init", init_request(), amm_init_abi()),
            ("amm_swap", swap_request(), amm_swap_abi()),
        ] {
            let Some(abi) = compiled_abi("amm", name) else {
                continue;
            };
            let req = node_request(&body);
            let run = |abi: &Abi| {
                let (m, shape) = setup(name, abi);
                let mut fake = Fake::default()
                    .with("0xa001", vec![shared(1), shared(2)])
                    .with("0xa002", pool())
                    .with("nsk_app", nsk());
                bind(&shape, &m, &req, &mut fake).unwrap()
            };
            assert_eq!(run(&abi), run(&inline), "{name}");
        }
    }

    #[test]
    fn range_checks_refuse_before_anything_is_loaded_or_sampled() {
        for (name, value, needle) in [
            ("amount_in", "0x10000000000000000", "parameter `amount_in`"),
            ("direction", "0x2", "parameter `direction`"),
        ] {
            let mut body = swap_request();
            body["public"][name] = json!(value);
            let mut fake = Fake::default()
                .with("0xa002", pool())
                .with("nsk_app", nsk());
            refused(
                bind_swap(&body, &mut fake),
                ErrorClass::BadRequest,
                &[needle, "does not fit in"],
            );
            assert_eq!(fake.calls(), 0, "{name}: a source was called");
        }
        // The largest u64 and amount_in = 0 are in range; the circuit refuses 0.
        for value in ["0xffffffffffffffff", "0x0"] {
            let mut body = swap_request();
            body["public"]["amount_in"] = json!(value);
            let mut fake = Fake::default()
                .with("0xa002", pool())
                .with("nsk_app", nsk());
            bind_swap(&body, &mut fake).unwrap();
        }
    }

    #[test]
    fn public_name_refusals() {
        let mut fake = Fake::default()
            .with("0xa002", pool())
            .with("nsk_app", nsk());
        // Missing.
        let mut body = swap_request();
        body["public"].as_object_mut().unwrap().remove("in0_nonce");
        refused(
            bind_swap(&body, &mut fake),
            ErrorClass::BadRequest,
            &["public.in0_nonce", "missing", "parameter `in0_nonce`"],
        );
        // Unexpected.
        let mut body = swap_request();
        body["public"]["slippage"] = json!("0x1");
        refused(
            bind_swap(&body, &mut fake),
            ErrorClass::BadRequest,
            &["public.slippage", "unexpected"],
        );
        // Duplicated: `x[0]` given directly and again by the list `x`.
        let mut body = swap_request();
        body["public"]["x"] = json!(["0x1", "0x2"]);
        body["public"]["x[0]"] = json!("0x3");
        let err = NodeRequest::from_json(&body.to_string()).unwrap_err();
        assert!(err.message.contains("duplicated"), "{err}");
        // The binder flattens again itself, so a request built in code is caught too.
        let mut req = node_request(&swap_request());
        req.public.insert(
            "x".into(),
            crate::request::PublicValue::Many(vec![1u64.into(), 2u64.into()]),
        );
        req.public
            .insert("x[0]".into(), crate::request::PublicValue::One(3u64.into()));
        let (m, shape) = setup("amm_swap", &amm_swap_abi());
        refused(
            bind(&shape, &m, &req, &mut fake),
            ErrorClass::BadRequest,
            &["duplicated"],
        );
        assert_eq!(fake.calls(), 0);
    }

    #[test]
    fn a_request_key_fed_into_public_must_be_a_field_element() {
        let mut body = swap_request();
        body["state_keys"] = json!({"reads": ["pool"], "writes": ["0xa002"]});
        let mut fake = Fake::default().with("pool", pool()).with("nsk_app", nsk());
        refused(
            bind_swap(&body, &mut fake),
            ErrorClass::BadRequest,
            &["state_keys.reads[0]", "`pool`", "parameter `in_slots`"],
        );
        assert_eq!(fake.calls(), 0);
    }

    // Under intake direct `0x1`, `0x01` and `1` are one public slot, so only
    // the short spelling is admitted: otherwise each would be a store row.
    #[test]
    fn a_request_key_fed_into_public_has_one_spelling_under_direct_intake() {
        for alias in [
            "0x0a002",
            "a002",
            "0xA002",
            &crate::field::fr_to_hex(Fr::from(0xa002u64)),
        ] {
            let mut body = swap_request();
            body["state_keys"] = json!({"reads": [alias], "writes": ["0xa002"]});
            let mut fake = Fake::default().with(alias, pool()).with("nsk_app", nsk());
            refused(
                bind_swap(&body, &mut fake),
                ErrorClass::BadRequest,
                &[
                    "state_keys.reads[0]",
                    "parameter `in_slots`",
                    "spelled `0xa002`",
                ],
            );
            assert_eq!(fake.calls(), 0);
        }
        assert_eq!(fr_to_short_hex(Fr::from(0u64)), "0x0");
        assert_eq!(fr_to_short_hex(Fr::from(0xa002u64)), "0xa002");
    }

    #[test]
    fn a_request_key_equal_to_a_fixed_key_is_refused() {
        // The request parser refuses it; a request built in code is refused here.
        let mut req = node_request(&swap_request());
        req.state_keys.reads[0] = "nsk_app".into();
        let (m, shape) = setup("amm_swap", &amm_swap_abi());
        let mut fake = Fake::default().with("nsk_app", nsk());
        refused(
            bind(&shape, &m, &req, &mut fake),
            ErrorClass::BadRequest,
            &["state_keys.reads[0]", "fixed key"],
        );
        assert_eq!(fake.calls(), 0);
    }

    #[test]
    fn wrong_key_counts_and_circuit_are_refused() {
        let mut fake = Fake::default();
        let mut body = swap_request();
        body["state_keys"]["writes"] = json!([]);
        refused(
            bind_swap(&body, &mut fake),
            ErrorClass::BadRequest,
            &["state_keys.writes", "takes 1 key(s), the request has 0"],
        );
        let mut body = swap_request();
        body["circuit"] = json!("amm_init");
        refused(
            bind_swap(&body, &mut fake),
            ErrorClass::BadRequest,
            &["circuit"],
        );
    }

    #[test]
    fn a_stored_vector_of_the_wrong_length_is_a_conflict() {
        let mut fake = Fake::default()
            .with("0xa002", vec![shared(10), shared(20)])
            .with("nsk_app", nsk());
        refused(
            bind_swap(&swap_request(), &mut fake),
            ErrorClass::Conflict,
            &[
                "$state_keys.reads[0] = `0xa002`",
                "2 element(s)",
                "expects 3",
            ],
        );
        assert_eq!(fake.next_sample, 0, "sampled before the refusal");
        // A source's own refusal passes through unchanged.
        let mut empty = Fake::default();
        refused(
            bind_swap(&swap_request(), &mut empty),
            ErrorClass::Conflict,
            &["no value"],
        );
    }

    // A stored vector keeps its tags: a public element loads as Public.
    #[test]
    fn loaded_elements_keep_their_stored_tags() {
        let mut fake = Fake::default()
            .with("0xa002", vec![public(5), shared(20), shared(30)])
            .with("nsk_app", nsk());
        let bound = bind_swap(&swap_request(), &mut fake).unwrap();
        assert_eq!(bound.input["in0_fields[0]"], public(5));
        assert_eq!(bound.input["in0_fields[1]"], shared(20));
    }

    #[test]
    fn the_public_prefix_is_the_public_parameters_in_order() {
        let (m, shape) = setup("amm_swap", &amm_swap_abi());
        let values = check_request(&shape, &m, &node_request(&swap_request())).unwrap();
        let want: Vec<Fr> = [0x1f2ea9c0u64, 0xafafaf, 0xa002, 0xa002, 0x2710, 0]
            .into_iter()
            .map(Fr::from)
            .collect();
        assert_eq!(values.public_prefix(&shape), want);
    }

    // The Monty Hall door round: client-held state, the door and its blinding as
    // INPUT_SHARED. The manifest is read from disk; the ABI is the compiled one
    // when present, else the same signature written inline.
    fn open_door_abi() -> Abi {
        compiled_abi("monty-hall", "monty_hall_open_door").unwrap_or_else(|| {
            crate::abi::tests::abi(
                &[
                    ("namespace", "public", field()),
                    ("owner", "public", field()),
                    ("in_slots", "public", array(1, field())),
                    ("out_slots", "public", array(1, field())),
                    ("door", "private", field()),
                    ("door_randomness", "private", field()),
                    ("in0_fields", "private", array(9, field())),
                    ("in0_randomness", "private", field()),
                    ("in0_nonce", "private", field()),
                    ("out0_randomness", "private", field()),
                    ("nsk_app", "private", field()),
                ],
                // PssEffects<1, 1, 2>: the opened door and the door commitment.
                Some(effects(1, 1, 2)),
            )
        })
    }

    fn door_request(shared_names: &[&str]) -> NodeRequest {
        let ct = json!({"eph": {"x": "0x1", "y": "0x2"}, "ct": ["0x3", "0x4"], "tag": "0x5"});
        let inputs: Vec<Value> = shared_names
            .iter()
            .map(|n| json!({"name": n, "share": ct, "share_hashes": ["0x0", "0x0", "0x0"]}))
            .collect();
        node_request(&json!({
            "namespace": NAMESPACE, "circuit": "monty_hall_open_door", "request_id": DOOR_ID,
            "public": {"in0_nonce": NONCE},
            "state_keys": {"reads": ["0xb001"], "writes": ["0xb001"]},
            "shared_inputs": inputs,
            "records": [{"key": "0xb001", "note_hash": "0x77", "c_i": "0x00",
                "record_hashes": ["0x0", "0x0", "0x0"]}]
        }))
    }

    fn game_state() -> Vec<Elem> {
        (0..10).map(|i| shared(40 + 2 * i)).collect()
    }

    #[test]
    fn the_door_comes_through_the_shared_input_hook() {
        let manifest = example_manifest("monty-hall", "monty_hall_open_door");
        let (m, shape) = check_manifest_value(&manifest, &open_door_abi()).unwrap();
        assert_eq!(shape.public_input_count, 10);
        let mut fake = Fake::default()
            .with("0xb001", game_state())
            .with("nsk_app", nsk());
        fake.shared.insert("door".into(), share(2, 3));
        fake.shared.insert("door_randomness".into(), share(4, 5));
        let req = door_request(&["door", "door_randomness"]);
        let bound = bind(&shape, &m, &req, &mut fake).unwrap();
        assert_eq!(fake.hooks, vec!["door", "door_randomness"]);
        assert_eq!(bound.input["door"], Elem::Shared(share(2, 3)));
        assert_eq!(bound.input["door_randomness"], Elem::Shared(share(4, 5)));
        assert_eq!(bound.input["in0_fields[8]"], shared(56));
        assert_eq!(bound.input["in0_randomness"], shared(58));
        assert_eq!(bound.input.len(), 4 + 2 + 9 + 4);
        assert_eq!(bound.samples, 1);

        // A shared input the manifest names but the request lacks, or the other
        // way round, is refused before any source is called.
        for (names, needle) in [
            (vec!["door"], "missing `door_randomness`"),
            (vec!["door", "door_randomness", "seat"], "unexpected `seat`"),
        ] {
            let mut fake = Fake::default().with("0xb001", game_state());
            refused(
                bind(&shape, &m, &door_request(&names), &mut fake),
                ErrorClass::BadRequest,
                &["shared_inputs", needle],
            );
            assert_eq!(fake.calls(), 0);
        }

        // The hook's refusal passes through, and nothing is sampled.
        let mut fake = Fake::default()
            .with("0xb001", game_state())
            .with("nsk_app", nsk());
        fake.shared.insert("door".into(), share(2, 3));
        refused(
            bind(&shape, &m, &req, &mut fake),
            ErrorClass::BadRequest,
            &["door_randomness", "does not decrypt"],
        );
        assert_eq!(fake.next_sample, 0);
    }

    // A wider public parameter filled from one request name takes `name[i]`, and
    // a typed array is range-checked element by element.
    #[test]
    fn a_public_array_binds_name_i_and_checks_each_element() {
        let abi = crate::abi::tests::abi(
            &[
                ("namespace", "public", field()),
                ("flags", "public", array(3, boolean())),
            ],
            Some(effects(0, 0, 0)),
        );
        let manifest = json!({
            "manifest": 1, "circuit": "flags", "namespace_param": "namespace",
            "state_keys": {"reads": 0, "writes": 0},
            "witness": [
                {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
                {"param": "flags", "from": {"PUBLIC": "flags"}}
            ],
            "outputs": [], "state": {}
        });
        let (m, shape) = check_manifest_value(&manifest, &abi).unwrap();
        let body = |flags: Value| {
            node_request(&json!({"namespace": NAMESPACE, "circuit": "flags",
                "request_id": SWAP_ID, "public": {"flags": flags}}))
        };
        let bound = bind(
            &shape,
            &m,
            &body(json!(["0x1", "0x0", "0x1"])),
            &mut Fake::default(),
        )
        .unwrap();
        assert_eq!(bound.input["flags[2]"], public(1));
        refused(
            bind(
                &shape,
                &m,
                &body(json!(["0x1", "0x2", "0x1"])),
                &mut Fake::default(),
            ),
            ErrorClass::BadRequest,
            &["parameter `flags` element 1", "public.flags[1]", "1 bit"],
        );
    }
}
