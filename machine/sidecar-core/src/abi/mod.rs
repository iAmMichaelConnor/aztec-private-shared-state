//! The REGISTER-time checks of a manifest against the compiled circuit's ABI, and
//! the circuit shape they produce for the witness binder (docs/ARCHITECTURE.md
//! section 7).
//!
//! The ABI walk and flattening follow co-noir's input map: a parameter of one
//! field element is the bare witness key `name`, a wider one is `name[0]`,
//! `name[1]`, ... over its fields in declaration order, whatever its type (array,
//! struct, tuple, string). The public-input array is every public parameter
//! flattened in declaration order, then the public return value flattened.
//!
//! What cannot be checked here: an output's `len` is the length of the vector the
//! circuit hands to `TACEO_store` (its fields plus blinding), which the ABI does not
//! describe. STORE checks it against what the circuit actually stored.
//!
//! Each `commitment_slot` names a public Field output and each
//! `public_reads[].param` a public parameter. REGISTER and a round's
//! resolution read a manifest the same way ([`check_manifest_value`]).
//! [`check_tip_public_prefix`] checks a queued circuit's public parameters
//! against the contract library's one public-input layout of a tip round.

use std::collections::BTreeSet;

use ark_ff::{BigInteger, PrimeField};
use noirc_abi::{Abi, AbiType, AbiVisibility};

use crate::error::Refusal;
use crate::field::{FieldHex, Fr};
use crate::manifest::{
    Freshness, KeyRef, Manifest, Output, PublicOperand, PublicSource, ReservedOperand,
    SharedReserved, Source, TreeLayout, WitnessEntry,
};

mod tip_prefix;
mod tree;

pub(crate) use tip_prefix::check_queued_public_prefix;
pub use tip_prefix::check_tip_public_prefix;
use tree::check_tree;

// The largest ABI this machine accepts, as a total count of field elements
// over every parameter and the return value; default 2^20. An ABI comes from
// the REGISTER body, so its array lengths are client data; this bound keeps a
// hostile `[[Field; 65536]; 65536]` from exhausting memory or overflowing the
// count (noirc_abi's own `field_count` panics on overflow). 2^20 is far above
// any round circuit (the AMM's largest takes 12 inputs and returns 5); raising
// it admits circuits with very large public arrays, lowering it refuses them
// at REGISTER.
pub const MAX_ABI_FIELDS: u64 = 1 << 20;

// The largest walk REGISTER makes of an ABI: the bytes of every path the
// flattening formats, each node costing its path's length plus one, over
// every parameter and the return value; 2^26. It bounds the time and memory
// of the walk, which MAX_ABI_FIELDS alone does not (an array of empty tuples
// has no field elements). MAX_ABI_FIELDS elements under paths of about 60
// bytes fit; a round circuit's walk is a few kilobytes.
pub const MAX_ABI_WALK: u64 = 1 << 26;

/// The range a flattened element must lie in when PUBLIC fills it, from its ABI
/// leaf type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leaf {
    /// A `Field`: any element of the field, no check.
    Field,
    /// `bool` (1 bit), `u<N>` / `i<N>` (N bits) or one string byte (8 bits): the
    /// value's bit length must be at most this.
    Bits(u32),
}

impl Leaf {
    /// Whether `value` lies in this leaf's range.
    pub fn admits(self, value: Fr) -> bool {
        match self {
            Leaf::Field => true,
            Leaf::Bits(bits) => value.into_bigint().num_bits() <= bits,
        }
    }
}

/// A parameter's ABI visibility. Databus parameters are refused at REGISTER.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Private,
}

/// One ABI parameter as the binder fills it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamShape {
    pub name: String,
    pub visibility: Visibility,
    /// The number of field elements (`AbiType::field_count`).
    pub width: usize,
    /// The co-noir witness keys: `[name]` for width 1, else `name[0]` ...
    pub keys: Vec<String>,
    /// The leaf type of each flattened element, for the typed range checks.
    pub leaves: Vec<Leaf>,
    /// The manifest's source for this parameter.
    pub source: Source,
    /// The index of this parameter's first element in the public-input array, for a
    /// public parameter.
    pub public_index: Option<usize>,
}

/// One manifest output with the public-input index of its note hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputShape {
    /// The name the circuit passes to `TACEO_store`.
    pub taceo_store: String,
    /// The key the vector is stored under.
    pub store: KeyRef,
    /// The stored vector's length (fields plus blinding); not checkable against
    /// the ABI.
    pub len: usize,
    /// The return-value path that commits to the vector, e.g. `new_note_hashes[0]`.
    pub note_hash: String,
    /// Its index in the public-input array.
    pub note_hash_index: usize,
}

/// What REGISTER learns from checking a manifest against the ABI: the witness
/// layout the binder walks, the public-input layout, and where the namespace and
/// each note hash sit in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitShape {
    /// Every ABI parameter in declaration order, with its source.
    pub params: Vec<ParamShape>,
    /// The number of public-input elements the public parameters fill; the public
    /// return value starts at this index.
    pub public_param_fields: usize,
    /// The path of every public return element, in public-input order, starting
    /// at index `public_param_fields`. Empty when the return value is private or
    /// absent.
    pub return_paths: Vec<String>,
    /// The length of the public-input array: public parameters flattened plus the
    /// public return value flattened.
    pub public_input_count: usize,
    /// The public-input index of the namespace parameter.
    pub namespace_index: usize,
    /// The manifest outputs, in manifest order.
    pub outputs: Vec<OutputShape>,
}

impl CircuitShape {
    /// The parameter of this name.
    pub fn param(&self, name: &str) -> Option<&ParamShape> {
        self.params.iter().find(|p| p.name == name)
    }

    /// The public-input index of a public return element, by path.
    pub fn return_index(&self, path: &str) -> Option<usize> {
        self.return_paths
            .iter()
            .position(|p| p == path)
            .map(|i| self.public_param_fields + i)
    }
}

/// The co-noir witness keys of a parameter of `width` fields: the bare name for
/// one field, `name[i]` otherwise (co_noir::witness_map_from_string_map).
pub fn witness_keys(name: &str, width: usize) -> Vec<String> {
    if width == 1 {
        vec![name.to_string()]
    } else {
        (0..width).map(|i| format!("{name}[{i}]")).collect()
    }
}

// What flattening a type takes, measured from the type alone before
// `flatten` runs: its field elements, and its walk cost, the bytes of every
// path the walk formats with each node costing its path's length plus one (an
// upper bound: every index of an array is counted at the width of its last).
// The cost bounds the walk itself, which the field count does not: an array
// of empty tuples has no field elements whatever its length, and long struct
// field names repeated by an array make long paths.
#[derive(Clone, Copy, Default)]
struct Walk {
    fields: u64,
    cost: u64,
}

impl Walk {
    fn add(self, other: Walk) -> Option<Walk> {
        Some(Walk {
            fields: self.fields.checked_add(other.fields)?,
            cost: self.cost.checked_add(other.cost)?,
        })
    }
}

// Why a type cannot be walked: an array of zero-width elements, or a size
// past what u64 counts (which is past every bound).
enum WalkRefusal {
    ZeroWidthElements,
    TooLarge,
}

// The decimal digits of the largest index below `length`.
fn index_digits(length: u64) -> u64 {
    u64::from(length.saturating_sub(1).max(1).ilog10()) + 1
}

// The walk of `typ` under a path of `prefix` bytes.
fn walk(typ: &AbiType, prefix: u64) -> Result<Walk, WalkRefusal> {
    let too_large = || WalkRefusal::TooLarge;
    let node = prefix.checked_add(1).ok_or_else(too_large)?;
    // a struct field or tuple element joins `.part`, bare at the root
    let joined = |part: u64| {
        if prefix == 0 {
            Some(part)
        } else {
            prefix.checked_add(1)?.checked_add(part)
        }
    };
    let repeated = |length: u64, each: Walk| -> Option<Walk> {
        Some(Walk {
            fields: each.fields.checked_mul(length)?,
            cost: each.cost.checked_mul(length)?.checked_add(node)?,
        })
    };
    let fold = |parts: &mut dyn Iterator<Item = (u64, &AbiType)>| {
        let mut sum = Walk {
            fields: 0,
            cost: node,
        };
        for (part, t) in parts {
            let at = joined(part).ok_or_else(too_large)?;
            sum = sum.add(walk(t, at)?).ok_or_else(too_large)?;
        }
        Ok(sum)
    };
    match typ {
        AbiType::Field | AbiType::Integer { .. } | AbiType::Boolean => Ok(Walk {
            fields: 1,
            cost: node,
        }),
        AbiType::String { length } => {
            let length = u64::from(*length);
            let byte = prefix
                .checked_add(3 + index_digits(length))
                .ok_or_else(too_large)?;
            repeated(
                length,
                Walk {
                    fields: 1,
                    cost: byte,
                },
            )
            .ok_or_else(too_large)
        }
        AbiType::Array { length, typ } => {
            let length = u64::from(*length);
            let at = prefix
                .checked_add(2 + index_digits(length))
                .ok_or_else(too_large)?;
            let each = walk(typ, at)?;
            if length > 0 && each.fields == 0 {
                return Err(WalkRefusal::ZeroWidthElements);
            }
            repeated(length, each).ok_or_else(too_large)
        }
        AbiType::Struct { fields, .. } => {
            fold(&mut fields.iter().map(|(name, t)| (name.len() as u64, t)))
        }
        AbiType::Tuple { fields } => fold(
            &mut fields
                .iter()
                .enumerate()
                .map(|(i, t)| (index_digits(i as u64 + 1), t)),
        ),
    }
}

// Flatten a type into (path, leaf) pairs. Paths: a struct field is `.field` (bare
// at the root), an array element `[i]`, a tuple element `.i`, a string byte `[i]`.
fn flatten(typ: &AbiType, path: &str, out: &mut Vec<(String, Leaf)>) {
    let join = |part: &str| {
        if path.is_empty() {
            part.to_string()
        } else {
            format!("{path}.{part}")
        }
    };
    match typ {
        AbiType::Field => out.push((path.to_string(), Leaf::Field)),
        AbiType::Boolean => out.push((path.to_string(), Leaf::Bits(1))),
        AbiType::Integer { width, .. } => out.push((path.to_string(), Leaf::Bits(*width))),
        AbiType::String { length } => {
            for i in 0..*length {
                out.push((format!("{path}[{i}]"), Leaf::Bits(8)));
            }
        }
        AbiType::Array { length, typ } => {
            for i in 0..*length {
                flatten(typ, &format!("{path}[{i}]"), out);
            }
        }
        AbiType::Struct { fields, .. } => {
            for (name, t) in fields {
                flatten(t, &join(name), out);
            }
        }
        AbiType::Tuple { fields } => {
            for (i, t) in fields.iter().enumerate() {
                flatten(t, &join(&i.to_string()), out);
            }
        }
    }
}

// The root path of a return value: a struct's fields are named bare
// (`new_note_hashes[0]`, `npk_app_hash`); any other type is rooted at `return`
// (`return`, `return[1]`, `return.0`).
fn return_root(typ: &AbiType) -> &'static str {
    match typ {
        AbiType::Struct { .. } => "",
        _ => "return",
    }
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('a'..='z' | 'A'..='Z' | '_'))
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn param_refusal(k: usize, name: &str, why: impl std::fmt::Display) -> Refusal {
    Refusal::bad_request(format!("field `witness[{k}]`, parameter `{name}`: {why}"))
}

fn leaf_name(leaf: Leaf) -> String {
    match leaf {
        Leaf::Field => "Field".into(),
        Leaf::Bits(n) => format!("{n}-bit"),
    }
}

/// Parse a manifest JSON value and check it against `abi`, as REGISTER, the
/// registry copies and a round's resolution read it: [`Manifest::parse`]
/// (which refuses what the schema does not define, such as a LOAD `create`),
/// then [`check_manifest`].
pub fn check_manifest_value(
    manifest: &serde_json::Value,
    abi: &Abi,
) -> Result<(Manifest, CircuitShape), Refusal> {
    let manifest = Manifest::parse(manifest)?;
    let shape = check_manifest(&manifest, abi)?;
    Ok((manifest, shape))
}

/// The circuit's return value flattened, and whether it is public: what an
/// output name is looked up in.
struct Returns {
    flat: Vec<(String, Leaf)>,
    public: bool,
}

impl Returns {
    /// The position in the flattened return value of `path`, which must name
    /// one public `Field` (400 naming `at` otherwise).
    fn public_field(&self, at: &str, path: &str) -> Result<usize, Refusal> {
        let found = self.flat.iter().position(|(p, _)| p == path);
        let Some(i) = found else {
            let prefix_of_leaf = self.flat.iter().any(|(p, _)| {
                p.strip_prefix(path)
                    .is_some_and(|rest| rest.starts_with('[') || rest.starts_with('.'))
            });
            let why = if prefix_of_leaf {
                format!("`{path}` is not one field element; name one, such as `{path}[0]`")
            } else {
                format!("`{path}` is not an output of the circuit")
            };
            return Err(Refusal::bad_request(format!("field `{at}`: {why}")));
        };
        if !self.public {
            return Err(Refusal::bad_request(format!(
                "field `{at}`: `{path}` is a private output; a commitment must be a public input"
            )));
        }
        if self.flat[i].1 != Leaf::Field {
            return Err(Refusal::bad_request(format!(
                "field `{at}`: `{path}` is a {} value, not a Field",
                leaf_name(self.flat[i].1)
            )));
        }
        Ok(i)
    }
}

/// The REGISTER checks of a manifest against the compiled circuit's ABI:
///
/// - every ABI parameter appears exactly once in `witness`, in declaration order;
/// - each source fills the parameter's flattened width: SAMPLE n draws n, a LOAD
///   slice has the width's length, INPUT_SHARED fills one field, a PUBLIC list has
///   one operand per field, and a single PUBLIC operand fills one field unless it
///   is a request public name (which the request then gives as a list);
/// - only PUBLIC fills a public parameter; databus visibility is refused;
/// - a PUBLIC constant lies in its leaf's typed range;
/// - `namespace_param` is a public `Field` filled by PUBLIC `$namespace`;
/// - every `outputs[].note_hash` names one public `Field` of the return value,
///   and no two outputs name the same one;
/// - every `commitment_slot.<key>.old` names one public `Field` of the return
///   value, as a note hash does;
/// - every `public_reads[].param` and `epoch_param` names a public parameter,
///   one Field under freshness epoch or tolerance;
/// - a tree's index and count inputs fill one field each; its `params`
///   are private with the widths of the layout (`old_hashes` and `indices`
///   `probe`, `siblings` `probe * depth`), and its `new_hashes` names
///   `probe` consecutive public Fields of the return value.
///
/// Every refusal is `bad_request` and names the parameter or field. The manifest
/// is expected to have passed [`Manifest::validate`] already (the parsers run it).
pub fn check_manifest(manifest: &Manifest, abi: &Abi) -> Result<CircuitShape, Refusal> {
    let (shape, returns) = check_round(
        &manifest.namespace_param,
        &manifest.witness,
        &manifest.outputs,
        abi,
    )?;
    for (key, slot) in manifest.commitment_slots() {
        returns.public_field(&format!("commitment_slot.{key}.old"), &slot.old)?;
    }
    for (k, read) in manifest.public_reads.iter().enumerate() {
        let fields = std::iter::once(("param", &read.param))
            .chain(read.epoch_param.as_ref().map(|p| ("epoch_param", p)));
        for (field, name) in fields {
            let at = format!("public_reads[{k}].{field}");
            let param = shape.param(name).ok_or_else(|| {
                Refusal::bad_request(format!(
                    "field `{at}`: `{name}` is not a parameter of the circuit"
                ))
            })?;
            if param.visibility != Visibility::Public {
                return Err(Refusal::bad_request(format!(
                    "field `{at}`: `{name}` is a private parameter; a public read fills a public input"
                )));
            }
            // an epoch or tolerance read compares one value (and one epoch)
            if read.freshness != Freshness::Exact && param.width != 1 {
                return Err(Refusal::bad_request(format!(
                    "field `{at}`: `{name}` has {} elements; a read under freshness {} fills one Field",
                    param.width,
                    read.freshness.as_str()
                )));
            }
        }
    }
    for (key, tree) in manifest.trees() {
        check_tree(&format!("tree.{key}"), tree, &shape, &returns)?;
    }
    Ok(shape)
}

// `total` plus the walk of `typ` under a path of `prefix` bytes, within
// MAX_ABI_FIELDS and MAX_ABI_WALK.
fn bounded_walk(total: Walk, typ: &AbiType, prefix: u64) -> Result<Walk, WalkRefusal> {
    let sum = total.add(walk(typ, prefix)?).ok_or(WalkRefusal::TooLarge)?;
    if sum.fields > MAX_ABI_FIELDS || sum.cost > MAX_ABI_WALK {
        return Err(WalkRefusal::TooLarge);
    }
    Ok(sum)
}

fn abi_refusal(what: &str, why: WalkRefusal) -> Refusal {
    Refusal::bad_request(match why {
        WalkRefusal::ZeroWidthElements => {
            format!("field `circuit.abi`: {what} has an array of elements with no field elements")
        }
        WalkRefusal::TooLarge => format!(
            "field `circuit.abi`: {what} takes the ABI past {MAX_ABI_FIELDS} field elements \
             or a walk of {MAX_ABI_WALK} path bytes"
        ),
    })
}

// The checks of `check_manifest` over the witness and the outputs, with the
// flattened return value for the other output names.
fn check_round(
    namespace_param: &str,
    witness: &[WitnessEntry],
    outputs: &[Output],
    abi: &Abi,
) -> Result<(CircuitShape, Returns), Refusal> {
    // The ABI itself: plain identifiers, each once, and a bounded size.
    let mut abi_names = BTreeSet::new();
    let mut total = Walk::default();
    for p in &abi.parameters {
        if !is_identifier(&p.name) {
            return Err(Refusal::bad_request(format!(
                "field `circuit.abi`: parameter name `{}` is not an identifier",
                p.name
            )));
        }
        if !abi_names.insert(p.name.as_str()) {
            return Err(Refusal::bad_request(format!(
                "field `circuit.abi`: parameter `{}` is declared twice",
                p.name
            )));
        }
        total = bounded_walk(total, &p.typ, p.name.len() as u64)
            .map_err(|why| abi_refusal(&format!("parameter `{}`", p.name), why))?;
    }
    if let Some(ret) = &abi.return_type {
        let root = return_root(&ret.abi_type).len() as u64;
        bounded_walk(total, &ret.abi_type, root)
            .map_err(|why| abi_refusal("the return value", why))?;
    }

    // Every parameter once, in declaration order. Report the first position where
    // the two lists differ, as a missing, an extra or a misplaced parameter.
    let witness_names: BTreeSet<&str> = witness.iter().map(|w| w.param.as_str()).collect();
    let n = abi.parameters.len().max(witness.len());
    for k in 0..n {
        let declared = abi.parameters.get(k).map(|p| p.name.as_str());
        let listed = witness.get(k).map(|w| w.param.as_str());
        if declared == listed {
            continue;
        }
        if let Some(d) = declared
            && !witness_names.contains(d)
        {
            return Err(Refusal::bad_request(format!(
                "field `witness`: parameter `{d}` (ABI parameter {k}) has no witness entry"
            )));
        }
        if let Some(l) = listed
            && !abi_names.contains(l)
        {
            return Err(param_refusal(k, l, "not a parameter of the circuit"));
        }
        let (d, l) = (declared.unwrap_or("?"), listed.unwrap_or("?"));
        return Err(param_refusal(
            k,
            l,
            format!("out of order: the ABI declares `{d}` at position {k}"),
        ));
    }

    // Each parameter against its source.
    let mut params = Vec::with_capacity(abi.parameters.len());
    let mut public_fields = 0usize;
    for (k, (p, entry)) in abi.parameters.iter().zip(witness).enumerate() {
        let name = p.name.as_str();
        let visibility = match p.visibility {
            AbiVisibility::Public => Visibility::Public,
            AbiVisibility::Private => Visibility::Private,
            AbiVisibility::DataBus => {
                return Err(param_refusal(
                    k,
                    name,
                    "databus visibility is not supported",
                ));
            }
        };
        let mut flat = Vec::new();
        flatten(&p.typ, name, &mut flat);
        let leaves: Vec<Leaf> = flat.into_iter().map(|(_, leaf)| leaf).collect();
        let width = leaves.len();
        if width == 0 {
            return Err(param_refusal(k, name, "takes no field elements"));
        }

        // Only PUBLIC fills a public parameter. Anything stored,
        // sampled or shared reaches the public inputs only through the circuit's
        // return value, which the circuit author chooses and constrains, so a
        // manifest cannot reveal a stored vector or a secret input by aiming it at
        // a `pub` parameter. Relaxing this would make the manifest, not the
        // circuit, a reveal channel. The converse is allowed: PUBLIC may fill a
        // private parameter (`in0_nonce`).
        if visibility == Visibility::Public && !matches!(entry.from, Source::Public(_)) {
            return Err(param_refusal(
                k,
                name,
                format!(
                    "a public parameter filled by {}; only PUBLIC fills a public parameter",
                    entry.from.opcode()
                ),
            ));
        }
        match &entry.from {
            Source::Public(PublicSource::One(op)) => {
                if width != 1 && !matches!(op, PublicOperand::Name(_)) {
                    return Err(param_refusal(
                        k,
                        name,
                        format!(
                            "one PUBLIC operand fills one field, the parameter has {width}; give a list"
                        ),
                    ));
                }
                if let PublicOperand::Const(c) = op {
                    check_const(k, name, 0, *c, leaves[0])?;
                }
                // A reserved operand's value is a full field element (a vk
                // hash, an address, a nonce, a commitment), so it fills a
                // Field.
                if let PublicOperand::Reserved(r) = op
                    && leaves[0] != Leaf::Field
                {
                    return Err(param_refusal(
                        k,
                        name,
                        format!(
                            "`{r}` is a full field element and fills a Field parameter, not a {} one",
                            leaf_name(leaves[0])
                        ),
                    ));
                }
                // The inputs commitment is a private witness: a proof that
                // made it public would publish a hash of the shared inputs.
                if let PublicOperand::Reserved(ReservedOperand::InputsHash) = op
                    && visibility == Visibility::Public
                {
                    return Err(param_refusal(
                        k,
                        name,
                        "`$inputs_hash` fills a private parameter; the inputs commitment is no public input of the proof".to_string(),
                    ));
                }
            }
            Source::Public(PublicSource::List(ops)) => {
                if ops.len() != width {
                    return Err(param_refusal(
                        k,
                        name,
                        format!(
                            "PUBLIC lists {} operand(s), the parameter has {width} field(s)",
                            ops.len()
                        ),
                    ));
                }
                for (i, op) in ops.iter().enumerate() {
                    if let PublicOperand::Const(c) = op {
                        check_const(k, name, i, *c, leaves[i])?;
                    }
                }
            }
            Source::Sample(n) => {
                if *n != width {
                    return Err(param_refusal(
                        k,
                        name,
                        format!("SAMPLE {n} draws {n}, the parameter has {width} field(s)"),
                    ));
                }
            }
            Source::Load(load) => {
                let [a, b] = load.slice;
                if b - a != width {
                    return Err(param_refusal(
                        k,
                        name,
                        format!(
                            "LOAD slice [{a}, {b}] has {} element(s), the parameter has {width} field(s)",
                            b - a
                        ),
                    ));
                }
            }
            Source::InputShared(input) => {
                // One INPUT_SHARED ciphertext carries one replicated pair, so it
                // fills exactly one field element. A wider secret input is several
                // named inputs, one per parameter.
                if width != 1 {
                    return Err(param_refusal(
                        k,
                        name,
                        format!(
                            "INPUT_SHARED `{input}` fills one field, the parameter has {width}"
                        ),
                    ));
                }
                // The reserved shared values are full field elements drawn
                // uniformly (a blinding, a key, a tag).
                if let Some(r) = SharedReserved::from_name(input)
                    && leaves[0] != Leaf::Field
                {
                    return Err(param_refusal(
                        k,
                        name,
                        format!(
                            "`{r}` is a full field element and fills a Field parameter, not a {} one",
                            leaf_name(leaves[0])
                        ),
                    ));
                }
            }
        }

        let public_index = (visibility == Visibility::Public).then_some(public_fields);
        if visibility == Visibility::Public {
            public_fields += width;
        }
        params.push(ParamShape {
            name: name.to_string(),
            visibility,
            width,
            keys: witness_keys(name, width),
            leaves,
            source: entry.from.clone(),
            public_index,
        });
    }

    // The namespace parameter: a public Field filled by PUBLIC $namespace.
    let ns = namespace_param;
    let (ns_param, ns_abi) = params
        .iter()
        .zip(&abi.parameters)
        .find(|(p, _)| p.name == ns)
        .ok_or_else(|| {
            Refusal::bad_request(format!(
                "field `namespace_param`: `{ns}` is not a parameter of the circuit"
            ))
        })?;
    if ns_abi.typ != AbiType::Field {
        return Err(Refusal::bad_request(format!(
            "field `namespace_param`: parameter `{ns}` is not a Field"
        )));
    }
    let Some(namespace_index) = ns_param.public_index else {
        return Err(Refusal::bad_request(format!(
            "field `namespace_param`: parameter `{ns}` is private; the namespace must be a public input"
        )));
    };
    if !matches!(
        ns_param.source,
        Source::Public(PublicSource::One(PublicOperand::Namespace))
    ) {
        return Err(Refusal::bad_request(format!(
            "field `namespace_param`: parameter `{ns}` must be filled by PUBLIC \"$namespace\""
        )));
    }

    // The return value: public elements follow the public parameters.
    let mut return_flat = Vec::new();
    let mut return_public = false;
    if let Some(ret) = &abi.return_type {
        flatten(&ret.abi_type, return_root(&ret.abi_type), &mut return_flat);
        return_public = match ret.visibility {
            AbiVisibility::Public => true,
            AbiVisibility::Private => false,
            AbiVisibility::DataBus => {
                return Err(Refusal::bad_request(
                    "field `circuit.abi`: the return value uses databus visibility, which is not supported",
                ));
            }
        };
    }
    let return_paths: Vec<String> = if return_public {
        return_flat.iter().map(|(p, _)| p.clone()).collect()
    } else {
        Vec::new()
    };
    let public_input_count = public_fields + return_paths.len();

    // Each output's note hash: one public Field of the return value.
    let returns = Returns {
        flat: return_flat,
        public: return_public,
    };
    let mut shapes = Vec::with_capacity(outputs.len());
    let mut named = BTreeSet::new();
    for (k, out) in outputs.iter().enumerate() {
        let at = format!("outputs[{k}].note_hash");
        let path = out.note_hash.as_str();
        let i = returns.public_field(&at, path)?;
        if !named.insert(path) {
            return Err(Refusal::bad_request(format!(
                "field `{at}`: `{path}` is named by two outputs"
            )));
        }
        shapes.push(OutputShape {
            taceo_store: out.taceo_store.clone(),
            store: out.store,
            len: out.len,
            note_hash: out.note_hash.clone(),
            note_hash_index: public_fields + i,
        });
    }

    let shape = CircuitShape {
        params,
        public_param_fields: public_fields,
        return_paths,
        public_input_count,
        namespace_index,
        outputs: shapes,
    };
    Ok((shape, returns))
}

fn check_const(k: usize, name: &str, i: usize, value: FieldHex, leaf: Leaf) -> Result<(), Refusal> {
    if leaf.admits(value.0) {
        return Ok(());
    }
    Err(param_refusal(
        k,
        name,
        format!(
            "constant {value} (element {i}) does not fit its {} type",
            leaf_name(leaf)
        ),
    ))
}

#[cfg(test)]
pub(crate) mod tests;
