//! What the secret-shared receipt intake suites share on top of the tip
//! harness (`common::tip`; `shared_receipt.rs`, `amm_tip_shared.rs`,
//! `lending_tip_shared.rs` and others taking the client's side): the
//! mock contract's secret-shared intakes; the client's side of
//! secret-shared receipt intake (the values, `C`, the chain request id,
//! every shared value sealed to each node under the intake associated data,
//! the summand vectors with their salts, commitments and digest, and the
//! request function's check that the sharing opens `C`);
//! the user's side of a private outcome (the ciphertext opened under
//! `$outcome_key` for the attempt, the completed note's hash recomputed from
//! the request's partial note); and the audit that no app input and no
//! requester address appears where the nodes or the chain see it.

#![allow(dead_code)]

use rand::RngCore;
use rand::rngs::OsRng;
use serde::Serialize;
use serde_json::{Value, json};

use sidecar_core::ae;
use sidecar_core::derived::Kind;
use sidecar_core::envelope::{EnvelopeAd, seal_envelope};
use sidecar_core::field::{FieldHex, Fr, fr_from_hex, fr_to_hex};
use sidecar_core::grumpkin::Point;
use sidecar_core::hash::poseidon2_hash;
use sidecar_core::keys::label_field;
use sidecar_core::request::SharedInput;
use sidecar_core::response::ExecuteResponse;
use sidecar_core::schnorr;
use sidecar_core::store::Store;
use sidecar_tip::audit::Requesters;
use sidecar_tip::chain::layout::request_log_tag;
use sidecar_tip::{
    ReceiptResponse, StoredReceipt, TipPackage, inputs_commitment, machine_request_id,
    shared_chain_request_id, shared_receipt_message, sharing_digest, summand_commitment,
};

use crate::common::tip::*;
use crate::common::*;

pub fn random() -> Fr {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    Fr::from(u128::from_be_bytes(bytes))
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// The smallest shared value the audit looks for; the suites' amounts are
/// chosen above it and above every block number and expiry they reach.
pub const AUDIT_FLOOR: u64 = 1024;

/// One app input of a secret-shared-intake round, in the circuit's ABI order:
/// clear to the nodes (a PUBLIC request name) or INPUT_SHARED.
#[derive(Clone, Debug)]
pub struct Input {
    pub name: &'static str,
    pub value: Fr,
    pub shared: bool,
}

pub fn clear(name: &'static str, value: Fr) -> Input {
    Input {
        name,
        value,
        shared: false,
    }
}

pub fn shared(name: &'static str, value: Fr) -> Input {
    Input {
        name,
        value,
        shared: true,
    }
}

/// One secret-shared receipt intake request as the client builds it: the app
/// inputs (with the reserved `$partial_note`, the last of them), the
/// reserved values, C, the chain request id, the sealed shared inputs in
/// the circuit's ABI order and the sharing they seal (`sharing`); `owner`,
/// when the test knows it, the address whose partial note the request
/// commits (never sent: the request carries only the partial note).
#[derive(Clone)]
pub struct SharedRequest {
    pub namespace: Fr,
    pub circuit: String,
    pub inputs: Vec<Input>,
    pub owner: Option<Fr>,
    pub outcome_key: Fr,
    pub outcome_tag: Fr,
    pub blinding: Fr,
    pub c: Fr,
    pub chain: Fr,
    pub sealed: Vec<SharedInput>,
    pub sharing: Sharing,
}

/// A secret-shared receipt request's sharing (pss_public_contract
/// `Sharing`): the values in summand order (C's shared values in C's
/// order, then `$blinding`), the three summand vectors over them, the
/// salts, the salts' envelopes (`$summand_salt`), the summand commitments
/// and the digest. Empty under secret-shared on-chain intake, whose
/// encoding is the sharing.
#[derive(Clone, Default)]
pub struct Sharing {
    pub values: Vec<Fr>,
    pub summands: [Vec<Fr>; 3],
    pub salts: [Fr; 3],
    pub salt_input: Option<SharedInput>,
    pub commitments: [Fr; 3],
    pub digest: Fr,
}

impl Sharing {
    /// Whether the summands add up to the values, the user's request
    /// function's check (`opened_sharing`): a sharing that does not open C
    /// is never queued.
    pub fn opens(&self) -> bool {
        self.values
            .iter()
            .enumerate()
            .all(|(k, v)| self.summands[0][k] + self.summands[1][k] + self.summands[2][k] == *v)
    }
}

impl SharedRequest {
    /// An honest request: every sharing reconstructs to its value.
    pub fn new(
        namespace: Fr,
        circuit: &str,
        vk_hash: Fr,
        enc_pks: &[Point; 3],
        inputs: Vec<Input>,
    ) -> Self {
        Self::skewed(namespace, circuit, vk_hash, enc_pks, inputs, None)
    }

    /// A request whose sharing of the shared input `skew.0` reconstructs to
    /// its value plus `skew.1`, so the shares do not open to C. No node can
    /// tell: C, every envelope and the summand commitments are well formed;
    /// the user's request function refuses it (`Sharing::opens`), so only
    /// nodes that change their shares can put it in a round
    /// ([`SharedRequest::reshared`], [`Net::change_shares`]).
    pub fn skewed(
        namespace: Fr,
        circuit: &str,
        vk_hash: Fr,
        enc_pks: &[Point; 3],
        inputs: Vec<Input>,
        skew: Option<(&str, u64)>,
    ) -> Self {
        Self::build(namespace, circuit, vk_hash, enc_pks, inputs, skew, None)
    }

    /// A request whose pair of the shared input `name` sealed to node
    /// `node` disagrees with node `node - 1`'s on the summand they share
    /// (its `b` is not node `node - 1`'s `a`). Every envelope opens and
    /// hashes correctly and C is well formed; node `node`'s `b` summands
    /// miss the summand commitment `S_(node-1)`, so that node refuses.
    pub fn inconsistent(
        namespace: Fr,
        circuit: &str,
        vk_hash: Fr,
        enc_pks: &[Point; 3],
        inputs: Vec<Input>,
        node: usize,
        name: &str,
    ) -> Self {
        let bent = Some((name, node));
        Self::build(namespace, circuit, vk_hash, enc_pks, inputs, None, bent)
    }

    fn build(
        namespace: Fr,
        circuit: &str,
        vk_hash: Fr,
        enc_pks: &[Point; 3],
        inputs: Vec<Input>,
        skew: Option<(&str, u64)>,
        bent: Option<(&str, usize)>,
    ) -> Self {
        let (outcome_key, outcome_tag, blinding) = (random(), random(), random());
        // C over the app inputs in ABI order ($partial_note last), then
        // $outcome_key and $outcome_tag, under $blinding
        let mut values: Vec<Fr> = inputs.iter().map(|i| i.value).collect();
        values.extend([outcome_key, outcome_tag]);
        let c = inputs_commitment(&values, blinding);
        let chain = shared_chain_request_id(namespace, vk_hash, c);
        let mut req = SharedRequest {
            namespace,
            circuit: circuit.to_string(),
            inputs,
            owner: None,
            outcome_key,
            outcome_tag,
            blinding,
            c,
            chain,
            sealed: vec![],
            sharing: Sharing::default(),
        };
        req.seal(enc_pks, skew, bent);
        req
    }

    /// The shared values in summand order: C's shared values in C's order
    /// (the shared app inputs, then `$outcome_key` and `$outcome_tag`), then
    /// `$blinding` (sidecar-tip `summand_names`).
    fn summand_values(&self) -> Vec<(&'static str, Fr)> {
        let mut named: Vec<(&'static str, Fr)> = self
            .inputs
            .iter()
            .filter(|i| i.shared)
            .map(|i| (i.name, i.value))
            .collect();
        named.extend([
            ("$outcome_key", self.outcome_key),
            ("$outcome_tag", self.outcome_tag),
            ("$blinding", self.blinding),
        ]);
        named
    }

    // Draw a fresh sharing of the values (the one of `skew.0` reconstructing
    // to its value plus `skew.1`) and fresh salts, and seal both to the
    // nodes (node `bent.1`'s pair of `bent.0` off by one in its `b`).
    fn seal(
        &mut self,
        enc_pks: &[Point; 3],
        skew: Option<(&str, u64)>,
        bent: Option<(&str, usize)>,
    ) {
        let named = self.summand_values();
        let mut summands: [Vec<Fr>; 3] = Default::default();
        let mut sealed = Vec::with_capacity(named.len());
        for (name, value) in &named {
            let value = match skew {
                Some((n, by)) if n == *name => *value + Fr::from(by),
                _ => *value,
            };
            let (x0, x1) = (random(), random());
            let sharing = [x0, x1, value - x0 - x1];
            for j in 0..3 {
                summands[j].push(sharing[j]);
            }
            let bent = bent.filter(|(n, _)| n == name).map(|(_, node)| node);
            sealed.push(self.seal_one(enc_pks, name, sharing, bent));
        }
        let salts = [random(), random(), random()];
        let salt_input = self.seal_one(enc_pks, sidecar_tip::SUMMAND_SALT, salts, None);
        let commitments: [Fr; 3] =
            std::array::from_fn(|j| summand_commitment(&summands[j], salts[j]));
        // D covers the kind of each of C's values (the app inputs, then the
        // outcome key and tag) and the clear inputs
        let kinds: Vec<Kind> = self
            .inputs
            .iter()
            .map(|i| if i.shared { Kind::Chosen } else { Kind::Clear })
            .chain([Kind::Chosen, Kind::Chosen])
            .collect();
        let clear: Vec<Fr> = self
            .inputs
            .iter()
            .filter(|i| !i.shared)
            .map(|i| i.value)
            .collect();
        self.sealed = sealed;
        self.sharing = Sharing {
            values: named.iter().map(|(_, v)| *v).collect(),
            summands,
            salts,
            salt_input: Some(salt_input),
            commitments,
            digest: sharing_digest(&commitments, &kinds, &clear),
        };
    }

    fn seal_one(
        &self,
        enc_pks: &[Point; 3],
        name: &str,
        sharing: [Fr; 3],
        bent: Option<usize>,
    ) -> SharedInput {
        seal_all(
            enc_pks,
            self.namespace,
            self.chain,
            &self.circuit,
            name,
            sharing,
            bent,
        )
    }

    /// The same request (the same values, C and chain request id) sealed
    /// again under a fresh sharing whose share of `skew.0` reconstructs to
    /// its value plus `skew.1`, in `package`'s ABI order: the envelopes nodes
    /// that change their shares after an honest intake hold
    /// ([`Net::change_shares`]).
    pub fn reshared(&self, enc_pks: &[Point; 3], skew: (&str, u64), package: &TipPackage) -> Self {
        let mut out = self.clone();
        out.seal(enc_pks, Some(skew), None);
        out.in_abi_order(package)
    }

    /// The same request with its sealed inputs in `package`'s ABI order,
    /// the order the scheduler synthesises them in from the nodes' rows
    /// (for a circuit that takes the reserved values in another order than
    /// [`SharedRequest::skewed`] seals them).
    pub fn in_abi_order(mut self, package: &TipPackage) -> Self {
        let names = sidecar_tip::shared_names(&package.shape, &package.tip);
        self.sealed.sort_by_key(|s| {
            names
                .iter()
                .position(|n| *n == s.name)
                .unwrap_or_else(|| panic!("`{}` is not a shared input of {}", s.name, package.name))
        });
        self
    }

    /// The request committing `owner`'s partial note (its `$partial_note`
    /// input): the audit looks for `owner` as a requester address.
    pub fn owned_by(mut self, owner: Fr) -> Self {
        self.owner = Some(owner);
        self
    }

    pub fn value(&self, name: &str) -> Fr {
        self.inputs
            .iter()
            .find(|i| i.name == name)
            .unwrap_or_else(|| panic!("no input `{name}`"))
            .value
    }

    /// The receipt route's body at `block`: the clear inputs by name, the
    /// sealed shared inputs and the salts' envelopes, C, the summand
    /// commitments and the digest.
    pub fn body(&self, block: u64) -> Value {
        let clear: serde_json::Map<String, Value> = self
            .inputs
            .iter()
            .filter(|i| !i.shared)
            .map(|i| (i.name.to_string(), json!(FieldHex(i.value))))
            .collect();
        json!({
            "namespace": FieldHex(self.namespace),
            "circuit": self.circuit,
            "inputs": clear,
            "shared_inputs": self.sealed.iter().chain(&self.sharing.salt_input).collect::<Vec<_>>(),
            "inputs_hash": FieldHex(self.c),
            "summand_commitments": self.sharing.commitments.map(FieldHex),
            "sharing_digest": FieldHex(self.sharing.digest),
            "current_block": block,
        })
    }

    /// The shared inputs with node `node`'s envelope of `name` replaced by a
    /// well-formed envelope of another pair, under the same associated data,
    /// with its share hash: what a node substituting its envelope sends.
    pub fn substituted(&self, enc_pks: &[Point; 3], node: usize, name: &str) -> Vec<SharedInput> {
        let mut out = self.sealed.clone();
        let input = out
            .iter_mut()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("no shared input `{name}`"));
        let ad = EnvelopeAd::for_intake(self.namespace, self.chain, &self.circuit, name);
        let share = seal_envelope(enc_pks[node], node, &ad, [random(), random()], &mut OsRng);
        input.shares[node] = share;
        input.share_hashes[node] = FieldHex(share.hash());
        out
    }

    /// The app values the nodes must never see in the clear: every shared
    /// app input, the partial note among them, at or above [`AUDIT_FLOOR`] (a
    /// smaller value, such as a swap's direction, equals the counters,
    /// indices and flags every request carries, so its absence proves
    /// nothing).
    pub fn hidden(&self) -> Vec<(String, Fr)> {
        self.inputs
            .iter()
            .filter(|i| i.shared && i.value >= Fr::from(AUDIT_FLOOR))
            .map(|i| (i.name.to_string(), i.value))
            .collect()
    }

    /// The private outcome of `out`, opened as the user opens it: the
    /// ciphertext under `$outcome_key` with its note hash's nonce, the note
    /// hash the completion of the request's `$partial_note` at
    /// `outcome_slot` with the plaintext and the chain request id
    /// (`completed_note_hash`, the note the user rebuilds with its `rho`),
    /// the request id the round computed over C, and the machine request id
    /// over it, the old commitment and `pinned`.
    pub fn open(&self, out: &PrivateOutputs, outcome_slot: Fr, pinned: &[Fr]) -> Vec<Fr> {
        assert_eq!(
            out.request_id, self.chain,
            "the round's request id is not C's"
        );
        assert_eq!(out.outcome_tag, self.outcome_tag);
        assert_eq!(
            out.machine_request_id,
            machine_request_id(self.chain, &[out.old_c], pinned),
            "the machine request id is not this attempt's"
        );
        let plaintext = open_outcome(self.outcome_key, out.note_hash, &out.ciphertext)
            .expect("the outcome ciphertext opens under the outcome key");
        assert_eq!(
            out.note_hash,
            completed_note_hash(
                outcome_slot,
                self.value("$partial_note"),
                &plaintext,
                out.request_id
            ),
            "the note hash is not the completion of the request's partial note"
        );
        plaintext
    }
}

/// The Rep3 sharing `sharing`, node i's pair `[x_i, x_{i-1}]` sealed to
/// its `enc` key under the intake associated data; with `bent`, that node's
/// `b` summand is off by one, so its pair disagrees with its previous
/// neighbour's.
fn seal_all(
    enc_pks: &[Point; 3],
    namespace: Fr,
    chain: Fr,
    circuit: &str,
    name: &str,
    sharing: [Fr; 3],
    bent: Option<usize>,
) -> SharedInput {
    let ad = EnvelopeAd::for_intake(namespace, chain, circuit, name);
    let shares = [0, 1, 2].map(|i| {
        let mut pair = [sharing[i], sharing[(i + 2) % 3]];
        if bent == Some(i) {
            pair[1] += Fr::from(1u64);
        }
        seal_envelope(enc_pks[i], i, &ad, pair, &mut OsRng)
    });
    SharedInput {
        name: name.to_string(),
        shares,
        share_hashes: shares.map(|s| FieldHex(s.hash())),
    }
}

// ---------------------------------------------------------------------------
// The user's side of a private outcome (pss_core tip/outcome.nr)
// ---------------------------------------------------------------------------

/// "sidecar.outcome", the AEAD nonce's domain of an outcome whose shares
/// open C.
pub fn sidecar_outcome_ad() -> Fr {
    label_field(b"sidecar.outcome")
}

/// "sidecar.mismatch", the AEAD nonce's domain of a round whose shares do
/// not open C.
pub fn sidecar_mismatch_ad() -> Fr {
    label_field(b"sidecar.mismatch")
}

/// aztec-nr v6's `DOM_SEP__NOTE_HASH`.
pub const DOM_SEP_NOTE_HASH: u64 = 116_501_019;

/// The AEAD nonce of a sealed plaintext (pss_core `seal_nonce`):
/// `poseidon2([note_hash, SIDECAR_OUTCOME_AD])` when the round's shares
/// open C, `poseidon2([note_hash, SIDECAR_MISMATCH_AD])` when they do not,
/// `note_hash` the completed note that packs the plaintext.
pub fn seal_nonce(note_hash: Fr, opened: bool) -> Fr {
    let domain = if opened {
        sidecar_outcome_ad()
    } else {
        sidecar_mismatch_ad()
    };
    poseidon2_hash(&[note_hash, domain])
}

/// The nonce of an outcome whose shares open C, `seal_nonce(note_hash,
/// true)`.
pub fn outcome_nonce(note_hash: Fr) -> Fr {
    seal_nonce(note_hash, true)
}

/// aztec-nr v6's `DOM_SEP__PARTIAL_NOTE_COMMITMENT`.
pub const DOM_SEP_PARTIAL_NOTE_COMMITMENT: u64 = 568_912_195;

/// A partial note's commitment, `poseidon2_hash_with_separator([owner, rho],
/// DOM_SEP__PARTIAL_NOTE_COMMITMENT)` (pss_core `partial_commitment`): what
/// the user's request function puts in the request as `$partial_note`.
pub fn partial_commitment(owner: Fr, rho: Fr) -> Fr {
    poseidon2_hash(&[Fr::from(DOM_SEP_PARTIAL_NOTE_COMMITMENT), owner, rho])
}

/// The hash of the note completing `partial` at `storage_slot` with
/// `fields` and the chain request id, `poseidon2_hash_with_separator(
/// [storage_slot, partial, fields…, request_id], DOM_SEP__NOTE_HASH)`
/// (pss_core `completed_note_hash`).
pub fn completed_note_hash(storage_slot: Fr, partial: Fr, fields: &[Fr], request_id: Fr) -> Fr {
    let mut input = vec![Fr::from(DOM_SEP_NOTE_HASH), storage_slot, partial];
    input.extend_from_slice(fields);
    input.push(request_id);
    poseidon2_hash(&input)
}

/// Open `[ct…, tag]` under `outcome_key` with the nonce of `note_hash`,
/// the completed note's hash (the round's public output, the log's first
/// field): in the opened domain, or, for a round whose shares did not open
/// C, the mismatch domain.
pub fn open_outcome(
    outcome_key: Fr,
    note_hash: Fr,
    ciphertext: &[Fr],
) -> Result<Vec<Fr>, ae::TagMismatch> {
    let (ct, tag) = ciphertext.split_at(ciphertext.len() - 1);
    ae::decrypt(outcome_key, seal_nonce(note_hash, true), ct, tag[0])
        .or_else(|_| ae::decrypt(outcome_key, seal_nonce(note_hash, false), ct, tag[0]))
}

/// testvectors/outcome.json, which pss_core and pss-client check: the
/// opener above agrees with it on every vector.
pub fn check_outcome_vectors() {
    let path = repo().join("testvectors/outcome.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let f = |x: &Value| fr_from_hex(x.as_str().unwrap()).unwrap();
    let fs = |x: &Value| -> Vec<Fr> { x.as_array().unwrap().iter().map(f).collect() };
    assert_eq!(f(&v["sidecar_outcome_ad"]), sidecar_outcome_ad());
    assert_eq!(f(&v["sidecar_mismatch_ad"]), sidecar_mismatch_ad());
    assert_eq!(v["dom_sep_note_hash"].as_u64(), Some(DOM_SEP_NOTE_HASH));
    assert_eq!(
        v["dom_sep_partial_note_commitment"].as_u64(),
        Some(DOM_SEP_PARTIAL_NOTE_COMMITMENT)
    );
    let vectors = v["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for c in vectors {
        let id = f(&c["machine_request_id"]);
        assert_eq!(
            id,
            machine_request_id(
                f(&c["chain_request_id"]),
                &fs(&c["old_commitments"]),
                &fs(&c["pinned"])
            ),
            "{}",
            c["name"]
        );
        let note_hash = f(&c["note_hash"]);
        assert_eq!(outcome_nonce(note_hash), f(&c["nonce"]), "{}", c["name"]);
        let key = f(&c["outcome_key"]);
        let ciphertext = fs(&c["ciphertext"]);
        assert_eq!(
            open_outcome(key, note_hash, &ciphertext).unwrap(),
            fs(&c["plaintext"]),
            "{}",
            c["name"]
        );
    }
    let p = &v["partial_note"];
    let partial = partial_commitment(f(&p["owner"]), f(&p["rho"]));
    assert_eq!(partial, f(&p["partial_note"]));
    let plaintext = open_outcome(
        f(&p["outcome_key"]),
        f(&p["note_hash"]),
        &fs(&p["ciphertext"]),
    )
    .unwrap();
    assert_eq!(plaintext, fs(&p["plaintext"]));
    assert_eq!(
        completed_note_hash(
            f(&p["storage_slot"]),
            partial,
            &plaintext,
            f(&p["request_id"])
        ),
        f(&p["note_hash"])
    );
    // a round whose shares do not open C: the code alone, under the
    // mismatch domain's nonce of its note hash, which is not the opened
    // domain's
    let m = &v["mismatch"];
    let note_hash = f(&m["note_hash"]);
    let plaintext = fs(&m["plaintext"]);
    assert_eq!(
        note_hash,
        completed_note_hash(
            f(&m["storage_slot"]),
            partial_commitment(f(&m["owner"]), f(&m["rho"])),
            &plaintext,
            f(&m["request_id"])
        )
    );
    assert_eq!(seal_nonce(note_hash, false), f(&m["nonce"]));
    assert_eq!(seal_nonce(note_hash, true), f(&m["opened_nonce"]));
    assert_ne!(f(&m["nonce"]), f(&m["opened_nonce"]));
    assert_eq!(
        open_outcome(f(&m["outcome_key"]), note_hash, &fs(&m["ciphertext"])).unwrap(),
        plaintext
    );
    assert_eq!(plaintext[0], f(&m["code"]));
    assert!(plaintext[1..].iter().all(|x| *x == Fr::from(0u64)));
}

/// A private-outcome round's public outputs (pss_core `Private`), after its
/// public parameters.
#[derive(Clone, Debug)]
pub struct PrivateOutputs {
    pub request_id: Fr,
    pub machine_request_id: Fr,
    pub old_c: Fr,
    pub new_c: Fr,
    pub npk_app_hash: Fr,
    pub new_hashes: Vec<Fr>,
    pub outcome_tag: Fr,
    pub note_hash: Fr,
    pub ciphertext: Vec<Fr>,
}

/// Split `result`'s public inputs: `params` public parameters, then one
/// read and one written key, `new_hashes` leaf hashes, one note hash and a
/// ciphertext of `ciphertext` fields, the last public outputs.
pub fn private_outputs(
    result: &ExecuteResponse,
    params: usize,
    new_hashes: usize,
    ciphertext: usize,
) -> PrivateOutputs {
    let pi: Vec<Fr> = result.public_inputs.iter().map(|f| f.fr()).collect();
    let at = |k: usize| pi[params + k];
    let tag = 5 + new_hashes;
    assert_eq!(
        pi.len(),
        params + tag + 2 + ciphertext,
        "nothing follows the ciphertext"
    );
    PrivateOutputs {
        request_id: at(0),
        machine_request_id: at(1),
        old_c: at(2),
        new_c: at(3),
        npk_app_hash: at(4),
        new_hashes: pi[params + 5..params + tag].to_vec(),
        outcome_tag: at(tag),
        note_hash: at(tag + 1),
        ciphertext: pi[params + tag + 2..].to_vec(),
    }
}

// ---------------------------------------------------------------------------
// The audit
// ---------------------------------------------------------------------------

/// What a suite must not find where the nodes, the orchestrator or the
/// chain see it: the requester addresses (sidecar-tip's `audit`) and the
/// shared app values.
#[derive(Clone, Debug, Default)]
pub struct Hidden {
    pub requesters: Requesters,
    pub values: Vec<(String, Fr)>,
}

impl Hidden {
    /// Add the owner of `req`'s partial note, when known, as a requester
    /// address, and its shared app values (the partial note among them).
    pub fn add(&mut self, req: &SharedRequest) {
        self.requesters.0.extend(req.owner);
        self.values.extend(req.hidden());
    }

    /// Panic when `value`, serialised as JSON, holds a requester address or
    /// a hidden app value as any field element, naming `what` and the path.
    pub fn assert_absent_in<T: Serialize>(&self, what: &str, value: &T) {
        self.requesters.assert_absent_in(what, value);
        let json = serde_json::to_value(value).expect("an audited value serialises");
        for (path, f) in json_fields(&json, String::new()) {
            if let Some((name, _)) = self.values.iter().find(|(_, v)| *v == f) {
                panic!(
                    "{what}: `{path}` is the shared app input `{name}` in the clear ({})",
                    fr_to_hex(f)
                );
            }
        }
    }

    pub fn assert_absent(&self, what: &str, fields: &[Fr]) {
        self.requesters.assert_absent(what, fields.iter().copied());
        for (k, f) in fields.iter().enumerate() {
            if let Some((name, _)) = self.values.iter().find(|(_, v)| v == f) {
                panic!("{what}: field {k} is the shared app input `{name}` in the clear");
            }
        }
    }
}

/// Every field element in a JSON value, with its path: every string that
/// parses as one and every unsigned number.
fn json_fields(v: &Value, path: String) -> Vec<(String, Fr)> {
    match v {
        Value::String(s) => fr_from_hex(s).map(|f| vec![(path, f)]).unwrap_or_default(),
        Value::Number(n) => n
            .as_u64()
            .map(|u| vec![(path, Fr::from(u))])
            .unwrap_or_default(),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .flat_map(|(i, x)| json_fields(x, format!("{path}[{i}]")))
            .collect(),
        Value::Object(map) => map
            .iter()
            .flat_map(|(k, x)| json_fields(x, format!("{path}.{k}")))
            .collect(),
        _ => vec![],
    }
}

impl Chain {
    /// Secret-shared receipt intake: the request function's checks, the
    /// sharing opens C and the three receipts verify under the pinned keys
    /// over the chain request id the contract recomputes from C and the
    /// sharing's digest; the block is before the expiry, and only the id is
    /// queued: the public call carries the id and the expiry, nothing of
    /// the request.
    pub fn intake_shared(
        &mut self,
        clock: &Clock,
        vk_hash: Fr,
        req: &SharedRequest,
        receipt: &ReceiptResponse,
        hidden: &Hidden,
    ) -> Fr {
        let c = req.c;
        assert!(
            req.sharing.opens(),
            "the summands do not add up to a shared value of C"
        );
        let id = shared_chain_request_id(self.ns, vk_hash, c);
        let message = shared_receipt_message(id, c, receipt.expiry_block, req.sharing.digest);
        for (i, sig) in receipt.signatures.iter().enumerate() {
            assert!(
                schnorr::verify(self.sig_pks[i], *sig, message),
                "receipt {i} does not verify"
            );
        }
        assert!(
            clock.block < u64::from(receipt.expiry_block),
            "receipt expired"
        );
        hidden.assert_absent(
            "the intake's public call",
            &[id, Fr::from(u64::from(receipt.expiry_block))],
        );
        self.append(clock, id);
        id
    }
}

impl Net {
    /// The three receipts of `req` at `block`, through the orchestrator's
    /// route: the body and every node's row are audited, and each node
    /// stored its own envelopes, C and no nonce.
    pub async fn receipt(
        &self,
        block: u64,
        req: &SharedRequest,
        hidden: &Hidden,
    ) -> ReceiptResponse {
        let body = req.body(block);
        hidden.assert_absent_in("the receipt body's clear inputs", &body["inputs"]);
        let answer = self.orch.post_json("/v1/receipt", &body).await;
        let receipt: ReceiptResponse = answer
            .json::<ReceiptResponse>()
            .unwrap()
            .unwrap_or_else(|e| panic!("receipt: {e}"));
        assert_eq!(receipt.request_id.fr(), req.chain);
        assert_eq!(receipt.inputs_hash.fr(), req.c);
        for (i, app) in self.real.apps.iter().enumerate() {
            let row = app
                .node
                .store
                .receipt(req.namespace, req.chain)
                .unwrap()
                .unwrap_or_else(|| panic!("node {i} stored no receipt row"));
            assert!(row.user_nonce.is_none());
            assert_eq!(row.inputs_hash, req.c);
            let own: Vec<_> = req.sealed.iter().map(|s| s.shares[i]).collect();
            assert_eq!(
                row.shares.iter().map(|s| s.share).collect::<Vec<_>>(),
                own,
                "node {i} keeps its own envelopes"
            );
            hidden.requesters.assert_receipt_row(req.namespace, &row);
            hidden.assert_absent_in(
                &format!("node {i}'s receipts row"),
                &StoredReceipt::new(req.namespace, &row),
            );
            hidden.assert_absent(&format!("node {i}'s receipts row inputs"), &row.inputs);
        }
        receipt
    }

    /// Nodes that change their shares after `req`'s honest intake: each
    /// node's stored row of `req` takes its envelopes of `to` (the same C
    /// and chain request id, another sharing,
    /// [`SharedRequest::reshared`]), so the head's round reads shares that
    /// do not open C.
    pub fn change_shares(&self, req: &SharedRequest, to: &SharedRequest) {
        assert_eq!((to.c, to.chain), (req.c, req.chain));
        for (i, app) in self.real.apps.iter().enumerate() {
            let mut row = app
                .node
                .store
                .receipt(req.namespace, req.chain)
                .unwrap()
                .unwrap_or_else(|| panic!("node {i} stored no receipt row"));
            row.shares = to
                .sealed
                .iter()
                .map(|s| sidecar_core::request::NodeSharedInput {
                    name: s.name.clone(),
                    share: s.shares[i],
                    share_hashes: s.share_hashes,
                })
                .collect();
            app.node.store.put_receipt(req.namespace, row).unwrap();
        }
    }

    /// The receipt route's refusal of `req`'s body at `block`, naming
    /// `needle`.
    pub async fn receipt_refused(&self, block: u64, req: &SharedRequest, needle: &str) {
        let answer = self.orch.post_json("/v1/receipt", &req.body(block)).await;
        let refusal = answer.json::<ReceiptResponse>().unwrap().unwrap_err();
        eprintln!("RECEIPT REFUSED: {refusal}");
        assert!(
            refusal.message.contains(needle),
            "`{needle}` not in {refusal}"
        );
    }

    /// Every request a node received for `req`: no requester, the public
    /// map holds no hidden value, and node i's shared inputs are its own
    /// envelopes of `req`.
    pub fn audit_received(&self, req: &SharedRequest, hidden: &Hidden) -> usize {
        let received = self.received_for(req.chain);
        for (i, r) in &received {
            assert!(r.get("requester").is_none_or(Value::is_null), "{r}");
            hidden.assert_absent_in(&format!("node {i}'s received public map"), &r["public"]);
            assert_eq!(r["public"]["inputs_hash"], json!(FieldHex(req.c)), "{r}");
            let shares: Vec<Value> = r["shared_inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["share"].clone())
                .collect();
            let own: Vec<Value> = req.sealed.iter().map(|s| json!(s.shares[*i])).collect();
            assert_eq!(shares, own, "node {i} received its own envelopes");
        }
        received.len()
    }
}

// ---------------------------------------------------------------------------
// Secret-shared on-chain intake (docs/ARCHITECTURE.md section 6, "Secret-shared
// on-chain intake"): the user's private function, the contract's key store and
// append, and a node's rotation into the contract
// ---------------------------------------------------------------------------

/// Where the mock contracts keep the library's `SharedOnchain` (`enc_keys`
/// at +0, `data_hashes` at +1).
pub const SHARED_ONCHAIN_SLOT: u64 = 0x40;

/// `ns` with the app's `SharedOnchain` at [`SHARED_ONCHAIN_SLOT`]: the
/// scheduler's queue layout, and so every chain verifier's ([`start`]).
pub fn with_shared_onchain(mut ns: TipEntry) -> TipEntry {
    ns.shared_onchain_slot = Some(FieldHex::from(SHARED_ONCHAIN_SLOT));
    ns
}

/// The three nodes' `enc` keys and their epochs as the contract stores them
/// (`enc_keys[i] = (pk, epoch)`), as a private function reads them at its
/// anchor block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncKeys {
    pub pks: [Point; 3],
    pub epochs: [u32; 3],
}

/// One secret-shared on-chain request as the user's private function builds it
/// from the keys at its anchor: the values in C's order (every shared value
/// the user's, `$blinding` the encoding's), C, the chain request id, and the
/// private request log under the request's tag with its data hash. `req`
/// holds what the user keeps (the outcome key and tag, the app values) in
/// the shape the private outcome helpers take; it carries no envelope.
#[derive(Clone)]
pub struct OnchainRequest {
    pub req: SharedRequest,
    pub epochs: [u32; 3],
    /// The request log after its tag.
    pub log: Vec<Fr>,
    pub tag: Fr,
    pub shared: Vec<sidecar_core::derived::DerivedInput>,
}

impl OnchainRequest {
    /// `inputs` (the app inputs by name) and `reserved` (the outcome key and
    /// tag, by name) of `package` in `namespace`, encoded under `keys` with a
    /// fresh ephemeral secret.
    pub fn new(
        namespace: Fr,
        package: &TipPackage,
        keys: EncKeys,
        inputs: Vec<Input>,
        reserved: &[(&str, Fr)],
    ) -> Self {
        use sidecar_core::derived::{Kind, encode, request_log};
        let layout = sidecar_tip::onchain_layout(&package.shape, &package.tip);
        let kinds = layout.commitment.value_kinds();
        let plain: Vec<Fr> = layout
            .commitment
            .kinds
            .iter()
            .map(|(name, _)| {
                let given = inputs
                    .iter()
                    .find(|i| i.name == name)
                    .map(|i| i.value)
                    .or_else(|| reserved.iter().find(|(n, _)| n == name).map(|(_, v)| *v));
                given.unwrap_or_else(|| panic!("no value for `{name}` of {}", package.name))
            })
            .collect();
        for i in &inputs {
            let is_shared = layout
                .commitment
                .kinds
                .iter()
                .any(|(n, k)| n == i.name && *k != Kind::Clear);
            assert_eq!(i.shared, is_shared, "`{}` of {}", i.name, package.name);
        }
        let encoding = encode(&kinds, &plain, random(), keys.pks);
        let c = inputs_commitment(&plain, encoding.blinding);
        let chain = shared_chain_request_id(namespace, package.vk_hash, c);
        let log = request_log(c, keys.epochs, &encoding);
        let value = |name: &str| {
            let p = layout
                .commitment
                .kinds
                .iter()
                .position(|(n, _)| n == name)
                .unwrap_or_else(|| panic!("C of {} takes no `{name}`", package.name));
            plain[p]
        };
        OnchainRequest {
            req: SharedRequest {
                namespace,
                circuit: package.name.clone(),
                inputs,
                owner: None,
                outcome_key: value("$outcome_key"),
                outcome_tag: value("$outcome_tag"),
                blinding: encoding.blinding,
                c,
                chain,
                sealed: vec![],
                sharing: Sharing::default(),
            },
            epochs: keys.epochs,
            log,
            tag: request_log_tag(chain),
            shared: layout.shared,
        }
    }

    pub fn chain(&self) -> Fr {
        self.req.chain
    }

    /// The request log as a synthesised request carries it.
    pub fn shared_log(&self) -> sidecar_core::derived::SharedLog {
        sidecar_core::derived::SharedLog {
            fields: self.log.iter().copied().map(FieldHex).collect(),
            shared: self.shared.clone(),
        }
    }

    /// The scheduler's inputs of this request: its clear app inputs, C and
    /// the log.
    pub fn intake_inputs(&self) -> sidecar_tip::SharedOnchainFound {
        let clear = self
            .req
            .inputs
            .iter()
            .filter(|i| !i.shared)
            .map(|i| i.value)
            .collect();
        sidecar_tip::SharedOnchainFound::new(clear, self.req.c, self.shared_log())
    }
}

impl Chain {
    /// This contract with the library's `SharedOnchain` at
    /// [`SHARED_ONCHAIN_SLOT`] and no node key yet (epoch 0 is no key).
    pub fn with_shared_onchain(mut self) -> Self {
        self.shared_onchain = Some(sidecar_tip::SharedOnchainLayout::new(Fr::from(
            SHARED_ONCHAIN_SLOT,
        )));
        self
    }

    fn enc_key_slot(&self, i: usize) -> Fr {
        self.shared_onchain
            .expect("the contract declares SharedOnchain")
            .enc_key(i)
    }

    /// `rotate_enc_key(i, key, signature)` then `set_enc_key`: node i's
    /// Schnorr signature under its pinned `sig` key over the rotation
    /// message must verify and the epoch be the stored one + 1; the public
    /// write sets `enc_keys[i]` (x, y, epoch).
    pub fn rotate_enc_key(
        &mut self,
        keys: &mut EncKeys,
        i: usize,
        pk: Point,
        epoch: u32,
        signature: sidecar_core::register::Signature,
    ) {
        let (x, y) = sidecar_core::grumpkin::coordinates(pk);
        let message = sidecar_tip::enc_rotation_message(self.ns, i, (x, y), epoch);
        assert!(
            schnorr::verify(self.sig_pks[i], signature, message),
            "node {i}'s rotation signature does not verify"
        );
        assert_eq!(
            epoch,
            keys.epochs[i] + 1,
            "the epoch is not the stored epoch + 1"
        );
        let slot = self.enc_key_slot(i);
        self.mem.set_storage(self.ns, slot, x);
        self.mem.set_storage(self.ns, slot + Fr::from(1u64), y);
        self.mem
            .set_storage(self.ns, slot + Fr::from(2u64), Fr::from(u64::from(epoch)));
        keys.pks[i] = pk;
        keys.epochs[i] = epoch;
    }

    /// Secret-shared on-chain intake as the contract writes it: the private
    /// function emits the request log under the request's tag (the chain
    /// silos it by this address) and the public `append_onchain_shared(id,
    /// data_hash, epochs)` checks each named epoch is the stored one or the
    /// one before it, stores `data_hashes[id]` and queues the id. Neither the
    /// public call nor the log holds an app value or a requester.
    pub fn intake_shared_onchain(
        &mut self,
        clock: &Clock,
        stored: &EncKeys,
        q: &OnchainRequest,
        hidden: &Hidden,
    ) -> Fr {
        use sidecar_core::derived::{data_hash, pack_epochs};
        let id = q.chain();
        for i in 0..3 {
            assert!(q.epochs[i] != 0, "the request names epoch 0, no enc key");
            assert!(
                q.epochs[i] == stored.epochs[i] || q.epochs[i] + 1 == stored.epochs[i],
                "node {i}: epoch {} is neither the stored epoch {} nor the one before it",
                q.epochs[i],
                stored.epochs[i]
            );
        }
        let hash = data_hash(&q.log);
        hidden.assert_absent(
            "the intake's public call",
            &[id, hash, pack_epochs(q.epochs)],
        );
        hidden.assert_absent("the private request log", &q.log);
        self.mem.node().push_private(
            clock.block,
            sidecar_tip::chain::layout::siloed_private_log_tag(self.ns, q.tag),
            &q.log,
        );
        let slot = self
            .shared_onchain
            .expect("SharedOnchain declared")
            .data_hash(id);
        self.mem.set_storage(self.ns, slot, hash);
        self.append(clock, id);
        id
    }
}

impl Net {
    /// Node `i` rotates into `chain`'s contract at `epoch` (the stored one +
    /// 1), as the node signs it with sidecar-tip's `rotate_into`: first, with
    /// `scalar`, it takes a new current `enc` key (otherwise it keeps its
    /// current one); `rotate_into` keeps the current scalar pending as that
    /// epoch's for this contract and signs; the node holds the keys before
    /// the transaction lands, the contract checks and stores the key, and
    /// the node records the scalar on reading the stored key, as its pruning
    /// job does (`EpochKeys::land`).
    pub fn rotate_onchain(
        &self,
        chain: &mut Chain,
        stored: &mut EncKeys,
        i: usize,
        scalar: Option<sidecar_core::grumpkin::Fq>,
        epoch: u32,
        now: u64,
    ) {
        let node = &self.real.apps[i].node;
        let mut keys = node.keys().as_ref().clone();
        if let Some(scalar) = scalar {
            keys = keys.rotate_enc(scalar, now).unwrap();
        }
        let signature = sidecar_tip::rotate_into(&mut keys, i, chain.ns, epoch, &mut OsRng)
            .unwrap_or_else(|e| panic!("node {i}'s rotation: {e}"));
        let pk = keys.enc_pk();
        node.set_keys(keys);
        chain.rotate_enc_key(stored, i, pk, epoch, signature);
        let mut keys = node.keys().as_ref().clone();
        let recorded = keys.epochs_mut().land(
            chain.ns,
            epoch,
            sidecar_core::grumpkin::coordinates(pk),
            &[],
        );
        assert!(recorded.contains(&epoch), "node {i}'s epoch {epoch} landed");
        assert!(keys.epochs().pending(chain.ns).is_empty());
        node.set_keys(keys);
    }

    /// Every request a node received for `q`: no requester, no hidden value
    /// in the public map or the log, C as `inputs_hash`, no envelope, and the
    /// request log as the chain holds it as `shared_log`.
    pub fn audit_received_onchain(&self, q: &OnchainRequest, hidden: &Hidden) -> usize {
        let received = self.received_for(q.chain());
        let log = json!(q.shared_log());
        for (i, r) in &received {
            assert!(r.get("requester").is_none_or(Value::is_null), "{r}");
            hidden.assert_absent_in(&format!("node {i}'s received public map"), &r["public"]);
            hidden.assert_absent_in(&format!("node {i}'s received shared_log"), &r["shared_log"]);
            assert_eq!(r["public"]["inputs_hash"], json!(FieldHex(q.req.c)), "{r}");
            assert!(
                r.get("shared_inputs")
                    .is_none_or(|s| s.as_array().is_some_and(Vec::is_empty)),
                "node {i} received an envelope: {r}"
            );
            assert_eq!(r["shared_log"], log, "node {i} received the chain's log");
        }
        received.len()
    }
}
