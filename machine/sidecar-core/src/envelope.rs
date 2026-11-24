//! INPUT_SHARED envelopes: node i's pair `[x_i, x_{i-1}]` of a shared input,
//! encrypted to node i's `enc` key and bound to the request body, or under
//! secret-shared receipt intake to the chain request.
//!
//! ```text
//! eph          a random field element, as a scalar by Noir's decomposition (pss_utils/dh.nr)
//! E            = eph · G
//! S            = (eph · enc_pk_i).x  on the client,  (enc_i · E).x  on node i
//! nonce        = poseidon2([namespace, request_id, poseidon2_hash_bytes(circuit),
//!                           poseidon2_hash_bytes(name), i, input_body_hash])      body AD
//!              = poseidon2([namespace, chain_request_id, poseidon2_hash_bytes(circuit),
//!                           poseidon2_hash_bytes(name), i, SIDECAR_INTAKE_AD])    intake AD
//! (ct, tag)    = ae::encrypt(S, nonce, [x_i, x_{i-1}])        AE::encrypt (N = 2) of pss_utils/ae.nr
//! envelope     = {eph: E, ct: [ct0, ct1], tag}
//! share_hashes[i] = poseidon2([E.x, E.y, ct0, ct1, tag])
//! ```
//!
//! `request_id` is the request id (one field element) and
//! `input_body_hash` is [`Request::input_body_hash`]. Under secret-shared receipt
//! intake the user cannot know the body the scheduler synthesises, so the
//! envelope binds the chain request instead (the intake associated data,
//! [`EnvelopeAd::for_intake`]); the binder picks the associated data from the
//! manifest's intake ([`EnvelopeAd::for_round`]). The client seals
//! ([`seal_envelope_with`] with a fresh ephemeral secret); node i opens with [`open_envelope`] (or
//! [`ShareSource::share`], the binder's hook), under its current `enc` scalar
//! and, during a rotation's grace window, its previous one; an envelope a
//! node takes to keep (the receipt route) opens under the current scalar
//! only ([`open_envelope_current`]).

use std::collections::BTreeSet;

use ark_ff::Zero;

use crate::ae;
use crate::bind::Share;
use crate::error::Refusal;
use crate::field::{FieldHex, Fr, RequestId};
use crate::grumpkin::{
    Point, coordinates, fixed_base_mul, mul, point_from_wire, point_to_wire, scalar_from_field,
};
use crate::hash::poseidon2_hash;
use crate::keys::{NodeKeys, label_field};
use crate::manifest::{EnvelopeBinding, Manifest, ShareSource};
use crate::request::{NODES, NodeRequest, Request, ShareCiphertext, View};
use crate::schnorr::poseidon2_hash_bytes;

/// The label of the intake associated data's last element.
pub const SIDECAR_INTAKE_AD_LABEL: &[u8] = b"sidecar.intake";

/// `SIDECAR_INTAKE_AD`, the last element of the intake associated data: the
/// bytes `sidecar.intake` read big-endian as one field element.
pub fn sidecar_intake_ad() -> Fr {
    label_field(SIDECAR_INTAKE_AD_LABEL)
}

/// The request id as the field element the associated data carries: the id
/// itself, which is one field element.
pub fn request_id_field(id: &RequestId) -> Fr {
    id.fr()
}

/// Everything an envelope's associated data binds except the node index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeAd {
    pub namespace: Fr,
    /// The request id (body AD) or the chain request id (intake AD).
    pub request_id: Fr,
    pub circuit: String,
    /// The shared input's name.
    pub name: String,
    /// The last element: [`Request::input_body_hash`] (body AD) or
    /// [`sidecar_intake_ad`] (intake AD).
    pub binds: Fr,
}

impl EnvelopeAd {
    /// The body associated data of the shared input `name` of `request`, in
    /// either view; the client and node i compute the same value.
    pub fn for_input<V: View>(request: &Request<V>, name: &str) -> Self {
        EnvelopeAd {
            namespace: request.namespace.fr(),
            request_id: request_id_field(&request.request_id),
            circuit: request.circuit.clone(),
            name: name.to_string(),
            binds: request.input_body_hash(),
        }
    }

    /// The intake associated data of the shared input `name` of chain
    /// request `chain_request_id` of `circuit` under `namespace`: what a
    /// secret-shared receipt intake client seals under before any body exists.
    pub fn for_intake(namespace: Fr, chain_request_id: Fr, circuit: &str, name: &str) -> Self {
        EnvelopeAd {
            namespace,
            request_id: chain_request_id,
            circuit: circuit.to_string(),
            name: name.to_string(),
            binds: sidecar_intake_ad(),
        }
    }

    /// The associated data node i opens the envelope of `name` in `request`
    /// under, as the intake's row binds it ([`EnvelopeBinding`]): the body
    /// associated data, or the intake associated data over the request's
    /// chain request id (400 when it carries none).
    pub fn for_round<V: View>(
        request: &Request<V>,
        binding: EnvelopeBinding,
        name: &str,
    ) -> Result<Self, Refusal> {
        match binding {
            EnvelopeBinding::Body => Ok(Self::for_input(request, name)),
            EnvelopeBinding::ChainRequest => {
                let chain = request.chain_request_id.ok_or_else(|| {
                    Refusal::bad_request(format!(
                        "shared input `{name}`: the request carries no chain request id, which its envelopes bind"
                    ))
                })?;
                Ok(Self::for_intake(
                    request.namespace.fr(),
                    chain.fr(),
                    &request.circuit,
                    name,
                ))
            }
        }
    }

    // The envelope's associated data is (namespace, request_id,
    // circuit, input name, node index i, input_body_hash), hashed with Poseidon2
    // into the AE nonce slot, so the tag covers it. namespace, request_id and
    // circuit stop an envelope moving to another namespace, request or round;
    // the name stops it filling another input of the same round; i stops it
    // opening at another node (whose key would also differ, but the index makes
    // the binding explicit). input_body_hash is the canonical body without the
    // whole shared_inputs array, so a changed public value, key, record hash or
    // requester after sealing makes every node's envelope fail, while the
    // envelopes need not cover their own hashes; share_hashes reach the nodes
    // through body_hash and the session handshake instead, and bind the
    // envelopes of one request to each other through the requester's
    // signature over the body, which step 4 demands of every request with a
    // shared input under intake direct (pipeline::prefix::authenticate). The
    // nonce is fresh per envelope because each envelope's ephemeral key gives
    // a fresh AE key S.
    // Under secret-shared receipt intake the chain request id stands for the request
    // id and SIDECAR_INTAKE_AD for input_body_hash: the chain request id
    // commits to the inputs commitment C, which covers every input, and
    // stays fixed across the recomputes of one queued request, while the
    // body the scheduler synthesises changes with each attempt; the constant
    // keeps an intake envelope from opening as a body envelope. A client may
    // seal all of node i's pairs under one ephemeral key: the input name in
    // the nonce keeps every encryption under that key distinct.
    // Adding or removing a field changes every client's envelopes.
    /// The AE nonce of the envelope to node `i`.
    pub fn nonce(&self, i: usize) -> Fr {
        assert!(i < NODES, "node index {i} out of range");
        poseidon2_hash(&[
            self.namespace,
            self.request_id,
            poseidon2_hash_bytes(self.circuit.as_bytes()),
            poseidon2_hash_bytes(self.name.as_bytes()),
            Fr::from(i as u64),
            self.binds,
        ])
    }
}

/// Seal node `i`'s pair under its `enc_pk` with the ephemeral secret `eph`, a
/// field element read as a Grumpkin scalar as pss_utils' ephemeral keys are.
/// A client draws `eph` fresh and nonzero for every envelope. Panics if `eph`
/// is zero.
pub fn seal_envelope_with(
    enc_pk: Point,
    i: usize,
    ad: &EnvelopeAd,
    pair: [Fr; 2],
    eph: Fr,
) -> ShareCiphertext {
    assert!(!eph.is_zero(), "the ephemeral secret is zero");
    let scalar = scalar_from_field(eph);
    let e = fixed_base_mul(scalar);
    let secret = coordinates(mul(enc_pk, scalar)).0;
    let (ct, tag) = ae::encrypt(secret, ad.nonce(i), &pair);
    ShareCiphertext {
        eph: point_to_wire(e),
        ct: [FieldHex(ct[0]), FieldHex(ct[1])],
        tag: FieldHex(tag),
    }
}

/// The client's side, for the tests: seal node `i`'s pair `[x_i, x_{i-1}]`
/// to its pinned `enc_pk` with a fresh ephemeral key from `rng`.
#[cfg(any(test, feature = "testing"))]
pub fn seal_envelope<R: ark_std::rand::RngCore + ark_std::rand::CryptoRng>(
    enc_pk: Point,
    i: usize,
    ad: &EnvelopeAd,
    pair: [Fr; 2],
    rng: &mut R,
) -> ShareCiphertext {
    let eph = loop {
        let eph = <Fr as ark_ff::UniformRand>::rand(rng);
        if !eph.is_zero() {
            break eph;
        }
    };
    seal_envelope_with(enc_pk, i, ad, pair, eph)
}

/// Node `i`'s side: open its envelope of the input `ad.name`. Tries the current
/// `enc` scalar, then the previous one during a grace window; the tag decides.
/// Refuses (400, naming the input) an ephemeral key that is not a point and an
/// envelope that does not open: sealed to another node, or for another
/// namespace, request, circuit, input, node index or request body.
pub fn open_envelope(
    keys: &NodeKeys,
    i: usize,
    ad: &EnvelopeAd,
    envelope: &ShareCiphertext,
) -> Result<[Fr; 2], Refusal> {
    let e = ephemeral_key(ad, envelope)?;
    keys.shared_secrets(e)
        .into_iter()
        .find_map(|secret| decrypt_pair(secret, i, ad, envelope))
        .ok_or_else(|| does_not_decrypt(i, ad))
}

/// Node `i`'s side when it takes an envelope to keep (the receipt route
/// under secret-shared receipt intake): open it under the current `enc` scalar
/// only, so the envelope still opens after a rotation's grace window ends
/// before the round runs. Refuses (400, naming the input) what
/// [`open_envelope`] refuses, and an envelope that opens only under the
/// previous scalar, saying so.
pub fn open_envelope_current(
    keys: &NodeKeys,
    i: usize,
    ad: &EnvelopeAd,
    envelope: &ShareCiphertext,
) -> Result<[Fr; 2], Refusal> {
    let e = ephemeral_key(ad, envelope)?;
    if let Some(pair) = decrypt_pair(keys.shared_secret(e), i, ad, envelope) {
        return Ok(pair);
    }
    if open_envelope(keys, i, ad, envelope).is_ok() {
        return Err(Refusal::bad_request(format!(
            "shared input `{}`: the envelope to node {i} is sealed to this node's previous enc \
             key; seal to its current key (GET /v1/nodes)",
            ad.name
        )));
    }
    Err(does_not_decrypt(i, ad))
}

// The envelope's ephemeral key as a point (400 naming the input otherwise).
fn ephemeral_key(ad: &EnvelopeAd, envelope: &ShareCiphertext) -> Result<Point, Refusal> {
    point_from_wire(&envelope.eph).map_err(|why| {
        Refusal::bad_request(format!(
            "shared input `{}`: the envelope's ephemeral key is not a key: {why}",
            ad.name
        ))
    })
}

// The pair, when the envelope to node `i` opens under the shared secret.
fn decrypt_pair(
    secret: Fr,
    i: usize,
    ad: &EnvelopeAd,
    envelope: &ShareCiphertext,
) -> Option<[Fr; 2]> {
    let ct = [envelope.ct[0].fr(), envelope.ct[1].fr()];
    ae::decrypt(secret, ad.nonce(i), &ct, envelope.tag.fr())
        .ok()
        .map(|pair| [pair[0], pair[1]])
}

fn does_not_decrypt(i: usize, ad: &EnvelopeAd) -> Refusal {
    Refusal::bad_request(format!(
        "shared input `{}`: the envelope to node {i} does not decrypt (sealed to another node key, or its associated data differs)",
        ad.name
    ))
}

/// Where node i's pair of each shared input comes from, the manifest
/// intake's row ([`crate::manifest::Intake::share_source`]): the binder and
/// the in-session loads ask the source and never name an intake.
impl ShareSource {
    /// The names of the shared inputs `request` gives: its envelopes' names,
    /// or under a derived log the log's (400 for a log beside envelopes,
    /// a missing log, or a log where the shares come in envelopes).
    pub fn given_names<'r, V: View>(
        self,
        request: &'r Request<V>,
        manifest: &Manifest,
    ) -> Result<BTreeSet<&'r str>, Refusal> {
        match (&request.shared_log, self) {
            (Some(log), ShareSource::DerivedLog) if request.shared_inputs.is_empty() => {
                Ok(log.shared.iter().map(|s| s.name.as_str()).collect())
            }
            (Some(_), ShareSource::DerivedLog) => Err(Refusal::bad_request(format!(
                "field `shared_inputs`: circuit `{}` takes {}, whose shares derive from \
                 `shared_log`; it takes no envelope",
                manifest.circuit,
                manifest.intake.as_str()
            ))),
            (None, ShareSource::DerivedLog) => Err(Refusal::bad_request(format!(
                "field `shared_log`: missing; circuit `{}` takes {}, whose shares derive from it",
                manifest.circuit,
                manifest.intake.as_str()
            ))),
            (Some(_), ShareSource::Envelopes(_)) => Err(Refusal::bad_request(format!(
                "field `shared_log`: circuit `{}` has intake {}, whose shares come in envelopes",
                manifest.circuit,
                manifest.intake.as_str()
            ))),
            (None, ShareSource::Envelopes(_)) => Ok(request
                .shared_inputs
                .iter()
                .map(|s| V::shared_input_name(s))
                .collect()),
        }
    }

    /// The binder's INPUT_SHARED hook for node `i`: this node's pair of the
    /// shared input `name` in `request`, as its Rep3 share (`a = x_i`,
    /// `b = x_{i-1}`), which the binder binds as `Rep3Type::Shared`: its
    /// envelope opened under the associated data the source binds
    /// ([`EnvelopeAd::for_round`]), or the pair derived from the request's
    /// `shared_log` ([`crate::derived::node_share`]). Refuses (400) a name
    /// the request does not carry.
    pub fn share(
        self,
        keys: &NodeKeys,
        i: usize,
        request: &NodeRequest,
        name: &str,
    ) -> Result<Share, Refusal> {
        let binding = match self {
            ShareSource::Envelopes(binding) => binding,
            ShareSource::DerivedLog => {
                let log = request.shared_log.as_ref().ok_or_else(|| {
                    Refusal::bad_request("field `shared_log`: missing; the shares derive from it")
                })?;
                return crate::derived::node_share(keys, i, request.namespace.fr(), log, name);
            }
        };
        let input = request
            .shared_inputs
            .iter()
            .find(|input| input.name == name)
            .ok_or_else(|| {
                Refusal::bad_request(format!("field `shared_inputs`: missing `{name}`"))
            })?;
        let ad = EnvelopeAd::for_round(request, binding, name)?;
        let [a, b] = open_envelope(keys, i, &ad, &input.share)?;
        Ok(Share::new(a, b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind::Elem;
    use crate::error::ErrorClass;
    use crate::field::fr_to_hex;
    use crate::grumpkin::scalar_to_limbs;
    use crate::keys::tests::sample_keys;
    use crate::manifest::Intake;
    use crate::request::{Full, SharedInput};
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;
    use serde_json::{Value, json};
    use std::path::{Path, PathBuf};

    const NAMES: [&str; 2] = ["door", "door_randomness"];

    // The Monty Hall door round, with the requester and the game-state record
    // (one shared element, sealed to each node) but no shared inputs yet: what
    // the client has before it seals.
    fn request_without_inputs() -> Request<Full> {
        let namespace = Fr::from(0x1f2ea9c0u64);
        let owner = fixed_base_mul(scalar_from_field(Fr::from(5u64)));
        let state = sharing(Fr::from(42u64), 30);
        let (c, record_hashes): (Vec<String>, Vec<String>) = (0..NODES)
            .map(|i| {
                let [a, b] = pair(&state, i);
                let third = crate::record::seal(
                    &sample_keys(i),
                    namespace,
                    "0xb001",
                    Fr::from(0x77u64),
                    owner,
                    &[Elem::Shared(Share::new(a, b))],
                );
                let hash = crate::record::record_hash(&third).unwrap();
                (crate::field::HexBytes(third).to_string(), fr_to_hex(hash))
            })
            .unzip();
        Request::from_json(
            &json!({
                "namespace": fr_to_hex(namespace),
                "circuit": "monty_hall_open_door",
                "request_id": "0x41d3000000000000000000000000beef",
                "public": {"in0_nonce": "0x0d935b18"},
                "state_keys": {"reads": ["0xb001"], "writes": ["0xb001"]},
                "records": [{"key": "0xb001", "note_hash": "0x77",
                    "c": c, "record_hashes": record_hashes}],
                "requester": point_to_wire(owner)
            })
            .to_string(),
        )
        .unwrap()
    }

    // A replicated sharing of `x`: x_0, x_1 from the seed, x_2 = x - x_0 - x_1.
    fn sharing(x: Fr, seed: u64) -> [Fr; 3] {
        let x0 = poseidon2_hash(&[Fr::from(seed), Fr::from(0u64)]);
        let x1 = poseidon2_hash(&[Fr::from(seed), Fr::from(1u64)]);
        [x0, x1, x - x0 - x1]
    }

    fn pair(sharing: &[Fr; 3], i: usize) -> [Fr; 2] {
        [sharing[i], sharing[(i + 2) % 3]]
    }

    // The ephemeral secret of envelope (input k, node i) in the vectors.
    fn vector_eph(k: usize, i: usize) -> Fr {
        poseidon2_hash(&[Fr::from(0xe9u64), Fr::from(k as u64), Fr::from(i as u64)])
    }

    // Seal every input to every node and fill in shares and share_hashes.
    fn sealed_request() -> (Request<Full>, Vec<[Fr; 3]>) {
        let mut req = request_without_inputs();
        let values = [Fr::from(1u64), Fr::from(0xdeadu64)];
        let sharings: Vec<[Fr; 3]> = values
            .iter()
            .enumerate()
            .map(|(k, x)| sharing(*x, 10 + k as u64))
            .collect();
        for (k, name) in NAMES.iter().enumerate() {
            let ad = EnvelopeAd::for_input(&req, name);
            let shares = [0, 1, 2].map(|i| {
                seal_envelope_with(
                    sample_keys(i).enc_pk(),
                    i,
                    &ad,
                    pair(&sharings[k], i),
                    vector_eph(k, i),
                )
            });
            let share_hashes = shares.map(|s| FieldHex(s.hash()));
            req.shared_inputs.push(SharedInput {
                name: name.to_string(),
                shares,
                share_hashes,
            });
        }
        (req, sharings)
    }

    fn refused(result: Result<[Fr; 2], Refusal>, name: &str) {
        let name = format!("`{name}`");
        crate::error::assert_refused(result, ErrorClass::BadRequest, &[&name, "does not decrypt"]);
    }

    #[test]
    fn each_node_opens_its_own_envelope_and_binds_its_pair() {
        let (req, sharings) = sealed_request();
        let mut rng = StdRng::seed_from_u64(7);
        for i in 0..NODES {
            let node = req.project(i);
            node.check_own_ciphertexts(i).unwrap();
            let keys = sample_keys(i);
            for (k, name) in NAMES.iter().enumerate() {
                let share = Intake::Direct
                    .share_source()
                    .share(&keys, i, &node, name)
                    .unwrap();
                assert_eq!([share.a, share.b], pair(&sharings[k], i));
                // A randomly sealed envelope opens the same way.
                let ad = EnvelopeAd::for_input(&node, name);
                let fresh = seal_envelope(keys.enc_pk(), i, &ad, [share.a, share.b], &mut rng);
                assert_ne!(fresh, node.shared_inputs[k].share);
                assert_eq!(
                    open_envelope(&keys, i, &ad, &fresh).unwrap(),
                    [share.a, share.b]
                );
            }
        }
        // The three pairs are one replicated sharing: they sum to the value.
        let s = &sharings[0];
        assert_eq!(s[0] + s[1] + s[2], Fr::from(1u64));
        // The binder's element type.
        let share = Intake::Direct
            .share_source()
            .share(&sample_keys(1), 1, &req.project(1), "door")
            .unwrap();
        assert!(matches!(Elem::Shared(share), Elem::Shared(_)));
        let err = Intake::Direct
            .share_source()
            .share(&sample_keys(1), 1, &req.project(1), "seat")
            .unwrap_err();
        assert!(err.message.contains("missing `seat`"));
    }

    /// Under secret-shared receipt intake node i opens its envelope under the intake
    /// associated data over the request's chain request id, which stays the
    /// same when the scheduler's body changes (a recompute); a body envelope
    /// does not open there, and a request without a chain request id is
    /// refused.
    #[test]
    fn shared_receipt_intake_opens_under_the_intake_associated_data() {
        let mut req = request_without_inputs();
        let chain = Fr::from(0xc4a1u64);
        req.chain_request_id = Some(FieldHex(chain));
        let sh = sharing(Fr::from(0xdeadu64), 30);
        let ad = EnvelopeAd::for_intake(req.namespace.fr(), chain, &req.circuit, "door");
        assert_eq!(
            EnvelopeAd::for_round(&req, EnvelopeBinding::ChainRequest, "door").unwrap(),
            ad
        );
        assert_eq!(ad.binds, sidecar_intake_ad());
        assert_eq!(sidecar_intake_ad(), label_field(b"sidecar.intake"));
        let shares = [0, 1, 2].map(|i| {
            seal_envelope_with(
                sample_keys(i).enc_pk(),
                i,
                &ad,
                pair(&sh, i),
                vector_eph(5, i),
            )
        });
        req.shared_inputs.push(SharedInput {
            name: "door".into(),
            share_hashes: shares.map(|s| FieldHex(s.hash())),
            shares,
        });
        let mut recomputed = req.clone();
        recomputed.request_id = RequestId(Fr::from(0x77u64));
        for body in [&req, &recomputed] {
            for i in 0..NODES {
                let node = body.project(i);
                let share = Intake::SharedReceipt
                    .share_source()
                    .share(&sample_keys(i), i, &node, "door")
                    .unwrap();
                assert_eq!([share.a, share.b], pair(&sh, i));
                // the body associated data does not open an intake envelope
                assert!(
                    Intake::Direct
                        .share_source()
                        .share(&sample_keys(i), i, &node, "door")
                        .is_err()
                );
            }
        }
        // another chain request does not open it
        let mut other = req.clone();
        other.chain_request_id = Some(FieldHex(chain + Fr::from(1u64)));
        assert!(
            Intake::SharedReceipt
                .share_source()
                .share(&sample_keys(0), 0, &other.project(0), "door")
                .is_err()
        );
        let mut none = req.clone();
        none.chain_request_id = None;
        let err = Intake::SharedReceipt
            .share_source()
            .share(&sample_keys(0), 0, &none.project(0), "door")
            .unwrap_err();
        assert!(err.message.contains("carries no chain request id"), "{err}");
    }

    #[test]
    fn a_wrong_associated_data_is_refused() {
        let (req, _) = sealed_request();
        let node = req.project(1);
        let keys = sample_keys(1);
        let envelope = node.shared_inputs[0].share;
        let ad = EnvelopeAd::for_input(&node, "door");
        open_envelope(&keys, 1, &ad, &envelope).unwrap();
        let one = Fr::from(1u64);
        let variants = [
            EnvelopeAd {
                namespace: ad.namespace + one,
                ..ad.clone()
            },
            EnvelopeAd {
                request_id: ad.request_id + one,
                ..ad.clone()
            },
            EnvelopeAd {
                circuit: "monty_hall_finish".into(),
                ..ad.clone()
            },
            EnvelopeAd {
                name: "door_randomness".into(),
                ..ad.clone()
            },
            EnvelopeAd {
                binds: ad.binds + one,
                ..ad.clone()
            },
        ];
        for other in &variants {
            refused(open_envelope(&keys, 1, other, &envelope), &other.name);
        }
        // Another node index under the right key.
        refused(open_envelope(&keys, 2, &ad, &envelope), "door");
        // One public value altered after sealing: every node's envelope fails.
        let mut altered = req.clone();
        altered.public.insert(
            "in0_nonce".into(),
            crate::request::PublicValue::One(FieldHex::from(5)),
        );
        let mut altered_record = req.clone();
        altered_record.records[0].record_hashes[2] = FieldHex::from(5);
        let mut altered_requester = req.clone();
        altered_requester.requester = Some(point_to_wire(fixed_base_mul(scalar_from_field(one))));
        for changed in [altered, altered_record, altered_requester] {
            for i in 0..NODES {
                let node = changed.project(i);
                let err = Intake::Direct
                    .share_source()
                    .share(&sample_keys(i), i, &node, "door")
                    .unwrap_err();
                assert!(err.message.contains("does not decrypt"), "{err}");
            }
        }
        // A tampered envelope.
        let mut bad = envelope;
        bad.ct[1] = FieldHex(bad.ct[1].fr() + one);
        refused(open_envelope(&keys, 1, &ad, &bad), "door");
        let mut bad = envelope;
        bad.eph.y = FieldHex(bad.eph.y.fr() + one);
        let err = open_envelope(&keys, 1, &ad, &bad).unwrap_err();
        assert!(err.message.contains("not a key"), "{err}");
    }

    #[test]
    fn an_envelope_sent_to_the_wrong_node_is_refused() {
        let (req, _) = sealed_request();
        // Node 0's envelope presented to node 1: step 6 catches it by hash...
        let mut wrong = req.project(1);
        wrong.shared_inputs[0].share = req.shared_inputs[0].shares[0];
        let err = wrong.check_own_ciphertexts(1).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(err.message.contains("share_hashes[1]"), "{err}");
        // ...and it would not open at node 1 either, nor under node 1's index.
        let ad = EnvelopeAd::for_input(&wrong, "door");
        refused(
            open_envelope(&sample_keys(1), 1, &ad, &req.shared_inputs[0].shares[0]),
            "door",
        );
        refused(
            open_envelope(&sample_keys(0), 1, &ad, &req.shared_inputs[0].shares[0]),
            "door",
        );
    }

    #[test]
    fn envelopes_open_under_the_previous_key_in_the_grace_window() {
        let (req, sharings) = sealed_request();
        let node = req.project(2);
        let rotated = sample_keys(2)
            .rotate_enc(sample_keys(0).enc_scalar(), 0)
            .unwrap();
        let share = Intake::Direct
            .share_source()
            .share(&rotated, 2, &node, "door")
            .unwrap();
        assert_eq!([share.a, share.b], pair(&sharings[0], 2));
        let retired = rotated.retire_previous_enc();
        assert!(
            Intake::Direct
                .share_source()
                .share(&retired, 2, &node, "door")
                .is_err()
        );
    }

    /// The opener for an envelope a node keeps takes the current key only and
    /// names an envelope sealed to the previous one.
    #[test]
    fn an_envelope_to_keep_opens_under_the_current_key_only() {
        let (req, sharings) = sealed_request();
        let node = req.project(2);
        let ad = EnvelopeAd::for_input(&node, "door");
        let envelope = node.shared_inputs[0].share;
        let current = sample_keys(2);
        assert_eq!(
            open_envelope_current(&current, 2, &ad, &envelope).unwrap(),
            pair(&sharings[0], 2)
        );
        let rotated = current.rotate_enc(sample_keys(0).enc_scalar(), 0).unwrap();
        assert!(open_envelope(&rotated, 2, &ad, &envelope).is_ok());
        let err = open_envelope_current(&rotated, 2, &ad, &envelope).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(err.message.contains("previous enc key"), "{err}");
        refused(
            open_envelope_current(&sample_keys(1), 2, &ad, &envelope),
            "door",
        );
    }

    // ---- known answers: testvectors/envelope.json and the Noir check ----

    fn vectors_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/envelope.json")
    }

    fn noir_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/noir/envelope_vectors")
    }

    fn vectors_json() -> Value {
        let (req, sharings) = sealed_request();
        let input_body = {
            let mut body = crate::request::canonical_body(&req);
            body.as_object_mut().unwrap().remove("shared_inputs");
            crate::schnorr::canonical_json(&body).unwrap()
        };
        let canonical_body =
            crate::schnorr::canonical_json(&crate::request::canonical_body(&req)).unwrap();
        let hex = |f: Fr| fr_to_hex(f);
        let mut envelopes = Vec::new();
        for (k, name) in NAMES.iter().enumerate() {
            let ad = EnvelopeAd::for_input(&req, name);
            for i in 0..NODES {
                let keys = sample_keys(i);
                let eph = vector_eph(k, i);
                let envelope = req.shared_inputs[k].shares[i];
                let e = point_from_wire(&envelope.eph).unwrap();
                let (enc_lo, enc_hi) = scalar_to_limbs(keys.enc_scalar());
                envelopes.push(json!({
                    "name": name,
                    "i": i,
                    "eph": hex(eph),
                    "pair": pair(&sharings[k], i).map(hex),
                    "enc_pk": point_to_wire(keys.enc_pk()),
                    "enc_limbs": {"lo": hex(enc_lo), "hi": hex(enc_hi)},
                    "E": envelope.eph,
                    "shared_secret": hex(keys.shared_secret(e)),
                    "nonce": hex(ad.nonce(i)),
                    "ct": envelope.ct,
                    "tag": envelope.tag,
                    "share_hash": hex(envelope.hash()),
                }));
            }
        }
        json!({
            "rules": {
                "eph": "a random field element read as a Grumpkin scalar (lo = low 128 bits, hi = the rest), E = eph·G",
                "shared_secret": "S = (eph·enc_pk).x = (enc·E).x",
                "nonce": "poseidon2([namespace, request_id, poseidon2_hash_bytes(circuit), poseidon2_hash_bytes(name), i, input_body_hash])",
                "request_id": "the request id, one field element",
                "input_body_hash": "poseidon2_hash_bytes(JCS(canonical body without shared_inputs)); input_body is that JCS string",
                "cipher": "(ct, tag) = Poseidon2 duplex AE (testvectors/ae.json, n = 2; pss_utils AE::encrypt, N = 2) with key S, the nonce, plaintext pair = [x_i, x_(i-1)]",
                "share_hash": "poseidon2([E.x, E.y, ct[0], ct[1], tag])",
                "body_hash": "poseidon2_hash_bytes(canonical_body), the full request's JCS canonical body with the share hashes",
                "keys": "enc_pk and enc_limbs are testvectors/keys.json node i",
            },
            "request": serde_json::to_value(&req).unwrap(),
            "namespace": req.namespace,
            "request_id": hex(request_id_field(&req.request_id)),
            "circuit": req.circuit,
            "circuit_hash": hex(poseidon2_hash_bytes(req.circuit.as_bytes())),
            "names": NAMES,
            "name_hashes": NAMES.map(|n| hex(poseidon2_hash_bytes(n.as_bytes()))),
            "input_body": input_body,
            "input_body_hash": hex(req.input_body_hash()),
            "canonical_body": canonical_body,
            "body_hash": hex(req.body_hash()),
            "values": [hex(Fr::from(1u64)), hex(Fr::from(0xdeadu64))],
            "envelopes": envelopes,
        })
    }

    // Prover.toml of testvectors/noir/envelope_vectors, from the vector file.
    fn prover_toml(file: &Value) -> String {
        let s = |v: &Value| format!("\"{}\"", v.as_str().unwrap());
        let mut out = String::from(
            "# Written by sidecar-core envelope::tests::write_envelope_json from testvectors/envelope.json.\n",
        );
        out += &format!("namespace = {}\n", s(&file["namespace"]));
        out += &format!("request_id = {}\n", s(&file["request_id"]));
        out += &format!("input_body_hash = {}\n", s(&file["input_body_hash"]));
        out += &format!("circuit_hash = {}\n", s(&file["circuit_hash"]));
        out += &format!(
            "name_hashes = [{}]\n",
            file["name_hashes"]
                .as_array()
                .unwrap()
                .iter()
                .map(s)
                .collect::<Vec<_>>()
                .join(", ")
        );
        for v in file["envelopes"].as_array().unwrap() {
            let k = NAMES.iter().position(|n| *n == v["name"]).unwrap();
            out += "\n[[envelopes]]\n";
            out += &format!("input = {k}\n");
            out += &format!("i = {}\n", v["i"]);
            out += &format!("eph = {}\n", s(&v["eph"]));
            out += &format!("pair = [{}, {}]\n", s(&v["pair"][0]), s(&v["pair"][1]));
            out += &format!(
                "enc_pk_x = {}\nenc_pk_y = {}\n",
                s(&v["enc_pk"]["x"]),
                s(&v["enc_pk"]["y"])
            );
            out += &format!(
                "enc_lo = {}\nenc_hi = {}\n",
                s(&v["enc_limbs"]["lo"]),
                s(&v["enc_limbs"]["hi"])
            );
            out += &format!("e_x = {}\ne_y = {}\n", s(&v["E"]["x"]), s(&v["E"]["y"]));
            out += &format!("shared_secret = {}\n", s(&v["shared_secret"]));
            out += &format!("nonce = {}\n", s(&v["nonce"]));
            out += &format!("ct = [{}, {}]\n", s(&v["ct"][0]), s(&v["ct"][1]));
            out += &format!("tag = {}\n", s(&v["tag"]));
            out += &format!("share_hash = {}\n", s(&v["share_hash"]));
        }
        out
    }

    // The Noir program's inputs are the vector file's (tests/vectors.rs
    // checks the file against this crate).
    #[test]
    fn the_noir_programs_inputs_are_the_vector_file() {
        let text = std::fs::read_to_string(vectors_path()).expect("testvectors/envelope.json");
        let file: Value = serde_json::from_str(&text).unwrap();
        let toml = std::fs::read_to_string(noir_dir().join("Prover.toml")).unwrap();
        assert_eq!(
            toml,
            prover_toml(&file),
            "rerun the ignored write_envelope_json test"
        );
    }

    // Regenerates testvectors/envelope.json and the Noir program's Prover.toml:
    // cargo test -p sidecar-core envelope::tests::write_envelope_json -- --ignored
    #[test]
    #[ignore = "writes testvectors/; run on purpose"]
    fn write_envelope_json() {
        let file = vectors_json();
        let text = serde_json::to_string_pretty(&file).unwrap() + "\n";
        std::fs::write(vectors_path(), text).unwrap();
        std::fs::write(noir_dir().join("Prover.toml"), prover_toml(&file)).unwrap();
    }
}
