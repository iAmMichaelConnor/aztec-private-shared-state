//! The content-derived request ids of the tip (docs/ARCHITECTURE.md section 1,
//! the hash table; section 6, the intake and scheduler rows).
//!
//! ```text
//! inputs_hash        = poseidon2(inputs)                     the app inputs in ABI order
//! chain_request_id   = poseidon2([namespace, vk_hash, inputs_hash, user_nonce])
//! machine request id = poseidon2([PSS_ATTEMPT, chain_request_id, old commitments...,
//!                                 pinned values...])
//!
//! secret-shared intakes:
//! C                  = poseidon2([v_1, ..., v_m, blinding])   the inputs commitment
//! chain_request_id   = poseidon2([namespace, vk_hash, C])
//!
//! secret-shared receipt intake's sharing:
//! S_j                = poseidon2([SUMMANDS_DOMAIN, s_j..., salt_j])   j = 0, 1, 2
//! D                  = poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds..., clear values...])
//! receipt message    = poseidon2([RECEIPT_DOMAIN, chain_request_id, C, expiry_block, D])
//! ```
//!
//! Under a secret-shared intake `v_1 ... v_m` are the values of every app input,
//! clear or INPUT_SHARED, and of `$outcome_key` and `$outcome_tag`, in the
//! order the ABI walk first meets each ([`crate::commitment_names`]), and
//! `blinding` is `$blinding`, drawn uniformly per request; the id holds no
//! requester and no nonce (docs/ARCHITECTURE.md section 6, "The inputs
//! commitment and the request id"). pss_core's `tip::intake::commit` and
//! `tip::intake::shared` compute the same two values in the round.
//!
//! `poseidon2` is the machine's sponge ([`sidecar_core::hash::poseidon2_hash`],
//! the one `vk_hash` uses), which is total-noir's `p2_hash`, protocol_types'
//! `poseidon2_hash` and aztec.js `poseidon2Hash`. `namespace` is the app
//! contract's address, `vk_hash` the registered package's (the contract's
//! Config pin) and `user_nonce` a salt the client draws at random per request
//! (128 bits). No id names the requester (docs/ARCHITECTURE.md section 6,
//! "The hidden requester"). The contract computes the
//! chain request id at intake and keys its queue by it; the machine request id
//! is the `request_id` of the execute request the scheduler synthesises for
//! one attempt at the head, so a recompute against a different state, or at a
//! different pinned value (an oracle price that moved), is a new request and
//! step 5's replay rule holds unchanged.
//!
//! [`check_request_ids`] is a library function, not a step of the lifecycle:
//! the scheduler (orchestrator) calls it on the request it synthesises, and
//! each node's chain verifier (the step 4 hook under a queued intake) calls
//! it before step 5, each with the chain request id of the inputs it holds
//! itself, as the package's intake gives them (crate::intake: the non-secret-shared
//! request log under on-chain intake, the inputs it stored when it signed the
//! receipt under receipt intake). It runs for queued manifests only; a
//! direct request keeps its random field id, which nothing here checks, and
//! step 1 parses both kinds of id the same way (one field element). The core
//! lifecycle does not call this itself: the check belongs to the chain
//! verifier the node injects at step 4.
//!
//! The known answers are in `testvectors/chain_request_id.json`, with the
//! preimages and each request's on-chain intake request log
//! (`[tag, inputs..., user_nonce]`, which [`crate::intake::onchain::RequestInputs::plain`]
//! splits), for the Noir intake helpers and pss-client to check against.

use crate::receipt::RECEIPT_DOMAIN;
use sidecar_core::derived::Kind;
use sidecar_core::error::Refusal;
use sidecar_core::field::{Fr, fr_to_hex};
use sidecar_core::hash::poseidon2_hash;
use sidecar_core::request::{Request, View};

// PSS_ATTEMPT, the first element of the machine request id, is
// ASCII "sidecar.attempt" read as a big-endian integer, in the family of the
// machine's other domain elements (RESULT_DOMAIN "sidecar.result",
// REGISTRY_DOMAIN "sidecar.registry", the tip's RECEIPT_DOMAIN
// "sidecar.receipt"); the name is docs/ARCHITECTURE.md section 1's. It keeps a
// machine request id from equalling any other Poseidon2 digest the system
// computes over a field list, in particular a chain request id, whose first
// element is a contract address. The scheduler, every node's chain verifier
// and the tip's process_result (which rebuilds the signed request id) must
// agree on it; changing it changes every machine request id and every row and
// result keyed by one.
/// ASCII "sidecar.attempt".
pub const PSS_ATTEMPT: u128 = 0x736964656361722e617474656d7074;

/// ASCII "sidecar.summands": the first element of a summand commitment
/// (pss_core's `tip::intake::SUMMANDS_DOMAIN`).
pub const SUMMANDS_DOMAIN: u128 = 0x736964656361722e73756d6d616e6473;

/// ASCII "sidecar.sharing": the first element of a sharing digest
/// (pss_core's `tip::intake::SHARING_DOMAIN`).
pub const SHARING_DOMAIN: u128 = 0x736964656361722e73686172696e67;

/// The commitment to one summand vector of a secret-shared receipt
/// request, `S_j = poseidon2([SUMMANDS_DOMAIN, s_j..., salt_j])`: `s_j` the
/// j-th summand of every shared value in [`crate::CommitmentLayout::summand_names`] order
/// (C's shared values, then `$blinding`), `salt_j` its salt (pss_core's
/// `tip::intake::summand_commitment`).
pub fn summand_commitment(summands: &[Fr], salt: Fr) -> Fr {
    let mut fields = Vec::with_capacity(summands.len() + 2);
    fields.push(Fr::from(SUMMANDS_DOMAIN));
    fields.extend_from_slice(summands);
    fields.push(salt);
    poseidon2_hash(&fields)
}

/// The sharing digest of a secret-shared receipt request,
/// `D = poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kind_1, ..., kind_m,
/// clear_1, ..., clear_q])`: the three summand commitments, the kind of each
/// of C's values in C's order ([`crate::commitment_layout`]'s, clear 0 and
/// chosen 1) and the clear values in C's order (the clear app inputs
/// [`crate::intake_inputs`] gives), which every receipt signs (pss_core's
/// `tip::intake::sharing_digest`).
pub fn sharing_digest(commitments: &[Fr; 3], kinds: &[Kind], clear: &[Fr]) -> Fr {
    let mut fields = Vec::with_capacity(4 + kinds.len() + clear.len());
    fields.push(Fr::from(SHARING_DOMAIN));
    fields.extend_from_slice(commitments);
    fields.extend(kinds.iter().map(|k| k.field()));
    fields.extend_from_slice(clear);
    poseidon2_hash(&fields)
}

/// The receipt message under secret-shared receipt intake:
/// `poseidon2([RECEIPT_DOMAIN, request_id, c, expiry_block, d])`, with `c`
/// the inputs commitment and `d` the sharing digest ([`sharing_digest`]):
/// five elements, so it is never a receipt intake message
/// ([`crate::receipt_message`]; pss_public_contract's
/// `shared_receipt_message`).
pub fn shared_receipt_message(request_id: Fr, c: Fr, expiry_block: u32, d: Fr) -> Fr {
    poseidon2_hash(&[
        Fr::from(RECEIPT_DOMAIN),
        request_id,
        c,
        Fr::from(u64::from(expiry_block)),
        d,
    ])
}

/// The inputs commitment of a secret-shared intake:
/// `C = poseidon2([values..., blinding])`, `values` in the order of
/// [`crate::commitment_names`] (pss_core's `tip::intake::commit`).
pub fn inputs_commitment(values: &[Fr], blinding: Fr) -> Fr {
    let mut fields = values.to_vec();
    fields.push(blinding);
    poseidon2_hash(&fields)
}

/// The chain request id of a secret-shared intake: `poseidon2([namespace, vk_hash,
/// C])` (pss_core's `tip::intake::shared`).
pub fn shared_chain_request_id(namespace: Fr, vk_hash: Fr, c: Fr) -> Fr {
    poseidon2_hash(&[namespace, vk_hash, c])
}

// What the machine request id covers:
// `poseidon2([PSS_ATTEMPT, chain_request_id, old commitments..., pinned
// values...])`, the old commitments in `commitment_slot` key order and then
// the pinned values in the manifest's `public_reads` order (each read's
// value, then an epoch read's epoch); a circuit with no pinned reads appends
// nothing, so its id is the one without the pinned part. An attempt is fixed
// by the state it ran against and the pinned values it used; `apply` rechecks
// both, so when an oracle price moves while the state does not, the
// recompute at the new price must be a new request, or step 5 refuses it
// (409, another body under a request id it holds) and the queue waits for
// `skip()`. No length prefix or separator between the two lists is needed:
// the chain request id commits to the vk hash and to the app inputs
// (inputs_hash, whose sponge IV carries their count), so it fixes the circuit
// and the manifest's split of its PUBLIC parameters, hence R (old
// commitments) and Q (pinned values); two preimages that share the second
// element share R and Q, and preimages of different lengths already differ
// in the sponge's IV (len << 64). The scheduler, every node's chain verifier
// (with the values it admits), the orchestrator's FETCH binding, pss-client
// and `process_result` must all append the same values in the same order, or
// every result is refused; a recompute at a value the read's freshness policy
// no longer admits is a new request.
/// The machine request id of one attempt at a queued request:
/// `poseidon2([PSS_ATTEMPT, chain_request_id, old commitments..., pinned
/// values...])`, the old commitments in the order of
/// [`crate::TipManifest::old_commitments`] (key order of `commitment_slot`),
/// as the round's public outputs carry them, and the pinned values in the
/// order of [`crate::TipManifest::public_reads`]
/// ([`crate::TipPackage::pinned_fields`] and
/// [`crate::TipPackage::reads_of`] give them).
pub fn machine_request_id(chain_request_id: Fr, old_commitments: &[Fr], pinned: &[Fr]) -> Fr {
    let mut fields = Vec::with_capacity(old_commitments.len() + pinned.len() + 2);
    fields.push(Fr::from(PSS_ATTEMPT));
    fields.push(chain_request_id);
    fields.extend_from_slice(old_commitments);
    fields.extend_from_slice(pinned);
    poseidon2_hash(&fields)
}

/// Check both ids of a queued request against the values the caller holds
/// itself (`chain`, the chain request id the inputs it holds give under the
/// package, [`crate::TipPackage::chain_request_id`]; the namespace; the old
/// commitments of the state the round runs against and the pinned values it
/// read itself, in `public_reads` order) and refuse (400) a request whose
/// `namespace`, `chain_request_id` or `request_id` differs, naming the
/// field. It never trusts an id the request carries: the machine request id
/// is recomputed from the caller's chain request id. For a queued manifest
/// only (module documentation).
pub fn check_request_ids<V: View>(
    chain: Fr,
    namespace: Fr,
    old_commitments: &[Fr],
    pinned: &[Fr],
    request: &Request<V>,
) -> Result<(), Refusal> {
    if request.namespace.0 != namespace {
        return Err(Refusal::bad_request(format!(
            "field `namespace`: {} is not the namespace {} the queued request was read from",
            request.namespace,
            fr_to_hex(namespace)
        )));
    }
    let Some(carried) = request.chain_request_id else {
        return Err(Refusal::bad_request(
            "field `chain_request_id`: missing; a queued request carries the chain request id it answers",
        ));
    };
    if carried.0 != chain {
        return Err(Refusal::bad_request(format!(
            "field `chain_request_id`: {carried} differs from {}, the chain request id of the \
             inputs held",
            fr_to_hex(chain)
        )));
    }
    let attempt = machine_request_id(chain, old_commitments, pinned);
    if request.request_id.fr() != attempt {
        return Err(Refusal::bad_request(format!(
            "field `request_id`: {} differs from {}, the machine request id \
             poseidon2(PSS_ATTEMPT, chain_request_id, old commitments..., pinned values...) \
             of the chain request id, the {} old commitments and the {} pinned values held",
            request.request_id,
            fr_to_hex(attempt),
            old_commitments.len(),
            pinned.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{chain_request_id, inputs_hash};
    use serde_json::{Value, json};
    use sidecar_core::error::ErrorClass;
    use sidecar_core::field::{FieldHex, RequestId};
    use sidecar_core::request::Full;
    use sidecar_test_fixtures::dirs::repo;
    use sidecar_test_fixtures::vectors::hex;

    const VECTORS: &str = "testvectors/chain_request_id.json";

    // p - 1, the largest field element: a field-sized value in every position
    // the vectors cover.
    fn minus_one() -> Fr {
        Fr::from(0u64) - Fr::from(1u64)
    }

    struct Case {
        name: &'static str,
        namespace: Fr,
        vk_hash: Fr,
        inputs: Vec<Fr>,
        user_nonce: Fr,
        old_commitments: Vec<Fr>,
        pinned_reads: Vec<Fr>,
    }

    fn cases() -> Vec<Case> {
        let ns = hex("0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809");
        let vk = hex("0x2a8f1c0e9b7d6a5f4e3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6");
        vec![
            Case {
                // the AMM tip's swap: amount_in, direction
                name: "amm_swap_tip: two inputs, one old commitment",
                namespace: ns,
                vk_hash: vk,
                inputs: vec![Fr::from(5000u64), Fr::from(0u64)],
                user_nonce: Fr::from(1u64),
                old_commitments: vec![hex(
                    "0x2f00c0ffee000000000000000000000000000000000000000000000000000001",
                )],
                pinned_reads: vec![],
            },
            Case {
                // a lending-style round: the oracle price is a pinned read
                name: "three inputs (one full rate block), two old commitments, one pinned read",
                namespace: ns,
                vk_hash: vk,
                inputs: vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
                user_nonce: Fr::from(0xfeedu64),
                old_commitments: vec![Fr::from(0xaaaau64), Fr::from(0xbbbbu64)],
                pinned_reads: vec![Fr::from(2000u64)],
            },
            Case {
                name: "no inputs, no old commitments",
                namespace: Fr::from(0x1234u64),
                vk_hash: Fr::from(0xabcdu64),
                inputs: vec![],
                user_nonce: Fr::from(0u64),
                old_commitments: vec![],
                pinned_reads: vec![],
            },
            Case {
                name: "four inputs, field-sized values (p - 1) in every position",
                namespace: minus_one(),
                vk_hash: minus_one(),
                inputs: vec![minus_one(), Fr::from(7u64), minus_one(), Fr::from(9u64)],
                user_nonce: minus_one(),
                old_commitments: vec![minus_one()],
                pinned_reads: vec![],
            },
            Case {
                name: "two inputs, one old commitment, two pinned reads (the second p - 1)",
                namespace: ns,
                vk_hash: vk,
                inputs: vec![Fr::from(7u64), Fr::from(8u64)],
                user_nonce: Fr::from(2u64),
                old_commitments: vec![Fr::from(0xddddu64)],
                pinned_reads: vec![Fr::from(0x64u64), minus_one()],
            },
        ]
    }

    fn vectors() -> Value {
        let vectors: Vec<Value> = cases()
            .iter()
            .map(|c| {
                let chain = chain_request_id(c.namespace, c.vk_hash, &c.inputs, c.user_nonce);
                let mut log = vec![crate::chain::layout::request_log_tag(chain)];
                log.extend(&c.inputs);
                log.push(c.user_nonce);
                json!({
                    "name": c.name,
                    "namespace": FieldHex(c.namespace),
                    "vk_hash": FieldHex(c.vk_hash),
                    "inputs": c.inputs.iter().copied().map(FieldHex).collect::<Vec<_>>(),
                    "inputs_hash": FieldHex(inputs_hash(&c.inputs)),
                    "user_nonce": FieldHex(c.user_nonce),
                    "chain_request_id": FieldHex(chain),
                    "old_commitments": c.old_commitments.iter().copied().map(FieldHex).collect::<Vec<_>>(),
                    "pinned_reads": c.pinned_reads.iter().copied().map(FieldHex).collect::<Vec<_>>(),
                    "machine_request_id": FieldHex(machine_request_id(chain, &c.old_commitments, &c.pinned_reads)),
                    "request_log": log.into_iter().map(FieldHex).collect::<Vec<_>>(),
                })
            })
            .collect();
        json!({
            "hash": "poseidon2 is the width-4 sponge of docs/ARCHITECTURE.md section 1 (IV len << 64 in the capacity element; Noir std Poseidon2::hash, protocol_types poseidon2_hash, total-noir p2_hash, aztec.js poseidon2Hash)",
            "inputs_hash_rule": "poseidon2(inputs), the app's circuit inputs in ABI order",
            "chain_request_id_rule": "poseidon2([namespace, vk_hash, inputs_hash, user_nonce]); namespace the app contract's address, vk_hash the circuit's Config pin, user_nonce the request's random salt; no requester address",
            "machine_request_id_rule": "poseidon2([PSS_ATTEMPT, chain_request_id, old_commitments..., pinned_reads...]), the old commitments in commitment_slot key order, then the pinned public read values in public_reads order (none for a circuit without pinned reads); PSS_ATTEMPT = ASCII \"sidecar.attempt\" as a big-endian integer",
            "request_log_rule": "the on-chain intake request log the app's append_onchain emits from the namespace contract: [tag, inputs..., user_nonce], tag = compute_log_tag(chain_request_id, REQUEST_DOMAIN) (log_tags.json), no requester; read by sidecar-tip intake/onchain.rs RequestInputs::plain, pss-client intake-onchain.ts parsePlainRequestLog and pss_public_contract intake.nr (request_log_tag, then PlainRequest::serialize)",
            "pss_attempt": FieldHex(Fr::from(PSS_ATTEMPT)),
            "vectors": vectors,
        })
    }

    /// The committed vectors are what this code computes.
    #[test]
    fn chain_request_id_vectors_match() {
        let text = std::fs::read_to_string(repo().join(VECTORS)).unwrap();
        let committed: Value = serde_json::from_str(&text).unwrap();
        for v in committed["vectors"].as_array().unwrap() {
            let f = |k: &str| hex(v[k].as_str().unwrap());
            let list = |k: &str| -> Vec<Fr> {
                v[k].as_array()
                    .unwrap()
                    .iter()
                    .map(|x| hex(x.as_str().unwrap()))
                    .collect()
            };
            let inputs = list("inputs");
            assert_eq!(inputs_hash(&inputs), f("inputs_hash"));
            let chain = chain_request_id(f("namespace"), f("vk_hash"), &inputs, f("user_nonce"));
            assert_eq!(chain, f("chain_request_id"), "{}", v["name"]);
            assert_eq!(
                machine_request_id(chain, &list("old_commitments"), &list("pinned_reads")),
                f("machine_request_id"),
                "{}",
                v["name"]
            );
            // the request log: the chain reader looks it up by its tag and
            // splits the fields after it by the non-secret-shared layout
            let log = list("request_log");
            assert_eq!(log[0], crate::chain::layout::request_log_tag(chain));
            let read = crate::intake::onchain::RequestInputs {
                chain_request_id: chain,
                fields: log[1..].to_vec(),
                log: crate::chain::LogRef {
                    block: 1,
                    tx_hash: String::new(),
                    tx_index: 0,
                    log_index: 0,
                },
            };
            let plain = read.plain().unwrap();
            assert_eq!(plain.inputs, &inputs[..], "{}", v["name"]);
            assert_eq!(plain.user_nonce, f("user_nonce"), "{}", v["name"]);
        }
        assert_eq!(committed, vectors(), "rerun write_chain_request_id_vectors");
    }

    /// `cargo test -p sidecar-tip write_chain_request_id_vectors -- --ignored`.
    #[test]
    #[ignore = "writes testvectors/; run on purpose"]
    fn write_chain_request_id_vectors() {
        let text = serde_json::to_string_pretty(&vectors()).unwrap() + "\n";
        std::fs::write(repo().join(VECTORS), text).unwrap();
    }

    #[test]
    fn the_domain_is_ascii_sidecar_attempt() {
        assert_eq!(
            Fr::from(PSS_ATTEMPT),
            sidecar_core::keys::label_field(b"sidecar.attempt")
        );
    }

    /// The ids are the plain sponge over the stated lists.
    #[test]
    fn the_ids_hash_the_stated_preimages() {
        let c = &cases()[0];
        let ih = poseidon2_hash(&c.inputs);
        assert_eq!(inputs_hash(&c.inputs), ih);
        let chain = chain_request_id(c.namespace, c.vk_hash, &c.inputs, c.user_nonce);
        assert_eq!(
            chain,
            poseidon2_hash(&[c.namespace, c.vk_hash, ih, c.user_nonce])
        );
        let mut preimage = vec![Fr::from(PSS_ATTEMPT), chain];
        preimage.extend(&c.old_commitments);
        // no pinned reads: the id is the hash of the attempt and the olds alone
        assert_eq!(
            machine_request_id(chain, &c.old_commitments, &[]),
            poseidon2_hash(&preimage)
        );
        // a recompute against another state is another request
        assert_ne!(
            machine_request_id(chain, &c.old_commitments, &[]),
            machine_request_id(chain, &[Fr::from(1u64)], &[])
        );
        // the pinned values follow the old commitments
        let priced = &cases()[1];
        let chain = chain_request_id(
            priced.namespace,
            priced.vk_hash,
            &priced.inputs,
            priced.user_nonce,
        );
        let mut preimage = vec![Fr::from(PSS_ATTEMPT), chain];
        preimage.extend(&priced.old_commitments);
        preimage.extend(&priced.pinned_reads);
        let id = machine_request_id(chain, &priced.old_commitments, &priced.pinned_reads);
        assert_eq!(id, poseidon2_hash(&preimage));
        // the same state at another pinned value (a moved price) is another
        // request, and so is the same state without the pinned value
        assert_ne!(
            id,
            machine_request_id(chain, &priced.old_commitments, &[Fr::from(2001u64)])
        );
        assert_ne!(id, machine_request_id(chain, &priced.old_commitments, &[]));
        // The two lists are not separated: the same fields split otherwise
        // give the same id. The chain request id fixes the split (it commits
        // to the vk hash and the app inputs, so to the circuit's R old
        // commitments and Q pinned reads), so no holder ever compares two
        // splits under one chain request id (see `machine_request_id`).
        let (olds, last) = priced.old_commitments.split_at(1);
        let moved: Vec<Fr> = last.iter().chain(&priced.pinned_reads).copied().collect();
        assert_eq!(machine_request_id(chain, olds, &moved), id);
    }

    // The values a holder of the queued request has, and the request the
    // scheduler synthesises from them.
    struct Held {
        inputs: Vec<Fr>,
        user_nonce: Fr,
        vk_hash: Fr,
        namespace: Fr,
        olds: Vec<Fr>,
        pinned: Vec<Fr>,
    }

    impl Held {
        fn new() -> Self {
            let c = cases().remove(1);
            Held {
                inputs: c.inputs,
                user_nonce: c.user_nonce,
                vk_hash: c.vk_hash,
                namespace: c.namespace,
                olds: c.old_commitments,
                pinned: c.pinned_reads,
            }
        }

        fn request(&self) -> Request<Full> {
            let chain =
                chain_request_id(self.namespace, self.vk_hash, &self.inputs, self.user_nonce);
            Request::<Full>::from_json(
                &json!({
                    "namespace": FieldHex(self.namespace),
                    "circuit": "amm_swap_tip",
                    "request_id": FieldHex(machine_request_id(chain, &self.olds, &self.pinned)),
                    "chain_request_id": FieldHex(chain),
                })
                .to_string(),
            )
            .unwrap()
        }

        fn check(&self, request: &Request<Full>) -> Result<(), Refusal> {
            let chain =
                chain_request_id(self.namespace, self.vk_hash, &self.inputs, self.user_nonce);
            check_request_ids(chain, self.namespace, &self.olds, &self.pinned, request)
        }
    }

    fn refused(result: Result<(), Refusal>, field: &str) {
        let err = result.unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
        assert!(
            err.message.starts_with(&format!("field `{field}`: ")),
            "{err}"
        );
    }

    #[test]
    fn a_correct_pair_is_accepted() {
        let held = Held::new();
        held.check(&held.request()).unwrap();
        // a request with no old commitments (a round that loads no chain key)
        let mut none = Held::new();
        none.olds.clear();
        none.check(&none.request()).unwrap();
        // and one with no pinned reads
        let mut unpinned = Held::new();
        unpinned.pinned.clear();
        unpinned.check(&unpinned.request()).unwrap();
    }

    /// A request built from substituted values is refused by a holder of the
    /// real ones, naming the request field whose id differs.
    #[test]
    fn a_substituted_value_is_refused_naming_the_field() {
        let held = Held::new();
        type Edit = fn(&mut Held);
        let substitutions: [(&str, Edit, &str); 8] = [
            (
                "an input",
                |h| h.inputs[0] += Fr::from(1u64),
                "chain_request_id",
            ),
            (
                "an input appended",
                |h| h.inputs.push(Fr::from(0u64)),
                "chain_request_id",
            ),
            (
                "the vk hash (another circuit)",
                |h| h.vk_hash += Fr::from(1u64),
                "chain_request_id",
            ),
            (
                "the nonce",
                |h| h.user_nonce += Fr::from(1u64),
                "chain_request_id",
            ),
            (
                "an old commitment",
                |h| h.olds[0] += Fr::from(1u64),
                "request_id",
            ),
            (
                "an old commitment dropped",
                |h| h.olds.clear(),
                "request_id",
            ),
            (
                "a pinned value (a moved price)",
                |h| h.pinned[0] += Fr::from(1u64),
                "request_id",
            ),
            ("a pinned value dropped", |h| h.pinned.clear(), "request_id"),
        ];
        for (what, edit, field) in substitutions {
            let mut other = Held::new();
            edit(&mut other);
            let req = other.request();
            let err = held.check(&req).unwrap_err();
            assert!(
                err.message.starts_with(&format!("field `{field}`: ")),
                "{what}: {err}"
            );
            assert_eq!(err.class, ErrorClass::BadRequest, "{what}");
        }

        // A substituted namespace: the request names another namespace, or
        // carries the ids of another namespace under this one.
        let mut other = Held::new();
        other.namespace += Fr::from(1u64);
        refused(held.check(&other.request()), "namespace");
        let mut moved = other.request();
        moved.namespace = FieldHex(held.namespace);
        refused(held.check(&moved), "chain_request_id");

        // ids the request carries are never trusted: a right chain request id
        // with a request id of another attempt, a missing chain request id,
        // or the chain request id used as the request id
        let mut req = held.request();
        req.request_id = RequestId(req.request_id.fr() + Fr::from(1u64));
        refused(held.check(&req), "request_id");
        let mut req = held.request();
        req.chain_request_id = None;
        refused(held.check(&req), "chain_request_id");
        let mut req = held.request();
        req.request_id = RequestId(req.chain_request_id.unwrap().0);
        refused(held.check(&req), "request_id");
    }

    /// Step 1 is unchanged by the tip: every request id, direct or queued, is
    /// one field element, so a field-sized id parses and one at or above the
    /// modulus is refused there (sidecar-core's
    /// `request::tests::request_id_must_be_a_field_element` covers the
    /// refusals); nothing here checks a direct request's random id.
    #[test]
    fn step_one_parses_both_kinds_of_id_alike() {
        let held = Held::new();
        let body =
            |id: &str| json!({"namespace": "0x1", "circuit": "c", "request_id": id}).to_string();
        let machine = held.request().request_id;
        let parsed = Request::<Full>::from_json(&body(&machine.to_string())).unwrap();
        assert_eq!(parsed.request_id, machine);
        Request::<Full>::from_json(&body("0x000102030405060708090a0b0c0d0e0f")).unwrap();
        let err = Request::<Full>::from_json(&body(
            "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        ))
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(err.message.contains("request_id"), "{err}");
    }

    // The sharing domains are their ASCII labels; D is the stated sponge
    // and binds each S_j's place, every kind and every clear value
    // (pss_core's `the_sharing_digest_binds_the_commitments_the_layout_and_the_clear_values`).
    #[test]
    fn the_sharing_digest_binds_the_commitments_the_layout_and_the_clear_values() {
        use sidecar_core::keys::label_field;
        assert_eq!(Fr::from(SUMMANDS_DOMAIN), label_field(b"sidecar.summands"));
        assert_eq!(Fr::from(SHARING_DOMAIN), label_field(b"sidecar.sharing"));
        let f = |x: u64| Fr::from(x);
        let s = [f(1), f(2), f(3)];
        let layout = [Kind::Clear, Kind::Chosen, Kind::Chosen];
        let d = sharing_digest(&s, &layout, &[f(7)]);
        assert_eq!(
            d,
            poseidon2_hash(&[
                Fr::from(SHARING_DOMAIN),
                f(1),
                f(2),
                f(3),
                f(0),
                f(1),
                f(1),
                f(7)
            ])
        );
        assert_ne!(d, sharing_digest(&[f(2), f(1), f(3)], &layout, &[f(7)]));
        assert_ne!(d, sharing_digest(&s, &layout, &[f(8)]));
        let moved = [Kind::Chosen, Kind::Clear, Kind::Chosen];
        assert_ne!(d, sharing_digest(&s, &moved, &[f(7)]));
    }
}
