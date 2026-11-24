//! Steps 1 to 4 of the lifecycle, which the node and the orchestrator
//! share.

use super::*;

// ---------------------------------------------------------------------------
// Steps 1 to 4, shared by the node and the orchestrator
// ---------------------------------------------------------------------------

/// Step 3 without the lock: the package (absent or disabled: 400), and the key
/// counts against its manifest (400).
pub(super) fn resolve_package<V: View, R: StoreRead + ?Sized>(
    registry: &R,
    req: &Request<V>,
) -> Result<PackageRow, Refusal> {
    registry::resolve(
        registry,
        req.namespace.fr(),
        &req.circuit,
        req.manifest_hash.map(FieldHex::fr),
    )
}

pub(super) fn check_key_counts<V: View>(
    req: &Request<V>,
    manifest: &Manifest,
) -> Result<(), Refusal> {
    for (list, keys, want) in [
        ("reads", &req.state_keys.reads, manifest.state_keys.reads),
        ("writes", &req.state_keys.writes, manifest.state_keys.writes),
    ] {
        if keys.len() != want {
            return Err(Refusal::bad_request(format!(
                "field `state_keys.{list}`: circuit `{}` takes {want} key(s), the request has {}",
                manifest.circuit,
                keys.len()
            )));
        }
    }
    Ok(())
}

/// Step 3: `chain_request_id` and `manifest_hash` against the manifest's
/// intake ([`crate::intake::IntakeRules::check_tip_fields`]; 400).
pub(super) fn check_tip_fields<V: View>(
    req: &Request<V>,
    manifest: &Manifest,
) -> Result<(), Refusal> {
    manifest.intake.rules().check_tip_fields(
        &req.circuit,
        crate::intake::TipFields {
            chain_request_id: req.chain_request_id.is_some(),
            manifest_hash: req.manifest_hash.is_some(),
        },
    )
}

/// The request key a key reference names (a fixed key's own name).
pub(super) fn key_of<V: View>(req: &Request<V>, keyref: KeyRef) -> &str {
    match keyref {
        KeyRef::Read(i) => &req.state_keys.reads[i],
        KeyRef::Write(j) => &req.state_keys.writes[j],
        KeyRef::Fixed(k) => k.name(),
    }
}

// The step order puts authentication after resolution. The signature
// requirement depends on the manifest (under intake direct a request needs a
// requester signature when it supplies a client-held record, stores a
// client-held key or carries a shared input), so the node must know the
// circuit before it can tell whether an unsigned request is acceptable; and
// resolution loads nothing (only the package row, which is public), so
// checking the signature after it opens no value to an unauthenticated
// request. Every record is opened only at step 8,
// after the signature, and only for the signer as owner. The replay check
// follows authentication, so a replayed body answers with the stored result
// only to a request that would itself be accepted.
//
// A request that carries a shared input is signed too. Each envelope's
// associated data covers the body without `shared_inputs`, so whoever holds
// the body (the orchestrator does) can seal a pair of its own for one input
// under the same associated data and swap it in beside the client's other
// inputs; only `body_hash`, over every share hash, tells the two bodies
// apart. The signature binds the client to that hash, and `requester` is
// part of the body every envelope's associated data covers: re-signing under
// another key changes `requester`, and then none of the client's envelopes
// opens. What is left to a party without the client's key is a request whose
// every shared input it sealed itself, which it could send as any client.
// Only intake direct ([`crate::intake::DirectIntake`]) authenticates this
// way; a queued intake binds its shared inputs to the chain request instead
// (the inputs commitment C).
/// Step 4 under intake direct: the requester's key when the request needs one,
/// after its signature over [`Request::signed_message`] verified. It needs one
/// when it supplies a record of, or stores, a key whose holder needs a
/// requester ([`StateHolder::needs_requester`]), or carries a shared input.
/// 400 without `requester`; 403 without a signature or with one that does not
/// verify.
pub(crate) fn authenticate<V: View>(
    req: &Request<V>,
    manifest: &Manifest,
    holding: &Holding,
) -> Result<Option<Point>, Refusal> {
    let signs = |keyref: KeyRef| holding.get(keyref).filter(|h| h.needs_requester());
    let supplies = holding.iter().find_map(|(keyref, _)| {
        let supplied = req
            .records
            .iter()
            .any(|r| V::record_key(r) == key_of(req, keyref));
        signs(keyref).filter(|_| supplied)
    });
    let stores = manifest.outputs.iter().find_map(|o| signs(o.store));
    let why = match (supplies, stores, req.shared_inputs.first()) {
        (Some(h), _, _) => format!("supplies a {} record", h.noun()),
        (None, Some(h), _) => format!("stores a {} key", h.noun()),
        (None, None, Some(input)) => {
            format!("carries the shared input `{}`", V::shared_input_name(input))
        }
        (None, None, None) => return Ok(None),
    };
    let requester = req.requester.ok_or_else(|| {
        Refusal::bad_request(format!(
            "field `requester`: missing; circuit `{}` {why}",
            manifest.circuit
        ))
    })?;
    let signature = req.signature.ok_or_else(|| {
        Refusal::forbidden(format!(
            "field `signature`: missing; a request that {why} is signed by its requester"
        ))
    })?;
    if !crate::schnorr::verify_wire(&requester, signature, req.signed_message()) {
        return Err(Refusal::forbidden(
            "field `signature`: does not verify under `requester` over the request body",
        ));
    }
    point_from_wire(&requester)
        .map(Some)
        .map_err(Refusal::forbidden)
}

/// Steps 1 to 4 as the orchestrator runs them on the full request, without the
/// namespace lock and before fan-out: the parse checks, `admit`, resolution
/// against the orchestrator's copy of the registry (`packages`), the key
/// counts, and the intake's step 4 without a node
/// ([`crate::intake::IntakeRules::authenticate_unlocked`]: the requester
/// signature under intake direct; nothing under a queued intake, whose chain
/// verifier is the nodes' alone). Returns the manifest and shape the
/// orchestrator verifies the nodes' answers with.
pub fn stateless_prefix<R: StoreRead + ?Sized>(
    req: &Request,
    registry: &R,
) -> Result<(Manifest, CircuitShape), Refusal> {
    req.validate()?;
    crate::admit::admit(req)?;
    let pkg = resolve_package(registry, req)?;
    let (manifest, shape) = pkg.parse()?;
    check_key_counts(req, &manifest)?;
    check_tip_fields(req, &manifest)?;
    manifest
        .intake
        .rules()
        .authenticate_unlocked(req, &manifest)?;
    Ok((manifest, shape))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{EnvelopeAd, seal_envelope_with};
    use crate::error::ErrorClass;
    use crate::grumpkin::{Fq, point_to_wire};
    use crate::keys::tests::sample_keys;
    use crate::manifest::Intake;
    use crate::request::{Full, SharedInput};
    use crate::schnorr::{public_key, sign};
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;
    use serde_json::json;

    const NAMES: [&str; 2] = ["door", "door_randomness"];

    // Monty Hall's open_door round with its game state node-held: shared
    // inputs and no client-held key, so only the shared inputs ask for a
    // signature.
    fn node_held_manifest() -> Manifest {
        Manifest::parse(&json!({
            "manifest": 1,
            "circuit": "monty_hall_open_door",
            "namespace_param": "namespace",
            "state_keys": {"reads": 1, "writes": 1},
            "witness": [
                {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
                {"param": "in_slots", "from": {"PUBLIC": ["$state_keys.reads[0]"]}},
                {"param": "door", "from": {"INPUT_SHARED": "door"}},
                {"param": "door_randomness", "from": {"INPUT_SHARED": "door_randomness"}},
                {"param": "in0_fields", "from": {"LOAD": "$state_keys.reads[0]", "slice": [0, 10], "len": 10}}
            ],
            "outputs": [{"TACEO_store": "out0", "STORE": "$state_keys.writes[0]", "len": 10,
                "note_hash": "new_note_hashes[0]"}]
        }))
        .unwrap()
    }

    // The request before any input is sealed: what the client has, and what
    // the orchestrator sees of it, the requester `who` named.
    fn body(who: Fq) -> Request<Full> {
        let mut req: Request<Full> = Request::from_json(
            &json!({
                "namespace": "0x1f2ea9c0",
                "circuit": "monty_hall_open_door",
                "request_id": "0x41d3000000000000000000000000beef",
                "state_keys": {"reads": ["0xb001"], "writes": ["0xb001"]}
            })
            .to_string(),
        )
        .unwrap();
        req.requester = Some(point_to_wire(public_key(who)));
        req
    }

    // Seal input `k` afresh to every node under the request's associated
    // data: anyone who holds the body and the nodes' public keys can.
    fn seal(req: &mut Request<Full>, k: usize, pair: [u64; 2], seed: u64) {
        let ad = EnvelopeAd::for_input(req, NAMES[k]);
        let shares = [0, 1, 2].map(|i| {
            seal_envelope_with(
                sample_keys(i).enc_pk(),
                i,
                &ad,
                pair.map(Fr::from),
                Fr::from(seed * 10 + i as u64 + 1),
            )
        });
        let input = SharedInput {
            name: NAMES[k].to_string(),
            share_hashes: shares.map(|s| FieldHex(s.hash())),
            shares,
        };
        match req.shared_inputs.get_mut(k) {
            Some(slot) => *slot = input,
            None => req.shared_inputs.push(input),
        }
    }

    fn signed(mut req: Request<Full>, signer: Fq) -> Request<Full> {
        req.signature = Some(sign(
            signer,
            req.signed_message(),
            &mut StdRng::seed_from_u64(9),
        ));
        req
    }

    // Whether every node opens its envelope of every input.
    fn opens(req: &Request<Full>) -> Result<(), Refusal> {
        for i in 0..NODES {
            let node = req.project(i);
            node.check_own_ciphertexts(i)?;
            for name in NAMES {
                Intake::Direct
                    .share_source()
                    .share(&sample_keys(i), i, &node, name)?;
            }
        }
        Ok(())
    }

    // Under intake direct a request that carries a shared input is signed by
    // its requester, so the orchestrator, which holds the body, cannot swap
    // in a pair of its own beside the client's other inputs: resealed under
    // the same associated data it opens, but the client's signature no
    // longer verifies; re-signed under the orchestrator's key, `requester`
    // changes, and the client's own envelopes no longer open.
    #[test]
    fn a_sibling_input_resealed_from_the_body_is_refused() {
        let manifest = node_held_manifest();
        let holding = StateHolders::core().choose(&manifest).unwrap();
        let auth = |r: &Request<Full>| authenticate(r, &manifest, &holding);
        let (client, orchestrator) = (Fq::from(5u64), Fq::from(7u64));

        let mut req = body(client);
        seal(&mut req, 0, [1, 2], 1);
        seal(&mut req, 1, [3, 4], 2);
        opens(&req).unwrap();

        // Unsigned: refused.
        let mut anonymous = req.clone();
        anonymous.requester = None;
        let err = auth(&anonymous).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
        assert!(
            err.message.contains("field `requester`: missing")
                && err.message.contains("carries the shared input `door`"),
            "{err}"
        );
        let err = auth(&req).unwrap_err();
        assert_eq!(err.class, ErrorClass::Forbidden, "{err}");
        assert!(err.message.contains("field `signature`: missing"), "{err}");

        let req = signed(req, client);
        assert_eq!(auth(&req).unwrap(), Some(public_key(client)));

        // Another request's envelopes of one input do not open here.
        let mut other = body(client);
        other.request_id = "0x41d3000000000000000000000000cafe".parse().unwrap();
        seal(&mut other, 0, [1, 2], 3);
        seal(&mut other, 1, [5, 6], 4);
        let mut swapped = req.clone();
        swapped.shared_inputs[1] = other.shared_inputs[1].clone();
        let err = opens(&swapped).unwrap_err();
        assert!(
            err.message.contains("`door_randomness`") && err.message.contains("does not decrypt"),
            "{err}"
        );

        // A pair the orchestrator seals from the body alone opens beside the
        // client's `door`, and the client's signature refuses the body.
        let mut resealed = req.clone();
        seal(&mut resealed, 1, [5, 6], 5);
        assert_eq!(resealed.input_body_hash(), req.input_body_hash());
        opens(&resealed).unwrap();
        let err = auth(&resealed).unwrap_err();
        assert_eq!(err.class, ErrorClass::Forbidden, "{err}");
        assert!(
            err.message.contains("does not verify under `requester`"),
            "{err}"
        );

        // Re-signed under the orchestrator's own key: it authenticates, and
        // the client's `door` envelopes no longer open.
        let mut taken = resealed;
        taken.requester = Some(point_to_wire(public_key(orchestrator)));
        seal(&mut taken, 1, [5, 6], 6);
        let taken = signed(taken, orchestrator);
        assert_eq!(auth(&taken).unwrap(), Some(public_key(orchestrator)));
        let err = opens(&taken).unwrap_err();
        assert!(
            err.message.contains("`door`") && err.message.contains("does not decrypt"),
            "{err}"
        );

        // A request without shared inputs or client-held keys needs none.
        let mut plain = body(client);
        plain.requester = None;
        assert_eq!(auth(&plain).unwrap(), None);
    }
}
