//! The session handshake (lifecycle step 10): one exchange between the three
//! nodes before witness extension, so they run one request on one body and hold
//! one consistent sharing of every shared value.
//!
//! Node i holds the pair `(x_i, x_{i-1})` of every shared element: `a = x_i`,
//! which node i+1 also holds as its `b`, and `b = x_{i-1}`, which node i-1 also
//! holds as its `a`. Node i sends each neighbour one [`HandshakeMessage`]:
//!
//! ```text
//! to node i+1:  request_id, body_hash, [poseidon2([request_id, a]) for every summand]
//! to node i-1:  request_id, body_hash, [poseidon2([request_id, b]) for every summand]
//! ```
//!
//! and checks that the message from node i-1 carries the hashes of its own `b`
//! values and the message from node i+1 the hashes of its own `a` values.
//! The summands are listed in one fixed order: the shared inputs in manifest
//! order, then every vector the round loaded, in key-reference order
//! (`$state_keys.reads[0]`, `[1]`, ..., then the fixed key `nsk_app`), element by
//! element: client-held records, node-held `values` rows and the namespace's
//! `nsk_app` share alike (a public element contributes its value in both
//! directions).
//!
//! [`exchange`] runs the handshake over an open session in two rounds, each
//! message one JSON frame, with next = i+1 and prev = i-1 (mod 3), the same
//! neighbours Rep3's reshare uses:
//!
//! ```text
//! round 1  send next: message_to_next()      send prev: message_to_prev()
//!          recv prev, recv next              check(from_prev, from_next)
//! round 2  send next and prev: Verdict       recv prev, recv next
//! ```
//!
//! A session goes on only when all three verdicts accept; otherwise every node
//! refuses (400) before witness extension or any SAMPLE.
//!
//! A node that refused the request before the session ([`exchange_refusing`])
//! still runs both rounds: its messages carry `refused: true` and no summand
//! hashes, its neighbours check only its request id and body hash, and its
//! verdict refuses, so they answer "node N refused the request: why".

use mpc_net::Network;
use mpc_net::bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::abi::CircuitShape;
use crate::bind::{Bound, Elem, Share};
use crate::envelope::request_id_field;
use crate::error::{Refusal, parse_json};
use crate::field::{FieldHex, Fr, RequestId};
use crate::hash::poseidon2_hash;
use crate::manifest::{Manifest, Source};
use crate::request::{next, prev};
use crate::state::Holding;

/// What node i sends one neighbour: the request it is running, the body hash,
/// and the hash of every summand it shares with that neighbour.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeMessage {
    pub request_id: RequestId,
    pub body_hash: FieldHex,
    pub summand_hashes: Vec<FieldHex>,
    /// Set by a node that refused the request before the session: it sends
    /// no summand hashes, and its verdict refuses.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub refused: bool,
}

impl HandshakeMessage {
    pub fn from_json(text: &str) -> Result<Self, Refusal> {
        parse_json(text)
    }
}

/// The hash of one shared summand as the handshake carries it:
/// `poseidon2([request_id, summand])`.
pub fn summand_hash(request_id: &RequestId, summand: Fr) -> Fr {
    poseidon2_hash(&[request_id_field(request_id), summand])
}

/// Node i's side of the handshake: what it sends each neighbour, and what it
/// expects back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub request_id: RequestId,
    pub body_hash: Fr,
    /// Hashes of this node's `a` summands (`x_i`), shared with node i+1.
    pub summand_hashes_to_next: Vec<Fr>,
    /// Hashes of this node's `b` summands (`x_{i-1}`), shared with node i-1.
    pub summand_hashes_to_prev: Vec<Fr>,
    /// What each position is, for refusals: "shared input `door`",
    /// "record `0xb001` element 3".
    labels: Vec<String>,
}

impl Handshake {
    /// Build node i's handshake from the opened pairs, already in the fixed
    /// order: `inputs` are the shared inputs' pairs in manifest order,
    /// `records` the opened vectors of the client-held records in manifest key
    /// order.
    pub fn build(
        request_id: RequestId,
        body_hash: Fr,
        inputs: &[(&str, Share)],
        records: &[(&str, &[Elem])],
    ) -> Self {
        let loaded: Vec<(String, &[Elem])> = records
            .iter()
            .map(|(key, vec)| (format!("record `{key}`"), *vec))
            .collect();
        Self::with_loads(request_id, body_hash, inputs, &loaded)
    }

    /// Build node i's handshake over vectors it holds itself (an audit
    /// round's, or a resync check's), each labelled for refusals by the
    /// name given with it, element by element in the order given.
    pub fn of_values(request_id: RequestId, body_hash: Fr, values: &[(String, &[Elem])]) -> Self {
        Self::with_loads(request_id, body_hash, &[], values)
    }

    // The handshake over the shared inputs, then each loaded vector element by
    // element; each load's label names the vector in refusals.
    fn with_loads(
        request_id: RequestId,
        body_hash: Fr,
        inputs: &[(&str, Share)],
        loads: &[(String, &[Elem])],
    ) -> Self {
        let mut hs = Handshake {
            request_id,
            body_hash,
            summand_hashes_to_next: Vec::new(),
            summand_hashes_to_prev: Vec::new(),
            labels: Vec::new(),
        };
        let mut push = |label: String, a: Fr, b: Fr| {
            hs.summand_hashes_to_next.push(summand_hash(&request_id, a));
            hs.summand_hashes_to_prev.push(summand_hash(&request_id, b));
            hs.labels.push(label);
        };
        for (name, share) in inputs {
            push(format!("shared input `{name}`"), share.a, share.b);
        }
        for (what, vec) in loads {
            for (j, elem) in vec.iter().enumerate() {
                let label = format!("{what} element {j}");
                match elem {
                    Elem::Shared(share) => push(label, share.a, share.b),
                    Elem::Public(v) => push(label, *v, *v),
                }
            }
        }
        hs
    }

    /// Build node i's handshake from what the binder bound: the INPUT_SHARED
    /// parameters in manifest order, then every read in key-reference order
    /// (`$state_keys.reads[0]`, `[1]`, ..., then `nsk_app`), whatever its state
    /// mode. A read is labelled by its holder in `holding`
    /// ([`crate::state::StateHolder::summand`]: "record `key`", "value
    /// `key`", or no summand for a key read in the session), the fixed key
    /// by its name.
    pub fn from_bound(
        request_id: RequestId,
        body_hash: Fr,
        shape: &CircuitShape,
        manifest: &Manifest,
        holding: &Holding,
        bound: &Bound,
    ) -> Self {
        let inputs: Vec<(&str, Share)> = manifest
            .witness
            .iter()
            .filter_map(|entry| match &entry.from {
                Source::InputShared(name) => Some((entry.param.as_str(), name.as_str())),
                _ => None,
            })
            .map(|(param, name)| {
                let key = &shape
                    .param(param)
                    .expect("the shape has every parameter")
                    .keys[0];
                match bound.input[key] {
                    Elem::Shared(share) => (name, share),
                    Elem::Public(_) => unreachable!("INPUT_SHARED binds a share"),
                }
            })
            .collect();
        // Each holder labels its key's summands; a key read inside the
        // session (an in-session holder) has none here: its values are
        // produced jointly after the handshake.
        let mut reads: Vec<_> = bound
            .reads
            .iter()
            .filter_map(|read| {
                let what = match holding.get(read.keyref) {
                    Some(holder) => holder.summand(&read.key)?,
                    None if read.keyref.is_fixed() => read.key.clone(),
                    None => format!("record `{}`", read.key),
                };
                Some((read.keyref, what, read.value.as_slice()))
            })
            .collect();
        reads.sort_by_key(|(keyref, _, _)| *keyref);
        let loads: Vec<(String, &[Elem])> = reads
            .into_iter()
            .map(|(_, what, value)| (what, value))
            .collect();
        Self::with_loads(request_id, body_hash, &inputs, &loads)
    }

    /// The message for node i+1.
    pub fn message_to_next(&self) -> HandshakeMessage {
        self.message(&self.summand_hashes_to_next)
    }

    /// The message for node i-1.
    pub fn message_to_prev(&self) -> HandshakeMessage {
        self.message(&self.summand_hashes_to_prev)
    }

    fn message(&self, hashes: &[Fr]) -> HandshakeMessage {
        HandshakeMessage {
            request_id: self.request_id,
            body_hash: FieldHex(self.body_hash),
            summand_hashes: hashes.iter().copied().map(FieldHex).collect(),
            refused: false,
        }
    }

    // What the handshake refuses, all as 400 before witness
    // extension: a neighbour running another request id, or the same id with
    // another body hash (two bodies under one id, or a tampered projection),
    // and any summand whose hash differs from the neighbour's. The summands are
    // every Rep3 pair the two neighbours both hold: envelopes, opened
    // client-held records, node-held `values` rows and the `nsk_app` share.
    // For envelopes and records the cause is a client that gave the nodes
    // inconsistent pairs, or mixed the thirds of two records into one request;
    // the client is untrusted, and inconsistent pairs would let it make a
    // round fail or succeed depending on secret data and learn from which
    // happened. For node-held rows and nsk_app the cause is a store that
    // diverged without any attacker: a commit that failed on one node while
    // the other two committed, or a rollback run on two nodes and not the
    // third. Covering them turns every later round on that key from a full
    // MPC round that fails at self-verification or the orchestrator's
    // agreement check, naming nothing, into a 400 at step 10 that names the
    // key, so the operator knows which node to repair. Each summand hash goes
    // only to the neighbour that already holds that summand: sending both
    // lists to both neighbours would let a node holding two summands of a
    // low-entropy value (a door in 0..3) recover it by trying each candidate
    // against the third summand's hash. The request id inside each hash keeps
    // a hash from one request useless in another. Sampled values are still not
    // checked: the nodes' correlated randomness makes them consistent by
    // construction, and the samples are drawn only after the handshake.
    /// Check the messages node i received from node i-1 (`from_prev`) and node
    /// i+1 (`from_next`). Refuses (400) naming the first mismatch: the request
    /// id, the body hash, the number of summands, or the summand. The summands
    /// of a neighbour that refused the request before the session (its
    /// message's `refused`) are not compared: it sent none, and its verdict
    /// refuses.
    pub fn check(
        &self,
        from_prev: &HandshakeMessage,
        from_next: &HandshakeMessage,
    ) -> Result<(), Refusal> {
        for (who, msg) in [("previous", from_prev), ("next", from_next)] {
            if msg.request_id != self.request_id {
                return Err(refuse(format!(
                    "the {who} node runs request {}, this node {}",
                    msg.request_id, self.request_id
                )));
            }
            if msg.body_hash.fr() != self.body_hash {
                return Err(refuse(format!(
                    "the {who} node's body hash differs from this node's"
                )));
            }
        }
        for (who, msg, mine) in [
            ("previous", from_prev, &self.summand_hashes_to_prev),
            ("next", from_next, &self.summand_hashes_to_next),
        ] {
            if msg.refused {
                continue;
            }
            if msg.summand_hashes.len() != mine.len() {
                return Err(refuse(format!(
                    "the {who} node holds {} shared summands, this node {}",
                    msg.summand_hashes.len(),
                    mine.len()
                )));
            }
            if let Some(k) = (0..mine.len()).find(|&k| msg.summand_hashes[k].fr() != mine[k]) {
                return Err(refuse(format!(
                    "{} is not shared consistently with the {who} node",
                    self.labels[k]
                )));
            }
        }
        Ok(())
    }
}

const PREFIX: &str = "session handshake: ";

fn refuse(why: String) -> Refusal {
    Refusal::bad_request(format!("{PREFIX}{why}"))
}

/// What each node tells both neighbours after checking their handshake
/// messages (the second round of [`exchange`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub accepted: bool,
    /// Why this node refused, when `accepted` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

// The verdict round, what it carries and how long it waits. The
// first round's checks are local: when one node's summand differs from one
// neighbour's, those two refuse and the third node's checks pass, and without
// a second round the third node would go on to witness extension on a mesh
// the other two have left and fail later with a transport error (500). So
// every node then sends both neighbours its verdict, and a refusal at any node
// refuses the request 400 at all three before anything is computed. A
// refusing verdict carries the text of the refusal (it names the mismatched
// position, such as "shared input `door`", never a value), so the third
// node's answer and log say which node refused and why; the text is the
// refusing node's own, so "previous" and "next" in it are from that node's
// side. The verdict has no timeout of its own: it waits as long as any
// receive on the session (the transport's I/O timeout; operator knob:
// DESIGN.md, "Configuration reference" (the mesh config's `timeout`)). A peer
// whose message does not parse, or that does not answer, fails the session
// with 500: that is a broken or incompatible node, not a bad request.
/// Lifecycle step 10 over an open session `net`: send each neighbour its
/// handshake message, check what both sent, then exchange verdicts with both.
///
/// Refuses (400) when this node's own check fails ([`Handshake::check`] names
/// the mismatch) or when a neighbour's verdict refuses ("node N refused the
/// request: why"); fails (500) when a frame cannot be sent or received or does
/// not parse. Every node sends its verdict even when its own check failed, so
/// the other two learn of the refusal instead of waiting.
pub fn exchange<N: Network>(net: &N, handshake: &Handshake) -> Result<(), Refusal> {
    run(net, handshake, None)
}

/// Step 10 for a node that refused the request before the session, by a
/// check that needs no mesh: it takes part in the handshake with `refusal` as
/// its verdict, so its neighbours, which passed their own checks and opened
/// the session, refuse 400 at the handshake ("node N refused the request:
/// why") instead of failing on a mesh this node never joined. Its messages
/// carry `refused` and no summand hashes (build `handshake` with none): a
/// node refused before it loaded anything has none to send. Returns
/// `refusal`, whatever the session did.
pub fn exchange_refusing<N: Network>(net: &N, handshake: &Handshake, refusal: Refusal) -> Refusal {
    let _ = run(net, handshake, Some(&refusal));
    refusal
}

fn run<N: Network>(
    net: &N,
    handshake: &Handshake,
    refused: Option<&Refusal>,
) -> Result<(), Refusal> {
    let me = net.id();
    let (next, prev) = (next(me), prev(me));

    let flagged = |mut msg: HandshakeMessage| {
        msg.refused = refused.is_some();
        msg
    };
    send_json(
        net,
        next,
        "handshake",
        &flagged(handshake.message_to_next()),
    )?;
    send_json(
        net,
        prev,
        "handshake",
        &flagged(handshake.message_to_prev()),
    )?;
    let from_prev: HandshakeMessage = recv_json(net, prev, "handshake message")?;
    let from_next: HandshakeMessage = recv_json(net, next, "handshake message")?;
    let refused_before = [(prev, from_prev.refused), (next, from_next.refused)];
    let mine = match refused {
        Some(refusal) => Err(refusal.clone()),
        None => handshake.check(&from_prev, &from_next),
    };

    verdicts(net, mine)?;
    // A node that said it refused, sent no summands, and then accepted is
    // broken: its summands were never checked.
    if let Some((peer, _)) = refused_before.iter().find(|(_, r)| *r) {
        return Err(Refusal::mpc_failure(format!(
            "MPC session: node {peer} refused the request in its handshake message and \
             accepted it in its verdict"
        )));
    }
    Ok(())
}

/// The verdict round over an open session: send both neighbours this
/// node's verdict (`mine`, its refusal's text without [`PREFIX`]), then
/// receive theirs. Ok only when all three accept. This node's own refusal
/// wins, even over a neighbour that went away after it; else the first
/// neighbour that refused, named; a frame that cannot be sent or received,
/// or does not parse, fails (500). Every node sends its verdict even when
/// it refuses, so the other two learn of the refusal instead of waiting.
fn verdicts<N: Network>(net: &N, mine: Result<(), Refusal>) -> Result<(), Refusal> {
    const WHAT: &str = "handshake verdict";
    let me = net.id();
    let (next, prev) = (next(me), prev(me));
    let verdict = match &mine {
        Ok(()) => Verdict {
            accepted: true,
            refusal: None,
        },
        Err(refusal) => Verdict {
            accepted: false,
            refusal: Some(
                refusal
                    .message
                    .strip_prefix(PREFIX)
                    .unwrap_or(&refusal.message)
                    .to_string(),
            ),
        },
    };
    send_json(net, next, WHAT, &verdict)?;
    send_json(net, prev, WHAT, &verdict)?;
    let received = [prev, next].map(|peer| (peer, recv_json::<Verdict, _>(net, peer, WHAT)));
    mine?;
    for (peer, verdict) in received {
        let verdict = verdict?;
        if !verdict.accepted {
            let why = verdict.refusal.unwrap_or_default();
            return Err(refuse(format!("node {peer} refused the request: {why}")));
        }
    }
    Ok(())
}

/// Send `value` to node `to` as one JSON frame over the session (500 when
/// the mesh fails), naming it `what` in the refusal.
pub(crate) fn send_json<N: Network, T: Serialize>(
    net: &N,
    to: usize,
    what: &str,
    value: &T,
) -> Result<(), Refusal> {
    let bytes = serde_json::to_vec(value).expect("session frames serialise");
    net.send(to, Bytes::from(bytes)).map_err(|e| {
        Refusal::mpc_failure(format!(
            "MPC session: sending the {what} to node {to} failed: {e:#}"
        ))
    })
}

/// Receive one JSON frame from node `from` (500 when the mesh fails or the
/// frame does not parse), naming it `what` in the refusal.
pub(crate) fn recv_json<T: DeserializeOwned, N: Network>(
    net: &N,
    from: usize,
    what: &str,
) -> Result<T, Refusal> {
    let bytes = net.recv(from).map_err(|e| {
        Refusal::mpc_failure(format!("MPC session: node {from} sent no {what}: {e:#}"))
    })?;
    serde_json::from_slice(&bytes).map_err(|e| {
        Refusal::mpc_failure(format!(
            "MPC session: node {from} sent a malformed {what}: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;
    use crate::grumpkin::{fixed_base_mul, scalar_from_field};
    use crate::keys::tests::sample_keys;
    use crate::manifest::KeyRef;
    use crate::record::{open, seal};

    const ID: RequestId = RequestId(ark_ff::MontFp!("9341084582143408800955381380479911687"));
    const NS: u64 = 0x1f2e;
    const KEY: &str = "0xb001";

    fn body() -> Fr {
        Fr::from(0xb0d7u64)
    }

    // A replicated sharing of `x`, as node i's pairs.
    fn pairs(x: u64, seed: u64) -> [Share; 3] {
        let x0 = poseidon2_hash(&[Fr::from(seed), Fr::from(0u64)]);
        let x1 = poseidon2_hash(&[Fr::from(seed), Fr::from(1u64)]);
        let s = [x0, x1, Fr::from(x) - x0 - x1];
        [0, 1, 2].map(|i| Share::new(s[i], s[(i + 2) % 3]))
    }

    // A stored vector of three elements, the middle one public, as each
    // node's third.
    fn thirds(seed: u64) -> [Vec<Elem>; 3] {
        let (p, q) = (pairs(40, seed), pairs(41, seed + 1));
        [0, 1, 2].map(|i| {
            vec![
                Elem::Shared(p[i]),
                Elem::Public(Fr::from(9u64)),
                Elem::Shared(q[i]),
            ]
        })
    }

    fn handshakes(
        bodies: [Fr; 3],
        inputs: &[[Share; 3]],
        records: &[[Vec<Elem>; 3]],
    ) -> [Handshake; 3] {
        [0, 1, 2].map(|i| {
            let names = ["door", "door_randomness"];
            let ins: Vec<(&str, Share)> = inputs
                .iter()
                .enumerate()
                .map(|(k, p)| (names[k], p[i]))
                .collect();
            let recs: Vec<(&str, &[Elem])> =
                records.iter().map(|r| (KEY, r[i].as_slice())).collect();
            Handshake::build(ID, bodies[i], &ins, &recs)
        })
    }

    // Every node's check of the messages its neighbours sent it.
    fn exchange(hs: &[Handshake; 3]) -> [Result<(), Refusal>; 3] {
        [0, 1, 2].map(|i| {
            let prev = &hs[(i + 2) % 3];
            let next = &hs[(i + 1) % 3];
            hs[i].check(&prev.message_to_next(), &next.message_to_prev())
        })
    }

    fn refused(result: &Result<(), Refusal>, needle: &str) {
        crate::error::assert_refused(result.clone(), ErrorClass::BadRequest, &[needle]);
    }

    #[test]
    fn a_consistent_sharing_is_accepted() {
        let hs = handshakes([body(); 3], &[pairs(1, 1), pairs(77, 2)], &[thirds(3)]);
        assert_eq!(hs[0].summand_hashes_to_next.len(), 2 + 3);
        for result in exchange(&hs) {
            result.unwrap();
        }
        // Nothing to share is consistent too.
        for result in exchange(&handshakes([body(); 3], &[], &[])) {
            result.unwrap();
        }
    }

    #[test]
    fn each_neighbour_receives_only_the_summands_it_holds() {
        let door = pairs(1, 1);
        let hs = handshakes([body(); 3], &[door], &[]);
        // Node 0 sends node 1 the hash of x_0 and node 2 the hash of x_2;
        // node 1 holds (x_1, x_0) and node 2 holds (x_2, x_1).
        assert_eq!(
            hs[0].message_to_next().summand_hashes,
            [FieldHex(summand_hash(&ID, door[1].b))]
        );
        assert_eq!(
            hs[0].message_to_prev().summand_hashes,
            [FieldHex(summand_hash(&ID, door[2].a))]
        );
        let msg = hs[0].message_to_next();
        let text = serde_json::to_string(&msg).unwrap();
        assert_eq!(HandshakeMessage::from_json(&text).unwrap(), msg);
        assert!(HandshakeMessage::from_json(&text.replace("}", ",\"x\":1}")).is_err());
    }

    #[test]
    fn a_different_body_hash_or_request_is_refused() {
        let mut bodies = [body(); 3];
        bodies[1] = body() + Fr::from(1u64);
        let results = exchange(&handshakes(bodies, &[pairs(1, 1)], &[]));
        refused(&results[0], "the next node's body hash differs");
        refused(&results[1], "body hash differs");
        refused(&results[2], "the previous node's body hash differs");

        let hs = handshakes([body(); 3], &[pairs(1, 1)], &[]);
        let mut other = hs[0].message_to_next();
        other.request_id = RequestId::from_u128_bytes([8; 16]);
        refused(
            &hs[1].check(&other, &hs[2].message_to_prev()),
            "the previous node runs request",
        );
    }

    #[test]
    fn an_inconsistent_sharing_is_refused() {
        // The client gives node 1 another x_1 for the door randomness: node 1
        // and node 2 no longer agree on x_1; node 0 still agrees with both.
        let door = pairs(1, 1);
        let mut randomness = pairs(77, 2);
        randomness[1].a += Fr::from(1u64);
        let results = exchange(&handshakes([body(); 3], &[door, randomness], &[]));
        results[0].as_ref().unwrap();
        refused(
            &results[1],
            "shared input `door_randomness` is not shared consistently with the next node",
        );
        refused(
            &results[2],
            "shared input `door_randomness` is not shared consistently with the previous node",
        );
        // A node with a summand fewer is refused by count.
        let hs = handshakes([body(); 3], &[door, pairs(77, 2)], &[]);
        let mut short = hs[0].message_to_next();
        short.summand_hashes.pop();
        refused(
            &hs[1].check(&short, &hs[2].message_to_prev()),
            "holds 1 shared summands, this node 2",
        );
    }

    #[test]
    fn mixed_thirds_of_two_records_are_refused() {
        // Two records of the same value and note hash, sealed from two
        // sharings. Every third opens on its own; node 0 is given record A's
        // third, nodes 1 and 2 record B's.
        let owner = fixed_base_mul(scalar_from_field(Fr::from(5u64)));
        let (ns, nh) = (Fr::from(NS), Fr::from(0x77u64));
        let (a, b) = (thirds(10), thirds(20));
        let sealed = |vecs: &[Vec<Elem>; 3]| {
            [0, 1, 2].map(|i| seal(&sample_keys(i), ns, KEY, nh, owner, &vecs[i]))
        };
        let (ca, cb) = (sealed(&a), sealed(&b));
        let presented = [&ca[0], &cb[1], &cb[2]];
        let opened: [Vec<Elem>; 3] =
            [0, 1, 2].map(|i| open(&sample_keys(i), ns, KEY, nh, owner, presented[i]).unwrap());
        assert_eq!(opened[0], a[0]);
        let results = exchange(&handshakes([body(); 3], &[pairs(1, 1)], &[opened]));
        refused(
            &results[0],
            "record `0xb001` element 0 is not shared consistently",
        );
        refused(
            &results[1],
            "record `0xb001` element 0 is not shared consistently with the previous node",
        );
        results[2].as_ref().unwrap_err();
        // The unmixed records pass.
        let opened: [Vec<Elem>; 3] =
            [0, 1, 2].map(|i| open(&sample_keys(i), ns, KEY, nh, owner, &cb[i]).unwrap());
        for result in exchange(&handshakes([body(); 3], &[pairs(1, 1)], &[opened])) {
            result.unwrap();
        }
    }

    // Run `exchange` on the three nodes over mpc-net's in-process network.
    fn exchange_over_local(hs: &[Handshake; 3]) -> [Result<(), Refusal>; 3] {
        let nets = mpc_net::local::LocalNetwork::new_3_parties();
        std::thread::scope(|s| {
            let handles: Vec<_> = nets
                .into_iter()
                .map(|net| s.spawn(move || super::exchange(&net, &hs[net.id()])))
                .collect();
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            results.try_into().unwrap()
        })
    }

    #[test]
    fn the_verdict_round_makes_the_third_node_refuse() {
        let door = pairs(1, 1);
        let mut randomness = pairs(77, 2);
        randomness[1].a += Fr::from(1u64);
        let results = exchange_over_local(&handshakes([body(); 3], &[door, randomness], &[]));
        refused(
            &results[1],
            "session handshake: shared input `door_randomness` is not shared consistently with the next node",
        );
        refused(
            &results[2],
            "session handshake: shared input `door_randomness` is not shared consistently with the previous node",
        );
        // Node 0's own checks pass; node 2's verdict refuses it.
        refused(
            &results[0],
            "session handshake: node 2 refused the request: shared input `door_randomness` is not \
             shared consistently with the previous node",
        );
        for result in exchange_over_local(&handshakes([body(); 3], &[door, pairs(77, 2)], &[])) {
            result.unwrap();
        }
        let verdict = Verdict {
            accepted: false,
            refusal: Some("why".into()),
        };
        let text = serde_json::to_string(&verdict).unwrap();
        assert_eq!(serde_json::from_str::<Verdict>(&text).unwrap(), verdict);
        assert_eq!(
            serde_json::to_string(&Verdict {
                accepted: true,
                refusal: None
            })
            .unwrap(),
            r#"{"accepted":true}"#
        );
    }

    #[test]
    fn a_differing_public_record_element_is_refused() {
        let mut r = thirds(3);
        r[2][1] = Elem::Public(Fr::from(10u64));
        let results = exchange(&handshakes([body(); 3], &[], &[r]));
        refused(&results[2], "record `0xb001` element 1");
    }

    #[test]
    fn from_bound_orders_inputs_by_manifest_and_every_read_by_key() {
        use crate::abi::check_manifest_value;
        use crate::abi::tests::{abi, array, effects, field};
        use crate::bind::Read;
        use crate::manifest::FixedKey;
        use serde_json::json;
        let shape_abi = abi(
            &[
                ("namespace", "public", field()),
                ("b_input", "private", field()),
                ("a_input", "private", field()),
                ("nsk_app", "private", field()),
                ("state2", "private", array(2, field())),
                ("state1", "private", array(1, field())),
                ("state0", "private", array(1, field())),
            ],
            Some(effects(0, 0, 0)),
        );
        let manifest = json!({
            "manifest": 1, "circuit": "c", "namespace_param": "namespace",
            "state_keys": {"reads": 3, "writes": 0},
            "witness": [
                {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
                {"param": "b_input", "from": {"INPUT_SHARED": "b"}},
                {"param": "a_input", "from": {"INPUT_SHARED": "a"}},
                {"param": "nsk_app", "from": {"LOAD": "nsk_app", "slice": [0, 1], "len": 1}},
                {"param": "state2", "from": {"LOAD": "$state_keys.reads[2]", "slice": [0, 2], "len": 2}},
                {"param": "state1", "from": {"LOAD": "$state_keys.reads[1]", "slice": [0, 1], "len": 1}},
                {"param": "state0", "from": {"LOAD": "$state_keys.reads[0]", "slice": [0, 1], "len": 1}}
            ],
            "outputs": [],
            "state": {"$state_keys.reads[0]": "client", "$state_keys.reads[1]": "client", "$state_keys.reads[2]": "node"},
            "consume": [{"key": "$state_keys.reads[0]", "policy": "never"}, {"key": "$state_keys.reads[1]", "policy": "never"}]
        });
        let (m, shape) = check_manifest_value(&manifest, &shape_abi).unwrap();
        let s = |x: u64| Share::new(Fr::from(x), Fr::from(x + 100));
        let bound = Bound {
            input: [
                ("namespace".to_string(), Elem::Public(Fr::from(NS))),
                ("b_input".to_string(), Elem::Shared(s(2))),
                ("a_input".to_string(), Elem::Shared(s(1))),
                ("nsk_app".to_string(), Elem::Shared(s(7))),
                ("state2[0]".to_string(), Elem::Shared(s(5))),
                ("state2[1]".to_string(), Elem::Public(Fr::from(6u64))),
                ("state1[0]".to_string(), Elem::Shared(s(4))),
                ("state0[0]".to_string(), Elem::Shared(s(3))),
            ]
            .into_iter()
            .collect(),
            reads: vec![
                Read {
                    keyref: KeyRef::Fixed(FixedKey::NskApp),
                    key: "nsk_app".into(),
                    value: vec![Elem::Shared(s(7))],
                },
                Read {
                    keyref: KeyRef::Read(2),
                    key: "k2".into(),
                    value: vec![Elem::Shared(s(5)), Elem::Public(Fr::from(6u64))],
                },
                Read {
                    keyref: KeyRef::Read(1),
                    key: "k1".into(),
                    value: vec![Elem::Shared(s(4))],
                },
                Read {
                    keyref: KeyRef::Read(0),
                    key: "k0".into(),
                    value: vec![Elem::Shared(s(3))],
                },
            ],
            samples: 0,
        };
        let holding = crate::state::StateHolders::core().choose(&m).unwrap();
        let hs = Handshake::from_bound(ID, body(), &shape, &m, &holding, &bound);
        // The shared inputs in manifest order, then every read in key order:
        // the client-held records, the node-held row, the fixed key.
        let a_and_b = Handshake::build(ID, body(), &[("b", s(2)), ("a", s(1))], &[]);
        assert_eq!(
            hs.summand_hashes_to_next[..2],
            a_and_b.summand_hashes_to_next[..]
        );
        let h = |x: Fr| summand_hash(&ID, x);
        let s7 = s(7);
        let (s3, s4, s5) = (s(3), s(4), s(5));
        assert_eq!(
            hs.summand_hashes_to_next[2..],
            [h(s3.a), h(s4.a), h(s5.a), h(Fr::from(6u64)), h(s7.a)]
        );
        assert_eq!(
            hs.summand_hashes_to_prev[2..],
            [h(s3.b), h(s4.b), h(s5.b), h(Fr::from(6u64)), h(s7.b)]
        );
        assert_eq!(
            hs.labels,
            [
                "shared input `b`",
                "shared input `a`",
                "record `k0` element 0",
                "record `k1` element 0",
                "value `k2` element 0",
                "value `k2` element 1",
                "nsk_app element 0",
            ]
        );
    }

    #[test]
    fn a_diverged_node_held_row_or_nsk_app_is_refused_naming_it() {
        // Node 2's copy of the row (or of the nsk_app share) is not the one its
        // neighbours hold, as after a commit that failed on node 2 only.
        for diverged in ["value `0xa002`", "nsk_app"] {
            let (row, nsk) = (thirds(5), pairs(70, 9));
            let mut hs = [0, 1, 2].map(|i| {
                let nsk_i = [Elem::Shared(nsk[i])];
                let loads: [(String, &[Elem]); 2] = [
                    ("value `0xa002`".to_string(), &row[i]),
                    ("nsk_app".to_string(), &nsk_i),
                ];
                Handshake::with_loads(ID, body(), &[], &loads)
            });
            let stale = thirds(6);
            let other_nsk = [Elem::Shared(pairs(70, 10)[2])];
            let loads: [(String, &[Elem]); 2] = if diverged == "nsk_app" {
                [
                    ("value `0xa002`".to_string(), &row[2]),
                    ("nsk_app".to_string(), &other_nsk),
                ]
            } else {
                [
                    ("value `0xa002`".to_string(), &stale[2]),
                    ("nsk_app".to_string(), &[Elem::Shared(nsk[2])]),
                ]
            };
            hs[2] = Handshake::with_loads(ID, body(), &[], &loads);
            let results = exchange(&hs);
            // Node 2 differs from both neighbours; nodes 0 and 1 agree with
            // each other and each refuse on their link to node 2.
            refused(
                &results[0],
                &format!("{diverged} element 0 is not shared consistently with the previous node"),
            );
            refused(
                &results[1],
                &format!("{diverged} element 0 is not shared consistently with the next node"),
            );
            refused(
                &results[2],
                &format!("{diverged} element 0 is not shared consistently"),
            );
        }
    }
}
