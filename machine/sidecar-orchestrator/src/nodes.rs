//! The node leg: one mutual-TLS JSON client per node, calls to the three at
//! once, and the reduction of their three answers to either three parsed
//! answers or one refusal.

use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use sidecar_core::request::NODES;
use sidecar_core::{ErrorClass, Refusal};
use sidecar_http::client::{Answer, ApiClient};

use crate::config::OrchestratorConfig;

// The node leg is the shared client (`sidecar_http::client::ApiClient`: one
// HTTP/1.1 connection per call over rustls) under the shared TLS set-up
// (`sidecar_http::tls::client_config`: the deployment CA as the only root, the
// orchestrator's client certificate presented). The node's tests drive the
// node's server with the same client, so both ends of the wire contract are
// one implementation. One connection per call keeps no idle sockets to the
// nodes; a round costs seconds, a TLS handshake milliseconds.
/// The three nodes' clients, node 0 first.
#[derive(Clone)]
pub struct Nodes {
    clients: Arc<[ApiClient; NODES]>,
    /// The same clients under [`LOOKUP_CALL_TIMEOUT`] ([`Nodes::lookups`]).
    lookups: Arc<[ApiClient; NODES]>,
}

/// One node's reply: its answer, or the transport failure that left none.
pub type Reply = eyre::Result<Answer>;

// Operator knob: DESIGN.md, "Configuration reference"
// (`node_call_timeout_secs`). One whole node call; one that runs out is a
// transport failure (500 naming the node) and releases the session lock. The
// invariant: the orchestrator's call bound is above the nodes' round bound.
// A node bounds each mesh send and receive by its mesh `timeout` (600 s by
// default, sidecar-node `mesh::DEFAULT_IO_TIMEOUT`) and then proves, so a
// round can outlast a shorter call bound; the orchestrator would then release
// the session lock while the three nodes still hold their mesh locks, and the
// next round's fan-out would queue at the nodes. The default covers a round:
// 30 s to open the mesh (`connect_timeout`) + 600 s of one full mesh timeout
// + 300 s of proving = 930 s, and 1,000 s leaves 70 s of margin; a deployment
// that raises the nodes' mesh timeout, or proves rounds for longer, raises
// this with it.
/// How long the orchestrator waits for one node call by default.
pub const DEFAULT_NODE_CALL_TIMEOUT: Duration = Duration::from_secs(1_000);

// Operator knob: DESIGN.md, "Configuration reference" (lookup call bound;
// no knob). A call that opens no session (FETCH, the receipt route, tree
// paths, the registry reads, `/v1/nodes`) reads rows or signs, and takes no
// lock a round holds, so it gets a minute, not the round bound: a node that
// accepts and never answers holds one of the listener's connections for that
// long, not for a round's 1,000 s.
/// How long the orchestrator waits for one node call that opens no session.
pub const LOOKUP_CALL_TIMEOUT: Duration = Duration::from_secs(60);

// Operator knob: DESIGN.md, "Configuration reference" (node answer caps; no
// knob). Every node answer is read under a cap by route class, so one node
// that streams without end fails its call instead of filling the
// orchestrator's memory. A round's answer (execute, FETCH, receipt, tree
// paths, keys, a registry body's answer) is a proof, its public inputs and
// a few records: 4 MiB. A registry row (`crate::sync`'s reads) carries a
// circuit a node accepted in a body of up to 32 MiB:
// `sidecar_http::client::DEFAULT_MAX_ANSWER_BYTES`, twice that.
/// The largest answer of a round route the orchestrator reads from a node.
pub const MAX_ROUND_ANSWER_BYTES: usize = 4 * 1024 * 1024;
/// The largest registry answer the orchestrator reads from a node.
pub const MAX_REGISTRY_ANSWER_BYTES: usize = sidecar_http::client::DEFAULT_MAX_ANSWER_BYTES;

// Operator knob: DESIGN.md, "Configuration reference" (relayed refusal
// text; no knob). A node's refusal message reaches the client and the log
// through the orchestrator; one node chooses it, so it is cut to 1 KiB.
/// The longest node refusal message the orchestrator relays, in bytes.
pub const MAX_RELAYED_MESSAGE_BYTES: usize = 1024;

impl Nodes {
    /// The clients of the config's three nodes over the node-leg TLS.
    pub fn new(config: &OrchestratorConfig) -> eyre::Result<Self> {
        let tls = sidecar_http::tls::client_config(
            &config.node_tls.ca,
            Some((&config.node_tls.cert, &config.node_tls.key)),
        )?;
        let mut clients = Vec::with_capacity(NODES);
        for node in &config.nodes {
            clients.push(ApiClient::to_host(
                node.host_and_port()?,
                &node.server_name()?,
                tls.clone(),
            )?);
        }
        let clients: [ApiClient; NODES] = clients
            .try_into()
            .map_err(|_| eyre::eyre!("the config names {NODES} nodes"))?;
        Ok(Self::with_timeout(clients, config.node_call_timeout()))
    }

    /// The three nodes behind clients built elsewhere, node 0 first, each
    /// call bounded by [`DEFAULT_NODE_CALL_TIMEOUT`].
    pub fn from_clients(clients: [ApiClient; NODES]) -> Self {
        Self::with_timeout(clients, DEFAULT_NODE_CALL_TIMEOUT)
    }

    /// The three nodes behind `clients`, each call bounded by `timeout` (a
    /// lookup's by the shorter of it and [`LOOKUP_CALL_TIMEOUT`]) and each
    /// answer by [`MAX_ROUND_ANSWER_BYTES`].
    pub fn with_timeout(clients: [ApiClient; NODES], timeout: Duration) -> Self {
        let bounded = |timeout: Duration| {
            Arc::new(clients.clone().map(|c| {
                c.with_timeout(timeout)
                    .with_max_answer(MAX_ROUND_ANSWER_BYTES)
            }))
        };
        Nodes {
            clients: bounded(timeout),
            lookups: bounded(timeout.min(LOOKUP_CALL_TIMEOUT)),
        }
    }

    /// The same nodes for calls that open no session: each bounded by
    /// [`LOOKUP_CALL_TIMEOUT`].
    pub fn lookups(&self) -> Self {
        Nodes {
            clients: self.lookups.clone(),
            lookups: self.lookups.clone(),
        }
    }

    /// The same nodes with each answer read up to `bytes` (a route class
    /// with larger answers: [`MAX_REGISTRY_ANSWER_BYTES`]).
    pub fn with_max_answer(&self, bytes: usize) -> Self {
        let capped = |clients: &Arc<[ApiClient; NODES]>| {
            Arc::new(clients.as_ref().clone().map(|c| c.with_max_answer(bytes)))
        };
        Nodes {
            clients: capped(&self.clients),
            lookups: capped(&self.lookups),
        }
    }

    /// POST node i's own body to node i, the three at once.
    pub async fn post_each(&self, path: &str, bodies: [Vec<u8>; NODES]) -> [Reply; NODES] {
        let [a, b, c] = bodies;
        let (x, y, z) = tokio::join!(
            self.clients[0].post_raw(path, a),
            self.clients[1].post_raw(path, b),
            self.clients[2].post_raw(path, c),
        );
        [x, y, z]
    }

    /// POST the same bytes to the three nodes at once.
    pub async fn post_same(&self, path: &str, body: &[u8]) -> [Reply; NODES] {
        self.post_each(path, [body.to_vec(), body.to_vec(), body.to_vec()])
            .await
    }

    /// GET `path` from the three nodes at once.
    pub async fn get(&self, path: &str) -> [Reply; NODES] {
        let (x, y, z) = tokio::join!(
            self.clients[0].get(path),
            self.clients[1].get(path),
            self.clients[2].get(path),
        );
        [x, y, z]
    }
}

/// Node i's reply as `T`, or the refusal it stands for: the node's own
/// refusal (its class, the message prefixed with the node), or 500 for a
/// transport failure or an answer that does not parse.
pub fn node_answer<T: DeserializeOwned>(node: usize, reply: Reply) -> Result<T, Refusal> {
    let answer =
        reply.map_err(|e| Refusal::mpc_failure(format!("node {node}: no answer: {e:#}")))?;
    match answer.json::<T>() {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(refusal)) => Err(Refusal::new(
            refusal.class,
            format!("node {node}: {}", capped(&refusal.message)),
        )),
        Err(e) => Err(Refusal::mpc_failure(format!(
            "node {node}: its answer (HTTP {}) does not parse: {}",
            answer.status,
            // The serde error alone: the context quotes the whole answer.
            e.root_cause()
        ))),
    }
}

/// `message` cut to [`MAX_RELAYED_MESSAGE_BYTES`] at a character boundary,
/// marked when cut.
fn capped(message: &str) -> std::borrow::Cow<'_, str> {
    if message.len() <= MAX_RELAYED_MESSAGE_BYTES {
        return message.into();
    }
    let mut end = MAX_RELAYED_MESSAGE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{} [cut at {MAX_RELAYED_MESSAGE_BYTES} bytes]",
        &message[..end]
    )
    .into()
}

// Which node refusal the client sees. When any node refuses,
// the orchestrator answers with one of the refusals, the most specific: a
// refusal of the request itself (400, 403, 404) first, then a conflict with
// stored state (409), then an unsatisfied circuit (422), then a 400 that only
// relays a neighbour's verdict at the session handshake ("session handshake:
// node N refused the request: ..."), and a node failure (500, a transport
// failure included) last, the lowest node index on a tie. A request one node
// refuses early can make the other two fail later: at the handshake, where
// the refusing node's verdict makes them refuse 400 (DECISIONS.md, "Sessions
// refuse together"), or with a generic error (a mesh that never opens).
// The refusing node's own class says what to fix (409: re-read `seq`; 403:
// the wrong key) and clients branch on the class, so a relayed verdict ranks
// below any node's own 403, 409 or 422; its message still names the node and
// quotes the reason. Answers of the nodes that did not refuse are dropped:
// nothing is assembled from fewer than three.
fn rank(refusal: &Refusal) -> u8 {
    match refusal.class {
        ErrorClass::BadRequest if relays_a_verdict(&refusal.message) => 3,
        ErrorClass::BadRequest | ErrorClass::Forbidden | ErrorClass::NotFound => 0,
        ErrorClass::Conflict => 1,
        ErrorClass::Unsatisfied => 2,
        ErrorClass::MpcFailure => 4,
    }
}

/// Whether node i's relayed message ("node i: ...") is a session handshake
/// refusal that relays another node's verdict ("session handshake: node N
/// refused the request: ...", sidecar-core's `handshake` module).
fn relays_a_verdict(message: &str) -> bool {
    let own = message.split_once(": ").map_or(message, |(_, rest)| rest);
    own.strip_prefix("session handshake: node ")
        .and_then(|rest| rest.split_once(' '))
        .is_some_and(|(peer, rest)| {
            peer.parse::<usize>().is_ok() && rest.starts_with("refused the request")
        })
}

/// The three replies as `T`, or the most specific refusal among them.
pub fn all_answers<T: DeserializeOwned>(replies: [Reply; NODES]) -> Result<[T; NODES], Refusal> {
    best_of(each_answer(replies))
}

/// Each node's reply as `T` or its refusal ([`node_answer`]), node 0 first.
pub fn each_answer<T: DeserializeOwned>(replies: [Reply; NODES]) -> [Result<T, Refusal>; NODES] {
    let [x, y, z] = replies;
    [node_answer(0, x), node_answer(1, y), node_answer(2, z)]
}

/// The three answers, or the most specific refusal among them.
pub fn best_of<T>(each: [Result<T, Refusal>; NODES]) -> Result<[T; NODES], Refusal> {
    let mut answers = Vec::with_capacity(NODES);
    let mut refusals = Vec::new();
    for answer in each {
        match answer {
            Ok(value) => answers.push(value),
            Err(refusal) => refusals.push(refusal),
        }
    }
    if let Some(best) = refusals.into_iter().min_by_key(rank) {
        tracing::info!(class = %best.class, error = %best.message, "a node refused");
        return Err(best);
    }
    Ok(answers
        .try_into()
        .unwrap_or_else(|_| unreachable!("three answers")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, body: &str) -> Reply {
        Ok(Answer {
            status,
            body: body.as_bytes().to_vec(),
        })
    }

    fn refusal(class: ErrorClass) -> Reply {
        answer(class.status(), &Refusal::new(class, "why").to_json())
    }

    /// A call that opens no session is bounded by the lookup bound, a
    /// round's call by the round bound: against a node that accepts and
    /// never answers, a lookup fails after a minute.
    #[tokio::test(start_paused = true)]
    async fn a_lookup_has_the_shorter_bound() {
        use sidecar_test_fixtures::dirs::TempDir;
        use sidecar_test_fixtures::nodes::{dev_certs, orchestrator_tls};
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = silent.local_addr().unwrap();
        let held = tokio::spawn(async move {
            let mut open = Vec::new();
            loop {
                open.push(silent.accept().await.unwrap());
            }
        });
        let tmp = TempDir::new("lookup-bound");
        let leg = orchestrator_tls(&dev_certs(tmp.path()));
        let tls = sidecar_http::tls::client_config(&leg.ca, Some((&leg.cert, &leg.key))).unwrap();
        let clients = [0, 1, 2].map(|_| ApiClient::new(addr, "localhost", tls.clone()).unwrap());
        let nodes = Nodes::with_timeout(clients, DEFAULT_NODE_CALL_TIMEOUT);
        for (nodes, bound) in [
            (nodes.lookups(), LOOKUP_CALL_TIMEOUT),
            (nodes, DEFAULT_NODE_CALL_TIMEOUT),
        ] {
            let start = tokio::time::Instant::now();
            let [reply, ..] = nodes.get("/v1/nodes").await;
            let err = format!("{:#}", reply.unwrap_err());
            assert!(
                err.contains(&format!("no answer within {bound:?}")),
                "{err}"
            );
            assert_eq!(start.elapsed(), bound);
        }
        held.abort();
    }

    #[test]
    fn three_answers_parse() {
        let got: [u64; NODES] =
            all_answers([answer(200, "1"), answer(200, "2"), answer(200, "3")]).unwrap();
        assert_eq!(got, [1, 2, 3]);
    }

    #[test]
    fn the_most_specific_refusal_wins() {
        let err = all_answers::<u64>([
            refusal(ErrorClass::MpcFailure),
            refusal(ErrorClass::Conflict),
            refusal(ErrorClass::BadRequest),
        ])
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert_eq!(err.message, "node 2: why");

        let err = all_answers::<u64>([
            answer(200, "1"),
            refusal(ErrorClass::Unsatisfied),
            refusal(ErrorClass::Conflict),
        ])
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::Conflict);
        assert!(err.message.starts_with("node 2"));

        // A transport failure and an answer that does not parse are 500s
        // naming the node, behind any refusal of the request.
        let err = all_answers::<u64>([
            Err(eyre::eyre!("connection refused")),
            answer(200, "1"),
            answer(200, "1"),
        ])
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::MpcFailure);
        assert!(err.message.contains("node 0: no answer"), "{err}");
        let err = all_answers::<u64>([answer(200, "1"), answer(200, "\"x\""), answer(502, "bad")])
            .unwrap_err();
        assert_eq!(err.class, ErrorClass::MpcFailure);
        assert!(err.message.contains("node 1: its answer"), "{err}");
        let err = all_answers::<u64>([
            Err(eyre::eyre!("reset")),
            refusal(ErrorClass::NotFound),
            refusal(ErrorClass::Conflict),
        ])
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::NotFound);
    }

    fn says(class: ErrorClass, message: &str) -> Reply {
        answer(class.status(), &Refusal::new(class, message).to_json())
    }

    // One node chooses the refusal text the client sees: it is cut to
    // MAX_RELAYED_MESSAGE_BYTES, at a character boundary.
    #[test]
    fn a_relayed_refusal_message_is_capped() {
        let long = "é".repeat(MAX_RELAYED_MESSAGE_BYTES);
        let err = node_answer::<u64>(1, says(ErrorClass::Conflict, &long)).unwrap_err();
        assert_eq!(err.class, ErrorClass::Conflict);
        let kept = err
            .message
            .strip_prefix("node 1: ")
            .and_then(|m| m.strip_suffix(" [cut at 1024 bytes]"))
            .unwrap();
        assert_eq!(kept, "é".repeat(MAX_RELAYED_MESSAGE_BYTES / 2));
        let short = node_answer::<u64>(0, says(ErrorClass::Conflict, "why")).unwrap_err();
        assert_eq!(short.message, "node 0: why");
    }

    #[test]
    fn a_relayed_handshake_verdict_ranks_below_the_refusal_it_relays() {
        let relayed =
            |peer: usize| format!("session handshake: node {peer} refused the request: why");
        // A seq 0 REGISTER node 2 refuses locally: 409 or 403 there, the
        // relayed verdict at the other two.
        for class in [ErrorClass::Conflict, ErrorClass::Forbidden] {
            let err = all_answers::<u64>([
                says(ErrorClass::BadRequest, &relayed(2)),
                says(ErrorClass::BadRequest, &relayed(2)),
                says(class, "why"),
            ])
            .unwrap_err();
            assert_eq!(err.class, class);
            assert_eq!(err.message, "node 2: why");
        }
        // An execute node 0 refuses 422 behind two relayed verdicts.
        let err = all_answers::<u64>([
            says(ErrorClass::Unsatisfied, "constraints"),
            says(ErrorClass::BadRequest, &relayed(0)),
            says(ErrorClass::BadRequest, &relayed(0)),
        ])
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::Unsatisfied);
        // A node's own handshake refusal (a summand mismatch it saw) is not a
        // relayed verdict, and ranks with the other refusals of the request.
        let err = all_answers::<u64>([
            says(ErrorClass::Conflict, "consumed"),
            says(
                ErrorClass::BadRequest,
                "session handshake: shared input `door` is not shared consistently",
            ),
            says(ErrorClass::BadRequest, &relayed(1)),
        ])
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(err.message.starts_with("node 1: session handshake: shared"));
        // A relayed verdict still ranks above a node failure.
        let err = all_answers::<u64>([
            says(ErrorClass::MpcFailure, "mesh"),
            says(ErrorClass::BadRequest, &relayed(0)),
            Err(eyre::eyre!("reset")),
        ])
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert_eq!(err.message, format!("node 1: {}", relayed(0)));
        assert!(relays_a_verdict(&format!("node 1: {}", relayed(0))));
        assert!(!relays_a_verdict("node 1: session handshake: node key"));
    }
}
