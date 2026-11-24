//! Three nodes in one process over the real TLS mesh on loopback ports
//! reserved for the test process: the session handshake, the pinned
//! certificates, the mesh session lock a session opens under and the reserved
//! ports themselves; and the development certificate set the mesh and the
//! APIs run on.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use mpc_core::protocols::rep3::arithmetic;
use mpc_net::config::NetworkConfigFile;
use sidecar_core::bind::{Elem, Share};
use sidecar_core::error::{ErrorClass, Refusal};
use sidecar_core::executor::{round_state, sample_share};
use sidecar_core::handshake::Handshake;
use sidecar_core::hash::poseidon2_hash;
use sidecar_core::{Fr, RequestId};
use sidecar_node::certs::{MeshIdentity, mesh_identity};
use sidecar_node::testing::reserve_ports;
use sidecar_node::{Mesh, MeshConfig, open_session};
use socket2::{Domain, Socket, Type};

const CONNECT: Duration = Duration::from_secs(10);
const IO: Duration = Duration::from_secs(30);
// The connect timeout of the sessions a rogue peer breaks.
const SHORT: Duration = Duration::from_secs(3);

fn request_id(n: u64) -> RequestId {
    format!("0x{n:032x}").parse().unwrap()
}

fn identities() -> [MeshIdentity; 3] {
    [0, 1, 2].map(|i| mesh_identity(i).unwrap())
}

/// Party `party`'s config: it holds `own` and pins `pinned`.
fn config(ports: [u16; 3], party: usize, own: &MeshIdentity, pinned: [&[u8]; 3]) -> MeshConfig {
    let bind: SocketAddr = format!("127.0.0.1:{}", ports[party]).parse().unwrap();
    MeshConfig::from_der(
        party,
        bind,
        ports.map(|p| format!("127.0.0.1:{p}")),
        own.key.clone(),
        pinned.map(<[u8]>::to_vec),
    )
    .unwrap()
    .with_timeouts(CONNECT, IO)
}

/// Three honest meshes on reserved ports.
fn meshes() -> [Mesh; 3] {
    let ids = identities();
    let ports: [u16; 3] = reserve_ports();
    let pinned = [ids[0].cert.as_slice(), &ids[1].cert, &ids[2].cert];
    [0, 1, 2].map(|i| Mesh::new(config(ports, i, &ids[i], pinned)))
}

/// Run `f` for parties 0, 1 and 2 on three threads.
fn run3<T: Send>(f: impl Fn(usize) -> T + Sync) -> [T; 3] {
    thread::scope(|s| {
        let handles = [0, 1, 2].map(|i| {
            let f = &f;
            s.spawn(move || f(i))
        });
        handles.map(|h| h.join().unwrap())
    })
}

// A replicated sharing of `x`, as node i's pairs (x_i, x_{i-1}).
fn pairs(x: u64, seed: u64) -> [Share; 3] {
    let x0 = poseidon2_hash(&[Fr::from(seed), Fr::from(0u64)]);
    let x1 = poseidon2_hash(&[Fr::from(seed), Fr::from(1u64)]);
    let s = [x0, x1, Fr::from(x) - x0 - x1];
    [0, 1, 2].map(|i| Share::new(s[i], s[(i + 2) % 3]))
}

// A stored record of two shared elements and one public one, as each node's third.
fn record(seed: u64) -> [Vec<Elem>; 3] {
    let (p, q) = (pairs(40, seed), pairs(41, seed + 1));
    [0, 1, 2].map(|i| {
        vec![
            Elem::Shared(p[i]),
            Elem::Public(Fr::from(9u64)),
            Elem::Shared(q[i]),
        ]
    })
}

/// Node i's handshake for a request with two shared inputs and one record.
fn handshake(
    id: RequestId,
    body: Fr,
    inputs: &[[Share; 3]; 2],
    rec: &[Vec<Elem>; 3],
    i: usize,
) -> Handshake {
    Handshake::build(
        id,
        body,
        &[("door", inputs[0][i]), ("door_randomness", inputs[1][i])],
        &[("0xb001", rec[i].as_slice())],
    )
}

fn consistent(id: RequestId, body: Fr) -> [Handshake; 3] {
    let inputs = [pairs(1, 1), pairs(77, 2)];
    let rec = record(3);
    [0, 1, 2].map(|i| handshake(id, body, &inputs, &rec, i))
}

/// Open `mesh`'s session for `hs` under its own lock, then close it: whether
/// it opened.
fn try_open(mesh: &Mesh, hs: &Handshake) -> Result<(), Refusal> {
    let held = mesh.lock().acquire();
    open_session(mesh, &held, hs).map(drop)
}

fn refusal(result: &Result<(), Refusal>) -> &Refusal {
    match result {
        Ok(()) => panic!("the session opened"),
        Err(refusal) => refusal,
    }
}

fn assert_refused(result: &Result<(), Refusal>, class: ErrorClass, needle: &str) {
    let r = refusal(result);
    assert_eq!(r.class, class, "{r}");
    assert!(
        r.message.contains(needle),
        "`{}` lacks `{needle}`",
        r.message
    );
}

#[test]
fn a_consistent_handshake_opens_a_session_that_runs_rep3() {
    let meshes = meshes();
    let hs = consistent(request_id(1), Fr::from(0xb0d7u64));
    let out = run3(|i| {
        let held = meshes[i].lock().acquire();
        let session = open_session(&meshes[i], &held, &hs[i]).unwrap();
        // a session opens only under its own mesh's lock
        let other = &meshes[(i + 1) % 3];
        let refused = open_session(other, &held, &hs[i]).err().unwrap();
        assert!(refused.message.contains("another mesh's"), "{refused}");
        let mut state = round_state(&session).unwrap();
        let x = sample_share(&mut state);
        let y = sample_share(&mut state);
        let z = arithmetic::mul(x, y, &session, &mut state).unwrap();
        let opened = [x, y, z].map(|s| arithmetic::open(s, &session).unwrap());
        drop(session);
        drop(held);
        (x, opened)
    });
    // SAMPLE drew one replicated sharing: node i's b is node i-1's a.
    for i in 0..3 {
        assert_eq!(out[i].0.b, out[(i + 2) % 3].0.a);
    }
    let [x, y, z] = out[0].1;
    assert_eq!(z, x * y);
    assert!(out.iter().all(|(_, opened)| *opened == out[0].1));
}

#[test]
fn an_inconsistent_sharing_is_refused_by_every_node() {
    let meshes = meshes();
    let (id, body) = (request_id(2), Fr::from(0xb0d7u64));
    // The client gives node 1 another x_1 of the door randomness: nodes 1 and
    // 2 disagree on it, node 0 agrees with both and still refuses.
    let mut randomness = pairs(77, 2);
    randomness[1].a += Fr::from(1u64);
    let inputs = [pairs(1, 1), randomness];
    let rec = record(3);
    let results = run3(|i| try_open(&meshes[i], &handshake(id, body, &inputs, &rec, i)));
    assert_refused(
        &results[1],
        ErrorClass::BadRequest,
        "shared input `door_randomness` is not shared consistently with the next node",
    );
    assert_refused(
        &results[2],
        ErrorClass::BadRequest,
        "shared input `door_randomness` is not shared consistently with the previous node",
    );
    // Node 0's own checks pass; it refuses on node 2's verdict, which names
    // the position (never a value).
    assert_refused(
        &results[0],
        ErrorClass::BadRequest,
        "session handshake: node 2 refused the request: shared input `door_randomness`",
    );
    assert_eq!(refusal(&results[0]).status(), 400);
    assert!(meshes.iter().all(|m| m.lock().is_free()));

    // A record whose element 2 differs at node 0 is refused the same way.
    let inputs = [pairs(1, 1), pairs(77, 2)];
    let mut rec = record(3);
    rec[0][2] = Elem::Shared(pairs(42, 9)[0]);
    let results = run3(|i| try_open(&meshes[i], &handshake(id, body, &inputs, &rec, i)));
    for result in &results {
        assert_refused(result, ErrorClass::BadRequest, "session handshake");
    }
    assert_refused(
        &results[0],
        ErrorClass::BadRequest,
        "record `0xb001` element 2",
    );
}

#[test]
fn two_requests_on_one_session_are_refused_by_every_node() {
    let meshes = meshes();
    let id = request_id(3);
    // Party 1 was handed another body under the same request id.
    let mut hs = consistent(id, Fr::from(0xb0d7u64));
    hs[1] = consistent(id, Fr::from(0xb0d8u64))[1].clone();
    let results = run3(|i| try_open(&meshes[i], &hs[i]));
    assert_refused(
        &results[0],
        ErrorClass::BadRequest,
        "the next node's body hash differs",
    );
    assert_refused(&results[1], ErrorClass::BadRequest, "body hash differs");
    assert_refused(
        &results[2],
        ErrorClass::BadRequest,
        "the previous node's body hash differs",
    );

    // Two requests handed to the nodes in different orders: every pairing
    // mixes them, so all six sessions are refused.
    let a = consistent(request_id(4), Fr::from(4u64));
    let b = consistent(request_id(5), Fr::from(5u64));
    let order = [[&a, &b], [&b, &a], [&a, &b]];
    let results = run3(|i| order[i].map(|req| try_open(&meshes[i], &req[i])));
    for pair in &results {
        for result in pair {
            assert_refused(result, ErrorClass::BadRequest, "runs request");
        }
    }
    assert!(meshes.iter().all(|m| m.lock().is_free()));
}

/// A TCP connection to a node's mesh port that sends nothing while a
/// session opens (anyone who can reach the port can make one) does not hold
/// the opening: the node drops it after the handshake bound, accepts its
/// real peers and the session opens, well within the connect timeout.
#[test]
fn a_silent_connection_to_the_mesh_port_does_not_hold_the_session() {
    let meshes = meshes();
    let hs = consistent(request_id(20), Fr::from(20u64));
    let port = meshes[2].config().bind_addr();
    let start = Instant::now();
    let results = thread::scope(|s| {
        // party 2 accepts from parties 0 and 1; the stranger reaches it first
        let last = s.spawn(|| try_open(&meshes[2], &hs[2]));
        let silent = loop {
            match std::net::TcpStream::connect(port) {
                Ok(stream) => break stream,
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        };
        thread::sleep(Duration::from_millis(300));
        let first = [0, 1].map(|i| {
            s.spawn({
                let (m, h) = (&meshes[i], &hs[i]);
                move || try_open(m, h)
            })
        });
        let first = first.map(|h| h.join().unwrap());
        let last = last.join().unwrap();
        drop(silent);
        [first[0].clone(), first[1].clone(), last]
    });
    for (i, r) in results.iter().enumerate() {
        assert!(r.is_ok(), "party {i}: {r:?}");
    }
    assert!(start.elapsed() < CONNECT, "took {:?}", start.elapsed());
}

/// A session past its whole-session bound fails its next send or receive,
/// however quickly each peer answers.
#[test]
fn a_session_past_its_deadline_fails() {
    let ids = identities();
    let ports: [u16; 3] = reserve_ports();
    let pinned = [ids[0].cert.as_slice(), &ids[1].cert, &ids[2].cert];
    let hs = consistent(request_id(21), Fr::from(21u64));
    let errors = run3(|i| {
        let config = config(ports, i, &ids[i], pinned).with_session_timeout(Duration::from_secs(2));
        let mesh = Mesh::new(config);
        let held = mesh.lock().acquire();
        let session = open_session(&mesh, &held, &hs[i]).unwrap();
        thread::sleep(Duration::from_secs(2));
        match round_state(&session) {
            Ok(_) => panic!("party {i}: the session ran past its deadline"),
            Err(e) => e.to_string(),
        }
    });
    for e in errors {
        assert!(e.contains("deadline"), "{e}");
    }
}

#[test]
fn a_peer_without_its_pinned_certificate_cannot_join() {
    let ids = identities();
    let rogue = mesh_identity(2).unwrap();
    let hs = consistent(request_id(6), Fr::from(6u64));
    let honest = [ids[0].cert.as_slice(), &ids[1].cert, &ids[2].cert];

    let cases: [(&str, usize, &MeshIdentity, [&[u8]; 3]); 3] = [
        // Seat 2 with a fresh certificate nobody pinned: the honest nodes
        // connect to it and refuse its server certificate.
        (
            "unpinned server",
            2,
            &rogue,
            [&ids[0].cert, &ids[1].cert, &rogue.cert],
        ),
        // Seat 0 with a fresh certificate: the honest nodes accept its
        // connections and refuse its client certificate.
        (
            "unpinned client",
            0,
            &rogue,
            [&rogue.cert, &ids[1].cert, &ids[2].cert],
        ),
        // Seat 2 served with party 1's own pinned key and certificate: the
        // chain verifies, the seat's pin does not match.
        (
            "wrong seat",
            2,
            &ids[1],
            [&ids[0].cert, &ids[1].cert, &ids[1].cert],
        ),
    ];
    for (case, seat, identity, rogue_pins) in cases {
        let ports: [u16; 3] = reserve_ports();
        let start = Instant::now();
        let results = run3(|i| {
            let config = if i == seat {
                config(ports, i, identity, rogue_pins)
            } else {
                config(ports, i, &ids[i], honest)
            }
            .with_timeouts(SHORT, IO);
            try_open(&Mesh::new(config), &hs[i])
        });
        for (i, result) in results.iter().enumerate() {
            if i == seat {
                continue;
            }
            let err = result.as_ref().expect_err(case);
            assert_eq!(err.class, ErrorClass::MpcFailure, "{case}: {err}");
            assert!(
                err.message.contains("the mesh did not open"),
                "{case}: {err}"
            );
        }
        // At least one honest node saw the certificate itself refused (the
        // other may see the rogue's connection close first).
        assert!(
            results
                .iter()
                .enumerate()
                .any(|(i, r)| i != seat
                    && r.as_ref().is_err_and(|e| e.message.contains("certificate"))),
            "{case}: no node refused the certificate"
        );
        assert!(
            start.elapsed() < SHORT + Duration::from_secs(5),
            "{case}: took too long"
        );
    }
}

#[test]
fn the_mesh_ports_stay_reserved_between_sessions() {
    let meshes = meshes();
    for n in [9, 10] {
        let hs = consistent(request_id(n), Fr::from(n));
        run3(|i| {
            let held = meshes[i].lock().acquire();
            let session = open_session(&meshes[i], &held, &hs[i]).unwrap();
            round_state(&session).unwrap();
        });
        // No session is open: a socket without SO_REUSEADDR (another test
        // process probing for a port, an outgoing connection) still cannot
        // take a mesh port, and the next session binds it again.
        for mesh in &meshes {
            let addr = mesh.config().bind_addr();
            let probe = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
            assert!(
                probe.bind(&addr.into()).is_err(),
                "{addr} was free between sessions"
            );
        }
    }
}

fn configs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("data/configs")
}

#[test]
fn the_party_configs_use_the_harness_ports_and_the_dev_keys() {
    let keys = Path::new(env!("CARGO_MANIFEST_DIR")).join("../data/keys");
    for i in 0..3 {
        let path = configs_dir().join(format!("party{i}.toml"));
        let file: NetworkConfigFile =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(file.my_id, i);
        assert_eq!(
            file.bind_addr,
            format!("127.0.0.1:{}", 10200 + i).parse().unwrap()
        );
        for (j, party) in file.parties.iter().enumerate() {
            assert_eq!(
                (party.id, party.dns_name.to_string()),
                (j, format!("127.0.0.1:{}", 10200 + j))
            );
        }
        let tls = file.tls.unwrap();
        let resolved =
            |p: &Path| std::fs::canonicalize(configs_dir().join(p).parent().unwrap()).ok();
        if let Some(dir) = resolved(&tls.key) {
            assert_eq!(Some(dir), std::fs::canonicalize(&keys).ok());
        }
        assert_eq!(
            tls.key.file_name().unwrap(),
            format!("mesh-key{i}.der").as_str()
        );
        let certs: Vec<_> = tls
            .certs
            .iter()
            .map(|c| c.file_name().unwrap().to_owned())
            .collect();
        assert_eq!(
            certs,
            ["mesh-cert0.der", "mesh-cert1.der", "mesh-cert2.der"]
        );
    }
}

#[test]
fn a_config_without_tls_is_refused() {
    let text = std::fs::read_to_string(configs_dir().join("party0.toml")).unwrap();
    let mut file: NetworkConfigFile = toml::from_str(&text).unwrap();
    file.tls = None;
    let err = MeshConfig::from_file(file, &configs_dir()).unwrap_err();
    assert!(format!("{err}").contains("no [tls] section"), "{err}");
}

#[test]
fn the_base_port_moves_all_three_ports() {
    let ids = identities();
    let pinned = [ids[0].cert.as_slice(), &ids[1].cert, &ids[2].cert];
    let moved = config([10200, 10201, 10202], 1, &ids[1], pinned)
        .with_base_port(20300)
        .unwrap();
    assert_eq!(moved.bind_addr(), "127.0.0.1:20301".parse().unwrap());
    assert_eq!(
        [0, 1, 2].map(|j| moved.address(j)),
        ["127.0.0.1:20300", "127.0.0.1:20301", "127.0.0.1:20302"]
    );
}

/// The development certificate set (`certs::generate`): a second run keeps
/// every file, a missing file regenerates its plane only, and the private
/// keys are the owner's alone.
#[test]
fn generation_is_idempotent_per_plane() {
    use sidecar_node::certs::generate;
    use std::fs;
    let tmp = sidecar_test_fixtures::dirs::TempDir::new("certs");
    let out = tmp.path().join("certs");

    let first = generate(&out, false).unwrap();
    assert_eq!(first.written.len(), 6 + 10);
    assert!(first.kept.is_empty());
    let cert0 = fs::read(out.join("mesh-cert0.der")).unwrap();

    let second = generate(&out, false).unwrap();
    assert!(second.written.is_empty());
    assert_eq!(second.kept.len(), 16);
    assert_eq!(fs::read(out.join("mesh-cert0.der")).unwrap(), cert0);

    // A missing file regenerates its plane only.
    fs::remove_file(out.join("https-node1-key.pem")).unwrap();
    let third = generate(&out, false).unwrap();
    assert_eq!(third.written.len(), 10);
    assert_eq!(fs::read(out.join("mesh-cert0.der")).unwrap(), cert0);

    use std::os::unix::fs::PermissionsExt;
    let mode = |n: &str| fs::metadata(out.join(n)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode("mesh-key0.der"), 0o600);
    assert_eq!(mode("https-ca-key.pem"), 0o600);
    assert_eq!(mode("mesh-cert0.der"), 0o644);
}
