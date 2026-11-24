//! The Rep3 mesh between the three nodes, over mutual TLS with every party's
//! certificate pinned, and the node-wide mesh session lock.
//!
//! TLS only: a party config without `[tls]` is refused, and there is no
//! plaintext fallback. A node keeps a [`Mesh`]: its party config and its
//! lock. Each MPC session opens a fresh [`NodeNetwork`] under that lock
//! ([`crate::session::open_session`]) and closes it when the session ends, so
//! one listener binds the mesh port per session and nothing outlives a request.
//!
//! The party config is mpc-net's TOML format (`NetworkConfigFile`):
//!
//! ```toml
//! my_id = 0
//! bind_addr = "127.0.0.1:10200"
//! connect_timeout = "30s"
//! timeout = "10m"
//! [[parties]]
//! id = 0
//! dns_name = "127.0.0.1:10200"
//! # ... parties 1 and 2
//! [tls]
//! key = "../../../data/keys/mesh-key0.der"
//! certs = ["../../../data/keys/mesh-cert0.der", "...cert1.der", "...cert2.der"]
//! ```
//!
//! Relative TLS paths resolve against the directory of the config file.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use eyre::{Context, ContextCompat, bail, ensure};
use mpc_net::config::{
    Address, NetworkConfig, NetworkConfigFile, NetworkParty, TlsConfig, TlsConfigFile,
};
use mpc_net::tls_session_blocking::{TlsNetwork as StreamsNetwork, TlsStream};
use mpc_net::{ConnectionStats, DEFAULT_MAX_FRAME_LENGTH, Network};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use sidecar_core::mesh_lock::MeshLock;
use sidecar_core::request::NODES;
use socket2::{Domain, SockRef, Socket, TcpKeepalive, Type};

// Operator knob: DESIGN.md, "Configuration reference" (mesh
// `connect_timeout`, `timeout`; the node's `mesh_session_timeout_secs`). The
// defaults below apply when a config sets none.
/// Default bound on opening a session: connecting to and accepting from both
/// peers, every TLS handshake and connection header included.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default bound on one send or receive inside a session.
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(600);
/// Default bound on one whole session, from opening to its last send or
/// receive.
pub const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(3600);

/// One node's validated mesh configuration: its party id, bind address, the
/// three party addresses, its TLS key and the three pinned certificates, and
/// its timeouts.
#[derive(Clone, Debug)]
pub struct MeshConfig {
    net: NetworkConfig,
    session_timeout: Duration,
}

impl MeshConfig {
    /// Read a party config file. Relative TLS paths resolve against the
    /// file's directory.
    pub fn load(path: &Path) -> eyre::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the mesh config {}", path.display()))?;
        let file: NetworkConfigFile = toml::from_str(&text)
            .with_context(|| format!("parsing the mesh config {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::from_file(file, base).with_context(|| format!("mesh config {}", path.display()))
    }

    /// A parsed party config whose relative TLS paths resolve against `base`.
    pub fn from_file(mut file: NetworkConfigFile, base: &Path) -> eyre::Result<Self> {
        // The mesh runs only over pinned TLS; a config without
        // a [tls] section is refused, and there is no plaintext fallback or
        // flag. The mesh carries the parties' reshared values and the
        // handshake's summand hashes, and over plaintext an unauthenticated
        // peer could join a session. Development uses the dev certificates
        // (`sidecar-node gen-certs`), which cost nothing to make.
        let Some(tls) = file.tls.take() else {
            bail!(
                "the mesh config has no [tls] section; the mesh runs only over TLS with the three \
                 party certificates pinned (`sidecar-node gen-certs` makes development ones)"
            );
        };
        let resolve = |p: PathBuf| if p.is_relative() { base.join(p) } else { p };
        file.tls = Some(TlsConfigFile {
            key: resolve(tls.key),
            certs: tls.certs.into_iter().map(resolve).collect(),
        });
        Self::new(NetworkConfig::try_from(file)?)
    }

    /// A configuration from in-memory parts: party `party` binds `bind_addr`,
    /// reaches party j at `addrs[j]` (`host:port`; the host must be a name or
    /// IP in party j's certificate), and holds the PKCS#8 DER `key` of its
    /// certificate `certs[party]`.
    pub fn from_der(
        party: usize,
        bind_addr: SocketAddr,
        addrs: [String; NODES],
        key: Vec<u8>,
        certs: [Vec<u8>; NODES],
    ) -> eyre::Result<Self> {
        let parties = addrs
            .into_iter()
            .enumerate()
            .map(|(id, addr)| {
                let address: Address = addr
                    .parse()
                    .map_err(|e| eyre::eyre!("party {id} address `{addr}`: {e}"))?;
                Ok(NetworkParty::new(id, address))
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        let tls = TlsConfig::new(
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            certs.into_iter().map(CertificateDer::from).collect(),
        );
        Self::new(
            NetworkConfig::builder(party, bind_addr, parties)
                .tls_config(tls)
                .build(),
        )
    }

    /// Validate a mesh-level configuration: three parties with ids 0, 1, 2, a
    /// party id among them, a TLS section with exactly three certificates.
    /// Fills in the default timeouts.
    pub fn new(mut net: NetworkConfig) -> eyre::Result<Self> {
        ensure!(
            net.parties.len() == NODES,
            "the mesh has {} parties, not {NODES}",
            net.parties.len()
        );
        net.parties.sort_by_key(|p| p.id);
        for (expected, party) in net.parties.iter().enumerate() {
            ensure!(
                party.id == expected,
                "the party ids must be 0, 1 and 2 (found {})",
                party.id
            );
        }
        ensure!(
            net.my_id < NODES,
            "my_id {} is not a party id (0, 1 or 2)",
            net.my_id
        );
        let Some(tls) = &net.tls else {
            bail!("the mesh runs only over TLS: the config has no TLS key and certificates");
        };
        ensure!(
            tls.certs.len() == NODES,
            "the TLS section pins {} certificates, not one per party ({NODES})",
            tls.certs.len()
        );
        net.connect_timeout.get_or_insert(DEFAULT_CONNECT_TIMEOUT);
        net.timeout.get_or_insert(DEFAULT_IO_TIMEOUT);
        Ok(MeshConfig {
            net,
            session_timeout: DEFAULT_SESSION_TIMEOUT,
        })
    }

    /// This node's party id.
    pub fn party(&self) -> usize {
        self.net.my_id
    }

    /// The address the session listener binds.
    pub fn bind_addr(&self) -> SocketAddr {
        self.net.bind_addr
    }

    /// Where party `id` is reached.
    pub fn address(&self, id: usize) -> String {
        self.net.parties[id].dns_name.to_string()
    }

    /// The bound on connecting to and accepting from both peers.
    pub fn connect_timeout(&self) -> Duration {
        self.net.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT)
    }

    /// The same configuration with other timeouts.
    pub fn with_timeouts(mut self, connect: Duration, io: Duration) -> Self {
        self.net.connect_timeout = Some(connect);
        self.net.timeout = Some(io);
        self
    }

    /// The same configuration with another bound on one whole session.
    pub fn with_session_timeout(mut self, session: Duration) -> Self {
        self.session_timeout = session;
        self
    }

    /// The same configuration with the mesh on ports `base`, `base + 1` and
    /// `base + 2`: party j is reached on `base + j` and this node binds
    /// `base + my_id`, keeping every host.
    pub fn with_base_port(mut self, base: u16) -> eyre::Result<Self> {
        for party in &mut self.net.parties {
            party.dns_name.port = base
                .checked_add(party.id as u16)
                .ok_or_else(|| eyre::eyre!("mesh base port {base} leaves no room for 3 ports"))?;
        }
        self.net.bind_addr.set_port(base + self.net.my_id as u16);
        Ok(self)
    }
}

// How a session opens, and what bounds it. The connection set-up is
// mpc-net's TlsNetwork's, byte for byte on the wire (per peer two TLS
// connections, the lower party id connecting; each opens with the header
// `0u64, party_id u64, direction u8`, big-endian), run here so that every
// step has a deadline: mpc-net's TlsNetwork clears the read timeout of an
// accepted connection before its TLS handshake and header, so one silent
// TCP connection to the mesh port would block the session, and the locks
// it holds, for ever. Here the whole opening shares one deadline
// (`connect_timeout`): each accept, connect, handshake and header read
// waits at most until it, and an accepted connection gets at most
// HANDSHAKE_TIMEOUT of it; an accepted connection that fails its handshake,
// presents no pinned certificate, sends a wrong header or stays silent is
// dropped and the next one accepted, so a stranger delays the opening and
// can make it fail at the deadline, but never holds it longer. The streams
// then go to mpc-net's own network over established streams (its session
// network), with no read timeout on the sockets (its reader threads block
// on them) and each receive bounded by `timeout`. The
// whole session is bounded by `mesh_session_timeout_secs`: a send, receive
// or flush after it fails, so a peer that keeps answering just inside the
// receive timeout cannot hold the mesh past it plus one receive timeout.
// The mesh port is still reachable by anyone who can route to it; firewall
// it to the two peers' addresses.
/// One MPC session's transport: a TLS connection pair to each peer, both
/// directions authenticated against the pinned certificates.
pub struct NodeNetwork {
    net: StreamsNetwork,
    /// When the session's time is up.
    deadline: Instant,
}

/// The connecting party's send direction (its first connection to a peer).
const STREAM_SEND: u8 = 0;
/// The connecting party's receive direction.
const STREAM_RECV: u8 = 1;
/// The connection header's length: `0u64, party_id u64, direction u8`.
const HEADER_LEN: usize = 17;
/// The most an accepted connection is given to finish its TLS handshake and
/// send its header (within the connect timeout).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

impl NodeNetwork {
    /// Bind the mesh port, connect to both peers (the lower id connects, the
    /// higher accepts) and check each peer presents the certificate pinned
    /// for its party id. Fails when a peer presents any other certificate,
    /// or does not arrive and finish its handshake within the connect
    /// timeout.
    pub fn connect(config: &MeshConfig) -> eyre::Result<Self> {
        sidecar_http::tls::install_crypto_provider();
        let started = Instant::now();
        let streams = open_streams(config, started + config.connect_timeout())?;
        let net = &config.net;
        Ok(NodeNetwork {
            net: StreamsNetwork::new(
                net.my_id,
                streams,
                net.max_frame_length.unwrap_or(DEFAULT_MAX_FRAME_LENGTH),
                net.timeout,
                net.flush_timeout,
            )?,
            deadline: started + config.session_timeout,
        })
    }

    fn in_time(&self) -> eyre::Result<()> {
        ensure!(
            Instant::now() <= self.deadline,
            "the MPC session ran past its deadline (mesh_session_timeout_secs)"
        );
        Ok(())
    }
}

/// The time left until `deadline`; an error naming `what` when none is.
fn left(deadline: Instant, what: &str) -> eyre::Result<Duration> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => bail!("{what}: the connect timeout passed"),
    }
}

/// Both TLS connections to each peer, by party id, as `(send, receive)`.
fn open_streams(
    config: &MeshConfig,
    deadline: Instant,
) -> eyre::Result<HashMap<usize, (TlsStream, TlsStream)>> {
    let net = &config.net;
    let me = net.my_id;
    let tls = net.tls.as_ref().context("the mesh runs only over TLS")?;
    let (client, server) = tls.into_rustls_configs(me)?;
    let listener = listen(net.bind_addr)?;
    let mut pending: HashMap<usize, (Option<TlsStream>, Option<TlsStream>)> = HashMap::new();
    // the order of mpc-net's TlsNetwork, which the peers follow too
    for direction in [STREAM_SEND, STREAM_RECV] {
        for party in &net.parties {
            let other = party.id;
            if other > me {
                let stream = connect(
                    &party.dns_name,
                    &client,
                    tls,
                    me,
                    other,
                    direction,
                    deadline,
                )
                .with_context(|| format!("connecting to party {other}"))?;
                let entry = pending.entry(other).or_default();
                // our send direction first, then our receive direction
                if direction == STREAM_SEND {
                    entry.0 = Some(stream);
                } else {
                    entry.1 = Some(stream);
                }
            } else if other < me {
                let (from, theirs, stream) =
                    accept(&listener, &server, tls, me, &pending, deadline)?;
                let entry = pending.entry(from).or_default();
                // the peer's send direction is our receive direction
                if theirs == STREAM_SEND {
                    entry.1 = Some(stream);
                } else {
                    entry.0 = Some(stream);
                }
            }
        }
    }
    pending
        .into_iter()
        .map(|(other, pair)| match pair {
            (Some(send), Some(recv)) => {
                release(&send, net.timeout)?;
                release(&recv, net.timeout)?;
                Ok((other, (send, recv)))
            }
            _ => bail!("party {other} opened one of its two connections"),
        })
        .collect()
}

/// The session listener on `addr`: the address reusable at once (the next
/// session binds it again), keepalive on, dual-stack on IPv6.
fn listen(addr: SocketAddr) -> eyre::Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_tcp_keepalive(&TcpKeepalive::new().with_interval(Duration::from_secs(1)))?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("binding the mesh port {addr}"))?;
    socket.listen(128)?;
    Ok(socket.into())
}

/// A connected socket's handshake bounds: reads and writes wait at most
/// until `deadline` while the TLS handshake and the header run.
fn bound(tcp: &TcpStream, deadline: Instant, what: &str) -> eyre::Result<()> {
    let left = left(deadline, what)?;
    tcp.set_read_timeout(Some(left))?;
    tcp.set_write_timeout(Some(left))?;
    tcp.set_nodelay(true)?;
    Ok(())
}

/// A session socket's bounds once it is open: no read timeout (mpc-net's
/// reader thread blocks on it; each receive is bounded by `timeout`), each
/// write bounded by `timeout`.
fn release(stream: &TlsStream, io: Option<Duration>) -> eyre::Result<()> {
    let tcp = match stream {
        TlsStream::Client(s) => &s.sock,
        TlsStream::Server(s) => &s.sock,
    };
    tcp.set_read_timeout(None)?;
    tcp.set_write_timeout(io)?;
    Ok(())
}

/// Connect to party `other` at `addr` (retrying until `deadline`), run the
/// TLS handshake, send the header and check the peer's certificate.
fn connect(
    addr: &Address,
    client: &Arc<rustls::ClientConfig>,
    tls: &TlsConfig,
    me: usize,
    other: usize,
    direction: u8,
    deadline: Instant,
) -> eyre::Result<TlsStream> {
    let what = format!("connecting to party {other} at {addr}");
    let socket = addr
        .to_socket_addrs()?
        .next()
        .with_context(|| format!("{what}: the address does not resolve"))?;
    let tcp = loop {
        match TcpStream::connect_timeout(&socket, left(deadline, &what)?) {
            Ok(tcp) => break tcp,
            Err(_) => std::thread::sleep(Duration::from_millis(100).min(left(deadline, &what)?)),
        }
    };
    bound(&tcp, deadline, &what)?;
    let name = ServerName::try_from(addr.hostname.clone())?;
    let conn = ClientConnection::new(client.clone(), name)?;
    let mut stream = TlsStream::from(StreamOwned::new(conn, tcp));
    let mut header = [0u8; HEADER_LEN];
    header[8..16].copy_from_slice(&(me as u64).to_be_bytes());
    header[16] = direction;
    // the handshake completes within the first write
    stream.write_all(&header)?;
    stream.flush()?;
    let TlsStream::Client(s) = &stream else {
        unreachable!("a connecting party's stream is a client stream")
    };
    tls.verify_peer(&s.conn, other)?;
    Ok(stream)
}

/// Accept the next connection from a party below `me` that completes its
/// TLS handshake within `deadline`, presents the certificate pinned for the
/// party id its header names and opens a direction not opened yet; any
/// other connection is dropped and the next accepted. Returns the party, its
/// direction and the stream.
fn accept(
    listener: &TcpListener,
    server: &Arc<rustls::ServerConfig>,
    tls: &TlsConfig,
    me: usize,
    opened: &HashMap<usize, (Option<TlsStream>, Option<TlsStream>)>,
    deadline: Instant,
) -> eyre::Result<(usize, u8, TlsStream)> {
    let what = "waiting for a peer to connect";
    // why the last connection was dropped, for the timeout's message
    let mut dropped = String::new();
    loop {
        let timed_out = |dropped: &str| eyre::eyre!("{what}: the connect timeout passed{dropped}");
        let Ok(left) = left(deadline, what) else {
            return Err(timed_out(&dropped));
        };
        // the listener's read timeout bounds accept()
        SockRef::from(listener).set_read_timeout(Some(left))?;
        let (tcp, from_addr) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(timed_out(&dropped));
            }
            Err(e) => return Err(e).context(what),
        };
        let handshake = move || -> eyre::Result<(usize, u8, TlsStream)> {
            // a connection gets HANDSHAKE_TIMEOUT at most, so one that stays
            // silent leaves the real peer time to connect
            bound(&tcp, deadline.min(Instant::now() + HANDSHAKE_TIMEOUT), what)?;
            let conn = ServerConnection::new(server.clone())?;
            let mut stream = TlsStream::from(StreamOwned::new(conn, tcp));
            let mut header = [0u8; HEADER_LEN];
            stream.read_exact(&mut header)?;
            let n = u64::from_be_bytes(header[..8].try_into().expect("8 bytes"));
            let from = u64::from_be_bytes(header[8..16].try_into().expect("8 bytes"));
            let direction = header[16];
            ensure!(n == 0, "network index {n}, not 0");
            let from = usize::try_from(from).ok().filter(|f| *f < me);
            let Some(from) = from else {
                bail!("a header naming a party that does not connect to party {me}")
            };
            ensure!(
                direction == STREAM_SEND || direction == STREAM_RECV,
                "direction {direction}"
            );
            let TlsStream::Server(s) = &stream else {
                unreachable!("an accepting party's stream is a server stream")
            };
            tls.verify_peer(&s.conn, from)?;
            let taken = opened.get(&from).is_some_and(|(send, recv)| {
                // the peer's send direction is our receive direction
                if direction == STREAM_SEND {
                    recv.is_some()
                } else {
                    send.is_some()
                }
            });
            ensure!(!taken, "party {from} opened direction {direction} twice");
            Ok((from, direction, stream))
        };
        match handshake() {
            Ok(accepted) => return Ok(accepted),
            Err(e) => {
                tracing::warn!(
                    peer = %from_addr,
                    error = %format!("{e:#}"),
                    "mesh: dropped a connection that did not open as a peer's"
                );
                dropped = format!(" (the last connection, from {from_addr}, was dropped: {e:#})");
            }
        }
    }
}

impl Network for NodeNetwork {
    fn id(&self) -> usize {
        self.net.id()
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        self.in_time()?;
        self.net.send(to, data)
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        self.in_time()?;
        self.net.recv(from)
    }

    fn flush(&self) -> eyre::Result<()> {
        self.in_time()?;
        self.net.flush()
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        self.net.get_connection_stats()
    }
}

/// A node's mesh: its configuration and its session lock
/// ([`MeshLock`], which the node's lifecycle shares: `App::new`). Clones
/// share the lock, so every request handler of one node holds a clone of one
/// `Mesh`.
#[derive(Clone, Debug)]
pub struct Mesh {
    config: Arc<MeshConfig>,
    lock: MeshLock,
}

impl Mesh {
    pub fn new(config: MeshConfig) -> Self {
        Mesh {
            config: Arc::new(config),
            lock: MeshLock::new(),
        }
    }

    pub fn config(&self) -> &MeshConfig {
        &self.config
    }

    pub fn party(&self) -> usize {
        self.config.party()
    }

    pub fn lock(&self) -> &MeshLock {
        &self.lock
    }
}
