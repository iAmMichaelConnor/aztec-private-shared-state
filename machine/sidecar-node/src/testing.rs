//! Test support (feature `test-util`): loopback ports for the meshes of
//! tests that run in parallel with other test processes and e2e runs on one
//! machine.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;

use socket2::{Domain, Socket, Type};

/// The sockets that hold this process's reserved ports until it exits.
static RESERVED: Mutex<Vec<Socket>> = Mutex::new(Vec::new());

/// `N` loopback ports reserved for this process until it exits, for mesh
/// configs whose sessions bind them one after another.
///
/// A mesh binds its port only while a session opens and releases it when the
/// session ends, so a port that was merely free at test start (a listener
/// bound to port 0, then dropped) can be taken between sessions by any
/// socket on the machine: an outgoing connection of another test process or
/// of an e2e run gets its local port from the same ephemeral range, and the
/// next session fails with "Address already in use". Here each port stays
/// bound by a socket with SO_REUSEADDR that never listens. The kernel lets
/// the session's own listener (also SO_REUSEADDR) bind beside it, and never
/// hands an explicitly bound port to a connect or a bind to port 0, so
/// nothing else lands on the port while the process lives.
pub fn reserve_ports<const N: usize>() -> [u16; N] {
    let mut held = RESERVED.lock().unwrap_or_else(|e| e.into_inner());
    std::array::from_fn(|_| {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).expect("a TCP socket");
        socket
            .set_reuse_address(true)
            .expect("setting SO_REUSEADDR");
        socket
            .bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
            .expect("binding a loopback port");
        let port = socket
            .local_addr()
            .ok()
            .and_then(|a| a.as_socket())
            .expect("the bound address")
            .port();
        held.push(socket);
        port
    })
}
