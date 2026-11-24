//! Opening an MPC session over the mesh: the TLS connections under the mesh
//! lock and the session handshake (lifecycle step 10), before anything else
//! runs on the session.
//!
//! The handshake, both its rounds (the messages, then the verdicts), is
//! `sidecar_core::handshake::exchange`, the same code the request lifecycle
//! runs at step 10; this module opens the mesh under the held lock and runs
//! it.
//! A session opens only when all three verdicts accept; otherwise every node
//! refuses (400) and closes the session before witness extension or any
//! SAMPLE.

use bytes::Bytes;
use mpc_net::{ConnectionStats, Network};
use sidecar_core::Refusal;
use sidecar_core::handshake::Handshake;
pub use sidecar_core::handshake::{Verdict, exchange};
use sidecar_core::mesh_lock::MeshHeld;

use crate::mesh::{Mesh, NodeNetwork};

/// An open MPC session: the mesh connections, opened under this node's mesh
/// lock, which its opener holds until it drops the session. Run the round on
/// it ([`Session::net`], or the session itself, which is a `Network`);
/// dropping it closes the connections.
pub struct Session {
    net: NodeNetwork,
}

impl Session {
    /// Open the mesh while `held`, this mesh's lock, is held, without the
    /// handshake (500 when the mesh cannot be opened): the lifecycle runs
    /// the handshake itself at step 10, and recovery runs its own exchange.
    pub fn connect(mesh: &Mesh, held: &MeshHeld) -> Result<Session, Refusal> {
        if !mesh.lock().holds(held) {
            return Err(Refusal::mpc_failure(
                "MPC session: the held mesh lock is another mesh's",
            ));
        }
        let net = NodeNetwork::connect(mesh.config()).map_err(|e| {
            Refusal::mpc_failure(format!("MPC session: the mesh did not open: {e:#}"))
        })?;
        Ok(Session { net })
    }

    /// The session's network, for `executor::round_state` and
    /// `executor::execute`.
    pub fn net(&self) -> &NodeNetwork {
        &self.net
    }

    /// This node's party id.
    pub fn party(&self) -> usize {
        self.net.id()
    }
}

impl Network for Session {
    fn id(&self) -> usize {
        self.net.id()
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        self.net.send(to, data)
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        self.net.recv(from)
    }

    fn flush(&self) -> eyre::Result<()> {
        self.net.flush()
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        self.net.get_connection_stats()
    }
}

/// Open the session while `held`, this mesh's lock, is held, and run the
/// handshake. Refuses 400 when any node's handshake check fails, 500 when
/// the mesh cannot be opened or a peer does not answer; either way nothing
/// ran. The caller drops the session before it releases the lock.
pub fn open_session(
    mesh: &Mesh,
    held: &MeshHeld,
    handshake: &Handshake,
) -> Result<Session, Refusal> {
    let id = &handshake.request_id;
    tracing::debug!(request_id = %id, "opening the MPC session");
    let session = Session::connect(mesh, held)?;
    exchange(&session.net, handshake)?;
    tracing::debug!(request_id = %id, "MPC session open, handshake accepted");
    Ok(session)
}
