//! The node-wide mesh session lock ([`MeshLock`]) and the witness that it is
//! held ([`MeshHeld`]), which the code that opens a mesh session takes.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

// One mesh session per node at a time, and so one per mesh port.
// Every session binds the node's single mesh port and its peers find it there,
// so two sessions on one node would fight over the port and could pair one
// request's connections with another's. The lock is node-wide (not per
// namespace): a second namespace's request waits here for the mesh but never
// sees the first one's state, which its own namespace lock and the pipeline
// keep apart. It is taken at lifecycle step 10, held through proving, and
// released when the session closes, whether it succeeded, was refused or
// failed. Waiting is unbounded on purpose: the orchestrator serialises
// sessions globally, so a wait here is a request that is already running; a
// node that waits past its peers' connect timeout fails the session (500)
// rather than run it out of order. Parallel sessions would need a port per
// session and a session id in the handshake (sharding, which arrives with
// per-queue locks; until then the orchestrator keeps its one global session
// lock, docs/DECISIONS.md section 5).
/// The node-wide mesh session lock. Clones share one lock: a node's
/// lifecycle ([`crate::Node::with_mesh_lock`]) and the mesh it connects
/// hold clones of one.
#[derive(Clone, Debug, Default)]
pub struct MeshLock(Arc<Mutex<()>>);

/// Proof that the holder holds a [`MeshLock`]: the code that opens a mesh
/// session takes it, and checks it is its own mesh's lock
/// ([`MeshLock::holds`]). Dropping it releases the lock, so the session it
/// opened is dropped first.
#[derive(Debug)]
pub struct MeshHeld<'a> {
    lock: &'a MeshLock,
    _guard: MutexGuard<'a, ()>,
}

impl MeshLock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wait for the lock (on a blocking thread: the lifecycle runs on one).
    pub fn acquire(&self) -> MeshHeld<'_> {
        MeshHeld {
            lock: self,
            _guard: self.0.lock().unwrap_or_else(PoisonError::into_inner),
        }
    }

    /// Whether this lock is free right now.
    pub fn is_free(&self) -> bool {
        self.0.try_lock().is_ok()
    }

    /// Whether `held` is this lock (or a clone of it).
    pub fn holds(&self, held: &MeshHeld<'_>) -> bool {
        Arc::ptr_eq(&self.0, &held.lock.0)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::MeshLock;

    /// A second holder of the lock (a clone, as a node's two request
    /// handlers hold one) waits until the first releases it; while one holds
    /// it, it is not free.
    #[test]
    fn the_mesh_lock_serialises_two_holders() {
        let lock = MeshLock::new();
        let (taken_tx, taken_rx) = mpsc::channel::<Instant>();
        let first = lock.acquire();
        assert!(!lock.is_free(), "the first holder holds it");
        let released = thread::scope(|s| {
            let second = lock.clone();
            s.spawn(move || {
                let _held = second.acquire();
                taken_tx.send(Instant::now()).unwrap();
            });
            assert!(
                taken_rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "the second holder took the lock while the first held it"
            );
            let released = Instant::now();
            drop(first);
            released
        });
        assert!(taken_rx.recv().unwrap() >= released, "it waited");
        assert!(lock.is_free());
    }

    /// A witness belongs to its lock and its clones, not to another lock.
    #[test]
    fn a_witness_is_its_own_locks() {
        let (lock, other) = (MeshLock::new(), MeshLock::new());
        let held = lock.acquire();
        assert!(lock.holds(&held));
        assert!(lock.clone().holds(&held));
        assert!(!other.holds(&held));
    }
}
