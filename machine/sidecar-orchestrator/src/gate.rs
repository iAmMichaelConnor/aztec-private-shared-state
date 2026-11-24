//! The global session gate: one execute, REGISTER or DISABLE session at a
//! time across every namespace (`crate::api`, "The orchestrator's one global
//! session lock"), served in two classes. A scheduler attempt (and the
//! operator's pause) waiting for the gate is served before any waiting
//! public session, first come first served within each class, except that
//! after [`SCHEDULER_SESSIONS_PER_PUBLIC`] scheduler sessions in a row a
//! waiting public session goes next, so busy queues never starve an owner's
//! DISABLE, a REGISTER or a sidecar-path execute; public
//! sessions wait in a bounded room, at most [`PUBLIC_WAITING_PER_NAMESPACE`]
//! per namespace and [`PUBLIC_WAITING_TOTAL`] in all, and one past either
//! bound is turned away at once ([`Busy`], 503 with `Retry-After`). So no
//! namespace's public traffic can hold a queue's scheduler behind it until
//! its head goes stale, and one namespace cannot fill the room alone.
//!
//! A waiter that is dropped (a client that disconnects while it waits)
//! gives up its place; a permit is released when it is dropped, and the gate
//! then passes to the next waiter.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use sidecar_core::field::{Fr, fr_to_hex};
use tokio::sync::oneshot;

// Operator knob: DESIGN.md, "Configuration reference" (public session
// waiting room; no knob). A round costs seconds to minutes, so 4 waiting
// sessions of one namespace and 32 in all is already minutes of queue; a
// client past them is told to come back rather than held on a connection.
/// The most public sessions of one namespace that wait for the gate.
pub const PUBLIC_WAITING_PER_NAMESPACE: usize = 4;
/// The most public sessions that wait for the gate in all.
pub const PUBLIC_WAITING_TOTAL: usize = 32;
/// The `Retry-After` of a public session turned away.
pub const RETRY_AFTER: Duration = Duration::from_secs(10);

// Operator knob: DESIGN.md, "Configuration reference" (public session
// waiting room; no knob). Strict priority would let two busy tip queues, or
// one that recomputes every block, hold every public session for ever. One
// public session after four scheduler sessions bounds a public wait by four
// scheduler rounds per session ahead of it, and costs the schedulers at most
// one round in five while public sessions wait.
/// How many scheduler sessions in a row are served before a waiting public
/// one.
pub const SCHEDULER_SESSIONS_PER_PUBLIC: usize = 4;

/// Who asks for the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// A scheduler attempt or the operator's pause: served first, never
    /// turned away.
    Scheduler,
    /// A public execute, REGISTER or DISABLE session of a namespace.
    Public(Fr),
}

/// A public session turned away: the waiting room was full.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Busy {
    pub message: String,
    pub retry_after: Duration,
}

/// The gate itself.
pub struct SessionGate {
    state: Arc<Mutex<State>>,
    per_namespace: usize,
    total: usize,
}

#[derive(Default)]
struct State {
    /// A permit is out (or being handed to the next waiter).
    held: bool,
    /// Scheduler sessions served since the last public one.
    since_public: usize,
    next_id: u64,
    first: VecDeque<Waiter>,
    public: VecDeque<Waiter>,
}

struct Waiter {
    id: u64,
    namespace: Option<Fr>,
    wake: oneshot::Sender<()>,
}

/// The gate, held until dropped.
pub struct Permit {
    state: Arc<Mutex<State>>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        release(&mut lock(&self.state));
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Count a session of `public`'s class as served.
fn served(state: &mut State, public: bool) {
    state.since_public = if public { 0 } else { state.since_public + 1 };
}

/// Pass the gate to the next waiter (a scheduler first, a public one once
/// [`SCHEDULER_SESSIONS_PER_PUBLIC`] scheduler sessions ran in a row), or
/// free it.
fn release(state: &mut State) {
    loop {
        let public_due = state.since_public >= SCHEDULER_SESSIONS_PER_PUBLIC;
        let next = match public_due {
            true => state.public.pop_front().or_else(|| state.first.pop_front()),
            false => state.first.pop_front().or_else(|| state.public.pop_front()),
        };
        match next {
            None => {
                state.held = false;
                return;
            }
            // A waiter dropped between its removal and this send leaves the
            // signal unread; its drop (`Waiting`) releases again.
            Some(waiter) => {
                let public = waiter.namespace.is_some();
                if waiter.wake.send(()).is_ok() {
                    served(state, public);
                    return;
                }
            }
        }
    }
}

/// A place in a queue; dropped before it is served, it leaves the queue,
/// or passes on a gate handed to it that it never took.
struct Waiting {
    state: Arc<Mutex<State>>,
    id: u64,
    signal: oneshot::Receiver<()>,
    served: bool,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if self.served {
            return;
        }
        let mut state = lock(&self.state);
        let before = state.first.len() + state.public.len();
        state.first.retain(|w| w.id != self.id);
        state.public.retain(|w| w.id != self.id);
        if state.first.len() + state.public.len() == before && self.signal.try_recv().is_ok() {
            release(&mut state);
        }
    }
}

impl Default for SessionGate {
    fn default() -> Self {
        Self::with_limits(PUBLIC_WAITING_PER_NAMESPACE, PUBLIC_WAITING_TOTAL)
    }
}

impl SessionGate {
    /// A gate whose public waiting room holds `per_namespace` sessions of
    /// one namespace and `total` in all.
    pub fn with_limits(per_namespace: usize, total: usize) -> Self {
        SessionGate {
            state: Arc::new(Mutex::new(State::default())),
            per_namespace,
            total,
        }
    }

    /// Wait for the gate as `class`; a public session is turned away when
    /// the waiting room is full.
    pub async fn enter(&self, class: Class) -> Result<Permit, Busy> {
        let (id, signal) = {
            let mut state = lock(&self.state);
            if !state.held {
                state.held = true;
                served(&mut state, matches!(class, Class::Public(_)));
                return Ok(self.permit());
            }
            let namespace = match class {
                Class::Scheduler => None,
                Class::Public(ns) => {
                    let waiting = state
                        .public
                        .iter()
                        .filter(|w| w.namespace == Some(ns))
                        .count();
                    if waiting >= self.per_namespace || state.public.len() >= self.total {
                        return Err(Busy {
                            message: format!(
                                "the orchestrator is busy: {} sessions of namespace {} and {} in \
                                 all already wait for the session lock; retry later",
                                waiting,
                                fr_to_hex(ns),
                                state.public.len()
                            ),
                            retry_after: RETRY_AFTER,
                        });
                    }
                    Some(ns)
                }
            };
            let id = state.next_id;
            state.next_id += 1;
            let (wake, signal) = oneshot::channel();
            let waiter = Waiter {
                id,
                namespace,
                wake,
            };
            match class {
                Class::Scheduler => state.first.push_back(waiter),
                Class::Public(_) => state.public.push_back(waiter),
            }
            (id, signal)
        };
        let mut waiting = Waiting {
            state: self.state.clone(),
            id,
            signal,
            served: false,
        };
        (&mut waiting.signal)
            .await
            .expect("a waiter's signal is dropped only with the waiter");
        waiting.served = true;
        Ok(self.permit())
    }

    /// The gate for a scheduler attempt or the pause, never turned away.
    pub async fn enter_first(&self) -> Permit {
        self.enter(Class::Scheduler)
            .await
            .unwrap_or_else(|_| unreachable!("a scheduler session is never turned away"))
    }

    fn permit(&self) -> Permit {
        Permit {
            state: self.state.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    fn ns(n: u64) -> Class {
        Class::Public(Fr::from(n))
    }

    fn waiting(gate: &SessionGate) -> usize {
        let state = lock(&gate.state);
        state.first.len() + state.public.len()
    }

    // While a session holds the gate, a scheduler attempt that arrives after
    // two queued public sessions is served before both; the public ones then
    // go in arrival order.
    #[tokio::test]
    async fn a_waiting_scheduler_goes_before_every_waiting_public_session() {
        let gate = Arc::new(SessionGate::default());
        let held = gate.enter(ns(1)).await.unwrap();
        let order = Arc::new(StdMutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for (name, class) in [
            ("public a", ns(1)),
            ("public b", ns(2)),
            ("scheduler", Class::Scheduler),
        ] {
            let (task_gate, order) = (gate.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                let permit = task_gate.enter(class).await.unwrap();
                order.lock().unwrap().push(name);
                tokio::task::yield_now().await;
                drop(permit);
            }));
            // queue them in this order
            while waiting(&gate) < tasks.len() {
                tokio::task::yield_now().await;
            }
        }
        drop(held);
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(
            *order.lock().unwrap(),
            ["scheduler", "public a", "public b"]
        );
        assert!(!lock(&gate.state).held);
    }

    // While schedulers keep the gate busy, a waiting public session is served
    // after every four scheduler sessions in a row, not never.
    #[tokio::test]
    async fn a_public_session_is_served_between_scheduler_sessions() {
        let gate = Arc::new(SessionGate::default());
        let held = gate.enter(ns(1)).await.unwrap();
        let order = Arc::new(StdMutex::new(Vec::new()));
        let mut tasks = Vec::new();
        let classes = [ns(1)]
            .into_iter()
            .chain(std::iter::repeat_n(Class::Scheduler, 6))
            .chain([ns(2)]);
        for (k, class) in classes.enumerate() {
            let (task_gate, order) = (gate.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                let permit = task_gate.enter(class).await.unwrap();
                order.lock().unwrap().push(k);
                tokio::task::yield_now().await;
                drop(permit);
            }));
            while waiting(&gate) < tasks.len() {
                tokio::task::yield_now().await;
            }
        }
        drop(held);
        for task in tasks {
            task.await.unwrap();
        }
        // 0 and 7 are public, 1 to 6 schedulers
        assert_eq!(*order.lock().unwrap(), [1, 2, 3, 4, 0, 5, 6, 7]);
        assert!(!lock(&gate.state).held);
    }

    // The public waiting room is bounded per namespace and in all; a
    // scheduler is never turned away, and a waiter that gives up frees its
    // place.
    #[tokio::test]
    async fn the_public_waiting_room_is_bounded() {
        let gate = Arc::new(SessionGate::with_limits(2, 3));
        let held = gate.enter(ns(1)).await.unwrap();
        let wait = |class: Class| {
            let gate = gate.clone();
            tokio::spawn(async move { gate.enter(class).await.map(drop) })
        };
        let settle = |n: usize| {
            let gate = gate.clone();
            async move {
                while lock(&gate.state).public.len() != n {
                    tokio::task::yield_now().await;
                }
            }
        };
        let a1 = wait(ns(1));
        let a2 = wait(ns(1));
        settle(2).await;
        let busy = gate.enter(ns(1)).await.err().unwrap();
        assert!(
            busy.message.contains("2 sessions of namespace 0x"),
            "{}",
            busy.message
        );
        assert_eq!(busy.retry_after, RETRY_AFTER);
        let b1 = wait(ns(2));
        settle(3).await;
        assert!(gate.enter(ns(3)).await.is_err(), "the room holds 3 in all");
        let first = wait(Class::Scheduler);
        // one of namespace 1 gives up: its place is free again
        a2.abort();
        let _ = a2.await;
        assert_eq!(lock(&gate.state).public.len(), 2);
        let a3 = wait(ns(1));
        settle(3).await;
        drop(held);
        for task in [first, a1, b1, a3] {
            task.await.unwrap().unwrap();
        }
        assert!(!lock(&gate.state).held);
    }

    // A waiter dropped after the gate was handed to it, before it took it,
    // passes the gate on rather than leaving it held for ever.
    #[test]
    fn a_gate_handed_to_a_dropped_waiter_passes_on() {
        let gate = SessionGate::default();
        let held = futures_ready(gate.enter(ns(1))).unwrap();
        let (wake, signal) = oneshot::channel();
        lock(&gate.state).public.push_back(Waiter {
            id: 7,
            namespace: Some(Fr::from(1u64)),
            wake,
        });
        let waiting = Waiting {
            state: gate.state.clone(),
            id: 7,
            signal,
            served: false,
        };
        drop(held); // hands the gate to waiter 7
        assert!(lock(&gate.state).held);
        drop(waiting); // never took it
        assert!(!lock(&gate.state).held);
    }

    /// The value of a future that is ready at once.
    fn futures_ready<F: std::future::Future>(f: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut f = std::pin::pin!(f);
        match f.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => panic!("not ready"),
        }
    }
}
