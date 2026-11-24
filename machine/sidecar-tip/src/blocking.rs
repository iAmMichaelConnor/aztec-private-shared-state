//! The bridge from a synchronous caller (the node's lifecycle hook, its
//! pruning job and receipt signer) to the chain reader's async reads: one
//! small runtime per holder, and the bound every such call's reads run
//! under.

use std::future::Future;
use std::time::Duration;

use tokio::runtime::{Handle, Runtime};

use crate::chain::ReadError;

/// A one-worker runtime the reads of one holder run on (a handful of HTTP
/// calls at a time).
pub(crate) struct Blocking {
    /// `Some` until `Drop` shuts it down without waiting: a holder may be
    /// dropped from inside an async context, where a blocking shutdown
    /// panics.
    runtime: Option<Runtime>,
    name: &'static str,
}

impl Blocking {
    /// The runtime, its worker named `name`.
    pub(crate) fn new(name: &'static str) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name(name)
            .enable_all()
            .build()?;
        Ok(Blocking {
            runtime: Some(runtime),
            name,
        })
    }

    /// Run `f` to completion from a synchronous caller: on the calling
    /// thread outside any runtime, else on a scoped thread (a runtime cannot
    /// be entered from inside another; the node's handlers call the
    /// lifecycle from a blocking thread of its own runtime).
    pub(crate) fn run<F>(&self, f: F) -> F::Output
    where
        F: Future + Send,
        F::Output: Send,
    {
        let runtime = self.runtime.as_ref().expect("taken only by Drop");
        if Handle::try_current().is_err() {
            return runtime.block_on(f);
        }
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name(format!("{}-call", self.name))
                .spawn_scoped(scope, || runtime.block_on(f))
                .expect("spawning a thread for the chain reads")
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        })
    }
}

impl Drop for Blocking {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// `read` bounded by `timeout`; a failure as the text a refusal carries.
pub(crate) async fn bounded<V>(
    timeout: Duration,
    read: impl Future<Output = Result<V, ReadError>>,
) -> Result<V, String> {
    match tokio::time::timeout(timeout, read).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!(
            "reading the chain through this node's Aztec node: {e}"
        )),
        Err(_) => Err(format!(
            "this node's Aztec node did not answer the reads within {timeout:?}"
        )),
    }
}
