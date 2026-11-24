//! What the machine's test suites share, so each suite writes only its own
//! cases:
//!
//! - [`dirs`]: scratch directories under TXE_TMP_ROOT, the repository and the
//!   prepared data directory;
//! - [`data`]: the prepared circuits, the manifests (the examples' and the
//!   machine's own test circuits', read from their files) and the CRS;
//! - [`vectors`]: the shared test vectors (testvectors/) by path, field hex
//!   and the sample deployment's node keys;
//! - [`block_on`]: a future run to completion from a synchronous test;
//! - [`requests`]: the example apps' requests (the AMM on node-held state,
//!   Monty Hall on client-held records) and the request helpers of
//!   sidecar-core's `testing` harness;
//! - [`nodes`] (feature `nodes`): the development TLS material and three
//!   in-process nodes on any store, each behind its HTTPS API and admin
//!   socket, over the pinned-TLS mesh on loopback;
//! - [`postgres`] (feature `postgres`): the Postgres server the store tests
//!   create their schemas on;
//! - [`receipts`]: the receipt route's package, as the orchestrator's and the
//!   node's receipt suites write it into a store.
//!
//! Test code only: no binary links this crate.

pub mod data;
pub mod dirs;
#[cfg(feature = "nodes")]
pub mod nodes;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod receipts;
pub mod requests;
pub mod vectors;

/// Run `f` to completion on a runtime of its own, on a scoped thread, so it
/// can be called from inside a test's runtime or outside any.
pub fn block_on<T: Send>(f: impl Future<Output = T> + Send) -> T {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(f)
            })
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}
