//! The admission hook every node runs on every execute request before it takes
//! the namespace lock.

use crate::error::Refusal;
use crate::request::{Request, View};

// Admission. `admit` runs at step 2 of every execute request, on
// every node (so a compromised orchestrator cannot bypass it), before the
// namespace lock and before resolution. It admits everything: anyone may
// run a registered circuit, since the circuit constrains what a round can do
// and reveal. This is the one place for fees, quotas, allow-lists or any
// authentication beyond the protocol's own; refuse with `Refusal::forbidden`
// (403) for an authentication failure. It is not where the protocol's checks
// live: under intake direct the requester signature of a request that
// supplies a client-held record, stores a client-held key or carries a shared
// input is checked at step 4 (authenticate), and REGISTER and DISABLE are
// authenticated by the namespace owner's signature and seq in `registry`,
// which does not call this hook. A fee on registry bodies would need its own hook there. A refusal
// joins the session handshake as the node's verdict, as every refusal at
// steps 2 to 9 does (pipeline `refuse_in_session`): the orchestrator runs
// this default, not a node's own hook, so a hook one node alone refuses with
// would otherwise leave the other two waiting out the mesh connect timeout.
// Each refused request therefore costs a handshake-only session under the
// mesh lock.
/// The research prototype's admission: every request, in either view (the orchestrator's full
/// one at its stateless prefix, node i's own at step 2).
pub fn admit<V: View>(req: &Request<V>) -> Result<(), Refusal> {
    let _ = req; // anyone may run a registered circuit
    Ok(())
}
