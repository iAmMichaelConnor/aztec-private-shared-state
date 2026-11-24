//! A tip app's queue and slots as its suite reads them, and the
//! post-condition of a refused call: one reader for every tip app.
//!
//! The design:
//! - one struct, `QueueReader`, bound to a deployment (the environment and
//!   the app's address); its generics are the app's types (its Config, its
//!   slot count S and its outcome type), which an
//!   app's suite names once, where it binds the reader to its `Setup`;
//! - the reads go through the views every tip app has under the same names
//!   and signatures (`get_state()`, `request_at(u64)`, `done_at(u64)`), and
//!   `outcome_at(u64)` for an app whose hook stores its public outputs by
//!   queue index (value delivery `none`), called by selector, so the reader
//!   needs no app's interface (as the library's probe calls any app's
//!   `skip()`);
//! - `assert_refused_without_effect` reads the probe's transaction through
//!   `shape`, the transaction-effect oracle, so it needs no probe contract's
//!   utility; the probe itself stays the caller's closure;
//! - `stage_proof` and `mine_until_next_block_is` stay free functions of
//!   this crate: they take the environment, not the queue, and an app's
//!   suite binds them where it knows the submitter.
use crate::shape::last_tx_shape;
use aztec::context::PublicStaticCall;
use aztec::protocol::abis::function_selector::FunctionSelector;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::Deserialize;
use aztec::test::helpers::test_environment::TestEnvironment;
use pss_public_contract::{Head, TipState};

/// How many queue entries a snapshot covers; every suite's refusal tests
/// use fewer.
pub global SNAPSHOT_ENTRIES: u32 = 4;

/// Everything of a tip app's queue and slots that a refused call could
/// change: the head with its clock, the tail, the first entries' request
/// ids and done codes, and the commitment of every slot. (The seen flags
/// follow the entries: a request id is seen exactly when it was appended.)
/// A refused call lands no transaction effect at all (no log, no note
/// hash), which `assert_refused_without_effect` checks beside it.
#[derive(Eq)]
pub struct Snapshot<let S: u32> {
    pub head: Head,
    pub tail: u64,
    pub requests: [Field; SNAPSHOT_ENTRIES],
    pub done: [u8; SNAPSHOT_ENTRIES],
    pub commitments: [Field; S],
}

/// The queue and slots of the tip app at `app`, whose state view returns
/// `TipState<Config, S, K, U>` and whose `outcome_at`, if it stores
/// outcomes, returns `Outcome`.
pub struct QueueReader<Config, let S: u32, Outcome, K, U> {
    pub env: TestEnvironment,
    pub app: AztecAddress,
}

impl<Config, let S: u32, Outcome, K, U> QueueReader<Config, S, Outcome, K, U>
where
    Config: Deserialize,
    Outcome: Deserialize + Eq,
    K: Deserialize,
    U: Deserialize,
{
    pub fn at(env: TestEnvironment, app: AztecAddress) -> Self {
        QueueReader { env, app }
    }

    /// The app's state view (`get_state`).
    pub unconstrained fn state(self) -> TipState<Config, S, K, U> {
        let selector = comptime { FunctionSelector::from_signature("get_state()") };
        self.env.view_public(PublicStaticCall::new(self.app, selector, "get_state", []))
    }

    pub unconstrained fn head(self) -> Head {
        self.state().head
    }

    pub unconstrained fn tail(self) -> u64 {
        self.state().tail
    }

    /// The current commitment in slot `k` (0 before the init round).
    pub unconstrained fn commitment(self, k: u32) -> Field {
        self.state().commitments[k]
    }

    pub unconstrained fn request_at(self, index: u64) -> Field {
        let selector = comptime { FunctionSelector::from_signature("request_at(u64)") };
        self.env.view_public(PublicStaticCall::new(self.app, selector, "request_at", [index as Field]))
    }

    pub unconstrained fn done_at(self, index: u64) -> u8 {
        let selector = comptime { FunctionSelector::from_signature("done_at(u64)") };
        self.env.view_public(PublicStaticCall::new(self.app, selector, "done_at", [index as Field]))
    }

    pub unconstrained fn outcome_at(self, index: u64) -> Outcome {
        let selector = comptime { FunctionSelector::from_signature("outcome_at(u64)") };
        self.env.view_public(PublicStaticCall::new(self.app, selector, "outcome_at", [index as Field]))
    }

    pub unconstrained fn snapshot(self) -> Snapshot<S> {
        let mut requests = [0; SNAPSHOT_ENTRIES];
        let mut done = [0; SNAPSHOT_ENTRIES];
        for i in 0..SNAPSHOT_ENTRIES {
            requests[i] = self.request_at(i as u64);
            done[i] = self.done_at(i as u64);
        }
        let state = self.state();
        Snapshot {
            head: state.head,
            tail: state.tail,
            requests,
            done,
            commitments: state.commitments,
        }
    }

    /// Run `probe`, one probe transaction whose nested call into the app is
    /// expected to be refused, and require that it was refused and left
    /// nothing: the `snapshot` as before, and no public or private log,
    /// note hash or message in the probe's transaction.
    pub unconstrained fn assert_refused_without_effect<Env>(self, probe: unconstrained fn[Env]() -> bool) {
        let before = self.snapshot();
        assert(!probe(), "the call was not refused");
        assert(self.snapshot() == before, "a refused call changed the queue or the slots");
        let effects = last_tx_shape(self.env);
        assert_eq(effects.public_logs, 0);
        assert_eq(effects.private_logs, 0);
        assert_eq(effects.note_hashes, 0);
        assert_eq(effects.l2_to_l1_msgs, 0);
    }
}
