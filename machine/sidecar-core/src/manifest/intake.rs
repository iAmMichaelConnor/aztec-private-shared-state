//! The intakes: how a request reaches the network, the queued intakes' table
//! and where a node's shares come from.

use super::*;

/// The stale period the examples' deployment descriptors state, 50 L2
/// blocks (DECISIONS.md, "The stale valve"); the contract manifest's
/// `queue.stale_blocks` has no default.
pub const DEFAULT_STALE_BLOCKS: u64 = 50;

/// How a request reaches the network: `direct` is the sidecar path, every
/// other intake queues the request at the tip.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intake {
    /// The client sends POST /v1/execute (the default).
    #[default]
    Direct,
    /// On-chain intake: the request log carries the inputs in the clear.
    Onchain,
    /// Receipt intake: the user obtains three node receipts over the inputs first.
    Receipt,
    /// Secret-shared receipt intake: each node receives one Rep3 pair of every
    /// INPUT_SHARED value and signs a receipt over the commitment `C`.
    SharedReceipt,
    /// Secret-shared on-chain intake: the user's private function logs encoded
    /// shares on chain, its hash stored beside the queue entry.
    SharedOnchain,
}

impl Intake {
    pub fn as_str(self) -> &'static str {
        match self.queued() {
            None => "direct",
            Some(intake) => intake.as_str(),
        }
    }

    /// Where a node's pair of each shared input comes from: the queued
    /// intake's row ([`QueuedIntake::share_source`]), or envelopes bound to
    /// the request body under `direct`.
    pub fn share_source(self) -> ShareSource {
        self.queued()
            .map_or(ShareSource::Envelopes(EnvelopeBinding::Body), |q| {
                q.share_source()
            })
    }

    /// The queued intake, or `None` for `direct` (the sidecar path).
    pub fn queued(self) -> Option<QueuedIntake> {
        match self {
            Intake::Direct => None,
            Intake::Onchain => Some(QueuedIntake::Onchain),
            Intake::Receipt => Some(QueuedIntake::Receipt),
            Intake::SharedReceipt => Some(QueuedIntake::SharedReceipt),
            Intake::SharedOnchain => Some(QueuedIntake::SharedOnchain),
        }
    }
}

/// A queued intake: how a tip request's inputs reach the network. Each
/// built one has one implementation of sidecar-tip's `IntakeSource`, which
/// the tip picks from this value once per package. Every per-intake fact of
/// sidecar-core is its row of one table ([`QueuedIntake::row`]): its
/// manifest value, its name, its family ([`QueuedIntake::shared`]), whose
/// manifest rules are [`Manifest::validate`]'s, whether it is built, and
/// where a node's shares come from ([`QueuedIntake::share_source`]); what a
/// queued intake does in the lifecycle and REGISTER is its implementation
/// of [`crate::intake::IntakeRules`]. Relayed intake is deferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QueuedIntake {
    /// On-chain intake (`onchain`): the request log carries the inputs in the clear.
    Onchain,
    /// Receipt intake (`receipt`): the user obtains three node receipts over
    /// the inputs first.
    Receipt,
    /// Secret-shared receipt intake (`shared_receipt`): receipts over the inputs
    /// commitment `C`, each node holding one Rep3 pair of the shared inputs.
    SharedReceipt,
    /// Secret-shared on-chain intake (`shared_onchain`): encoded shares in a
    /// private log, its hash stored beside the queue entry.
    SharedOnchain,
}

/// Where node i's Rep3 pair of each INPUT_SHARED value comes from, a fact
/// of the intake's row ([`Intake::share_source`]). The source answers which
/// shared inputs a request gives and node i's share of each
/// ([`ShareSource::given_names`], [`ShareSource::share`]); the binder asks
/// it and never names an intake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareSource {
    /// An INPUT_SHARED envelope in the request, sealed to node i's `enc` key
    /// under the associated data `EnvelopeBinding` names.
    Envelopes(EnvelopeBinding),
    /// Derived from the request log the request carries (`shared_log`) with
    /// node i's `enc` scalar of the epoch the log names; no envelope.
    DerivedLog,
}

/// What an envelope's associated data binds besides the namespace, round,
/// input name and node index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeBinding {
    /// The request body (`input_body_hash`): the client seals after the
    /// body is fixed.
    Body,
    /// The chain request id under the intake label: the client seals
    /// before any body exists (secret-shared receipt intake).
    ChainRequest,
}

/// One queued intake's row of [`QueuedIntake`]'s table.
struct IntakeRow {
    /// The manifest value.
    value: &'static str,
    /// The descriptive name.
    name: &'static str,
    /// The intake's family: secret-shared or non-secret-shared.
    shared: bool,
    /// Whether this machine builds the intake.
    built: bool,
    /// Where a node's pair of each shared input comes from.
    shares: ShareSource,
}

impl QueuedIntake {
    /// Every queued intake, in manifest order.
    pub const ALL: [QueuedIntake; 4] = [
        QueuedIntake::Onchain,
        QueuedIntake::Receipt,
        QueuedIntake::SharedReceipt,
        QueuedIntake::SharedOnchain,
    ];

    /// The intake's row: the one place a per-intake fact of sidecar-core is
    /// written down.
    fn row(self) -> &'static IntakeRow {
        match self {
            QueuedIntake::Onchain => &IntakeRow {
                value: "onchain",
                name: "on-chain intake",
                shared: false,
                built: true,
                shares: ShareSource::Envelopes(EnvelopeBinding::Body),
            },
            QueuedIntake::Receipt => &IntakeRow {
                value: "receipt",
                name: "receipt intake",
                shared: false,
                built: true,
                shares: ShareSource::Envelopes(EnvelopeBinding::Body),
            },
            QueuedIntake::SharedReceipt => &IntakeRow {
                value: "shared_receipt",
                name: "secret-shared receipt intake",
                shared: true,
                built: true,
                shares: ShareSource::Envelopes(EnvelopeBinding::ChainRequest),
            },
            QueuedIntake::SharedOnchain => &IntakeRow {
                value: "shared_onchain",
                name: "secret-shared on-chain intake",
                shared: true,
                built: true,
                shares: ShareSource::DerivedLog,
            },
        }
    }

    /// The manifest value.
    pub fn as_str(self) -> &'static str {
        self.row().value
    }

    /// The descriptive name ("on-chain intake", "receipt intake").
    pub fn name(self) -> &'static str {
        self.row().name
    }

    /// Whether the intake is a secret-shared one: its requests take INPUT_SHARED
    /// app inputs and the reserved shared values, and its chain request id
    /// commits to `C` (`$inputs_hash`) instead of `user_nonce`. A non-secret-shared one
    /// takes clear inputs only, since a request log carries and a node signs
    /// clear inputs.
    pub fn shared(self) -> bool {
        self.row().shared
    }

    /// Whether this machine builds the intake: REGISTER refuses a manifest
    /// of one it does not ([`crate::registry::refuse_deferred_options`]), and
    /// sidecar-tip has an `IntakeSource` for each one it does.
    pub fn built(self) -> bool {
        self.row().built
    }

    /// Where a node's pair of each shared input comes from (a non-secret-shared intake
    /// takes none; its row names the body-bound envelopes `direct` takes).
    pub fn share_source(self) -> ShareSource {
        self.row().shares
    }
}
