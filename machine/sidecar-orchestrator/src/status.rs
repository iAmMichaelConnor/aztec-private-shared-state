//! The registry check, the chain readers' gauge and `GET /v1/status`.
//! [`check_registry`] compares the
//! three nodes' registry rows with each other and with the copy, logs what
//! differs and keeps what it found in memory ([`RegistryReport`]). It runs at
//! start, before the listener serves (`server::run`); again after every
//! registry body a node may have written ([`recheck`], from the REGISTER and
//! DISABLE routes); and on a timer ([`spawn_timer`], every `[registry]
//! check_interval_secs`). The reruns are tasks of their own and take no lock:
//! no request waits on them, and a run that overlaps a registry body still in
//! flight may name a row that body is committing, until the run after that
//! body records what it left (the run that began last is the one kept). The
//! reruns after bodies are coalesced ([`Rechecks`]): one runs at a time, and
//! the bodies that land while it runs share the one run after it, so a client
//! that resends a body (an idempotent seq 0 REGISTER needs no owner of the
//! namespace) starts no more reads of every registry row than one at a time.
//!
//! `GET /v1/status` answers the latest run's counts only
//! ([`RegistryStatus`]): the rows that differ name namespaces and circuits,
//! which the public API does not enumerate (`readers` names only the tip
//! namespaces of the orchestrator's config), so they and the reason a run
//! could not read the nodes are served on the admin socket's `status`
//! command (`crate::admin`), where the operator reads them, and in the log.
//!
//! `readers` is each scheduler's chain reader as of its last step
//! ([`ReaderStatus`]): the four tips, the settled block and how many block
//! hashes it holds, back to the finalized tip. It follows L1 finality (an
//! epoch-scale lag plus L1 finality) and grows, with nothing dropped, while
//! the finalized tip stalls (the reader also logs each doubling); empty
//! without `[tip]`.
//!
//! ```text
//! GET /v1/status -> {"registry": null, "readers": []}      (before the check has run)
//!                -> {"registry": {"compared_at": 1790000000, "counts": {"namespaces": 1,
//!                      "packages": 2, "between_nodes": 0, "copy_only": 0}}, "readers": []}
//!                -> {"registry": {"compared_at": 1790000000, "unread": true}, "readers": []}
//! ```

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sidecar_core::registry_check::{Divergence, RegistryCheck};
use tokio::task::JoinHandle;

use crate::api::Orchestrator;
use crate::sync::COPY;

/// The answer of `GET /v1/status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    /// The latest registry check's counts; `None` until the first has run.
    pub registry: Option<RegistryStatus>,
    /// Each scheduler's chain reader, by namespace.
    #[serde(default)]
    pub readers: Vec<ReaderStatus>,
}

/// One scheduler's chain reader as of its last step: the block hashes it
/// holds (sidecar-tip's `HeldBlocks`), the gauge of its memory, and the
/// Aztec node's four tips as its last poll read them (a tip lower than the
/// last answer's is the first sign of a replacement).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderStatus {
    /// The namespace contract, `0x` hex.
    pub namespace: String,
    /// How many `(number, hash)` pairs the reader holds.
    pub blocks: u64,
    /// The lowest block held; absent before the first snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lowest: Option<u64>,
    /// The proposed tip at the last poll.
    pub tip: u64,
    /// The checkpointed tip at the last poll.
    pub checkpointed: u64,
    /// The proven tip at the last poll.
    pub proven: u64,
    /// The finalized tip at the last poll.
    pub finalized: u64,
    /// The settled block, the floor of what the reader holds and of what
    /// the nodes delete: the finalized tip once the reader has seen it
    /// move, else 0.
    pub settled: u64,
}

impl ReaderStatus {
    pub fn of(namespace: String, held: sidecar_tip::chain::HeldBlocks) -> Self {
        ReaderStatus {
            namespace,
            blocks: held.blocks as u64,
            lowest: held.lowest,
            tip: held.tip,
            checkpointed: held.checkpointed,
            proven: held.proven,
            finalized: held.finalized,
            settled: held.settled,
        }
    }
}

/// One run of the registry check: when it compared the three nodes'
/// registry rows with each other and with the copy, and what it found. The
/// admin socket's `status` command answers it whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryReport {
    /// When the check ran, in unix seconds.
    pub compared_at: u64,
    /// What it found; absent when the nodes could not all be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agreement: Option<RegistrySummary>,
    /// Why the nodes' registries could not be read, so the check did not
    /// run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread: Option<String>,
}

/// What [`check_registry`] found: the report, and how many of its rows the
/// nodes themselves differ on and how many only the copy does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySummary {
    pub check: RegistryCheck,
    pub between_nodes: usize,
    pub copy_only: usize,
}

/// One run of the registry check as `GET /v1/status` answers it: when, and
/// how many rows were compared and differ, without naming them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryStatus {
    /// When the check ran, in unix seconds.
    pub compared_at: u64,
    /// What it counted; absent when the nodes could not all be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<RegistryCounts>,
    /// The nodes' registries could not all be read, so the check did not
    /// run (the reason is on the admin socket and in the log).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unread: bool,
}

/// The counts of a [`RegistrySummary`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCounts {
    /// Namespaces compared.
    pub namespaces: usize,
    /// Packages compared.
    pub packages: usize,
    /// Rows the three nodes do not hold alike.
    pub between_nodes: usize,
    /// Rows the three nodes hold alike and the copy does not.
    pub copy_only: usize,
}

impl RegistryStatus {
    /// The public counts of `report`.
    pub fn of(report: &RegistryReport) -> Self {
        RegistryStatus {
            compared_at: report.compared_at,
            counts: report.agreement.as_ref().map(|s| RegistryCounts {
                namespaces: s.check.namespaces,
                packages: s.check.packages,
                between_nodes: s.between_nodes,
                copy_only: s.copy_only,
            }),
            unread: report.unread.is_some(),
        }
    }
}

impl RegistrySummary {
    fn of(check: RegistryCheck) -> Self {
        let copy_only = check.divergences.iter().filter(|d| nodes_agree(d)).count();
        RegistrySummary {
            between_nodes: check.divergences.len() - copy_only,
            copy_only,
            check,
        }
    }
}

/// Whether the three nodes hold the row alike (so only the copy differs).
fn nodes_agree(d: &Divergence) -> bool {
    d.held.iter().any(|h| {
        h.holders.len() == sidecar_core::request::NODES && !h.holders.iter().any(|n| n == COPY)
    })
}

/// What started a run of the check, as its log lines name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum When {
    /// At start, before the listener serves.
    Start,
    /// After a REGISTER or DISABLE body a node may have written.
    AfterBody,
    /// On the timer.
    Timer,
    /// Before a resume ([`crate::api::Orchestrator::resume`]).
    Resume,
}

impl fmt::Display for When {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            When::Start => "at start",
            When::AfterBody => "after a registry body",
            When::Timer => "on its timer",
            When::Resume => "before a resume",
        })
    }
}

/// Compare the three nodes' registry rows with each other and with the copy
/// ([`crate::sync::check_agreement`]) and log the outcome, every row that
/// differs as a warning with its repair. The orchestrator serves either way:
/// the nodes refuse in-session what their diverged rows refuse
/// (ARCHITECTURE.md section 4), and the check only names the divergence
/// before traffic meets it. Records the outcome and its time for
/// `GET /v1/status` and the admin socket
/// ([`crate::registry::Registry::record_agreement`]), unless a run that began
/// later has already recorded its own, and returns it; its `agreement` is
/// `None` when the nodes could not all be read (also a warning).
pub async fn check_registry(app: &Orchestrator, when: When) -> RegistryReport {
    let ticket = app.registry.begin_check();
    let compared_at = sidecar_core::pipeline::unix_now();
    let found = match crate::sync::check_agreement(&app.nodes, app.registry.store()).await {
        Ok(found) => found,
        Err(e) => {
            let error = format!("{e:#}");
            tracing::warn!(
                error = %error,
                "registry check {when}: the nodes' registries could not be read; \
                 serving without the check"
            );
            let report = RegistryReport {
                compared_at,
                agreement: None,
                unread: Some(error),
            };
            app.registry.record_agreement(ticket, report.clone());
            return report;
        }
    };
    let summary = RegistrySummary::of(found);
    let report = RegistryReport {
        compared_at,
        agreement: Some(summary.clone()),
        unread: None,
    };
    app.registry.record_agreement(ticket, report.clone());
    let found = &summary.check;
    for d in &found.divergences {
        let repair = if nodes_agree(d) {
            "the nodes agree and the copy differs: rebuild the copy (sidecar-orchestrator \
             sync-registry)"
        } else {
            "the nodes differ: resend the signed body that diverged, or resync the registry \
             of the node behind from a neighbour (sidecar-node sync-registry --lost <i> \
             --from <j>; DESIGN.md, \"A registry body only some nodes committed\")"
        };
        tracing::warn!(divergence = %d, repair, "registry check {when}: a row differs");
    }
    if found.divergences.is_empty() {
        tracing::info!(
            namespaces = found.namespaces,
            packages = found.packages,
            "registry check {when}: the three nodes and the copy agree"
        );
    } else {
        tracing::warn!(
            namespaces = found.namespaces,
            packages = found.packages,
            between_nodes = summary.between_nodes,
            copy_only = summary.copy_only,
            "registry check {when}: the registries differ"
        );
    }
    report
}

/// The coalescing of the reruns after registry bodies: whether one is
/// running, and whether a body landed since it began (so one more must run
/// after it).
#[derive(Debug, Default)]
pub struct Rechecks {
    state: std::sync::Mutex<(bool, bool)>,
}

impl Rechecks {
    /// A body asks for a run: true when the caller starts one, false when
    /// the running one will run once more after it.
    fn ask(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (running, again) = &mut *state;
        if *running {
            *again = true;
            return false;
        }
        *running = true;
        true
    }

    /// A run ended: true when another must run (a body landed during it).
    fn ended(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (running, again) = &mut *state;
        if std::mem::take(again) {
            return true;
        }
        *running = false;
        false
    }
}

/// Run the check again in a task of its own, after a registry body: the
/// route that relayed the body does not wait for it. Coalesced
/// ([`Rechecks`]): while a rerun is in flight, this only asks it to run once
/// more when it ends.
pub fn recheck(app: &Arc<Orchestrator>) {
    if !app.rechecks.ask() {
        return;
    }
    let app = app.clone();
    tokio::spawn(async move {
        loop {
            check_registry(&app, When::AfterBody).await;
            if !app.rechecks.ended() {
                return;
            }
        }
    });
}

/// Run the check every `interval` (the first run one interval from now),
/// until the task is aborted.
pub fn spawn_timer(app: Arc<Orchestrator>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            check_registry(&app, When::Timer).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::Rechecks;

    // Bodies that land while a rerun runs share one more run after it; the
    // next body after that starts a fresh one.
    #[test]
    fn reruns_after_bodies_are_coalesced() {
        let r = Rechecks::default();
        assert!(r.ask(), "the first body starts a run");
        assert!(!r.ask(), "a second body during it starts none");
        assert!(!r.ask(), "nor a third");
        assert!(r.ended(), "one more run follows, for both");
        assert!(!r.ended(), "and then none");
        assert!(r.ask(), "a later body starts a run again");
        assert!(!r.ended());
    }
}
