//! The intake brick of the request lifecycle and REGISTER: what differs
//! between intake direct (the sidecar path) and a queued intake (the tip) at
//! steps 3, 4, 9 and 15 and in REGISTER's intake rules, behind one interface,
//! [`IntakeRules`]. The manifest's intake picks the implementation once
//! ([`Intake::rules`]): [`DirectIntake`], or the [`QueuedIntake`] itself. The
//! lifecycle, the orchestrator's prefix, the binder, the state holders'
//! table and REGISTER ask it and never compare an intake. Where a queued
//! intake's shares come from is its row's ([`Intake::share_source`]); the
//! manifest's own rules per intake are [`Manifest::validate`]'s.

use crate::abi::{CircuitShape, check_queued_public_prefix};
use crate::error::Refusal;
use crate::field::Fr;
use crate::grumpkin::Point;
use crate::manifest::{Binding, Intake, Manifest, Outcome, QueuedIntake};
use crate::pipeline::{ChainRound, ChainVerifier, VerifierRows, authenticate};
use crate::request::{NodeRequest, Request};
use crate::state::{Holding, Path, QueueRead, StateHolders};
use crate::store::{StoreRead, rules};

/// What step 4 on a node is given: the request, its package (manifest,
/// shape, the key holders and the `packages` row's vk_hash), this node's own
/// rows and its chain verifier.
pub struct AuthCtx<'a> {
    pub req: &'a NodeRequest,
    pub manifest: &'a Manifest,
    pub shape: &'a CircuitShape,
    pub holding: &'a Holding,
    pub vk_hash: Fr,
    /// The contract manifest version the package was resolved in.
    pub manifest_hash: Fr,
    pub rows: &'a dyn VerifierRows,
    pub chain_verifier: &'a ChainVerifier,
}

/// What step 4 gives the rest of a round: the requester it authenticated,
/// if the request needed one, and under a queued intake what the chain
/// verifier read, which the tip's holders load and commit against.
pub struct Authenticated {
    pub requester: Option<Point>,
    pub chain: Option<QueueRead>,
}

/// One intake as the request lifecycle and REGISTER see it. Every method
/// but [`Self::authenticate`] (which runs the node's chain verifier) reads
/// only its arguments; refusals are 400 unless a method says otherwise.
pub trait IntakeRules: Send + Sync {
    /// The path the intake's requests run on, the key of the state holders'
    /// table ([`StateHolders`]).
    fn path(&self) -> Path;

    /// Step 3: refuse a request of `circuit` that carries a tip-only field
    /// the intake does not take, or lacks one it requires: a
    /// `chain_request_id` (the comment at [`Request::chain_request_id`]) and
    /// a `manifest_hash` (the comment at [`Request::manifest_hash`]).
    fn check_tip_fields(&self, circuit: &str, carried: TipFields) -> Result<(), Refusal>;

    /// Step 4 on a node, under the namespace lock: the requester signature
    /// (400 without `requester`, 403 without a signature or with one that
    /// does not verify), or the node's chain verifier in its place.
    fn authenticate(&self, at: &AuthCtx<'_>) -> Result<Authenticated, Refusal>;

    /// Step 4 at the orchestrator, before fan-out and without the lock: the
    /// part of [`Self::authenticate`] that needs no node.
    fn authenticate_unlocked(&self, req: &Request, manifest: &Manifest) -> Result<(), Refusal>;

    /// Step 9: whether a request key that feeds a public parameter is
    /// admitted as `key` when its short form (0x and lowercase hex digits
    /// without leading zeros) is `short`.
    fn admits_key_spelling(&self, key: &str, short: &str) -> bool;

    /// Step 15: the request row's `created_at` at unix time `now`.
    fn created_at(
        &self,
        read: &dyn StoreRead,
        namespace: Fr,
        req: &NodeRequest,
        now: u64,
    ) -> Result<u64, Refusal>;

    /// REGISTER, on the parsed manifest: refuse an option this machine has
    /// not built under the intake.
    fn refuse_deferred(&self, manifest: &Manifest) -> Result<(), Refusal>;

    /// How the round's value reaches the user when the manifest names no
    /// `outcome` ([`Manifest::outcome`]).
    fn default_outcome(&self) -> Outcome;

    /// REGISTER: the outcome form the intake takes, naming the field.
    fn check_outcome(&self, manifest: &Manifest, shape: &CircuitShape) -> Result<(), Refusal>;

    /// REGISTER: the circuit's public parameters against the public-input
    /// layout the intake's contract rebuilds.
    fn check_public_prefix(&self, manifest: &Manifest, shape: &CircuitShape)
    -> Result<(), Refusal>;

    /// REGISTER, in a node's own check ([`crate::registry::RegisterHook`]):
    /// run `check`, the node's checks of a queued package against its tip
    /// configuration, given the queued intake.
    fn check_queued(
        &self,
        check: &mut dyn FnMut(QueuedIntake) -> Result<(), Refusal>,
    ) -> Result<(), Refusal>;
}

/// Which tip-only fields a request carries.
#[derive(Clone, Copy, Debug)]
pub struct TipFields {
    pub chain_request_id: bool,
    pub manifest_hash: bool,
}

/// The refusal of an option REGISTER defers.
fn deferred(field: &str, why: &str) -> Refusal {
    Refusal::bad_request(format!("field `manifest.{field}`: {why}"))
}

/// Intake direct, the sidecar path: the client sends the request itself,
/// signed by its requester where the request needs one.
pub struct DirectIntake;

impl IntakeRules for DirectIntake {
    fn path(&self) -> Path {
        Path::Sidecar
    }

    // A namespace may hold several versions (a tip contract manifest that
    // also lists direct packages, or an all-direct one under upgrades). Only
    // a queued round is bound to the version in force, by each node's chain
    // verifier, so a direct request runs under the newest version and may
    // not name an older one, whose circuit the owner replaced.
    fn check_tip_fields(&self, circuit: &str, carried: TipFields) -> Result<(), Refusal> {
        if carried.chain_request_id {
            return Err(Refusal::bad_request(format!(
                "field `chain_request_id`: circuit `{circuit}` has intake direct; \
                 only a queued (tip) request carries a chain request id"
            )));
        }
        if carried.manifest_hash {
            return Err(Refusal::bad_request(format!(
                "field `manifest_hash`: circuit `{circuit}` has intake direct; \
                 only a queued (tip) request names a contract manifest version"
            )));
        }
        Ok(())
    }

    /// The requester signature ([`authenticate`]) over the node's holders.
    fn authenticate(&self, at: &AuthCtx<'_>) -> Result<Authenticated, Refusal> {
        Ok(Authenticated {
            requester: authenticate(at.req, at.manifest, at.holding)?,
            chain: None,
        })
    }

    /// The requester signature ([`authenticate`]); every key under intake
    /// direct is client- or node-held, the core holders
    /// ([`StateHolders::core`]).
    fn authenticate_unlocked(&self, req: &Request, manifest: &Manifest) -> Result<(), Refusal> {
        let holding = StateHolders::core().choose(manifest)?;
        authenticate(req, manifest, &holding).map(drop)
    }

    // A key is a store row by its string and a public value by its field
    // element, so `0x1`, `0x01` and `1` would be three rows of one slot;
    // under intake direct the request spells it, so only the short form is
    // admitted.
    fn admits_key_spelling(&self, key: &str, short: &str) -> bool {
        key == short
    }

    fn created_at(
        &self,
        _read: &dyn StoreRead,
        _namespace: Fr,
        _req: &NodeRequest,
        now: u64,
    ) -> Result<u64, Refusal> {
        Ok(now)
    }

    /// A pinned public read: the scheduler of a queued intake fills it.
    fn refuse_deferred(&self, manifest: &Manifest) -> Result<(), Refusal> {
        if !manifest.public_reads.is_empty() {
            return Err(deferred(
                "public_reads",
                "a pinned public read under intake direct is deferred (the scheduler of a queued intake fills it)",
            ));
        }
        Ok(())
    }

    /// `none`: the round's effects are its outcome.
    fn default_outcome(&self) -> Outcome {
        Outcome::None
    }

    /// No `outcome` field: the round's effects are its outcome.
    fn check_outcome(&self, manifest: &Manifest, _shape: &CircuitShape) -> Result<(), Refusal> {
        if manifest.outcome.is_some() {
            return Err(Refusal::bad_request(
                "field `outcome`: only with a queued intake; this manifest has intake direct",
            ));
        }
        Ok(())
    }

    /// Any layout: the note contract library reads the effects.
    fn check_public_prefix(
        &self,
        _manifest: &Manifest,
        _shape: &CircuitShape,
    ) -> Result<(), Refusal> {
        Ok(())
    }

    /// Nothing: no round under intake direct reads the tip configuration.
    fn check_queued(
        &self,
        _check: &mut dyn FnMut(QueuedIntake) -> Result<(), Refusal>,
    ) -> Result<(), Refusal> {
        Ok(())
    }
}

impl IntakeRules for QueuedIntake {
    fn path(&self) -> Path {
        Path::Tip
    }

    /// `manifest_hash` is optional: the chain verifier checks it against
    /// the version the pins name.
    fn check_tip_fields(&self, circuit: &str, carried: TipFields) -> Result<(), Refusal> {
        if !carried.chain_request_id {
            return Err(Refusal::bad_request(format!(
                "field `chain_request_id`: missing; circuit `{circuit}` has a queued intake ({})",
                self.as_str()
            )));
        }
        Ok(())
    }

    /// The node's chain verifier, in place of a requester signature (a tip
    /// key has no requester); its view of the chain is what the tip's
    /// holders load and commit against.
    fn authenticate(&self, at: &AuthCtx<'_>) -> Result<Authenticated, Refusal> {
        let version = at
            .rows
            .contract_manifests(at.req.namespace.fr())?
            .into_iter()
            .find(|m| m.manifest_hash == at.manifest_hash);
        let stale_blocks = match version {
            Some(row) => row.parse()?.stale_blocks(),
            None => {
                return Err(Refusal::mpc_failure(format!(
                    "store: namespace {} holds no contract manifest {}",
                    crate::field::fr_to_hex(at.req.namespace.fr()),
                    crate::field::fr_to_hex(at.manifest_hash)
                )));
            }
        };
        let round = ChainRound {
            manifest: at.manifest,
            intake: *self,
            shape: at.shape,
            vk_hash: at.vk_hash,
            manifest_hash: at.manifest_hash,
            stale_blocks,
            rows: at.rows,
        };
        Ok(Authenticated {
            requester: None,
            chain: Some((at.chain_verifier)(at.req, &round)?),
        })
    }

    /// Nothing: the chain verifier is the nodes' alone.
    fn authenticate_unlocked(&self, _req: &Request, _manifest: &Manifest) -> Result<(), Refusal> {
        Ok(())
    }

    // A queued intake's request keys are the tip configuration's, which
    // spells each slot one way.
    fn admits_key_spelling(&self, _key: &str, _short: &str) -> bool {
        true
    }

    /// Dated after the latest row carrying the request's chain request id
    /// ([`rules::chain_created_at`]), which step 3 requires.
    fn created_at(
        &self,
        read: &dyn StoreRead,
        namespace: Fr,
        req: &NodeRequest,
        now: u64,
    ) -> Result<u64, Refusal> {
        let chain = req
            .chain_request_id
            .expect("step 3 requires a chain request id under a queued intake");
        rules::chain_created_at(read, namespace, chain.0, now)
    }

    /// `binding: exact` (every queued intake is built, and the manifest
    /// rules of the secret-shared intakes are [`Manifest::validate`]'s).
    fn refuse_deferred(&self, manifest: &Manifest) -> Result<(), Refusal> {
        if manifest.binding() == Binding::Exact {
            return Err(deferred(
                "binding",
                "`exact` is deferred; a queued intake runs `turn`",
            ));
        }
        Ok(())
    }

    /// `partial`: the round completes the user's partial note.
    fn default_outcome(&self) -> Outcome {
        Outcome::Partial
    }

    /// Under a secret-shared intake `partial` (the default), never `none`
    /// (its outcome is private and must reach the user); under a
    /// non-secret-shared intake `partial` (the default), whose round returns
    /// its `$partial_note` as the public output `partial_note` right after
    /// `ok` (`pss_core`'s `tip::outputs::BoundPartial`, the contract
    /// library's `PartialResult`), or `none`, written out, for a round that
    /// completes no note.
    fn check_outcome(&self, manifest: &Manifest, shape: &CircuitShape) -> Result<(), Refusal> {
        match (self.shared(), manifest.outcome()) {
            (true, Outcome::None) => Err(Refusal::bad_request(format!(
                "field `outcome`: `none` is refused under intake {}, whose outcome is \
                 private and reaches the user only by `partial`",
                self.as_str()
            ))),
            (false, Outcome::Partial) => {
                let paths = &shape.return_paths;
                let after_ok = paths
                    .iter()
                    .position(|p| p == "ok")
                    .and_then(|k| paths.get(k + 1));
                if after_ok.map(String::as_str) != Some("partial_note") {
                    let returns = paths
                        .iter()
                        .map(|p| format!("`{p}`"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(Refusal::bad_request(format!(
                        "field `outcome`: under `outcome: partial` the round returns its \
                         `$partial_note` as the public output `partial_note` right after `ok`, \
                         where the contract library binds it; circuit `{}` returns {returns}",
                        manifest.circuit
                    )));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// [`check_queued_public_prefix`]: the contract library's public-input
    /// layout of a tip round.
    fn check_public_prefix(
        &self,
        manifest: &Manifest,
        shape: &CircuitShape,
    ) -> Result<(), Refusal> {
        check_queued_public_prefix(*self, manifest, shape)
    }

    fn check_queued(
        &self,
        check: &mut dyn FnMut(QueuedIntake) -> Result<(), Refusal>,
    ) -> Result<(), Refusal> {
        check(*self)
    }
}

/// Every queued intake, for [`Intake::rules`].
static QUEUED: [QueuedIntake; 4] = QueuedIntake::ALL;

impl Intake {
    /// The intake's implementation of the lifecycle's intake rules.
    pub fn rules(self) -> &'static dyn IntakeRules {
        match self.queued() {
            None => &DirectIntake,
            Some(intake) => QUEUED
                .iter()
                .find(|q| **q == intake)
                .expect("QueuedIntake::ALL lists every queued intake"),
        }
    }
}
