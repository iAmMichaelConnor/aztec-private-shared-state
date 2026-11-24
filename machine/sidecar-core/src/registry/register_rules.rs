//! The REGISTER rules over one circuit manifest, and the intake family rule
//! between two packages.

use super::*;
use crate::manifest::QueuedIntake;

/// Refuse (400) a manifest that names an option this machine has not built
/// for its intake ([`crate::intake::IntakeRules::refuse_deferred`]). It runs on the parsed
/// manifest; which state modes a node serves on each path, and what each
/// accepts, is its holders' check ([`StateHolders::check_register`]: a mode
/// not served on the manifest's path, the chain-held size bound, the store's
/// `values`).
pub fn refuse_deferred_options(manifest: &Manifest) -> Result<(), Refusal> {
    manifest.intake.rules().refuse_deferred(manifest)
}

/// The REGISTER checks of the outcome form against the manifest's intake
/// ([`crate::intake::IntakeRules::check_outcome`]; [`Manifest::validate`] has checked the
/// partial note against `outcome` already). Refusals are `bad_request`,
/// naming the field.
pub fn check_outcome(manifest: &Manifest, shape: &CircuitShape) -> Result<(), Refusal> {
    manifest.intake.rules().check_outcome(manifest, shape)
}

// One intake family per key, by namespace (DECISIONS.md section 9, "One
// intake family per namespace"). REGISTER refuses, in one contract manifest, a
// non-secret-shared-intake package (`onchain`, `receipt`) that reads a key
// beside a secret-shared-intake package (`shared_receipt`, `shared_onchain`)
// that writes one, since the non-secret-shared round's public outputs would
// publish state that shared inputs touched. A non-secret-shared package that
// reads no key (an init round, which only writes) sees no such state, so it
// sits beside secret-shared rounds. The rule is namespace-wide although the
// contract manifest names each package's keys.
//
// DEV DECISION (app developer): how an app that wants both intake families
// splits its keys. Default: one namespace (one contract) per family, so an
// app with a non-secret-shared key and a secret-shared key deploys two
// contracts, as the examples do for their non-secret-shared cases.
// Consequence: one more deployment, and no round reads keys of both. The
// alternative: a rule per named key of the contract manifest, refusing a
// second family for the same key only.
/// Whether two queued packages of one namespace break the one-intake-family
/// rule: one is a non-secret-shared package that loads a key (its public
/// outputs publish it) and the other a secret-shared package that writes one
/// (it puts shared inputs into it). The contract manifest's checks apply it
/// to every pair of its packages
/// ([`crate::manifest::contract::ContractManifest::check`]).
pub fn intake_families_clash(a: (&Manifest, QueuedIntake), b: (&Manifest, QueuedIntake)) -> bool {
    let publishes = |(m, i): (&Manifest, QueuedIntake)| !i.shared() && m.state_keys.reads > 0;
    let hides = |(m, i): (&Manifest, QueuedIntake)| i.shared() && m.state_keys.writes > 0;
    (publishes(a) && hides(b)) || (hides(a) && publishes(b))
}
