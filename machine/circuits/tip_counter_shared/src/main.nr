//! The machine's queued test counter under secret-shared receipt intake, on a
//! node-held key: the amount is a shared input, so no node and no proof
//! output holds it, and the round binds its inputs through the inputs
//! commitment C (docs/ARCHITECTURE.md section 6, "Secret-shared intake"). It
//! loads the counter, adds the amount when C opens to the shared values
//! and stores the result under a fresh blinding:
//!
//!   inputs_match = commit([amount, partial_note, outcome_key, outcome_tag], blinding)
//!                  == inputs_hash
//!   state        = [value + amount, r_new]   (inputs_match; else the round
//!                                             fails and keeps the old state)
//!   request_id   = shared(namespace, vk_hash, inputs_hash)
//!
//! A flag, not an assertion: shares that do not reconstruct to C make an
//! `ok = false` round whose new commitment is the old one, so the circuit
//! stays total and the queue moves.
//!
//! The manifest (intake shared_receipt, sidecar-orchestrator
//! tests/shared_receipt.rs) fills `namespace` with PUBLIC $namespace,
//! `vk_hash` with PUBLIC $vk_hash, the slots with PUBLIC $state_keys,
//! `inputs_hash` with PUBLIC $inputs_hash, `amount` with INPUT_SHARED
//! "amount", `partial_note`, `outcome_key`, `blinding` and `outcome_tag`
//! with the reserved INPUT_SHARED values, `value` and `r_old` with LOAD
//! $state_keys.reads[0] and `r_new` with SAMPLE 1; it stores out0 under
//! $state_keys.writes[0] (state mode node, note hash `new_c`) and names `old_c` as
//! the commitment slot of $state_keys.reads[0]. C commits to the app input, then
//! `$partial_note`, `$outcome_key` and `$outcome_tag`, with `$blinding`
//! last, the order every secret-shared intake round uses
//! (docs/ARCHITECTURE.md section 6, "Private outcomes"). This round is the
//! machine's intake test: it binds the partial note through C but completes
//! no note and encrypts nothing under `outcome_key`.
//!
//! Public inputs (7), in ACIR order: [namespace, vk_hash, in_slots[0],
//! out_slots[0], request_id, old_c, new_c], the contract library's
//! receipt intake layout.

use pss_core::tip::{intake, slot};
use total::cmp::eq;
use total::ctl::Outcome;

/// The public outputs, after the public parameters.
pub struct SharedCounterOutputs {
    /// the chain request id, from the namespace, vk_hash and C
    pub request_id: Field,
    /// the commitment of the state the round loaded
    pub old_c: Field,
    /// the commitment of the stored state
    pub new_c: Field,
}

fn main(
    namespace: pub Field,
    vk_hash: pub Field,
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    inputs_hash: Field,
    amount: Field,
    partial_note: Field,
    outcome_key: Field,
    blinding: Field,
    outcome_tag: Field,
    value: [Field; 1],
    r_old: Field,
    r_new: Field,
) -> pub SharedCounterOutputs {
    let c = intake::commit([amount, partial_note, outcome_key, outcome_tag], blinding);
    let outcome = Outcome::good().require(eq(c, inputs_hash), 1);
    let key = slot::load(namespace, in_slots[0], out_slots[0], value, r_old, r_new);
    let round = key.finish(outcome, [value[0] + amount]);
    round.store(0);
    SharedCounterOutputs {
        request_id: intake::shared(namespace, vk_hash, inputs_hash),
        old_c: round.old_c,
        new_c: round.new_c,
    }
}
