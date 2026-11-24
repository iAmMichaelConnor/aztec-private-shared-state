//! The machine's queued test counter with its amount an epoch read: the
//! same round as tip_counter (load the counter, add the amount, store under
//! a fresh blinding), with the amount a pinned read under freshness epoch
//! and its epoch one more public input, as such a read puts them
//! (docs/ARCHITECTURE.md section 6, "Pinned reads"). The round does not use
//! the epoch; it is there so that the proof, the machine request id and
//! `apply` carry it. The request has no app inputs, so its request id is
//! over the empty list and its nonce.
//!
//! The manifest (intake onchain, sidecar-orchestrator tests/scheduler.rs)
//! is tip_counter's with `amount_epoch` filled by PUBLIC "amount_epoch" and
//! the read {"function": "get_amount_epoch", "param": "amount",
//! "freshness": "epoch", "epoch_param": "amount_epoch"}.
//!
//! Public inputs (8), in ACIR order: [namespace, vk_hash, in_slots[0],
//! out_slots[0], amount, amount_epoch, request_id, old_c, new_c], the
//! contract library's public-input prefix (the pinned value, then its
//! epoch, after the key slots).

use pss_core::tip::{intake, slot};
use total::ctl::Outcome;

/// The public outputs, after the public parameters.
pub struct CounterOutputs {
    /// the chain request id over the round's (no) inputs
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
    amount: pub Field,
    amount_epoch: pub Field,
    user_nonce: Field,
    value: [Field; 1],
    r_old: Field,
    r_new: Field,
) -> pub CounterOutputs {
    let _ = amount_epoch;
    let key = slot::load(namespace, in_slots[0], out_slots[0], value, r_old, r_new);
    let round = key.finish(Outcome::good(), [value[0] + amount]);
    round.store(0);
    CounterOutputs {
        request_id: intake::plain(namespace, vk_hash, [], user_nonce),
        old_c: round.old_c,
        new_c: round.new_c,
    }
}
