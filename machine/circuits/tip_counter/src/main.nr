//! A queued round of the machine's queued test counter: it loads the
//! counter's state (a chain-held key the nodes sealed to themselves), adds
//! the request's amount and stores the result under a fresh blinding,
//! through pss_core's slot helpers (tip::slot), and outputs the request id
//! over its inputs (tip::intake::plain), as every queued round does.
//!
//!   request_id = intake::plain(namespace, vk_hash, [amount], user_nonce)
//!   old_c = slot::commitment(namespace, in_slots[0], value, r_old)
//!   state = [value + amount, r_new]  TACEO_store("out0", state)
//!   new_c = slot::commitment(namespace, out_slots[0], [value + amount], r_new)
//!
//! The manifest (intake onchain, sidecar-core tests/lifecycle.rs) fills
//! `namespace` with PUBLIC $namespace, `vk_hash` with PUBLIC $vk_hash,
//! `in_slots` with PUBLIC ["$state_keys.reads[0]"], `out_slots` with PUBLIC
//! ["$state_keys.writes[0]"], `amount` with PUBLIC "amount", `user_nonce` with
//! PUBLIC $user_nonce, `value` with LOAD $state_keys.reads[0] slice [0, 1] len 2,
//! `r_old` with the same LOAD slice [1, 2] and `r_new` with SAMPLE 1; it
//! stores out0 under $state_keys.writes[0] (state mode chain, note hash `new_c`)
//! and names `old_c` as the commitment slot of $state_keys.reads[0].
//!
//! Public inputs (7), in ACIR order: [namespace, vk_hash, in_slots[0],
//! out_slots[0], request_id, old_c, new_c], the contract library's
//! public-input prefix (the app inputs private).

use pss_core::tip::{intake, slot};
use total::ctl::Outcome;

/// The public outputs, after the public parameters.
pub struct CounterOutputs {
    /// the chain request id over the round's inputs
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
    amount: Field,
    user_nonce: Field,
    value: [Field; 1],
    r_old: Field,
    r_new: Field,
) -> pub CounterOutputs {
    let key = slot::load(namespace, in_slots[0], out_slots[0], value, r_old, r_new);
    let round = key.finish(Outcome::good(), [value[0] + amount]);
    round.store(0);
    CounterOutputs {
        request_id: intake::plain(namespace, vk_hash, [amount], user_nonce),
        old_c: round.old_c,
        new_c: round.new_c,
    }
}
