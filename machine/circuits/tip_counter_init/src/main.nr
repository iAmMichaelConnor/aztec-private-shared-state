//! The first round of the machine's queued test counter: it writes the
//! counter's first state, a chain-held key, and its slot commitment
//! (pss_core tip::slot), and outputs the init request id over its input
//! (tip::intake::plain with nonce 0).
//!
//!   request_id = intake::plain(namespace, vk_hash, [start], 0)
//!   state = [start, r_new]     stored as TACEO_store("out0", state)
//!   new_c = slot::commitment(namespace, out_slots[0], [start], r_new)
//!
//! The manifest (intake onchain, sidecar-core tests/lifecycle.rs) fills
//! `namespace` with PUBLIC $namespace, `vk_hash` with PUBLIC $vk_hash,
//! `out_slots` with PUBLIC
//! ["$state_keys.writes[0]"], `start` with PUBLIC "start" and `r_new` with
//! SAMPLE 1, and stores out0 under $state_keys.writes[0] with state mode chain
//! and note hash `new_c`. The round loads nothing, so it has no commitment
//! slot.
//!
//! Public inputs (5), in ACIR order: [namespace, vk_hash, out_slots[0],
//! request_id, new_c], the contract library's public-input prefix (the app
//! input private).

use pss_core::mpc_store;
use pss_core::tip::{intake, slot};

/// The public outputs, after the public parameters.
pub struct InitOutputs {
    /// the init request id over the round's input
    pub request_id: Field,
    /// the commitment of the stored state
    pub new_c: Field,
}

fn main(
    namespace: pub Field,
    vk_hash: pub Field,
    out_slots: pub [Field; 1],
    start: Field,
    r_new: Field,
) -> pub InitOutputs {
    // Safety: side-effect-only oracle (pss_core mpc_store); the nodes keep
    // the state's shares, which new_c commits to
    unsafe { mpc_store::store_out_note(0, [start], r_new) };
    InitOutputs {
        request_id: intake::plain(namespace, vk_hash, [start], 0),
        new_c: slot::commitment(namespace, out_slots[0], [start], r_new),
    }
}
