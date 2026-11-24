//! The counter at the tip of the chain: what its round circuits compute, as
//! one library the mains and the contract share. `counter` is the app's own
//! rule (the transition function, total); `shared` is what a secret-shared
//! intake with a private outcome adds to it.
//!
//! State mode `node`: the counter is one flat key whose stored vector is
//! `[total, blinding]` (the manifests' `len` 2), held by the three nodes as
//! Rep3 shares. On chain it is a commitment in one public slot.
pub mod counter;
pub mod shared;
