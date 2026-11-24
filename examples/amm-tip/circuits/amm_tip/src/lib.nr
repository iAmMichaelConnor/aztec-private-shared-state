//! The AMM at the tip of the chain: what its round circuits compute,
//! as one library so that the swap's entries (amm_swap_tip, one circuit for
//! on-chain intake and receipt intake; amm_swap_tip_shared, secret-shared receipt
//! intake's) and the init round (amm_init_tip) share it: `tip` is the swap,
//! `shared` what a secret-shared intake adds to it. The swap itself is amm_total's
//! swap_total (examples/amm-swap-total), called by path and never restated
//! here.
//!
//! State mode `node` (docs/ARCHITECTURE.md section 6, "The examples on
//! node-held state"): the pool is one flat key whose stored vector is
//! [reserve_x, reserve_y, blinding] (the manifest's `len` 3), held by the
//! three nodes as Rep3 pairs, one version per commitment. On chain it is a
//! commitment in one PublicMutable slot; every round outputs the commitment it read
//! (`old_c`, named by the manifest's commitment_slot) and the one it
//! leaves (`new_c`, the key's outputs[].note_hash), and hands the
//! vector that `new_c` commits to to the machine through TACEO_store.
pub mod shared;
pub mod tip;
