//! The `TACEO_store` oracle: how a circuit hands a freshly created piece
//! of private shared state back to the MPC driver.
//!
//! When a round circuit creates a new note, its preimage exists only as
//! secret shares inside the MPC execution. The nodes need to KEEP those
//! shares so a later round can open the note. This oracle is the
//! hand-off: co-brillig intercepts it by name (`co-brillig/src/
//! brillig_vm.rs`, match on "TACEO_store") and stashes the shared values
//! in the node's store, keyed by `name`.
//!
//! It is side-effect-only: nothing in the circuit is constrained by it,
//! so a malicious resolver can at worst lose data, never break soundness.
//! Under plain `nargo` (tests, single-prover runs) there is no handler;
//! `scripts/oracle-stub.py` answers it with an empty result.
//!
//! ## Key convention
//!
//! A circuit's manifest maps the key `out<j>` to `$state_keys.writes[j]` (its
//! `outputs` entry), and the stored vector is `[fields..., randomness]`
//! (the last element is the note's blinding). Oracle keys must be `str<S>` literals, so
//! `store_out_note` picks the literal for `j` with a branch on a public
//! index; every key has the same length, which keeps one oracle
//! signature.

/// The most created notes one round can hand to the machine, so the
/// highest W of a round circuit that creates its notes with
/// `effects::create_note`. Default 8 (`out0` to `out7`); range 1 to 10.
/// Oracle
/// keys must be `str<S>` literals, so `store_out_note` names note `j`
/// with one branch per index, and every key has the same length, which
/// keeps one oracle signature. A circuit that creates more notes fails
/// the assert below when its witness is generated. To raise the limit,
/// raise this constant and add the matching `"out<j>"` branches (the
/// final `else` names the highest index); the manifest's `outputs`
/// entries name the same `out<j>` keys, each STOREd to
/// `$state_keys.writes[j]`. Past 10 a key would need two digits (`out10`) and
/// break the one-length rule, so the naming of every key, in the circuits
/// and the manifests, would have to change with it. The function is
/// unconstrained, so unused branches add no constraints and lowering the
/// limit saves nothing.
pub global MAX_OUT_NOTES: u32 = 8;

#[oracle(TACEO_store)]
unconstrained fn store_oracle<let N: u32, let S: u32>(name: str<S>, preimage: [Field; N]) {}

/// Hand created note `j`'s preimage to the machine as
/// `TACEO_store("out<j>", [fields..., randomness])`. `j` is the note's
/// position in the circuit's `out_slots` and must be a constant.
pub unconstrained fn store_out_note<let N: u32>(j: u32, fields: [Field; N], randomness: Field) {
    store_out(j, fields.concat([randomness]))
}

/// Hand a stored vector to the machine as `TACEO_store("out<j>",
/// preimage)`: the key convention above, for any vector (a created note's
/// preimage, a tree key's stored leaves). `j` is the key's position in the
/// circuit's `out_slots` and must be a constant. Call sites wrap it in
/// `unsafe` with a Safety comment noting it is side-effect-only.
pub unconstrained fn store_out<let N: u32>(j: u32, preimage: [Field; N]) {
    assert(j < MAX_OUT_NOTES, "store_out: out index too large");
    // Each oracle call below is an abort site of the lint (an oracle the
    // executor might not answer): the nodes' co-noir driver answers
    // TACEO_store by name, plain nargo runs answer it with
    // scripts/oracle-stub.py, a node that cannot answer refuses the round (a
    // node fault, like losing its store), and no answer changes a constraint.
    if j == 0 {
        store_oracle("out0", preimage) // total-lint: allow the TACEO_store hand-off (the comment above)
    } else if j == 1 {
        store_oracle("out1", preimage) // total-lint: allow the TACEO_store hand-off (the comment above)
    } else if j == 2 {
        store_oracle("out2", preimage) // total-lint: allow the TACEO_store hand-off (the comment above)
    } else if j == 3 {
        store_oracle("out3", preimage) // total-lint: allow the TACEO_store hand-off (the comment above)
    } else if j == 4 {
        store_oracle("out4", preimage) // total-lint: allow the TACEO_store hand-off (the comment above)
    } else if j == 5 {
        store_oracle("out5", preimage) // total-lint: allow the TACEO_store hand-off (the comment above)
    } else if j == 6 {
        store_oracle("out6", preimage) // total-lint: allow the TACEO_store hand-off (the comment above)
    } else {
        store_oracle("out7", preimage) // total-lint: allow the TACEO_store hand-off (the comment above)
    }
}
