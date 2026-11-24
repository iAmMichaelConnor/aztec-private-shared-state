//! Checks the public-input arrays of testvectors/outcome.json with the
//! function the tip contract library verifies a private-outcome proof
//! against (noir/pss_public_contract outcome.nr
//! `outcome_public_inputs`), after the machine request id over each case's
//! old commitments and pinned values (result.nr `machine_request_id`, which
//! `check_round` computes itself). The outcome's own values (ciphertext,
//! note hash, padding) are outcome_vectors' to check with the round's
//! functions. Prover.toml is written from the vector file by pss-client
//! (test/outcome.test.ts); `nargo execute` fails on any disagreement.

use pss_public_contract::outcome::outcome_public_inputs;
use pss_public_contract::result::machine_request_id;

/// One case: R keys read, W written, H note hashes, a ciphertext of L
/// fields, M public inputs. Its pinned values and new leaf hashes are the
/// entry point's `{case}_pinned` and `{case}_new_hashes` where it has some.
struct Case<let R: u32, let W: u32, let L: u32, let M: u32> {
    namespace: Field,
    vk_hash: Field,
    chain_request_id: Field,
    machine_request_id: Field,
    npk_app_hash: Field,
    outcome_tag: Field,
    note_hash: Field,
    in_slots: [Field; R],
    out_slots: [Field; W],
    old_commitments: [Field; R],
    new_commitments: [Field; W],
    ciphertext: [Field; L],
    public_inputs: [Field; M],
}

fn check<let R: u32, let W: u32, let L: u32, let M: u32, let Q: u32, let T: u32>(
    c: Case<R, W, L, M>,
    pinned: [Field; Q],
    new_hashes: [Field; T],
) {
    let machine = machine_request_id(c.chain_request_id, c.old_commitments, pinned);
    assert_eq(machine, c.machine_request_id, "machine_request_id");
    let pi = outcome_public_inputs(
        c.namespace,
        c.vk_hash,
        c.in_slots,
        c.out_slots,
        pinned,
        c.chain_request_id,
        machine,
        c.old_commitments,
        c.new_commitments,
        c.npk_app_hash,
        new_hashes,
        c.outcome_tag,
        [c.note_hash],
        c.ciphertext,
    );
    assert_eq(pi.len(), M, "public-input count");
    for k in 0..M {
        assert_eq(pi[k], c.public_inputs[k], "public input");
    }
}

fn main(
    lending_pinned: [Field; 1],
    lending_new_hashes: [Field; 2],
    amm: Case<1, 1, 3, 14>,
    lending: Case<1, 1, 8, 22>,
) {
    // a flat key, no pinned read: the ciphertext is the last public input
    check(amm, [], []);
    // a tree-valued key's new leaf hashes after npk_app_hash, one pinned read
    check(lending, lending_pinned, lending_new_hashes);
}
