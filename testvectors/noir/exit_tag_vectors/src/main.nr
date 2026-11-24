//! Checks testvectors/exit_tag.json with the functions the round circuits
//! call (noir/pss_core's `tip::exit`): the two domains, each tag case
//! (`exit_tag` of its partial commitment, request id and entry), each filler
//! case (`exit_filler`), and a note's tag from its owner and randomness
//! (`partial_commitment`, then `exit_tag`), which pss-client's `exitTagOf`
//! computes. Prover.toml is written from the vector file by pss-client's
//! test/hatch.test.ts; `nargo execute` fails on any disagreement.

use pss_core::tip::exit::{exit_filler, exit_tag, PSS_EXIT_FILLER, PSS_EXIT_TAG};
use pss_core::tip::outcome::partial_commitment;

struct TagVector {
    partial: Field,
    request_id: Field,
    entry: Field,
    tag: Field,
}

struct FillerVector {
    partial: Field,
    request_id: Field,
    j: Field,
    filler: Field,
}

struct NoteVector {
    owner: Field,
    rho: Field,
    partial: Field,
    request_id: Field,
    entry: Field,
    tag: Field,
}

fn check_tag(v: TagVector) {
    assert_eq(exit_tag(v.partial, v.request_id, v.entry), v.tag);
}

fn check_filler(v: FillerVector) {
    assert_eq(exit_filler(v.partial, v.request_id, v.j as u32), v.filler);
}

fn main(
    pss_exit_tag: Field,
    pss_exit_filler: Field,
    tag_0: TagVector,
    tag_1: TagVector,
    tag_2: TagVector,
    filler_0: FillerVector,
    filler_1: FillerVector,
    note: NoteVector,
) {
    assert_eq(pss_exit_tag, PSS_EXIT_TAG);
    assert_eq(pss_exit_filler, PSS_EXIT_FILLER);
    check_tag(tag_0);
    check_tag(tag_1);
    check_tag(tag_2);
    check_filler(filler_0);
    check_filler(filler_1);
    assert_eq(partial_commitment(note.owner, note.rho), note.partial);
    assert_eq(exit_tag(note.partial, note.request_id, note.entry), note.tag);
}
