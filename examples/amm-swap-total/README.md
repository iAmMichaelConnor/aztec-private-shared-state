# Total AMM swap

> **A simple example.** The swap of a minimal constant-product pool, here to show a total
> round circuit, not a design for a private AMM. A trader who sees two swaps' amounts can
> solve both reserves; the examples that use this swap say who sees them.

The constant-product swap of `examples/amm` in total form: no input can make the
circuit unsatisfiable. A bad request (a zero or oversized amount, a bad direction,
a trade that overflows, rounds to zero or drains the pool) still proves, and the
proof says `ok = 0` and why, instead of the round failing with no proof. This is
the one total swap in the repository: `examples/amm` registers this circuit as its
total swap, and `examples/amm-tip` calls its library by path. The swap is the library
`circuits/amm_total`, so other Nargo packages can depend on it (Noir cannot depend on a
`bin` package), and `circuits/amm_swap_total` is the round circuit that calls it. Its origin is in
[`docs/PROVENANCE.md`](../../docs/PROVENANCE.md).

Bricks: the library `circuits/amm_total` is app code that calls no brick, and its circuit
`circuits/amm_swap_total` is `examples/amm`'s total swap round, whose bricks
(`PssEffects`, the sidecar path's effects) that example's "Bricks this example uses" table
lists.

## What the circuit computes

`amm_swap_total` consumes the pool note `[reserve_x, reserve_y]`, applies one swap
and re-creates the pool note under a fresh blinding `out0_randomness`. `amount_in`
and `direction` are public raw Fields (a typed `u64` or `bool` parameter would put
a range check a bad request can falsify at the entry). On success it pays out
`floor(r_out * amount_in / (r_in + amount_in))` and writes the new reserves,
exactly as `amm::pool::Pool::swap` does. On failure it writes the old reserves,
pays out 0, and reports the first failing check:

| Code | Meaning | What `amm_swap` does instead |
| --- | --- | --- |
| 0 | ok (`ok = 1`) | the same trade |
| 1 | `amount_in` is zero | asserts `amount_in > 0` |
| 2 | `amount_in` is not below 2^64 | `u64` parameter range check |
| 3 | `direction` is neither 0 nor 1 | `bool` parameter range check |
| 4 | `r_in + amount_in` overflows 64 bits | `u64` addition overflow |
| 5 | the output rounds down to zero | asserts `out > 0` |
| 6 | the output would drain the pool (only with `r_in = 0`) | asserts `out < r_out` |
| 7 | a reserve in the note preimage is not below 2^64 (defensive; no proven round writes one) | truncates silently |

The checks run in the order 2, 3, 7, 1, 4, 5, 6 (the order `amm_swap` would fail
in). `app_outputs` is `[ok, code, amount_out]`, so the circuit has 13 public
inputs: `[namespace, owner, in_slots[0], out_slots[0], amount_in,
direction, read_leaves[0], nullifiers[0], new_note_hashes[0], npk_app_hash, ok,
code, amount_out]`. The contract still proves the read leaf, pushes the nullifier
and the new note hash and pins `npk_app_hash`, whatever `ok` is, so the pool
advances to a fresh note either way. The library's doc comments classify every
constraint and argue determinedness.

## Layout and checks

```
circuits/circuits.env       CIRCUITS, LIBS and TOTAL_CIRCUITS for scripts/check-noir.sh
circuits/amm_total/         library: swap_total and its 16 tests
circuits/amm_swap_total/    the round circuit, Prover.toml and 8 Prover-<case>.toml
circuits/outputs.txt        each case's expected outputs
```

```
scripts/check-noir.sh examples/amm-swap-total --outputs examples/amm-swap-total/circuits/outputs.txt
# compile, tests, total-lint, solve every case, and each case's app_outputs and note hash
```

| Prover file | Request | `[ok, code, amount_out]` |
| --- | --- | --- |
| `Prover.toml` | sell 25000 x on the pool `amm_init` makes | `[1, 0, 33450]` |
| `Prover-zero.toml` | `amount_in = 0` | `[0, 1, 0]` |
| `Prover-oversize.toml` | `amount_in = 2^64` | `[0, 2, 0]` |
| `Prover-direction2.toml` | `direction = 2` | `[0, 3, 0]` |
| `Prover-direction-neg.toml` | `direction = p - 1` | `[0, 3, 0]` |
| `Prover-overflow.toml` | `r_x + amount_in = 2^64` | `[0, 4, 0]` |
| `Prover-dust.toml` | sell 1 y | `[0, 5, 0]` |
| `Prover-drain.toml` | sell 5 x on `[0, 1000000]` | `[0, 6, 0]` |
| `Prover-bad-reserve.toml` | `reserve_x = 2^64` in the preimage | `[0, 7, 0]` |

The lint (total-lint at the pin, `--lib-src` total's and noir-lang/schnorr's src in
nargo's cache) reports, on the circuit compiled with Noir
1.0.0:

```
1 ACIR function(s), 190 opcodes; 8 Brillig function(s)
  definition 133, hint-compiler 12, hint-library 40, hint-unreviewed 5, input-falsifiable 0
  brillig abort sites 1 reachable (0 unjustified outside the library), 1 guarded
  reported (unjustified) 0 (+5 justified), exit code 0
```

The reachable abort site is `pss_core`'s `TACEO_store` oracle call, justified by its
markers in `mpc_store.nr`. The swap calls total-noir entries whose hints co-noir runs
(`to_u64_or`, `add_or`, `mul_div_or`; a comment in `amm_total/src/swap.nr` says
why): the network extends this circuit's witness in co-noir, whose Brillig VM at the
pinned co-snarks rev runs no integer shift, mask or `ConditionalMov`. `bb gates` gives
4280; `total-lint <artifact> --brillig-ops` reports 0 unsupported ops, and co-noir's
three-party REP3 witness extension succeeds on every Prover case.

The circuit takes the namespace key `nsk_app` by name (the fixed LOAD) and uses it as
the nullifier key, as every round on `noir/pss_core` does, so it has one scalar
decomposition, the one of `npk_app_hash` (marked in `pss_core`'s `aztec_note.nr`). For comparison `examples/amm`'s `amm_swap` is 108
opcodes and lints with 3 input-falsifiable, 14 hint-unreviewed and 1 hint-pinned items
(13 unjustified, exit 1).

## How the other AMM examples use it

`examples/amm` (the sidecar path) registers this round circuit as it
stands, as its total swap beside the asserting `amm_swap`: its interface is already
that example's (the canonical prefix, the pool key on both sides, `amount_in` and
`direction` public, the fixed LOAD `nsk_app`), so `examples/amm/circuits/amm_swap_total`
is a link to `circuits/amm_swap_total` here, not a second package, and the manifest is
`examples/amm/manifests/amm_swap_total.json`. `scripts/check-noir.sh examples/amm`
compiles, lints and solves it through the link, Prover cases included.

`examples/amm-tip` (the tip of chain) writes its own round circuit with its own public
interface and manifest, and calls `amm_total::swap::swap_total` for the trade. It
depends on the library by path and never copies `swap.nr`; from a package under
`examples/<name>/circuits/`:

```toml
amm_total = { path = "../../../amm-swap-total/circuits/amm_total" }
```

`amm_total` takes total-noir's `total` as a Nargo git dependency at the pinned tag, so its
users inherit the pin.
Their lint needs no extra `--lib-src` (`TOTAL_LIB_SRC`) for it: `swap_total` adds
no hint of its own, and all its hint constraints come from total's src, which
`scripts/check-noir.sh` whitelists. Each round that outputs `npk_app_hash(nsk_app)` gets
the same 5 std items, justified by `pss_core`'s marker in `aztec_note.nr`.

This example has no manifest; the examples that run the swap on the machine write
theirs.
