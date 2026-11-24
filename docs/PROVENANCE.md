# Provenance of third-party code

The trees below come from other projects; the root `NOTICE` gives their licences.

| Here | Source | Changed |
| --- | --- | --- |
| `machine/sidecar-oblivious/vendor/{primitives,circuits,data-structures,doram}` | [TaceoLabs/gigadoram-rs](https://github.com/TaceoLabs/gigadoram-rs) at commit `09bea241410bb554b143957bd7b34b30626d7be2` (MIT OR Apache-2.0) | ported to the pinned co-snarks, with persistence, a sparse address space and framing added; `machine/sidecar-oblivious/vendor/PROVENANCE.md` lists every change, and the licence texts sit beside it |
| `examples/monty-hall/` | [TaceoLabs/monty-hall-aztec](https://github.com/TaceoLabs/monty-hall-aztec) at commit `d33340438db7b5e1361d3dfc154582bd1a1d381f` (MIT, `examples/monty-hall/LICENSE`): its game logic (`noir_logic/monty_hall/src/game_state.nr`), its round circuits and its contract's entry points | `circuits/monty_hall/src/game_state.nr` keeps the game state and its `init`, `choose_door` and `switch` logic, with the winning-door draw made unbiased and the host's coin flip rewritten. The round circuits are rewritten on `noir/pss_core`'s canonical interface (the seed round is the generic `pss_seed`, a link to `examples/amm`'s; `monty_hall_open_door` takes the door as an INPUT_SHARED input; `monty_hall_finish` writes nothing). The contract keeps the upstream's entry-point names and game flow; their bodies are written here, over `noir/pss_contract`'s `apply` (`examples/monty-hall/README.md`, "The contract's state"). The end-to-end flow (`e2e/scenarios/monty.ts`) is written here; the upstream's Rust orchestration and nodes are not used |
| `noir/pss_utils/src/{ae.nr,dh.nr}` | `noir_logic/pss_utils/src/{ae.nr,dh.nr}` of the same Monty Hall application (MIT) | `ae.nr`: the same duplex construction (state `[key, nonce, 0, tag]`, the IO-pattern tag, separator `0x4142`) generalised from fixed lengths 1 to 3 to any length, its functions `pub` (`DECISIONS.md`, "One authenticated encryption, one hash family"); `dh.nr`: `derive_ecdh_shared_secret` kept, the key pair from std's `EmbeddedCurveScalar::from_field`, the address-point helpers dropped; dependencies on `deps/` |
| `noir/pss_core/src/prng.nr` | `noir_logic/pss_utils/src/prng.nr` of the same Monty Hall application (MIT) | `position` typed `u32`, `from_parts` added, the trait dropped for an inherent `as_field_array`, a known-answer test |
| `examples/token/contract/token/` | [aztec-labs-eng/aztec-node](https://github.com/aztec-labs-eng/aztec-node) v6.0.0 (commit `d2e67c1d938f06a6476dd7d4bd01e73771923dd1`, the `toolchain.json` `AZTEC_WORLD_DIR` pin), `noir-projects/noir-contracts/contracts/app/token_contract` (Apache-2.0) | `src/main.nr`: a header comment added and the `mod test;` line removed (the test module is not copied); the rest of the contract unchanged. `Nargo.toml` rewritten: package name `token`, the aztec-nr dependencies by path into `deps/aztec-world`, no `generic_proxy_contract` (a test dependency) |

`examples/amm-swap-total/` began as an example in total-noir, by the author of this
repository, and carries no third-party code.

## Dependencies used in place

Not copied: these are read where they are, through a gitignored `deps/` link (the Aztec
worlds) or Nargo's git cache, at the pins in `toolchain.json`; `scripts/bootstrap.sh` checks each one.

| Dependency | Pin | Reached as | Used by |
| --- | --- | --- | --- |
| total-noir ([github.com/iAmMichaelConnor/total-noir](https://github.com/iAmMichaelConnor/total-noir)) | tag `v0.1.0`, commit `f93196faeb775e6a58bcd8ce6eed425051f36f4f` (`toolchain.json` `total_noir`); `scripts/bootstrap.sh` fails when a `Nargo.toml` names another tag or Nargo's cached copy is at another commit | Nargo git dependency (`directory = "noir/total"`), cached by nargo at `~/nargo/github.com/iAmMichaelConnor/total-noir/v0.1.0`, for `noir/pss_core`, `noir/pss_public_contract`, the examples' round circuit libraries, the machine's test circuits and `testvectors/noir`; `lint/total-lint`, installed by `scripts/install-toolchain.sh` from the same commit | the total round circuits, the tip contract library, and total-lint |
| noir-lang/sha256, noir-lang/keccak256 | tags `v0.3.0` and `v0.1.3`, commits `9442e5b6856f98b2ec029882d7e90199ecff91ba` and `f64ab3af714aa1a1e2699243037e0f11fe5bf706` | Nargo git dependencies of total-noir's `total`, cached by nargo at `~/nargo/github.com/noir-lang/sha256/v0.3.0` and `~/nargo/github.com/noir-lang/keccak256/v0.1.3` | `total` (no round here calls them) |
| noir-lang/schnorr | tag `v0.4.0`, commit `9995bcc45e24c9eaccabe3bcf59c36f9aedaa00c` | Nargo git dependency, cached by nargo at `~/nargo/github.com/noir-lang/schnorr/v0.4.0` | `noir/pss_public_contract` (result signatures and receipts) |
| noir-lang/poseidon | tag `v0.4.0`, commit `e105cdd5c79c222860d53c5dfdb8fa8012b291c0` | Nargo git dependency, cached by nargo at `~/nargo/github.com/noir-lang/poseidon/v0.4.0` | `machine/circuits/sidecar_register` (the registration circuit) |
