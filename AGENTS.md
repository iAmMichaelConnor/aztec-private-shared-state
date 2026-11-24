# AGENTS.md

Entry point for an AI assistant working in this repository: either helping an app developer
build on private shared state (PSS), or changing the repository itself.

PSS: three MPC nodes hold an app's state as Rep3 shares; a request names a registered Noir
circuit, a manifest says where each input comes from, the nodes prove the round as a
collaborative UltraHonk proof, and an Aztec contract verifies it and applies the effects.

## "I want to build X"

1. **Ask the questions** of `docs/design-guide/README.md`, "The decision tree" (fifteen
   questions in one table, each with its options, default, cost, leakage and the code to
   start from). Ask first what must be shared at all: everything else stays user-owned
   notes, and a leak of all three nodes' secrets may cost privacy and can freeze funds,
   never take them. A round pays or informs only its requester (and the holder of a delivery
   handle that party's own request left), so every other party that must be paid acts in a
   round of its own on a note of its own. Never design against the guide's "Fixed
   properties". `docs/design-guide/design-space.json` `questions` holds thirteen questions
   that each set an axis, a second cut of the same choices that `--plan <axis>=<value>`
   uses. `docs/design-guide/BRICKS.md` says what bricks exist, what you call, and the
   alternatives.
2. **Land on a blueprint.** Use the [design guide's blueprints](docs/design-guide/README.md#blueprints).

3. **Print its plan:** `python3 -I scripts/check-design-space.py --plan <blueprint>` lists
   the axis values, every brick with its module path and status, the example, the files to
   start from and the deviations the blueprint allows, with the bricks each one adds and
   drops. A deviation outside that list must pass the constraints in `design-space.json`;
   `--compat` prints which value pairs the constraints forbid.
4. **Start from the example** the plan and [design guide](docs/design-guide/README.md#blueprints) name.
   Monty Hall is the `note-client` example. `examples/amm` is a node-held deviation on
   the sidecar path.

   `examples/amm-swap-total` is the model of a total app library that every path shares.
   Each example's README lists its rounds and manifests and has a "Bricks this example
   uses" table near its top; `// BRICK` markers in its code show each seam and its
   alternatives. An example's combination is one choice, never the only one: the AMM tip and
   lending carry every intake so each can be run; an app picks one of each and declares
   only those entry points.
5. **Build what exists.** `note-client`, `tip-flat` and `tip-tree` build end to end, each
   with its example; `tip-chain` has no example (its plan prints the status of each brick).
   A non-secret-shared intake with public outputs is the test path of the AMM tip and
   lending, on test deployments only. Read the mechanism only for the part you build:
   `docs/ARCHITECTURE.md` section 6 (the tip) and 7 (the manifest), sections 3 to 5 (the
   sidecar path and the invariants).
6. **Write only the app's part.** An app developer writes an app library (the transition
   function and its validity checks, total where the network proves it), one main per round
   per public-input layout, a manifest per round, the round table, the contract's pins and
   the outcome fields. Everything else is a brick: if you find yourself copying machine or
   library code into an app, say so instead; the missing brick is the work to do.
7. **State what it leaks.** Copy the rows the app uses from the guide's "What each party
   sees" into its leakage statement and name the economic value (front-running within
   `min_out`, a liquidation edge, a game's hidden answer).
8. **Say what is not built.** A brick or value marked "to build" does not exist yet;
   REGISTER refuses deferred values (relayed intake, `binding: exact`); the oblivious trees
   are experimental; the design guide's "Not built, or experimental" lists the rest. Tell
   the developer rather than working around it.

## Where things are

| Path | What |
| --- | --- |
| `docs/design-guide/` | the decision guide (`README.md`), `design-space.json` (axes, constraints, bricks with the library items an app calls, blueprints: the source the guide's generated tables, `check-design-space.py --plan` and `BRICKS.md` read) and the generated brick reference `BRICKS.md` |
| `docs/GLOSSARY.md` | the one glossary of the repository's own terms, each defined once; use these terms exactly |
| `docs/ARCHITECTURE.md` | the mechanism: the tip is section 6 (with partial-note delivery, the oblivious tree and sparse map, the escape hatch), the manifest section 7 |
| `docs/DECISIONS.md` | the settled choices and why (`docs/ARCHITECTURE.md`'s opening says which source wins: the code, over both) |
| `docs/DESIGN.md` | trust, setup, running the services, the operator's procedures, the configuration reference, recovery and limits |
| `docs/TESTING.md` | the gates: every command, what each suite proves and costs, CI |
| `docs/manifest.schema.json`, `docs/contract-manifest.schema.json` | the schema of a round's manifest, and of the contract manifest a deployment registers |
| `machine/` | the Rust workspace: `sidecar-core`, `sidecar-http`, `sidecar-node`, `sidecar-orchestrator`, `sidecar-tip`, `sidecar-oblivious`, `sidecar-test-fixtures` |
| `machine/circuits/` | the machine's circuits: `sidecar_register` and `sidecar_audit`, which sidecar-core embeds (`build.rs`), and the test circuits; their manifests in `machine/circuits/manifests/` |
| `noir/` | the Noir libraries (`pss_core`, `pss_contract`, `pss_public_contract`, `pss_utils`), their test Nargo packages (`pss_public_contract_test`, `pss_tip_test`) and the `pss_probe` contract (a test-only probe the tip suites deploy) |
| `ts/` | `pss-client` and `pss-relayer` (TypeScript), `test-support` (the test-only fixtures and mock orchestrator both share) and `hooks` (the JSON-import hook the `@aztec-labs` packages need: `node --import ./ts/hooks/register.mjs`) |
| `examples/<example>/` | `circuits/` (the app library, one main per round, `circuits.env`, the fixtures' expected `outputs.txt`), `manifests/`, `contract/`, `deployments/` (the tip examples' deployment descriptors, which `pss-manifest build` reads), `README.md` (for lending, the market's whole design); `examples/counter-tip/client/` is the one example client |
| `e2e/` | the end-to-end harness, driver and scenarios (`e2e/README.md`, `e2e/scenarios/README.md`) and the tip deployments (`e2e/tip/`) |
| `testvectors/` | vectors that Rust, TypeScript and Noir all read; `testvectors/manifests/` the test manifests; `testvectors/noir/` the Noir vector programs |
| `scripts/` | `install-toolchain.sh` (the pinned tools into `.tools/`), `bootstrap.sh` (checks them, links `deps/`), `toolchain.sh` (the tool paths), `prepare-data.sh`, `gen-dev-certs.sh`, `check-noir.sh` (with `oracle-stub.py`), `witness-extend.sh`, `check-vectors.sh`, `check-contracts.sh`, `txe.sh`, the python checkers and generators |
| `toolchain.json` | every pinned tool and dependency |
| `txe.json` | the Nargo packages the TXE runner tests and the contracts they deploy |
| `.github/` | the CI workflows (`ci.yml` on every change, `nightly.yml`) and their shared setup actions |

## Working rules

- **Toolchain.** `toolchain.json` pins every tool; `docs/DESIGN.md`, "Setup", has the
  commands that install, check and prepare them (total-noir's `total` library is a Nargo
  git dependency that nargo fetches).
- **Test with the fast checks for as long as you can.** The README's "Build and test" lists
  them: `npm test`, the python checkers, `cargo fmt --check` and `bash -n`, about half a
  minute in all, with no compilation. Run them after every change. When a change is one
  they cannot see (Rust, Noir, a contract), run the cheapest slow check that covers it:
  `cargo clippy -p <crate>`, `cargo nextest run --profile quick -p <crate>`,
  `scripts/check-noir.sh <example>`, `scripts/check-contracts.sh <dir>`, `scripts/txe.sh
  --contracts --only <package>`. Leave the proving checks (the full `cargo nextest run`,
  `witness-extend.sh`, the e2e) to the full gate, which runs every check once.
  `docs/TESTING.md` has every command and what each costs. Run slow checks under
  `nice -n 19` on a shared machine.
- **The design guide.** After editing `docs/design-guide/design-space.json` or a `// BRICK`
  marker, run `python3 -I scripts/check-design-space.py --write-readme`, then
  `--write-bricks`, then the check itself and `python3 -I scripts/check-docs-links.py`.
- **Temporary files** go under `TXE_TMP_ROOT` (default `.runs/tmp`, gitignored), never
  the system temp directory; the root must stay short because the TXE binds Unix sockets
  below it.
- **Bricks, not toggles.** One interface per axis, one implementation per supported value,
  chosen once by the manifest or the configuration. Code above an interface never compares
  an axis value; no branch-per-mode spread across modules. Where a circuit layout must
  differ, use Noir generics or comptime over one source.
- **BRICK markers** only at a seam where another option could be chosen (the option, the
  library item, the alternatives), or where an example adds a brick in no axis; never for an
  always-present brick (`docs/design-guide/README.md`, "BRICK markers").
- **DEV DECISION markers** only for a choice an app developer makes (what, default, why,
  consequences, the alternative); an open design question is never a marker. Parameters
  get doc comments with their defaults; operator knobs go in `docs/DESIGN.md`,
  "Configuration reference" (`docs/design-guide/README.md`, "DEV DECISION markers").
- **Invariant 0 and minimal PSS.** A leak of all three nodes' secrets may put privacy at
  risk and freeze funds, never take or lose them; keep everything that need not be shared
  as user-owned notes (`docs/DECISIONS.md`, "Principles").
- **Names.** Use `docs/GLOSSARY.md`'s terms exactly: the sidecar path and the tip; on-chain,
  receipt, secret-shared receipt and secret-shared on-chain intake; client-held, node-held
  and chain-held state. A bare "package" is a registered circuit; write "Nargo package" or
  "npm package" for the others. Never "plain" or "mode 1/2" in prose; code identifiers stay
  as they are.
- **Docs are the current spec**, not history: say what the system is and does.
- **Verifiable delivery.** Data for anyone other than the nodes that is value-bearing or
  needed to spend is encrypted inside the circuit (Poseidon2 AEAD under a key the recipient
  supplied) and exposed as public outputs.
- **Read-only dependencies.** Only `scripts/install-toolchain.sh` writes under `TOOLS_DIR`,
  and nothing edits nargo's cached copies of the git dependencies (total-noir among them);
  everything else only reads the pinned tools and total-noir.
