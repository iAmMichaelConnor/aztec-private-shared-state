# Decisions

Why each building block of private shared state is the way it is. Each decision states the
choice in a sentence or two, why it was made, the alternatives considered and rejected and
why, and where the mechanism is specified. `ARCHITECTURE.md` is the one specification of
how things work; where this file and the code disagree, the code wins (the top of
`ARCHITECTURE.md` states the order of sources).

Every decision here is settled; an open question is recorded neither here nor as a marker
in code. Terms (the sidecar path, the tip, the intakes, the state modes, round, attempt and
the rest) are defined in `GLOSSARY.md`. In identifiers and manifests `shared_receipt`,
`shared_onchain` and `shared` mean secret-shared, and `onchain`, `receipt` and `plain` mean
non-secret-shared. The design guide (`design-guide/README.md`) maps the axes these choices
sit on to bricks and blueprints.

## 1. Principles

- **Invariant 0: a leak of all three nodes' secrets puts privacy at risk and can freeze
  funds, but can never take or lose them.** An adversary holding every node's keys, shares
  and stores, and running the orchestrator and the relayer, must still move nobody's value
  and lose none. Every design choice is checked against it. *Consequences:* no value a
  circuit trusts as an authorisation is a shared input or a node-held value (ownership is
  proven in the user's private function over a user-owned note, never inside the MPC); the
  circuits a contract runs are committed by its address, never by node signatures (section
  11); escrow, deposits and refunds are user-owned notes that public functions complete, so
  no value waits on a round (section 12); a frozen market has an escape hatch that needs no
  node. Frozen value is a liveness failure, which the invariant does not forbid: the hatch
  opens against nodes that stop, not against nodes that keep landing rounds while refusing
  service. [ARCHITECTURE.md section 5](ARCHITECTURE.md#5-invariants) states the invariant
  and checks every brick against it.
- **Minimal PSS.** Everything that need not be shared stays user-owned private state (Aztec
  notes): ownership, a user's balances and positions, outcomes, escrow and refunds. Only
  the essential shared state is PSS: a book's aggregates, a pool's reserves, what a
  liquidator or keeper must probe. The first question of any design is what can leave the
  PSS. *Why:* a user-owned note is at risk only from the user's own device, and the three
  nodes hold nothing that moves it. *Consequence:* value reaches users only by partial-note
  completion (section 10).
- **Lego bricks.** Each axis of the design has one interface and one implementation per
  supported value, chosen once (at REGISTER, client setup or compile time), never as a
  runtime toggle spread across modules; code above an interface never compares an axis
  value; where a layout must differ, Noir generics or comptime compile one source several
  ways. An app is a choice of implementations plus its own transition function, validity
  checks, outcome fields and pins. *Why:* the code must not grow combinatorially with the
  axes. *Consequence:* each axis of `design-guide/design-space.json` is a module boundary,
  and its bricks, each with a module path and a status, are the structure.
- **Verifiable delivery.** Data for anyone other than the nodes that is value-bearing or
  needed to spend is encrypted inside the circuit, so a result lands only if its recipient
  can open it (section 10, "Verifiable delivery: constrained or node-sealed").
- **Chain-held state is one isolated module.** It stays as an option for small fixed-size
  states (section 7), one module per layer behind the state-mode seam (the state holder and
  `TipState` in the machine, `Sealing` in the contract library, a `StateModule` in the
  client). *Why:* the option is kept, but not at the cost of a second path through shared
  code.
- **Docs are the current spec.** Docs say what the system is and does, not how it got
  there. *Why:* a reader should not have to replay history to learn the design.
- **DEV DECISION markers are for app-developer choices only.** A marker states a choice an
  app developer makes: what it is, its default, why, its consequences and the alternative.
  A design rule is an ordinary comment that points here; a module parameter gets a doc
  comment with its default; an operator knob goes in the configuration reference. *Why:*
  under a broader rule most markers would be constants, invariants or cross-references; the
  markers should be a short list of real choices.

## 2. Components, languages and wire format

- **Language split.** Operator-run components are Rust in one cargo workspace (`machine/`);
  JSON over HTTPS on both legs, no gRPC; user-side code is TypeScript (`pss-client`,
  hand-written JSON manifests, the e2e driver and harness). *Why:* one language for the MPC
  stack (co-snarks is Rust), and the user side next to aztec.js.
- **The relayer is TypeScript** (`pss-relayer`, on `pss-client` plus a PXE), operator-run,
  outside the Rust machine. *Why:* it builds and sends Aztec transactions, which needs a
  PXE.
- **One repository.** The machine and the tip live here; the machine's decisions bind the
  tip unless a decision states an exception. Total-circuit tooling is the separate project
  total-noir, a Nargo git dependency, never duplicated.
- **Harness ports.** Each harness (sidecar, tip) has its own port range and every port can
  be overridden (`e2e/README.md` lists them). *Why:* runs on one machine must not collide.
  The e2e pauses the relayer with SIGSTOP and SIGCONT, so its status port needs no pause
  endpoint.

## 3. Opcodes, manifest and namespaces

- **Opcodes.** REGISTER, DISABLE, GET, PUBLIC, SAMPLE, LOAD, INPUT_SHARED, EXECUTE,
  VERIFY, STORE, CONSUME, FETCH; no chain reads in the machine; a fresh sampled value enters
  the store through a SAMPLE parameter plus STORE (LOAD never creates a value). *Why:* the
  smallest set that runs every example; chain access belongs to the tip, outside the
  machine. [ARCHITECTURE.md section 3](ARCHITECTURE.md#3-the-request-lifecycle).
- **Namespaces.** The namespace is the contract address; it owns a set of circuits; a
  circuit resolves by (namespace, name) before any LOAD; the first registrant's key owns the
  namespace and signs every later registry body; GET and FETCH are namespace-scoped. *Why:*
  a circuit can only ever reach its own namespace's values.
- **Registry bodies carry sequence numbers and signed answers.** The first REGISTER has
  `seq` 0 and records the owner key; every later body carries the stored `seq` plus one; a
  `seq` 0 body is accepted while the stored `seq` is 0 and reruns the registration circuit
  on all three nodes; DISABLE keeps the record and a later REGISTER re-enables it. The
  nodes sign every registry answer with their `sig` keys. *Why:* replay protection, a repair
  path for a first REGISTER that committed on some nodes only, and values a developer can
  pin because three nodes signed them. [ARCHITECTURE.md section
  4](ARCHITECTURE.md#4-the-registry-lifecycle).
- **A node that refuses a registry body still joins the registration handshake**, with its
  refusal as its verdict. *Why:* the other two then refuse at once instead of failing on a
  closed mesh.
- **Manifests.** One schema serves both paths; `intake` selects the path (`direct`, the
  default, is the sidecar path; every other intake is the tip). The manifest refuses
  unknown fields and the other path's fields, and the intake decides which sources and
  reserved operands are allowed (for example, a non-secret-shared intake refuses
  INPUT_SHARED; `$user` is refused under every tip intake). *Why:* the manifest is the one
  place an app selects its bricks, and a field the round cannot honour must fail at
  REGISTER, not at run time. [ARCHITECTURE.md section 7](ARCHITECTURE.md#7-the-manifest)
  and `manifest.schema.json` carry the fields, defaults and rules.
- **No `queue` field.** One lock and one queue per namespace. *Why:* nothing shards yet;
  per-queue locks would come with sharding, with exclusion enforced at commit.
- **REGISTER gates what is not built.** A manifest naming a deferred option (`binding:
  exact`, relayed intake) is refused at REGISTER (400). *Why:* a deployment can never depend
  on a path that does not exist.

## 4. Keys and cryptography

- **Every key is Grumpkin.** Namespace owner keys, requester keys, node keys and receipt
  keys. A node holds two independent scalars, `enc` (key exchange) and `sig` (Schnorr),
  plus its master nullifier share. `enc` rotates on its own, with a grace window; `sig`
  changes only with a node-key epoch (section 15), because contracts pin it. The client
  takes the key set from the contract; `GET /v1/nodes` is discovery only, never a key
  source. *Why:* one curve that Noir circuits handle natively; rotation where it does not
  break pins. [ARCHITECTURE.md section 2](ARCHITECTURE.md#2-the-key-hierarchy).
- **One signature scheme.** Schnorr over Grumpkin in the encoding of noir-lang/schnorr
  v0.4.0, for owner keys, receipts, results, registry answers and Aztec accounts.
  Result and receipt signatures use derived nonces; registry answers use random ones.
  *Why:* pure Noir, so it proves inside the co-SNARK (co-noir has no ECDSA), and a derived
  nonce needs no random source inside the round's library call.
- **One authenticated encryption, one hash family.** Everything the machine seals is field
  elements, sealed by the Poseidon2 duplex (SAFE sponge) AEAD of `pss_utils/ae.nr`; every
  structured hash is Poseidon2; envelopes use an ephemeral Grumpkin key exchange with the
  node's `enc` key. No other cipher or hash family exists in the protocol; TLS is
  transport. *Why:* cheap to constrain in a circuit, and one construction to audit.
  [ARCHITECTURE.md, "Hashes and associated data"](ARCHITECTURE.md#hashes-and-associated-data)
  lists every hash and associated-data layout; `PROVENANCE.md` the origin of `dh.nr` and
  `ae.nr`.
- **Per-namespace nullifier keys derived in a machine circuit.** Each node holds one master
  nullifier secret share. At a namespace's first REGISTER a fixed registration circuit,
  compiled into the machine and never registerable, derives the namespace's `nsk_app` (kept
  as shares) and outputs `npk_app_hash` as a proven public value, which the contract pins.
  Application circuits take `nsk_app` by a fixed LOAD; the master never enters one. *Why:*
  a malicious circuit can only ever see its own namespace's key, so nothing leaks across
  namespaces, and the network identity exists before any round. The separators are machine
  constants, not Aztec's, since the contract is the only verifier of these nullifiers.
  [ARCHITECTURE.md, "The registration circuit"](ARCHITECTURE.md#the-registration-circuit).
- **Results are signed by every node.** Each node signs the result over the namespace, the
  request id, the new commitments and a hash of its own new record thirds; the orchestrator,
  `pss-client` and the tip's result function check all three against the pinned `sig` keys.
  *Why:* binds every result to the network a second time, beside `npk_app_hash`, and
  removes `npk_app_hash` as the single point of failure for state that cannot be
  recovered.

## 5. The request lifecycle and its checks

- **Security checks.** INPUT_SHARED is first-class with the neighbour consistency check;
  each node self-verifies the proof before storing; typed range checks run before the mesh;
  the orchestrator requires identical answers from the three nodes and verifies the proof;
  TLS on every leg, mutual TLS between orchestrator and nodes. The orchestrator serialises
  sessions under one global lock, serving a waiting scheduler session first but one public
  session after every four scheduler sessions in a row, and bounds public waiters (503 with
  `Retry-After`). *Why:* semi-honest Rep3 with checks that bound what one deviating node can
  do; the tip's queue must not starve public requests nor be starved by them.
  [ARCHITECTURE.md section 3](ARCHITECTURE.md#3-the-request-lifecycle).
- **Request ids.** One field element. A sidecar-path client draws 128 random bits; at the
  tip ids are derived from content and public. *Why:* the id is the replay token, and on the
  sidecar path the capability for FETCH, so FETCH by id is safe to leave open.
- **Sessions refuse together.** A mesh session opens with one exchange in which each node
  sends (request id, body hash) and the neighbour hash of every shared summand, and tells its
  neighbours its verdict; a node that refused earlier still joins with its refusal as its
  verdict and runs nothing. *Why:* a request one node refuses must not hold the machine's
  one session for the connect timeout, and a store that diverged at one node is refused at
  the handshake naming the key.
- **Bind runs twice.** A check bind with placeholder samples before any session, then a real
  bind inside the session with the correlated randomness; the two must agree on everything
  but the samples. *Why:* a bad request never reaches the mesh, and real samples exist only
  inside the session.
- **A supplied record no client-held read opens is refused** (400). *Why:* the body must
  equal what the round used.
- **Owner-bound records.** A client-held record's owner is the Grumpkin key of the request
  that created it. A request that supplies a client-held record, stores a client-held key
  or carries a shared input (intake direct) carries a Schnorr signature over its canonical
  body, checked before any record opens (403); a record opens only when its owner equals the
  signer. *Why:* FETCH stays open while only the owner can use a record; and since the
  signature covers every share hash and the requester is in every envelope's associated
  data, whoever holds the body cannot reseal one of the client's shared inputs with its own.
- **Key binding is an Aztec convention.** The same request field feeds LOAD and a public
  parameter of the circuit; the machine binds only the namespace. Public inputs never carry
  stored fields, blindings or persistent secrets; LOAD takes a public key only (no
  oblivious lookup on this path). *Why:* the proof names the key the round loaded, which the
  contract can check, while the machine needs no knowledge of an app's key layout.
- **Operator-run trust.** An operator-run network is enough for the research prototype.
  REGISTER, DISABLE and record-supplying requests are signed; other requests are
  unauthenticated, and fees, quotas and allow-lists go in `admit`. *Why:* the signed bodies
  are the ones that change who may use a namespace or a record; signing every other request
  would cost each user a key and stop nothing `admit` cannot. `DESIGN.md`, ["The
  operator-run trust rule"](DESIGN.md#the-operator-run-trust-rule).

## 6. State on the sidecar path

- **State mode per key.** Client-held (a per-node AEAD-sealed share pair, returned to the
  user and supplied back) for single-owner state; node-held (one row per key) for shared
  state; no versioned storage on this path. *Why:* a per-user record needs no database;
  shared state cannot be carried by one user.
- **Where state lives on Aztec.** User-owned single-reader state in ordinary PXE notes
  owned by the reader; many-reader state as a hash anchor presented as an argument plus a
  nonce; MPC-held state in the sidecar. Nonce mining and the effects split live in
  `pss-client`, not in aztec-nr unconstrained code. *Why:* each kind of state takes the
  least machinery that keeps it, and aztec-nr stays unmodified.
- **CONSUME is `once` or `never`, default `once`.** A consumed state is refused whatever the
  circuit or inputs, and a round may not re-store a consumed note hash; the consumed row
  records the consuming circuit's vk hash and request id and is never pruned except by
  rollback. A retry is FETCH by request id. *Why:* one evaluation per state, with no
  ambiguity about which circuit consumed it.
- **Every node keeps a `requests` table, pruned by age.** It holds what FETCH and rollback
  need (body hash, vk hash, proof, public inputs, records, sealed replaced vectors, status),
  in both state modes; the default window is 30 days. *Why:* FETCH and rollback need the
  row, and the orchestrator is never the sole holder of anything.
- **Node-held write rule.** A node-held key may be written by a request that loaded it,
  when its stored value's note hash is consumed, or when it is empty (409 otherwise).
  *Why:* two rounds cannot both overwrite one row from different starting values.
- **Rollback without versioned storage.** When STORE replaces a row the node seals the
  replaced vector to itself in the same commit; an operator-only `restore` on a local socket
  undoes a request, in reverse order of commit. At the tip the same restore discards an
  attempt committed at fewer than three nodes and keeps its row, so a resend runs again under
  the same request id. *Why:* a round whose transaction can never land is recoverable in
  both state modes; at the tip the machine request id is fixed by the state and the pinned
  values, so without it the entry would wait for `skip()`. [ARCHITECTURE.md section
  3](ARCHITECTURE.md#3-the-request-lifecycle); `DESIGN.md`, ["A node-held round whose
  transaction cannot land"](DESIGN.md#a-node-held-round-whose-transaction-cannot-land-the-sidecar-path).

## 7. Tip: state

- **Node-held state is the tip default.** The nodes hold the state as Rep3 pairs; the chain
  holds one commitment per key (a tree's root for a tree-valued key) and logs no state.
  *Why:* broadcasting the whole state on every apply does not suit a large book, and the
  nodes already hold the secrets everything rests on. *Consequence:* recovery rests on the
  nodes. [ARCHITECTURE.md, "Node-held state"](ARCHITECTURE.md#node-held-state).
- **Tip state is versioned and anchored to the chain.** A round loads the version its old
  commitment names and creates a new version under its new commitment; nothing is
  overwritten, and the slot's commitment names the canonical version. *Why:* the chain
  decides which version counts, so no tip round needs rolling back, and the scheduler can
  pipeline rounds on versions that are still live.
- **Version retention back to the finalized tip.** An orphaned or superseded version is
  kept until the block that orphaned it is behind the Aztec node's finalized tip; receipt
  inputs and retired `enc` scalars are deleted by the same rule; a node that cannot read the
  chain deletes nothing. *Why:* no block replacement reaches the finalized tip, while a
  count of proven blocks is no bound (a proof can land seconds after the one before it, and
  an L1 reorg can remove both). *Consequence:* the orphans held grow with the proving
  interval and under a finality stall. `DESIGN.md`, ["Retention and
  pruning"](DESIGN.md#retention-and-pruning).
- **Equal commitments create no version.** A round whose new commitment equals its old one
  (a non-secret-shared no-op) keeps the parent and the round's output for that key is
  discarded. *Why:* the non-secret-shared no-op rule holds unchanged. *Rejected:* a fresh
  blinding on every node-held round (it would change that rule).
- **Recovery from the neighbours.** Every Rep3 component is held by two nodes, so one lost
  store is resynced from its two neighbours and audited; a lost key directory is recoverable
  only from an offline backup, else the node is replaced (section 15); two lost stores lose
  the state. No encryption at rest beyond disk encryption. *Why:* one node's pairs reveal
  nothing alone, and Rep3 redundancy already gives one-loss recovery. `DESIGN.md`,
  ["Recovery"](DESIGN.md#recovery).
- **Chain-held state stays as an option for small, fixed-size states.** Every apply logs
  the whole new state sealed to the nodes' keys. Recovery needs those keys, the package
  that decodes the log, and a matching log from the last 64 queue entries or the init
  round. REGISTER bounds the state by one public log. No further
  investment beyond keeping it clean. *Why:* it is built and tested and gives recovery
  without trusting the nodes' stores. *Consequence:* the sealed state stays on chain for
  good (harvest now, decrypt later). `DESIGN.md`, ["Chain-held
  state"](DESIGN.md#chain-held-state).
- **The chain-held blueprint takes secret-shared on-chain intake.** *Why:* it keeps queued
  inputs available on chain for recovery alongside the sealed state. Secret-shared receipt
  intake keeps inputs off chain while the state history is on chain anyway.
  *Consequence:* no example builds it; chain-held state is tested on the machine's test
  rounds and the contract library's test contract.
- **Large books are Poseidon2 Merkle trees.** A tree-valued key has a fixed depth `D`, a
  leaf width and a probe width `K` (the most leaves one round touches); every write gives a
  leaf a fresh blinding, so leaf and internal hashes are public data the nodes keep in the
  clear. A round loads only its touched leaves (shared) and their paths (public), verifies
  the old paths inside the MPC and computes the new root; REGISTER bounds a round by `K` and
  `D`. *Why:* a round's cost depends on what it touches, not on the size of the book.
  [ARCHITECTURE.md, "Tree-valued keys"](ARCHITECTURE.md#tree-valued-keys).
- **Every round fits a 2^14 circuit, and a tree's `D` and `K` are sized to it.** `K` is the
  largest probe width at which every round of the app, the secret-shared entries included,
  stays below 16,384 gates (bb `gates`); `D` sets the capacity (`2^D - 1` positions opened
  over the book's life) and the path cost of every slot. *Why:* a tree round costs
  `K·D` shared Poseidon2 permutations, sequential in depth, so the link latency between the
  nodes sets the round time; one budget keeps every round of an app alike in cost.
  *Rejected:* a larger budget for one round (the keeper's scan at 2^15 would allow a window
  of 32). Lending's measured counts are in
  [examples/lending-tip/README.md](../examples/lending-tip/README.md), "Capacity".
- **The header lives in leaf 0.** A book's pool-level fields (lending's aggregates and the
  append index) are leaf 0 of the tree. *Why:* one root commits to the whole market.
  *Rejected:* a second small key and slot.
- **The nodes source a tree round's path values, and the old-leaf check is an assertion.**
  The scheduler places the old leaf hashes and siblings in the request from the three
  nodes' agreeing trees, each chain verifier compares them with its own, and the loaded
  pairs are handshake summands; inside the round each old leaf is asserted against its old
  hash. *Why:* a diverged tree is found before the round, and a mismatch means a diverged
  node store, not a user error, so it is not a flagged code. *Rejected:* only a hash of the
  path values in the handshake (it finds a diverged tree later).
- **Leaf indices are clear to the nodes by default; the oblivious tree is an experimental
  option.** The default tree shows the nodes which positions a round touches. The oblivious
  tree keeps leaves and internal hashes in a distributed oblivious RAM with the index a
  shared input, as a dense tree and as a sparse keyed map with proofs of absence; it is
  built but never a default and never in a blueprint. *Why:* under partial-note completion
  the index names no owner (the nodes learn that position 41 moved, not whose it is), which
  is good enough for most books; the oblivious tree closes the remaining gap (linking a
  position's requests, the activity of positions) at a cost a deployment must accept.
  *Consequence:* the dense oblivious tree has the clear tree's escape hatch, from the same
  code, since an exit needs no index or path; a keyed map has no hatch (below).
  [ARCHITECTURE.md, "The oblivious tree"](ARCHITECTURE.md#the-oblivious-tree).
- **The oblivious tree takes secret-shared intakes only.** Its index inputs must be
  INPUT_SHARED, which the non-secret-shared intakes refuse. *Why:* under a non-secret-shared
  intake the index would be public anyway.
- **An opening on the oblivious tree is public.** An opening round carries a public `opens`
  flag and the scheduler's public `$new_leaf`, and outputs the public append index. *Why:*
  the append index stays circuit-enforced (above) with no extra DORAM access. *Alternative
  not built:* the nodes read the header first and use their share of its append index as the
  opening's address in a second, dependent DORAM batch, which makes the opening index
  private at one dependent batch per opening; it is worth adopting if that batch measures
  under 10% of the oblivious phase.
- **The DORAM is the vendored gigadoram-rs.** It lives under `machine/sidecar-oblivious/vendor`
  (Apache-2.0 / MIT, its changes in that directory's `PROVENANCE.md`). *Why:* the build and
  its tests need no other remote.
- **One field per DORAM address.** Each tree element is its own address. *Why:* the interface
  is the same either way, and which is faster at `D = 16, W = 8` is a measurement.
  *Alternative:* one leaf per address (a `W`-field value): `D + 2` accesses per slot
  instead of `D + 1 + W`, a quarter of the address space, a wider sort per rebuild.
  [ARCHITECTURE.md, "The DORAM and its layout"](ARCHITECTURE.md#the-doram-and-its-layout).
- **Persistence per level.** A commit writes the DORAM's head and only the levels a rebuild
  replaced, each a holder blob. *Why:* a commit at depth 16 writes about 26 KB rather than
  the whole DORAM's 760 to 800 MB, the bottom level stays under Postgres's value limit, and
  the blob format lets node replacement, resync and backup carry the DORAM without the
  holder. [ARCHITECTURE.md, "Persistence, resync, share refresh,
  audit"](ARCHITECTURE.md#persistence-resync-share-refresh-audit).
- **A journal lives as long as its version or as long as its entry is applied, whichever is
  longer.** *Why:* an applied orphan whose version retention deleted must still be undone
  by the key's next sync. [ARCHITECTURE.md, "Versions, rollback and
  pipelining"](ARCHITECTURE.md#versions-rollback-and-pipelining).
- **An oblivious key is never audited in the clear.** The clear audit would leak the set of
  leaves changed since the last audit, which is what the brick exists to hide; its audit is
  an MPC pass over shared leaf hashes (not built). The DORAM rebuilds when its cache fills,
  inside an access; a rebuild at the session's start, or a maintenance session between
  rounds, is not built.
- **The keyed map widens the DORAM's address.** The vendored DORAM's address is 128 bits
  with a capacity-bounded lazy bottom level: the dense brick's access count at the map's
  depth, one batch per slot, no second hashing layer. *Rejected:* the OMap's cuckoo tables
  per level over the unchanged 32-bit port (five times the accesses, a stash and its failure
  mode, PRFs over shares) and a pointer tree (`D` dependent batches per slot).
  [ARCHITECTURE.md, "The oblivious sparse map"](ARCHITECTURE.md#the-oblivious-sparse-map).
- **A keyed map's default depth is 64.** *Why:* a 2^64 targeted collision and random
  collisions at about four billion keys, for 256 shared permutations per two-slot round.
  Depth 32 halves the cost and suits maps of unpredictable keys only; the depth is a per-key
  layout parameter (up to `MAX_MAP_DEPTH`, 120).
- **The full key is in the leaf and checked.** *Why:* a low-bit collision is then a refusal,
  never a wrong value, for one element per leaf and one equality per slot. *Rejected:*
  trusting the path alone (a collision would silently merge two keys' values).
- **No hash in the keyed map.** The path is the key's low `D` bits; the app's request
  functions hash every key at entry. *Why:* the app hashes at entry for free. *Rejected:* a
  Poseidon2 of the key in the brick (one permutation in the circuit, one MPC permutation per
  key at the nodes, and the mpc-core Poseidon2 gadget as a dependency). *Consequence:* the
  collision argument rests on apps hashing their keys.
- **The fill count opens the number of real records** at each bottom rebuild. *Why:* the
  capacity bound then restarts from the truth plus every access since, so a map within its
  working size runs indefinitely; it leaks the number of distinct addresses touched, once per
  bottom-rebuild cycle. *Rejected:* opening one over-capacity bit (the bound would count every
  access since the map's creation and refuse any map after `capacity / (2·K·(D + 1 + W))`
  rounds).
- **A full keyed map stays full.** A resize (extract every record, build a larger DORAM,
  carry the applied list) is not built; a deployment sets its capacity with headroom.
- **A keyed map has no escape hatch.** Its private write re-blinds slots at keys the prover
  chose, so it cannot keep the exit tag's rule that a round whose shares do not open `C`
  writes no entry. Vanished nodes freeze its entries; queued escrow returns by `skip()`.
- **The dense brick keeps its bottom build.** It could drop it, and its `2^(D + 1 + LW)`
  memory, with the keyed map's encoding and a capacity; nothing in the keyed map changes the
  dense brick.
- **The keyed example is credits paid to a key** (`examples/credits-tip`): the smallest
  deployment with insert, update, lookup, prove-absent and two keys in a round, a use
  partial notes cannot serve. *Rejected:* lending keyed by owner commitment (no scan is
  possible on a keyed map, so it would need a new keeper round and liquidation discovery: a
  redesign of the market). Minimal PSS still applies: a balance only its owner reads and
  writes is a note; a keyed map earns its place where writer and owner never interact or a
  round proves a fact about a key it does not own.
- **The append index is circuit-enforced.** A tree's header leaf carries the append index;
  an opening round requires its new leaf to sit there and advances it, a mismatch being a
  flagged no-op. The scheduler's assignment is the hint the circuit verifies. *Why:*
  invariant 0: otherwise a compromised network could open a position in a gap far past the
  frontier, which a keeper never scans, borrow to the limit and leave the loss to the
  lenders. *Rejected:* trusting the scheduler's assignment (the nodes are the adversary).
- **Lending is a tree; the AMM a small key.** Lending's borrowers and lenders are leaves of
  two kinds in one book, with the market's aggregates and the append index in leaf 0; the
  AMM's reserves are one three-element key. Lending takes `D = 16`, `K = 2` by the 2^14 rule
  (above). *Why:* a lending book grows with its users, so a round must cost what it touches;
  three reserves fit one flat key. [examples/lending-tip/README.md](../examples/lending-tip/README.md),
  "The book", has the leaf layouts.
- **Liquidation discovery under hidden positions is a lottery among liquidators.**
  Liquidators sweep, each probing `K - 1` positions per round, and many sweeping at once is
  the intended market; a keeper round reads a window of `W = 8` positions and returns their
  health bits to the keeper alone, as a private outcome. Owners read their positions through
  their own rounds' outcomes and an owner-bound `view` round. *Why:* no position data leaks
  and nothing new enters the machine; `W = 8` is the largest window the 2^14 rule allows.
  *Rejected:* a health flag revealed to the nodes. [ARCHITECTURE.md, "A read-only window on
  a tree key"](ARCHITECTURE.md#a-read-only-window-on-a-tree-key).
- **`enc` rotation does not touch node-held state**, which is stored as Rep3 pairs, not
  sealed to `enc`. *Why:* an idle namespace then survives any number of rotations.

## 8. Tip: queue and rounds

- **The chain orders requests.** Commitments live in public storage; requests enter a
  chain-ordered queue that refuses a repeated request id; one queue, one lock and one proof
  per request per namespace, no batching. *Why:* nobody, the network included, can reorder
  or drop a request without the chain showing it. [ARCHITECTURE.md section
  6](ARCHITECTURE.md#6-the-tip-as-an-extension).
- **Who drives a round.** The orchestrator is the single serialiser: its chain reader and
  scheduler synthesise the head's request, with a machine request id derived from the chain
  request id, the old commitments and the pinned values, and run it as an ordinary request;
  each node's chain verifier re-reads the chain through its own Aztec node and refuses a
  request that differs from its own view. *Why:* a recompute against a different state or
  price is a new request, so the replay rule holds; a lying or stale reader can only delay.
  [ARCHITECTURE.md, "The coordinator (tip)"](ARCHITECTURE.md#the-coordinator-tip).
- **The chain reader follows proposed blocks** (about every 6 s) and keeps only the
  namespace's logs; when a proposed block is replaced, the scheduler recomputes on the
  replacement chain and each chain verifier reads again. *Why:* latency; node-held versions
  survive replacement through the retention rule.
- **The chain reader keeps block hashes back to the settled block**, the finalized tip, not
  a fixed ring; every read names a block's number and hash. *Why:* any replacement (a
  proposer's blocks, an epoch prune, an L1 reorg) then voids exactly the reads above the
  last shared block, in memory bounded by the blocks above the finalized tip, the one block
  no replacement reaches (aztec's `L2BlockStream` takes the same floor). *Rejected:* a
  depth knob (a fixed ring silently loses detection past its depth). *Consequence:* memory
  grows under a finality stall, which the reader logs and `GET /v1/status` reports.
- **Nodes run and sign rounds at the proposed tip.** A round starts once the three chain
  verifiers see its request in a proposed block; one rule for every deployment, no setting.
  *Why:* waiting for a checkpoint would add up to a slot to each round and hold the
  orchestrator's one session meanwhile. *Consequence:* a proposer that abandons a block
  holding a request lets its requester read the outcome of a round that never lands, at the
  cost of its slot's checkpoint (`DESIGN.md`, ["Replaced blocks"](DESIGN.md#replaced-blocks)).
- **Records of a rolled-back round are dead.** The nodes never sign a round on a branch they
  abandoned, and refuse the abandoned branch's records by note hash. *Why:* a record is
  node-sealed at creation with its note hash in the associated data, so the abandoned
  branch's records are a fixed, finite set the user can neither re-randomise nor mint.
- **Log discovery is a standalone module** wrapping the Aztec node's log RPC, used by the
  reader, the scheduler and every chain verifier. *Why:* one place handles paging, anchoring
  and replaced blocks; it forks no Aztec code.
- **The result transaction.** A private result function verifies the vk pin, the co-SNARK
  and the three result signatures and enqueues a public `apply`, which makes its pinned
  external calls first, then checks the head and slots and writes. Result submission is
  permissionless, with an operator-run relayer by default. *Why:* a failed check reverts and
  changes nothing; making the external calls first means a re-entrant `skip()` cannot
  interleave.
- **Pinned public reads** are nested public calls whose returned values the circuit takes as
  public inputs and `apply` re-checks; the machine request id covers them. *Why:* an oracle
  price is read at apply time, not trusted from the request. [ARCHITECTURE.md, "Pinned
  reads"](ARCHITECTURE.md#pinned-reads).
- **Pinned-read freshness is a parameter of each read**: `exact` (the default), `epoch` (the
  current or the previous epoch's value, the previous one offered only for a window after an
  epoch opens) or `tolerance` (a band checked in `apply`). The chain verifiers admit a
  request's own value by the same rule on an entry's first attempt only. *Why:* a round
  takes minutes to land and an oracle may move every block; under equality alone such a head
  recomputes until `skip()`, costing the user the request and its fee. The first-attempt rule
  stops the orchestrator running one entry at many admitted values.
- **Lending's oracle read uses `epoch`.** *Why:* the price is the one pinned value expected
  to move often, and an epoch keeps an exact price check (no band to tune) while letting a
  round span one update.
- **Binding: `turn`** ("apply to the state when my turn comes") is the default and the only
  built binding; `exact` ("bind to this exact state") is deferred.
- **Total circuits.** Every tip circuit is total (always satisfiable): `ok` plus codes
  instead of assertions on user data; total-lint gates each example's check script, and
  REGISTER does not gate on it. *Why:* an unsatisfiable head would hold the queue until
  `skip()`.
- **A failed round keeps its state.** On the public-output path a round with `ok = false`
  outputs, for every key it writes, the commitment the slot holds; the result function
  refuses one that does not, and `apply` writes nothing. *Why:* whoever follows the state
  from the results takes the new commitments whatever `ok` is, so a failed round that named
  another commitment would desynchronise slot and result. *Consequence:* under private
  outcomes, which have no public `ok`, flat rounds re-blind and write on every outcome
  (section 10).
- **The stale valve.** After the contract manifest's `queue.stale_blocks` (the examples
  state 50 L2 blocks) anyone may `skip()` the head, which returns what the skipped request
  put in, its usage deposit and any escrow. *Why:* a junk or unservable head holds the queue
  for at most the stale period, and the usage deposit prices the queue (section 12).
  [ARCHITECTURE.md, "The refund rule"](ARCHITECTURE.md#the-refund-rule).

## 9. Tip: intake

- **One compiled circuit per round per intake family.** `<round>_shared` serves both
  secret-shared intakes; `<round>` serves both non-secret-shared intakes. Each is a thin
  main over the round's one function in the app library, written once over pss_core's intake
  family (`tip::family`: `Plain` and `SharedIntake`). *Why:* the two layouts differ, so
  artifacts multiply, but code does not; circuits per example grow as rounds plus two, not
  rounds times intakes.
- **Secret-shared receipt intake is the default; the non-secret-shared intakes are test
  paths; secret-shared on-chain intake is an option; relayed intake is deferred.** Every
  round of every tip example but its init round runs under secret-shared receipt intake; the
  non-secret-shared intakes run on one round each of the AMM tip and lending (the swap, the
  deposit), on deployments of their own. Relayed intake (the network submits the request
  transaction) is deferred for composability reasons. *Why:* the default hides inputs from
  the chain and from any single node; the test paths keep the non-secret-shared code tested.
  Any example round can run under any intake by the recipe in the design guide's [Running a
  round under another intake](design-guide/README.md#running-a-round-under-another-intake),
  with no change to the round's logic.
- **On-chain intake.** The user's private function checks static validity and enqueues the
  app's request wrapper; the inputs travel in a public request log. *Why:* the simplest
  intake, with no off-chain step.
- **Receipt intake.** Inputs reach the nodes in the clear over TLS, never the chain; each
  node signs a receipt over (request id, inputs hash, expiry block) and the intake function
  checks the three. *Why:* inputs stay off chain while the chain still orders the request.
- **Receipt pruning by queue standing.** A node keeps a receipt's stored inputs while its
  request is queued and not done, and prunes, after the expiry plus the stale period, only
  receipts whose request never reached the queue or is done; the standing is read at the
  settled block. The same rule governs stored envelopes. *Why:* a fixed clock would drop an
  honest request's inputs before it reached the head and stall the queue for a stale period;
  reading at the settled block means a replaced block never drops a queued request's inputs.
- **Secret-shared receipt intake.** Each node receives one Rep3 pair of each sensitive
  input in an envelope; nothing reaches the chain but the request id and the expiry block.
  *Why:* no `enc` key is pinned in a contract, so `enc` keeps rotating; no ciphertext of an
  input ever reaches the chain, so nothing on chain waits for a future break of the key
  exchange (the post-quantum property); and it reuses the receipt route, table and contract
  check. [ARCHITECTURE.md, "Secret-shared intake"](ARCHITECTURE.md#secret-shared-intake).
- **A hiding commitment binds the shared inputs.** `C`, a Poseidon2 hash of the app inputs,
  the outcome key and tag, and a blinding, stands where the inputs hash stands in the
  receipt, and the chain request id is computed from it. *Why:* the round's proof, not only
  the nodes' signatures, binds the inputs to the queued request; the user's private function
  computes `C` from the plaintext it checks; request ids do not depend on envelope
  encryption or `enc` keys; both secret-shared intakes compute it the same way, so one
  circuit serves both.
- **The request function proves the sharing; each node checks its own vectors.** The client
  commits to each of the three salted summand vectors and signs over a digest of those
  commitments, the layout and the clear values; each node checks alone that its two vectors
  match their commitments, and the user's private function proves that the summands add up
  to `C`'s values and checks the three receipts over the digest. *Why:* the user already
  proves its request, so the check costs about ten Poseidon2 permutations in the cheapest
  place there is; no MPC runs at receipt time, the nodes exchange nothing, and the
  orchestrator compares nothing. A request whose shares do not open `C` is never queued.
  The node lacking a vector cannot test guesses against its commitment, since the vector
  holds a summand of the uniform blinding.
- **The MPC receipt check is a flag.** Each secret-shared-intake round recomputes `C` inside
  the MPC and folds the equality into `ok` as its first check (the AMM's code 9, lending's
  14). Only nodes that change their shares after intake make it fail; such a round lands as
  a no-op and refunds the request's escrow and usage deposit. *Why:* round circuits stay
  total; an assertion would make such a round unsatisfiable and hold the head until
  `skip()`.
- **The outcome nonce is the hash of the note the plaintext completes.** An outcome is
  sealed under a nonce derived from the completed note's hash, in a separate domain for a
  round whose shares do not open `C`. *Why:* in the duplex AEAD two plaintexts under one key
  and nonce show their difference; the note hash commits to the plaintext, so one nonce only
  ever seals one plaintext whatever the run draws or the nodes change. *Rejected:* a nonce
  per attempt (two runs of one attempt draw fresh blindings, so their outcomes differ under
  one nonce).
- **The intake associated data binds the chain request**, not the synthesised body. *Why:*
  the user cannot know the body the scheduler synthesises, and every recompute must reuse
  the same envelopes.
- **Static validity stays at intake.** The user's private function asserts the app's
  `is_valid` over the plaintext; the receipt route checks only the inputs left clear; the
  circuits keep flagging the same checks as codes. *Why:* a malformed request never costs a
  round; the flags are the backstop.
- **Receipts take envelopes to the current `enc` key only**, and a node keeps a retired
  scalar until no queued request needs it. *Why:* a receipt the network signed must still
  open when its round runs, however long a backlog keeps it queued.
- **The scheduler takes the envelopes from the nodes.** Each node stores only its own
  envelope and the three share hashes; the scheduler places the envelopes in the synthesised
  request. `C` is not a public input of the proof. *Why:* the user sends each node only its
  own envelope and cannot know the synthesised body; the share hashes let each node check at
  the handshake that its neighbours hold the same sharing.
- **Secret-shared on-chain intake.** The contract keeps each node's current `enc` key and
  epoch in public storage, rotated by a transaction the node's `sig` key signs; the user's
  private function emits one private log of the shares (at most nine clear inputs and chosen
  shared values together, padded to one length) and stores its hash beside the queue entry;
  the current and the previous epoch are accepted. *Why:* an app that wants no off-chain
  step. *Consequence:* the ciphertexts stay on chain for good, and the clear app inputs are
  public in the log. The keys are read from public storage at the anchor block; a delayed
  public mutable was rejected because it adds a delay to every rotation. The request data is
  a private log plus a stored hash; a public log was rejected because it would pass the data
  through public calldata. [ARCHITECTURE.md, "Secret-shared on-chain
  intake"](ARCHITECTURE.md#secret-shared-on-chain-intake).
- **The requester is hidden under every intake.** Chain request ids carry no address (a
  random salt per request under a non-secret-shared intake, the blinding in `C` under a
  secret-shared one); the user's private function reads no `msg_sender` for the request and
  enqueues the app's `#[only_self]` wrapper; `$user` is refused under every tip intake; a
  user who must hide its network address on the receipt route uses a mixnet or relay (out of
  scope). *Why:* the requester's address must reach neither the chain nor the nodes. The
  salt is random per request, never a counter.
- **One intake family per namespace.** REGISTER refuses, in one namespace, a
  non-secret-shared package that reads a key beside a secret-shared package that writes one;
  a non-secret-shared round that reads no key (an init round) may sit beside secret-shared
  rounds. *Why:* a non-secret-shared round's public outputs would publish state that shared
  inputs touched. *Consequence:* the examples run their non-secret-shared cases on
  deployments of their own, and lending's contract refuses the same mix in its
  configuration. *Alternative not taken:* a rule per concrete key, which needs the concrete
  keys at REGISTER; `sidecar-core::registry` carries it as a DEV DECISION.
- **Lending's ownership is a note.** The book records no owner: a position's owner is
  whoever holds a completed note of it. A request on an open position opens one of the
  sender's notes of it in the private request function (never nullified) and commits the
  request's partial note to the sender again; an opening deposit, a liquidation and a scan
  are open to anyone. *Why:* no request carries the requester's address, and invariant 0
  forbids an authorisation the nodes hold even in shares. *Rejected:* an owner secret or
  owner key in the leaf (an authorisation the nodes hold). *Consequence:* an index is never
  reassigned and a position is not transferable; a liquidation reaches the owner through a
  delivery handle (section 10). [ARCHITECTURE.md, "Secret-shared
  intake"](ARCHITECTURE.md#secret-shared-intake) ("Ownership by note").
- **Public activity is accepted.** The queue, the slots, the pinned reads and each
  transaction's timing stay public. *Why:* hiding them needs cover traffic or batching,
  which the first apps do not need; they show activity, not inputs or state.

## 10. Tip: outcomes and delivery

- **Non-secret-shared intakes: public outputs.** App outputs are public inputs of the proof
  that `apply` uses as the app wishes (completing the user's partial note, or storing them
  under `outcome: none`); there are no outcome logs. *Why:* the inputs are public anyway.
- **Secret-shared intakes: private outcomes.** The result function verifies the co-SNARK,
  pushes the note hashes the circuit computed and emits one private log of the outcome,
  encrypted inside the MPC under the user's outcome key; the enqueued `apply` checks the head,
  slots and pinned reads and writes the new commitments whatever `ok` is. Flat rounds draw
  fresh blindings on every outcome; a tree round that placed nothing writes nothing, since
  the nodes know that case from public data. *Why:* no note or log can land without its
  `apply`, and the slot write reveals nothing about `ok`. [ARCHITECTURE.md, "Secret-shared
  intake"](ARCHITECTURE.md#secret-shared-intake) ("Private outcomes").
- **App values beside a private outcome: one convention.** A round may output public values
  for the app's contract after its private outcome (`pss_core` `Finished::valued`,
  `pss_public_contract` `outcome::Private::valued`), never an amount, an owner or anything
  of the outcome. An app that escrows puts the public inputs-opened bit last, and `apply`
  passes it to the token brick (`token::settle_applied`), which refunds the escrow and the
  usage deposit when the shares did not open `C`. *Why:* deviating nodes can make any round
  fail the receipt check, and invariant 0 forbids that costing the user; one place for the
  bit lets every app read it the same way.
- **Outputs and value delivery are two axes.** Outputs (public or private) and value
  delivery (partial-note completion, or `none` for public outputs an app stores) are chosen
  separately. *Why:* they are independent (a private outcome always delivers, a public one
  may or may not), so fewer combinations need explaining.
- **Value delivery is partial-note completion.** In the request the user privately commits
  to its address and the note's randomness as a partial note (aztec-nr's convention), which
  travels as the reserved shared value `$partial_note`; the nodes complete the note in the
  co-SNARK for a private result, or `apply` completes it in public for a public one. Across
  rounds a participant opens its completed note in its own private function and creates the
  next partial note committed to the same address. The note randomness, outcome key and tag
  derive from the wallet secret and a per-namespace request counter; the circuit derives
  none. Each partial note serves one request: the request function computes it from its
  preimage and pushes a use nullifier. A refund (escrow, usage deposit) is a partial note a
  public function completes, never a round. *Why:* invariant 0 and minimal PSS: the user's
  address never enters the circuit, the value lands in one transaction with no second step,
  the result transaction makes no call, and the relayer sees ciphertext and hashes; a payout
  made in the result transaction would show its amount and recipient to the nodes, the
  orchestrator and the relayer. The use nullifier keeps the PXE's first-completion
  discovery sound. *Rejected:* payment through an app hook in the result transaction, an
  outcome note owned by an address the request names, and note randomness derived in the
  circuit. [ARCHITECTURE.md, "Partial-note
  delivery"](ARCHITECTURE.md#partial-note-delivery) is the mechanism.
- **The partial note's details.** `$partial_note` is a shared value, not a clear one: a clear
  `P` would let the nodes link it to the completed note hash. The outcome tag travels as
  `$outcome_tag`; deriving it from `$outcome_key` inside the circuit would save one shared
  value and one log field and is the alternative left open. aztec-nr's validity commitment
  is not used: `P` is bound to its request through `C` and the chain request id, and the
  queue lands one completion per request. The use nullifier, not delivery keyed by request
  id, stops two requests naming one `P`: the alternative needs client code for the public
  completion that the nullifier makes unnecessary.
- **The request-side owner is `msg_sender`.** Every request function commits the partial
  note to its sender, with no owner argument, so every completed note is its sender's (a DEV
  DECISION in each contract). *Alternative:* an authwit from another account, which lets a
  delegate request rounds on a position. A position is not transferable and its index is
  never reassigned: reuse or transfer would need a generation element in the leaf that the
  request's note must match, which is not added.
- **Token custody is public, settled by the user's own redeem.** The app holds its tokens in
  public balances and pays a note's amount into a token partial note of the user's in a public
  function: the amount is public at redeem time, unlinked to the request, the recipient
  hidden. *Rejected:* a public result completed in `apply` (the amount public at the
  result), a private transfer in the result transaction (the relayer would see the amount),
  and private custody of the app's tokens (it needs a key the result transaction's builder
  holds, concentrating funds behind an operator key). [ARCHITECTURE.md, "Tokens and
  escrow"](ARCHITECTURE.md#tokens-and-escrow).
- **Public outcomes are refused under a secret-shared intake.** *Why:* what the shares hide
  must not be published. An app whose result is public by nature (an auction's clearing
  price) would use the public completion with the user hidden, under a DEV DECISION naming
  what its public outputs reveal.
- **A private outcome lands only in the revertible phase.** The result function asserts it
  before pushing a note hash or emitting the outcome log. *Why:* neither can then land
  without its `apply`; dropping the assertion would rely on v6 dropping a transaction whose
  setup-phase public call reverts.
- **A position changed by another party reaches its owner through a delivery handle.** The
  owner's last request leaves a standing handle in the leaf, which every round that changes
  the position on someone else's behalf (a liquidation) completes, each under its own log
  tag; the escape hatch exits on the newest such note. *Why:* the owner is never named to
  the nodes, yet learns privately of every change. *Rejected:* no notification (a position
  liquidated after its owner's last round could then not exit a frozen market, since the
  liquidation spent its note's exit tag and no note of the owner's holds the new one). *Consequence:* every result of such an
  app carries a second note hash and log, a filler where nobody is notified.
- **Verifiable delivery: constrained or node-sealed.** Constrained: the circuit computes the
  ciphertext inside the MPC under a key the recipient supplied (so no key exchange runs in
  the MPC) and exposes it with the note hashes as public outputs; used for anything
  value-bearing or needed to spend. Node-sealed: the nodes seal outside the circuit, only
  where the recipient is a node itself (record thirds, sealed vectors). *Why:* a node that
  seals garbage to itself can only halt, which any one node can already do in Rep3, while
  garbage sealed to a user would lose its value; withholding a result entirely is a liveness
  question (the stale valve), which no constraint fixes.
- **No node-sealed delivery to users.** Data for a user is constrained in the circuit or
  public. *Why:* node-sealed data for a user would let a node withhold or garble
  value-bearing data without detection, and no blueprint needs it. *Consequence:* an app
  with cheap data that is neither value-bearing nor needed to spend pays the in-circuit
  encryption or publishes the data.
- **Off-chain delivery belongs to the sidecar path.** On the sidecar path the user receives
  its result off chain, verifies the co-SNARK and the three signatures in its own private
  function (`pss_contract::verify_pinned`) and submits the transaction itself. At the tip
  the relayer lands results, so data for a user travels only in the encrypted outcome log.
  *Why:* off chain, only the requester can carry its result into its own transaction; at the
  tip the transaction is the relayer's.
- **The round type is hidden under a secret-shared intake.** Each app exposes one public
  request wrapper and one public `apply` with the same arguments on every round, makes the
  same pinned reads, pushes the same number of note hashes and logs, and pads the outcome
  log (and the on-chain request log) to 16 fields deterministically, from the tag (or the
  blinding). A round type stays visible only where it must change genuinely public state,
  stated in the app's DEV DECISION. *Why:* deterministic padding leaves whoever submits the
  transaction no covert channel in the padding fields. *Consequence:* timing stays visible
  (proving time per circuit; redeems follow only some rounds); the non-secret-shared intakes
  reveal the round type through their clear inputs; the nodes and the relayer see the
  circuit.

## 11. Tip: deployment

- **A constructor that pins the circuits, then a once-only `configure`.** The namespace is
  the contract's address and REGISTER derives `npk_app_hash` from it, so the constructor
  cannot take it. The constructor takes what does not depend on the namespace (the node `sig`
  keys, `stale_blocks`, the packages and their vk hashes, the app's constants); the deployer
  draws a secret salt, REGISTERs every package against the computed address, deploys, calls
  `configure` and sends the init round. *Why:* the first REGISTER's signer becomes the
  namespace owner, so an address public before its first REGISTER could be taken.
  [ARCHITECTURE.md, "Deployment, configure and the init
  round"](ARCHITECTURE.md#deployment-configure-and-the-init-round).
- **The vk hashes and the contract manifest's hash are pinned in the constructor;
  `configure` takes only the signed `npk_app_hash`.** `configure` is a private function
  anyone may call: it checks the three node signatures over the manifest answer for this
  address and the constructor's pins, then writes `npk_app_hash` once. *Why:* the address
  then commits to the circuits and to the manifest the nodes run them under, which anyone
  checks from the address alone. *Rejected:* `configure` pinning whatever vk hashes the
  nodes signed (invariant 0: nodes compromised before a deployment would pin a malicious
  circuit). *Consequence:* a namespace taken before the deployment can only be disabled (a
  denial of service), never given other circuits.
- **The form of `configure` is an app developer's choice.** The permissionless,
  signature-checked form is the library's default. An app may instead entrust its deployer
  to call `configure` with the data: wrong data voids the contract, users must validate the
  stored pins before relying on it, and the deployer's account stays in public state and
  must stay available. *Rejected:* pinning the owner key in the registry message (it changes
  the machine's registry message).
- **Until configured, nothing runs.** Every request, init, result, `apply` and `skip`
  function asserts `configured`. *Why:* before `configure` the pins are unset, so a round
  would run against vk hashes and network keys nobody checked. *Consequence:* a stray
  DISABLE before `configure` means a new salt; once configured, a later REGISTER changes
  nothing in the contract.
- **One contract manifest per namespace, registered whole.** REGISTER takes a namespace's
  whole contract manifest; DISABLE stops one package. On the sidecar path a new contract
  manifest replaces the stored one; a tip namespace's manifest is fixed unless the contract
  has upgradable circuits (below). *Why:* the address and the pins decide what the nodes
  run, so neither the owner key nor DISABLE-then-REGISTER can swap a manifest under a
  deployed contract. [ARCHITECTURE.md, "The contract
  manifest"](ARCHITECTURE.md#the-contract-manifest).
- **The machine reads a tip namespace's facts from its registered contract manifest.** The
  queue, stale period, slots, each package's request keys and the init round come from the
  contract manifest the owner signed, generated from the compiled contract; the operator's
  configuration only lists the addresses served. Before a round the scheduler and each
  chain verifier check that the instance's current contract class is the manifest's. *Why:*
  no slot is copied by hand into four configuration files, and a manifest never runs against
  a contract with other code. *Consequence:* a wrong declaration costs that namespace's
  liveness only, since the contract checks every result against its real storage.
- **Circuits may be upgradable, chosen per app at compile time; the default is fixed.** The
  `upgrades` axis (`fixed`, `circuits`, `contract`) is one trait (`CircuitsInForce`) with
  one brick per value. `CircuitUpgrades` keeps scheduled pins in aztec-nr's
  `DelayedPublicMutable`, replaced by an upgrade authority the constructor pins after a
  delay (one day by default; aztec-nr's floor is one hour); the never-written value means
  the constructor's pins. *Why:* the same primitive Aztec's own class upgrade uses, so a
  circuit upgrade is public and dated from the moment it is scheduled, and a transaction
  that read the old pins cannot be included after the switch, so no grace logic is needed;
  the pins stay data, so the authority's power is "which circuits", never "any code".
  *Rejected:* pins in the key-epoch pattern (no minimum delay, a hand-built schedule, one
  more public check per round) and circuits as constants of the contract class (every fix a
  new class, the authority able to change all code). *Consequence:* each round function
  reads the pins and enqueues a class guard, at a cost in gates and bytecode
  (`examples/amm-tip/README.md`, "Upgrades"); the authority is trusted like an upgradable
  contract's upgrader, and no node signature appears on the upgrade path (invariant 0). The
  credits and lending examples stay fixed, lending on bytecode grounds.
  [ARCHITECTURE.md, "Upgrades"](ARCHITECTURE.md#upgrades).
- **One path for every upgrade: the whole contract manifest at the next `seq`, then the
  authority's call.** The nodes accept a new version when the contract's facts and every
  state key's layout are unchanged, no key is added and the intake family is the same, and
  hold it beside the version in force; every reader runs a round only under the version the
  pins name at its block. *Why:* the vk hash is inside the contract manifest, so any circuit
  fix changes its hash anyway; one path means one set of rules; the owner key alone can
  upload a version, never make one run. *Consequence:* no migration rounds; a change of a
  key's layout is a new deployment; a request queued under a replaced circuit is never
  answered, so an upgradable contract manifest must have a stale period.
- **A class upgrade is one authority call that schedules the class and the pins together,
  and fails closed when they are out of step.** `upgrade_contract` schedules the protocol's
  class change and the new pins in one transaction, refusing unless both take effect at one
  timestamp; every round function's class guard refuses pins of another class than the one
  running. *Why:* two separate calls, or a delay change between them, could otherwise run
  old code with new pins or new code with old pins; with the guard such a window costs
  liveness and nothing else, and each version's manifest is a statement about one named
  piece of public code that anyone can check (`pss-manifest verify`). *Consequence:* the
  authority can replace all of the contract's code after the delay, so the delay is the
  users' only protection.
- **The scheduler sends the init round** once the contract is configured and the slot is
  empty; the relayer lands it, open to anyone. *Why:* the init round needs no user, and the
  scheduler already drives every round the chain verifiers check.

## 12. Fees

- **Every tip transaction pays through Wonderland's private fee-payment contract (wFJ)**,
  the `PrivateFPC` of `@alejoamiras/private-fee-juice`, a dependency never vendored. Each
  payer funds its private balance in a dedicated funding transaction, never inside a
  request; one gas setting per app and transaction kind, equal across round types. Users,
  the relayer and the e2e harness all pay this way; the fee method is an app developer's
  choice (a DEV DECISION in pss-client's `fee.ts`). *Why:* every tip transaction then shows
  the same fee payer, so the fee names nobody. *Consequence:* timing, gas, the number of
  balance notes spent and each L1 deposit with its claim stay public. [ARCHITECTURE.md, "Fee
  payment"](ARCHITECTURE.md#fee-payment).
- **An app can price queue access with a usage deposit.** In an app that takes one, each
  request pays a pinned amount of a pinned token before it enqueues (`pss_public_contract`
  `token`, the `UsageDeposit` pin). The request draws it privately (lending draws it from
  the user's credit note beside the escrow), so nothing public names the requester or the
  amount. Whether a served round keeps the deposit is the app developer's choice. The
  library defaults to refunding it. Lending keeps it
  and sweeps kept deposits to a treasury pin. A round whose shares did not open `C`
  refunds the deposit. When the stale period is enabled, the skip wrapper must call
  `token::refund_skipped` to return any escrow and the usage deposit in full.
  *Why:* a hidden requester has no identity to rate-limit. The deposit prices access
  to the queue. Invariant 0 requires a way to release the deposit without a round.
  *Rejected:* keeping the deposit on skip, which would pay a network for skipping heads
  it never served. *Consequence:* in an app that draws the deposit from a credit note,
  each request spends the note, inserts its change and commits the refund notes.
  These effects are the same across round types. [Tokens and escrow](ARCHITECTURE.md#tokens-and-escrow).
- **No declared-maximum request fee check.** No request function checks its transaction's
  declared maximum gas cost. *Why:* a declared maximum is not a payment: it binds money only
  through wFJ's no-refund `pay_fee`, which a private function cannot see is in use, so such a
  check is not anti-spam; the usage deposit is.

## 13. Examples

- **The set.** The sidecar path: the AMM on node-held state, Monty Hall on client-held
  state. The tip: a counter (the minimal app), the AMM, lending with liquidation, and a
  credits ledger on the oblivious keyed map, all node-held, every round under secret-shared
  receipt intake but the init rounds and the non-secret-shared test rounds (section 9).
  *Why:* together they cover both paths, the state modes and shapes and both completions of
  partial-note delivery, each in an app a reader knows. Each example's README lists its
  rounds.
- **Lending is a full, realistic market.** Real tokens (aztec-nr v6's reference token,
  vendored as `examples/token`); escrow at request time drawn from a private credit note;
  borrowers and lenders in one book with interest through a borrow index; a borrow limit
  below the liquidation threshold; liquidation with a repay budget and residual debt written
  off across lenders; payouts through the user's own `redeem`; ownership by note; kept usage
  deposits swept to a treasury; an escape hatch for a frozen market on every deployment.
  Everything a user does starts in the user's private function; the PSS holds only what must
  be shared (the book's aggregates, the leaves a liquidator or keeper must probe, the lender
  leaves as the authority over shares). *Why:* a lending market someone could use, not a
  demonstration. *Consequence:* what stays unrealistic is stated: the price oracle, a single
  asset pair, parameters fixed per deployment, one liquidation per round, and no public
  liabilities total, so in a frozen market whoever withdraws credit last may be short.
  [examples/lending-tip/README.md](../examples/lending-tip/README.md) is the design.
- **Lending's two tree accesses: two contracts over one library.** The market runs over the
  clear tree and the oblivious tree as two contract packages, `lending_tip` and
  `lending_tip_oblivious`, both thin over the library `lending_market`. Each names its tree
  access once, in its round table (`RoundTable::clear`, `RoundTable::oblivious`); nothing
  reads the access at run time. Request functions keep one name per round on both, and the
  oblivious rounds' mains and manifests are generated from the clear ones
  (`scripts/gen-access.py`). *Why:* the access is an axis value, chosen once, and a request
  function's ABI depends on it (a position clear in one and shared in the other).
  *Rejected:* one contract with a twin request function per round and a runtime bit choosing
  package names. aztec-nr cannot add or drop an `#[external]` function by a comptime value,
  so each contract writes out its own entry points, each one call into the library.
  *Consequence:* two contract classes and builds; each carries only its own entry points.
- **One total AMM swap.** `examples/amm-swap-total` (from total-noir, with a PROVENANCE row
  and a total-lint check) is the swap both the tip AMM and the sidecar-path total AMM depend
  on by path, never copy. *Why:* one swap circuit, tested once.

## 14. Toolchain

- **Round circuits compile with released Noir 1.0.0; Aztec contracts and the TXE with
  1.0.0-rc.3.** The co-snarks fork, bb, Rust and `@aztec-labs/*` versions are pinned in
  `toolchain.json`, the tool paths in `scripts/toolchain.sh`. *Why:* the co-snarks revision
  depends on the Noir 1.0.0 crates, so circuits it proves must come from the same compiler,
  while aztec-nr v6 contracts need rc.3.

## 15. Node replacement

Node replacement is built: a compromised or departing node, or a key directory lost
without a backup, is replaced under every running namespace.
[ARCHITECTURE.md, "Node replacement and key
epochs"](ARCHITECTURE.md#node-replacement-and-key-epochs) is the mechanism.

- **A signed node-key epoch.** An epoch is a numbered key set (the three nodes' `sig` and
  `enc` keys), not a time period. The constructor pins key set 0; the contract library's
  `rotate_keys` declares the next epoch when two of the three current `sig` keys sign it;
  signatures made before a rotation are accepted for a grace window of `stale_blocks`
  blocks. *Why:* one procedure for a stolen key, a departing operator and a lost key
  directory, in which the departed node need not exist; one stolen key can neither rotate
  nor land a result. *Rejected:* three signatures (a departed node would have a veto).
  *Consequence:* two colluding operators, who can already read every value, can rotate the
  third out and run rounds with no honest node present (the proof still bounds what lands),
  so integrity rests on two honest nodes of three, as confidentiality already does; a
  rotation is public and dated. An app may instead compose a fixed key set (`FixedKeys`,
  the `node_keys` axis), with no rotation code; a node replacement then means redeploying.
- **Share refresh before import.** Rep3 lets any two nodes reconstruct, so the two
  remaining nodes first refresh every sharing they hold with a fresh zero-sharing in one MPC
  session, without reconstructing anything, which makes the departed node's pairs useless;
  only then does the newcomer import its pairs from them. Per-node sealed data (client-held
  and chain-held thirds, receipt envelopes) is not refreshed and the departed node's is lost.
  *Why:* a hand-over alone would leave the departed node's pair valid forever. Nothing on
  chain changes, since commitments are over clear values and blindings.
- **Checked, and atomic against the queue.** The newcomer's pairs pass the handshake's
  neighbour check, the `npk_app_hash` check and an audit before the epoch is declared; the
  orchestrator pauses scheduling for the whole procedure. Queued requests only the departed
  node could open are skipped and resent; chain-held tip namespaces do not survive.
- **The key set's sources.** The orchestrator takes its key set from its configuration,
  never from a contract, and computes nothing for a namespace at another key set; a node
  keeps a declared rotation pending until its own chain view shows it landed. *Why:* a
  hostile rotation must not drive the machine.
- **Rejected alternatives.** Redeploying everything (a compromise costs a full redeploy and
  a manual state move). Two nodes plus the namespace owner's key (an availability dependence
  on a key the owner may lose). A deployer override key (brings back the trusted deployer
  that permissionless `configure` removed). A contest window in which the third key freezes
  a rotation (a compromised third stalls its own removal).
