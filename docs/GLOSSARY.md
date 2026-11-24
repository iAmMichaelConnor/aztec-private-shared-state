# Glossary

The repository's terms, each defined once. The docs, the design guide and code comments
use them exactly as written here, and each entry links the section that explains it in
full. The terms are grouped under six headings in the order a reader meets them, so an
entry uses only terms defined above it.

## The network

- **Rep3 share.** A value split into three random summands that add up to it, each node
  holding two of them (its pair): one node learns nothing of the value, any two together
  learn it.
- **Node.** One of the three operator-run MPC processes (`sidecar-node`), with its own
  store, its `sig` key (signatures) and its `enc` key (envelopes and sealed records).
  Together the three hold every shared value as Rep3 shares
  ([ARCHITECTURE.md](ARCHITECTURE.md#2-the-key-hierarchy), section 2).
- **Orchestrator.** The operator's front process (`sidecar-orchestrator`): clients and the
  relayer talk to it, it drives the three nodes, and at the tip its scheduler runs the
  queue's head.
- **co-SNARK.** A collaborative UltraHonk proof that the three nodes produce together under
  co-noir from a witness held in shares; it verifies like any other proof.
- **Relayer.** `pss-relayer`, the operator's service that lands tip results and sends
  `skip()` for a stale head. It can delay a result, never change one.
- **The machine.** The Rust workspace in `machine/`: the node and orchestrator binaries
  and the libraries they share, the round as a library (`sidecar-core`) among them
  ([ARCHITECTURE.md](ARCHITECTURE.md#1-module-boundaries), section 1).
- **Keeper.** Whoever requests an app's maintenance rounds, such as lending's liquidator,
  who scans windows of the book and liquidates what they report
  ([design guide, question 13](design-guide/README.md#13-keeper-rounds-and-discovery);
  pss-client `keeper.ts`).
- **Key set, key epoch.** A key set is the three nodes' `sig` and `enc` public keys, node 0
  first. A key epoch is a number and a key set: the one a tip contract checks every node
  signature under. Epoch 0 is the constructor's `sig` keys, and two of the three current
  nodes sign the next ([ARCHITECTURE.md](ARCHITECTURE.md#node-replacement-and-key-epochs),
  "Node replacement and key epochs"). A contract with a fixed key set checks every
  signature under epoch 0's keys for its whole life and has no next epoch. Which of the two
  a contract has is its `node_keys` axis (`rotating` or `fixed`).

## Round types and packages

- **Namespace.** One app deployment at the nodes: its packages, the state of its state keys
  and, at the tip, its one queue and one lock live under it. At the tip it is the app
  contract's address.
- **Round type.** One kind of state change an app defines (a borrow, a repay, a swap),
  written once as a Noir function in the app's library.
- **Manifest** (circuit manifest). The JSON file beside a compiled circuit that says where
  each circuit input comes from (the request, the nodes' state, a pinned read), the state
  keys it reads and writes, and the intake ([ARCHITECTURE.md](ARCHITECTURE.md#7-the-manifest),
  section 7; `docs/manifest.schema.json`). "Manifest" alone always means this one.
- **Contract manifest.** The JSON document of one namespace: the facts about its contract
  the machine reads (the node keys and upgrades axes, the class id, the package capacity,
  the queue, storage and state key slots, the init round) and every package with its
  circuit's vk hash and its circuit manifest. pss-client generates it from the contract
  artifact, the compiled circuits and a deployment descriptor; its hash is the **manifest
  hash**, which a tip contract's constructor pins beside its package list, so the address
  commits to the manifest. The scheduler and every node read a tip namespace's slots and
  request keys from it, and replace-node its `node_keys`; the operator's
  `[[tip.namespaces]]` only lists which namespaces are served
  ([ARCHITECTURE.md](ARCHITECTURE.md#the-contract-manifest);
  `docs/contract-manifest.schema.json`).
- **Package.** One compiled, registered form of a round type: an entry of a contract
  manifest's `packages` (its name, the compiled circuit that backs it, its circuit
  manifest), and at the nodes its verification key and vk hash, stored under (namespace,
  manifest hash, name) by REGISTER. The nodes run only registered packages, and the tip
  contract's constructor pins each listed package's name hash and vk hash (with the
  manifest hash), so the contract's address commits to its circuits. One round type may have several packages
  (lending's borrow as `borrow_shared` and `borrow_oblivious`), and one compiled circuit
  may back two (the AMM tip's secret-shared swap, once per secret-shared intake): a package
  with `alias_of` is another intake of the listed package it names, verified under that
  package's pin and not in the contract's list; the manifest hash covers its circuit
  manifest. A package is never a Nargo package (a
  Noir crate with a `Nargo.toml`) or an npm package; the docs always write "Nargo package"
  and "npm package" for those.
- **REGISTER, DISABLE.** The two signed registry bodies the nodes commit: REGISTER (its body
  the manifest message) registers a namespace's whole contract manifest in one commit per
  node, the same one again re-enables its packages, on the sidecar path another one
  replaces it, and under upgradable circuits another one is kept as a new version beside
  the one in force; DISABLE stops one package from running
  ([ARCHITECTURE.md](ARCHITECTURE.md#4-the-registry-lifecycle), section 4).
- **Manifest message** (contract manifest registration message). The REGISTER body: the
  namespace, its contract manifest, each compiled circuit the manifest names once
  (stripped to the members the nodes read), the owner key, `seq` and the owner's
  signature. Each node answers it with one signature over the manifest result message (the
  namespace, the manifest hash, the packages hash, `npk_app_hash`, `seq`), and a tip
  contract's `configure` checks the three.
- **Circuit pins.** What a tip contract verifies results under: the contract manifest's
  hash, the package list (each listed package's name hash) and each listed package's vk
  hash (`pss_public_contract` `CircuitPins`). The constructor pins them; under upgradable
  circuits an upgrade may replace them.
- **Round table.** A tip app contract's one row per package (`TipRound`, by the package's
  name hash): its vk pin and the state keys it reads and writes. Every library entry point
  (a request, a result, the init round) takes the row of its round
  (`pss_public_contract` `app`).
- **Circuit upgrade.** The replacement of a tip contract's circuit pins, under the contract
  manifest's `upgrades` `circuits` or `contract`: the namespace owner registers the new
  contract manifest at the next `seq`, then the upgrade authority schedules its pins on
  chain, and they take effect after the upgrade delay. The contract's code does not change
  ([ARCHITECTURE.md](ARCHITECTURE.md#upgrades), "Upgrades").
- **Class upgrade.** The move of a tip contract instance to another contract class with the
  circuit pins of the contract manifest built for that class, under `upgrades: contract`:
  the upgrade authority's one `upgrade_contract` call schedules the protocol's class change
  (`ContractInstanceRegistry.update`) and the pins, both after the same delay. The address,
  the namespace, the storage and the node-held state stay.
- **Class guard.** The check every round function of an upgradable contract enqueues
  (`assert_upgrade_class`): the circuit pins in force belong to the contract class that is
  running, else the round is refused. It keeps old code from running with new pins and new
  code with old pins while a class change and a pins change are out of step.
- **Upgrade authority.** The on-chain address a contract under upgradable circuits pins in
  its constructor, the only one whose `upgrade_circuits` (and, under `contract`,
  `upgrade_contract`) call can schedule new circuit pins or another class. It is trusted
  like an upgradable contract's upgrader: under `circuits` it can change the rules of the
  shared state after the delay, under `contract` all of the contract's code. It is not the
  namespace owner key, which only uploads versions.
- **Upgrade delay.** How long scheduled circuit pins wait before they take effect: one day
  in the examples (`DEFAULT_UPGRADE_DELAY`), at least one hour (aztec-nr's floor). Users
  see the change for the whole delay.
- **Version** (contract manifest version). One registered contract manifest of a
  namespace, named by its manifest hash. A namespace under upgradable circuits **holds** up
  to three versions at the nodes; the **version in force** is the one whose hash the
  contract's circuit pins name at a given block (the constructor's while no upgrade was ever
  scheduled), and every round runs under it.
- **TXE.** Aztec's test execution environment, in which the contracts' Nargo test packages
  run (`scripts/txe.sh`, `txe.json`; [TESTING.md](TESTING.md)).
- **Total circuit.** A round circuit that no input can make unsatisfiable: a request the
  state does not allow still proves and lands as an `ok = 0` no-op with a code. Every
  queued round is total (total-noir; `scripts/check-noir.sh` gates it).
- **`nsk_app`, `npk_app_hash`.** `nsk_app` is a namespace's nullifier secret, which the
  nodes derive as Rep3 shares at its first REGISTER and which nullifies every note its
  rounds consume. `npk_app_hash` is the hash of its public key `nsk_app · G`: a round that
  consumes a note outputs it, and the app contract pins it, which binds every nullifying
  round to this network (`pss_core` `aztec_note::npk_app_hash`).

## Requests and rounds

- **Path.** Where a result lands. **The sidecar path** ("note mode" in the machine's code): a user's
  private function sends a request straight to the network and lands the result itself; manifest
  intake `direct`; [ARCHITECTURE.md](ARCHITECTURE.md#3-the-request-lifecycle) sections 3
  to 5. **The tip**: requests queue in a public contract and the network runs the head;
  any intake other than `direct`; [ARCHITECTURE.md](ARCHITECTURE.md#6-the-tip-as-an-extension)
  section 6.
- **Request.** What a user sends to have a round run: on the sidecar path the body its
  client sends to the orchestrator (`POST /v1/execute`); at the tip the request
  transaction, whose private function appends the request to the queue, after the intake's
  off-chain step if it has one.
- **Intake.** How a request's inputs reach the network, the manifest's `intake`:
  - **On-chain intake** (`onchain`): the inputs travel in a public request log.
  - **Receipt intake** (`receipt`): the inputs go to the nodes in the clear over TLS; each
    node signs a receipt, and only the request id and the expiry block reach the chain.
  - **Secret-shared receipt intake** (`shared_receipt`): as receipt intake, but each node
    receives one Rep3 pair of each sensitive input in an envelope; the default of the tip
    examples.
  - **Secret-shared on-chain intake** (`shared_onchain`): the user's private function
    shares the inputs itself into a private log only the nodes can open.
  - **Relayed intake** (deferred): the network submits the request transaction.
  - **The two intake families.** The **non-secret-shared intakes**, on-chain intake and
    receipt intake, give the nodes every input in the clear. The **secret-shared
    intakes**, secret-shared receipt intake and secret-shared on-chain intake, hand each
    node only Rep3 shares.
  - **Names in code.** In identifiers and manifests, `shared_receipt`, `shared_onchain` and
    `shared` (`SHARED_PACKAGES`, the `*_shared` circuits) mean secret-shared, and `plain`
    (`intake::plain`, `PLAIN_PACKAGES`), `onchain` and `receipt` mean non-secret-shared.
  - `direct`: the sidecar path's intake; the client sends the request to the orchestrator
    itself.
- **Queue, head.** The queue is the FIFO of chain request ids in a tip app's contract
  (pss_public_contract `Queue`); the head is its oldest unresolved entry, which the
  scheduler runs next.
- **Request id.** At the tip, two. The **chain request id** is the id a request is queued
  under, a hash of the namespace, the package's vk hash and either the request's inputs
  with a nonce (the non-secret-shared intakes) or their commitment `C`, whose blinding
  makes it unique (the secret-shared intakes); no address is in it. The **machine request id** names one
  attempt at the nodes: a hash of the chain request id, the old commitments and the pinned
  values ([ARCHITECTURE.md](ARCHITECTURE.md#hashes-and-associated-data), "Hashes and
  associated data").
- **Clear app input.** An app input a secret-shared round takes in the clear, beside the
  shared ones (lending's position indices, a scan's start): the nodes and the orchestrator see
  it, and under secret-shared on-chain intake the world does too.
- **Envelope.** What one node receives of a secret-shared request: its Rep3 pair of each
  sensitive input (an `INPUT_SHARED` value), encrypted to that node's `enc` key and bound
  to the namespace, the request, the circuit, the input's name and the node
  ([ARCHITECTURE.md](ARCHITECTURE.md#hashes-and-associated-data), "Hashes and associated
  data").
- **Receipt.** A node's Schnorr signature over a request id, the request's inputs hash (or
  `C`, and under secret-shared receipt intake the sharing digest below) and an expiry block,
  under receipt intake and secret-shared receipt intake. A request function checks the
  three receipts before it appends the request id to the queue.
- **Sharing, summand commitment, sharing digest.** Under secret-shared receipt intake the
  client splits `C`'s shared values and the blinding into three Rep3 summand vectors
  `s_0 + s_1 + s_2` (node i holds `s_i` and `s_{i-1}`) with a fresh salt each: the
  **sharing**, which the user's request function takes as its private argument
  `sharing: Sharing<L>` (`summands`, `salts`). A **summand commitment** `S_j` hashes one
  vector and its salt; the **sharing digest** `D` hashes the three, the kind of each of
  `C`'s values (clear or shared) and the clear values. Each node checks `D` against its
  layout and the clear inputs it stores, checks its two vectors against their commitments
  and signs `D`; the request function proves that the summands add up to `C`'s values,
  computes `D` over `C`'s own clear values and checks the receipts over it, so a request
  whose shares or clear inputs do not open `C` is never queued
  ([ARCHITECTURE.md](ARCHITECTURE.md#hashes-and-associated-data), "Hashes and associated
  data").
- **Round.** One execution: the nodes run one package on one request (or, once per
  deployment, the init round on none), produce one co-SNARK and the new state
  commitments, and the app contract verifies and applies it.
- **Attempt.** One try at a round at the tip. When a slot or a pinned value moves under a
  computed result before it lands, the scheduler computes the round again: a new attempt,
  with a new machine request id.
- **Pinned read.** A public call the manifest fixes (an oracle's price, the market's
  clock) whose value a round takes as public inputs; `apply` makes the call again and
  admits the round's value under the read's freshness policy (`exact`, `epoch` or
  `tolerance`) ([ARCHITECTURE.md](ARCHITECTURE.md#pinned-reads), "Pinned reads").
- **Chain reader.** The tip's reader of one Aztec node at one proposed block: a
  namespace's queue, commitment slots, request logs and the tip, with a replaced block
  reported as a prune event (`sidecar-tip` `chain`).
- **Four tips, settled block.** An Aztec node's chain tips: proposed (the latest block it
  has), checkpointed (its checkpoint is on L1), proven (that checkpoint's proof is on L1)
  and finalized (that proof's L1 transaction is final). The settled block is the finalized
  tip as a chain reader read it, once it has seen it move: no replacement reaches it, so
  everything a node deletes by its chain view waits for it
  ([DESIGN.md](DESIGN.md#replaced-blocks), "Replaced blocks").
- **Scheduler.** The orchestrator's loop at the tip: it reads the queue through its chain
  reader, synthesises the head's request, drives the three nodes, and computes a new
  attempt when a slot or a pinned value moves; it also sends the init round
  ([ARCHITECTURE.md](ARCHITECTURE.md#6-the-tip-as-an-extension), section 6).
- **Chain verifier.** A node's check before every queued round: it re-reads the chain
  through the node's own Aztec node, rebuilds the request the scheduler should have sent,
  and refuses one that differs (`sidecar-tip` `verifier`).
- **Init round.** The one round of a tip deployment that is not queued: once the contract
  is configured and its slots are empty, the scheduler runs it under a fixed request id to
  create the initial state.
- **Result.** What a round leaves for the chain: the proof, its public inputs and, at the
  tip, the three nodes' signatures. A result transaction lands it: its private function
  verifies it and its public `apply` applies it.
- **FETCH.** Reading a committed round's result back from the nodes through the
  orchestrator: by machine request id (`POST /v1/fetch`) or, at the tip, the latest attempt
  of a chain request id (`POST /v1/fetch/chain`). Anyone holding the id may ask.
- **Lander, submitter.** The submitter is whoever sends a result transaction: the relayer,
  or the user. The Lander is pss-client's one way to do it: FETCH, prepare the call, send,
  under a retry policy.
- **Outcome.** What a round reports to its requester: a code (0 when the round applied) and
  the app's outcome fields; public outputs under a non-secret-shared intake, a private
  outcome encrypted to the requester under a secret-shared one.
- **Private outcome.** An outcome encrypted to the requester's per-request outcome key
  and logged under its outcome tag, which only the requester can open; the
  secret-shared intakes' form of outcome.
- **MPC receipt check.** A secret-shared-intake round's first check: whether `C` opens to
  the shares the nodes hold (`SharedIntake::opens`), a flag folded into the outcome with the
  app's mismatch code (the AMM's 9, lending's 14), so the round stays total. The request
  function already proved the user's sharing, so only nodes that changed their shares make
  it fail.
- **Outcome nonce, mismatch nonce.** The AEAD nonce of a sealed plaintext is the hash
  of the completed note that packs it, under a domain: the **outcome nonce**
  `poseidon2([note_hash, SIDECAR_OUTCOME_AD])` for an outcome whose shares open `C` and
  for every delivery, the **mismatch nonce** `poseidon2([note_hash, SIDECAR_MISMATCH_AD])`
  for a round whose shares do not open `C`, which seals its mismatch code alone. The note
  hash commits to the plaintext, so one nonce never seals two plaintexts; the outcome log
  carries the note hash so the reader can derive the nonce.
- **Skip, stale.** A head that has waited `stale_blocks` blocks (the contract manifest's, 50 in the examples) is stale;
  anyone may then call `skip()`, which moves the head past it and refunds what the request
  put in. The rule is the **stale rule**, and `stale_blocks` the **stale period**.
- **Grace window.** The blocks after a key-set rotation during which a tip contract still
  accepts signatures under the previous key set (`G`, stored with the key epoch: the
  contract's `stale_blocks`), so requests in flight at a rotation still land. A node keeps a
  retired `enc` scalar the same way until no queued request can name it
  ([DESIGN.md](DESIGN.md#rotating-a-nodes-enc-key), "Rotating a node's `enc` key").

## State

- **State key.** The app's name for one piece of shared state; it maps to a contract storage
  slot and a record at the nodes (at the tip the key is the storage slot itself). A request
  names the state keys it reads and writes, in order (`state_keys.reads`,
  `state_keys.writes`); its manifest says how many (`state_keys`) and refers to them by
  position as `$state_keys.reads[i]` and `$state_keys.writes[j]`. Never a cryptographic key.
- **State mode** (manifest `state`): where a key's state lives between rounds.
  **Client-held, node-held and chain-held state** (`client`, `node`, `chain`): the user
  carries a record; the nodes hold the state; every apply logs the whole state sealed to
  the nodes ([ARCHITECTURE.md](ARCHITECTURE.md#state-modes-at-the-tip), "State modes at the
  tip").
- **State shape** (manifest `tree`): a key's state as one flat vector, or as a Merkle tree
  of leaves (the clear-index tree, the oblivious tree, the oblivious keyed map) of which a
  round touches a few ([ARCHITECTURE.md](ARCHITECTURE.md#tree-valued-keys), "Tree-valued
  keys").
- **DORAM.** A distributed oblivious RAM: memory the three nodes hold in shares and read
  and write at secret-shared addresses, so no node learns which address a round touches.
  The oblivious tree and the oblivious keyed map keep their leaves and hashes in one
  (GigaDORAM, vendored in `machine/sidecar-oblivious/vendor`).

## Value and ownership

- **Partial note, partial-note completion.** A partial note is an Aztec note whose owner and
  randomness are committed first, `P = partial_commitment(owner, rho)`, and whose value is
  filled in later. Partial-note completion is the one form of value delivery: a request
  commits its sender's partial note, and the round completes it with the outcome, in the
  co-SNARK or in `apply` ([ARCHITECTURE.md](ARCHITECTURE.md#partial-note-delivery), "Partial-note
  delivery").
- **Delivery handle.** A standing partial note and key that a recipient's own request
  writes into its entry, so that a round another party requests can complete a note for the
  recipient (lending's liquidation notice); it authorises nothing, and any number of rounds
  may complete it until the recipient's next request writes a new one, each completion
  another note under a log tag of its own, `poseidon2([key, PSS_HANDLE_TAG, request_id])`
  ([design guide, question 7](design-guide/README.md#7-value-delivery-how-does-value-reach-the-user)).
- **Escape hatch.** The exit from a frozen app with no node, a library brick
  (pss_public_contract `hatch`, pss_core `tip::exit`, pss-client `hatch.ts`): once the app
  has starved for its liveness period, anyone opens the hatch, after which no request is
  queued and no round lands, and each owner of an entry exits once, privately, on its
  newest note by pushing that note's exit tag. Lending uses it on every deployment
  ([ARCHITECTURE.md](ARCHITECTURE.md#the-escape-hatch), "The escape hatch";
  [design guide, question 14](design-guide/README.md#14-node-replacement-recovery-and-liveness)).
- **Exit tag.** The nullifier an entry's newest note exits with,
  `exit_tag(P, request_id, entry)` over the note's partial commitment, its round's chain
  request id and the entry's index. The round that writes an entry stores the tag of the
  note it issues for it in the leaf; the landing of the next round that writes the leaf
  emits the old tag as a nullifier, so exactly one tag per entry is unspent, the newest
  note's. A round that spends no tag in a slot outputs an **exit filler** there instead, a
  hash that cannot equal a tag and that nobody without the requester's partial commitment
  can tell from one, so every landing emits the same number of values
  ([ARCHITECTURE.md](ARCHITECTURE.md#the-escape-hatch), "The escape hatch").
- **Credit note.** A user's private balance in an app, as a note of the app's
  (lending's `app::Credit`, both assets in one note): funded with tokens in a transaction
  of its own, drawn on by requests, withdrawn as tokens.
- **Escrow.** The amount a request puts in at request time (a deposit, a repayment, a
  liquidator's budget), if the app takes it. The private request function draws it from
  the sender's credit note. The app's apply wrapper can refund escrow when the round
  leaves it unused or when the shares do not open `C`. The skip wrapper refunds escrow
  when the stale period is enabled and it calls `token::refund_skipped`.
- **Usage deposit.** An app-chosen amount and token, pinned at deployment, that prices
  requests from a hidden requester. The app chooses whether to keep it when a round
  serves the request. `token::settle_applied` refunds it when the shares do not open `C`.
  The skip wrapper refunds it when the stale period is enabled and it calls
  `token::refund_skipped`
  ([ARCHITECTURE.md](ARCHITECTURE.md#tokens-and-escrow), "Tokens and escrow").
- **wFJ.** The private fee-payment contract (`@alejoamiras/private-fee-juice`) every tip
  transaction pays its fee through by default, so the fee payer names nobody.
- **Invariant 0.** The rule over every other invariant: a leak of all three nodes'
  secrets can cost privacy and freeze funds, never take or lose them
  ([ARCHITECTURE.md](ARCHITECTURE.md#5-invariants), section 5).
- **Minimal PSS.** Everything that need not be shared stays user-owned private state
  (notes); only the essential shared state is private shared state
  ([DECISIONS.md](DECISIONS.md)).

## The design space

- **Axis.** One choice an app makes, such as its intake or its state shape
  (`design-guide/design-space.json` `axes`).
- **Option.** One value of an axis (`shared_receipt` of the intake axis).
- **Brick.** One library module with one job; each option is a set of bricks, and
  [BRICKS.md](design-guide/BRICKS.md) lists them with what an app calls.
- **Seam.** The interface between an axis and its bricks: the place where one option's
  bricks plug in and another's could instead.
- **Status.** How far an option or brick is built: built, kept option (built, not the
  default), experimental (offered for trial, never a default), deferred (REGISTER refuses
  it), to build, not offered, external (a third party's code)
  (`design-guide/design-space.json` `statuses`).
- **Blueprint.** One robust combination of options, with its bricks, its example and the
  files to start from ([design guide](design-guide/README.md#blueprints), "Blueprints").
- **Deviation.** A value a blueprint allows in place of one of its own, with the bricks it
  adds and drops (`check-design-space.py --plan <blueprint>` lists them).
- **BRICK marker.** A `// BRICK` comment in an example's code at a seam where another
  option could have been chosen, naming the option, the library item and the alternatives
  ([design guide](design-guide/README.md#brick-markers), "BRICK markers").
- **DEV DECISION marker.** A `DEV DECISION` comment at a choice an app developer makes
  within a brick: what it is, its default, why, and the alternative
  ([design guide](design-guide/README.md#dev-decision-markers), "DEV DECISION markers").
