# Design: trust, operation and limits

What the system trusts, what each party sees, how to set it up and run it, what an
operator does when something goes wrong, every setting a deployment chooses, and what the
system does not do, on the sidecar path and at the tip. The mechanisms are in
[ARCHITECTURE.md](ARCHITECTURE.md), cited by section (the tip is section 6, errors and
recovery section 8; its opening says which source wins where docs differ); the reasons are
in [DECISIONS.md](DECISIONS.md); the gates are in [TESTING.md](TESTING.md). The repository
map is the README's "Layout" table, and ARCHITECTURE.md section 1 is the module spec.

## The trust boundary

Three nodes, run by one operator in the research prototype (DECISIONS.md, "Operator-run
trust"), hold every secret as Rep3 replicated shares: each node holds two of the three
additive shares of a value, so one node alone learns nothing about it and any two nodes
together can reconstruct it. The model is semi-honest: privacy holds while the nodes follow
the protocol and no two of them collude. Nothing claims security against a node that
deviates; what one can do is bounded by the checks the machine runs anyway (the three
nodes' answers must agree, every node and the orchestrator verify the proof, neighbours
compare hashes of every shared input before computing; ARCHITECTURE.md section 3, steps 10
and 11). At the tip a secret-shared request's sharing is checked before it is queued: each
node checks alone that its two summand vectors match the client's commitments and signs the
digest of the three, and the user's request function proves that the summands add up to the
values `C` commits to and checks the three receipts over that digest, so a request whose
shares do not open `C` never reaches the queue (ARCHITECTURE.md section 6, "Secret-shared
receipt intake, end to end"). A contract accepts a round only with a
proof that verifies under the vk hash it pins and, for a round that nullifies, an
`npk_app_hash` equal to its pin, so the chain never trusts the operator for what a round
computed.

Who sees what on the sidecar path:

| Party | Sees | Never sees |
| --- | --- | --- |
| node i | its share pair of every node-held value, of every client-held record it opens (its own third, sealed to it), of every INPUT_SHARED input (envelope i) and of each namespace's `nsk_app`; its master share; every request's public map, keys and ciphertext hashes; what a round opens: the proof and its public inputs and outputs | another node's shares; any secret in the clear |
| the orchestrator | the full request: all three envelopes and record thirds as ciphertext, their hashes, the public map; the proofs, public inputs and node signatures; its registry copy; the pinned node public keys | any share or secret: it holds no key that opens a ciphertext |
| the client | its own inputs in the clear; its records as ciphertext (it carries them but cannot open them); the proofs, public inputs and signatures of its rounds | the nodes' shares, including those of its own state |

The orchestrator holds no protocol secret and is never the sole holder of anything
(ARCHITECTURE.md section 5, invariant 12): every row it answers from is also held by the
three nodes, its registry copy is rebuilt from them, and FETCH reads the nodes. Its only
private material is transport: the keys of its public server certificate and of the node
leg's client certificate. The second is an operator credential: whoever holds it can send
requests to the nodes directly, and the nodes then run every check of the lifecycle
themselves. The orchestrator together with one node learns no more than that node.

## At the tip

At the tip the state is node-held by default: the three nodes hold every key as Rep3 pairs,
one version per commitment, and the chain holds one commitment per key (a tree root for a
tree-valued key) in the app contract's public storage. Requests queue in the contract, the
nodes compute the head, and a relayer (or anyone) lands the result (ARCHITECTURE.md
section 6). The contract trusts the network for nothing a proof covers: a result lands only
with a proof under a pinned vk hash, three signatures under the pinned `sig` keys, and old
commitments equal to the slots.

### Who sees what

What each party sees depends on the intake (the intakes are defined in
[GLOSSARY.md](GLOSSARY.md); ARCHITECTURE.md section 6, "Secret-shared intake", says how the
inputs reach the nodes under each). With node-held state:

| Party | Under the non-secret-shared intakes (on-chain, receipt): the examples' non-secret-shared deployments | Under secret-shared receipt intake: the examples' default |
| --- | --- | --- |
| the world (the chain) | the request id, the queue's activity, the new commitments, the pinned reads, the round's public outputs; under on-chain intake also every input, in the request log; so the state, whenever the initial state and the inputs determine it (lending), and otherwise to whoever can solve it from public inputs and outputs (the AMM's reserves, by probing) | the request id and expiry block, the queue's activity (`done[index]`), the new commitments (for a tree, nothing of the leaves), the pinned reads, and per result one note hash and one 16-field private log, the outcome encrypted to the user (one more of each per delivery of an app with the delivery handle); under public completion also `P`'s tag and the completion log, with the amount, the owner hidden; on lending also each landing's exit-tag nullifiers ("Exit tags", below) |
| node i | every input in the clear, so it can follow any state that public data determines (lending's book, element by element); its pairs of every value | the clear app inputs (lending's position indices, a liquidation's probes, a scan's `start`), `C`, the circuit and so the round type, which leaves a round touches, the commitments and leaf hashes, its own pair of every shared value, the result's public inputs; so it can link requests that touch one position, but never sees a shared input, a leaf value, an amount, `P`, an owner, the requester or an outcome |
| all three nodes, every secret included | as one node | every shared value in the clear: amounts, the outcome key and tag, `P`, the book's leaves, every outcome; the network addresses they are given; never the owner behind `P` (hidden by `rho`) or a position's owner |
| the orchestrator | under receipt intake every input; the user's network address on the receipt route | the clear app inputs, the three envelopes as ciphertext, `C`, the summand commitments and their digest (hashes of random summands and salts, which tell it nothing), the request id, the outcome tag, the user's network address, and the circuit, so the round type; together they link a network address to a lending position's index and to each operation on it |
| the relayer | the results it lands, their public inputs included, and the queue | the results it lands and so the circuit: ciphertext, note hashes, commitments and pinned values, never an amount, an owner or `P` |
| the user | its own inputs, the public outputs | its own inputs, notes and outcomes |

A participant still learns what its own outcomes determine: the AMM example is a minimal
constant-product pool, not a private AMM design, and a trader infers both reserves from two
of its swaps.

**Funds.** No party in the table, and not all three nodes with every secret, can take or
lose a user's value (invariant 0, ARCHITECTURE.md section 5); one node, the orchestrator or
the relayer can refuse or withhold, which costs liveness only ("Liveness"). No shared value
authorises a move: a request on a lending position needs its owner's note in the owner's
private function, a result lands only with a proof over `C` of a request the owner's private
function made, a completed note is nullifiable by its owner's keys alone, and the
constructor pins every circuit's vk hash, so neither a round nor `configure` can name
another circuit. Escrow and the usage deposit are drawn from the user's private balance in
the app when configured. The amounts stay private. The refund notes are user-owned partial
notes. A deployment with the stale period enabled can complete them without a round
by calling `token::refund_skipped` from its skip wrapper.

Secret-shared on-chain intake shows the nodes what secret-shared receipt intake does, with
two differences. The user never meets the orchestrator: its private function reads the
nodes' `enc` keys from the app contract and puts the encoded shares, the clear app inputs
and `C` in one private log beside the queue entry, so the orchestrator sees no network
address. And that log is on chain for good: the clear app inputs in it are public (a lending
position's index links the requests on it), and anyone who later holds two nodes' `enc`
scalars of the epoch it names, or breaks the Grumpkin key exchange, opens its shared inputs.
That is why the examples default to secret-shared receipt intake.

No account address enters a request id, a request log, a receipt, a node's row, a
synthesised request or a proof's public inputs. The default `wfj` fee method names the
private fee-payment contract as fee payer. The `account` method names the sender as fee
payer, which links its requests. On the receipt routes the orchestrator sees the user's
network address beside the inputs or
`C`, hence the chain request id, so it can link the address to the request on chain, to the
result's public outcome tag and to the timing of a later redeem. A user who must hide it
reaches the orchestrator through a relay or a mixnet, which this repository does not
provide. The owner of a completed note never reaches the nodes, the orchestrator or the
relayer: the request carries only the partial note `P`, which hides the owner behind the
user's randomness (ARCHITECTURE.md section 6, "[Partial-note delivery](ARCHITECTURE.md#partial-note-delivery)").

The user's own Aztec node (the RPC node its wallet and pss-client talk to) is not hidden
from either. pss-client finds each outcome by asking that node for the logs under the
request's outcome tag (`OutcomeReader`, `DeliveryReader`), a recovery asks for the tags of
`n = 0, 1, …` in one session (`SecretStore.recover`), and an owner on an app with exit tags
asks for its notes' exit tags in the nullifier tree and for the blocks that spent them
(pss-client `hatch.ts`), so that node can link a user's requests to one another and to their
outcome logs and landings; a user who must hide this runs its own Aztec node. A client given
a `keyEpochNode` also takes the node key set after a rotation from that node's storage
reads, with no proof: a lying node can make it seal its shared inputs to keys the network
does not hold, which gives them away.

What stays public under every intake: when each transaction lands; that a request joined
and that one resolved (`done[index]`: applied or skipped); the new commitments; the pinned
public reads; the gas settings and the fee charged; the number of wFJ balance notes spent;
and each L1 deposit that funds a payer, with its L2 claim. The gas settings tell nothing of
a round: each app declares one fixed gas setting per transaction kind (deploy, configure,
request, result, redeem, skip; the examples' `AMM_TIP_FEE_SETTING` and
`LENDING_TIP_FEE_SETTING` in `e2e/harness/fee-settings.ts`), and the gas each kind uses in
the real-proof e2e is the same across round types (`e2e/scenarios/README.md`, "Gas per
transaction kind"). Under the non-secret-shared intakes the round type shows through the
clear inputs; under a secret-shared intake it is hidden (one wrapper, one `apply`, the same
pinned reads, effect counts and padded log lengths on every round, lending's exit-tag
nullifiers included), as every tip example does and the AMM tip's and lending's TXE suites
check. Timing stays visible either way: proving time differs by circuit (a liquidation
touches `K` leaves, an owner round two), and only some outcomes are followed by a redeem
transaction (lending's borrows and liquidations); a fixed relayer cadence and a redeem after
every round would close both, and neither is built.

**Exit tags.** A tag is known to whoever knows its note's `P`: the owner (from its address
and the note's `rho`), any two nodes (which reconstruct `P`), and a liquidator for the tag
its liquidation stores on a probed leaf that holds no delivery handle (made from its own
request's delivery seed: it recognises the landing that next writes that position, but no
note opens to the seed, so it can neither spend nor exit on it). Nobody else computes one:
one node holds two summands, and on the private-outcome path `P` appears only inside the use
nullifier and the note hash. Knowing a tag lets one see it spent (which landing replaced the
leaf, or that its owner exited), never spend it: only the contract's code emits a tag
nullifier, for a pinned circuit's output at the head or for a note the sender owns. The
world sees, per landing, the same number of tag nullifiers on every round type, each a tag
or a filler it cannot tell apart, and no index; per exit, a private transaction with one
nullifier beside the app's payment. Someone watching the pool who sees two landings of one
request (one reverted or evicted) sees whether the exit value changed between the attempts,
which happens only when a liquidation's probe changed health with the price.

**A read-only window.** A keeper's window round (ARCHITECTURE.md section 6, "A read-only
window on a tree key") tells the requester what the app's outcome reports about the window
(for a report, one bit per leaf, and the occupancy count gives the tree's size to within
`W`): a probe reveals the same bit per probed leaf, so a window changes the rate (`W` bits
per fee and queue turn instead of `K - 1`), not the kind. The world sees a request joined
and resolved, a new commitment and the timing; the nodes see `start` and the circuit, and,
by inference, that an act round naming leaves of a recent window probably acts on its
report. A public report would hand the list to the world.

**Outcomes before finality.** The nodes run a round as soon as their Aztec nodes show its
request at a proposed block and sign its result when the round ends, so the result is on
FETCH before it lands and before its request is final. A request that a replaced block
drops changes no state and charges no fee, so whoever can replace the block holding a
request (the proposer of its slot, by abandoning the block; an epoch prune; an L1 reorg)
lets its requester read the outcome of a round on the live state that never lands, for free
("Replaced blocks", below). The design assumes each node reads the chain through its own
Aztec node: three chain verifiers on three Aztec nodes must all show a request before a
round runs, while one Aztec node shared by the three (the local e2e's setup) alone decides
what they run.

### Liveness

Privacy and integrity do not depend on anyone acting; progress does. A queued request
resolves only if all three nodes, the orchestrator and a submitter act: Rep3 needs every
node in every round, so any one node, or the orchestrator, can stop the rounds. Nothing in a
contract can force a result. What bounds a stall is the stale rule:

- **The stale rule.** The head may be skipped from block `head_since + stale_blocks` on
  (inclusive), where `head_since` is the block at which the request became the head (an
  `apply` or a `skip()` moves the head and restarts the clock; a request appended to an
  empty queue starts it). `stale_blocks` is fixed per namespace by the registered contract
  manifest's `queue.stale_blocks` (the examples state 50 L2 blocks, the contract library's
  `DEFAULT_STALE_BLOCKS`; `null` disables skipping, which secret-shared receipt intake
  refuses) and taken by the constructor. The scheduler and the receipt pruning read it from
  the contract manifest, and the relayer from its pss-client configuration. At every queued
  round each node's chain verifier reads the contract's stored value at the manifest's
  `queue.stale_blocks_slot` and refuses the round while it differs, so a namespace whose
  contract and contract manifest disagree runs no queued round until one is redeployed. The
  scheduler computes nothing for a head older than the period, and the relayer skips a stale
  head rather than landing a result for it.
- **`skip()` refunds the deposits, not the fee.** Anyone may call it once the head is stale;
  it writes `done[index] = 2` (skipped), moves the head and leaves the state and the slots
  alone. It completes the request's refund notes (its escrow in full and its usage deposit);
  the user loses the request and its transaction fee. `done[index]` (0 not finished, 1
  applied, 2 skipped) is the record a client reads. A request that failed in the round
  (`ok = 0` under public outputs) is applied, not skipped, and keeps the state.
- **Who lands.** The relayer by default; anyone holding a result can send `process_result`,
  since it carries no request input (pss-client's `Lander`); every result is FETCHable on the
  orchestrator's public listener, so no user depends on the relayer to land its own result.
- **What the relayer pays for.** It pays every result, the init round and every `skip()` (a
  skip about 1M L2 gas). A user cannot forge a result (three signatures under the contract's
  keys) and one failing result is sent at most `maxSameResultSends` times, so the lever is a
  request the network never serves (a receipt-intake request whose nodes refuse at bind, a
  shared on-chain log the nodes cannot open): each costs the relayer one `skip()` after
  `stale_blocks`, against the request fee its sender paid.
- **Moving pinned values.** A pinned read under `exact` freshness lands only if the value
  does not move between the scheduler's read and `apply`; a source that moves faster than a
  round lands (minutes with real proofs) keeps the head waiting until it is skipped. Under
  `epoch`, a round lands if at most one new epoch opens before `apply` and the source still
  offers the previous value (an epoch source offers it only within a window after each new
  epoch: the lending oracle's `previous_blocks`); it is recomputed at most once per epoch
  length `L` and lands a value at most `2L` blocks old. Under `tolerance`, it lands while the
  value stays within the band (ARCHITECTURE.md section 6, "Pinned reads"). Lending's oracle
  read uses `epoch`.

### Replaced blocks

An Aztec chain replaces blocks at three levels. Each node and the scheduler follow the chain
through the chain reader, which reads the Aztec node's four tips (proposed, checkpointed,
proven, finalized) and detects a replaced block by its hash (ARCHITECTURE.md section 6,
"Following the chain"). Every party follows the proposed chain, a block
every 6 s: the scheduler, the nodes' chain verifiers, pss-relayer and pss-client read at the
proposed tip, the nodes sign a round's result when it ends, every transaction the libraries
send returns once it is in a proposed block, and the user's PXE syncs to the proposed tip.
None waits for a checkpoint or a proof. What PSS does at each level, what it costs and who
can cause it:

| Level | Who can cause it | How deep (mainnet and testnet presets) | What PSS does | What it costs |
| --- | --- | --- | --- | --- |
| Proposed blocks not yet in a checkpoint on L1 | one proposer, by fault or by choice (a missed or abandoned slot) | up to one slot, 10 blocks | The scheduler drops what it built on the replaced blocks and recomputes the head on the replacement chain; an unchanged request has the same request id, which the nodes answer from their rows. Each chain verifier reads again. A round already running on the replaced block runs to its end, and its result is signed and served ("A round on an abandoned block", below). A request or result transaction in such a block can leave the chain after its send returned: the relayer lands a result again when it reads the head still queued, the node's pool mines a request again while it is valid, and an app that must know uses pss-client's opt-in watchers. | a recompute; a requester whose request was in an abandoned block can read its round's outcome for free (below) |
| Checkpoints on L1 without a proof by the deadline (an epoch prune) | every prover missing the window | up to two epochs, about 77 min and 640 blocks | As above, and the results that landed in the pruned blocks land again (the relayer reads the queue each tick). A request transaction the node's pool drops is not sent again unless the app does it (pss-client's opt-in `watchRequest`); a client waiting with `pollResult` follows its request to its new index. A user's PXE drops an outcome note delivered from a pruned block; pss-client's opt-in `watchOutcome` delivers it again once it lands again. Node-held versions are kept back to the finalized tip, so the state at every commitment the slot can return to is still held. | the outcomes of signed rounds whose requests were pruned are known to their requesters for free; rounds recomputed after a pinned value moved can give outcomes other than those already seen |
| An L1 reorg | Ethereum validators | bounded by L1 finality | As for an epoch prune: checkpoints, proofs and L1-to-L2 messages above the reorg's depth are replaced. | as for an epoch prune |
| Below the finalized tip | nobody | none | Nothing below it is replaced. Every deletion a node makes by its chain view waits for the finalized tip: node-held versions orphaned below it, receipt inputs of requests done below it, retired `enc` scalars. | versions, receipts and scalars are kept until L1 finalizes the proof above them, and longer while finality stalls ("Configuration reference", block hashes kept) |

The finalized tip is the floor for everything a node deletes because it is the only tip no
replacement reaches: a proof can land seconds after the one before it, so a count of proofs
is no bound on how far an L1 reorg reaches. A fresh reader deletes nothing until it has seen
the finalized tip move. Every mark a node makes on a version carries its block's hash, and a
mark made on a chain a replacement undid no longer matches and is made again instead of
deleting (ARCHITECTURE.md section 6, "Node-held state"). A chain view that lies (a lying
Aztec node) can still make its own node delete early, which a resync of the key from the two
neighbours repairs ("Recovery").

**A round on an abandoned block.** A round starts once the three chain verifiers show its
request at the proposed tip, and its result is signed when the round ends, whatever happened
to that block meanwhile. A block replaced while its round runs leaves a signed result that
FETCH serves for a request no longer on the chain.

- *Who can cause it.* The proposer of the slot whose blocks hold the request, by abandoning
  them: it proposes the blocks and never publishes their checkpoint, or replaces them. Past
  the checkpoint, only an epoch prune or an L1 reorg can (the rows above).
- *What it costs them.* The proposer loses its slot's checkpoint, with the fees and rewards
  of every block it drops. The request itself changes no state and charges no fee; the nodes
  spend a round on it, and the queue waits that round's length.
- *What it gains.* The requester reads the outcome of a round on the live state that never
  lands: what its request would have done (a swap's output, whether a borrow is accepted)
  without committing to it. It can then send the request again, or not. A requester that is,
  or pays, the proposer gets one such look per abandoned slot; for a public result anyone who
  knows the request id reads it.

### Chain-held state

Chain-held state (manifest `state: chain`, an option for small fixed-size states) puts the
whole new state on chain at every `apply`: the new commitments and each node's third, sealed
under that node's record key `K_i` (derived from its `enc` key), in one public log. That
ciphertext is permanent. Anyone can read every past state's thirds for ever, and the past
states stay confidential only while no two nodes' `enc` keys of the time they were sealed
are ever exposed, including retired keys and old key-directory backups. Node-held state puts
nothing on chain but the commitment.

Its size is bounded by one Aztec public log: the tag, the W new commitments and `9n + 15`
fields of sealed thirds per output of `n` shared elements must fit in
`MAX_PUBLIC_LOG_SIZE_IN_FIELDS` = 4,094 fields, so one output holds at most 453 elements (a
public element uses 2 fields per third, so `9n + 15` is the all-shared maximum). REGISTER
refuses a chain-held manifest over the bound. Landing also needs one sealed third width
for all chain-held outputs in the round. Any other public log of the apply transaction (an
event the app's apply hook emits) takes its length plus 2 header fields from the same budget
(ARCHITECTURE.md section 6, "Bounds and policies"). Chain-held state is re-sealed only by an
`apply`, so each such namespace needs one `apply` inside every `enc` grace window
("Rotating a node's `enc` key").

### Upgrades

An app chooses whether its circuits, or its contract's code, may change after deployment
(ARCHITECTURE.md section 7, "Upgrades"; the design guide's question 15). Under
`upgrades: fixed`, the default, the circuit pins are the constructor's for the life of the
contract, and nothing new is trusted.

Under `upgrades: circuits` an **upgrade authority**, an address the constructor pins, can
schedule new circuit pins, which take effect after the upgrade delay (one day in the
examples). Plainly: the authority can replace the rules by which the shared state changes.
A hostile or compromised authority can register a circuit that credits itself and pays out
through the app's normal outcome path, so it can take whatever value the shared state
controls. What limits it:

- the change is public from the moment it is scheduled, and applies only after the delay, so
  users can leave first;
- it cannot change the contract's code: escrow, the escape hatch, `skip()` and refunds stay
  as deployed, and user-owned notes that no round controls are out of its reach;
- it cannot change the node keys or the stale period.

Under `upgrades: contract` (the AMM tip) the same authority can also move the instance to
another contract class, after the same delay. Plainly: it can replace all of the contract's
code, exactly like any upgradable Aztec contract: every function, the escape hatch included,
and with it everything the contract holds. The delay is the users' only protection, so its
length and the identity of the authority are the two facts to publish. The class change and
the new pins are scheduled in one call and take effect together; if they are ever out of
step, the class guard refuses every round and the nodes run nothing until they agree again
(liveness only).

Users of an upgradable app must be told who the authority is and how long the delay is,
exactly as for an upgradable contract. It should be a multisig or a governance contract,
never a node or a key the nodes hold.

Invariant 0 is unaffected. The contract verifies a result only under a vk hash in its own
pins, and the only code paths that write the pins are `upgrade_circuits` and
`upgrade_contract`, which check the authority and no node signature (and the protocol's
registry accepts a class update only from the instance itself): an adversary with every node
secret, the orchestrator and the relayer can store any contract manifest at the nodes and
prove any circuit, and still lands nothing the pins do not name. The namespace owner key can
upload a new version and DISABLE packages, never make another version run.

## Keys

ARCHITECTURE.md section 2 has the hierarchy and its derivations. In short:

| Key | Held by | Binds |
| --- | --- | --- |
| `enc_i` (Grumpkin scalar, from `sidecar-node setup`) | node i | ciphertext to node i: the INPUT_SHARED envelope to node i (ECDH) and, through the record key `K_i` derived from it, node i's third of every client-held record; a third's first 8 bytes are the key id. Rotates ("Rotating a node's `enc` key"). |
| `sig_i` (Grumpkin scalar, from setup) | node i | results and registry answers to node i (Schnorr); clients and the orchestrator check all three. No routine rotation; a node replacement can replace it in a `rotating` contract's key epoch ("Node replacement"). |
| master nullifier share | node i (sampled over the mesh at setup; nobody learns the master) | nothing directly: its only consumer is the registration circuit |
| `nsk_app` share / `npk_app_hash` | node i holds one `nsk_app` share per namespace, from the namespace's first REGISTER; the contract pins `npk_app_hash` | nullifiers to the namespace, and every nullifying round to this network |
| namespace owner key | the developer | the namespace's packages: it signs every REGISTER and DISABLE, with `seq` |
| requester key | a user | client-held records to their owner: a record's associated data names it, and it signs every request that supplies or stores a client-held record or, under intake direct, carries a shared input |

TLS certificates (the pinned mesh certificates; the deployment CA of the orchestrator's
mutual-TLS leg) are transport and sit outside this hierarchy.

## The operator-run trust rule

DECISIONS.md, "Operator-run trust":

- **Requests without records are unauthenticated.** An execute request that supplies no
  client-held record, stores no client-held key and carries no shared input needs no
  signature, and `admit` (`machine/sidecar-core/src/admit.rs`, run by the orchestrator and
  by every node) admits everything. Anyone may run any registered, enabled circuit, for
  example the AMM's `amm_swap`; the circuit bounds what a round can do and reveal.
- **REGISTER and DISABLE are signed** by the namespace owner key, with the next `seq`
  (ARCHITECTURE.md section 4).
- **Record-supplying and shared-input requests are signed.** A request that supplies a
  client-held record, stores a client-held key or (under intake direct) carries a shared
  input names `requester` and carries a Schnorr signature over its canonical body (400
  without `requester`, 403 without a valid signature); a node opens a third only for the
  owner it was sealed for (section 3, steps 4 and 8). A shared input needs the signature
  because whoever holds the body (the orchestrator does) could seal a pair of its own for one
  input under the same associated data and swap it in: the signature covers every share
  hash, and `requester` is in every envelope's associated data, so a body re-signed under
  another key opens none of the client's envelopes.

Fees, quotas, allow-lists or any further authentication go in `admit`.

At the tip:

- **Anyone may queue a request** from any account. The request functions read no
  `msg_sender`, so there is no account to rate-limit. An app may take escrow or a usage
  deposit in a pinned token. With the stale period enabled, the skip wrapper refunds
  any escrow and usage deposit it took by calling `token::refund_skipped`. For a landed
  round whose shares did not open `C`, `apply` refunds the deposit. When the round serves
  the request, `apply` keeps or refunds the deposit as the app chooses. A declared
  gas maximum is not a payment, so the request function does not check one. See
  [Fee payment](ARCHITECTURE.md#fee-payment) and DECISIONS.md section 12.
- **`configure` is permissionless and signature-checked**: anyone may send it once after the
  constructor, which pins the circuits (each package's vk hash, so the address commits to
  them), and it writes the signed `npk_app_hash` only under the three node signatures the
  constructor pinned, over the constructor's vk hashes (ARCHITECTURE.md section 6,
  "Deployment, configure and the init round"), so a compromise of all three nodes cannot pin
  another circuit.
- **REGISTER and DISABLE** are signed by the namespace owner key as on the sidecar path; a
  re-registered circuit is a new deployment of the contract, which pins its vk hashes.

## Setup

Every command runs from the repository root unless it says otherwise. A clean clone needs
x86_64 Linux with bash, `curl`, `tar`, `sha256sum`, `git`, `jq` and Python 3.11 or later
(the scripts read TOML with `tomllib`); rustup (or Rust 1.90.0 on `PATH`); Node 24 or later;
and docker (the nodes' Postgres; `scripts/bootstrap.sh` fails without it). The end-to-end
runs also need Foundry and util-linux's `flock` and `setsid`.

```sh
rustup toolchain install 1.90.0                    # the Rust that machine/rust-toolchain.toml selects
cargo install cargo-nextest --version 0.9.103 --locked   # the Rust test runner (toolchain.json cargo_nextest)
scripts/install-toolchain.sh                       # fetch the pinned tools, total-lint and the source worlds into .tools/ (gitignored)
scripts/bootstrap.sh                               # check every pinned tool, link deps/ (gitignored)
npm ci --no-audit --no-fund                        # the root workspace: pss-client, test-support, pss-relayer, e2e and the counter-tip client
npm ci --prefix scripts/txe --no-audit --no-fund   # the TXE runner's npm packages
scripts/prepare-data.sh                            # compile the round and embedded circuits, write the CRS into machine/data
scripts/gen-dev-certs.sh                           # build sidecar-node, write the development TLS planes into machine/data/keys
```

`install-toolchain.sh --with-foundry` also fetches Foundry 1.8.5, which only the e2e uses.

**The pinned tools.** `toolchain.json` pins every tool and dependency, and
`scripts/toolchain.sh` reads it. Round circuits compile with nargo 1.0.0 (`NARGO_BIN`); Aztec
contracts and the TXE with nargo 1.0.0-rc.3 (`CONTRACT_NARGO_BIN`); proofs use bb 6.0.0
(`BB_BIN`) and the co-snarks fork at the pinned rev. total-noir's `total`, noir-lang/schnorr
and noir-lang/poseidon are Nargo git dependencies, which nargo fetches on first use
([PROVENANCE.md](PROVENANCE.md), "Dependencies used in place").
`scripts/install-toolchain.sh` downloads the pinned binaries (sha256-checked), installs
total-lint from total-noir at the pinned commit and checks out the two Aztec source worlds
into `.tools/` (gitignored, `TOOLS_DIR`); every path can be overridden by its variable.
`scripts/bootstrap.sh` checks every tool against the pins, that every `Nargo.toml` names the
pinned tags and that Nargo's cached copies are at the pinned commits, Node 24 or later and
docker.

**Prepared data.** `prepare-data.sh` writes `machine/data/circuits/` and the CRS files, and
`gen-dev-certs.sh` writes `machine/data/keys/` (all gitignored). Every cargo build of the
machine needs `prepare-data.sh` first (at least `scripts/prepare-data.sh machine`):
sidecar-core's build script embeds the registration and audit circuits from the data
directory, and refuses an artifact whose bytecode differs from its line in
`machine/sidecar-core/embedded.sha256`. A test that reads a compiled circuit fails when the
artifact is older than a `.nr` file or `Nargo.toml` of its Nargo package (or of a Nargo
package it names by path in this repository), naming the command to run:
`scripts/check-noir.sh examples/<example>` or `scripts/prepare-data.sh`. Which tests skip
without the data, and the variables that make a skip a failure, are in
[TESTING.md](TESTING.md).

**Temporary files.** Every script and test puts its temporary files under `TXE_TMP_ROOT`
(default `.runs/tmp` in the repository, gitignored) and never in the system temp directory.
The root has to stay short, because the TXE server and the world-state process bind Unix
sockets below it and a socket path is limited to 107 bytes; the e2e harnesses keep their run
directories there until you remove them.

## Running the services

`cargo build --release` in `machine/` puts `sidecar-node` and `sidecar-orchestrator` in
`machine/target/release/` (the workspace's default members leave out
`sidecar-test-fixtures`, so this builds the binaries without the test features). The config
formats are documented at the top of `machine/sidecar-node/src/config.rs` and
`machine/sidecar-orchestrator/src/config.rs`, and every key is in "Configuration reference".
The development configs in `machine/sidecar-node/data/configs/` (`node{0,1,2}.toml` and the
mesh configs `party{0,1,2}.toml`) run three nodes on loopback with the in-memory store, with
the TLS material `scripts/gen-dev-certs.sh` writes. That development set has no certificate
for the orchestrator's public listener (the harness serves node 0's development server
certificate there).

```sh
sidecar-node setup --config <node config>      # on all three nodes at once: enc, sig, master share
sidecar-node serve --config <node config>
sidecar-orchestrator --config <orchestrator config>
```

`setup` prints each node's public `enc` and `sig` keys as one JSON line; they go into the
orchestrator's `[[nodes]]` entries and every client's `nodeKeys`. `setup --dealer` (three
`--config`s, one process, no mesh) is for development only: one process writes all three
nodes' keys and a sharing of a master it saw.

`sidecar-node`'s other subcommands are the operator procedures and recovery below
(`restore`, `prune`, `rotate-enc`, `sign-enc-key`, `sync-registry`, `resync`, `audit`,
`backup-key`, `backup`, `backup-keys`, `restore-backup`, `restore-keys`, `replace-node`)
and two set-up aids, `gen-certs` (the development TLS material) and `mesh-check` (on all
three nodes: one empty MPC session, a check that the mesh config, certificates and ports
work);
`sidecar-orchestrator` takes `sync-registry`, `pause`, `resume` and `status`.

Firewall each node's mesh port so only its two peers' addresses reach it, and its API port
so only the orchestrator's host reaches it ("Configuration reference": mesh config
`connect_timeout`, listener transport).

**At the tip**, the three node configs and the orchestrator's carry the same `[tip]`
section, each naming its own Aztec node, and the same `[[tip.namespaces]]` list of the tip
contracts the machine serves ("The tip sections (`[tip]`)"). A deployment generates its
contract manifest (`pss-manifest build`) and uses pss-client's `deployTip` (the packages'
vk hashes computed locally, the constructor's pins with the manifest hash, one REGISTER of
the contract manifest, the deployment, `configure`), then starts one relayer per
deployment:

```sh
node --conditions=source --import ./ts/hooks/register.mjs ts/pss-relayer/src/main.ts relayer.json
```

[ts/pss-relayer/README.md](../ts/pss-relayer/README.md) lists the configuration file's keys
and the full format is the header of `ts/pss-relayer/src/main.ts` ("Configuration
reference", pss-relayer). The relayer reaches the network through the orchestrator's public
listener, as every client does. It takes the stale period from its client's tip manifests
and serves `GET /status` on `127.0.0.1:<statusPort>`. `ts/pss-relayer/test/local-network.ts`
embeds it with `createAztecRelayer`; an app whose result call does not take the library's
`TipResult` supplies an encoder module (`encoder`).

## Operator procedures

Every `sidecar-node` operator command is a client of the node's admin socket: a Unix
socket at `<run_dir>/admin.sock` (or the config's `admin_socket`, or `--admin-socket` /
`NODE_ADMIN_SOCKET`), mode 0600 in a 0700 run directory, never reachable over the network.
Each command sends one JSON line, for example `{"op": "restore", "namespace": "0x…",
"request_id": "0x…"}`, and the node answers `{"ok": true}` or
`{"ok": false, "refusal": {"class": "…", "error": "…"}}` (`machine/sidecar-node/src/admin.rs`).
Run them on the node's host, as the node's OS user, while the node runs, unless a procedure
says otherwise.

### A node-held round whose transaction cannot land (the sidecar path)

A node-held round commits at the nodes before its transaction reaches the chain. If the
transaction never lands, the row is ahead of the chain: the next round loads a value whose
note hash the chain does not hold, and its transaction fails at the contract.
ARCHITECTURE.md section 8 lists the cases (wrong nonce, a caller-bound hook).

1. **Find the request id.** The client that sent the round has it (pss-client keeps the
   body in its request store). Otherwise every node logs each request under its
   `request_id`, and on a Postgres node the newest rows of the namespace are

   ```sql
   SELECT '0x' || encode(request_id, 'hex') AS request_id, status, created_at, stored_keys
   FROM requests
   WHERE namespace = decode('<the namespace as 64 hex digits>', 'hex')
   ORDER BY created_at DESC;
   ```

2. **FETCH the stored result and land it.** FETCH is open to anyone who holds the request
   id: `POST /v1/fetch` on the orchestrator with `{"namespace": "0x…", "request_id": "0x…"}`,
   or with pss-client `client.fetch(requestId, { circuit, namespace })` (`circuit` is needed
   when this client did not send the request). The answer is the round's proof, public
   inputs, records and three node signatures, checked like an execute answer. Build the
   transaction from it as for a fresh answer. The AMM's `swap` is open to any caller, so
   anyone can land a stuck swap; a round whose landing function is caller-bound (the AMM's
   `start_pool` is operator-only) needs that caller.

3. **Only if it cannot land, roll it back on all three nodes:**

   ```sh
   sidecar-node restore --config <node config> --namespace 0x… --request-id 0x…
   ```

   Under the namespace lock, the node writes back every node-held vector the round replaced
   (opened from the sealed replaced vectors in its `requests` row), deletes every row the
   round created, deletes every consumed entry the round wrote, and marks the request
   `rolled_back`; its FETCH then answers 409 (ARCHITECTURE.md section 3, the rollback path).
   Refusals: 404 for an unknown or pruned request; 409 for one already rolled back, or while
   a later committed request rewrote a key this one wrote or consumed a state it created;
   500 when a sealed replaced vector no longer opens (it was sealed under an `enc` key
   retired since).

   Roll requests back in reverse order of commit, the newest first (DECISIONS.md, "Rollback
   without versioned storage"). Between nodes the order does not matter, but all three must roll back: a key
   restored on only some nodes no longer has a consistent sharing, and the next round on it
   is refused at the session handshake (400, naming the key) until the remaining nodes are
   restored too. Roll back only a round whose transaction can never land: if it lands
   afterwards, the chain has nullified the restored state and every later round on it fails
   at the contract.

The same rollback recovers a client-held round: the consumed entry is deleted, so the owner
presents its old record again. At the tip a round that landed never needs this: `apply` is
the only state mover, and node-held tip state is versioned, with the chain deciding which
version counts.

The tip's one use of the rollback is an attempt committed at fewer than three nodes (a node
stopped or timed out at its commit). The scheduler's resends of it are refused at the
handshake ("this node already holds request …" from the nodes that committed it), and the
entry waits for `skip()`. First check that one node lacks the row: FETCH of the request id
answers 404 while any node lacks it, and the resend's handshake refusal names the nodes that
hold it. A node signs a result only after it commits it, so that attempt holds at most two
of the three signatures `process_result` needs and can never land. Then roll it back at the
nodes that hold it, with the same command. Each marks the versions of the keys the request
wrote against its own chain view, deletes every version the request wrote (with the tree
nodes only they reach) and keeps the row `rolled_back`. It refuses (409) a version the slot
holds in that view (the attempt landed), a version a later attempt builds on (roll that one
back first), a version of an oblivious tree (its DORAM state cannot be put back: resync the
key from its neighbours, and the entry is skipped after `stale_blocks`), and any version
when the node's chain view does not answer. The scheduler's next resend of the attempt, the
same request id and body, then runs at all three nodes and replaces the rolled-back rows.

### Retention and pruning

Each node keeps its `requests` rows for `requests_retention_days` (default 30). That is the
window for FETCH and for rollback, since a row holds both the stored result and the sealed
replaced vectors. The pruning job deletes the rows created before `now - retention`: at
start and then every `prune_interval_secs` (default 3600; 0 turns the timer off, for a
deployment that runs the command from cron), so a row lives at most one interval past the
window. To prune once:

```sh
sidecar-node prune --config <node config>      # {"op": "prune"} on the admin socket; prints how many rows
```

After the window, FETCH of the id answers 404 (rolled-back rows included), the round can no
longer be rolled back, and a resent body runs as a new request. The consumed set is never
pruned (only a rollback removes entries), so a consumed state stays consumed. The three
nodes should use the same window: the orchestrator answers 404 when any node has pruned the
row.

On a node with `[tip]` the same job also, at the settled block (the finalized tip as the
node's own Aztec node reports it):

- prunes the receipts past their window (ARCHITECTURE.md section 6, the receipts row), after
  reading their requests' standing in the queue ("Configuration reference", receipt standing
  scan);
- marks the node-held versions of every namespace of `[[tip.namespaces]]`, under the
  namespace's lock, against each key's slot and the queue's head, as a round's commit does,
  and deletes the orphans first marked orphan below the settled block (ARCHITECTURE.md
  section 6, "Node-held state", retention), so a key no round commits on still loses its
  orphans within one interval of their retention; the answer counts them
  (`pruned_versions`). A run whose Aztec node does not answer changes no version;
- records and retires the node's secret-shared on-chain epoch scalars ("Rotating a node's
  `enc` key").

The deletion floor comes from each node's own Aztec node: one that lies about the finalized
tip makes its node delete versions early, but only that node's copy, and a resync of the key
from the two neighbours restores it.

### Rotating a node's `enc` key

Only `enc` rotates on its own; a new `sig` key comes only with a node replacement ("Node
replacement"). Rotate while the node runs:

```sh
sidecar-node rotate-enc --config <node config>      # the admin socket's rotate_enc
```

The node draws a new `enc` scalar, keeps the old one in its key directory as
`enc.previous.key` beside `enc.rotated_at` (the rotation time), switches to the new key at
once and prints one JSON line: the new `enc` and the unchanged `sig` public keys, the new and
the previous key ids, and `previous_retires_at`, when the window ends. Each node rotates on
its own; the other two are unaffected.

- **Re-pin.** Put the new `enc` key in every client's pinned node keys (pss-client
  `nodeKeys`) and in the orchestrator's `[[nodes]]` entry, then restart the orchestrator:
  until its pin matches, its `GET /v1/nodes` refuses (500) because the node answers the new
  key. A node's own `GET /v1/nodes` returns only the current keys.
- **The window.** `enc_grace_days` (default 30), counted from the rotation time, which
  survives restarts. During it the node opens record thirds under either key id and
  envelopes sealed to either key, and seals every new third under the new key only. A
  secret-shared receipt request sealed to the previous key is refused; REGISTER refuses a
  secret-shared receipt package whose receipt life outlasts the window.
- **Re-seal.** A round that loads a client-held record and stores it again returns it sealed
  under the new key, so an app re-seals each live record within the window by running any
  such round. Node-held values are not sealed under `enc` and need nothing.
- **After the window.** The node removes the previous key (at start, and on an hourly check)
  once no queued secret-shared receipt request still needs it: while a stored receipt row's
  envelope to the node opens only under the previous key and its request is queued (or not
  yet seen before its expiry), the node keeps the key and logs why. Once removed, a third
  sealed only under it is refused (400) and is lost, like a lost record; an envelope sealed
  to it is refused; the rollback of a round committed before the rotation fails, because its
  sealed replaced vectors were sealed under the old key.
- **Twice in a window.** `rotate-enc` refuses while a previous key is inside its window, or
  held past it by a queued secret-shared receipt request, since a second rotation drops that
  key at once; `--force` does it anyway.
- **Backups.** Take a key directory backup after the rotation (`backup-keys`, "Backups").

**Secret-shared on-chain intake.** Such a namespace keeps its own copy of each node's `enc`
public key, with an epoch, in the app contract's public storage, and `rotate-enc` does not
touch it. A node puts a key there (the first, epoch 1, included) with a transaction to the
app's `rotate_enc_key`, carrying its `sig` signature over the key and the next epoch. One
command signs and submits the rotation, contract by contract:

```sh
npm run rotate-enc-key --workspace ts/pss-relayer -- rotate.json   # sign, submit, check and record, per contract
```

For each contract it reads the node's stored epoch, asks the node's admin socket to sign the
next one (`sign_enc_key`), lands `rotate_enc_key(i, key, signature)` from the operator's
account (the relayer's account and fee settings; it pays as the fee kind `configure`), checks
`get_enc_key(i)` and runs the node's `prune`, so the node records the scalar at once
("Configuration reference", pss-relayer `rotate-enc-key`). To sign without submitting:

```sh
sidecar-node sign-enc-key --config <node config> --namespace <contract> --epoch <e>   # the admin socket's sign_enc_key
```

prints one JSON line, the arguments of the contract's `rotate_enc_key(i, key, signature)`,
for the operator to submit (the e2e's `tipEncKey` step does both).

The node records a contract epoch's scalar when the rotation lands, not when it signs:
signing keeps its current scalar pending in the key directory's `enc.epochs.json`, and the
pruning job records it once the contract stores the node's key (pss-relayer's command runs
the prune at once). A rotation that never landed leaves nothing to clear: sign the same
epoch again (after `rotate-enc`, under the new scalar). A landed epoch answers again under
its own scalar and is refused under another, as is an epoch below it; the pruning job
deletes an epoch's scalar once the contract's epoch is two ahead and the head has passed
every request that could name it (ARCHITECTURE.md section 6, "Secret-shared on-chain
intake"). Take a key directory backup after each rotation lands.

**Chain-held state.** A tip namespace with chain-held state is re-sealed only by an `apply`:
its state is the last sealed-thirds log. So every such namespace needs one `apply` inside
each grace window, or its state is lost when the window closes and the app is frozen for
good. Before the window closes, the operator checks each chain-held namespace for an
`apply` since the rotation and, for an idle one, sends a keep-alive: a statically valid
request that fails against the state (for the AMM, a swap whose `min_out` no pool can pay),
which lands as an `ok = false` no-op and re-seals the unchanged state under the new key.
Node-held state needs no keep-alive.

### The orchestrator's registry copy

The orchestrator keeps the nodes' `namespaces` and `packages` rows in `[registry] path`,
written from the REGISTER and DISABLE answers it relays. A copy one body behind is brought
level by resending that signed body; one that is further behind, lost or opened under the
wrong path is rebuilt from the three nodes:

```sh
sidecar-orchestrator --config <orchestrator config> sync-registry   # with the orchestrator stopped
sidecar-orchestrator --config <orchestrator config> --sync-registry # or rebuild at start
```

The three nodes must agree on every row, each vk is recomputed from its circuit, and the old
copy is replaced only when the new one is whole. Backing the directory up saves a rebuild
but is not required.

At every start, before it serves, the orchestrator reads the three nodes' registry rows and
compares them with each other and with its copy, writing nothing. It logs "registry check at
start: the three nodes and the copy agree", or one warning per row that differs, naming the
namespace, the row (the namespace row, or a package by name) and what each holder holds:

```text
registry check at start: a row differs divergence=namespace 0x…40e7: package
`monty_hall_open_door`: node 0 and node 1 hold seq 2, disabled, vk_hash 0x…; node 2 and the
copy hold seq 1, enabled, vk_hash 0x… repair=the nodes differ: …
```

It serves either way: a row the nodes differ on is the next section's case (the nodes refuse
in-session what their rows refuse), and a row only the copy differs on ("the nodes agree and
the copy differs") is repaired by `sync-registry`. A node that cannot be read is a warning
that the check did not run. The check runs again after every REGISTER or DISABLE the
orchestrator relays that not all three nodes refused, and every `[registry]
check_interval_secs` (default 600), which catches a change made at the nodes alone; no
request waits on it.

`GET /v1/status` answers the latest check's counts from memory: `{"registry":
{"compared_at": <unix seconds>, "counts": {"namespaces", "packages", "between_nodes",
"copy_only"}}}`, or `"unread": true` in place of `"counts"` when a node could not be read,
and `{"registry": null}` before the first check. It names no row: the rows name namespaces
and circuits, which the public API does not enumerate. The operator reads the rows, and the
reason a node could not be read, with `sidecar-orchestrator status` (the admin socket's
`status`: `"registry": {"compared_at", "agreement": {"check": {"namespaces", "packages",
"divergences"}, "between_nodes", "copy_only"}}` or `"unread": <reason>`) and in the log.

### A registry body only some nodes committed

A REGISTER or DISABLE that one node refuses or fails to commit (a store failure there) while
the other two commit it leaves the nodes' registries diverged. The orchestrator answers it
500, "the nodes' registries diverged: nodes 0 and 1 committed this DISABLE body and node 2
did not (node 2: …)", and leaves its copy unchanged. While a DISABLE is diverged, an execute
of that circuit passes the orchestrator (its copy holds the circuit enabled) and is refused
400 by all three nodes within the session handshake ("session handshake: node 0 refused the
request: … is disabled …"); nothing is stored. A circuit a diverged REGISTER added is
refused by the orchestrator, whose copy does not hold it.

The repair is to resend the same signed body, through the orchestrator as before. The nodes
that hold it answer it unchanged (the idempotent case), the others commit it, and the
orchestrator records it in its copy. A `seq` 0 REGISTER is resent the same way while the
namespace's `seq` is still 0 (the registration circuit runs again and every node keeps a
fresh share of the same `nsk_app`). Nobody should send the next body first: the
orchestrator's pre-check refuses it 409 against its copy until the resend lands.

To see which rows differ, run the registry check on all three nodes at once (one mesh
session, like `audit`; it writes nothing):

```sh
sidecar-node sync-registry --config <node config> --check [--namespace <namespace>]
```

Each node prints the same report as one JSON line (`namespaces`, `packages`,
`divergences`) and fails naming every row the three do not hold alike, for example
"namespace 0x…: package `pss_seed`: node 0 and node 1 hold seq 3, disabled, vk_hash 0x…;
node 2 holds seq 0, enabled, vk_hash 0x…". It compares each namespace's owner, `seq` and
`npk_app_hash`, and each package's vk_hash, manifest, disabled flag and `seq` (never a
share).

If a node refuses the resend again, its rows differ from the other two for another reason
than this body (an earlier body it never committed, or a damaged store); the check names
them. A node more than one body behind cannot be brought level by resending: resync its
registry from a neighbour ("Resync of one node's registry").

### Upgrading an app's circuits

For a namespace whose contract manifest says `upgrades: circuits` or `contract`
("Upgrades"). Three parties act: the developer, the namespace owner (the key that signs
manifest messages) and the upgrade authority (the on-chain address the contract pins). They
may be one party or three.

1. The developer compiles the new circuit and regenerates the contract manifest with
   `pss-manifest build` from a descriptor naming it
   (`examples/amm-tip/deployments/amm-tip-next.json` registers `amm_swap_tip_next` under the
   package `amm_swap_tip`). Only circuits and circuit manifests may change: the contract's
   facts and every state key's layout stay, no key is added and the intake family stays, or
   REGISTER refuses the version (400, naming the field). A circuit whose bytes are unchanged
   keeps its stored vk.
2. The owner sends it as a manifest message at the next `seq`. The nodes keep it beside the
   version in force; nothing changes on chain or in the rounds yet. Check that
   `GET /v1/namespaces/{ns}/manifests/{hash}` answers it from the orchestrator.
3. Give the relayer the new circuits beside the old ones before the switch: it finds a
   result's circuit by its vk hash, so with both it lands results under either version (the
   e2e harness lists each replaced package's new circuit under `<package>@upgrade`).
4. The authority calls `upgrade_circuits` with the new pins (pss-client `circuitPinsOf` and
   `upgradeCircuits`). The change and its time are public from then on.
5. At the time of change the contract, the scheduler and every node switch together: each
   runs a round only under the version the pins name at its block. Results proven under the
   old circuits land before the switch or not at all. Requests queued under a replaced
   circuit go stale and are skipped; clients ask again. Clients follow the version in force
   (`readCircuitPins`, `PssClient.adoptManifest`).

Register before scheduling: until the nodes hold the version the pins name, no round runs
(liveness only). A namespace holds at most three versions (`MAX_HELD_VERSIONS`), the oldest
by `seq` dropped first, so an owner who registers several versions the chain never names can
push the version in force out; registering it again at the next `seq` brings it back.

### Upgrading an app's contract code

For a namespace whose contract manifest says `upgrades: contract`. The same three parties,
and the same rules for the circuits.

1. The developer compiles the new class from the app's sources. It keeps every state key
   (name, slot and layout), the slot of `circuit_upgrades` and the package capacity, and it
   never embeds a contract manifest's hash. The developer publishes the class on chain (no
   new instance) and generates its contract manifest with `pss-manifest build` from the new
   artifact: a new `contract.class_id`, the slots recomputed, the circuits as they are or new
   ones. REGISTER refuses a version that moves a state key, the pins' slot or the capacity,
   changes `upgrades`, or turns a rotating key set fixed (400, naming the field).
2. The owner sends it as a manifest message at the next `seq`, as for a circuit upgrade.
3. Give the relayer the new artifact (pss-relayer `upgradeArtifacts`) and, when circuits
   change, the new circuits.
4. The authority calls `upgrade_contract(new_class_id, pins)` (pss-client `upgradeContract`,
   which takes both from the new contract manifest). It refuses unless the instance's
   class-update delay is the pins' delay; with the default day on both nothing needs
   setting. An app with another delay sets the instance's in its constructor
   (`set_update_delay`, itself delayed).
5. At the time of change the class and the pins switch at one timestamp, and the nodes with
   them. A transaction proven under the old class expires at the switch; a result whose
   circuit did not change is landed again through the new class. Every wallet registers the
   instance again with the new artifact (pss-client `followContractClass`); the relayer does
   so itself when `upgradeArtifacts` is set.
6. Check the deployment: `pss-manifest verify --manifest <file> --artifact <file> --node <url>
   --address <address>` compares the instance's current class and the artifact's with
   `contract.class_id`, every slot the generator derives from the artifact, and the pins in
   force with the manifest's hash, package list and vk hashes; it prints one line per check
   and exits non-zero on any mismatch.

## Configuration reference

Every setting a deployment chooses, by component, with its default and what turning it
costs; the code keeps a one-line pointer to this section where it reads each one. The node
and orchestrator config formats are at the top of `machine/sidecar-node/src/config.rs` and
`machine/sidecar-orchestrator/src/config.rs`. App parameters (the contract manifest's
`stale_blocks`, the tree's dimensions and the rest) are the app developer's, not the
operator's: [the design guide](design-guide/README.md) lists them.

### Command line and environment

Each of these flags also reads the environment variable beside it; the flag wins when both
are given.

| Flag | Variable | Binary | Meaning |
| --- | --- | --- | --- |
| `--config` | `NODE_CONFIG` | sidecar-node, every subcommand that reads a node config | the node config file (`setup --dealer` takes three) |
| `--api-listen` | `NODE_API_LISTEN` | sidecar-node | in place of the config's `api_listen` |
| `--mesh-base-port` | `NODE_MESH_BASE_PORT` | sidecar-node | the mesh on ports base, base + 1 and base + 2, in place of the config's `mesh_base_port` |
| `--admin-socket` | `NODE_ADMIN_SOCKET` | sidecar-node | in place of the config's `admin_socket` |
| `--mesh-config` | `NODE_MESH_CONFIG` | sidecar-node `mesh-check` | the party mesh config |
| `--out` | `SIDECAR_KEYS_DIR` | sidecar-node `gen-certs` | where the development TLS material is written |
| `--config` | `ORCHESTRATOR_CONFIG` | sidecar-orchestrator | the orchestrator config file |
| `--listen` | `ORCHESTRATOR_LISTEN` | sidecar-orchestrator | in place of the config's `listen` |

### Node (`sidecar-node` config and mesh config)

| Key | Default | Meaning | Code |
| --- | --- | --- | --- |
| `api_listen` (`--api-listen`) | development: node j on 127.0.0.1:8200 + j (`DEFAULT_API_BASE_PORT`) | The HTTPS API the orchestrator calls; the flag takes port 0 for a free port. A deployment binds the interface the orchestrator reaches and opens the port to the orchestrator's host only. | `machine/sidecar-node/src/config.rs` |
| `mesh_config`, `key_dir` | required | The party mesh config (`my_id`, `bind_addr`, `parties`, `[tls]`; its relative TLS paths resolve against its own directory) and the node's key directory ("Recovery" lists its files). | `machine/sidecar-node/src/config.rs` (`mesh_config`, `key_dir`) |
| mesh config `bind_addr`, party addresses; node config `mesh_base_port` (`--mesh-base-port`) | development: party j on 127.0.0.1:10200 + j | The development mesh binds loopback, so it is never reachable from another host; `--mesh-base-port` moves all three ports together. A deployment binds the interface its peers reach, names its peers by addresses their certificates carry, and opens only the mesh port to the two peer hosts. | `machine/sidecar-node/src/config.rs` (`bind_addr`, `mesh_base_port`) |
| `[store] backend` (`memory`, `postgres` with `url`, `local` with `path`) | `memory` (the development configs) | `memory` is lost on exit (a restarted node has forgotten every namespace, package and request): tests and development only. `postgres` for deployments with node-held keys (`state: node`), with a database server's durability and backups. `local` (the append-only file store `store.log`, which begins with a version 3 format marker, every record header checksummed; a log without the marker is refused) for deployments whose keys are all client-held: REGISTER refuses (400) a manifest with a `node` key and its commit refuses a node-held write (500); a node moves to Postgres with the same tables. The three behave the same because the write rule, the rollback and the consumed check live above the store trait. The Postgres URL may carry a password, so the config file is as private as the key directory; the link carries the node's shares, so a server on another host is reached with `sslmode=verify-full` (the CA among the webpki roots or the URL's `sslrootcert`) unless the URL or `PGSSLMODE` names another mode, used with a warning; a loopback host or a Unix socket keeps `prefer`. | `machine/sidecar-node/src/config.rs` (`StoreConfig`), `machine/sidecar-node/src/postgres.rs` (`PostgresStore`, `connect_options`) |
| `requests_retention_days` | 30 (`DEFAULT_REQUESTS_RETENTION_SECS` in days); at least 1 | The window for FETCH and the rollback ("Retention and pruning"), by the node's clock. Longer costs disk (a proof and the sealed thirds per round) and keeps sealed material longer; shorter shortens the time to land a transaction or roll a round back. Use one value on all three nodes. | `machine/sidecar-node/src/config.rs`, `machine/sidecar-core/src/pipeline/node.rs`, `machine/sidecar-core/src/store/mod.rs` |
| `enc_grace_days` | 30; at least 1, and with `[tip]` at least the life of a receipt | The window after `rotate-enc` in which the previous scalar still opens thirds and envelopes ("Rotating a node's `enc` key"; the hourly retirement check is `rotation::DEFAULT_RETIRE_CHECK_SECS`). Longer keeps an old secret on disk longer; shorter loses the records of apps that do not re-seal in time. With `[tip]`: `sidecar_tip::check_enc_grace`, and REGISTER refuses a secret-shared receipt package whose stale period is null or too long for it. | `machine/sidecar-node/src/config.rs`, `machine/sidecar-core/src/keys.rs` (`enc_grace_days`) |
| `prune_interval_secs` | 3600 (`DEFAULT_PRUNE_INTERVAL_SECS`); 0 turns the timer off | How often the pruning job runs ("Retention and pruning"). Longer delays the deletions and the record of a landed `enc` epoch (a later signature at that epoch is refused only once recorded); shorter costs chain reads (five storage reads per secret-shared on-chain contract) and a store scan more often. `sidecar-node prune`, and `rotate-enc-key` after each rotation, run it at once. | `machine/sidecar-node/src/config.rs` (`prune_interval_secs`) |
| `receipt_allowance_blocks` | 10 (`DEFAULT_RECEIPT_ALLOWANCE_BLOCKS`) | A node signs an `expiry_block` at most `ttl + allowance` after its own current block, which differs from the orchestrator's by a few proposed blocks. Larger lets a skewed orchestrator get longer-lived receipts; smaller refuses receipts whenever the readers disagree by more. A first deployment's measured skew is the evidence to revisit it. | `machine/sidecar-node/src/receipt.rs` |
| `receipt_ttl_blocks` (node and orchestrator) | 300 L2 blocks (`sidecar_tip::DEFAULT_RECEIPT_TTL_BLOCKS`); at least 1 at the node | Three hours at 36 s per block, half an hour at 6 s proposed blocks. The orchestrator fixes `expiry_block = current_block + receipt_ttl_blocks` (the three receipts sign one message); each node signs only an expiry after its own current block and at most `ttl + allowance` ahead, so an orchestrator value above that makes every receipt refused. A user whose intake transaction misses the expiry asks again (the same nonce gets a later receipt, `receipt::sign`). Longer: the nodes hold inputs of requests that never come for longer (until expiry plus the stale period, `receipt::prune`); shorter: slow users need a second round trip. Use one value on all four; a first deployment's measured receipt-to-landed time is the evidence to revisit it. | `machine/sidecar-tip/src/config.rs`, `machine/sidecar-orchestrator/src/config.rs` (`receipt_ttl_blocks`), `noir/pss_public_contract/src/receipt.nr` (module doc) |
| mesh config `connect_timeout`, `timeout` | 30 s (`DEFAULT_CONNECT_TIMEOUT`); 10 min (`DEFAULT_IO_TIMEOUT`) | `connect_timeout` bounds a session's whole opening (every connect, accept, TLS handshake and connection header), so a node whose peers never arrive refuses with 500 and releases the mesh lock; an accepted connection gets at most 5 s of it, and one that stays silent, fails its handshake or presents no pinned certificate is dropped. Anyone who reaches the mesh port can delay an opening up to `connect_timeout` and make it fail: firewall the port to the two peers. `timeout` bounds the wait on one message inside a round, whose longest gap is a peer building its proving key or proof for the largest circuit: raise it for larger circuits. Per party config. | `machine/sidecar-node/src/mesh.rs` (`connect_timeout`, `timeout`), `machine/sidecar-core/src/handshake.rs` |
| `mesh_session_timeout_secs` | 3600 (`DEFAULT_SESSION_TIMEOUT`); at least 1 | One whole MPC session; past it a send, receive or flush fails the session (500) and releases the mesh and namespace locks, so a peer answering just inside `timeout` cannot hold the mesh for ever. Raise it for a resync, replacement or audit of a large store. | `machine/sidecar-node/src/mesh.rs`, `machine/sidecar-node/src/config.rs` |
| node `[tip]` section | absent: no chain reads | "The tip sections (`[tip]`)". Without it the node's step 4 hook refuses every queued round (400, "this node has no [tip] section") and its receipt signer every receipt request (400, `receipt::NO_TIP_SECTION`): a node must never run a queued round it did not check, drop the inputs of a request still queued, or store receipts it cannot prune. One node without it stops every queued round and every receipt. | `machine/sidecar-node/src/config.rs` (`TipConfig`) |

### Node and orchestrator (`[crs]`)

| Key | Default | Meaning | Code |
| --- | --- | --- | --- |
| `[crs] g1`, `[crs] g2` | none (required paths) | `g1` is the start of the public Aztec BN254 ceremony output (bb's `~/.bb-crs/bn254_g1.dat`, copied by `scripts/prepare-data.sh`); `g2` its 128-byte `[x]_2`. Only the points the largest circuit needs are read; a file too short fails at start-up. Another CRS is another trusted setup, whose proofs do not verify against bb's keys. | `machine/sidecar-core/src/crs.rs` (`Crs::read`) |
| `[crs] circuits_dir`, `[crs] circuit_size` | both absent: sized for the embedded circuits only | The CRS read at start is sized for the largest circuit in `circuits_dir` (the circuits the deployment will register) and the embedded circuits, or for `circuit_size` when larger. A REGISTER of a larger circuit fails until the node restarts with a larger size; more points cost memory and start-up time. | `machine/sidecar-core/src/crs.rs` (`Crs::load`) |

### Orchestrator (`sidecar-orchestrator` config)

| Key | Default | Meaning | Code |
| --- | --- | --- | --- |
| `listen` (`--listen`) | 127.0.0.1:3200 (`DEFAULT_LISTEN`) | The public API; the flag takes port 0. A deployment binds the interface its clients reach: the API is public (no client certificate), protected by the protocol's own checks plus whatever `admit` adds. | `machine/sidecar-orchestrator/src/config.rs` |
| `[tls]` `cert`, `key`; `[node_tls]` `ca`, `cert`, `key` | required | The public listener serves TLS 1.2 or 1.3 with the orchestrator's server certificate and asks no client certificate. The node leg is mutual TLS: `ca` is the deployment CA the nodes' certificates chain to, `cert`/`key` the orchestrator's client certificate under it, as private as an operator credential (whoever holds it can drive the nodes). Separate files, so the public certificate can be renewed or issued by a public CA without touching the node leg. The development set has no public server certificate; the tests use a node's, which names `localhost`. | `machine/sidecar-orchestrator/src/config.rs` (`PublicTls`, `node_tls`) |
| `[[nodes]]` `url`, `server_name`, `enc`, `sig` | required, node 0 first; `server_name` the URL's host | `server_name` is the name the node's server certificate must carry. The keys are the deployment's published identity, written by the operator, never learned from a node: `sig` checks every result and registry signature; `enc` is compared, and `GET /v1/nodes` refuses (500, naming the node) a node answer that differs. Update `enc` after a rotation; `sig` changes only with a node replacement. This file is the key set's one source for the orchestrator, never a contract, so a hostile rotation cannot drive the scheduler, which computes nothing for a namespace whose contract is at another key set. | `machine/sidecar-orchestrator/src/config.rs` (`NodeEntry`) |
| `[registry] path` | required | The orchestrator's registry copy ("The orchestrator's registry copy"); `sync-registry` rebuilds it. | `machine/sidecar-orchestrator/src/config.rs` (`RegistryFiles`) |
| `[registry] check_interval_secs` | 600; at least 1 | The registry check's timer ("The orchestrator's registry copy"): it catches what changes at the nodes alone (a node restored from a backup, a `sidecar-node sync-registry` repair, a body sent to the nodes directly). Each run reads every row over the nodes' GETs and takes no lock. | `machine/sidecar-orchestrator/src/config.rs` |
| `admin_socket`; `--paused` | `admin.sock` in the directory holding the registry copy; not paused | The operator's Unix socket (directory 0700, socket 0600; path checked against the 107-byte bound). `sidecar-orchestrator pause` stops scheduling between rounds (it returns once the round in flight ends), `resume` resumes only when the three nodes' registries agree, `status` prints the state and the latest registry check with the rows that differ. `--paused` starts paused (a node replacement). | `machine/sidecar-orchestrator/src/admin.rs` |
| `node_call_timeout_secs` (and the lookup call bound) | 1,000 s (`nodes::DEFAULT_NODE_CALL_TIMEOUT`); at least 60 (`MIN_NODE_CALL_TIMEOUT_SECS`) | One whole node call, so a node that accepts a connection and never answers cannot hold the global session lock. It must stay above a round's bound: 30 s mesh opening + 600 s mesh `timeout` + 300 s of proving = 930 s. A call that runs out is a transport failure (500 naming the node) and releases the session lock while the nodes may still hold their mesh locks, so the next round queues at the nodes and FETCH of the timed-out round answers 404 until it commits. Raise it with the mesh `timeout` or for circuits that prove longer. A call that opens no session (FETCH, a receipt, tree paths, a registry read, `/v1/nodes`) is bounded at 60 s (`nodes::LOOKUP_CALL_TIMEOUT`, no knob). | `machine/sidecar-orchestrator/src/nodes.rs`, `machine/sidecar-orchestrator/src/config.rs` (`node_call_timeout_secs`) |
| orchestrator `[tip]` section | absent: no scheduler | "The tip sections (`[tip]`)". Without it the orchestrator starts no scheduler and reads no chain; the public API is the same either way, so a deployment that runs no tip app needs no Aztec node. A queued package can be registered without `[tip]`, but nothing drives its queue until the section names its namespace. | `machine/sidecar-orchestrator/src/config.rs` (`TipConfig`) |

### The tip sections (`[tip]`)

A tip deployment configures `[tip]` in all four config files: the three nodes' (the chain
verifier, the receipt signer and the receipt pruning) and the orchestrator's (the
scheduler).

| Key | In | Default | Meaning | Code |
| --- | --- | --- | --- | --- |
| `aztec_node` | all four | required | The Aztec node's JSON-RPC URL, `http://` or `https://`. Each node names its own, never the orchestrator's or another node's, so a request the three chain verifiers accept is one three Aztec nodes show ("Outcomes before finality"); logs and transport errors show only its scheme, host and port. | `machine/sidecar-tip/src/config.rs` (`AztecNode`) |
| `aztec_node_ca` | all four | none | For an `https://` node, required: the only root its certificate may chain to. | `machine/sidecar-tip/src/config.rs` |
| `block_time_secs` | nodes | 36 (`DEFAULT_BLOCK_TIME_SECS`, one Aztec slot) | The L2 block time at which a node checks its `enc` grace window against the life of a receipt; at least 1. | `machine/sidecar-node/src/config.rs` |
| `poll_interval_ms` | orchestrator | 1000; at least 100 | How often the chain reader asks for the proposed tip (`next_snapshot` gives up after 60 s without a new block, `DEFAULT_FOLLOW_TIMEOUT`); a block comes about every 6 s, and the scheduler steps once per new block. | `machine/sidecar-tip/src/chain/mod.rs` (`DEFAULT_POLL_INTERVAL`, `DEFAULT_FOLLOW_TIMEOUT`), `machine/sidecar-orchestrator/src/config.rs` |
| `pipeline_depth` | orchestrator | 1 | Requests computed after the head on the speculative state; 0 computes the head only; at most the reader's lookahead (4). One ahead hides one round's latency behind the relayer's transaction; each speculative round is a full MPC round under the global session lock, wasted when the head is skipped or superseded. At 2 or more, an entry pipelined on an attempt that left a node-held key's commitment unchanged waits until the entry before that attempt lands (ARCHITECTURE.md section 6, "Node-held state"). | `machine/sidecar-orchestrator/src/config.rs` (`pipeline_depth`) |
| `[[tip.namespaces]]` `contract` | all four | at least one entry | The allowlist (`sidecar_tip::TipNamespace`): one entry per tip contract the machine serves, each the app contract's address alone, each contract once; the operator writes the same list into the four files. A namespace is driven when it is both listed and registered with a tip contract manifest (one with a queue); a node that does not list it refuses every round of it. | `machine/sidecar-tip/src/config.rs` (`TipNamespace`) |

Everything else about a namespace comes from its registered contract manifest
(ARCHITECTURE.md section 7, "The contract manifest"), which pss-client generates from the
compiled contract, so no slot is copied into a config file (`sidecar_tip::TipLayout`): the
queue's slot, the stored stale period's slot, the `Configured` flag's slot, the
`SharedOnchain` slot, each package's request keys, the plain reads, and the init round with
its input slots. The scheduler reads them from the orchestrator's registry copy, and each
node's chain verifier and receipt chain view from the node's own store, at each round. The
machine reads declared slots only at the namespace's own address, so a wrong declaration
costs that namespace's liveness and nothing else: a wrong slot reads zeros, an unconfigured
contract (nothing runs) or an input the request id then does not match, which every node
refuses. The stale period is the contract manifest's too ("Liveness").

Before a round, the scheduler and each node's chain verifier compare the instance's current
contract class on their own Aztec node (`node_getContract` at the round's block) with the
contract manifest's `contract.class_id`, and under upgradable circuits read the contract's
circuit pins at that block and run a round only under the contract manifest version the pins
name; while the class and the pins disagree, no round runs for that namespace (liveness
only). With an `init` in the contract manifest, the scheduler sends the init round once the
contract is configured and every slot the init creates is empty, and computes nothing before
(ARCHITECTURE.md section 6, "Deployment, configure and the init round").

### Fixed bounds (code constants a deployment changes in code)

| Key | Default | Meaning | Code |
| --- | --- | --- | --- |
| listener transport: `ListenerLimits` (`tls_handshake`, `header_read`, `max_connections`, `max_handshakes`), `TLS_HANDSHAKE_TIMEOUT`, `WRITE_STALL_TIMEOUT`, `PUBLIC_LISTENER` | handshake 10 s; request head 30 s; write stall 30 s; node 512 connections and 512 handshakes (`sidecar-node` `api.rs`); orchestrator public 256 and 256 | One implementation for the node's mutual-TLS listener and the orchestrator's public one. An unfinished TLS handshake is closed after 10 s; a request head (also the wait for a kept-alive connection's next request) must arrive within 30 s; a write that makes no progress for 30 s ends the connection. At most `max_handshakes` connections are in or just past their handshake at once (the accept loop waits, so further clients wait in the kernel's backlog and hold no task); a connection takes one of the `max_connections` slots only once its handshake is done, so at the node only a holder of a CA-signed client certificate takes one. The node's cap is twice the public one because each public FETCH or GET holds one connection to each node. Silent connections can still fill a port's handshakes (about 52 a second at the node) and delay new connections, so a deployment firewalls the node's API port to the orchestrator. These are the only bounds a public client meets before a route runs; with the 4 MiB public body limit they bound the buffered bodies at 1 GiB. Requests have no handler timeout: the mesh timeouts bound a round at the node, the node call timeout at the orchestrator. | `machine/sidecar-http/src/listen.rs`, `machine/sidecar-orchestrator/src/server.rs` |
| node body limit: `MAX_BODY_BYTES` and body read timeout | 32 MiB; 60 s | REGISTER bodies are the largest (each circuit stripped to its ABI and bytecode: lending's 11 are about 0.3 MB). The node is reached only by the orchestrator, so this sits above the public limit; a deployment with larger circuits raises both. Too large: 413; not arrived 60 s after its head: 408 (class `bad_request`, `sidecar_http::listen::read_body`). | `machine/sidecar-node/src/api.rs` |
| public body limit: `PUBLIC_MAX_BODY_BYTES` and body read timeout | 4 MiB; 60 s | Bodies are buffered whole before a route runs, so this times the connection cap bounds what clients make the orchestrator hold. With at most 32 packages per contract manifest it leaves room for circuits many times lending's; raise it for larger circuits, up to the node's 32 MiB. 413 and 408 as at the node (60 s for 4 MiB asks about 70 KB/s). | `machine/sidecar-orchestrator/src/api.rs` |
| public session waiting room: `PUBLIC_WAITING_PER_NAMESPACE`, `PUBLIC_WAITING_TOTAL`, `RETRY_AFTER`, `SCHEDULER_SESSIONS_PER_PUBLIC` | 4 waiting sessions per namespace, 32 in all; `Retry-After: 10`; a public session after 4 scheduler sessions in a row | The global session lock serves the scheduler's sessions and the operator's pause before a waiting public session (execute, REGISTER, DISABLE), except that after 4 scheduler sessions in a row a public session goes next, so busy queues cannot hold a DISABLE or a sidecar-path execute for ever (a cost of at most one scheduler round in five). One public session past either bound is answered 503 with `Retry-After`, so public traffic cannot hold a scheduler until its head goes stale, nor one namespace fill the room. | `machine/sidecar-orchestrator/src/gate.rs` |
| node answer caps: `MAX_ROUND_ANSWER_BYTES`, `MAX_REGISTRY_ANSWER_BYTES` | 4 MiB per round answer; 64 MiB per registry answer | Every node answer is read under a cap by route class, so a node that streams without end fails its call (a transport failure naming it). | `machine/sidecar-orchestrator/src/nodes.rs` |
| answer size caps: `DEFAULT_MAX_ANSWER_BYTES` (`ApiClient::with_max_answer` lowers it) | 64 MiB | The default cap of any node-API client call: twice the node's body limit, the largest answer class. Callers that know their route class lower it. | `machine/sidecar-http/src/client.rs` |
| relayed refusal text: `MAX_RELAYED_MESSAGE_BYTES` | 1 KiB | One node chooses its refusal message, which reaches the client and the log through the orchestrator, so the orchestrator cuts it to 1 KiB at a character boundary. | `machine/sidecar-orchestrator/src/nodes.rs` |
| registry check bounds: `REGISTRY_CHECK_DEADLINE`, `MAX_CHECK_ROW_BYTES` | 5 min per run; 256 MiB of rows per node | One node chooses how many rows the check reads and how large; a listed name that is no package name, more than 256 MiB from one node, or a run past five minutes stops the run (unread, naming the reason). Five minutes is under the timer's ten, so runs do not pile up. | `machine/sidecar-orchestrator/src/sync.rs` |
| concurrent vk builds: `MAX_CONCURRENT_VK_BUILDS` | 2 at once | A REGISTER body whose owner signature verifies costs a vk build per circuit (seconds of CPU and the circuit's memory) before the session lock, and anyone can sign a `seq` 0 body for a new namespace; at most two bodies are built at once, on blocking threads, and a third waits. Rounds build no vk: the verifier is decoded from the stored vk. | `machine/sidecar-orchestrator/src/api.rs` |
| REGISTER ABI bounds: `MAX_ABI_FIELDS`, `MAX_ABI_WALK` | 2^20 field elements; 2^26 path bytes | The largest ABI REGISTER accepts, over every parameter and the return value, and the largest walk it makes of one (each node costs its path's length plus one): together they bound what a hostile REGISTER body can make a node allocate and how long the walk takes. | `machine/sidecar-core/src/abi/mod.rs` |
| Postgres pool size: `DEFAULT_MAX_CONNECTIONS` (`PostgresStore::connect_with` takes another) | 8 connections, on a store runtime of two worker threads | A node runs one round per namespace and one mesh session at a time, so its store traffic is a few reads and one commit per round plus FETCH and the pruning job; 8 leaves room for concurrent FETCHes. A larger pool costs Postgres memory per connection; a smaller one makes FETCH wait behind a commit. | `machine/sidecar-node/src/postgres.rs` |
| Aztec node RPC timeout: `DEFAULT_RPC_TIMEOUT` (`HttpTransport::with_timeout`) | 10 s per call, connect to last byte | A storage read or log query answers in milliseconds and a simulation in well under a second (about 0.4 s on a local 6.0.0 network), while a block takes about 6 s: a node silent for longer than a block is treated as down. A slower node fails every read and delays the queue (liveness only, invariant 13). | `machine/sidecar-tip/src/chain/rpc.rs` |
| Aztec node answer size: `DEFAULT_RPC_MAX_ANSWER` | 16 MiB per answer | The largest answer the reader takes is a tag query's (up to 100 tags of 20 logs each, a few MiB); the cap keeps a hostile or on-path Aztec node from filling memory. | `machine/sidecar-tip/src/chain/rpc.rs` |
| logs per tag: `MAX_PAGES_PER_TAG` | 50 pages of 20 logs | Every tag the tip reads holds a log or a few per chain request, so 1,000 logs under one tag is a node that keeps answering full pages; the read stops there with an error. | `machine/sidecar-tip/src/chain/logs.rs` |
| reader lookahead: `DEFAULT_LOOKAHEAD` | 4 entries after the head | The reader reads `requests[head]` and up to 4 entries after it, never past `tail`, one storage read per entry per snapshot. At about 4 to 5 s per round and 6 s per block a pipelined scheduler runs at most a block or two ahead, so four cover it. `pipeline_depth` is capped at it, and the chain verifier accepts a pipelined request only within it. | `machine/sidecar-tip/src/chain/mod.rs` |
| reload lookback: `RELOAD_LOOKBACK` | 64 queue entries | A chain-held reload searches the 64 entries before the head and then the init round for a sealed-thirds log matching the slot's commitment. It needs the package that produced the log to decode it. A no-op apply refreshes the log for an unchanged slot among the round's outputs. A run of 64 entries without an apply that wrote the slot (skips, or applies of rounds that do not write it) can put the last matching log outside the window. When no matching record can be recovered, the scheduler stops for that namespace. | `machine/sidecar-tip/src/state/chain.rs` |
| receipt standing scan: `DEFAULT_STANDING_SCAN`, `DEFAULT_STANDING_TIMEOUT` | 4,096 entries; 120 s per run | When a receipt past its window has its request id `seen`, the pruning job reads `requests[head..tail)` (one storage read per entry, at most 4,096, within 120 s) to tell a queued request from a done one. A request not found is kept: the bound can only keep inputs longer. A queue longer than the bound, or a silent Aztec node, keeps the receipts (and says so). | `machine/sidecar-tip/src/standing.rs` |
| block hashes kept, node-held version retention, receipt pruning and `enc` retirement (no knob; `ChainReader::settled`) | back to the finalized tip | The chain reader keeps `(number, hash)` for every block from the proposed tip back to the finalized tip, so a replacement voids exactly the reads above the last block both chains share; each node keeps orphaned versions, receipts and retired `enc` scalars until the finalized tip passes them ("Replaced blocks"). The cost follows L1 finality: a few hundred blocks of hashes (tens of kilobytes) per reader and the orphans of the same span per node. Under a finality stall both grow with no cap: each reader logs every doubling of the hashes it holds, the orchestrator's `GET /v1/status` reports each scheduler's reader (`readers`: the four tips, the settled block, the hashes held), and both shrink once the finalized tip moves. | `machine/sidecar-tip/src/chain/mod.rs`, `machine/sidecar-tip/src/chain/follow.rs`, `machine/sidecar-core/src/store/versions.rs` |

### pss-client (`PssClientConfig` and the deployment helpers)

pss-client's other module parameters are in [its README](../ts/pss-client/README.md),
"Parameters".

| Key | Default | Meaning | Code |
| --- | --- | --- | --- |
| `allowInsecureHttp` | false | `orchestratorUrl` must be `https:`; a plain `http:` URL is refused with ConfigError unless true, for local tests against a mock or loopback orchestrator only. Every secret is sealed to the pinned node keys and every answer checked against them, so plain TCP lets no observer open a share or forge a result, but it shows public values, keys, request ids and results to anyone on the path, and the request id alone scopes FETCH. | `ts/pss-client/src/config.ts` |
| `nodeKeys` | none (required) | Each node's `enc` and `sig` public keys, node 0 first, part of the deployment's published identity. `checkNodes()` compares all six with `GET /v1/nodes` and refuses any difference, naming node and key. Taking keys from the orchestrator would let it substitute its own three, decrypt every share and re-encrypt to the real nodes unnoticed, so a key rotation needs a configuration update here (or a `keyEpochNode`). | `ts/pss-client/src/config.ts` |
| `vkHashes` | none | Per circuit name, the vk hash the contract pins (poseidon2 of the bb vk fields, `vkHashFromFields`). The client refuses to build a request for an unpinned circuit and refuses a response with another vk hash before any transaction is built, which also catches a namespace registered with a circuit other than the contract expects. | `ts/pss-client/src/config.ts` |
| `circuits` | none | Per circuit name, the nargo output JSON (or its `abi`) and manifest as sent to REGISTER: the note-hash public-input indices (`outputNoteHashIndices`) rebuild the result message each node signed, and the state modes decide whether a request must be signed. A circuit without an entry cannot be executed or fetched (ConfigError); another circuit or manifest fails every answer with ResultSignatureError. An optional `aliasOf` names the target whose result reader an alias uses. The alias's vk hash must equal the target's. Client construction refuses two result readers for the same vk hash. | `ts/pss-client/src/config.ts` |
| `contractAddress` | none | The namespace of every request. Another deployment's address sends requests into an unrelated namespace. A client that only REGISTERs a new namespace (`deployTip`'s registry) leaves it out; every request then refuses. | `ts/pss-client/src/config.ts` |
| `timeoutMs` | 120,000 ms | How long one `POST /v1/execute` may take before the client switches to FETCH (a round is about 5 s for the AMM swap on the reference machine, far longer for larger circuits). Too short: slow rounds go through FETCH (harmless, slower); too long: a dead orchestrator blocks the caller that long. | `ts/pss-client/src/config.ts` |
| `fetchRetry` (`attempts`, `initialDelayMs`, `maxDelayMs`, `timeoutMs`) | 6 attempts, 1 s doubling to at most 16 s, 15 s per call | After a timeout or transport error on execute the client FETCHes the same request id with backoff, never a new body; after the bound the caller may `resend()` the saved body, which the nodes answer from their rows or run once. A rebuilt request is a new round. Which failures are retried: `recover()` in `execute.ts`. | `ts/pss-client/src/config.ts` |
| `verifyProof` | off | An optional hook verifying the returned proof (for example bb.js against the circuit's vk) before a transaction is spent on it; throw or resolve false to refuse. Turn it on when the orchestrator is not trusted for liveness, so a bad proof fails in seconds instead of at client-side proving. | `ts/pss-client/src/config.ts` |
| `receiptTtlBlocks` | 300 (the orchestrator's and nodes' default) | `obtainIntake` refuses (ProtocolError) an answer whose expiry is not after the current block or more than `receiptTtlBlocks` after it: the client's own bound on how long the nodes hold its inputs. Set it to the deployment's published TTL; a value below the orchestrator's refuses every receipt. | `ts/pss-client/src/config.ts` |
| `receiptMarginBlocks` | 20 blocks (about two minutes) | `TipReceipts.expiresSoon` at block b when `b + receiptMarginBlocks >= expiry_block`: an intake transaction built then may land at or after expiry, where `append` reverts and the client-side proving is wasted. Larger asks again more often; smaller risks a late landing. | `ts/pss-client/src/config.ts` |
| `keyEpochNode` | none: the pinned `nodeKeys` | An Aztec node the client reads the app contract's key epoch from (ARCHITECTURE.md section 6, "Node replacement and key epochs"), so it follows a node replacement without a new configuration: result signatures under the current key set or, inside its grace window, the previous one; receipts, `GET /v1/nodes` and envelopes under the current set. The read is trusted: a lying node can make the client refuse answers, accept signatures the contract would refuse, or seal shared inputs to keys the network does not hold. The relayer passes its own node. | `ts/pss-client/src/config.ts` |
| `manifestHash` | none: fixed circuits | Under upgradable circuits, the hash of the contract manifest version `vkHashes` come from; every receipt request names it, and the request id is computed under it. After an upgrade a client reads the pins in force (`readCircuitPins`) and calls `PssClient.adoptManifest` with the version they name (`getManifestVersion`); a client on the replaced version has its receipt requests refused (400). | `ts/pss-client/src/config.ts`, `ts/pss-client/src/upgrades.ts` |
| request store (`RequestStore`; `MemoryRequestStore`, `JsonFileRequestStore`) | in memory | The client saves the request id and exact body before sending, until the caller discards it once the transaction is mined and the notes' nonces are taken from it (`nonces.ts`). Memory survives a lost response, not a crash: without a durable store a crash after sending loses the only way to FETCH the round, and a node-held key stays ahead of the chain until an operator intervenes. | `ts/pss-client/src/store.ts` |
| record store (`RecordStore`; `MemoryRecordStore`, `JsonFileRecordStore`) | in memory | A record is the only copy of a client-held state outside the nodes' `requests` rows (pruned after their retention window); losing it loses the state. Older records are kept (a round that never lands is recovered by the operator's rollback, after which the previous record is presented again); prune them once a later round has landed. | `ts/pss-client/src/records.ts` |
| `deployTip` salt (`options.salt`) | a fresh `randomField()` per deployment, secret until the deployment lands | Whoever learns the salt before the deployment lands can compute the address and REGISTER under it first, taking the namespace so `configure` never completes. A chosen salt is for reproducible test deployments only; after a leak or a failure part way, a new salt is a new namespace. | `ts/pss-client/src/deployment.ts` (`deployTip`) |

### pss-relayer

| Key | Default | Meaning | Code |
| --- | --- | --- | --- |
| `account` (`RelayerAccount`) | none (required) | An initializerless Schnorr account (usable at once) from the operator's secret key, signing key and salt, given inline or as `keyFile` (refused unless only its owner can read it), or `"local-network"`, the local network's first genesis-funded test account, only when named and only on a local network. Any account works, since result submission and `skip()` are permissionless. It pays every result and skip (through wFJ, from its private balance), and its address is public in every transaction it sends. A deployment takes the secret from the operator's key store. | `ts/pss-relayer/src/aztec.ts` (`RelayerAccount`) |
| `aztecNodeUrl`, `statusPort` | `http://127.0.0.1:8380`, 3301 (the tip harness's ports, [e2e/README.md](../e2e/README.md), "Ports") | The Aztec node the relayer reads and sends through, and its status endpoint; the orchestrator URL comes from the pss-client configuration. The status endpoint binds loopback only and reports what the relayer last did (no secret); 0 turns it off. | `ts/pss-relayer/src/main.ts` |
| `pollIntervalMs` | 2,000 ms (a third of a proposed block) | The relayer reads the queue once per period (one `getBlockNumber`, one `getBlockData` and up to four storage reads pinned to the block hash). Ticks never overlap: a tick that sends waits for the transaction to be mined, and the next starts one period after it ends. Shorter costs RPCs and FETCH calls; longer delays each landing by up to a period. | `ts/pss-relayer/src/relayer.ts` |
| `maxSameResultSends` (`RelayerOptions`) | 2 | Reverted sends of one result before the relayer waits for a newer attempt or `skip()`. A same-height block replacement also releases held results. Identical send failures other than reverts start doubling the retry delay after the second failure, up to 32 skipped ticks. `GET /status` reports `submit-backoff` with the error, repeat count and ticks until the next send. | `ts/pss-relayer/src/relayer.ts` (`RelayerOptions`) |
| `upgradeArtifacts` | none | Under `upgrades: contract`, the compiled artifacts of the app's other classes. At start and once per poll period the relayer reads the instance's current class and registers the instance in its wallet with the artifact that builds it (pss-client `followContractClass`); without it the relayer's transactions fail once a class upgrade takes effect, until it is restarted with the new artifact. | `ts/pss-relayer/src/main.ts` |
| `rotate-enc-key` configuration: `aztecNodeUrl`, `adminSocket`, `party`, `contracts` (each `address`, `artifact`, optional `epoch`) | all required but `epoch` (the stored one + 1); `account`, `fee` and `proverEnabled` as the relayer's | ("Rotating a node's `enc` key".) `adminSocket` and `party` are the node config's, and the node's answer is checked against `party`; `epoch`, when given, must be the stored one + 1, so a stale configuration fails before signing; `aztecNodeUrl` is naturally the node's own `[tip] aztec_node`. The transaction pays as the fee kind `configure` (about 1,000 DA and 750,000 L2 gas measured). It stops at the first failure; a rerun signs the failed contract's epoch again, and a contract whose stored key is already the signed one gets only the prune. | `ts/pss-relayer/src/rotate-enc-key.ts` (`FileConfig`) |

### Library and example parameters

Parameters of modules without a README of their own, each documented at its definition:

| Module | Parameter | Default | Meaning |
| --- | --- | --- | --- |
| pss_core | `MAX_OUT_NOTES` (`mpc_store.nr`) | 8 (1 to 10) | the most notes one round hands to the machine (`out0` to `out7`) |
| pss_public_contract | `PinnedRead.l2_gas` (`result.nr`) | 100,000 (`DEFAULT_PINNED_READ_L2_GAS`) | the L2 gas a pinned read's static call gets: caps what a bad target costs the submitter; too little fails every result that reads it (liveness only) |
| examples/amm | `SEED_RESERVE_BASE`, `SEED_RESERVE_SPAN` (`pool.nr`) | 1,000,000 each | the range the starting reserves are drawn from; a change changes `amm_init`'s vk |

## Recovery

A node's state is its key directory and its store (the Postgres database, or the local
store's directory). The key directory holds `enc.key`, `sig.key` and `master.share` (which
`setup` writes), `enc.previous.key` and `enc.rotated_at` during an `enc` rotation window,
`enc.epochs.json` under secret-shared on-chain intake, `key_epochs.json` after a node
replacement, `refresh.json` while one runs, and `store.unverified` while a resync's import
has not passed its checks. The orchestrator's registry directory is a convenience:
`sync-registry` rebuilds it. Rep3 gives every component of a value to two nodes: node i
holds `(x_i, x_{i-1})`, so node i + 1 also holds `x_i` and node i - 1 holds `x_{i-1}`; the
recovery mechanisms are in ARCHITECTURE.md section 6, "Node-held state", recovery. The
cases:

| Lost | What is gone | What the operator does |
| --- | --- | --- |
| one node's store, its key directory intact | that node's rows | restore its store backup with a delta from its two neighbours, or without a backup resync it from them |
| one tip key at one node (its slot names a commitment the node does not hold, or its clear tree diverged) | that key's versions or tree at that node | resync that key from the two neighbours |
| the registry of one node (several registry bodies behind) | its namespaces' `seq` and the `packages` rows written since | resync its registry from a neighbour that agrees with the third node |
| one node's key directory | its `enc` and `sig` scalars, which exist only on that node | restore the key directory from its backup and restart; without one the node is replaced |
| a node replaced (compromised, or leaving the deployment) | the departed node's pairs (retired by the refresh), its record thirds and its envelopes | node replacement: pause, share refresh, newcomer import, audit, the new key set declared to every contract, resume; chain-held namespaces are a new deployment |
| two nodes' stores | the node-held state: the remaining node holds two of each value's three components | nothing recovers it, exactly as two lost key shares already lose every secret; clients and apps start over on a new deployment |

**What every multi-node procedure shares.** Resync, restore, audit, the registry resync and
node replacement run on all three nodes at once, as one MPC session over the mesh on each
node's admin socket; nothing passes through the orchestrator. Stop the orchestrator first
(no round can run while one node's store is empty anyway; a node replacement pauses it
instead). `--pins nodes.json` is the deployment's pinned public keys of all three nodes, in
the `GET /v1/nodes` form (the keys published at setup, not the orchestrator's answer); each
node refuses pins whose own entry is not its keys. A node running a resync or a replacement
refuses rounds, REGISTER, DISABLE and receipts (500) until the session ends. Each node marks
its node-held versions against its own Aztec node, under each namespace's lock, right before
it collects its bundle, picks its audit targets or writes a backup, so neighbours that last
pruned at different times send and audit the same versions; if a node's Aztec node does not
answer and the bundles then differ in a namespace's versions, or the audit says a node holds
no canonical version of a key, rerun once every node's Aztec node answers at the same tip
before reading it as lost state. Each node prints a report (what was imported or sent, the
namespaces checked, the audit per key) and fails if any key failed.

### Resync of a lost store

Brings back the `namespaces` rows with their `nsk_app` shares, the packages, every canonical
and live version of every tip key with the nodes of its clear tree, the holder blobs of the
oblivious keys, the sidecar path's `values` rows and consumed set, the dead records (the
client-held records rolled-back rounds created), the non-secret-shared receipt rows and the
master share.

1. Stop the orchestrator.
2. Start the lost node on an empty store with its key directory as it was. It refuses every
   round until the resync is done.
3. On all three nodes at once:

   ```sh
   sidecar-node resync --config <node config> --lost <i> --pins nodes.json
   ```

   Each neighbour sends the lost node a bundle signed with its `sig` key: the rows in the
   clear, and the component it shares with the lost node of every shared value and blob,
   sealed to the lost node's pinned `enc` key. The lost node checks both signatures against
   the pins, requires the two bodies to agree, rebuilds its pairs, requires the rebuilt
   master pair to equal its key directory's and imports every namespace. It keeps a
   receipt-intake row only when both neighbours hold it alike and its signatures and ids
   check, and signs it again. Then the three check each namespace's `npk_app_hash` (the
   registration circuit runs on the master shares), the rebuilt `nsk_app` pairs, every
   `values` row's and holder blob's components against the neighbours', and audit every
   canonical version ("Audit").
4. Read the reports, then start the orchestrator.

What a resync does not bring back: the secret-shared receipt intake rows (an envelope was
sealed to the lost node alone) and any receipt-intake row the two neighbours do not both
hold alike (sidecar-tip `receipt_resync`), so a queued request whose receipt is not back is
refused at that node and its head is skipped after `stale_blocks`; the `requests` rows, so
FETCH of an earlier round from this node answers 404 (the scheduler recomputes instead of
resending) and an earlier round cannot be rolled back at that node; and orphaned versions
(the retention starts again from the resync). The report counts the receipt rows left out.

A resync imports before it checks: the importing node first writes `store.unverified` into
its key directory and removes it only when every check passed. If the resync fails or the
node crashes before the checks end, the file stays and the node refuses every round,
REGISTER, DISABLE and receipt (500), after a restart too, until a resync passes: empty its
store again and rerun the resync. A resync into a store that holds any namespace is refused.

### Resync of one key

A node that refuses rounds on a key because its slot names a commitment the node holds no
version of (a chain view that lied, or a result the node did not commit), or whose clear
tree diverged, needs only that key back. Stop the orchestrator, then on all three nodes at
once:

```sh
sidecar-node resync --config <node config> --lost <i> --pins nodes.json \
  --namespace 0x... --key <key>
```

Each neighbour sends the namespace's row and its canonical and live versions of the key with
their tree nodes, sealed and signed as above. The node requires its own namespace row to be
the one the bundles rebuild (otherwise resync the whole store), then one commit replaces its
versions and tree nodes of the key with the rebuilt ones, and the three audit the key. The
namespace's other keys and rows are untouched. A key the neighbours hold no canonical or
live version of is refused; for a failed run, run it again.

### Resync of one node's registry

A node several REGISTER or DISABLE bodies behind (its commits failed while the other two
committed them, so it refuses each later body as out of order) needs only its registry rows
back. With the orchestrator stopped, on all three nodes at once:

```sh
sidecar-node sync-registry --config <node config> --lost <i> --from <j>
```

with `<i>` the node behind and `<j>` the neighbour it takes the rows from. Every node
compares node `<j>`'s rows with the third node's; a row those two hold otherwise refuses the
resync at all three (409, naming each row), so bring them level first (resend the body that
diverged between them). Node `<j>` then sends node `<i>` the circuit of each package `<i>`
holds otherwise or not at all; node `<i>` builds each vk itself under its own CRS, requires
it to hash to the agreed vk hash, writes the packages with the agreed manifest, disabled
flag and `seq`, and advances the namespace's `seq`. Its `namespaces` rows keep their
`nsk_app` shares. The report counts `repaired`, `namespaces`, `packages` and (at node `<i>`)
`vks_built`; a second run finds nothing to do. Refused at all three (409, naming each with
its repair): a namespace node `<i>` holds no row of (resend the `seq` 0 REGISTER while `seq`
is 0, or resync its store), another owner or `npk_app_hash`, and a `seq` or a package node
`<i>` holds ahead of the other two (resend the body only it committed). Then start the
orchestrator; its check at start reports the three agree. The resync copies only the newest
contract manifest version of a namespace ("Limits").

### Audit

```sh
sidecar-node audit --config <node config> [--namespace 0x...]
```

For each tip key's canonical version (live versions are not audited: the scheduler
recomputes their entries), the session handshake compares the pairs, and the machine's
audit circuit recomputes the commitment of a flat key or the hash of each stored leaf of a
tree and compares it with the commitment and the clear tree's leaf hashes (ARCHITECTURE.md
section 6, "Node-held state", the audit). Each key's `outcome` is `"passed"`,
`{"failed": <why>}` or `{"not_audited": <why>}`; a tree held in its holder's blobs (the
oblivious tree) is not audited, counts as no failure, and the CLI names it on standard
error. The audit writes nothing. One round takes 16 hashes of at most 16 fields (a flat
vector of up to 13 elements, a leaf of up to 12; a longer vector fails the audit); a tree of
`n` stored leaves takes `ceil(n / 16)` rounds (the report's `rounds`), and the first chunk
that fails fails the key. The chunk size is the circuit's, not a setting. An audit of a large
tree holds the mesh for all its rounds, so run it when no round is due (the orchestrator
stopped). The resync and the restore run the same audit.

A handshake failure names a component whose two holders hold different copies: after a
resync, the neighbour that sent it sent something other than what it holds, and the
operator empties the lost node's store and resyncs again. A circuit failure means both
holders hold the same wrong component: no two nodes hold it correctly, so the key's state is
lost, as with two lost stores, and the app starts the key over on a new deployment.

### Backups

Each node backs up its store and, separately, its key directory, each as one file encrypted
(ChaCha20-Poly1305) under a backup key its operator holds offline. The key is 32 random
bytes, never derived from the node's keys and never kept on the node's disk; it travels in
the command only.

```sh
sidecar-node backup-key --out /media/offline/node1.backup-key     # once: a fresh key; keep it offline
sidecar-node backup-keys --config <node config> --backup-key /media/offline/node1.backup-key \
  --out /backups/node1-keys-<date>                                # after setup, every rotate-enc and every landed key rotation
sidecar-node backup --config <node config> --backup-key - \
  --out /backups/node1-store-<date> < /media/offline/node1.backup-key   # the store, on a schedule
```

`--backup-key` is the key file's path, or `-` to read it from standard input, and is refused
inside the node's key directory, run directory or local store directory; `--out` is a new
file (never overwritten, mode 0600), which the operator copies off the host.

`backup-keys` reads the config's key directory itself; take it after `setup`, after each
`rotate-enc` (not during one) and after each rotation into a secret-shared on-chain contract
lands. A key backup taken before the last `rotate-enc` restores the old `enc` key, and
records sealed since under the new key no longer open.

`backup` goes through the running node's admin socket and reads each namespace under its
lock (marking its versions first; if the Aztec node does not answer, it backs up on the
marks it holds and logs a warning), so rounds go on around it. The file holds every
namespace row with this node's `nsk_app` pair, the packages, every canonical and live tip
version with the nodes of its clear tree, and the `values`, `consumed`, `receipts` and
`requests` rows; orphaned versions and the dead records are left out, and a restore takes
both from the neighbours. A backup restores into the same node only, and only from a file
of the store backup format this node reads (`restore-backup` refuses another, naming both
formats). How often to back up is the operator's choice: a restore takes from the
neighbours whatever was written since, so an older backup costs only a larger delta, and
what only the backup can bring back (the `requests` rows, the secret-shared receipt intake
envelopes) is as old as the backup.

### Restore of a lost store from its backup

With the key directory intact (restore it first if it was lost too):

1. Stop the orchestrator.
2. Start the lost node on an empty store with its key directory. It refuses every round
   until the restore is done.
3. On all three nodes at once:

   ```sh
   # the restored node
   sidecar-node restore-backup --config <node config> --lost <i> --pins nodes.json \
     --backup /backups/node<i>-store-<date> --backup-key /media/offline/node<i>.backup-key
   # each neighbour
   sidecar-node restore-backup --config <node config> --lost <i> --pins nodes.json
   ```

   It is a resync with a delta: the restored node opens its backup (refused under another
   key, if changed, or if it is another node's) and tells the neighbours what it holds; they
   send the components only of what was written since. The neighbours' bodies decide what
   exists (a version pruned or a row rewritten since the backup is not brought back, and the
   dead records are the neighbours' set); the master and every `nsk_app` come from the
   neighbours. The node imports with the backup's `requests` rows and the receipt rows the
   neighbours did not bring back (a secret-shared receipt intake envelope comes back only
   this way), and the checks and the audit run as after a resync.
4. Read the reports (`imported.from_backup` counts the vectors taken from the backup), then
   start the orchestrator.

A restore does not bring back the `requests` rows and the secret-shared receipt intake rows
created after the backup. If it fails, empty the store and rerun it, or resync without the
backup.

### Restore of a lost key directory

With the node stopped:

```sh
sidecar-node restore-keys --config <node config> --backup-key /media/offline/node<i>.backup-key \
  --backup /backups/node<i>-keys-<date>
```

It writes the key files into the config's key directory (mode 0700, files 0600), refusing
another node's backup and a directory that holds any key file. Then start the node; if its
store was lost too, restore it or resync it.

### Node replacement

For a node compromised, leaving, or whose key directory is lost without a backup. The two
remaining nodes refresh their shares and a newcomer takes the departed node's index
(ARCHITECTURE.md section 6, "Node replacement and key epochs"):

1. `sidecar-orchestrator pause --config <orchestrator config>`: it returns once the round in
   flight has ended; queued requests wait (and age against `stale_blocks`).
2. On the newcomer's host, with a config of party `<i>` (the departed index), an empty store
   and an empty key directory: `sidecar-node setup --config <newcomer config> --newcomer`.
   It prints the newcomer's `enc` and `sig` public keys (save them as `newcomer.json`); give
   them and the newcomer's mesh certificate to the remaining nodes' operators, who put the
   newcomer in party `<i>`'s place in their mesh configs and restart their nodes.
3. On all three at once (the newcomer not yet served):

   ```sh
   sidecar-node replace-node --config <node config> --departed <i> --newcomer newcomer.json \
     --pins nodes.json
   ```

   with `nodes.json` the current key set (the departed node's keys in its place). The two
   remaining nodes refresh every pair they hold and delete their `requests` rows; the
   newcomer imports its pairs from them and installs its master share; all three check every
   namespace's `npk_app_hash` and `values` pairs and audit every canonical version; then the
   remaining nodes sign the new key set for every `[tip]` namespace whose contract manifest
   says `node_keys: rotating`, at its next key epoch. Each node prints one
   `{"rotate_keys": {"namespace", "epoch", "keys", "signatures"}}` line per such contract
   and one `{"redeploy": "<namespace>"}` line per registered tip namespace whose manifest
   says `fixed`, and fails if any key failed the audit (nothing is declared then). A failed
   run can be run again: the remaining nodes keep the refresh seed and the run's generation
   in `refresh.json`, so no mask is applied twice; a failed newcomer is set up again from an
   empty store.
4. Submit each contract's `rotate_keys(epoch, keys, signatures)` with the printed arguments
   (the departed node's signature as zeros), from any account. A contract with a fixed key
   set (`FixedKeys`, `node_keys: fixed`) has no `rotate_keys`: its namespace gets nothing
   computed from the resume on; its app is redeployed under a new salt (REGISTER,
   `configure`, its init round), its old queue drains through `skip()`, and a tree's owners
   exit through the escape hatch.
5. Start the newcomer with `serve`; write the new key set into the orchestrator's
   `[[nodes]]`, restart it with `--paused`, then `sidecar-orchestrator resume`, which
   refuses while the newcomer's registry differs from the others'. A namespace whose
   rotation has not landed yet gets nothing computed until it does; each node's pruning job
   reports the rotations still pending (`sidecar-node prune`).
6. Under secret-shared on-chain intake, the newcomer rotates its `enc` key into each
   contract (`sign-enc-key` or pss-relayer's `rotate-enc-key`, at the stored epoch + 1): the
   declaration voided the departed node's key there.
7. Destroy every backup taken before the refresh (it holds pairs of the old sharing), take
   new store and key directory backups on all three nodes, and give clients the new key set
   (or a `keyEpochNode`).

## Limits

### The machine and the sidecar path

- **A lost node store.** A resync brings back everything but the `requests` rows: FETCH of an
  earlier round from that node answers 404, and an earlier round can no longer be rolled
  back there. A restore from a store backup brings them back as old as the backup. The local
  store holds no `values`; its consumed set comes back.
- **A lost key directory.** Without `enc` the node's thirds of every client-held record no
  longer open; without `sig` the deployment's pinned signing key is gone (a node
  replacement, or a new deployment); without the master share no new namespace can be
  registered.
- **A lost record.** A client that loses a client-held record can FETCH it again by request
  id within the retention window; after it the state is lost. Give pss-client durable
  stores (the `store` and `recordStore` options, for example `JsonFileRequestStore` and
  `JsonFileRecordStore`); the default keeps both in memory. A third sealed only under a
  retired `enc` key is lost the same way.
- **What the research prototype does not authenticate.** Execute requests without
  client-held records or shared inputs (anyone may run an enabled circuit, and a node-held
  round anyone triggers but nobody lands needs the rollback procedure); FETCH (open to
  whoever holds the unguessable request id; the records it returns are ciphertext); the
  registry GETs and `GET /v1/nodes` (conveniences: pin the values REGISTER answered with
  three signatures, and pin the node keys). The public API has no client authentication,
  and nothing limits a client beyond the listener bounds ("Configuration reference",
  listener transport). The admin socket is protected by file permissions only.
- **The orchestrator is the availability bottleneck.** One execute, REGISTER or DISABLE
  session runs at a time across all namespaces (the global session lock; the nodes have one
  mesh session each); FETCH and the GETs take no lock. The scheduler's sessions go first,
  with the public waiting room's bounds ("Configuration reference", public session waiting
  room). A node that hangs inside a round holds the session lock up to the round bound
  (`node_call_timeout_secs`, 1,000 s), longer than the examples' stale window (50 blocks,
  about 5 minutes), so every namespace's head may be skipped meanwhile: a deployment whose
  rounds prove in well under that lowers the mesh `timeout` and `node_call_timeout_secs`
  together, keeping the call bound above the mesh bound plus the longest proof. While the
  orchestrator is down nothing runs, but nothing is lost: another orchestrator with the same
  config and a synced registry answers FETCH for every round still inside the retention
  window.
- **`sidecar-node setup --dealer` is for development only**: one process sees every secret.
  A deployment runs `setup` on each node, which samples the master share over the mesh.
- **No ECDSA inside a round circuit.** co-noir at the pinned co-snarks revision has no Rep3
  implementation of the two ECDSA black boxes, so a circuit that verifies an ECDSA signature
  cannot be proven by the network. Schnorr over Grumpkin (pure Noir) is the signature scheme
  for anything a round verifies; ECDSA stays in the contract (ARCHITECTURE.md section 6).
- **No integer shifts or bitwise ops in unconstrained code.** co-noir's Brillig VM at the
  pinned revision has no integer And, Or, Xor, Shl or Shr; a hint or oracle that uses one
  fails MPC witness extension (500) however the constrained circuit looks, and nargo and the
  TXE do not catch it. Inside a co-SNARK circuit use total-noir's entries (not those its
  page "co-noir compatibility of the library's hints" excludes) and check the artifact with total-lint's Brillig-ops report
  (ARCHITECTURE.md section 6).

### At the tip

- **Upgrades.** A resync of a node's store and a store backup carry every held contract
  manifest version, so a resynced or restored node runs rounds under the version in force
  while a newer one waits for its time of change. A resync of a node's registry and the
  orchestrator's `sync-registry` copy only the newest version: after one, a node or copy
  whose namespace's version in force is an older one runs nothing for it until the owner
  registers that version again at the next `seq`. A replacement that adds a state key or
  changes a key's layout is refused: there are no migration rounds, and such a change is a
  new deployment. A request queued under a replaced circuit is skipped, not answered; an app
  that escrows at request time refunds it in `skip()`, while the AMM tip and the credits tip
  take nothing at request time, so nothing is owed.
- **Deferred.** The `exact` binding and relayed intake: REGISTER refuses `binding: exact`,
  and relayed intake has no manifest value.
- **Replaced blocks.** A result built on a replaced block reverts at `apply`, and an outcome
  signed before its request was removed is known to its requester for free ("Replaced
  blocks").
- **Node replacement loses what was sealed to the departed node.** A replacement keeps every
  node-held value, but the departed node's client-held record thirds, chain-held thirds and
  secret-shared receipt envelopes are lost with its key: such records cannot run again (a
  planned departure re-seals live records first), chain-held namespaces are a new
  deployment, and queued secret-shared requests that named its envelope are skipped and
  resent. Two nodes gone is a new deployment.
- **Spam.** Under the hidden requester there is no identity to rate-limit, so a queued
  request costs the network an MPC round (and, under secret-shared receipt intake, node
  storage). The anti-spam is the usage deposit, a pinned amount of a pinned token per
  request: a skipped request and a request whose round did not serve it get it back, a
  request that is served pays it as the app chose (DECISIONS.md section 12).
- **A compromise of all three nodes** costs privacy and can freeze funds, never take or lose
  them ("Funds"). Under upgradable circuits only the upgrade authority's call changes the
  pins, and it checks no node signature. A tree's append index is enforced by the round
  circuit against the header's `next_index`, so no network can open a position the keeper
  never scans.
- **The escape hatch.** A frozen lending market (on every deployment) lets each owner exit
  once, privately, on its newest note of a position, by pushing that note's exit tag
  (ARCHITECTURE.md section 6, "The escape hatch"); a position liquidated any number of times
  exits on its newest notice. What remains: an owner round refused on the leaf's own state
  or kind (codes 4 and 5) re-blinds the leaf and names no position, so the owner's earlier
  note does not exit until its next round (only the owner's own request does this, and the
  contract's note check stops the kind case); nodes that keep landing rounds while refusing
  service keep the hatch shut. An owner sees no public log of the rounds that touch its
  position: it learns of one from its notice, or by checking whether its newest note's exit
  tag is spent.
- **What the orchestrator sees.** The requester's network address, `C`, the request id and
  the outcome tag on the receipt routes ("Who sees what").
- **Liquidation by sweeping.** Under a secret-shared intake nobody holds a lending position
  in the clear, so a liquidator finds unhealthy positions by probing, `K - 1` positions per
  queued round, and many liquidators sweeping is a lottery among them (DECISIONS.md section
  7); each probe tells the liquidator one health bit per probed position at the pinned
  price. The keeper round scans a window of `W = 8` positions per round and reports their
  health bits to the keeper alone (ARCHITECTURE.md section 6, "A read-only window on a tree
  key"; lending's `scan_shared` with pss-client's `keeperPass`).
- **Residual leaks.** Timing (proving time differs by circuit; redeems follow only some
  outcomes); the round type under the non-secret-shared intakes; the clear app inputs to the
  nodes and the orchestrator under secret-shared receipt intake, and to the world under
  secret-shared on-chain intake; the L1 deposits that fund wFJ balances.
- **Pinned-read freshness** and **chain-held state**: a fast-moving `exact` read starves the
  head ("Liveness"); chain-held state keeps every past state on chain as ciphertext for ever
  and holds at most 453 shared elements per output ("Chain-held state").
- **One queue and one lock per namespace**, and one global session lock in the
  orchestrator: a namespace's requests run one at a time in queue order (the scheduler
  pipelines up to `pipeline_depth` after the head), and every namespace shares the
  orchestrator's sessions.
- **What the real-proof scenarios show, and what they do not.** The tip scenarios run end to
  end with real proofs through the three nodes, the scheduler and the relayer on a local
  network, every transaction paid through wFJ: the init rounds, the AMM's secret-shared swap
  and a failed one, lending's secret-shared rounds with their outcomes opened and a borrow
  claimed, the non-secret-shared cases, each secret-shared request's transactions audited
  for what they show (`e2e/scenarios/README.md`). They do not show real block times, a
  sequencer's ordering inside a block, or the recovery from a replaced proposed block (the
  machine's tests cover it); the reorg scenarios, run on request on a local network with a
  custom launcher, cover L1 reorgs and an epoch prune.
- **The structure.** Every axis is one interface with one implementation per value, chosen
  once by the manifest or the configuration (ARCHITECTURE.md, "Axes, bricks and status").
  The accepted exceptions: the dozen `#[external]` wrappers each tip contract repeats
  (aztec-nr's macros cannot generate them on the pinned toolchain), one main per round per
  public-input layout (public outputs and private outcomes differ), the init round as a
  branch of the scheduler and the chain verifier, and the manifest and REGISTER rules as the
  one place that compares intake, state and outcome values.
