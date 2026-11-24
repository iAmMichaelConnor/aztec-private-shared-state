# Architecture

How the private-shared-state machine and its tip-of-chain extension work. This file is the
specification; the code wins where the two differ, and this file is then corrected.
[DECISIONS.md](DECISIONS.md) gives the reason for each rule; [DESIGN.md](DESIGN.md) covers
trust, who sees what, liveness, the operator's procedures, the configuration reference and
the limits; [design-guide/README.md](design-guide/README.md) takes an app developer from a
use case to axes, blueprints and bricks. Terms are defined once, in
[GLOSSARY.md](GLOSSARY.md). "Node i" is one of the three MPC nodes; "the orchestrator" is
the operator's front process; "the machine" is the Rust workspace; "on Aztec" names the
Aztec-specific Noir and TypeScript around it.

## Axes, bricks and status

An app is one value per axis, chosen once. The axes, their values, the bricks and each
brick's status (**built**, **experimental**, **kept option** or **deferred**) are those of
`design-guide/design-space.json`: the repository's README lists the axes, the generated
`design-guide/BRICKS.md` lists every brick with its layer, status and the library items an
app calls, and `scripts/check-design-space.py --plan` prints them per blueprint. One
interface per axis and one implementation per value: code above an interface never compares
an axis value.

Parameters (not axes; `design-space.json` `parameters`), with their defaults: `stale_blocks`
(50 L2 blocks), a tree's depth `D`, leaf width and probe width `K` (per app, measured), the
consume policy (`once`), the init strategy, access control (open), the outcome fields and
each pinned read's freshness (`exact`; "Pinned reads").

Fixed properties (`design-space.json` `properties`): the requester hidden from the chain and
the nodes under every intake ("The hidden requester"); every tip transaction paid through a
private fee-payment contract ("Fee payment"); verifiable delivery ("Verifiable delivery");
total, co-noir-compatible round circuits (gated by `scripts/check-noir.sh`); the round type
hidden under a secret-shared intake; one FIFO queue and one lock per namespace; one intake
family per namespace; deployment by secret salt and a once-only `configure`; one compiled
circuit per round per intake family.

An app developer writes an app library (the transition function and its validity checks,
total where the network proves it), a round table, the app's pins and its outcome fields.
The app developer writes the contract's request function, the client's request and each
round's main (`<round>` for both non-secret-shared intakes and `<round>_shared` for both
secret-shared intakes). `scripts/gen-intake.py` derives the manifests for the other intakes
from the round's hand-written secret-shared manifest and generates the secret-shared
commitment layouts. Every round of every tip example except its init round runs under
the default intake, secret-shared receipt intake. The non-secret-shared intakes run
on one round of the AMM tip and of lending (the swap, the deposit), on test deployments.
A round takes its inputs as private witnesses bound by `C = poseidon2(inputs, blinding)`.
The intakes differ in who computes `C` ("Secret-shared intake").

## 1. Module boundaries

One cargo workspace, `machine/`, with seven crates (and the four vendored GigaDORAM crates
under `sidecar-oblivious/vendor/`). User-side code is TypeScript under `ts/`.

| Crate | Kind | Responsibility | Never contains |
| --- | --- | --- | --- |
| `sidecar-core` | library | Everything that defines a round and can be tested in one process: wire types, field encoding, versioned manifest parsing, ABI checks, the witness binder, the AEAD and node keys, state records, the store trait with its memory backend and the local append-only store (`local`), the consumed set, Schnorr and Grumpkin, CRS and verification keys, the executor (witness extension, proving, self-verification), the registration and audit circuits, the request state machine (section 3) as a library call, the intake's rules (`intake`: direct or queued, picked once from the manifest), the state-holder seam (`state`: one implementation per state mode, chosen per key at REGISTER and load), the clear tree of a tree-valued key (`tree`), node recovery (`resync`, `store::blob`, `backup`, `audit`), the registry comparison (`registry_check`) and `admit`. Receipt rows reach a resync through the node's receipt hook (`resync::ReceiptResync`), which sidecar-tip fills. | sockets, TLS, Postgres, chain access |
| `sidecar-node` | binary, three instances | The node process: configuration and key files, the Postgres store, the pinned-TLS Rep3 mesh, the HTTPS API served to the orchestrator over mutual TLS, the operator-only admin socket (rollback, prune, `enc` rotation, store backup, resync of a lost store or one tip key, restore, audit, registry comparison), encrypted backups of the store and the key directory, the pruning job, logging under the request id. At the tip: the chain verifier and the receipt signer. | application logic, chain reads that affect soundness |
| `sidecar-orchestrator` | binary | The public HTTPS API, stateless request checks, global serialisation of sessions, fan-out with per-node projection, the agreement check, proof and result-signature verification, record assembly, FETCH, the registry copy (rebuilt from the nodes; compared with them at start, after each registry body and on a timer). At the tip: the chain reader and the scheduler. | secrets of any kind; any data the nodes do not also hold |
| `sidecar-http` | library | HTTPS plumbing both binaries share: TLS set-up, the bounded listener (connection cap, timeouts, body limits), JSON answers in the one error shape (section 8), the node API's mutual-TLS client, and the admin socket (0700 directory, 0600 socket, one JSON command per line). | routes, application logic |
| `sidecar-tip` | library | The tip additions shared by node and orchestrator: the queued-manifest view, the chain request id and the machine request id, the chain reader (`chain`, with its `LogSource` log discovery), the request synthesiser, the receipt message and signer (`receipt`), the `TipState` seam (`state`: the scheduler's, synthesiser's and chain verifier's view of a key, per state mode; `state::chain` the chain-held holder and its apply log; `state::tree` a tree-valued key's node-sourced paths), the `IntakeSource` seam (`intake`: one implementation per queued intake, including its `receipt_resync`), and `config` (`TipNamespace`, `AztecNode`). | a second store, a second pipeline |
| `sidecar-oblivious` | library | The oblivious bricks: `ObliviousTree` and `ObliviousMap`, the state holders of a tree-valued key under `access: oblivious`, over the vendored three-party DORAM; behind sidecar-core's state seam, each paired with its `TipState` by sidecar-tip ("The oblivious tree", "The oblivious sparse map"). | sockets, TLS, chain access |
| `sidecar-test-fixtures` | library (tests only) | What the test suites share: scratch directories, prepared circuits and manifests, vectors, example requests, three in-process nodes on any store, the Postgres test server. A dev-dependency outside the default members, so `cargo build` never unifies its features into the binaries. | production code paths |

On Aztec, TypeScript: `pss-client` (requests, envelopes, records, signing, effects split,
nonces, capsules, REGISTER/DISABLE, result-signature checks, the tip client) and
`pss-relayer` (tip only: lands results and the init round, sends `skip`). On Aztec, Noir:
`pss_core` (round circuits), `pss_contract` (sidecar-path contracts), `pss_public_contract`
(tip contracts), `pss_utils` (the AEAD, ECDH and PRNG primitives shared with circuits).

### Types that cross a boundary

All are defined in `sidecar-core` (the receipt-route types in `sidecar-tip` `receipt`) and
serialised as JSON: field elements as `0x` hex (64 digits out, 1 to 64 in, refused at or
above the modulus); unknown fields refused.

| Type | From → to | Content |
| --- | --- | --- |
| `Request<Full>` | client → orchestrator | `namespace, circuit, request_id, public, state_keys {reads, writes}, shared_inputs [{name, shares[3], share_hashes[3]}], records [{key, note_hash, c[3], record_hashes[3]}], requester?, signature?, chain_request_id?, manifest_hash?, shared_log?`. `request_id` is one field: a sidecar-path client draws 128 random bits; at the tip the scheduler derives it (section 6). `chain_request_id`: required under a queued intake, refused (400) under intake direct, kept in the `requests` row. `manifest_hash`: at the tip under `upgrades` `circuits` or `contract`, the contract manifest version the round runs under (section 7, "Upgrades"); refused under intake direct. `shared_log`: secret-shared on-chain intake only (below). Every name a binding hashes (store key, record key, circuit or package name, shared input name) is 1 to 256 bytes of visible ASCII (0x21 to 0x7E). Under intake direct a key the manifest also feeds into PUBLIC is spelled `0x` plus lowercase hex without leading zeros (`0x0` for zero), checked at step 9 |
| `Request<ForNode>` | orchestrator → node i | the same with `shares` and `c` reduced to node i's element; `share_hashes` and `record_hashes` kept |
| canonical body | every side | the full request without `shares`, `c` and `signature`, serialised with RFC 8785 (JCS); the hashes stand in for the per-node ciphertexts, so every node and the client compute the same `body_hash` |
| `Manifest` | client → nodes and orchestrator (in REGISTER); nodes → orchestrator (GET) | section 7 |
| `CircuitShape` | inside a node and the orchestrator | the ABI walk: parameters in order with flattened witness keys, visibility, leaf types, sources; public-input count; the namespace index; each output's note-hash index |
| `Bound` | binder → executor | co-noir's `Rep3SharedInput` map, the list of reads, the sample count |
| `RoundOutput` | executor → pipeline | proof (bb format), public inputs, `TACEO_store` vectors by name, timings |
| sealed third `c_i` | node i → orchestrator → client (and back) | `key id ‖ ct[] ‖ tag`; AD = (namespace, key, note_hash, owner key) |
| `ConsumedRow` | pipeline → store | `(namespace, note_hash) → circuit vk_hash, request_id` |
| `NodeResult` | node i → orchestrator | `request_id, proof, public_inputs, stored [keys], records [{key, note_hash, c_i}], signature_i`; a FETCH answer also carries the row's `vk_hash` |
| `ExecuteResponse` | orchestrator → client | `request_id, vk_hash, proof, public_inputs, stored, records [{key, note_hash, c[3]}], signatures[3]` |
| `SharedLog` (`Request.shared_log`) | scheduler → orchestrator → node i | secret-shared on-chain intake only: `fields [FieldHex; REQUEST_LOG_LEN]`, the request log after its tag as the chain holds it (each node derives only its own pairs), and `shared [{…}]`, every INPUT_SHARED value in the encoding's order with where its correction sits (sidecar-core `derived`). Part of the canonical body; a chain verifier refuses a `shared_log` that is not the log it read |
| `ReceiptRequest<Full>` | client → orchestrator (`POST /v1/receipt`) | receipt intakes: `namespace, circuit, inputs {name: value}, current_block`; receipt intake adds `user_nonce`; secret-shared receipt intake adds `inputs_hash` (`C`), `shared_inputs` (the envelopes, the salts' envelope `$summand_salt` last), `summand_commitments [S_0, S_1, S_2]` and `sharing_digest` (`D`); `manifest_hash?` when the namespace is upgradable; never a requester; `expiry_block` refused |
| `ReceiptRequest` (`ForNode`) | orchestrator → node i | each shared input reduced to node i's envelope, `share_hashes` kept, `expiry_block` set by the orchestrator |
| `ReceiptAnswer` | node i → orchestrator | `request_id` (the chain request id), `inputs_hash, expiry_block, signature` |
| `ReceiptResponse` | orchestrator → client | `request_id, inputs_hash, expiry_block, signatures[3]`, node 0 first, as the request function's `receipts: [Receipt; 3]` takes them |
| `StoredReceipt` | node i → scheduler and chain verifier (`GET /v1/receipt/{namespace}/{request_id}`) | `namespace, request_id, circuit, vk_hash, inputs` (clear app inputs in ABI order), `inputs_hash` (the hash or `C`), `user_nonce?`, `shared_inputs` (this node's envelope and the three share hashes per shared input; the salts' envelope is not stored), `expiry_block, stale_blocks?, signature`; no requester |
| `ManifestMessage` / `DisableRequest` | client → orchestrator → nodes | signed registry bodies (section 4) |
| `ManifestAnswer` / `ManifestResponse`, `DisableAnswer` / `DisableResponse` | nodes → orchestrator → client | `manifest_hash, packages_hash, npk_app_hash, seq` (DISABLE: `circuit, vk_hash, npk_app_hash, disabled, seq`) with node i's signature, the response all three; a node's answer to a `seq` 0 body also carries `registration: {proof, public_inputs}`, which the orchestrator verifies and does not forward |
| `NodesResponse` | orchestrator → client | three `{enc: {x,y}, sig: {x,y}}` |

### Hashes and associated data

Every hash the machine computes over structured data is defined here. `poseidon2` is the
width-4 sponge every part shares; `poseidon2_hash_bytes` is the aztec.js packing (31-byte
little-endian chunks). A label written "the bytes `x.y`" is that ASCII string read big-endian
as one field. The only non-Poseidon2 derivation is the TLS material, which is transport.

The machine and the sidecar path:

| Name | Definition | Used at |
| --- | --- | --- |
| `body_hash` | `poseidon2_hash_bytes(JCS(canonical body))` | step 5, step 10, the `requests` row |
| signed message | `poseidon2_hash_bytes(domain ‖ JCS(canonical body))`, domains `cosnark-sidecar/v1/{register,disable,execute}` (a registry body's canonical body is the body without `signature`) | step 4, section 4 |
| `share_hashes[i]` | `poseidon2([eph.x, eph.y, ct[0], ct[1], tag])` of envelope i | step 6 |
| `record_hashes[i]` | `poseidon2([key id as an integer, ct…, tag])` of third i | step 6 |
| envelope AD (its nonce) | `poseidon2([namespace, request_id, poseidon2_hash_bytes(circuit), poseidon2_hash_bytes(name), i, input_body_hash])`, `input_body_hash` the canonical body's hash without the `shared_inputs` array | step 9; the client when sealing |
| record AD (its nonce) | `poseidon2([namespace, poseidon2_hash_bytes(key), note_hash, owner.x, owner.y, SIDECAR_RECORD_AD])` | steps 8, 13 |
| key id | first 8 bytes (big-endian) of `poseidon2([enc_pk.x, enc_pk.y])` | every `c_i` |
| `K_i` | `poseidon2([enc.lo, enc.hi, SIDECAR_SEAL_KEY])`, `lo` the low 128 bits of node i's enc scalar, `hi` the rest, the label the bytes `sidecar.seal_key`; never leaves node i | seals and opens every `c_i` |
| `vk_hash` | `poseidon2` over the bb verification-key fields (the 115 fields of `bb write_vk --output_format json`; aztec.js `poseidon2Hash(vk.fields)`) | REGISTER step 4; `consumed`, `packages`; result and registry messages |
| registration handshake values | request id = the namespace, body hash = the REGISTER body's signed message, no summands | section 4 step 4 |
| handshake summand hash | `poseidon2([request_id, x])` for a summand `x` both neighbours hold; sent only to the neighbour that holds it | step 10 |
| `H(sealed_i)` | `poseidon2` of the list of `record_hashes` of node i's new record thirds in manifest order (a one-element list for one third), 0 if none | step 14 |
| result message | `poseidon2(RESULT_DOMAIN, namespace, request_id, new commitments…, i, H(sealed_i))`, the new commitments the outputs' note hashes in manifest order | step 14; the orchestrator; `process_result` |
| result-nonce seed | `poseidon2([label, sig.lo, sig.hi, message])`, label the bytes `sidecar.result_nonce`; its 32 big-endian bytes seed the Schnorr nonce generator | step 14 |
| registry result message | `poseidon2(REGISTRY_DOMAIN, namespace, poseidon2_hash_bytes(name), vk_hash, npk_app_hash, seq, disabled, i)`, `disabled` 1 (the answer to a DISABLE; no node signs 0) | section 4 step 6 |
| manifest result message | `poseidon2([MANIFEST_DOMAIN, namespace, manifest_hash, packages_hash, npk_app_hash, seq, 0, i])`, `MANIFEST_DOMAIN` the bytes `sidecar.manifest` (`testvectors/registry.json`) | section 4 step 6; `configure` |

The AE's per-length pattern tag and the Schnorr challenge are internal to `ae.rs` and
`schnorr.rs`: for `n` plaintext fields the tag is `packed·2^16 + 0x4142` for up to 6 fields,
`packed` the fold `acc·2^32 + w` over the IO-pattern words `[0x80000002, k, 0x80000000|k, …,
1]` (one `k, 0x80000000|k` pair per block of up to 3 fields), and `poseidon2(words ‖ 0x4142)`
for 7 or more; the challenge is `poseidon2([DST, R.x, pk.x, pk.y, message])`, `DST =
poseidon2_hash_bytes("schnorr_grumpkin_poseidon2")`.

The tip (section 6). Each is implemented once per language and pinned by the named test
vector:

| Name | Definition | Used at |
| --- | --- | --- |
| non-secret-shared chain request id | `poseidon2([namespace, vk_hash, inputs_hash, user_nonce])`, `inputs_hash = poseidon2(app inputs)`, `user_nonce` 128 random bits per request; no `user` (`testvectors/chain_request_id.json`) | on-chain intake, receipt intake |
| inputs commitment `C` | `poseidon2([v_1, …, v_m, blinding])`: the app inputs and the reserved `$partial_note`, `$outcome_key`, `$outcome_tag` the round takes, in ABI order (sidecar-tip `ids`, `pss_public_contract` `shared_intake`, `testvectors/shared_intake.json`) | secret-shared intakes |
| secret-shared chain request id | `poseidon2([namespace, vk_hash, C])` | secret-shared intakes |
| machine request id | `poseidon2(PSS_ATTEMPT, chain_request_id, old commitments…, pinned values…)`: old commitments in `commitment_slot` key order, then each pinned read's value and, for an epoch read, its epoch, in `public_reads` order; no length prefix (the chain request id fixes the circuit and so both counts) | the scheduler, the chain verifier, the round circuit |
| receipt message | `poseidon2(RECEIPT_DOMAIN, request_id, inputs_hash, expiry_block)`; under secret-shared receipt intake `poseidon2(RECEIPT_DOMAIN, request_id, C, expiry_block, D)`, five elements, so never a receipt intake message | the receipt route, the request function |
| receipt-nonce seed | as the result-nonce seed with label the bytes `sidecar.receipt_nonce`, so equal messages give equal signatures and a receipt and a result never share a nonce | the receipt route |
| summand commitment `S_j` | `poseidon2([SUMMANDS_DOMAIN, s_j…, salt_j])`, `j = 0, 1, 2`: `s_j` the j-th Rep3 summand of each of C's shared values in C's order, then of `$blinding` (sidecar-tip `CommitmentLayout::summand_names`), `salt_j` a fresh salt per vector, label the bytes `sidecar.summands`; both holders of `s_j` check `S_j` | secret-shared receipt intake |
| sharing digest `D` | `poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kind_1, …, kind_m, clear_1, …, clear_q])`: the kind of each of C's values in C's order (clear 0, shared 1), then the clear values in C's order; label the bytes `sidecar.sharing` | secret-shared receipt intake |
| intake associated data | an envelope's nonce: `poseidon2([namespace, chain_request_id, poseidon2_hash_bytes(circuit), poseidon2_hash_bytes(name), i, SIDECAR_INTAKE_AD])`, label the bytes `sidecar.intake` (sidecar-core `envelope`) | the receipt route; step 9 under a secret-shared intake |
| derived intake shares | `PRF(k, j) = poseidon2([k, j, SIDECAR_INTAKE_PRF])`, label the bytes `sidecar.intake_prf`; seeds `t_i = PRF(x(e·P_i), 0)`, wraps `w_i = t_i + PRF(s_{i+1}, 1)`, value shares `PRF(t_i, j + 2)`; epochs packed `e_0 + e_1·2^32 + e_2·2^64`; `data_hash = poseidon2(log after the tag)` (sidecar-core `derived`, `pss_core::tip::derived`, `testvectors/shared_onchain.json`) | secret-shared on-chain intake |
| `enc` rotation message | `poseidon2([PSS_ENC_ROTATE, namespace, i, pk.x, pk.y, epoch])`, label the bytes `pss.enc_rotate` | secret-shared on-chain intake |
| key rotation message | `poseidon2([PSS_ROTATE_KEYS, namespace, epoch, H(keys)])`, `H(keys) = poseidon2([sig_0.x, sig_0.y, enc_0.x, enc_0.y, sig_1.x, …, enc_2.y])` (sidecar-core `key_epoch::rotation_message`) | "Node replacement and key epochs" |
| slot commitment | `poseidon2([TIP_STATE_SEP, namespace, slot, fields…, blinding])`, label the bytes `pss.tip.state`, `fields` the stored vector before its blinding (`pss_core::tip::slot::commitment`, `testvectors/slot_commitment.json`) | a flat key's `old_c`, `new_c` |
| tip tree hashes | `leaf_hash(i, leaf) = poseidon2_with_separator([namespace, key, i, leaf…], PSS_TIP_LEAF)` (0 for an empty leaf), `node(l, r) = poseidon2_with_separator([l, r], PSS_TIP_NODE)`, commitment `poseidon2_with_separator([namespace, key, root], PSS_TIP_TREE)`; empty subtrees `Z_0 = 0`, `Z_{l+1} = node(Z_l, Z_l)`; labels the bytes `pss.tip.leaf`, `pss.tip.node`, `pss.tip.tree` (sidecar-core `tree`, `pss_core::tip::tree`, `testvectors/tip_tree.json`) | "Tree-valued keys" |
| outcome AD | the AEAD nonce `poseidon2([note_hash, SIDECAR_OUTCOME_AD])` over the completed note that packs the plaintext; a round whose shares do not open `C` seals its mismatch code under `poseidon2([note_hash, SIDECAR_MISMATCH_AD])`; labels the bytes `sidecar.outcome`, `sidecar.mismatch` (`pss_core::tip::outcome`, `testvectors/outcome.json`) | "Private outcomes" |
| partial note `P` | `poseidon2_hash_with_separator([owner, rho], DOM_SEP__PARTIAL_NOTE_COMMITMENT)`, the separator 568912195 (aztec-nr v6 `uint_note.nr`); an app's refund notes take `partial_commitment_with(owner, randomness, content)` with the amounts as private content | "Partial-note delivery" |
| completed note hash | `poseidon2_hash_with_separator([storage_slot, P, fields…, request_id], DOM_SEP__NOTE_HASH)`, aztec-nr's `compute_note_hash(storage_slot, [P, packed…])` with the packing `[fields…, request_id]`, at most eight fields; pinned against aztec-nr's `UintNote` in `pss_public_contract_test` | "Partial-note delivery" |
| completion log tag | `compute_log_tag(P, DOM_SEP__NOTE_COMPLETION_LOG_TAG)` = `poseidon2_hash_with_separator([P], 3372669888)`; the log is `[storage_slot, fields…, request_id]` | the public completion |
| use and redeem nullifiers | use: `poseidon2_hash_with_separator([P], PSS_PARTIAL_USED)`, pushed by the request function; redeem: `poseidon2_hash_with_separator([note_hash_for_nullification, nhk_app], PSS_REDEEM)`; labels the bytes `pss.partial_used`, `pss.redeem` | "Partial-note delivery" |
| request secrets | for the user's `n`-th request in a namespace: `rho = poseidon2([PSS_PARTIAL_RANDOMNESS, wallet_secret, namespace, n])`, `$outcome_key` and `$outcome_tag` the same under `PSS_OUTCOME_KEY`, `PSS_OUTCOME_TAG`; labels the bytes `pss.partial_randomness`, `pss.outcome_key`, `pss.outcome_tag` (pss-client `SecretStore`, `testvectors/secret_store.json`) | the tip client |
| exit tag and filler | `exit_tag(P, request_id, entry) = poseidon2([PSS_EXIT_TAG + 2^128·entry, P, request_id])`, `exit_filler(P, request_id, j) = poseidon2([PSS_EXIT_FILLER + 2^128·j, P, request_id])`, labels the bytes `pss.exit_tag`, `pss.exit_filler` (`testvectors/exit_tag.json`) | "The escape hatch" |

Log tags: the request log is `compute_log_tag(request_id, REQUEST_DOMAIN)`; the chain-held
sealed-thirds log `compute_log_tag(request_id, PSS_STATE)`.

### The store trait

`Store` is one trait in `sidecar-core` with a transactional `begin … commit` and these
tables, identical on every node except for the shares each holds:

| Table | Key | Row | Written by |
| --- | --- | --- | --- |
| `namespaces` | namespace | owner key, `seq`, nsk_app share, npk_app_hash | the first REGISTER; `seq` by every later registry body |
| `manifests` | (namespace, manifest_hash) | the contract manifest, the `seq` of the REGISTER that last wrote it | REGISTER; one version per namespace, up to three when upgradable (section 7, "Upgrades"); a version no longer held is deleted with its packages |
| `packages` | (namespace, manifest_hash, name) | circuit JSON, manifest, vk, vk_hash, `disabled`, `seq` | REGISTER, DISABLE |
| `consumed` | (namespace, note_hash) | circuit vk_hash, request_id | the commit; never pruned; a rollback deletes the rolled-back request's entries |
| `dead_records` | (namespace, note_hash) | the rolled-back request that created the record | the rollback, for every client-held record the request created; deleted by a commit that creates a record with that note hash; a resync or restore imports the neighbours'; never pruned. Note hashes suffice: a record is node-sealed with its note hash in the AD, so an abandoned branch's records are a fixed set the user can neither re-randomise nor mint |
| `requests` | (namespace, request_id) | body_hash, vk_hash, proof, public inputs, stored keys, records (key, note_hash, this node's third), sealed replaced vectors (key, prior request id, the sealed vector), created keys, signature, status (`committed`, `rolled_back`), created_at; at the tip `chain_request_id` | the commit; a restore imports the backup's; pruned by age (default 30 days) |
| `values` | (namespace, key) | tagged vector, note_hash, request_id | the commit (sidecar-path node-held keys) |
| `tip_versions` | (namespace, key, commitment) | parent commitment, the queue index of the entry it was computed for, the request that created it, this node's pairs (flat key) or the root of its clear tree and its append index (tree-valued key), status (`canonical`, `live`, `orphan`), the block at which it was last canonical or live (an orphan: first marked orphan) and that block's hash | a tip round's commit; deleted by the retention rule (section 6, "Node-held state") |
| `tip_nodes` | (namespace, key, hash) | an internal node's two children in the clear, or a leaf's index and this node's pairs of it; a reference count of the stored nodes and versions that point to it | a tip round's commit; deleted when its count reaches 0 |
| `tip_blobs` | (namespace, key, name) | opaque bytes of a holder that keeps its own state (the oblivious bricks' DORAM state and journal), never interpreted by the store | a tip round's commit, by the holder |
| `receipts` | (namespace, request_id) | inputs, user_nonce, expiry_block, signature, never a requester (under secret-shared receipt intake no `user_nonce`, but `C`, this node's envelope per shared input and the three share hashes) | the receipt route; kept and pruned by the receipt rule (section 6) |

Besides per-row reads, the trait lists the namespaces it holds and a namespace's package
names, which a node serves to an orchestrator rebuilding its registry copy (section 4).

Three implementations: `MemoryStore` (tests and in-process three-party suites),
`PostgresStore` (sidecar-node; deployments with node-held keys) and `LocalStore` (an
append-only file store for deployments whose keys are all client-held, and the
orchestrator's registry copy: `MemoryStore`'s tables with their log beside them, the
node-held tables always empty; `store.log` begins with an 8-byte format marker, version 3,
each record's header checksums its length and payload, and a log without the marker is
refused). Each says whether it holds `values` (`holds_values`); on a store that does not,
REGISTER refuses (400) a manifest that gives any key the state mode `node`. The rules that
use the tables (write rule, rollback, consumed check) live above the trait, in the pipeline,
and a checked commit's writes are one ordered list (`Txn::writes`) that each backend applies
in order, so the three behave the same. `tip_versions`, `tip_nodes` and `tip_blobs` exist in
the memory and Postgres stores only.

### The registration circuit

One Noir circuit compiled into the machine (`machine/circuits/sidecar_register`): private
input `master` (bound as this node's share), public input `namespace`; it computes `nsk_app =
poseidon2_with_separator([master, namespace], SIDECAR_NSK_APP)`, hands it to the node with
`TACEO_store("nsk_app", [nsk_app])`, and returns `npk_app_hash =
poseidon2_with_separator([(nsk_app·G).x, (nsk_app·G).y], SIDECAR_NPK_APP)`.
`scripts/prepare-data.sh` compiles it and sidecar-core's build script embeds the artifact,
refusing one whose bytecode differs from its SHA-256 in `machine/sidecar-core/embedded.sha256`,
so every node proves and verifies the same circuit with no compiler at run time; its vk is
computed under the node's CRS. It has no namespace and cannot be registered or disabled. It
runs through the same executor and self-verification as a round.

The audit circuit (`machine/circuits/sidecar_audit`) is built the same way. Its private input
is the preimages of 16 hashes of at most 16 fields each, laid out by the node (public labels
and names, then the stored pairs); its public inputs are the namespace and each preimage's
length; it returns each preimage's Poseidon2 hash (total-noir's `p2_hash_var_or`). The audit
round (section 6, "Node-held state") runs it. Its vk is built when an audit starts.

### The coordinator (tip)

At the tip the orchestrator is the single serialiser and the only party that decides what
runs: its chain reader observes the queue, its scheduler turns the head into an ordinary
`Request<Full>` and the normal pipeline runs it. Each node verifies the chain view before it
accepts such a request (section 6). Nothing else in the machine knows the chain exists.

## 2. The key hierarchy

```
node i (generated at setup, held by node i only)
├── enc_i   Grumpkin scalar; published, pinned by clients and the orchestrator
│   ├── ECDH with a client's ephemeral key           → opens INPUT_SHARED envelope i
│   └── K_i = poseidon2([enc_i.lo, enc_i.hi, SIDECAR_SEAL_KEY])   → seals and opens record thirds
├── sig_i   Grumpkin scalar; published, pinned by clients, the orchestrator and tip contracts
│   ├── result signature (step 14): nonce derived from sig_i and the message
│   ├── registry result signature (section 4): nonce from the node's random source
│   └── tip receipt signature: nonce derived from sig_i and the message
└── master nullifier share (sampled over the mesh at setup; persisted with the keys)
    └── nsk_app[namespace] share  = registration circuit at the first REGISTER (in namespaces)
        └── npk_app_hash[namespace]   its public output; pinned by the contract (at the tip through `configure`)
namespace owner key (Grumpkin; generated by the developer, root of trust of a namespace)
└── signs REGISTER and DISABLE bodies (with seq); the first REGISTER records the key
requester key (Grumpkin; a user's key, often their Aztec account's signing key)
└── owner of every client-held record its requests create; signs record-supplying and shared-input requests (intake direct)
```

What each binds: `enc` binds a ciphertext to one node; `K_i` binds a record third to node i
and, through the AD, to (namespace, key, note hash, owner); `sig_i` binds a result, a receipt
and a registry answer to node i; `nsk_app` binds nullifiers to a namespace; `npk_app_hash`
binds every nullifying round to the network; the owner key binds a namespace's packages; the
requester key binds a record to its user. The orchestrator holds only public keys. TLS
certificates are transport keys outside this hierarchy: the mesh pins the three party
certificates, and the orchestrator-to-node leg is mutual TLS under a deployment CA.

Setup and rotation. `sidecar-node setup` generates `enc_i` and `sig_i` and, over one mesh session with the
other two nodes, samples the master share (SAMPLE: nobody learns the master); all three are
persisted in the node's key directory beside the TLS material. The admin socket is a Unix
domain socket in the node's run directory with no network listener.

`enc` rotation. The operator installs a new `enc` scalar; the node keeps the previous one for
a configured grace window, opens thirds under either key id and envelopes under either scalar
(the tag decides), and seals under the new one only. A round that loads a record and stores
it again re-seals it, so an app re-seals its live records within the window by running a
round. The node retires the previous scalar once the window has lapsed and the head has
passed every queued secret-shared receipt request whose stored envelope to it opens only
under that scalar (in the node's own chain view), and `rotate-enc` refuses to rotate again
while such a request holds it (409, unless `--force`). Thirds sealed only under a retired key
are lost. Under secret-shared on-chain intake each contract also stores each node's `enc`
key by epoch ("Secret-shared on-chain intake"). The procedure is DESIGN.md, "Rotating a
node's `enc` key".

`sig` rotates only with a node replacement: contracts pin key set 0 and move to a new key set
when two of the three current nodes sign it (section 6, "Node replacement and key epochs").

## 3. The request lifecycle

One state machine, run by every node for every execute request, exposed by `sidecar-core` as
a library call so the node's HTTPS handler and the tip's scheduler drive the same code. The
orchestrator runs steps 1 to 4 as they apply to it, without the lock, before fan-out (at the
tip its step 4 is empty: the chain verifier is the node's), so a bad request never leaves two
nodes waiting on the mesh. Every failure before step 15 changes nothing; the error classes
are in section 8. A key's state mode comes from the manifest: `client` (owner: the
requester), `node` (rows in `values` on the sidecar path; versions at the tip) or, at the
tip, `chain` (a record owned by the machine itself).

| Step | Name | What happens | Refusal |
| --- | --- | --- | --- |
| 1 | parse | JSON to `Request`; hex, lengths, unknown fields; `request_id` one field; no key listed twice in `reads` or in `writes`. | 400 |
| 2 | admit | `admit(req)`: the hook for fees or further authentication; admits everything by default. A refusal joins the session like steps 3 to 9 (step 10). | as the hook says |
| 3 | resolve | Take the namespace lock. Look up `(namespace, circuit)` in `packages`: absent or `disabled` → refused. Load the manifest and `CircuitShape`; check key counts; a request key equal to the fixed key `nsk_app` is refused. Nothing is loaded yet, so a request naming another namespace's circuit cannot reach that namespace's values. | 400 |
| 4 | authenticate | Under intake direct, if the manifest gives any supplied record's key the mode `client`, or stores a client-held key, or the request carries a shared input: `requester` must be present and `signature` must verify as Schnorr over the signed message. The signature covers every share hash, and `requester` is in the body every envelope AD covers, so whoever holds the body cannot reseal one input beside the client's others. Under a queued intake the node's chain verifier runs here instead (section 6), and `C` binds the shared inputs. Requests with no client-held record or store and no shared input need no signature. | 403 (signature), 400 (requester missing; chain verifier) |
| 5 | replay | `requests[(namespace, request_id)]`: absent → continue; equal `body_hash` and `committed` → return the stored result after a handshake-only session (step 10); another body → refused; `rolled_back` → refused, except a rolled-back tip attempt (its row carries a chain request id) with equal `body_hash`, which counts as absent and whose commit replaces the row. | 409 |
| 6 | own ciphertexts | `H(share_i) == share_hashes[i]` for every shared input; `H(c_i) == record_hashes[i]` for every record. | 400 |
| 7 | consumed | No supplied client-held record's claimed `note_hash` is in `dead_records`. For every `consume` key with policy `once`, the state's note hash (the `values` row's for a node-held key, else the record's claimed one) is not in `consumed`. | 400 (dead record), 409 naming the consuming circuit (never the request) |
| 8 | open and load | Client-held keys: open `c_i` under `K_i` with AD (namespace, key, note_hash, requester); chain-held keys: the same with owner `enc_pk_i`; node-held keys: read `values` (at the tip, the version the old commitment names); `nsk_app` from `namespaces`. A supplied record whose key is not a client-held key the request reads is refused after the loads. | 400 (open; unread record), 409 (missing) |
| 9 | bind | The check bind, before any session: typed range checks on every PUBLIC value; under intake direct a request key fed into PUBLIC in its one short spelling; LOAD slices; INPUT_SHARED decryption (ECDH with `enc_i`, the envelope AD or, under a secret-shared intake, the intake associated data); every SAMPLE a placeholder zero. A stored vector whose length differs from the manifest's `len`. | 400, 409 (length) |
| 10 | session | Take the node-wide mesh lock; open the Rep3 session; one exchange carrying `(request_id, body_hash)` and the hash of every shared summand the two neighbours both hold (envelopes, opened client-held records, node-held rows and versions, `nsk_app`). Each node then tells both neighbours its verdict, so a refusal at any node refuses at all three before anything is computed. After the handshake the binder runs again with the session's correlated randomness, drawing the SAMPLEs last in declaration order; the two binds must agree on everything but the samples. | 400 (handshake), 500 (the binds differ) |
| 10b | in-session loads | A key whose holder reads it by a joint protocol of the three nodes (the oblivious bricks, "The oblivious tree") is loaded now, in the open session, in place of its step 8 placeholder; the round's bind then takes it. | 400 (plan mismatch), 500 (diverged oblivious state) |
| 11 | execute and verify | co-noir witness extension, proving key, ZK UltraHonk proof; node i verifies its own proof against the vk and checks the namespace public input. | 422 (constraints or namespace), 500 (mesh, proving) |
| 12 | outputs | Map `TACEO_store` vectors to the manifest's `outputs`: every output present, none extra, lengths equal `len`; the note hash is the public input the manifest names. A stored note hash already in `consumed`, or consumed by this round, is refused (checked again in step 15). Node-held write rule: the key is empty, or the request loaded it, or its stored note hash is in `consumed`. | 500 (circuit mismatch), 409 (consumed note hash; write rule) |
| 13 | seal | Each client-held output: `c_i = seal(K_i, (namespace, key, note_hash, requester), node i's pairs)`; each chain-held output: the same with owner `enc_pk_i`. Each sidecar-path node-held row the round replaces: seal the old vector with owner `enc_pk_i` into the sealed replaced vectors; record every key the round creates. | — |
| 14 | sign | `signature_i = schnorr_sign(sig_i, result message)`, the nonce generator seeded with the result-nonce seed, so equal messages give equal signatures. | — |
| 15 | commit | One transaction: `values` writes (at the tip, new versions), `consumed` entries for every `once` key consumed, the `requests` row (replacing a rolled-back row step 5 counted as absent). It refuses a stored note hash in `consumed`, a write the write rule forbids and a key changed since the round read it. Release the mesh and namespace locks. | 409, 500 (store) |
| 16 | respond | `NodeResult`. | — |

The session handshake in detail. A node that refused the request at steps 2 to 9 still takes
the mesh lock, opens the session and sends its refusal as its verdict (with no summand
hashes); it runs no circuit, stores nothing and answers its own refusal (alone, if the mesh
cannot be opened), and the other two refuse 400 ("node N refused the request") at once instead
of waiting out the mesh connect timeout. A node that answered from its row at step 5 joins
the same way, with the verdict "this node already holds request …", and answers its stored
result: when a first attempt's commit failed on one or two nodes, those nodes reach the
handshake and refuse the resend 400 at once, naming the node that holds it; when all three
replay, a resend costs one handshake-only session. From an honest orchestrator a node
refuses at steps 2 to 4 only when admit hooks differ between nodes, the registries diverged
(section 4) or its chain verifier refuses. A summand-hash mismatch is seen by the two
neighbours that hold the summand; the third learns it from their verdicts. An admit refusal
at all three costs a handshake-only session, so a hook that refuses many requests makes each
wait for the session in progress.

The orchestrator's half: steps 1 to 4 on the full request; take the global session lock (one
session at a time across every namespace; a scheduler attempt and the operator's pause go
first, but one public session after every four scheduler sessions in a row, first come first
served within each class; at most 4 public sessions of one namespace and 32 in all wait, and
one past either bound is refused 503 with `Retry-After` 10 s; sidecar-orchestrator `gate`);
project to node i; fan out in a task that holds the lock until the three answers are checked,
so a client that disconnects cancels nothing and FETCHes the round instead; require the
three `NodeResult`s to agree on proof, public inputs, stored keys and each record's (key,
note_hash); verify the proof with its own vk and the namespace public input; verify each
`signature_i` against the pinned `sig_i`; assemble each record from its three thirds; respond
with the package's `vk_hash`. FETCH asks every node for its `requests` row; the three must
also agree on the row's `vk_hash`, which picks the package in the registry copy (disabled ones
included); the proof is verified under that vk and checked and assembled as above. FETCH of a
pruned id is 404; of a rolled-back one, or of a round whose `vk_hash` no package of the
namespace carries, 409.

The client's half (pss-client): check the request id, the pinned `vk_hash` and the three
signatures against its own pinned `sig` keys; then, before it keeps a record, the labels no
signature covers: one record per client-held output in manifest order, each under the write
key that output's STORE names and the new commitment at its note-hash index.

The rollback, on the node's admin socket, per request: `restore(namespace, request_id)` takes
the namespace lock and refuses (409) unless every key the request wrote still holds the row
it wrote and no later committed request consumed a state it created; then it writes back
every sealed replaced vector (opened under owner `enc_pk_i`), deletes every row the request
created and every `consumed` entry carrying its id, writes every client-held record it
created into `dead_records` and marks the request `rolled_back`. Requests are rolled back in
reverse order of commit; the operator runs it on all three nodes (DESIGN.md, "A node-held
round whose transaction cannot land").

At the tip the same `restore` discards an attempt committed at fewer than three nodes
(section 6, "Node-held state"): for a row with a chain request id it deletes every
`tip_versions` row the request wrote, with the tree nodes only those versions reach, after
marking the key's versions against the node's chain view, and keeps the row as
`rolled_back`. It refuses (409) a version the slot holds (the attempt landed), a version
another kept version builds on, a version held in blobs (an oblivious key is resynced
instead) and a request with versions when the node has no chain view of the namespace.

## 4. The registry lifecycle

REGISTER and DISABLE are signed registry bodies: `message_for(domain, canonical body)`,
domains `cosnark-sidecar/v1/register` and `cosnark-sidecar/v1/disable`, signed by the
namespace owner key. The REGISTER body (the manifest message) carries one namespace's whole
contract manifest (section 7) and each of its compiled circuits once, so a namespace is
registered in one body and each node commits it in one transaction. Every registry body takes
the namespace lock; a REGISTER with `seq` 0 also takes the node's mesh lock and the
orchestrator's global session lock, because it runs the registration circuit.

| Step | REGISTER | DISABLE |
| --- | --- | --- |
| 1 parse | `namespace, manifest, circuits {id: compiled circuit}, owner_pubkey, seq, signature`; each circuit stripped to exactly `noir_version`, `hash`, `abi`, `bytecode` and a fixed empty `debug_symbols` and `file_map` (the vk comes from `bytecode`); `circuits` names exactly the manifest's circuits; the contract manifest's own checks (sidecar-core `manifest::contract`, section 7) | `namespace, circuit, owner_pubkey, seq, signature` |
| 2 owner and seq | The signature verifies under `owner_pubkey` (403). `seq` 0: the namespace row is absent, or present with the same owner, stored `seq` 0 and the same contract manifest (the repair case); another manifest at `seq` 0 is 409. `seq` ≥ 1: `owner_pubkey` equals the stored owner (403); a body whose manifest hash was written at this `seq` with nothing committed since returns the stored values (idempotent); otherwise `seq` = stored + 1 (409). The stored manifest at the next `seq` re-enables every package; another manifest replaces it on the sidecar path, is checked as an upgrade under `upgrades` `circuits` or `contract` (section 7), and is refused (400) for a `fixed` tip namespace. A repair never changes `seq`, and its answer carries `seq` 0. | the same owner and `seq` rules; idempotent for an already disabled circuit at its recorded `seq` |
| 3 checks | per package: the manifest schema and the path rules of its intake (section 7); the manifest against the circuit's ABI; refused: a deferred option (`binding: exact`, `intake: relayed`), a chain-held manifest over the apply log's bound, an INPUT_SHARED source under a non-secret-shared intake, a direct manifest with a pinned read, a pinned read naming the namespace's own address (it is written `$self`), a `node` key on a store without `values`; then the node's own check, a hook given the package and the contract manifest (sidecar-node refuses a secret-shared receipt intake package when `queue.stale_blocks` is null or outlasts its `enc` grace window, and a secret-shared on-chain intake package whose clear inputs and chosen shared values exceed 9). 400 | the package exists in a held version (404) |
| 4 keys | each circuit's vk and vk_hash from its bytes and the CRS, which must be the contract manifest's `circuits.<id>.vk_hash` (400); a circuit whose bytes equal a held version's package keeps that vk. `seq` 0: run the registration circuit (steps 10 and 11 of section 3 with the master share bound as `master` and the registration handshake values), keep the `nsk_app` share and the proven `npk_app_hash`; a node that already has the row requires the same `npk_app_hash` and replaces its share (a fresh sharing of the same value), so a partly committed first REGISTER is repaired by resending it. | — |
| 5 commit | One transaction: the `namespaces` row (or its `seq`), the `manifests` row and every `packages` row with the `seq` it was registered with; a version beyond the held limit is deleted with its packages. | the `disabled` flag and `seq` of the package of that name in every held version; `seq`. A later REGISTER re-enables only the packages of the version it writes |
| 6 respond | `manifest_hash, packages_hash, npk_app_hash, seq, signature_i` over the manifest result message, plus `registration` on a `seq` 0 body; the orchestrator requires agreement and that the values are the body's, verifies the registration proof against the built-in vk (public inputs: the namespace and `npk_app_hash`), checks every signature and returns the values and signatures. A tip contract's `configure` checks the three signatures. | `namespace, circuit, vk_hash, npk_app_hash, disabled: true, seq, signature_i` over the registry result message, `vk_hash` that of the newest held version's package |

A node runs steps 2 and 3 and the vk computation before it opens the registration session, so
every check that needs no mesh is local; a `seq` 0 body a node refuses there still joins the
handshake with its refusal as its verdict.

A body some nodes commit and others refuse or fail to commit leaves the registries diverged.
The orchestrator answers 500 naming the nodes on each side and records nothing in its copy,
which holds only rows all three nodes hold. Until repaired, an execute of a circuit a diverged
DISABLE names is refused in-session by the nodes that committed it (all three answer 400 at
once); an execute of a circuit a diverged REGISTER added is refused by the orchestrator's copy.
The repair is to resend the same signed body (a `seq` 0 body while `seq` is still 0). The
nodes' rows are compared read-only by `sidecar-node sync-registry --check` (one mesh session;
each node sends both neighbours its public rows) and by the orchestrator (at start, after each
registry body and on a timer; counts on `GET /v1/status`, rows on the admin socket's
`status`); neither repairs (sidecar-core `registry_check`). A node several bodies behind is
repaired by `sidecar-node sync-registry --lost <i> --from <j>` (`resync::resync_registry`):
it takes node j's rows once node j and the third node agree, keeping its `nsk_app` shares,
building each vk itself and advancing `seq`. The procedure is DESIGN.md, "A registry body only
some nodes committed".

Reads: GET `/v1/packages/{namespace}/{name}` (the package with its manifest hash), GET
`/v1/namespaces/{namespace}` (`owner_pubkey, seq, npk_app_hash, manifest_hash`), GET
`/v1/namespaces/{namespace}/manifest` (the newest contract manifest, its hash and `seq`), GET
`/v1/namespaces/{namespace}/manifests/{manifest_hash}` (any held version). On its mutual-TLS
leg only, a node also answers GET `/v1/namespaces` and GET `/v1/packages/{namespace}` (names,
disabled included), from which the orchestrator's `sync-registry` rebuilds its copy, requiring
the three nodes to agree on every row and recomputing each vk.

## 5. Invariants

The machine's guarantees, each enforced at a named step of section 3 or 4. Invariant 0 is the
rule over every other one and over every design choice.

0. **If all three nodes' secrets leak, privacy is at risk and funds may be frozen, but no
   funds can be taken or lost.** An adversary holding every scalar, share and store, and
   running the orchestrator and the relayer, can open every value and run and sign any
   registered circuit on any inputs; it must still be unable to move or lose anyone's value.
   It can freeze value held in shared state. Escrow and usage deposits are app choices.
   When the stale period is enabled and the skip wrapper calls `token::refund_skipped`,
   `skip()` returns any escrow and usage deposit the request paid. Value in a shared book
   moves only by a round or through an escape hatch, which nodes that keep landing
   rounds while refusing service keep shut. No value the circuit trusts as an
   authorisation may be a shared input or a node-held value
   (authorisation is proven in the user's private function over a user-owned note); the
   circuits a contract pins may not rest on node signatures (the address commits to them);
   nothing of value may be releasable only by a round (escrow and deposits complete user-owned
   notes in public functions; an escape hatch pays on a user-owned note with no round). The
   companion rule, minimal PSS: state that need not be shared is a user-owned Aztec note, and
   only the essential shared state is PSS (DECISIONS.md, "Principles").
1. Only a circuit the namespace owner registered, and has not disabled, ever receives the
   namespace's values (step 3; section 4 steps 2 and 3).
2. Only a proof that verifies, under the request's namespace, changes the store (step 11
   before step 15; the orchestrator verifies again).
3. A round commits atomically, under one namespace lock, with its consumed entries, its
   request row and its sealed replaced vectors (steps 3 and 15).
4. A state is evaluated at most once under policy `once`: the consumed set is checked before
   any load and written in the same commit, never pruned, and no round may re-store a
   consumed note hash (steps 7, 12 and 15).
5. A stored sidecar-path node-held value is overwritten only by a request that loaded it or
   after it is consumed (step 12), and every row a request replaced or created is recoverable
   by the rollback within the retention window. At the tip a round never overwrites: it
   creates a new version from the version its old commitment names, the slot names the
   canonical one, and a version leaves the store only by the retention rule.
6. A client-held record third opens only at node i, only for the namespace, key, note hash
   and owner it was sealed for, and only inside a request signed by that owner; a chain-held
   third opens only at node i for the machine's own owner key (steps 4, 8). Node-held state
   seals no thirds: a node's pairs leave its store only sealed, to a lost neighbour in a
   resync and in its encrypted backup.
7. An envelope opens only at node i, only for the request it was made for (steps 6 and 9): on
   the sidecar path the request body (the envelope AD); under secret-shared receipt intake the
   chain request id, circuit and input (the intake associated data), checked at the receipt
   route and again at step 9 of every attempt.
8. The three nodes run one request per session on one body: the handshake (step 10) refuses
   otherwise, and the neighbour hashes refuse an inconsistent sharing before any computation.
9. Within the `requests` retention window a request id is a once-only token: a replay returns
   the first result and never runs a second round, and another body under a reused id is
   refused (step 5); after the window a resent body is a new request, which the consumed set
   still bounds.
10. Every result is bound to the network twice: by `npk_app_hash` in the public inputs of
    nullifying rounds and by three node signatures over the request id and the new
    commitments (step 14). Registry answers are bound the same way (section 4 step 6).
11. The master never enters an application circuit; the registration circuit is the only
    circuit that reads it, and its output is proven (section 4 step 4).
12. The orchestrator is never the sole holder of anything; whatever it answers, the nodes'
    `requests` rows also hold.
13. Nothing in the machine reads a chain for soundness; the tip's chain reads can only delay.
    Under node-held tip state a lying chain view can make a node prune a version it later
    needs, which stops rounds on that key at that node until it is resynced; no state is lost
    while the other two hold the version, and no wrong result can land. A node deletes by its
    chain view only below the finalized tip.
14. A result that delivers value or a spendable note to someone other than the nodes lands
    only if its recipient can open it: the ciphertext and the note hashes are computed inside
    the circuit and are public outputs of the proof ("Verifiable delivery"). What the nodes
    seal outside the circuit is sealed only to a node itself.

## 6. The tip as an extension

Status: everything in this section is built, except that the oblivious tree and the
oblivious sparse map are experimental options ("The oblivious tree", "The oblivious sparse
map"), and relayed intake and the `exact` binding are deferred and refused at REGISTER. Which
example exercises which brick is in each example's README; which suite proves what is in
[TESTING.md](TESTING.md).

The tip adds intake, a queue and a result transaction on the chain, and a coordinator in the
orchestrator. It reuses the machine's types and the lifecycle of section 3. The chain holds,
per state key, one commitment in public storage (for a tree-valued key, a commitment to the
tree's root); under node-held state, the default, the state itself lives on the three nodes as
Rep3 shares.

| Piece | Where | Adds |
| --- | --- | --- |
| intake | the app contract (`pss_public_contract`), the user's PXE (`pss-client`) | the chain request id (section 1); `append()` with the `request_id → seen` mapping (a repeat reverts), `requests[tail]`, `tail`, `head`, `head_since`; under on-chain intakes a request log; under receipt intakes three node receipts verified in the request function ("Secret-shared intake") |
| receipts | node route `POST /v1/receipt` (proxied by the orchestrator); sidecar-tip `receipt` | below, "The receipt route" |
| tip state | each node's store | versions anchored to the chain ("Node-held state") |
| chain reader | orchestrator, sidecar-tip `chain` | reads `head`, `tail`, `requests[head]`, the commitment slots and, under on-chain intakes, the request logs; follows proposed blocks and reports replaced blocks (below) |
| scheduler | orchestrator, sidecar-tip | synthesises the head's request as a `Request<Full>` (below, "The scheduler") |
| chain verifier | node, at step 4 under a queued intake (a hook of the library call, like `admit`) | re-reads the chain through the node's own Aztec node and refuses (400) a synthesised request that differs from its view (below, "The chain verifier") |
| the round | steps 5 to 16 | unchanged but for the version rule at steps 8 and 15 |
| result | `ExecuteResponse` with the three signatures; `H(sealed_i) = 0` under node-held state | FETCH by chain request id (`POST /v1/fetch/chain`): the latest row for it (greatest `created_at`), 409 if rolled back, 404 if none; the contract library's `process_result` and `process_init` check each node's signature, and `apply` and `apply_init` write the commitments and log nothing |
| relayer | `pss-relayer` (operator-run) | below, "The relayer" |
| outputs | the app contract | non-secret-shared intakes: public app outputs, which `apply` stores as the app wishes; secret-shared intakes: private outcomes by partial-note completion ("Partial-note delivery"); `done[index]` (`applied` or `skipped`) is the one library-level write a client needs |
| key epochs | the app contract (`pss_public_contract::key_epoch`), each node's admin socket, the orchestrator, pss-client | "Node replacement and key epochs" |

Where a queued intake changes a step of section 3: step 1's request id is the machine request
id the scheduler derived; step 4 runs the chain verifier instead of a signature check (a tip
key has no requester); step 7's consumed set is unused (the slot write is the spend); step 8
loads a node-held key at the version its old commitment names, and a tree-valued key's
touched leaves at that version; step 10's handshake adds the loaded pairs of every node-held
key and touched leaf as summands; step 15 writes a new version and never overwrites one. The
lock is one per namespace: one queue per namespace.

`inputs_hash = poseidon2(app inputs)` (non-secret-shared intakes) covers the app inputs only:
the values the manifest's PUBLIC sources take from request public names, in the order the ABI
walk first meets each (sidecar-tip `intake_inputs`, pss-client `intakeLayout`). `$namespace`,
request keys, constants, the parameters a pinned read fills and the reserved operands
(section 7) are not app inputs. The receipt route fills `vk_hash` from the registered package
(of the version in force under upgrades) and refuses a body that supplies it; the scheduler
places reserved values in the synthesised request's `public` map under the names of the
parameters they fill.

**The receipt route** (receipt intakes). The orchestrator proxies `POST /v1/receipt` to the
three nodes, setting `expiry_block`, which each node bounds by its own current block. A node
checks the static validity of the clear inputs ("Static validity"), stores the inputs (or its
envelopes) and signs the receipt message (section 1). A repeat under a stored id must carry the
stored clear inputs and envelopes (409). A node without `[tip]` refuses every receipt (400).
Secret-shared receipt intake adds its envelope and sharing checks ("Secret-shared receipt
intake, end to end"). Pruning: a receipt is kept while its request id is `seen` on chain and
`done[index]` is not written, however deep in the queue it waits. After `expiry_block +
stale_blocks` (50 for a null stale period) a node prunes only receipts whose request never
reached the queue (`seen` false, which past the expiry it never can be) or is done, reading
`seen`, `requests[head..tail]` and the head through its own Aztec node at its settled block
(the finalized tip), since an apply in a block a replacement drops would put the request back
in the queue (sidecar-tip `standing`). A node whose Aztec node does not answer keeps every
receipt.

**The scheduler** (sidecar-orchestrator `scheduler`). For the head entry it builds a
`Request<Full>` whose `request_id` is the machine request id, so a recompute against a moved
state or pinned value is a new request and step 5 holds. It fills the PUBLIC map from the
request log or the stored receipt rows, the pinned reads it simulated at its snapshot ("Pinned
reads"), the old commitment of every key the round reads (the slot's, or the latest attempt's
of a still-live earlier entry when pipelining) and, for a tree-valued key, the touched
indices with each leaf's old hash and siblings read from all three nodes' clear trees, which
must agree ("Tree-valued keys"). It reads the contract's stored `TipConfig.stale_blocks` and
computes nothing for a head whose contract manifest's `queue.stale_blocks` differs from it, or
that is older than `stale_blocks`. It recomputes whenever a slot differs from its expected
commitment, keeps the latest result per chain request id, and recomputes a held attempt whose
pinned values the chain no longer admits.

Retries. A request id the nodes refused (any class but a node failure) meets the same
refusal unless a node's view moves, so the scheduler resends that id after 1, 2, 4, ... blocks,
at most 32 apart (`MAX_REFUSAL_WAIT`); a different id runs at once. A step that stopped at a
failure that can pass with no new block (a node failure, a chain read, an entry whose inputs
no node gave yet) runs again after a backoff: the poll interval, doubled per failure in a row,
at most 30 s (`MAX_RETRY_BACKOFF`). A scheduler task that stops stops the orchestrator with an
error, for its supervisor to restart.

**The chain verifier.** It refuses (400) a synthesised request whose head, inputs, machine
request id (recomputed from `requests[head]`, the old commitments and the node's own pinned
values), slot commitments, pinned values, leaf indices, or leaf hashes and siblings (against
its own clear tree, naming the key) differ from its own view. Pinned values: on an entry's
first attempt it admits the request's own values where the read's freshness policy admits
them against its read, as `apply` would; once the node holds any attempt of the entry, it
requires its own values, so an orchestrator cannot run one entry's inputs at many admitted
values and learn from the outputs. Old commitments: it accepts the slot's, or the new
commitment of the latest attempt this node produced for the entry just before while that
entry's `done[index]` is unwritten (the pipelining rule, "Node-held state").

**The relayer** (`pss-relayer`, TypeScript, operator-run). It reads `head` and
`requests[head]`, FETCHes the result (the answer's circuit, found by its vk hash, gives the
form) and sends the round's result function (`process_result` unless the relayer's `methods`
names another, with the round's `ROUND_*` index) with the result and the signatures (for
chain-held outputs also the sealed thirds). The private result function checks the vk pin,
recomputes the bindings, verifies the proof and the three signatures (under a secret-shared
intake it also completes the note and emits the private log) and enqueues `apply`, which runs
the pinned reads first, each under its freshness policy, then checks `requests[head] ==
request_id` and slot equality, writes the slots, advances `head` and `head_since` and writes
`done[index] = applied`. It sends `skip()` when `head_since + stale_blocks` has passed and
`head < tail` (`done[index] = skipped`). Before anything is queued it lands the init round
("Deployment, configure and the init round"). It pays every transaction through the private
fee-payment contract ("Fee payment").

A failed round keeps its state. On the public-output path a round with `ok = false` outputs,
for every key it writes, the commitment its slot holds: the old commitment of a key it reads,
0 for a key it creates (`pss_core::tip::slot`, `Loaded::finish`). `process_result` refuses a
result that does not (`check_round` through `assert_failed_round_keeps_its_state`); `apply`
writes nothing on `ok = false` and keeps its write rule (a key written without being read must
be empty); the scheduler leaves a slot whose new commitment is 0 empty. Under private outcomes
there is no public `ok`: every round draws a fresh blinding and every write lands ("Private
outcomes").

Two constraints of co-noir at the pinned co-snarks revision on every circuit the network
proves. Neither ECDSA black box is implemented in the Rep3 witness extension, so no round
circuit verifies an ECDSA signature; Schnorr over Grumpkin, pure Noir, is the machine's one
signature scheme, and ECDSA belongs in the contract, outside the co-SNARK. Its Brillig VM has
no integer And, Or, Xor, Shl or Shr and implements only the `ToRadix` black box, so
unconstrained code a round runs may not shift, mask or call other black boxes (total-noir's
hints follow this; its page "co-noir compatibility of the library's hints" names the entries co-noir cannot run).
`scripts/check-noir.sh` runs total-lint's Brillig-ops report on every circuit the network
proves and fails on an unsupported op; beyond that only a co-noir witness extension catches a
violation, as `mpc_failure` at step 11.

Bounds and policies: one proof per request; a round's size is bounded by the leaves it touches (probe
width `K` and depth `D`), never by the size of the state; the stale period is `stale_blocks`;
`skip()` refunds what the skipped request put in ("Tokens and escrow").

**Following the chain.** Every party follows the proposed chain (a block every 6 s): the
scheduler and each chain verifier read at the proposed tip; pss-relayer and pss-client read
there; every transaction either library sends returns once it is in a proposed block
(pss-client `SEND_WAIT`); the user's PXE syncs to the proposed tip. How each party stays safe
across replaced blocks, and the one case that remains (a round started on a block that is then
replaced), is DESIGN.md, "Replaced blocks". The mechanism:

- The chain reader reads the Aztec node's four tips (proposed, checkpointed, proven,
  finalized, each a number and hash) on every poll and refuses an answer out of order. When
  blocks are replaced, log discovery ("Log discovery") reports a prune event, which voids
  every read above the last block both chains share (`Prune::voids`). A prune is reported to
  the one poll that sees it, so the chain verifier, whose reader the node's namespaces share,
  also confirms its reads by the snapshot's block hash. Every read names the block's hash
  (`{number, hash}`), so the Aztec node itself refuses a read of a replaced block.
- The follower keeps block hashes back to the settled block, the finalized tip, so every
  replacement is placed exactly. Its memory grows with the blocks between the finalized tip
  and the tip; each reader logs every doubling, and the orchestrator's `GET /v1/status`
  reports each reader (`readers`). Between two polls it reads every block in between, except
  after a long gap the blocks at or below the proven tip, where a replacement is placed at the
  highest kept block below them (deeper than the true point, never shallower). Until it has
  seen the finalized tip move it keeps every block since its first poll, and its node deletes
  nothing by it.
- On a prune the scheduler drops its held attempts and live state, reloads the queue and
  state at the replacement chain's tip and recomputes the head (an unchanged attempt is the
  same machine request id, which the nodes answer from their rows), and forgets refusals made
  at replaced blocks. Each chain verifier polls the follower once more after its reads and
  reads again at a new snapshot when its block was replaced. A node signs a round's result
  when the round ends, without looking at the chain again; a result built on a replaced block
  that still lands reverts at `apply` (`requests[head]` or a slot differs). Node-held state
  survives through the retention rule ("Node-held state").

### Pinned reads

A pinned public read (`public_reads`, section 7) is a public call the manifest fixes
(contract, function, arguments) whose result a round takes as public inputs. The scheduler
simulates it at its snapshot and places the value under the parameter's name; each chain
verifier repeats it at step 4; `apply` makes it again, as a nested static call, before any
storage read. The machine request id covers the pinned values. In the circuit's public inputs
the pinned values follow the app inputs, in `public_reads` order: each read's value, then an
epoch read's epoch.

Freshness is a parameter of each read, `freshness` (default `exact`): when a value read
earlier still lets the result land. It is one rule, which `apply` checks
(`pss_public_contract::result::Freshness`), by which the scheduler keeps a held attempt and by
which each chain verifier admits the request's own value on an entry's first attempt
(sidecar-core `PublicRead::admits`), so the machine never runs or keeps an attempt `apply`
would refuse.

| Policy | The read returns | The circuit takes | `apply` accepts |
| --- | --- | --- | --- |
| `exact` (default) | the value | the value | the current value |
| `epoch` | `[value, epoch, previous]`: the value, a u64 epoch counter the source increments with each new value, and the previous epoch's value while the source still offers it (its window), else the current value | the value and its epoch (`epoch_param`, the next public input) | the current epoch with its value, or the epoch before with `previous` |
| `tolerance` | the value | the value | a value within `band` of the current one: `absolute` (a u128) or `relative_bps` (1 to 10,000 basis points); both values below 2^128 |

The scheduler keeps an attempt while its policy admits its values against the chain's, and
recomputes it, with the attempts after it, once it does not. Under `exact` an attempt lands
only if the value does not move (for values a trusted party moves rarely). Under `epoch` it
lands if at most one new epoch opens before `apply`, and is recomputed once when a second
opens: a source that opens epochs at least `L` blocks apart lands every round that takes fewer
than `L` blocks from read to `apply`, recomputes a slower one at most once per `L` blocks, and
lands a value at most `2L` blocks old, provided its window outlasts a round. Under `tolerance`
it lands while the value stays within the band; a larger move costs one recompute. The epoch
source offers `previous` only for a bounded number of blocks after its epoch opens, so the
party computing the round cannot land a stale value indefinitely; `L` and the window belong to
the source (lending's oracle: `epoch_blocks`, `previous_blocks`). An epoch read is always
simulated (a `plain_reads` slot holds one field, not three); under `epoch` and `tolerance`
each parameter is one Field.

### Deployment, configure and the init round

Built in `pss_public_contract` (`configure`), pss-client (`deployment.ts`: `tipPins`,
`configureArgs`, `deployTip`), the machine (the scheduler's init round, the chain verifier's
init branch, sidecar-tip `init`) and pss-relayer (`fetchInitResult` and the `Lander`).

The namespace is the app contract's address, which Aztec derives from the constructor's
arguments and a salt, and REGISTER derives `npk_app_hash` from the namespace, so no
constructor can take it. A tip contract therefore takes its pins in two calls:

1. The developer compiles every package and computes each vk hash locally (pss-client
   `localVkHash`: bb `write_vk` with the nodes' flags), generates the contract manifest
   (section 7) and its hash, draws a secret random salt and computes the address from the
   class, the salt and the constructor's arguments: `stale_blocks`, the three node `sig` keys,
   the circuit pins (`CircuitPins`: the manifest hash; the package list as each listed
   package's name hash, `poseidon2_hash_bytes(name)`, in the manifest's order, then zeros up
   to the contract's capacity; each listed package's vk hash in the same order, then zeros)
   and the app's own constants. The address commits to all of them, so anyone checks which
   circuits and manifest a deployment runs from its address alone. The manifest never holds
   the address (a self-read is `$self`).
2. REGISTER the contract manifest at that address at `seq` 0 (section 4), before the address is
   public; each node recomputes every vk hash from the circuit's bytes. REGISTER reads no
   chain. A squatter who registered first could not change the circuits (step 4 accepts only
   an answer over the constructor's manifest hash and list), only DISABLE them; recovery is a
   new salt.
3. Deploy: the constructor (public, `#[initializer]`) checks the package list (listed names
   first, then zeros, no name twice, a vk hash for every listed package and none past the
   end) and writes the pins (`TipPins` in the app's Config).
4. `configure(npk_app_hash, answer)` (private; anyone may call it): `answer` is the REGISTER
   answer's `seq` and three node signatures. It computes the packages hash of the
   constructor's list and checks every node's Schnorr signature under the constructor's `sig`
   key `i` over the manifest result message with this contract's address and the
   constructor's manifest hash. It then enqueues an `#[only_self]` public call that
   initialises a `PublicImmutable` (`Configured`: `configured = true`, `npk_app_hash` and the
   constructor's pins), so every later private function reads its pins in one read; a second
   `configure` reverts at the immutable's initialisation nullifier. `skip()` reads
   `Configured`'s first four fields alone (`ConfiguredHead`, `stale_blocks_in_public`;
   `read_head_in_public` reads a record's head).
5. The init round (below), then the queue.

Whoever calls `configure`, and whichever registration of the manifest the answer comes from,
it can only write the same values. A DISABLE answer and an answer over another manifest or
list do not verify. Cost: three Schnorr verifications and one hash per listed package, once
(as private function circuits: the AMM tip's 12,095 gates, credits 12,297, lending 12,853; bb
6.0.0 `gates`, chonk). The form of `configure` is a DEV DECISION in `configure.nr`; the
alternative forms and their trust are in DECISIONS.md, section 11.

A deployment's packages are those REGISTER accepted at deployment time, and one deployment
serves one intake family plus the non-secret-shared init round. The examples deploy each tip
contract twice: a secret-shared deployment and a non-secret-shared test deployment (the
packages of each are in the example's README). An alias (another intake of a listed package
on its circuit, section 7) is not in the contract's list. A package added later needs a new
deployment, unless the contract has upgradable circuits (section 7, "Upgrades").

Until configured, nothing runs: every request, init, result, `apply` and `skip` function
asserts `configured` (`Configured`'s accessors assert the flag; a public function that reads
no pin checks the immutable is initialised). A function whose package is not in the
deployment's list refuses ("package not in this deployment": its vk pin is 0). Once
configured, a later REGISTER changes nothing in the contract; a DISABLE stops that round type
at the nodes.

The init round. It is never queued and has no requester, so the scheduler sends it: once the
contract is configured and the key's slot is empty, it synthesises the init request under a
fixed request id from the namespace, the init's vk pin and the configured init inputs (the
non-secret-shared id form with `user_nonce` 0), and machine request id
`machine_request_id(init id, [0; W], [])`, which `process_init` checks the signatures under.
Each chain verifier, in its init branch, checks on its own view that the contract is
configured, the slot is empty, the init vk pin is the registered package's and the request is
the one rebuilt from the configured inputs. The scheduler and the verifiers find the init
package, the `Configured.configured` slot and the init inputs' slots in the contract manifest
(`init`, `storage.configured`). On node-held state the round creates the key's first version.
The scheduler computes nothing until the contract is configured and nothing for the queue
while the init is due; it sends the init once and holds the attempt until a slot it creates is
written. The relayer FETCHes the result by the init id (pss-client `fetchInitResult`), sends
nothing once a slot is written, and otherwise sends the app's init function (`init_pool`,
`init_market`), which enqueues `apply_init` and writes the first commitment while the slot is
empty. The relayer holds a result after two mined reverts by default. A newer result or a
replaced block lets it try again. Repeated identical send errors other than reverts delay
retries and appear in the relayer's status. Under chain-held state the scheduler reloads a slot the init wrote, with no apply since, from the sealed thirds
`apply_init` logged under the init id.

### Node replacement and key epochs

A node is replaced when its `sig` key is stolen, its operator leaves, or its key directory is
lost without a backup; the three cases take one procedure, and the departed node contributes
nothing. The operator's steps are DESIGN.md, "Recovery"; why two of three signatures, the
threat cases and the alternatives are DECISIONS.md, section 15.

**The epoch.** A key set is the three nodes' `sig` and `enc` public keys in node order; an
epoch is a number and a key set. Epoch 0 is the constructor's `sig` keys
(`TipPins::node_sig_keys`), with no `enc` keys on record. `key_epoch` (pss_public_contract)
moves a contract from epoch `E` to `E + 1` through the app's `rotate_keys(epoch, keys,
signatures)`: a private function (`check_rotation`) that reads the key epoch at its anchor
block, requires `epoch = E + 1`, every key a Grumpkin point, the three `sig` keys pairwise
different and the three `enc` keys too, and two of the three signatures, each in its own
node's place under epoch `E`'s `sig` keys, to verify over the key rotation message (section 1).
It enqueues the app's `#[only_self]` `set_node_keys`, whose public body (`install`) requires
`epoch` = stored + 1 (a replay or a stale anchor reverts) and stores `NodeKeys { epoch,
rotated_at, grace, sig, enc, previous }` (the landing block, the grace window `G`, the new set
and the previous set's `sig` keys). One rotation replaces any subset of the six keys. Anyone
may submit it; the key set is network-wide, the epochs per contract. `NodeKeys` lives at the
library's own slot `NODE_KEYS_SLOT` (the bytes `pss.node_keys`), outside the app's
`#[storage]`, with its hash beside it (aztec-nr's `WithHash`), so a private function proves
one slot and every reader finds every contract's epoch at the same place; nothing stored reads
as epoch 0. The members the public check reads come first (`NodeKeysHead`,
`read_stored_head`).

No signed message carries a chain id, and an Aztec address does not depend on the chain, so a
network serves one chain under one key directory.

**The contract's checks.** `Configured` stays immutable. Every private function that verifies
node signatures (results, private outcomes, the init round, receipts) takes its keys from the
app's `node_keys` brick, the last type parameter of its round table row (`TipRound<C, R, W,
K>`, `K: SigningKeys`). Under `KeyEpochs` that is `key_epoch::signing_keys`: it reads
`NodeKeys` at its anchor block, verifies under the current set, or under the previous set for
signatures made before the rotation (which set is an unconstrained hint; the verification and
the public check bind it, so a wrong hint only fails), and enqueues the app's `#[only_self]`
`assert_key_epoch(epoch, current_only)`. Its public body (`assert_epoch`) accepts the stored
epoch, or the one before while `block <= rotated_at + G`, and refuses anything else ("key
epoch expired"). `G` is the namespace's `stale_blocks`, or `DEFAULT_STALE_BLOCKS` (50) when
skipping is disabled. So a result signed before a rotation lands inside the window, receipts
under the old set expire with it, and a departed node's signatures are worth nothing after it.
A node's `rotate_enc_key` verifies under the current epoch's `sig` key only
(`current_sig_key`, `current_only`). A deployment made after a replacement pins the current
set as its key set 0.

**A fixed key set.** An app that never replaces a node in place names `FixedKeys` in its round
table rows (examples/credits-tip): every signature is checked under key set 0 for the life of
the contract, by the same constrained verification of all three signatures; there is no anchor
read, no `assert_key_epoch` and none of `key_epoch`'s entry points. `rotate_enc_key` still
verifies under node i's pinned key. The contract never writes `NODE_KEYS_SLOT`, so it reads as
epoch 0 for good; its contract manifest says `node_keys: fixed` (written from the brick the
contract's state view reports, pss-client `bricks.ts`). After a replacement the orchestrator's
key-set gate computes nothing for it, replace-node names it under `redeploy` instead of
printing a `rotate_keys` line, and pss-client's `assertKeyRotation` refuses it. A replacement
means redeploying the app (a new salt, REGISTER, `configure`, the init round); the old queue
drains through `skip()` and a tree's owners exit through the escape hatch.

**The machine.** The orchestrator takes the key set from its configuration (`[[nodes]]`),
never from a contract. Its scheduler computes nothing for a namespace whose contract's current
`sig` keys are not the configured ones (epoch 0 compared through the constructor's
`node_sig_keys`, read beside `TipConfig.stale_blocks`, the fields after
`queue.stale_blocks_slot`), and logs why; it reads one slot per step and the whole epoch only
when that slot changes. Each node keeps every contract's declared rotation pending in its key
directory (`key_epochs.json`) and its pruning job records it once its own chain view shows the
contract at that epoch under that set, or past it. pss-client, given an Aztec node
(`keyEpochNode`), checks result signatures under the current set or, inside the window, the
previous one, and receipts, `GET /v1/nodes` and envelope `enc` keys under the current set.

The machine request id does not change with a rotation, so a recompute under the new set of an
unmoved request has the same id; it still runs as a new attempt at all three nodes, because
the refresh deletes the remaining nodes' `requests` rows and the newcomer holds none.

**The procedure** (sidecar-core `replace`): the orchestrator pauses (no new session; the
round in flight finishes); the newcomer runs `sidecar-node setup --newcomer` (`enc` and `sig`
only, an empty store) and the remaining nodes restart with it in the departed node's place on
the mesh; `sidecar-node replace-node --departed i --newcomer <keys> --pins <current set>` on
all three runs one MPC session: the share refresh, the newcomer's import, the checks and the
audit round, after which each remaining node signs `rotate_keys` for every `[tip]` namespace
at its next epoch and all three print one line per contract, which the operator submits; the
orchestrator restarts with the new `[[nodes]]` (`--paused`) and `resume` refuses while the
newcomer's registry differs from the others'.

The share refresh. A newcomer rebuilt from the neighbours holds exactly the departed node's
pairs, so the two remaining nodes first add a fresh zero-sharing to every pair they hold,
reconstructing nothing: with `d` the departed index, each value's components `x_d`, `x_{d+1}`
and `x_{d-1}` move by `r_d`, `r_s` and `-(r_d + r_s)`, fresh per element, so the value is
unchanged and the departed pair combines with neither new pair. The masks come from a seed
node `d - 1` draws and sends node `d + 1`, through Poseidon2 as a PRF keyed by the seed and the
run's generation over each element's identity (table, namespace, key, commitment or note hash,
position). A holder blob's share components are XOR shares of bytes: the same rule with XOR,
the masks ChaCha20 streams keyed by the PRF over the blob's identity; its copies and public
bytes are left. Refreshed: the master share, every `nsk_app` pair, every stored version of
every node-held key in any status, every leaf, every `values` row, every holder blob's share
components; the `requests` rows are deleted (no rollback or FETCH spans a replacement). Not
refreshed: client-held and chain-held thirds and secret-shared receipt envelopes, sealed per
node, which are lost with the departed key; a backup taken before the refresh must be destroyed
and a new one taken. The departed node keeps its copy of the DORAM receivers' shuffles until
each level's next rebuild. Each remaining node keeps the seed and generation in `refresh.json`
until the replacement ends; every run is the next generation, so no mask is applied twice. An
item one node committed and the other did not is found by comparing the component's current
hash with its hash one refresh back under each earlier generation, and only the node behind
refreshes it.

The import is the lost-store resync ("Node-held state") under a replacement scope: each
remaining node sends the newcomer, sealed to its new `enc` key and signed, only the component
it shares with the departed index (node `d + 1` its `x_d`, node `d - 1` its `x_{d-1}`). The
newcomer installs the master pair the two bundles rebuild and writes it to its key directory
only when every check passed: per namespace the registration circuit on the installed master
(its `npk_app_hash` must be the registered one), the `nsk_app` pairs against the circuit's
fresh sharing, the `values` handshake, then the audit round over every canonical version. The
remaining nodes sign the declarations only when every audited key passed. Nothing on chain
changes.

Requests in flight. A result signed before the pause lands under `E` until `rotated_at + G`,
then is recomputed. Queued requests stay queued and age against `stale_blocks`; after the
resume the scheduler recomputes every head at all three nodes. A queued secret-shared receipt
request whose envelope only the departed node held cannot run and is skipped after
`stale_blocks`; non-secret-shared receipt rows both remaining nodes hold alike are re-signed by
the newcomer.

What one stolen `sig` key can do until the honest two rotate it out: stall every round (a round
needs all three nodes), sign receipts and registry answers the other two did not, equivocate as
node i, and, under secret-shared on-chain intake, `rotate_enc_key` for node i (sending it one
share of each future value). It cannot rotate, land a result, an init or a `configure`, or open
any state. A stolen key directory also holds the mesh TLS key and the `enc` scalar, which opens
node i's share of every past envelope, log and record third; its pairs and master share stay
valid one-of-three shares until the refresh. Two nodes gone or hostile leave no quorum: the
namespace is stuck at its last slot values, its node-held state is lost with two stores, and
the only move is a new deployment of every namespace.

**The `enc` side.** Under secret-shared on-chain intake the install also voids the replaced
node's key in `enc_keys` (the app's `Keys` is `KeyEpochs<SharedOnchain<PublicContext>>`, whose
`EncKeys::void_replaced` runs with `Keys::install`): every node whose stored key is not its key
in the new set gets the zero point at its stored epoch + 2, so a request naming the departed
key's epoch reverts at intake, and the zero point refuses new requests until the newcomer's own
`rotate_enc_key`, signed under the new set, sets its key at the stored epoch + 1. On the
sidecar path a client-held third sealed under the departed node's `K_i` is lost; a planned
departure announces a window in which apps re-seal live records by running a round. A
chain-held tip namespace does not survive a replacement (its third i opens only at the departed
node): it is a new deployment. The remaining nodes' `enc` keys are untouched.

### Fee payment

Every transaction the system sends (a request, a result, a redeem, `configure`, the init, an
`enc` rotation, a `skip`) pays its fee through Wonderland's private fee-payment contract,
called wFJ here: the `PrivateFPC` of the npm package `@alejoamiras/private-fee-juice`
(github.com/alejoamiras/ecosystem-tooling, `packages/private-fee-juice`), versioned in lockstep
with Aztec, a dependency and never vendored. It has no public functions and no constructor, so
it needs no deployment transaction: its address follows from its class and a salt (at Aztec
6.0.0, salt 1, `0x0516ebb4f9c7988eb3cf6dd9459a47556f7a92db06b17cfa47ffb37fd35c6915`), and each
PXE registers it (`registerWfj` checks the node's Aztec version against the pin first).

A transaction's setup phase calls `pay_fee()`, a private function that takes the transaction's
maximum gas cost from the caller's private FJ balance in the contract, makes the contract the
fee payer (`set_as_fee_payer()`) and ends the setup phase (`end_setup()`), which is what lets
`process_result`'s `in_revertible_phase()` assertion pass. The contract's public FeeJuice
balance pays the sequencer, so every transaction shows the same fee payer. There is no refund:
the maximum is charged in full. Each payer funds its private balance by an L1 deposit to the
contract's address (`FeeJuicePortal.depositToAztecPublic`) and a dedicated funding transaction
(`FeeJuice.claim` with `mint_and_pay_fee`, paying its own fee through the contract);
pss-client never funds inside a request and refuses a payment method that calls FeeJuice. The
relayer pays results and inits from its own balance and refuses to start without one.

The fee setting: one per app, `FeeSetting` in pss-client (`fee.ts`): the fee method and a fixed
gas setting per transaction kind (`deploy`, `configure`, `request`, `result`, `redeem`, `skip`;
the init's landing is a result). The method is wFJ by default; an app may choose an
app-sponsored fee-payment contract or the sender's own account (the DEV DECISION in `fee.ts`
says what each reveals). `feeOptions(setting, kind)` gives one transaction's send options with
the kind's fixed gas limits, never estimated per transaction, so two requests' gas settings are
equal whatever their round type; a kind without limits declares what the wallet chooses. The
Lander applies it to every result and `submitIntake` to every request by default. The tip
examples' settings (`e2e/harness/fee-settings.ts`) are the largest gas each kind used in the
tip e2e plus 25% (`e2e/scenarios/README.md`, "Gas per transaction kind"). The e2e harness pays
every tip transaction through wFJ and checks it (`e2e/harness/fee-payers.ts`): wFJ must be the
fee payer of every transaction, with a FeeJuice claim in the funding transactions only.

Apps may choose escrow and a usage deposit (`pss_public_contract` `token`, the
`UsageDeposit` pin). Counter-tip takes neither. The deposit prices queue access because a
hidden requester has no identity to rate-limit. When configured, it is a pinned amount
of a pinned token. The request's private function draws it from the sender's credit and
commits a separate refund note. `UsageDeposit::kept` is a `DEV DECISION`. The library's
default refunds the deposit when the round runs. Lending keeps it when the round serves
the request. A round whose shares do not open `C` refunds the deposit. With the stale
period enabled, a skip wrapper that calls `token::refund_skipped` returns the escrow and
the deposit regardless of `kept`. The network earns no deposit from a round it forces to
fail the `C` check or from a head it skips (invariant 0). A request whose credit does not
cover the deposit reverts in its own transaction. The request function has no access to
the transaction's declared maximum gas cost (DECISIONS.md, section 12). See [who sees
what](DESIGN.md#who-sees-what).

### Tokens and escrow

Built in `pss_public_contract` `token` (`take`, `prepare_note`, `pay`, `pay_public`,
`public_balance`, `Refunds`, `refund_randomness`, `commit_refunds`, `refund_skipped`,
`settle_applied`, `UsageDeposit`) and `partial_note` (partial notes with private content), and
used by lending; the token is `examples/token`, aztec-nr v6.0.0's reference token. The AMM
moves no token: its completed note is the trader's credit, spent by `redeem`.

Custody. An app holds every token it takes in its own public balance of that token, so only its
code moves them (private custody would need a note key some operator holds). Each user's claim
is a private balance of the app: its credit notes, the app's own note type.

In. `fund` moves tokens from the user's private balance to the app's public one (the token's
`transfer_to_public` under the user's authwit) and credits the user a note, in a transaction of
its own: amounts public, linked to no request. A request's private function spends one of the
sender's credit notes covering its escrow and the usage deposit, inserts the change and commits
two refund notes (`token::commit_refunds`): partial notes of the app's credit type whose
commitments bind their amounts as private content, their randomness derived from the request's
`rho`. The public wrapper records the two commitments beside the queue entry (`Refunds`): no
token call, no amount, the same for every round type. The amount drawn is the one the request
puts into `C`, so a round never settles more than was put in.

Out. `redeem` credits a note's settlement privately (a credit note), and `withdraw_funds` turns
credit into token notes of the user's that a public function completes from the app's public
balance (the token's `finalize_transfer_to_private`): amounts public, owner hidden. A
withdrawal never draws on the kept usage deposits (`borrowed + kept <= balance`).

In a deployment that takes escrow and enables the stale period, a `skip()` wrapper
that calls `token::refund_skipped` completes the refund notes in public. It needs no
round, node, signature or token balance. The apply wrapper
(`token::settle_applied`) keeps the deposit or completes its refund per the app's pin and
completes the escrow's refund when the round consumed nothing or its inputs-opened bit is 0;
otherwise, under private outcomes, the round settles the escrow inside its completed note.

### State modes at the tip

| Mode | Where the state lives | On chain | For |
| --- | --- | --- | --- |
| `node` (the default) | the three nodes' stores, as versioned Rep3 pairs | one commitment per key (a tree root's for a tree-valued key) | every shared state, small or large |
| `chain` (an option) | the apply log of every result: the whole state sealed to the nodes' keys | the commitment and the sealed state, every apply | small fixed-size states whose operators want recovery from a recent sealed-thirds log or the init log |
| `client` (the sidecar path) | the user, as a record it supplies | — | state pertinent to one user (sections 3, 4) |

A manifest names the mode per key (`state {keyref: node | chain}`). The lifecycle calls the
state holder chosen per key by (mode, path); the scheduler, the synthesiser and the chain
verifier see a key's state through sidecar-tip's `TipState`. One table in sidecar-tip
(`TIP_MODES`) pairs each mode's holder with its tip state, and a node or orchestrator serving
queued intakes installs them (`sidecar_tip::holders()`): node-held state is sidecar-core's
`NodeVersions` (both traits), chain-held state `state::chain::ChainSealed` and
`state::chain::ChainTip`. In the contract library every shared result body is generic over `S:
Sealing`, `NodeHeld` (no thirds, `H(sealed_i) = 0`) or `chain_state`'s `SealedThirds`, passed
as the `sealed` argument of `check_round`, `apply_round`, `process_init` and `apply_init`; in
pss-client the result path carries a holder's opaque arguments from its `StateModule`
(`stateArgs()`, empty under node-held state).

Chain-held state is bounded by one Aztec public log, the sealed-thirds log `apply` emits: its
tag, the `W` new commitments and `9n + 15` fields per chain-held output of `n` shared elements
(`1 + W + 9·sum(n) + 15T` fields for `T` outputs) must be at most
`MAX_PUBLIC_LOG_SIZE_IN_FIELDS` = 4,094 (every public log of a transaction shares one
4,096-field payload behind a 2-field header). REGISTER uses this all-shared bound. Each
public element uses two fields per third, and each shared element uses three. Landing
requires every chain-held output in a round to have the same sealed third width `L`
(`SealedThirds<T, L>`). The width is `5 + 2p + 3s` for `p` public and `s` shared elements.
The manifest gives vector lengths, and the executor determines which elements are public or
shared. Any other public log of the apply transaction takes its
length plus 2 from the same budget.

Every queued package of a namespace that loads or stores a request key gives it one layout (its
state mode and, for a tree, its shape): REGISTER refuses (400) a contract manifest in which two
packages differ (sidecar-core `manifest::contract`), and the scheduler computes no round while
two queued packages give one key of its schedule different layouts (`sidecar_tip::one_layout`).

### Node-held state

Built in sidecar-core's `NodeVersions` (steps 8 and 15 over `tip_versions`) with its tip state
in sidecar-tip; recovery in sidecar-core's `resync`, `backup` and `audit` and the admin
socket's `resync`, `resync_key`, `backup`, `restore_backup` and `audit`.

The chain is the arbiter of order; the nodes hold the values. Each node keeps every tip key as
a set of versions: a version is the key's vector of this node's Rep3 pairs (for a tree-valued
key, its leaves and internal hashes), named by its commitment, with the version it came from.
The init round creates the first version, whose commitment `init_*` writes to the slot. Every
later round loads the version its old commitment names and creates one new version under its
new commitment; nothing is overwritten. Tip keys have no one-row-per-key storage, and a round
that landed is never rolled back.

- **Liveness by queue entry.** Each version records the queue index `j` of its entry. The
  canonical version is the one whose commitment is in the slot. A version computed for entry
  `j` is live while `done[j]` is unwritten and its parent is canonical or live, for every
  attempt of that entry: an older attempt whose old commitments and pinned values still hold
  can land after a recompute, and its version must then be there. When `done[j]` is written,
  the attempt whose new commitment the slot holds becomes canonical and the other attempts,
  with every version built on them, become orphans; a skip orphans them all.
- **Pipelining.** The scheduler pipelines on the latest attempt of a live entry only, and the
  chain verifier expects one old commitment per key: the new commitment of this node's latest
  attempt for the entry just before, while that entry is live and the attempt created a
  version of the key, else the slot's (sidecar-tip `state`). That version must be live under
  the verifier's own read of the slot and the head. At a pipeline depth of 2 or more, an entry
  pipelined on an attempt that left a key's commitment unchanged is refused until the entry
  before lands (it costs time only; the default depth 1 never meets it).
- **Retention.** A node deletes an orphan, or a superseded canonical version, only once the
  block that orphaned or superseded it lies behind the settled block (the finalized tip, also
  the floor of the chain reader's block hashes), so any block replacement finds every version
  that was canonical or live above the finalized tip. A chain view that has not seen the
  finalized tip move deletes nothing. A round's commit marks the key's versions against the
  chain view it was verified at and deletes orphans marked below its settled block; the
  pruning job does the same for every node-held key between rounds (`NodeVersions::prune`,
  every `prune_interval_secs`; DESIGN.md, "Retention and pruning"). Each mark carries its
  block's hash (`tip_versions.block_hash`); before a mark below the finalized tip deletes a
  version, the node reads that block's hash, and a mark whose block the chain no longer holds
  is ignored and the version marked again (`TipState::replaced`, `VersionView::replaced`).
- **A slot at a commitment the node does not hold** is a fault (a result landed that this node
  did not commit, impossible while it is honest and keeps its store, or a lying chain view).
  The node refuses rounds on that key until it is resynced from the neighbours.
- **Equal commitments.** A round whose new commitment for a key equals its old one (a
  non-secret-shared round's `ok = false`) creates no version for that key. Under private
  outcomes every round draws fresh blindings, so this does not arise there.
- **An attempt committed at fewer than three nodes** can never land (`process_result` needs
  three signatures and a node signs only after it commits); every resend is refused at the
  handshake by the node without the row, so the entry waits for `skip()`, unless the operator
  rolls the row back at the nodes that hold it (section 3, the rollback). The rolled-back row
  still counts as an attempt for the chain verifier's first-attempt rule; the next resend runs
  at all three.
- The result message has `H(sealed_i) = 0`; `apply` writes the commitments and logs no state.
- `enc` rotation does not touch node-held state: versions are Rep3 pairs, not sealed to `enc`.
  Encryption at rest is the deployment's disk encryption.

**Recovery.** Rep3 gives every component to two nodes: node i holds `(x_i, x_{i-1})`, so node
`i + 1` also holds `x_i` and node `i - 1` holds `x_{i-1}`. Every recovery is one MPC session of
the three nodes, started by the operator on each admin socket (never through the orchestrator),
with the three nodes' pinned public keys. The runbook is DESIGN.md, "Recovery".

- **A lost store, key directory intact.** Each neighbour sends a bundle: in the clear, every
  `namespaces` row without its share, every package, every canonical and live version (for a
  tree, its root and every node its clear tree reaches), the sidecar path's `values` rows (key,
  note hash, writer), `consumed` and `dead_records` rows, every non-secret-shared receipt row
  with the neighbour's receipt signature, and every holder blob's public bytes; sealed to the
  node's pinned `enc` key, the component it shares with the node of every shared value (the
  master share, every `nsk_app` share, every element of every version, leaf, `values` row and
  holder blob). It signs both with `sig`. The node checks the signatures, requires the two
  bodies to agree (except each version's status, block and block hash, which each sender marks
  against its own view: a version takes the later block), rebuilds its pairs, requires the
  master pair to equal its key directory's and imports into its empty store. A receipt row is
  kept only when both neighbours send it alike with valid signatures and correct ids, and the
  node signs it again (the derived receipt nonce gives the signature it first gave). Then, per
  namespace, the registration circuit runs on the master shares and its `npk_app_hash` must be
  the registered one; the rebuilt `nsk_app` pairs must open against the circuit's fresh sharing
  to the same value; a handshake compares every `values` row's pairs with the neighbours'; a
  blob handshake compares every holder blob's components (each node sends node `i + 1` the
  digest of its `a` components with the public bytes and copies, node `i - 1` that of its
  `b`); then the audit runs. Orphans and `requests` rows are not copied. Secret-shared receipt
  envelopes, sealed to the node alone, are not recoverable from the neighbours: such a queued
  request is skipped after `stale_blocks`, as is a non-secret-shared one whose row the
  neighbours do not both hold alike.
- **One key** (a slot at a commitment the node does not hold, or a diverged clear tree). The
  same session with a key scope: each neighbour sends the namespace row and the key's canonical
  and live versions, tree nodes and holder blobs; the node requires its namespace row to be the
  rebuilt one, and one commit replaces its versions, tree nodes and blobs of that key; then the
  blob handshake and the audit run over that key.
- **Holder blobs.** A holder that keeps a key's state outside the versions (the oblivious
  bricks) writes each `tip_blobs` row in one format (sidecar-core `store::blob`): public bytes,
  equal at the three nodes; the node's two components of XOR shares as byte streams `a` (`x_i`)
  and `b` (`x_{i-1}`), element after element in the same order; and copies, values two nodes
  hold alike, placed by the same rule. So recovery carries a blob without knowing whose it is:
  a resync rebuilds node i's `a` from node `i + 1`'s `b` and its `b` from node `i - 1`'s `a`.
  A version whose tree lives in blobs carries no clear tree (root 0, the append index alone):
  the import stages no nodes for it, and the audit reports it not audited; the blob handshake is
  what recovery checks of its state.
- **A lost key directory.** The `sig` and `enc` scalars exist only on that node: restore the
  offline key backup, or replace the node ("Node replacement and key epochs").
- **The audit.** Per tip key, its canonical version: the session handshake compares the
  version's pairs with the neighbours', then an audit round (the audit circuit, section 1)
  recomputes from the pairs the commitment of a flat key, or the leaf hash of every stored leaf
  of a tree, and compares them with the version's commitment and the clear tree's leaf hashes;
  the clear tree is checked against the root in the clear. One round takes 16 hashes; a larger
  tree is audited in chunks of 16 leaves in leaf order, and the first failing chunk fails the
  key. Live versions are not audited (the scheduler recomputes their entries). Each key is
  passed, failed or not audited, with why. A node whose resync imported and then failed a
  check, or stopped before the checks, keeps `store.unverified` in its key directory and
  refuses every round, REGISTER, DISABLE and receipt, across restarts, until a resync passes.
- **Backups.** Each node backs up its store and, separately, its key directory, each one file
  encrypted (ChaCha20-Poly1305) under a backup key its operator holds offline. The store
  backup, taken on the admin socket with each namespace read under its lock right after its
  versions are marked, holds every row with this node's pairs and holder blobs (orphans and
  dead records left out). A restore is a delta resync: the restored node, on an empty store,
  sends both neighbours the names of what its backup holds (versions by key and commitment,
  leaves by hash, `values` rows by key, note hash and writer, blobs by key and name with the
  digest of each neighbour's part); each neighbour sends a store resync's bundle without those
  components (a blob part only when its digest differs); the node takes those from its backup
  (checked against the bodies' public elements) and the rest, the master and every `nsk_app`
  from the neighbours, imports the backup's `requests` rows and the receipt rows the neighbours
  did not bring (the only way a secret-shared receipt envelope comes back), and the checks and
  the audit run as after a resync.
- Losing two nodes' stores loses the state, as losing two nodes' key shares loses every secret.

### Tree-valued keys

Built in sidecar-core's `tree` (hashes, clear tree, touched leaves) and `NodeTree` (the holder
of a key with a `tree` entry), the store's `tip_nodes`, sidecar-tip's `tip_tree`, the node route
`POST /v1/tree` and `pss_core::tip::tree`. The machine's test rounds are
`machine/circuits/tip_tree_init` and `tip_tree` (depth 16, `K = 3`, three-element leaves,
header `[total, next_index, blinding]`, about 12,600 gates).

A large book is a tree-valued key: a binary Poseidon2 Merkle tree of fixed depth `D` (the tip
tree hashes, section 1) whose leaves are vectors of `w` field elements. A round touches at most
`K` leaves, the manifest's probe width; its cost depends on `K` and `D`, not on how many leaves
are in use.

- Every leaf carries its own blinding, drawn fresh (SAMPLE) whenever a round writes it, so a
  leaf hash is hiding. Leaf and internal hashes are therefore public data: each node keeps the
  whole tree of hashes in the clear and the leaves as Rep3 pairs.
- Under the default `access: clear`, leaf indices are clear to the nodes: the scheduler names
  the touched indices, each chain verifier checks them, and the loads select by index. The
  world sees only commitments. `access: oblivious` moves the index into the shared inputs and
  the hashes and leaves into a distributed oblivious RAM ("The oblivious tree").
- Index rules (static validity, asserted in the intake's `is_valid` and flagged in the circuit
  with the app's codes): leaf 0 of a tree with a header is a fixed touch and never an app
  input; a position is in `1 … 2^D - 1`; the touched indices of one round are pairwise distinct
  (a repeat would apply one update twice to stale values). A round naming fewer leaves than its
  probe width carries a count (an app input); slots past it are skipped. The checks compare
  public indices.
- The effective index of each slot: 0 in a header's slot; an index input's value when below
  `2^D`; `$new_leaf` for the open input at 0; 0 for an unused slot and for a value the tree
  cannot hold. Every slot carries a real path of the loaded tree (an unused one leaf 0's), and
  the circuit compares the placed indices with those its inputs give.
- A round's sources: LOAD_LEAF (the shared leaves of the touched slots, slot after slot), and
  each leaf's old hash, its `D` siblings and the effective indices (PUBLIC names the `tree`
  entry's `params` give). The scheduler reads them from all three nodes' clear trees at the
  loaded version (`POST /v1/tree`, one read per key), requires agreement and places them in the
  request, so `body_hash` covers them; each chain verifier derives them from its own tree and
  refuses others (400, naming the key); step 10 compares the LOAD_LEAF pairs as summands. A
  loader asked for an index with no stored leaf returns zero pairs.
- In the circuit: every old path is verified against the old root first. Each touched shared
  old leaf is checked against its old hash (an old hash of 0, an empty leaf, by asserting the
  loaded leaf is zero; any other by hashing); a mismatch means a diverged store. New leaves are
  written with fresh blindings and the new root computed path by path in slot order: where path
  `k` meets a sibling position an earlier path passed through, it uses the latest earlier
  path's recomputed node (a selection on public indices).
- Cost: each new leaf hash is computed from shared leaves and stays shared, so the `D` node
  hashes above it are shared Poseidon2 permutations: `K·D` per round, sequential in depth (120
  at `K = 6`, `D = 20`), plus the old-path checks. Their communication rounds, more than the
  gate count, set witness-extension time under network latency.
- The round's public outputs include the new leaf hashes (`new_hashes`); each node writes the
  used slots' hashes into the parent's clear tree in slot order and refuses (500, nothing
  stored) a root whose commitment is not the round's new commitment.
- The write policy (`Tree::update_private`, under private outcomes): one flag per slot, a
  constant of the circuit. A flagged slot (a header, the requester's own leaf) is re-blinded on
  every outcome, so its new hash tells nothing of `ok`; but a round whose shares do not open
  `C` re-blinds the header alone, since its other indices are unbound. An unflagged slot is
  written only where the round writes it and otherwise keeps its leaf and hash, so its exit tag
  stays unspent ("The escape hatch"); its `new_hashes` entry is its old hash, which each node
  takes as no change. The node seeing the index learns that the round left it.
- The tagged write (`Tree::update_private_tagged`, "The escape hatch"): the write policy with
  an exit tag in each written entry leaf and the replaced tags as app values.
- Insertion. An opening request names the open sentinel (position 0) in place of an index; the
  scheduler assigns the append index of the version it computes on (one past the highest leaf
  ever written, which each version records) as the reserved operand `$new_leaf`, which each
  chain verifier checks. The tree query names the open slot and each node answers it at its
  version's append index, so one read gives the index and its path; a node answers only at its
  tree's depth (400 otherwise). The circuit enforces the append index: the header leaf carries
  `next_index` (1 when the init creates the tree); an opening round requires the old leaf hash
  to be 0 and `$new_leaf` to equal `next_index`, and writes `next_index + 1` (`tip::tree::append`);
  a mismatch is a flagged no-op with the app's code (the header re-blinded, the leaf left
  empty). With no deletion, the opened leaves are a prefix of the tree even under a fully
  compromised network, and `2^D - 1` bounds the positions opened over the tree's life. When
  the tree is full the scheduler places 0 and the circuit flags the round. The outcome reports
  the assigned index.
- The node store keeps internal hashes content-addressed (a new version adds `D` nodes per
  touched leaf) and leaves per (index, leaf hash), so versions share what they do not change;
  each stored node counts the nodes and versions pointing to it, and a pruned version releases
  its root, deleting each node whose count reaches 0.
- Manifest: the `tree` entry of section 7. REGISTER bounds the round by `K` and `D` and accepts
  any number of leaves. A tree's layout is declared once, under the reference that loads it;
  the reference it is stored back at (`store`) takes that layout and must name the same key
  (400 otherwise). A round that loads and stores trees stores each tree it loads and creates
  none; a tree a round creates (an init) is declared under the reference that stores it.

### The oblivious tree

Status: experimental, an option a deployment chooses per key, never a default
(`docs/DECISIONS.md` section 7). Built as the crate `machine/sidecar-oblivious`; lending's
oblivious deployment runs real rounds over three nodes in process
(`machine/sidecar-orchestrator/tests/lending_oblivious.rs`), in TXE and in its e2e scenario
with real proofs.

A tree-valued node-held key whose `tree` entry says `access: oblivious` keeps its leaves and
internal hashes in a distributed oblivious RAM (DORAM) the three nodes hold as XOR shares,
one per key, and takes its position index as an `INPUT_SHARED` app input bound through `C`.
The nodes read and write each slot's path at a shared address, so no node learns which leaf
a round touches, and the paths reach the circuit as shared witnesses instead of PUBLIC
request values. The circuit verifies every path along index bits it takes from the inputs:
the DORAM is not proven, the Merkle check on the committed index is. Dense only: positions
are `0 … 2^D - 1`, the header is leaf 0, openings take the append index. Hashes, leaf rules
and the slot-order update are those of [Tree-valued keys](#tree-valued-keys); only the
differences are stated here.

#### The state-holder value

The manifest rules of `access: oblivious` are in [section 7](#7-the-manifest) (`tree`,
`access`). Since every index input is `INPUT_SHARED`, the key needs a secret-shared intake.
REGISTER also checks the shape one node can serve (sidecar-oblivious `check_shape`):
`depth` 1 to 20, `leaf_len` 1 to 64, `probe` 1 to 16, a DORAM of at most `2^22` addresses
(`MAX_DENSE_LOG_ADDRESSES`), each a 400 naming the field.

The holder is chosen once per key at package load (`sidecar_tip::state::node_held`):
`NodeVersions` (flat), `NodeTree` (`access: clear`) or `ObliviousTree`, which implements
`StateHolder` and sidecar-tip's `TipState` (`state/oblivious.rs`). Nothing above these seams
compares `access`.

#### The DORAM and its measurements

GigaDORAM (Falk, Ostrovsky, Shtepel, Zhang, USENIX Security 2023) in TACEO's Rust port
gigadoram-rs, vendored under `machine/sidecar-oblivious/vendor/` on the machine's co-snarks
pin (`vendor/PROVENANCE.md`). Three-party replicated sharing, semi-honest, the machine's
model. Oblivious cuckoo hash tables in levels behind a linear speed cache: an access touches
every live level once and writes back into the cache; a full cache rebuilds levels
downwards, the bottom level (every address) least often.

Measured on the vendored copy: 188 cores, `--release`, the parties as threads over
`mpc_net::local::LocalNetwork` (no latency), 4,000 random accesses, half writes, bottom built
at start; `recv`s counted per party (an upper bound on sequential rounds). Rows are the
hierarchies `layout::hierarchy` picks.

| Addresses (levels / amp) | bottom build | per access | `recv`s per access | peak RSS, 3 parties |
| --- | --- | --- | --- | --- |
| 2^12 (2 / 4) | 26 ms | 0.51 ms | 23.6 | 22 MB |
| 2^17 (4 / 3) | 1.18 s | 0.70 ms | 26.7 | 654 MB |
| 2^20 (4 / 4) | 12.0 s | 0.66 ms | 23.6 | 4.9 GB |

- An access is about 0.5 ms of compute and 50 to 60 KB per party at every size; a batch of 25
  addresses about 49 `recv`s, of 50 about 75.
- The bottom build scales with the address space. It runs at the key's first session and
  then every `2^(amp·(levels-1)) · (cache - 8)` accesses (`Doram::schedule`): 1,015,808 at
  2^20. Upper rebuilds take milliseconds.
- The bottom level holds every address: about 240 MB per party at 2^17, 1.7 GB at 2^20.
- Lending (`D = 16, K = 2, W = 8`, 2^20): a round reads two slots of 25 addresses and writes
  the previous round's two, about 55 ms of compute and 200 sequential `recv`s plus two
  conversion batches: about two seconds on a 10 ms round trip. The link cost is projected,
  not measured.

#### The DORAM and its layout

One `GigaDoramBn254` per key (one field element per address) of
`2^(D + 1 + max(1, ceil(log2 W)))` addresses:

```text
hash region   heap index: root 1, children of h at 2h, 2h + 1; leaf i's hash at 2^D + i;
              the node at height l on leaf i's path at 2^(D-l) + (i >> l), its sibling ^ 1
leaf region   2^(D+1) + i·W' + e for element e of leaf i, W' = 2^ceil(log2 W)
```

A slot's `D + 1 + W` addresses are shifts, XORs with public constants and ORs of disjoint
index bits, so the nodes derive them locally from an XOR sharing of the index. The DORAM is
built at the key's first session, bottom level first, from the empty tree (`Z_l` at each
hash node of height `l`, zeros in the leaf region), so an empty leaf reads as `tree::load`
expects. Its configuration is public (`layout::hierarchy`): for `2^N` addresses
`levels = 1 + ceil((N - 8) / 4)`, `amp = ceil((N - 8) / (levels - 1))` (log2 of the
amplification), a speed cache of at most 256; stash 8.

#### The round

The [request lifecycle](#3-the-request-lifecycle) with the key's load moved into the mesh
session (the holder's `summand` is none; its load is `load_in_session`):

1. Step 8 skips the key; step 9's check bind uses zeros of its length; step 10's handshake
   carries no summand for it.
2. Step 10b (sidecar-core `pipeline`): read the DORAM from `tip_blobs` (or build it);
   sync it to the loaded version ("Versions, rollback and pipelining", below); convert the
   shared indices to XOR shares (`a2b`, one batch; a public address is a trivial share);
   read each slot's `D` siblings, leaf hash and `W` elements in one batch, slot after slot,
   then the window; convert back (`b2a`, one batch). Rebuilds run inside the accesses.
3. The bind fills `leaves`, `old_hashes`, `siblings` from `[leaves: K·W][old_hashes:
   K][siblings: K·D]`, then the window's leaves, hashes and siblings.
4. The circuit's `TACEO_store` output is, per slot, the stored leaf (`W`), the new leaf hash
   and the `D` new path nodes, slot after slot.
5. Step 15 stages the version (that output) and its journal. Nothing is written to the DORAM
   in this session; what the session advanced (speed cache, rebuilt levels) is persisted in
   the same transaction.

The writes wait for the next session because each node commits on its own: staged as
shares, a one-node commit failure stays a refusal, not a divergence of the joint DORAM.
`a2b`/`b2a` are mpc-core's, about nine rounds per batch.

#### The circuit

The round runs `pss_core::tip::tree`: `tree::load` gives the same `Tree<K, D, W>`, so a
round function over `Tree` is the same under either access. What differs:

- **Indices.** `tree::slot_indices` composes the slots: leaf 0 in the header slot and every
  unused slot, `$new_leaf` in the first position slot when `opens` is 1, else the shared
  input's low `D` bits (`low_bits`), the addresses the nodes read. An input of `2^D` or more
  is read at its low bits and refused by the round's range flag on the raw input.
- **Load.** The index bits are shared; each path is checked by conditional swaps on them;
  every slot's root must equal slot 0's (`paths_ok`), which gives `old_c`. The old-leaf
  check is the one assertion (a diverged DORAM); `count_ok`, `in_range`, `distinct` and
  `paths_ok` are flags.
- **Update and store.** `Tree::update_paths` (and the tagged write) also returns each slot's
  new path nodes; `tree::Oblivious` holds both; `Updated::store_oblivious` stores them.
  Shared ancestors take the later slot's write, as the nodes write slot after slot; an
  unwritten slot gets its old values back.
- **Outputs.** `tree::Oblivious<K, W, D, T>` outputs `T` leaf hashes, all zero (`T = K`
  keeps the clear deployment's public-input layout, `T = 0` none), and `next_index` when the
  layout opens leaves. Under private outcomes the write policy is the clear tree's, and
  nobody but the circuit sees whether a slot changed.

A path of another leaf fails `paths_ok` (a flagged no-op that lands); garbage fails the
old-leaf assertion before anything is stored. Gates are the clear round's less its
leaf-hash outputs and index comparison; the cost is in witness extension: `2·K·D` shared
permutations, sequential in depth twice (64 at `K = 2, D = 16`, against 32 on the clear tree).

#### Openings, the append index and the window

- `opens` is a PUBLIC 0/1 input. At 1 the first position slot opens `$new_leaf`, assigned
  by the scheduler from the nodes' append index and checked by each chain verifier, read at
  a public address; `tree::append` enforces it against the header as on the clear tree.
- The header's `next_index` after the round is public, so the nodes advance their append
  index exactly when an opening applied (they cannot read the shared header).
- A window is `Tree::window` ([A read-only window on a tree key](#a-read-only-window-on-a-tree-key));
  the nodes read its leaves, hashes and the `D - log2 W` siblings at public addresses.

#### Versions, rollback and pipelining

Versions, liveness and retention are [Node-held state](#node-held-state)'s. An oblivious key
cannot have one DORAM per version, so:

- Each attempt's version has the STORE output as its `vec`, and a **journal**
  (`journal.<commitment>`): per slot its read addresses (XOR shares), the raw values read,
  its write addresses and, once applied, the raw values those held, which an undo writes
  back.
- The DORAM holds the canonical state plus every applied attempt in queue order (`applied`).
  The sync plans from the node's chain view which applied entries are orphans (undone
  newest first) and which live ancestors of the loaded version are not applied (applied
  oldest first). The three exchange the plan's hash (400 on a mismatch) and a digest of the
  DORAM head's public bytes, the fill bound and the session's access count (500, "diverged
  oblivious state: resync"). Either way the operator resyncs the diverged node.
- A journal lives as long as its version or its applied entry, whichever is longer; the
  holder's commit deletes the rest. Entries before the parent of the loaded version's
  oldest held ancestor are the DORAM's base, dropped with their journals.
- `pipeline_depth` above 1 works the same, but an orphaned middle attempt undoes everything
  after it. A round with an unchanged commitment stages no version but persists its session.

#### Persistence, resync, share refresh, audit

Each node keeps a key's DORAM in `tip_blobs`, in the holder-blob format of
[Node-held state](#node-held-state) ("Holder blobs"):

```text
oram            head: configuration, level counters, each live level's stamp and query
                bookkeeping, the speed cache; written at every commit that ran a session
oram.level.<l>  level l's build (PRF key, stash, table, the CHT as Rep3 shares, the receivers'
                shuffle as a copy); written after a rebuild replaced it, deleted when gone
applied         the applied list (public); journal.<c> one per attempt
```

At depth 16 (`tests/three_party.rs`) a commit writes the head, about 26 KB; the bottom level,
370 to 386 MB, is written at the first session and after each bottom rebuild.

- **Resync** carries every blob, orphaned attempts' journals included, so the sync can undo
  an applied orphan whose version did not come back; the blob handshake checks the result.
- **Share refresh** XORs a zero-sharing into every blob
  ([Node replacement and key epochs](#node-replacement-and-key-epochs)). The departed node's
  knowledge of the current level layouts reveals no address without the PRF key, whose
  shares moved; each level's next rebuild draws a fresh key and shuffles.
- **Backups** carry the blobs; a restore's delta resync sends a level only when it differs.
- **Audit.** The clear audit reports the key not audited. The oblivious audit is specified,
  not built: an MPC pass, the DORAM paused, that extracts every address and value as
  shares, checks the leaves against their hashes (`2^D`), rebuilds the hash tree
  (`2^D - 1` shared permutations, `D` steps) and opens only the root.

#### The escape hatch on the oblivious tree

[The escape hatch](#the-escape-hatch) runs from the same code: the tagged write stores
`exit_tag(P, request_id, index)` in each written position leaf, the shared index added to the
tag's domain locally; the landing emits the replaced tag; the owner exits on its newest note.

#### Leakage

One node sees `C`, the round type, the probe count, `opens` and the append index (how many
positions exist, whether an opening applied), a window's start and timing; never an index, a
hash or whether a probe was written. The orchestrator sees `C`, the count, `opens` and the
network address. Two nodes see everything; the world sees what it sees on the clear tree. The DORAM leaks its access count (constant per round type) and its
rebuild schedule; every slot is read and written back, so reads and writes look alike. A
round failing after its session is not persisted, so the next session repeats level queries:
the nodes learn which addresses repeat (where two paths part), never an index or a value.
The parties table: `docs/design-guide/README.md`, "What each party sees".

#### The scheduler and the chain verifier

The scheduler reads no paths: `TipState::node_values` returns only `$new_leaf` (when the
layout opens leaves), from `POST /v1/tree` with no indices (the answer carries `next`; the
three must agree). Each chain verifier derives `$new_leaf` from its own append index and
refuses (400) another. `is_valid` cannot range-check shared indices; the circuit's
`in_range` and `distinct` flags do. At step 15 the round's `next_index` must equal the
nodes' append index, or one more on an opening round (500 otherwise, nothing stored). A
creating round writes leaf 0, so its version's append index is 1.

#### The interface the sparse map shares

The dense tree and [the oblivious sparse map](#the-oblivious-sparse-map) are one holder,
`Holder<L: Layout>` (`ObliviousTree = Holder<Addressing>`, `ObliviousMap =
Holder<MapAddressing>`): the DORAM wrapper `oram::Doram<L>` (`read_slot`, `write_slot`,
`undo`, the journal, the schedule, the levels), the sync, the blobs and the recovery are one
code. The `Layout` trait (`layout.rs`) differs in:

- shape: `depth`, `leaf_len`, `log_addresses`, `log_capacity` (all addresses for the dense
  tree, a configured capacity for the map), sized by `try_config`;
- addresses: `slot_reads` (`D` siblings, leaf hash, `W` elements), `slot_writes` (`W`
  elements, leaf hash, `D` path nodes), `mask_path`, `window_reads` (empty for the map);
- the empty tree: `read_offsets`, `write_offsets`, `empty_reads`, `empty_writes`,
  `build_empty`;
- the fill bound `Layout::Bound`: none for the dense tree, `fill::Fill` for the map.

An update writes a loaded leaf, an insert an empty one (old hash 0); absence is a read with
old hash 0 on a verified path.

#### What is built, and what stays experimental

Built: `machine/sidecar-oblivious` (`layout.rs`, `oram.rs`, `holder.rs`) with unit tests,
`tests/three_party.rs` (also depth 16 over a TCP loopback mesh) and `tests/recovery.rs`;
sidecar-core's `access`, `next_index`, `load_in_session`, step 10b, `tip_blobs` (memory and
Postgres) and the holder-blob recovery; sidecar-tip's `state/oblivious.rs`; pss_core's
`slot_indices`, `low_bits`, `update_paths`, `tree::Oblivious`, `store_oblivious`. Lending's
deployment and gate counts: [examples/lending-tip/README.md](../examples/lending-tip/README.md),
"The oblivious deployment".

Not built: the oblivious audit; a rebuild at the session's start (the DORAM rebuilds when
its cache fills, inside an access). It stays experimental because the link cost is
projected and the DORAM is a new joint state whose divergence is detected (sync exchange,
old-leaf assertion, blob handshake) and repaired by resync, with no production history.

### The oblivious sparse map

Status: experimental, never a default ([DECISIONS.md](DECISIONS.md) section 7). A tree-valued node-held key
whose `tree` entry says `access: oblivious` and `keyed: true` is a keyed map: a sparse Merkle
tree of depth `D` whose leaf for a key sits at the path of the key's low `D` bits and holds
`[key, value …, blinding]`, its nodes in one GigaDORAM per key held as XOR shares, its keys
`INPUT_SHARED` inputs bound through `C`. A round proves a key present with its value, or
absent, and neither the nodes nor the chain learn the key, which of the two, or whether a write
inserted or updated. It is the dense brick ([the oblivious tree](#the-oblivious-tree)) over a second address
layout. Its example, `examples/credits-tip`, runs real rounds over three nodes
(`machine/sidecar-orchestrator/tests/credits_map.rs`), in TXE and in e2e with real proofs.

#### What a keyed map is

| | dense oblivious tree | keyed map |
| --- | --- | --- |
| a leaf is named by | a position, from the public append index | a key the app chooses; its path is its low `D` bits |
| depth | 1 to 20, nearly full | 32 to 120 (default 64), almost all empty |
| header, openings, append index, windows | yes | none: the first write to a key inserts it; nobody can enumerate the map |
| non-membership | not asked | a verified path to an empty leaf |
| the DORAM holds | every address, built at the first session | the addresses ever read or written, within a set capacity |

It suits state that whoever knows the key touches and that a round checks for presence or
absence: credits paid to an owner commitment before its owner acts, a registry, a
spent-identifier set. Not a book a third party must scan, a public entry count, or anything
that needs the escape hatch.

#### The key, the path and the depth

**The key is a field element the app supplies**; the brick does not hash it. The circuit takes
its path with `map::path_of::<D>` (`tree::low_bits`: one hinted split of the low limb at bit
`D`, two range checks); the nodes take the low `D` bits of the key share's `a2b` conversion.

**The leaf stores the full key as its first element**, checked against the slot's key wherever
the leaf is not empty. A leaf holding another key with the same low bits is `taken`: the round
refuses it and never writes it under this key. A collision costs liveness for one key, never a
wrong value or a wrong proof of absence.

**Keys must be hash outputs; apps hash at entry.** The request function computes every key as
a domain-separated Poseidon2 of what the caller supplies (free there; in the example,
`map_key(handle)`). A raw key would let anyone block a known key `K` with one request, since
`K + 2^D` takes `K`'s path; through the hash that costs a `2^D` search. `pss_core::tip::map`'s
doc comment states the rule; REGISTER cannot check it. Shares that do not open `C` insert no
key (below), so the hash binds every key that enters the map.

**Depth: default 64, allowed 32 to 120.** With hashed keys a targeted collision costs `2^D` key
hashes and random collisions appear near `2^(D/2)` keys (four billion at 64, 65 thousand at
32). Gates, accesses and memory are linear in `D`, a generic of the circuit.

#### The commitment and the proofs

The hashes, `Z_l` and the commitment are `tip::tree`'s ("[Hashes and associated data](#hashes-and-associated-data)"); an empty map's root is
`Z_D`. Every proof is on the committed root along the request's own key bits, so the DORAM is
not trusted:

- **Membership**: old hash not 0, stored key equal to the slot's, `paths_ok`; the value is the
  leaf's elements `1 … W - 2`.
- **Non-membership**: old hash 0 and the same path check; `tree::load`'s assertion requires the
  zero leaf under old hash 0, so nodes cannot present an occupied leaf as empty.
- **Insert, update, insert-or-update**: a write at an absent or present key; insert-or-update
  is one select on `present`. **Delete** (the zero leaf) is allowed; the example does not use it.

#### The storage: one DORAM addressed by (height, prefix)

**The port changes** (vendored gigadoram-rs, its `PROVENANCE.md`): `primitives::X` is `u128`;
`GigaDoramConfig.log_capacity` sizes the bottom level below `log_address_space_size`
(`GigaDoramConfig::sparse`, built lazily by `GigaDoram::new`, an unwritten address reading 0);
the sort packs `flag | x << 1`; dummy labels are `u128`. A sparse bottom rebuild opens the
sorted dummy flags, which tell the number of real records (`GigaDoram::fill_count`), and fails
on a fill over the capacity instead of truncating. One address type serves both bricks.

**The address layout** (`MapAddressing`, `machine/sidecar-oblivious/src/layout.rs`),
`LW = ceil(log2 W)`:

```text
hash node at height l on the path of key bits p (root: l = D, prefix 0):
    address = l · 2^(D + LW) + (p >> l)          sibling: address ^ 1 (l < D)
leaf element e:   address = (D + 1) · 2^(D + LW) + (p << LW) + e
width N = ceil(log2 (D + 2)) + D + LW <= 126     (D = 64, W = 3: 73 bits)
```

A slot's `D + 1 + W` addresses are shifts, ORs with public constants or XORs with 1 of the
XOR-shared path: local, one batch. Read and write orders, LOAD slices and journal have the
dense brick's shape.

**The empty value is encoded, not built.** The DORAM stores a hash at height `l` as `v ⊕ Z_l`
(leaf elements and leaf hashes as they are), encoded at write and decoded at read on the XOR
shares before `b2a` (`Layout::read_offsets`, `write_offsets`), so an untouched node decodes to
`Z_l` and an untouched leaf to zeros with hash 0. The journal keeps raw encoded values.

**Capacity and the fill bound.** The DORAM keeps a record of every address ever read or
written; its bottom level holds `2^capacity` (the `tree` entry's `capacity`, 8 to 36, default
18; part of the key's shape). A new key costs about `2(D - log2 n) + W + 3` addresses among `n`
keys; reading an absent key costs addresses too. The holder's public bound (`fill.rs`, `fill`
blob) is the count opened at the last bottom rebuild plus every access since, each counted as
new. A session that would run the next bottom rebuild while that bound could pass the capacity
is refused before any access (409, "the keyed map is full"), as is one whose accesses span two
bottom rebuilds (409). A full map stays full: no grow path; set the capacity with headroom.

**Configuration.** From capacity `2^C` (`layout::hierarchy`): `levels = 1 + ceil((C - 8) / 4)`,
`amp = ceil((C - 8) / (levels - 1))`, speed cache `2^(C - (levels - 1) · amp)` (8 of it the
stash); a bottom rebuild every `2^(amp · (levels - 1)) · (cache - 8)` accesses. At `D = 64, W =
3` ("working": keys whose rounds pass the bound indefinitely; memory and rebuild time measured
at `2^17` and `2^20` (240 MB, 1.2 s; 1.7 GB, 12 s) and scaled between, [the DORAM's measurements](#the-doram-and-its-measurements)):

| capacity | levels / amp, cache | keys working | keys that fill it | memory per node | bottom rebuild |
| --- | --- | --- | --- | --- | --- |
| `2^16` | 3 / 4, 256 | 16 | 580 | 120 MB | 0.7 s per 63,488 accesses |
| `2^17` | 4 / 3, 256 | 33 | 1,181 | 240 MB | 1.2 s per 126,976 |
| `2^18` (default) | 4 / 4, 64 | 285 | 2,410 | 430 MB | 3 s per 229,376 |
| `2^20` | 4 / 4, 256 | 285 | 10,018 | 1.7 GB | 12 s per 1,015,808 |
| `2^22` | 5 / 4, 64 | 4,914 | 41,727 | 6.8 GB | 48 s per 3,670,016 |

At `D = 32` a capacity keeps about twice the keys.

#### The round on a keyed map

[The dense tree's round](#the-round), step for step. Inside step 10b: the sync encodes each applied
value; the fill bound runs; key shares go to XOR (`a2b_many`, one batch), their low `D` bits
the path (path 0 in an unused slot); one `batch_read` per slot, decoded; `b2a_many` into the
LOAD vector. The request carries the keys (shared), the count and the app's inputs, nothing
from the nodes.

#### The keyed map's circuit

`pss_core::tip::map` is `tip::tree`'s `Tree<K, D, W>` loaded at the keys' paths, so
`update_paths` and `Updated::store_oblivious` are the dense brick's.

```text
map::path_of::<D>(key);  map::paths::<K, D>(keys, n_used)   (0 in an unused slot)
map::load(namespace, key_slot, keys, leaves, old_hashes, siblings, n_used) -> Map; map::empty
    present[k] = !is_zero(old_hashes[k]) & !is_zero(leaves[k][0])
    taken[k]   = present[k] & !eq(leaves[k][0], keys[k]);   keys_ok; value(k); absent(k)
Map::update(ok, writes, values, r_new)    leaf [keys[k], values[k] …, r_new[k]], never if taken
Map::update_private(opened, ok, writes, reblind, values, r_new);   Map::change -> MapChange
```

The brick writes the key, never the app. Flags for the app's codes: `distinct`, `paths_ok`,
`count_ok`, `keys_ok`. `Tree::placed` (`count_ok & in_range & distinct & paths_ok`; `in_range`
always holds for a map) is folded into every update: an unplaced map writes nothing and is the one round
that leaves the commitment unchanged. The app requires `present`, its negation, selects on it
or outputs it privately.

**Every keyed round writes a fresh blinding.** Under private outcomes every used slot not
`taken` is written on every outcome: the round's value where it lands, else the slot's own
value (zero when absent, so an absent key enters with zero); a `taken` slot is re-blinded with
the other key's leaf. The app reads zero as absence. The credits example's `shared::finish` is
the rule's code.

**No key enters unless `C` opens.** Under `opened` false (`SharedIntake::opens`) nothing lands;
each slot is re-blinded as loaded, an empty one into a vacant leaf `[0, 0 …, r]` (key 0, no
hash output), absent to every round.

**Gates.** `2 · K · D` shared Poseidon2 permutations plus the leaf hashes; witness extension
runs `2 · D` sequential shared permutations per slot. Measured in `examples/credits-tip` (`D =
64, W = 3`, app logic included): 15,027 to 15,139 for one-key rounds, 26,489 for `K = 2`.

#### The keyed map's manifest entry and REGISTER

[Section 7](#7-the-manifest)'s `tree` row specifies `keyed` and `capacity`. Under `keyed: true` REGISTER requires,
beyond the `access: oblivious` rules: no `header`, `open`, `next_index` or `window`; `depth` in
`32 ..= 120` with `N <= 126`; `leaf_len` in `3 ..= 64`; `capacity` in `8 ..= 36` with a
hierarchy the DORAM accepts; `probe` in `1 ..= 16`; `index` the key inputs in slot order; a
created map `probe` 1 and no `index` (sidecar-oblivious `check_shape`, sidecar-core
`validate_keyed`). `sidecar_tip::state::node_held` picks `ObliviousMap` at package load.

#### Versions, persistence, recovery and the hatch of a keyed map

As the dense brick ([versions](#versions-rollback-and-pipelining), [persistence and recovery](#persistence-resync-share-refresh-audit), [node-held state](#node-held-state)), except: the holder keeps the
public `fill` blob, compared in the sync handshake; a resync by replay needs no bottom build;
the oblivious audit (not built) walks the extracted records, not `2^D`. **No hatch**: the map's
private write re-blinds slots at keys the prover chose, so it breaks the exit tag's rule that a
round whose shares do not open `C` writes no entry ([the escape hatch](#the-escape-hatch)). Vanished nodes freeze the entries; queued escrow returns by `skip()`.

#### What a keyed map leaks

As the dense tree's, except: no entry count exists anywhere, and each node sees the fill count
opened at every bottom rebuild (the order of the key count). Who sees what: [DESIGN.md](DESIGN.md).

#### The scheduler and the chain verifier on a keyed map

Nothing: a keyed round carries no node-sourced value (`TreeValues for ObliviousMap`).

#### The interface shared with the dense tree

One `Holder<L: Layout>` ([the interface the sparse map shares](#the-interface-the-sparse-map-shares)). The map's `Layout`,
`MapAddressing`: (height, prefix) addresses, `mask_path` the low `D` bits, no window reads,
lazy `build_empty`, the encoding offsets, `fill::Fill` as its bound.

#### Costs of a keyed slot

Per slot, from the [measured per-access numbers](#the-doram-and-its-measurements):

| | lending's dense slot (`D = 16, W = 8`) | keyed slot (`D = 64, W = 3`) |
| --- | --- | --- |
| DORAM reads, then writes next session | 25 + 25 | 68 + 68 |
| sequential `recv`s per batch | about 49 | about 95 |
| per round, `K = 2` | about 55 ms; 2 s at a 10 ms round trip | about 150 ms; 4 s |
| shared permutations in the circuit | 64 | 256 |

#### The keyed example: credits paid to a key

`examples/credits-tip`: anyone pays credit to a key (insert-or-update); its owner claims, views
(the prove-absent round) or moves it (`K = 2`). [Its README](../examples/credits-tip/README.md)
has the rounds, codes, contract and costs.

#### What of the keyed map is built, and what stays experimental

Built: the port changes; `MapAddressing`, `Doram<L>` with the encoding, `Holder<L>` with the
fill bound, `ObliviousMap`, with a three-party test against a clear sparse tree; sidecar-core's
`keyed` and `capacity`; pss-client's reader; the schema; pss_core `tip::map`; the credits
example end to end. Not built: a resize of a full map (extract every record, rebuild larger,
carry the applied list); the oblivious audit. Experimental beyond the dense brick's reasons:
the widened address changes vendored protocol code, measured in-process only; a full map stays
full; the collision argument rests on apps hashing keys; the fill count leaks the map's size.

### The escape hatch

A library brick with two halves and a client module: pss_core `tip::exit` (the exit tag of a
tree-valued key's entries and the tagged write), pss_public_contract `hatch` (the `Hatch` state
variable: the starving clock, the opening, the landing's tag emission and the private exit) and
pss-client `hatch.ts`. Lending uses it on every deployment
([examples/lending-tip/README.md](../examples/lending-tip/README.md), "The escape hatch").

An app whose network stops serving it is frozen: `skip()` refunds what is queued, but value
held in shared state has no round to release it (invariant 0). The hatch opens such an app for
good after a liveness period and then lets each owner of an entry leave with one private
transaction on its newest note: no node, signature, FETCH, round or public call. The chain does
not learn which entry left.

**The clock and the opening.** `Hatch` takes one storage slot, `HatchState` packed (`open` and
`starving_since`, the block from which the app has had demand and no landed round; 0: not
starving). The app calls `queued()` in every request wrapper and in its permissionless `poke()`:
it refuses while open and starts a stopped clock. It calls `landed(queue, served, tags)` in
every function that lands a queued request: it refuses while open, emits the round's exit tags,
and, when the round served its request, stops the clock (or restarts it when requests are still
queued). A round that served nobody (shares that did not open `C`) leaves the clock running, and
`skip()` never touches it, so only the nodes stop the clock, by serving a request. `open(t_live)`
is the body of the app's `open_hatch()`, which anyone may call once the clock has run the app's
liveness period; nothing clears `open`. Once open, no request is queued and no round lands;
`skip()` and the app's `redeem` keep working.

**The exit tag** (section 1, "exit tag and filler"). `P` is the partial commitment of the note
the tag belongs to, `request_id` the chain request id of the round that issued the note (never
the attempt's, so every attempt outputs the same values) and `entry` the entry's leaf index
(below `2^120`), folded into the first element so each hash is one permutation. `P` is the
secret. No sampled value enters a tag, so nodes cannot aim one tag at another.

**The rules** (pss_core `Tree::update_private_tagged`, `Tagged`, and `Hatch`):

1. *One unspent tag per entry, the newest note's.* Every non-empty entry leaf holds one tag in
   its second-to-last element (the last is its blinding); the header leaf holds none. A round
   that writes an entry slot stores `exit_tag(P_k, request_id, index_k)` in the new leaf, `P_k`
   the partial commitment of the note the round issues for that entry (the requester's own, or a
   delivery handle's for an entry it changes on its owner's behalf: "Partial-note delivery"), and
   outputs the old leaf's tag, which its landing emits as a nullifier. Any change of a leaf's
   content is a write, so a note whose tag is unspent reports the leaf as it stands.
2. *Every round outputs the same number of exit values*, `EXIT_TAGS`, the most entry slots any
   round of the app has (`Tagged::nullifiers`): per entry slot the old tag where the round wrote a
   leaf that held one, else a filler; then fillers. A filler is `exit_filler(requester's P,
   request_id, j)`, or, for a slot that opens an empty leaf, the second output element of the
   permutation that made the slot's new tag. Only the requester tells fillers from tags, and no
   filler equals a tag, so every round type shows the chain the same effects.
3. *A note names an entry only if its round wrote that entry.* `Tagged::entry(k)` is the slot's
   index where written and 0 otherwise.
4. *A round whose shares do not open `C` writes no entry slot* (only the header's index is bound),
   so nodes that change their shares cannot spend an owner's tag. A keyed map's private write does
   not keep this rule, so there is no tagged map.
5. *Once open, no request queues and no round lands*, so every unspent tag stays unspent until
   its owner exits.

The circuit half is permutations, additions and selects: no assertion, and it runs in co-noir.
Each entry slot costs one permutation in every round, each padding filler one more.

**The landing emits the tags in public.** The landing's private function passes the proof-bound
exit values to the public call that moves the commitment (lending's `apply_shared(apply, opened,
tags)`), where `Hatch::landed` emits each as a nullifier, refusing 0. So a tag is spent exactly
when its leaf is replaced, and a landing whose public part reverts spends nothing. Emitting in
public keeps two landings of one result from sharing a pending nullifier, which would let anyone
evict an honest landing with a higher-fee copy that then reverts. A public nullifier is siloed
with the contract's address like a private one, so an exit collides with it.

**The private exit.** `Hatch::exit(note, sender)`, under a private context, takes the note the
app read with its inclusion check (`ExitNote`: the entry it names and its round's request id),
requires it to be the sender's (`partial_note::assert_owned`) and to name an entry, reads `open`
at the anchor block from the slot's history (`open` never clears), and pushes `exit_tag(P,
request_id, entry)` with `P` rebuilt from the note's owner and randomness. Every input comes from
the note, so a second exit, or an exit on an older note of the entry, pushes an existing
nullifier and is refused. The exit writes no public state; the app pays what the note says after
the call (lending credits it as `redeem` does).

On the client: `exitTagOf(note)` computes a note's tag; `liveExitNote(node, app, notes)` returns
the newest note whose tag is unspent; `exitTagSpentAt` and `exitTagSpender` give the block and the
transaction that spent a tag (a round the owner did not request wrote its entry); the owner reads
that round's delivery to its handle among the transaction's private logs (`DeliveryReader.readIn`).
This needs no old state: the nullifier tree names the block and the archiver keeps every block's
transactions. `recoverExitNote` repeats that walk while the newest note's tag is spent, handing the
app each notice, and ends on the note an exit takes (or on a tag spent by a transaction with no
delivery to the handle, which only the owner makes). `hatchReady(state)` says whether
`open_hatch()` lands and how many blocks are left.

**What an app needs to use it.**

1. Private outcomes by partial-note completion (a secret-shared intake), so each note has a `P`,
   and one intake family per deployment (a non-secret-shared round writes no tag).
2. Per-owner entries in a tree (not a keyed map, rule 4) whose leaf spares its second-to-last
   element for the tag.
3. An outcome note that names the entry it reports and its round's request id (`ExitNote`).
4. Every round that writes an entry issues the entry's owner a note reporting the entry after
   the write (the requester's own, or a delivery to a handle the owner left in the entry); a write
   that issues none freezes that entry until the owner's next round, never loses it.
5. A rule for what a note pays on exit, applied after `Hatch::exit`.

An app with no per-owner entry (a pool, a counter) cannot exit by tag; it can use `Hatch`'s
clock, opening and refusals with an exit rule of its own.

A tag is known to whoever knows its `P`: the owner; two or all three nodes (any two reconstruct
`P`); a liquidator, for the tag its liquidation stores at a probe whose leaf holds no handle
(made from its own request's delivery seed; no note opens to it). Not to one node, the relayer, a
FETCH reader or a chain observer. Knowing a tag lets one see it spent, never spend it: only the
contract emits a nullifier under its address, a landing emits only what a pinned circuit's proof
outputs for the head request, and `exit` only the tag of a note the sender owns. What the world
and the nodes see is in DESIGN.md, "Who sees what".

### The examples on node-held state

Every tip example's rounds run on node-held state; each example's README gives its rounds,
manifests, layout and measured costs.

- The AMM tip (`examples/amm-tip`): the pool's reserves are one flat key of three elements (two
  reserves and a blinding). Under a secret-shared intake the trader's request commits the partial
  note of its own address, the round completes it with `[code, amount_out, request_id]`
  (`amount_out` 0 on a failed swap), and the trader spends it with `redeem`. The non-secret-shared
  swap commits the same note and `apply` completes it in public.
- Lending (`examples/lending-tip`): the book is a tree-valued key (`D = 16`, `K = 2`, eight-element
  leaves; leaf 0 the market header with its append index); owner rounds touch the header and one
  position, a liquidation up to `K - 1` named positions, the keeper's scan a window; every round
  makes a pinned price read (`epoch`) and a pinned clock read (`tolerance`), so the public `apply`
  is the same for every round type.
- The credits tip (`examples/credits-tip`): the oblivious sparse map with a fixed key set.
- The counter tip (`examples/counter-tip`): the minimal app with a client.

### Secret-shared intake

Status: built, both intakes, in the machine, the contract library and pss-client.
Secret-shared receipt intake (`shared_receipt`) is the default intake of every tip
example's queued rounds. Secret-shared on-chain intake (`shared_onchain`) runs on the AMM
tip's swap and lending's deposit: each is its round's one secret-shared circuit registered
again under a manifest of its own (`amm_swap_tip_shared_onchain.json`,
`deposit_shared_onchain.json`). Rust, TypeScript and Noir read the same vectors
(`testvectors/shared_intake.json`, `shared_onchain.json`, `onchain_layouts.json`). The
three-party cases run them over three nodes in process (sidecar-orchestrator
`tests/shared_receipt.rs`, `amm_tip_shared.rs`, `lending_tip_shared.rs`; the machine's
`tip_counter_shared` circuit), each example's TXE suite runs them in the contract, and the
e2e scenarios run them with real proofs (`docs/TESTING.md`).

Under on-chain intake and receipt intake every node sees every request input in the clear.
A secret-shared intake hands each node one Rep3 pair of each sensitive input instead, and
binds the inputs through a hiding commitment `C`. The two secret-shared intakes differ only
in where the shares come from: envelopes sent through the orchestrator (receipt), or one
private log the user's own proof writes (on-chain). Round circuits, the MPC receipt check,
the outcome path and the result path are the same, so one compiled circuit per round,
`<round>_shared`, serves both, and `<round>` serves both non-secret-shared intakes (a thin
generated main over the round's one source in the app library: artifacts multiply, code
does not). The round takes its inputs as private witnesses under every intake; co-noir
treats a witness as public or shared by how it is supplied, so the intakes differ in who
computes the binding: the contract from the request log (on-chain intake), the nodes
(receipt intake), the user (secret-shared intakes).

| Intake | `intake` | Inputs reach node i as | Binding | Chain request id | On chain |
| --- | --- | --- | --- | --- | --- |
| on-chain intake | `onchain` | clear, from a public request log | `inputs_hash` | `poseidon2([namespace, vk_hash, inputs_hash, user_nonce])` | request id; the request log (inputs, `user_nonce`) |
| receipt intake | `receipt` | clear, over TLS through the orchestrator | `inputs_hash` | as on-chain intake | request id, expiry block |
| secret-shared receipt intake | `shared_receipt` | its own envelopes, through the orchestrator; clear app inputs in the clear | `C` | `poseidon2([namespace, vk_hash, C])` | request id, expiry block |
| secret-shared on-chain intake | `shared_onchain` | its pairs derived from one private log; clear app inputs in that log | `C` | as above | request id, `data_hash`; the private log, for good |
| relayed intake | deferred, refused at REGISTER | | | | |

The non-secret-shared intakes take one public-input layout, `[namespace, vk_hash, in_slots,
out_slots, pinned values | request_id, old commitments, new commitments, npk_app_hash, ok,
app outputs]` (`proved_public_inputs`), with the app inputs and `user_nonce` private and
the chain request id a proof output; the init round's layout is the same
(`init_public_inputs`, nonce 0). The secret-shared proofs output the chain request id too.
A pinned value is a public input and an app input never is, so a round whose pinned reads
differ is a circuit of its own.

Who sees what under each intake (the world, each node, the orchestrator, the relayer), what
a participant infers from its own outcomes, and what a leak of all three nodes costs:
[DESIGN.md, "Who sees what"](DESIGN.md#who-sees-what).

#### What the world learns: not the round type

Node-held state logs no state, so under a secret-shared intake a contract can make every
round type look the same, and both tip examples do. Each app has one public request
wrapper and one public `apply` with the same arguments on every round, makes the same
pinned reads on every round (lending reads the price on deposits and repays too), and
pushes the same effects on every result: one note hash (the AMM's completed note, lending's
outcome note) and one private outcome log. The outcome log and secret-shared on-chain
intake's request log are padded to the full 16-field v6 private log with deterministic
padding: position `i` holds `poseidon2([tag, i])` in the outcome log (`pss_core::tip::outcome::log_padding`,
over the unsiloed tag) and `poseidon2([blinding, i])` in the request log (whose tag anyone
computes from the public request id), so the submitter chooses no field. The private
functions behind the wrapper may differ per round type: v6 publishes only their effects and
the public calls they enqueue. Gas follows effects and public execution, and each app sends
every transaction kind under one gas setting (pss-client `FeeSetting.gas`). Each example's
TXE suite (`test_round_shape.nr`) compares every round type's request and result (the public
calls, the counts of note hashes, nullifiers, public writes and logs, each private log's
length and the metered gas), and the tip e2e compares the gas each transaction used; each
example's README tabulates both. An app keeps a round type visible only where it must
change genuinely public state, and says so in a DEV DECISION; neither example does. The
non-secret-shared intakes reveal the round type through their clear inputs. Timing stays
visible (proving time per circuit; a redeem after only some rounds).

#### The inputs commitment and the request id

`C`, the secret-shared chain request id, the summand commitments `S_j`, the sharing digest
`D` and the receipt message are defined in section 1, "Hashes and associated data". `S_j`
and `D` exist only under secret-shared receipt intake; on-chain intake has no receipt.

`C = poseidon2([v_1, …, v_m, blinding])` covers every value the round takes as an app input
or reserved shared value, in the order the ABI walk first meets each: the request public
names of the PUBLIC sources (the inputs left clear to the nodes), the INPUT_SHARED app
inputs, and the reserved INPUT_SHARED `$partial_note`, `$outcome_key` and `$outcome_tag`.
`blinding` is drawn uniformly per request and sent as the INPUT_SHARED value `$blinding`.
The circuit recomputes `C` (the MPC receipt check, below), so the round's proof, not only the
nodes' signatures, binds its inputs to the queued request; the user's private function
computes `C` from the same plaintext over which it asserts static validity; `C` does not
depend on the envelope encryption, so `enc` rotation leaves request ids alone. Because `C`
covers `$outcome_key` and `$outcome_tag`, no node can swap the key the outcome is sealed
under.

The id holds no `user` and no `user_nonce`: two requests share an id only if their `C`
values collide, and the binding of a request to its owner is a note (lending, "Ownership by
note"). The receipt message has `D` after the expiry block, five elements, so a
secret-shared receipt is never a receipt intake one. The non-secret-shared chain request id
holds no `user` either; its `user_nonce` is a uniqueness salt drawn at random per request,
never a counter.

#### The hidden requester

Under every intake the requester's address reaches neither the chain nor the nodes. The
user's private function reads `msg_sender` only in private, into nothing public: a round
anyone may request asserts no calling account; an owner-bound round asserts that the opened
note's owner is `msg_sender` ("Ownership by note"), a private check whose result enters no
request id, log or public argument. It enqueues the app's own `#[only_self]` public wrapper
(`enqueue_self`), so the public call's `msg_sender` is the app contract; a call into
another contract's public function goes through an incognito enqueue. The address never
enters a request id, a request log, a receipt, a `receipts` row, a synthesised request or a
proof's public inputs, and REGISTER refuses `$user` under every tip intake. Every
transaction pays through the private fee-payment contract ("Fee payment"); the usage
deposit moves a token from the user into the app contract, so the token sees the app
contract as caller; and the owner of a completed note is behind its partial note `P`
("Private outcomes"). On the receipt routes the orchestrator sees the user's network address
beside the inputs or `C`; a user who must hide it uses a relay or a mixnet, outside the build
(DESIGN.md, "Who sees what"). The requester audit runs in pss_tip_test `audit`, sidecar-tip
`audit`, pss-client `assertNoRequester` and the e2e `tip-audit` step.

**One intake family per namespace.** REGISTER refuses, in one namespace, a
non-secret-shared package that reads a key beside a secret-shared package that writes one,
since the non-secret-shared round's public outputs would publish state that shared inputs
touched. A manifest names keys only by position (`$state_keys.reads[i]`), so the rule
applies to the namespace: every key a queued package reads or writes counts as every other
queued package's (sidecar-core `registry::intake_families_clash`, 400; the orchestrator runs
it on its registry copy before forwarding). A non-secret-shared package that reads no key
(the init round) sits beside the secret-shared rounds; the examples run their other
non-secret-shared cases on deployments of their own.

#### Secret-shared receipt intake, end to end

The wire types (`ReceiptRequest`, `ReceiptAnswer`, `ReceiptResponse`, `StoredReceipt`) are in
section 1, "Types that cross a boundary".

1. Client (pss-client `intake-shared-receipt.ts`, `sharedReceiptIntake` through
   `obtainIntake`): draws `blinding`, and takes `$outcome_key`, `$outcome_tag` and `rho` from
   its `SecretStore` ("Private outcomes"); computes `C` and the chain request id; splits C's
   shared values (every INPUT_SHARED value, the reserved ones included, in C's order) and
   the blinding into three Rep3 summand vectors `s_0 + s_1 + s_2` (sidecar-tip
   `CommitmentLayout::summand_names`), node i's pair of each value `[x_i, x_{i-1}]`; draws a
   salt per vector and computes `S_j` and `D`; seals each pair in an envelope under the
   intake associated data, and node i's salts `[salt_i, salt_{i-1}]` in one more envelope,
   `$summand_salt`, the last of `shared_inputs`; sends `POST /v1/receipt`. It keeps the
   sharing for the request function. The node that lacks `s_j` cannot test guesses against
   `S_j`: the vector's last element is a summand of the uniform blinding.
2. Orchestrator (receipt proxy): checks `share_hashes[i]` against envelope i for every
   envelope and node, and that `D` is the digest of the summand commitments, the circuit's
   layout kinds and the clear inputs (400); fixes `expiry_block`; projects to node i; requires
   the three answers to agree on `(request_id, inputs_hash, expiry_block)` and each signature
   to verify over `C` and `D`; returns the three signatures. It opens no envelope.
3. Node i (with `[tip]`; without it 400): checks the expiry against its own chain view;
   resolves the package; range-checks the clear app inputs (the only static validity it can
   check); checks `D` against the summand commitments, the layout it derives from the manifest
   (`commitment_layout`) and those clear inputs (400, before anything is stored); computes the
   chain request id from the namespace, the package's `vk_hash` and `C`; checks the hash of
   each of its envelopes, the salts' included; opens each under its current `enc` scalar and
   the intake associated data (400 for an envelope that does not open or opens only under the
   previous scalar of a rotation); checks alone that its opened pairs, in `summand_names`
   order, with `[salt_i, salt_{i-1}]`, hash to `S_i` and `S_{i-1}` (400 naming
   `summand_commitments[j]`), and keeps no pair; signs the receipt message over `C` and `D`
   (the receipt-nonce seed of section 1); stores the `receipts` row: circuit, `vk_hash`, the
   clear inputs, `inputs_hash` = `C`, `expiry_block`, `stale_blocks`, the signature, and per
   shared input its own envelope and the three share hashes (not the salts' envelope). It
   never stores or signs a plaintext shared input. Each `S_j` is checked by both nodes that
   hold `s_j`, so three receipts over one `D` mean the three nodes hold one sharing and the
   same clear inputs. A repeat under a stored id must carry the stored clear inputs and
   envelopes (409 otherwise) and is signed over its own `D`. Pruning is receipt intake's
   ("The receipt route").
4. User's private function (`pss_public_contract` `outcome_request`, the body of every
   secret-shared request function, which commits the sender's partial note and calls
   `shared_receipt_request`): takes the round's row of the round table (the vk pin and the
   `sig` keys), the round's `Layout` global (CLEAR or CHOSEN per value of `C`, generated from
   the manifest by `scripts/gen-intake.py --layouts`, and equal to the machine's
   `commitment_layout`), and as private arguments the plaintext inputs, the reserved values,
   the sharing (`Sharing<L>`: `summands [[Field; L]; 3]`, `salts [Field; 3]`, `L` the shared
   values plus one), `expiry_block` and the three receipts; asserts the app's `is_valid`;
   asserts that the summands add up to C's CHOSEN values in order and takes the blinding as
   the sum of their last elements (`opened_sharing`); computes `C`, the chain request id,
   each `S_j` and `D`; checks the three receipts against the row's `sig` keys; and enqueues
   `append_before(request_id, expiry_block)` through the app's one request wrapper. The
   chain sees the request id and the expiry block. A request whose shares or clear inputs do
   not open `C`, or whose layout is not the machine's, fails in the user's own proof. The
   sharing check costs about ten Poseidon2 permutations.
5. Scheduler: for a head whose package has intake `shared_receipt`, reads the row from all
   three nodes (`GET /v1/receipt`), requires them to agree on everything but the envelope,
   and synthesises the `Request<Full>`: `public` holds the clear app inputs, `$vk_hash`,
   `$inputs_hash` = `C` and the pinned values; `shared_inputs` holds one entry per shared
   input in ABI order, the three nodes' envelopes as `shares` with the stored
   `share_hashes`. No public value is a shared input, and `C` is not a public input of the
   proof. Rows missing at a node or disagreeing give no request (logged); the entry waits and,
   once stale, is skipped.
6. Chain verifier at node i: takes the inputs from its own row, recomputes the chain request
   id from `C`, and compares its projection of the rebuilt request byte for byte.
7. The round: steps 5 to 16 of section 3. Step 6 checks node i's envelope hash, step 9
   opens it under the intake associated data, and step 10's handshake compares the summand
   hash of every pair two neighbours hold, so a substituted pair is refused before witness
   extension. Every recompute (a new machine request id) reuses the same envelopes and share
   hashes.
8. Result: the private outcome path ("Private outcomes"). The proof outputs the chain
   request id, so `process_result` takes no request input; it computes the machine request
   id from its private arguments, and the world sees only the enqueued `apply`.

#### The intake associated data

The user cannot know the body the scheduler synthesises, so under a secret-shared intake an
envelope's associated data binds the chain request instead of the body (the nonce, section 1,
"intake associated data"). The binder takes it for a request whose manifest has intake
`shared_receipt`. An envelope opens only at node i, for its namespace, chain request, circuit
and input name, and every recompute reuses it; invariant 7 holds with "the chain request" for
"the request body". A client may seal all of node i's pairs under one ephemeral key: the
input name in the nonce keeps every encryption distinct.

#### The MPC receipt check

Every secret-shared round circuit takes `C` (PUBLIC `$inputs_hash`), `blinding` and the
shared inputs as private witnesses, and `vk_hash` as every queued round does. Inside the MPC
it computes `inputs_match = (poseidon2([v_1, …, v_m, blinding]) == C)` and folds it into `ok`
as the first check, with its own code (the AMM's 9, lending's 14), and outputs the chain
request id computed from the namespace, `vk_hash` and `C`. It is a flag, not an assertion,
so the circuit stays total. The sharing is checked before the queue, so the flag is a
backstop:

- a request whose shares or clear inputs do not open `C` is never queued: under
  secret-shared receipt intake the nodes' checks against `S_j` and `D` (step 3) and the
  request function's (step 4) bind one sharing that opens `C`; under secret-shared on-chain
  intake the user's proof computes the encoding itself;
- an honest user's malformed request is never queued: its private function asserted
  `is_valid`;
- a node cannot substitute an input alone: the handshake compares its pairs with its
  neighbours' and step 6 checks its envelope hash. Only nodes that change their shares after
  intake make a round that does not open (two colluding nodes, outside Rep3's honest
  majority). That round is an `ok = false` no-op: the head moves, its outcome is the mismatch
  code alone, sealed in the mismatch domain ("Private outcomes"), and `apply` returns the
  escrow and usage deposit in full (the inputs-opened bit, "Tokens and escrow"). Without a
  Poseidon2 collision no party proves a round on inputs other than those `C` commits to;
- the output request id depends only on values every node checked against `requests[head]`,
  so a mismatch never fails `apply`'s head check;
- the bricks gate their writes on it: the private updates (pss_core
  `Loaded::finish_private`, `Tree::update_private`, `Map::update_private`) take the flag as
  `opened` and land nothing when it is false, whatever the app's `ok`. They still re-blind
  what is bound without the inputs (a flat key's vector, a tree's header), and a keyed map
  re-blinds the slots as loaded, an empty one into a vacant leaf, so no key the request did
  not commit enters the map.

The flag and its code are inside the outcome ciphertext: the user learns of a mismatch, the
world does not.

#### Static validity

The intake's static checks (the AMM's codes 1 to 3 and `min_out` below 2^64; lending's codes
1 to 3 and 15, the index rules of a tree-valued key) are asserted in the user's private
function, which sees the plaintext. The receipt route checks only the clear app inputs. The
round circuits flag the same codes as total circuits do, the backstop for an app whose
intake omits `is_valid`; each example puts its mismatch code ahead of them.

#### Secret-shared on-chain intake

The user's private function shares the inputs itself and puts them on chain in a form only
the nodes can open, so the user never meets the orchestrator. The ciphertexts stay on chain
for good: whoever later learns two nodes' `enc` scalars of an epoch, or breaks the Grumpkin
key exchange, opens every request's inputs under it (DESIGN.md, "Who sees what").

**Node keys in public state.** The library's `SharedOnchain` keeps two slots, `enc_keys` and
`data_hashes` (the contract manifest's `storage.shared_onchain`). `enc_keys[i] = (pk,
epoch)` holds node i's current `enc` public key; nothing pins an `enc` key at deployment, and
epoch 0 is no key. A node rotates with a transaction to the app's private `rotate_enc_key(i,
key, signature)`: its library half (`check_enc_rotation`) checks that the key is a Grumpkin
point and node i's Schnorr signature over the `enc` rotation message (section 1), under its
`sig` key of the contract's current key epoch (no grace window), and enqueues
`SharedOnchain::rotate`, which requires `epoch` = stored epoch + 1. The node signs with
sidecar-tip's `rotate_into` (`sidecar-node sign-enc-key`, the admin socket's
`sign_enc_key`), which keeps its current scalar pending as that epoch's for that contract;
the operator submits the transaction (pss-relayer `rotate-enc-key`, per contract, the first
key, epoch 1, included). The node records the scalar when the rotation lands: its pruning job
reads the contract's stored key with the queue's head and tail at one block, and records the
epoch once the stored key is its own or the stored epoch has passed it. Signing a pending
epoch again replaces its scalar, so a rotation that never lands leaves nothing to clear; a
landed epoch is refused under another scalar. The binder derives with a pending scalar too,
since a request names an epoch only once it has landed.

**The epoch rule.** The user's private function reads the three keys at its anchor block (a
historical public-storage read) and names their epochs in the log. The public
`append_onchain_shared` asserts that each named epoch is the stored epoch or the one before
it, so a request on an older anchor reverts at intake and the user resends. A node retires a
scalar once the contract's stored epoch is two ahead of it and the head has passed every
queued request naming it: from the block the stored epoch reached `e + 2` no new request names
`e`, so the scalar goes once the head reaches the tail read then (sidecar-core `epochs`,
`EpochKeys::observe`, run by the pruning job per contract). The stored epoch, head and tail
come from one snapshot at the settled block, the finalized tip (sidecar-tip `standing`): a
request appended between separate reads would lose its scalar early, and a block above the
finalized tip can still be replaced. Each contract keeps its own `enc_keys`, so one node
rotation is one transaction per secret-shared on-chain namespace, and a node keeps its epochs
and retired scalars per contract, in the key directory's `enc.epochs.json`, which
`backup-keys` carries.

**The encoding** (sidecar-core `derived`, `pss_core::tip::derived`, pss-client
`intake-shared-onchain.ts`; the hashes in section 1, "derived intake shares"). The user
draws one ephemeral scalar `e`, computes `E = e·G` and, per node, `s_i = x(e·P_i)`:

- seeds `t_i = PRF(s_i, 0)`; seed `t_i` must reach node i and node `i + 1`, so the log carries
  the wrap `w_i = t_i + PRF(s_{i+1}, 1)`, which node `i + 1` unwraps;
- for the j-th shared value `x_j` (C's shared values in C's order, then `$blinding`),
  `a_{0,j} = PRF(t_0, j + 2)`, `a_{1,j} = PRF(t_1, j + 2)`, `a_{2,j} = PRF(t_2, j + 2) + c_j`,
  with the correction `c_j = x_j − a_{0,j} − a_{1,j} − PRF(t_2, j + 2)` in the log. Every
  shared value but `$blinding` is chosen by the user (each INPUT_SHARED app input,
  `$partial_note`, `$outcome_key`, `$outcome_tag`), one correction each; `$blinding` is
  defined by the encoding as `a_0 + a_1 + a_2`, with no correction;
- node i knows `t_i` and `t_{i-1}`, so it holds the pair `(a_i, a_{i-1})`, the Rep3 layout,
  and lacks `t_{i+1}`. `E` travels as its x-coordinate (`x(s·E)` is the same for `±E`).

**The request log** is one private log: `[tag, C, epochs, E.x, w_0, w_1, w_2, clear inputs…,
c_1 … c_m, padding…]`, `7 + q + m` fields for `q` clear app inputs and `m` chosen shared
values, `q + m <= 9`, padded to 16 (the epochs packed in one field). The AMM swap needs 13
fields, lending's deposit and owner rounds 12, a liquidation `11 + K` (so `K <= 5`). The tag
is `compute_log_tag(chain_request_id, REQUEST_DOMAIN)`, siloed by the kernel. The library's
`shared_onchain_request` (called by `outcome_request`, given the round's `Layout`) emits it and
enqueues `append_onchain_shared(request_id, data_hash, epochs)`, whose body
(`SharedOnchain::append`) checks the epochs, appends the request and stores
`data_hashes[request_id] = poseidon2(log fields after the tag)`; no input passes through
public calldata. The user's proof computes all of it from the plaintext (static validity,
`C`, the id, the keys at the anchor, the encoding, `data_hash`), so a correct proof is a
correct sharing and needs no AEAD tag. In-circuit cost: one fixed-base and three
variable-base Grumpkin multiplications, six hashes for the seeds and wraps and about three
per shared value. REGISTER refuses a manifest whose clear inputs and chosen values exceed the
log (sidecar-tip `SharedOnchain::check_register`), and a contract manifest with a
secret-shared on-chain package and no `storage.shared_onchain` (sidecar-core
`manifest::contract`).

**At the head**, the scheduler and every chain verifier fetch the private logs by the siloed
tag through log discovery (below) and take the one that hashes to the stored `data_hash`; a
log that hashes otherwise is refused. The synthesised request carries it in place of
envelopes, as `shared_log` (section 1, `SharedLog`). Each node's chain verifier refuses a
request whose `shared_log` is not the log it read; the binder takes node i's derived pairs,
under its scalar of the epoch the log names for it, as node i's shares (sidecar-core
`derived::node_share`), and step 10's handshake checks that the three bodies agree.

#### Log discovery

One module finds the logs the tip reads: on-chain intake's public request log, secret-shared
on-chain intake's private request log, and the chain-held option's sealed-thirds log. v6's
node cannot list a contract's logs; it answers `getPublicLogsByTags` (by contract address and
tag) and `getPrivateLogsByTags` (by siloed tag), at most 20 logs per tag and 100 tags per
call, paged with an `afterLog` cursor and anchored by a `referenceBlock`. Every tip tag
follows from a request id the queue holds, so the module is driven by the queue and keeps no
cursor of its own. It wraps the node RPC and forks nothing. It has two parts (sidecar-tip
`chain::follow`, `chain::logs`): the follower, a port of the block-hash comparison in
aztec's `L2BlockStream` (`(number, hash)` of the followed proposed blocks back to the
finalized tip, a hash mismatch a prune event; section 6, "Following the chain"); and tag
queries that page with `afterLog`, pass `referenceBlock` and treat "reference block not
found" as a prune. The chain reader takes every snapshot from the follower and reads every
log at the snapshot's block hash. Every RPC shape it uses is checked against a local 6.0.0
network by the chain reader's recorded fixture (`tests/chain/run.sh --record`). Nothing of it
is configured. On the user's side pss-client reads its outcome log with one
`getPrivateLogsByTags` call.

#### Manifest additions for the secret-shared intakes

Section 7 lists the fields and reserved operands; these are REGISTER's rules for them. Under
a secret-shared intake: at least one app input is INPUT_SHARED, or the round takes a shared
`$partial_note` (lending's view and scan, whose app inputs are all clear); INPUT_SHARED
`$blinding`, `$outcome_key`, `$outcome_tag` and `$partial_note` each fill exactly one private
Field parameter; PUBLIC `$inputs_hash` fills exactly one private Field parameter; `$vk_hash`
is used as under the other queued intakes; `$user_nonce` is refused; every other
INPUT_SHARED source is an app input; `outcome: none` is refused. Under `shared_onchain` every
shared value but `$blinding` is the user's, and more than 9 clear inputs and shared values
together are refused. `onchain` and `receipt` refuse INPUT_SHARED sources and the four
names. Under every tip intake `$user` is refused, and one intake family per namespace holds
("The hidden requester"). The receipt walk takes INPUT_SHARED app inputs into C's order.

#### Interactions

The reserved operands are those of section 7 plus `$inputs_hash`, `$blinding`,
`$outcome_key` and `$outcome_tag`. The machine request id is unchanged: shared inputs do not
enter it, and the share hashes, which enter `body_hash`, stay fixed across recomputes of one
chain request. The receipt route accepts envelopes to a node's current `enc` scalar only, so
a node's rotation grace window must outlast the longest receipt life: a node with `[tip]`
refuses a configuration whose `enc_grace_days` is shorter than `receipt_ttl_blocks +
receipt_allowance_blocks + stale_blocks` (the default stale period, 50) blocks at `[tip]
block_time_secs` (default 36), and REGISTER on each node refuses a secret-shared receipt
package whose contract manifest's `queue.stale_blocks` is null or makes that sum outlast the
node's window (sidecar-tip `check_register_intake`). Past the window a node keeps its
previous scalar until the head has passed every queued request whose stored envelope opens
only under it (DESIGN.md, "Rotating a node's `enc` key"). Secret-shared on-chain intake is
bounded by the epoch rule instead of the grace window.

The choices this subsection leaves to app developers and operators, with their defaults and
classes, are in [the design guide](design-guide/README.md) and
[DECISIONS.md](DECISIONS.md), "Tip: intake".

### Partial-note delivery

Status: built in the libraries, the machine, the AMM tip and lending; it is the only form of
value delivery. A round's value and outcome reach the user as a standard Aztec note of the
app contract. The user commits a partial note in its request; the network completes it,
inside the co-SNARK for a private result or in a public function for a public one. The note
is owned by an address nobody but the user sees, lands with the result transaction (no second
transaction), and shows nothing value-bearing to the nodes, the orchestrator or the relayer.
Ownership is proven in the user's own private function by opening a completed note, never
inside the MPC: a check on a shared owner secret would let three compromised nodes act as the
owner, which invariant 0 (section 5) forbids. Why this design: `DECISIONS.md` section 10. Who
sees what: [`DESIGN.md`, "Who sees what"](DESIGN.md#who-sees-what). The hashes used here
(partial note `P`, completed note hash, completion log tag, use and redeem nullifiers, request
secrets, outcome AD) are defined in section 1, "Hashes and associated data".

#### The partial-note convention

The convention is aztec-nr v6's (`note/partial_note.nr`, `uint-note/src/uint_note.nr`,
`partial_notes/`, `messages/logs/partial_note.nr` in the pinned Aztec world,
`deps/aztec-world`). A note's hash is split in two: `P` over `[owner, randomness]`, and the
completed note hash over `[storage_slot, P, fields…]`, so a note created whole and one
completed from a partial hash alike. The recipient's PXE learns a partial note from a
partial-note private message `(owner, randomness, completion log tag, note type id, private
content)` and completes it when a log under the completion log tag carries `[storage_slot,
fields…]`.

An app's outcome note is a struct of its outcome fields with `request_id` last, marked
`#[outcome_note]` (`pss_public_contract::partial_note::outcome_note`). The attribute registers
it as aztec-nr's `#[custom_note]` with the two-step hash (`partial_note::note_hash`) and the
canonical nullifier, and fails at compile time unless the last field is `request_id` (an
attribute because aztec-nr v6's note macros take no generic struct). A note packs at most
`MAX_NOTE_PACKED_LEN` = 8 fields; the partial-note state machine drops an over-length
completion (`fsm.nr` `complete_with_log`). So an app has at most seven outcome fields.

One partial note per request. The PXE completes a partial note on the first log under its tag
and then stops tracking it, so a second request naming the same `P` could hide the real
completion. The request function therefore computes `P` from its preimage
(`partial_note::commit`), never takes it as an argument (only the holder of `rho` can name
it), and pushes the use nullifier, so a second request with the same `P` reverts. aztec-nr's
validity commitment is not used: `P` is bound to its request through `C` and the chain
request id, and the queue lands one completion per request.

#### Private outcomes

Under a secret-shared intake the outcome is private: the result transaction verifies the
co-SNARK in a private function, which creates the outcome as a note and tells the user in a
private log; the public call it enqueues only marks the request resolved and writes the new
commitments.

**The request.** The app's request function (one per round type) takes, beside the round's
inputs, `rho`, `$outcome_key` and `$outcome_tag` (the request secrets), and the intake's own
arguments. It takes no owner: the owner is `msg_sender()`, so every completed note is its
sender's. It computes `P` and puts it in the request as the reserved shared value
`$partial_note`; `owner` and `rho` enter nothing but `P`. The rest (static validity, `C`, the
chain request id, the receipts, the incognito enqueue) is "Secret-shared intake" above. `C`
holds the INPUT_SHARED app inputs, then `$partial_note`, `$outcome_key`, `$outcome_tag`, and
`$blinding` last. `P` is shared, not clear, so the nodes cannot link the request to the note
hash in the result. REGISTER requires exactly one INPUT_SHARED `$partial_note` under `outcome:
partial`, accepts it as a round's only shared value (lending's `view_shared`, `scan_shared`), and refuses an app input named `recipient` (sidecar-core `manifest/validate.rs`).
Under secret-shared on-chain intake the three are chosen values ("Secret-shared on-chain
intake").

**The round.** The circuit takes `P` as a private witness (`SharedIntake.partial`), flags
whether `C` opens (the MPC receipt check), computes the outcome plaintext (the app's outcome
struct, `code` first), outputs the completed note hash over `[storage_slot, P, outcome fields…,
request_id]`, and encrypts the plaintext under `$outcome_key` with the Poseidon2 duplex AEAD of
`pss_utils` under the outcome AD (pss_core `finish`). `storage_slot` is a circuit constant;
`outcome::Private::of` refuses a contract whose outcome-note set is at another slot. The round
derives no randomness and outputs no nullifier. The duplex's first keystream block depends
only on key, nonce and length, so the nonce must commit to the plaintext: the note hash does,
so one nonce seals one plaintext however often the round runs. A round whose shares do not
open `C` seals `[mismatch code, 0, …]` under the mismatch domain. The encryption has no
failure path, so the circuit stays total.

The public outputs are `pss_core`'s `tip::outcome::Private`: `[request_id,
machine_request_id, old…, new…, npk_app_hash, new_hashes…, outcome_tag, note_hash,
ciphertext…]`, optionally followed by app values (`Valued`, the inputs-opened bit last) and
deliveries ("The standing delivery handle"). `ok`, the code and the app outputs stay inside
the ciphertext; `ok` is not a field of the note (`code = 0` says the round applied). Every
round draws a fresh state blinding whatever `ok` is, so the slot write hides `ok`, except
that a tree round whose placement fails (codes 3, 15, 16 and 4) keeps its commitment
(`Tree::update_private`).

**The result transaction.** The relayer (or anyone) FETCHes the result and sends the app's
private `process_result` (`check_round` over `outcome::Private`). It asserts
`context.in_revertible_phase()` first, so the note hash and log land only with an `apply`
that lands (`pay_fee()` ends the setup phase, "Fee payment"); pins the vk, recomputes the
machine request id, verifies the proof and the three result signatures, pushes the note hash,
emits the outcome log and enqueues `apply`. It calls no other contract. The relayer sees
ciphertext, hashes, commitments and signatures, never an owner, an amount or `P`.

The outcome log is the full v6 private log, 16 fields: `[outcome_tag, note_hash, ct…,
padding…]` (`outcome::outcome_log`; the kernel silos the tag). It carries the note hash
because the chain shows only the siloed unique one. After the tag, position `i` from `1 + L`
(for an `L`-field ciphertext) holds `poseidon2([outcome_tag, i])`, so the submitter chooses no
field and the length tells neither app nor round type. `apply` (`apply_round` over
`OutcomeApply`, the same argument on every round type) runs the pinned reads and the head and
slot checks, writes every new commitment unconditionally (there is no public `ok`) and sets
`done[index]`.

**The user's side.** `pss-client`'s `OutcomeReader` finds the log by the siloed
`$outcome_tag`, decrypts it under the logged note hash's nonce (`openOutcome` tries the opened
domain, then the mismatch domain), rebuilds the note `[fields…, request_id]` and checks it
against the logged hash (`outcomeDeliveryArgs` refuses a mismatch). It hands the note to its
PXE through the outcome-note utility (`outcome::deliver_outcome_note` or
`deliver_outcome_into`), which calls aztec-nr's `process_private_note_msg` with `(note type
id, owner, storage_slot, rho, packed note)` and the transaction's hash, unique note hashes and
first nullifier. The note is then an ordinary note of the owner's.

**Value delivery is one axis.** The manifest's `outcome` is `partial` (the default under every
queued intake) or `none`: the app hook stores public outputs (`apply_round` over `TipResult`)
and delivers nothing, refused under a secret-shared intake. A non-secret-shared round that
completes no note (an init round, the machine's test counters) declares `none`. No form pays
through an app hook in the result transaction: it would show the amount and recipient to the
nodes, the orchestrator and the relayer.

#### Completion in a public function

Under the non-secret-shared intakes the outcome is public and the note is completed in `apply`,
the owner still hidden. `$partial_note` is a PUBLIC clear input covered by `inputs_hash`
(REGISTER requires exactly one). The round outputs `P` right after `ok` (pss_core
`tip::outputs::BoundPartial`), and `apply` completes it on every round whatever `ok` is
(`PartialResult::completing`, through `partial_note::complete_in_public`, as aztec-nr's
`UintNote::complete` does): the public log `[storage_slot, code, app_outputs…, request_id]`
under the completion log tag, and the note hash pushed from the public context. The world sees
the amount and `P`, never the owner.

The request function tells the owner's PXE of the partial note (`partial_note::deliver_partial_note`,
empty private content), by default `MessageDelivery::offchain()` (on-chain unconstrained delivery for a PXE that must recover from the chain alone). The wallet does not deliver
an offchain message itself: aztec.js returns it in the send result's `offchainMessages`, and
the client hands it to the contract's `offchain_receive`. The PXE then completes the note when
the completion log lands.

#### The note hash and randomness rule

One rule for every round, under both completions:

- The owner and randomness are the user's: `rho`, `$outcome_key` and `$outcome_tag` come from
  the client's per-namespace counter `n`, advanced on every request sent, failed or not
  (`pss-client` `SecretStore`). The circuit derives nothing.
- The chain request id is the note's last field. It is never zero, which the public completion
  needs (v6 public logs trim trailing zeros), and it names the request the note answers.
- The note packs the outcome fields (`code` first, no `ok`) then `request_id`, at most eight;
  the plaintext packs the same fields without `request_id`.
- Recovery: a user who lost local state rescans `n = 0, 1, …` to the gap limit (20 empty `n`
  in a row, `SecretStore.recover`). Private completion: it finds each outcome log by
  `$outcome_tag`, decrypts it, and takes the request id from the queue (the log's transaction
  writes `done[index]`; `requests[index]` is public). Public completion: it finds the
  completion log by the tag of `P` re-derived from `rho`, per owner account it used.

#### Verifiable delivery

Where an output that leaves a round is value-bearing or needed to spend, the circuit itself
produces it in the form the recipient opens, so a result lands only if its recipient can use
it. The nodes never seal data for a user outside the circuit; at the tip data for a user
travels only in the in-circuit encrypted outcome log (on the sidecar path the user verifies
the co-SNARK in its own private function, `pss_contract::verify_pinned`).

| Output | Recipient | Delivery |
| --- | --- | --- |
| outcome ciphertext; completed note (private completion) | the user, the owner of `P` | constrained: computed inside the MPC under the user's `$outcome_key` (no key exchange in the MPC), public outputs `process_result` logs and pushes |
| completed note (public completion) | the owner of `P` | public: `apply` completes it from `P` and the public outputs |
| public outputs, new commitments, new leaf hashes | the world, the contract | public outputs of the proof |
| record thirds, sealed vectors | node i itself | unconstrained: sealed to its own `K_i`, covered by the result signature through `H(sealed_i)` |

The outcome key cannot be swapped: `C` covers it, the request function proves the user's
sharing opens `C`, the AEAD runs under the key the shares open to, and `apply` compares the
chain request id over `C` with `requests[head]`. A node that seals garbage to itself can only
halt, which one node can already do; garbage handed to a user would destroy value.
Withholding a result is liveness (`skip()` after `stale_blocks`).

#### Ownership by note

A position's owner is whoever holds a completed note of it. No request carries the
requester's address and no round checks an owner. Lending is the example
([`examples/lending-tip/README.md`](../examples/lending-tip/README.md)); the AMM has no chain.

- **Opening.** An opening request (lending's deposit or supply with `position = 0`) writes the
  leaf the scheduler appends at; its note, the sender's, reports the index. Anyone may open.
- **Acting on a position.** The request function reads one of the sender's notes (with its
  inclusion check), requires its owner to be `msg_sender` (`partial_note::assert_owned`), its
  `code` 0 and its position the requested one (lending's `assert_holds`), and commits the next
  partial note to the same sender. The round never sees an owner. Each round completes the
  next note, reporting the position after the round.
- **Which notes confer ownership.** One note type serves every round, so the rule is in the
  fields: `code = 0` and `position != 0`. A failed round's note confers nothing; the owner
  keeps its earlier notes.
- **Not nullified.** The opened note stays valid, so a skipped or failed request leaves the
  owner able to act; the leaf is the authority and the round's checks hold at each turn.
  Hence an index is never reassigned (a leaf's kind never returns to 0, `next_index` only
  grows) and a position is not transferable.
- **The leaf holds no owner**: its kind, values, the standing delivery handle and the newest
  note's exit tag. Lending's code 5 ("the position is not of the round's kind") is a backstop
  an honest request never trips.
- **The note is the exit's claim.** A round that writes a position stores the exit tag of the
  note it completes; the next write spends it as a nullifier. Only the newest note's tag is
  unspent, and the escape hatch exits on it ("The escape hatch").
- **Invariant 0.** With every node secret an attacker reads every leaf, amount, `P` and
  outcome, but cannot request a round on a position, land a result without a proof over a
  queued request, spend a note (the owner's nullifier key) or redirect a payout (`P` fixes the
  owner).

#### What the completed note is worth

The completed note is the value note, spent through the app's private `redeem`. An unchained
note (the AMM's swap note) is nullified by its spend. A chained note (a position note) is never
nullified; its payout is spent once through the redeem nullifier (`partial_note::redeem`,
which requires `owner == msg_sender`), so a second redeem fails and the note stays readable. A
payout of 0 has nothing to redeem. The spend does not link to the result's note hash; its
timing can. Payment in an external token is the app's public custody ("Tokens and escrow").

#### The refund rule

An app that takes escrow or a usage deposit can commit user-owned partial notes for
refunds. Public functions complete these refunds. A round, a node signature and an
off-chain step never complete a refund note. The skip route requires the app to enable
the stale period and call `token::refund_skipped` in its skip wrapper.

- **Commit** (`token::commit_refunds`): the request function commits two refund notes of the
  app's credit type, `partial_commitment_with(owner, randomness, content)` with the amounts as
  private content, randomness `poseidon2_hash_with_separator([rho], PSS_REFUND_ESCROW)` and
  `…PSS_REFUND_DEPOSIT` (`token::refund_randomness`; labels `pss.refund_escrow`,
  `pss.refund_deposit`), each with its use nullifier. The public wrapper records the
  commitments beside the queue entry (`Refunds`). No round reads them, so they are not in `C`.
- **`skip()`** completes both for the full amounts, the request id the only public field
  (`token::refund_skipped`).
- **`apply`** calls `token::settle_applied(…, escrow_unused, served)` after a round lands.
  It completes the escrow refund when the round consumed nothing (`escrow_unused`) or
  its shares did not open `C` (inputs-opened bit 0, lending's code 14). It completes the
  usage deposit refund unless both `UsageDeposit::kept` and `served` are true. When the
  round uses escrow under private outcomes, its completed note carries what it returns.
- **Forbidden:** keeping a deposit when the request is skipped or not served (a stake).
- **Recovery.** The amounts are not derivable from the counter, so the request delivers the
  refund messages on chain (`MessageDelivery::onchain_unconstrained()`): a PXE restored from
  its keys finds each pending refund and stores it when its completion log appears.

In lending, every request commits the same two refund notes, so neither the amounts nor
the round type are public. The AMM escrows nothing ("Tokens and escrow", "Fee payment").

#### The standing delivery handle

A party other than the requester (a liquidated owner, an auction's winner) is reached by
another party's round only through a standing delivery handle it left in its own entry
(`pss_core` `tip::handle`, `pss_public_contract` `handle`, `pss-client` `handle.ts`).

**The handle** is `Handle { partial, key }`, two fields of the entry (`partial = 0`: none).
`partial` is a partial note computed by the recipient's request function from `msg_sender()`
and `handle_rho` (`handle::commit`, never an argument); `key` is the delivery's AEAD key. The
client derives both from the request counter `n` (`poseidon2([PSS_HANDLE_RANDOMNESS,
wallet_secret, namespace, n])`, likewise `PSS_HANDLE_KEY`; `SecretStore.handle`). A delivery's
log tag is `handle_tag(key, request_id) = poseidon2([key, PSS_HANDLE_TAG, request_id])`, the
delivering round's chain request id (labels `pss.handle_randomness`, `pss.handle_key`,
`pss.handle_tag`).

**Writing it.** A request carries `handle_partial` and `handle_key` as two shared app inputs
in `C` right after the other app inputs. The round writes them on every outcome that writes or
re-blinds the entry (`Tree::update_private`'s `kept` leaves), so a refused request also leaves
a fresh handle.

**Completing it** (`handle::deliver`), in a round another party requested:

```text
seed       = poseidon2([blinding, PSS_HANDLE_FILLER])        (the request's $blinding)
P, k       = delivers ? (handle.partial, handle.key) : (seed, seed)    (delivers: the app's rule)
fields'    = delivers ? fields : 0s
note_hash  = completed note hash over (slot, P, fields', request_id)
ciphertext = AEAD([fields'…, request_id], k, outcome AD of note_hash)
tag        = handle_tag(k, request_id)
```

The handle stays, so any number of rounds may complete it until the recipient's next request
replaces it; each completion is another note under another tag. Every round of an app with the
brick outputs the same number of deliveries after its app values (`Delivered`, per delivery
`[tag, note_hash, ciphertext…]`); `pss_public_contract`'s `handle::Delivered` pushes each note
hash and emits each log after the outcome's. A round with no entry to notify outputs a filler
(`handle::filler`: tag `handle_tag(seed, request_id)`, note hash `poseidon2([seed,
PSS_HANDLE_FILLER])`, zeros encrypted). An app with several deliveries seeds delivery `d > 0` with `poseidon2([seed, d])` (lending's `delivery_seeds`).
No seeded or filler note hash is a note anyone can hold, and the circuit computes them, so
neither the round type nor whether anyone was notified shows.

**Reading it.** `DeliveryReader.read(keys, requestId)` finds the log under `handle_tag`, opens
it (`openDeliveryLog`, which refuses a rebuilt note that is not the logged one) and hands the
PXE the note under `handle_rho`; `readIn(keys, tx)` reads a known transaction's logs instead.
The handle authorises nothing: knowing it opens a delivery, never moves value, and only a
request the entry owner's private function admitted can write it. The nodes hold it, so they
can link the recipient's earlier request to a delivery.

Lending's liquidation notice is the worked example, with how an owner finds a liquidation
through its spent exit tag and the cost per round:
[`examples/lending-tip/README.md`](../examples/lending-tip/README.md), "The liquidated owner's
notice".

#### Where it is built

- `noir/pss_core/src/tip/`: `outcome.nr` (`partial_commitment`, `completed_note_hash`,
  `completion_log_tag`, `finish`, `Private`, `Valued`), `outputs.nr` (`BoundPartial`),
  `intake.nr` (`SharedIntake.partial`), `handle.nr`.
- `noir/pss_public_contract/src/`: `partial_note.nr`, `outcome.nr`, `result.nr`
  (`PartialResult`), `handle.nr`, `token.nr` (refunds); `pss_public_contract_test` pins the
  note hash against aztec-nr's `UintNote` and has TXE cases for both completions, chaining,
  redeem and refunds.
- `machine/sidecar-core/src/manifest/` (`outcome`, `$partial_note`),
  `machine/sidecar-tip/src/intake/`.
- `ts/pss-client/src/`: `secrets.ts`, `outcome.ts`, `discovery.ts`, `handle.ts`, `hatch.ts`.
- `testvectors/outcome.json`, `secret_store.json`, `shared_intake.json`; `testvectors/noir/`.

Cost: the completed note hash in the round (4 Poseidon2 permutations for seven outcome fields,
2 for two) and `P` among `C`'s values; `P` (one permutation) and, on an owned position, one
note read in the request function. Gate counts: the examples' READMEs
([AMM tip](../examples/amm-tip/README.md), [lending](../examples/lending-tip/README.md)).

### A read-only window on a tree key

Built: the manifest's `window` form of the `tree` entry with REGISTER's bound, the machine's
window load, its placement by the scheduler and check by the chain verifier, `Tree::window`, and
the client's keeper loop (pss-client `keeper.ts`). Lending's keeper scan is the worked case
(`scan_shared` at `W = 8`).

A round that must look at many leaves without a user naming each as a probe reads a window: `W`
consecutive leaves `start … start + W - 1` inside the MPC. It is the brick for discovery over a
tree nobody sees in the clear, where probing `K - 1` leaves per round would take about
`2^D / (K - 1)` rounds per pass.

**The manifest entry.** The `tree` entry for the loaded key carries `window {width, start, params
{leaves, old_hashes, siblings}}` (section 7): `width` is `W`, a power of two at most `2^D` and at
most `MAX_TREE_WINDOW` (8), enforced by REGISTER so a window round fits a 2^14 circuit; `start` is
the app input naming the first leaf. The nodes load the window's leaves after the round's slots
(every LOAD of the key is then `(probe + W) * leaf_len` long, its outputs still
`probe * leaf_len`), and the scheduler places the window's old hashes and the window root's
`D - log2 W` siblings from the clear trees, which each chain verifier checks. A `start` not below
`2^D` or not a multiple of `W` places the window at leaf 0 and the round flags it.

**What the round may do.** Read the window, never write it: `Tree::window` checks each window
leaf against its public old hash, rebuilds the window's subtree root from the `W` public old
hashes (`W - 1` permutations over clear values) and takes it up the public siblings to the old
root, which it compares with the root the slots' paths give (`root_ok`, a flag for the app). The
round's own slots load, and may be written, as in any tree round. What the round computes over
the window is the app's: typically a bit per leaf of a predicate packed into one field (the
report) and an occupancy count, sent to the requester alone as a private outcome.

**Report, then act.** A window round reports; separate act rounds act on the indices it names,
`K - 1` per round. Acting inside the window round would need secret selection among `W` leaves and
a rebuild of the window subtree over shared values. Between report and act other rounds may change
a named leaf, so the act round re-checks its own condition (`binding: turn`).

**Cost.** Per leaf one leaf hash and the app's per-leaf work, plus `W - 1` subtree nodes and
`D - log2 W` siblings, on top of the round's fixed part and slots; depth barely matters and `W` is
the knob. The shared work is wide, not deep, so witness extension under latency costs about an
owner round's. Lending's scan is 15,795 gates at `W = 8`, `D = 16` (it does not fit at `W = 16`).

**The keeper loop.** `keeperPass` reads `W`, `D`, the start input and the act round's index and
count inputs from the two manifests, reads each scan's report at the field positions the app gives
(`ScanLayout`), scans from `start` = 0 advancing by `W`, hands each window's reported indices to
the act round, `K - 1` per round, before the next scan, and stops at the first window that is not
full (`W` occupied, `W - 1` in window 0), at the last window, or at a failed scan. For a tree whose
leaves are appended and never reclaimed a pass over `n` occupied leaves is `ceil(n / W)` rounds.

The requester learns one bit per window leaf (a probe reveals the same bit per probed leaf, so a
window changes the rate, which the fee and the queue bound); the nodes see `start`; further
leakage is in DESIGN.md, "Who sees what". The network does not schedule window rounds (`start` is
the requester's clear input), and the window has no oblivious access.

## 7. The manifest

One JSON Schema, `manifest.schema.json`, serves both paths. `intake` selects the path: `direct`
(the default) is the sidecar path; every other intake queues the request at the tip. Every field
is read by a step of section 3, 4 or 6. sidecar-core's `Manifest` and pss-client's
`parseManifest` read the schema with its defaults applied.

The fields of both paths:

| Field | Read at |
| --- | --- |
| `manifest` (1) | REGISTER step 3: the schema version; unknown fields refused |
| `circuit` | REGISTER step 3: equals the registered name |
| `namespace_param` | REGISTER step 3 (a public Field filled by PUBLIC `$namespace`); step 11 |
| `state_keys {reads, writes}` | step 3 (counts): how many state keys a request names; the manifest refers to them as `$state_keys.reads[i]` and `$state_keys.writes[j]` |
| `witness [{param, from}]` | REGISTER step 3 (against the ABI); step 9 (the binder) |
| `outputs [{TACEO_store, STORE, len, note_hash}]` | REGISTER step 3 (`note_hash` names a public output); step 12 |
| `intake: direct` (default) \| `onchain` \| `receipt` \| `shared_receipt` \| `shared_onchain` | REGISTER step 3 (the path rules below); step 3 (`chain_request_id` only when queued); step 4 (the chain verifier when queued); the scheduler; the contract library (which intake function to generate) |
| `state {keyref: client \| node \| chain}` (default `node`) | steps 4, 7, 8, 12, 13. `client`: intake direct only. `node`: both paths; at the tip steps 8 and 15 use versions. `chain`: queued intakes only, the record path with the machine as owner |
| `public_reads [{contract, function, args, param, freshness, epoch_param, band}]` | the scheduler (fills `param`, and under `epoch` `epoch_param`, from a simulated call); the chain verifier (step 4); `apply` (recheck). `contract` is an address, or `$self` for the namespace's own contract (the address written out is refused). `freshness`: `exact` (default), `epoch` or `tolerance` (section 6, "Pinned reads"); `epoch_param` required under `epoch` only, a public Field right after `param`; `band` required under `tolerance` only, `{absolute: "<u128, decimal>"}` or `{relative_bps: 1 … 10000}`. REGISTER and `parseManifest` refuse an unknown policy, a missing or misplaced `epoch_param` or `band`, and a zero or out-of-range band. Refused under intake direct |

The fields of intake `direct` only:

| Field | Read at |
| --- | --- |
| `consume [{key, policy: once \| never}]` | steps 7 and 15; default `once` |

The fields of a queued intake only:

| Field | Read at |
| --- | --- |
| `binding: turn` | the scheduler (run against the current state; `exact` deferred) |
| `commitment_slot {keyref: {old: <public output>}}` | the public output that carries the old commitment the circuit read (the slot follows from the key); the scheduler; the chain verifier. The new commitment is the key's `outputs[].note_hash` |
| `tree {keyref: {…}}` | one entry per tree-valued key the round uses (below) |
| `outcome: partial \| none` (default `partial`) | the contract library (which outputs brick `check_round` and `apply_round` take: `outcome::Private` and `OutcomeApply`, `PartialResult` and `PartialResult::completing`, or `TipResult`); REGISTER (refuses `none` under a secret-shared intake and, under a non-secret-shared `partial`, a round without PUBLIC `$partial_note` or without the output `partial_note` right after `ok`); `parseManifest` |
| PUBLIC `$vk_hash`, `$user_nonce` | reserved operands: each fills one whole Field parameter at most once, never in a PUBLIC list, under a name no request public name shares; not app inputs; the scheduler fills `$vk_hash` with the package's vk hash and `$user_nonce` from the request log or stored receipt; the binder reads each from the request's `public` map. `$user` is refused under every intake |
| PUBLIC `$new_leaf` | exactly when a tree has an `open` input: the scheduler (the append index, 0 when full); the chain verifier; the binder |
| INPUT_SHARED `$blinding`, `$outcome_key`, `$outcome_tag`; PUBLIC `$inputs_hash` | secret-shared intakes only, each exactly once in a private Field parameter ("Manifest additions for the secret-shared intakes"); `C` covers `$outcome_key` and `$outcome_tag` in ABI order and ends in `$blinding`; the scheduler fills `$inputs_hash` from the stored row |

The `tree` entry, `{depth, leaf_len, probe, header, index, count, open, params, store, new_hashes,
window, access, keyed, capacity, next_index}` (section 6, "Tree-valued keys"):

- Placement: under the `$state_keys.reads[i]` reference that loads the tree, with `params` and,
  when the round stores it back, `store` (the `$state_keys.writes[j]` reference, which takes this
  layout and has no entry of its own) and `new_hashes`; or, for a tree the round creates, under the
  `$state_keys.writes[j]` reference that stores it, with `new_hashes` only. A round that loads and
  stores trees stores each tree it loads and creates none.
- `depth` (1 to 32), `leaf_len`, `probe` (the most leaves a round touches, header included):
  REGISTER bounds the round by them, and every LOAD and output of the key has `probe * leaf_len`
  elements. `header` (bool): leaf 0 is a fixed touch in slot 0.
- `index`: the app inputs naming position indices, in slot order (so covered by `C` under a
  secret-shared intake); `count`: the app input saying how many are used (absent: all). `open`: the
  `index` input whose value 0 means "open a new leaf", only with `header`; the scheduler then
  places `$new_leaf`.
- `params {leaves, old_hashes, siblings, indices}`: the private ABI parameters that receive the
  loaded shared leaves (`[[Field; leaf_len]; probe]`), their old hashes (`[Field; probe]`) and
  siblings (`[[Field; depth]; probe]`, bottom up), and the effective indices (`[Field; probe]`, 0 in
  an unused slot); the last three are PUBLIC names the scheduler fills, not app inputs.
- `new_hashes`: the public output carrying the new leaf hashes, which each node reads at step 15.
- `window {width, start, params {leaves, old_hashes, siblings}}` (a loaded reference only): section
  6, "A read-only window on a tree key"; `width` a power of two at most 8 (`MAX_TREE_WINDOW`) and at
  most `2^D`; `leaves` the LOAD after the slots (`[[Field; leaf_len]; width]`), `old_hashes`
  (`[Field; width]`) and `siblings` (the window root's `depth - log2 width`) PUBLIC names.
- `access`: `clear` (default) or `oblivious` (experimental, "The oblivious tree"): every `index`
  input is INPUT_SHARED; `open` names a PUBLIC 0/1 input other than the index and count inputs;
  `params` has no `indices`, and its `leaves`, `old_hashes` and `siblings` are the three LOAD slices
  of the key in that order; no `new_hashes`; `next_index` names the public output of the header's
  append index after the round (with `open`); every LOAD and output of the key has
  `probe * (leaf_len + 1 + depth)` elements before a window. One access per key across the
  namespace's rounds.
- `keyed` (bool; `access: oblivious` only, experimental, "The oblivious sparse map"): the `index`
  inputs are keys; `depth` 32 to 120, `leaf_len` at least 3, no `header`, `open`, `next_index` or
  `window`; a map a round creates has `probe` 1 and no `index`. `capacity` (`keyed` only): log2 of
  the distinct DORAM addresses the map may ever access (8 to 36, default 18; sidecar-oblivious
  `MIN_MAP_CAPACITY`, `MAX_MAP_CAPACITY`).

REGISTER refuses unknown fields, a field of the other path (even empty), a state mode the intake
does not allow, and a reserved operand under intake direct. Under every queued intake it also
refuses a circuit whose public parameters do not follow the contract library's layout, since no
proof of it verifies at a contract built on the library: exactly `[$namespace, $vk_hash,
$state_keys.reads[0..R], $state_keys.writes[0..W], the pinned values]`, the app inputs and every
other reserved operand private; the pinned values are each read's value and then an epoch read's
epoch, in `public_reads` order.

### The contract manifest

One JSON document per namespace, `contract-manifest.schema.json`, holds the facts about the
contract that the machine reads and every package's circuit manifest. Nobody writes it by hand:
pss-client's generator (`contract-manifest.ts`, the `pss-manifest build` command) takes the
compiled contract artifact, the compiled circuits, the circuit manifests and a descriptor per
deployment (`examples/<example>/deployments/<deployment>.json`: the package list in the
contract's order, each package's circuit and state key names, the init inputs as `Config`
members, the stale period, the contract each placeholder read calls) and computes every slot from
the artifact.

| Field | What |
| --- | --- |
| `contract_manifest` (1) | the schema version |
| `name` | a label |
| `node_keys: rotating \| fixed` | `rotating` exactly when the artifact has `rotate_keys` (section 6, "A fixed key set") |
| `upgrades: fixed \| circuits \| contract` | what may change ("Upgrades" below): the value the contract's state view reports (`TipState`'s `upgrades`), the generator refusing an artifact whose upgrade entry points disagree. Under the other two the package list is at most 14 (`circuits`) or 13 (`contract`) long (an upgrade rewrites `4P + 6` slots, a class upgrade 4 more, and a transaction writes at most 63) and `queue.stale_blocks` is not null |
| `contract {class_id, package_capacity}` | the class the document was built for, which the scheduler and every chain verifier compare with the instance's current class before a round, and the length of the constructor's package list |
| `queue {slot, stale_blocks, stale_blocks_slot}` | the queue's slot, the stale period and the slot of the stored period. `stale_blocks` (at least 1, or null: never skipped) is the one source of the stale period for REGISTER (null refused under secret-shared receipt intake, and a period outlasting the node's `enc` grace window), the scheduler, receipt pruning, the relayer's `skip`, the contract's constructor and the chain verifier (which refuses every round while the stored `TipConfig.stale_blocks` differs) |
| `storage {configured, shared_onchain, circuit_pins}` | the `configured` flag's slot; exactly with a secret-shared on-chain package, `SharedOnchain`'s; exactly when `upgrades` is not `fixed`, `CircuitUpgrades`' |
| `state_keys {name: slot}` | every state key the rounds touch |
| `plain_reads {param: slot}` | pinned reads read from a slot instead of simulated |
| `init {package, input_slots}` | the init round and its inputs' slots |
| `circuits {id: {vk_hash}}` | each compiled circuit once |
| `packages [{name, circuit, alias_of, state_keys {reads, writes}, manifest}]` | the packages in the contract's list order: the backing circuit, its request keys by name (queued packages) and its circuit manifest. `alias_of` marks another intake of a listed package: the same circuit, verified under that package's pin, not in the contract's list |

The **manifest hash** is `poseidon2_hash_bytes(JCS(document))`; the **packages hash** runs over
the listed packages (those without `alias_of`) in order, `h = poseidon2([h,
poseidon2_hash_bytes(name), vk_hash])` from `h = 0` (`testvectors/contract_manifest.json`). A tip
contract's constructor pins the manifest hash beside its package list and `configure` checks the
nodes' signatures over both, so the address commits to the document. The document never holds the
namespace's own address: a read of the namespace's own contract is `$self`.

REGISTER takes the document whole. sidecar-core's `manifest::contract` checks it in pure
functions, at the nodes and at the orchestrator before it forwards the body: each circuit manifest
parses and names its package; every package's circuit is an entry of `circuits` and every entry is
used; names are unique; at most 32 packages, the listed ones within `package_capacity`; the
sections present exactly as the packages need them; every state key has a slot and a writer;
every package on a key gives it one state mode, one tree shape (depth, leaf length, header,
access, keyed, capacity) and one flat length; a tree is stored back at the key it is loaded from;
one intake family per namespace.

At run time the scheduler, each chain verifier and each node's receipt chain view read a tip
namespace's facts from its registered contract manifest (`sidecar_tip::TipLayout`); the operator's
`[[tip.namespaces]]` is only the allowlist of contract addresses, and a namespace is driven when
both listed and registered. Before a round each compares the instance's current class on its own
Aztec node (`node_getContract`, `currentContractClassId`) with `contract.class_id` and runs nothing
while they differ (liveness only).

### Upgrades

The `upgrades` axis (design guide, question 15) says what about a deployed app may change. Under
`fixed` (`FixedCircuits`) the circuit pins are the constructor's for the life of the contract, and
REGISTER refuses any other contract manifest for the namespace. Under `circuits`
(`CircuitUpgrades`, `pss_public_contract` `upgrades`) an upgrade authority can replace the
circuits; the contract's code cannot change. Under `contract` the same brick also moves the
instance to another contract class (`CircuitUpgrades::upgrade_contract`). The operator's steps are
DESIGN.md, "Upgrading an app's circuits" and "Upgrading an app's contract code"; what the
authority can do, DESIGN.md, "Upgrades".

**On chain.** The app declares `CircuitUpgrades<P, DELAY, Context>` last in its storage
(`storage.circuit_pins`). It holds the scheduled pins (`UpgradedPins`: the class id they were
scheduled under, then the manifest hash, the package list and the vk hashes) in aztec-nr's
`DelayedPublicMutable`, then the upgrade authority, an address the constructor pins, with the
deployed class (`UpgradeAuthority`). `upgrade_circuits(pins)` checks `msg_sender` against the
authority (never the zero address), checks the list as the constructor does and schedules the
pins, in force after `DELAY` (the examples: one day; aztec-nr refuses less than one hour). It
refuses while a class upgrade is pending (the authority calls `upgrade_contract` again instead).
Every round function builds its round table rows from `CircuitUpgrades::in_force` over
`Configured`: the scheduled pins once in force, else the constructor's. The read is one historical
public-storage proof and caps the transaction's expiration below the next time of change, so a
transaction built under the old pins cannot be included once the new ones are in force. `in_force`
also enqueues the app's `#[only_self]` `assert_upgrade_class` with the class the pins belong to (0
for the constructor's), the class guard, which refuses the round unless that class is running.
`configure` is not repeated: `npk_app_hash` belongs to the namespace.

Storage, from `storage.circuit_pins` (`S`), for capacity `P` and `N = 2P + 2`: `S` the metadata
field, whose low 32 bits are the time of change; `S + 1 .. S + N` the pins before the change;
`S + N + 1 .. S + 2N` the pins after it; then their hash, then the authority. In each half the
class id comes first and the manifest hash second (sidecar-core `circuit_pins`). The pins in force
at a block of timestamp `t` are the half after the change when `t` is at least the time of change,
else the half before; when that half is zero the constructor's manifest hash, at
`queue.stale_blocks_slot + 8` (after the stale period and the three `sig` keys), is in force.

**A new version.** The owner uploads the new contract manifest as a manifest message at the next
`seq`. Each node checks it against the newest version it holds (`manifest::upgrade::check_upgrade`,
400 naming the field):

1. the held version is not `fixed`;
2. the contract-level facts are the held ones: `upgrades`, `node_keys`, the class id, the package
   capacity, `queue`, `storage`, `state_keys`, `plain_reads` and `init` (relaxed by a class upgrade,
   below);
3. each state key keeps its layout (state mode, flat length, and for a tree its depth, leaf length,
   header, access, keyed flag and capacity), so every stored version loads unchanged; a new layout
   is a new deployment;
4. no state key is added, and the intake family is unchanged.

Packages may be dropped and circuits replaced. The answer signs the new manifest hash and packages
hash under the unchanged `npk_app_hash`. An upgradable namespace holds up to three versions
(`MAX_HELD_VERSIONS`); a REGISTER beyond that drops the oldest by `seq`.

**Which version runs.** A round runs only under the version whose hash the pins name in force at
the block the reader reads, on its own Aztec node (`ChainReader::manifest_in_force`: four storage
reads and the block's timestamp from `node_getBlockData`). The scheduler drives that version among
those its registry copy holds and names it in each synthesised request (`manifest_hash`);
resolution takes that version's package; each chain verifier refuses (400) a round whose version is
not the one its own view's pins name. The receipt route computes a request id under the version in
force: the client names the version it built under, the orchestrator resolves the package in it,
and a node refuses a version its view does not name. A node that does not hold the version in force
runs nothing until it does. A request under intake direct runs under the newest version and may not
name one (400); for the same reason `upgrades` other than `fixed` needs a queued package (an
all-direct contract manifest is refused). A DISABLE stops the circuit under every held version.

**Across the switch.** A result proven under the replaced circuit lands before the time of change
or not at all. A request id binds its package's vk hash, so a request queued under the old pins
whose package changed is answered by neither circuit after the switch: it waits out
`stale_blocks` and is skipped, which refunds any escrow. Hence an upgradable contract manifest must
have a stale period.

**A class upgrade** (`upgrades: contract`). The protocol's `ContractInstanceRegistry.update`
upgrades its caller after the instance's own update delay (a `DelayedPublicMutable` of the
registry, one day by default, at least 600 s); from then on the private kernel proves the
instance's private functions, and the AVM runs its public functions, under the new class. The
address, and with it the namespace, the storage and every node-held version, stay. The developer
publishes the new class and generates its contract manifest (a new `class_id`); the owner registers
it at the next `seq`; the authority calls `upgrade_contract(new_class_id, pins)`, which checks the
authority, calls the registry's `update`, refuses unless the instance's class-update delay
(`get_update_delay`) equals the pins' delay, and schedules the pins under the new class, so both
take effect at one timestamp. Should they ever be out of step, the class guard and the readers'
class comparison stop every round for the gap (liveness only). A result proven before the change
expires at it; when the circuits did not change, the round is landed again through the new class.

Under a class change `check_upgrade` relaxes rule 2: `queue`, `storage.configured`,
`storage.shared_onchain`, `plain_reads` and `init` may change (the stale period stays finite), and
`node_keys` may go from `fixed` to `rotating`. Never: `upgrades`, `node_keys` from `rotating` to
`fixed`, `storage.circuit_pins` or the package capacity (both classes read the same stored pins),
and rules 3 and 4. The new class never embeds a contract manifest's hash: the hash arrives through
the pins. A wallet that registered the instance with the old artifact registers it again with the
new one (pss-client `followContractClass`; the relayer's `upgradeArtifacts`). `pss-manifest verify`
checks a deployed contract against a contract manifest: the instance's and the artifact's class
against `contract.class_id`, every slot the generator derives, and the pins in force against the
manifest's hash, package list and vk hashes.

`upgrade_circuits` and `upgrade_contract` check no node signature, and the registry accepts an
update only from the instance itself, so no number of node keys authorises an upgrade (invariant
0). The owner key alone can upload a version, never make it run.

## 8. Errors and failures

| Class | HTTP | Raised at | Effect |
| --- | --- | --- | --- |
| bad_request | 400 | parse, resolve (unknown or disabled circuit, a fixed-key name), authenticate (missing requester; chain verifier), own-ciphertext check, a dead record (step 7), open (AD, key id; a record no client-held key reads), bind (range, missing or unexpected public name), session handshake | nothing loaded beyond the step; nothing stored |
| forbidden | 403 | requester signature (intake direct); REGISTER/DISABLE owner check | nothing stored |
| not_found | 404 | GET of an unknown package or namespace; FETCH of an unknown or pruned request id; DISABLE of an unregistered circuit | — |
| conflict | 409 | replay with another body or of a rolled-back request (except a rolled-back tip attempt resent with its body); FETCH of a round whose circuit is no longer registered; consumed state; missing value or record; stored length; a re-stored consumed note hash; write rule; wrong `seq`; name taken; rollback out of order | nothing stored |
| unsatisfied | 422 | self-verification fails or the namespace public input differs | nothing stored; the proof is discarded |
| mpc_failure | 500 | mesh or proving failure; wrong set of outputs; nodes disagree; a registry body only some nodes committed; the two binds differ; store failure | nothing stored (a diverged registry body: at the nodes that committed it, not in the orchestrator's copy) |

When nodes refuse, the orchestrator relays one refusal, prefixed with the node: a refusal of the
request (400, 403, 404) first, then 409, then 422, then a 400 that only relays a neighbour's
verdict at the handshake, then 500, the lowest node index on a tie; so a body one node refuses with
403 or 409 reaches the client with that class, not as the handshake's 400.

Both HTTPS listeners answer transport refusals in the same shape: a body over the listener's limit
is 413 and a body that does not arrive within the body read timeout 408, both `bad_request`; a
connection whose request head does not arrive in time is closed. A public session turned away from
a full waiting room is 503 with `Retry-After` and the class `mpc_failure`.

What bricks, and the recovery (the operator's procedures are in DESIGN.md, "Operator procedures"
and "Recovery"):

| Situation | The sidecar path | Tip |
| --- | --- | --- |
| a round whose transaction can never land | node-held: FETCH and land if possible, else the per-request rollback; client-held: the rollback deletes the round's consumed entry and marks the round's records dead; without a rollback the state is lost after the `requests` prune | cannot happen: `apply` is the only state mover and a failed `apply` reverts |
| a request the circuit cannot satisfy | 422, nothing stored | the head waits for `skip()`; total circuits make it an `ok = false` no-op (under private outcomes a code inside the outcome, the state re-blinded) |
| a secret-shared request whose shares or clear inputs do not open `C` | — | never queued: the receipt route and the request function refuse it ("Secret-shared receipt intake, end to end"); only nodes that change their shares after intake make such a round, which lands as a failure inside the outcome (the app's mismatch code) and moves the head |
| an envelope that does not open at node i | refused at step 9 (400) | refused at the receipt route before node i signs; at the head the chain verifier refuses an envelope other than the one it stored |
| the network offline or two nodes down | no rounds | `skip()` keeps the queue moving and refunds every queued escrow and deposit; the state is frozen, and an app with an escape hatch lets owners exit once its starving clock reaches the liveness period ("The escape hatch") |
| a lost record | FETCH within the retention window, then lost | node-held: the nodes' versions; chain-held: the apply log |
| a lost node store, key directory intact | resync from the neighbours (not the `requests` rows) | resync from the two neighbours, checks and audit ("Node-held state"), or restore a backup with a delta resync (which also brings back `requests` rows and secret-shared receipt envelopes as old as the backup); queued secret-shared receipt requests whose envelope was lost are skipped; two lost stores lose the state; chain-held: reload from the last apply log |
| a lost key directory | the node's records and envelopes no longer open | restore the offline key backup; without one, replace the node |
| a node replaced | the departed node's thirds and envelopes are lost | "Node replacement and key epochs"; chain-held namespaces are a new deployment |
| a tip attempt committed at one or two nodes | — | cannot land; the operator rolls its row back at the nodes that hold it and the next resend runs at all three; for an oblivious key, or without a rollback, the entry is skipped |
| a slot at a commitment the node does not hold | — | the node refuses rounds on that key until it is resynced; no state is lost |
| a diverged clear tree at one node | — | the chain verifier refuses (400, naming the key); resync that key |
| a replaced block | — | the scheduler drops its attempts and recomputes on the replacement chain; each chain verifier reads again; a result built on the replaced block reverts at `apply`; node-held versions survive by the retention rule; a round already running finishes and its result is served (DESIGN.md, "Replaced blocks") |
| a replayed signed body | refused by `seq` (registry) or by request id and body hash (execute) | the same, plus `seen` in `append()` |
| a registry body only some nodes committed | 500 naming both sides; repaired by resending the same body; compared by `sync-registry --check` and the orchestrator; a node several bodies behind resynced by `sync-registry --lost <i> --from <j>` (section 4) | the same |
