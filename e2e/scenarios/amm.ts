// The node-held AMM of examples/amm end to end (docs/ARCHITECTURE.md
// sections 3, 4 and 8): REGISTER and its refusals, the happy path (seed,
// init_pool, init, start_pool, two swaps), the refusals on consumed and
// foreign state, DISABLE and re-enable, a rolled-back swap, a dropped
// transaction recovered by FETCH, the client-side and node-side tamper
// negatives, and the total swap. scenarios/README.md lists every case.
import type { AnsweredRound, Scenario } from "../scenario.ts";

// The keys and the owner constant. SEED_SLOT and POOL_SLOT are
// the contract's globals (examples/amm/contract/amm/src/main.nr), the
// request keys of the machine and the storage slots in the note hashes;
// OWNER is the manifests' `owner` const, which the circuits bake into every
// note hash and the Config pins. Keys are bigints, which pss-client writes in
// short hex (0xa002), the one spelling the nodes take for a key the manifest
// feeds into PUBLIC. Changing any of them here without the
// contract and the manifests makes every proof fail on chain.
const SEED_SLOT = 0xa001n;
const POOL_SLOT = 0xa002n;
const OWNER = 0xafafafn;
const DOM_SEP__AMM_ANCHOR = 0x414d4d01;

// The trades. The first swap sells x for y, the second y for x;
// the rolled-back swap uses the second swap's inputs, so the restored pool
// must answer it with the same amount_out. Any non-zero amount below the
// reserves works; the reserves derive from a random seed, so amount_out
// differs between runs.
const SWAP1 = { amount_in: 10_000n, direction: 0n };
const SWAP2 = { amount_in: 7_000n, direction: 1n };

// The total swaps. A zero amount first, the one failure every
// pool gives whatever its random reserves (codes 2, 3 and 4 are as
// deterministic; 5 and 6 depend on the reserves; 7 cannot be reached), so
// the run lands an ok = 0 proof; then a trade, which must spend the note the
// no-op re-created. The zero amount is also the request the asserting
// amm_swap is refused for, so the run shows both failure modes on one input.
const TOTAL1 = { amount_in: 0n, direction: 0n };
const TOTAL2 = { amount_in: 5_000n, direction: 0n };

// The total swap runs in co-noir, because the total-noir entries
// amm_swap_total calls (to_u64_or, add_or, mul_div_or) have hints that
// divide by constants and use Field arithmetic instead of the integer And,
// Or, Xor, Shl, Shr and ConditionalMov that co-noir's Brillig VM (co-brillig
// at the pinned co-snarks rev) does not implement; check-noir's
// total-lint --brillig-ops step reports 0 such ops in the circuit.

const onSeed = { reads: [SEED_SLOT], writes: [POOL_SLOT] };
const onPool = { reads: [POOL_SLOT], writes: [POOL_SLOT] };
const swapArgs = (round: string, t: { amount_in: bigint; direction: bigint }) => ["$config", "$anchorNonce", t.amount_in, t.direction, `$${round}.effects`];
const swapRound = (name: string, t: { amount_in: bigint; direction: bigint }, circuit = "amm_swap"): AnsweredRound => ({
  round: circuit,
  name,
  public: { ...t, in0_nonce: "$pool.nonce" },
  stateKeys: onPool,
  consumes: ["$pool"],
  expect: circuit === "amm_swap" ? [["gt", `$${name}.out[0]`, 0]] : [],
});

export const scenario: Scenario = {
  example: "amm",
  accounts: ["operator", "trader"],
  // The pool contract, deployed by the operator without an initializer
  // (init_pool anchors its Config later); its address is the namespace.
  contracts: { amm: { package: "amm", from: "operator" } },
  // The foreign namespace is a random field element with its
  // own owner key, and its package reuses pss_seed's circuit under the name
  // foreign_seed, so a request naming it here is refused by name.
  keys: { owner: "owner", stranger: "owner", foreignOwner: "owner" },
  namespaces: { main: "$contracts.amm", foreign: { random: "field" } },
  aliases: { foreign_seed: "pss_seed" },
  steps: [
    // REGISTER the contract manifest: the owner, the vk hashes, npk_app_hash.
    { register: ["pss_seed", "amm_init", "amm_swap", "amm_swap_total"] },
    { register: ["amm_swap"], seq: 1, by: "stranger", what: "REGISTER signed by a non-owner key", refused: { class: "forbidden", status: 403 } },
    // The Config pins. The vk hashes are the REGISTER answers
    // (equal to bb's local hashes), npk_app_hash the first REGISTER's, owner
    // the manifests' const, operator the deploying account. init_pool
    // anchors them; every later call proves them by the anchor.
    {
      let: {
        config: {
          operator: "$accounts.operator",
          owner: OWNER,
          npk_app_hash: "$pins.main.npk_app_hash",
          seed_vk_hash: "$pins.main.vk.pss_seed",
          init_vk_hash: "$pins.main.vk.amm_init",
          swap_vk_hash: "$pins.main.vk.amm_swap",
          swap_total_vk_hash: "$pins.main.vk.amm_swap_total",
        },
        anchorHash: {
          poseidon2: ["$accounts.operator", OWNER, "$pins.main.npk_app_hash", "$pins.main.vk.pss_seed", "$pins.main.vk.amm_init", "$pins.main.vk.amm_swap", "$pins.main.vk.amm_swap_total"],
          separator: DOM_SEP__AMM_ANCHOR,
        },
      },
    },
    { register: ["foreign_seed"], namespace: "foreign", by: "foreignOwner" },

    // seed and init_pool: init_pool pushes 0 = seed note, 1 = anchor (the contract's comment).
    { round: "pss_seed", name: "seed", stateKeys: { writes: [SEED_SLOT] } },
    { tx: "init_pool", from: "operator", args: ["$config", "$seed.effects.new_note_hashes[0]"], capsule: "$seed", notes: ["seedNote"], mine: [{ index: 1, hash: "$anchorHash", as: "anchorNonce" }] },
    // amm_init and start_pool.
    { round: "amm_init", name: "init", public: { in0_nonce: "$seedNote.nonce" }, stateKeys: onSeed, consumes: ["$seedNote"] },
    {
      tx: "start_pool",
      from: "operator",
      args: ["$config", "$anchorNonce", "$init.effects.read_leaves", "$init.effects.nullifiers", "$init.effects.new_note_hashes", "$init.effects.npk_app_hash"],
      capsule: "$init",
      notes: ["pool"],
    },

    // Refusals on the consumed seed and a foreign circuit.
    {
      round: "amm_init",
      what: "a second amm_init on the consumed seed",
      public: { in0_nonce: "$seedNote.nonce" },
      stateKeys: onSeed,
      refused: { class: "conflict", status: 409, mentions: ["already consumed"] },
    },
    {
      round: "amm_swap",
      what: "amm_swap on the consumed seed",
      public: { amount_in: 1n, direction: 0n, in0_nonce: "$seedNote.nonce" },
      stateKeys: onSeed,
      refused: { class: "conflict", status: 409, mentions: ["already consumed", "vk_hash ${pins.main.vk.amm_init}"] },
    },
    {
      round: "foreign_seed",
      what: "a request naming foreign_seed, registered only under another namespace",
      stateKeys: { writes: [0xa0f0n] },
      refused: { class: "bad_request", status: 400, mentions: ["`foreign_seed` is not registered under namespace"] },
    },

    // Swap 1, carrying the node-side negative.
    swapRound("swap1", SWAP1),
    { tx: "swap", what: "swap 1", from: "trader", args: swapArgs("swap1", SWAP1), capsule: "$swap1", notes: ["pool"], nodeTamper: true },

    // DISABLE, a refused swap, re-enable.
    { disable: "amm_swap", seq: 1 },
    {
      round: "amm_swap",
      what: "a swap request to the disabled amm_swap",
      public: { ...SWAP2, in0_nonce: "$pool.nonce" },
      stateKeys: onPool,
      refused: { class: "bad_request", status: 400, mentions: ["`amm_swap` is disabled"] },
    },
    { register: ["pss_seed", "amm_init", "amm_swap", "amm_swap_total"], seq: 2, what: "REGISTER the same contract manifest again (re-enables amm_swap)" },

    // Rollback: a swap that never lands.
    swapRound("unlandable", SWAP2),
    { restore: "$unlandable", what: "the unlandable swap" },

    // Swap 2: the restored pool, a dropped transaction, FETCH.
    {
      ...swapRound("swap2", SWAP2),
      expect: [
        ["gt", "$swap2.out[0]", 0],
        ["eq", "$swap2.out[0]", "$unlandable.out[0]"],
        ["ne", "$swap2.effects.new_note_hashes[0]", "$unlandable.effects.new_note_hashes[0]"],
      ],
    },
    { tx: "swap", what: "swap 2", from: "trader", args: swapArgs("swap2", SWAP2), capsule: "$swap2", drop: true },
    { fetch: "$swap2", name: "swap2f", what: "swap 2 (fetched)", fresh: true },
    // The client-side negative, while the pool note is unspent and the
    // anchor would let the call through, so the proof is the only thing wrong.
    { tx: "swap", what: "swap 2 (the fetched proof)", from: "trader", args: swapArgs("swap2f", SWAP2), capsule: "$swap2f", notes: ["pool"], clientTamper: true },

    // The total swap: a failure lands as a no-op. The asserting circuit
    // first: amount_in 0 fails amm_swap's assert, so the round runs to its
    // proof, which does not verify; nothing is stored and the pool note the
    // chain holds stays current.
    {
      round: "amm_swap",
      what: "amm_swap with amount_in 0 (the asserting swap)",
      public: { ...TOTAL1, in0_nonce: "$pool.nonce" },
      stateKeys: onPool,
      refused: { class: "unsatisfied", status: 422 },
    },
    // The re-store rule (DECISIONS.md, "CONSUME is `once` or `never`"): the new pool note is
    // never the one consumed, on ok = 0 too, where it holds the old reserves
    // under the fresh blinding the network sampled. app_outputs are [ok, code, amount_out].
    {
      ...swapRound("total1", TOTAL1, "amm_swap_total"),
      expect: [
        ["eq", "$total1.out[0]", 0],
        ["eq", "$total1.out[1]", 1],
        ["eq", "$total1.out[2]", 0],
        ["ne", "$total1.effects.new_note_hashes[0]", "$pool.noteHash"],
      ],
    },
    { tx: "swap_total", what: "total swap 1 (an ok = 0 no-op)", from: "trader", args: swapArgs("total1", TOTAL1), capsule: "$total1", notes: ["pool"] },
    {
      ...swapRound("total2", TOTAL2, "amm_swap_total"),
      expect: [
        ["eq", "$total2.out[0]", 1],
        ["eq", "$total2.out[1]", 0],
        ["gt", "$total2.out[2]", 0],
        ["ne", "$total2.effects.new_note_hashes[0]", "$pool.noteHash"],
      ],
    },
    { tx: "swap_total", what: "total swap 2 (an ok = 1 trade)", from: "trader", args: swapArgs("total2", TOTAL2), capsule: "$total2", notes: ["pool"] },

    { log: "POOL COMPLETE: seed, start and two swaps mined; amount_out ${swap1.out[0]}, ${swap2f.out[0]}; npk_app_hash ${pins.main.npk_app_hash}" },
  ],
};
