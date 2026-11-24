// The client-held Monty Hall game of examples/monty-hall end to end
// (docs/ARCHITECTURE.md section 3, the record path; section 5, invariants 6
// to 9; section 8): a full game whose seed and game state live only as state
// records the player carries, a second game for the mixed-record case, every
// refusal of the record path, the lost answer recovered by FETCH, and the
// client-side and node-side tamper negatives. scenarios/README.md lists every case.
import type { Scenario } from "../scenario.ts";

// The contract's constants (examples/monty-hall/contract/montyhall/src/main.nr
// and notes.nr) and the manifests' owner const. Keys are strings, sent as
// written.
const SEED_KEY = "0xff01";
const GAME_KEY = "0xff02";
const OWNER = 0xafafafn;
const DOM_SEP__MH_DOOR_CHOICE = 0x4d480003;

// The player's moves. By default door 1, then switch. The
// winning door is drawn from the network's seed, so nobody (the driver
// included) knows it and either move can win; the scenario checks the game's
// consistency, not the outcome. Any door 0..2 and either choice exercise the
// same rounds.
const DOOR = 1;
const SWITCH = true;

const open = { public: { in0_nonce: "$game0.nonce" }, stateKeys: { reads: [GAME_KEY], writes: [GAME_KEY] }, records: ["$init.records[0]"], shared: { door: DOOR, door_randomness: "$doorRandomness" } };
const finish = { public: { switch: SWITCH, in0_nonce: "$game1.nonce" }, stateKeys: { reads: [GAME_KEY], writes: [] }, records: ["$open.records[0]"] };

export const scenario: Scenario = {
  example: "monty-hall",
  accounts: ["operator", "player"],
  // The game contract, deployed by the operator without an initializer
  // (init_game creates its Config note); its address is the namespace.
  contracts: { montyhall: { package: "montyhall", from: "operator" } },
  // Both accounts are in the driver's one EmbeddedWallet: start_game, sent
  // to an account of the same wallet, tags the Game note with the
  // address-derived (operator, player) secret, and the PXE scans its own
  // accounts as senders, so registering the operator as a sender changes
  // nothing here. monty-two-wallets.ts runs the game across two wallets,
  // where the note goes through a handshake.
  senders: ["operator"],
  // The run's keys are fresh: the namespace owner key
  // (registers the contract manifest of the four circuits), the player's requester key (owns every
  // record of the game) and the operator's requester key (used only by the
  // negative cases that try the player's round). A deployment keeps the
  // owner key with its deployer secrets and the requester key with the user.
  keys: { owner: "owner", otherOwner: "owner", player: "requester", operator: "requester" },
  // Every round names the player's requester key and is signed by it, so
  // every record the rounds create is owned by the player.
  signer: "player",
  namespaces: { main: "$contracts.montyhall", other: { random: "field" } },
  steps: [
    { register: ["pss_seed", "monty_hall_init", "monty_hall_open_door", "monty_hall_finish"] },
    // The operator's Config note (whoever sends init_game is the operator);
    // start_game copies the pins the player's calls use into the player's
    // Game note.
    {
      let: {
        config: {
          player: "$accounts.player",
          owner: OWNER,
          npk_app_hash: "$pins.main.npk_app_hash",
          seed_vk_hash: "$pins.main.vk.pss_seed",
          init_vk_hash: "$pins.main.vk.monty_hall_init",
          open_vk_hash: "$pins.main.vk.monty_hall_open_door",
          finish_vk_hash: "$pins.main.vk.monty_hall_finish",
        },
      },
    },

    // SEED and init_game (operator): init_game pushes 0 = seed note, 1 = the
    // operator's Config note (found by the operator's PXE; nobody mines its nonce).
    { round: "pss_seed", name: "seed", stateKeys: { writes: [SEED_KEY] } },
    { tx: "init_game", from: "operator", args: ["$config", "$seed.effects.new_note_hashes[0]"], capsule: "$seed", notes: ["seedNote"], noteHashes: 2 },
    // INIT and start_game (operator): start_game pushes 0 = game-state note,
    // 1 = the player's Game note (found by the player's PXE).
    { round: "monty_hall_init", name: "init", public: { in0_nonce: "$seedNote.nonce" }, stateKeys: { reads: [SEED_KEY], writes: [GAME_KEY] }, records: ["$seed.records[0]"], consumes: ["$seedNote"] },
    {
      tx: "start_game",
      from: "operator",
      args: ["$init.effects.read_leaves", "$init.effects.nullifiers", "$init.effects.new_note_hashes", "$init.effects.npk_app_hash"],
      capsule: "$init",
      notes: ["game0"],
      noteHashes: 2,
    },

    // choose_door (player): the door and its blinding are the player's own
    // note; the same two values go to the network below as INPUT_SHARED inputs.
    { let: { doorRandomness: { random: "field" } } },
    { tx: "choose_door", from: "player", args: [DOOR, "$doorRandomness"] },
    { let: { doorCommitment: { poseidon2: [DOOR, "$doorRandomness"], separator: DOM_SEP__MH_DOOR_CHOICE } } },
    { log: "choose_door: door commitment ${doorCommitment}" },

    // A second game, for the mixed-record case: seed and init only. Its game
    // record is a valid record of this namespace, key and owner, for another
    // note hash.
    { round: "pss_seed", name: "seedB", what: "second game seed", stateKeys: { writes: [SEED_KEY] } },
    { round: "monty_hall_init", name: "initB", what: "second game init", public: { in0_nonce: 1 }, stateKeys: { reads: [SEED_KEY], writes: [GAME_KEY] }, records: ["$seedB.records[0]"] },

    // OPEN_DOOR: refusals first, then the round.
    {
      round: "monty_hall_open_door",
      ...open,
      what: "open_door with the door shared inconsistently between nodes (step 10)",
      tamper: { share: "door" },
      refused: { class: "bad_request", status: 400, mentions: ["session handshake"] },
    },
    // Records mixed from two games: the second game's record with node 0's
    // third replaced by this game's. The signature covers the record hashes,
    // not the thirds, so it still verifies; the client's own check refuses
    // the body, and sent past it, the own-ciphertext check (step 6) refuses it.
    {
      round: "monty_hall_open_door",
      ...open,
      records: ["$initB.records[0]"],
      what: "open_door with records mixed from two games",
      tamper: { third: { record: 0, node: 0, from: "$init.records[0]" } },
      clientRefuses: ["record_hashes[0]: not the hash of c[0]"],
      refused: { class: "bad_request", status: 400, mentions: ["record_hashes[0]"] },
    },
    {
      round: "monty_hall_open_door",
      name: "open",
      ...open,
      consumes: ["$game0"],
      expect: [
        ["in", "$open.out[0]", [0, 1, 2]],
        ["ne", "$open.out[0]", DOOR],
        ["eq", "$open.out[1]", "$doorCommitment"],
      ],
    },
    // The node-side negative on this client-proved transaction.
    { tx: "open_door", from: "player", args: ["$open.effects"], capsule: "$open", notes: ["game1"], nodeTamper: true },
    { tx: "switch_door", from: "player", args: [SWITCH] },

    // FINISH: refusals first, then the round.
    // Another circuit on a consumed game record: finish on the record
    // open_door consumed, refused before anything is loaded, naming the
    // consuming circuit by its vk hash (never the consuming request).
    {
      round: "monty_hall_finish",
      ...finish,
      public: { switch: 1, in0_nonce: "$game0.nonce" },
      records: ["$init.records[0]"],
      what: "finish on the game record open_door consumed",
      refused: { class: "conflict", status: 409, mentions: ["already consumed by another circuit", "$pins.main.vk.monty_hall_open_door"] },
    },
    // The player's record presented under another namespace, where the
    // finish circuit is registered too: the thirds were sealed for this
    // namespace and do not open there.
    { register: ["monty_hall_finish"], namespace: "other", by: "otherOwner" },
    {
      round: "monty_hall_finish",
      ...finish,
      namespace: "other",
      what: "finish with the game record under another namespace (step 8)",
      refused: { class: "bad_request", status: 400, mentions: ["does not open"] },
    },
    // The operator tries the player's finish with the player's record: named
    // as the player and signed by the operator, the client refuses it, and
    // sent past the client the signature check refuses it; named as the
    // operator and signed by it, the signature verifies and the player's
    // thirds do not open for another owner.
    {
      round: "monty_hall_finish",
      ...finish,
      what: "finish by the operator: the player's record, the operator's signature (step 4)",
      tamper: { signWith: "operator" },
      clientRefuses: ["does not verify under requester"],
      refused: { class: "forbidden", status: 403, mentions: ["signature"] },
    },
    {
      round: "monty_hall_finish",
      ...finish,
      signer: "operator",
      what: "finish by the operator under its own requester key (step 8)",
      refused: { class: "bad_request", status: 400, mentions: ["does not open"] },
    },
    // The finish answer is lost: the client has only the request id.
    {
      round: "monty_hall_finish",
      name: "finish",
      ...finish,
      answer: "lost",
      consumes: ["$game1"],
      expect: [
        ["in", "$finish.out[0]", [0, 1]],
        ["len", "$finish.records", 0],
        ["len", "$finish.response.stored", 0],
      ],
    },
    // The client-side tamper negative, then the honest finish_game.
    {
      tx: "finish_game",
      from: "player",
      args: ["$finish.effects.read_leaves", "$finish.effects.nullifiers", "$finish.effects.npk_app_hash", "$finish.effects.app_outputs"],
      capsule: "$finish",
      clientTamper: true,
    },
    // A finish replay under a new request id on the consumed record.
    {
      round: "monty_hall_finish",
      ...finish,
      what: "finish replayed under a new request id on the consumed game record",
      refused: { class: "conflict", status: 409, mentions: ["is already consumed; a retry of the consuming round uses FETCH"] },
    },

    { log: "GAME COMPLETE: the player chose door 1, the host opened door ${open.out[0]}, the player switched, win = ${finish.out[0]}" },
  ],
};
