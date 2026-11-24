// Credits paid to a key (scenarios/README.md, "credits-tip.ts";
// examples/credits-tip): one deployment the harness made of CreditsTip
// (E2E_TIP=1, E2E_TIP_DEPLOYMENTS="credits-tip"), its ledger a keyed oblivious
// map (`access: oblivious, keyed: true`) created by the init round. Every
// round runs under secret-shared receipt intake with a private outcome
// completing the requester's partial note: bob pays alice's handle, which no
// partial note of alice's could have received; alice claims from it (her key
// derived from her address and secret in her request function); bob's view of
// his own key proves it absent; alice moves credit to bob's handle, and bob's
// view then finds it. Every key the nodes receive is a map key, the hash of a
// handle (`map_key` in the contract), which the request function computes
// from the handle or the secret it takes in the key's place.
import type { Expect, Scenario, Step, Value } from "../scenario.ts";

/** The separators of a handle, `payee_handle(owner, secret)`, and of a map
 * key, `map_key(handle)`, in the contract
 * (examples/credits-tip/contract/credits_tip/src/app.nr `DOM_SEP__CREDITS_HANDLE`,
 * `DOM_SEP__CREDITS_MAP_KEY`). */
const DOM_SEP__CREDITS_HANDLE = 0x63726864;
const DOM_SEP__CREDITS_MAP_KEY = 0x63726d6b;
const ALICE_SECRET = 0xa5ec;
const BOB_SECRET = 0xb5ec;

type Round = "pay" | "claim" | "view" | "move";
const METHODS: Record<Round, string> = { pay: "pay", claim: "claim", view: "view_balance", move: "move_credit" };

/** A request of `round` from `from`; `privateArgs` names, by input, what the
 * request function takes in the place of a key it derives: a handle (`pay`'s
 * `key`, a move's `to`) or the owner's secret (the sender's own `key`, a
 * move's `from`). */
function request(round: Round, from: string, inputs: Record<string, Value>, name: string, privateArgs: Record<string, Value>): Step {
  return {
    tipRequest: round,
    namespace: "credits",
    from,
    method: METHODS[round],
    inputs,
    privateArgs,
    name,
  } as Step;
}

/** A round's end: the ledger takes the result's new commitment on the
 * previous one; one completed note hash. */
function result(req: string, previous: string): Step {
  const out = `${req}Out`;
  return {
    tipResult: req,
    name: out,
    expect: [
      ["eq", `$${out}.oldCommitments[0]`, previous],
      ["len", `$${out}.noteHashes`, 1],
    ],
  };
}

/** Each round's place in the package list, the `round` its outcome names
 * (examples/credits-tip/circuits/credits_tip/src/ledger.nr `ROUND_*`). */
const ROUNDS: Record<Round, number> = { pay: 1, claim: 2, view: 3, move: 4 };

/** The requester opens `[code, round, a, b]` and takes the completed note
 * `[code, round, a, b, request_id]`, which its PXE then holds (`credit_notes`). */
function outcome(req: string, owner: string, plaintext: Value[]): Step {
  const name = `${req}Outcome`;
  const expect: Expect[] = [["len", `$${name}.plaintext`, 4], ["len", `$${name}.note.packed`, 5]];
  plaintext.forEach((v, i) => expect.push(["eq", `$${name}.plaintext[${i}]`, v]));
  return { tipOutcome: req, owner, notes: "credit_notes", name, expect };
}

export const scenario: Scenario = {
  example: "credits-tip",
  accounts: ["operator", "alice", "bob"],
  wallets: { alice: ["operator", "alice"], bob: ["bob"] },
  keys: {},
  contracts: {},
  namespaces: {},
  tip: { credits: "credits-tip" },
  steps: [
    { tipInit: "credits", name: "creditsInit" },
    {
      let: {
        aliceHandle: { poseidon2: ["$accounts.alice", ALICE_SECRET], separator: DOM_SEP__CREDITS_HANDLE },
        bobHandle: { poseidon2: ["$accounts.bob", BOB_SECRET], separator: DOM_SEP__CREDITS_HANDLE },
      },
    },
    {
      let: {
        aliceKey: { poseidon2: ["$aliceHandle"], separator: DOM_SEP__CREDITS_MAP_KEY },
        bobKey: { poseidon2: ["$bobHandle"], separator: DOM_SEP__CREDITS_MAP_KEY },
      },
    },

    // bob pays alice's handle, its key absent: the round inserts it; bob's note says [0, 1, amount, 0], nothing of alice's balance
    { ...request("pay", "bob", { key: "$aliceKey", amount: 31_337 }, "pay", { key: "$aliceHandle" }), nodeTamper: true } as Step,
    result("pay", "$creditsInit.newCommitments[0]"),
    outcome("pay", "bob", [0, ROUNDS.pay, 31_337, 0]),
    // neither transaction names bob or carries the key, the amount or the outcome
    { tipAudit: "pay", outcome: "payOutcome" },

    // alice claims from her key, named by her secret in her request function
    request("claim", "alice", { key: "$aliceKey", amount: 1_000 }, "claim", { key: ALICE_SECRET }),
    result("claim", "$payOut.newCommitments[0]"),
    outcome("claim", "alice", [0, ROUNDS.claim, 1_000, 30_337]),

    // bob looks his key up before anyone paid it: present 0, the prove-absent outcome
    request("view", "bob", { key: "$bobKey" }, "absent", { key: BOB_SECRET }),
    result("absent", "$claimOut.newCommitments[0]"),
    outcome("absent", "bob", [0, ROUNDS.view, 0, 0]),

    // alice moves credit to bob's handle, whose key the move inserts
    request("move", "alice", { from: "$aliceKey", to: "$bobKey", amount: 2_000 }, "move", { from: ALICE_SECRET, to: "$bobHandle" }),
    result("move", "$absentOut.newCommitments[0]"),
    outcome("move", "alice", [0, ROUNDS.move, 2_000, 28_337]),

    // bob's view now finds his key with the moved credit
    request("view", "bob", { key: "$bobKey" }, "view", { key: BOB_SECRET }),
    result("view", "$moveOut.newCommitments[0]"),
    outcome("view", "bob", [0, ROUNDS.view, 1, 2_000]),
  ],
};
