// The bricks a contract artifact reports (bricks.ts): the axis values read
// from the state view's TipState markers, whatever the view is called, and
// the lint that refuses an artifact whose functions disagree with them.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type { AbiType, FunctionAbi } from "@aztec-labs/stdlib/abi";
import { FunctionType } from "@aztec-labs/stdlib/abi";

import { brickProblems, bricksOf, checkedBricks, RESERVED_NAMES, TIP_STATE_PATH, type BrickArtifact } from "../src/internal.ts";

const FIELD: AbiType = { kind: "field" };
const U32: AbiType = { kind: "integer", sign: "unsigned", width: 32 };
const BOOL: AbiType = { kind: "boolean" };

const marker = (path: string): AbiType => ({ kind: "struct", path, fields: [] });

/** The library's TipState with the two brick markers. */
function tipState(nodeKeys: string, upgrades: string): AbiType {
  return {
    kind: "struct",
    path: TIP_STATE_PATH,
    fields: [
      { name: "tail", type: FIELD },
      { name: "node_keys", type: marker(nodeKeys) },
      { name: "upgrades", type: marker(upgrades) },
    ],
  };
}

function fn(name: string, parameters: AbiType[] = [], functionType = FunctionType.PUBLIC, returnType?: AbiType): FunctionAbi {
  return {
    name,
    functionType,
    isOnlySelf: false,
    isStatic: false,
    isInitializer: false,
    parameters: parameters.map((type, i) => ({ name: `p${i}`, type, visibility: "private" as const })),
    ...(returnType !== undefined && { returnType }),
    errorTypes: {},
  };
}

const KEY_EPOCHS = "pss_public_contract::key_epoch::KeyEpochs";
const FIXED_KEYS = "pss_public_contract::signing_keys::FixedKeys";
const FIXED_CIRCUITS = "pss_public_contract::upgrades::FixedCircuits";
const UPGRADES_CIRCUITS = "pss_public_contract::upgrades::UpgradesCircuits";
const UPGRADES_CONTRACT = "pss_public_contract::upgrades::UpgradesContract";

/** A contract whose view (named `view` here: the name is the app's) reports
 * the two bricks, with the extra public functions `publics`. */
function artifact(nodeKeys: string, upgrades: string, publics: FunctionAbi[] = []): BrickArtifact {
  return {
    name: "App",
    functions: [fn("process_result", [], FunctionType.PRIVATE), fn("public_dispatch", [FIELD])],
    nonDispatchPublicFunctions: [fn("view", [], FunctionType.PUBLIC, tipState(nodeKeys, upgrades)), fn("skip"), ...publics],
  };
}

const ROTATION = [fn("rotate_keys", [], FunctionType.PRIVATE), fn("assert_key_epoch", [U32, BOOL])];
const UPGRADE = [fn("upgrade_circuits", [FIELD]), fn("assert_upgrade_class", [FIELD])];

describe("the axis values the state view reports", () => {
  test("each brick's marker is its axis value, whatever the view is named", () => {
    assert.deepEqual(bricksOf(artifact(KEY_EPOCHS, UPGRADES_CONTRACT)), { node_keys: "rotating", upgrades: "contract" });
    assert.deepEqual(bricksOf(artifact(FIXED_KEYS, FIXED_CIRCUITS)), { node_keys: "fixed", upgrades: "fixed" });
    assert.deepEqual(bricksOf(artifact(FIXED_KEYS, UPGRADES_CIRCUITS)), { node_keys: "fixed", upgrades: "circuits" });
  });

  test("a contract with no TipState view reports nothing; an unknown marker is refused", () => {
    assert.equal(bricksOf({ name: "Note", functions: [fn("enter", [], FunctionType.PRIVATE)] }), undefined);
    assert.throws(() => bricksOf(artifact("app::MyKeys", FIXED_CIRCUITS)), /App's view node_keys is `app::MyKeys`, which is none of/);
  });
});

describe("the lint over the artifact", () => {
  test("an artifact that agrees with its bricks passes", () => {
    assert.deepEqual(checkedBricks(artifact(KEY_EPOCHS, UPGRADES_CIRCUITS, [...ROTATION, ...UPGRADE]), { sharedOnchain: false }), {
      node_keys: "rotating",
      upgrades: "circuits",
    });
    assert.deepEqual(brickProblems(artifact(FIXED_KEYS, FIXED_CIRCUITS), bricksOf(artifact(FIXED_KEYS, FIXED_CIRCUITS)), { sharedOnchain: false }), []);
  });

  test("a wrapper the library enqueues by selector must exist with exactly its signature", () => {
    const misnamed = artifact(KEY_EPOCHS, FIXED_CIRCUITS, [fn("rotate_keys", [], FunctionType.PRIVATE), fn("assert_epoch", [U32, BOOL])]);
    assert.throws(() => checkedBricks(misnamed, { sharedOnchain: false }), {
      message: /node_keys rotating, so the library enqueues assert_key_epoch\(u32,bool\) by selector, which the artifact does not declare/,
    });
    const wrongArgs = artifact(KEY_EPOCHS, FIXED_CIRCUITS, [fn("rotate_keys", [], FunctionType.PRIVATE), fn("assert_key_epoch", [U32])]);
    assert.throws(() => checkedBricks(wrongArgs, { sharedOnchain: false }), {
      message: /the artifact's assert_key_epoch is the public assert_key_epoch\(u32\)/,
    });
    const privateGuard = artifact(FIXED_KEYS, UPGRADES_CIRCUITS, [fn("upgrade_circuits", [FIELD]), fn("assert_upgrade_class", [FIELD], FunctionType.PRIVATE)]);
    assert.throws(() => checkedBricks(privateGuard, { sharedOnchain: false }), {
      message: /enqueues assert_upgrade_class\(Field\) by selector, but the artifact's assert_upgrade_class is the private assert_upgrade_class\(Field\)/,
    });
  });

  test("the entry points the client calls must exist for the bricks reported", () => {
    const noUpgradeContract = artifact(FIXED_KEYS, UPGRADES_CONTRACT, UPGRADE);
    assert.throws(() => checkedBricks(noUpgradeContract, { sharedOnchain: false }), {
      message: /upgrades contract, so the artifact must declare upgrade_contract, which it does not/,
    });
    const onchain = artifact(FIXED_KEYS, FIXED_CIRCUITS, [fn("get_enc_key", [U32])]);
    assert.throws(() => checkedBricks(onchain, { sharedOnchain: true }), {
      message: /secret-shared on-chain intake, so the artifact must declare rotate_enc_key, which it does not/,
    });
  });

  test("an entry point of a brick the view does not report is a disagreement, refused loudly", () => {
    const rotatesUnderFixedKeys = artifact(FIXED_KEYS, FIXED_CIRCUITS, ROTATION);
    assert.deepEqual(brickProblems(rotatesUnderFixedKeys, bricksOf(rotatesUnderFixedKeys), { sharedOnchain: false }), [
      "the state view reports node_keys fixed, but the artifact declares assert_key_epoch",
      "the state view reports node_keys fixed, but the artifact declares rotate_keys",
    ]);
    const upgradesUnderFixed = artifact(FIXED_KEYS, FIXED_CIRCUITS, UPGRADE);
    assert.throws(() => checkedBricks(upgradesUnderFixed, { sharedOnchain: false }), /reports upgrades fixed, but the artifact declares assert_upgrade_class/);
    const contractUnderCircuits = artifact(FIXED_KEYS, UPGRADES_CIRCUITS, [...UPGRADE, fn("upgrade_contract", [FIELD, FIELD])]);
    assert.throws(() => checkedBricks(contractUnderCircuits, { sharedOnchain: false }), /reports upgrades circuits, but the artifact declares upgrade_contract/);
    // a contract with no state view reports fixed and fixed, so the same holds
    const noView: BrickArtifact = { name: "Bare", functions: [fn("rotate_keys", [], FunctionType.PRIVATE)] };
    assert.throws(() => checkedBricks(noView, { sharedOnchain: false }), /reports node_keys fixed, but the artifact declares rotate_keys/);
  });
});

test("the reserved names: each entry once, each function the library calls a signature", () => {
  const names = Object.values(RESERVED_NAMES).map((r) => r.name);
  assert.equal(new Set(names).size, names.length);
  for (const r of Object.values(RESERVED_NAMES)) {
    assert.equal(r.kind === "function the library calls", /^\w+\(.*\)$/.test(r.name), r.name);
  }
});
