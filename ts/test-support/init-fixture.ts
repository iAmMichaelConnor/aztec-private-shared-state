// Signed init results for the init tests of pss-client and pss-relayer: an
// answer to FETCH by the init's chain request id, made the way the
// orchestrator answers it (the machine request id of the init id over one
// old commitment of 0 per created key, the public inputs in init.nr's
// init_public_inputs order, no record under node-held state, the three
// nodes' result signatures with the keys.json sig keys and H(sealed_i) = 0),
// for examples/amm-tip's amm_init_tip (one slot key, no new leaf hashes) and
// examples/lending-tip's lending_init (one tree-valued key, its header's new
// leaf hash, one init input).
//
// fixtures/{amm_init_tip,lending_init}.abi.json are the `abi` of the
// circuits compiled with nargo 1.0.0; pss-client's fixtures.test.ts compares
// each with its build.

import { readFileSync } from "node:fs";

import { initChainRequestId, fieldHex } from "@aztec-pss/pss-client/internal";
import { MARKET_KEY, NAMESPACE, NPK_APP_HASH, POOL_KEY, VK_HASH, signedAnswer } from "./tip-fixture.ts";

const json = (p: string) => JSON.parse(readFileSync(new URL(p, import.meta.url), "utf8"));

export const AMM_INIT = {
  circuit: { abi: json("fixtures/amm_init_tip.abi.json").abi },
  manifest: json("../../examples/amm-tip/manifests/amm_init_tip.json"),
};

export const LENDING_INIT = {
  circuit: { abi: json("fixtures/lending_init.abi.json").abi },
  manifest: json("../../examples/lending-tip/manifests/lending_init.json"),
};

/** lending_init's input: the Config's liquidity. */
export const LIQUIDITY = 1_000_000n;

/** amm_init_tip's answer: the pool's first commitment `newC`. */
export async function ammInitAnswer(newC: bigint, opts: { inputs?: bigint[]; oldC?: bigint } = {}) {
  const chain = fieldHex((await initChainRequestId(NAMESPACE, VK_HASH, opts.inputs ?? [])).toBigInt());
  const response = await signedAnswer({
    chainRequestId: chain,
    publicInputs: [BigInt(NAMESPACE), BigInt(VK_HASH), POOL_KEY, chain, opts.oldC ?? 0n, newC, NPK_APP_HASH],
    oldCommitments: [opts.oldC ?? 0n],
    newCommitments: [newC],
    thirdFields: 0,
  });
  return { chain, response };
}

/** lending_init's answer: the market's first commitment `newC` and its
 * header leaf hash `newHash`. */
export async function lendingInitAnswer(newC: bigint, newHash: bigint) {
  const chain = fieldHex((await initChainRequestId(NAMESPACE, VK_HASH, [LIQUIDITY])).toBigInt());
  const response = await signedAnswer({
    chainRequestId: chain,
    publicInputs: [BigInt(NAMESPACE), BigInt(VK_HASH), MARKET_KEY, chain, 0n, newC, NPK_APP_HASH, newHash],
    oldCommitments: [0n],
    newCommitments: [newC],
    thirdFields: 0,
  });
  return { chain, response };
}
