// The fee setting: wFJ by default at the pinned address, fixed gas per
// transaction kind, the refusal of a payment that claims FeeJuice, the node
// version check, and the maximum gas cost wFJ charges.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { describe, test } from "node:test";

import { FPCFeePaymentMethod, PrivateMintAndPayFeePaymentMethod } from "@alejoamiras/private-fee-juice/fee-payment-methods";
import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { Gas } from "@aztec-labs/stdlib/gas";

import {
  ConfigError,
  DEFAULT_FEE_SETTING,
  SEND_WAIT,
  WFJ,
  checkWfjNode,
  feeOptions,
  maxGasCost,
  txSendOptions,
  wfjAddress,
  type FeeSetting,
} from "../src/internal.ts";

const canonical = JSON.parse(readFileSync(createRequire(import.meta.url).resolve("@alejoamiras/private-fee-juice/canonical-deployment.json"), "utf8")) as {
  aztecVersion: string;
  salt: string;
  expectedAddress: string;
};

const GAS = { gasLimits: { daGas: 100_000, l2Gas: 2_000_000 } };
const TEARDOWN = { daGas: 1, l2Gas: 1 };
/** The gas settings feeOptions returns for GAS (and a teardown limit). */
const settings = (teardown?: typeof TEARDOWN) => ({ gasLimits: Gas.from(GAS.gasLimits), ...(teardown && { teardownGasLimits: Gas.from(teardown) }) });

describe("fee setting", () => {
  test("the pin is the package's canonical deployment", () => {
    assert.equal(WFJ.aztecVersion, canonical.aztecVersion);
    assert.equal(WFJ.salt, BigInt(canonical.salt));
    assert.ok(wfjAddress().equals(AztecAddress.fromBigIntUnsafe(BigInt(canonical.expectedAddress))));
  });

  test("the default pays every kind through wFJ's pay_fee, at the wallet's gas", async () => {
    for (const kind of ["deploy", "configure", "request", "result", "redeem", "skip"] as const) {
      const { fee } = await feeOptions(undefined, kind);
      assert.ok(fee?.paymentMethod instanceof FPCFeePaymentMethod, kind);
      assert.ok((await fee.paymentMethod.getFeePayer()).equals(wfjAddress()));
      assert.equal(fee.gasSettings, undefined);
    }
    const payload = await (await feeOptions(DEFAULT_FEE_SETTING, "request")).fee!.paymentMethod!.getExecutionPayload();
    assert.deepEqual(payload.calls.map((c) => [c.name, c.to.toString()]), [["pay_fee", WFJ.address]]);
  });

  test("gas is fixed per kind, the same for every request", async () => {
    const setting: FeeSetting = { method: "wfj", gas: { request: GAS, result: { ...GAS, teardownGasLimits: TEARDOWN } } };
    const a = await feeOptions(setting, "request");
    const b = await feeOptions(setting, "request");
    assert.deepEqual(a.fee!.gasSettings, settings());
    assert.deepEqual(b.fee!.gasSettings, a.fee!.gasSettings);
    assert.deepEqual((await feeOptions(setting, "result")).fee!.gasSettings, settings(TEARDOWN));
    assert.equal((await feeOptions(setting, "skip")).fee!.gasSettings, undefined);
    await assert.rejects(feeOptions({ method: "wfj", gas: { redeem: { gasLimits: { daGas: 0, l2Gas: 5 } } } }, "redeem"), /fee\.gas\.redeem\.gasLimits\.daGas: a positive integer, got 0/);
  });

  test("every send of the library waits for proposed, with the fee of its kind", async () => {
    assert.deepEqual(SEND_WAIT, { waitForStatus: "proposed" });
    assert.deepEqual(await txSendOptions({ method: "account" }, "skip"), { wait: SEND_WAIT });
    const sent = await txSendOptions(undefined, "result");
    assert.equal(sent.wait, SEND_WAIT);
    assert.ok(sent.fee?.paymentMethod instanceof FPCFeePaymentMethod);
  });

  test("account pays with no payment method", async () => {
    assert.deepEqual(await feeOptions({ method: "account" }, "request"), {});
    assert.deepEqual(await feeOptions({ method: "account", gas: { request: GAS } }, "request"), { fee: { gasSettings: settings() } });
  });

  test("an app's own fee-payment contract is used as given", async () => {
    const sponsor = AztecAddress.fromBigIntUnsafe(0x5150n);
    const { fee } = await feeOptions({ method: { paymentMethod: new FPCFeePaymentMethod(sponsor), name: "app" } }, "request");
    assert.ok((await fee!.paymentMethod!.getFeePayer()).equals(sponsor));
  });

  test("a payment that claims FeeJuice (cold-start mint_and_pay_fee) is refused", async () => {
    const coldStart = new PrivateMintAndPayFeePaymentMethod(wfjAddress(), 10n, new Fr(1n), new Fr(2n), new Fr(3n));
    await assert.rejects(
      feeOptions({ method: { paymentMethod: coldStart, name: "cold start" } }, "request"),
      (e: unknown) => e instanceof ConfigError && /fee method cold start: its payment calls FeeJuice \(a claim\).*never inside a request/.test((e as Error).message),
    );
  });

  test("the node's version must be the pinned one", async () => {
    await checkWfjNode({ getNodeInfo: async () => ({ nodeVersion: WFJ.aztecVersion }) });
    await assert.rejects(
      checkWfjNode({ getNodeInfo: async () => ({ nodeVersion: "6.0.1" }) }),
      (e: unknown) => e instanceof ConfigError && /the node runs Aztec 6\.0\.1, wFJ is pinned at 0x0516.* for Aztec 6\.0\.0/.test((e as Error).message),
    );
  });
});

describe("the maximum gas cost", () => {
  test("is wFJ's: DA and L2 limits at the max fees per gas", () => {
    assert.equal(maxGasCost({ daGas: 1000, l2Gas: 2000 }, { feePerDaGas: 3n, feePerL2Gas: 5n }), 3n * 1000n + 5n * 2000n);
  });
});
