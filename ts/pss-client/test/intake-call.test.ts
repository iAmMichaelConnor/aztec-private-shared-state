// The request function's parameters (src/intake.ts layIntakeArgs and submitIntake's contract form): each intake's arguments
// laid onto the compiled request functions of examples/amm-tip (inputs one
// by one, and C's values as one array) and examples/lending-tip (inputs one
// by one, an array and a count, rho in the partial note's place), each
// encoded through aztec.js against the function's ABI, a secret-shared
// receipt request's sharing as a struct after C's values; and the refusals.
// submitIntake's default fee: the fee setting's request fee, wFJ by
// default; an explicit fee wins.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { FPCFeePaymentMethod } from "@alejoamiras/private-fee-juice/fee-payment-methods";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { encodeArguments, type FunctionAbi } from "@aztec-labs/stdlib/abi";

import {
  SharedReceipts,
  TipReceipts,
  intakeArgs,
  intakeCall,
  intakeModule,
  SEND_WAIT,
  feeOptions,
  layIntakeArgs,
  submitIntake,
  wfjAddress,
  type FeeSendOptions,
  type FeeSetting,
  type RequestIntake,
  type SubmitOptions,
  type SharedReceiptRequest,
  type Signature,
  type Triple,
} from "../src/internal.ts";
import { contractAbis, hex } from "@aztec-pss/test-support";

const AMM = contractAbis("AmmTip").functions;
const LENDING = contractAbis("LendingTip").functions;
const encoded = (fn: FunctionAbi, args: unknown[]) => encodeArguments(fn, args).map((f) => f.toString());
/** `intake`'s arguments laid onto `fn` (layIntakeArgs over intakeArgs). */
const laid = (fn: FunctionAbi, intake: RequestIntake, options: SubmitOptions = {}) => layIntakeArgs(fn, intake.intake, intakeArgs(intake, options), options.after);

const SIGS = [0, 1, 2].map((i) => ({ s: [hex(0x510 + i), hex(0x520 + i)], e: [hex(0xe10 + i), hex(0xe20 + i)] })) as Triple<Signature>;
const SIG_FIELDS = SIGS.flatMap((s) => [...s.s, ...s.e]);
const EXPIRY = 1300;
const NONCE = 0x7en;
// an app argument after the intake's own (`after`), which no request
// function of the fixtures takes
const AFTER = new Fr(0xe5n);

const onchain = (inputs: bigint[]): RequestIntake => ({
  intake: "onchain",
  request: { namespace: hex(0xa11ce5), vkHash: hex(0x7c), inputs: inputs.map(hex), userNonce: hex(NONCE), inputsHash: hex(0x1a), chainRequestId: hex(0x1d) },
});
const receipt = (inputs: bigint[]): RequestIntake => ({
  intake: "receipt",
  receipts: new TipReceipts({
    namespace: hex(0xa11ce5),
    circuit: "c",
    requestId: hex(0x1d),
    inputsHash: hex(0x1a),
    expiryBlock: EXPIRY,
    receipts: SIGS,
    inputs: inputs.map(hex),
    userNonce: hex(NONCE),
    marginBlocks: 20,
  }),
});
/** A sharing of `l` summands per vector, distinctive per vector and position. */
const sharing = (l: number) => ({
  summands: [0, 1, 2].map((j) => Array.from({ length: l }, (_, k) => hex(0x5000 + 0x100 * j + k))) as Triple<string[]>,
  salts: [0, 1, 2].map((j) => hex(0x5a0 + j)) as Triple<string>,
});
/** The fields `sharing(l)` encodes to: the three summand vectors, then the salts. */
const sharingFields = (l: number) => [...sharing(l).summands.flat(), ...sharing(l).salts];
/** A secret-shared receipt intake of C's `values`, its sharing `l` summands
 * per vector (the shared values and the blinding). */
const shared = (values: bigint[], l = 1): RequestIntake => ({
  intake: "shared_receipt",
  receipts: new SharedReceipts({ values: values.map(hex), sharing: sharing(l), chainRequestId: hex(0x1d) } as SharedReceiptRequest, EXPIRY, SIGS, 20),
});

describe("layIntakeArgs: the intake's arguments on the request function's parameters", () => {
  test("AmmTip's swap takes the inputs one by one, rho in the partial note's place, then user_nonce (on-chain intake)", () => {
    assert.deepEqual(AMM.swap!.parameters.map((p) => p.name), ["amount_in", "direction", "min_out", "rho", "user_nonce"]);
    const args = laid(AMM.swap!, onchain([25000n, 0n, 33000n, 0x9an]));
    assert.equal(args.length, 5);
    assert.ok(args.every((a) => a instanceof Fr));
    assert.deepEqual(encoded(AMM.swap!, args), [25000, 0, 33000, 0x9a, NONCE].map(hex));
    // the request function computes the partial note from its sender and rho
    const target = { contract: { methods: { swap: () => ({ send: async () => undefined }) }, artifact: { functions: [AMM.swap!] } }, method: "swap" };
    const call = intakeCall(target as never, onchain([25000n, 0n, 33000n, 0x9an]), { valuesAt: { 3: 0x5eedn } });
    assert.deepEqual(encoded(AMM.swap!, call.args), [25000, 0, 33000, 0x5eed, NONCE].map(hex));
  });

  test("AmmTip's swap_with_receipts: the inputs, then user_nonce, expiry_block and the receipts (receipt intake)", () => {
    const fn = AMM.swap_with_receipts!;
    const args = laid(fn, receipt([25000n, 0n, 33000n, 0x9an]));
    assert.equal(args.length, 7);
    assert.deepEqual(encoded(fn, args), [...[25000, 0, 33000, 0x9a, NONCE].map(hex), hex(EXPIRY), ...SIG_FIELDS]);
  });

  test("AmmTip's swap_shared takes C's values one by one, rho in the partial note's place, then the sharing (secret-shared receipt intake)", () => {
    const fn = AMM.swap_shared!;
    assert.deepEqual(fn.parameters.slice(0, 6).map((p) => p.name), ["amount_in", "direction", "min_out", "rho", "outcome_key", "outcome_tag"]);
    const values = [25000n, 0n, 33000n, 0x9a9an, 0x6bn, 0x7an];
    // every value of C is shared: six summands and the blinding's
    const intake = shared(values, 7);
    // the request function computes the partial note from its sender and
    // rho, so the sender passes rho at the partial note's position
    const call = intakeCall({ contract: { methods: { swap_shared: () => ({ send: async () => undefined }) }, artifact: { functions: [fn] } }, method: "swap_shared" } as never, intake, { valuesAt: { 3: 0x5eedn } });
    assert.deepEqual(encoded(fn, call.args), [...[25000n, 0n, 33000n, 0x5eedn, 0x6bn, 0x7an].map(hex), ...sharingFields(7), hex(EXPIRY), ...SIG_FIELDS]);
    assert.deepEqual(encoded(fn, laid(fn, intake)), [...values.map(hex), ...sharingFields(7), hex(EXPIRY), ...SIG_FIELDS]);
  });

  test("lending's non-secret-shared deposit takes the inputs one by one under each non-secret-shared intake", () => {
    const fn = LENDING.deposit!;
    assert.deepEqual(encoded(fn, laid(fn, onchain([1n, 500n, 0x5ecn]))), [1, 500, 0x5ec, NONCE].map(hex));
    const withReceipts = LENDING.deposit_with_receipts!;
    const args = laid(withReceipts, receipt([1n, 500n, 0x5ecn]));
    assert.equal(args.length, 6);
    assert.deepEqual(encoded(withReceipts, args), [...[1, 500, 0x5ec, NONCE].map(hex), hex(EXPIRY), ...SIG_FIELDS]);
    // with an argument after the intake's, the parameters do not end in the intake's
    assert.throws(() => laid(fn, onchain([1n, 500n, 0x5ecn]), { after: [AFTER] }), RangeError);
  });

  test("lending's secret-shared rounds take C's values one by one, rho in the partial note's place, a borrower round the handle's randomness in its commitment's; a liquidation an array, a count and a budget; a quote none", () => {
    // the request function computes the partial note from its sender and
    // rho, so the sender passes rho (0x5eed) where C holds the partial note,
    // and likewise the delivery handle's randomness (0xaa11) where C holds
    // the handle's partial commitment (0xaa), the handle's key (0x6c) after
    // it; the sharing holds `l` summands per vector, every shared value of C
    // (all but the position) and the blinding
    const call = (name: string, values: bigint[], l: number, at: number, handleAt?: number) =>
      intakeCall({ contract: { methods: { [name]: () => ({ send: async () => undefined }) }, artifact: { functions: [LENDING[name]!] } }, method: name } as never, shared(values, l), {
        valuesAt: { [at]: 0x5eedn, ...(handleAt === undefined ? {} : { [handleAt]: 0xaa11n }) },
      }).args;
    for (const name of ["deposit_shared", "borrow_shared", "repay_shared", "withdraw_shared"]) {
      const args = call(name, [1n, 500n, 0xaan, 0x6cn, 0x9an, 0x6bn, 0x7an], 7, 4, 2);
      assert.equal(args.length, 10);
      assert.deepEqual(encoded(LENDING[name]!, args), [...[1n, 500n, 0xaa11n, 0x6cn, 0x5eedn, 0x6bn, 0x7an].map(hex), ...sharingFields(7), hex(EXPIRY), ...SIG_FIELDS]);
    }
    for (const name of ["supply_shared", "withdraw_supply_shared"]) {
      const args = call(name, [1n, 500n, 0x9an, 0x6bn, 0x7an], 5, 2);
      assert.equal(args.length, 8);
      assert.deepEqual(encoded(LENDING[name]!, args), [...[1n, 500n, 0x5eedn, 0x6bn, 0x7an].map(hex), ...sharingFields(5), hex(EXPIRY), ...SIG_FIELDS]);
    }
    assert.deepEqual(encoded(LENDING.view_shared!, call("view_shared", [1n, 0xaan, 0x6cn, 0x9an, 0x6bn, 0x7an], 6, 3, 1)), [
      ...[1n, 0xaa11n, 0x6cn, 0x5eedn, 0x6bn, 0x7an].map(hex),
      ...sharingFields(6),
      hex(EXPIRY),
      ...SIG_FIELDS,
    ]);
    // one probe (K = 2): positions [p1], the count, the budget
    const args = call("liquidate_shared", [1n, 1n, 1000n, 0x9an, 0x6bn, 0x7an], 5, 3);
    assert.equal(args.length, 9);
    assert.deepEqual((args[0] as Fr[]).map((f) => f.toBigInt()), [1n]);
    assert.deepEqual(encoded(LENDING.liquidate_shared!, args), [...[1n, 1n, 1000n, 0x5eedn, 0x6bn, 0x7an].map(hex), ...sharingFields(5), hex(EXPIRY), ...SIG_FIELDS]);
    // a quote takes no app input: rho first
    assert.deepEqual(encoded(LENDING.quote_shared!, call("quote_shared", [0x9an, 0x6bn, 0x7an], 4, 0)), [
      ...[0x5eedn, 0x6bn, 0x7an].map(hex),
      ...sharingFields(4),
      hex(EXPIRY),
      ...SIG_FIELDS,
    ]);
  });

  test("layIntakeArgs lays arguments the caller changed (a private value in an input's place)", () => {
    const args = intakeArgs(onchain([1n, 500n, 0x5ecn]));
    (args[0] as Fr[])[2] = new Fr(0x5ec2n);
    assert.deepEqual(encoded(LENDING.deposit!, layIntakeArgs(LENDING.deposit!, "onchain", args)), [1, 500, 0x5ec2, NONCE].map(hex));
  });

  test("intakeCall: values in place of the intake's by position, or laid arguments as given", () => {
    const target = { contract: { methods: { deposit: () => ({ send: async () => undefined }) }, artifact: { functions: [LENDING.deposit!] } }, method: "deposit" };
    const call = intakeCall(target, onchain([1n, 500n, 0x5ecn]), { valuesAt: { 2: 0x5ec2n } });
    assert.deepEqual(encoded(LENDING.deposit!, call.args), [1, 500, 0x5ec2, NONCE].map(hex));
    assert.deepEqual(intakeCall(target, { args: call.args }).args, call.args);
    assert.throws(() => intakeCall(target, onchain([1n, 500n, 0x5ecn]), { valuesAt: { 3: 1n } }), /valuesAt\[3\]: the request function takes 3 values/);
    assert.throws(() => intakeCall(target, { args: call.args }, { valuesAt: { 0: 1n } }), /laid arguments take no values/);
  });

  test("refused, naming the function: another intake's parameters, or values that do not fill the parameters", () => {
    assert.deepEqual(intakeModule("onchain").parameters, [["user_nonce", "field"]]);
    assert.throws(() => laid(AMM.swap_with_receipts!, onchain([25000n, 0n, 33000n, 0x9an])), /swap_with_receipts: its parameters .* do not end in onchain intake's \(user_nonce: field\)/);
    assert.throws(() => laid(AMM.swap!, receipt([25000n, 0n, 33000n, 0x9an])), /swap: its parameters .* do not end in receipt intake's/);
    assert.throws(() => laid(LENDING.deposit_shared!, receipt([1n, 500n, 0x5ecn, 0x6bn, 0x7an])), /deposit_shared: .* do not end in receipt intake's/);
    assert.throws(() => laid(AMM.swap!, onchain([25000n, 0n])), /swap: its 4 parameters before user_nonce take 4 fields; the intake gives 2 values/);
    assert.throws(() => laid(LENDING.deposit!, onchain([1n, 3n, 2n, 4n])), /deposit: its 3 parameters before user_nonce take 3 fields; the intake gives 4 values/);
    assert.throws(() => layIntakeArgs(AMM.swap!, "onchain", [[new Fr(1n)]]), /swap: onchain intake arguments are the values and 1 more/);
  });

  test("secret-shared receipt intake's arguments are the values, {summands, salts}, the expiry and the receipts, laid onto (sharing: struct, expiry_block, receipts)", () => {
    assert.deepEqual(intakeModule("shared_receipt").parameters, [["sharing", "struct"], ["expiry_block", "integer"], ["receipts", "array"]]);
    const field = { kind: "field" };
    const arr = (n: number, type: unknown = field) => ({ kind: "array", length: n, type });
    const receiptStruct = { kind: "struct", path: "pss_public_contract::receipt::Receipt", fields: [{ name: "s", type: arr(2) }, { name: "e", type: arr(2) }] };
    const sharingStruct = { kind: "struct", path: "pss_public_contract::shared_intake::Sharing", fields: [{ name: "summands", type: arr(3, arr(3)) }, { name: "salts", type: arr(3) }] };
    const request = {
      name: "request_shared",
      parameters: [
        { name: "amount", type: field, visibility: "private" },
        { name: "outcome_key", type: field, visibility: "private" },
        { name: "sharing", type: sharingStruct, visibility: "private" },
        { name: "expiry_block", type: { kind: "integer", sign: "unsigned", width: 32 }, visibility: "private" },
        { name: "receipts", type: arr(3, receiptStruct), visibility: "private" },
      ],
      functionType: "private",
      isOnlySelf: false,
      isStatic: false,
      isInitializer: false,
      returnTypes: [],
      errorTypes: {},
    } as unknown as FunctionAbi;
    const intake = shared([500n, 0x6bn], 3);
    const args = intakeArgs(intake);
    assert.equal(args.length, 4);
    assert.deepEqual(args[1], { summands: sharing(3).summands.map((s) => s.map((v) => new Fr(BigInt(v)))), salts: sharing(3).salts.map((v) => new Fr(BigInt(v))) });
    assert.deepEqual(encoded(request, laid(request, intake)), [...[500n, 0x6bn].map(hex), ...sharingFields(3), hex(EXPIRY), ...SIG_FIELDS]);
  });

  test("secret-shared receipt intake refuses receipts that expire soon", () => {
    assert.throws(() => intakeArgs(shared([1n]), { currentBlock: EXPIRY - 20 }), /expire at block 1300, too soon after 1280; ask again/);
    assert.equal(intakeArgs(shared([1n]), { currentBlock: EXPIRY - 21 }).length, 4);
  });
});

const calls: { method: string; args: unknown[]; opts: { fee?: unknown } }[] = [];
const methods = new Proxy({}, {
  get: (_t, method: string) => (...args: unknown[]) => ({
    send: async (opts: { fee?: unknown }) => {
      calls.push({ method, args, opts });
      return { txHash: `0x${method}` };
    },
  }),
}) as Record<string, (...args: never[]) => { send(o: unknown): Promise<unknown> }>;

describe("submitIntake through a contract that carries its artifact", () => {
  const artifact = { functions: [AMM.swap!, LENDING.deposit_shared!] };
  // an explicit fee, sent as given
  const fee = { paymentMethod: "explicit" };

  test("lays the arguments onto the method's parameters; a factory gets the modules' order", async () => {
    calls.length = 0;
    await submitIntake({ contract: { methods, artifact }, method: "swap" }, onchain([25000n, 0n, 33000n, 0x9an]), { from: 0x1234n, fee });
    assert.deepEqual(calls[0]!.args, laid(AMM.swap!, onchain([25000n, 0n, 33000n, 0x9an])));
    // C's values: the position, the amount, the delivery handle, the partial note, the outcome key and tag
    const values = [1n, 500n, 0xaan, 0x6cn, 0x5ecn, 0x6bn, 0x7an];
    await submitIntake({ contract: { methods, artifact }, method: "deposit_shared" }, shared(values, 7), { from: 0x1234n, fee }, { currentBlock: 1000 });
    assert.deepEqual(encoded(LENDING.deposit_shared!, calls[1]!.args), [...values.map(hex), ...sharingFields(7), hex(EXPIRY), ...SIG_FIELDS]);
    await submitIntake(methods.swap_shared!, shared(values, 7), { from: 0x1234n, fee });
    assert.deepEqual(calls[2]!.args, intakeArgs(shared(values, 7)));
  });
});

describe("submitIntake's fee", () => {
  const GAS = { gasLimits: { daGas: 100_000, l2Gas: 2_000_000 } };
  const setting: FeeSetting = { method: "wfj", gas: { request: GAS } };
  const intake = onchain([25000n, 0n, 33000n]);

  test("by default a request pays the fee setting's request fee, through wFJ", async () => {
    calls.length = 0;
    await submitIntake(methods.swap!, intake, { from: 0x1234n }, { fee: setting });
    const sent = calls[0]!.opts as FeeSendOptions & { from: bigint; wait?: unknown };
    assert.equal(sent.from, 0x1234n);
    assert.deepEqual(sent.wait, SEND_WAIT, "the send waits for proposed");
    assert.ok(sent.fee?.paymentMethod instanceof FPCFeePaymentMethod);
    assert.ok((await sent.fee.paymentMethod.getFeePayer()).equals(wfjAddress()));
    assert.deepEqual(sent.fee.gasSettings, (await feeOptions(setting, "request")).fee!.gasSettings);
    // the default setting: wFJ at the wallet's gas
    await submitIntake(methods.swap!, intake, { from: 0x1234n });
    const plain = (calls[1]!.opts as FeeSendOptions).fee;
    assert.ok(plain?.paymentMethod instanceof FPCFeePaymentMethod);
    assert.equal(plain.gasSettings, undefined);
  });

  test("an explicit fee wins", async () => {
    calls.length = 0;
    const fee = { paymentMethod: "explicit" };
    await submitIntake(methods.swap!, intake, { from: 0x1234n, fee }, { fee: setting });
    assert.equal(calls[0]!.opts.fee, fee);
  });

  test("an own fee: undefined keeps the configured payer", async () => {
    calls.length = 0;
    await submitIntake(methods.swap!, intake, { from: 0x1234n, fee: undefined }, { fee: setting });
    const sent = (calls[0]!.opts as FeeSendOptions).fee;
    assert.ok(sent?.paymentMethod instanceof FPCFeePaymentMethod);
    assert.ok((await sent.paymentMethod.getFeePayer()).equals(wfjAddress()));
  });
});
