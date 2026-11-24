// Schnorr signatures over Grumpkin for the signed bodies of the sidecar API:
// REGISTER and DISABLE (signed by the namespace owner) and an execute request
// that supplies client-held records (signed by the requester). The scheme is
// noir-lang/schnorr v0.4.0, which @aztec-labs/foundation's Schnorr (barretenberg)
// implements; the message rule is machine/sidecar-core/src/schnorr.rs's
// message_for, byte for byte.

import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { poseidon2HashBytes } from "@aztec-labs/foundation/crypto/poseidon";
import { Schnorr, SchnorrSignature } from "@aztec-labs/foundation/crypto/schnorr";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { GrumpkinScalar, Point } from "@aztec-labs/foundation/curves/grumpkin";

import { fieldBigInt, fieldHex, type FieldLike } from "./field.ts";
import {
  canonicalJson,
  checkName,
  normaliseSignature,
  type DisableBody,
  type DisableRequest,
  type GrumpkinPoint,
  type ManifestBody,
  type ManifestMessage,
  type Signature,
} from "./wire.ts";

// The signed-body message domains. The message a key signs for a JSON body
// is poseidon2HashBytes(domain ‖ JCS(body without its top-level
// `signature`)), with one domain per kind of body: the three strings below,
// the same constants as sidecar-core (REGISTER_DOMAIN, DISABLE_DOMAIN,
// EXECUTE_DOMAIN in schnorr.rs). The domain keeps a signature on one kind of
// body from being accepted as another, or as any other message the same key
// signs (a tip receipt, an Aztec authwit). Changing one here without the
// nodes makes every signature of that kind fail with 403; changing both
// invalidates every signed body in flight.
export const REGISTER_DOMAIN = "cosnark-sidecar/v1/register";
export const DISABLE_DOMAIN = "cosnark-sidecar/v1/disable";
export const EXECUTE_DOMAIN = "cosnark-sidecar/v1/execute";

/** The field element a key signs for `body` under `domain`:
 * `poseidon2HashBytes(domain ‖ JCS(body))`, with a top-level `signature`
 * member left out. The body is taken as it would be sent (through
 * JSON.stringify), so what is signed is exactly what the nodes parse. */
export async function messageFor(domain: string, body: object): Promise<Fr> {
  const sent: unknown = JSON.parse(JSON.stringify(body));
  if (typeof sent !== "object" || sent === null || Array.isArray(sent)) {
    throw new TypeError("the signed body is not a JSON object");
  }
  const { signature: _omit, ...unsigned } = sent as Record<string, unknown>;
  const bytes = Buffer.concat([Buffer.from(domain, "utf8"), Buffer.from(canonicalJson(unsigned), "utf8")]);
  return poseidon2HashBytes(bytes);
}

/** The message of a REGISTER body (signed by the namespace owner). */
export function registerMessage(body: object): Promise<Fr> {
  return messageFor(REGISTER_DOMAIN, body);
}

/** The message of a DISABLE body (signed by the namespace owner). */
export function disableMessage(body: object): Promise<Fr> {
  return messageFor(DISABLE_DOMAIN, body);
}

// The message of an execute request is executeMessage() in request.ts: the
// same rule over the request's canonical body.

// ---- the 64-byte form ----

const LIMB = 1n << 128n;

/** The wire signature of barretenberg's 64-byte `s ‖ e` (each 32 bytes
 * big-endian): `s: [lo, hi]`, `e: [lo, hi]`. */
export function signatureFromBytes(bytes: Uint8Array): Signature {
  if (bytes.length !== SchnorrSignature.SIZE) throw new RangeError(`signature: ${bytes.length} bytes, expected 64`);
  const [sLo, sHi, eLo, eHi] = new SchnorrSignature(Buffer.from(bytes)).toLimbFields();
  return { s: [sLo.toString(), sHi.toString()], e: [eLo.toString(), eHi.toString()] };
}

/** The 64-byte `s ‖ e` form of a wire signature. Refused when a limb is not
 * below 2^128. */
export function signatureToBytes(sig: Signature): Uint8Array {
  const { s, e } = normaliseSignature(sig);
  const out = Buffer.alloc(64);
  for (const [offset, limb] of [[0, s[1]], [16, s[0]], [32, e[1]], [48, e[0]]] as const) {
    const v = fieldBigInt(limb);
    if (v >= LIMB) throw new RangeError(`signature limb ${limb} is not below 2^128`);
    out.set(Buffer.from(v.toString(16).padStart(32, "0"), "hex"), offset);
  }
  return new Uint8Array(out);
}

const schnorr = new Schnorr();

/** noir-lang/schnorr v0.4.0 verification of a wire signature. False for a key
 * off the curve (the point (0, 0) included) or a limb out of range, as in
 * sidecar-core's verify_wire. */
export async function verifySignature(message: FieldLike, pubkey: { x: FieldLike; y: FieldLike }, sig: Signature): Promise<boolean> {
  let bytes: Uint8Array;
  let pk: Point;
  try {
    bytes = signatureToBytes(sig);
    const x = fieldBigInt(pubkey.x, "pubkey.x");
    const y = fieldBigInt(pubkey.y, "pubkey.y");
    if (x === 0n && y === 0n) return false;
    pk = new Point(new Fr(x), new Fr(y));
    if (!pk.isOnCurve()) return false;
  } catch {
    return false;
  }
  return schnorr.verifySignature(new Fr(fieldBigInt(message, "message")), pk, new SchnorrSignature(Buffer.from(bytes)));
}

/** The check of the three nodes' signatures on one answer (a round result, a
 * registry answer, receipts): node i's signature over `messages[i]` under
 * node i's key, all three under one of `sigKeySets` (key-epoch.ts
 * signatureKeySets: the contract's current set first and, inside its grace
 * window, the previous one; never keys a server reports). Returns undefined
 * when they verify, otherwise the first node failing under the first set,
 * which the caller turns into its own error. */
export async function failingNode(
  messages: readonly FieldLike[],
  signatures: readonly Signature[],
  sigKeySets: readonly (readonly { x: FieldLike; y: FieldLike }[])[],
): Promise<number | undefined> {
  let firstFailure: number | undefined;
  for (const keys of sigKeySets) {
    let failed: number | undefined;
    for (let i = 0; i < keys.length && failed === undefined; i++) {
      if (!(await verifySignature(messages[i]!, keys[i]!, signatures[i]!))) failed = i;
    }
    if (failed === undefined) return undefined;
    firstFailure ??= failed;
  }
  return firstFailure ?? 0;
}

// ---- signers ----

/** A Grumpkin Schnorr key that can sign messages: a SchnorrKey (OwnerKey,
 * RequesterKey), or a wallet or hardware signer behind the same two calls. */
export interface SchnorrSigner {
  publicKey(): Promise<GrumpkinPoint>;
  /** Sign one field element (the output of messageFor). */
  sign(message: Fr): Promise<Signature>;
}

const HEX_KEY = /^0x[0-9a-fA-F]{64}$/;

// One key class, two roles. SchnorrKey is a Grumpkin secret key in memory;
// OwnerKey and RequesterKey are the same class under the name of the role a
// key plays, so code reads as what it holds. The class does not enforce the
// role: the message domains do (an owner's REGISTER or DISABLE signature
// never verifies as an execute signature, nor the reverse), and the caller
// keeps the two keys apart. The namespace owner key signs registry bodies
// and belongs with the contract's deployer secrets (below); a requester key
// signs execute bodies and owns client-held records (the requester key
// source, request.ts), and lives wherever the app keeps its users' keys.
// Never use one key in both roles: a requester key on a user's machine that
// is also the owner key lets that machine replace the namespace's circuits.
// The two names exist for readability only; tests also use the class for
// the node sig keys of their mock nodes.
// The namespace owner key is the deployment's root of trust. The first
// REGISTER under a namespace records this key's public key as the owner;
// every later REGISTER and every DISABLE there must be signed by it, and
// there is no rotation or recovery. OwnerKey.generate(), the default source,
// draws 64 bytes from the operating system's CSPRNG (node:crypto, never
// foundation's randomness singleton, which tests can make deterministic) and
// reduces them mod the Grumpkin scalar order; save() writes it as one line
// of 0x + 64 hex digits to a file created with mode 0600 in a 0700
// directory, and refuses to overwrite an existing file. Keep that file with
// the contract's deployer secrets, off the machines that run the client for
// users. Losing it means no further REGISTER or DISABLE under the namespace
// (the registered circuits keep working); leaking it lets the holder disable
// the namespace's packages and, on the sidecar path, replace its contract
// manifest. A key in a wallet or HSM plugs in as a
// SchnorrSigner instead.
/** A Grumpkin secret key that signs: a namespace owner key (OwnerKey) or a
 * requester key (RequesterKey). */
export class SchnorrKey implements SchnorrSigner {
  readonly #secret: GrumpkinScalar;
  #pub: Promise<GrumpkinPoint> | undefined;

  private constructor(secret: GrumpkinScalar) {
    if (secret.isZero()) throw new RangeError("key: the zero scalar is not a secret key");
    this.#secret = secret;
  }

  /** A fresh key from the operating system's CSPRNG. */
  static generate(): SchnorrKey {
    for (;;) {
      const v = BigInt("0x" + randomBytes(64).toString("hex")) % GrumpkinScalar.MODULUS;
      if (v !== 0n) return new SchnorrKey(new GrumpkinScalar(v));
    }
  }

  /** A key from `0x` + 64 hex digits (below the Grumpkin scalar order, nonzero). */
  static fromHex(hex: string): SchnorrKey {
    const t = hex.trim();
    if (!HEX_KEY.test(t)) throw new RangeError("key: expected 0x followed by 64 hex digits");
    const v = BigInt(t);
    if (v >= GrumpkinScalar.MODULUS) throw new RangeError("key: not below the Grumpkin scalar order");
    return new SchnorrKey(new GrumpkinScalar(v));
  }

  /** Read a key file written by save(). */
  static async load(path: string): Promise<SchnorrKey> {
    return SchnorrKey.fromHex(await readFile(path, "utf8"));
  }

  /** The secret as `0x` + 64 lowercase hex digits. */
  toHex(): string {
    return "0x" + this.#secret.toBigInt().toString(16).padStart(64, "0");
  }

  /** Write the key to a new file (mode 0600). Refuses to overwrite. */
  async save(path: string): Promise<void> {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    await writeFile(path, this.toHex() + "\n", { mode: 0o600, flag: "wx" });
  }

  /** The public key `secret · G`, in the wire form of `owner_pubkey`. */
  publicKey(): Promise<GrumpkinPoint> {
    this.#pub ??= schnorr.computePublicKey(this.#secret).then((p) => ({ x: fieldHex(p.x.toBigInt()), y: fieldHex(p.y.toBigInt()) }));
    return this.#pub;
  }

  /** A Schnorr signature over one field element, in the wire form. */
  async sign(message: Fr): Promise<Signature> {
    const sig = await schnorr.constructSignature(new Fr(message.toBigInt()), this.#secret);
    return signatureFromBytes(sig.toBuffer());
  }

  /** Never print the secret. */
  toJSON(): string {
    return "SchnorrKey";
  }
}

/** The namespace owner key: a SchnorrKey, named for its role. */
export const OwnerKey = SchnorrKey;
export type OwnerKey = SchnorrKey;

/** A requester key: a SchnorrKey, named for its role. */
export const RequesterKey = SchnorrKey;
export type RequesterKey = SchnorrKey;

// ---- signed REGISTER and DISABLE bodies ----

/** A registry sequence number as a body carries it: an integer from 0 to
 * 2^53 - 1. */
export function checkSeq(seq: unknown, what = "seq"): number {
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 0) throw new RangeError(`${what}: not a non-negative integer`);
  return seq;
}

/** Sign a manifest message (the REGISTER body): adds the signer's key as
 * `owner_pubkey` and its signature over the body (owner_pubkey and seq
 * included) under the REGISTER domain. */
export async function signManifest(body: ManifestBody, signer: SchnorrSigner): Promise<ManifestMessage> {
  const unsigned = {
    namespace: fieldHex(body.namespace, "namespace"),
    manifest: body.manifest,
    circuits: body.circuits,
    owner_pubkey: await signer.publicKey(),
    seq: checkSeq(body.seq),
  };
  const signature = normaliseSignature(await signer.sign(await registerMessage(unsigned)));
  return { ...unsigned, signature };
}

/** The DISABLE body for a circuit of a namespace, claiming registry sequence
 * number `seq`. */
export function disableBody(namespace: FieldLike, circuit: string, seq: number): DisableBody {
  return { namespace: fieldHex(namespace, "namespace"), circuit: checkName("circuit", "circuit name", circuit), seq: checkSeq(seq) };
}

/** Sign a DISABLE body: adds `owner_pubkey` and the signature under the
 * DISABLE domain. */
export async function signDisable(body: DisableBody, signer: SchnorrSigner): Promise<DisableRequest> {
  const unsigned = { ...disableBody(body.namespace, body.circuit, body.seq), owner_pubkey: await signer.publicKey() };
  const signature = normaliseSignature(await signer.sign(await disableMessage(unsigned)));
  return { ...unsigned, signature };
}
