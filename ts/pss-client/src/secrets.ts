// The user's per-request secrets (docs/ARCHITECTURE.md section 6, "The note
// hash and randomness rule"; docs/ARCHITECTURE.md section 1's hash table): every
// request a user sends in one namespace takes the next value n of a client-side
// request counter, advanced on every request sent, failed or not, and derives from
// a wallet secret
//
//   rho          = poseidon2([PSS_PARTIAL_RANDOMNESS, wallet_secret, namespace, n])
//   outcome_key  = poseidon2([PSS_OUTCOME_KEY,        wallet_secret, namespace, n])
//   outcome_tag  = poseidon2([PSS_OUTCOME_TAG,        wallet_secret, namespace, n])
//
// rho is the randomness of the request's partial note (`$partial_note` =
// partialCommitment(owner, rho), outcome.ts), and the key and tag those of
// its private outcome. SecretStore keeps the counter in a RequestStore-shaped durable map
// and recovers it from the wallet secret alone by rescanning n = 0, 1, ...
// (recover, gap limit DEFAULT_GAP_LIMIT), so no partial note, key or tag is
// used twice and a user who loses local state re-derives every request's
// partial note and outcome key, its notes coming back with them (a private
// completion's note from its outcome log, and its chain request id, the
// note's last field, from the log transaction's done[index] write and
// requests[index]; a public completion's from its completion log, which
// carries the request id). Two requests of one user are unlinkable on chain
// and to the nodes; the Aztec node the client asks for their tags can link
// them (docs/DESIGN.md, "Who sees what"). testvectors/secret_store.json holds known
// answers, which testvectors/noir/outcome_vectors checks with Noir's Poseidon2. The
// notes of an entry owned by note (e.g. a lending position) come back with the
// rest: the opening round's note reports the assigned index, and every later note
// of the entry names it (docs/ARCHITECTURE.md section 6, "Ownership by note").

import { Fr } from "@aztec-labs/aztec.js/fields";
import { poseidon2Hash } from "@aztec-labs/foundation/crypto/poseidon";

import { fieldBigInt, fieldHex, randomField, type FieldHexString, type FieldLike } from "./field.ts";
import { handleSecrets, nextHandle, type NextHandle } from "./handle.ts";
import type { SharedSecrets } from "./tip.ts";
import { PARTIAL_NOTE_NAME } from "./manifest.ts";
import { partialCommitment } from "./outcome.ts";
import { MemoryRequestStore, SerialQueue, type RequestStore } from "./store.ts";
import { asciiLabel } from "./labels.ts";

/** The bytes `pss.partial_randomness` read big-endian: rho's label. */
export const PSS_PARTIAL_RANDOMNESS = asciiLabel("pss.partial_randomness");
/** The bytes `pss.outcome_key` read big-endian. */
export const PSS_OUTCOME_KEY = asciiLabel("pss.outcome_key");
/** The bytes `pss.outcome_tag` read big-endian. */
export const PSS_OUTCOME_TAG = asciiLabel("pss.outcome_tag");

/** The rescan's gap limit: recover stops after this many consecutive n
 * with no outcome. Default 20. A request that was never sent or whose
 * intake reverted leaves its n unused; a user who leaves more unused n in a
 * row than the limit loses the requests past the run from a rescan (a
 * larger limit finds them, at one log query per n). */
export const DEFAULT_GAP_LIMIT = 20;

const counter = (j: number) => {
  if (!Number.isSafeInteger(j) || j < 0) throw new RangeError("counter: a non-negative integer");
  return BigInt(j);
};

async function derive(label: bigint, walletSecret: FieldLike, namespace: FieldLike, j: number): Promise<bigint> {
  const inputs = [label, fieldBigInt(walletSecret, "wallet_secret"), fieldBigInt(namespace, "namespace"), counter(j)];
  return (await poseidon2Hash(inputs.map((v) => new Fr(v)))).toBigInt();
}

/** What the user's n-th request in a namespace derives. */
export interface RequestSecrets {
  n: number;
  /** The partial note's randomness: `$partial_note` = partialCommitment(owner, rho). */
  rho: FieldHexString;
  /** The private outcome's `$outcome_key` and `$outcome_tag`. */
  outcomeKey: FieldHexString;
  outcomeTag: FieldHexString;
}

/** The secrets of the user's n-th request in the namespace `namespace`. */
export async function requestSecrets(walletSecret: FieldLike, namespace: FieldLike, n: number): Promise<RequestSecrets> {
  return {
    n,
    rho: fieldHex(await derive(PSS_PARTIAL_RANDOMNESS, walletSecret, namespace, n)),
    outcomeKey: fieldHex(await derive(PSS_OUTCOME_KEY, walletSecret, namespace, n)),
    outcomeTag: fieldHex(await derive(PSS_OUTCOME_TAG, walletSecret, namespace, n)),
  };
}

/** A request about to be built: its secrets, and the values to pass as
 * an ask's `secrets` (IntakeAsk.secrets: the derived key and tag, a fresh
 * random blinding). */
export interface NextRequest extends RequestSecrets {
  secrets: SharedSecrets;
}

/** A request under partial-note delivery about to be built (SecretStore.
 * nextPartial): its secrets, its partial note, and where each goes. */
export interface NextPartialRequest extends NextRequest {
  /** The note's owner, an account in the user's PXE (the request
   * function's sender where the app binds the owner to it, as the AMM tip
   * does). */
  owner: FieldHexString;
  /** `$partial_note` = partialCommitment(owner, rho). */
  partialNote: FieldHexString;
  /** Merge into the request's named inputs: the partial note under its
   * reserved name, which C commits to. */
  inputs: { [PARTIAL_NOTE_NAME]: FieldHexString };
  /** The request function's argument in the partial note's place
   * (requestIntake's `values`): `rho`, from which the function computes
   * the partial note itself (it never takes it as an argument). */
  values: { [PARTIAL_NOTE_NAME]: FieldHexString };
}

/** Whether the user's request `s` has an outcome on chain: the caller's
 * lookup. Under the private completion, the outcome log under `s.outcomeTag`
 * (discovery.ts OutcomeReader.read with `s.outcomeKey`); under the public
 * completion, the completion log under completionLogTag(partialCommitment(
 * owner, s.rho)) for each `owner` account the user requests with. */
export type RequestFinder = (s: RequestSecrets) => Promise<boolean>;

interface Counter {
  next: number;
}

// DEV DECISION: the wallet secret. The app chooses the field element every
// request secret derives from and where its wallet keeps and backs it up;
// for example a hash of the account's secret key under an app label.
// Whoever holds it can find and open every outcome of the user but spend
// nothing (a note is spent with the owner's keys). The alternative, random
// values per request, makes the client's store the only record of the
// user's requests. Design: docs/ARCHITECTURE.md section 6, "The note hash and
// randomness rule".
/** The request counter of one wallet in one namespace. The counter is kept
 * in a durable string map under the namespace; any RequestStore serves
 * (default in memory; a JsonFileRequestStore with a file of its own when the
 * counter must survive the process). One SecretStore per wallet, namespace
 * and map. */
export class SecretStore {
  readonly namespace: FieldHexString;
  // an ES private field, so neither util.inspect nor a logger prints it
  readonly #walletSecret: bigint;
  private readonly store: RequestStore;
  private readonly queue = new SerialQueue();

  constructor(walletSecret: FieldLike, namespace: FieldLike, store: RequestStore = new MemoryRequestStore()) {
    this.#walletSecret = fieldBigInt(walletSecret, "wallet_secret");
    this.namespace = fieldHex(namespace, "namespace");
    this.store = store;
  }

  private async load(): Promise<Counter> {
    const text = await this.store.load(this.namespace);
    if (text === undefined) return { next: 0 };
    const v = JSON.parse(text) as Counter;
    if (!Number.isSafeInteger(v?.next) || v.next < 0) {
      throw new Error(`secret store entry ${this.namespace}: not a request counter`);
    }
    return v;
  }

  // Serialise read-modify-write cycles of this instance.
  private update<T>(change: (c: Counter) => T): Promise<T> {
    return this.queue.run(async () => {
      const c = await this.load();
      const out = change(c);
      await this.store.save(this.namespace, JSON.stringify(c));
      return out;
    });
  }

  /** The secrets of the n-th request. */
  secrets(n: number): Promise<RequestSecrets> {
    return requestSecrets(this.#walletSecret, this.namespace, n);
  }

  /** Take the next counter for a request: n is advanced and saved before
   * this resolves, whether or not the request is ever sent. */
  async next(): Promise<NextRequest> {
    const n = await this.update((c) => c.next++);
    const s = await this.secrets(n);
    return { ...s, secrets: { blinding: randomField(), outcomeKey: BigInt(s.outcomeKey), outcomeTag: BigInt(s.outcomeTag) } };
  }

  /** next() for a request under partial-note delivery whose completed note
   * belongs to `owner`: the partial note it commits, the named input that
   * carries it and the request function's `rho` in its place. Keep `rho`
   * (and the chain request id) to rebuild the completed note
   * (OutcomeKeys.rho, OutcomeKeys.requestId). */
  async nextPartial(owner: FieldLike): Promise<NextPartialRequest> {
    const next = await this.next();
    const partialNote = fieldHex(await partialCommitment(owner, next.rho));
    return {
      ...next,
      owner: fieldHex(owner, "owner"),
      partialNote,
      inputs: { [PARTIAL_NOTE_NAME]: partialNote },
      values: { [PARTIAL_NOTE_NAME]: next.rho },
    };
  }

  /** The delivery handle request `n` leaves for `owner` (handle.ts): the
   * request that took counter `n` (next, nextPartial) commits it when its
   * round carries one, so a rescan of `n` finds its deliveries too. Keep its
   * `handleKey` and `handleRho` until a delivery under it is found or a
   * later request on the entry replaces it. */
  async handle(owner: FieldLike, n: number): Promise<NextHandle> {
    return nextHandle(await handleSecrets(this.#walletSecret, this.namespace, n), owner);
  }

  /** The counter next() would take. */
  async peek(): Promise<number> {
    await this.queue.idle();
    return (await this.load()).next;
  }

  /** Rebuild the counter from the wallet secret alone: look for each
   * request's outcome with `find` for n = 0, 1, ..., stop after `gapLimit`
   * consecutive n with none, move the counter past the last n used, and
   * return the n that have an outcome. Run it when no request of the user is
   * still in flight: one queued but not yet finished has no outcome yet, and
   * a counter that does not pass it would be taken again. A skipped request
   * leaves no outcome (its refund note, if any, is a completion log under
   * its refund note's tag, which `find` may look for too). */
  async recover(find: RequestFinder, gapLimit = DEFAULT_GAP_LIMIT): Promise<number[]> {
    if (!Number.isSafeInteger(gapLimit) || gapLimit < 1) throw new RangeError("gapLimit: a positive integer");
    const found: number[] = [];
    for (let n = 0, misses = 0; misses < gapLimit; n++) {
      if (await find(await this.secrets(n))) {
        found.push(n);
        misses = 0;
      } else {
        misses++;
      }
    }
    const last = found.length === 0 ? -1 : found[found.length - 1]!;
    await this.update((c) => {
      c.next = Math.max(c.next, last + 1);
    });
    return found;
  }

  /** What JSON.stringify writes: the class name, never the secret. */
  toJSON(): string {
    return "SecretStore";
  }
}
