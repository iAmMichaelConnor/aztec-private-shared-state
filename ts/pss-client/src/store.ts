// Where the client keeps the request ids it has sent and the exact bodies it
// sent under them, so that after a crash or a lost response it can FETCH the
// result, or resend the same body, instead of building a new request.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

// Operator knob: DESIGN.md, "Configuration reference" (pss-client request
// store). The client saves (request_id, exact JSON body) before it sends and
// keeps it until the caller discards it; the default store is in memory.
/** A durable map from request id to the exact JSON body sent under it. */
export interface RequestStore {
  /** Record the body before it is sent. Must be durable when it resolves. */
  save(requestId: string, body: string): Promise<void>;
  /** The saved body, or undefined. */
  load(requestId: string): Promise<string | undefined>;
  /** Forget a request once its transaction is mined. */
  delete(requestId: string): Promise<void>;
  /** The ids still saved: rounds whose transaction has not been confirmed. */
  list(): Promise<string[]>;
}

/** The default store: a Map. Lost when the process exits. */
export class MemoryRequestStore implements RequestStore {
  private readonly entries = new Map<string, string>();
  async save(requestId: string, body: string): Promise<void> {
    this.entries.set(requestId, body);
  }
  async load(requestId: string): Promise<string | undefined> {
    return this.entries.get(requestId);
  }
  async delete(requestId: string): Promise<void> {
    this.entries.delete(requestId);
  }
  async list(): Promise<string[]> {
    return [...this.entries.keys()];
  }
}

/** Runs async tasks one after another, so the read-modify-write cycles of
 * one owner never interleave. */
export class SerialQueue {
  private tail: Promise<unknown> = Promise.resolve();

  run<R>(task: () => Promise<R>): Promise<R> {
    const next = this.tail.then(task);
    this.tail = next.catch(() => undefined);
    return next;
  }

  /** Resolves once every task queued so far has settled. */
  async idle(): Promise<void> {
    await this.tail;
  }
}

/** A JSON object in a file, rewritten atomically (write a temporary file,
 * then rename) on every change, its read-modify-write cycles serialised
 * within this process. One process per file; a missing file reads as `{}`. */
export class JsonFile<T extends object> {
  readonly path: string;
  private readonly kind: string;
  private readonly queue = new SerialQueue();

  /** `kind` names the content in the error for a file that holds no object. */
  constructor(path: string, kind: string) {
    this.path = path;
    this.kind = kind;
  }

  /** The content, after every queued change. */
  async read(): Promise<T> {
    await this.queue.idle();
    return this.load();
  }

  /** Apply `change` to the content and write it back; resolves to what
   * `change` returns. */
  update<R>(change: (content: T) => R): Promise<R> {
    return this.queue.run(async () => {
      const content = await this.load();
      const out = change(content);
      await mkdir(dirname(this.path), { recursive: true });
      const tmp = `${this.path}.${process.pid}.tmp`;
      await writeFile(tmp, JSON.stringify(content, null, 1) + "\n", { encoding: "utf8", flush: true });
      await rename(tmp, this.path);
      return out;
    });
  }

  private async load(): Promise<T> {
    let text: string;
    try {
      text = await readFile(this.path, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return {} as T;
      throw e;
    }
    const v: unknown = JSON.parse(text);
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error(`${this.path}: not a ${this.kind}`);
    return v as T;
  }
}

/** A JSON file `{ "<request_id>": "<body>" , ... }` (JsonFile). */
export class JsonFileRequestStore implements RequestStore {
  readonly path: string;
  private readonly file: JsonFile<Record<string, string>>;
  constructor(path: string) {
    this.path = path;
    this.file = new JsonFile(path, "request store");
  }

  save(requestId: string, body: string): Promise<void> {
    return this.file.update((e) => {
      e[requestId] = body;
    });
  }
  async load(requestId: string): Promise<string | undefined> {
    return (await this.file.read())[requestId];
  }
  delete(requestId: string): Promise<void> {
    return this.file.update((e) => {
      delete e[requestId];
    });
  }
  async list(): Promise<string[]> {
    return Object.keys(await this.file.read());
  }
}
