// A stand-in orchestrator for the client and relayer tests: a node http server whose routes
// the test sets, recording every request it receives, and a registry that
// answers REGISTER (the manifest message), DISABLE and GET /v1/namespaces the
// way the nodes do as far as owners, sequence numbers, the contract manifest
// rules and signed answers go.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import {
  SchnorrKey,
  contractManifestHash,
  disableMessage,
  fieldHex,
  manifestMessage,
  packagesHash,
  registerMessage,
  registryMessage,
  verifySignature,
  type ContractManifest,
  type GrumpkinPoint,
  type Signature,
} from "@aztec-pss/pss-client/internal";

export interface Received {
  method: string;
  path: string;
  body: string;
}

/** What a route does: answer, never answer, or drop the connection. */
export type Reply = { status: number; body: unknown } | { hang: true } | { drop: true };

export type Route = (req: Received, n: number) => Reply | Promise<Reply>;

export class MockOrchestrator {
  readonly received: Received[] = [];
  readonly routes = new Map<string, Route>();
  readonly prefixes = new Map<string, Route>();
  private server: Server;
  private readonly hanging: ServerResponse[] = [];

  constructor() {
    this.server = createServer((req, res) => void this.handle(req, res));
  }

  /** Set the handler of `METHOD /path`. */
  on(method: string, path: string, route: Route): this {
    this.routes.set(`${method} ${path}`, route);
    return this;
  }

  /** Set the handler of every `METHOD /prefix...` path without an exact route. */
  onPrefix(method: string, prefix: string, route: Route): this {
    this.prefixes.set(`${method} ${prefix}`, route);
    return this;
  }

  count(method: string, path: string): number {
    return this.received.filter((r) => r.method === method && r.path === path).length;
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const r: Received = { method: req.method ?? "", path: req.url ?? "", body: Buffer.concat(chunks).toString("utf8") };
    this.received.push(r);
    const route =
      this.routes.get(`${r.method} ${r.path}`) ??
      [...this.prefixes].find(([k]) => `${r.method} ${r.path}`.startsWith(k))?.[1];
    const reply: Reply = route
      ? await route(r, this.count(r.method, r.path))
      : { status: 404, body: { error: `no route ${r.method} ${r.path}`, class: "not_found" } };
    if ("hang" in reply) {
      this.hanging.push(res);
      return;
    }
    if ("drop" in reply) {
      req.socket.destroy();
      return;
    }
    const text = typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body);
    res.writeHead(reply.status, { "content-type": "application/json" });
    res.end(text);
  }

  async start(): Promise<string> {
    await new Promise<void>((resolve) => this.server.listen(0, "127.0.0.1", resolve));
    const { port } = this.server.address() as AddressInfo;
    return `http://127.0.0.1:${port}`;
  }

  async stop(): Promise<void> {
    for (const res of this.hanging) res.destroy();
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }
}

const refuse = (status: number, cls: string, error: string): Reply => ({ status, body: { error, class: cls } });

interface Package {
  vk_hash: string;
  seq: number;
  disabled: boolean;
}

/** A namespace as the mock holds it: its owner, seq and contract manifest
 * (the document, its hash and the seq that wrote it). */
interface Namespace {
  owner: GrumpkinPoint;
  seq: number;
  manifest: ContractManifest;
  manifestHash: string;
  manifestSeq: number;
}

/** The nodes' registry rules for owners, seq and contract manifests
 * (ARCHITECTURE section 4), with every answer signed by three node sig keys.
 * A namespace's first REGISTER carries seq 0; every later body the stored
 * seq plus one; the last REGISTER resent with its seq, nothing committed
 * since, answers the stored values; any other seq is 409. A later REGISTER
 * of the stored contract manifest re-enables every package; another one is
 * refused (400) when either has a queue (a tip namespace), and replaces the
 * stored one otherwise (the sidecar path). The vk hashes are the manifest's
 * own (no circuit is built). */
export class MockRegistry {
  readonly namespaces = new Map<string, Namespace>();
  /** By `namespace/name`. */
  readonly packages = new Map<string, Package>();

  readonly nodeSigKeys: [SchnorrKey, SchnorrKey, SchnorrKey];
  readonly npkAppHash: string;

  constructor(nodeSigKeys: [SchnorrKey, SchnorrKey, SchnorrKey], npkAppHash: string) {
    this.nodeSigKeys = nodeSigKeys;
    this.npkAppHash = npkAppHash;
  }

  /** Serve POST /v1/register, POST /v1/disable, GET /v1/namespaces/{ns}
   * and GET /v1/namespaces/{ns}/manifest. */
  install(mock: MockOrchestrator): void {
    mock.on("POST", "/v1/register", (r) => this.register(r.body));
    mock.on("POST", "/v1/disable", (r) => this.disable(r.body));
    mock.onPrefix("GET", "/v1/namespaces/", (r) => this.namespace(r.path.slice("/v1/namespaces/".length)));
  }

  private async signAll(message: (i: number) => Promise<Parameters<SchnorrKey["sign"]>[0]>): Promise<[Signature, Signature, Signature]> {
    return (await Promise.all(this.nodeSigKeys.map(async (k, i) => k.sign(await message(i))))) as [Signature, Signature, Signature];
  }

  private async answer(namespace: string, m: ContractManifest, seq: number): Promise<Reply> {
    const manifestHash = fieldHex((await contractManifestHash(m)).toBigInt());
    const listedHash = fieldHex((await packagesHash(m)).toBigInt());
    return {
      status: 200,
      body: {
        manifest_hash: manifestHash,
        packages_hash: listedHash,
        npk_app_hash: this.npkAppHash,
        seq,
        signatures: await this.signAll((i) => manifestMessage(namespace, manifestHash, listedHash, this.npkAppHash, seq, i)),
      },
    };
  }

  private store(namespace: string, m: ContractManifest, hash: string, seq: number, owner: GrumpkinPoint): void {
    for (const k of [...this.packages.keys()]) if (k.startsWith(`${namespace}/`)) this.packages.delete(k);
    for (const p of m.packages) this.packages.set(`${namespace}/${p.name}`, { vk_hash: fieldHex(m.circuits[p.circuit]!.vk_hash), seq, disabled: false });
    this.namespaces.set(namespace, { owner, seq, manifest: m, manifestHash: hash, manifestSeq: seq });
  }

  async register(text: string): Promise<Reply> {
    const b = JSON.parse(text);
    if (!(await verifySignature(await registerMessage(b), b.owner_pubkey, b.signature))) return refuse(403, "forbidden", "bad signature");
    const m = b.manifest as ContractManifest;
    const hash = fieldHex((await contractManifestHash(m)).toBigInt());
    for (const id of Object.keys(m.circuits ?? {})) {
      if (b.circuits?.[id] === undefined) return refuse(400, "bad_request", `field \`circuits\`: \`${id}\` of \`manifest.circuits\` is missing`);
    }
    const ns = this.namespaces.get(b.namespace);
    const sameOwner = ns !== undefined && ns.owner.x === b.owner_pubkey.x && ns.owner.y === b.owner_pubkey.y;
    if (b.seq === 0) {
      if (ns !== undefined) {
        if (!sameOwner) return refuse(403, "forbidden", "not signed by the namespace owner");
        if (ns.seq !== 0) return refuse(409, "conflict", `seq 0 but the namespace's seq is ${ns.seq}`);
        if (ns.manifestHash !== hash) return refuse(409, "conflict", `namespace ${b.namespace} registered contract manifest ${ns.manifestHash} at seq 0`);
      }
      this.store(b.namespace, m, hash, 0, b.owner_pubkey);
      return this.answer(b.namespace, m, 0);
    }
    if (ns === undefined || !sameOwner) return refuse(403, "forbidden", "not signed by the namespace owner");
    if (ns.seq === b.seq && ns.manifestHash === hash && ns.manifestSeq === b.seq) return this.answer(b.namespace, m, b.seq);
    if (b.seq !== ns.seq + 1) return refuse(409, "conflict", `seq ${b.seq}, expected ${ns.seq + 1}`);
    if (ns.manifestHash === hash) {
      for (const [k, p] of this.packages) {
        if (k.startsWith(`${b.namespace}/`)) Object.assign(p, { disabled: false, seq: b.seq });
      }
      Object.assign(ns, { seq: b.seq, manifestSeq: b.seq });
      return this.answer(b.namespace, m, b.seq);
    }
    if (ns.manifest.queue !== undefined || m.queue !== undefined) {
      return refuse(400, "bad_request", `field \`manifest\`: namespace ${b.namespace} holds contract manifest ${ns.manifestHash}; a tip namespace's contract manifest is fixed`);
    }
    this.store(b.namespace, m, hash, b.seq, ns.owner);
    return this.answer(b.namespace, m, b.seq);
  }

  async disable(text: string): Promise<Reply> {
    const b = JSON.parse(text);
    if (!(await verifySignature(await disableMessage(b), b.owner_pubkey, b.signature))) return refuse(403, "forbidden", "bad signature");
    const pkg = this.packages.get(`${b.namespace}/${b.circuit}`);
    if (b.seq === 0) return refuse(409, "conflict", "a DISABLE never carries seq 0");
    const ns = this.namespaces.get(b.namespace);
    const sameOwner = ns !== undefined && ns.owner.x === b.owner_pubkey.x && ns.owner.y === b.owner_pubkey.y;
    if (ns === undefined || !sameOwner) return refuse(403, "forbidden", "not signed by the namespace owner");
    const resent = pkg !== undefined && pkg.disabled && pkg.seq === b.seq;
    if (!resent) {
      if (b.seq !== ns.seq + 1) return refuse(409, "conflict", `seq ${b.seq}, expected ${ns.seq + 1}`);
      if (pkg === undefined) return refuse(404, "not_found", `circuit ${b.circuit} is not registered`);
      ns.seq = b.seq;
      pkg.disabled = true;
      pkg.seq = b.seq;
    }
    const p = pkg!;
    return {
      status: 200,
      body: {
        namespace: b.namespace,
        circuit: b.circuit,
        vk_hash: p.vk_hash,
        npk_app_hash: this.npkAppHash,
        disabled: true,
        seq: p.seq,
        signatures: await this.signAll((i) => registryMessage(b.namespace, b.circuit, p.vk_hash, this.npkAppHash, p.seq, true, i)),
      },
    };
  }

  namespace(path: string): Reply {
    const manifest = path.endsWith("/manifest");
    const ns = manifest ? path.slice(0, -"/manifest".length) : path;
    const row = this.namespaces.get(ns);
    if (row === undefined) return refuse(404, "not_found", `no namespace ${ns}`);
    if (manifest) return { status: 200, body: { namespace: ns, manifest_hash: row.manifestHash, seq: row.manifestSeq, manifest: row.manifest } };
    return { status: 200, body: { namespace: ns, owner_pubkey: row.owner, seq: row.seq, npk_app_hash: this.npkAppHash, manifest_hash: row.manifestHash } };
  }
}
