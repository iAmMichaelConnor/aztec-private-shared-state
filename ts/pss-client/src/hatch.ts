// The escape hatch, the client side (pss_core tip/exit.nr, pss_public_contract
// hatch.nr; docs/ARCHITECTURE.md section 6, "The escape hatch"): how the
// owner of an entry of a tree-valued key leaves a frozen app on its newest
// note, privately and with no node.
//
// Every round that writes an entry stores in its leaf the exit tag of the
// note it issues for the entry,
//
//   exitTag(P, requestId, entry) = poseidon2([PSS_EXIT_TAG + 2^128 * entry, P, requestId])
//
// P the note's partial commitment (partialCommitment(owner, rho): the
// request's rho, or a delivery handle's), and its landing emits the tag of
// the note it replaces as a nullifier of the app. So the one unspent tag of
// an entry is its newest note's: an owner's client finds that note by
// looking its notes' tags up in the nullifier tree (liveExitNote), and the
// app's private `exit` pushes it once. A spent tag also tells the owner that
// a round it did not request wrote its entry (lending's liquidation): the
// transaction that spent it is that round's landing (exitTagSpender: the
// nullifier tree names the block by number and hash, and that block's body
// holds the transaction with the nullifier), and its private logs hold the
// round's delivery to the owner's handle, which carries the round's request
// id (handle.ts DeliveryReader.readIn). The node needs no old state for
// this: the nullifier tree's latest state names the block, and the block's
// body is the archiver's. recoverExitNote is that walk: from the owner's
// newest note of an entry, while its tag is spent by a round that delivered
// to the entry's handle, take that delivery (a notice) as the newest note
// and go on, to the note an exit takes or to a tag spent with no delivery
// (the owner's own exit, or a round of the owner's whose note this client
// does not hold). hatchReady is the keeper-side check: whether the app's
// public hatch state lets `open_hatch()` land now.

import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import type { BlockHash, BlockParameter } from "@aztec-labs/stdlib/block";
import { siloNullifier } from "@aztec-labs/stdlib/hash";
import { MerkleTreeId } from "@aztec-labs/stdlib/trees";

import type { PrivateLogNode, TxEffects } from "./discovery.ts";
import { ProtocolError } from "./errors.ts";
import { fieldAddress, fieldBigInt, hashFields, type FieldLike } from "./field.ts";
import { DeliveryReader, type DeliveryKeys, type FoundDelivery } from "./handle.ts";
import { asciiLabel } from "./labels.ts";
import { partialCommitment } from "./outcome.ts";

/** ASCII "pss.exit_tag" read big-endian: an exit tag's domain (pss_core
 * tip/exit.nr PSS_EXIT_TAG). */
export const PSS_EXIT_TAG = asciiLabel("pss.exit_tag");
/** ASCII "pss.exit_filler": a filler's domain (pss_core tip/exit.nr
 * PSS_EXIT_FILLER), the output of a round's slot that spends no tag. */
export const PSS_EXIT_FILLER = asciiLabel("pss.exit_filler");

const TWO_POW_128 = 1n << 128n;

/** A tag's or a filler's hash: `poseidon2([domain + 2^128 * at, partial,
 * requestId])`. */
async function exitHash(domain: bigint, at: bigint, partial: FieldLike, requestId: FieldLike): Promise<Fr> {
  if (at < 0n || at >> 120n !== 0n) throw new RangeError("an entry or a filler's place is below 2^120");
  return new Fr(await hashFields([domain + TWO_POW_128 * at, fieldBigInt(partial, "partial"), fieldBigInt(requestId, "request_id")]));
}

/** The exit tag of the note completing `partial` in the round of chain
 * request `requestId`, naming entry `entry` (a leaf index). */
export function exitTag(partial: FieldLike, requestId: FieldLike, entry: FieldLike): Promise<Fr> {
  return exitHash(PSS_EXIT_TAG, fieldBigInt(entry, "entry"), partial, requestId);
}

/** The `j`-th filler of a round of chain request `requestId` whose
 * requester's partial commitment is `partial` (the vectors' check of the
 * circuit's; no client needs it). */
export function exitFiller(partial: FieldLike, requestId: FieldLike, j: number): Promise<Fr> {
  if (!Number.isSafeInteger(j) || j < 0) throw new RangeError("j: a non-negative integer");
  return exitHash(PSS_EXIT_FILLER, BigInt(j), partial, requestId);
}

/** What the client keeps of each note that names an entry. */
export interface ExitNote {
  /** The note's owner (an account of the client's). */
  owner: FieldLike | AztecAddress;
  /** The note's randomness: its request's rho, or the delivery handle's. */
  rho: FieldLike;
  /** The chain request id of the round that issued it. */
  requestId: FieldLike;
  /** The entry it names (lending's position). */
  entry: FieldLike;
}

/** The exit tag of `note`: the nullifier its exit pushes. */
export async function exitTagOf(note: ExitNote): Promise<Fr> {
  return exitTag(await partialCommitment(note.owner, note.rho), note.requestId, note.entry);
}

/** The node call that looks nullifiers up (aztec.js AztecNode
 * `findLeavesIndexes` on the nullifier tree). */
export interface NullifierNode {
  findLeavesIndexes(referenceBlock: BlockParameter, treeId: MerkleTreeId, leafValues: Fr[]): Promise<({ l2BlockNumber: number | bigint } | undefined)[]>;
}

// Where the tag lookups read. Every party follows the proposed chain
// (docs/ARCHITECTURE.md section 6, "Following the chain"), so they read the
// nullifier tree at the proposed tip by default ("proposed"; v6's "latest"
// is an alias of it). A tag spent in a proposed block reads as spent until
// a replacement drops that block, and reads as unspent again after; a
// caller that must know a tag is spent for good passes a deeper block
// (`checkpointed`, `proven`, `finalized`, or a block number or hash).

/** `tag` as a nullifier of the app `app` (siloed with its address), and
 * the nullifier tree's entry for it as of block `at`; undefined while it is
 * unspent there. */
async function spentTag<F>(
  node: { findLeavesIndexes(referenceBlock: BlockParameter, treeId: MerkleTreeId, leafValues: Fr[]): Promise<(F | undefined)[]> },
  app: FieldLike | AztecAddress,
  tag: FieldLike,
  at: BlockParameter,
): Promise<{ siloed: Fr; found: F | undefined }> {
  const siloed = await siloNullifier(fieldAddress(app, "app"), new Fr(fieldBigInt(tag, "tag")));
  const [found] = await node.findLeavesIndexes(at, MerkleTreeId.NULLIFIER_TREE, [siloed]);
  return { siloed, found };
}

/** The block `tag` was spent in, as a nullifier of the app `app` (siloed
 * with its address), as of block `at` (default the proposed tip); undefined
 * while it is unspent there. */
export async function exitTagSpentAt(node: NullifierNode, app: FieldLike | AztecAddress, tag: FieldLike, at: BlockParameter = "proposed"): Promise<number | undefined> {
  const { found } = await spentTag(node, app, tag, at);
  return found === undefined ? undefined : Number(found.l2BlockNumber);
}

/** The node calls exitTagSpender makes (an aztec.js AztecNode is one): the
 * nullifier lookup, which also names the block a nullifier went in by its
 * hash, and a block's transactions by its hash. */
export interface SpenderNode extends NullifierNode {
  findLeavesIndexes(
    referenceBlock: BlockParameter,
    treeId: MerkleTreeId,
    leafValues: Fr[],
  ): Promise<({ l2BlockNumber: number | bigint; l2BlockHash: BlockHash } | undefined)[]>;
  getBlock(block: BlockHash, options: { includeTransactions: true }): Promise<{ body: { txEffects: TxEffects[] } } | undefined>;
}

/** The transaction that spent `tag` as a nullifier of the app `app`, with
 * its block's number; undefined while the tag is unspent as of block `at`
 * (default the proposed tip). The block is read
 * by the hash the nullifier tree names, so a block that a replacement took
 * off the chain since is never read in its place. An Error when the node
 * does not serve that block (replaced between the two calls: ask again) or
 * no transaction of it holds the nullifier. */
export async function exitTagSpender(
  node: SpenderNode,
  app: FieldLike | AztecAddress,
  tag: FieldLike,
  at: BlockParameter = "proposed",
): Promise<{ block: number; tx: TxEffects } | undefined> {
  const { siloed, found } = await spentTag(node, app, tag, at);
  if (found === undefined) return undefined;
  const block = Number(found.l2BlockNumber);
  const response = await node.getBlock(found.l2BlockHash, { includeTransactions: true });
  if (response === undefined) throw new Error(`the node names block ${block} (${found.l2BlockHash}) for nullifier ${siloed} and does not serve it`);
  const tx = response.body.txEffects.find((t) => t.nullifiers.some((n) => n.equals(siloed)));
  if (tx === undefined) throw new Error(`no transaction of block ${block} (${found.l2BlockHash}) holds nullifier ${siloed}`);
  return { block, tx };
}

/** The first of `notes`, the owner's notes of one entry newest first, whose
 * exit tag is unspent as of block `at` (default the proposed tip): the note
 * an exit takes. Undefined when every tag is spent, which on a live app
 * means a round the owner did not request wrote the entry since its newest
 * note (lending: a liquidation, whose notice is the newest note;
 * recoverExitNote finds it). */
export async function liveExitNote<N extends ExitNote>(
  node: NullifierNode,
  app: FieldLike | AztecAddress,
  notes: readonly N[],
  at: BlockParameter = "proposed",
): Promise<N | undefined> {
  for (const note of notes) {
    if ((await exitTagSpentAt(node, app, await exitTagOf(note), at)) === undefined) return note;
  }
  return undefined;
}

/** How many notices one recoverExitNote walk follows at most. */
export const MAX_RECOVERED_NOTICES = 16;

/** What recoverExitNote walks from. */
export interface RecoverOptions {
  /** The node (an aztec.js AztecNode is one). */
  node: SpenderNode & PrivateLogNode;
  /** The app's address. */
  app: FieldLike | AztecAddress;
  /** The owner's newest note of the entry this client holds. */
  note: ExitNote;
  /** The keys of the delivery handle the entry holds after that note's
   * round; none when it holds none (lending's lender positions). */
  handle?: DeliveryKeys;
  /** The plaintext field of a delivered note that names its entry
   * (lending's position): each notice must name `note.entry`
   * (ProtocolError otherwise). */
  entryField?: number;
  /** Called with each notice, oldest first, and the note it is, before the
   * walk goes on from it: the app hands it to the owner's PXE (its
   * outcome-note utility, discovery.ts outcomeDeliveryArgs) and keeps it. */
  onNotice?: (found: FoundDelivery, note: ExitNote) => Promise<void>;
  /** Default MAX_RECOVERED_NOTICES. */
  maxNotices?: number;
  /** The block the tags are read at (exitTagSpender); default the proposed
   * tip. */
  at?: BlockParameter;
}

/** Where a recoverExitNote walk ended: `notices` are the deliveries it
 * followed, oldest first, and `note` the newest note it reached.
 *
 * - `live`: `note`'s tag is unspent; an exit takes it.
 * - `spent-by-owner`: `note`'s tag was spent by `spent.tx`, which holds no
 *   delivery to the entry's handle (or the entry holds none). Only the owner
 *   writes such an entry: by its own exit on `note` (nothing is left to
 *   exit), or by a round it requested whose note this client does not hold
 *   (a restored wallet: read that note with the owner's outcome reader and
 *   walk again from it). While the app's hatch is not open it is the round.
 */
export type ExitRecovery =
  | { status: "live"; note: ExitNote; notices: FoundDelivery[] }
  | { status: "spent-by-owner"; note: ExitNote; notices: FoundDelivery[]; spent: { block: number; tx: TxEffects } };

/** The owner's recovery of the notices of rounds it did not request, from
 * the chain alone (module comment): while the tag of the newest note is
 * spent, read the delivery to the entry's handle in the transaction that
 * spent it (exitTagSpender, DeliveryReader.readIn); the notice, under the
 * handle's randomness and the delivering round's request id, is the newest
 * note from then on. RangeError past `maxNotices` notices; what the node
 * calls and readIn throw. */
export async function recoverExitNote(o: RecoverOptions): Promise<ExitRecovery> {
  const { handle } = o;
  const reader = new DeliveryReader(o.node, o.app);
  const max = o.maxNotices ?? MAX_RECOVERED_NOTICES;
  const entry = fieldBigInt(o.note.entry, "entry");
  const notices: FoundDelivery[] = [];
  let note = o.note;
  for (;;) {
    const spent = await exitTagSpender(o.node, o.app, await exitTagOf(note), o.at);
    if (spent === undefined) return { status: "live", note, notices };
    const found = handle && (await reader.readIn(handle, spent.tx));
    if (handle === undefined || found === undefined) return { status: "spent-by-owner", note, notices, spent };
    if (notices.length >= max) throw new RangeError(`more than ${max} notices in a row on entry ${entry}`);
    if (o.entryField !== undefined && found.plaintext[o.entryField] !== entry) {
      throw new ProtocolError(`the notice of request ${found.requestId} names entry ${found.plaintext[o.entryField]}, not ${entry}`);
    }
    const next: ExitNote = { owner: note.owner, rho: handle.handleRho, requestId: found.requestId, entry: note.entry };
    await o.onNotice?.(found, next);
    notices.push(found);
    note = next;
  }
}

/** The contract's public hatch state the trigger reads. */
export interface HatchState {
  open: boolean;
  /** HatchState::starving_since: the block from which the app has had
   * demand (a queued request or a `poke()`) and no landed round; 0 when not
   * starving */
  starvingSince: number;
  /** Config::t_live */
  tLive: number;
  /** the block a call made now lands in */
  block: number;
}

/** Whether `open_hatch()` lands at `state.block` (the contract's rule: the
 * app has starved for T_LIVE blocks; a landed round stops or restarts the
 * clock, `skip()` never touches it), and if not why, with the blocks left
 * when only time is missing. A mirror of pss_public_contract hatch.nr
 * `Hatch::open`, kept by hand: no vector pins it. A keeper that finds the clock stopped on an
 * app it suspects frozen calls `poke()` (anyone may, an empty queue
 * included) and `open_hatch()` once it is `openable`; an owner exits once
 * it is `open`. */
export function hatchReady(state: HatchState): { open: boolean; openable: boolean; reason?: string; blocksLeft?: number } {
  if (state.open) return { open: true, openable: false, reason: "the hatch is open" };
  if (state.starvingSince === 0) return { open: false, openable: false, reason: "the app is not starving (no demand since the last round; anyone may poke())" };
  const at = state.starvingSince + state.tLive;
  if (state.block >= at) return { open: false, openable: true };
  return { open: false, openable: false, reason: "the app has starved for under T_LIVE blocks", blocksLeft: at - state.block };
}
