// pss-relayer: the operator-run relayer of the PSS sidecar at the tip of the
// chain (docs/ARCHITECTURE.md sections 1 and 6, row "relayer").
//
// It reads the app contract's queue (head, head_since, tail, requests[head])
// at one block, FETCHes the head's latest result by chain request id through
// pss-client, and lands it with the private result function of its circuit
// (process_result unless the configuration names another; a non-secret-shared intake's
// public outputs or a secret-shared intake's private outcome), which enqueues
// apply, re-fetching after a revert; it sends skip() exactly when the head is
// stale (head_since + stale_blocks has passed) and the queue is not empty.
// Before anything is queued it lands the init round the same way: FETCH by
// the init's fixed chain request id, the app's init function (which enqueues
// apply_init), nothing once a slot the init creates is written.
// The result transaction itself (FETCH, the binding checks, the arguments,
// the capsule) is pss-client's, shared with users who submit a result
// themselves; this package only drives it.
//
// - relayer.ts: the loop (Relayer, tick/start/stop) over interfaces, for tests
//   and drivers;
// - aztec.ts: createAztecRelayer, the loop on an aztec.js node, an embedded
//   wallet, the relayer's account, its fee setting (wFJ by default), the app
//   contract its PXE registers and the result function per circuit;
// - main.ts: the command line (a JSON configuration file) and the status
//   endpoint;
// - enc-key.ts: rotateEncKey, a node operator's signed rotation of its
//   node's enc key into each secret-shared on-chain intake contract, signed on the
//   node's admin socket and submitted through the same wallet path
//   (operatorWallet); rotate-enc-key.ts is its command line.
export * from "./relayer.ts";
export * from "./aztec.ts";
export * from "./enc-key.ts";
