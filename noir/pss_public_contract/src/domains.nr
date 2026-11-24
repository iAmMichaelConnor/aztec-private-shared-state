//! The domain constants of the tip contracts, named once: every tag and
//! every signed or hashed message the shared library builds starts from one
//! of these, and the machine (`sidecar-tip`), pss-client and pss-relayer use
//! the same values. A state module that logs keeps its log's tag separator
//! in its own module.

/// The separator of the on-chain request log's tag:
/// `compute_log_tag(request_id, REQUEST_DOMAIN)`, a u32 because aztec-nr's
/// `compute_log_tag` takes Aztec's u32 `DOM_SEP__` form. ASCII "psrq" read
/// big-endian. The chain reader asks the Aztec node for
/// `getPublicLogsByTags([compute_log_tag(request_id, REQUEST_DOMAIN)])`.
///
/// `REQUEST_DOMAIN = 0x70737271`: it only has to differ from
/// every other tag separator a namespace contract emits under (aztec-nr's
/// `DOM_SEP__` values, a state module's log tag) so a request log is never
/// mistaken for another log of the same contract; the chain reader also
/// keeps only logs whose AVM-set emitting address is the namespace. It is
/// part of the interface with the chain reader.
pub global REQUEST_DOMAIN: u32 = 0x70737271;

/// The first element of a receipt message, receipt intake's
/// `poseidon2([RECEIPT_DOMAIN, request_id, inputs_hash, expiry_block])`
/// (`receipt_message`) and secret-shared receipt intake's
/// `poseidon2([RECEIPT_DOMAIN, request_id, C, expiry_block, D])`
/// (`shared_receipt_message`, D the sharing digest):
/// ASCII "sidecar.receipt" read big-endian, in the style of the machine's
/// `RESULT_DOMAIN` ("sidecar.result") and `MANIFEST_DOMAIN`
/// ("sidecar.manifest").
///
/// `RECEIPT_DOMAIN = ASCII "sidecar.receipt"`: a node's `sig`
/// key signs results, registry answers and receipts; the distinct first
/// element keeps a receipt from ever verifying as a result or registry
/// signature and the other way round. Every node signs with it and every
/// tip contract checks it.
pub global RECEIPT_DOMAIN: Field = 0x736964656361722e72656365697074;

/// The first element of every manifest result message,
/// `poseidon2([MANIFEST_DOMAIN, namespace, manifest_hash, packages_hash,
/// npk_app_hash, seq, 0, i])`: ASCII "sidecar.manifest" read big-endian, the
/// machine's constant (machine/sidecar-core/src/registry/answers.rs
/// MANIFEST_DOMAIN), which every node signs its REGISTER answers under and
/// `configure` checks them with. Part of the interface with the machine: a
/// different value here refuses every answer. A DISABLE answer is signed
/// under the machine's own `REGISTRY_DOMAIN` ("sidecar.registry"), so it
/// never verifies here.
pub global MANIFEST_DOMAIN: Field = 0x736964656361722e6d616e6966657374;

/// The first element of every result message,
/// `poseidon2([RESULT_DOMAIN, namespace, request_id, new commitments…, i,
/// H(sealed_i)])`: ASCII "sidecar.result" read big-endian, the machine's
/// constant (machine/sidecar-core/src/pipeline/result.rs RESULT_DOMAIN), which
/// every node signs under. It is part of the interface with the machine and
/// has one right answer: a different value refuses every result. Defined
/// in pss_core (`tip::outputs`).
pub use pss_core::tip::outputs::RESULT_DOMAIN;

/// The machine request id's domain, `PSS_ATTEMPT` in
/// `poseidon2(PSS_ATTEMPT, chain_request_id, old commitments…, pinned
/// values…)` (docs/ARCHITECTURE.md section 1): the round circuits' own
/// constant (`pss_core::tip::outcome`), ASCII "sidecar.attempt". The
/// scheduler (sidecar-tip, `ids::PSS_ATTEMPT`) derives the same id, and the
/// nodes sign results under it, so the three must agree; a different value
/// refuses every result here.
pub use pss_core::tip::outcome::PSS_ATTEMPT;

/// The first element of a node's `enc` rotation message,
/// `poseidon2([PSS_ENC_ROTATE, namespace, i, pk.x, pk.y, epoch])`
/// (`shared_onchain::enc_rotation_message`): ASCII "pss.enc_rotate" read
/// big-endian. A node's `sig` key signs results, registry answers, receipts
/// and rotations; the distinct first element keeps a rotation from ever
/// verifying as another message. The node (sidecar-tip's
/// `enc_rotation_message`) signs under it, so it is part of the interface
/// with the machine.
pub global PSS_ENC_ROTATE: Field = 0x7073732e656e635f726f74617465;

/// The first element of a key-set rotation message,
/// `poseidon2([PSS_ROTATE_KEYS, namespace, epoch, H(keys)])`
/// (`key_epoch::rotation_message`): ASCII "pss.rotate_keys" read big-endian.
/// Two of the three current nodes sign it (sidecar-core's
/// `epoch::rotation_message`), so it is part of the interface with the
/// machine; the distinct first element keeps a rotation from verifying as
/// any other node message.
pub global PSS_ROTATE_KEYS: Field = 0x7073732e726f746174655f6b657973;
