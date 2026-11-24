//! The secret-shared intakes' request side (docs/ARCHITECTURE.md section 6,
//! "Secret-shared intake"): the inputs commitment `C`, the secret-shared chain request id
//! and secret-shared receipt intake's private request function body. The result
//! side is the `outcome` brick (private outcomes); the round circuit computes
//! the same `C` and id with pss_core's `tip::intake::commit` and `shared`.
//!
//! ```text
//! C                 = poseidon2([v_1, …, v_m, blinding])
//! chain_request_id  = poseidon2([namespace, vk_hash, C])
//! S_j               = poseidon2([SUMMANDS_DOMAIN, s_j…, salt_j])        j = 0, 1, 2
//! D                 = poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds…, clear values…])
//! receipt message   = poseidon2([RECEIPT_DOMAIN, chain_request_id, C, expiry_block, D])
//! ```
//!
//! `v_1 … v_m` are the values of every app input (clear or INPUT_SHARED) and
//! of the reserved `$partial_note` (the request's partial note,
//! `crate::partial_note::commit`), `$outcome_key` and `$outcome_tag`, in the
//! order the round's ABI walk first meets each (pss-client `IntakeLayout.commitment`,
//! sidecar-tip `commitment_names`), and `blinding` is the request's
//! `$blinding`, drawn uniformly by the client. The id names no requester and
//! has no nonce: the blinding makes it unique and hides the inputs.
//!
//! Secret-shared receipt intake (`intake: shared_receipt`). The client splits
//! the shared values (every value of C's the round's `Layout` marks CHOSEN,
//! in C's order) and the blinding into three Rep3 summand vectors `s_0 + s_1
//! + s_2`, draws a salt per vector (`Sharing`) and sends each node `C`, the
//! three summand commitments `S_j`, `D`, the clear values and its
//! envelopes: node i's opens to `s_i`, `s_{i-1}` and their salts. `D`
//! covers the `S_j`, the kind of each of C's values and the clear values
//! (pss_core's `sharing_digest`). Each node checks alone that its two
//! vectors hash to their `S_j` and that `D` is the digest of the `S_j`, the
//! layout it derives from the round's manifest and the clear values it
//! stores, then stores them with the envelopes and signs the receipt
//! message over `C` and `D` without seeing a shared value. Each `S_j` is
//! checked by both nodes that hold `s_j`, so the three nodes hold one
//! sharing and one set of clear values. The app's private request function
//! then calls `outcome_request` with the plaintext values and a
//! `SharedReceiptArgs` (the sharing, the expiry block and the receipts),
//! which commits the sender's partial note and runs `shared_receipt_request`:
//! it asserts that the summands add up to C's shared values and
//! blinding and checks the receipts over the `D` it computes from its
//! layout and C's clear values: a request whose shares or clear values do
//! not open `C` is never queued. It enqueues the app's one
//! `#[only_self]` request wrapper with the request id and the expiry
//! block, the wrapper receipt intake enqueues too, whose body is
//! `Queue::append_before`:
//!
//! ```noir
//! #[external("private")]
//! fn swap(swap: [Field; 3], rho: Field, outcome_key: Field, outcome_tag: Field, sharing: Sharing<7>,
//!     expiry_block: u32, receipts: [Receipt; 3]) {
//!     let round = rounds(self.internal.configured_in_force(), self.storage.pool).swap;
//!     let r: ReceiptRequest = outcome_request(self.context, round, self.msg_sender(), swap,
//!         SWAP_SHARED_LAYOUT, SharedReceiptArgs { rho, outcome_key, outcome_tag, sharing, expiry_block,
//!         receipts }, valid_swap);
//!     self.enqueue_self.append_receipt(r.request_id, r.expiry_block);
//! }
//!
//! #[external("public")]
//! #[only_self]
//! fn append_receipt(request_id: Field, expiry_block: u32) {
//!     let _ = self.storage.queue.append_before(request_id, expiry_block);
//! }
//! ```
//!
//! The row is the app's round table row (`crate::app`), the one
//! `onchain_request` and `receipt_request` take, so every request entry point
//! has one shape. Every round type of an app enqueues that one wrapper with
//! the same two arguments, so the public call tells neither the round type nor anything of
//! the inputs; the private functions behind it may differ per round type. The
//! function reads `msg_sender` only in private, into nothing public (an
//! owner-bound round's check of the note it opens); a call it
//! makes into another contract's public function goes through an incognito
//! enqueue (docs/ARCHITECTURE.md section 6, "The hidden requester").
use crate::app::TipRound;
use crate::config::NODES;
use crate::partial_note;
use crate::signing_keys::SigningKeys;
use crate::receipt::{check_epoch_receipts, Receipt, shared_receipt_message};
use aztec::context::PrivateContext;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::{Deserialize, Serialize, ToField};
/// The kind of each of C's values (CLEAR or CHOSEN), pss_core's: one
/// global per round, shared by both secret-shared intakes.
pub use pss_core::tip::derived::{CHOSEN, CLEAR, Layout};
use pss_core::tip::intake::{sharing_digest, summand_commitment};

/// The inputs commitment `C = poseidon2([values…, blinding])`, `values` in
/// the round's commitment order (the module docs): pss_core's
/// `tip::intake::commit`, the function the round circuits call. Total.
pub fn inputs_commitment<let M: u32>(values: [Field; M], blinding: Field) -> Field {
    pss_core::tip::intake::commit(values, blinding)
}

/// The secret-shared intakes' chain request id, `poseidon2([namespace, vk_hash, C])`,
/// with `namespace` the app contract's address: pss_core's
/// `tip::intake::shared` over the address as a field.
pub fn shared_chain_request_id(namespace: AztecAddress, vk_hash: Field, c: Field) -> Field {
    pss_core::tip::intake::shared(namespace.to_field(), vk_hash, c)
}

/// The values `C` commits to after the app inputs, in the round's order:
/// `$partial_note`,
/// `$outcome_key` and `$outcome_tag` (pss_core's `tip::intake::SharedIntake`);
/// the `$blinding` follows them.
pub(crate) global SHARED_TAIL: u32 = 3;

/// The app inputs among `C`'s values: the first `I`, before the shared tail
/// (`SHARED_TAIL`), the array the app's static-validity predicate takes.
pub fn app_inputs<let M: u32, let I: u32>(values: [Field; M]) -> [Field; I] {
    std::static_assert(
        I + SHARED_TAIL == M,
        "C's values are the app inputs, then $partial_note, $outcome_key and $outcome_tag",
    );
    let mut inputs = [0; I];
    for k in 0..I {
        inputs[k] = values[k];
    }
    inputs
}

/// A secret-shared receipt request's sharing, the request function's
/// private argument: three Rep3 summand vectors of L elements, one per
/// value the round's `Layout` marks CHOSEN (in C's order) and the
/// blinding's last, so `summands[0][k] + summands[1][k] + summands[2][k]`
/// is the k-th shared value, and the salt of each vector. Node i holds
/// `summands[i]` and `summands[i - 1]` with their salts, sealed to it.
#[derive(Deserialize, Eq, Serialize)]
pub struct Sharing<let L: u32> {
    pub summands: [[Field; L]; NODES],
    pub salts: [Field; NODES],
}

impl<let L: u32> Sharing<L> {
    /// The k-th shared value the three summand vectors add up to. Total.
    pub fn value(self, k: u32) -> Field {
        self.summands[0][k] + self.summands[1][k] + self.summands[2][k]
    }

    /// The sharing digest `D` over the three summand commitments, the
    /// `layout` and C's `clear` values (pss_core's `summand_commitment` and
    /// `sharing_digest`), the value every node's receipt signs. Total.
    pub fn digest<let M: u32, let Q: u32, let X: u32>(self, layout: Layout<M, Q, X>, clear: [Field; Q]) -> Field {
        let mut commitments = [0; NODES];
        for j in 0..NODES {
            commitments[j] = summand_commitment(self.summands[j], self.salts[j]);
        }
        sharing_digest(commitments, layout, clear)
    }
}

/// Assert that `sharing` opens C's values: the summands add up, in order, to
/// every value of `values` the `layout` marks CHOSEN, and their last
/// elements to the blinding, which it returns with the sharing digest `D`
/// over the summand commitments, the layout and the CLEAR values of
/// `values`. `values` are C's values in the round's commitment order. The
/// layout must be the one the machine derives from the round's manifest
/// (sidecar-tip `onchain_layout`: every shared value CHOSEN, every other
/// CLEAR), the one each node puts in the `D` it signs: under another layout
/// the `D` here is not the nodes', and the receipts do not verify.
pub fn opened_sharing<let M: u32, let Q: u32, let X: u32, let L: u32>(
    layout: Layout<M, Q, X>,
    values: [Field; M],
    sharing: Sharing<L>,
) -> (Field, Field) {
    std::static_assert(L == X + 1, "a sharing holds the X shared values, then the blinding");
    let (clear, chosen) = layout.split(values);
    for x in 0..X {
        assert_eq(sharing.value(x), chosen[x], "the summands do not add up to a shared value of C");
    }
    (sharing.value(X), sharing.digest(layout, clear))
}

/// The private half of secret-shared receipt intake: assert that `sharing`
/// opens the values under the round's `layout` (`opened_sharing`, which
/// gives the blinding and `D`), compute `C`, admit the request under
/// `round` (`TipRound::admit`: the vk pin and `is_valid` over the app
/// inputs) with the secret-shared chain request id over `C`, check the
/// three receipts over `shared_receipt_message(request_id, C, expiry_block,
/// D)` against the row's node `sig` keys, and return the request id for the
/// app's request wrapper, which enqueues it with `expiry_block`. A request
/// whose shares do not open `C`, or whose nodes signed other clear values
/// than C's, fails here and is never queued.
///
/// `values` are the plaintext values `C` commits to, the reserved
/// `$outcome_key` and `$outcome_tag` among them, in the round's commitment
/// order, and `sharing` the summand vectors and salts the nodes' envelopes
/// hold; all are private arguments, and none reaches the chain. `is_valid`
/// is the app's static-validity predicate over its app inputs
/// (`app_inputs`: the values before the shared tail), the one its
/// non-secret-shared intakes take; the tail is not checked (the partial
/// note is the request function's own commitment, and a key or tag the
/// user did not keep only loses it its own outcome). The nodes see only the
/// clear inputs, so this is the only place the shared inputs' static
/// validity is asserted before a round runs (the round's flags are the
/// backstop). `round` is the app's round table row (`crate::app`): the vk
/// pin and the stored `TipConfig` with the `sig` keys, built from the app's
/// stored `Configured`, never from an argument of the request function.
pub fn shared_receipt_request<C, K, let R: u32, let W: u32, let M: u32, let Q: u32, let X: u32, let L: u32, let I: u32, Env>(
    context: &mut PrivateContext,
    round: TipRound<C, R, W, K>,
    layout: Layout<M, Q, X>,
    values: [Field; M],
    sharing: Sharing<L>,
    expiry_block: u32,
    receipts: [Receipt; NODES],
    is_valid: fn[Env]([Field; I]) -> bool,
) -> Field
where
    K: SigningKeys,
{
    let (blinding, d) = opened_sharing(layout, values, sharing);
    let c = inputs_commitment(values, blinding);
    let request_id = round.admit(
        context,
        app_inputs(values),
        is_valid,
        |namespace, vk_hash| shared_chain_request_id(namespace, vk_hash, c),
    );
    check_epoch_receipts::<K>(
        context,
        round.tip.node_sig_keys,
        receipts,
        shared_receipt_message(request_id, c, expiry_block, d),
    );
    request_id
}

/// A request under a secret-shared intake as its request function hands it
/// to `outcome_request`, one implementation per intake, `T` what the app's
/// public request wrapper enqueues and `K` the round row's `node_keys` brick:
///
/// - `SharedReceiptArgs`: secret-shared receipt intake (the sharing, the
///   expiry block and the three receipts), `T` = `ReceiptRequest`;
/// - `shared_onchain::SharedOnchainArgs`: secret-shared on-chain intake (the
///   app's `SharedOnchain` storage slot and the ephemeral secret), `T` =
///   `shared_onchain::SharedOnchainRequest`, for a `K` that retires a
///   replaced node's `enc` key (`signing_keys::RetiresEncKeys`).
///
/// Both carry what every private outcome's request takes: `rho`, the
/// randomness of the sender's partial note, and the outcome key and tag.
/// The request function's arguments stay its own (its ABI); it builds the
/// value from them.
pub trait SharedRequest<T, K> {
    /// The randomness of the sender's partial note (`partial_note::commit`).
    fn rho(self) -> Field;

    /// The request's `$outcome_key` and `$outcome_tag`, C's last two values.
    fn outcome_key_tag(self) -> [Field; 2];

    /// The intake's private half over C's values `values` in the round's
    /// commitment order, shared as `layout` says: `shared_receipt_request`
    /// or `shared_onchain::shared_onchain_request`.
    fn request<C, let R: u32, let W: u32, let M: u32, let Q: u32, let X: u32, let I: u32, Env>(
        self,
        context: &mut PrivateContext,
        round: TipRound<C, R, W, K>,
        layout: Layout<M, Q, X>,
        values: [Field; M],
        is_valid: fn[Env]([Field; I]) -> bool,
    ) -> T;
}

/// What the app's receipt-intake wrapper enqueues (`Queue::append_receipt`):
/// the request id and the expiry block.
pub struct ReceiptRequest {
    pub request_id: Field,
    pub expiry_block: u32,
}

/// A secret-shared receipt intake request (`SharedRequest`): the partial
/// note's randomness, the outcome key and tag, the sharing the nodes hold,
/// the expiry block and the three receipts, all private arguments of the
/// request function.
pub struct SharedReceiptArgs<let L: u32> {
    pub rho: Field,
    pub outcome_key: Field,
    pub outcome_tag: Field,
    pub sharing: Sharing<L>,
    pub expiry_block: u32,
    pub receipts: [Receipt; NODES],
}

impl<K, let L: u32> SharedRequest<ReceiptRequest, K> for SharedReceiptArgs<L>
where
    K: SigningKeys,
{
    fn rho(self) -> Field {
        self.rho
    }

    fn outcome_key_tag(self) -> [Field; 2] {
        [self.outcome_key, self.outcome_tag]
    }

    fn request<C, let R: u32, let W: u32, let M: u32, let Q: u32, let X: u32, let I: u32, Env>(
        self,
        context: &mut PrivateContext,
        round: TipRound<C, R, W, K>,
        layout: Layout<M, Q, X>,
        values: [Field; M],
        is_valid: fn[Env]([Field; I]) -> bool,
    ) -> ReceiptRequest {
        let request_id = shared_receipt_request(
            context,
            round,
            layout,
            values,
            self.sharing,
            self.expiry_block,
            self.receipts,
            is_valid,
        );
        ReceiptRequest { request_id, expiry_block: self.expiry_block }
    }
}

/// The body of every request function of a round under private outcomes,
/// under either secret-shared intake (`request`, a `SharedRequest`): commit
/// the sender's partial note `P = partial_commitment(sender, rho)`
/// (`partial_note::commit`, its use nullifier pushed), so the round's
/// completed note is the sender's, then take C over the app inputs
/// `inputs`, then `P`, `$outcome_key` and `$outcome_tag` (`is_valid` over
/// `inputs`), shared as `layout` says (the kind of each of those values, in
/// that order: the round's generated layout global), through the intake's
/// private half. Returns what the app's public request wrapper enqueues.
pub fn outcome_request<C, K, T, I, let R: u32, let W: u32, let N: u32, let Q: u32, let X: u32, Env>(
    context: &mut PrivateContext,
    round: TipRound<C, R, W, K>,
    sender: AztecAddress,
    inputs: [Field; N],
    layout: Layout<N + SHARED_TAIL, Q, X>,
    request: I,
    is_valid: fn[Env]([Field; N]) -> bool,
) -> T
where
    K: SigningKeys,
    I: SharedRequest<T, K>,
{
    let partial = partial_note::commit(context, sender, request.rho());
    let tail = request.outcome_key_tag();
    request.request(context, round, layout, inputs.concat([partial, tail[0], tail[1]]), is_valid)
}

mod test {
    use super::{CHOSEN, CLEAR, inputs_commitment, Layout, opened_sharing, shared_chain_request_id, Sharing};
    use crate::intake::chain_request_id;
    use aztec::protocol::address::AztecAddress;
    use aztec::protocol::hash::poseidon2_hash;
    use pss_core::tip::intake::{sharing_digest, summand_commitment};

    /// `[clear 7, shared 25000, shared 0xbeef]`: one CLEAR value, two CHOSEN.
    global LAYOUT: Layout<3, 1, 2> = Layout { kinds: [CLEAR, CHOSEN, CHOSEN] };
    global VALUES: [Field; 3] = [7, 25000, 0xbeef];
    global BLINDING: Field = 0xb1;

    /// A Rep3 sharing of `[25000, 0xbeef, BLINDING]` with three salts.
    fn sharing() -> Sharing<3> {
        let s0 = [11, 22, 33];
        let s1 = [44, 55, 66];
        Sharing {
            summands: [s0, s1, [25000 - 11 - 44, 0xbeef - 22 - 55, BLINDING - 33 - 66]],
            salts: [0x5a0, 0x5a1, 0x5a2],
        }
    }

    // The shared id hashes three elements, so it is never a
    // non-secret-shared intake's id, which hashes four.
    #[test]
    fn the_shared_id_is_never_a_plain_id() {
        let ns = AztecAddress { inner: 0xc0ffee };
        assert(shared_chain_request_id(ns, 0x5a, 0x1c) != chain_request_id(ns, 0x5a, 0x1c, 0));
    }

    // A sharing whose summands add up to C's CHOSEN values and the blinding
    // opens: it gives the blinding and D over the three summand commitments,
    // the layout and C's clear value.
    #[test]
    fn a_sharing_that_adds_up_gives_the_blinding_and_the_digest() {
        let sh = sharing();
        let (blinding, d) = opened_sharing(LAYOUT, VALUES, sh);
        assert_eq(blinding, BLINDING);
        let commitments = [0, 1, 2].map(|j: u32| summand_commitment(sh.summands[j], sh.salts[j]));
        assert_eq(d, sharing_digest(commitments, LAYOUT, [7]));
        assert_eq(inputs_commitment(VALUES, blinding), poseidon2_hash([7, 25000, 0xbeef, BLINDING]));
        // another salt gives another D, the same blinding
        let mut salted = sh;
        salted.salts[2] = 0x5a3;
        let (b2, d2) = opened_sharing(LAYOUT, VALUES, salted);
        assert_eq(b2, BLINDING);
        assert(d2 != d);
    }

    // Summands that miss a shared value refuse the request in the user's own
    // proof: such shares never reach the queue.
    #[test(should_fail_with = "the summands do not add up to a shared value of C")]
    fn summands_that_miss_a_shared_value_are_refused() {
        let mut sh = sharing();
        sh.summands[1][1] += 1;
        let _ = opened_sharing(LAYOUT, VALUES, sh);
    }

    // The summands are matched to the CHOSEN values in C's order: the same
    // sharing against a value that changed is refused.
    #[test(should_fail_with = "the summands do not add up to a shared value of C")]
    fn a_changed_value_is_refused() {
        let _ = opened_sharing(LAYOUT, [7, 25001, 0xbeef], sharing());
    }
}
