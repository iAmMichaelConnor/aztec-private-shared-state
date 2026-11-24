//! The init round: the one round of a tip app that never enters the queue
//! (nobody requests it; it runs once the contract is configured). It
//! writes the first commitment of each key it creates, while the slot is
//! empty, and is checked as a result is: the vk pin, the proof over the
//! contract's namespace, keys and `npk_app_hash`, and the three result
//! signatures, under a request id fixed by the namespace, the init vk and
//! the init's inputs.
//!
//! An app writes two thin wrappers (examples/amm-tip's `init_pool` and
//! `apply_init`), over the init row of its round table (a `TipRound` that
//! reads no key and creates the keys the init writes):
//!
//! ```noir
//! #[external("private")]
//! fn init_pool(new_c: Field, signatures: [ResultSignature; 3]) {
//!     let round = rounds(self.storage.configured.read(), self.storage.pool).init;
//!     let request_id = process_init(round, self.context, self.msg_sender(), [], [new_c], [],
//!         NodeHeld {}, signatures);
//!     self.enqueue_self.apply_init(request_id, new_c);
//! }
//!
//! #[external("public")]
//! #[only_self]
//! fn apply_init(request_id: Field, new_c: Field) {
//!     let state_keys = rounds(self.storage.configured.read(), self.storage.pool).init.state_keys;
//!     init::apply_init(self.context, state_keys, request_id, [new_c], NodeHeld {});
//! }
//! ```
//!
//! The state mode is the `sealed` argument of both (`result::Sealing`):
//! `NodeHeld {}` for node-held state; under chain-held state the app passes
//! its sealed thirds (`crate::chain_state`) to both: the nodes' signatures
//! cover them and `apply_init` logs them as an apply does, so the chain
//! reader reads the first state the same way.
//!
//! How the never-queued init lands: through the app's init function,
//! outside the queue, open to anyone. The init round is never a
//! queue entry (nobody requests it; it runs once the contract is
//! configured), so it has its own entry point that checks everything
//! `process_result` checks for a queued round (the vk pin, the proof over
//! the contract's namespace, keys, the init request id over the inputs the
//! Config pins and `npk_app_hash`, the three signatures under the fixed init request id with
//! every old commitment 0) and an `apply_init` that writes only while each
//! slot is 0 (the circuit's `old_c = 0`), so a second init reverts. Open, not
//! operator-only: the only thing that lands here is a result the three
//! nodes signed for this namespace and these keys, which the network
//! produces only when the operator runs the round, and it lands once;
//! restricting the caller would add an operator address to the Config and
//! make the operator's own account a liveness dependency for no safety
//! gain. The alternatives are a first queued request (a queue entry nobody
//! requested, and a round circuit that must handle an empty slot) and a
//! REGISTER-time manifest flag (a machine change for one round). Its
//! manifest carries `intake: onchain` because a tip round takes a queued
//! intake; the contract never enqueues it.
use crate::app::{StateKeys, TipRound};
use crate::config::NODES;
use crate::configure::assert_deployed;
use crate::intake::{chain_request_id, inputs_hash};
use crate::result::{
    assert_epoch_signatures, machine_request_id, public_input_prefix, ResultSignature,
    Sealing, slot_keys,
};
use crate::signing_keys::SigningKeys;
use aztec::context::{PrivateContext, PublicContext};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::ToField;
use pss_contract::verify_pinned;

/// The chain request id of the init round: the chain request id of a
/// request of the init's `inputs` with nonce 0 under the init circuit's vk
/// hash: `chain_request_id(namespace, init_vk_hash, inputs_hash(inputs),
/// 0)`.
///
/// The init round's request id is fixed, not chosen. The nodes sign the init result, like every result,
/// under the machine request id `poseidon2(PSS_ATTEMPT, chain_request_id,
/// old commitments…)` with each empty slot's old commitment 0, and under
/// chain-held state the init logs its sealed thirds under
/// `compute_log_tag(init request id, PSS_STATE)`. A fixed id means the
/// operator's driver sends the init round with a request id it can
/// recompute, the machine's replay check runs that round at most once per
/// namespace, init vk and inputs (a lost answer is recovered by FETCH, not
/// by a second init), and the chain reader finds the state for the first
/// request (head 0 has no previous apply) under a tag it derives from the
/// namespace, the registered init vk hash and the inputs alone. No queued
/// request has this id: every queued request is under the vk hash of a
/// queued round, never the init's. The inputs are the init circuit's app
/// inputs, which its manifest fills by PUBLIC from the request
/// (examples/lending-tip's `liquidity`; none for examples/amm-tip), private
/// witnesses of the circuit, which outputs this id over them
/// (`pss_core::tip::intake::plain` with nonce 0), so the id covers the
/// values the app's Config pins.
pub fn init_request_id<let P: u32>(
    namespace: AztecAddress,
    init_vk_hash: Field,
    inputs: [Field; P],
) -> Field {
    chain_request_id(namespace, init_vk_hash, inputs_hash(inputs), 0)
}

/// The public-input array of an init circuit, rebuilt from what the
/// contract holds:
///
/// ```text
/// [namespace, vk_hash, out_slots[0..W], request_id, 0 (W times),
///  new_commitments[0..W], npk_app_hash, new_hashes[0..H]]
/// ```
///
/// The circuit declares `namespace`, `vk_hash` and `out_slots` as pub
/// parameters, takes its app inputs as private witnesses, and returns the
/// init request id over them, the empty slots' old commitments (0), the
/// new commitments and `npk_app_hash`: the public-input prefix of every tip
/// round (`crate::result::proved_public_inputs`, with no key read and no
/// pinned value) and the leading outputs of a round, without `ok` and app
/// outputs. A tree-valued key's init then returns the new leaf hashes it
/// writes (the manifest's `new_hashes`, from which the nodes build the
/// clear tree), H of them; an init of slot keys returns none (H = 0).
///
/// examples/amm-tip's `amm_init_tip` is this layout with W = 1, no inputs
/// and no new leaf hashes, examples/lending-tip's `lending_init` with W = 1,
/// one input (`liquidity`) and the tree header's leaf hash. Every init
/// circuit and this function must agree, or no init proof verifies; the
/// circuit side's `Init` has one old and one new commitment, so W is 1
/// (a static assertion: an init of two keys would compile here and never
/// verify).
pub fn init_public_inputs<let W: u32, let H: u32>(
    namespace: Field,
    vk_hash: Field,
    out_slots: [Field; W],
    request_id: Field,
    new_commitments: [Field; W],
    npk_app_hash: Field,
    new_hashes: [Field; H],
) -> [Field; 2 + W + 1 + W + W + 1 + H] {
    std::static_assert(W == 1, "an init round writes one key (pss_core tip::outputs::Init)");
    public_input_prefix(namespace, vk_hash, [], out_slots, [], request_id)
        .concat([0; W])
        .concat(new_commitments)
        .concat([npk_app_hash])
        .concat(new_hashes)
}

/// The body of the app's private init function: verify the init proof over
/// `init_public_inputs` (with the init request id of `inputs`) under the
/// init row's pinned vk and the three result
/// signatures over the new commitments, each node's message ending in its
/// `H(sealed_i)` from `sealed`, under the machine request id of the init
/// request id with every old commitment 0. Returns the init request id,
/// which the wrapper enqueues to its `apply_init`. `new_hashes` are the new
/// leaf hashes a tree-valued key's init outputs (`[]` for slot keys), the
/// tail of the init layout.
///
/// `round.state_keys.writes` are the slots the init creates (its manifest's
/// `$state_keys.writes`, in order); `inputs` its app inputs, from the app's
/// Config. Open to anyone: the only thing that lands is a result the three
/// nodes signed for this namespace, these keys and these inputs, and
/// `apply_init` lands it once.
pub fn process_init<C, S, K, let W: u32, let P: u32, let H: u32>(
    round: TipRound<C, 0, W, K>,
    context: &mut PrivateContext,
    scope: AztecAddress,
    inputs: [Field; P],
    new_commitments: [Field; W],
    new_hashes: [Field; H],
    sealed: S,
    signatures: [ResultSignature; NODES],
) -> Field
where
    S: Sealing,
    K: SigningKeys,
{
    assert_deployed(round.vk_hash);
    let this = context.this_address();
    let request_id = init_request_id(this, round.vk_hash, inputs);
    verify_pinned(
        context,
        scope,
        round.vk_hash,
        init_public_inputs(
            this.to_field(),
            round.vk_hash,
            slot_keys(round.state_keys.writes),
            request_id,
            new_commitments,
            round.tip.npk_app_hash,
            new_hashes,
        ),
    );
    assert_epoch_signatures::<K, W>(
        context,
        round.tip.node_sig_keys,
        this.to_field(),
        machine_request_id(request_id, [0; W], []),
        new_commitments,
        sealed.sealed_hashes(),
        signatures,
    );
    request_id
}

/// The body of the app's public `apply_init`: write each first commitment
/// while its slot is empty, so a second init reverts, then the state mode's
/// log (`Sealing::log`: nothing under node-held state; the sealed thirds
/// under the init request id under chain-held state, the payload an apply
/// logs).
/// Touches no queue storage. `state_keys` are the init row's (`row.state_keys`,
/// from the table whose row `process_init` took).
pub fn apply_init<S, let W: u32>(
    context: PublicContext,
    state_keys: StateKeys<PublicContext, 0, W>,
    request_id: Field,
    new_commitments: [Field; W],
    sealed: S,
)
where
    S: Sealing,
{
    let write_slots = state_keys.writes;
    for w in 0..W {
        assert_eq(write_slots[w].read(), 0, "already initialised");
        // a commitment of 0 would leave the slot looking empty; a real one
        // is a Poseidon2 output, so this never refuses an honest init
        assert(new_commitments[w] != 0, "zero commitment");
        write_slots[w].write(new_commitments[w]);
    }
    sealed.log(context, request_id, new_commitments);
}

mod test {
    use super::{init_public_inputs, init_request_id};
    use crate::intake::{chain_request_id, inputs_hash};
    use aztec::protocol::address::AztecAddress;

    // The init request id is the chain request id of the init inputs under
    // the init vk hash with nonce 0: it covers the inputs and the init vk.
    #[test]
    fn the_init_request_id_covers_the_inputs_and_the_init_vk() {
        let ns = AztecAddress { inner: 0xc0ffee };
        let id = init_request_id(ns, 0x8e, [1000]);
        assert_eq(id, chain_request_id(ns, 0x8e, inputs_hash([1000]), 0));
        assert(init_request_id(ns, 0x8e, [1001]) != id);
        assert(init_request_id(ns, 0x9e, [1000]) != id);
    }

    #[test]
    fn init_public_input_orders() {
        // examples/amm-tip amm_init_tip: [namespace, vk_hash, pool key,
        // request_id, old_c = 0, new_c, npk_app_hash]
        assert_eq(
            init_public_inputs(0xa0, 0x7e, [0x51], 0x1d, [0x1c], 0x9b, []),
            [0xa0, 0x7e, 0x51, 0x1d, 0, 0x1c, 0x9b],
        );
        // a tree init: the new leaf hashes after npk_app_hash
        assert_eq(
            init_public_inputs(0xa0, 0x7e, [0x52], 0x1d, [0x1c], 0x9b, [0x4a]),
            [0xa0, 0x7e, 0x52, 0x1d, 0, 0x1c, 0x9b, 0x4a],
        );
    }
}
