//! TXE tests for the CreditsTip contract: what the library's suites do not
//! already prove for this app, the credits ledger's own wiring. The init
//! round creating the empty keyed map; a pay round inserting the key and
//! completing the payer's note; the owner's claim and move, an absent view,
//! and a pay to a field on a known key's path that leaves the key free
//! (test_rounds.nr); and one refusal per app rule (test_refusals.nr).
//! The queue, the receipts, the result signatures, the key epochs,
//! `configure` and `skip()` are the library's, proven by
//! pss_public_contract_test and the AMM and lending suites over the same
//! bodies.
//!
//! Every round is computed by the circuits' own entries (credits_tip's
//! `shared::pay`, `claim`, `view` and `move_credit`, which a main stores),
//! at the deployed namespace and ledger key, so the commitments, the
//! completed note hash and the ciphertext the contract lands are the ones
//! the round circuit outputs. The nodes' oblivious reads of a slot (its leaf,
//! old hash and siblings) come from pss_core's clear model of the map
//! (`Ledger`), which follows every landed round's stored leaves.
//!
//! The proofs: recursive proof verification is a no-op during TXE witness
//! execution, so the staged capsule carries a dummy vk whose hash the Config
//! pins and a zero proof; the vk pin in front of the verification runs for
//! real, and so does everything after it. The signatures are real (the test
//! network of pss_tip_test).
mod test_refusals;
mod test_rounds;

use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash;
use aztec::protocol::traits::ToField;
use aztec::test::helpers::test_environment::TestEnvironment;
use aztec::test::helpers::txe_oracles;
use credits_circuit::ledger::{DEPTH, LEAF_LEN, OUTCOME_FIELDS};
use credits_circuit::shared::{self, KeyedRound, OUTCOME_SLOT, Prefix, Shared, Slots};
use credits_tip::CreditsTip;
use credits_tip::app::{
    Config, CREDITS_PACKAGES, CreditNotes, CreditsResult, Keys, map_key, own_map_key,
    PACKAGES, ROUND_CLAIM, ROUND_MOVE, ROUND_PAY, ROUND_VIEW,
};
use credits_tip::layouts::{CLAIM_LAYOUT, MOVE_LAYOUT, PAY_LAYOUT, VIEW_LAYOUT};
use pss_core::test_support::keyed_map::ClearMap;
use pss_core::tip::intake::SharedIntake;
use pss_core::tip::tree::{commitment, empty_root};
use pss_public_contract::{FixedCircuits, inputs_commitment, Layout, Receipt, shared_chain_request_id, Sharing, StaleBlocks};
use pss_public_contract::init::init_request_id;
use pss_public_contract::partial_note::partial_commitment;
use pss_public_contract::result::{NodeHeld, Sealing};
pub use pss_tip_test::last_tx;
use pss_tip_test::{configure_answer, result_signatures, tip_pins};
use pss_tip_test::outcome::{open_outcome_log, outcome_result, outcome_signatures};
use pss_tip_test::queue::QueueReader;
use pss_tip_test::sharing::{shared_receipts, sharing_of};

/// The stale period the tests deploy with.
pub global STALE: u32 = 4;
/// The network identity `configure` pins (a stand-in: no proof is checked).
pub global NPK_APP_HASH: Field = 0x9b9b;
/// The nodes' app nullifier key the rounds use.
pub global NSK_APP: Field = 777;
/// Every requester's outcome key and tag in the suite.
pub global OUTCOME_KEY: Field = 0x6b6b;
pub global OUTCOME_TAG: Field = 0x7a7a;

// one dummy vk per circuit, so each pin is tested against the others' proofs
pub unconstrained fn vk_of(round: u32) -> [Field; 115] {
    [5 + round as Field; 115]
}

pub unconstrained fn vk_hash_of(round: u32) -> Field {
    poseidon2_hash(vk_of(round))
}

pub struct Setup {
    pub env: TestEnvironment,
    pub deployer: AztecAddress,
    /// the payee of most tests: the owner of the handle `payee_handle(alice,
    /// secret)`
    pub alice: AztecAddress,
    /// the payer of most tests
    pub bob: AztecAddress,
    pub relayer: AztecAddress,
    pub app: AztecAddress,
    pub config: Config,
}

/// The test deployment's Config: the test network's keys, the short stale
/// period, the package list with one dummy vk hash per package.
pub unconstrained fn config() -> Config {
    let mut vk_hashes = [0; PACKAGES];
    for p in 0..PACKAGES {
        vk_hashes[p] = vk_hash_of(p);
    }
    Config { tip: tip_pins(StaleBlocks::after(STALE), CREDITS_PACKAGES, vk_hashes) }
}

/// Deploy and configure the contract with the network's answers; the ledger
/// is not initialised.
pub unconstrained fn deploy() -> Setup {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let alice = env.create_light_account();
    let bob = env.create_light_account();
    let relayer = env.create_light_account();
    let config = config();
    let app = env.deploy("../credits_tip@credits_tip/CreditsTip").with_public_initializer(
        deployer,
        CreditsTip::interface().constructor(config),
    );
    let s = Setup { env, deployer, alice, bob, relayer, app, config };
    let answer = configure_answer(s.app, s.config.tip, NPK_APP_HASH);
    s.env.call_private(s.relayer, CreditsTip::at(s.app).configure(NPK_APP_HASH, answer));
    s
}

/// Deploy and land the init round (the empty map).
pub unconstrained fn setup() -> Setup {
    let s = deploy();
    init(s);
    s
}

impl Setup {
    /// The app's queue and ledger slot as the suite reads them (pss_tip_test
    /// `queue`).
    pub unconstrained fn queue(self) -> QueueReader<Config, 1, Field, Keys, FixedCircuits> {
        QueueReader::at(self.env, self.app)
    }

    /// The ledger key: the `ledger` slot's storage slot.
    pub unconstrained fn ledger_key(self) -> Field {
        self.queue().state().state_keys[0]
    }

    /// The ledger's current commitment.
    pub unconstrained fn ledger(self) -> Field {
        self.queue().commitment(0)
    }
}

/// Stage the (vk, proof) capsule the result and init functions load, under
/// the relayer as scope.
pub unconstrained fn stage_proof(s: Setup, vk: [Field; 115]) {
    pss_tip_test::stage_proof(s.env, s.app, s.relayer, vk);
}

// ---- init --------------------------------------------------------------------

/// The commitment of the empty map at the ledger key: what `credits_init`
/// outputs as `new_c` (its main's test checks the same equality).
pub unconstrained fn empty_ledger(s: Setup) -> Field {
    commitment(s.app.to_field(), s.ledger_key(), empty_root::<DEPTH>())
}

/// Land the init round leaving the empty map, signed for the empty slot.
pub unconstrained fn init(s: Setup) {
    let new_c = empty_ledger(s);
    let id = init_request_id(s.app, vk_hash_of(0), []);
    let sigs = result_signatures(s.app.to_field(), id, [0], [], [new_c], NodeHeld {}.sealed_hashes());
    stage_proof(s, vk_of(0));
    s.env.call_private(s.relayer, CreditsTip::at(s.app).init_ledger(new_c, sigs));
}

// ---- the nodes' map ------------------------------------------------------------

/// The most leaves a test's map holds.
pub global ENTRIES: u32 = 4;

/// The suite's clear model of the ledger: the leaves `[key, balance,
/// blinding]` the landed rounds stored (`after`); a slot's leaf, old hash
/// and siblings as the nodes' oblivious reads give them (`slots`).
pub type Ledger = ClearMap<ENTRIES, DEPTH, LEAF_LEN>;

/// The empty ledger at the deployment's namespace and ledger key.
pub unconstrained fn empty_map(s: Setup) -> Ledger {
    ClearMap::empty(s.app.to_field(), s.ledger_key())
}

// ---- requests ------------------------------------------------------------------

/// A request as the suite sends it: the requester, its round, the app inputs
/// (C's values before the partial note: `[key, amount]`, `[key]` or `[from,
/// to, amount]`, every key a map key as the request function computes it),
/// its `rho` and blinding.
pub struct Request<let I: u32> {
    pub sender: AztecAddress,
    pub round: u32,
    pub inputs: [Field; I],
    pub rho: Field,
    pub blinding: Field,
}

impl<let I: u32> Request<I> {
    /// The partial note the request commits: the sender's under `rho`.
    pub fn partial(self) -> Field {
        partial_commitment(self.sender, self.rho)
    }

    /// C's values: the app inputs, the partial note, the outcome key and tag.
    pub fn values(self) -> [Field; I + 3] {
        self.inputs.concat([self.partial(), OUTCOME_KEY, OUTCOME_TAG])
    }

    /// C over the values under the request's blinding.
    pub fn c(self) -> Field {
        inputs_commitment(self.values(), self.blinding)
    }

    /// The chain request id over C under the round's vk.
    pub unconstrained fn id(self, s: Setup) -> Field {
        shared_chain_request_id(s.app, vk_hash_of(self.round), self.c())
    }

    /// The request's sharing under its round's `layout` (`sharing_of`: C's
    /// values, then the blinding).
    pub unconstrained fn sharing<let Q: u32, let X: u32, let L: u32>(self, layout: Layout<I + 3, Q, X>) -> Sharing<L> {
        sharing_of(layout, self.values(), self.blinding)
    }

    /// The round's secret-shared intake as the nodes hold it.
    pub fn intake(self) -> SharedIntake {
        SharedIntake {
            inputs_hash: self.c(),
            partial: self.partial(),
            outcome_key: OUTCOME_KEY,
            outcome_tag: OUTCOME_TAG,
            blinding: self.blinding,
        }
    }
}

/// The three nodes' receipts over the request and its `sharing`'s digest
/// under the round's `layout`, expiring ten blocks on, and the expiry block.
pub unconstrained fn receipts_for<let I: u32, let Q: u32, let X: u32, let L: u32>(
    s: Setup,
    r: Request<I>,
    layout: Layout<I + 3, Q, X>,
    sharing: Sharing<L>,
) -> ([Receipt; 3], u32) {
    let expiry = s.env.next_block_number() + 10;
    (shared_receipts(r.id(s), r.c(), expiry, layout, r.values(), sharing), expiry)
}

/// `from` pays `amount` to the handle `handle` under `rho`; returns the
/// request, whose key is `map_key(handle)`.
pub unconstrained fn pay(s: Setup, from: AztecAddress, handle: Field, amount: Field, rho: Field) -> Request<2> {
    let r = Request { sender: from, round: ROUND_PAY, inputs: [map_key(handle), amount], rho, blinding: rho + 0xb1 };
    let sharing: Sharing<6> = r.sharing(PAY_LAYOUT);
    let (rs, expiry) = receipts_for(s, r, PAY_LAYOUT, sharing);
    s.env.call_private(
        from,
        CreditsTip::at(s.app).pay(handle, amount, rho, OUTCOME_KEY, OUTCOME_TAG, sharing, expiry, rs),
    );
    r
}

/// `owner` claims `amount` from its key under `secret`.
pub unconstrained fn claim(s: Setup, owner: AztecAddress, secret: Field, amount: Field, rho: Field) -> Request<2> {
    let r = Request { sender: owner, round: ROUND_CLAIM, inputs: [own_map_key(owner, secret), amount], rho, blinding: rho + 0xb1 };
    let sharing: Sharing<6> = r.sharing(CLAIM_LAYOUT);
    let (rs, expiry) = receipts_for(s, r, CLAIM_LAYOUT, sharing);
    s.env.call_private(
        owner,
        CreditsTip::at(s.app).claim(secret, amount, rho, OUTCOME_KEY, OUTCOME_TAG, sharing, expiry, rs),
    );
    r
}

/// `owner` looks its key under `secret` up.
pub unconstrained fn view(s: Setup, owner: AztecAddress, secret: Field, rho: Field) -> Request<1> {
    let r = Request { sender: owner, round: ROUND_VIEW, inputs: [own_map_key(owner, secret)], rho, blinding: rho + 0xb1 };
    let sharing: Sharing<5> = r.sharing(VIEW_LAYOUT);
    let (rs, expiry) = receipts_for(s, r, VIEW_LAYOUT, sharing);
    s.env.call_private(
        owner,
        CreditsTip::at(s.app).view_balance(secret, rho, OUTCOME_KEY, OUTCOME_TAG, sharing, expiry, rs),
    );
    r
}

/// `owner` moves `amount` from its key under `secret` to the handle `to`.
pub unconstrained fn move_to(
    s: Setup,
    owner: AztecAddress,
    secret: Field,
    to: Field,
    amount: Field,
    rho: Field,
) -> Request<3> {
    let inputs = [own_map_key(owner, secret), map_key(to), amount];
    let r = Request { sender: owner, round: ROUND_MOVE, inputs, rho, blinding: rho + 0xb1 };
    let sharing: Sharing<7> = r.sharing(MOVE_LAYOUT);
    let (rs, expiry) = receipts_for(s, r, MOVE_LAYOUT, sharing);
    s.env.call_private(
        owner,
        CreditsTip::at(s.app).move_credit(secret, to, amount, rho, OUTCOME_KEY, OUTCOME_TAG, sharing, expiry, rs),
    );
    r
}

// ---- rounds ----------------------------------------------------------------------

/// Request `r`'s round's public prefix: the deployment's namespace, the
/// round's vk hash and the ledger key read and written.
unconstrained fn prefix<let I: u32>(s: Setup, r: Request<I>) -> Prefix {
    let key = s.ledger_key();
    Prefix { namespace: s.app.to_field(), vk_hash: vk_hash_of(r.round), in_slots: [key], out_slots: [key] }
}

/// The slots of `keys` on `ledger` as the round's three LOAD slices.
unconstrained fn slots<let K: u32>(ledger: Ledger, keys: [Field; K]) -> Slots<K> {
    let read = ledger.slots(keys);
    Slots { leaves: read.leaves, old_hashes: read.old_hashes, siblings: read.siblings }
}

/// The pay round the circuit computes for `r` on `ledger`, written with the
/// fresh blinding `r_new`.
pub unconstrained fn pay_round(s: Setup, ledger: Ledger, r: Request<2>, r_new: Field) -> KeyedRound<1> {
    pay_round_on(s, ledger, r, r.inputs, r_new)
}

/// The pay round for `r` when the shares the nodes hold carry `shares` in
/// place of the request's inputs (C still the request's).
pub unconstrained fn pay_round_on(s: Setup, ledger: Ledger, r: Request<2>, shares: [Field; 2], r_new: Field) -> KeyedRound<1> {
    shared::pay(prefix(s, r), r.intake(), shares, slots(ledger, [shares[0]]), [r_new], NSK_APP)
}

/// The claim round for `r` on `ledger`.
pub unconstrained fn claim_round(s: Setup, ledger: Ledger, r: Request<2>, r_new: Field) -> KeyedRound<1> {
    shared::claim(prefix(s, r), r.intake(), r.inputs, slots(ledger, [r.inputs[0]]), [r_new], NSK_APP)
}

/// The view round for `r` on `ledger`.
pub unconstrained fn view_round(s: Setup, ledger: Ledger, r: Request<1>, r_new: Field) -> KeyedRound<1> {
    shared::view(prefix(s, r), r.intake(), r.inputs, slots(ledger, r.inputs), [r_new], NSK_APP)
}

/// The move round for `r` on `ledger`.
pub unconstrained fn move_round(s: Setup, ledger: Ledger, r: Request<3>, r_new: [Field; 2]) -> KeyedRound<2> {
    shared::move_credit(prefix(s, r), r.intake(), r.inputs, slots(ledger, [r.inputs[0], r.inputs[1]]), r_new, NSK_APP)
}

/// The relayer lands the round's outputs as round `round` with the three
/// nodes' signatures, under the proof of `vk`.
pub unconstrained fn submit_as(s: Setup, round: u32, vk: [Field; 115], o: Shared) {
    let sigs = outcome_signatures(s.app.to_field(), o, [], NodeHeld {}.sealed_hashes());
    stage_proof(s, vk);
    let result: CreditsResult = outcome_result(o, []);
    s.env.call_private(s.relayer, CreditsTip::at(s.app).process_result(round, result, sigs));
}

/// The relayer lands request `r`'s round.
pub unconstrained fn submit<let I: u32>(s: Setup, r: Request<I>, o: Shared) {
    submit_as(s, r.round, vk_of(r.round), o);
}

// ---- outcomes ----------------------------------------------------------------------

/// Open the last transaction's outcome log as the requester does: `[code,
/// round, a, b]`.
pub unconstrained fn opened_outcome() -> [Field; OUTCOME_FIELDS] {
    let effects = txe_oracles::get_last_tx_effects();
    assert_eq(effects.private_logs.len(), 1);
    open_outcome_log(effects.private_logs.get(0), OUTCOME_KEY)
}

/// Deliver the last transaction's completed note to the requester's PXE as
/// its client does, and return the opened outcome.
pub unconstrained fn deliver<let I: u32>(s: Setup, r: Request<I>) -> [Field; OUTCOME_FIELDS] {
    let tx = last_tx();
    let outcome = opened_outcome();
    s.env.execute_utility(CreditsTip::at(s.app).deliver_outcome(r.sender, r.rho, outcome.concat([r.id(s)]), tx));
    outcome
}

/// The outcome notes `owner`'s PXE holds.
pub unconstrained fn notes_of(s: Setup, owner: AztecAddress) -> CreditNotes {
    s.env.execute_utility(CreditsTip::at(s.app).credit_notes(owner))
}

/// The outcome-note slot the rounds complete notes at, as the state view
/// reports it.
pub unconstrained fn outcome_slot(s: Setup) -> Field {
    let slot = s.queue().state().outcome_slot;
    assert_eq(slot, OUTCOME_SLOT);
    slot
}
