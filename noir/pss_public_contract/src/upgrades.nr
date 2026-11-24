//! The `upgrades` axis (docs/design-guide/README.md, "Upgrades"): where the
//! circuit pins a private function verifies under come from. One trait,
//! `CircuitsInForce`, with one implementation per brick:
//!
//! - `FixedCircuits` (`upgrades: fixed`): the constructor's pins in
//!   `Configured`, for the life of the contract. Nothing read, nothing
//!   stored, no upgrade function;
//! - `CircuitUpgrades` (`upgrades: circuits`): the constructor's pins until
//!   an upgrade authority the app names schedules others, which take effect
//!   after a delay. The pins live in aztec-nr's `DelayedPublicMutable`, a
//!   public value that private functions may read and whose writes wait out
//!   the delay; while it was never written it reads as zero, which means
//!   "the constructor's pins". The same brick under `upgrades: contract`,
//!   with one more wrapper the app writes over `upgrade_contract`: the
//!   authority can also move the instance to another contract class, and
//!   the class change and the new pins take effect together.
//!
//! The app names its brick once, where its private functions take their
//! round table rows from `Configured`. An app on `FixedCircuits` declares no
//! storage and no upgrade function and compiles none of this module's
//! upgrade code. An app on `CircuitUpgrades` declares the storage and one
//! public wrapper (examples/amm-tip):
//!
//! ```noir
//! #[storage]
//! struct Storage<Context> {
//!     configured: PublicImmutable<Configured<P>, Context>,
//!     ...
//!     // last, so no other slot moves
//!     circuit_upgrades: CircuitUpgrades<P, UPGRADE_DELAY, Context>,
//! }
//!
//! #[external("public")]
//! #[initializer]
//! fn constructor(config: Config, upgrade_authority: AztecAddress) {
//!     self.storage.config.initialize(config);
//!     self.storage.circuit_upgrades.init(upgrade_authority);
//! }
//!
//! #[external("private")]
//! fn process_result(round: SwapResult, signatures: [ResultSignature; 3]) {
//!     let tip = self.storage.circuit_upgrades.in_force(self.storage.configured.read());
//!     let checked = check_round(rounds(tip, self.storage.pool).swap, ...);
//!     ...
//! }
//!
//! #[external("public")]
//! fn upgrade_circuits(circuits: CircuitPins<P>) {
//!     self.storage.circuit_upgrades.upgrade_circuits(self.msg_sender(), circuits);
//! }
//!
//! // the class guard every round function enqueues (`in_force`)
//! #[external("public")]
//! #[only_self]
//! fn assert_upgrade_class(class_id: Field) {
//!     self.storage.circuit_upgrades.assert_class(class_id);
//! }
//!
//! // `upgrades: contract` only
//! #[external("public")]
//! fn upgrade_contract(new_class_id: Field, circuits: CircuitPins<P>) {
//!     self.storage.circuit_upgrades.upgrade_contract(self.msg_sender(), new_class_id, circuits);
//! }
//! ```
//!
//! Everything above the trait (the round table, `check_round`, the intake,
//! result and init bodies) is the same code for both bricks.
//!
//! The switch. A scheduled change carries its time of change `T`. A private
//! function reads the value at its anchor block, and the read caps the
//! transaction's expiration below `T` (aztec-nr's `get_current_value`), so a
//! transaction built under the old pins cannot be included once the new
//! ones are in force: a result proven under a replaced circuit lands before
//! `T` or not at all, and no grace logic is needed. The nodes switch at the
//! same point: each runs a round only under the contract manifest whose
//! hash the pins in force name, read on its own Aztec node.
//!
//! A class upgrade. The protocol's `ContractInstanceRegistry.update`
//! upgrades its caller, after the instance's own update delay (the
//! registry's `DelayedPublicMutable`, one day by default, at least 600 s);
//! from the change on, the instance's private functions are proven under
//! the new class (the private kernel checks the registry's entry at the
//! anchor block and caps the expiration below a pending change) and its
//! public functions run the new class's bytecode (the AVM reads the same
//! entry at the block's timestamp). The address, and so the namespace, the
//! storage and every node-held version, stay. `upgrade_contract` schedules
//! the class change and the new pins in one transaction and refuses unless
//! the two delays are equal, so both take effect at the same timestamp;
//! `upgrade_circuits` refuses while such a change is pending, since it
//! would replace the pins of the new class with pins of the old one.
//! Should they ever be out of step (another delay set in between), the
//! pins carry the class they belong to and every round function enqueues
//! `assert_upgrade_class`, which refuses a round whose pins belong to
//! another class than the one running: old code never runs with new pins,
//! nor new code with old pins, and the nodes run nothing either until the
//! class and the pins agree again. The new class must keep this storage at
//! the same slot and the same package capacity (the stored value's width),
//! and must never embed a contract manifest's hash: the manifest names the
//! class, so its hash arrives through the pins.
//!
//! A request queued under the old pins whose package's vk hash changed can
//! never be answered after `T`: its chain request id binds the vk hash, so
//! the new circuit computes another id and the old one is not pinned. It
//! goes the way of any head the network cannot answer: after the stale
//! period anyone may `skip()` it and the user asks again. An app that
//! escrows value at request time must refund on `skip()`; in an app that
//! moves nothing of value at request time (the AMM tip, the credits tip) a
//! skipped request costs its user only an unused request, so nothing is
//! owed. This is why REGISTER refuses an upgradable contract manifest whose
//! `stale_blocks` is null: one such request would block the queue for ever.
//!
//! Trust. Under `circuits` the upgrade authority can replace the rules by
//! which the shared state changes, so it can take whatever value the shared
//! state controls, in public and after the delay; it cannot change the
//! contract's code, the node keys or the stale period. Under `contract` it
//! can replace all of the contract's code after the delay, as for any
//! upgradable Aztec contract: every function, the escape hatch included,
//! and with it everything the contract holds; the delay is the users' only
//! protection. No node signature appears on the upgrade
//! path, so no number of node keys authorises an upgrade (invariant 0).
//! A `fixed` contract is only as fixed as its class: one that can reach the
//! protocol's `ContractInstanceRegistry.update` can replace the code that
//! reads its pins, and this library adds no such call for `fixed`.
use crate::configure::{CircuitPins, Configured, read_in_public};
use aztec::context::{gas::GasOpts, PrivateContext, PublicContext};
use aztec::oracle::get_contract_instance::get_contract_instance_current_class_id_avm;
use aztec::protocol::{
    abis::function_selector::FunctionSelector,
    address::AztecAddress,
    constants::CONTRACT_INSTANCE_REGISTRY_CONTRACT_ADDRESS,
    delayed_public_mutable::DelayedPublicMutableValues,
    traits::{Deserialize, Packable, Serialize, ToField},
};
use aztec::state_vars::{DelayedPublicMutable, PublicImmutable, StateVariable};

/// The pins an upgrade schedules: the contract class they belong to and the
/// circuit pins (the contract manifest's hash, the package list and its vk
/// hashes). `class_id` first and `circuits.manifest_hash` next, so a reader
/// of the stored value (the machine's chain reader, pss-client) finds the
/// two facts it needs in the first two fields of each half
/// (`UPGRADED_PINS_CLASS_ID`, `UPGRADED_PINS_MANIFEST_HASH`). All zero is
/// the never-written value: the constructor's pins are in force.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct UpgradedPins<let P: u32> {
    /// the contract class the pins were scheduled under
    pub class_id: Field,
    pub circuits: CircuitPins<P>,
}

/// The index of `class_id` in `UpgradedPins`' packing.
pub global UPGRADED_PINS_CLASS_ID: u32 = 0;
/// The index of `circuits.manifest_hash` in `UpgradedPins`' packing.
pub global UPGRADED_PINS_MANIFEST_HASH: u32 = 1;

/// The upgrade authority and the class the instance was deployed with,
/// both fixed by the constructor (`CircuitUpgrades::init`). The class is
/// what never-written pins belong to (`CircuitUpgrades::assert_class`).
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct UpgradeAuthority {
    pub address: AztecAddress,
    pub original_class_id: Field,
}

/// The delay the examples schedule upgrades with: one day, which is also
/// Aztec's longest transaction lifetime (`MAX_TX_LIFETIME`) and its default
/// class-update delay.
///
/// DEV DECISION (app developer): the upgrade delay, the `DELAY` of
/// `CircuitUpgrades`. Default one day. Users see a scheduled change for the
/// whole delay before it applies, so it is their time to leave; and every
/// private read of the pins caps the reading transaction's lifetime at the
/// delay, so a delay of one day hides an app's transactions among those of
/// every contract (a shorter one marks them). aztec-nr refuses less than
/// one hour (`DELAYED_PUBLIC_MUTABLE_MINIMUM_DELAY`, checked at compile
/// time). Longer: more warning, slower fixes. Design guide: "upgrades".
pub global DEFAULT_UPGRADE_DELAY: u64 = 86400;

/// Where a private function takes the circuit pins it verifies under. The
/// result replaces the circuit pins of the stored `Configured` (its
/// `configured` flag, `npk_app_hash`, stale period and node keys stay), so
/// the round table built from it (`Configured::round`) pins the vk hashes in
/// force.
pub trait CircuitsInForce<let P: u32> {
    fn in_force(self, configured: Configured<P>) -> Configured<P>;
}

/// The `upgrades` value an app's state view reports
/// (`crate::view::TipState::upgrades`), a struct with no fields whose path
/// the contract manifest generator reads from the artifact (pss-client
/// `bricks.ts`): `FixedCircuits` (`fixed`), `UpgradesCircuits` (`circuits`)
/// or `UpgradesContract` (`contract`). The view names the one of the
/// brick its round functions take their pins through; the generator
/// refuses an artifact whose upgrade entry points disagree with it.
pub trait UpgradesAxis {}

/// The fixed circuits: the constructor's pins for the life of the contract.
/// No storage, no read and no upgrade function.
#[derive(Deserialize, Eq, Serialize)]
pub struct FixedCircuits {}

impl UpgradesAxis for FixedCircuits {}

/// `upgrades: circuits`: the app takes its pins through `CircuitUpgrades`
/// and declares `upgrade_circuits` and `assert_upgrade_class`.
#[derive(Deserialize, Eq, Serialize)]
pub struct UpgradesCircuits {}

impl UpgradesAxis for UpgradesCircuits {}

/// `upgrades: contract`: as `UpgradesCircuits`, and the app declares
/// `upgrade_contract` too.
#[derive(Deserialize, Eq, Serialize)]
pub struct UpgradesContract {}

impl UpgradesAxis for UpgradesContract {}

impl<let P: u32> CircuitsInForce<P> for FixedCircuits {
    fn in_force(_self: Self, configured: Configured<P>) -> Configured<P> {
        configured
    }
}

/// Upgradable circuits: the scheduled pins (`UpgradedPins`) in a
/// `DelayedPublicMutable` of delay `DELAY`, and the upgrade authority, an
/// Aztec address the constructor pins (`init`), so the address commits to
/// it.
///
/// Storage, from the slot `#[storage]` gives it (the contract manifest's
/// `storage.circuit_pins`): +0 the delayed value (its metadata field, whose
/// low 32 bits are the time of change, then the `2P + 2` fields of the
/// value before the change, the `2P + 2` after it, and the hash, `4P + 6`
/// slots), then the authority and the original class (a
/// `PublicImmutable<UpgradeAuthority>`, three slots).
///
/// DEV DECISION (app developer): who may upgrade. Default, built here: an
/// Aztec address the constructor pins, checked against `msg_sender` in
/// `upgrade_circuits`; in practice a multisig or a governance contract.
/// Alternatives: a transferable authority (one more public function and a
/// mutable slot), or none at all (the zero address: no call passes, and
/// the contract keeps the constructor's circuits, as `fixed` but with the
/// upgrade code compiled in). The authority must never be a node or a key
/// the nodes hold: then the nodes alone could change the circuits, which
/// breaks invariant 0. The namespace owner key (the off-chain key that
/// signs the manifest message) is another key and may be another party:
/// one uploads a contract manifest, the other approves it on chain.
pub struct CircuitUpgrades<let P: u32, let DELAY: u64, Context> {
    context: Context,
    pub pins: DelayedPublicMutable<UpgradedPins<P>, DELAY, Context>,
    pub authority: PublicImmutable<UpgradeAuthority, Context>,
}

impl<let P: u32, let DELAY: u64, Context, let M: u32> StateVariable<M + 4, Context> for CircuitUpgrades<P, DELAY, Context>
where
    DelayedPublicMutableValues<UpgradedPins<P>, DELAY>: Packable<N = M>,
{
    fn new(context: Context, storage_slot: Field) -> Self {
        CircuitUpgrades {
            context,
            pins: DelayedPublicMutable::new(context, storage_slot),
            authority: PublicImmutable::new(context, storage_slot + M as Field + 1),
        }
    }

    fn get_storage_slot(self) -> Field {
        self.pins.get_storage_slot()
    }
}

impl<let P: u32, let DELAY: u64> CircuitsInForce<P> for CircuitUpgrades<P, DELAY, &mut PrivateContext> {
    /// The pins at the anchor block: the scheduled ones once in force, the
    /// constructor's while none was ever scheduled. The read is one
    /// historical public-storage proof and sets the transaction's
    /// expiration below the next time of change. Enqueues the app's
    /// `assert_upgrade_class` with the class the pins belong to (0 for the
    /// constructor's), the guard against a class and pins out of step.
    fn in_force(self, configured: Configured<P>) -> Configured<P> {
        let scheduled = self.pins.get_current_value();
        let selector = comptime { FunctionSelector::from_signature("assert_upgrade_class(Field)") };
        self.context.call_public_function(
            self.context.this_address(),
            selector,
            [scheduled.class_id],
            false,
        );
        if scheduled.circuits.manifest_hash == 0 {
            configured
        } else {
            configured.with_circuits(scheduled.circuits)
        }
    }
}

impl<let P: u32, let DELAY: u64> CircuitUpgrades<P, DELAY, PublicContext> {
    /// The constructor's half: pin the upgrade authority and the class the
    /// instance is deployed with, once.
    pub fn init(self, authority: AztecAddress) {
        let original_class_id = self.current_class();
        self.authority.initialize(UpgradeAuthority { address: authority, original_class_id });
    }

    /// This instance's current contract class, as the AVM proves it.
    fn current_class(self) -> Field {
        get_contract_instance_current_class_id_avm(self.context.this_address())
            .expect(f"this contract has no current class")
            .to_field()
    }

    /// The upgrade authority, refusing `sender` unless it is the authority
    /// (never the zero address).
    fn assert_authority(self, sender: AztecAddress) {
        let authority: UpgradeAuthority = read_in_public(self.context, self.authority);
        assert(
            (authority.address != AztecAddress::zero()) & (sender == authority.address),
            "not the upgrade authority",
        );
    }

    /// The body of the app's `#[only_self]` `assert_upgrade_class`, which
    /// every round function enqueues with the class its pins belong to
    /// (`in_force`; 0 for the constructor's pins, which belong to the
    /// class the instance was deployed with): refuse unless that class is
    /// the one running.
    pub fn assert_class(self, class_id: Field) {
        let expected = if class_id == 0 {
            let authority: UpgradeAuthority = read_in_public(self.context, self.authority);
            authority.original_class_id
        } else {
            class_id
        };
        assert(
            self.current_class() == expected,
            "the circuit pins belong to another contract class",
        );
    }

    /// The body of the app's public `upgrade_contract` (`upgrades:
    /// contract`): `sender` must be the authority; it schedules this
    /// instance's move to the class `new_class_id` (the protocol's
    /// `ContractInstanceRegistry.update`, which requires the class to be
    /// registered) and the new pins, scheduled under that class, and
    /// refuses unless the instance's class-update delay is the pins' delay,
    /// so both take effect at the same timestamp. With the examples' one
    /// day both are Aztec's default; an app with another delay sets the
    /// instance's in its constructor (`set_update_delay`, itself delayed).
    pub fn upgrade_contract(self, sender: AztecAddress, new_class_id: Field, circuits: CircuitPins<P>) {
        self.assert_authority(sender);
        circuits.assert_valid();
        // Safety: a public function is bytecode the AVM proves, so the
        // unconstrained calls enforce what constrained ones would (aztec-nr's
        // public calls are unconstrained wrappers of the AVM's call opcodes).
        let class_delay = unsafe { schedule_class_update(self.context, new_class_id) };
        assert(
            class_delay == self.pins.get_current_delay() as Field,
            "the class-update delay is not the pins' delay",
        );
        self.pins.schedule_value_change(UpgradedPins { class_id: new_class_id, circuits });
    }

    /// The body of the app's public `upgrade_circuits`: `sender` must be
    /// the authority (never the zero address); the new pins pass the
    /// constructor's check of a package list (`CircuitPins::assert_valid`)
    /// and are scheduled under this contract's current class, to take
    /// effect after the delay. A second call before the first takes effect
    /// replaces it, with a new delay.
    ///
    /// Refused while a class upgrade is pending (`upgrade_contract`'s pins,
    /// of another class, not yet in force): replacing them would leave the
    /// class change scheduled at the protocol's registry with no pins of
    /// the new class, so from its time of change every round would fail the
    /// class guard (`assert_class`) until another upgrade took effect, a
    /// full delay later. The authority calls `upgrade_contract` again
    /// instead, which reschedules both together.
    pub fn upgrade_circuits(self, sender: AztecAddress, circuits: CircuitPins<P>) {
        self.assert_authority(sender);
        circuits.assert_valid();
        let class_id = self.current_class();
        let (scheduled, time_of_change) = self.pins.get_scheduled_value();
        assert(
            (time_of_change <= self.context.timestamp()) | (scheduled.class_id == class_id),
            "a class upgrade is pending: use upgrade_contract",
        );
        self.pins.schedule_value_change(UpgradedPins { class_id, circuits });
    }
}

/// Call the protocol's `ContractInstanceRegistry.update(new_class_id)`,
/// which schedules this instance's class change after its update delay,
/// then read that delay (`get_update_delay`, the caller's own).
unconstrained fn schedule_class_update(context: PublicContext, new_class_id: Field) -> Field {
    let registry = CONTRACT_INSTANCE_REGISTRY_CONTRACT_ADDRESS;
    let update = comptime { FunctionSelector::from_signature("update((Field))") };
    let get_delay = comptime { FunctionSelector::from_signature("get_update_delay()") };
    let _ = context.call_public_function(registry, update, [new_class_id], GasOpts::default());
    context.static_call_public_function(registry, get_delay, [], GasOpts::default())[0]
}

mod test {
    use super::{UPGRADED_PINS_CLASS_ID, UPGRADED_PINS_MANIFEST_HASH, UpgradedPins};
    use crate::configure::CircuitPins;
    use aztec::protocol::traits::Packable;

    // The machine and pss-client read the class id and the manifest hash at
    // these indices of each half of the stored value.
    #[test]
    fn the_class_id_and_manifest_hash_lead_the_packing() {
        let pins = UpgradedPins {
            class_id: 0xc1a55,
            circuits: CircuitPins { manifest_hash: 0x3a5, packages: [1, 2], vk_hashes: [3, 4] },
        };
        let packed = pins.pack();
        assert_eq(packed.len(), 2 * 2 + 2);
        assert_eq(packed[UPGRADED_PINS_CLASS_ID], 0xc1a55);
        assert_eq(packed[UPGRADED_PINS_MANIFEST_HASH], 0x3a5);
    }
}
