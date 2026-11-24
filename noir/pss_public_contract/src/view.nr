//! The app's state view: every read of a tip app's storage that takes no
//! argument, returned by one `#[external("public")] #[view]` wrapper (the
//! app's `get_state`), so an app writes one view where it would write one
//! per read. The per-index reads (`request_at`, `done_at`, the app's
//! `outcome_at`) stay views of their own.
//!
//! The view also reports the app's `node_keys` and `upgrades` bricks, by
//! type: `TipState<Config, S, NodeKeysBrick, UpgradesBrick>`'s `node_keys`
//! is the node-keys brick (`KeyEpochs` or `FixedKeys`, the app's `Keys`
//! alias) and its `upgrades` the upgrades value
//! (`crate::upgrades::UpgradesAxis`).
//! Both are structs with no fields, so the view returns nothing more, and
//! the artifact's ABI names each by its path, which is where the contract
//! manifest generator reads the two axis values (pss-client `bricks.ts`),
//! whatever the view is called.
use crate::configure::{Configured, ConfiguredHead, head_body, is_set_body, read_in_public};
use crate::queue::{CommitmentSlot, Head, Queue};
use crate::signing_keys::SigningKeys;
use crate::upgrades::UpgradesAxis;
use aztec::context::PublicContext;
use aztec::protocol::traits::{Deserialize, Packable, Serialize};
use aztec::state_vars::{PublicImmutable, StateVariable};

/// What a tip app's state view (`get_state`) returns.
#[derive(Deserialize, Eq, Serialize)]
pub struct TipState<Config, let S: u32, NodeKeysBrick, UpgradesBrick> {
    /// the constructor's pins
    pub config: Config,
    /// configure's head: the flag, `npk_app_hash` and the stale period; all
    /// zero (so `configured.configured` is false) before `configure` has
    /// landed. Its pins are the Config's, which `configure` copied, so the
    /// view reads the head alone (`Configured::head`).
    pub configured: ConfiguredHead,
    pub head: Head,
    pub tail: u64,
    /// the current commitment in each of the app's commitment slots, 0
    /// before the init round
    pub commitments: [Field; S],
    /// the machine key of each slot (`$state_keys.reads` / `$state_keys.writes`): its
    /// storage slot
    pub state_keys: [Field; S],
    /// the storage slot of the app's outcome notes, the secret-shared rounds'
    /// `OUTCOME_SLOT`
    pub outcome_slot: Field,
    /// the node-keys brick (no fields: reported by its type)
    pub node_keys: NodeKeysBrick,
    /// the upgrades value (no fields: reported by its type)
    pub upgrades: UpgradesBrick,
}

impl<Config, let S: u32, NodeKeysBrick, UpgradesBrick> TipState<Config, S, NodeKeysBrick, UpgradesBrick>
where
    Config: Packable,
    NodeKeysBrick: SigningKeys,
    UpgradesBrick: UpgradesAxis,
{
    /// Read the state from the app's storage. Never reverts: before
    /// `configure` the configured head reads as zero.
    pub fn read<let P: u32>(
        context: PublicContext,
        config: PublicImmutable<Config, PublicContext>,
        configured: PublicImmutable<Configured<P>, PublicContext>,
        queue: Queue<PublicContext>,
        slots: [CommitmentSlot<PublicContext>; S],
        outcome_slot: Field,
    ) -> Self {
        let slot = configured.get_storage_slot();
        // Safety: a public function is bytecode the AVM proves, so
        // unconstrained bodies enforce what constrained ones would
        // (`read_head_in_public`'s, without its refusal of an unset record).
        let head: ConfiguredHead = unsafe {
            if is_set_body(context, slot) {
                head_body(context, slot)
            } else {
                std::mem::zeroed()
            }
        };
        TipState::new(read_in_public(context, config), head, queue, slots, outcome_slot)
    }

    /// The state from the Config and the configured head already read (all
    /// zero before `configure`, as `read` gives them).
    pub fn new(
        config: Config,
        configured: ConfiguredHead,
        queue: Queue<PublicContext>,
        slots: [CommitmentSlot<PublicContext>; S],
        outcome_slot: Field,
    ) -> Self {
        TipState {
            config,
            configured,
            head: queue.get_head(),
            tail: queue.get_tail(),
            commitments: slots.map(|slot: CommitmentSlot<PublicContext>| slot.read()),
            state_keys: slots.map(|slot: CommitmentSlot<PublicContext>| slot.get_storage_slot()),
            outcome_slot,
            // the bricks have no fields: their values are their types
            node_keys: std::mem::zeroed(),
            upgrades: std::mem::zeroed(),
        }
    }
}
