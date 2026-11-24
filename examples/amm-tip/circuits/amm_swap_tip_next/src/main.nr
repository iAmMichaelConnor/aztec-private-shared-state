// The upgraded swap circuit the e2e's circuit upgrade registers under the
// package `amm_swap_tip` (examples/amm-tip README, "Upgrades"): the same
// parameters, outputs, manifests and request id as amm_swap_tip, whose
// main.nr documents each of them, with one rule in front of the swap
// (amm_tip::tip::swap_round_min_trade: a trade below MIN_TRADE lands as a
// no-op with code 10). Another bytecode, so another vk hash, which a
// contract on `upgrades: circuits` or `contract` pins after its upgrade
// authority schedules the new contract manifest's pins.

use amm_tip::tip::{swap_round_min_trade, SwapOutputs};
use pss_core::tip::family::Plain;
use pss_core::tip::outputs::BoundPartial;
use pss_core::tip::slot;

/// amm_swap_tip's swap under the upgraded rule; total, as amm_swap_tip.
fn main(
    namespace: pub Field,
    vk_hash: pub Field,
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    amount_in: Field,
    direction: Field,
    min_out: Field,
    partial_note: Field,
    user_nonce: Field,
    pool: [Field; 2],
    r_old: Field,
    r_new: Field,
    nsk_app: Field,
) -> pub BoundPartial<SwapOutputs> {
    let key = slot::load(namespace, in_slots[0], out_slots[0], pool, r_old, r_new);
    let family = Plain { partial_note, user_nonce };
    swap_round_min_trade(vk_hash, key, [amount_in, direction, min_out], family, nsk_app).stored()
}
