//! A nested public call that reports its revert instead of rethrowing it,
//! the probes' and the re-entrant mock's one primitive, and the oracle's gas burner.
use aztec::context::{PublicCall, PublicContext};
use aztec::oracle::avm;
use aztec::protocol::traits::ToField;

/// Make `call` as a nested public call with `l2_gas` and `da_gas` allotted,
/// and return whether it succeeded, without rethrowing its revert (aztec-nr's
/// `call_public_function` rethrows). A nested call that reverts leaves none
/// of its writes, logs or nested effects, as a transaction whose app-logic
/// phase reverts leaves none of its own: the AVM discards the call's
/// journal either way. A call the AVM halts exceptionally (a storage write
/// in a static context, out of gas) consumes its whole allotment, so the
/// caller keeps only what it did not allot.
pub unconstrained fn attempt<let M: u32, let N: u32, T>(
    call: PublicCall<M, N, T>,
    l2_gas: u32,
    da_gas: u32,
) -> bool {
    avm::call(l2_gas, da_gas, call.target_contract, [call.selector.to_field()].concat(call.args));
    avm::success_copy()
}

/// Spend `l2_gas` of the current call's L2 gas, then return: the oracle's
/// `READ_BURN` mode. A call allotted less halts exceptionally inside the
/// loop, as a read target that loops forever does.
pub unconstrained fn burn_l2_gas(context: PublicContext, l2_gas: u32) {
    let start = context.l2_gas_left();
    while start - context.l2_gas_left() < l2_gas {}
}
