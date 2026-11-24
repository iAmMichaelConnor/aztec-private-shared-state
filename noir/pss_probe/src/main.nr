use aztec::macros::aztec;

/// The tip examples' test probe (test-only: no app deploys or trusts it):
/// a contract a suite deploys beside the app, uninitialised, to read a
/// settled transaction (`tx_summary`, `tx_names_no_requester`, which run in
/// a utility function, where the TXE answers the transaction-effect
/// oracle), to attempt the app's open `skip()` as a nested call that
/// reports its revert instead of rethrowing it (`try_skip`), and, in the
/// end-to-end tests of a reverted landing, to make a transaction revert:
/// in its public part (`always_revert`, a call that reverts) or in its
/// teardown alone (`revert_in_teardown`, which a test fee payment calls
/// beside the real one, so the app logic runs and the teardown reverts). It
/// holds no state and no pin. The library's own suite reads its test
/// contract the same way (pss_public_contract_test).
#[aztec]
pub contract PssProbe {
    use aztec::macros::functions::external;
    use aztec::oracle::avm;
    use aztec::oracle::message_processing::get_tx_effect;
    use aztec::protocol::abis::function_selector::FunctionSelector;
    use aztec::protocol::address::AztecAddress;
    use aztec::protocol::traits::ToField;
    use pss_tip_test::audit::assert_tx_names_no_requester;
    use pss_tip_test::shape::{summarize, TxSummary};
    use pss_tip_test::{PROBE_DA_GAS, PROBE_L2_GAS};

    /// Call `skip()` on `target` as a nested public call and return whether
    /// it landed; a revert leaves none of the call's effects and is not
    /// rethrown (aztec-nr's `call_public_function` rethrows).
    #[external("public")]
    fn try_skip(target: AztecAddress) -> bool {
        let selector = comptime { FunctionSelector::from_signature("skip()") };
        avm::call(PROBE_L2_GAS, PROBE_DA_GAS, target, [selector.to_field()]);
        avm::success_copy()
    }

    /// Set the transaction's teardown to `always_revert()`, as a
    /// fee-payment contract sets its teardown: the transaction's setup and
    /// app logic run, then its teardown reverts, which drops the effects of
    /// both revertible phases (the app logic's public calls and every
    /// revertible private effect). A test fee payment calls it beside the
    /// payment that makes another contract the fee payer, which the revert
    /// does not touch (the setup phase cannot revert).
    #[external("private")]
    fn revert_in_teardown() {
        self.context.set_public_teardown_function(
            self.address,
            comptime { FunctionSelector::from_signature("always_revert()") },
            [],
            false,
        );
    }

    /// Revert, whenever called: a public call that makes the transaction's
    /// phase revert (no block has number 0).
    #[external("public")]
    fn always_revert() {
        assert(self.context.block_number() == 0, "the probe reverts");
    }

    /// The requester audit of transaction `tx_hash` (pss_tip_test `audit`):
    /// fails when one of `accounts` appears anywhere in its effect; true
    /// otherwise.
    #[external("utility")]
    unconstrained fn tx_names_no_requester(tx_hash: Field, accounts: [AztecAddress; 4]) -> bool {
        assert_tx_names_no_requester(get_tx_effect(tx_hash).expect(f"no such transaction"), accounts);
        true
    }

    /// Every side effect of transaction `tx_hash`, counted by kind, with the
    /// heads of its public logs (pss_tip_test `shape::summarize`).
    #[external("utility")]
    unconstrained fn tx_summary(tx_hash: Field) -> TxSummary {
        summarize(get_tx_effect(tx_hash).expect(f"no such transaction"))
    }
}
