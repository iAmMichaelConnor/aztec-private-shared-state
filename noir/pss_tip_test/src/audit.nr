//! The requester audit (docs/ARCHITECTURE.md section 6, "The hidden
//! requester"): no account address reaches the chain through a request.
//! A suite gives the accounts its test made (the requester, the deployer,
//! the relayer) and the fields it audits: an intake function's arguments,
//! the public call it enqueues, a request log, a proof's public inputs, or
//! every field a transaction left on chain (`assert_tx_names_no_requester`,
//! which runs inside a contract's utility function, where the TXE answers
//! the transaction-effect oracle: `tx_names_no_requester` of
//! pss_public_contract_test for the library's suite, and of `pss_probe`,
//! which the tip examples' suites deploy beside their app). The same walk
//! over any other values a suite hides is `assert_tx_holds_none`.
//! The machine's in-process suites (sidecar-tip `testing::audit`) and the
//! e2e drivers (pss-client `assertNoRequester`) audit the off-chain places
//! the same way.
use aztec::protocol::address::AztecAddress;
use aztec::protocol::blob_data::TxEffect;

/// Whether `value` is the address of one of `accounts`.
pub fn names_an_account<let K: u32>(value: Field, accounts: [AztecAddress; K]) -> bool {
    let mut found = false;
    for k in 0..K {
        found = found | (value == accounts[k].inner);
    }
    found
}

/// Assert that none of `fields` is the address of one of `accounts`.
pub fn assert_no_requester<let N: u32, let K: u32>(fields: [Field; N], accounts: [AztecAddress; K]) {
    for i in 0..N {
        assert(!names_an_account(fields[i], accounts), "an account address appears in the audited fields");
    }
}

/// Assert that no account address appears anywhere in `effect`
/// (`assert_tx_holds_none` over the accounts' addresses).
pub unconstrained fn assert_tx_names_no_requester<let K: u32>(effect: TxEffect, accounts: [AztecAddress; K]) {
    assert_tx_holds_none(effect, accounts.map(|a: AztecAddress| a.inner));
}

/// Assert that none of `values` appears anywhere in `effect`: its note
/// hashes, nullifiers, L2-to-L1 messages, public data writes (slot and
/// value), private logs, public logs (every field of the flat payload but
/// each log's emitting contract, which is the app) and contract class logs.
/// The requester audit's walk, and a suite's for any other value it hides
/// (lending's oblivious deployment: a position and the append index).
pub unconstrained fn assert_tx_holds_none<let K: u32>(effect: TxEffect, values: [Field; K]) {
    let found = |v: Field| {
        let mut f = false;
        for k in 0..K {
            f = f | (v == values[k]);
        }
        f
    };
    for v in effect.note_hashes {
        assert(!found(v), "an audited value appears in a note hash");
    }
    for v in effect.nullifiers {
        assert(!found(v), "an audited value appears in a nullifier");
    }
    for v in effect.l2_to_l1_msgs {
        assert(!found(v), "an audited value appears in an L2-to-L1 message");
    }
    for w in effect.public_data_writes {
        assert(!found(w.leaf_slot) & !found(w.value), "an audited value appears in a public data write");
    }
    for log in effect.private_logs {
        for v in log.fields {
            assert(!found(v), "an audited value appears in a private log");
        }
    }
    for log in effect.contract_class_logs {
        for v in log.log.fields {
            assert(!found(v), "an audited value appears in a contract class log");
        }
    }
    let payload = effect.public_logs.payload;
    let mut j = 0;
    // each log in the flat payload: [length, emitting address, fields…]
    while j < effect.public_logs.length {
        let len = payload[j] as u32;
        for k in 0..len {
            assert(!found(payload[j + 2 + k]), "an audited value appears in a public log");
        }
        j += 2 + len;
    }
}

mod tests {
    use super::{assert_no_requester, names_an_account};
    use aztec::protocol::address::AztecAddress;

    #[test]
    fn an_address_among_the_fields_is_found() {
        let accounts = [AztecAddress { inner: 0xa11ce }, AztecAddress { inner: 0xb0b }];
        assert(names_an_account(0xb0b, accounts));
        assert(!names_an_account(0xb0c, accounts));
        assert_no_requester([1, 2, 3], accounts);
    }

    #[test(should_fail_with = "an account address appears in the audited fields")]
    fn an_address_in_the_fields_fails() {
        assert_no_requester([1, 0xa11ce], [AztecAddress { inner: 0xa11ce }]);
    }
}
