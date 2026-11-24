//! The shape of a transaction as the world sees it, for the hidden round
//! type (docs/ARCHITECTURE.md section 6, "What the world learns: not the
//! round type"): what a tip example's suite compares across the round types
//! of one app under secret-shared intake. A transaction's shape is the count of
//! each kind of effect it left (note hashes, nullifiers with its own first
//! one, L2-to-L1 messages, public data writes, private, public and contract
//! class logs) and the length of each private log, read from the settled
//! `TxEffect`; its gas is what the protocol meters for those effects.
//!
//! The same count, with the head of each public log, is what the library's
//! test contract returns from its `tx_summary` utility (`TxSummary`), and
//! `log_fields` reads one public log's fields back.
//!
//! What the TXE does not expose, so no suite here can compare it: the public
//! calls a transaction enqueues (the `TxEffect` carries none and the TXE has
//! no oracle for them; a suite compares the call each request or result
//! function builds through the contract's interface, and the public effects
//! its execution leaves), the AVM's execution gas (the TXE runs blocks at
//! zero gas fees, records no transaction fee and reports no gas used), and
//! proving time.
use aztec::ephemeral::EphemeralArray;
use aztec::oracle::message_processing::get_tx_effects;
use aztec::protocol::abis::{gas::Gas, gas_fees::GasFees, gas_settings::GasSettings};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::blob_data::TxEffect;
use aztec::protocol::constants::{
    AVM_EMITNOTEHASH_BASE_L2_GAS, AVM_EMITNULLIFIER_BASE_L2_GAS, AVM_SSTORE_DYN_DA_GAS,
    DA_GAS_PER_FIELD, FIXED_AVM_STARTUP_L2_GAS, L2_GAS_PER_NOTE_HASH, L2_GAS_PER_NULLIFIER,
    L2_GAS_PER_PRIVATE_LOG, PRIVATE_TX_L2_GAS_OVERHEAD, PUBLIC_DATA_WRITE_LENGTH,
    PUBLIC_TX_L2_GAS_OVERHEAD, TX_DA_GAS_OVERHEAD,
};
use aztec::test::helpers::test_environment::{CallPrivateOptions, TestEnvironment};
use aztec::protocol::traits::{Deserialize, Serialize};
use aztec::test::helpers::txe_oracles;

/// The number of private logs whose lengths a shape lists, and of public
/// logs whose heads a summary lists; a tip transaction emits at most one
/// private log.
pub global LISTED_LOGS: u32 = 4;

/// One transaction's effects, counted by kind, and its private logs'
/// lengths (tag included, 0 past the last log).
#[derive(Eq)]
pub struct TxShape {
    pub note_hashes: u32,
    pub nullifiers: u32,
    pub l2_to_l1_msgs: u32,
    pub public_data_writes: u32,
    pub private_logs: u32,
    pub private_log_lengths: [u32; LISTED_LOGS],
    pub public_logs: u32,
    pub contract_class_logs: u32,
}

unconstrained fn non_zero<let N: u32>(values: [Field; N]) -> u32 {
    let mut n = 0;
    for i in 0..N {
        if values[i] != 0 {
            n += 1;
        }
    }
    n
}

/// The shape of `effect`.
pub unconstrained fn shape_of(effect: TxEffect) -> TxShape {
    let mut private_logs = 0;
    let mut private_log_lengths = [0; LISTED_LOGS];
    for log in effect.private_logs {
        if log.length != 0 {
            if private_logs < LISTED_LOGS {
                private_log_lengths[private_logs] = log.length;
            }
            private_logs += 1;
        }
    }
    let mut public_data_writes = 0;
    for w in effect.public_data_writes {
        if w.leaf_slot != 0 {
            public_data_writes += 1;
        }
    }
    let mut contract_class_logs = 0;
    for log in effect.contract_class_logs {
        if log.log.length != 0 {
            contract_class_logs += 1;
        }
    }
    // each public log in the flat payload: [length, emitting address, fields…]
    let mut public_logs = 0;
    let mut j = 0;
    while j < effect.public_logs.length {
        j += 2 + effect.public_logs.payload[j] as u32;
        public_logs += 1;
    }
    TxShape {
        note_hashes: non_zero(effect.note_hashes),
        nullifiers: non_zero(effect.nullifiers),
        l2_to_l1_msgs: non_zero(effect.l2_to_l1_msgs),
        public_data_writes,
        private_logs,
        private_log_lengths,
        public_logs,
        contract_class_logs,
    }
}

/// One public log's head: the AVM-set emitting contract, field 0 (the tag)
/// and the number of fields, tag included.
#[derive(Deserialize, Eq, Serialize)]
pub struct LogHead {
    pub emitter: AztecAddress,
    pub tag: Field,
    pub length: u32,
}

impl LogHead {
    pub fn none() -> Self {
        LogHead { emitter: AztecAddress::zero(), tag: 0, length: 0 }
    }
}

/// A transaction's effects counted by kind (`TxShape`'s counts) with the
/// heads of its first `LISTED_LOGS` public logs in emission order, as a
/// contract's utility returns it. `nullifiers` includes the transaction's
/// own first nullifier, so a transaction that emits none of its own has one.
#[derive(Deserialize, Eq, Serialize)]
pub struct TxSummary {
    pub note_hashes: u32,
    pub nullifiers: u32,
    pub l2_to_l1_msgs: u32,
    pub private_logs: u32,
    pub contract_class_logs: u32,
    pub public_logs: u32,
    pub logs: [LogHead; LISTED_LOGS],
}

/// The summary of `effect`.
pub unconstrained fn summarize(effect: TxEffect) -> TxSummary {
    let shape = shape_of(effect);
    let mut logs = [LogHead::none(); LISTED_LOGS];
    let payload = effect.public_logs.payload;
    let (mut n, mut j) = (0, 0);
    while (j < effect.public_logs.length) & (n < LISTED_LOGS) {
        let len = payload[j] as u32;
        logs[n] = LogHead { emitter: AztecAddress { inner: payload[j + 1] }, tag: payload[j + 2], length: len };
        n += 1;
        j += 2 + len;
    }
    TxSummary {
        note_hashes: shape.note_hashes,
        nullifiers: shape.nullifiers,
        l2_to_l1_msgs: shape.l2_to_l1_msgs,
        private_logs: shape.private_logs,
        contract_class_logs: shape.contract_class_logs,
        public_logs: shape.public_logs,
        logs,
    }
}

/// The N fields after the tag of the one public log that `emitter` emitted
/// under `tag`; fails if there is none, more than one, or it has another
/// length.
pub unconstrained fn log_fields<let N: u32>(
    effect: TxEffect,
    emitter: AztecAddress,
    tag: Field,
) -> [Field; N] {
    let payload = effect.public_logs.payload;
    let mut found = 0;
    let mut fields = [0; N];
    let mut j = 0;
    while j < effect.public_logs.length {
        let len = payload[j] as u32;
        if (payload[j + 1] == emitter.inner) & (payload[j + 2] == tag) {
            assert(len == N + 1, "the log has another length");
            for k in 0..N {
                fields[k] = payload[j + 3 + k];
            }
            found += 1;
        }
        j += 2 + len;
    }
    assert(found == 1, "no single log with this tag from this contract");
    fields
}

/// The settled effect of transaction `tx_hash`, as a utility function reads
/// it (the node's transaction-effect oracle).
pub unconstrained fn tx_effect(env: TestEnvironment, tx_hash: Field) -> TxEffect {
    env.utility_context(|_| {
        get_tx_effects(EphemeralArray::from_array([tx_hash])).get(0).expect(
            f"no such transaction",
        )
    })
}

/// The shape of the last transaction the TXE included.
pub unconstrained fn last_tx_shape(env: TestEnvironment) -> TxShape {
    shape_of(tx_effect(env, txe_oracles::get_last_tx_effects().tx_hash))
}

/// The gas the protocol meters for a transaction of `shape` that enqueues
/// `public_calls` public calls: its private part as the private kernel tail
/// meters it (per note hash, nullifier, L2-to-L1 message and private log,
/// each log's fields and its length on DA, a fixed AVM start per enqueued
/// call, the transaction overhead), plus the DA of its public data writes.
/// The AVM's execution gas of the enqueued calls is not in it; the TXE does
/// not report it. A transaction that enqueues no call is private-only: its
/// effects are metered at the private rates, and its DA carries the fee
/// payer's balance write.
pub fn metered_gas(shape: TxShape, public_calls: u32) -> Gas {
    let private_only = public_calls == 0;
    let mut log_fields = 0;
    for i in 0..LISTED_LOGS {
        if shape.private_log_lengths[i] != 0 {
            // every private log puts its length on DA too
            log_fields += shape.private_log_lengths[i] + 1;
        }
    }
    let mut da_fields = shape.note_hashes + shape.nullifiers + shape.l2_to_l1_msgs + log_fields;
    let mut l2 = shape.private_logs * L2_GAS_PER_PRIVATE_LOG;
    let mut public_da = 0;
    if private_only {
        da_fields += PUBLIC_DATA_WRITE_LENGTH;
        l2 += shape.note_hashes * L2_GAS_PER_NOTE_HASH
            + shape.nullifiers * L2_GAS_PER_NULLIFIER
            + PRIVATE_TX_L2_GAS_OVERHEAD;
    } else {
        l2 += shape.note_hashes * AVM_EMITNOTEHASH_BASE_L2_GAS
            + shape.nullifiers * AVM_EMITNULLIFIER_BASE_L2_GAS
            + public_calls * FIXED_AVM_STARTUP_L2_GAS
            + PUBLIC_TX_L2_GAS_OVERHEAD;
        public_da = shape.public_data_writes * AVM_SSTORE_DYN_DA_GAS;
    }
    Gas::new(da_fields * DA_GAS_PER_FIELD + TX_DA_GAS_OVERHEAD + public_da, l2)
}

/// The gas settings of one transaction kind as an app's fee setting fixes
/// them (pss-client `FeeSetting.gas`): `limits`, and teardown limits of half
/// the DA and an eighth of the L2 limit (the client's default; wFJ runs no
/// teardown), at zero fees (the TXE charges none).
pub fn kind_gas(limits: Gas) -> GasSettings {
    GasSettings::new(
        limits,
        Gas::new(limits.da_gas / 2, limits.l2_gas / 8),
        GasFees::new(0, 0),
        GasFees::new(0, 0),
    )
}

/// The call options of a transaction sent under `kind_gas(limits)`.
pub fn kind_options(limits: Gas) -> CallPrivateOptions<0, 0> {
    CallPrivateOptions::new().with_gas_settings(kind_gas(limits))
}
