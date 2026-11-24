//! Reading a contract's own public log back by tag, for clients and tests
//! that hold a transaction hash: the request log of an on-chain intake
//! request (`intake::request_log_tag(request_id)`) or the sealed-thirds log
//! of an apply or the init (`compute_log_tag(request_id,
//! chain_state::PSS_STATE)`). The chain reader uses the node's
//! `getPublicLogsByTags` instead.
use aztec::oracle::message_processing::get_tx_effect;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::ToField;

/// The fields after the tag of the last public log `emitter` emitted under
/// `tag` in transaction `tx_hash`, at most M of them (a longer log fails);
/// empty when there is none. The body of an app's `log_in_tx` utility.
pub unconstrained fn log_in_tx<let M: u32>(
    emitter: AztecAddress,
    tx_hash: Field,
    tag: Field,
) -> BoundedVec<Field, M> {
    let logs = get_tx_effect(tx_hash).expect(f"no such transaction").public_logs;
    let mut fields: BoundedVec<Field, M> = BoundedVec::new();
    let mut j = 0;
    // each log in the flat payload: [length, emitting address, tag, fields…]
    while j < logs.length {
        let len = logs.payload[j] as u32;
        if (len != 0) & (logs.payload[j + 1] == emitter.to_field()) & (logs.payload[j + 2] == tag) {
            assert(len - 1 <= M, "log longer than the utility's bound");
            fields = BoundedVec::new();
            for k in 0..M {
                if k < len - 1 {
                    fields.push(logs.payload[j + 3 + k]);
                }
            }
        }
        j += 2 + len;
    }
    fields
}
