// The contract record-logs.ts deploys to record tests/fixtures/logs.json:
// it emits request-shaped and sealed-shaped public logs under the library's
// own tags, computed in Noir by aztec-nr, from an address that is not the
// namespace contract, so the recording shows the reader filtering by
// emitter; and, for the reader's tag queries, more public logs under one tag
// than the node answers in a page, and a private log.
use aztec::macros::aztec;

#[aztec]
pub contract LogEmitter {
    use aztec::macros::functions::{external, initializer};
    use aztec::protocol::hash::compute_log_tag;
    use pss_public_contract::chain_state::PSS_STATE;
    use pss_public_contract::request_log_tag;

    #[external("public")]
    #[initializer]
    fn constructor() {}

    #[external("public")]
    fn emit_request(request_id: Field, fields: [Field; 3]) {
        self.context.emit_public_log_unsafe(request_log_tag(request_id), fields);
    }

    #[external("public")]
    fn emit_sealed(request_id: Field, fields: [Field; 6]) {
        self.context.emit_public_log_unsafe(compute_log_tag(request_id, PSS_STATE), fields);
    }

    // `count` one-field logs under `tag`, the i-th holding i.
    #[external("public")]
    fn emit_many(tag: Field, count: u32) {
        for i in 0..count {
            self.context.emit_public_log_unsafe(tag, i as Field);
        }
    }

    // A private log whose field 0, once the kernel silos it with this
    // contract's address, is the tag the node indexes it under.
    #[external("private")]
    fn emit_private(tag: Field, fields: [Field; 3]) {
        self.context.emit_private_log_unsafe(tag, BoundedVec::from_array(fields));
    }
}
