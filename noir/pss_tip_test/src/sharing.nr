//! Secret-shared receipt intake's sharing as a suite builds it: a Rep3
//! sharing of a request's shared values and blinding (`sharing_of`, under
//! the round's `Layout`) and the three node receipts over C and the
//! sharing's digest (`shared_receipts`: over the summand commitments, the
//! layout and C's clear values), what a client and the nodes produce
//! before the user's request function runs.
use crate::nodes::receipts;
use pss_public_contract::{Layout, NODES, Receipt, shared_receipt_message, Sharing};

/// A Rep3 sharing of the values of `values` the `layout` marks CHOSEN, in
/// order, then of `blinding`: two fixed summand vectors (`0x5100 + k` and
/// `0x5200 + k`) and the third that makes them add up, with three fixed
/// salts. A suite that needs a sharing that does not open C changes one
/// summand of it.
pub unconstrained fn sharing_of<let M: u32, let Q: u32, let X: u32, let L: u32>(
    layout: Layout<M, Q, X>,
    values: [Field; M],
    blinding: Field,
) -> Sharing<L> {
    std::static_assert(L == X + 1, "a sharing holds the X shared values, then the blinding");
    let (_, chosen) = layout.split(values);
    let mut shared = [0; L];
    for x in 0..X {
        shared[x] = chosen[x];
    }
    shared[X] = blinding;
    let mut summands = [[0; L]; NODES];
    for k in 0..L {
        summands[0][k] = 0x5100 + k as Field;
        summands[1][k] = 0x5200 + k as Field;
        summands[2][k] = shared[k] - summands[0][k] - summands[1][k];
    }
    Sharing { summands, salts: [0x5a10, 0x5a11, 0x5a12] }
}

/// The three nodes' receipts over the request `request_id` with inputs
/// commitment `c`, expiring at `expiry_block`, after each checked its
/// envelopes against `sharing` and stored the CLEAR values of `values` (C's,
/// in its order) under `layout`: the message over the digest
/// (`Sharing::digest`, `shared_receipt_message`). A suite whose nodes
/// signed other clear values passes those values.
pub unconstrained fn shared_receipts<let M: u32, let Q: u32, let X: u32, let L: u32>(
    request_id: Field,
    c: Field,
    expiry_block: u32,
    layout: Layout<M, Q, X>,
    values: [Field; M],
    sharing: Sharing<L>,
) -> [Receipt; NODES] {
    let (clear, _) = layout.split(values);
    receipts(shared_receipt_message(request_id, c, expiry_block, sharing.digest(layout, clear)))
}
