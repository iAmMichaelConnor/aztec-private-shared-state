//! The receipt rows a resync carries. Which stored rows a neighbour can send,
//! and how the lost node checks a copied row and signs it again, are the
//! rules of the row's intake, which the core does not know: the node takes
//! them from its [`ReceiptResync`] hook (sidecar-tip fills it from its
//! intakes). The core pairs the two neighbours' rows by request id and hands
//! the hook only the pairs both sent alike.

use std::sync::Arc;

use super::*;

/// How a resync carries a node's receipt rows (docs/ARCHITECTURE.md
/// section 6, the receipts row). A row is one intake's, which alone answers
/// for it.
pub trait ReceiptResync: Send + Sync {
    /// The body a neighbour sends of its stored row `row`, with its own
    /// receipt signature; `None` for a row no neighbour can rebuild, which is
    /// not sent.
    fn send(&self, row: &ReceiptRow) -> Option<ReceiptBody>;

    /// The row the lost node keeps of one request of `namespace` whose two
    /// neighbours sent `from_prev` and `from_next`, alike but for their
    /// signatures: when each signature verifies under its sender's pinned
    /// sig key (`pins`: node me-1's, then node me+1's) and the ids hash
    /// right, the row signed again with the node's own `keys`; `None`
    /// otherwise.
    fn keep(
        &self,
        namespace: Fr,
        from_prev: &ReceiptBody,
        from_next: &ReceiptBody,
        pins: [Point; 2],
        keys: &NodeKeys,
    ) -> Option<ReceiptRow>;
}

/// A node's receipt resync hook ([`crate::pipeline::Node::with_receipt_resync`]).
pub type ReceiptResyncHook = Arc<dyn ReceiptResync>;

/// The default hook: no row is sent and none is kept.
pub struct NoReceiptResync;

impl ReceiptResync for NoReceiptResync {
    fn send(&self, _: &ReceiptRow) -> Option<ReceiptBody> {
        None
    }

    fn keep(
        &self,
        _: Fr,
        _: &ReceiptBody,
        _: &ReceiptBody,
        _: [Point; 2],
        _: &NodeKeys,
    ) -> Option<ReceiptRow> {
        None
    }
}

// How a resync copies the receipt rows. Each neighbour sends the rows its
// hook sends, each with its own receipt signature. Node `me` hands the hook
// a row only when both neighbours send it with the same fields, and keeps
// what the hook returns (checked and signed again with its own key). A row
// only one neighbour holds (the other pruned it, or never signed it), or
// held differently, is left out: the request then cannot run at this node
// and its head is skipped after `stale_blocks`, as when no row is copied. A
// single neighbour's word never makes this node sign a receipt.
/// The receipt rows of `namespace` node `me` keeps, from its neighbours'
/// (`from_prev` from node me-1, `from_next` from node me+1), and how many
/// it leaves out; 400 when a neighbour's pinned sig key is not a point.
pub(super) fn receipt_rows(
    me: usize,
    namespace: Fr,
    from_prev: &[ReceiptBody],
    from_next: &[ReceiptBody],
    keys: &NodeKeys,
    pins: &NodesResponse,
    hook: &dyn ReceiptResync,
) -> Result<(Vec<ReceiptRow>, usize), Refusal> {
    let pin = |i: usize| {
        point_from_wire(&pins.nodes[i].sig)
            .map_err(|e| Refusal::bad_request(format!("resync: node {i}'s pinned sig: {e}")))
    };
    let senders = [pin(prev(me))?, pin(next(me))?];
    let by_id: BTreeMap<FieldHex, &ReceiptBody> =
        from_prev.iter().map(|r| (r.request_id, r)).collect();
    let mut kept = Vec::new();
    let mut matched = 0;
    for n in from_next {
        let Some(p) = by_id.get(&n.request_id) else {
            continue;
        };
        matched += 1;
        let alike = ReceiptBody {
            signature: n.signature,
            ..(*p).clone()
        } == *n;
        if alike && let Some(row) = hook.keep(namespace, p, n, senders, keys) {
            kept.push(row);
        }
    }
    let left_out = (from_prev.len() + from_next.len()).saturating_sub(matched + kept.len());
    Ok((kept, left_out))
}
