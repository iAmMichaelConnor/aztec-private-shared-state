//! Receipt intake (`intake: receipt`): each node stored the inputs when it
//! signed the receipt (`POST /v1/receipt`). A resync copies these rows from
//! the lost node's neighbours, which checks and signs them again.

use sidecar_core::field::FieldHex;
use sidecar_core::register::Signature;

use crate::receipt::{
    chain_request_id, inputs_hash, receipt_message, sign_receipt, verify_receipt,
};

use super::*;
use crate::intake::route::{ReceiptSigning, intake_inputs};

/// Receipt intake (`intake: receipt`): the inputs a node stored when it
/// signed the receipt.
#[derive(Clone, Copy, Debug)]
pub struct ReceiptPlain;

impl ReceiptPlain {
    /// The inputs of chain request `chain` in one node's stored receipt;
    /// why not, when the receipt names another package or request or its
    /// inputs do not give `chain`.
    fn found(
        receipt: &StoredReceipt,
        namespace: Fr,
        package: &TipPackage,
        chain: Fr,
    ) -> Result<PlainFound, String> {
        check_origin(receipt, namespace, package, chain).map_err(|e| e.message)?;
        let inputs = Self::stored_inputs(receipt).map_err(|e| e.message)?;
        let derived = package.chain_request_id(namespace, &inputs);
        if derived != chain {
            return Err(format!(
                "its inputs give chain request {}",
                fr_to_hex(derived)
            ));
        }
        Ok(inputs)
    }

    /// The inputs of a stored receipt; 400 for a row without a nonce (a
    /// secret-shared receipt intake row).
    pub(super) fn stored_inputs(receipt: &StoredReceipt) -> Result<PlainFound, Refusal> {
        let Some(user_nonce) = receipt.user_nonce else {
            return Err(Refusal::bad_request(format!(
                "the stored receipt of chain request {} holds no user_nonce",
                receipt.request_id
            )));
        };
        Ok(PlainFound::new(
            receipt.inputs.iter().map(|f| f.fr()).collect(),
            user_nonce.fr(),
        ))
    }
}

impl IntakeSource for ReceiptPlain {
    fn intake(&self) -> QueuedIntake {
        QueuedIntake::Receipt
    }

    fn reads_nodes(&self) -> bool {
        true
    }

    /// The first node's stored receipt that gives `chain` under `package`.
    /// A receipt of another circuit is another package's entry, which the
    /// scheduler asks that package's intake for; any other receipt that
    /// gives no request here (another vk_hash, namespace or request, no
    /// nonce, inputs that do not give `chain`) is a fault of the node that
    /// answered it, logged, and the next node's receipt is tried.
    fn find<'a>(
        &'a self,
        at: &'a dyn IntakeLookup,
        package: &'a TipPackage,
        chain: Fr,
    ) -> TipFuture<'a, Result<Option<Found>, ReadError>> {
        Box::pin(async move {
            let namespace = at.namespace();
            for (node, receipt) in at.stored_receipts(chain).await.into_iter().enumerate() {
                let Some(receipt) = receipt.filter(|r| r.circuit == package.name) else {
                    continue;
                };
                match Self::found(&receipt, namespace, package, chain) {
                    Ok(inputs) => return Ok(Some(found(inputs))),
                    Err(why) => tracing::warn!(
                        node,
                        circuit = %package.name,
                        chain_request_id = %fr_to_hex(chain),
                        "scheduler: node {node}'s stored receipt gives no request ({why}); \
                         trying the next node's"
                    ),
                }
            }
            Ok(None)
        })
    }

    fn node_view(&self, at: &NodeInputs<'_>) -> Result<Found, Refusal> {
        let row = at
            .rows
            .receipt(at.namespace, at.chain_request_id)?
            .ok_or_else(|| {
                refused(format!(
                    "this node holds no receipt for chain request {} (never signed, or pruned)",
                    fr_to_hex(at.chain_request_id)
                ))
            })?;
        let receipt = StoredReceipt::new(at.namespace, &row);
        check_origin(&receipt, at.namespace, at.package, at.chain_request_id)
            .map_err(|e| refused(e.message))?;
        Ok(found(
            Self::stored_inputs(&receipt).map_err(|e| refused(e.message))?,
        ))
    }

    fn check_receipt(
        &self,
        package: &TipPackage,
        req: &ReceiptRequest,
    ) -> Result<CheckedReceipt, Refusal> {
        let intake = self.intake();
        if req.inputs_hash.is_some() {
            return Err(not_taken(
                "inputs_hash",
                intake,
                "the node computes inputs_hash from the inputs",
            ));
        }
        if !req.shared_inputs.is_empty() {
            return Err(not_taken("shared_inputs", intake, "its inputs are clear"));
        }
        for (field, given) in [
            ("summand_commitments", req.summand_commitments.is_some()),
            ("sharing_digest", req.sharing_digest.is_some()),
        ] {
            if given {
                return Err(not_taken(
                    field,
                    intake,
                    "its inputs are clear, with no sharing",
                ));
            }
        }
        let missing = |field: &str| {
            Refusal::bad_request(format!(
                "field `{field}`: missing; {} signs over the requester's nonce",
                intake.name()
            ))
        };
        let user_nonce = req.user_nonce.ok_or_else(|| missing("user_nonce"))?.fr();
        let inputs = PlainFound::new(
            intake_inputs(&package.shape, &package.tip, &req.inputs)?,
            user_nonce,
        );
        Ok(CheckedReceipt {
            request_id: package.chain_request_id(req.namespace.fr(), &inputs),
            inputs_hash: inputs_hash(&inputs.inputs),
            inputs: inputs.inputs,
            user_nonce: Some(user_nonce),
            shares: vec![],
            vk_hash: package.vk_hash,
            stale_blocks: package.tip.stale_blocks(),
            signing: Arc::new(ReceiptPlain),
        })
    }

    /// A receipt intake row (a nonce and no shares) is sent with this node's
    /// signature: its inputs are clear, so the lost node can check and sign
    /// it again.
    fn resync_send(&self, row: &ReceiptRow) -> Option<ReceiptBody> {
        let nonce = row.user_nonce.filter(|_| row.shares.is_empty())?;
        Some(ReceiptBody {
            request_id: FieldHex(row.request_id),
            circuit: row.circuit.clone(),
            vk_hash: FieldHex(row.vk_hash),
            inputs: row.inputs.iter().copied().map(FieldHex).collect(),
            inputs_hash: FieldHex(row.inputs_hash),
            user_nonce: FieldHex(nonce),
            expiry_block: row.expiry_block,
            stale_blocks: row.stale_blocks,
            signature: row.signature,
        })
    }

    // Both neighbours' signatures must verify under their pinned sig keys
    // and the ids must hash right (`inputs_hash = poseidon2(inputs)`, the
    // chain request id from the namespace, vk_hash, inputs_hash and nonce).
    // The receipt nonce is derived from the key and the message
    // (crate::receipt), so the row signed again carries the signature this
    // node gave the requester when it first signed.
    fn resync_keep(
        &self,
        namespace: Fr,
        from_prev: &ReceiptBody,
        from_next: &ReceiptBody,
        [prev_pk, next_pk]: [Point; 2],
        keys: &NodeKeys,
    ) -> Option<ReceiptRow> {
        let n = from_next;
        let inputs: Vec<Fr> = n.inputs.iter().map(|f| f.fr()).collect();
        let (id, hash) = (n.request_id.fr(), n.inputs_hash.fr());
        let expiry = u32::try_from(n.expiry_block).ok()?;
        let signed = |pk: Point, sig: Signature| verify_receipt(pk, sig, id, hash, expiry);
        let checks = inputs_hash(&inputs) == hash
            && chain_request_id(namespace, n.vk_hash.fr(), &inputs, n.user_nonce.fr()) == id
            && signed(prev_pk, from_prev.signature)
            && signed(next_pk, n.signature);
        checks.then(|| ReceiptRow {
            request_id: id,
            circuit: n.circuit.clone(),
            vk_hash: n.vk_hash.fr(),
            inputs,
            inputs_hash: hash,
            user_nonce: Some(n.user_nonce.fr()),
            shares: vec![],
            expiry_block: n.expiry_block,
            stale_blocks: n.stale_blocks,
            signature: sign_receipt(keys.sig_scalar(), id, hash, expiry),
        })
    }
}

/// Receipt intake's receipt signs the inputs hash
/// ([`crate::receipt::receipt_message`]); its inputs are all clear,
/// so there is no envelope to check.
impl ReceiptSigning for ReceiptPlain {
    fn message(&self, receipt: &CheckedReceipt, expiry_block: u32) -> Fr {
        receipt_message(receipt.request_id, receipt.inputs_hash, expiry_block)
    }
}
