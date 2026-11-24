//! On-chain intake (`intake: onchain`): the request log carries the inputs in
//! the clear and `user_nonce`. The log is the namespace contract's public log
//! under `compute_log_tag(chain_request_id, REQUEST_DOMAIN)`
//! ([`request_log`]).

use super::*;
use crate::chain::LogRef;
use crate::chain::layout::request_log_tag;

/// The on-chain request log of one chain request: its fields after the tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestInputs {
    pub chain_request_id: Fr,
    pub fields: Vec<Fr>,
    pub log: LogRef,
}

/// The on-chain intake layout of a request log:
/// the app inputs in ABI order, then `user_nonce`; no requester.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlainInputs<'a> {
    pub inputs: &'a [Fr],
    pub user_nonce: Fr,
}

impl RequestInputs {
    // The non-secret-shared request log layout: the fields after the
    // tag are the app inputs in ABI order, then `user_nonce`
    // (`PlainRequest::serialize()`, written down in
    // noir/pss_public_contract/src/intake.nr; each case of
    // testvectors/chain_request_id.json carries one), what the library's
    // `append_onchain` emits; `fields` keeps the raw log, and the split needs no
    // input count, so one reader serves every app. Secret-shared on-chain intake reads a
    // private log of its own, not this split.
    /// The fields split by the non-secret-shared layout; refused when empty.
    pub fn plain(&self) -> Result<PlainInputs<'_>, ReadError> {
        let Some((user_nonce, inputs)) = self.fields.split_last() else {
            return Err(ReadError::Malformed {
                method: "node_getPublicLogsByTags",
                detail: "a non-secret-shared request log needs user_nonce; it has no fields".into(),
            });
        };
        Ok(PlainInputs {
            inputs,
            user_nonce: *user_nonce,
        })
    }
}

// Several logs under one tag from the namespace contract: the request log
// taken is the earliest (the sealed-thirds log, the latest). The library's
// `append` reverts on a repeated request id, so the log exists at most once
// per chain request id and the rule never decides anything for the library's
// contracts; it only fixes an answer for a contract that emits more.
/// The on-chain request log of `chain_request_id`, tagged
/// `compute_log_tag(chain_request_id, REQUEST_DOMAIN)`, as the namespace
/// contract emitted it, read at `at`'s snapshot; `None` before intake.
pub async fn request_log(
    at: &dyn ChainLogs,
    chain_request_id: Fr,
) -> Result<Option<RequestInputs>, ReadError> {
    let logs = at.public_logs(request_log_tag(chain_request_id)).await?;
    Ok(logs.into_iter().next().map(|(fields, log)| RequestInputs {
        chain_request_id,
        fields,
        log,
    }))
}

/// The inputs of a non-secret-shared request log.
fn logged_inputs(log: &RequestInputs) -> Result<PlainFound, ReadError> {
    let p = log.plain()?;
    Ok(PlainFound::new(p.inputs.to_vec(), p.user_nonce))
}

/// On-chain intake (`intake: onchain`): the request log carries the inputs,
/// split by [`RequestInputs::plain`].
#[derive(Clone, Copy, Debug)]
pub struct OnchainPlain;

impl IntakeSource for OnchainPlain {
    fn intake(&self) -> QueuedIntake {
        QueuedIntake::Onchain
    }

    fn reads_nodes(&self) -> bool {
        false
    }

    fn find<'a>(
        &'a self,
        at: &'a dyn IntakeLookup,
        package: &'a TipPackage,
        chain: Fr,
    ) -> TipFuture<'a, Result<Option<Found>, ReadError>> {
        Box::pin(async move {
            let Some(log) = request_log(at, chain).await? else {
                return Ok(None);
            };
            Ok(logged_inputs(&log)
                .ok()
                .filter(|inputs| package.chain_request_id(at.namespace(), inputs) == chain)
                .map(found))
        })
    }

    fn read_chain<'a>(
        &'a self,
        at: &'a dyn ChainLogs,
        chain: Fr,
    ) -> TipFuture<'a, Result<ChainHeld, ReadError>> {
        Box::pin(async move {
            Ok(request_log(at, chain)
                .await?
                .map_or_else(ChainHeld::none, ChainHeld::new))
        })
    }

    fn node_view(&self, at: &NodeInputs<'_>) -> Result<Found, Refusal> {
        let log = at.held.get::<RequestInputs>().ok_or_else(|| {
            refused(format!(
                "no request log of chain request {} on chain at block {}",
                fr_to_hex(at.chain_request_id),
                at.block
            ))
        })?;
        Ok(found(logged_inputs(log).map_err(refused)?))
    }
}
