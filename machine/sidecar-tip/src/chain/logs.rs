//! Tag queries, the way the PXE pages them (stdlib
//! `logs/query_all_logs_by_tags.js`): one call per group of at most
//! [`MAX_TAGS_PER_CALL`] tags; a tag whose page is full
//! ([`MAX_LOGS_PER_TAG`] logs) is asked again with `afterLog` set to its last
//! log, until a short page, at most [`MAX_PAGES_PER_TAG`] pages per tag
//! (more is a broken or hostile answer, refused). Every call names the same `referenceBlock`, the
//! hash of the followed block the logs are read at, so every page reads one
//! chain; a node that no longer has that block answers "Reference block ...
//! not found", which is a replaced block ([`ReadError::ReferenceGone`]).
//! The node first waits for a hash it has not seen
//! (`rpcUnseenBlockByHashWaitMs`, 3 s by default), so that answer is slow.
//!
//! RPC methods (Aztec node 6.0.0, `@aztec-labs/stdlib`
//! `interfaces/aztec-node.d.ts`, `logs/logs_query.js`; sidecar-tip's
//! `tests/fixtures/logs.json` records a local network's answers):
//! - `node_getPublicLogsByTags([{contractAddress, tags, referenceBlock,
//!   fromBlock?}])`: the logs `contractAddress` emitted, matched against the
//!   emitting address the AVM sets on each public log, with the tag in field
//!   0.
//! - `node_getPrivateLogsByTags([{tags, referenceBlock, fromBlock?}])`: the
//!   private logs whose field 0 is the siloed tag.
//!
//! Each answers one list of logs per tag, in input order and chain order:
//! `{logData, blockNumber, blockHash, blockTimestamp, txHash,
//! txIndexWithinBlock, logIndexWithinTx}`.

use serde_json::{Map, Value, json};
use sidecar_core::Fr;
use sidecar_core::field::fr_to_hex;

use super::ReadError;
use super::follow::BlockId;
use super::rpc::{RpcError, Transport, call, field, malformed, number};

/// The node's page size per tag (stdlib `MAX_LOGS_PER_TAG`).
pub const MAX_LOGS_PER_TAG: usize = 20;
/// The most tags one call takes (stdlib `MAX_RPC_LEN`).
pub const MAX_TAGS_PER_CALL: usize = 100;
// Operator knob: DESIGN.md, "Configuration reference" (logs per tag; no
// knob). Every tag the tip reads holds a log or a few per chain request (the
// request log, the sealed-thirds log, a secret-shared request's private
// logs), so 50 full pages (1,000 logs) under one tag is a node that keeps
// answering full pages; the read stops there instead of paging for ever.
/// The most pages one tag is read in.
pub const MAX_PAGES_PER_TAG: usize = 50;

/// Which logs a query reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Public logs `contract` emitted, by tag.
    Public { contract: Fr },
    /// Private logs, by siloed tag.
    Private,
}

impl Source {
    fn method(self) -> &'static str {
        match self {
            Source::Public { .. } => "node_getPublicLogsByTags",
            Source::Private => "node_getPrivateLogsByTags",
        }
    }
}

/// One log as the node returned it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    /// Every field, the tag first.
    pub data: Vec<Fr>,
    pub block: u64,
    pub block_hash: Fr,
    pub tx_hash: String,
    pub tx_index: u64,
    pub log_index: u64,
}

impl Log {
    pub fn tag(&self) -> Fr {
        self.data[0]
    }

    /// The fields after the tag.
    pub fn fields(&self) -> &[Fr] {
        &self.data[1..]
    }

    /// Chain order, the order of the node's log index and of `afterLog`.
    pub fn position(&self) -> (u64, u64, u64) {
        (self.block, self.tx_index, self.log_index)
    }
}

/// A tag still paging: its index into the query's tags and the position of
/// the last log it returned, which the next page starts after.
type Paging = (usize, Option<(u64, u64, u64)>);

/// Every log under `tag` up to `reference`.
pub async fn logs_by_tag<T: Transport + ?Sized>(
    node: &T,
    source: Source,
    tag: Fr,
    reference: BlockId,
) -> Result<Vec<Log>, ReadError> {
    let mut per_tag = logs_by_tags(node, source, &[tag], reference, None).await?;
    Ok(per_tag.pop().unwrap_or_default())
}

/// Every log under each of `tags` from block `from_block` (from genesis when
/// `None`) up to `reference`: one list per tag, in `tags` order, each in
/// chain order.
pub async fn logs_by_tags<T: Transport + ?Sized>(
    node: &T,
    source: Source,
    tags: &[Fr],
    reference: BlockId,
    from_block: Option<u64>,
) -> Result<Vec<Vec<Log>>, ReadError> {
    let method = source.method();
    let mut out: Vec<Vec<Log>> = vec![Vec::new(); tags.len()];
    let mut taken = vec![0usize; tags.len()];
    for start in (0..tags.len()).step_by(MAX_TAGS_PER_CALL) {
        let end = tags.len().min(start + MAX_TAGS_PER_CALL);
        let mut active: Vec<Paging> = (start..end).map(|i| (i, None)).collect();
        while !active.is_empty() {
            let entries: Vec<Value> = active
                .iter()
                .map(|&(i, after)| match after {
                    None => json!(fr_to_hex(tags[i])),
                    Some((block, tx, log)) => json!({
                        "tag": fr_to_hex(tags[i]),
                        "afterLog": {
                            "blockNumber": block,
                            "txIndexWithinBlock": tx,
                            "logIndexWithinTx": log,
                        },
                    }),
                })
                .collect();
            let mut query = Map::new();
            if let Source::Public { contract } = source {
                query.insert("contractAddress".into(), json!(fr_to_hex(contract)));
            }
            query.insert("tags".into(), Value::Array(entries));
            query.insert("referenceBlock".into(), json!(fr_to_hex(reference.hash)));
            if let Some(from) = from_block {
                query.insert("fromBlock".into(), json!(from));
            }
            let answer = match call(node, method, json!([query])).await {
                Err(ReadError::Rpc {
                    error: RpcError::Node { message, .. },
                    ..
                }) if reference_gone(&message) => {
                    return Err(ReadError::ReferenceGone {
                        block: reference.number,
                    });
                }
                other => other?,
            };
            let pages = answer
                .as_array()
                .filter(|a| a.len() == active.len())
                .ok_or_else(|| {
                    malformed(
                        method,
                        format!("not one list of logs per tag for {} tags", active.len()),
                    )
                })?;
            let mut next = Vec::new();
            for (&(i, after), page) in active.iter().zip(pages) {
                let page = page
                    .as_array()
                    .ok_or_else(|| malformed(method, "a tag's logs are not a list"))?;
                let mut last = after;
                for value in page {
                    let log = parse_log(method, value)?;
                    // field 0 is the tag; another value is a broken answer,
                    // not a log to filter out
                    if log.tag() != tags[i] {
                        return Err(malformed(
                            method,
                            "a log whose field 0 is not the queried tag",
                        ));
                    }
                    if log.block > reference.number {
                        return Err(malformed(
                            method,
                            format!(
                                "a log of block {} past the reference block {}",
                                log.block, reference.number
                            ),
                        ));
                    }
                    if last.is_some_and(|l| log.position() <= l) {
                        return Err(malformed(method, "logs out of chain order"));
                    }
                    last = Some(log.position());
                    out[i].push(log);
                }
                taken[i] += 1;
                if page.len() >= MAX_LOGS_PER_TAG {
                    if taken[i] >= MAX_PAGES_PER_TAG {
                        return Err(malformed(
                            method,
                            format!(
                                "more than {} logs under one tag ({MAX_PAGES_PER_TAG} full pages)",
                                MAX_PAGES_PER_TAG * MAX_LOGS_PER_TAG
                            ),
                        ));
                    }
                    next.push((i, last));
                }
            }
            active = next;
        }
    }
    Ok(out)
}

/// The node's refusal of a query whose reference block it does not have
/// (aztec-node `NodeLogsProvider`, archiver `log_store`: error -32702,
/// "Reference block {hash} not found in the node. This might indicate a reorg
/// has occurred.").
fn reference_gone(message: &str) -> bool {
    message.contains("Reference block") && message.contains("not found")
}

fn parse_log(method: &'static str, value: &Value) -> Result<Log, ReadError> {
    let data = value
        .get("logData")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(method, "a log without logData"))?
        .iter()
        .map(|v| field(method, v))
        .collect::<Result<Vec<_>, _>>()?;
    if data.is_empty() {
        return Err(malformed(method, "a log without a tag"));
    }
    let tx_hash = value
        .get("txHash")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(method, "a log without txHash"))?
        .to_string();
    Ok(Log {
        data,
        block: number(method, value, "blockNumber")?,
        block_hash: field(method, value.get("blockHash").unwrap_or(&Value::Null))?,
        tx_hash,
        tx_index: number(method, value, "txIndexWithinBlock")?,
        log_index: number(method, value, "logIndexWithinTx")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MemoryNode;

    fn at(node: &MemoryNode) -> BlockId {
        let number = node.tip();
        BlockId {
            number,
            hash: node.hash(number),
        }
    }

    #[tokio::test]
    async fn a_tag_with_more_than_a_page_is_paged_with_after_log() {
        let node = MemoryNode::new(60);
        let ns = Fr::from(0xabcu64);
        let tag = Fr::from(7u64);
        // 45 logs under one tag over three blocks, and others around them
        for i in 0..45u64 {
            node.push_public(ns, 10 + i / 20, tag, &[Fr::from(i)]);
        }
        node.push_public(ns, 11, Fr::from(8u64), &[Fr::from(99u64)]);
        node.push_public(Fr::from(0xdefu64), 11, tag, &[Fr::from(98u64)]);
        let logs = logs_by_tag(&node, Source::Public { contract: ns }, tag, at(&node))
            .await
            .unwrap();
        assert_eq!(
            logs.iter().map(|l| l.fields()[0]).collect::<Vec<_>>(),
            (0..45u64).map(Fr::from).collect::<Vec<_>>()
        );
        // pages of 20, 20 and 5
        assert_eq!(node.calls("node_getPublicLogsByTags"), 3);
        assert!(logs.windows(2).all(|w| w[0].position() < w[1].position()));
        assert_eq!(logs[0].block_hash, node.hash(10));

        // a page of exactly 20 asks once more and gets an empty page
        let node = MemoryNode::new(60);
        for i in 0..20u64 {
            node.push_private(12, tag, &[Fr::from(i)]);
        }
        let logs = logs_by_tag(&node, Source::Private, tag, at(&node))
            .await
            .unwrap();
        assert_eq!(logs.len(), 20);
        assert_eq!(node.calls("node_getPrivateLogsByTags"), 2);
    }

    // A node that keeps answering full pages is refused once one tag has
    // taken `MAX_PAGES_PER_TAG` of them, instead of being paged for ever.
    #[tokio::test]
    async fn a_tag_is_read_in_at_most_max_pages_per_tag() {
        let node = MemoryNode::new(60);
        let tag = Fr::from(7u64);
        let full = (MAX_PAGES_PER_TAG * MAX_LOGS_PER_TAG) as u64;
        for i in 0..full - 1 {
            node.push_private(10, tag, &[Fr::from(i)]);
        }
        let logs = logs_by_tag(&node, Source::Private, tag, at(&node))
            .await
            .unwrap();
        assert_eq!(logs.len() as u64, full - 1);
        node.push_private(11, tag, &[Fr::from(full)]);
        let err = logs_by_tag(&node, Source::Private, tag, at(&node))
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("more than 1000 logs under one tag"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn more_than_a_hundred_tags_take_several_calls() {
        let node = MemoryNode::new(60);
        let tags: Vec<Fr> = (1..=150u64).map(Fr::from).collect();
        for t in &tags {
            node.push_private(5, *t, &[*t + Fr::from(1u64)]);
        }
        let per_tag = logs_by_tags(&node, Source::Private, &tags, at(&node), None)
            .await
            .unwrap();
        assert_eq!(per_tag.len(), 150);
        assert!(
            per_tag
                .iter()
                .zip(&tags)
                .all(|(logs, t)| logs.len() == 1 && logs[0].tag() == *t)
        );
        assert_eq!(node.calls("node_getPrivateLogsByTags"), 2);
        // from a block on
        node.push_private(9, tags[0], &[Fr::from(0u64)]);
        let later = logs_by_tags(&node, Source::Private, &tags[..1], at(&node), Some(6))
            .await
            .unwrap();
        assert_eq!(later[0].iter().map(|l| l.block).collect::<Vec<_>>(), [9]);
    }

    #[tokio::test]
    async fn the_reference_block_bounds_the_logs_and_a_replaced_one_is_gone() {
        let node = MemoryNode::new(30);
        let ns = Fr::from(1u64);
        let tag = Fr::from(2u64);
        node.push_public(ns, 20, tag, &[]);
        node.push_public(ns, 25, tag, &[]);
        let at20 = BlockId {
            number: 20,
            hash: node.hash(20),
        };
        let logs = logs_by_tag(&node, Source::Public { contract: ns }, tag, at20)
            .await
            .unwrap();
        assert_eq!(logs.iter().map(|l| l.block).collect::<Vec<_>>(), [20]);
        node.replace_from(20);
        assert_eq!(
            logs_by_tag(&node, Source::Public { contract: ns }, tag, at20).await,
            Err(ReadError::ReferenceGone { block: 20 })
        );
    }
}
