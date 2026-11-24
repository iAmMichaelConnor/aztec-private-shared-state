//! An in-memory Aztec node for tests: the block and log methods this crate
//! calls, over a chain whose tip a test moves and whose blocks it replaces.
//! A block's hash names its number and how often it was replaced, so a
//! replaced block (and every block after it) hashes differently. The node
//! answers four tips in the order a node keeps them (finalized <= proven <=
//! checkpointed <= proposed): the checkpointed tip follows the proposed one
//! unless a test holds it back; the proven tip is the test's; the finalized
//! tip trails it by one proof (each move of the proven tip finalizes the
//! one before) unless a test sets it. Logs are visible from their block on
//! and go with a replaced block; each sits alone in its transaction, the
//! next transaction of its block. Tag queries page at [`MAX_LOGS_PER_TAG`],
//! honour `afterLog`, `fromBlock` and `toBlock`, and refuse a
//! `referenceBlock` that is not on the current chain the way the node does.
//! [`super::MemoryChain`] answers these methods through it.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{Value, json};
use sidecar_core::Fr;
use sidecar_core::field::{fr_from_hex, fr_to_hex};

use crate::chain::logs::MAX_LOGS_PER_TAG;
use crate::chain::rpc::{RpcError, Transport};

#[derive(Clone, Debug)]
struct StoredLog {
    /// The emitting contract of a public log; `None` for a private log.
    contract: Option<Fr>,
    block: u64,
    tx_index: u64,
    tx_hash: Fr,
    data: Vec<Fr>,
}

#[derive(Clone, Debug, Default)]
struct Node {
    /// Successive answers of the tip; the last repeats.
    tips: Vec<u64>,
    tip_calls: usize,
    /// The checkpointed tip a test holds back; `None`: the proposed tip.
    checkpointed: Option<u64>,
    proven: u64,
    finalized: u64,
    /// The first block of each replacement.
    replaced: Vec<u64>,
    /// A replacement to make right after the next tips answer.
    replace_after_tips: Option<u64>,
    logs: Vec<StoredLog>,
    next_tx: u64,
    calls: BTreeMap<String, Vec<Value>>,
}

impl Node {
    fn tip(&self) -> u64 {
        self.tips[self.tip_calls.saturating_sub(1).min(self.tips.len() - 1)]
    }

    fn hash(&self, number: u64) -> Fr {
        let forks = self.replaced.iter().filter(|r| **r <= number).count() as u128;
        Fr::from((0xb10c_u128 << 96) | (forks << 64) | u128::from(number))
    }

    /// The four tips' numbers, in the node's order.
    fn tips_now(&self) -> [u64; 4] {
        let proposed = self.tip();
        let checkpointed = self.checkpointed.unwrap_or(proposed).min(proposed);
        let proven = self.proven.min(checkpointed);
        [proposed, checkpointed, proven, self.finalized.min(proven)]
    }

    fn replace_from(&mut self, from: u64) {
        self.replaced.push(from);
        self.logs.retain(|l| l.block < from);
    }
}

/// The in-memory node.
#[derive(Default)]
pub struct MemoryNode {
    node: Mutex<Node>,
}

impl Clone for MemoryNode {
    /// A copy that goes on alone from here: another node's view of the
    /// same chain, which a test moves on its own (three nodes that see a
    /// replacement at different times).
    fn clone(&self) -> Self {
        MemoryNode {
            node: Mutex::new(self.node.lock().unwrap().clone()),
        }
    }
}

impl MemoryNode {
    pub fn new(tip: u64) -> Self {
        let node = MemoryNode::default();
        node.set_tip(tip);
        node
    }

    /// The tip from now on.
    pub fn set_tip(&self, tip: u64) {
        self.script_tips(&[tip]);
    }

    /// Successive answers of the next tip reads; the last one repeats.
    pub fn script_tips(&self, tips: &[u64]) {
        let mut n = self.node.lock().unwrap();
        n.tips = tips.to_vec();
        n.tip_calls = 0;
    }

    /// The tip as the last tip read answered it (the first scripted one
    /// before any).
    pub fn tip(&self) -> u64 {
        self.node.lock().unwrap().tip()
    }

    /// The proven tip from now on; 0 until set. A move up finalizes the
    /// proven tip before it (the finalized tip trails by one proof); a move
    /// down (an L1 reorg that removes a proof) lowers the finalized tip to
    /// it at most.
    pub fn set_proven(&self, block: u64) {
        let mut n = self.node.lock().unwrap();
        if block > n.proven {
            n.finalized = n.proven;
        } else {
            n.finalized = n.finalized.min(block);
        }
        n.proven = block;
    }

    /// The finalized tip from now on (answered at most the proven tip).
    pub fn set_finalized(&self, block: u64) {
        self.node.lock().unwrap().finalized = block;
    }

    /// Hold the checkpointed tip at `block` (`None`: it follows the
    /// proposed tip, as it does until set).
    pub fn set_checkpointed(&self, block: Option<u64>) {
        self.node.lock().unwrap().checkpointed = block;
    }

    /// The four tips as the node answers them now: proposed, checkpointed,
    /// proven, finalized.
    pub fn tips(&self) -> [u64; 4] {
        self.node.lock().unwrap().tips_now()
    }

    /// The hash of block `number` on the current chain.
    pub fn hash(&self, number: u64) -> Fr {
        self.node.lock().unwrap().hash(number)
    }

    /// Replace block `from` and every block after it: each hashes anew and
    /// loses its logs (and [`super::MemoryChain`]'s storage written from
    /// it); the test then writes the replacement's.
    pub fn replace_from(&self, from: u64) {
        self.node.lock().unwrap().replace_from(from);
    }

    /// Replace block `from` and every block after it right after the next
    /// tips answer: a node that switches fork between a reader's tips read
    /// and its next call.
    pub fn replace_after_next_tips(&self, from: u64) {
        self.node.lock().unwrap().replace_after_tips = Some(from);
    }

    /// A public log `contract` emitted in `block`: `tag`, then `fields`.
    pub fn push_public(&self, contract: Fr, block: u64, tag: Fr, fields: &[Fr]) {
        self.push(Some(contract), block, tag, fields);
    }

    /// A private log in `block` under the siloed `tag`.
    pub fn push_private(&self, block: u64, tag: Fr, fields: &[Fr]) {
        self.push(None, block, tag, fields);
    }

    fn push(&self, contract: Option<Fr>, block: u64, tag: Fr, fields: &[Fr]) {
        let mut n = self.node.lock().unwrap();
        n.next_tx += 1;
        let tx_hash = Fr::from((0x7a_u128 << 64) | u128::from(n.next_tx));
        let tx_index = n.logs.iter().filter(|l| l.block == block).count() as u64;
        let mut data = vec![tag];
        data.extend_from_slice(fields);
        n.logs.push(StoredLog {
            contract,
            block,
            tx_index,
            tx_hash,
            data,
        });
    }

    /// How many calls of `method` the node answered.
    pub fn calls(&self, method: &str) -> usize {
        self.node
            .lock()
            .unwrap()
            .calls
            .get(method)
            .map_or(0, Vec::len)
    }

    /// The query object (`params[0]`) of the `i`-th call of `method`.
    pub fn query(&self, method: &str, i: usize) -> Value {
        self.node.lock().unwrap().calls[method][i][0].clone()
    }

    /// The query object of the last call of `method`.
    pub fn last_query(&self, method: &str) -> Option<Value> {
        let n = self.node.lock().unwrap();
        n.calls.get(method)?.last().map(|p| p[0].clone())
    }

    /// The answer to `method`, or `None` for a method this node does not
    /// serve ([`super::MemoryChain`] answers the rest).
    pub fn answer(&self, method: &str, params: &Value) -> Option<Result<Value, RpcError>> {
        let mut n = self.node.lock().unwrap();
        let known = matches!(
            method,
            "node_getChainTips"
                | "node_getBlockNumber"
                | "node_getBlockData"
                | "node_getPublicLogsByTags"
                | "node_getPrivateLogsByTags"
        );
        if !known {
            return None;
        }
        n.calls
            .entry(method.to_string())
            .or_default()
            .push(params.clone());
        Some(match method {
            "node_getChainTips" | "node_getBlockNumber" => {
                n.tip_calls += 1;
                let tip = n.tip();
                if method == "node_getBlockNumber" {
                    return Some(Ok(json!(tip)));
                }
                let [proposed, checkpointed, proven, finalized] = n.tips_now();
                let answer = {
                    let id = |b: u64| json!({"number": b, "hash": fr_to_hex(n.hash(b))});
                    let tier = |b: u64| json!({"block": id(b), "checkpoint": {"number": b, "hash": fr_to_hex(n.hash(b))}});
                    json!({
                        "proposed": id(proposed),
                        "checkpointed": tier(checkpointed),
                        "proven": tier(proven),
                        "finalized": tier(finalized),
                    })
                };
                if let Some(from) = n.replace_after_tips.take() {
                    n.replace_from(from);
                }
                Ok(answer)
            }
            "node_getBlockData" => {
                let number = params[0].as_u64().unwrap_or(u64::MAX);
                Ok(if number > n.tip() {
                    Value::Null
                } else {
                    json!({
                        "blockHash": fr_to_hex(n.hash(number)),
                        "header": {"globalVariables": {
                            "blockNumber": number,
                            "timestamp": format!("0x{:x}", super::block_timestamp(number)),
                        }},
                    })
                })
            }
            _ => logs(&n, method, &params[0]),
        })
    }
}

fn logs(n: &Node, method: &str, q: &Value) -> Result<Value, RpcError> {
    // the node's code for a refused call (foundation `SafeJsonRpcServer`)
    let refuse = |message: String| RpcError::Node {
        code: -32702,
        message,
    };
    let f = |v: &Value| fr_from_hex(v.as_str().unwrap_or("")).map_err(RpcError::Malformed);
    let contract = match method {
        "node_getPublicLogsByTags" => Some(f(&q["contractAddress"])?),
        _ => None,
    };
    let mut upper = q["toBlock"].as_u64().unwrap_or(u64::MAX);
    if let Some(reference) = q.get("referenceBlock") {
        let hash = f(reference)?;
        let Some(number) = (0..=n.tip()).rev().find(|b| n.hash(*b) == hash) else {
            return Err(refuse(format!(
                "Reference block {} not found in the node. This might indicate a reorg has occurred.",
                fr_to_hex(hash)
            )));
        };
        upper = upper.min(number + 1);
    }
    let from = q["fromBlock"].as_u64().unwrap_or(1);
    let limit = q["limitPerTag"]
        .as_u64()
        .map_or(MAX_LOGS_PER_TAG, |l| l as usize);
    let mut matching: Vec<&StoredLog> = n
        .logs
        .iter()
        .filter(|l| l.contract == contract && l.block < upper && l.block <= n.tip())
        .collect();
    matching.sort_by_key(|l| (l.block, l.tx_index));
    let per_tag: Vec<Value> = q["tags"]
        .as_array()
        .ok_or_else(|| RpcError::Malformed("no tags".into()))?
        .iter()
        .map(|entry| {
            let (tag, after) = match entry {
                Value::String(_) => (f(entry)?, None),
                _ => {
                    let a = &entry["afterLog"];
                    let pos = (
                        a["blockNumber"].as_u64().unwrap_or(0),
                        a["txIndexWithinBlock"].as_u64().unwrap_or(0),
                        a["logIndexWithinTx"].as_u64().unwrap_or(0),
                    );
                    (f(&entry["tag"])?, Some(pos))
                }
            };
            let page: Vec<Value> = matching
                .iter()
                .filter(|l| l.data[0] == tag)
                .filter(|l| match after {
                    Some(pos) => (l.block, l.tx_index, 0) > pos,
                    None => l.block >= from,
                })
                .take(limit)
                .map(|l| {
                    json!({
                        "logData": l.data.iter().map(|v| fr_to_hex(*v)).collect::<Vec<_>>(),
                        "blockNumber": l.block,
                        "blockHash": fr_to_hex(n.hash(l.block)),
                        "blockTimestamp": l.block * 6,
                        "txHash": fr_to_hex(l.tx_hash),
                        "txIndexWithinBlock": l.tx_index,
                        "logIndexWithinTx": 0,
                    })
                })
                .collect();
            Ok(Value::Array(page))
        })
        .collect::<Result<_, RpcError>>()?;
    Ok(Value::Array(per_tag))
}

impl Transport for MemoryNode {
    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.answer(method, &params).unwrap_or_else(|| {
            Err(RpcError::Node {
                code: -32601,
                message: format!("unknown method {method}"),
            })
        })
    }
}
