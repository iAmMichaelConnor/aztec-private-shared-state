//! Transports for tests of the reader and of its consumers (the scheduler,
//! the chain verifier): [`FixtureTransport`] answers from JSON-RPC bodies
//! recorded from a real node, and [`MemoryChain`] is an in-memory Aztec node
//! a test writes a queue, slots, logs and getter results into; its blocks,
//! block hashes and logs are the in-memory node's ([`MemoryChain::node`]).

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{Value, json};
use sidecar_core::Fr;
use sidecar_core::field::{fr_from_hex, fr_to_hex};

use crate::chain::layout::QueueLayout;
use crate::chain::rpc::{RpcError, Transport, response_result};
use crate::chain::simulate::{SimulatedCall, base64};
use crate::testing::MemoryNode;

/// Answers each call with a recorded response whose method and params equal
/// the call's. A fixture file is `{"calls": [{"method", "params",
/// "response"}]}`; a `data` param written as `{"zeros_except": {"len",
/// "runs": [[offset, hex]]}}` stands for the base64 of those bytes. Calls
/// that match several entries take them in recorded order, the last one
/// repeating. A call with no recorded answer fails with a transport error
/// naming it, so a test also checks the request the reader sends.
pub struct FixtureTransport {
    calls: Vec<(String, Value, Value)>,
    used: Mutex<Vec<bool>>,
}

impl FixtureTransport {
    pub fn new(fixture: &Value) -> Self {
        let calls: Vec<(String, Value, Value)> = fixture["calls"]
            .as_array()
            .expect("a fixture has calls")
            .iter()
            .map(|c| {
                (
                    c["method"].as_str().expect("method").to_string(),
                    expand(c["params"].clone()),
                    c["response"].clone(),
                )
            })
            .collect();
        let used = Mutex::new(vec![false; calls.len()]);
        FixtureTransport { calls, used }
    }

    pub fn from_json(text: &str) -> Self {
        Self::new(&serde_json::from_str(text).expect("fixture JSON"))
    }

    /// Recorded calls never asked for.
    pub fn unused(&self) -> Vec<String> {
        let used = self.used.lock().unwrap();
        self.calls
            .iter()
            .zip(used.iter())
            .filter(|(_, u)| !**u)
            .map(|((m, p, _), _)| format!("{m} {p}"))
            .collect()
    }
}

fn expand(value: Value) -> Value {
    match value {
        Value::Object(map) if map.contains_key("zeros_except") => {
            let spec = &map["zeros_except"];
            let mut bytes = vec![0u8; spec["len"].as_u64().unwrap() as usize];
            for run in spec["runs"].as_array().unwrap() {
                let at = run[0].as_u64().unwrap() as usize;
                let hex = run[1].as_str().unwrap();
                for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
                    bytes[at + i] =
                        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
                }
            }
            Value::String(base64(&bytes))
        }
        Value::Object(map) => Value::Object(map.into_iter().map(|(k, v)| (k, expand(v))).collect()),
        Value::Array(items) => Value::Array(items.into_iter().map(expand).collect()),
        other => other,
    }
}

impl Transport for FixtureTransport {
    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let matching: Vec<usize> = self
            .calls
            .iter()
            .enumerate()
            .filter(|(_, (m, p, _))| m == method && *p == params)
            .map(|(i, _)| i)
            .collect();
        let Some(&last) = matching.last() else {
            return Err(RpcError::Transport(format!(
                "no recorded answer for {method} {params}"
            )));
        };
        let mut used = self.used.lock().unwrap();
        let pick = matching.iter().copied().find(|i| !used[*i]).unwrap_or(last);
        used[pick] = true;
        response_result(self.calls[pick].2.clone())
    }
}

/// The contract class an instance runs on a [`MemoryChain`] unless a test
/// sets another ([`MemoryChain::set_class`]): the class the test contract
/// manifests name (sidecar-core `testing::TipFacts`).
pub const MEMORY_CLASS_ID: u64 = 0xc1a55;

#[derive(Clone, Default)]
struct Chain {
    /// Each slot's writes by the block each was written at, with that
    /// block's hash then: a write stands while its block does, so a
    /// replacement of its block takes it back.
    storage: BTreeMap<(Fr, Fr), BTreeMap<u64, (Fr, Fr)>>,
    calls: BTreeMap<(Fr, Vec<Fr>), Result<Vec<Fr>, String>>,
    /// Each instance's current class, where a test set one (`None`: no
    /// instance published); every other address runs [`MEMORY_CLASS_ID`].
    classes: BTreeMap<Fr, Option<Fr>>,
}

/// An in-memory Aztec node: the methods the reader calls, over storage,
/// logs and getter results a test sets. The tip, the block hashes, the four
/// tips and the logs are [`MemoryNode`]'s (a log is visible from its block
/// on, tag queries page and take a reference block). Storage is kept per
/// block: a slot written with [`Self::set_storage`] has one value at every
/// block; one written with [`Self::set_storage_at`] has that value from its
/// block on, while that block is on the chain, so a replacement of the
/// block rewinds the slot to what the blocks before it hold. Storage is
/// readable at any block up to the tip, by number or by number and hash
/// (refused, as the node refuses it, when the hash is not that block's on
/// the chain); a simulation runs on the tip and answers the result set for
/// its contract and calldata; every address holds an instance of
/// [`MEMORY_CLASS_ID`] unless [`Self::set_class`] says otherwise. A copy
/// ([`Self::copy`]) is another node's view, which a test moves on its own.
pub struct MemoryChain {
    chain: Mutex<Chain>,
    node: MemoryNode,
}

impl MemoryChain {
    pub fn new(tip: u64) -> Self {
        MemoryChain {
            chain: Mutex::default(),
            node: MemoryNode::new(tip),
        }
    }

    /// A copy of this chain that goes on alone from here: another node's
    /// view, which a test moves (and replaces blocks of) on its own.
    pub fn copy(&self) -> Self {
        MemoryChain {
            chain: Mutex::new(self.chain.lock().unwrap().clone()),
            node: self.node.clone(),
        }
    }

    /// The blocks and logs: to replace a block, push a private log, or count
    /// the queries a test made.
    pub fn node(&self) -> &MemoryNode {
        &self.node
    }

    /// The tip from now on.
    pub fn set_tip(&self, tip: u64) {
        self.node.set_tip(tip);
    }

    /// Successive answers of the next tip reads; the last one repeats.
    pub fn script_tips(&self, tips: &[u64]) {
        self.node.script_tips(tips);
    }

    fn tip(&self) -> u64 {
        self.node.tip()
    }

    /// The slot's value at every block, replacing what it held.
    pub fn set_storage(&self, contract: Fr, slot: Fr, value: Fr) {
        let at = self.node.hash(0);
        self.chain
            .lock()
            .unwrap()
            .storage
            .insert((contract, slot), BTreeMap::from([(0, (value, at))]));
    }

    /// The slot's value from `block` on, while `block` stays on the chain;
    /// the blocks before it keep theirs.
    pub fn set_storage_at(&self, block: u64, contract: Fr, slot: Fr, value: Fr) {
        let at = self.node.hash(block);
        self.chain
            .lock()
            .unwrap()
            .storage
            .entry((contract, slot))
            .or_default()
            .insert(block, (value, at));
    }

    /// The slot's value at `block` on the current chain: the latest write
    /// at or below it whose block is still the one it was written at.
    pub fn storage_at(&self, block: u64, contract: Fr, slot: Fr) -> Fr {
        let c = self.chain.lock().unwrap();
        c.storage
            .get(&(contract, slot))
            .and_then(|writes| {
                writes
                    .range(..=block)
                    .rev()
                    .find(|(b, (_, at))| self.node.hash(**b) == *at)
                    .map(|(_, (v, _))| *v)
            })
            .unwrap_or_default()
    }

    /// The block the block parameter `at` names: refused, as the node
    /// refuses it, when it is past the tip or names a hash that is not its
    /// block's on the chain.
    fn resolve(&self, at: &Value) -> Result<u64, RpcError> {
        let block = at["number"].as_u64().unwrap_or(u64::MAX);
        // the node resolves a block given by hash by its hash
        self.pinned(at)?;
        if block > self.tip() {
            return Err(refused(format!(
                "Block not found for number={block} when resolving query."
            )));
        }
        Ok(block)
    }

    /// Refused when the block parameter `at` carries a hash that is not its
    /// block's on the chain (the node's answer to a replaced anchor block).
    fn pinned(&self, at: &Value) -> Result<(), RpcError> {
        let Some(hash) = at.get("hash") else {
            return Ok(());
        };
        let hash = fr_from_hex(hash.as_str().unwrap_or("")).map_err(RpcError::Malformed)?;
        let block = at["number"].as_u64().unwrap_or(u64::MAX);
        if block > self.tip() || self.node.hash(block) != hash {
            return Err(refused(format!(
                "Block hash {} not found when resolving query. If the node API has been queried \
                 with anchor block hash possibly a reorg has occurred.",
                fr_to_hex(hash)
            )));
        }
        Ok(())
    }

    /// The current class of the instance at `contract` from now on (`None`:
    /// no instance is published there).
    pub fn set_class(&self, contract: Fr, class: Option<Fr>) {
        self.chain.lock().unwrap().classes.insert(contract, class);
    }

    /// Writes a queue: `requests[i]` for each id from index 0, `tail` the
    /// id count, `head` {`head`, `since`}.
    pub fn write_queue(
        &self,
        contract: Fr,
        layout: QueueLayout,
        ids: &[Fr],
        head: u64,
        since: u64,
    ) {
        for (i, id) in ids.iter().enumerate() {
            self.set_storage(contract, layout.request(i as u64), *id);
        }
        self.set_storage(contract, layout.tail(), Fr::from(ids.len() as u64));
        self.set_storage(contract, layout.head_index(), Fr::from(head));
        self.set_storage(contract, layout.head_since(), Fr::from(since));
    }

    /// A public log `contract` emitted in `block`: `tag`, then `fields`.
    pub fn push_log(&self, contract: Fr, block: u64, tag: Fr, fields: &[Fr]) {
        self.node.push_public(contract, block, tag, fields);
    }

    /// What a static call of `signature` with `args` on `contract` returns,
    /// or `Err(message)` for a revert.
    pub fn set_call(
        &self,
        contract: Fr,
        signature: &str,
        args: &[Fr],
        result: Result<Vec<Fr>, String>,
    ) {
        let calldata = SimulatedCall::new(Fr::from(0u64), contract, signature, args).calldata;
        self.chain
            .lock()
            .unwrap()
            .calls
            .insert((contract, calldata), result);
    }

    fn answer(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        if let Some(answer) = self.node.answer(method, params) {
            return answer;
        }
        let refuse = |message: String| RpcError::Node {
            code: -32702,
            message,
        };
        let f = |v: &Value| fr_from_hex(v.as_str().unwrap_or("")).map_err(RpcError::Malformed);
        match method {
            "node_getPublicStorageAt" => {
                let block = self.resolve(&params[0])?;
                let value = self.storage_at(block, f(&params[1])?, f(&params[2])?);
                Ok(json!(fr_to_hex(value)))
            }
            "node_getContract" => {
                self.pinned(&params[1])?;
                let contract = f(&params[0])?;
                let class = self
                    .chain
                    .lock()
                    .unwrap()
                    .classes
                    .get(&contract)
                    .copied()
                    .unwrap_or(Some(Fr::from(MEMORY_CLASS_ID)));
                Ok(match class {
                    Some(class) => json!({
                        "address": fr_to_hex(contract),
                        "currentContractClassId": fr_to_hex(class),
                        "originalContractClassId": fr_to_hex(class),
                    }),
                    None => Value::Null,
                })
            }
            "node_simulatePublicCalls" => {
                let tx = &params[0];
                let calldata: Vec<Fr> = tx["publicFunctionCalldata"][0]["values"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| fr_from_hex(v.as_str().unwrap()).unwrap())
                    .collect();
                let tip = self.tip();
                let c = self.chain.lock().unwrap();
                let found = c.calls.iter().find(|((contract, data), _)| {
                    *data == calldata && tx_names_contract(tx, *contract)
                });
                let globals = json!({"blockNumber": tip + 1});
                match found {
                    Some((_, Ok(values))) => Ok(json!({
                        "globalVariables": globals,
                        "publicReturnValues": [{"values": values.iter().map(|v| fr_to_hex(*v)).collect::<Vec<_>>(), "nested": []}],
                    })),
                    Some((_, Err(message))) => Ok(json!({
                        "globalVariables": globals,
                        "revertReason": {"originalMessage": message},
                        "publicReturnValues": [{"values": [], "nested": []}],
                    })),
                    None => Ok(json!({
                        "globalVariables": globals,
                        "revertReason": {"originalMessage": "no such function"},
                        "publicReturnValues": [{"values": [], "nested": []}],
                    })),
                }
            }
            _ => Err(refuse(format!("unknown method {method}"))),
        }
    }
}

/// The node's refusal of a call (foundation `SafeJsonRpcServer`'s code).
fn refused(message: String) -> RpcError {
    RpcError::Node {
        code: -32702,
        message,
    }
}

/// Whether the simulated transaction's call request names `contract` (the
/// address sits at a fixed offset of the tail bytes; `crate::chain::simulate`).
fn tx_names_contract(tx: &Value, contract: Fr) -> bool {
    let bytes = unbase64(tx["data"].as_str().unwrap_or(""));
    const CONTRACT: usize = 79_605;
    bytes.len() == crate::chain::simulate::TAIL_LEN
        && bytes[CONTRACT..CONTRACT + 32] == sidecar_core::field::fr_to_be_bytes(contract)[..]
}

fn unbase64(text: &str) -> Vec<u8> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        _ => 63,
    };
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for group in text.as_bytes().chunks(4) {
        let pad = group.iter().filter(|c| **c == b'=').count();
        let n = group
            .iter()
            .map(|c| if *c == b'=' { 0 } else { u32::from(value(*c)) })
            .fold(0u32, |acc, v| (acc << 6) | v);
        let three = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&three[..3 - pad]);
    }
    out
}

impl Transport for MemoryChain {
    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.answer(method, &params)
    }
}
