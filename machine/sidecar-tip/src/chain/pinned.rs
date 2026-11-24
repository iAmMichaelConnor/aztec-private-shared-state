//! The pinned public reads: each `public_reads` entry filled at a snapshot,
//! by simulating its call or from the storage slot that backs a plain getter.

use std::collections::BTreeMap;

use serde_json::Value;
use sidecar_core::Fr;
use sidecar_core::manifest::{Freshness, PublicRead};

use super::simulate::{SimulatedCall, call_signature};
use super::{ChainReader, ReadError, Snapshot, Transport, field, malformed};
use crate::TipManifest;

/// How a pinned value was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinnedSource {
    /// `simulatePublicCalls` of the manifest's call.
    Simulated,
    /// `getPublicStorageAt` of a plain getter's backing slot.
    Storage { slot: Fr },
}

/// One filled `public_reads` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedValue {
    /// The public parameter the value fills.
    pub param: String,
    pub contract: Fr,
    /// The full signature called.
    pub function: String,
    pub args: Vec<Fr>,
    /// The values the circuit takes from the read, in public-input order:
    /// the returned fields (one for a Field or integer getter), or under
    /// freshness epoch the first two of the three returned, the value and
    /// its epoch.
    pub values: Vec<Fr>,
    /// Under freshness epoch, the third returned field: the value of the
    /// epoch before. `None` for every other read.
    pub previous: Option<Fr>,
    /// The block whose state the value was read at.
    pub block: u64,
    pub source: PinnedSource,
}

/// Every pinned value of a manifest, in manifest order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PinnedValues(pub Vec<PinnedValue>);

impl PinnedValues {
    /// The value filling `param`.
    pub fn get(&self, param: &str) -> Option<&PinnedValue> {
        self.0.iter().find(|v| v.param == param)
    }
}

impl<T: Transport> ChainReader<T> {
    /// One pinned read by simulation: the call `apply` makes, as a static
    /// call from the namespace contract, on top of the snapshot's block.
    pub async fn simulate(
        &self,
        snap: Snapshot,
        namespace: Fr,
        read: &PublicRead,
    ) -> Result<PinnedValue, ReadError> {
        const METHOD: &str = "node_simulatePublicCalls";
        let args: Vec<Fr> = read.args.iter().map(|a| a.fr()).collect();
        let signature = call_signature(&read.function, args.len());
        let contract = read.contract.address(namespace);
        let call = SimulatedCall::new(namespace, contract, &signature, &args);
        let answer = self.call(METHOD, call.params()).await?;
        if let Some(reason) = answer.get("revertReason").filter(|r| !r.is_null()) {
            let reason = reason
                .get("originalMessage")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| reason.to_string());
            return Err(ReadError::Reverted {
                function: signature,
                reason,
            });
        }
        // the node simulates the next block on the latest proposed one
        let simulated = answer
            .pointer("/globalVariables/blockNumber")
            .and_then(Value::as_u64)
            .ok_or_else(|| malformed(METHOD, "no globalVariables.blockNumber"))?;
        if simulated != snap.block + 1 {
            return Err(ReadError::SnapshotMoved {
                snapshot: snap.block,
                simulated: simulated.saturating_sub(1),
            });
        }
        let values = match answer.pointer("/publicReturnValues/0/values") {
            Some(Value::Array(values)) => values
                .iter()
                .map(|v| field(METHOD, v))
                .collect::<Result<Vec<_>, _>>()?,
            Some(Value::Null) | None if answer.pointer("/publicReturnValues/0").is_some() => {
                Vec::new()
            }
            _ => return Err(malformed(METHOD, "no return values for the call")),
        };
        let (values, previous) = match (read.freshness, values.as_slice()) {
            (Freshness::Epoch, [value, epoch, previous]) => (vec![*value, *epoch], Some(*previous)),
            (Freshness::Epoch, other) => {
                return Err(malformed(
                    METHOD,
                    format!(
                        "the epoch read {signature} returned {} field(s), not 3 (the value, its \
                         epoch, the value of the epoch before)",
                        other.len()
                    ),
                ));
            }
            _ => (values, None),
        };
        Ok(PinnedValue {
            param: read.param.clone(),
            contract,
            function: signature,
            args,
            values,
            previous,
            block: snap.block,
            source: PinnedSource::Simulated,
        })
    }

    /// One pinned read of a plain getter, from the slot that backs it.
    pub async fn pinned_storage(
        &self,
        snap: Snapshot,
        namespace: Fr,
        read: &PublicRead,
        slot: Fr,
    ) -> Result<PinnedValue, ReadError> {
        let args: Vec<Fr> = read.args.iter().map(|a| a.fr()).collect();
        let function = call_signature(&read.function, args.len());
        if read.freshness == Freshness::Epoch {
            return Err(malformed(
                "node_getPublicStorageAt",
                format!(
                    "the epoch read {function} returns three fields, which one storage slot \
                     does not hold; it is simulated"
                ),
            ));
        }
        let contract = read.contract.address(namespace);
        let value = self.storage(snap, contract, slot).await?;
        Ok(PinnedValue {
            param: read.param.clone(),
            contract,
            function,
            args,
            values: vec![value],
            previous: None,
            block: snap.block,
            source: PinnedSource::Storage { slot },
        })
    }

    // The RPC of a pinned read: every `public_reads`
    // entry is filled by simulating its call (`simulatePublicCalls`), except
    // one whose `param` the caller maps to a backing slot in `plain`, which is
    // read with `getPublicStorageAt`. The simulation runs exactly the call
    // `apply` makes, so any getter works; the manifest cannot say that a getter
    // is plain, so only the app's configuration (`plain_reads`) can choose the
    // storage read, which saves the simulation (about 0.4 s against a
    // millisecond) but is right only while the getter returns that slot
    // unchanged; an epoch read returns three fields and is always simulated.
    // The AMM-tip example has no pinned reads; the lending example's oracle read
    // `get_price_epoch` is an epoch read, so it is simulated, and its market's
    // `clock()` returns the block number, no storage slot, so it is simulated
    // too.
    /// Every pinned value of `manifest`.
    pub async fn pinned_values(
        &self,
        snap: Snapshot,
        namespace: Fr,
        manifest: &TipManifest,
        plain: &BTreeMap<String, Fr>,
    ) -> Result<PinnedValues, ReadError> {
        let mut out = Vec::with_capacity(manifest.public_reads().len());
        for read in manifest.public_reads() {
            out.push(match plain.get(&read.param) {
                Some(&slot) => self.pinned_storage(snap, namespace, read, slot).await?,
                None => self.simulate(snap, namespace, read).await?,
            });
        }
        Ok(PinnedValues(out))
    }
}
