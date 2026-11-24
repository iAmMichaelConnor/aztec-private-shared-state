//! The scheduler's and the chain verifier's side of a tree-valued key with
//! `access: oblivious` (docs/ARCHITECTURE.md section 6, "The oblivious tree",
//! "The scheduler and the chain verifier"); each node's own side is
//! sidecar-oblivious's `ObliviousTree`.
//!
//! The scheduler learns no index and reads no path: the only node-sourced
//! value such a round carries is `$new_leaf`, when the layout opens leaves,
//! from the nodes' public append index (the tree query with no indices,
//! which the three must answer alike); each node's chain verifier derives it
//! from its own version and refuses a request that carries another.

use sidecar_core::error::Refusal;
use sidecar_core::field::{FieldHex, Fr, fr_to_hex};
use sidecar_core::manifest::{Manifest, TreeLayout};
use sidecar_core::request::PublicValue;
use sidecar_core::tree;
use sidecar_oblivious::{ObliviousMap, ObliviousTree};

use crate::state::tree::{PublicMap, TreeSource};
use crate::state::{KeyState, TipCheck, TipFuture, TreeValues};
use crate::synth::TipPackage;
use crate::verifier::refused;

/// `$new_leaf` under its parameter's name, for a layout that opens leaves
/// and a version with append index `next`; nothing otherwise.
fn values(manifest: &Manifest, layout: &TreeLayout, next: u64) -> PublicMap {
    let mut out = PublicMap::new();
    if let (Some(_), Some(param)) = (&layout.open, manifest.new_leaf_param()) {
        out.insert(
            param.to_string(),
            PublicValue::One(FieldHex(Fr::from(tree::new_leaf(next, layout.depth)))),
        );
    }
    out
}

impl TreeValues for ObliviousTree {
    /// This node's own `$new_leaf` at the version `state` names.
    fn round_values(&self, at: &TipCheck<'_>, state: &KeyState) -> Result<PublicMap, Refusal> {
        if state.commitment == Fr::from(0u64) || self.layout().open.is_none() {
            return Ok(PublicMap::new());
        }
        let ns = at.req.namespace.fr();
        let key = &at.slot.key;
        let next = at
            .rows
            .tip_versions(ns, key)?
            .into_iter()
            .find(|v| v.commitment == state.commitment)
            .and_then(|v| v.tree)
            .map(|t| t.next())
            .ok_or_else(|| {
                refused(format!(
                    "key `{key}`: this node holds no tree under commitment {}",
                    fr_to_hex(state.commitment)
                ))
            })?;
        Ok(values(at.package.tip.manifest(), self.layout(), next))
    }

    /// `$new_leaf` from the three nodes' append index at the version `state`
    /// names, in one read that names no index.
    fn node_values<'a>(
        &'a self,
        package: &'a TipPackage,
        key: &'a str,
        state: &'a KeyState,
        _public: &'a PublicMap,
        trees: &'a dyn TreeSource,
    ) -> TipFuture<'a, Result<PublicMap, Refusal>> {
        Box::pin(async move {
            let layout = self.layout();
            if layout.open.is_none() {
                return Ok(PublicMap::new());
            }
            let paths = trees
                .paths(
                    key.to_string(),
                    state.commitment,
                    layout.depth,
                    vec![],
                    None,
                )
                .await?;
            Ok(values(package.tip.manifest(), layout, paths.next))
        })
    }
}

/// A keyed map carries no node-sourced value: no header, no opening, no
/// append index, no window (docs/ARCHITECTURE.md section 6, "The scheduler and
/// the chain verifier on a keyed map").
impl TreeValues for ObliviousMap {}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sidecar_core::error::ErrorClass;
    use sidecar_test_fixtures::data::manifest;

    use crate::state::holders;

    const R0: &str = "$state_keys.reads[0]";

    /// REGISTER's state checks under the tip machine's holders.
    fn check(manifest: Value) -> Result<(), sidecar_core::error::Refusal> {
        holders()
            .check_register(&sidecar_core::manifest::Manifest::parse(&manifest)?)
            .map(|_| ())
    }

    fn refused(manifest: Value, needle: &str) {
        let err = check(manifest).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
        assert!(err.message.contains(needle), "`{err}` lacks `{needle}`");
    }

    /// The manifest with the tree under [`R0`] reshaped to `depth` and
    /// `leaf_len`, its LOAD slices and output lengths following, so only the
    /// shape is new.
    fn reshaped(mut m: Value, depth: u64, leaf_len: u64) -> Value {
        let tree = &mut m["tree"][R0];
        tree["depth"] = depth.into();
        tree["leaf_len"] = leaf_len.into();
        let k = tree["probe"].as_u64().unwrap();
        let params = tree["params"].clone();
        let len = k * (leaf_len + 1 + depth);
        let slices = [
            (params["leaves"].clone(), [0, k * leaf_len]),
            (
                params["old_hashes"].clone(),
                [k * leaf_len, k * (leaf_len + 1)],
            ),
            (params["siblings"].clone(), [k * (leaf_len + 1), len]),
        ];
        for w in m["witness"].as_array_mut().unwrap() {
            if w["from"]["LOAD"] == R0 {
                let slice = slices.iter().find(|(p, _)| *p == w["param"]).unwrap().1;
                w["from"]["slice"] = json!(slice);
                w["from"]["len"] = len.into();
            }
        }
        let store = m["tree"][R0]["store"].clone();
        for o in m["outputs"].as_array_mut().unwrap() {
            if o["STORE"] == store {
                o["len"] = len.into();
            }
        }
        m
    }

    /// Every oblivious manifest of the examples registers.
    #[test]
    fn every_oblivious_manifest_registers() {
        let lending = [
            "borrow",
            "deposit",
            "lending_init",
            "liquidate",
            "quote",
            "repay",
            "scan",
            "supply",
            "view",
            "withdraw",
            "withdraw_supply",
        ];
        for name in lending {
            let name = format!("{name}_oblivious");
            check(manifest("lending-tip", &name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        for name in ["credits_init", "claim", "move", "pay", "view"] {
            check(manifest("credits-tip", name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    /// REGISTER refuses (400, naming the field) every oblivious shape the
    /// brick cannot serve, each one a shape the manifest checks alone
    /// accept: a dense DORAM over 2^22 addresses (depth 19 to 28 with leaves
    /// of 8), a dense tree of depth 1 with leaves of 1 or 2 (a DORAM of 2^3
    /// addresses, whose speed cache cannot hold the stash), a keyed map's
    /// capacity of 2^37 to 2^40 (nine levels; the DORAM names eight) and a
    /// leaf past the bricks' 64 elements; the reshaping itself registers at
    /// shapes in bounds.
    #[test]
    fn register_refuses_an_oblivious_shape_the_brick_cannot_serve() {
        let dense = manifest("lending-tip", "deposit_oblivious");
        check(reshaped(dense.clone(), 18, 8)).unwrap();
        check(reshaped(dense.clone(), 1, 3)).unwrap();
        for depth in [19, 20, 28, 29] {
            refused(
                reshaped(dense.clone(), depth, 8),
                "field `manifest.tree.$state_keys.reads[0].depth`: a dense oblivious tree",
            );
        }
        for leaf_len in [1, 2] {
            refused(
                reshaped(dense.clone(), 1, leaf_len),
                "which the DORAM cannot take: stash must fit inside the speed cache",
            );
        }

        let map = manifest("credits-tip", "move");
        let with = |capacity: u64| {
            let mut v = map.clone();
            v["tree"][R0]["capacity"] = capacity.into();
            v
        };
        for capacity in [8, 36] {
            check(with(capacity)).unwrap();
        }
        for capacity in [7, 37, 38, 40, 41] {
            refused(
                with(capacity),
                "field `manifest.tree.$state_keys.reads[0].capacity`: log2 of the distinct",
            );
        }
        check(reshaped(map.clone(), 64, 64)).unwrap();
        for leaf_len in [65, 1 << 20] {
            refused(
                reshaped(map.clone(), 64, leaf_len),
                "tree.$state_keys.reads[0].leaf_len`",
            );
        }
        // past every tree's bound the manifest checks refuse it themselves
        refused(
            reshaped(map.clone(), 64, (1 << 20) + 1),
            "tree.$state_keys.reads[0].leaf_len`",
        );
    }
}
