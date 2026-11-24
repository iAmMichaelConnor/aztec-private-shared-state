//! One node's rows as the chain verifier and the tip states read them
//! (sidecar-core's `VerifierRows`), set by a test.

use std::collections::BTreeMap;

use sidecar_core::error::Refusal;
use sidecar_core::field::Fr;
use sidecar_core::pipeline::VerifierRows;
use sidecar_core::store::{ManifestRow, ReceiptRow, RequestRow, TipVersion};
use sidecar_core::tree::TreeNode;

/// A node's latest result per chain request id, its stored receipts, and
/// the versions of its node-held keys; no tree node.
#[derive(Clone, Debug, Default)]
pub struct Rows {
    pub results: BTreeMap<Fr, RequestRow>,
    pub receipts: BTreeMap<Fr, ReceiptRow>,
    /// Each version with the namespace it is read under; `None` answers
    /// every namespace.
    pub versions: Vec<(Option<Fr>, TipVersion)>,
}

impl Rows {
    /// Rows holding these receipts, by chain request id.
    pub fn with_receipts(receipts: impl IntoIterator<Item = (Fr, ReceiptRow)>) -> Self {
        Rows {
            receipts: receipts.into_iter().collect(),
            ..Rows::default()
        }
    }

    /// Rows holding these versions, under every namespace.
    pub fn with_versions(versions: impl IntoIterator<Item = TipVersion>) -> Self {
        Rows {
            versions: versions.into_iter().map(|v| (None, v)).collect(),
            ..Rows::default()
        }
    }

    /// Rows holding these versions, each under its own namespace.
    pub fn namespaced(versions: impl IntoIterator<Item = (Fr, TipVersion)>) -> Self {
        Rows {
            versions: versions.into_iter().map(|(ns, v)| (Some(ns), v)).collect(),
            ..Rows::default()
        }
    }
}

impl VerifierRows for Rows {
    fn chain_request(&self, _: Fr, chain: Fr) -> Result<Option<RequestRow>, Refusal> {
        Ok(self.results.get(&chain).cloned())
    }

    fn receipt(&self, _: Fr, chain: Fr) -> Result<Option<ReceiptRow>, Refusal> {
        Ok(self.receipts.get(&chain).cloned())
    }

    fn tip_versions(&self, namespace: Fr, key: &str) -> Result<Vec<TipVersion>, Refusal> {
        Ok(self
            .versions
            .iter()
            .filter(|(ns, v)| ns.is_none_or(|ns| ns == namespace) && v.key == key)
            .map(|(_, v)| v.clone())
            .collect())
    }

    fn tip_node(&self, _: Fr, _: &str, _: Fr) -> Result<Option<TreeNode>, Refusal> {
        Ok(None)
    }

    fn contract_manifest(&self, _: Fr) -> Result<Option<ManifestRow>, Refusal> {
        Ok(None)
    }

    fn contract_manifests(&self, _: Fr) -> Result<Vec<ManifestRow>, Refusal> {
        Ok(Vec::new())
    }
}
