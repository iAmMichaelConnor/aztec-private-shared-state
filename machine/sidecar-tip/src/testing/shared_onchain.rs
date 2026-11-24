//! The request of secret-shared on-chain intake's vectors
//! (testvectors/shared_onchain.json): the round of
//! testvectors/manifests/shared_onchain_round.json, its values, the request
//! as the user's private function computes it under given node keys, and
//! the node keys' epoch records.

use serde_json::json;
use sidecar_core::derived::{self, Kind, SharedLog, request_log};
use sidecar_core::error::parse_json;
use sidecar_core::field::{FieldHex, Fr, fr_from_hex};
use sidecar_core::grumpkin::{Fq, Point};
use sidecar_core::keys::NodeKeys;
use sidecar_core::request::NODES;
use sidecar_core::store::PackageRow;

use crate::chain::LogRef;
use crate::chain::layout::request_log_tag;
use crate::intake::shared_onchain::{OnchainLayout, SharedRead, onchain_layout};
use crate::synth::TipPackage;
use crate::testing::shared_circuit_abi;
use crate::{inputs_commitment, shared_chain_request_id};

/// testvectors/manifests/shared_onchain_round.json.
pub const SHARED_ONCHAIN_ROUND: &str =
    include_str!("../../../../testvectors/manifests/shared_onchain_round.json");

fn hex(s: &str) -> Fr {
    fr_from_hex(s).unwrap()
}

/// The round of testvectors/manifests/shared_onchain_round.json on the ABI of
/// secret-shared receipt intake's vectors (two shared app inputs around a clear
/// `position`, and the three reserved shared values), every shared value
/// chosen.
pub fn package() -> TipPackage {
    let row = PackageRow {
        name: "shared_onchain_round".into(),
        manifest_hash: Fr::from(0u64),
        circuit_json: serde_json::to_vec(&json!({"abi": shared_circuit_abi()})).unwrap(),
        manifest: parse_json(SHARED_ONCHAIN_ROUND).unwrap(),
        vk: vec![],
        vk_hash: hex("0x1b7f0c2e9d8a6b5c4f3e2d1c0b9a8f7e6d5c4b3a29180f7e6d5c4b3a29180f7e"),
        disabled: false,
        seq: 1,
    };
    TipPackage::from_row(&row, Some(50)).unwrap().unwrap()
}

pub const NAMESPACE: &str = "0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";
pub const EPH: &str = "0x0e9e9e9e00c0ffee00000000000000000000000000000000000000000000e9e9";
pub const EPOCHS: [u32; NODES] = [2, 2, 1];

/// The request's values by commitment name: `position` clear, `amount`,
/// `$partial_note`, `$outcome_key` and `$outcome_tag` chosen.
pub fn values() -> Vec<(&'static str, Fr)> {
    vec![
        ("amount", Fr::from(5000u64)),
        ("position", Fr::from(7u64)),
        (
            "$partial_note",
            hex("0x0b7e3a1f00c0ffee00000000000000000000000000000000000000000000beef"),
        ),
        (
            "$outcome_key",
            hex("0x1d0c5e7a9b3f24681357acebdf0246813579bdf02468ace13579bdf02468ace1"),
        ),
        (
            "$outcome_tag",
            hex("0x0e7a9c1b3d5f02468ace13579bdf02468ace13579bdf02468ace13579bdf0246"),
        ),
    ]
}

/// One request of the vectors, as the user's private function computes it.
pub struct Request {
    pub pkg: TipPackage,
    pub ns: Fr,
    pub layout: OnchainLayout,
    /// The inputs commitment's values, in its order.
    pub values: Vec<Fr>,
    pub encoding: derived::Encoding,
    pub c: Fr,
    pub id: Fr,
    pub tag: Fr,
    pub log: Vec<Fr>,
}

/// The vectors' request under the node keys `keys` at `epochs`.
pub fn request_under(keys: [Point; NODES], epochs: [u32; NODES]) -> Request {
    let pkg = package();
    let ns = hex(NAMESPACE);
    let layout = onchain_layout(&pkg.shape, &pkg.tip);
    let vals = values();
    let kinds = layout.commitment.value_kinds();
    let plain: Vec<Fr> = layout
        .commitment
        .kinds
        .iter()
        .map(|(n, _)| vals.iter().find(|(m, _)| m == n).unwrap().1)
        .collect();
    let encoding = derived::encode(&kinds, &plain, hex(EPH), keys);
    let c = inputs_commitment(&plain, encoding.blinding);
    let id = shared_chain_request_id(ns, pkg.vk_hash, c);
    let tag = request_log_tag(id);
    let log = request_log(c, epochs, &encoding);
    Request {
        pkg,
        ns,
        layout,
        values: plain,
        encoding,
        c,
        id,
        tag,
        log,
    }
}

pub fn enc_pks(keys: &[NodeKeys]) -> [Point; NODES] {
    std::array::from_fn(|i| keys[i].enc_pk())
}

/// The vectors' request under the node keys `keys` (testvectors/keys.json's)
/// at [`EPOCHS`].
pub fn the_request(keys: &[NodeKeys]) -> Request {
    request_under(enc_pks(keys), EPOCHS)
}

impl Request {
    pub fn read(&self) -> SharedRead {
        SharedRead {
            logs: vec![(self.log.clone(), log_ref(1))],
            data_hash: derived::data_hash(&self.log),
        }
    }

    pub fn shared_log(&self) -> SharedLog {
        SharedLog {
            fields: self.log.iter().copied().map(FieldHex).collect(),
            shared: self.layout.shared.clone(),
        }
    }

    /// The value of each shared input in the encoding's order.
    pub fn shared_values(&self) -> Vec<Fr> {
        let mut out: Vec<Fr> = self
            .layout
            .commitment
            .kinds
            .iter()
            .zip(&self.values)
            .filter(|((_, k), _)| *k != Kind::Clear)
            .map(|(_, v)| *v)
            .collect();
        out.push(self.encoding.blinding);
        out
    }
}

pub fn log_ref(n: u64) -> LogRef {
    LogRef {
        block: 40 + n,
        tx_hash: format!("0x{n:064x}"),
        tx_index: 0,
        log_index: n,
    }
}

/// `node` with `scalar` recorded for each `(epoch, scalar)` in `ns`.
pub fn node_with(node: &NodeKeys, ns: Fr, epochs: &[(u32, Fq)]) -> NodeKeys {
    let mut keys = node.clone();
    for &(e, scalar) in epochs {
        keys.epochs_mut().record(ns, e, scalar).unwrap();
    }
    keys
}

/// The rotation of the vectors: node 1 sets a new key at epoch 3.
pub fn rotation_scalar() -> Fq {
    Fq::from(0x0f1f2f3fu64)
}
